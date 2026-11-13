// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Wasmtime;

namespace Sigill.Sdk.Policy;

/// <summary>
/// The official Cedar policy core (<c>cedar-policy</c> <see cref="CoreVersion"/>) as one WebAssembly module, hosted
/// in-process with Wasmtime. The module is embedded in this assembly and refused unless its sha256 is
/// <see cref="ModuleSha256"/>. It gets no filesystem, network, clock, environment or stdio, and at most
/// <see cref="MemoryLimitBytes"/> of memory. Loaded on first use; one instance behind a lock, so an engine can be shared
/// between threads and tasks. Calls and answers are never logged.
/// </summary>
public sealed class CedarEngine : IPolicyEngine, IDisposable
{
    /// <summary>The sha256 of the embedded module (<c>engine/README.md</c>).</summary>
    public const string ModuleSha256 = "a0cd395067e77a157116f6b25bcdb612d34c61d1a4446918d75da1a07c80d1f3";

    /// <summary>The Cedar core the module is built from; its <c>cedar_version</c> must report exactly this.</summary>
    public const string CoreVersion = "4.14.0";

    /// <summary>The cap on the module's linear memory: a hostile policy or request cannot exhaust the host.</summary>
    public const long MemoryLimitBytes = 256L * 1024 * 1024;

    private const string ResourceName = "Sigill.Sdk.Policy.sigill_cedar.wasm";

    private readonly object _gate = new();
    private readonly Func<byte[]> _moduleBytes;
    private readonly long _memoryLimit;
    private Engine? _engine;
    private Module? _module;
    private Linker? _linker;
    private Session? _session;
    private bool _disposed;

    /// <summary>The engine with the embedded module. Nothing is loaded until the first call.</summary>
    public CedarEngine() : this(ReadEmbedded, MemoryLimitBytes) { }

    /// <summary>Tests: another module (it must still have the pinned sha256) or a smaller memory cap.</summary>
    internal CedarEngine(byte[] module, long memoryLimit) : this(() => module, memoryLimit) { }

    private CedarEngine(Func<byte[]> moduleBytes, long memoryLimit)
    {
        _moduleBytes = moduleBytes;
        _memoryLimit = memoryLimit;
    }

    /// <inheritdoc />
    /// <exception cref="PolicyEngineException">The module could not be loaded.</exception>
    public string Version
    {
        get { lock (_gate) return Ready().Version; }
    }

    /// <inheritdoc />
    /// <exception cref="PolicyEngineException">The module could not be loaded, or trapped.</exception>
    public JsonObject Authorize(JsonObject call) => Call("cedar_authorize", s => s.Authorize, call);

    /// <inheritdoc />
    /// <exception cref="PolicyEngineException">The module could not be loaded, or trapped.</exception>
    public JsonObject Validate(JsonObject call) => Call("cedar_validate", s => s.Validate, call);

    /// <summary>Releases the Wasmtime engine, module and instance.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            Discard();
            _linker?.Dispose();
            _module?.Dispose();
            _engine?.Dispose();
        }
    }

    private JsonObject Call(string name, Func<Session, Func<int, int, int, int>> export, JsonObject call)
    {
        if (call is null) throw new ArgumentNullException(nameof(call));
        byte[] input;
        // RFC 8785: numbers in the form the reference reads them (-0, 20.0 and 2e1 are the integers they equal).
        try { input = EnvelopeHashing.Canonicalize(call); }
        catch (Exception ex) { throw new PolicyEngineException($"The policy engine failed ({name}): the call is not I-JSON ({ex.Message})", ex); }
        byte[] answer;
        lock (_gate)
        {
            var session = Ready();
            try { answer = session.Call(export(session), input); }
            catch (Exception ex)
            {
                Discard(); // after a trap the instance's state is undefined: the next call instantiates again
                throw new PolicyEngineException($"The policy engine failed ({name}): {ex.Message}", ex);
            }
        }
        JsonObject? parsed;
        try { parsed = JsonNode.Parse(answer) as JsonObject; }
        catch (Exception) { parsed = null; } // not JSON at all
        return parsed ?? throw new PolicyEngineException($"The policy engine's answer ({name}) is not a JSON object.");
    }

    /// <summary>The live instance, created on first use and after a trap. Callers hold the lock.</summary>
    private Session Ready()
    {
        if (_disposed) throw new ObjectDisposedException(nameof(CedarEngine));
        if (_session is not null) return _session;
        Store? store = null;
        try
        {
            if (_module is null)
            {
                var bytes = _moduleBytes();
                var sha = EnvelopeHashing.HashHex(bytes);
                if (sha != ModuleSha256)
                    throw new PolicyEngineException("The policy engine module is not the bundled sigill_cedar.wasm (its SHA-256 differs); it is not run.");
                _engine = new Engine();
                _module = Module.FromBytes(_engine, "sigill_cedar", bytes);
                _linker = new Linker(_engine);
                _linker.DefineWasi();
            }
            store = new Store(_engine!);
            store.SetLimits(memorySize: _memoryLimit);
            store.SetWasiConfiguration(new WasiConfiguration()); // no arguments, environment, directories or inherited stdio
            var session = new Session(store, _linker!.Instantiate(store, _module));
            if (session.Version != CoreVersion)
                throw new PolicyEngineException($"The policy engine module carries Cedar {session.Version}, not {CoreVersion}.");
            _session = session;
            return session;
        }
        catch (Exception ex)
        {
            store?.Dispose();
            if (ex is PolicyEngineException) throw;
            throw new PolicyEngineException("The policy engine could not be loaded: " + ex.Message, ex);
        }
    }

    private void Discard()
    {
        _session?.Store.Dispose();
        _session = null;
    }

    private static byte[] ReadEmbedded()
    {
        using var stream = typeof(CedarEngine).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"the embedded module '{ResourceName}' is missing");
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    /// <summary>One instance of the module and its exports (engine/README.md: the ABI).</summary>
    private sealed class Session
    {
        public readonly Store Store;
        public readonly Func<int, int, int, int> Authorize, Validate;
        public readonly string Version;
        private readonly Memory _memory;
        private readonly Func<int, int> _alloc;
        private readonly Action<int, int> _free;

        public Session(Store store, Instance instance)
        {
            Store = store;
            instance.GetAction("_initialize")?.Invoke();
            string Missing(string name) => $"the module has no export '{name}'";
            _memory = instance.GetMemory("memory") ?? throw new InvalidOperationException(Missing("memory"));
            _alloc = instance.GetFunction<int, int>("cedar_alloc") ?? throw new InvalidOperationException(Missing("cedar_alloc"));
            _free = instance.GetAction<int, int>("cedar_free") ?? throw new InvalidOperationException(Missing("cedar_free"));
            Authorize = instance.GetFunction<int, int, int, int>("cedar_authorize") ?? throw new InvalidOperationException(Missing("cedar_authorize"));
            Validate = instance.GetFunction<int, int, int, int>("cedar_validate") ?? throw new InvalidOperationException(Missing("cedar_validate"));
            var version = instance.GetFunction<int, int>("cedar_version") ?? throw new InvalidOperationException(Missing("cedar_version"));
            var slot = _alloc(4);
            Version = Encoding.UTF8.GetString(Take(version(slot), slot));
            _free(slot, 4);
        }

        /// <summary>Input, then a 4-byte slot for the answer's length; the module's answer is copied out and freed.</summary>
        public byte[] Call(Func<int, int, int, int> export, byte[] input)
        {
            var p = _alloc(input.Length + 4);
            input.CopyTo(_memory.GetSpan(p, input.Length));
            var answer = Take(export(p, input.Length, p + input.Length), p + input.Length);
            _free(p, input.Length + 4);
            return answer;
        }

        private byte[] Take(int pointer, int lengthSlot)
        {
            var length = _memory.ReadInt32(lengthSlot);
            var bytes = _memory.GetSpan(pointer, length).ToArray();
            _free(pointer, length);
            return bytes;
        }
    }
}
