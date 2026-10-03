// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>
/// Records one agent run under AgentExecutionProfileV1
/// (<c>spec/agent-execution-profile-v1.md</c>). Every step becomes a v2
/// artifact, sealed blind (digests and opaque URIs only) and chained to the
/// previous step's signature, so a verifier can detect removed, reordered,
/// inserted or spliced steps.
///
/// <code>
/// var run = await AgentRun.StartAsync(client, agent, new AgentRunOptions { CertificateId = certId });
/// await run.RecordToolCallAsync("lookup_ticket", argsJson);
/// await run.RecordToolResultAsync("lookup_ticket", resultJson);
/// await run.RecordModelOutputAsync(answer);
/// AgentRunBundle bundle = await run.FinishAsync("completed");
/// </code>
///
/// Steps are sealed one at a time, in call order; calls may come from any
/// thread. A sealing failure throws and stops the chain (spec §6): later
/// calls throw <see cref="InvalidOperationException"/>, and the bundle so far
/// verifies as open or invalid, never as finalized.
/// </summary>
public sealed class AgentRun
{
    private readonly ISigillAiEvidenceClient _client;
    private readonly AgentDefinition _agent;
    private readonly AgentRunOptions _options;
    private readonly Func<DateTimeOffset> _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<AgentRunArtifact> _artifacts = new();
    private readonly Dictionary<string, byte[]> _payloads = new(StringComparer.Ordinal);
    private AgentExecutionProfile.TimestampCoverage _coverage;
    private string? _prevChainDigest;
    private string? _prevEvidenceId;
    private bool _broken;
    private bool _finished;

    /// <summary>The run identifier (<c>activity.correlationId</c>).</summary>
    public string CorrelationId { get; }

    /// <summary>The identity record this run's <c>run_start</c> references. Reuse it for later runs of the same configuration.</summary>
    public AgentRunArtifact Identity { get; private set; } = null!;

    /// <summary>The sealed artifacts so far, in chain order.</summary>
    public IReadOnlyList<AgentRunArtifact> Artifacts
    {
        get { lock (_artifacts) return _artifacts.ToArray(); }
    }

    /// <summary>A sealing failure stopped the chain.</summary>
    public bool IsBroken => _broken;

    /// <summary><c>run_end</c> has been sealed.</summary>
    public bool IsFinished => _finished;

    private AgentRun(ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options, Func<DateTimeOffset> clock)
    {
        _client = client;
        _agent = agent;
        _options = options;
        _clock = clock;
        CorrelationId = options.CorrelationId ?? "urn:uuid:" + Guid.NewGuid();
        var p = options.TimestampPolicy;
        _coverage = new AgentExecutionProfile.TimestampCoverage(p.Profile, p.EveryEvents, p.EverySeconds, p.RunStart);
    }

    /// <summary>
    /// Opens a run: registers the identity record unless
    /// <see cref="AgentRunOptions.Identity"/> supplies one, then seals
    /// <c>run_start</c> binding the agent's configuration.
    /// </summary>
    /// <exception cref="ArgumentException">The supplied identity record was registered for a different configuration.</exception>
    public static Task<AgentRun> StartAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options, CancellationToken cancellationToken = default) =>
        StartCoreAsync(client, agent, options, () => DateTimeOffset.UtcNow, cancellationToken);

    internal static async Task<AgentRun> StartCoreAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options,
        Func<DateTimeOffset> clock, CancellationToken cancellationToken)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        if (agent is null) throw new ArgumentNullException(nameof(agent));
        if (options is null) throw new ArgumentNullException(nameof(options));
        ValidatePolicy(options.TimestampPolicy);

        var configDigest = AgentExecutionProfile.ConfigurationDigest(
            agent.Manifest ?? AgentExecutionProfile.DefaultManifest(agent), agent.Configuration);
        var identity = options.Identity;
        IReadOnlyList<AgentRunObject>? registeredObjects = null;
        if (identity is not null)
        {
            var ext = identity.Envelope["extensions"]?[AgentExecutionProfile.ExtensionKey];
            if (AgentExecutionProfile.Str(ext?["configSha256"]) != configDigest
                || AgentExecutionProfile.Str(ext?["agentId"]) != agent.AgentId
                || AgentExecutionProfile.Str(ext?["agentVersion"]) != agent.AgentVersion)
                throw new ArgumentException(
                    "The supplied identity record was registered for a different agent, version or configuration; register a new one.",
                    nameof(options));
        }
        else
        {
            (identity, registeredObjects) = await RegisterIdentityCoreAsync(client, agent, options.CertificateId,
                options.RegisteredBy, options.Qualified, clock, cancellationToken).ConfigureAwait(false);
        }

        var run = new AgentRun(client, agent, options, clock) { Identity = identity };
        run._prevEvidenceId = identity.EvidenceId;
        if (options.RetainPayloads)
        {
            if (registeredObjects is not null)
                foreach (var o in registeredObjects) run._payloads[o.Uri] = o.Bytes;
            else
                foreach (var o in IdentityObjects(agent, identity)) run._payloads[o.Key] = o.Value;
        }

        var objects = AgentExecutionProfile.ConfigurationObjects(agent.Configuration);
        if (options.StartObjects is not null) objects.AddRange(options.StartObjects);

        var block = new JsonObject
        {
            ["agentIdentityEvidenceId"] = identity.EvidenceId,
            ["assuranceProfile"] = options.TimestampPolicy.Profile,
            ["timestampPolicy"] = options.TimestampPolicy.ToJson(),
        };
        var start = await run.SealStepAsync("run_start", objects, block, consequential: false, cancellationToken).ConfigureAwait(false);
        // §4.1: one certificate per run, identity record included.
        if (AgentExecutionProfile.SignerOf(start.Signature).Thumbprint != AgentExecutionProfile.SignerOf(identity.Signature).Thumbprint)
        {
            run._broken = true;
            throw new SigillException(
                "The identity record was sealed with a different certificate than this run (certificate rotated?); register a new identity record.");
        }
        await run.NotifyAsync(start, cancellationToken).ConfigureAwait(false);
        return run;
    }

    /// <summary>
    /// Registers an identity record (spec §3.6) for the agent's current
    /// configuration. Store the result and pass it as
    /// <see cref="AgentRunOptions.Identity"/> while the configuration is
    /// unchanged.
    /// </summary>
    public static async Task<AgentRunArtifact> RegisterIdentityAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, Guid certificateId,
        string? registeredBy = null, bool qualified = false, CancellationToken cancellationToken = default) =>
        (await RegisterIdentityCoreAsync(client, agent, certificateId, registeredBy, qualified,
            () => DateTimeOffset.UtcNow, cancellationToken).ConfigureAwait(false)).Artifact;

    private static async Task<(AgentRunArtifact Artifact, IReadOnlyList<AgentRunObject> Objects)> RegisterIdentityCoreAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, Guid certificateId, string? registeredBy,
        bool qualified, Func<DateTimeOffset> clock, CancellationToken cancellationToken)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        if (agent is null) throw new ArgumentNullException(nameof(agent));

        var now = AgentExecutionProfile.Truncate(clock());
        var manifest = agent.Manifest ?? AgentExecutionProfile.DefaultManifest(agent);
        var configDigest = AgentExecutionProfile.ConfigurationDigest(manifest, agent.Configuration);
        var registration = new JsonObject
        {
            ["action"] = "agent-registration",
            ["mode"] = "automatic-on-first-use",
            ["agentId"] = agent.AgentId,
            ["configSha256"] = configDigest,
            ["registeredAt"] = AgentExecutionProfile.FormatTime(now),
        };
        if (registeredBy is not null) registration["registeredBy"] = registeredBy;

        var objects = new List<AgentRunObject>
        {
            new() { Kind = "agent-manifest", Role = "input", ContentType = "application/json", Bytes = manifest },
        };
        objects.AddRange(AgentExecutionProfile.ConfigurationObjects(agent.Configuration));
        objects.Add(new AgentRunObject
        {
            Kind = "registration-record", Role = "input", ContentType = "application/json",
            Bytes = AgentExecutionProfile.Canonical(registration),
        });
        var block = new JsonObject
        {
            ["recordType"] = "agent-identity",
            ["stepType"] = "record:agent-identity",
            ["agentId"] = agent.AgentId,
            ["agentVersion"] = agent.AgentVersion,
            ["configSha256"] = configDigest,
            ["eventTime"] = AgentExecutionProfile.FormatTime(now),
        };
        if (registeredBy is not null) block["registeredBy"] = registeredBy;

        var envelope = AgentExecutionProfile.BuildEnvelope(
            Guid.NewGuid().ToString(), now, "agent-identity", agent, "agent_identity",
            correlationId: null, parentEvidenceId: null, objects, chainSeq: null, prevChainDigest: null, block);
        AgentRunVerifier.Prevalidate(envelope);
        var result = await SealAsync(client, envelope, objects, certificateId, timestamp: true, qualified,
            cancellationToken).ConfigureAwait(false);
        if (result.TimestampedBy is null)
            throw new SigillException("The identity record must be timestamped, but the seal carries no timestamp.");
        return (new AgentRunArtifact(envelope, result.Signature, Digests(objects)), objects);
    }

    // ── Steps ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Seals one step. <paramref name="consequential"/> marks an external side
    /// effect (a write-class tool call, a delivered message); such steps are
    /// always timestamped. <paramref name="extension"/> adds producer fields to
    /// the signed profile block — keep them free of personal data.
    /// </summary>
    public async Task<AgentRunArtifact> RecordAsync(
        string stepType, IReadOnlyList<AgentRunObject>? objects = null, JsonObject? extension = null,
        bool consequential = false, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(stepType)) throw new ArgumentException("stepType is required.", nameof(stepType));
        if (stepType is "run_start" or "run_end" || stepType.StartsWith("record:", StringComparison.Ordinal))
            throw new ArgumentException($"'{stepType}' is not a step type a producer may record.", nameof(stepType));
        var reserved = extension?.Select(kv => kv.Key).Where(AgentExecutionProfile.ReservedExtensionKeys.Contains)
            .OrderBy(k => k, StringComparer.Ordinal).ToList();
        if (reserved is { Count: > 0 })
            throw new ArgumentException("extension uses reserved profile name(s): " + string.Join(", ", reserved), nameof(extension));
        AgentRunArtifact artifact;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureOpen();
            artifact = await SealStepAsync(stepType, objects ?? Array.Empty<AgentRunObject>(),
                (JsonObject?)extension?.DeepClone() ?? new JsonObject(), consequential, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
        await NotifyAsync(artifact, cancellationToken).ConfigureAwait(false);
        return artifact;
    }

    /// <summary>Retrieved context (RAG) the agent read.</summary>
    public Task<AgentRunArtifact> RecordRetrievalAsync(byte[] context, string contentType = "text/plain", CancellationToken cancellationToken = default) =>
        RecordAsync("retrieval", new[] { Obj("retrieval-result", "context", context, contentType) }, cancellationToken: cancellationToken);

    /// <summary>
    /// A tool call the agent decided to make (spec §3.4). <paramref name="operation"/>
    /// classifies it (e.g. <c>read</c>, <c>write</c>); mark write-class calls
    /// <paramref name="consequential"/>. <paramref name="authorization"/> records
    /// the policy decision taken before the call.
    /// </summary>
    public Task<AgentRunArtifact> RecordToolCallAsync(string tool, byte[] arguments, string? operation = null,
        AgentAuthorization? authorization = null, bool consequential = false, string? useId = null,
        string contentType = "application/json", CancellationToken cancellationToken = default)
    {
        var ext = new JsonObject { ["tool"] = ToolBlock(tool, operation, useId) };
        if (authorization is not null) ext["authorization"] = authorization.ToJson();
        return RecordAsync("tool_call", new[] { Obj("tool-arguments", "input", arguments, contentType) },
            ext, consequential, cancellationToken);
    }

    /// <summary>The result a tool returned — context for the model's next turn.</summary>
    public Task<AgentRunArtifact> RecordToolResultAsync(string tool, byte[] result, string? useId = null,
        string contentType = "application/json", CancellationToken cancellationToken = default) =>
        RecordAsync("tool_result", new[] { Obj("tool-result", "context", result, contentType) },
            new JsonObject { ["tool"] = ToolBlock(tool, null, useId) }, cancellationToken: cancellationToken);

    /// <summary>A standalone policy decision (spec §3.4), e.g. "this write needs approval".</summary>
    public Task<AgentRunArtifact> RecordAuthorizationAsync(AgentAuthorization authorization, string? tool = null,
        string? operation = null, CancellationToken cancellationToken = default)
    {
        if (authorization is null) throw new ArgumentNullException(nameof(authorization));
        var ext = new JsonObject { ["authorization"] = authorization.ToJson() };
        if (tool is not null) ext["tool"] = ToolBlock(tool, operation, null);
        return RecordAsync("authorization", extension: ext, cancellationToken: cancellationToken);
    }

    /// <summary>
    /// A human approval (spec §3.4). <paramref name="approverRef"/> is opaque —
    /// never a name or e-mail address. The receipt and an identity assertion
    /// (e.g. an IdP token) are bound as detached objects; their bytes stay
    /// local. Consequential by default: an approval authorizes a side effect.
    /// </summary>
    public Task<AgentRunArtifact> RecordHumanApprovalAsync(string decision, byte[]? receipt = null,
        byte[]? identityAssertion = null, string? approverRef = null, string? actionEvidenceId = null,
        DateTimeOffset? decidedAt = null, bool consequential = true, string receiptContentType = "application/json",
        string identityAssertionContentType = "application/jwt", CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(decision)) throw new ArgumentException("decision is required.", nameof(decision));
        var approval = new JsonObject { ["decision"] = decision };
        if (approverRef is not null) approval["approverRef"] = approverRef;
        if (actionEvidenceId is not null) approval["actionEvidenceId"] = actionEvidenceId;
        if (decidedAt is { } at) approval["decidedAt"] = AgentExecutionProfile.FormatTime(at);
        var objects = new List<AgentRunObject>();
        if (receipt is not null) objects.Add(Obj("approval-receipt", "input", receipt, receiptContentType));
        if (identityAssertion is not null) objects.Add(Obj("identity-assertion", "input", identityAssertion, identityAssertionContentType));
        return RecordAsync("human_approval", objects, new JsonObject { ["approval"] = approval }, consequential, cancellationToken);
    }

    /// <summary>What the model produced.</summary>
    public Task<AgentRunArtifact> RecordModelOutputAsync(byte[] output, string contentType = "text/plain",
        CancellationToken cancellationToken = default) =>
        RecordAsync("model_output", new[] { Obj("assistant-reply", "output", output, contentType) }, cancellationToken: cancellationToken);

    /// <summary>
    /// Anchors the chain head with a timestamped <c>checkpoint</c> step (spec
    /// §5) — e.g. from a timer while the agent is idle, so an unanchored head
    /// does not wait for the next event.
    /// </summary>
    public Task<AgentRunArtifact> CheckpointAsync(string reason = "idle", CancellationToken cancellationToken = default) =>
        RecordAsync("checkpoint", extension: new JsonObject { ["checkpoint"] = new JsonObject { ["reason"] = reason } },
            cancellationToken: cancellationToken);

    /// <summary>
    /// Seals <c>run_end</c>, committing to the chain head (spec §3.3), and
    /// returns the bundle. <paramref name="disposition"/>: completed | failed | aborted.
    /// </summary>
    public async Task<AgentRunBundle> FinishAsync(
        string disposition = "completed", JsonObject? usage = null, CancellationToken cancellationToken = default)
    {
        if (disposition is not ("completed" or "failed" or "aborted"))
            throw new ArgumentException("disposition must be completed, failed or aborted.", nameof(disposition));
        AgentRunArtifact artifact;
        AgentRunBundle bundle;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureOpen();
            AgentRunArtifact head;
            lock (_artifacts) head = _artifacts[_artifacts.Count - 1];
            var block = new JsonObject
            {
                ["finalSeq"] = head.Seq,
                ["finalPrevSignatureSha256"] = _prevChainDigest,
                ["runDisposition"] = disposition,
            };
            if (usage is not null) block["usage"] = usage.DeepClone();
            artifact = await SealStepAsync("run_end", Array.Empty<AgentRunObject>(), block, consequential: true, cancellationToken).ConfigureAwait(false);
            bundle = ToBundle();
        }
        finally { _gate.Release(); }
        await NotifyAsync(artifact, cancellationToken).ConfigureAwait(false);
        return bundle;
    }

    /// <summary>The run as a bundle — available at any point, including after a failure.</summary>
    public AgentRunBundle ToBundle()
    {
        Dictionary<string, byte[]> payloads;
        lock (_artifacts) payloads = new Dictionary<string, byte[]>(_payloads, StringComparer.Ordinal);
        return new AgentRunBundle(CorrelationId, Identity, Artifacts, payloads);
    }

    // ── Sealing ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds, validates and seals one step. Call with the gate held; the
    /// callback is the caller's job, after releasing it.
    /// </summary>
    private async Task<AgentRunArtifact> SealStepAsync(
        string stepType, IReadOnlyList<AgentRunObject> objects, JsonObject block, bool consequential, CancellationToken ct)
    {
        var now = AgentExecutionProfile.Truncate(_clock()); // the decision below must use the signed, truncated time
        int seq;
        lock (_artifacts) seq = _artifacts.Count;
        var coverage = _coverage.Clone(); // committed only once the step is sealed
        var declared = AgentExecutionProfile.Str(block["timestamp"]) == "required";
        var stamp = coverage.Next(seq, stepType, consequential, declared, now);

        block["stepType"] = stepType;
        block["agentVersion"] = _agent.AgentVersion;
        block["eventTime"] = AgentExecutionProfile.FormatTime(now);
        block["consequential"] = consequential;
        block["timestamp"] = stamp ? "required" : "none";

        var envelope = AgentExecutionProfile.BuildEnvelope(
            Guid.NewGuid().ToString(), now, "agent-execution", _agent, stepType, CorrelationId, _prevEvidenceId,
            objects, seq, _prevChainDigest, block);
        var digests = Digests(objects);
        AgentRunVerifier.Prevalidate(envelope); // an ArgumentException here leaves the run usable

        try
        {
            var result = await SealAsync(_client, envelope, objects, _options.CertificateId, stamp, _options.Qualified, ct)
                .ConfigureAwait(false);
            if (stamp && result.TimestampedBy is null)
                throw new SigillException($"{stepType}: a timestamp is required by the run's policy, but the seal carries none.");

            var artifact = new AgentRunArtifact(envelope, result.Signature, digests);
            _prevChainDigest = artifact.ChainDigest
                ?? throw new SigillException("The seal returned no classical signature to chain to.");
            _prevEvidenceId = artifact.EvidenceId;
            _coverage = coverage;
            lock (_artifacts)
            {
                _artifacts.Add(artifact);
                if (stepType == "run_end") _finished = true; // committed with the append, before any caller code runs
                if (_options.RetainPayloads)
                    foreach (var o in objects) _payloads[o.Uri] = o.Bytes;
            }
            return artifact;
        }
        catch (Exception)
        {
            _broken = true;
            throw;
        }
    }

    /// <summary>
    /// Runs the callback outside the gate, so it may call back into the run.
    /// The artifact is already part of the chain; a failing callback is the
    /// caller's error and does not break the run.
    /// </summary>
    private async Task NotifyAsync(AgentRunArtifact artifact, CancellationToken ct)
    {
        if (_options.OnArtifactSealed is { } callback)
            await callback(artifact, ct).ConfigureAwait(false);
    }

    // No operation label: a step type can be producer-defined, and only digests,
    // opaque URIs and content types reach the sealing service (spec §6).
    private static async Task<SignHashesResult> SealAsync(
        ISigillAiEvidenceClient client, JsonObject envelope, IReadOnlyList<AgentRunObject> objects, Guid certificateId,
        bool timestamp, bool qualified, CancellationToken ct)
    {
        var digests = objects.Select(o => new SignedObjectDigest
        {
            Uri = o.Uri,
            HashHex = EnvelopeHashing.HashHex(o.Bytes),
            ContentType = o.ContentType,
        }).ToList();
        return await client.SignObjectHashesAsync(
            EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(envelope)),
            digests,
            certificateId,
            new ObjectSignOptions { Timestamp = timestamp, Qualified = qualified && timestamp },
            ct).ConfigureAwait(false);
    }

    private void EnsureOpen()
    {
        if (_broken) throw new InvalidOperationException("The run's chain is broken by an earlier sealing failure; no further steps can be sealed.");
        if (_finished) throw new InvalidOperationException("The run is finished.");
    }

    private static void ValidatePolicy(AgentTimestampPolicy p)
    {
        if (p is null) throw new ArgumentNullException(nameof(p));
        if (p.Profile is not ("throughput" or "per-event"))
            throw new ArgumentException("TimestampPolicy.Profile must be 'throughput' or 'per-event'.");
        if (p.EveryEvents < 0 || p.EverySeconds < 0)
            throw new ArgumentException("TimestampPolicy cadence values must be zero or positive.");
    }

    private static JsonObject ToolBlock(string name, string? operation, string? useId)
    {
        if (string.IsNullOrEmpty(name)) throw new ArgumentException("tool name is required.", nameof(name));
        var block = new JsonObject { ["name"] = name };
        if (useId is not null) block["useId"] = useId;
        if (operation is not null) block["operation"] = operation;
        return block;
    }

    private static AgentRunObject Obj(string kind, string role, byte[] bytes, string contentType) =>
        new() { Kind = kind, Role = role, Bytes = bytes ?? throw new ArgumentNullException(nameof(bytes)), ContentType = contentType };

    private static IReadOnlyDictionary<string, string> Digests(IReadOnlyList<AgentRunObject> objects)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var o in objects)
        {
            if (d.ContainsKey(o.Uri)) throw new ArgumentException($"Duplicate object URI '{o.Uri}'.");
            d[o.Uri] = EnvelopeHashing.HashHex(o.Bytes);
        }
        return d;
    }

    /// <summary>The identity record's payloads, recovered from the definition by kind.</summary>
    private static IEnumerable<KeyValuePair<string, byte[]>> IdentityObjects(AgentDefinition agent, AgentRunArtifact identity)
    {
        if (identity.Envelope["extensions"]?[AgentExecutionProfile.ExtensionKey]?["objectKinds"] is not JsonObject kinds)
            yield break;
        foreach (var kv in kinds)
        {
            byte[]? bytes = AgentExecutionProfile.Str(kv.Value) switch
            {
                "agent-manifest"   => agent.Manifest ?? AgentExecutionProfile.DefaultManifest(agent),
                "instruction-set"  => agent.Configuration.InstructionSet,
                "tool-manifest"    => agent.Configuration.ToolManifest,
                "model-config"     => agent.Configuration.ModelConfig,
                "execution-policy" => agent.Configuration.ExecutionPolicy,
                _ => null, // the registration record's bytes are not reconstructible here
            };
            if (bytes is not null) yield return new KeyValuePair<string, byte[]>(kv.Key, bytes);
        }
    }
}
