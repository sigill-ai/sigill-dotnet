// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sigill.Sdk;

/// <summary>
/// The guard of one run (<c>spec/agent-policy-control-set-v2.md</c> §7): it keeps the run's facts state, evaluates each
/// sealed event's facts request with the engine and decides. <see cref="AgentRun"/> seals what it decides, under the run's
/// gate. It only decides in <c>enforce</c> mode; otherwise it reports matching rules.
/// </summary>
internal sealed class AgentGuard
{
    /// <summary>The core <c>Sigill.Sdk.Policy</c> pins; named in a record only when the engine cannot even report its version.</summary>
    // shortcut: assumes the engine is CedarEngine when its version is unreadable; upgrade when other engines are supported.
    private const string FallbackCoreVersion = "4.14.0";
    private static readonly Regex CoreVersion = new(@"^[0-9]+\.[0-9]+\.[0-9]+\z", RegexOptions.CultureInvariant);

    /// <summary>What the guard decided for one producer event.</summary>
    /// <param name="Kind"><c>denied</c>, <c>halted</c> (a record, then <c>run_end</c>) or <c>observed</c> (rules matched; nothing sealed).</param>
    /// <param name="Reason">The record's reason; null for <c>observed</c>.</param>
    /// <param name="Rules">The record's <c>rules</c>; for <c>observed</c>, the matching rules.</param>
    /// <param name="Tool">The denied call's tool name, when the record names a call.</param>
    /// <param name="UseId">Its <c>useId</c>.</param>
    internal sealed record Decision(string Kind, string? Reason, IReadOnlyList<string> Rules, string? Tool = null, string? UseId = null)
    {
        public bool Seals => Kind != "observed";
        public bool Halts => Kind == "halted";
    }

    private readonly IPolicyEngine _engine;
    private readonly JsonObject _call;
    private readonly AgentPolicy.FactsState _facts;
    private readonly PolicyEnforcement _settings;
    private readonly Dictionary<string, string?> _tools = new(StringComparer.Ordinal); // known Tool → its definitionSha256
    private readonly bool _unavailableAtStart;
    private int _records;

    public AgentEnforcement Options { get; }

    /// <summary>Tests: runs inside <see cref="Decide"/>, after the event is fed to the facts (a fault there must break the run).</summary>
    internal Action<int>? Fault { get; set; }

    /// <summary><c>enforce</c> mode: the guard denies and halts (otherwise it only reports).</summary>
    public bool Enforcing { get; }

    /// <summary><c>enforcer.engine</c> of every record.</summary>
    public string EngineName { get; }

    private AgentGuard(AgentEnforcement options, JsonObject doc, PolicyEnforcement settings, bool enforcing, string version, bool unavailable,
        string agentId, bool isChildRun)
    {
        Options = options;
        _engine = options.Engine;
        _settings = settings;
        Enforcing = enforcing;
        EngineName = "cedar-policy@" + version;
        _unavailableAtStart = unavailable;
        var v2 = doc.ContainsKey("schemaVersion");
        _facts = new AgentPolicy.FactsState(agentId, v2, isChildRun);
        _call = AgentPolicy.AuthorizeCall(doc);
        foreach (var e in (_call["entities"] as JsonArray)!.OfType<JsonObject>().Where(e => AgentProfiles.Str(e["uid"]?["type"]) == "Tool"))
            _tools[AgentProfiles.Str(e["uid"]?["id"])!] = AgentProfiles.Str(e["attrs"]?["definitionSha256"]);
    }

    /// <summary>
    /// The guard of a run with these options, or null when there is none (no engine, or a control set that is not a policy control
    /// set). Runs before anything is sealed: an enforcing control set without an engine and strict-validation problems are caller
    /// errors. In <c>enforce</c> mode an engine that cannot validate or name its version is <c>unavailable</c> (the start is refused,
    /// §7.4); otherwise its failure is raised.
    /// </summary>
    public static AgentGuard? Create(AgentRunOptions options, string agentId, bool isChildRun)
    {
        var content = options.ControlSet.Content;
        var doc = options.ControlSet.ContentType == AgentPolicy.ControlSetContentType ? AgentPolicy.Parse(content, out _) : null;
        var settings = doc is null ? null : AgentPolicy.Enforcement(content); // validated by the recorder already
        var enforcing = settings?.Mode == "enforce";
        if (enforcing && options.Enforcement is null)
            throw new ArgumentException("The control set enforces its policy: pass enforcement with a policy engine.", nameof(options));
        if (options.Enforcement is null || doc is null) return null;

        IReadOnlyList<string>? problems = null;
        string? version = null;
        try
        {
            problems = AgentPolicy.ValidateStrict(content, options.Enforcement.Engine);
            version = options.Enforcement.Engine.Version;
        }
        catch (Exception) when (enforcing) { } // §7.5: whatever the engine throws, it is unavailable
        catch (Exception ex) when (ex is not PolicyEngineException) // observe mode: raised, as the engine's exception type
        {
            throw new PolicyEngineException("The policy engine failed: " + ex.Message, ex);
        }
        if (problems is { Count: > 0 })
            throw new ArgumentException("Invalid policy control set: " + string.Join("; ", problems), nameof(options));
        var usable = version is not null && CoreVersion.IsMatch(version);
        return new AgentGuard(options.Enforcement, doc, settings!, enforcing, usable ? version! : FallbackCoreVersion, !usable, agentId, isChildRun);
    }

    /// <summary>
    /// Feeds one sealed event into the facts and decides on it: null for nothing to report. The guard's own events
    /// (<paramref name="byGuard"/>) and the producer's <c>run_end</c> are not evaluated (§7.1): they only advance the facts.
    /// </summary>
    public Decision? Decide(int seq, JsonObject envelope, IReadOnlyDictionary<string, string> digests, bool byGuard, AgentRunArtifact control)
    {
        var request = _facts.Next(seq, envelope, digests);
        Fault?.Invoke(seq);
        var step = (JsonObject)envelope["step"]!;
        var type = AgentProfiles.Str(step["type"]);
        if (byGuard || type == "run_end") return null; // counted in the facts, never evaluated
        var tool = step["tool"] as JsonObject;
        // The call a denial names (tool_call), and the tool an observation names (tool_call and tool_result).
        var named = type is "tool_call" or "tool_result" ? (Name: AgentProfiles.Str(tool?["name"]), UseId: AgentProfiles.Str(tool?["useId"])) : default;
        var call = type == "tool_call" ? named : default;

        // §7.4: the start gate, in order, before the engine is asked anything.
        if (Enforcing && type == "run_start")
        {
            if (_settings.LockedConfiguration.Any(kv => DigestOf(control, kv.Key) != kv.Value)) return Deny("configuration_locked", null, default, true);
            if (_unavailableAtStart) return Deny("unavailable", null, default, true);
        }
        var answer = Ask(request);
        if (!Enforcing) return answer is null ? null : Observed(answer.Reason, named);
        if (answer is not { } d) return Deny("unavailable", null, call, true); // §7.5
        if (type != "tool_call")
        {
            // §7.3: only a matching halt rule acts on another event.
            var halting = d.Reason.Where(r => Effect(r) == "halt").ToList();
            return halting.Count > 0 ? Deny("rule", halting, default, true) : Observed(d.Reason, named);
        }

        // §7.2: the first reason that applies.
        var blockingErrors = d.Errors.Where(r => Effect(r) != "observe").ToList();
        var blocking = d.Reason.Where(r => Effect(r) != "observe").ToList();
        var known = call.Name is not null && _tools.ContainsKey(call.Name);
        var (reason, rules) =
            !known && _settings.UnknownTools == "deny" ? ("unknown_tool", (List<string>?)null)
            : known && _tools[call.Name!] is { } definition && DefinitionOf(envelope, digests) != definition ? ("tool_changed", null)
            : blockingErrors.Count > 0 && _settings.OnRuleError == "deny" ? ("rule_error", blockingErrors)
            : blocking.Count > 0 ? ("rule", blocking)
            : ((string?)null, null);
        if (reason is null) return Observed(d.Reason, call);
        // A matching halt rule always halts, whatever reason won the record; so does the denial that reaches haltAfterDenials.
        var halt = d.Reason.Any(r => Effect(r) == "halt")
            || (_settings.HaltAfterDenials > 0 && _records + 1 == _settings.HaltAfterDenials);
        return Deny(reason, rules, call, halt);
    }

    private sealed record Diagnostics(IReadOnlyList<string> Reason, IReadOnlyList<string> Errors);

    private Decision Deny(string reason, List<string>? rules, (string? Name, string? UseId) call, bool halt)
    {
        _records++;
        return new Decision(halt ? "halted" : "denied", reason, (IReadOnlyList<string>?)rules ?? Array.Empty<string>(), call.Name, call.UseId);
    }

    private static Decision? Observed(IReadOnlyList<string> reason, (string? Name, string? UseId) call = default) =>
        reason.Count > 0 ? new Decision("observed", null, reason, call.Name, call.UseId) : null;

    private string Effect(string rule) => _settings.RuleEffects.TryGetValue(rule, out var e) ? e : "observe";

    /// <summary>Cedar's matching and erroring rules for one request (sorted, unique, without the baseline permit), or null when the engine failed.</summary>
    private Diagnostics? Ask(JsonObject request)
    {
        foreach (var member in new[] { "principal", "action", "resource", "context" }) _call[member] = request[member]!.DeepClone();
        try
        {
            // A refusal (type failure) or an answer that is not an isAuthorized answer is a failure too.
            // The engine gets its own copy: one that changes its input cannot change a later decision.
            if (!AgentPolicy.TryDiagnostics(_engine.Authorize((JsonObject)_call.DeepClone()), _call, out var reason, out var errors)) return null;
            return new Diagnostics(reason.Distinct().ToList(), errors.Distinct().ToList());
        }
        catch (Exception) { return null; } // §7.5: the engine raised or trapped
    }

    /// <summary>The digest of the Control Artifact's object of <paramref name="role"/>; null when it has none.</summary>
    private static string? DigestOf(AgentRunArtifact control, string role) =>
        (control.Envelope["objects"] as JsonArray)?.OfType<JsonObject>().Where(o => AgentProfiles.Str(o["role"]) == role)
            .Select(o => control.ObjectDigests.TryGetValue(AgentProfiles.Str(o["uri"]) ?? "", out var hex) ? hex : null).FirstOrDefault();

    /// <summary>The signed digest of the call's one <c>tool-definition</c> object; null unless there is exactly one.</summary>
    private static string? DefinitionOf(JsonObject envelope, IReadOnlyDictionary<string, string> digests)
    {
        var defs = (envelope["objects"] as JsonArray)?.OfType<JsonObject>().Where(o => AgentProfiles.Str(o["role"]) == "tool-definition").ToList();
        return defs is { Count: 1 } && digests.TryGetValue(AgentProfiles.Str(defs[0]["uri"]) ?? "", out var hex) ? hex : null;
    }
}
