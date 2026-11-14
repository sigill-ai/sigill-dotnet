// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

namespace Sigill.Sdk;

public static partial class AgentPolicy
{
    private static readonly HashSet<string> InconsistentChain = new(StringComparer.Ordinal)
    {
        "executed_after_denial", "misplaced_decision", "unrecorded_halt", "duplicate_use_id", "continued_after_halt",
    };

    // ControlEvaluation v3 §5.5, the closed list in the order of its table; true = class "let through".
    private static readonly (string Code, bool LetThrough)[] ComparisonFindings =
    {
        ("refusal_missing", true), ("unknown_tool_allowed", true), ("configuration_not_enforced", true), ("halt_missing", true),
        ("unfounded_record", false), ("unfounded_halt", false), ("reason_mismatch", false), ("rules_mismatch", false),
    };

    /// <summary>
    /// The enforcement comparison of a run under a v2 policy control set (<c>spec/control-evaluation-v3.md</c> §4–§6): for each
    /// event of the evaluated prefix, what the control set required the guard to do against what the chain records. Returns the
    /// <c>policy.enforcement</c> member of a ControlEvaluation v3, exactly as specified (canonicalise it for bytes).
    /// <para>
    /// It reads what an evidence index holds and nothing more: the Control Artifact and the events, each with the object
    /// digests its signature confirms (pass only confirmed digests), and the control-set document — never a payload. The
    /// events may come in any order; the comparison takes the contiguous prefix from seq 0.
    /// </para>
    /// <para>
    /// <paramref name="engine"/> is the evaluator's own core. When the prefix's enforcement records name one core and it is not
    /// this one, or name two, the comparison is <c>not_performed</c> and the engine is not asked anything; so is it for a chain
    /// that contradicts its own records (§5.1). Otherwise every request of the prefix is evaluated with it.
    /// </para>
    /// </summary>
    /// <param name="controlArtifact">The run's Control Artifact: its envelope and signed object digests.</param>
    /// <param name="events">The run's events (at least the evaluated prefix), each with its signed object digests.</param>
    /// <param name="controlSetDocument">The run's v2 policy control set, exactly the bytes the Control Artifact seals.</param>
    /// <param name="engine">The evaluator's Cedar core.</param>
    /// <exception cref="ArgumentException">The control set is not a valid v2 policy control set, is not the one the Control Artifact seals, the Control
    /// Artifact does not carry exactly one control-set object, carries a lockable role twice or names no agent or correlationId, the events are not a chain, or an enforcement record
    /// names no <c>enforcer.engine</c>.</exception>
    /// <exception cref="PolicyEngineException">The engine failed or refused a request: there is no comparison of this prefix.</exception>
    public static JsonObject CompareEnforcement(AgentRunArtifact controlArtifact, IEnumerable<AgentRunArtifact> events, byte[] controlSetDocument,
        IPolicyEngine engine)
    {
        if (controlArtifact is null) throw new ArgumentNullException(nameof(controlArtifact));
        if (events is null) throw new ArgumentNullException(nameof(events));
        if (engine is null) throw new ArgumentNullException(nameof(engine));
        var problems = Validate(controlSetDocument);
        if (problems.Count > 0) throw new ArgumentException("Invalid policy control set: " + string.Join("; ", problems), nameof(controlSetDocument));
        var doc = Parse(controlSetDocument)!;
        if (AgentProfiles.Str(doc["schemaVersion"]) != "2")
            throw new ArgumentException("The enforcement comparison needs a v2 policy control set (schemaVersion \"2\").", nameof(controlSetDocument));
        var sealedSets = (controlArtifact.Envelope["objects"] as JsonArray)?.OfType<JsonObject>().Where(o => AgentProfiles.Str(o["role"]) == "control-set").ToList()
            ?? new List<JsonObject>();
        if (sealedSets.Count != 1)
            throw new ArgumentException("The Control Artifact must carry exactly one control-set object.", nameof(controlArtifact));
        if (!controlArtifact.ObjectDigests.TryGetValue(AgentProfiles.Str(sealedSets[0]["uri"]) ?? "", out var sealedHex)
            || sealedHex != EnvelopeHashing.HashHex(controlSetDocument))
            throw new ArgumentException("The control set is not the one the Control Artifact seals.", nameof(controlSetDocument));
        var agentId = AgentProfiles.Str(controlArtifact.Envelope["agent"]?["id"]);
        var correlationId = AgentProfiles.Str(controlArtifact.Envelope["activity"]?["correlationId"]);
        if (agentId is null || correlationId is null)
            throw new ArgumentException("The Control Artifact names no agent or correlationId.", nameof(controlArtifact));

        // The contiguous prefix from seq 0 (ControlEvaluation v2 §4.2).
        var bySeq = new SortedDictionary<int, AgentRunArtifact>();
        foreach (var a in events)
        {
            var seq = AgentProfiles.Int(a.Envelope["chain"]?["seq"]) ?? throw new ArgumentException("an event has no chain.seq", nameof(events));
            if (bySeq.ContainsKey(seq)) throw new ArgumentException($"two events claim seq {seq}", nameof(events));
            bySeq.Add(seq, a);
        }
        var prefix = new List<AgentRunArtifact>();
        while (bySeq.TryGetValue(prefix.Count, out var next)) prefix.Add(next);
        static JsonObject StepOf(AgentRunArtifact a) => a.Envelope["step"] as JsonObject ?? new JsonObject();
        static string? TypeOf(AgentRunArtifact a) => AgentProfiles.Str(StepOf(a)["type"]);
        var envelopes = prefix.Select(a => a.Envelope).ToList();
        if (ComparisonInputProblem(controlArtifact.Envelope, envelopes) is { } input) throw new ArgumentException(input, nameof(events));

        var result = new JsonObject();
        var (inconsistent, engines) = ComparisonPreconditions(envelopes);
        if (engines.Count == 1) result["recordedEngine"] = engines[0];
        string? notPerformed = inconsistent ? "chain_inconsistent"
            : engines.Count > 1 ? "engine_inconsistent"
            : engines.Count == 1 && engines[0] != "cedar-policy@" + Surfaced(() => engine.Version) ? "engine_unavailable"
            : null;
        // A performed comparison names the evaluator's own core, so its version is read even when no record names one.
        if (notPerformed is null) Surfaced(() => engine.Version);
        if (notPerformed is not null)
        {
            result["comparison"] = "not_performed";
            result["notPerformed"] = notPerformed;
            return Ordered(result);
        }

        var settings = Enforcement(controlSetDocument);
        var call = AuthorizeCall(doc);
        var tools = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var e in (call["entities"] as JsonArray)!.OfType<JsonObject>().Where(e => AgentProfiles.Str(e["uid"]?["type"]) == "Tool"))
            tools[AgentProfiles.Str(e["uid"]?["id"])!] = AgentProfiles.Str(e["attrs"]?["definitionSha256"]);
        // The facts of the prefix: one request per event and, when it holds run_end, the run-level request.
        var requests = (JsonNode.Parse(BuildFactsV2(agentId, correlationId, prefix, controlSetDocument).Bytes)!["requests"] as JsonArray)!
            .OfType<JsonObject>().ToList();
        // §4: every request is evaluated, also without rules (the baseline permit alone); a refusal ends the comparison.
        var diagnostics = requests.Select((request, i) =>
        {
            foreach (var member in new[] { "principal", "action", "resource", "context" }) call[member] = request[member]!.DeepClone();
            var answer = Surfaced(() => engine.Authorize((JsonObject)call.DeepClone()));
            var seq = AgentProfiles.Str(request["seq"]) ?? i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            if (AgentProfiles.Str(answer?["type"]) == "failure")
                throw new PolicyEngineException($"The policy engine refused request {seq}: {FailureMessages(answer!)}", refused: true);
            if (!TryDiagnostics(answer, call, out var reason, out var errors))
                throw new PolicyEngineException("The policy engine's answer is not an isAuthorized answer.");
            return (Reason: reason, Errors: errors);
        }).ToList();

        var decisions = new JsonArray();
        var outcomes = new List<string>();
        for (var s = 0; s < prefix.Count; s++)
        {
            var e = prefix[s];
            var type = TypeOf(e);
            var request = requests[s];
            var (reason, errors) = diagnostics[s];

            // §5.2: what was due.
            string due = "none";
            string? dueReason = null;
            IReadOnlyList<string> dueRules = Array.Empty<string>();
            if (!IsEnforcementRecord(e.Envelope) && type != "run_end" && settings.Mode == "enforce")
            {
                if (type == "run_start" && EnforcementRule.ConfigurationLocked(settings, controlArtifact))
                    (due, dueReason) = ("halted", "configuration_locked");
                else
                {
                    var denials = AgentProfiles.Int(request["context"]?["denialsSoFar"]) ?? 0;
                    var toolName = type == "tool_call" ? AgentProfiles.Str((StepOf(e)["tool"] as JsonObject)?["name"]) : null;
                    if (EnforcementRule.Due(type, reason.Distinct().ToList(), errors.Distinct().ToList(), settings, tools, toolName,
                            AgentGuard.DefinitionOf(e.Envelope, e.ObjectDigests), denials, countAtLeast: true) is { } d)
                        (due, dueReason, dueRules) = (d.Halts ? "halted" : "refused", d.Reason, d.Rules);
                }
            }

            // §5.3, §5.4: what is recorded, read by position; an open event asserts nothing.
            var recorded = RecordedOutcome(envelopes, s, out var open);
            if (due == "none" && recorded is null or "none") continue; // not listed
            var record = recorded is "refused" or "halted" ? StepOf(prefix[s + 1]) : null;
            var recordedReason = AgentProfiles.Str(record?["enforcer"]?["reason"]);
            var recordedRules = new HashSet<string>((record?["rules"] as JsonArray ?? new JsonArray()).Select(AgentProfiles.Str).OfType<string>(), StringComparer.Ordinal);

            // §5.5: outcome and findings.
            var findings = new List<string>();
            if (recorded is not null)
            {
                var call_ = type == "tool_call";
                void Find(string code, bool applies) { if (applies) findings.Add(code); }
                Find("refusal_missing", call_ && due != "none" && dueReason != "unknown_tool" && recorded == "none");
                Find("unknown_tool_allowed", call_ && dueReason == "unknown_tool" && recorded == "none");
                Find("configuration_not_enforced", dueReason == "configuration_locked" && recorded != "halted");
                Find("halt_missing", due == "halted" && dueReason != "configuration_locked" && recorded != "halted");
                Find("unfounded_record", due == "none" && recorded != "none");
                Find("unfounded_halt", due == "refused" && recorded == "halted");
                Find("reason_mismatch", due != "none" && recorded != "none" && recordedReason != dueReason);
                Find("rules_mismatch", due != "none" && recorded != "none" && recordedReason == dueReason && !recordedRules.SetEquals(dueRules));
            }
            var letThrough = findings.Any(f => ComparisonFindings.Single(x => x.Code == f).LetThrough);
            var outcome = open ? "pending"
                : recordedReason == "unavailable" && dueReason != "configuration_locked" ? "not_checkable"
                : letThrough ? "let_through"
                : findings.Count > 0 ? "over_enforced"
                : "as_required";
            outcomes.Add(outcome);

            var decision = new JsonObject { ["seq"] = s, ["due"] = due };
            if (dueReason is not null) decision["dueReason"] = dueReason;
            if (dueReason is "rule" or "rule_error") decision["dueRules"] = new JsonArray(dueRules.Select(r => (JsonNode?)r).ToArray());
            if (recorded is not null) decision["recorded"] = recorded;
            decision["outcome"] = outcome;
            if (outcome is "let_through" or "over_enforced") decision["findings"] = new JsonArray(findings.Select(f => (JsonNode?)f).ToArray());
            decisions.Add(decision);
        }
        result["comparison"] = "performed";
        result["decisions"] = decisions;
        result["result"] = new[] { "let_through", "over_enforced", "not_checkable", "pending" }.FirstOrDefault(outcomes.Contains) ?? "as_required";
        return Ordered(result);
    }

    /// <summary>
    /// What makes a run one the comparison cannot read, checked without a core: a Control Artifact without exactly one
    /// control-set object, without agent or correlationId, or with a lockable role twice (which digest is locked would be a
    /// guess), or an enforcement record that names no core.
    /// </summary>
    internal static string? ComparisonInputProblem(JsonObject controlEnvelope, IReadOnlyList<JsonObject> prefix)
    {
        var objects = (controlEnvelope["objects"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().ToList();
        if (objects.Count(o => AgentProfiles.Str(o["role"]) == "control-set") != 1) return "The Control Artifact must carry exactly one control-set object.";
        if (AgentProfiles.Str(controlEnvelope["agent"]?["id"]) is null || AgentProfiles.Str(controlEnvelope["activity"]?["correlationId"]) is null)
            return "The Control Artifact names no agent or correlationId.";
        foreach (var role in LockableRoles.OrderBy(r => r, StringComparer.Ordinal))
            if (objects.Count(o => AgentProfiles.Str(o["role"]) == role) > 1) return $"The Control Artifact carries more than one {role} object.";
        return prefix.FirstOrDefault(e => IsEnforcementRecord(e) && AgentProfiles.Str(e["step"]?["enforcer"]?["engine"]) is null) is { } bare
            ? $"the enforcement record at seq {AgentProfiles.Int(bare["chain"]?["seq"])} has no enforcer.engine" : null;
    }

    /// <summary>Whatever the engine throws is the <see cref="PolicyEngineException"/> the comparison promises.</summary>
    private static T Surfaced<T>(Func<T> f)
    {
        try { return f(); }
        catch (PolicyEngineException) { throw; }
        catch (Exception ex) { throw new PolicyEngineException($"The policy engine failed: {ex.Message}", ex); }
    }

    /// <summary>The prefix holds <c>run_end</c>: no event of it is open (§5.4).</summary>
    internal static bool Ended(IReadOnlyList<JsonObject> prefix) => prefix.Any(e => AgentProfiles.Str(e["step"]?["type"]) == "run_end");

    /// <summary>
    /// §5.1 and §4 on the events of a prefix (seq 0…T, in order): whether the chain contradicts its own records, and the distinct
    /// cores its enforcement records name. A record at T of a prefix without <c>run_end</c> is not <c>continued_after_halt</c>:
    /// its next event is unknown, not absent.
    /// </summary>
    internal static (bool Inconsistent, List<string> Engines) ComparisonPreconditions(IReadOnlyList<JsonObject> prefix)
    {
        var ended = Ended(prefix);
        var through = prefix.Count - 1;
        // evidence_version_mismatch: the comparison only runs under a v2 control set, so any event that is not v4 is one (§5.1).
        var inconsistent = prefix.Any(e => AgentProfiles.Str(e["schemaVersion"]) != "4")
            || AgentRunVerifier.EnforcementFindings(prefix, null, null)
                .Any(f => InconsistentChain.Contains(f.Code) && !(f.Code == "continued_after_halt" && !ended && f.Seqs.SequenceEqual(new[] { through })));
        var engines = prefix.Where(IsEnforcementRecord)
            .Select(e => AgentProfiles.Str(e["step"]?["enforcer"]?["engine"]) ?? "").Distinct(StringComparer.Ordinal).ToList();
        return (inconsistent, engines);
    }

    /// <summary>
    /// §5.3, §5.4: the recorded outcome of the event at <paramref name="s"/>, read by position — <c>halted</c>, <c>refused</c> or
    /// <c>none</c>; null when it is unknown (the open event at T). <paramref name="open"/>: the event is open.
    /// </summary>
    internal static string? RecordedOutcome(IReadOnlyList<JsonObject> prefix, int s, out bool open)
    {
        var through = prefix.Count - 1;
        var ended = Ended(prefix);
        bool RecordAt(int at) => at >= 0 && at < prefix.Count && IsEnforcementRecord(prefix[at]);
        bool HaltAt(int at) => at < prefix.Count && AgentProfiles.Str(prefix[at]["step"]?["type"]) == "run_end"
            && AgentProfiles.Str(prefix[at]["step"]?["runDisposition"]) == "halted";
        var openAtEnd = !ended && s == through;
        open = openAtEnd || (!ended && s == through - 1 && RecordAt(through));
        if (openAtEnd) return null;
        if (open) return "refused"; // the record is there; whether a halt follows is not known
        return RecordAt(s + 1) ? (HaltAt(s + 2) ? "halted" : "refused") : "none";
    }

    /// <summary>Whether a finding is of class "let through" (§5.5); null for a code outside the closed list.</summary>
    internal static bool? IsLetThrough(string code) => ComparisonFindings.Any(x => x.Code == code) ? ComparisonFindings.Single(x => x.Code == code).LetThrough : null;

    /// <summary>The position of a finding in §5.5's table; -1 outside it.</summary>
    internal static int FindingOrder(string code) => Array.FindIndex(ComparisonFindings, x => x.Code == code);

    /// <summary>The member in the order of §6's table (JCS sorts anyway; this is for readers).</summary>
    private static JsonObject Ordered(JsonObject m)
    {
        var o = new JsonObject();
        foreach (var key in new[] { "comparison", "notPerformed", "recordedEngine", "decisions", "result" })
            if (m.TryGetPropertyValue(key, out var v)) { m.Remove(key); o[key] = v; }
        return o;
    }
}
