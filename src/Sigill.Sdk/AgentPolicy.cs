// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sigill.Sdk;

/// <summary>The two identities of a policy control set (<c>spec/agent-policy-control-set-v1.md</c> §3).</summary>
/// <param name="ApprovalScopeDigest">SHA-256 of JCS(document without <c>id</c> and <c>version</c>): what an owner approves.</param>
/// <param name="CedarDigest">SHA-256 of JCS(<c>cedar</c>), or null without Cedar rules: the rules alone.</param>
public sealed record PolicyDigests(string ApprovalScopeDigest, string? CedarDigest);

/// <summary>A run's facts document (<c>spec/control-evaluation-v2.md</c> §4.5).</summary>
/// <param name="Bytes">The exact JCS bytes: the <c>evaluation-facts</c> object of a policy evaluation.</param>
/// <param name="Sha256">Lowercase hex SHA-256 of <paramref name="Bytes"/>.</param>
/// <param name="ThroughSeq">Last seq of the contiguous prefix that was evaluated (−1 without seq 0).</param>
/// <param name="MissingSeqs">Seqs missing below the highest received one.</param>
/// <param name="RunLevel">Whether the run-level request is present (run_end in, nothing missing).</param>
public sealed record PolicyFacts(byte[] Bytes, string Sha256, int ThroughSeq, IReadOnlyList<int> MissingSeqs, bool RunLevel);

/// <summary>
/// Declared agent policies (<c>spec/agent-policy-control-set-v1.md</c>): a control-set document with the
/// content type <see cref="ControlSetContentType"/> that carries forbid-only Cedar rules, private controls
/// and a coverage contract. Keep the approved document as a file and pass the same bytes to every run.
/// </summary>
public static class AgentPolicy
{
    public const string ControlSetContentType = "application/vnd.sigill.control-set+json";

    private static readonly HashSet<string> Members = ["id", "version", "controls", "cedar", "privateControls", "coverage"];
    private static readonly Regex RuleId = new("^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant);
    // I-JSON also covers §4 rule 4: integers beyond ±2^53-1 are refused anywhere in the document.
    private const string NotIJson = "the document is not an I-JSON object (no repeated names, integers within ±2^53-1)";
    private static readonly Regex Hex64 = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

    /// <summary>
    /// The control set for <see cref="AgentRunOptions.ControlSet"/>: the document's bytes unchanged, its
    /// <c>id</c> and <c>version</c>, and the policy content type. Throws <see cref="ArgumentException"/>
    /// listing every problem when the document is not a valid policy control set.
    /// </summary>
    public static AgentControlSet ControlSetFromDocument(byte[] document)
    {
        var errors = Validate(document);
        if (errors.Count > 0) throw new ArgumentException("Invalid policy control set: " + string.Join("; ", errors), nameof(document));
        var doc = (JsonObject)JsonNode.Parse(document)!;
        return new AgentControlSet
        {
            Id = doc["id"]!.GetValue<string>(), Version = doc["version"]!.GetValue<string>(),
            Content = document, ContentType = ControlSetContentType,
        };
    }

    /// <summary>
    /// The document's <see cref="PolicyDigests"/>. Digests are defined for valid policy control sets only, so this
    /// throws <see cref="ArgumentException"/> listing the problems when <see cref="Validate"/> finds any.
    /// </summary>
    public static PolicyDigests ComputeDigests(byte[] document)
    {
        var errors = Validate(document);
        if (errors.Count > 0) throw new ArgumentException("Invalid policy control set: " + string.Join("; ", errors), nameof(document));
        var doc = Parse(document)!;
        var scope = (JsonObject)doc.DeepClone();
        scope.Remove("id");
        scope.Remove("version");
        return new PolicyDigests(
            EnvelopeHashing.HashHex(AgentProfiles.Canonical(scope)),
            doc["cedar"] is JsonObject cedar ? EnvelopeHashing.HashHex(AgentProfiles.Canonical(cedar)) : null);
    }

    /// <summary>
    /// Structural checks of §2 and §4 rules 1–4 (rule 4 through I-JSON). Strict validation against the Cedar schema (rule 5) needs a
    /// Cedar engine and is not done here. An empty list means valid.
    /// </summary>
    public static IReadOnlyList<string> Validate(byte[] document)
    {
        var errors = new List<string>();
        if (document is null) { errors.Add("document is required"); return errors; }
        var doc = Parse(document);
        if (doc is null) { errors.Add(NotIJson); return errors; }
        foreach (var key in doc.Select(kv => kv.Key).Where(k => !Members.Contains(k))) errors.Add($"unknown member '{key}'");
        if (!IsNonEmptyString(doc["id"])) errors.Add("id must be a non-empty string");
        if (!IsNonEmptyString(doc["version"])) errors.Add("version must be a non-empty string");
        if (doc["controls"] is not JsonArray controls) errors.Add("controls must be an array");
        else if (controls.Any(c => !IsNonEmptyString(c) && !(c is JsonObject o && IsNonEmptyString(o["id"]))))
            errors.Add("each control is a string or an object with a string id");

        if (doc.TryGetPropertyValue("privateControls", out var pc))
        {
            if (pc is not JsonArray arr || arr.Any(p => p is not JsonObject o || !IsNonEmptyString(o["id"])))
                errors.Add("privateControls must be an array of objects with a string id");
            else if (arr.Select(p => p!["id"]!.GetValue<string>()).GroupBy(x => x).Any(g => g.Count() > 1))
                errors.Add("privateControls ids must be unique");
        }

        if (doc.TryGetPropertyValue("coverage", out var cov))
        {
            if (cov is not JsonObject c) errors.Add("coverage must be an object");
            else
            {
                if (!IsNonEmptyString(c["sourceProfile"])) errors.Add("coverage.sourceProfile must be a non-empty string");
                if (!IsNonEmptyString(c["scope"])) errors.Add("coverage.scope must be a non-empty string");
                if (c["idleSeconds"] is not JsonValue v || !v.TryGetValue<long>(out var idle) || idle < 0)
                    errors.Add("coverage.idleSeconds must be an integer >= 0");
            }
        }

        if (doc.TryGetPropertyValue("cedar", out var cedarNode)) ValidateCedar(cedarNode, errors);
        return errors;
    }

    private static void ValidateCedar(JsonNode? cedarNode, List<string> errors)
    {
        if (cedarNode is not JsonObject cedar) { errors.Add("cedar must be an object"); return; }
        if (cedar["schemaSha256"] is not JsonValue sv || !sv.TryGetValue<string>(out var sha) || !Hex64.IsMatch(sha))
            errors.Add("cedar.schemaSha256 must be a lowercase hex SHA-256");
        if (cedar["policies"] is not JsonObject set) { errors.Add("cedar.policies must be a Cedar JSON policy set"); return; }
        if (set["templates"] is JsonObject t && t.Count > 0) errors.Add("cedar.policies must not contain templates");
        if (set["templateLinks"] is JsonArray l && l.Count > 0) errors.Add("cedar.policies must not contain template links");
        if (set["staticPolicies"] is not JsonObject policies || policies.Count == 0)
        {
            errors.Add("cedar.policies.staticPolicies must hold at least one policy");
            return;
        }
        foreach (var (key, node) in policies)
        {
            if (node is not JsonObject p) { errors.Add($"policy '{key}' is not an object"); continue; }
            if (!RuleId.IsMatch(key)) errors.Add($"policy id '{key}' must be 1-64 characters of A-Z a-z 0-9 . _ -");
            if (!IsNonEmptyString(p["effect"]) || p["effect"]!.GetValue<string>() != "forbid")
                errors.Add($"policy '{key}' must be forbid (step 1 is tripwire mode)");
            var annotated = p["annotations"] is JsonObject annotations ? annotations["id"] : null;
            if (!IsNonEmptyString(annotated) || annotated!.GetValue<string>() != key)
                errors.Add($"policy '{key}' must carry @id(\"{key}\")");
        }
    }

    /// <summary>The facts version this SDK builds (<c>spec/agent-policy-control-set-v1.md</c> §5).</summary>
    public const string FactsVersion = "1";

    /// <summary>
    /// The facts a run is evaluated on (<c>spec/agent-policy-control-set-v1.md</c> §5, factsVersion 1), as the
    /// facts document of <c>spec/control-evaluation-v2.md</c> §4.5: one Cedar request per event of the contiguous
    /// prefix seq 0…k, plus the run-level request when <c>run_end</c> is in and nothing is missing.
    /// </summary>
    /// <param name="agentId">The Control Artifact's signed <c>agent.id</c>.</param>
    /// <param name="correlationId">The run's <c>activity.correlationId</c>.</param>
    /// <param name="events">The run's Agent Execution Evidence envelopes, any order. Only typed fields are read.</param>
    /// <exception cref="ArgumentException">An event has no seq, or two claim the same one (the chain is not valid).</exception>
    public static PolicyFacts BuildFacts(string agentId, string correlationId, IEnumerable<JsonObject> events)
    {
        var bySeq = new SortedDictionary<int, JsonObject>();
        foreach (var e in events)
        {
            var seq = AgentProfiles.Int(e["chain"]?["seq"]) ?? throw new ArgumentException("an event has no chain.seq", nameof(events));
            if (bySeq.ContainsKey(seq)) throw new ArgumentException($"two events claim seq {seq}", nameof(events));
            bySeq.Add(seq, e);
        }
        var maxSeq = bySeq.Count == 0 ? -1 : bySeq.Keys.Max();
        var missing = new List<int>();
        for (var s = 0; s <= maxSeq; s++) if (!bySeq.ContainsKey(s)) missing.Add(s);
        var throughSeq = missing.Count > 0 ? missing[0] - 1 : maxSeq;
        var prefix = bySeq.Where(kv => kv.Key <= throughSeq).Select(kv => (Seq: kv.Key, Env: kv.Value)).ToList();

        static JsonObject? Step(JsonObject e) => e["step"] as JsonObject;
        static string StepType(JsonObject e) => AgentProfiles.Str(Step(e)?["type"]) ?? "";
        static bool Consequential(JsonObject e) => Step(e)?["consequential"] is JsonValue v && v.GetValueKind() == JsonValueKind.True;
        static string? Tool(JsonObject e, string field) => AgentProfiles.Str(Step(e)?["tool"]?[field]);
        JsonObject Principal() => new() { ["type"] = "Agent", ["id"] = agentId };

        var isChildRun = bySeq.TryGetValue(0, out var first) && StepType(first) == "run_start"
            && AgentProfiles.Str(first["binds"]?["parentCorrelationId"]) is { Length: > 0 };
        var requests = new JsonArray();
        var consequentialCount = 0;
        var sawApproval = false;
        foreach (var (seq, e) in prefix)
        {
            var type = StepType(e);
            var consequential = Consequential(e);
            if (consequential) consequentialCount++;
            requests.Add(new JsonObject
            {
                ["seq"] = seq,
                ["principal"] = Principal(),
                ["action"] = new JsonObject { ["type"] = "Action", ["id"] = type },
                ["resource"] = type is "tool_call" or "tool_result"
                    ? new JsonObject { ["type"] = "Tool", ["id"] = Tool(e, "name") ?? "" }
                    : new JsonObject { ["type"] = "Step", ["id"] = seq.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                ["context"] = Context(consequential, Tool(e, "operation") ?? "", seq, sawApproval ? "unbound" : "none",
                    isChildRun, 0, consequentialCount, 0),
            });
            if (type == "human_approval") sawApproval = true;
        }

        var runEnd = prefix.FirstOrDefault(x => StepType(x.Env) == "run_end");
        var runLevel = runEnd.Env is not null && missing.Count == 0;
        if (runLevel)
        {
            var finalSeq = AgentProfiles.Int(Step(runEnd.Env!)?["finalSeq"]) ?? runEnd.Seq;
            var calls = prefix.Where(x => StepType(x.Env) == "tool_call").ToList();
            var uses = calls.Select(c => Tool(c.Env, "useId")).OfType<string>().GroupBy(u => u).ToDictionary(g => g.Key, g => g.Count());
            // §5: a call without useId, or whose useId another call also uses, counts as unpaired.
            var unpaired = calls.Count(c =>
            {
                var u = Tool(c.Env, "useId");
                var paired = u is not null && uses[u] == 1
                    && prefix.Any(x => StepType(x.Env) == "tool_result" && x.Seq > c.Seq && Tool(x.Env, "useId") == u);
                return !paired && Consequential(c.Env);
            });
            requests.Add(new JsonObject
            {
                ["seq"] = "run",
                ["principal"] = Principal(),
                ["action"] = new JsonObject { ["type"] = "Action", ["id"] = "run" },
                ["resource"] = new JsonObject { ["type"] = "Run", ["id"] = correlationId },
                ["context"] = Context(false, "", finalSeq, "none", isChildRun, finalSeq, consequentialCount, unpaired),
            });
        }

        var document = new JsonObject
        {
            ["factsVersion"] = FactsVersion,
            ["throughSeq"] = throughSeq,
            ["missingSeqs"] = new JsonArray(missing.Select(m => (JsonNode?)m).ToArray()),
            ["runLevel"] = runLevel,
            ["requests"] = requests,
        };
        var bytes = AgentProfiles.Canonical(document);
        return new PolicyFacts(bytes, EnvelopeHashing.HashHex(bytes), throughSeq, missing, runLevel);
    }

    private static JsonObject Context(bool consequential, string operation, int stepsSoFar, string approval, bool isChildRun,
        int totalSteps, int consequentialCount, int unpairedConsequential) => new()
    {
        ["consequential"] = consequential,
        ["operation"] = operation,
        ["stepsSoFar"] = stepsSoFar,
        ["approval"] = approval,
        ["isChildRun"] = isChildRun,
        ["totalSteps"] = totalSteps,
        ["consequentialCount"] = consequentialCount,
        ["unpairedConsequential"] = unpairedConsequential,
    };

    private static bool IsNonEmptyString(JsonNode? n) =>
        n is JsonValue v && v.GetValueKind() == JsonValueKind.String && v.GetValue<string>().Length > 0;

    private static JsonObject? Parse(byte[] document)
    {
        // I-JSON (§2): no repeated names, which JsonNode would only notice lazily — check with JsonDocument first.
        try
        {
            using (var d = JsonDocument.Parse(document))
                if (AgentProfiles.FindDuplicateName(d.RootElement) is not null) return null;
            if (JsonNode.Parse(document) is not JsonObject o || !AgentProfiles.IsIJson(o)) return null;
            AgentProfiles.Canonical(o); // a number JCS cannot serialize (e.g. 1e999) is not usable either
            return o;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException or SigillCanonicalizationException) { return null; }
    }
}
