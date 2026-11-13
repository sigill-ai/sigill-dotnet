// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sigill.Sdk.Internal;

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
/// The effective enforcement settings of a policy control set, defaults applied (<c>spec/agent-policy-control-set-v2.md</c>
/// §4 rule 7, §6). A document without <c>enforcement</c> (every v1 document) is <c>observe</c>.
/// </summary>
public sealed class PolicyEnforcement
{
    /// <summary><c>observe</c> (the guard never denies or halts) or <c>enforce</c>.</summary>
    public string Mode { get; init; } = "observe";

    /// <summary><c>deny</c> or <c>halt</c>: the effect of a rule without an <c>effect</c> annotation.</summary>
    public string DefaultEffect { get; init; } = "deny";

    /// <summary>Control Artifact role → the SHA-256 its object must have.</summary>
    public IReadOnlyDictionary<string, string> LockedConfiguration { get; init; } = new Dictionary<string, string>();

    /// <summary><c>deny</c> or <c>allow</c>: a <c>tool_call</c> of a tool the entities do not declare.</summary>
    public string UnknownTools { get; init; } = "allow";

    /// <summary><c>deny</c> or <c>allow</c>: a <c>deny</c> or <c>halt</c> rule that errors on a <c>tool_call</c>.</summary>
    public string OnRuleError { get; init; } = "deny";

    /// <summary>Halt at the denial that brings the run's enforcement records to this number; 0 never.</summary>
    public long HaltAfterDenials { get; init; }

    /// <summary>Rule id → effective effect (<c>observe</c>, <c>deny</c> or <c>halt</c>); every rule is <c>observe</c> unless the mode is <c>enforce</c>.</summary>
    public IReadOnlyDictionary<string, string> RuleEffects { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Declared agent policies (<c>spec/agent-policy-control-set-v1.md</c>): a control-set document with the
/// content type <see cref="ControlSetContentType"/> that carries forbid-only Cedar rules, private controls
/// and a coverage contract. Keep the approved document as a file and pass the same bytes to every run.
/// </summary>
public static class AgentPolicy
{
    public const string ControlSetContentType = "application/vnd.sigill.control-set+json";

    private static readonly HashSet<string> Members = ["id", "version", "controls", "cedar", "privateControls", "coverage"];
    private static readonly HashSet<string> MembersV2 = [.. Members, "schemaVersion", "enforcement"];
    private static readonly HashSet<string> CedarMembersV2 = ["policies", "schemaSha256", "entities"];
    private static readonly HashSet<string> EnforcementMembers = ["mode", "defaultEffect", "lockedConfiguration", "unknownTools", "onRuleError", "haltAfterDenials"];
    private static readonly HashSet<string> LockableRoles = ["instruction-set", "tool-manifest", "execution-policy", "model-config"];
    private static readonly string[] Effects = ["observe", "deny", "halt"];
    // v2 §5: the parent type each entity type may have (AgentGroup: none).
    private static readonly Dictionary<string, string?> ParentTypes = new(StringComparer.Ordinal)
    {
        ["Tool"] = "ToolGroup", ["ToolGroup"] = "ToolGroup", ["Agent"] = "AgentGroup", ["AgentGroup"] = null,
    };
    private static readonly Regex RuleId = new(@"^[A-Za-z0-9._-]{1,64}\z", RegexOptions.CultureInvariant);

    /// <summary>SHA-256 of JCS(<c>agent-policy-cedar-schema-v2.json</c>): the <c>cedar.schemaSha256</c> of every v2 document (v2 §4).</summary>
    internal static string CedarSchemaV2Sha256 => SchemaV2Digest.Value;

    private static readonly Lazy<string> SchemaV2Digest = new(() =>
    {
        using var stream = typeof(AgentPolicy).Assembly.GetManifestResourceStream("Sigill.Sdk.agent-policy-cedar-schema-v2.json")
            ?? throw new InvalidOperationException("Embedded schema 'agent-policy-cedar-schema-v2.json' is missing.");
        using var reader = new System.IO.StreamReader(stream);
        return EnvelopeHashing.HashHex(AgentProfiles.Canonical(JsonNode.Parse(reader.ReadToEnd())!));
    });
    // I-JSON also covers §4 rule 4: integers beyond ±2^53-1 are refused anywhere in the document.
    private const string NotIJson = "the document is not an I-JSON object (no repeated names, integers within ±2^53-1, no lone surrogates)";
    private const string NotUtf8 = "the document is not UTF-8 without a byte-order mark";
    private const string TooDeep = "the document exceeds the nesting depth of 64 levels";
    private const int MaxNestingDepth = 64;
    // \z: `$` would also match before a final newline.
    private static readonly Regex Hex64 = new(@"^[0-9a-f]{64}\z", RegexOptions.CultureInvariant);

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
    /// Cedar engine and is not done here. An empty list means valid. A document with <c>schemaVersion</c> is checked as a v2 control
    /// set (<c>spec/agent-policy-control-set-v2.md</c> §1–§6): annotations, the policy cap, <c>cedar.entities</c>,
    /// <c>enforcement</c> and the schema v2 digest; strict Cedar validation of policies and entities is not done here either.
    /// </summary>
    public static IReadOnlyList<string> Validate(byte[] document)
    {
        var errors = new List<string>();
        if (document is null) { errors.Add("document is required"); return errors; }
        var doc = Parse(document, out var problem);
        if (doc is null) { errors.Add(problem!); return errors; }
        // v2 §1: no schemaVersion is v1; any value other than "2" (including "1") is invalid.
        var v2 = doc.ContainsKey("schemaVersion");
        foreach (var key in doc.Select(kv => kv.Key).Where(k => !(v2 ? MembersV2 : Members).Contains(k))) errors.Add($"unknown member '{key}'");
        if (v2 && AgentProfiles.Str(doc["schemaVersion"]) != "2") errors.Add("schemaVersion must be \"2\" (a v1 document carries none)");
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

        if (doc.TryGetPropertyValue("cedar", out var cedarNode)) ValidateCedar(cedarNode, errors, v2);
        if (v2 && doc.TryGetPropertyValue("enforcement", out var enforcement)) ValidateEnforcement(enforcement, errors);
        return errors;
    }

    private static void ValidateCedar(JsonNode? cedarNode, List<string> errors, bool v2)
    {
        if (cedarNode is not JsonObject cedar) { errors.Add("cedar must be an object"); return; }
        if (cedar["schemaSha256"] is not JsonValue sv || !sv.TryGetValue<string>(out var sha) || !Hex64.IsMatch(sha))
            errors.Add("cedar.schemaSha256 must be a lowercase hex SHA-256");
        else if (v2 && sha != CedarSchemaV2Sha256)
            errors.Add("cedar.schemaSha256 must be the SHA-256 of JCS(agent-policy-cedar-schema-v2.json)");
        if (v2)
        {
            foreach (var key in cedar.Select(kv => kv.Key).Where(k => !CedarMembersV2.Contains(k))) errors.Add($"cedar has unknown member '{key}'");
            if (cedar.TryGetPropertyValue("entities", out var entities)) ValidateEntities(entities, errors);
        }
        if (cedar["policies"] is not JsonObject set) { errors.Add("cedar.policies must be a Cedar JSON policy set"); return; }
        if (set["templates"] is JsonObject t && t.Count > 0) errors.Add("cedar.policies must not contain templates");
        if (set["templateLinks"] is JsonArray l && l.Count > 0) errors.Add("cedar.policies must not contain template links");
        if (set["staticPolicies"] is not JsonObject policies || policies.Count == 0)
        {
            errors.Add("cedar.policies.staticPolicies must hold at least one policy");
            return;
        }
        if (v2 && policies.Count > 256) errors.Add($"cedar.policies holds {policies.Count} policies; at most 256 are allowed");
        foreach (var (key, node) in policies)
        {
            if (node is not JsonObject p) { errors.Add($"policy '{key}' is not an object"); continue; }
            if (!RuleId.IsMatch(key)) errors.Add($"policy id '{key}' must be 1-64 characters of A-Z a-z 0-9 . _ -");
            if (!IsNonEmptyString(p["effect"]) || p["effect"]!.GetValue<string>() != "forbid")
                errors.Add($"policy '{key}' must be forbid (step 1 is tripwire mode)");
            var annotated = p["annotations"] is JsonObject annotations ? annotations["id"] : null;
            if (!IsNonEmptyString(annotated) || annotated!.GetValue<string>() != key)
                errors.Add($"policy '{key}' must carry @id(\"{key}\")");
            if (!v2 || p["annotations"] is not JsonObject all) continue;
            // v2 §4 rules 6-7: only id and effect; effect is observe, deny or halt (a non-string id fails @id above).
            foreach (var name in all.Select(kv => kv.Key).Where(n => n is not ("id" or "effect")))
                errors.Add($"policy '{key}' has annotation '{name}'; only id and effect are allowed");
            if (all.TryGetPropertyValue("effect", out var effect) && !Effects.Contains(AgentProfiles.Str(effect)))
                errors.Add($"policy '{key}': its effect annotation must be observe, deny or halt");
        }
    }

    /// <summary>v2 §5 without the Cedar core: shape, types, attributes, unique uids, parents declared, typed and acyclic.</summary>
    private static void ValidateEntities(JsonNode? node, List<string> errors)
    {
        if (node is not JsonArray array) { errors.Add("cedar.entities must be an array"); return; }
        if (array.Count > 1024) errors.Add($"cedar.entities holds {array.Count} entities; at most 1024 are allowed");
        static (string Type, string Id)? Uid(JsonNode? n) =>
            n is JsonObject u && u.Count == 2 && AgentProfiles.Str(u["type"]) is { } t && AgentProfiles.Str(u["id"]) is { } id
                && id.Length - id.Count(char.IsLowSurrogate) is >= 1 and <= 255 ? (t, id) : null;
        static string Show((string Type, string Id) u) => $"{u.Type}::\"{u.Id}\"";
        var declared = new Dictionary<(string Type, string Id), (int Index, List<(string Type, string Id)> Parents)>();
        for (var i = 0; i < array.Count; i++)
        {
            var at = $"cedar.entities[{i}]";
            if (array[i] is not JsonObject e || e.Count != 3 || !e.ContainsKey("uid") || !e.ContainsKey("attrs") || !e.ContainsKey("parents"))
            {
                errors.Add($"{at} must have exactly uid, attrs and parents");
                continue;
            }
            if (Uid(e["uid"]) is not { } uid) { errors.Add($"{at}.uid must be exactly {{type, id}}, strings, the id 1-255 characters"); continue; }
            if (!ParentTypes.TryGetValue(uid.Type, out var parentType))
            {
                errors.Add($"{at} has type '{uid.Type}'; only Tool, ToolGroup, Agent and AgentGroup are allowed");
                continue;
            }
            if (declared.ContainsKey(uid)) { errors.Add($"cedar.entities declares {Show(uid)} more than once"); continue; }
            if (e["attrs"] is not JsonObject attrs) errors.Add($"{at}.attrs must be an object");
            else if (uid.Type == "Tool")
            {
                foreach (var (name, value) in attrs)
                    if (!(name == "consequential" ? value is JsonValue b && b.GetValueKind() is JsonValueKind.True or JsonValueKind.False
                            : name == "definitionSha256" && AgentProfiles.Str(value) is { } h && Hex64.IsMatch(h)))
                        errors.Add($"{at} (Tool) has attribute '{name}'; a Tool may carry only consequential (boolean) and definitionSha256 (lowercase hex SHA-256)");
            }
            else if (attrs.Count > 0) errors.Add($"{at} ({uid.Type}) must have no attributes");
            var parents = new List<(string Type, string Id)>();
            if (e["parents"] is not JsonArray list) errors.Add($"{at}.parents must be an array");
            else
                foreach (var p in list)
                {
                    if (Uid(p) is not { } parent || parent.Type != parentType)
                        errors.Add(parentType is null ? $"{at}.parents: a {uid.Type} has no parents" : $"{at}.parents: a {uid.Type} may have only {parentType} parents");
                    else if (parents.Contains(parent)) errors.Add($"{at}.parents lists {Show(parent)} twice");
                    else parents.Add(parent);
                }
            declared[uid] = (i, parents);
        }
        foreach (var (index, parents) in declared.Values)
            foreach (var parent in parents.Where(p => !declared.ContainsKey(p)))
                errors.Add($"cedar.entities[{index}].parents: {Show(parent)} is not an entity of the array");
        var state = new Dictionary<(string Type, string Id), bool>(); // false: on the current path, true: done
        bool Cyclic((string Type, string Id) u)
        {
            if (state.TryGetValue(u, out var done)) return !done;
            state[u] = false;
            if (declared.TryGetValue(u, out var d) && d.Parents.Any(Cyclic)) return true;
            state[u] = true;
            return false;
        }
        if (declared.Keys.ToList().Any(Cyclic)) errors.Add("cedar.entities parents form a cycle");
    }

    /// <summary>v2 §6: members, values and ranges of <c>enforcement</c>.</summary>
    private static void ValidateEnforcement(JsonNode? node, List<string> errors)
    {
        if (node is not JsonObject e) { errors.Add("enforcement must be an object"); return; }
        foreach (var key in e.Select(kv => kv.Key).Where(k => !EnforcementMembers.Contains(k))) errors.Add($"enforcement has unknown member '{key}'");
        if (AgentProfiles.Str(e["mode"]) is not ("observe" or "enforce")) errors.Add("enforcement.mode is required: observe or enforce");
        void OneOf(string member, params string[] values)
        {
            if (e.TryGetPropertyValue(member, out var v) && !values.Contains(AgentProfiles.Str(v)))
                errors.Add($"enforcement.{member} must be {string.Join(" or ", values)}");
        }
        OneOf("defaultEffect", "deny", "halt");
        OneOf("unknownTools", "deny", "allow");
        OneOf("onRuleError", "deny", "allow");
        if (e.TryGetPropertyValue("lockedConfiguration", out var lc))
        {
            if (lc is not JsonObject locked) errors.Add("enforcement.lockedConfiguration must be an object");
            else
                foreach (var (role, digest) in locked)
                {
                    if (!LockableRoles.Contains(role))
                        errors.Add($"enforcement.lockedConfiguration has unknown role '{role}'");
                    else if (AgentProfiles.Str(digest) is not { } hex || !Hex64.IsMatch(hex))
                        errors.Add($"enforcement.lockedConfiguration['{role}'] must be a lowercase hex SHA-256");
                }
        }
        if (e.TryGetPropertyValue("haltAfterDenials", out var h) && !(h is JsonValue hv && hv.TryGetValue<long>(out var n) && n >= 0))
            errors.Add("enforcement.haltAfterDenials must be an integer >= 0");
    }

    /// <summary>
    /// The document's effective enforcement settings and each rule's effective effect, defaults applied
    /// (<c>spec/agent-policy-control-set-v2.md</c> §4 rule 7, §6). Throws <see cref="ArgumentException"/> listing the problems
    /// when <see cref="Validate"/> finds any.
    /// </summary>
    public static PolicyEnforcement Enforcement(byte[] document)
    {
        var errors = Validate(document);
        if (errors.Count > 0) throw new ArgumentException("Invalid policy control set: " + string.Join("; ", errors), nameof(document));
        var doc = Parse(document)!;
        var e = doc["enforcement"] as JsonObject;
        string Setting(string member, string otherwise) => AgentProfiles.Str(e?[member]) ?? otherwise;
        var mode = Setting("mode", "observe");
        var defaultEffect = Setting("defaultEffect", "deny");
        var locked = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (role, digest) in e?["lockedConfiguration"] as JsonObject ?? new JsonObject()) locked[role] = AgentProfiles.Str(digest)!;
        var effects = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var (id, rule) in doc["cedar"]?["policies"]?["staticPolicies"] as JsonObject ?? new JsonObject())
            effects[id] = mode == "enforce" ? AgentProfiles.Str(rule?["annotations"]?["effect"]) ?? defaultEffect : "observe";
        return new PolicyEnforcement
        {
            Mode = mode, DefaultEffect = defaultEffect, LockedConfiguration = locked, UnknownTools = Setting("unknownTools", "allow"),
            OnRuleError = Setting("onRuleError", "deny"), RuleEffects = effects,
            HaltAfterDenials = e?["haltAfterDenials"] is JsonValue hv && hv.TryGetValue<long>(out var n) ? n : 0,
        };
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
    public static PolicyFacts BuildFacts(string agentId, string correlationId, IEnumerable<JsonObject> events) =>
        BuildFacts(agentId, correlationId, events, null);

    /// <summary>
    /// With <paramref name="claimedMissing"/>, <paramref name="events"/> is an evaluator's contiguous prefix and the
    /// gaps it reported above it are taken as given: what a verifier rebuilds (<c>control-evaluation-v2.md</c> §4.5).
    /// </summary>
    internal static PolicyFacts BuildFacts(string agentId, string correlationId, IEnumerable<JsonObject> events, IReadOnlyList<int>? claimedMissing) =>
        BuildFacts(agentId, correlationId, events, claimedMissing, null, null);

    /// <summary>
    /// The facts v2 of a run under a v2 policy control set (<c>spec/agent-policy-control-set-v2.md</c> §8): the facts v1 requests
    /// with <c>toolCallsSoFar</c>, <c>callsOfThisTool</c>, <c>denialsSoFar</c>, the <c>approval</c> of §8.1 on each
    /// <c>tool_call</c>, <c>unpairedConsequential</c> without denied calls, and the control set's <c>cedar.entities</c> as
    /// <c>entities</c> (the entities input of every request). The facts document has <c>factsVersion "2"</c>.
    /// </summary>
    /// <param name="agentId">The Control Artifact's signed <c>agent.id</c>.</param>
    /// <param name="correlationId">The run's <c>activity.correlationId</c>.</param>
    /// <param name="events">
    /// The run's events, any order. Facts v2 read each event's signed object digests (<see cref="AgentRunArtifact.ObjectDigests"/>):
    /// a call's <c>argumentsSha256</c> is the digest of its one <c>tool-arguments</c> object. Pass digests the signature confirmed.
    /// </param>
    /// <param name="controlSetDocument">The run's v2 policy control set, exact bytes.</param>
    /// <exception cref="ArgumentException">The control set is not a valid v2 policy control set, or the chain is not valid (as <see cref="BuildFacts(string, string, IEnumerable{JsonObject})"/>).</exception>
    public static PolicyFacts BuildFactsV2(string agentId, string correlationId, IEnumerable<AgentRunArtifact> events, byte[] controlSetDocument)
    {
        var errors = Validate(controlSetDocument);
        if (errors.Count > 0) throw new ArgumentException("Invalid policy control set: " + string.Join("; ", errors), nameof(controlSetDocument));
        var doc = Parse(controlSetDocument)!;
        if (AgentProfiles.Str(doc["schemaVersion"]) != "2")
            throw new ArgumentException("Facts v2 need a v2 policy control set (schemaVersion \"2\").", nameof(controlSetDocument));
        var list = (events ?? throw new ArgumentNullException(nameof(events))).ToList();
        var digests = new Dictionary<JsonObject, IReadOnlyDictionary<string, string>>(); // by reference: one entry per envelope
        foreach (var a in list) digests.TryAdd(a.Envelope, a.ObjectDigests); // the first set of digests wins
        var entities = (JsonArray)(doc["cedar"]?["entities"] ?? new JsonArray()).DeepClone();
        return BuildFacts(agentId, correlationId, list.Select(a => a.Envelope), null, entities, digests);
    }

    /// <summary>The core of both facts versions: <paramref name="entities"/> is non-null exactly for facts v2.</summary>
    private static PolicyFacts BuildFacts(string agentId, string correlationId, IEnumerable<JsonObject> events, IReadOnlyList<int>? claimedMissing,
        JsonArray? entities, IReadOnlyDictionary<JsonObject, IReadOnlyDictionary<string, string>>? digests)
    {
        var v2 = entities is not null;
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
        if (claimedMissing is not null)
        {
            if (missing.Count > 0) throw new ArgumentException($"the prefix is not contiguous (seq {missing[0]} missing)", nameof(events));
            missing = claimedMissing.ToList();
        }
        var prefix = bySeq.Where(kv => kv.Key <= throughSeq).Select(kv => (Seq: kv.Key, Env: kv.Value)).ToList();

        static JsonObject? Step(JsonObject e) => e["step"] as JsonObject;
        static string StepType(JsonObject e) => AgentProfiles.Str(Step(e)?["type"]) ?? "";
        static bool Consequential(JsonObject e) => Step(e)?["consequential"] is JsonValue v && v.GetValueKind() == JsonValueKind.True;
        static string? Tool(JsonObject e, string field) => AgentProfiles.Str((Step(e)?["tool"] as JsonObject)?[field]); // a non-object tool is absent
        JsonObject Principal() => new() { ["type"] = "Agent", ["id"] = agentId };

        var isChildRun = bySeq.TryGetValue(0, out var first) && StepType(first) == "run_start"
            && AgentProfiles.Str(first["binds"]?["parentCorrelationId"]) is { Length: > 0 };
        var requests = new JsonArray();
        var consequentialCount = 0;
        var sawApproval = false;
        var approvals = v2 ? ToolCallApprovals(prefix, digests!) : null;
        var callsByTool = new Dictionary<string, int>(StringComparer.Ordinal);
        int toolCalls = 0, denials = 0;
        foreach (var (seq, e) in prefix)
        {
            var type = StepType(e);
            var consequential = Consequential(e);
            if (consequential) consequentialCount++;
            var context = Context(consequential, Tool(e, "operation") ?? "", seq, sawApproval ? "unbound" : "none",
                isChildRun, 0, consequentialCount, 0);
            if (v2)
            {
                // v2 §8: counters up to and including this seq; denials strictly before it.
                // An absent tool name equals nothing: such a call counts in toolCallsSoFar only, and its callsOfThisTool is 0.
                var name = Tool(e, "name");
                if (type == "tool_call")
                {
                    toolCalls++;
                    if (name is not null) callsByTool[name] = (callsByTool.TryGetValue(name, out var c) ? c : 0) + 1;
                    context["approval"] = approvals![seq];
                }
                context["toolCallsSoFar"] = toolCalls;
                context["callsOfThisTool"] = type is "tool_call" or "tool_result" && name is not null && callsByTool.TryGetValue(name, out var n) ? n : 0;
                context["denialsSoFar"] = denials;
                if (IsEnforcementRecord(e)) denials++;
            }
            requests.Add(new JsonObject
            {
                ["seq"] = seq,
                ["principal"] = Principal(),
                ["action"] = new JsonObject { ["type"] = "Action", ["id"] = type },
                ["resource"] = type is "tool_call" or "tool_result"
                    ? new JsonObject { ["type"] = "Tool", ["id"] = Tool(e, "name") ?? "" }
                    : new JsonObject { ["type"] = "Step", ["id"] = seq.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                ["context"] = context,
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
                // v2 §8: a call that an enforcement record denied is not unpaired.
                if (v2 && u is not null && prefix.Any(x => IsEnforcementRecord(x.Env) && x.Seq > c.Seq && Tool(x.Env, "useId") == u)) return false;
                var paired = u is not null && uses[u] == 1
                    && prefix.Any(x => StepType(x.Env) == "tool_result" && x.Seq > c.Seq && Tool(x.Env, "useId") == u);
                return !paired && Consequential(c.Env);
            });
            var context = Context(false, "", finalSeq, "none", isChildRun, finalSeq, consequentialCount, unpaired);
            if (v2)
            {
                context["toolCallsSoFar"] = calls.Count;
                context["callsOfThisTool"] = 0;
                context["denialsSoFar"] = prefix.Count(x => IsEnforcementRecord(x.Env));
            }
            requests.Add(new JsonObject
            {
                ["seq"] = "run",
                ["principal"] = Principal(),
                ["action"] = new JsonObject { ["type"] = "Action", ["id"] = "run" },
                ["resource"] = new JsonObject { ["type"] = "Run", ["id"] = correlationId },
                ["context"] = context,
            });
        }

        var document = new JsonObject
        {
            ["factsVersion"] = v2 ? "2" : FactsVersion,
            ["throughSeq"] = throughSeq,
            ["missingSeqs"] = new JsonArray(missing.Select(m => (JsonNode?)m).ToArray()),
            ["runLevel"] = runLevel,
            ["requests"] = requests,
        };
        if (v2) document["entities"] = entities;
        var bytes = AgentProfiles.Canonical(document);
        return new PolicyFacts(bytes, EnvelopeHashing.HashHex(bytes), throughSeq, missing, runLevel);
    }

    /// <summary>An enforcement record (Agent Enforcement v1 §3.4): an <c>authorization</c> with an <c>enforcer</c> member.</summary>
    internal static bool IsEnforcementRecord(JsonObject e) =>
        e["step"] is JsonObject step && AgentProfiles.Str(step["type"]) == "authorization" && step.ContainsKey("enforcer");

    /// <summary>
    /// v2 §8.1: the <c>approval</c> of every <c>tool_call</c> of the prefix, by seq. The calls are walked in seq order and a
    /// <c>bound</c> call consumes the lowest-seq approval that matches it, so one approval binds at most one call.
    /// </summary>
    private static Dictionary<int, string> ToolCallApprovals(List<(int Seq, JsonObject Env)> prefix,
        IReadOnlyDictionary<JsonObject, IReadOnlyDictionary<string, string>> digests)
    {
        var result = new Dictionary<int, string>();
        var earlier = new List<(int Seq, JsonObject Step)>();
        var consumed = new HashSet<int>();
        foreach (var (seq, env) in prefix)
        {
            if (env["step"] is not JsonObject step) continue;
            var type = AgentProfiles.Str(step["type"]);
            if (type == "human_approval") earlier.Add((seq, step));
            if (type != "tool_call") continue;
            var u = AgentProfiles.Str((step["tool"] as JsonObject)?["useId"]);
            var t = AgentProfiles.Str((step["tool"] as JsonObject)?["name"]);
            // a: the signed digest of the call's one tool-arguments object; undefined (null) otherwise, and equal to nothing.
            var args = (env["objects"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
                .Where(o => AgentProfiles.Str(o["role"]) == "tool-arguments").ToList();
            var a = args.Count == 1 && AgentProfiles.Str(args[0]["uri"]) is { } uri && digests.TryGetValue(env, out var d)
                && d.TryGetValue(uri, out var hex) ? hex : null;
            // P7: a missing or non-string member is absent, and an absent value equals nothing.
            bool Covers(JsonObject c) => t is not null && AgentProfiles.Str(c["tool"]) == t && a is not null && AgentProfiles.Str(c["argumentsSha256"]) == a;
            bool Live(JsonObject c) => !c.ContainsKey("expiresAt")
                || (EnvelopeSchema.TryParseDateTime(AgentProfiles.Str(step["eventTime"]), out var at)
                    && EnvelopeSchema.TryParseDateTime(AgentProfiles.Str(c["expiresAt"]), out var expires) && at < expires);
            if (earlier.Any(x => AgentProfiles.Str(x.Step["decision"]) == "rejected" && x.Step["covers"] is JsonObject c
                    && ((u is not null && AgentProfiles.Str(c["useId"]) == u) || Covers(c))))
                result[seq] = "rejected"; // sticky; a rejection ignores expiresAt
            else if (earlier.FirstOrDefault(x => AgentProfiles.Str(x.Step["decision"]) == "approved" && x.Step["covers"] is JsonObject c
                    && Covers(c) && (!c.ContainsKey("useId") || (u is not null && AgentProfiles.Str(c["useId"]) == u)) && Live(c) && !consumed.Contains(x.Seq))
                is { Step: not null } binding)
            {
                result[seq] = "bound";
                consumed.Add(binding.Seq);
            }
            else result[seq] = earlier.Count > 0 ? "unbound" : "none";
        }
        return result;
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

    private static JsonObject? Parse(byte[]? document) => Parse(document, out _);

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>
    /// The one strict parse of a control set (Control Set v2 §2), used by validation, the facts builder and the verifier:
    /// UTF-8 without a byte-order mark, I-JSON (no repeated names, integers within ±(2^53 − 1), no NaN or Infinity, no lone
    /// surrogates, raw or escaped), nested at most 64 levels with the outermost object or array as level 1. Null, with
    /// <paramref name="problem"/> saying why, for anything else; never an exception.
    /// </summary>
    internal static JsonObject? Parse(byte[]? document, out string? problem)
    {
        problem = NotUtf8;
        if (document is null || document.Length >= 3 && document[0] == 0xEF && document[1] == 0xBB && document[2] == 0xBF) return null;
        try { StrictUtf8.GetString(document); }
        catch (ArgumentException) { return null; } // DecoderFallbackException: not UTF-8 (UTF-16, encoded surrogates, …)
        // Measured on the bytes before parsing, so a deep document never reaches a recursive reader.
        problem = TooDeep;
        if (NestingDepth(document) > MaxNestingDepth) return null;
        problem = NotIJson;
        try
        {
            // I-JSON: no repeated names, which JsonNode would only notice lazily — check with JsonDocument first.
            var options = new JsonDocumentOptions { MaxDepth = MaxNestingDepth };
            using (var d = JsonDocument.Parse(document, options))
                if (AgentProfiles.FindDuplicateName(d.RootElement) is not null) return null;
            if (JsonNode.Parse(document, null, options) is not JsonObject o || !AgentProfiles.IsIJson(o, safeIntegers: true)) return null;
            AgentProfiles.Canonical(o); // a number JCS cannot serialize (e.g. 1e999) is not usable either
            problem = null;
            return o;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException or SigillCanonicalizationException) { return null; }
    }

    /// <summary>The deepest nesting of objects and arrays, the outermost being level 1 (strings skipped, escapes honoured).</summary>
    private static int NestingDepth(byte[] json)
    {
        int depth = 0, deepest = 0;
        bool inString = false, escaped = false;
        foreach (var b in json)
        {
            if (inString)
            {
                if (escaped) escaped = false;
                else if (b == '\\') escaped = true;
                else if (b == '"') inString = false;
            }
            else if (b == '"') inString = true;
            else if (b is (byte)'{' or (byte)'[') deepest = Math.Max(deepest, ++depth);
            else if (b is (byte)'}' or (byte)']') depth--;
        }
        return deepest;
    }
}
