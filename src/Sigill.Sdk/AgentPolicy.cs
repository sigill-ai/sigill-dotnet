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
