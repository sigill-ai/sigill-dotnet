// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sigill.Sdk;

/// <summary>
/// The portable form of an agent run (spec §7): every artifact, the identity
/// record, each object's digest, and optionally the payload bytes. Hand it to
/// anyone who should verify the run; without payloads it reveals no content.
/// </summary>
public sealed class AgentRunBundle
{
    /// <summary>Upper bound on artifacts per bundle (spec §7).</summary>
    public const int MaxArtifacts = 2000;

    private static readonly Regex Hex64 = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

    public string Profile { get; }
    public string? CorrelationId { get; }
    public AgentRunArtifact? AgentIdentity { get; }
    public IReadOnlyList<AgentRunArtifact> Artifacts { get; }

    /// <summary>Payload bytes keyed by object URI. Empty for a digests-only bundle.</summary>
    public IReadOnlyDictionary<string, byte[]> Payloads { get; }

    public AgentRunBundle(
        string? correlationId,
        AgentRunArtifact? agentIdentity,
        IReadOnlyList<AgentRunArtifact> artifacts,
        IReadOnlyDictionary<string, byte[]>? payloads = null)
        : this(AgentExecutionProfile.Name, correlationId, agentIdentity, artifacts, payloads) { }

    private AgentRunBundle(
        string profile, string? correlationId, AgentRunArtifact? agentIdentity,
        IReadOnlyList<AgentRunArtifact> artifacts, IReadOnlyDictionary<string, byte[]>? payloads)
    {
        Profile = profile;
        CorrelationId = correlationId;
        AgentIdentity = agentIdentity;
        Artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        Payloads = payloads ?? new Dictionary<string, byte[]>(StringComparer.Ordinal);
    }

    /// <summary>The same bundle with (other) payload bytes, e.g. to share content with an auditor.</summary>
    public AgentRunBundle WithPayloads(IReadOnlyDictionary<string, byte[]>? payloads) =>
        new(Profile, CorrelationId, AgentIdentity, Artifacts, payloads);

    public JsonObject ToJson()
    {
        var json = new JsonObject
        {
            ["profile"] = Profile,
            ["bundleVersion"] = AgentExecutionProfile.BundleVersion,
            ["correlationId"] = CorrelationId,
            ["agentIdentity"] = AgentIdentity?.ToJson(),
            ["artifacts"] = new JsonArray(Artifacts.Select(a => (JsonNode)a.ToJson()).ToArray()),
        };
        if (Payloads.Count > 0)
        {
            var p = new JsonObject();
            foreach (var kv in Payloads.OrderBy(k => k.Key, StringComparer.Ordinal))
                p[kv.Key] = Convert.ToBase64String(kv.Value);
            json["payloads"] = p;
        }
        return json;
    }

    public string ToJsonString(bool indented = true) =>
        ToJson().ToJsonString(new JsonSerializerOptions { WriteIndented = indented });

    /// <summary>
    /// Strict parse (spec §7): every entry must be well-formed. A malformed
    /// container throws <see cref="AgentRunBundleFormatException"/> listing every
    /// problem; nothing is skipped.
    /// </summary>
    public static AgentRunBundle Parse(string json)
    {
        JsonNode? node;
        try
        {
            // I-JSON forbids duplicate names, and parsers disagree on which value wins: refuse them (§7).
            using (var doc = JsonDocument.Parse(json))
                if (FindDuplicateName(doc.RootElement) is { } dup)
                    throw new AgentRunBundleFormatException(new[] { $"bundle repeats a duplicate member name '{dup}'" });
            node = JsonNode.Parse(json);
        }
        catch (JsonException ex) { throw new AgentRunBundleFormatException(new[] { "bundle is not valid JSON: " + ex.Message }); }
        return Parse(node);
    }

    private static string? FindDuplicateName(JsonElement e)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var p in e.EnumerateObject())
                {
                    if (!seen.Add(p.Name)) return p.Name;
                    if (FindDuplicateName(p.Value) is { } inner) return inner;
                }
                return null;
            case JsonValueKind.Array:
                foreach (var x in e.EnumerateArray())
                    if (FindDuplicateName(x) is { } inner) return inner;
                return null;
            default:
                return null;
        }
    }

    public static AgentRunBundle Parse(JsonNode? node)
    {
        var errors = new List<string>();
        if (node is not JsonObject input)
            throw new AgentRunBundleFormatException(new[] { "bundle must be a JSON object" });

        var profile = AgentExecutionProfile.Str(input["profile"]);
        if (profile != AgentExecutionProfile.Name)
            errors.Add($"unsupported profile '{profile ?? input["profile"]?.ToJsonString() ?? "None"}' (expected {AgentExecutionProfile.Name})");
        var bundleVersion = AgentExecutionProfile.Str(input["bundleVersion"]);
        if (bundleVersion != AgentExecutionProfile.BundleVersion)
            errors.Add($"unsupported bundleVersion '{bundleVersion ?? input["bundleVersion"]?.ToJsonString() ?? "None"}' (expected {AgentExecutionProfile.BundleVersion})");

        var artifacts = new List<AgentRunArtifact>();
        if (input["artifacts"] is not JsonArray arr || arr.Count == 0) errors.Add("artifacts[] missing or empty");
        else if (arr.Count > MaxArtifacts) errors.Add($"more than {MaxArtifacts} artifacts");
        else
            for (var i = 0; i < arr.Count; i++)
                if (ReadArtifact(arr[i], $"artifacts[{i}]", errors) is { } a) artifacts.Add(a);

        AgentRunArtifact? identity = null;
        if (input["agentIdentity"] is { } idNode)
            identity = ReadArtifact(idNode, "agentIdentity", errors);

        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (input.ContainsKey("payloads") && input["payloads"] is not null)
        {
            if (input["payloads"] is not JsonObject p) errors.Add("payloads is not an object");
            else
                foreach (var kv in p)
                {
                    if (AgentExecutionProfile.Str(kv.Value) is { } b64 && TryBase64(b64, out var bytes)) payloads[kv.Key] = bytes;
                    else errors.Add($"payloads['{kv.Key}'] is not valid base64");
                }
        }

        if (errors.Count > 0) throw new AgentRunBundleFormatException(errors);
        return new AgentRunBundle(profile!, AgentExecutionProfile.Str(input["correlationId"]), identity, artifacts, payloads);
    }

    private static AgentRunArtifact? ReadArtifact(JsonNode? node, string label, List<string> errors)
    {
        if (node is not JsonObject a) { errors.Add($"{label}: not an object"); return null; }
        if (a["envelope"] is not JsonObject env || a["signature"] is not JsonObject sig)
        {
            errors.Add($"{label}: lacks envelope or signature object");
            return null;
        }
        var digests = new Dictionary<string, string>(StringComparer.Ordinal);
        var ok = true;
        if (a.ContainsKey("objectDigests"))
        {
            if (a["objectDigests"] is not JsonObject d) { errors.Add($"{label}: objectDigests is not an object"); return null; }
            foreach (var kv in d)
            {
                var hex = AgentExecutionProfile.Str(kv.Value);
                if (hex is null || !Hex64.IsMatch(hex))
                {
                    errors.Add($"{label}: objectDigests['{kv.Key}'] is not a 64-char hex digest");
                    ok = false;
                }
                else digests[kv.Key] = hex;
            }
        }
        return ok ? new AgentRunArtifact((JsonObject)env.DeepClone(), (JsonObject)sig.DeepClone(), digests) : null;
    }

    private static bool TryBase64(string s, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (s.Length % 4 != 0 || !Regex.IsMatch(s, "^[A-Za-z0-9+/]*={0,2}$")) return false;
        try { bytes = Convert.FromBase64String(s); return true; }
        catch (FormatException) { return false; }
    }
}

/// <summary>A bundle failed strict parsing; <see cref="Errors"/> lists every problem found.</summary>
public sealed class AgentRunBundleFormatException : SigillException
{
    public IReadOnlyList<string> Errors { get; }

    public AgentRunBundleFormatException(IReadOnlyList<string> errors)
        : base("Malformed agent run bundle: " + string.Join("; ", errors)) => Errors = errors;
}
