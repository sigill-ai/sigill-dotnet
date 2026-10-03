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
/// The portable form of a controlled agent run (common rules §7): the Control
/// Artifact, every event, any Control Evaluations, each object's digest, and
/// optionally the payload bytes. Hand it to anyone who should verify the run;
/// without payloads it reveals no content.
/// </summary>
public sealed class AgentRunBundle
{
    /// <summary>Upper bound on events per bundle (§7).</summary>
    public const int MaxArtifacts = 2000;

    /// <summary>Upper bound on Control Evaluations per bundle; each costs one signature check.</summary>
    public const int MaxEvaluations = 64;

    /// <summary>Upper bound on supplied payloads per bundle.</summary>
    public const int MaxPayloads = 20000;

    /// <summary>Upper bound on JSON nesting depth.</summary>
    public const int MaxDepth = 64;

    private static readonly Regex Hex64 = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

    /// <summary>An index for humans; verifiers take the run identifier only from the signed envelopes.</summary>
    public string? CorrelationId { get; }

    /// <summary>The run's Control Artifact; null for a run-only bundle.</summary>
    public AgentRunArtifact? ControlArtifact { get; }

    /// <summary>The Execution Evidence events.</summary>
    public IReadOnlyList<AgentRunArtifact> Artifacts { get; }

    public IReadOnlyList<AgentRunArtifact> Evaluations { get; }

    /// <summary>Payload bytes keyed by object URI. Empty for a digests-only bundle.</summary>
    public IReadOnlyDictionary<string, byte[]> Payloads { get; }

    public AgentRunBundle(
        string? correlationId,
        AgentRunArtifact? controlArtifact,
        IReadOnlyList<AgentRunArtifact> artifacts,
        IReadOnlyList<AgentRunArtifact>? evaluations = null,
        IReadOnlyDictionary<string, byte[]>? payloads = null)
    {
        CorrelationId = correlationId;
        ControlArtifact = controlArtifact;
        Artifacts = artifacts ?? throw new ArgumentNullException(nameof(artifacts));
        Evaluations = evaluations ?? Array.Empty<AgentRunArtifact>();
        Payloads = payloads ?? new Dictionary<string, byte[]>(StringComparer.Ordinal);
        // The limits are properties of a bundle (§7), not only of its parser: a bundle built here must parse again.
        if (Artifacts.Count > MaxArtifacts) throw new ArgumentException($"more than {MaxArtifacts} artifacts", nameof(artifacts));
        if (Evaluations.Count > MaxEvaluations) throw new ArgumentException($"more than {MaxEvaluations} evaluations", nameof(evaluations));
        if (Payloads.Count > MaxPayloads) throw new ArgumentException($"more than {MaxPayloads} payloads", nameof(payloads));
    }

    /// <summary>The same bundle with (other) payload bytes, e.g. to share content with an auditor.</summary>
    public AgentRunBundle WithPayloads(IReadOnlyDictionary<string, byte[]>? payloads) =>
        new(CorrelationId, ControlArtifact, Artifacts, Evaluations, payloads);

    /// <summary>The same bundle with Control Evaluations added.</summary>
    public AgentRunBundle WithEvaluations(params AgentRunArtifact[] evaluations) =>
        new(CorrelationId, ControlArtifact, Artifacts, Evaluations.Concat(evaluations).ToList(), Payloads);

    public JsonObject ToJson()
    {
        var json = new JsonObject
        {
            ["format"] = AgentProfiles.BundleFormat,
            ["bundleVersion"] = AgentProfiles.BundleVersion,
            ["correlationId"] = CorrelationId,
            ["controlArtifact"] = ControlArtifact?.ToJson(),
            ["artifacts"] = new JsonArray(Artifacts.Select(a => (JsonNode)a.ToJson()).ToArray()),
        };
        if (Evaluations.Count > 0)
            json["evaluations"] = new JsonArray(Evaluations.Select(a => (JsonNode)a.ToJson()).ToArray());
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
    /// Strict parse (§7): every entry must be well-formed. A malformed
    /// container throws <see cref="AgentRunBundleFormatException"/> listing every
    /// problem; nothing is skipped.
    /// </summary>
    public static AgentRunBundle Parse(string json)
    {
        JsonNode? node;
        try
        {
            // I-JSON forbids duplicate names, and parsers disagree on which value wins: refuse them (§7).
            using (var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 1024 }))
            {
                if (Depth(doc.RootElement) > MaxDepth)
                    throw new AgentRunBundleFormatException(new[] { $"bundle nests deeper than {MaxDepth} levels" });
                if (AgentProfiles.FindDuplicateName(doc.RootElement) is { } dup)
                    throw new AgentRunBundleFormatException(new[] { $"bundle repeats a duplicate member name '{dup}'" });
            }
            node = JsonNode.Parse(json);
        }
        catch (JsonException ex) { throw new AgentRunBundleFormatException(new[] { "bundle is not valid JSON: " + ex.Message }); }
        return Parse(node);
    }

    /// <summary>Nesting depth: a scalar is 0, an object or array one more than its deepest member.</summary>
    private static int Depth(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => 1 + e.EnumerateObject().Select(p => Depth(p.Value)).DefaultIfEmpty(0).Max(),
        JsonValueKind.Array => 1 + e.EnumerateArray().Select(Depth).DefaultIfEmpty(0).Max(),
        _ => 0,
    };

    public static AgentRunBundle Parse(JsonNode? node)
    {
        // A node parsed from text with a repeated member name throws when first read (JsonObject is lazy).
        try
        {
            Materialize(node); // surfaces a repeated name here, the same way Parse(string) refuses it
            return ParseNode(node);
        }
        catch (ArgumentException ex) when (ex is not ArgumentNullException)
        {
            throw new AgentRunBundleFormatException(new[] { "bundle repeats a duplicate member name: " + ex.Message });
        }
    }

    private static void Materialize(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o: foreach (var kv in o) Materialize(kv.Value); break;
            case JsonArray a: foreach (var x in a) Materialize(x); break;
        }
    }

    private static AgentRunBundle ParseNode(JsonNode? node)
    {
        var errors = new List<string>();
        if (node is not JsonObject input)
            throw new AgentRunBundleFormatException(new[] { "bundle must be a JSON object" });

        string Shown(string key) => AgentProfiles.Str(input[key]) ?? input[key]?.ToJsonString() ?? "None";
        if (AgentProfiles.Str(input["format"]) != AgentProfiles.BundleFormat)
            errors.Add($"unsupported format '{Shown("format")}' (expected {AgentProfiles.BundleFormat})");
        if (AgentProfiles.Str(input["bundleVersion"]) != AgentProfiles.BundleVersion)
            errors.Add($"unsupported bundleVersion '{Shown("bundleVersion")}' (expected {AgentProfiles.BundleVersion})");

        AgentRunArtifact? control = null;
        if (input["controlArtifact"] is { } controlNode)
            control = ReadArtifact(controlNode, "controlArtifact", errors);

        var artifacts = new List<AgentRunArtifact>();
        if (input["artifacts"] is not JsonArray arr) errors.Add("artifacts[] missing or not an array");
        else if (arr.Count > MaxArtifacts) errors.Add($"more than {MaxArtifacts} artifacts");
        else
        {
            if (arr.Count == 0 && input["controlArtifact"] is null) errors.Add("bundle carries neither a Control Artifact nor any event");
            for (var i = 0; i < arr.Count; i++)
                if (ReadArtifact(arr[i], $"artifacts[{i}]", errors) is { } a) artifacts.Add(a);
        }

        var evaluations = new List<AgentRunArtifact>();
        if (input["evaluations"] is { } evalNode)
        {
            if (evalNode is not JsonArray evals) errors.Add("evaluations is not an array");
            else if (evals.Count > MaxEvaluations) errors.Add($"more than {MaxEvaluations} evaluations");
            else
                for (var i = 0; i < evals.Count; i++)
                    if (ReadArtifact(evals[i], $"evaluations[{i}]", errors) is { } a) evaluations.Add(a);
        }

        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (input["payloads"] is { } payloadNode)
        {
            if (payloadNode is not JsonObject p) errors.Add("payloads is not an object");
            else if (p.Count > MaxPayloads) errors.Add($"more than {MaxPayloads} payloads");
            else
                foreach (var kv in p)
                {
                    if (AgentProfiles.Str(kv.Value) is { } b64 && TryBase64(b64, out var bytes)) payloads[kv.Key] = bytes;
                    else errors.Add($"payloads['{kv.Key}'] is not valid base64");
                }
        }

        if (errors.Count > 0) throw new AgentRunBundleFormatException(errors);
        return new AgentRunBundle(AgentProfiles.Str(input["correlationId"]), control, artifacts, evaluations, payloads);
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
                var hex = AgentProfiles.Str(kv.Value);
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
