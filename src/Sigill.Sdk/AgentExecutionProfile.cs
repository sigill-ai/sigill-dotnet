// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Text.Json.Nodes;
using Sigill.Sdk.Internal;

namespace Sigill.Sdk;

/// <summary>
/// Constants and the normative digests of AgentExecutionProfileV1
/// (<c>spec/agent-execution-profile-v1.md</c>): the chain digest (§4) and
/// the configuration digest (§3.6). Recording and verification build on these;
/// they are public so other producers and verifiers can reproduce them.
/// </summary>
public static class AgentExecutionProfile
{
    /// <summary>The bundle's <c>profile</c> value.</summary>
    public const string Name = "AgentExecutionProfileV1";

    /// <summary>The bundle format version.</summary>
    public const string BundleVersion = "1";

    /// <summary>Key of the signed profile block under <c>extensions</c>.</summary>
    public const string ExtensionKey = "ai.sigill.agent-execution";

    /// <summary>The configuration object kinds bound by <c>run_start</c> and the identity record (§3.2).</summary>
    public static IReadOnlyList<string> ConfigurationKinds { get; } =
        new[] { "instruction-set", "tool-manifest", "model-config", "execution-policy" };

    /// <summary>Configuration kinds that may be absent — on both sides, or on neither (§3.2).</summary>
    public static IReadOnlyList<string> OptionalConfigurationKinds { get; } = new[] { "model-config" };

    /// <summary>The object kinds an identity record carries, at most one each; all but the optional configuration kinds are required (§3.6).</summary>
    public static IReadOnlyList<string> IdentityKinds { get; } =
        new[] { "agent-manifest", "instruction-set", "tool-manifest", "model-config", "execution-policy", "registration-record" };

    /// <summary>
    /// The chain digest of an artifact (§4): lowercase SHA-256 hex over the
    /// base64url-decoded JWS Signature Value of its classical signature — the
    /// first <c>signatures[]</c> entry whose protected <c>alg</c> is not ML-DSA,
    /// or the <c>signature</c> member of a flattened JWS. Unprotected headers
    /// are excluded, so augmenting an artifact later never breaks the chain.
    /// Returns null when the JWS carries no usable classical signature.
    /// </summary>
    public static string? ChainDigest(JsonObject signature)
    {
        if (signature is null) throw new ArgumentNullException(nameof(signature));
        foreach (var (entry, _) in ClassicalEntries(signature))
        {
            if (!TryString(entry["signature"], out var sig)) continue;
            try { return EnvelopeHashing.HashHex(Base64UrlDecode(sig)); }
            catch (FormatException) { return null; }
        }
        return null;
    }

    /// <summary>
    /// The signer of an artifact (§4.1): the <c>x5t#S256</c> of its single
    /// classical signature, or null and the reason it cannot be established.
    /// Requires exactly one classical entry whose protected header carries
    /// <c>x5c</c> and an <c>x5t#S256</c> equal to the SHA-256 of <c>x5c[0]</c>.
    /// </summary>
    public static (string? Thumbprint, string? Problem) SignerOf(JsonObject signature)
    {
        if (signature is null) throw new ArgumentNullException(nameof(signature));
        var classical = ClassicalEntries(signature);
        if (classical.Count != 1)
            return (null, $"carries {classical.Count} classical signatures; exactly one classical signature is required");
        var header = classical[0].Header;
        if (header is null || Str(header["alg"]) is null)
            return (null, "its classical signature has no readable protected header");
        if (Str(header["x5t#S256"]) is not { } thumb || header["x5c"] is not JsonArray x5c || x5c.Count == 0 || Str(x5c[0]) is not { } leafB64)
            return (null, "its protected header names no signing certificate (x5c, x5t#S256)");
        byte[] leaf;
        try { leaf = Convert.FromBase64String(leafB64); }
        catch (FormatException) { return (null, "its x5c[0] is not valid base64"); }
        using var sha = SHA256.Create();
        var computed = Convert.ToBase64String(sha.ComputeHash(leaf)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return computed == thumb ? (thumb, null) : (null, "its x5t#S256 is not the SHA-256 of x5c[0]");
    }

    /// <summary>Every non-ML-DSA entry, with its protected header (null when unreadable — it still counts, §4).</summary>
    internal static List<(JsonObject Entry, JsonObject? Header)> ClassicalEntries(JsonObject signature)
    {
        IEnumerable<JsonNode?> entries = signature["signatures"] is JsonArray arr
            ? arr
            : signature["signature"] is not null ? new JsonNode?[] { signature } : Array.Empty<JsonNode?>();
        var result = new List<(JsonObject, JsonObject?)>();
        foreach (var e in entries)
        {
            if (e is not JsonObject entry) continue;
            JsonObject? header = null;
            try
            {
                if (TryString(entry["protected"], out var prot))
                    header = JsonNode.Parse(Encoding.UTF8.GetString(Base64UrlDecode(prot))) as JsonObject;
            }
            catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException) { /* unreadable */ }
            if (Str(header?["alg"]) is { } alg && alg.StartsWith("ML-DSA", StringComparison.OrdinalIgnoreCase)) continue;
            result.Add((entry, header));
        }
        return result;
    }

    /// <summary>Profile-block names a producer extension must not use (§6).</summary>
    public static IReadOnlyCollection<string> ReservedExtensionKeys { get; } = new HashSet<string>(StringComparer.Ordinal)
    {
        "stepType", "agentVersion", "eventTime", "consequential", "timestamp", "objectKinds",
        "agentIdentityEvidenceId", "assuranceProfile", "timestampPolicy", "finalSeq", "finalPrevSignatureSha256",
        "runDisposition", "recordType", "agentId", "configSha256", "registeredBy", "delegation", "parentRun",
    };

    /// <summary>
    /// The configuration digest (§3.6): SHA-256 over the JCS of the
    /// configuration objects' SHA-256 digests (<c>modelConfig</c> only when
    /// bound). One value identifies one agent configuration; a changed
    /// configuration needs a new identity record.
    /// </summary>
    public static string ConfigurationDigest(byte[] agentManifest, AgentConfiguration configuration)
    {
        if (agentManifest is null) throw new ArgumentNullException(nameof(agentManifest));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));
        return ConfigurationDigestFromHex(
            EnvelopeHashing.HashHex(agentManifest), EnvelopeHashing.HashHex(configuration.InstructionSet),
            EnvelopeHashing.HashHex(configuration.ToolManifest),
            configuration.ModelConfig is { } mc ? EnvelopeHashing.HashHex(mc) : null,
            EnvelopeHashing.HashHex(configuration.ExecutionPolicy));
    }

    internal static string ConfigurationDigestFromHex(
        string manifest, string instructionSet, string toolManifest, string? modelConfig, string executionPolicy)
    {
        var digests = new JsonObject
        {
            ["agentManifest"]   = manifest,
            ["instructionSet"]  = instructionSet,
            ["toolManifest"]    = toolManifest,
            ["executionPolicy"] = executionPolicy,
        };
        if (modelConfig is not null) digests["modelConfig"] = modelConfig;
        return EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(digests));
    }

    /// <summary>The configuration as detached objects, in a fixed order.</summary>
    internal static List<AgentRunObject> ConfigurationObjects(AgentConfiguration c)
    {
        var objects = new List<AgentRunObject>
        {
            new() { Kind = "instruction-set", Role = "input", ContentType = "text/plain",       Bytes = c.InstructionSet },
            new() { Kind = "tool-manifest",   Role = "input", ContentType = "application/json", Bytes = c.ToolManifest },
        };
        if (c.ModelConfig is { } mc)
            objects.Add(new AgentRunObject { Kind = "model-config", Role = "input", ContentType = "application/json", Bytes = mc });
        objects.Add(new AgentRunObject { Kind = "execution-policy", Role = "input", ContentType = "application/json", Bytes = c.ExecutionPolicy });
        return objects;
    }

    // ── internals shared by the recorder and the verifier ────────────────────

    internal const string EnvelopeUri = AiEvidenceV2Artifact.EnvelopeUri;

    internal static bool TryString(JsonNode? node, out string value)
    {
        value = "";
        if (node is JsonValue v && v.TryGetValue<string>(out var s)) { value = s; return true; }
        return false;
    }

    internal static string? Str(JsonNode? node) => TryString(node, out var s) ? s : null;

    internal static int? Int(JsonNode? node)
    {
        if (node is not JsonValue v) return null;
        if (v.TryGetValue<int>(out var i)) return i;
        if (v.TryGetValue<long>(out var l) && l is >= int.MinValue and <= int.MaxValue) return (int)l;
        if (v.TryGetValue<double>(out var d) && d == Math.Floor(d) && d is >= int.MinValue and <= int.MaxValue) return (int)d;
        return null;
    }

    internal static bool IsTrue(JsonNode? node) => node is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    private static readonly Regex Base64UrlAlphabet = new("^[A-Za-z0-9_-]*$", RegexOptions.CultureInvariant);
    private static readonly BigInteger IJsonMaxInt = BigInteger.Pow(2, 53);

    /// <summary>Strict base64url: no padding, nothing outside the alphabet (§4).</summary>
    internal static byte[] Base64UrlDecode(string s)
    {
        if (!Base64UrlAlphabet.IsMatch(s) || s.Length % 4 == 1) throw new FormatException("not base64url");
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }

    /// <summary>The millisecond precision <c>eventTime</c> is signed with (§6.7).</summary>
    internal static DateTimeOffset Truncate(DateTimeOffset t) =>
        new(t.Ticks - t.Ticks % TimeSpan.TicksPerMillisecond, t.Offset);

    /// <summary>§8: <c>urn:uuid:</c> and bare forms of the same UUID compare equal.</summary>
    internal static string? NormId(string? v)
    {
        if (v is null) return null;
        if (v.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase)) v = v.Substring(9);
        return v.ToLowerInvariant();
    }

    /// <summary>No integers beyond ±2^53 and no lone surrogates (§7). Never throws: unreadable is not I-JSON.</summary>
    internal static bool IsIJson(JsonNode? node)
    {
        try { return IsIJsonCore(node); }
        catch (InvalidOperationException) { return false; } // e.g. a lone surrogate the reader refuses to decode
    }

    private static bool IsIJsonCore(JsonNode? node)
    {
        switch (node)
        {
            case null: return true;
            case JsonObject o:
                foreach (var kv in o) if (!IsIJsonString(kv.Key) || !IsIJsonCore(kv.Value)) return false;
                return true;
            case JsonArray a:
                foreach (var x in a) if (!IsIJsonCore(x)) return false;
                return true;
        }
        var v = (JsonValue)node;
        if (v.TryGetValue<JsonElement>(out var el))
            return el.ValueKind switch
            {
                JsonValueKind.String => IsIJsonString(el.GetString()!),
                JsonValueKind.Number => IsIJsonNumber(el.GetRawText()),
                _ => true,
            };
        if (v.TryGetValue<string>(out var s)) return IsIJsonString(s);
        if (v.TryGetValue<long>(out var l)) return BigInteger.Abs(l) <= IJsonMaxInt;
        if (v.TryGetValue<ulong>(out var ul)) return ul <= (ulong)IJsonMaxInt;
        if (v.TryGetValue<decimal>(out var m)) return m != decimal.Floor(m) || BigInteger.Abs(new BigInteger(m)) <= IJsonMaxInt;
        return true;
    }

    private static bool IsIJsonNumber(string raw)
    {
        if (raw.IndexOfAny(new[] { '.', 'e', 'E' }) >= 0) return true; // a fraction or exponent: not an integer literal
        return BigInteger.TryParse(raw, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n)
            && BigInteger.Abs(n) <= IJsonMaxInt;
    }

    private static bool IsIJsonString(string s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            if (char.IsHighSurrogate(s[i]))
            {
                if (i + 1 >= s.Length || !char.IsLowSurrogate(s[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(s[i])) return false;
        }
        return true;
    }

    internal static string FormatTime(DateTimeOffset t) =>
        t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    internal static byte[] Canonical(JsonNode node) => JsonCanonicalizer.Canonicalize(node.ToJsonString());

    /// <summary>
    /// The §5 coverage rule, walked in seq order. Used by the recorder to
    /// decide which steps it must timestamp and by the verifier to recompute
    /// the same decision from the signed policy — one implementation, so the
    /// two can never drift apart.
    /// </summary>
    internal sealed class TimestampCoverage
    {
        private readonly string _profile;
        private readonly int _everyEvents;
        private readonly int _everySeconds;
        private readonly bool _runStart;
        private int _sinceStamp;
        private DateTimeOffset? _lastStampTime;

        /// <summary>A copy, so a decision can be committed only once the step is sealed.</summary>
        public TimestampCoverage Clone() => (TimestampCoverage)MemberwiseClone();

        public TimestampCoverage(string profile, int everyEvents, int everySeconds, bool runStart)
        {
            _profile = profile; _everyEvents = everyEvents; _everySeconds = everySeconds; _runStart = runStart;
        }

        public bool Next(int seq, string stepType, bool consequential, bool declaredRequired, DateTimeOffset? eventTime)
        {
            var required = _profile == "per-event"
                || stepType is "run_end" or "checkpoint"
                || consequential
                || (seq == 0 && _runStart)
                || (_everyEvents > 0 && _sinceStamp + 1 >= _everyEvents)
                || (_everySeconds > 0 && seq > 0 && _lastStampTime is { } last && eventTime is { } at
                    && (at - last).TotalSeconds >= _everySeconds)
                || declaredRequired;
            if (required) { _sinceStamp = 0; _lastStampTime = eventTime; }
            else _sinceStamp++;
            if (seq == 0 && _lastStampTime is null) _lastStampTime = eventTime;
            return required;
        }
    }

    /// <summary>Builds one profile envelope (§2). Object kinds go into the signed profile block.</summary>
    internal static JsonObject BuildEnvelope(
        string evidenceId, DateTimeOffset createdAt, string purposeCategory, AgentDefinition agent,
        string activityName, string? correlationId, string? parentEvidenceId,
        IReadOnlyList<AgentRunObject> objects, int? chainSeq, string? prevChainDigest, JsonObject profileBlock)
    {
        var activity = new JsonObject { ["name"] = activityName };
        if (correlationId is not null) activity["correlationId"] = correlationId;
        if (parentEvidenceId is not null) activity["parentEvidenceId"] = parentEvidenceId;

        var purpose = new JsonObject { ["category"] = purposeCategory };
        if (agent.BusinessContext is not null) purpose["businessContext"] = agent.BusinessContext;

        var actor = new JsonObject { ["type"] = "agent", ["id"] = agent.AgentId };
        if (agent.TenantId is not null) actor["tenantId"] = agent.TenantId;

        var model = new JsonObject { ["provider"] = agent.Model.Provider, ["name"] = agent.Model.Name };
        if (agent.Model.DeploymentId is not null) model["deploymentId"] = agent.Model.DeploymentId;

        var objs = new JsonArray();
        var kinds = new JsonObject();
        foreach (var o in objects)
        {
            objs.Add(new JsonObject
            {
                ["uri"] = o.Uri, ["role"] = o.Role, ["contentType"] = o.ContentType, ["sizeBytes"] = o.Bytes.Length,
            });
            kinds[o.Uri] = o.Kind;
        }
        profileBlock["objectKinds"] = kinds;

        var env = new JsonObject
        {
            ["schemaName"]    = "AiEvidenceEnvelope",
            ["schemaVersion"] = "2",
            ["evidenceId"]    = evidenceId,
            ["createdAt"]     = FormatTime(createdAt),
            ["purpose"]       = purpose,
            ["actor"]         = actor,
            ["activity"]      = activity,
            ["model"]         = model,
            ["objects"]       = objs,
        };
        if (chainSeq is int seq)
        {
            var chain = new JsonObject { ["seq"] = seq };
            if (prevChainDigest is not null) chain["prevSignatureSha256"] = prevChainDigest;
            env["chain"] = chain;
        }
        env["extensions"] = new JsonObject { [ExtensionKey] = profileBlock };
        return env;
    }

    /// <summary>The default agent manifest bytes (JCS) when the definition supplies none.</summary>
    internal static byte[] DefaultManifest(AgentDefinition agent)
    {
        var model = new JsonObject { ["provider"] = agent.Model.Provider, ["name"] = agent.Model.Name };
        if (agent.Model.DeploymentId is not null) model["deploymentId"] = agent.Model.DeploymentId;
        var manifest = new JsonObject
        {
            ["agentId"] = agent.AgentId,
            ["agentVersion"] = agent.AgentVersion,
            ["model"] = model,
        };
        if (agent.DisplayName is not null) manifest["displayName"] = agent.DisplayName;
        return Canonical(manifest);
    }
}
