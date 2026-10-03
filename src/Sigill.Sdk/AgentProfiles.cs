// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sigill.Sdk.Internal;

namespace Sigill.Sdk;

/// <summary>
/// Constants and the normative digests of the Agent Evidence Profiles v1
/// (<c>spec/agent-profiles-common-v1.md</c>): the binding digest (§2) and the
/// signer (§3). Recording and verification build on these; they are public so
/// other producers and verifiers can reproduce them.
/// </summary>
public static class AgentProfiles
{
    /// <summary>The bundle's <c>format</c> value (§7).</summary>
    public const string BundleFormat = "AgentRunBundle";

    /// <summary>The bundle format version.</summary>
    public const string BundleVersion = "1";

    public const string ControlArtifactSchema = "AgentControlArtifact";
    public const string ExecutionEvidenceSchema = "AgentExecutionEvidence";
    public const string ControlEvaluationSchema = "ControlEvaluation";

    /// <summary>The Control Artifact's content type, signed as <c>sigD.ctys[0]</c>.</summary>
    public const string ControlArtifactContentType = "application/vnd.sigill.agent-control+json";
    public const string ExecutionEvidenceContentType = "application/vnd.sigill.agent-execution+json";
    public const string ControlEvaluationContentType = "application/vnd.sigill.control-evaluation+json";

    /// <summary>
    /// The binding digest of an artifact (§2): lowercase SHA-256 hex over the
    /// base64url-decoded JWS Signature Value of its classical signature — the
    /// first <c>signatures[]</c> entry whose protected <c>alg</c> is not ML-DSA,
    /// or the <c>signature</c> member of a flattened JWS. Unprotected headers
    /// are excluded. Null when the JWS carries no usable classical signature.
    /// </summary>
    public static string? SignatureSha256(JsonObject signature)
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
    /// The signer of an artifact (§3): the <c>x5t#S256</c> of its single
    /// classical signature, or null and the reason it cannot be established.
    /// Requires exactly one classical entry whose protected header carries
    /// <c>x5c</c> and an <c>x5t#S256</c> equal to the SHA-256 of <c>x5c[0]</c>.
    /// This names the signer; it proves it together with a signature check
    /// against that same <c>x5c[0]</c>.
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

    /// <summary>Every non-ML-DSA entry, with its protected header (null when unreadable — it still counts, §2).</summary>
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
                // A repeated member name makes the header unreadable (§1): parsers disagree on which value wins.
                // JsonNode builds its dictionary lazily, so check with JsonDocument before materializing anything.
                // §1 applies to the header too: strict UTF-8, no repeated names, I-JSON throughout.
                if (TryString(entry["protected"], out var prot))
                {
                    var text = StrictUtf8.GetString(Base64UrlDecode(prot));
                    using (var doc = JsonDocument.Parse(text))
                        if (FindDuplicateName(doc.RootElement) is null && JsonNode.Parse(text) is JsonObject parsed && IsIJson(parsed))
                            header = parsed;
                }
            }
            catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException) { /* unreadable */ }
            if (Str(header?["alg"]) is { } alg && alg.StartsWith("ML-DSA", StringComparison.OrdinalIgnoreCase)) continue;
            result.Add((entry, header));
        }
        return result;
    }

    /// <summary>The first member name repeated anywhere in the element (I-JSON forbids them), or null.</summary>
    internal static string? FindDuplicateName(JsonElement e)
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

    // ── internals shared by the recorder and the verifier ────────────────────

    internal const string EnvelopeUri = AiEvidenceV2Artifact.EnvelopeUri;

    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    internal static bool TryString(JsonNode? node, out string value)
    {
        value = "";
        if (node is JsonValue v && v.TryGetValue<string>(out var s)) { value = s; return true; }
        return false;
    }

    internal static string? Str(JsonNode? node) => TryString(node, out var s) ? s : null;

    internal static int? Int(JsonNode? node)
    {
        if (node is not JsonValue v || v.TryGetValue<bool>(out _)) return null;
        if (v.TryGetValue<int>(out var i)) return i;
        if (v.TryGetValue<long>(out var l) && l is >= int.MinValue and <= int.MaxValue) return (int)l;
        if (v.TryGetValue<double>(out var d) && d == Math.Floor(d) && d is >= int.MinValue and <= int.MaxValue) return (int)d;
        return null;
    }

    internal static bool IsTrue(JsonNode? node) => node is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    private static readonly Regex Base64UrlAlphabet = new("^[A-Za-z0-9_-]*$", RegexOptions.CultureInvariant);
    private static readonly BigInteger IJsonMaxInt = BigInteger.Pow(2, 53);

    /// <summary>Strict base64url: no padding, nothing outside the alphabet (§2).</summary>
    internal static byte[] Base64UrlDecode(string s)
    {
        if (!Base64UrlAlphabet.IsMatch(s) || s.Length % 4 == 1) throw new FormatException("not base64url");
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }

    /// <summary>The millisecond precision <c>eventTime</c> is signed with (§4).</summary>
    internal static DateTimeOffset Truncate(DateTimeOffset t) =>
        new(t.Ticks - t.Ticks % TimeSpan.TicksPerMillisecond, t.Offset);

    internal static string FormatTime(DateTimeOffset t) =>
        t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    internal static byte[] Canonical(JsonNode node) => JsonCanonicalizer.Canonicalize(node.ToJsonString());

    /// <summary>No integers beyond ±2^53 and no lone surrogates (§1). Never throws: unreadable is not I-JSON.</summary>
    internal static bool IsIJson(JsonNode? node)
    {
        try { return IsIJsonCore(node); }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            return false; // a lone surrogate the reader refuses to decode, or a duplicate name JsonObject refuses to hold
        }
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
        if (v.TryGetValue<double>(out var d)) return !double.IsNaN(d) && !double.IsInfinity(d);
        if (v.TryGetValue<float>(out var f)) return !float.IsNaN(f) && !float.IsInfinity(f);
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

    /// <summary>
    /// The §4 coverage rule, walked in seq order. Used by the recorder to
    /// decide which events it must timestamp and by the verifier to recompute
    /// the same decision from the signed policy — one implementation, so the
    /// two can never drift apart.
    /// </summary>
    internal sealed class TimestampCoverage
    {
        private readonly AgentTimestampPolicy? _policy;
        private int _sinceStamp;
        private DateTimeOffset? _lastStampTime;

        /// <param name="policy">The signed policy; null when unknown (no Control Artifact): only run_end and declared events.</param>
        public TimestampCoverage(AgentTimestampPolicy? policy) => _policy = policy;

        /// <summary>A copy, so a decision can be committed only once the event is sealed.</summary>
        public TimestampCoverage Clone() => (TimestampCoverage)MemberwiseClone();

        public bool Next(int seq, string stepType, bool consequential, bool declaredRequired, DateTimeOffset? eventTime)
        {
            var p = _policy;
            var required = stepType == "run_end"
                || declaredRequired
                || (p is not null && (p.Profile == "per-event"
                    || (p.Consequential && consequential)
                    || (p.EveryEvents > 0 && _sinceStamp + 1 >= p.EveryEvents)
                    || (p.EverySeconds > 0 && seq > 0 && _lastStampTime is { } last && eventTime is { } at
                        && (at - last).TotalSeconds >= p.EverySeconds)));
            if (required) { _sinceStamp = 0; _lastStampTime = eventTime; }
            else _sinceStamp++;
            if (seq == 0 && _lastStampTime is null) _lastStampTime = eventTime;
            return required;
        }
    }
}
