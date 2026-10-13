// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;

namespace Sigill.Sdk;

/// <summary>The form of a seal's envelope reference, <c>sigD.pars[0]</c> (AiEvidenceEnvelopeV2 §5.2 rule 2).</summary>
public enum EnvelopeReferenceForm
{
    /// <summary>Neither envelope reference: the signature does not name an envelope.</summary>
    Invalid,

    /// <summary><c>sigill-envelope.json</c> — the v2.1 locator reference new seals carry.</summary>
    Locator,

    /// <summary><c>urn:sigill:envelope</c> — the v2.0 reference; retained for compatibility, not locator form.</summary>
    LegacyUrn,
}

/// <summary>
/// The <c>sigD.pars</c> reference rules of AiEvidenceEnvelopeV2 v2.1 (§3.1, §5.2, §5.4). One place for every
/// reader and every producer in this SDK: the envelope reference is classified from the signature being verified,
/// never from configuration, and the two accepted values are exact strings, never aliases.
/// </summary>
public static class EnvelopeReferences
{
    /// <summary>The envelope reference new seals carry (v2.1).</summary>
    public const string LocatorReference = "sigill-envelope.json";

    /// <summary>The envelope reference of seals made before v2.1.</summary>
    public const string LegacyReference = "urn:sigill:envelope";

    /// <summary>The explanatory diagnostic for a legacy envelope reference (§5.4). Never a warning.</summary>
    public const string LegacyDiagnostic = "legacy URN envelope reference; retained for compatibility, not locator form";

    /// <summary>Classifies a <c>sigD.pars[0]</c> value by exact string match.</summary>
    public static EnvelopeReferenceForm Classify(string? pars0) => pars0 switch
    {
        LocatorReference => EnvelopeReferenceForm.Locator,
        LegacyReference => EnvelopeReferenceForm.LegacyUrn,
        _ => EnvelopeReferenceForm.Invalid,
    };

    /// <summary>Both envelope references are reserved: neither may name an object (§3.1).</summary>
    public static bool IsReserved(string? uri) => uri is LocatorReference or LegacyReference;

    /// <summary>A new opaque object URI in the production profile: <c>objects/&lt;uuid&gt;</c>.</summary>
    public static string NewObjectUri() => "objects/" + Guid.NewGuid().ToString("D");

    /// <summary>
    /// Whether <paramref name="uri"/> matches the §3.1 production reference profile — Sigill's deliberately narrower
    /// subset of relative references: non-empty segments of <c>A–Z a–z 0–9 . _ ~ -</c>, separated by single
    /// <c>/</c>, no <c>.</c> or <c>..</c> segment. Governs what a producer emits; never applied to historical
    /// evidence.
    /// </summary>
    public static bool IsProductionReference(string? uri)
    {
        if (string.IsNullOrEmpty(uri)) return false;
        foreach (var segment in uri!.Split('/'))
        {
            if (segment.Length == 0 || segment == "." || segment == "..") return false;
            foreach (var c in segment)
                if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '~' or '-'))
                    return false;
        }
        return true;
    }

    /// <summary>Throws unless <paramref name="uri"/> may be emitted as a NEW object URI.</summary>
    internal static void RequireEmittable(string uri)
    {
        if (IsReserved(uri))
            throw new SigillException($"'{uri}' is reserved for the envelope itself.");
        if (!IsProductionReference(uri))
            throw new SigillException(
                $"Object URI '{uri}' is not a production-profile reference (AiEvidenceEnvelopeV2 §3.1): use relative " +
                "segments of A–Z a–z 0–9 . _ ~ - separated by '/', e.g. objects/<uuid>. Omit the URI to have one generated.");
    }

    /// <summary>
    /// <c>sigD.pars</c> of the signature's ONLY classical entry, in signed order — the strict view every success
    /// decision uses. Null unless there is exactly one classical entry, its protected header passes the strict
    /// reading (§1: strict UTF-8, no repeated member names, I-JSON) and <c>pars</c> is an array of strings.
    /// </summary>
    internal static List<string>? StrictSignedPars(JsonObject signature)
    {
        var classical = AgentProfiles.ClassicalEntries(signature);
        return classical.Count == 1 ? ParsOf(classical[0].Header) : null;
    }

    /// <summary>
    /// The envelope reference of a structurally valid signature (<see cref="StrictSignedPars"/>), when it is one of
    /// the two; otherwise null. Only this establishes a valid envelope form.
    /// </summary>
    internal static string? StrictEnvelopeReference(JsonObject signature) =>
        StrictSignedPars(signature)?.FirstOrDefault() is { } r && Classify(r) != EnvelopeReferenceForm.Invalid ? r : null;

    /// <summary>
    /// The key under which a verifier supplies the envelope digest. From the strict view when it yields one of the
    /// two references; otherwise the locator reference — a fallback key never establishes a valid form.
    /// <paramref name="lenient"/> (agent-run verification only): when the strict view fails, read <c>pars[0]</c> of
    /// the FIRST classical entry the way a lenient signature service does (repeated member: the last value wins),
    /// so the cryptographic dimension is still reported; that run's signer and verdict fail on their own (common
    /// rules §1–§3) and the key is never treated as a valid form.
    /// </summary>
    internal static string DigestKeyFor(JsonObject signature, bool lenient)
    {
        if (StrictEnvelopeReference(signature) is { } strict) return strict;
        if (lenient && LenientFirstEnvelopeReference(signature) is { } r && Classify(r) != EnvelopeReferenceForm.Invalid) return r;
        return LocatorReference;
    }

    /// <summary>
    /// True when an ML-DSA entry carries a <c>sigD</c> whose <c>pars</c> differ from the classical entry's (v2 §5.2
    /// rule 5: byte-identical, including the envelope reference form). An ML-DSA entry without a readable
    /// <c>sigD</c> is left to the cryptographic tier.
    /// </summary>
    internal static bool PqcParsMismatch(JsonObject signature)
    {
        var classical = StrictSignedPars(signature);
        if (classical is null || signature["signatures"] is not JsonArray entries) return false;
        foreach (var e in entries.OfType<JsonObject>())
        {
            var header = ReadHeader(e);
            if (header is null || header["alg"] is not JsonValue a || !a.TryGetValue<string>(out var alg)
                || !alg.StartsWith("ML-DSA", StringComparison.OrdinalIgnoreCase))
                continue;
            if (header["sigD"] is null) continue;
            var pqc = ParsOf(header);
            if (pqc is null || !pqc.SequenceEqual(classical, StringComparer.Ordinal)) return true;
        }
        return false;
    }

    private static List<string>? ParsOf(JsonObject? header)
    {
        if (header?["sigD"] is not JsonObject sigD || sigD["pars"] is not JsonArray pars) return null;
        var list = new List<string>();
        foreach (var p in pars)
        {
            if (p is not JsonValue v || !v.TryGetValue<string>(out var s)) return null;
            list.Add(s);
        }
        return list;
    }

    private static JsonObject? ReadHeader(JsonObject entry)
    {
        if (entry["protected"] is not JsonValue pv || !pv.TryGetValue<string>(out var prot)) return null;
        try { return JsonNode.Parse(AgentProfiles.Base64UrlDecode(prot)) as JsonObject; }
        catch (Exception e) when (e is System.Text.Json.JsonException or FormatException or ArgumentException) { return null; }
    }

    private static string? LenientFirstEnvelopeReference(JsonObject signature)
    {
        var classical = AgentProfiles.ClassicalEntries(signature);
        if (classical.Count == 0 || classical[0].Entry["protected"] is not JsonValue pv || !pv.TryGetValue<string>(out var prot))
            return null;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(AgentProfiles.Base64UrlDecode(prot));
            static System.Text.Json.JsonElement? Last(System.Text.Json.JsonElement o, string name)
            {
                System.Text.Json.JsonElement? hit = null;
                if (o.ValueKind != System.Text.Json.JsonValueKind.Object) return null;
                foreach (var p in o.EnumerateObject()) if (p.NameEquals(name)) hit = p.Value;
                return hit;
            }
            if (Last(doc.RootElement, "sigD") is { } sigD && Last(sigD, "pars") is { ValueKind: System.Text.Json.JsonValueKind.Array } pars
                && pars.GetArrayLength() > 0 && pars[0].ValueKind == System.Text.Json.JsonValueKind.String)
                return pars[0].GetString();
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or FormatException or ArgumentException) { }
        return null;
    }
}
