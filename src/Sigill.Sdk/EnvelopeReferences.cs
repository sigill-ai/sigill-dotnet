// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
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

    /// <summary><c>sigD.pars[0]</c> of the first classical signature entry, or null (see <see cref="SignedPars"/>).</summary>
    internal static string? EnvelopeReferenceOf(JsonObject signature) => SignedPars(signature)?.FirstOrDefault();

    /// <summary>
    /// <c>sigD.pars</c> of the first classical signature entry — the one a signature service verifies — in signed
    /// order; null when that entry's header is unreadable or its <c>pars</c> is not an array of strings. That a JWS
    /// carries exactly one classical entry is a separate check (common rules §2).
    /// </summary>
    internal static System.Collections.Generic.List<string>? SignedPars(JsonObject signature)
    {
        var classical = AgentProfiles.ClassicalEntries(signature);
        if (classical.Count == 0 || classical[0].Header?["sigD"] is not JsonObject sigD) return null;
        if (sigD["pars"] is not JsonArray pars) return null;
        var list = new System.Collections.Generic.List<string>();
        foreach (var p in pars)
        {
            if (p is not JsonValue v || !v.TryGetValue<string>(out var s)) return null;
            list.Add(s);
        }
        return list;
    }

    /// <summary>
    /// The key under which a verifier supplies the envelope digest for <paramref name="signature"/>: the reference
    /// it carries when that is one of the two, otherwise the locator reference — an unknown name is never trusted,
    /// so the envelope then reads as not covered.
    /// </summary>
    internal static string DigestKeyFor(JsonObject signature)
    {
        var r = EnvelopeReferenceOf(signature) ?? LenientEnvelopeReference(signature);
        return r is not null && Classify(r) != EnvelopeReferenceForm.Invalid ? r : LocatorReference;
    }

    /// <summary>
    /// <c>sigD.pars[0]</c> of the first classical entry read leniently — a repeated member name: the last value
    /// wins — as a lenient signature service reads a header the profile layer refuses. Only for choosing the digest
    /// key; refusing such a header stays the signer check's job (common rules §1, §3).
    /// </summary>
    private static string? LenientEnvelopeReference(JsonObject signature)
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
