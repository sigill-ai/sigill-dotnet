// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sigill.Sdk;

/// <summary>
/// One content payload of an AI evidence v2 record. The bytes NEVER leave the
/// machine — the SDK hashes them locally and transmits digests only (the blind
/// contract, spec §7.1/§8). URIs are opaque identifiers; when omitted the SDK
/// generates a <c>urn:uuid:</c> — the normative choice for remote paths (spec
/// §3.1): human-meaningful names (filenames, paths) belong in
/// <see cref="Metadata"/>, which stays inside the envelope.
/// </summary>
public sealed record AiEvidenceV2Payload
{
    /// <summary>prompt | input | context | output | artifact | log.</summary>
    public required string Role { get; init; }

    /// <summary>The payload bytes as fed to / produced by the model. Hashed locally, never transmitted.</summary>
    public required byte[] Bytes { get; init; }

    /// <summary>Opaque URI identifying the payload. Default: a generated <c>urn:uuid:</c>.</summary>
    public string? Uri { get; init; }

    /// <summary>MIME type, e.g. <c>text/plain</c>. Plain type/subtype only — it is persisted by Sigill.</summary>
    public string? ContentType { get; init; }

    /// <summary>"utf-8" for text serialized as UTF-8, "binary" for raw file bytes (spec §3.1).</summary>
    public string? Encoding { get; init; }

    /// <summary>Free-form payload metadata (rank/score/source for RAG context, filenames, …). Stays in the envelope.</summary>
    public JsonObject? Metadata { get; init; }
}

/// <summary>Options for <see cref="ISigillAiEvidenceClient.SealEvidenceV2Async"/>.</summary>
public sealed record EvidenceV2SealOptions
{
    /// <summary>Request an eIDAS-qualified signature timestamp.</summary>
    public bool Qualified { get; init; }

    /// <summary>Add the ML-DSA-87 hybrid signer; SHA-512 digests are computed and sent alongside.</summary>
    public bool Pqc { get; init; }

    /// <summary>Label stored in the Sigill operation log. Keep it opaque — it rests server-side.</summary>
    public string? Label { get; init; }

    /// <summary>Evidence tags attached at creation (max 10 × 40 chars).</summary>
    public IReadOnlyList<string>? Tags { get; init; }

    /// <summary>"inherit" (default) | "on" | "off" — renewal reminder override.</summary>
    public string? Reminders { get; init; }

    /// <summary>Reminder horizon in days, when <see cref="Reminders"/> is "on".</summary>
    public int? ReminderDays { get; init; }
}

/// <summary>
/// The self-contained AI evidence v2 artifact: <c>{ envelope, signature }</c>
/// (spec §6). Always assembled client-side — Sigill returns the JAdES JWS and
/// has never seen the envelope.
/// </summary>
public sealed class AiEvidenceV2Artifact
{
    /// <summary>The reserved sigD URI of the envelope (object 0).</summary>
    public const string EnvelopeUri = "urn:sigill:envelope";

    /// <summary>The artifact media type / default envelope cty.</summary>
    public const string MediaType = "application/vnd.sigill.ai-evidence+json";

    /// <summary>The v2 envelope — the signed metadata document.</summary>
    public JsonObject Envelope { get; }

    /// <summary>The JAdES signature (General JWS JSON Serialization).</summary>
    public JsonObject Signature { get; }

    /// <summary>SHA-256 hex of the RFC 8785 canonical envelope — the signed hashV[0] and the operation's document hash.</summary>
    public string EnvelopeHashHex { get; }

    public AiEvidenceV2Artifact(JsonObject envelope, JsonObject signature, string envelopeHashHex)
    {
        Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        EnvelopeHashHex = envelopeHashHex;
    }

    /// <summary>Serialize the artifact file (<c>*.ai-evidence.json</c>).</summary>
    public string ToJsonString(bool indented = true) =>
        new JsonObject { ["envelope"] = Envelope.DeepClone(), ["signature"] = Signature.DeepClone() }
            .ToJsonString(new JsonSerializerOptions { WriteIndented = indented });

    /// <summary>Load a previously produced artifact. Recomputes the envelope digest with the SDK canonicalizer.</summary>
    public static AiEvidenceV2Artifact Parse(string json)
    {
        var root = JsonNode.Parse(json) as JsonObject
            ?? throw new SigillException("Artifact is not a JSON object.");
        if (root["envelope"] is not JsonObject env || root["signature"] is not JsonObject sig)
            throw new SigillException("Artifact must carry 'envelope' and 'signature' members.");
        var hex = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(env));
        return new AiEvidenceV2Artifact(env, sig, hex);
    }
}

/// <summary>Per-object verdict from blind object-level verification.</summary>
public sealed record EvidenceV2ObjectVerdict(
    string Uri,
    string? ContentType,
    bool Supplied,
    bool HashMatch);

/// <summary>
/// Compound result of <see cref="ISigillAiEvidenceClient.VerifyEvidenceV2Async"/>:
/// the platform's cryptographic verdicts (blind — it saw digests only) plus the
/// envelope-layer checks that are the SDK's job (spec §7.1): role coverage and
/// envelope/sigD alignment.
/// </summary>
public sealed record EvidenceV2VerificationResult
{
    /// <summary>The winning classical signature verifies cryptographically.</summary>
    public required bool SignatureValid { get; init; }

    /// <summary>The record-keeping verdict: signature valid ∧ every signed object supplied and
    /// matched ∧ (for hybrid seals) the ML-DSA commitment verified.</summary>
    public required bool Complete { get; init; }

    /// <summary>absent | verified | failed | not_checked — the hybrid dimension (spec §7).</summary>
    public required string Pqc { get; init; }

    public required int ObjectCount { get; init; }
    public required int SuppliedCount { get; init; }
    public required int MatchedCount { get; init; }

    public required IReadOnlyList<EvidenceV2ObjectVerdict> Objects { get; init; }

    /// <summary>Signed URIs no digest was supplied for.</summary>
    public required IReadOnlyList<string> Missing { get; init; }

    /// <summary>Supplied URIs the signature never signed — flagged, never silently accepted.</summary>
    public required IReadOnlyList<string> Unreferenced { get; init; }

    /// <summary>The envelope's objects[] URIs align 1:1, in order, with the signed pars[1…] (spec §5.2).</summary>
    public required bool AlignmentOk { get; init; }

    /// <summary>Required roles (when requested) that are absent from the envelope or whose payload did not verify.</summary>
    public required IReadOnlyList<string> MissingRoles { get; init; }

    /// <summary>Envelope-layer + platform issues, human-readable. Empty when everything holds.</summary>
    public required IReadOnlyList<string> Issues { get; init; }

    /// <summary>The full platform response, for diagnostics and rendering.</summary>
    public required JsonObject Raw { get; init; }

    /// <summary>The single answer: complete ∧ aligned ∧ required roles covered.</summary>
    public bool Ok => Complete && AlignmentOk && MissingRoles.Count == 0;
}
