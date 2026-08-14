// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace Sigill.Sdk;

/// <summary>
/// One detached object of a blind multi-object seal: an opaque URI-reference
/// and the digest(s) of the object bytes, computed by the caller. Content
/// never travels — this is the digests-in tier beneath the AI-evidence
/// profile, for sibling profiles that hold hashes rather than bytes
/// (spec §2, §12). URIs must carry no personal data (opaque URNs).
/// </summary>
public sealed record SignedObjectDigest
{
    /// <summary>Opaque URI identifying the object (byte-exact unique; <c>urn:sigill:envelope</c> is reserved).</summary>
    public required string Uri { get; init; }

    /// <summary>SHA-256 of the object bytes, lowercase hex.</summary>
    public required string HashHex { get; init; }

    /// <summary>SHA-512 of the same bytes — required for every object when <see cref="ObjectSignOptions.Pqc"/>.</summary>
    public string? HashHex512 { get; init; }

    /// <summary>MIME type persisted as the object's signed <c>ctys</c> entry. Plain type/subtype only.</summary>
    public string? ContentType { get; init; }
}

/// <summary>Options for <see cref="ISigillAiEvidenceClient.SignObjectHashesAsync"/>.</summary>
public sealed record ObjectSignOptions
{
    /// <summary>
    /// Content type of object 0 (the profile discriminator, spec §5.2). When
    /// omitted the platform applies the AI-evidence default; sibling profiles
    /// supply their own. Plain type/subtype, no parameters, max 255 chars.
    /// </summary>
    public string? EnvelopeContentType { get; init; }

    /// <summary>SHA-512 of the canonical envelope — required when <see cref="Pqc"/>.</summary>
    public string? EnvelopeHashHex512 { get; init; }

    /// <summary>Request an eIDAS-qualified signature timestamp.</summary>
    public bool Qualified { get; init; }

    /// <summary>Add the ML-DSA-87 hybrid signer; SHA-512 digests must be supplied throughout.</summary>
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
/// Result of a blind multi-object signing call: the JAdES signature (General
/// JWS JSON Serialization) plus the operation identity. The caller assembles
/// its own artifact — no artifact ever exists server-side.
/// </summary>
public sealed record SignHashesResult
{
    /// <summary>The JAdES signature over the multi-object sigD.</summary>
    public required JsonObject Signature { get; init; }

    /// <summary>The seal operation id in the Sigill ledger.</summary>
    public required System.Guid OperationId { get; init; }

    /// <summary>e.g. <c>jades-b-t</c>.</summary>
    public string? Format { get; init; }

    /// <summary>TSA that timestamped the signature, when reported.</summary>
    public string? TimestampedBy { get; init; }

    /// <summary>The signature timestamp is eIDAS-qualified.</summary>
    public bool Qualified { get; init; }

    /// <summary>The seal carries the ML-DSA-87 hybrid signer.</summary>
    public bool Pqc { get; init; }
}

/// <summary>Per-object verdict from blind object-level verification.</summary>
public sealed record SignedObjectVerdict(
    string Uri,
    string? ContentType,
    bool Supplied,
    bool HashMatch);

/// <summary>
/// Result of <see cref="ISigillAiEvidenceClient.VerifyObjectHashesAsync"/> —
/// the platform's cryptographic verdicts over a multi-object seal, profile
/// agnostic. Envelope-layer checks (schema, alignment, role coverage) are the
/// calling profile's job on its own copy of the envelope.
/// </summary>
public sealed record ObjectsVerificationResult
{
    /// <summary>The winning classical signature verifies cryptographically.</summary>
    public required bool SignatureValid { get; init; }

    /// <summary>Signature valid ∧ every signed object supplied and matched ∧
    /// (for hybrid seals) the ML-DSA commitment verified.</summary>
    public required bool Complete { get; init; }

    /// <summary>absent | verified | failed | not_checked — the hybrid dimension.</summary>
    public required string Pqc { get; init; }

    public required int ObjectCount { get; init; }
    public required int SuppliedCount { get; init; }
    public required int MatchedCount { get; init; }

    public required IReadOnlyList<SignedObjectVerdict> Objects { get; init; }

    /// <summary>Signed URIs no digest was supplied for.</summary>
    public required IReadOnlyList<string> Missing { get; init; }

    /// <summary>Supplied URIs the signature never signed — flagged, never silently accepted.</summary>
    public required IReadOnlyList<string> Unreferenced { get; init; }

    /// <summary>Platform warnings plus client-side observations, human-readable.</summary>
    public required IReadOnlyList<string> Issues { get; init; }

    /// <summary>The full platform response, for diagnostics and rendering.</summary>
    public required JsonObject Raw { get; init; }

    /// <summary>
    /// The cryptographic answer: complete ∧ the hybrid dimension settled
    /// (<see cref="Pqc"/> absent-or-verified). Enforced client-side as well as
    /// server-side, so a hybrid seal is never Ok from the classical verdict
    /// alone. Profile-layer checks come on top of this.
    /// </summary>
    public bool Ok => Complete && Pqc is "absent" or "verified";
}
