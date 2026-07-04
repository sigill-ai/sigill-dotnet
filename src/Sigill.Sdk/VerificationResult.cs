// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;

namespace Sigill.Sdk;

/// <summary>
/// Result of <see cref="ISigillAiEvidenceClient.VerifyCadesAsync"/> — server-side CAdES verification.
/// <list type="bullet">
///   <item><see cref="IsValid"/> — true iff <see cref="HashMatch"/>, <see cref="SignatureValid"/>, and no <see cref="Error"/>.</item>
///   <item><see cref="HashMatch"/> — the .p7s messageDigest matched SHA-256(original document).</item>
///   <item><see cref="SignatureValid"/> — RSA/ECDSA signature over signedAttrs verified against the signer cert.</item>
///   <item><see cref="Signer"/> — certificate subject DN of the signing certificate.</item>
///   <item><see cref="Trust"/> — chain trust status: "trusted_chain", "self_signed", "dev_ca", etc.</item>
///   <item><see cref="TsaName"/> — name of the embedded timestamp authority.</item>
///   <item><see cref="GenTime"/> — ISO-8601 timestamp from the embedded RFC 3161 token.</item>
///   <item><see cref="Qualified"/> — true if the TSA qualification source is LOTL or QC statement.</item>
///   <item><see cref="Error"/> — server error message, or null on success.</item>
///   <item><see cref="Warnings"/> — non-fatal warnings from the server verifier.</item>
///   <item><see cref="PostQuantum"/> — non-null when the seal carries an ML-DSA-87 signer.</item>
/// </list>
/// <para>
/// <see cref="IsValid"/> reflects the classical signer only — the legal instrument.
/// The post-quantum signer is reported separately via <see cref="PostQuantum"/> and
/// is additive (quantum-resistant protection, not a qualified/legal upgrade).
/// </para>
/// </summary>
public sealed record CadesVerifyResult(
    bool IsValid,
    bool HashMatch,
    bool SignatureValid,
    string? Signer,
    string? Trust,
    string? TsaName,
    string? GenTime,
    bool Qualified,
    string? Error,
    IReadOnlyList<string> Warnings,
    PqcVerifyInfo? PostQuantum = null);

/// <summary>
/// Post-quantum dimension of a CAdES verification (the ML-DSA-87 SignerInfo).
/// <list type="bullet">
///   <item><see cref="Present"/> — an ML-DSA signer is present in the CMS.</item>
///   <item><see cref="SignatureValid"/> — the ML-DSA signature over its signedAttrs verified.</item>
///   <item><see cref="ContentBound"/> — "yes" | "no" | "not_checked" (the last when no SHA-512 was supplied on the hash-based path).</item>
///   <item><see cref="Trusted"/> — "yes" | "no" | "not_evaluated" (self-signed platform certs are "not_evaluated").</item>
///   <item><see cref="Valid"/> — signature verified AND content bound; convenience roll-up.</item>
///   <item><see cref="Algorithm"/> — e.g. "ml-dsa-87".</item>
/// </list>
/// </summary>
public sealed record PqcVerifyInfo(
    bool Present,
    bool Valid,
    bool SignatureValid,
    string ContentBound,
    string Trusted,
    string Algorithm);

/// <summary>
/// The four documented verification failure kinds from spec §7.
/// </summary>
public enum VerificationIssueKind
{
    /// <summary>The envelope cannot be canonicalized at all (malformed JSON, NaN/Inf, ...)</summary>
    CanonicalizationFailed,

    /// <summary>The envelope's recomputed hash does not match the registered one,
    /// OR a referenced external payload is missing / hashes to a different value.</summary>
    HashMismatch,

    /// <summary>A proof (TSR) cannot be parsed, or its message-imprint does not bind to the envelope.</summary>
    InvalidProof,

    /// <summary>The envelope has no proofs[] (was sealed without a timestamp because every TSA failed).</summary>
    TimestampUnavailable,
}

/// <summary>
/// One issue found while verifying an envelope. Verification collects every
/// issue rather than short-circuiting on the first — auditors want a complete report.
/// </summary>
public sealed record VerificationIssue(
    VerificationIssueKind Kind,
    string Target,
    string Message,
    string? Expected = null,
    string? Actual = null);

/// <summary>
/// Structured result of <see cref="ISigillAiEvidenceClient.VerifyAsync"/>.
/// </summary>
public sealed class AiEvidenceVerificationResult
{
    /// <summary>True iff there are no issues. Convenience for the common path.</summary>
    public bool IsValid { get; private set; } = true;

    /// <summary>The hex digest the verifier computed for the envelope. Null only
    /// if canonicalization itself failed.</summary>
    public string? EnvelopeHashHex { get; internal set; }

    /// <summary>Every issue found, in the order encountered.</summary>
    public List<VerificationIssue> Issues { get; } = new();

    /// <summary>One entry per successfully-parsed proof. Captures TSA-asserted
    /// time, serial, hashed message, qualified flag.</summary>
    public List<ParsedTimestamp> Timestamps { get; } = new();

    internal void AddIssue(VerificationIssue issue)
    {
        Issues.Add(issue);
        IsValid = false;
    }
}

/// <summary>Snapshot of an RFC 3161 TSR parsed during verification.</summary>
public sealed record ParsedTimestamp(
    string? TsaName,
    System.DateTimeOffset GenTime,
    string Serial,
    string HashAlgorithm,
    string HashedMessageHex,
    bool Qualified,
    string? PolicyOid);
