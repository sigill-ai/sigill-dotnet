// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;

namespace Sigill.Sdk;

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
