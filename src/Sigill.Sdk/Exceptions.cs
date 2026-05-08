// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace Sigill.Sdk;

/// <summary>Base class for all errors raised by the Sigill SDK.</summary>
public class SigillException : Exception
{
    public SigillException(string message) : base(message) { }
    public SigillException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The envelope cannot be canonicalized. Typical causes: input contains values
/// JCS rejects (NaN, Infinity), the top-level value is not an object, or the
/// JSON is malformed.
/// </summary>
public sealed class SigillCanonicalizationException : SigillException
{
    public SigillCanonicalizationException(string message) : base(message) { }
    public SigillCanonicalizationException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// A pre-declared payload hash does not match the supplied bytes. Raised at
/// <see cref="SigillClient.SealAsync(AiEvidenceEnvelopeInput, IReadOnlyDictionary{string, byte[]}?, SealOptions?, System.Threading.CancellationToken)"/> time.
///
/// During verification, hash mismatches are reported as
/// <see cref="VerificationIssue"/> entries inside an
/// <see cref="AiEvidenceVerificationResult"/> rather than thrown.
/// </summary>
public sealed class SigillHashMismatchException : SigillException
{
    public string Reference { get; }
    public string Expected { get; }
    public string Actual { get; }

    public SigillHashMismatchException(string @ref, string expected, string actual)
        : base($"Pre-declared hash for ref '{@ref}' ({expected}) does not match supplied bytes ({actual})")
    {
        Reference = @ref;
        Expected = expected;
        Actual = actual;
    }
}

/// <summary>A proof (e.g. RFC 3161 TSR) cannot be parsed or its signature is invalid.</summary>
public sealed class SigillInvalidProofException : SigillException
{
    public SigillInvalidProofException(string message) : base(message) { }
    public SigillInvalidProofException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Sigill returned 502 — every TSA in the auto-rotation failed. The structured
/// failure list is on <see cref="Failures"/>. The envelope was NOT sealed; the
/// caller decides whether to retry, fall back, or surface to a human.
/// </summary>
public sealed class SigillTimestampUnavailableException : SigillException
{
    public IReadOnlyList<TsaFailure> Failures { get; }
    public int AttemptsTried { get; }

    public SigillTimestampUnavailableException(string message, IReadOnlyList<TsaFailure> failures, int attempts)
        : base(message)
    {
        Failures = failures;
        AttemptsTried = attempts;
    }
}

/// <summary>One entry in the failure list returned by Sigill on a 502.</summary>
public sealed record TsaFailure(
    string Tsa,
    string ErrorClass,
    int? StatusCode,
    string Message,
    long LatencyMs);
