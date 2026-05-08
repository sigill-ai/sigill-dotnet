// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>
/// The Sigill AI evidence SDK contract: seal an envelope (canonicalize → hash →
/// timestamp), verify a previously-sealed envelope.
///
/// Match the surface in the implementation guide so consumers can mock easily.
/// </summary>
public interface ISigillAiEvidenceClient
{
    /// <summary>
    /// Seal an envelope. Steps:
    /// <list type="number">
    ///   <item>Hash any external payloads supplied via <paramref name="externalPayloads"/>
    ///         and record the resulting digests in matching <c>payloadRef</c> entries.</item>
    ///   <item>Set <c>integrity.canonicalization</c> = <c>"RFC8785"</c>.</item>
    ///   <item>Strip <c>integrity.envelopeHash</c> and <c>proofs</c>, canonicalize, hash;
    ///         write the digest into <c>integrity.envelopeHash</c>.</item>
    ///   <item>Submit the canonical bytes to Sigill's <c>/tsa/stamp</c>; attach the
    ///         returned TSR as a single entry in <c>proofs[]</c>.</item>
    /// </list>
    ///
    /// Throws <see cref="SigillTimestampUnavailableException"/> if every TSA in the
    /// rotation fails. Throws <see cref="SigillHashMismatchException"/> if a
    /// pre-declared hash conflicts with supplied bytes. Throws
    /// <see cref="SigillCanonicalizationException"/> if the input cannot be canonicalized.
    /// </summary>
    Task<SealedAiEvidenceEnvelope> SealAsync(
        AiEvidenceEnvelopeInput input,
        IReadOnlyDictionary<string, byte[]>? externalPayloads = null,
        SealOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify a sealed envelope. Walks the envelope, recomputing the hash and
    /// checking each external payload reference and each proof. Collects every
    /// issue found into the result's <see cref="AiEvidenceVerificationResult.Issues"/>;
    /// does NOT throw on the first problem.
    /// </summary>
    Task<AiEvidenceVerificationResult> VerifyAsync(
        SealedAiEvidenceEnvelope envelope,
        IReadOnlyDictionary<string, byte[]>? externalPayloads = null,
        CancellationToken cancellationToken = default);
}
