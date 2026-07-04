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
    ///   <item>Submit the envelope hash to Sigill's <c>/tsa/stamp-hash</c>; attach the
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
    /// CAdES-seal arbitrary data (JSON, binary, etc.) via <c>/seal/sign-hash</c>.
    /// Only digests are transmitted — the original document never leaves the machine.
    /// Returns the raw DER-encoded detached CAdES signature (.p7s bytes).
    /// <para>
    /// When <paramref name="pqc"/> is true, adds a post-quantum ML-DSA-87 (FIPS 204) signer
    /// alongside the classical one in the same CMS — one .p7s, both independently verifiable.
    /// The SHA-512 digest is computed locally and sent as the ML-DSA signer's messageDigest;
    /// content still never leaves the machine. Requires a platform PQC certificate server-side.
    /// </para>
    /// </summary>
    Task<byte[]> SealCadesAsync(
        byte[] data,
        Guid certificateId,
        string? label = null,
        bool qualified = false,
        bool pqc = false,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify a detached CAdES signature via <c>POST /seal/verify</c>. The endpoint
    /// is public — no API key is required — but the existing HTTP client works fine.
    /// </summary>
    Task<CadesVerifyResult> VerifyCadesAsync(
        byte[] data,
        byte[] p7s,
        byte[]? tsr = null,
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
