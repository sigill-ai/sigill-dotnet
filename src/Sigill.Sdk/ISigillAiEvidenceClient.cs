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
        IReadOnlyList<string>? tags = null,
        string? reminders = null,
        int? reminderDays = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// PAdES-seal a PDF without the PDF ever leaving the machine (delegated
    /// signing via <c>/seal/sign-pades-hash</c>). The SDK assembles the PDF
    /// signature revision locally, transmits only the ByteRange digest, embeds
    /// the returned CMS, and — with <see cref="PadesSealOptions.Ltv"/> (default) —
    /// upgrades to B-LT/B-LTA by embedding the Document Security Store and a
    /// DocTimeStamp obtained via <c>/tsa/stamp-hash</c>.
    /// <para>
    /// Throws <see cref="SigillPdfUnsupportedException"/> when the local parser
    /// cannot handle the PDF's structure. With
    /// <see cref="PadesSealOptions.AllowUploadFallback"/> (opt-in, default off)
    /// such documents are instead sealed server-side via <c>POST /seal/sign</c>
    /// — identical PAdES output, but the PDF is transmitted. By default the SDK
    /// transmits nothing but digests.
    /// </para>
    /// </summary>
    Task<PadesSealResult> SealPadesAsync(
        byte[] pdf,
        Guid certificateId,
        PadesSealOptions? options = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// JAdES-seal data via <c>/seal/sign-hash</c> with <c>format: "jades"</c> —
    /// the ETSI signature format for JSON (TS 119 182-1), the natural fit for
    /// JSON/JSONL content such as AI evidence and agent logs. Only digests are
    /// transmitted; returns the detached <c>.jades.json</c> artifact bytes.
    /// The seal covers the exact bytes — re-serializing the JSON breaks it by design.
    /// <para>
    /// When <paramref name="pqc"/> is true, adds an ML-DSA-87 signer as a second
    /// JWS <c>signatures[]</c> entry (RFC 9964), same hybrid model as CAdES.
    /// </para>
    /// </summary>
    Task<byte[]> SealJadesAsync(
        byte[] data,
        Guid certificateId,
        string? label = null,
        bool qualified = false,
        bool pqc = false,
        string? contentType = null,
        IReadOnlyList<string>? tags = null,
        string? reminders = null,
        int? reminderDays = null,
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
    /// Verify a detached JAdES signature via <c>POST /seal/verify-hash</c> —
    /// hash-only, the original content never leaves the machine. The endpoint is
    /// public — no API key is required — but the existing HTTP client works fine.
    /// </summary>
    Task<JadesVerifyResult> VerifyJadesAsync(
        byte[] data,
        byte[] jades,
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

    /// <summary>
    /// Download the escrowed signature object for a seal operation, or null when
    /// nothing is stored. For PAdES this is the /Contents CMS — the input to
    /// <see cref="SigillClient.CompletePades"/>.
    /// </summary>
    Task<byte[]?> GetSealCmsAsync(Guid operationId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Newest evidence record for an artifact hash as recorded for the
    /// authenticated tenant, or null when none exists. The CI-gate primitive.
    /// </summary>
    Task<EvidenceRecord?> GetEvidenceRecordAsync(string hashHex, CancellationToken cancellationToken = default);

    /// <summary>
    /// Public consent-gated existence check for an artifact hash, or null when
    /// no publicly disclosed record exists.
    /// </summary>
    Task<PublicLookupResult?> LookupAsync(string hashHex, CancellationToken cancellationToken = default);

    /// <summary>
    /// Download the evidence's independently-verifiable audit package
    /// (tokens, certificates, verification report, custody log, manifest).
    /// </summary>
    Task<byte[]> ExportAuditPackageAsync(Guid transactionId, CancellationToken cancellationToken = default);
}
