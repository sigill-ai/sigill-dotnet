// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace Sigill.Sdk;

/// <summary>
/// Options for <see cref="ISigillAiEvidenceClient.SealPadesAsync"/>.
/// </summary>
public sealed record PadesSealOptions
{
    /// <summary>Human-readable label shown in the Sigill dashboard. Defaults to a hash prefix.</summary>
    public string? Label { get; init; }

    /// <summary>Use an eIDAS-qualified timestamp authority for all timestamps in the seal.</summary>
    public bool Qualified { get; init; }

    /// <summary>
    /// Upgrade to PAdES B-LT / B-LTA when the server returns LTV material:
    /// embeds a Document Security Store (chain + OCSP) and a DocTimeStamp
    /// obtained via <c>/tsa/stamp-hash</c>. Default true. Note the DocTimeStamp
    /// consumes one timestamp from the tenant quota.
    /// </summary>
    public bool Ltv { get; init; } = true;

    /// <summary>
    /// Expiry-reminder policy for the created evidence: null/"inherit" follows
    /// the tenant default, "on" forces reminders, "off" mutes the evidence
    /// (e.g. short-lived artifacts that will never need renewal).
    /// </summary>
    public string? Reminders { get; init; }

    /// <summary>Reminder threshold override in days (30/60/90/180) when Reminders is "on".</summary>
    public int? ReminderDays { get; init; }

    /// <summary>
    /// Evidence tags attached at creation — the grouping/filter dimension of the
    /// Sigill evidence store (e.g. a release name or pipeline id). At most 10
    /// distinct tags per evidence, 40 characters each; more than 10 in one
    /// request is rejected with 400.
    /// </summary>
    public IReadOnlyList<string>? Tags { get; init; }

    /// <summary>
    /// When the local PDF parser cannot handle the document's structure, fall
    /// back to server-side sealing by uploading the PDF to <c>POST /seal/sign</c>
    /// (identical PAdES output, but the PDF is transmitted to Sigill).
    /// <para>
    /// Default <c>false</c>: the hash-only privacy guarantee is absolute — a
    /// PDF that cannot be prepared locally throws
    /// <see cref="SigillPdfUnsupportedException"/> and nothing but digests ever
    /// leaves the machine. Leave it off under a strict data-residency policy.
    /// </para>
    /// </summary>
    public bool AllowUploadFallback { get; init; }

    /// <summary>Written into the PDF signature dictionary's /Reason field.</summary>
    public string? Reason { get; init; }

    /// <summary>Written into the PDF signature dictionary's /Location field.</summary>
    public string? Location { get; init; }
}

/// <summary>
/// Result of a delegated PAdES seal: the sealed PDF plus the server-side
/// operation metadata. The input PDF's bytes never left the machine — only
/// the ByteRange digest was transmitted.
/// <para>
/// Post-quantum hybrid sealing is deliberately absent here: the PAdES baseline
/// profile (ETSI EN 319 142-1) allows a single SignerInfo in the embedded CMS,
/// so the ML-DSA-87 hybrid stays on the detached CAdES/JAdES formats until an
/// ETSI PQC PAdES profile exists.
/// </para>
/// </summary>
public sealed record PadesSealResult(
    byte[] SealedPdf,
    Guid OperationId,
    string Format,
    string? TimestampedBy,
    bool Qualified);

/// <summary>
/// Output of <see cref="SigillClient.PreparePades"/>: the PDF with its placeholder
/// signature revision appended, plus the ByteRange digest that will be signed.
/// <para>
/// <see cref="Bytes"/> is the crash checkpoint: persist it before calling
/// <see cref="SigillClient.SealPreparedPadesAsync"/> and a pipeline that dies
/// after the server signed can later finish locally — re-fetch the CMS with
/// <see cref="SigillClient.GetSealCmsAsync"/> (requires the tenant's
/// "Store PAdES seal data" escrow setting) and call
/// <see cref="SigillClient.CompletePades"/>. Everything needed to resume is
/// re-derived from these bytes; no other state must survive the crash.
/// </para>
/// </summary>
public sealed record PreparedPadesPdf(
    byte[] Bytes,
    string HashHex);
