// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;

namespace Sigill.Sdk;

/// <summary>
/// The newest evidence record for an artifact hash, as recorded for the
/// authenticated tenant (<c>GET /api/transactions/by-hash/{hash}</c>).
/// <para>
/// The natural CI gate: <see cref="CertNotAfter"/> is the evidence's renewal
/// horizon — the moment the active timestamp token's TSA certificate expires.
/// A pipeline can fail a release when the artifact has no record, or when the
/// horizon is closer than the policy allows.
/// </para>
/// </summary>
public sealed record EvidenceRecord(
    Guid TransactionId,
    string Hash,
    string? HashAlgorithm,
    DateTimeOffset? GenTime,
    DateTimeOffset CreatedAt,
    string? TsaName,
    string? Label,
    DateTimeOffset? CertNotBefore,
    DateTimeOffset? CertNotAfter,
    bool IsRestamp,
    bool HasTsr);

/// <summary>
/// One record in a public (consent-gated) hash lookup. Cryptographic facts
/// only — no labels, no tenant identity; see the Sigill lookup contract.
/// </summary>
public sealed record PublicLookupRecord(
    Guid TransactionId,
    string Hash,
    string? HashAlgorithm,
    DateTimeOffset? GenTime,
    DateTimeOffset CreatedAt,
    string? TsaName,
    DateTimeOffset? CertNotBefore,
    DateTimeOffset? CertNotAfter,
    bool IsRestamp);

/// <summary>
/// Result of a public existence check (<c>GET /api/lookup/{hash}</c>).
/// Discoverability is opt-in per tenant/evidence: a null return from
/// <see cref="SigillClient.LookupAsync(string, System.Threading.CancellationToken)"/>
/// means "no publicly disclosed record" — deliberately indistinguishable from
/// "never stamped".
/// </summary>
public sealed record PublicLookupResult(
    int Count,
    PublicLookupRecord Latest,
    System.Collections.Generic.IReadOnlyList<PublicLookupRecord> Records);
