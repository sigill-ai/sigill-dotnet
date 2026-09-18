// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk.Agent;

/// <summary>
/// Det ene kallet profilene trenger fra platformen: en konvolutthash, en
/// digestliste og en innholdstype inn, en JWS-signatur ut. Platformen ser
/// aldri konvolutten (notatet 4.1).
/// </summary>
public interface IArtifactSealer
{
    Task<JsonObject> SealAsync(
        string envelopeHashHex,
        IReadOnlyList<SignedObjectDigest> objects,
        string envelopeContentType,
        CancellationToken cancellationToken = default);
}

/// <summary>Forsegler gjennom <see cref="ISigillAiEvidenceClient.SignObjectHashesAsync"/> med ett fast sertifikat.</summary>
public sealed class SigillArtifactSealer : IArtifactSealer
{
    private readonly ISigillAiEvidenceClient _client;
    private readonly Guid _certificateId;
    private readonly bool _qualified;

    public SigillArtifactSealer(ISigillAiEvidenceClient client, Guid certificateId, bool qualified = false)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        if (certificateId == Guid.Empty) throw new ArgumentException("certificateId er påkrevd.", nameof(certificateId));
        _certificateId = certificateId;
        _qualified = qualified;
    }

    public async Task<JsonObject> SealAsync(
        string envelopeHashHex,
        IReadOnlyList<SignedObjectDigest> objects,
        string envelopeContentType,
        CancellationToken cancellationToken = default)
    {
        var result = await _client.SignObjectHashesAsync(
            envelopeHashHex,
            objects,
            _certificateId,
            new ObjectSignOptions { EnvelopeContentType = envelopeContentType, Qualified = _qualified },
            cancellationToken).ConfigureAwait(false);
        return result.Signature;
    }
}
