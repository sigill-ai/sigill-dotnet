// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace Sigill.Sdk;

/// <summary>
/// An unsealed envelope, ready to pass to <see cref="ISigillAiEvidenceClient.SealAsync"/>.
///
/// The shape mirrors the JSON Schema in <c>spec/ai-evidence-envelope-v1.schema.json</c>.
/// The wrapped <see cref="JsonObject"/> can be authored directly, or via
/// <see cref="EnvelopeBuilder"/> for ergonomics.
/// </summary>
public sealed class AiEvidenceEnvelopeInput
{
    /// <summary>The underlying JSON object. Mutable; copy if you need stability.</summary>
    public JsonObject Json { get; }

    public AiEvidenceEnvelopeInput(JsonObject json) => Json = json ?? throw new ArgumentNullException(nameof(json));

    /// <summary>Construct from any JSON-shaped value. Used by callers that already have a JsonNode.</summary>
    public static AiEvidenceEnvelopeInput FromJson(JsonObject json) => new(json);
}

/// <summary>
/// A sealed envelope as returned from <see cref="ISigillAiEvidenceClient.SealAsync"/>.
///
/// <see cref="Json"/> contains the populated <c>integrity.envelopeHash</c> and a
/// <c>proofs</c> array with at least one RFC 3161 timestamp. The bytes used to
/// produce that hash are exposed via <see cref="CanonicalBytes"/> for diagnostic and
/// audit purposes.
/// </summary>
public sealed class SealedAiEvidenceEnvelope
{
    /// <summary>The sealed envelope as a JSON object.</summary>
    public JsonObject Json { get; }

    /// <summary>The exact RFC 8785 canonical bytes whose hash is recorded in <c>integrity.envelopeHash</c>.</summary>
    public byte[] CanonicalBytes { get; }

    /// <summary>The hex digest stored in <c>integrity.envelopeHash.hex</c>. Convenience accessor.</summary>
    public string EnvelopeHashHex { get; }

    public SealedAiEvidenceEnvelope(JsonObject json, byte[] canonicalBytes, string envelopeHashHex)
    {
        Json = json;
        CanonicalBytes = canonicalBytes;
        EnvelopeHashHex = envelopeHashHex;
    }

    /// <summary>
    /// Wrap a previously-persisted sealed envelope (re-loaded from disk or a database)
    /// for verification. The canonical bytes and hash are recomputed lazily by the verifier.
    /// </summary>
    public static SealedAiEvidenceEnvelope FromJson(JsonObject json)
    {
        var hex = json["integrity"]?["envelopeHash"]?["hex"]?.GetValue<string>() ?? string.Empty;
        return new SealedAiEvidenceEnvelope(json, Array.Empty<byte>(), hex);
    }
}

/// <summary>
/// Options that vary per <c>SealAsync</c> call. The defaults — auto-rotation across
/// every TSA enabled for your tenant, non-qualified — are the recommended setting.
/// </summary>
public sealed record SealOptions
{
    /// <summary>
    /// Which TSA to use. Defaults to <c>"auto"</c>: round-robin with failover. Pass a
    /// specific slug (<c>digicert</c>, <c>sectigo</c>, <c>skid-ecc</c>, ...) when a
    /// compliance reason demands a deterministic choice.
    /// </summary>
    public string TsaSlug { get; init; } = "auto";

    /// <summary>
    /// Request an eIDAS-qualified timestamp instead of a standard one. Counts against
    /// a separate monthly quota per Sigill's pricing.
    /// </summary>
    public bool Qualified { get; init; }

    /// <summary>
    /// Optional human-readable label stored in Sigill's transaction log alongside the
    /// timestamp. Useful for searching the dashboard later. Not part of the canonical
    /// envelope — does not affect the envelope hash.
    /// </summary>
    public string? Label { get; init; }
}
