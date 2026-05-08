// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Sigill.Sdk.Internal;

namespace Sigill.Sdk;

/// <summary>
/// Static helpers for the spec's deterministic operations. Exposed publicly so callers
/// can reach for the canonicalization / hashing primitives outside the seal/verify
/// flow if they need to (e.g. computing a hash for an existing envelope without
/// re-stamping it).
/// </summary>
public static class EnvelopeHashing
{
    /// <summary>Canonicalize a JSON object per RFC 8785 (JCS).</summary>
    public static byte[] Canonicalize(JsonObject envelope)
    {
        if (envelope is null) throw new ArgumentNullException(nameof(envelope));
        // JsonNode → JsonElement to feed the canonicalizer.
        var rawText = envelope.ToJsonString();
        return JsonCanonicalizer.Canonicalize(rawText);
    }

    /// <summary>
    /// Compute the envelope hash per spec §4: strip <c>integrity.envelopeHash</c> and
    /// <c>proofs</c>, canonicalize, hash. Returns the hex digest and the canonical bytes.
    ///
    /// The input is NOT mutated — a deep clone is taken before stripping.
    /// </summary>
    public static (string HexDigest, byte[] CanonicalBytes) ComputeEnvelopeHash(
        JsonObject envelope, string algorithm = "SHA-256")
    {
        if (envelope is null) throw new ArgumentNullException(nameof(envelope));

        var clone = (JsonObject)JsonNode.Parse(envelope.ToJsonString())!;
        if (clone["integrity"] is JsonObject integrity)
        {
            integrity.Remove("envelopeHash");
        }
        clone.Remove("proofs");

        var canonicalBytes = Canonicalize(clone);
        var hex = HashHex(canonicalBytes, algorithm);
        return (hex, canonicalBytes);
    }

    /// <summary>Hash arbitrary bytes with the named algorithm, return lowercase hex.</summary>
    public static string HashHex(byte[] data, string algorithm = "SHA-256")
    {
        using HashAlgorithm hasher = algorithm switch
        {
            "SHA-256" => SHA256.Create(),
            "SHA-384" => SHA384.Create(),
            "SHA-512" => SHA512.Create(),
            _ => throw new SigillCanonicalizationException(
                $"Unsupported hash algorithm '{algorithm}'. Supported: SHA-256, SHA-384, SHA-512."),
        };
        var bytes = hasher.ComputeHash(data);
        return ToLowerHex(bytes);
    }

    internal static string ToLowerHex(byte[] bytes)
    {
        // .NET's Convert.ToHexString returns uppercase on net6+; we want lowercase.
        // Hand-roll for portability and to avoid the extra string allocation.
        var chars = new char[bytes.Length * 2];
        const string hex = "0123456789abcdef";
        for (int i = 0; i < bytes.Length; i++)
        {
            chars[i * 2]     = hex[bytes[i] >> 4];
            chars[i * 2 + 1] = hex[bytes[i] & 0xF];
        }
        return new string(chars);
    }
}
