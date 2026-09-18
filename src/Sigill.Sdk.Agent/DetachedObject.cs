// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent;

/// <summary>
/// Innhold som forblir hos produsenten. Bare digesten og en opak URI går
/// inn i artefaktet (notatet 5.4).
/// </summary>
public sealed class DetachedObject
{
    public DetachedObject(string role, byte[] bytes, string? contentType = null, string? uri = null)
    {
        if (string.IsNullOrWhiteSpace(role)) throw new ArgumentException("role er påkrevd.", nameof(role));
        Role = role;
        Bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
        ContentType = contentType;
        Uri = string.IsNullOrWhiteSpace(uri) ? $"urn:uuid:{Guid.NewGuid()}" : uri!.Trim();
    }

    public string Role { get; }
    public byte[] Bytes { get; }
    public string? ContentType { get; }
    public string Uri { get; }

    public string HashHex => EnvelopeHashing.HashHex(Bytes);

    internal SignedObjectDigest ToDigest() => new()
    {
        Uri = Uri,
        HashHex = HashHex,
        ContentType = ContentType,
    };

    internal JsonObject ToEnvelopeEntry()
    {
        var entry = new JsonObject { ["uri"] = Uri, ["role"] = Role };
        if (ContentType is not null) entry["contentType"] = ContentType;
        return entry;
    }
}
