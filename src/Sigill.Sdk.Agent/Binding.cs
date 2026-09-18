// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent;

/// <summary>
/// Én bindingsmekanisme (notatet 4.4): SHA-256 over den base64url-dekodede
/// klassiske JWS-signaturverdien til målartefaktet. Kjeden og bindingene
/// mellom bevisklassene bruker samme regel.
/// </summary>
public static class Binding
{
    public static string SignatureSha256(JsonObject signature)
    {
        var entry = ClassicalEntry(signature)
            ?? throw new SigillException("Signaturen har ingen klassisk JWS-signatur i signatures[].");
        var value = Json.ReadString(entry["signature"])
            ?? throw new SigillException("Den klassiske signaturen mangler signaturverdi.");
        return EnvelopeHashing.HashHex(Base64Url.Decode(value));
    }

    /// <summary>Første innslag i signatures[] som ikke er ML-DSA. PQC-signeren binder ikke kjeden.</summary>
    public static JsonObject? ClassicalEntry(JsonObject signature)
    {
        if (signature["signatures"] is not JsonArray entries) return null;
        foreach (var entry in entries.OfType<JsonObject>())
        {
            var header = ProtectedHeader(entry);
            var alg = Json.ReadString(header?["alg"]);
            if (alg is not null && alg.StartsWith("ML-DSA", StringComparison.Ordinal)) continue;
            return entry;
        }
        return null;
    }

    public static JsonObject? ProtectedHeader(JsonObject entry)
    {
        var protectedB64 = Json.ReadString(entry["protected"]);
        if (protectedB64 is null) return null;
        try
        {
            return JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.Decode(protectedB64))) as JsonObject;
        }
        catch (Exception exception) when (exception is FormatException or System.Text.Json.JsonException)
        {
            return null;
        }
    }
}
