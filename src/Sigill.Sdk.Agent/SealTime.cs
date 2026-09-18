// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Text;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent;

/// <summary>
/// Seal-tiden er <c>genTime</c> i <c>sigTst</c> (RFC 3161) i den klassiske
/// signaturens ubeskyttede <c>etsiU</c>-header. Det er platformens tidsstempel,
/// ikke produsentens klokke, og det er den som beviser rekkefølgen «kontroll
/// forseglet før run_start».
/// </summary>
public static class SealTime
{
    public static DateTimeOffset? Of(JsonObject signature)
    {
        var entry = Binding.ClassicalEntry(signature);
        if (entry?["header"]?["etsiU"] is not JsonArray etsiU) return null;
        foreach (var item in etsiU)
        {
            var component = item as JsonObject ?? DecodeComponent(Json.ReadString(item));
            if (component?["sigTst"]?["tstTokens"] is not JsonArray tokens) continue;
            foreach (var tokenNode in tokens.OfType<JsonObject>())
            {
                var value = Json.ReadString(tokenNode["val"]);
                if (value is null) continue;
                var bytes = TryDecodeBase64(value);
                if (bytes is not null && Rfc3161TimestampToken.TryDecode(bytes, out var token, out _))
                    return token.TokenInfo.Timestamp;
            }
        }
        return null;
    }

    private static JsonObject? DecodeComponent(string? base64Url)
    {
        if (base64Url is null) return null;
        try { return JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.Decode(base64Url))) as JsonObject; }
        catch (Exception exception) when (exception is FormatException or System.Text.Json.JsonException) { return null; }
    }

    private static byte[]? TryDecodeBase64(string value)
    {
        try { return Convert.FromBase64String(value); }
        catch (FormatException)
        {
            try { return Base64Url.Decode(value); } catch (FormatException) { return null; }
        }
    }
}
