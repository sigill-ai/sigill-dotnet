// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent;

/// <summary>
/// Ett artefakt <c>{ envelope, signature }</c> etter envelope-v2 §6, for en av
/// de tre søsterprofilene. Profilen leses fra <c>sigD.ctys[0]</c> i den
/// klassiske signaturen, som er platformens profildiskriminator.
/// </summary>
public sealed class AgentArtifact
{
    private string? _signatureSha256;

    public AgentArtifact(JsonObject envelope, JsonObject signature)
    {
        Envelope = envelope ?? throw new ArgumentNullException(nameof(envelope));
        Signature = signature ?? throw new ArgumentNullException(nameof(signature));
        EnvelopeHashHex = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(envelope));
    }

    public JsonObject Envelope { get; }
    public JsonObject Signature { get; }
    public string EnvelopeHashHex { get; }

    /// <summary>Bindingshashen andre artefakter peker på (notatet 4.4).</summary>
    public string SignatureSha256 => _signatureSha256 ??= Binding.SignatureSha256(Signature);

    public string? ContentType
    {
        get
        {
            var entry = Binding.ClassicalEntry(Signature);
            var ctys = entry is null ? null : Binding.ProtectedHeader(entry)?["sigD"]?["ctys"] as JsonArray;
            return ctys is { Count: > 0 } ? Json.ReadString(ctys[0]) : null;
        }
    }

    public string? SchemaName => Json.ReadString(Envelope["schemaName"]);
    public string? CorrelationId => Json.ReadString(Envelope["activity"]?["correlationId"]);
    public string? StepType => Json.ReadString(Envelope["step"]?["type"]);
    public int? Seq => Json.ReadInt(Envelope["chain"]?["seq"]);
    public string? PrevSignatureSha256 => Json.ReadString(Envelope["chain"]?["prevSignatureSha256"]);

    /// <summary>
    /// Objektene slik de er signert: <c>sigD.pars</c>, <c>hashV</c> og <c>ctys</c>
    /// fra den klassiske signaturen. Indeks 0 er konvolutten selv.
    /// </summary>
    public IReadOnlyList<SignedObjectDigest> SignedObjects
    {
        get
        {
            var entry = Binding.ClassicalEntry(Signature);
            var sigD = entry is null ? null : Binding.ProtectedHeader(entry)?["sigD"] as JsonObject;
            if (sigD?["pars"] is not JsonArray pars || sigD["hashV"] is not JsonArray hashV)
                return Array.Empty<SignedObjectDigest>();
            var ctys = sigD["ctys"] as JsonArray;
            var list = new List<SignedObjectDigest>(pars.Count);
            for (var i = 0; i < pars.Count && i < hashV.Count; i++)
            {
                var uri = Json.ReadString(pars[i]) ?? "";
                var hashB64 = Json.ReadString(hashV[i]) ?? "";
                var cty = ctys is not null && i < ctys.Count ? Json.ReadString(ctys[i]) : null;
                list.Add(new SignedObjectDigest
                {
                    Uri = uri,
                    HashHex = HexOf(hashB64),
                    ContentType = string.IsNullOrEmpty(cty) ? null : cty,
                });
            }
            return list;
        }
    }

    /// <summary>URI for objektet med gitt rolle i konvolutten, eller null.</summary>
    public string? UriOfRole(string role) =>
        (Envelope["objects"] as JsonArray ?? new JsonArray())
            .OfType<JsonObject>()
            .Where(o => string.Equals(Json.ReadString(o["role"]), role, StringComparison.Ordinal))
            .Select(o => Json.ReadString(o["uri"]))
            .FirstOrDefault();

    public string ToJsonString(bool indented = true) =>
        new JsonObject { ["envelope"] = Envelope.DeepClone(), ["signature"] = Signature.DeepClone() }
            .ToJsonString(new JsonSerializerOptions { WriteIndented = indented });

    public static AgentArtifact Parse(string json)
    {
        var root = JsonNode.Parse(json) as JsonObject
            ?? throw new SigillException("Artefaktet er ikke et JSON-objekt.");
        if (root["envelope"] is not JsonObject envelope || root["signature"] is not JsonObject signature)
            throw new SigillException("Artefaktet må ha medlemmene 'envelope' og 'signature'.");
        return new AgentArtifact(envelope, signature);
    }

    private static string HexOf(string base64Url)
    {
        try
        {
            var bytes = Base64Url.Decode(base64Url);
            var chars = new char[bytes.Length * 2];
            const string hex = "0123456789abcdef";
            for (var i = 0; i < bytes.Length; i++)
            {
                chars[i * 2] = hex[bytes[i] >> 4];
                chars[i * 2 + 1] = hex[bytes[i] & 0xF];
            }
            return new string(chars);
        }
        catch (FormatException)
        {
            return "";
        }
    }
}
