// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// The profile-agnostic tier (spec §2/§12): sibling profiles sign and verify
// multi-object seals by digests, with their own envelope content type — the
// profile discriminator. The AI-evidence methods stay pinned to their own cty
// on top of this same tier. HTTP is faked; hashes are real.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public class ObjectSigningTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, JsonObject, Task<HttpResponseMessage>> _impl;
        public List<(string Path, JsonObject Body)> Requests { get; } = new();
        public FakeHandler(Func<HttpRequestMessage, JsonObject, Task<HttpResponseMessage>> impl) => _impl = impl;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = new JsonObject();
            if (request.Content is not null)
            {
                var raw = await request.Content.ReadAsStringAsync(ct);
                if (JsonNode.Parse(raw) is JsonObject obj) body = obj;
            }
            Requests.Add((request.RequestUri!.AbsolutePath, (JsonObject)body.DeepClone()));
            return await _impl(request, body);
        }
    }

    private static SigillClient Client(FakeHandler handler) =>
        new(new HttpClient(handler) { BaseAddress = new Uri("https://api.example") });

    private static string Sha256Hex(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
    private static string Sha512Hex(byte[] b) => Convert.ToHexString(SHA512.HashData(b)).ToLowerInvariant();

    private static HttpResponseMessage Json(JsonObject body) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
    };

    private const string SiblingCty = "application/vnd.example.records+json";

    private static readonly string EnvelopeHex  = Sha256Hex("a sibling-profile envelope"u8.ToArray());
    private static readonly string Envelope512  = Sha512Hex("a sibling-profile envelope"u8.ToArray());
    private static readonly string ObjectHex    = Sha256Hex("object one"u8.ToArray());
    private static readonly string Object512    = Sha512Hex("object one"u8.ToArray());

    [Fact]
    public async Task SignObjectHashes_CarriesCallerContentTypes_IncludingObjectZero()
    {
        var opId = Guid.NewGuid();
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["signature"] = new JsonObject { ["signatures"] = new JsonArray() },
            ["operationId"] = opId.ToString(),
            ["format"] = "jades-b-t",
            ["timestampedBy"] = "Sigill TSA",
            ["qualified"] = false,
            ["pqc"] = false,
        })));
        using var client = Client(handler);

        var result = await client.SignObjectHashesAsync(
            EnvelopeHex,
            new[]
            {
                new SignedObjectDigest { Uri = "urn:example:1", HashHex = ObjectHex, ContentType = "text/plain" },
                new SignedObjectDigest { Uri = "urn:example:2", HashHex = Sha256Hex("object two"u8.ToArray()) },
            },
            Guid.NewGuid(),
            new ObjectSignOptions { EnvelopeContentType = SiblingCty, Label = "sibling-seal" });

        var (path, body) = handler.Requests.Single();
        path.Should().Be("/seal/sign-hashes");

        // Object 0's content type — the profile discriminator — travels.
        body["envelopeContentType"]!.GetValue<string>().Should().Be(SiblingCty);
        body["envelopeHashHex"]!.GetValue<string>().Should().Be(EnvelopeHex);

        var objects = body["objects"]!.AsArray();
        objects.Should().HaveCount(2);
        objects[0]!["uri"]!.GetValue<string>().Should().Be("urn:example:1");
        objects[0]!["hashHex"]!.GetValue<string>().Should().Be(ObjectHex);
        objects[0]!["contentType"]!.GetValue<string>().Should().Be("text/plain");
        objects[1]!.AsObject().ContainsKey("contentType").Should().BeFalse("absent ctys stay absent");

        // Digests-in: nothing but digests, URIs, and ctys ever travels.
        body.ContainsKey("envelope").Should().BeFalse();
        body["label"]!.GetValue<string>().Should().Be("sibling-seal");

        result.OperationId.Should().Be(opId);
        result.Format.Should().Be("jades-b-t");
        result.TimestampedBy.Should().Be("Sigill TSA");
        result.Signature["signatures"].Should().NotBeNull();
    }

    [Fact]
    public async Task SignObjectHashes_Pqc_RequiresAndSends_Sha512Throughout()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["signature"] = new JsonObject { ["signatures"] = new JsonArray() },
            ["pqc"] = true,
        })));
        using var client = Client(handler);

        // Missing the SHA-512 envelope digest → rejected before any network call.
        var missingEnvelope512 = () => client.SignObjectHashesAsync(
            EnvelopeHex,
            new[] { new SignedObjectDigest { Uri = "urn:example:1", HashHex = ObjectHex, HashHex512 = Object512 } },
            Guid.NewGuid(),
            new ObjectSignOptions { Pqc = true });
        await missingEnvelope512.Should().ThrowAsync<SigillException>().WithMessage("*EnvelopeHashHex512*");

        // Missing a per-object SHA-512 digest → rejected before any network call.
        var missingObject512 = () => client.SignObjectHashesAsync(
            EnvelopeHex,
            new[] { new SignedObjectDigest { Uri = "urn:example:1", HashHex = ObjectHex } },
            Guid.NewGuid(),
            new ObjectSignOptions { Pqc = true, EnvelopeHashHex512 = Envelope512 });
        await missingObject512.Should().ThrowAsync<SigillException>().WithMessage("*hashHex512*");
        handler.Requests.Should().BeEmpty("validation failures must not reach the network");

        var result = await client.SignObjectHashesAsync(
            EnvelopeHex,
            new[] { new SignedObjectDigest { Uri = "urn:example:1", HashHex = ObjectHex, HashHex512 = Object512 } },
            Guid.NewGuid(),
            new ObjectSignOptions { Pqc = true, EnvelopeHashHex512 = Envelope512 });

        var body = handler.Requests.Single().Body;
        body["pqc"]!.GetValue<bool>().Should().BeTrue();
        body["envelopeHashHex512"]!.GetValue<string>().Should().Be(Envelope512);
        body["objects"]![0]!["hashHex512"]!.GetValue<string>().Should().Be(Object512);
        result.Pqc.Should().BeTrue();
    }

    [Fact]
    public async Task SignObjectHashes_ValidatesUrisAndDigests_BeforeNetwork()
    {
        var handler = new FakeHandler((_, _) =>
            throw new InvalidOperationException("validation failures must not reach the network"));
        using var client = Client(handler);
        var cert = Guid.NewGuid();
        var one = new SignedObjectDigest { Uri = "urn:example:1", HashHex = ObjectHex };

        var reserved = () => client.SignObjectHashesAsync(
            EnvelopeHex, new[] { one with { Uri = "urn:sigill:envelope" } }, cert);
        await reserved.Should().ThrowAsync<SigillException>().WithMessage("*reserved*");

        var duplicate = () => client.SignObjectHashesAsync(EnvelopeHex, new[] { one, one }, cert);
        await duplicate.Should().ThrowAsync<SigillException>().WithMessage("*Duplicate*");

        // Byte-exact identity: a padded URI is rejected, never silently
        // trimmed — the caller's envelope already references it verbatim, and
        // a normalized signature would no longer align with that envelope.
        var padded = () => client.SignObjectHashesAsync(
            EnvelopeHex, new[] { one with { Uri = "urn:example:1 " } }, cert);
        await padded.Should().ThrowAsync<SigillException>().WithMessage("*whitespace*");

        var badEnvelopeHash = () => client.SignObjectHashesAsync("not-hex", new[] { one }, cert);
        await badEnvelopeHash.Should().ThrowAsync<SigillException>().WithMessage("*envelopeHashHex*");

        var badObjectHash = () => client.SignObjectHashesAsync(
            EnvelopeHex, new[] { one with { HashHex = "abc" } }, cert);
        await badObjectHash.Should().ThrowAsync<SigillException>().WithMessage("*64 hex*");

        var overCap = () => client.SignObjectHashesAsync(
            EnvelopeHex,
            Enumerable.Range(0, 129).Select(i => one with { Uri = $"urn:example:{i}" }).ToArray(),
            cert);
        await overCap.Should().ThrowAsync<SigillException>().WithMessage("*capped*");

        handler.Requests.Should().BeEmpty();
    }

    private static JsonObject Verdict(Action<JsonObject>? mutate = null)
    {
        var r = new JsonObject
        {
            ["signatureValid"] = true,
            ["complete"] = true,
            ["pqc"] = "absent",
            ["objectCount"] = 2,
            ["suppliedCount"] = 2,
            ["matchedCount"] = 2,
            ["objects"] = new JsonArray(
                new JsonObject { ["par"] = "urn:sigill:envelope", ["contentType"] = SiblingCty, ["supplied"] = true, ["hashMatch"] = true },
                new JsonObject { ["par"] = "urn:example:1", ["supplied"] = true, ["hashMatch"] = true }),
            ["missing"] = new JsonArray(),
            ["unreferenced"] = new JsonArray(),
        };
        mutate?.Invoke(r);
        return new JsonObject { ["objects"] = r };
    }

    private static JsonObject ClassicalJws() => new()
    {
        ["signatures"] = new JsonArray(new JsonObject { ["protected"] = "e30", ["signature"] = "c2ln" }),
    };

    private static void AddMlDsaEntry(JsonObject jws)
    {
        var header = Convert.ToBase64String("{\"alg\":\"ML-DSA-87\"}"u8.ToArray())
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        jws["signatures"]!.AsArray().Add(new JsonObject { ["protected"] = header, ["signature"] = "cA" });
    }

    [Fact]
    public async Task VerifyObjectHashes_SendsDigestMapsVerbatim_AndMapsVerdicts()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(Verdict())));
        using var client = Client(handler);

        var result = await client.VerifyObjectHashesAsync(
            ClassicalJws(),
            new Dictionary<string, string>
            {
                ["urn:sigill:envelope"] = EnvelopeHex,
                ["urn:example:1"] = ObjectHex,
            });

        var (path, body) = handler.Requests.Single();
        path.Should().Be("/seal/verify-objects");
        body["digests"]!["urn:sigill:envelope"]!.GetValue<string>().Should().Be(EnvelopeHex);
        body["digests"]!["urn:example:1"]!.GetValue<string>().Should().Be(ObjectHex);
        body.ContainsKey("digests512").Should().BeFalse();
        body.ContainsKey("tsrBase64").Should().BeFalse();

        result.SignatureValid.Should().BeTrue();
        result.Complete.Should().BeTrue();
        result.Pqc.Should().Be("absent");
        result.Objects.Should().HaveCount(2);
        result.Objects[0].Uri.Should().Be("urn:sigill:envelope");
        result.Objects[0].ContentType.Should().Be(SiblingCty, "the signed cty comes back — the profile discriminator is verifiable");
        result.Ok.Should().BeTrue();
    }

    [Fact]
    public async Task VerifyObjectHashes_HybridWithoutPqcVerdict_NeverOk()
    {
        // A verifier build that predates the hybrid contract returns
        // complete=true from the classical dimension and NO pqc field. The SDK
        // detected the ML-DSA signer itself, so the classical verdict must
        // never stand in for the hybrid one.
        var legacy = Verdict(r => r.Remove("pqc"));
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(legacy)));
        using var client = Client(handler);

        var jws = ClassicalJws();
        AddMlDsaEntry(jws);
        var result = await client.VerifyObjectHashesAsync(
            jws,
            new Dictionary<string, string> { ["urn:sigill:envelope"] = EnvelopeHex },
            new Dictionary<string, string> { ["urn:sigill:envelope"] = Envelope512 });

        result.Complete.Should().BeTrue("the classical verdict is what the old verifier reported");
        result.Pqc.Should().Be("not_checked");
        result.Ok.Should().BeFalse("the classical verdict must never stand in for the hybrid one");
        result.Issues.Should().Contain(i => i.Contains("no pqc verdict"));
    }

    [Fact]
    public async Task VerifyObjectHashes_HybridWithoutSha512Digests_FlagsTheGap()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(Verdict(r =>
        {
            r["pqc"] = "not_checked";
            r["complete"] = false;
        }))));
        using var client = Client(handler);

        var jws = ClassicalJws();
        AddMlDsaEntry(jws);
        var result = await client.VerifyObjectHashesAsync(
            jws, new Dictionary<string, string> { ["urn:sigill:envelope"] = EnvelopeHex });

        result.Ok.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Contains("no SHA-512 digests"));
    }

    [Fact]
    public async Task V2Seal_StaysPinnedToItsOwnProfile()
    {
        // The AI-evidence methods ride the same tier but never expose the
        // envelope content type: object 0 keeps the platform's AI-evidence
        // default, so a sibling profile cannot be minted as AI evidence.
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["signature"] = new JsonObject { ["signatures"] = new JsonArray() },
        })));
        using var client = Client(handler);

        await client.SealEvidenceV2Async(
            new JsonObject { ["purpose"] = new JsonObject { ["category"] = "summarization" } },
            new[] { new AiEvidenceV2Payload { Role = "prompt", Bytes = "p"u8.ToArray() } },
            Guid.NewGuid());

        handler.Requests.Single().Body.ContainsKey("envelopeContentType")
            .Should().BeFalse("the AI-evidence profile is pinned to the platform default cty");
    }
}
