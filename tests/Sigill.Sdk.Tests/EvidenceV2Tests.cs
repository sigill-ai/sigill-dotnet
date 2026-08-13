// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// The blind v2 contract from the SDK side: seal sends digests + opaque URIs
// only (never envelope, never content), the artifact is assembled client-side,
// and verification compounds the platform's cryptographic verdicts with the
// envelope-layer checks that are the SDK's job (alignment, role coverage,
// hybrid digests512). HTTP is faked; hashes are real.

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

public class EvidenceV2Tests
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

    private static JsonObject CoreEnvelope() => new()
    {
        ["purpose"]  = new JsonObject { ["category"] = "summarization" },
        ["actor"]    = new JsonObject { ["type"] = "user", ["id"] = "opaque-actor" },
        ["activity"] = new JsonObject { ["name"] = "chat.completion" },
        ["model"]    = new JsonObject { ["provider"] = "anthropic", ["name"] = "claude-fable-5" },
    };

    [Fact]
    public async Task Seal_SendsDigestsOnly_AndAssemblesArtifactClientSide()
    {
        var prompt = "the prompt"u8.ToArray();
        var output = "the output"u8.ToArray();
        var fakeSignature = new JsonObject
        {
            ["signatures"] = new JsonArray(new JsonObject { ["protected"] = "e30", ["signature"] = "c2ln" }),
        };
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["signature"] = fakeSignature.DeepClone(),
            ["operationId"] = Guid.NewGuid().ToString(),
            ["format"] = "jades-b-t",
        })));
        using var client = Client(handler);

        var artifact = await client.SealEvidenceV2Async(
            CoreEnvelope(),
            new[]
            {
                new AiEvidenceV2Payload { Role = "prompt", Bytes = prompt, ContentType = "text/plain", Encoding = "utf-8" },
                new AiEvidenceV2Payload { Role = "output", Bytes = output, Uri = "urn:test:out", ContentType = "text/markdown" },
            },
            Guid.NewGuid());

        var (path, body) = handler.Requests.Single();
        path.Should().Be("/seal/sign-hashes");

        // Blind: the request carries digests + URIs + ctys — and nothing else.
        body.ContainsKey("envelope").Should().BeFalse("the envelope must never be transmitted");
        var raw = body.ToJsonString();
        raw.Should().NotContain("the prompt").And.NotContain("the output");
        raw.Should().NotContain("summarization", "envelope metadata must never be transmitted");

        var objects = body["objects"]!.AsArray();
        objects.Count.Should().Be(2);
        objects[0]!["hashHex"]!.GetValue<string>().Should().Be(Sha256Hex(prompt));
        objects[0]!["uri"]!.GetValue<string>().Should().StartWith("urn:uuid:", "generated URIs are opaque by default");
        objects[1]!["uri"]!.GetValue<string>().Should().Be("urn:test:out");

        // The envelope hash binds the SDK's own canonicalization.
        var expectedHash = Sha256Hex(EnvelopeHashing.Canonicalize(artifact.Envelope));
        body["envelopeHashHex"]!.GetValue<string>().Should().Be(expectedHash);
        artifact.EnvelopeHashHex.Should().Be(expectedHash);

        // Client-side artifact: envelope (with SDK-owned objects[]) + returned JWS.
        artifact.Envelope["schemaName"]!.GetValue<string>().Should().Be("AiEvidenceEnvelope");
        artifact.Envelope["schemaVersion"]!.GetValue<string>().Should().Be("2");
        artifact.Envelope["objects"]!.AsArray().Count.Should().Be(2);
        artifact.Envelope["objects"]![0]!["role"]!.GetValue<string>().Should().Be("prompt");
        artifact.Signature.ToJsonString().Should().Be(fakeSignature.ToJsonString());

        // Round-trips through the artifact file format.
        var reparsed = AiEvidenceV2Artifact.Parse(artifact.ToJsonString());
        reparsed.EnvelopeHashHex.Should().Be(expectedHash);
    }

    [Fact]
    public async Task Seal_Pqc_SendsSha512Digests_Throughout()
    {
        var prompt = "pqc prompt"u8.ToArray();
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["signature"] = new JsonObject { ["signatures"] = new JsonArray() },
        })));
        using var client = Client(handler);

        var artifact = await client.SealEvidenceV2Async(
            CoreEnvelope(),
            new[] { new AiEvidenceV2Payload { Role = "prompt", Bytes = prompt } },
            Guid.NewGuid(),
            new EvidenceV2SealOptions { Pqc = true });

        var body = handler.Requests.Single().Body;
        body["pqc"]!.GetValue<bool>().Should().BeTrue();
        body["envelopeHashHex512"]!.GetValue<string>().Should().Be(
            Sha512Hex(EnvelopeHashing.Canonicalize(artifact.Envelope)));
        body["objects"]![0]!["hashHex512"]!.GetValue<string>().Should().Be(Sha512Hex(prompt));
    }

    [Fact]
    public async Task Seal_RejectsReservedAndDuplicateUris_AndBadRoles()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject())));
        using var client = Client(handler);
        var bytes = "x"u8.ToArray();

        var reserved = () => client.SealEvidenceV2Async(CoreEnvelope(),
            new[] { new AiEvidenceV2Payload { Role = "prompt", Bytes = bytes, Uri = "urn:sigill:envelope" } },
            Guid.NewGuid());
        await reserved.Should().ThrowAsync<SigillException>().WithMessage("*reserved*");

        var dup = () => client.SealEvidenceV2Async(CoreEnvelope(),
            new[]
            {
                new AiEvidenceV2Payload { Role = "prompt", Bytes = bytes, Uri = "urn:t:a" },
                new AiEvidenceV2Payload { Role = "output", Bytes = bytes, Uri = "urn:t:a" },
            },
            Guid.NewGuid());
        await dup.Should().ThrowAsync<SigillException>().WithMessage("*Duplicate*");

        var role = () => client.SealEvidenceV2Async(CoreEnvelope(),
            new[] { new AiEvidenceV2Payload { Role = "thought", Bytes = bytes } },
            Guid.NewGuid());
        await role.Should().ThrowAsync<SigillException>().WithMessage("*role*");

        handler.Requests.Should().BeEmpty("validation failures must not reach the network");
    }

    private static AiEvidenceV2Artifact ArtifactWith(string envelopeHex, params (string Uri, string Role)[] objects)
    {
        var envObjects = new JsonArray(objects
            .Select(o => (JsonNode)new JsonObject { ["uri"] = o.Uri, ["role"] = o.Role }).ToArray());
        var envelope = CoreEnvelope();
        envelope["schemaName"] = "AiEvidenceEnvelope";
        envelope["schemaVersion"] = "2";
        envelope["objects"] = envObjects;
        var signature = new JsonObject
        {
            ["signatures"] = new JsonArray(new JsonObject { ["protected"] = "e30", ["signature"] = "c2ln" }),
        };
        return new AiEvidenceV2Artifact(envelope, signature, envelopeHex);
    }

    [Fact]
    public async Task Verify_CompoundsPlatformVerdicts_WithEnvelopeLayerChecks()
    {
        var prompt = "verify me"u8.ToArray();
        var artifact = ArtifactWith("ignored", ("urn:t:prompt", "prompt"));
        var envelopeHex = Sha256Hex(EnvelopeHashing.Canonicalize(artifact.Envelope));

        var handler = new FakeHandler((_, body) =>
        {
            // The platform sees digests only; echo a verdict keyed to them.
            var verdict = new JsonObject
            {
                ["objects"] = new JsonObject
                {
                    ["signatureValid"] = true,
                    ["complete"] = true,
                    ["pqc"] = "absent",
                    ["objectCount"] = 2,
                    ["suppliedCount"] = 2,
                    ["matchedCount"] = 2,
                    ["objects"] = new JsonArray(
                        new JsonObject { ["par"] = "urn:sigill:envelope", ["supplied"] = true, ["hashMatch"] = true },
                        new JsonObject { ["par"] = "urn:t:prompt", ["supplied"] = true, ["hashMatch"] = true }),
                    ["missing"] = new JsonArray(),
                    ["unreferenced"] = new JsonArray(),
                },
            };
            return Task.FromResult(Json(verdict));
        });
        using var client = Client(handler);

        var result = await client.VerifyEvidenceV2Async(
            artifact,
            new Dictionary<string, byte[]> { ["urn:t:prompt"] = prompt },
            requiredRoles: new[] { "prompt" });

        var (path, body) = handler.Requests.Single();
        path.Should().Be("/seal/verify-objects");
        body["digests"]!["urn:sigill:envelope"]!.GetValue<string>().Should().Be(envelopeHex,
            "the envelope digest is computed locally with JCS — the envelope itself never travels");
        body["digests"]!["urn:t:prompt"]!.GetValue<string>().Should().Be(Sha256Hex(prompt));
        body.ContainsKey("digests512").Should().BeFalse("no ML-DSA signer in this JWS");
        body.ToJsonString().Should().NotContain("summarization");

        result.SignatureValid.Should().BeTrue();
        result.Complete.Should().BeTrue();
        result.AlignmentOk.Should().BeTrue();
        result.MissingRoles.Should().BeEmpty();
        result.Ok.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_HybridSeal_SendsDigests512_Automatically()
    {
        // A protected header with alg ML-DSA-87, base64url-encoded.
        var mlHeader = Convert.ToBase64String("""{"alg":"ML-DSA-87"}"""u8.ToArray())
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var artifact = ArtifactWith("ignored", ("urn:t:prompt", "prompt"));
        artifact.Signature["signatures"]!.AsArray()
            .Add(new JsonObject { ["protected"] = mlHeader, ["signature"] = "cA" });

        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["objects"] = new JsonObject
            {
                ["signatureValid"] = true, ["complete"] = true, ["pqc"] = "verified",
                ["objectCount"] = 2, ["suppliedCount"] = 2, ["matchedCount"] = 2,
                ["objects"] = new JsonArray(
                    new JsonObject { ["par"] = "urn:sigill:envelope", ["supplied"] = true, ["hashMatch"] = true },
                    new JsonObject { ["par"] = "urn:t:prompt", ["supplied"] = true, ["hashMatch"] = true }),
                ["missing"] = new JsonArray(), ["unreferenced"] = new JsonArray(),
            },
        })));
        using var client = Client(handler);

        var prompt = "hybrid payload"u8.ToArray();
        var result = await client.VerifyEvidenceV2Async(
            artifact, new Dictionary<string, byte[]> { ["urn:t:prompt"] = prompt });

        var body = handler.Requests.Single().Body;
        body["digests512"]!["urn:t:prompt"]!.GetValue<string>().Should().Be(Sha512Hex(prompt));
        body["digests512"]!["urn:sigill:envelope"]!.GetValue<string>().Should().Be(
            Sha512Hex(EnvelopeHashing.Canonicalize(artifact.Envelope)));
        result.Pqc.Should().Be("verified");
        result.Ok.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_HybridSeal_AgainstVerifierWithoutPqcVerdict_NeverReportsOk()
    {
        // QA scenario: a verifier build that predates the hybrid contract
        // returns complete=true from the classical dimension and NO pqc field.
        // The SDK detected the ML-DSA signer itself, so it must refuse to let
        // that stand in for the hybrid verdict: Pqc → not_checked, Ok → false.
        var mlHeader = Convert.ToBase64String("""{"alg":"ML-DSA-87"}"""u8.ToArray())
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var artifact = ArtifactWith("ignored", ("urn:t:prompt", "prompt"));
        artifact.Signature["signatures"]!.AsArray()
            .Add(new JsonObject { ["protected"] = mlHeader, ["signature"] = "cA" });

        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["objects"] = new JsonObject
            {
                // Legacy shape: classical verdict only, no "pqc" member.
                ["signatureValid"] = true, ["complete"] = true,
                ["objectCount"] = 2, ["suppliedCount"] = 2, ["matchedCount"] = 2,
                ["objects"] = new JsonArray(
                    new JsonObject { ["par"] = "urn:sigill:envelope", ["supplied"] = true, ["hashMatch"] = true },
                    new JsonObject { ["par"] = "urn:t:prompt", ["supplied"] = true, ["hashMatch"] = true }),
                ["missing"] = new JsonArray(), ["unreferenced"] = new JsonArray(),
            },
        })));
        using var client = Client(handler);

        var result = await client.VerifyEvidenceV2Async(
            artifact, new Dictionary<string, byte[]> { ["urn:t:prompt"] = "p"u8.ToArray() });

        result.Complete.Should().BeTrue("the classical verdict is what the old verifier reported");
        result.Pqc.Should().Be("not_checked", "a hybrid JWS with no pqc verdict is unchecked, not absent");
        result.Ok.Should().BeFalse("the classical verdict must never stand in for the hybrid one");
        result.Issues.Should().Contain(i => i.Contains("no pqc verdict"));
    }

    [Fact]
    public async Task Verify_SurfacesMisalignment_AndUncoveredRoles()
    {
        // Envelope claims urn:t:prompt, but the signature signed urn:t:evil.
        var artifact = ArtifactWith("ignored", ("urn:t:prompt", "prompt"));
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["objects"] = new JsonObject
            {
                ["signatureValid"] = true, ["complete"] = false, ["pqc"] = "absent",
                ["objectCount"] = 2, ["suppliedCount"] = 1, ["matchedCount"] = 1,
                ["objects"] = new JsonArray(
                    new JsonObject { ["par"] = "urn:sigill:envelope", ["supplied"] = true, ["hashMatch"] = true },
                    new JsonObject { ["par"] = "urn:t:evil", ["supplied"] = false, ["hashMatch"] = false }),
                ["missing"] = new JsonArray("urn:t:evil"),
                ["unreferenced"] = new JsonArray(),
            },
        })));
        using var client = Client(handler);

        var result = await client.VerifyEvidenceV2Async(artifact, requiredRoles: new[] { "prompt" });

        result.AlignmentOk.Should().BeFalse("the signed object list does not mirror the envelope's");
        result.MissingRoles.Should().ContainSingle().Which.Should().Be("prompt");
        result.Ok.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Contains("align"));
    }
}
