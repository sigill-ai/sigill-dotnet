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
                new AiEvidenceV2Payload { Role = "output", Bytes = output, Uri = "objects/test-out", ContentType = "text/markdown" },
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
        objects[0]!["uri"]!.GetValue<string>().Should().MatchRegex("^objects/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            "generated URIs are opaque production-profile references by default (spec §3.1)");
        objects[1]!["uri"]!.GetValue<string>().Should().Be("objects/test-out");

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

        var reservedLocator = () => client.SealEvidenceV2Async(CoreEnvelope(),
            new[] { new AiEvidenceV2Payload { Role = "prompt", Bytes = bytes, Uri = "sigill-envelope.json" } },
            Guid.NewGuid());
        await reservedLocator.Should().ThrowAsync<SigillException>().WithMessage("*reserved*");

        var dup = () => client.SealEvidenceV2Async(CoreEnvelope(),
            new[]
            {
                new AiEvidenceV2Payload { Role = "prompt", Bytes = bytes, Uri = "objects/a" },
                new AiEvidenceV2Payload { Role = "output", Bytes = bytes, Uri = "objects/a" },
            },
            Guid.NewGuid());
        await dup.Should().ThrowAsync<SigillException>().WithMessage("*Duplicate*");

        var role = () => client.SealEvidenceV2Async(CoreEnvelope(),
            new[] { new AiEvidenceV2Payload { Role = "thought", Bytes = bytes } },
            Guid.NewGuid());
        await role.Should().ThrowAsync<SigillException>().WithMessage("*role*");

        handler.Requests.Should().BeEmpty("validation failures must not reach the network");
    }

    private static AiEvidenceV2Artifact ArtifactWith(string envelopeHex, params (string Uri, string Role)[] objects) =>
        ArtifactSigned(EnvelopeReferences.LegacyReference, objects.Select(o => o.Uri).ToArray(), envelopeHex, objects);

    /// <summary>An artifact whose classical header signs <c>pars = [envelopeRef, signedObjects…]</c>.</summary>
    private static AiEvidenceV2Artifact ArtifactSigned(
        string envelopeRef, string[] signedObjects, string envelopeHex, params (string Uri, string Role)[] objects)
    {
        var envObjects = new JsonArray(objects
            .Select(o => (JsonNode)new JsonObject { ["uri"] = o.Uri, ["role"] = o.Role }).ToArray());
        var envelope = CoreEnvelope();
        envelope["schemaName"] = "AiEvidenceEnvelope";
        envelope["schemaVersion"] = "2";
        envelope["objects"] = envObjects;
        var header = new JsonObject
        {
            ["alg"] = "RS256",
            ["sigD"] = new JsonObject
            {
                ["pars"] = new JsonArray(new[] { envelopeRef }.Concat(signedObjects).Select(u => (JsonNode)u!).ToArray()),
            },
        };
        var protectedB64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(header.ToJsonString()))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var signature = new JsonObject
        {
            ["signatures"] = new JsonArray(new JsonObject { ["protected"] = protectedB64, ["signature"] = "c2ln" }),
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
        var artifact = ArtifactSigned(EnvelopeReferences.LegacyReference, new[] { "urn:t:evil" }, "ignored", ("urn:t:prompt", "prompt"));
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

    // ── v2.1 reference form (spec §3.1, §5.2, §5.4) ───────────────────────────

    private static FakeHandler Verdict(params string[] pars) => new((_, _) => Task.FromResult(Json(new JsonObject
    {
        ["objects"] = new JsonObject
        {
            ["signatureValid"] = true, ["complete"] = true, ["pqc"] = "absent",
            ["objectCount"] = pars.Length, ["suppliedCount"] = pars.Length, ["matchedCount"] = pars.Length,
            ["objects"] = new JsonArray(pars.Select(p =>
                (JsonNode)new JsonObject { ["par"] = p, ["supplied"] = true, ["hashMatch"] = true }).ToArray()),
            ["missing"] = new JsonArray(), ["unreferenced"] = new JsonArray(),
        },
    })));

    [Theory]
    [InlineData(EnvelopeReferences.LocatorReference)]
    [InlineData(EnvelopeReferences.LegacyReference)]
    public async Task Verify_KeysTheEnvelopeDigestByTheReferenceTheSignatureCarries(string envelopeRef)
    {
        var prompt = "p"u8.ToArray();
        var artifact = ArtifactSigned(envelopeRef, new[] { "objects/p" }, "ignored", ("objects/p", "prompt"));
        var handler = Verdict(envelopeRef, "objects/p");
        using var client = Client(handler);

        var result = await client.VerifyEvidenceV2Async(artifact, new Dictionary<string, byte[]> { ["objects/p"] = prompt });

        var digests = handler.Requests.Single().Body["digests"]!.AsObject();
        digests.Select(kv => kv.Key).Should().BeEquivalentTo(new[] { envelopeRef, "objects/p" },
            "the envelope digest travels under this signature's own reference, never under both");
        digests[envelopeRef]!.GetValue<string>().Should().Be(Sha256Hex(EnvelopeHashing.Canonicalize(artifact.Envelope)));
        result.AlignmentOk.Should().BeTrue();
        result.Ok.Should().BeTrue("a legacy reference is a diagnostic, never a failure");
        EnvelopeReferences.Classify(envelopeRef).Should().NotBe(EnvelopeReferenceForm.Invalid);
        if (envelopeRef == EnvelopeReferences.LegacyReference)
            result.Notes.Should().Equal(EnvelopeReferences.LegacyDiagnostic);
        else
            result.Notes.Should().BeEmpty();
    }

    [Fact]
    public async Task Verify_RejectsAnUnknownEnvelopeReference()
    {
        var artifact = ArtifactSigned("envelope.json", new[] { "objects/p" }, "ignored", ("objects/p", "prompt"));
        var handler = Verdict("envelope.json", "objects/p");
        using var client = Client(handler);

        var result = await client.VerifyEvidenceV2Async(artifact, new Dictionary<string, byte[]> { ["objects/p"] = "p"u8.ToArray() });

        handler.Requests.Single().Body["digests"]!.AsObject().ContainsKey("envelope.json")
            .Should().BeFalse("an unknown name is never trusted as the envelope");
        result.AlignmentOk.Should().BeFalse();
        result.Ok.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Contains("not an envelope reference"));
    }

    [Theory]
    [InlineData(EnvelopeReferences.LocatorReference)]
    [InlineData(EnvelopeReferences.LegacyReference)]
    public async Task Verify_FailsWhenAnObjectUsesAReservedName(string reserved)
    {
        var artifact = ArtifactSigned(EnvelopeReferences.LocatorReference, new[] { reserved }, "ignored", (reserved, "prompt"));
        using var client = Client(Verdict(EnvelopeReferences.LocatorReference, reserved));

        var result = await client.VerifyEvidenceV2Async(artifact);

        result.Ok.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Contains("reserved"));
    }

    [Theory]
    [InlineData("", false)]
    [InlineData(".", false)]
    [InlineData("..", false)]
    [InlineData("a/", false)]
    [InlineData("/a", false)]
    [InlineData("a//b", false)]
    [InlineData("a\\b", false)]
    [InlineData("a b", false)]
    [InlineData("a%20b", false)]
    [InlineData("a?b", false)]
    [InlineData("a#b", false)]
    [InlineData("urn:x", false)]
    [InlineData("https://x", false)]
    [InlineData("objects/../x", false)]
    [InlineData("a\tb", false)]
    [InlineData("ø", false)]
    [InlineData("a", true)]
    [InlineData("objects/6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90", true)]
    [InlineData("x/y.z/A_b~c-d", true)]
    [InlineData("...", true)]
    public void ProductionProfile_Boundaries(string uri, bool expected) =>
        EnvelopeReferences.IsProductionReference(uri).Should().Be(expected, uri);

    [Fact]
    public void NewObjectUri_IsInTheProductionProfile()
    {
        var uri = EnvelopeReferences.NewObjectUri();
        EnvelopeReferences.IsProductionReference(uri).Should().BeTrue();
        uri.Should().MatchRegex("^objects/[0-9a-f-]{36}$");
        EnvelopeReferences.IsReserved(uri).Should().BeFalse();
    }

    [Theory]
    [InlineData("urn:uuid:6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90")]
    [InlineData("contract olsen.pdf")]
    [InlineData("https://example.com/x")]
    public async Task Seal_RejectsCallerUrisOutsideTheProductionProfile(string uri)
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject())));
        using var client = Client(handler);

        var seal = () => client.SealEvidenceV2Async(CoreEnvelope(),
            new[] { new AiEvidenceV2Payload { Role = "prompt", Bytes = "x"u8.ToArray(), Uri = uri } }, Guid.NewGuid());

        await seal.Should().ThrowAsync<SigillException>().WithMessage("*production-profile*");
        handler.Requests.Should().BeEmpty();
    }

    // ── Round-4 regressions: a verifier that really compares digests ─────────

    private static string B64Url(string json) =>
        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(json)).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static string Header(string alg, params string[] pars) =>
        B64Url(new JsonObject
        {
            ["alg"] = alg,
            ["sigD"] = new JsonObject { ["pars"] = new JsonArray(pars.Select(p => (JsonNode)p!).ToArray()) },
        }.ToJsonString());

    /// <summary>Compares the supplied digests with what was signed, like the platform; hybrid when expected512 is given.</summary>
    private static FakeHandler Comparing(IReadOnlyList<string> pars, IReadOnlyDictionary<string, string> expected,
        IReadOnlyDictionary<string, string>? expected512 = null) => new((_, body) =>
    {
        var supplied = body["digests"]!.AsObject();
        var verdicts = pars.Select(p => (JsonNode)new JsonObject
        {
            ["par"] = p, ["supplied"] = supplied.ContainsKey(p),
            ["hashMatch"] = supplied[p]?.GetValue<string>() == expected[p],
        }).ToArray();
        var allMatch = pars.All(p => supplied[p]?.GetValue<string>() == expected[p]);
        var pqc = "absent";
        if (expected512 is not null)
            pqc = body["digests512"] is JsonObject d512
                ? pars.All(p => d512[p]?.GetValue<string>() == expected512[p]) ? "verified" : "failed"
                : "not_checked";
        return Task.FromResult(Json(new JsonObject
        {
            ["objects"] = new JsonObject
            {
                ["signatureValid"] = true, ["complete"] = allMatch && pqc is "absent" or "verified", ["pqc"] = pqc,
                ["objectCount"] = pars.Count, ["suppliedCount"] = pars.Count(supplied.ContainsKey),
                ["matchedCount"] = pars.Count(p => supplied[p]?.GetValue<string>() == expected[p]),
                ["objects"] = new JsonArray(verdicts),
                ["missing"] = new JsonArray(pars.Where(p => !supplied.ContainsKey(p)).Select(p => (JsonNode)p!).ToArray()),
                ["unreferenced"] = new JsonArray(),
            },
        }));
    });

    [Theory]
    [InlineData(EnvelopeReferences.LocatorReference)]
    [InlineData(EnvelopeReferences.LegacyReference)]
    public async Task Verify_RefusesAPayloadUnderEitherEnvelopeReference(string reserved)
    {
        // Codex R4: supplying the ORIGINAL envelope bytes under the envelope key used to replace the SDK's own digest,
        // so an edited envelope verified.
        var artifact = ArtifactSigned(EnvelopeReferences.LocatorReference, new[] { "objects/p" }, "ignored", ("objects/p", "prompt"));
        var original = EnvelopeHashing.Canonicalize(artifact.Envelope);
        artifact.Envelope["purpose"] = "edited after sealing";
        var handler = Verdict(EnvelopeReferences.LocatorReference, "objects/p");
        using var client = Client(handler);

        var verify = () => client.VerifyEvidenceV2Async(artifact,
            new Dictionary<string, byte[]> { [reserved] = original, ["objects/p"] = "p"u8.ToArray() });

        await verify.Should().ThrowAsync<SigillException>().WithMessage("*reserved*");
        handler.Requests.Should().BeEmpty();
    }

    [Theory]
    [InlineData(EnvelopeReferences.LocatorReference, false)]
    [InlineData(EnvelopeReferences.LegacyReference, false)]
    [InlineData(EnvelopeReferences.LocatorReference, true)]
    [InlineData(EnvelopeReferences.LegacyReference, true)]
    public async Task Verify_AnEditedEnvelopeFails_InBothForms(string envelopeRef, bool hybrid)
    {
        var prompt = "p"u8.ToArray();
        var artifact = ArtifactSigned(envelopeRef, new[] { "objects/p" }, "ignored", ("objects/p", "prompt"));
        var canonical = EnvelopeHashing.Canonicalize(artifact.Envelope);
        var pars = new[] { envelopeRef, "objects/p" };
        var expected = new Dictionary<string, string> { [envelopeRef] = Sha256Hex(canonical), ["objects/p"] = Sha256Hex(prompt) };
        Dictionary<string, string>? expected512 = null;
        if (hybrid)
        {
            artifact.Signature["signatures"]!.AsArray().Add(new JsonObject { ["protected"] = Header("ML-DSA-87", pars), ["signature"] = "cA" });
            expected512 = new() { [envelopeRef] = Sha512Hex(canonical), ["objects/p"] = Sha512Hex(prompt) };
        }
        var payloads = new Dictionary<string, byte[]> { ["objects/p"] = prompt };

        using (var client = Client(Comparing(pars, expected, expected512)))
            (await client.VerifyEvidenceV2Async(artifact, payloads)).Ok.Should().BeTrue("the untouched artifact verifies");

        artifact.Envelope["purpose"] = "edited after sealing";
        using (var client = Client(Comparing(pars, expected, expected512)))
        {
            var result = await client.VerifyEvidenceV2Async(artifact, payloads);
            result.Ok.Should().BeFalse();
            result.Objects.Single(o => o.Uri == envelopeRef).HashMatch.Should().BeFalse();
        }
    }

    [Fact]
    public async Task Verify_HybridLocatorSeal_KeysSha512ByTheLocatorReference()
    {
        var prompt = "p"u8.ToArray();
        var pars = new[] { EnvelopeReferences.LocatorReference, "objects/p" };
        var artifact = ArtifactSigned(pars[0], new[] { "objects/p" }, "ignored", ("objects/p", "prompt"));
        artifact.Signature["signatures"]!.AsArray().Add(new JsonObject { ["protected"] = Header("ML-DSA-87", pars), ["signature"] = "cA" });
        var canonical = EnvelopeHashing.Canonicalize(artifact.Envelope);
        var handler = Comparing(pars,
            new Dictionary<string, string> { [pars[0]] = Sha256Hex(canonical), ["objects/p"] = Sha256Hex(prompt) },
            new Dictionary<string, string> { [pars[0]] = Sha512Hex(canonical), ["objects/p"] = Sha512Hex(prompt) });
        using var client = Client(handler);

        var result = await client.VerifyEvidenceV2Async(artifact, new Dictionary<string, byte[]> { ["objects/p"] = prompt });

        var d512 = handler.Requests.Single().Body["digests512"]!.AsObject();
        d512.Select(kv => kv.Key).Should().BeEquivalentTo(pars);
        d512[pars[0]]!.GetValue<string>().Should().Be(Sha512Hex(canonical));
        result.Pqc.Should().Be("verified");
        result.Ok.Should().BeTrue();
    }

    [Fact]
    public async Task Verify_PqcEntryWithAnotherReferenceForm_FailsAlignment()
    {
        var artifact = ArtifactSigned(EnvelopeReferences.LocatorReference, new[] { "objects/p" }, "ignored", ("objects/p", "prompt"));
        artifact.Signature["signatures"]!.AsArray().Add(new JsonObject
        {
            ["protected"] = Header("ML-DSA-87", EnvelopeReferences.LegacyReference, "objects/p"), ["signature"] = "cA",
        });
        using var client = Client(Verdict(EnvelopeReferences.LocatorReference, "objects/p"));

        var result = await client.VerifyEvidenceV2Async(artifact, new Dictionary<string, byte[]> { ["objects/p"] = "p"u8.ToArray() });

        result.AlignmentOk.Should().BeFalse();
        result.Ok.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Contains("ML-DSA"));
    }

    public static IEnumerable<object[]> StructurallyInvalidHeaders()
    {
        foreach (var form in new[] { EnvelopeReferences.LocatorReference, EnvelopeReferences.LegacyReference })
        {
            yield return new object[] { "duplicate-member", form,
                B64Url($$$"""{"alg":"RS256","alg":"RS256","sigD":{"pars":["{{{form}}}","objects/p"]}}""") };
            yield return new object[] { "duplicate-pars", form,
                B64Url($$$"""{"alg":"RS256","sigD":{"pars":["evil"],"pars":["{{{form}}}","objects/p"]}}""") };
            yield return new object[] { "missing-pars", form, B64Url("""{"alg":"RS256","sigD":{}}""") };
            yield return new object[] { "non-string-pars", form, B64Url($$$"""{"alg":"RS256","sigD":{"pars":["{{{form}}}",7]}}""") };
            yield return new object[] { "two-classical", form, Header("RS256", form, "objects/p") };
        }
    }

    [Theory]
    [MemberData(nameof(StructurallyInvalidHeaders))]
    public async Task Verify_RefusesAStructurallyInvalidHeader_EvenWhenTheCryptoTierIsLenient(string name, string form, string protectedB64)
    {
        var artifact = ArtifactSigned(form, new[] { "objects/p" }, "ignored", ("objects/p", "prompt"));
        var entries = artifact.Signature["signatures"]!.AsArray();
        if (name == "two-classical")
            entries.Add(new JsonObject { ["protected"] = protectedB64, ["signature"] = "c2ln" });
        else
            entries[0]!["protected"] = protectedB64;
        using var client = Client(Verdict(form, "objects/p")); // a lenient service that reports everything fine

        var result = await client.VerifyEvidenceV2Async(artifact, new Dictionary<string, byte[]> { ["objects/p"] = "p"u8.ToArray() });

        result.AlignmentOk.Should().BeFalse(name);
        result.Ok.Should().BeFalse(name);
        result.Notes.Should().BeEmpty("a form is only reported from a structurally valid header");
    }

    [Fact]
    public async Task SignObjectHashes_EnforcesTheProfile_ExceptForReusedUris()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(Json(new JsonObject
        {
            ["signature"] = new JsonObject { ["signatures"] = new JsonArray() },
        })));
        using var client = Client(handler);
        var hex = new string('a', 64);
        SignedObjectDigest Obj(string uri) => new() { Uri = uri, HashHex = hex };

        var legacy = () => client.SignObjectHashesAsync(hex, new[] { Obj("urn:uuid:6f1c2a4e-0b7d-4c1e-9a52-3d8f0e1b7c90") }, Guid.NewGuid());
        await legacy.Should().ThrowAsync<SigillException>().WithMessage("*production-profile*");
        foreach (var reserved in new[] { EnvelopeReferences.LocatorReference, EnvelopeReferences.LegacyReference })
        {
            var r = () => client.SignObjectHashesAsync(hex, new[] { Obj(reserved) }, Guid.NewGuid(),
                new ObjectSignOptions { ReusedUris = new[] { reserved } });
            await r.Should().ThrowAsync<SigillException>().WithMessage("*reserved*", "reuse never admits a reserved name");
        }
        handler.Requests.Should().BeEmpty();

        // An evaluation of a run that straddles the upgrade re-references the control set its Control Artifact
        // sealed under a legacy URI: the transition allowance (spec §10.1). Its own new objects still conform.
        const string reusedLegacy = "urn:uuid:00000000-0000-4000-8000-000000000001";
        try
        {
            await client.SignObjectHashesAsync(hex, new[] { Obj("objects/observed"), Obj(reusedLegacy) }, Guid.NewGuid(),
                new ObjectSignOptions { ReusedUris = new[] { reusedLegacy } });
        }
        catch (SigillException e) when (!e.Message.Contains("production-profile") && !e.Message.Contains("reserved")) { }
        handler.Requests.Should().ContainSingle().Which.Body["objects"]!.AsArray()
            .Select(o => o!["uri"]!.GetValue<string>()).Should().Equal("objects/observed", reusedLegacy);
    }

    // Codex round-4 reviewer cases, kept verbatim as regressions.
    [Theory]
    [InlineData(EnvelopeReferences.LocatorReference)]
    [InlineData(EnvelopeReferences.LegacyReference)]
    public async Task Codex_ExternalPayloadMustNotReplaceEnvelopeDigest(string envelopeRef)
    {
        var artifact = ArtifactSigned(envelopeRef, Array.Empty<string>(), "ignored");
        var original = EnvelopeHashing.Canonicalize(artifact.Envelope);
        artifact.Envelope["purpose"]!["category"] = "tampered-purpose";
        var handler = new FakeHandler((_, body) => {
            var match = body["digests"]![envelopeRef]!.GetValue<string>() == Sha256Hex(original);
            return Task.FromResult(Json(new JsonObject {
                ["objects"] = new JsonObject {
                    ["signatureValid"] = true, ["complete"] = match, ["pqc"] = "absent",
                    ["objectCount"] = 1, ["suppliedCount"] = 1, ["matchedCount"] = match ? 1 : 0,
                    ["objects"] = new JsonArray(new JsonObject {
                        ["par"] = envelopeRef, ["supplied"] = true, ["hashMatch"] = match
                    }), ["missing"] = new JsonArray(), ["unreferenced"] = new JsonArray()
                }
            }));
        });
        using var client = Client(handler);
        try {
            var result = await client.VerifyEvidenceV2Async(artifact,
                new Dictionary<string, byte[]> { [envelopeRef] = original });
            result.Ok.Should().BeFalse("the displayed envelope was modified after sealing");
        } catch (SigillException) { }
    }

    [Theory]
    [InlineData(EnvelopeReferences.LocatorReference)]
    [InlineData(EnvelopeReferences.LegacyReference)]
    public async Task Codex_DuplicateProtectedHeaderMustNotPassGenericProfile(string envelopeRef)
    {
        var artifact = ArtifactSigned(envelopeRef, Array.Empty<string>(), "ignored");
        var raw = "{\"alg\":\"RS256\",\"alg\":\"RS256\",\"sigD\":{\"pars\":[\"" + envelopeRef + "\"]}}";
        artifact.Signature["signatures"]![0]!["protected"] = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(raw))
            .Replace('+','-').Replace('/','_').TrimEnd('=');
        using var client = Client(Verdict(envelopeRef));
        var result = await client.VerifyEvidenceV2Async(artifact);
        result.Ok.Should().BeFalse("the profile must reject the non-I-JSON protected header even with a lenient crypto service");
    }
}
