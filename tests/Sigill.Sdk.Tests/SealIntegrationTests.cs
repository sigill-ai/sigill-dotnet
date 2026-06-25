// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors python/tests/test_seal_integration.py. We can't use httpx.MockTransport,
// so we plug a custom HttpMessageHandler into the SigillClient.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public class SealIntegrationTests
{
    /// <summary>
    /// Pluggable handler: caller supplies a function that turns a request into a response.
    /// Captures the most recent request body for assertion convenience.
    /// </summary>
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _impl;
        public List<JsonObject> Requests { get; } = new();
        public FakeHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> impl) => _impl = impl;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.Content is not null)
            {
                var raw = await request.Content.ReadAsStringAsync(ct);
                if (!string.IsNullOrEmpty(raw))
                {
                    try { if (JsonNode.Parse(raw) is JsonObject obj) Requests.Add(obj); }
                    catch (System.Text.Json.JsonException) { /* multipart or non-JSON body — skip capture */ }
                }
            }
            return await _impl(request);
        }
    }

    private static SigillClient ClientWith(FakeHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.sigill.ai") };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "fake");
        return new SigillClient(http);
    }

    private static HttpResponseMessage StampOk(string hashHex, string tsaName = "Test TSA",
        bool qualified = false, string? policyOid = null)
    {
        var imprint = Convert.FromHexString(hashHex);
        var tsr = TsrFactory.MakeTsr(imprint);

        var body = new JsonObject
        {
            ["serial"] = "1234567",
            ["genTime"] = "2026-05-08T12:00:00Z",
            ["hashAlgorithmOid"] = "2.16.840.1.101.3.4.2.1",
            ["hashHex"] = hashHex,
            ["tsrBase64"] = Convert.ToBase64String(tsr),
            ["tsaName"] = tsaName,
            ["qualified"] = qualified,
            ["policyOid"] = policyOid,
        };
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
    }

    // -------------------------------------------------------------- happy path

    [Fact]
    public async Task Seal_calls_tsa_stamp_and_attaches_proof()
    {
        var handler = new FakeHandler(async req =>
        {
            req.RequestUri!.AbsolutePath.Should().Be("/tsa/stamp-hash");
            var body = JsonNode.Parse(await req.Content!.ReadAsStringAsync())!.AsObject();
            return StampOk(body["hashHex"]!.GetValue<string>(), tsaName: "Sigill SDK Test TSA");
        });
        var client = ClientWith(handler);

        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        // Strip integrity and proofs so SealAsync builds them fresh
        expected.Remove("integrity");
        expected.Remove("proofs");
        var input = new AiEvidenceEnvelopeInput(expected);

        var sealed_ = await client.SealAsync(input);

        sealed_.Json["integrity"]!["canonicalization"]!.GetValue<string>().Should().Be("RFC8785");
        sealed_.Json["integrity"]!["envelopeHash"].Should().NotBeNull();
        sealed_.Json["integrity"]!["envelopeHash"]!["alg"]!.GetValue<string>().Should().Be("SHA-256");
        sealed_.Json["proofs"]![0]!["type"]!.GetValue<string>().Should().Be("rfc3161");
        sealed_.Json["proofs"]![0]!["tsaName"]!.GetValue<string>().Should().Be("Sigill SDK Test TSA");

        // The captured request body must use defaults and contain the envelope hash
        handler.Requests.Should().HaveCount(1);
        handler.Requests[0]["tsaSlug"]!.GetValue<string>().Should().Be("auto");
        handler.Requests[0]["qualified"]!.GetValue<bool>().Should().BeFalse();
        handler.Requests[0]["hashHex"]!.GetValue<string>().Should().HaveLength(64); // SHA-256
        handler.Requests[0]["hashHex"]!.GetValue<string>().Should().Be(sealed_.EnvelopeHashHex);
    }

    [Fact]
    public async Task Seal_forwards_tsa_slug_and_qualified()
    {
        var handler = new FakeHandler(async req =>
        {
            var body = JsonNode.Parse(await req.Content!.ReadAsStringAsync())!.AsObject();
            return StampOk(body["hashHex"]!.GetValue<string>(), tsaName: "DigiCert", qualified: true,
                policyOid: "1.3.6.1.4.1.4146.2.2");
        });
        var client = ClientWith(handler);

        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("a").WithModel("p", "n")
            .Build();
        var sealed_ = await client.SealAsync(env, options: new SealOptions
        {
            TsaSlug = "digicert",
            Qualified = true,
        });

        handler.Requests[0]["tsaSlug"]!.GetValue<string>().Should().Be("digicert");
        handler.Requests[0]["qualified"]!.GetValue<bool>().Should().BeTrue();
        sealed_.Json["proofs"]![0]!["qualified"]!.GetValue<bool>().Should().BeTrue();
        sealed_.Json["proofs"]![0]!["policyOid"]!.GetValue<string>().Should().Be("1.3.6.1.4.1.4146.2.2");
    }

    // -------------------------------------------------------------- label

    [Fact]
    public async Task Seal_defaults_label_to_activity_name()
    {
        var handler = new FakeHandler(async req =>
        {
            var body = JsonNode.Parse(await req.Content!.ReadAsStringAsync())!.AsObject();
            return StampOk(body["hashHex"]!.GetValue<string>());
        });
        var client = ClientWith(handler);

        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("ticket.summarize").WithModel("p", "n")
            .Build();
        await client.SealAsync(env);

        handler.Requests[0]["label"]!.GetValue<string>().Should().Be("ticket.summarize");
    }

    [Fact]
    public async Task Seal_explicit_label_overrides_activity_name()
    {
        var handler = new FakeHandler(async req =>
        {
            var body = JsonNode.Parse(await req.Content!.ReadAsStringAsync())!.AsObject();
            return StampOk(body["hashHex"]!.GetValue<string>());
        });
        var client = ClientWith(handler);

        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("ticket.summarize").WithModel("p", "n")
            .Build();
        await client.SealAsync(env, options: new SealOptions { Label = "my custom label" });

        handler.Requests[0]["label"]!.GetValue<string>().Should().Be("my custom label");
    }

    // -------------------------------------------------------------- external payloads

    [Fact]
    public async Task Seal_hashes_supplied_external_payloads()
    {
        var handler = new FakeHandler(async req =>
        {
            var body = JsonNode.Parse(await req.Content!.ReadAsStringAsync())!.AsObject();
            return StampOk(body["hashHex"]!.GetValue<string>());
        });
        var client = ClientWith(handler);

        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("a").WithModel("p", "n")
            .WithPromptRef("prompt").WithOutputRef("output")
            .Build();
        var payloads = new Dictionary<string, byte[]>
        {
            ["prompt"] = Encoding.UTF8.GetBytes("the prompt"),
            ["output"] = Encoding.UTF8.GetBytes("the response"),
        };

        var sealed_ = await client.SealAsync(env, payloads);

        var expectedPromptHex = EnvelopeHashing.HashHex(Encoding.UTF8.GetBytes("the prompt"));
        var expectedOutputHex = EnvelopeHashing.HashHex(Encoding.UTF8.GetBytes("the response"));
        sealed_.Json["prompt"]!["hash"]!["hex"]!.GetValue<string>().Should().Be(expectedPromptHex);
        sealed_.Json["prompt"]!["hash"]!["sizeBytes"]!.GetValue<int>().Should().Be("the prompt".Length);
        sealed_.Json["output"]!["hash"]!["hex"]!.GetValue<string>().Should().Be(expectedOutputHex);
    }

    [Fact]
    public async Task Seal_rejects_predeclared_hash_that_doesnt_match_bytes()
    {
        var handler = new FakeHandler(_ => throw new InvalidOperationException("should not reach HTTP"));
        var client = ClientWith(handler);

        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("a").WithModel("p", "n")
            .Build();
        // Pre-declare a wrong hash on prompt
        env.Json["prompt"] = new JsonObject
        {
            ["ref"] = "prompt",
            ["contentType"] = "text/plain",
            ["encoding"] = "utf-8",
            ["hash"] = new JsonObject { ["alg"] = "SHA-256", ["hex"] = new string('0', 64) },
        };

        var act = async () => await client.SealAsync(env,
            new Dictionary<string, byte[]> { ["prompt"] = Encoding.UTF8.GetBytes("hello") });
        await act.Should().ThrowAsync<SigillHashMismatchException>();
    }

    // -------------------------------------------------------------- TSA outage

    [Fact]
    public async Task Seal_502_raises_timestamp_unavailable()
    {
        var failuresJson = new JsonArray(
            new JsonObject
            {
                ["tsa"] = "DigiCert",
                ["errorClass"] = "timeout",
                ["statusCode"] = null,
                ["message"] = "Request timed out",
                ["latencyMs"] = 10042,
            },
            new JsonObject
            {
                ["tsa"] = "Sectigo",
                ["errorClass"] = "http_status",
                ["statusCode"] = 503,
                ["message"] = "service unavailable",
                ["latencyMs"] = 412,
            });

        var handler = new FakeHandler(_ => Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent(new JsonObject
            {
                ["message"] = "All enabled TSAs failed.",
                ["attemptsTried"] = 2,
                ["failures"] = failuresJson,
            }.ToJsonString(), Encoding.UTF8, "application/json"),
        }));
        var client = ClientWith(handler);

        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("a").WithModel("p", "n")
            .Build();

        var act = async () => await client.SealAsync(env);
        var ex = await act.Should().ThrowAsync<SigillTimestampUnavailableException>();
        ex.Which.AttemptsTried.Should().Be(2);
        ex.Which.Failures.Should().HaveCount(2);
        ex.Which.Failures[0].Tsa.Should().Be("DigiCert");
    }

    // -------------------------------------------------------------- VerifyCades

    [Fact]
    public async Task VerifyCades_parses_response_into_result()
    {
        var fakeBody = """
            {
              "format": "cades",
              "cades": {
                "signaturePresent": true,
                "hashMatch": true,
                "signatureValid": true,
                "certificate": {
                  "subject": "CN=Sigill Platform Seal,O=SIGILL AS",
                  "trust": "trusted_chain"
                },
                "timestamp": {
                  "genTime": "2026-06-25T16:16:31Z",
                  "tsaName": "SSL.com",
                  "qualificationSource": "none"
                },
                "tsrSource": "embedded",
                "error": null,
                "warnings": null
              }
            }
            """;
        JsonObject? capturedBody = null;

        var handler = new FakeHandler(async req =>
        {
            req.RequestUri!.AbsolutePath.Should().Be("/seal/verify-hash");
            capturedBody = (JsonObject)JsonNode.Parse(await req.Content!.ReadAsStringAsync())!;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(fakeBody, Encoding.UTF8, "application/json"),
            };
        });
        var client = ClientWith(handler);

        var data = Encoding.UTF8.GetBytes("original doc");
        var result = await client.VerifyCadesAsync(data, new byte[] { 0x30, 0x00 });

        result.IsValid.Should().BeTrue();
        result.HashMatch.Should().BeTrue();
        result.SignatureValid.Should().BeTrue();
        result.Signer.Should().Be("CN=Sigill Platform Seal,O=SIGILL AS");
        result.Trust.Should().Be("trusted_chain");
        result.TsaName.Should().Be("SSL.com");
        result.GenTime.Should().Be("2026-06-25T16:16:31Z");
        result.Qualified.Should().BeFalse();
        result.Error.Should().BeNull();
        result.Warnings.Should().BeEmpty();
        capturedBody.Should().NotBeNull();
        capturedBody!["hashHex"]!.GetValue<string>()
            .Should().Be(Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant());
        capturedBody["p7sBase64"]!.GetValue<string>().Should().Be(Convert.ToBase64String(new byte[] { 0x30, 0x00 }));
        capturedBody.ContainsKey("tsrBase64").Should().BeFalse();
    }

    [Fact]
    public async Task VerifyCades_includes_tsr_field_when_supplied()
    {
        JsonObject? capturedBody = null;

        var handler = new FakeHandler(async req =>
        {
            capturedBody = (JsonObject)JsonNode.Parse(await req.Content!.ReadAsStringAsync())!;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""
                    {"format":"cades","cades":{"hashMatch":false,"signatureValid":false,"error":"TSR does not cover this .p7s"}}
                    """, Encoding.UTF8, "application/json"),
            };
        });
        var client = ClientWith(handler);

        var tsr = new byte[] { 0x30, 0x01, 0x00 };
        var result = await client.VerifyCadesAsync(
            Encoding.UTF8.GetBytes("doc"),
            new byte[] { 0x30, 0x00 },
            tsr: tsr);

        capturedBody!.ContainsKey("tsrBase64").Should().BeTrue();
        capturedBody["tsrBase64"]!.GetValue<string>().Should().Be(Convert.ToBase64String(tsr));
        result.IsValid.Should().BeFalse();
        result.Error.Should().Be("TSR does not cover this .p7s");
    }

    // -------------------------------------------------------------- SealCades

    [Fact]
    public async Task SealCades_sends_hash_and_returns_p7s_bytes()
    {
        var fakePkcs7 = new byte[] { 0x30, 0x82, 0x01, 0x00 };
        JsonObject? capturedBody = null;

        var handler = new FakeHandler(async req =>
        {
            req.RequestUri!.AbsolutePath.Should().Be("/seal/sign-hash");
            capturedBody = (JsonObject)JsonNode.Parse(await req.Content!.ReadAsStringAsync())!;
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(fakePkcs7),
            };
            resp.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("application/pkcs7-signature");
            return resp;
        });
        var client = ClientWith(handler);

        var data = Encoding.UTF8.GetBytes("this is a JSON envelope or any document");
        var certId = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-ffffffffffff");
        var p7s = await client.SealCadesAsync(data, certId);

        p7s.Should().Equal(fakePkcs7);
        capturedBody.Should().NotBeNull();
        capturedBody!["hashHex"]!.GetValue<string>()
            .Should().Be(Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant());
        capturedBody["certificateId"]!.GetValue<string>()
            .Should().Be("aaaaaaaa-bbbb-cccc-dddd-ffffffffffff");
        capturedBody["qualified"]!.GetValue<bool>().Should().BeFalse();
        capturedBody.ContainsKey("label").Should().BeFalse();
    }

    [Fact]
    public async Task SealCades_forwards_label_and_qualified()
    {
        JsonObject? capturedBody = null;

        var handler = new FakeHandler(async req =>
        {
            capturedBody = (JsonObject)JsonNode.Parse(await req.Content!.ReadAsStringAsync())!;
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(new byte[] { 0x30, 0x00 }),
            };
        });
        var client = ClientWith(handler);

        await client.SealCadesAsync(Encoding.UTF8.GetBytes("doc"),
            Guid.NewGuid(), label: "my-doc.json", qualified: true);

        capturedBody!["label"]!.GetValue<string>().Should().Be("my-doc.json");
        capturedBody["qualified"]!.GetValue<bool>().Should().BeTrue();
    }

    // -------------------------------------------------------------- end-to-end

    [Fact]
    public async Task Seal_then_verify_roundtrip()
    {
        // Acid test: seal through the SDK, verify through the SDK. Must be valid.
        var handler = new FakeHandler(async req =>
        {
            var body = JsonNode.Parse(await req.Content!.ReadAsStringAsync())!.AsObject();
            return StampOk(body["hashHex"]!.GetValue<string>(), tsaName: "Test TSA");
        });
        var client = ClientWith(handler);

        var env = new EnvelopeBuilder()
            .WithPurpose("summarization")
            .WithActor("service", "svc-x")
            .WithActivity("ticket.summarize")
            .WithModel("anthropic", "claude-opus-4-7")
            .WithPromptRef("p")
            .WithOutputRef("o")
            .Build();
        var payloads = new Dictionary<string, byte[]>
        {
            ["p"] = Encoding.UTF8.GetBytes("prompt bytes"),
            ["o"] = Encoding.UTF8.GetBytes("output bytes"),
        };

        var sealed_ = await client.SealAsync(env, payloads);
        var result = await client.VerifyAsync(sealed_, payloads);

        result.IsValid.Should().BeTrue("got issues: " + string.Join("; ", result.Issues.Select(i => i.Message)));
        result.Timestamps.Should().HaveCount(1);
    }
}
