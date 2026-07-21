// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// JAdES detached sealing (ETSI TS 119 182-1) — same hash-only model as CAdES,
// routed through /seal/sign-hash with format: "jades". Verification goes via
// /seal/verify-hash, which sniffs the artifact bytes (JSON → JAdES).

using System;
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

public class JadesSealTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, string, Task<HttpResponseMessage>> _impl;
        public JsonObject? LastBody { get; private set; }
        public FakeHandler(Func<HttpRequestMessage, string, Task<HttpResponseMessage>> impl) => _impl = impl;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            if (!string.IsNullOrEmpty(body)) LastBody = (JsonObject)JsonNode.Parse(body)!;
            return await _impl(request, body);
        }
    }

    private static SigillClient ClientWith(FakeHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.sigill.ai") };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "fake");
        return new SigillClient(http);
    }

    // The artifact is JSON text (a detached JWS with sigD), not DER.
    private static readonly byte[] FakeJades =
        Encoding.UTF8.GetBytes("""{"payload":"","signatures":[{"protected":"e30","signature":"c2ln"}]}""");

    [Fact]
    public async Task SealJades_sends_format_jades_and_returns_artifact_bytes()
    {
        var handler = new FakeHandler((req, _) =>
        {
            req.RequestUri!.AbsolutePath.Should().Be("/seal/sign-hash");
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(FakeJades) };
            resp.Content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");
            return Task.FromResult(resp);
        });
        var client = ClientWith(handler);

        var data = Encoding.UTF8.GetBytes("""{"decision":"approved","amount":42000}""");
        var artifact = await client.SealJadesAsync(data, Guid.NewGuid(),
            label: "decision.json", contentType: "application/json");

        artifact.Should().Equal(FakeJades);
        var sent = handler.LastBody!;
        sent["format"]!.GetValue<string>().Should().Be("jades");
        sent["contentType"]!.GetValue<string>().Should().Be("application/json");
        sent["hashHex"]!.GetValue<string>()
            .Should().Be(Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant());
        sent.ContainsKey("pqc").Should().BeFalse();
    }

    [Fact]
    public async Task SealJades_pqc_sends_sha512_and_flag()
    {
        var handler = new FakeHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(FakeJades) }));
        var client = ClientWith(handler);

        var data = Encoding.UTF8.GetBytes("content");
        await client.SealJadesAsync(data, Guid.NewGuid(), pqc: true);

        var sent = handler.LastBody!;
        sent["pqc"]!.GetValue<bool>().Should().BeTrue();
        sent["hashHex512"]!.GetValue<string>()
            .Should().Be(Convert.ToHexString(SHA512.HashData(data)).ToLowerInvariant());
    }

    [Fact]
    public async Task VerifyJades_parses_jades_branch_into_result()
    {
        const string fakeBody = """
            {
              "format": "jades",
              "jades": {
                "signaturePresent": true,
                "hashMatch": true,
                "signatureValid": true,
                "certificate": { "subject": "CN=Sigill Platform Seal,O=SIGILL AS", "trust": "trusted_chain" },
                "timestamp": { "genTime": "2026-07-19T10:00:00Z", "tsaName": "SSL.com", "qualificationSource": "none" },
                "tsrSource": "embedded",
                "error": null,
                "warnings": null,
                "postQuantum": {
                  "present": true, "valid": true, "signatureValid": true,
                  "contentBound": "yes", "trusted": "not_evaluated", "algorithm": "ml-dsa-87"
                }
              }
            }
            """;
        var handler = new FakeHandler((req, _) =>
        {
            req.RequestUri!.AbsolutePath.Should().Be("/seal/verify-hash");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(fakeBody, Encoding.UTF8, "application/json"),
            });
        });
        var client = ClientWith(handler);

        var data = Encoding.UTF8.GetBytes("""{"decision":"approved"}""");
        var result = await client.VerifyJadesAsync(data, FakeJades);

        result.IsValid.Should().BeTrue();
        result.Signer.Should().Be("CN=Sigill Platform Seal,O=SIGILL AS");
        result.Trust.Should().Be("trusted_chain");
        result.TsaName.Should().Be("SSL.com");
        result.Qualified.Should().BeFalse();
        result.PostQuantum.Should().NotBeNull();
        result.PostQuantum!.Algorithm.Should().Be("ml-dsa-87");
        result.PostQuantum.ContentBound.Should().Be("yes");

        // Both digests always go along so a hybrid seal's SHA-512 binding is checked.
        var sent = handler.LastBody!;
        sent["hashHex"]!.GetValue<string>()
            .Should().Be(Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant());
        sent["hashHex512"]!.GetValue<string>()
            .Should().Be(Convert.ToHexString(SHA512.HashData(data)).ToLowerInvariant());
        sent["p7sBase64"]!.GetValue<string>().Should().Be(Convert.ToBase64String(FakeJades));
    }
}
