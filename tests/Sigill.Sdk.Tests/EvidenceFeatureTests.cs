// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Evidence-store features: create-time tags, the two-phase PAdES flow
// (prepare → seal-prepared / complete-from-escrow), and the evidence helpers
// (GetSealCmsAsync, GetEvidenceRecordAsync, LookupAsync, ExportAuditPackageAsync).
// All against a fake HTTP handler; mirrors the Python SDK's test_evidence_features.

using System;
using System.Collections.Generic;
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
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public class EvidenceFeatureTests
{
    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, string, Task<HttpResponseMessage>> _impl;
        public List<(string Path, string Body)> Calls { get; } = new();
        public FakeHandler(Func<HttpRequestMessage, string, Task<HttpResponseMessage>> impl) => _impl = impl;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
            Calls.Add((request.RequestUri!.AbsolutePath, body));
            return await _impl(request, body);
        }
    }

    private static SigillClient ClientWith(FakeHandler handler)
    {
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.sigill.ai") };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "fake");
        return new SigillClient(http);
    }

    private static byte[] MinimalPdf()
    {
        const string pdf = "%PDF-1.4\n" +
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
            "xref\n0 4\n0000000000 65535 f \n" +
            "trailer\n<< /Size 4 /Root 1 0 R >>\n" +
            "startxref\n9\n%%EOF\n";
        return Encoding.ASCII.GetBytes(pdf);
    }

    private static readonly byte[] FakeCms = Enumerable.Range(0, 900).Select(i => (byte)(i % 251)).ToArray();
    private const string OperationId = "6a1e12e8-6bb9-4d0e-9f6e-1c2d3e4f5a6b";
    private const string TxId = "9c7cbb17-aaaa-bbbb-cccc-ddddeeeeffff";

    private static HttpResponseMessage SignPadesOk()
    {
        var body = new JsonObject
        {
            ["cmsBase64"]     = Convert.ToBase64String(FakeCms),
            ["certChainDers"] = new JsonArray(),
            ["ocspDers"]      = new JsonArray(),
            ["operationId"]   = OperationId,
            ["certificateId"] = "0b7f7c6e-1111-2222-3333-444455556666",
            ["timestampedBy"] = "Test TSA",
            ["qualified"]     = false,
            ["format"]        = "pades-b-t",
        };
        return Json(body);
    }

    private static HttpResponseMessage Json(JsonObject body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };

    // ------------------------------------------------------------------ tags

    [Fact]
    public async Task Tags_AreForwarded_OnAllSealMethods()
    {
        var bodies = new Dictionary<string, JsonObject>();
        var handler = new FakeHandler((req, body) =>
        {
            var path = req.RequestUri!.AbsolutePath;
            if (body.Length > 0) bodies[path] = (JsonObject)JsonNode.Parse(body)!;
            return Task.FromResult(path switch
            {
                "/seal/sign-pades-hash" => SignPadesOk(),
                "/tsa/stamp-hash" => Json(new JsonObject
                {
                    ["tsrBase64"] = Convert.ToBase64String(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 }),
                    ["tsaName"]   = "Test TSA",
                }),
                _ => new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new ByteArrayContent(Encoding.ASCII.GetBytes("sig-bytes")) },
            });
        });
        var client = ClientWith(handler);
        var tags = new[] { "release-4.2", "backend" };
        var certId = Guid.NewGuid();

        await client.SealCadesAsync(Encoding.ASCII.GetBytes("data"), certId,
            tags: tags, reminders: "on", reminderDays: 60);
        bodies["/seal/sign-hash"]["tags"]!.AsArray().Select(n => n!.GetValue<string>()).Should().Equal(tags);
        bodies["/seal/sign-hash"]["reminders"]!.GetValue<string>().Should().Be("on");
        bodies["/seal/sign-hash"]["reminderDays"]!.GetValue<int>().Should().Be(60);

        await client.SealJadesAsync(Encoding.ASCII.GetBytes("{\"a\":1}"), certId,
            tags: tags, reminders: "off");
        bodies["/seal/sign-hash"]["tags"]!.AsArray().Select(n => n!.GetValue<string>()).Should().Equal(tags);
        bodies["/seal/sign-hash"]["reminders"]!.GetValue<string>().Should().Be("off");

        await client.SealPadesAsync(MinimalPdf(), certId,
            new PadesSealOptions { Ltv = false, Tags = tags });
        bodies["/seal/sign-pades-hash"]["tags"]!.AsArray().Select(n => n!.GetValue<string>()).Should().Equal(tags);
    }

    [Fact]
    public async Task Tags_AreOmitted_WhenNotSupplied()
    {
        JsonObject? seen = null;
        var handler = new FakeHandler((req, body) =>
        {
            seen = (JsonObject)JsonNode.Parse(body)!;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new ByteArrayContent(Encoding.ASCII.GetBytes("sig-bytes")) });
        });
        var client = ClientWith(handler);

        await client.SealCadesAsync(Encoding.ASCII.GetBytes("data"), Guid.NewGuid());
        seen!.ContainsKey("tags").Should().BeFalse();
        seen.ContainsKey("reminders").Should().BeFalse();
    }

    // -------------------------------------------------------- two-phase flow

    [Fact]
    public void PrepareRecover_Roundtrip_IsExact()
    {
        var client = ClientWith(new FakeHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError))));

        var checkpoint = client.PreparePades(MinimalPdf());
        var recovered  = PdfIncrementalSigner.Recover(checkpoint.Bytes);

        // The recovered offsets and digest must match what Prepare computed —
        // the checkpoint alone carries everything needed to resume.
        Convert.ToHexString(recovered.DocumentHash).ToLowerInvariant().Should().Be(checkpoint.HashHex);
        recovered.Bytes.Should().Equal(checkpoint.Bytes);

        var sealed_ = PdfIncrementalSigner.Embed(recovered, FakeCms);
        sealed_.Take(MinimalPdf().Length).Should().Equal(MinimalPdf());
        Encoding.ASCII.GetString(sealed_).Should().Contain(Convert.ToHexString(FakeCms).ToLowerInvariant());
    }

    [Fact]
    public async Task SealPreparedPades_SignsTheCheckpointDigest()
    {
        JsonObject? seen = null;
        var handler = new FakeHandler((req, body) =>
        {
            seen = (JsonObject)JsonNode.Parse(body)!;
            return Task.FromResult(SignPadesOk());
        });
        var client = ClientWith(handler);

        var checkpoint = client.PreparePades(MinimalPdf());
        var result = await client.SealPreparedPadesAsync(checkpoint.Bytes, Guid.NewGuid(),
            new PadesSealOptions { Ltv = false });

        seen!["hashHex"]!.GetValue<string>().Should().Be(checkpoint.HashHex);
        result.OperationId.Should().Be(Guid.Parse(OperationId));
        result.Format.Should().Be("pades-b-t");
        Encoding.ASCII.GetString(result.SealedPdf).Should().Contain(Convert.ToHexString(FakeCms).ToLowerInvariant());
    }

    [Fact]
    public async Task CompletePades_FinishesFromEscrowedCms()
    {
        var handler = new FakeHandler((req, _) =>
        {
            if (req.RequestUri!.AbsolutePath == $"/seal/operations/{OperationId}/p7s")
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    { Content = new ByteArrayContent(FakeCms) });
            return Task.FromResult(SignPadesOk());
        });
        var client = ClientWith(handler);

        // The crash story: phase 1 checkpointed, phase 2's response was lost.
        var checkpoint = client.PreparePades(MinimalPdf());
        await client.SealPreparedPadesAsync(checkpoint.Bytes, Guid.NewGuid(),
            new PadesSealOptions { Ltv = false });

        // Later process: re-fetch the escrowed CMS and finish offline.
        var cms = await client.GetSealCmsAsync(Guid.Parse(OperationId));
        cms.Should().Equal(FakeCms);
        var sealed_ = SigillClient.CompletePades(checkpoint.Bytes, cms!);

        // Byte-identical to what the uninterrupted flow would have produced.
        var recovered = PdfIncrementalSigner.Recover(checkpoint.Bytes);
        sealed_.Should().Equal(PdfIncrementalSigner.Embed(recovered, FakeCms));
    }

    [Fact]
    public void Recover_RejectsUnpreparedBytes()
    {
        var act = () => PdfIncrementalSigner.Recover(MinimalPdf());
        act.Should().Throw<InvalidOperationException>();
    }

    [Fact]
    public async Task GetSealCms_ReturnsNull_WhenNotStored()
    {
        var client = ClientWith(new FakeHandler((_, _) =>
            Task.FromResult(Json(new JsonObject { ["message"] = "not stored" }, HttpStatusCode.NotFound))));
        (await client.GetSealCmsAsync(Guid.Parse(OperationId))).Should().BeNull();
    }

    // -------------------------------------------------------------- evidence

    [Fact]
    public async Task GetEvidenceRecord_MapsFields_AndHashesLocally()
    {
        var data = Encoding.ASCII.GetBytes("artifact-bytes");
        var expectedHash = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        string? seenPath = null;

        var handler = new FakeHandler((req, _) =>
        {
            seenPath = req.RequestUri!.AbsolutePath;
            return Task.FromResult(Json(new JsonObject
            {
                ["id"]            = TxId,
                ["hash"]          = expectedHash,
                ["alg"]           = "SHA-256",
                ["genTime"]       = "2026-07-31T10:00:00Z",
                ["createdAt"]     = "2026-07-31T10:00:01Z",
                ["tsaName"]       = "DigiCert",
                ["label"]         = "artifact.bin",
                ["certNotBefore"] = "2026-01-01T00:00:00Z",
                ["certNotAfter"]  = "2028-01-01T00:00:00Z",
                ["isRestamp"]     = false,
                ["hasTsr"]        = true,
            }));
        });
        var client = ClientWith(handler);

        var rec = await client.GetEvidenceRecordAsync(data);

        seenPath.Should().Be($"/api/transactions/by-hash/{expectedHash}");
        rec.Should().NotBeNull();
        rec!.TransactionId.Should().Be(Guid.Parse(TxId));
        rec.CertNotAfter.Should().Be(DateTimeOffset.Parse("2028-01-01T00:00:00Z"));
        rec.TsaName.Should().Be("DigiCert");
        rec.HasTsr.Should().BeTrue();
    }

    [Fact]
    public async Task GetEvidenceRecord_ReturnsNull_On404()
    {
        var client = ClientWith(new FakeHandler((_, _) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound))));
        (await client.GetEvidenceRecordAsync(new string('a', 64))).Should().BeNull();
    }

    [Fact]
    public async Task Lookup_MapsResult_AndNullOn404()
    {
        var handler = new FakeHandler((req, _) =>
        {
            if (req.RequestUri!.AbsolutePath.EndsWith(new string('f', 64)))
                return Task.FromResult(Json(new JsonObject { ["found"] = false }, HttpStatusCode.NotFound));
            return Task.FromResult(Json(new JsonObject
            {
                ["found"] = true,
                ["count"] = 2,
                ["records"] = new JsonArray(
                    new JsonObject { ["id"] = TxId, ["hash"] = new string('a', 64), ["createdAt"] = "2026-07-31T10:00:01Z" },
                    new JsonObject { ["id"] = OperationId, ["hash"] = new string('a', 64), ["createdAt"] = "2026-07-30T10:00:01Z" }),
                ["latest"] = new JsonObject { ["id"] = TxId, ["hash"] = new string('a', 64), ["createdAt"] = "2026-07-31T10:00:01Z" },
            }));
        });
        var client = ClientWith(handler);

        // Uppercase input is normalized to lowercase on the wire.
        var result = await client.LookupAsync(new string('A', 64));
        result.Should().NotBeNull();
        result!.Count.Should().Be(2);
        result.Latest.TransactionId.Should().Be(Guid.Parse(TxId));
        result.Records.Should().HaveCount(2);

        (await client.LookupAsync(new string('f', 64))).Should().BeNull();
    }

    [Fact]
    public async Task ExportAuditPackage_ReturnsZipBytes()
    {
        var handler = new FakeHandler((req, _) =>
        {
            req.RequestUri!.AbsolutePath.Should().Be($"/api/transactions/{TxId}/audit-package.zip");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new ByteArrayContent(Encoding.ASCII.GetBytes("PK\x03\x04fakezip")) });
        });
        var client = ClientWith(handler);

        var zip = await client.ExportAuditPackageAsync(Guid.Parse(TxId));
        Encoding.ASCII.GetString(zip).Should().StartWith("PK");
    }
}
