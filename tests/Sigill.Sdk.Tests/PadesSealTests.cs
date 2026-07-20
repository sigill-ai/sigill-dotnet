// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Delegated PAdES sealing: the SDK assembles the PDF signature revision locally
// and only ByteRange digests cross the wire. These tests exercise the full
// orchestration against a fake HTTP handler and assert the privacy property
// directly (no request ever carries the PDF bytes).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public class PadesSealTests
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

    /// <summary>Minimal but structurally complete xref-table PDF.</summary>
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

    private static readonly byte[] FakeCms   = Enumerable.Range(0, 900).Select(i => (byte)(i % 251)).ToArray();
    private static readonly byte[] FakeCert  = Enumerable.Range(0, 300).Select(i => (byte)(i % 13)).ToArray();
    private static readonly byte[] FakeOcsp  = Enumerable.Range(0, 200).Select(i => (byte)(i % 17)).ToArray();
    private static readonly byte[] FakeToken = Enumerable.Range(0, 400).Select(i => (byte)(i % 23)).ToArray();

    private static HttpResponseMessage SignPadesOk(bool withLtv)
    {
        var body = new JsonObject
        {
            ["cmsBase64"]     = Convert.ToBase64String(FakeCms),
            ["certChainDers"] = withLtv ? new JsonArray(Convert.ToBase64String(FakeCert)) : new JsonArray(),
            ["ocspDers"]      = withLtv ? new JsonArray(Convert.ToBase64String(FakeOcsp)) : new JsonArray(),
            ["operationId"]   = "6a1e12e8-6bb9-4d0e-9f6e-1c2d3e4f5a6b",
            ["certificateId"] = "0b7f7c6e-1111-2222-3333-444455556666",
            ["timestampedBy"] = "Test TSA",
            ["qualified"]     = false,
            ["format"]        = "pades-b-t",
        };
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
    }

    private static HttpResponseMessage StampOk()
    {
        var body = new JsonObject
        {
            ["tsrBase64"]   = Convert.ToBase64String(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 }),
            ["tokenBase64"] = Convert.ToBase64String(FakeToken),
            ["tsaName"]     = "Test TSA",
            ["qualified"]   = false,
        };
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json"),
        };
    }

    // ------------------------------------------------------------- happy path

    [Fact]
    public async Task SealPades_transmits_only_hashes_never_pdf_bytes()
    {
        var pdf = MinimalPdf();
        var handler = new FakeHandler((req, _) =>
        {
            req.RequestUri!.AbsolutePath.Should().Be("/seal/sign-pades-hash");
            return Task.FromResult(SignPadesOk(withLtv: false));
        });
        var client = ClientWith(handler);

        var result = await client.SealPadesAsync(pdf, Guid.NewGuid());

        // The privacy claim, asserted literally: no request body may contain the
        // PDF (raw, base64, or hex).
        var pdfB64 = Convert.ToBase64String(pdf);
        foreach (var (_, body) in handler.Calls)
        {
            body.Should().NotContain("%PDF");
            body.Should().NotContain(pdfB64);
        }

        // Exactly one round-trip, JSON only, with the two identity fields.
        handler.Calls.Should().HaveCount(1);
        var sent = JsonNode.Parse(handler.Calls[0].Body)!.AsObject();
        sent["hashHex"]!.GetValue<string>().Should().HaveLength(64);
        sent["certificateId"].Should().NotBeNull();

        result.Format.Should().Be("pades-b-t");
        result.TimestampedBy.Should().Be("Test TSA");
        result.OperationId.Should().Be(Guid.Parse("6a1e12e8-6bb9-4d0e-9f6e-1c2d3e4f5a6b"));

        // Output: original bytes are an untouched prefix (incremental update model)
        // and the CMS hex landed in the /Contents slot.
        result.SealedPdf.Take(pdf.Length).Should().Equal(pdf);
        var text = Encoding.ASCII.GetString(result.SealedPdf);
        text.Should().Contain("/SubFilter /ETSI.CAdES.detached");
        text.Should().Contain(ToLowerHex(FakeCms));
    }

    [Fact]
    public async Task SealPades_hash_covers_the_declared_byte_ranges_of_the_output()
    {
        var pdf = MinimalPdf();
        string? sentHashHex = null;
        var handler = new FakeHandler((_, body) =>
        {
            sentHashHex = JsonNode.Parse(body)!.AsObject()["hashHex"]!.GetValue<string>();
            return Task.FromResult(SignPadesOk(withLtv: false));
        });
        var client = ClientWith(handler);

        var result = await client.SealPadesAsync(pdf, Guid.NewGuid());

        // Recompute the digest from the sealed artifact exactly the way a PAdES
        // validator does: parse /ByteRange, hash the two ranges. Embedding the
        // CMS must not have disturbed the signed ranges.
        var text = Encoding.ASCII.GetString(result.SealedPdf);
        var br = Regex.Match(text, @"/ByteRange \[(\d+) (\d+) (\d+) (\d+)\]\s");
        br.Success.Should().BeTrue();
        int r1 = int.Parse(br.Groups[1].Value), r1Len = int.Parse(br.Groups[2].Value);
        int r2 = int.Parse(br.Groups[3].Value), r2Len = int.Parse(br.Groups[4].Value);

        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(result.SealedPdf, r1, r1Len);
        sha.AppendData(result.SealedPdf, r2, r2Len);
        ToLowerHex(sha.GetHashAndReset()).Should().Be(sentHashHex);

        // The gap between the ranges is exactly '<' + hex + '>'.
        (r2 - (r1 + r1Len)).Should().Be(16_384 * 2 + 2);
        (r2 + r2Len).Should().Be(result.SealedPdf.Length);
    }

    // -------------------------------------------------------------------- ltv

    [Fact]
    public async Task SealPades_with_ltv_material_builds_dss_and_doc_timestamp()
    {
        var handler = new FakeHandler((req, _) =>
            Task.FromResult(req.RequestUri!.AbsolutePath == "/seal/sign-pades-hash"
                ? SignPadesOk(withLtv: true)
                : StampOk()));
        var client = ClientWith(handler);

        var result = await client.SealPadesAsync(MinimalPdf(), Guid.NewGuid());

        handler.Calls.Select(c => c.Path).Should().Equal("/seal/sign-pades-hash", "/tsa/stamp-hash");
        result.Format.Should().Be("pades-b-lta");

        var text = Encoding.ASCII.GetString(result.SealedPdf);
        text.Should().Contain("/Type /DSS");
        text.Should().Contain("/VRI");
        text.Should().Contain("/Type /DocTimeStamp");
        text.Should().Contain("/SubFilter /ETSI.RFC3161");
        text.Should().Contain(ToLowerHex(FakeToken));
    }

    [Fact]
    public async Task SealPades_doc_timestamp_failure_degrades_to_b_lt()
    {
        var handler = new FakeHandler((req, _) =>
            Task.FromResult(req.RequestUri!.AbsolutePath == "/seal/sign-pades-hash"
                ? SignPadesOk(withLtv: true)
                : new HttpResponseMessage(HttpStatusCode.BadGateway)));
        var client = ClientWith(handler);

        var result = await client.SealPadesAsync(MinimalPdf(), Guid.NewGuid());

        result.Format.Should().Be("pades-b-lt");
        var text = Encoding.ASCII.GetString(result.SealedPdf);
        text.Should().Contain("/Type /DSS");
        text.Should().NotContain("/Type /DocTimeStamp");
    }

    [Fact]
    public async Task SealPades_ltv_false_stays_b_t()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(SignPadesOk(withLtv: true)));
        var client = ClientWith(handler);

        var result = await client.SealPadesAsync(MinimalPdf(), Guid.NewGuid(),
            new PadesSealOptions { Ltv = false });

        handler.Calls.Should().HaveCount(1);
        result.Format.Should().Be("pades-b-t");
        Encoding.ASCII.GetString(result.SealedPdf).Should().NotContain("/Type /DSS");
    }

    // ------------------------------------------------------------- unsupported

    [Fact]
    public async Task SealPades_unsupported_pdf_throws_with_upload_fallback_hint()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(SignPadesOk(withLtv: false)));
        var client = ClientWith(handler);

        var act = () => client.SealPadesAsync(Encoding.ASCII.GetBytes("%PDF-1.4\nnot really a pdf"), Guid.NewGuid());

        var ex = await act.Should().ThrowAsync<SigillPdfUnsupportedException>();
        ex.Which.Message.Should().Contain("/seal/sign");
        handler.Calls.Should().BeEmpty("nothing should be transmitted when local preparation fails");
    }

    [Fact]
    public async Task SealPades_upload_fallback_is_off_by_default_and_opt_in_uploads()
    {
        var unsupported = Encoding.ASCII.GetBytes("%PDF-1.4\nnot really a pdf");
        var sealedByServer = Enumerable.Range(0, 500).Select(i => (byte)(i % 29)).ToArray();

        var handler = new FakeHandler((req, _) =>
        {
            req.RequestUri!.AbsolutePath.Should().Be("/seal/sign");
            req.Content.Should().BeOfType<MultipartFormDataContent>();
            var resp = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(sealedByServer),
            };
            resp.Headers.Add("X-Seal-Operation-Id", "9c65b917-6a10-4c7a-8f3e-2b1a0d4e5f60");
            resp.Headers.Add("X-Seal-Format", "pades-b-lta");
            resp.Headers.Add("X-Seal-Timestamped-By", "Test TSA");
            resp.Headers.Add("X-Seal-Qualified", "false");
            return Task.FromResult(resp);
        });
        var client = ClientWith(handler);

        // Default: hard privacy guarantee — throws, transmits nothing.
        var strict = () => client.SealPadesAsync(unsupported, Guid.NewGuid());
        await strict.Should().ThrowAsync<SigillPdfUnsupportedException>();
        handler.Calls.Should().BeEmpty();

        // Opt-in: the SDK uploads via /seal/sign and maps the header metadata.
        var result = await client.SealPadesAsync(unsupported, Guid.NewGuid(),
            new PadesSealOptions { AllowUploadFallback = true });

        handler.Calls.Should().HaveCount(1);
        result.SealedPdf.Should().Equal(sealedByServer);
        result.Format.Should().Be("pades-b-lta");
        result.TimestampedBy.Should().Be("Test TSA");
        result.OperationId.Should().Be(Guid.Parse("9c65b917-6a10-4c7a-8f3e-2b1a0d4e5f60"));
    }

    [Fact]
    public async Task SealPades_reason_and_location_land_in_signature_dictionary()
    {
        var handler = new FakeHandler((_, _) => Task.FromResult(SignPadesOk(withLtv: false)));
        var client = ClientWith(handler);

        var result = await client.SealPadesAsync(MinimalPdf(), Guid.NewGuid(),
            new PadesSealOptions { Reason = "Approval", Location = "Oslo (NO)" });

        var text = Encoding.ASCII.GetString(result.SealedPdf);
        text.Should().Contain("/Reason (Approval)");
        text.Should().Contain(@"/Location (Oslo \(NO\))");
    }

    private static string ToLowerHex(byte[] bytes) =>
        string.Concat(bytes.Select(b => b.ToString("x2")));
}
