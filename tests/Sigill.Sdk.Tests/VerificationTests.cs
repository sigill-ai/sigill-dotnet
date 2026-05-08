// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Mirrors python/tests/test_verification.py 1:1 — same vectors, same scenarios,
// same assertions. If a test passes in Python and fails here (or vice versa), the
// SDKs have drifted; that's release-blocking.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public class VerificationTests
{
    /// <summary>Mimic SealAsync without HTTP: locally stamps the canonical bytes via TsrFactory.</summary>
    private static SealedAiEvidenceEnvelope SealOffline(JsonObject expected)
    {
        var env = (JsonObject)JsonNode.Parse(expected.ToJsonString())!;
        var integrity = env["integrity"] as JsonObject ?? new JsonObject();
        integrity["canonicalization"] = "RFC8785";
        integrity.Remove("envelopeHash");
        env["integrity"] = integrity;
        env.Remove("proofs");

        var (digestHex, canonical) = EnvelopeHashing.ComputeEnvelopeHash(env);
        ((JsonObject)env["integrity"]!)["envelopeHash"] = new JsonObject
        {
            ["alg"] = "SHA-256",
            ["hex"] = digestHex,
        };

        using var sha = SHA256.Create();
        var imprint = sha.ComputeHash(canonical);
        var tsrBytes = TsrFactory.MakeTsr(imprint);
        env["proofs"] = new JsonArray(new JsonObject
        {
            ["type"] = "rfc3161",
            ["tsrBase64"] = Convert.ToBase64String(tsrBytes),
            ["tsaName"] = "Sigill SDK Test TSA",
        });

        return new SealedAiEvidenceEnvelope(env, canonical, digestHex);
    }

    private static SigillClient NewClient()
    {
        // No verification path makes a network call, but SigillClient demands an HttpClient
        // with BaseAddress. Use a never-called handler.
        var http = new HttpClient(new ThrowingHandler()) { BaseAddress = new Uri("https://api.sigill.ai") };
        return new SigillClient(http);
    }

    private sealed class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, System.Threading.CancellationToken ct) =>
            throw new InvalidOperationException("Verification tests must not make HTTP calls");
    }

    // ---------------------------------------------------------------- happy path

    [Fact]
    public async Task Verify_happy_path_inline()
    {
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);

        var result = await NewClient().VerifyAsync(sealed_);

        result.IsValid.Should().BeTrue("got issues: " + string.Join("; ", result.Issues.Select(i => i.Message)));
        result.EnvelopeHashHex.Should().Be(sealed_.EnvelopeHashHex);
        result.Timestamps.Should().HaveCount(1);
        result.Timestamps[0].TsaName.Should().Be("Sigill SDK Test TSA");
    }

    [Fact]
    public async Task Verify_happy_path_with_external_payloads()
    {
        var vec = Path.Combine(SpecRoot.TestVectorsDir, "02-pii-redacted");
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;
        var sealed_ = SealOffline(expected);

        var payloads = new Dictionary<string, byte[]>
        {
            ["prompt"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "prompt.txt")),
            ["ctx-1"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "ctx-1.txt")),
            ["output"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "output.json")),
        };

        var result = await NewClient().VerifyAsync(sealed_, payloads);
        result.IsValid.Should().BeTrue("got issues: " + string.Join("; ", result.Issues.Select(i => i.Message)));
    }

    // ---------------------------------------------------------------- envelope tampering

    [Fact]
    public async Task Envelope_tampering_is_detected()
    {
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);

        // Mutate any canonical-bound field; recomputed hash should diverge from the registered one
        ((JsonObject)sealed_.Json["model"]!)["name"] = "claude-haiku-4-5-20251001";

        var result = await NewClient().VerifyAsync(sealed_);
        result.IsValid.Should().BeFalse();
        var hashIssues = result.Issues
            .Where(i => i.Kind == VerificationIssueKind.HashMismatch && i.Target == "envelope")
            .ToList();
        hashIssues.Should().HaveCount(1);
        hashIssues[0].Message.Should().Contain("envelope_hash_does_not_match");
        hashIssues[0].Expected.Should().NotBe(hashIssues[0].Actual);
    }

    [Fact]
    public async Task Missing_envelope_hash_is_reported()
    {
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);
        ((JsonObject)sealed_.Json["integrity"]!).Remove("envelopeHash");

        var result = await NewClient().VerifyAsync(sealed_);
        result.IsValid.Should().BeFalse();
        result.Issues.Should().Contain(i =>
            i.Kind == VerificationIssueKind.HashMismatch && i.Target == "envelope");
    }

    // ---------------------------------------------------------------- external payloads

    [Fact]
    public async Task Missing_external_payload_is_reported()
    {
        var vec = Path.Combine(SpecRoot.TestVectorsDir, "02-pii-redacted");
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;
        var sealed_ = SealOffline(expected);

        var payloads = new Dictionary<string, byte[]>
        {
            ["ctx-1"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "ctx-1.txt")),
            ["output"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "output.json")),
            // prompt deliberately omitted
        };

        var result = await NewClient().VerifyAsync(sealed_, payloads);
        result.IsValid.Should().BeFalse();
        var missing = result.Issues.Where(i => i.Target == "prompt").ToList();
        missing.Should().HaveCount(1);
        missing[0].Kind.Should().Be(VerificationIssueKind.HashMismatch);
        missing[0].Message.Should().Contain("payload_not_supplied");
        missing[0].Expected.Should().NotBeNullOrEmpty(); // diagnostic hash surfaced
    }

    [Fact]
    public async Task Wrong_external_payload_is_reported()
    {
        var vec = Path.Combine(SpecRoot.TestVectorsDir, "02-pii-redacted");
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;
        var sealed_ = SealOffline(expected);

        var payloads = new Dictionary<string, byte[]>
        {
            ["prompt"] = Encoding.UTF8.GetBytes("these are the wrong bytes entirely"),
            ["ctx-1"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "ctx-1.txt")),
            ["output"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "output.json")),
        };

        var result = await NewClient().VerifyAsync(sealed_, payloads);
        result.IsValid.Should().BeFalse();
        var bad = result.Issues.Where(i => i.Target == "prompt").ToList();
        bad.Should().HaveCount(1);
        bad[0].Kind.Should().Be(VerificationIssueKind.HashMismatch);
        bad[0].Message.Should().Contain("digest_does_not_match");
        bad[0].Expected.Should().NotBeNullOrEmpty();
        bad[0].Actual.Should().NotBeNullOrEmpty();
        bad[0].Expected.Should().NotBe(bad[0].Actual);
    }

    // ---------------------------------------------------------------- proof errors

    [Fact]
    public async Task Malformed_tsr_is_reported()
    {
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);
        ((JsonObject)sealed_.Json["proofs"]![0]!)["tsrBase64"] =
            Convert.ToBase64String(Encoding.UTF8.GetBytes("garbage that is not a TSR"));

        var result = await NewClient().VerifyAsync(sealed_);
        result.IsValid.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Kind == VerificationIssueKind.InvalidProof);
    }

    [Fact]
    public async Task Tsr_imprint_mismatch_is_reported()
    {
        // Proof-substitution attack: TSR is well-formed and signed, but its imprint
        // is over different bytes than the envelope's canonical form.
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);

        using var sha = SHA256.Create();
        var fakeImprint = sha.ComputeHash(Encoding.UTF8.GetBytes("this is not the canonical envelope"));
        var bogusTsr = TsrFactory.MakeTsr(fakeImprint);
        ((JsonObject)sealed_.Json["proofs"]![0]!)["tsrBase64"] = Convert.ToBase64String(bogusTsr);

        var result = await NewClient().VerifyAsync(sealed_);
        result.IsValid.Should().BeFalse();
        var proofIssues = result.Issues
            .Where(i => i.Kind == VerificationIssueKind.InvalidProof)
            .ToList();
        proofIssues.Should().NotBeEmpty();
        proofIssues.Should().Contain(i => i.Message.Contains("message-imprint"));
    }

    [Fact]
    public async Task Unsupported_proof_type_is_reported()
    {
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);
        sealed_.Json["proofs"] = new JsonArray(new JsonObject
        {
            ["type"] = "jws",
            ["value"] = "not-supported-in-v1",
        });

        var result = await NewClient().VerifyAsync(sealed_);
        result.IsValid.Should().BeFalse();
        result.Issues.Should().Contain(i =>
            i.Kind == VerificationIssueKind.InvalidProof &&
            i.Message.Contains("unsupported proof type"));
    }

    // ---------------------------------------------------------------- timestamp_unavailable

    [Fact]
    public async Task Envelope_with_no_proofs_reports_timestamp_unavailable()
    {
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);
        sealed_.Json.Remove("proofs");

        var result = await NewClient().VerifyAsync(sealed_);
        result.IsValid.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Kind == VerificationIssueKind.TimestampUnavailable);
    }

    [Fact]
    public async Task Empty_proofs_array_also_reports_timestamp_unavailable()
    {
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(
            Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call", "expected.json")))!;
        var sealed_ = SealOffline(expected);
        sealed_.Json["proofs"] = new JsonArray();

        var result = await NewClient().VerifyAsync(sealed_);
        result.IsValid.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Kind == VerificationIssueKind.TimestampUnavailable);
    }

    // ---------------------------------------------------------------- multi-issue

    [Fact]
    public async Task Verify_collects_all_issues_not_just_first()
    {
        // An audit UI needs the full report — VerifyAsync MUST NOT short-circuit.
        var vec = Path.Combine(SpecRoot.TestVectorsDir, "02-pii-redacted");
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;
        var sealed_ = SealOffline(expected);

        ((JsonObject)sealed_.Json["model"]!)["name"] = "tampered";

        var payloads = new Dictionary<string, byte[]>
        {
            ["prompt"] = Encoding.UTF8.GetBytes("wrong bytes"),
            ["ctx-1"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "ctx-1.txt")),
            ["output"] = File.ReadAllBytes(Path.Combine(vec, "external-payloads", "output.json")),
        };

        var result = await NewClient().VerifyAsync(sealed_, payloads);
        result.IsValid.Should().BeFalse();
        var targets = result.Issues.Select(i => i.Target).ToHashSet();
        targets.Should().Contain("envelope");
        targets.Should().Contain("prompt");
    }
}
