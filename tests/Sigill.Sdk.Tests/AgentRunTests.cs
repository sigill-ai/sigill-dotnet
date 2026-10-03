// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Agent Evidence Profiles v1: the cross-language vectors (spec/test-vectors/agent-run)
// verified through the stub verifier, the real sealed run (vector 10), and the
// recorder end-to-end against a fake sealing endpoint that signs with the same
// stub. HTTP is faked; hashes and binding digests are real.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public class AgentRunTests
{
    private static string VectorsDir => Path.Combine(SpecRoot.TestVectorsDir, "agent-run");

    // ── The stub signer / verifier (spec/test-vectors/agent-run/README.md) ──

    private static string B64U(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static readonly byte[] CertA = Encoding.ASCII.GetBytes("test signing certificate A");
    private static readonly byte[] CertB = Encoding.ASCII.GetBytes("test signing certificate B");
    private static readonly byte[] CertV = Encoding.ASCII.GetBytes("test signing certificate V (verifier)");

    private static string Thumbprint(byte[] cert) => B64U(SHA256.HashData(cert));

    private static JsonObject StubSign(string envelopeHashHex, IEnumerable<(string Uri, string Hex)> objects, string? cty,
        bool timestamp, string genTime, byte[] cert, bool withSigner = true)
    {
        var pars = new JsonArray { "urn:sigill:envelope" };
        var hashV = new JsonArray { B64U(Convert.FromHexString(envelopeHashHex)) };
        foreach (var (uri, hex) in objects) { pars.Add(uri); hashV.Add(B64U(Convert.FromHexString(hex))); }
        var sigD = new JsonObject { ["pars"] = pars, ["hashV"] = hashV };
        if (cty is not null) sigD["ctys"] = new JsonArray { cty };
        var header = new JsonObject { ["alg"] = "ES256", ["sigD"] = sigD };
        if (withSigner)
        {
            header["x5c"] = new JsonArray { Convert.ToBase64String(cert) };
            header["x5t#S256"] = Thumbprint(cert);
        }
        var prot = B64U(JsonCanonicalizer.Canonicalize(header.ToJsonString()));
        var entry = new JsonObject { ["protected"] = prot, ["signature"] = B64U(SHA256.HashData(Encoding.ASCII.GetBytes(prot))) };
        if (timestamp) entry["header"] = new JsonObject { ["stubTimestamp"] = new JsonObject { ["genTime"] = genTime, ["valid"] = true } };
        return new JsonObject { ["signatures"] = new JsonArray { entry } };
    }

    private static System.Text.Json.JsonElement Header(JsonObject e) =>
        System.Text.Json.JsonDocument.Parse(AgentProfiles.Base64UrlDecode(e["protected"]!.GetValue<string>())).RootElement;

    /// <summary>The first non-ML-DSA entry; headers read leniently (a repeated name: last value wins).</summary>
    private static JsonObject ClassicalEntry(JsonObject signature)
    {
        static string LastAlg(System.Text.Json.JsonElement h) => h.EnumerateObject().Last(p => p.Name == "alg").Value.GetString()!;
        return signature["signatures"]!.AsArray().OfType<JsonObject>().First(e =>
            !LastAlg(Header(e)).StartsWith("ML-DSA", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Compares the supplied digests with the signed hashV.</summary>
    private static (List<(string, bool)> Objects, List<string> Missing, List<string> Unreferenced) MatchDigests(
        System.Text.Json.JsonElement header, IReadOnlyDictionary<string, string> digests)
    {
        var sigD = header.GetProperty("sigD");
        var pars = sigD.GetProperty("pars").EnumerateArray().Select(n => n.GetString()!).ToList();
        var hashV = sigD.GetProperty("hashV").EnumerateArray()
            .Select(n => Convert.ToHexString(AgentProfiles.Base64UrlDecode(n.GetString()!)).ToLowerInvariant()).ToList();
        var objects = pars.Select((p, i) => (p, digests.TryGetValue(p, out var d) && d == hashV[i])).ToList();
        return (objects, pars.Where(p => !digests.ContainsKey(p)).ToList(), digests.Keys.Where(k => !pars.Contains(k)).ToList());
    }

    private static Task<BlindObjectsVerdict> StubVerify(JsonObject signature, IReadOnlyDictionary<string, string> digests, CancellationToken _)
    {
        var entry = ClassicalEntry(signature);
        var prot = entry["protected"]!.GetValue<string>();
        var valid = entry["signature"]!.GetValue<string>() == B64U(SHA256.HashData(Encoding.ASCII.GetBytes(prot)));
        var (objects, missing, unreferenced) = MatchDigests(Header(entry), digests);
        SignatureTimestampInfo? ts = null;
        if (entry["header"]?["stubTimestamp"] is JsonObject st)
            ts = new SignatureTimestampInfo(st["genTime"]!.GetValue<string>(), "Stub TSA", st["valid"]!.GetValue<bool>());
        return Task.FromResult(new BlindObjectsVerdict
        {
            SignatureValid = valid,
            Complete = valid && objects.All(o => o.Item2),
            Objects = objects,
            Missing = missing,
            Unreferenced = unreferenced,
            Timestamp = ts,
            Certificate = new SignerCertificateInfo("CN=Stub Signer", "CN=Stub CA", "2030-01-01T00:00:00Z", "trusted_chain"),
        });
    }

    // ── Vectors ──────────────────────────────────────────────────────────────

    [Fact]
    public void SignatureSha256_MatchesVectors()
    {
        var cases = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "signature-sha256.json")))!.AsArray();
        cases.Should().HaveCount(4);
        foreach (var c in cases)
            AgentProfiles.SignatureSha256(c!["signature"]!.AsObject())
                .Should().Be(c["expected"]?.GetValue<string>(), c["name"]!.GetValue<string>());
    }

    public static IEnumerable<object[]> RunVectors() =>
        Directory.GetFiles(Path.Combine(VectorsDir, "runs"), "*.json")
            .OrderBy(f => f, StringComparer.Ordinal).Select(f => new object[] { Path.GetFileName(f) });

    [Fact]
    public void RunVectors_AreAllPresent() =>
        RunVectors().Should().HaveCount(54);

    [Theory]
    [MemberData(nameof(RunVectors))]
    public async Task RunVector_ReproducesExpectedVerdict(string file)
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", file)))!;
        var expected = v["expected"]!;
        if (v["bundleText"] is { } text) // a container that must not parse at all
        {
            var act = () => AgentRunBundle.Parse(text.GetValue<string>());
            act.Should().Throw<AgentRunBundleFormatException>()
                .Which.Errors.Should().Contain(e => e.Contains(expected["parseError"]!.GetValue<string>()));
            return;
        }
        var bundle = AgentRunBundle.Parse(v["bundle"]);

        var result = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);

        var all = string.Join(" | ", result.Findings);
        result.Verdict.Should().Be(expected["verdict"]!.GetValue<string>(), all);
        foreach (var kv in expected["checks"]!.AsObject())
            result.Checks[kv.Key].Should().Be(kv.Value!.GetValue<string>(), $"check '{kv.Key}' — {all}");
        result.Checks.Should().HaveCount(9);
        result.Binding.Should().Be(expected["binding"]!.GetValue<string>(), all);
        result.MissingSeqs.Should().Equal(expected["missingSeqs"]!.AsArray().Select(n => n!.GetValue<int>()));
        result.Fingerprint.Should().Be(expected["fingerprint"]?.GetValue<string>(), "null when the evidence is not valid I-JSON");
        foreach (var f in expected["findingsContain"]!.AsArray())
            result.Findings.Should().Contain(x => x.Contains(f!.GetValue<string>()), all);
        if (result.Verdict != "run_invalid") result.Findings.Should().BeEmpty();
        var warnings = string.Join(" | ", result.Warnings);
        foreach (var w in expected["warningsContain"]!.AsArray())
            result.Warnings.Should().Contain(x => x.Contains(w!.GetValue<string>()), warnings);
        result.Warnings.Should().HaveCount(expected["warningCount"]!.GetValue<int>(), warnings);
        result.ControlSealedBeforeRun.Should().Be(expected["controlSealedBeforeRun"]?.GetValue<bool>());
        result.EventTimesPlausible.Should().Be(expected["eventTimesPlausible"]?.GetValue<bool>());

        var evals = expected["evaluations"]!.AsArray();
        result.Evaluations.Should().HaveCount(evals.Count);
        for (var i = 0; i < evals.Count; i++)
        {
            var e = evals[i]!;
            var r = result.Evaluations[i];
            var because = string.Join(" | ", r.Findings);
            r.SubjectBound.Should().Be(e["subjectBound"]!.GetValue<bool>(), because);
            r.ControlSetDigestMatches.Should().Be(e["controlSetDigestMatches"]!.GetValue<bool>(), because);
            r.BaselineDigestMatches.Should().Be(e["baselineDigestMatches"]!.GetValue<bool>(), because);
            r.SignatureValid.Should().Be(e["signatureValid"]!.GetValue<bool>(), because);
            r.TimestampValid.Should().Be(e["timestampValid"]!.GetValue<bool>(), because);
            r.Overall.Should().Be(e["overall"]!.GetValue<string>());
        }
    }

    private static AgentRunBundle VectorBundle(string name) =>
        AgentRunBundle.Parse(JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", name)))!["bundle"]);

    [Fact]
    public void Bundle_RoundTripsThroughJson()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", "02-finalized-with-payloads.json")))!;
        var bundle = AgentRunBundle.Parse(v["bundle"]);
        var again = AgentRunBundle.Parse(bundle.ToJsonString());
        AgentRunVerifier.Fingerprint(again).Should().Be(v["expected"]!["fingerprint"]!.GetValue<string>());
        again.Payloads.Should().HaveCount(bundle.Payloads.Count);
        again.Evaluations.Should().HaveCount(1);
        again.ControlArtifact.Should().NotBeNull();
    }

    [Fact]
    public void Bundle_ParseIsStrict_AndListsEveryProblem()
    {
        var bad = new JsonObject
        {
            ["format"] = "SomethingElse",
            ["artifacts"] = new JsonArray
            {
                new JsonObject { ["envelope"] = new JsonObject(), ["signature"] = new JsonObject(), ["objectDigests"] = new JsonObject { ["urn:x"] = "ABC" } },
                "not an object",
            },
            ["evaluations"] = new JsonObject(),
            ["payloads"] = new JsonObject { ["urn:y"] = "%%%" },
        };
        var act = () => AgentRunBundle.Parse(bad);
        var ex = act.Should().Throw<AgentRunBundleFormatException>().Which;
        ex.Errors.Should().HaveCount(6);
        ex.Errors.Should().Contain(e => e.Contains("unsupported format"));
        ex.Errors.Should().Contain(e => e.Contains("unsupported bundleVersion"));
        ex.Errors.Should().Contain(e => e.Contains("64-char hex"));
        ex.Errors.Should().Contain(e => e.Contains("artifacts[1]: not an object"));
        ex.Errors.Should().Contain(e => e.Contains("evaluations is not an array"));
        ex.Errors.Should().Contain(e => e.Contains("not valid base64"));
    }

    [Fact]
    public void Bundle_ParseReportsEveryBadDigestOfAnArtifact()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", "01-finalized-digests-only.json")))!;
        v["bundle"]!["artifacts"]![0]!["objectDigests"] = new JsonObject { ["urn:a"] = "x", ["urn:b"] = "y" };
        var act = () => AgentRunBundle.Parse(v["bundle"]);
        act.Should().Throw<AgentRunBundleFormatException>()
            .Which.Errors.Count(e => e.Contains("is not a 64-char hex digest")).Should().Be(2);
    }

    [Fact]
    public void Bundle_ParseOfANodeWithADuplicateName_IsAFormatError()
    {
        var text = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", "39-duplicate-member.json")))!["bundleText"]!.GetValue<string>();
        var act = () => AgentRunBundle.Parse(JsonNode.Parse(text));
        act.Should().Throw<AgentRunBundleFormatException>().Which.Message.Should().Contain("duplicate member name");
    }

    [Fact]
    public async Task MalformedEnvelope_IsAnInvalidVerdict_NeverAnException()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", "01-finalized-digests-only.json")))!;
        v["bundle"]!["artifacts"]![1]!["envelope"]!["chain"] = "seq one";
        var result = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(v["bundle"]), StubVerify);
        result.Verdict.Should().Be("run_invalid");
        result.Checks["envelope"].Should().Be("bad");
        result.Findings.Should().Contain(f => f.Contains("chain must be of type object"));
    }

    [Fact]
    public async Task ExpectedSigners_PinTheRun_AndTheEvaluationSeparately()
    {
        var bundle = VectorBundle("01-finalized-digests-only.json");
        var ok = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        ok.Signer.Should().NotBeNull();
        var evaluationSigner = ok.Evaluations.Single().Signer!;
        evaluationSigner.Should().NotBe(ok.Signer, "the evaluating verifier seals with its own certificate");
        (await AgentRunVerifier.VerifyAsync(bundle, StubVerify, new[] { ok.Signer! }, new[] { evaluationSigner }))
            .Verdict.Should().Be("run_finalized");

        var pinned = await AgentRunVerifier.VerifyAsync(bundle, StubVerify, new[] { "someone-else" });
        pinned.Verdict.Should().Be("run_invalid");
        pinned.Checks["signatures"].Should().Be("bad");
        pinned.Findings.Should().Contain(f => f.Contains("not among the expected signers"));

        var evalPinned = await AgentRunVerifier.VerifyAsync(bundle, StubVerify, null, new[] { ok.Signer! });
        evalPinned.Verdict.Should().Be("run_finalized", "an evaluation never changes the run verdict");
        evalPinned.Evaluations.Single().SignatureValid.Should().BeFalse();
    }

    [Fact]
    public async Task SelfSignedCertificate_IsAWarning()
    {
        BlindObjectsVerifier selfSigned = async (sig, d, ct) => (await StubVerify(sig, d, ct)) with
        {
            Certificate = new SignerCertificateInfo("CN=x", "CN=x", "2030-01-01T00:00:00Z", "self_signed"),
        };
        var r = await AgentRunVerifier.VerifyAsync(VectorBundle("01-finalized-digests-only.json"), selfSigned);
        r.Verdict.Should().Be("run_finalized");
        r.Warnings.Should().Contain(w => w.Contains("trust: self_signed"));
    }

    [Fact]
    public async Task UntrustedChain_WarnsUnlessSignersArePinned()
    {
        BlindObjectsVerifier untrusted = async (sig, d, ct) => (await StubVerify(sig, d, ct)) with
        {
            Certificate = new SignerCertificateInfo("CN=Sigill Seal", "CN=Attacker CA", "2030-01-01T00:00:00Z", "valid_untrusted_chain"),
        };
        var bundle = VectorBundle("01-finalized-digests-only.json");
        var open = await AgentRunVerifier.VerifyAsync(bundle, untrusted);
        open.Verdict.Should().Be("run_finalized");
        open.Warnings.Should().Contain(w => w.Contains("valid_untrusted_chain") && w.Contains("does not establish who produced it"));
        var pinned = await AgentRunVerifier.VerifyAsync(bundle, untrusted, new[] { open.Signer! }, new[] { open.Evaluations[0].Signer! });
        pinned.Warnings.Should().NotContain(w => w.Contains("trusted root"));
        BlindObjectsVerdict.FromVerifyObjectsResponse(JsonNode.Parse("""
            {"objects":{"underlying":{"certificate":{"subject":"a","issuer":"b","notAfter":"c","isSelfSigned":false,"trust":"valid_untrusted_chain"}}}}
            """)!.AsObject()).Certificate!.Trust.Should().Be("valid_untrusted_chain");
    }

    [Fact]
    public async Task HybridCommitmentNotVerified_FailsSignatures()
    {
        BlindObjectsVerifier pqc = async (sig, d, ct) => (await StubVerify(sig, d, ct)) with { Pqc = "not_checked" };
        var r = await AgentRunVerifier.VerifyAsync(VectorBundle("01-finalized-digests-only.json"), pqc);
        r.Verdict.Should().Be("run_invalid");
        r.Checks["signatures"].Should().Be("bad");
        r.Findings.Should().Contain(f => f.Contains("ML-DSA commitment is 'not_checked'"));
    }

    [Fact]
    public async Task ControlOnlyBundle_IsReportedAsSuch()
    {
        var b = VectorBundle("01-finalized-digests-only.json");
        var r = await AgentRunVerifier.VerifyAsync(new AgentRunBundle(b.CorrelationId, b.ControlArtifact, Array.Empty<AgentRunArtifact>()), StubVerify);
        r.Binding.Should().Be("control_only");
        r.Verdict.Should().Be("run_open");
    }

    // ── Vector 10: one run sealed for real ───────────────────────────────────

    private static string Vector10Dir => Path.Combine(SpecRoot.TestVectorsDir, "10-agent-controlled-run");

    [Fact]
    public void Vector10_CanonicalBytesAndEnvelopeHashes_AreReproduced()
    {
        foreach (var file in Directory.GetFiles(Path.Combine(Vector10Dir, "artifacts"), "*.json"))
        {
            var name = Path.GetFileName(file).Split('.')[0];
            var envelope = JsonNode.Parse(File.ReadAllText(file))!["envelope"]!.AsObject();
            var canonical = EnvelopeHashing.Canonicalize(envelope);
            canonical.Should().Equal(File.ReadAllBytes(Path.Combine(Vector10Dir, "canonical", name + ".canonical.json")), name);
            EnvelopeHashing.HashHex(canonical).Should().Be(
                File.ReadAllText(Path.Combine(Vector10Dir, "canonical", name + ".envelope-hash.txt")).Trim(), name);
        }
    }

    /// <summary>
    /// The first GeneralizedTime in a timestamp token is TSTInfo.genTime (it
    /// precedes the certificates). Enough for this offline check.
    /// </summary>
    private static string? GenTimeOf(byte[] der)
    {
        for (var i = 0; i + 2 < der.Length; i++)
        {
            if (der[i] != 0x18 || der[i + 1] < 15 || der[i + 1] > 23 || i + 2 + der[i + 1] > der.Length) continue;
            var s = Encoding.ASCII.GetString(der, i + 2, der[i + 1]);
            if (!s.EndsWith('Z') || !s.StartsWith("20", StringComparison.Ordinal)) continue;
            var formats = new[] { "yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss.f'Z'", "yyyyMMddHHmmss.ff'Z'", "yyyyMMddHHmmss.fff'Z'" };
            if (DateTimeOffset.TryParseExact(s, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var t))
                return t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        }
        return null;
    }

    /// <summary>
    /// Offline and NOT cryptographic: checks every hashV against the supplied
    /// digests and reads the timestamp's genTime, but treats signature values and
    /// timestamp tokens as valid without checking them — that needs the blind
    /// endpoint (<see cref="AgentRunVerifier.Remote"/>) or a TS 119 182-1 validator.
    /// </summary>
    private static Task<BlindObjectsVerdict> DigestsOnlyVerify(JsonObject signature, IReadOnlyDictionary<string, string> digests, CancellationToken _)
    {
        var entry = ClassicalEntry(signature);
        var (objects, missing, unreferenced) = MatchDigests(Header(entry), digests);
        SignatureTimestampInfo? ts = null;
        foreach (var u in entry["header"]?["etsiU"] as JsonArray ?? new JsonArray())
        {
            var item = JsonNode.Parse(AgentProfiles.Base64UrlDecode(u!.GetValue<string>()));
            if (item?["sigTst"]?["tstTokens"]?[0]?["val"]?.GetValue<string>() is { } val)
                ts = new SignatureTimestampInfo(GenTimeOf(Convert.FromBase64String(val)), "TSA", true);
        }
        return Task.FromResult(new BlindObjectsVerdict
        {
            SignatureValid = true, Complete = objects.All(o => o.Item2), Objects = objects, Missing = missing,
            Unreferenced = unreferenced, Timestamp = ts,
            Certificate = new SignerCertificateInfo("CN=test tenant", "CN=CA", "2030-01-01T00:00:00Z", "trusted_chain"),
        });
    }

    [Fact]
    public async Task Vector10_RealSealedRun_ProfileLayerHoldsOffline_SignaturesAssumed()
    {
        AgentRunArtifact Load(string file)
        {
            var a = JsonNode.Parse(File.ReadAllText(Path.Combine(Vector10Dir, "artifacts", file)))!;
            return new AgentRunArtifact(a["envelope"]!.AsObject(), a["signature"]!.AsObject(), new Dictionary<string, string>());
        }
        var files = Directory.GetFiles(Path.Combine(Vector10Dir, "artifacts")).Select(f => Path.GetFileName(f)!).OrderBy(f => f, StringComparer.Ordinal).ToList();
        var payloads = JsonNode.Parse(File.ReadAllText(Path.Combine(Vector10Dir, "objects.json")))!.AsObject()
            .ToDictionary(kv => kv.Key, kv => File.ReadAllBytes(Path.Combine(Vector10Dir, kv.Value!.GetValue<string>())), StringComparer.Ordinal);
        var bundle = new AgentRunBundle(null,
            Load(files.Single(f => f.Contains("control-artifact"))),
            files.Where(f => f.EndsWith(".agent-execution.json", StringComparison.Ordinal)).Select(Load).ToList(),
            files.Where(f => f.EndsWith(".control-evaluation.json", StringComparison.Ordinal)).Select(Load).ToList(),
            payloads);

        var r = await AgentRunVerifier.VerifyAsync(bundle, DigestsOnlyVerify);
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(Vector10Dir, "expected-result.json")))!;
        r.Verdict.Should().Be(expected["runVerdict"]!.GetValue<string>(), string.Join(" | ", r.Findings));
        r.Binding.Should().Be(expected["binding"]!.GetValue<string>());
        r.Checks.Values.Should().OnlyContain(s => s == "ok");
        r.Disposition.Should().Be(expected["runDisposition"]!.GetValue<string>());
        r.Artifacts.Last().Seq.Should().Be(expected["finalSeq"]!.GetValue<int>());
        r.ControlSealedBeforeRun.Should().Be(expected["controlSealedBeforeRun"]!.GetValue<bool>());
        r.EventTimesPlausible.Should().Be(expected["eventTimesPlausible"]!.GetValue<bool>());
        r.Warnings.Should().Contain(w => w.Contains("signs no timestampPolicy"));
        var e = expected["evaluations"]![0]!;
        var ev = r.Evaluations.Single();
        ev.VerifierId.Should().Be(e["verifier"]!.GetValue<string>());
        ev.VerifierVersion.Should().Be(e["verifierVersion"]!.GetValue<string>());
        ev.Overall.Should().Be(e["overall"]!.GetValue<string>());
        ev.SubjectBound.Should().Be(e["subjectBound"]!.GetValue<bool>());
        ev.ControlSetDigestMatches.Should().Be(e["controlSetDigestMatches"]!.GetValue<bool>());
        ev.BaselineDigestMatches.Should().Be(e["baselineDigestMatches"]!.GetValue<bool>());
        ev.Controls.Should().Contain(c => c.Result == "FAIL");
    }

    // ── Recorder ─────────────────────────────────────────────────────────────

    /// <summary>A sign-hashes endpoint that signs with the stub and records every request.</summary>
    private sealed class StubSealer : HttpMessageHandler
    {
        public List<JsonObject> Requests { get; } = new();
        public int FailOnCall { get; set; } = -1;
        public bool DropTimestamps { get; set; }
        public byte[] Cert { get; set; } = CertA;
        public bool OmitSignerHeader { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            request.RequestUri!.AbsolutePath.Should().Be("/seal/sign-hashes");
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject();
            Requests.Add(body);
            if (Requests.Count - 1 == FailOnCall)
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("busy") };
            var stamp = (body["timestamp"]?.GetValue<bool>() ?? true) && !DropTimestamps;
            var sig = StubSign(body["envelopeHashHex"]!.GetValue<string>(),
                body["objects"]!.AsArray().Select(o => (o!["uri"]!.GetValue<string>(), o["hashHex"]!.GetValue<string>())),
                body["envelopeContentType"]?.GetValue<string>(), stamp, "2026-10-01T09:00:00Z", Cert, !OmitSignerHeader);
            var res = new JsonObject
            {
                ["signature"] = sig, ["operationId"] = Guid.NewGuid().ToString(), ["format"] = stamp ? "jades-b-t" : "jades-b-b",
                ["timestampedBy"] = stamp ? "Stub TSA" : null, ["qualified"] = false, ["pqc"] = false,
            };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(res.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }

    private static readonly Guid Cert = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid VerifierCert = Guid.Parse("66666666-7777-8888-9999-000000000000");

    private static AgentDefinition Agent() => new()
    {
        AgentId = "urn:example:agent:triage",
        AgentVersion = "1.0.0",
        TenantId = "tenant-example",
        Configuration = new AgentConfiguration
        {
            InstructionSet = Encoding.UTF8.GetBytes("You triage support tickets."),
            ToolManifest = Encoding.UTF8.GetBytes("""{"tools":["lookup_ticket","close_ticket"]}"""),
            ModelConfig = Encoding.UTF8.GetBytes("""{"temperature":0}"""),
            ExecutionPolicy = Encoding.UTF8.GetBytes("""{"allow":["lookup_ticket","close_ticket"]}"""),
        },
    };

    private static AgentRunOptions Options(AgentTimestampPolicy? policy = null) => new()
    {
        CertificateId = Cert,
        Activity = "support-ticket-close",
        ControlSet = new AgentControlSet
        {
            Id = "ticket-close-v2", Version = "2",
            Content = Encoding.UTF8.GetBytes("""{"controls":["ticket-closed","owner-unchanged"]}"""),
        },
        BaselineState = Encoding.UTF8.GetBytes("""{"ticket":"4411","status":"open","owner":"team-a"}"""),
        TimestampPolicy = policy ?? new AgentTimestampPolicy(),
    };

    private static SigillClient Client(StubSealer sealer) =>
        new(new HttpClient(sealer) { BaseAddress = new Uri("https://api.example") });

    /// <summary>A clock that advances one minute per reading.</summary>
    private static Func<DateTimeOffset> Clock()
    {
        var t = new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);
        return () => (t = t.AddMinutes(1));
    }

    private static Task<AgentRun> Start(SigillClient client, AgentRunOptions? options = null) =>
        AgentRun.StartCoreAsync(client, Agent(), options ?? Options(), Clock(), CancellationToken.None);

    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("customer 4411: Jane Doe cannot log in");

    private static bool Stamped(JsonObject request) => request["timestamp"]?.GetValue<bool>() ?? true;

    [Fact]
    public async Task RecordedRun_WithEvaluation_VerifiesAsFinalized_WithThreeTimestamps_AndNoContentTravels()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var sealedOrder = new List<string?>();
        var options = Options() with
        {
            StartObjects = new[] { new AgentRunObject { Role = "model-input", Bytes = Secret, ContentType = "text/plain" } },
            OnArtifactSealed = (a, _) => { sealedOrder.Add(a.StepType ?? a.SchemaName); return Task.CompletedTask; },
        };
        var run = await Start(client, options);
        await run.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("""{"ticket":"4411"}"""), operation: "read", useId: "call-1");
        await run.RecordToolResultAsync("lookup_ticket", Encoding.UTF8.GetBytes("""{"status":"open"}"""), useId: "call-1");
        await run.RecordToolCallAsync("close_ticket", Encoding.UTF8.GetBytes("""{"ticket":"4411"}"""), operation: "write", consequential: true);
        await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("Closed."));
        var bundle = await run.FinishAsync("completed");

        sealer.Cert = CertV; // the evaluating verifier seals with its own certificate
        var evaluation = await ControlEvaluation.SealCoreAsync(client, new ControlEvaluationRequest
        {
            CertificateId = VerifierCert, VerifierId = "urn:example:verifier:ticket-state", VerifierVersion = "1.3.0",
            ControlArtifact = run.ControlArtifact, RunEnd = bundle.Artifacts[^1],
            ObservedState = new[] { AgentRunObject.Json("observed-state", JsonNode.Parse("""{"ticket":"4411","status":"closed"}""")!) },
            Controls = new[] { new ControlResult("ticket-closed", "PASS"), new ControlResult("owner-unchanged", "PASS") },
            Overall = "PASS",
        }, Clock(), CancellationToken.None);
        bundle = bundle.WithEvaluations(evaluation);

        var result = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(bundle.ToJsonString()), StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.Binding.Should().Be("bound");
        result.Checks.Values.Should().OnlyContain(s => s == "ok" || s == "warn");
        result.Checks["objects"].Should().Be("warn", "no payloads retained by default");
        result.Checks["timestamps"].Should().Be("ok");
        result.Disposition.Should().Be("completed");
        result.Timestamps.PolicySigned.Should().BeTrue();
        var ev = result.Evaluations.Single();
        ev.SubjectBound.Should().BeTrue(string.Join(" | ", ev.Findings));
        ev.ControlSetDigestMatches.Should().BeTrue();
        ev.BaselineDigestMatches.Should().BeTrue();
        ev.SignatureValid.Should().BeTrue();
        ev.TimestampValid.Should().BeTrue();
        ev.Signer.Should().Be(Thumbprint(CertV)).And.NotBe(result.Signer);
        sealedOrder.Should().Equal("AgentControlArtifact", "run_start", "tool_call", "tool_result", "tool_call", "model_output", "run_end");

        // Seal every event, timestamp to wrap up: control, run_end and the evaluation — three for the whole run.
        sealer.Requests.Select(Stamped).Should().Equal(true, false, false, false, false, false, true, true);
        sealer.Requests.Select(r => r["envelopeContentType"]!.GetValue<string>()).Should().Equal(
            new[] { AgentProfiles.ControlArtifactContentType }
                .Concat(Enumerable.Repeat(AgentProfiles.ExecutionEvidenceContentType, 6))
                .Append(AgentProfiles.ControlEvaluationContentType));

        // Blind contract: digests and opaque URIs only (strings that cannot occur by chance in a digest or UUID).
        var wire = string.Join("\n", sealer.Requests.Select(r => r.ToJsonString()));
        wire.Should().NotContain("Jane Doe").And.NotContain("ticket").And.NotContain("triage support").And.NotContain("tool_call");
        bundle.Payloads.Should().BeEmpty();
        bundle.ToJsonString().Should().NotContain("Jane Doe");

        // run_end closes on its own seq and its own link.
        var end = bundle.Artifacts[^1].Envelope;
        end["step"]!["finalSeq"]!.GetValue<int>().Should().Be(end["chain"]!["seq"]!.GetValue<int>());
        end["step"]!["finalPrevSignatureSha256"]!.GetValue<string>().Should().Be(end["chain"]!["prevSignatureSha256"]!.GetValue<string>());
        foreach (var a in bundle.Artifacts.Append(bundle.ControlArtifact!).Append(evaluation))
            Guid.TryParse(a.EvidenceId, out _).Should().BeTrue("evidenceId is a bare UUID");
    }

    [Fact]
    public async Task AuthorizationAndHumanApprovalFlow_VerifiesAsFinalized()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client);
        var auth = await run.RecordAuthorizationAsync(new AgentAuthorization
        {
            Decision = "allow_with_human_approval", PolicyId = "support-tools-v1", Detail = "write requires approval",
        });
        var approval = await run.RecordHumanApprovalAsync("approved",
            receipt: Encoding.UTF8.GetBytes("""{"decision":"approved"}"""),
            identityAssertion: Encoding.UTF8.GetBytes("eyJhbGciOiJFUzI1NiJ9.x.y"),
            approver: "urn:example:approver:42");
        await run.RecordToolCallAsync("close_ticket", Encoding.UTF8.GetBytes("""{"ticket":"4411"}"""), operation: "write", consequential: true);
        var bundle = await run.FinishAsync();

        auth.Envelope["step"]!["decision"]!.GetValue<string>().Should().Be("allow_with_human_approval");
        auth.Envelope["step"]!["policyId"]!.GetValue<string>().Should().Be("support-tools-v1");
        approval.Envelope["step"]!["approver"]!.GetValue<string>().Should().Be("urn:example:approver:42");
        approval.Envelope["objects"]!.AsArray().Select(o => o!["role"]!.GetValue<string>())
            .Should().Equal("approval-receipt", "identity-assertion");

        var result = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        string.Join("\n", sealer.Requests.Select(r => r.ToJsonString())).Should().NotContain("eyJhbGciOiJFUzI1NiJ9");
    }

    [Fact]
    public async Task ConsequentialPolicy_StampsTheWrite()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, Options(new AgentTimestampPolicy { Consequential = true }));
        var write = await run.RecordToolCallAsync("close_ticket", Encoding.UTF8.GetBytes("{}"), operation: "write", consequential: true);
        write.Envelope["step"]!["timestamp"]!.GetValue<string>().Should().Be("required");
        Stamped(sealer.Requests[^1]).Should().BeTrue();
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task Checkpoint_AndRequireTimestamp_StampEventsThePolicyWouldNot()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client);
        var checkpoint = await run.CheckpointAsync("idle");
        checkpoint.StepType.Should().Be("checkpoint");
        checkpoint.Envelope["step"]!["timestamp"]!.GetValue<string>().Should().Be("required");
        Stamped(sealer.Requests[^1]).Should().BeTrue();
        await run.RecordAsync("retrieval", requireTimestamp: true);
        Stamped(sealer.Requests[^1]).Should().BeTrue();
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task Recorder_RefusesASignatureWhoseSignerCannotBeEstablished()
    {
        using var client = Client(new StubSealer { OmitSignerHeader = true });
        await FluentActions.Invoking(() => Start(client))
            .Should().ThrowAsync<SigillException>().WithMessage("*signer cannot be established*");
    }

    [Fact]
    public async Task CertificateRotatedMidRun_BreaksTheRun()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client);
        sealer.Cert = CertB;
        await run.Invoking(r => r.RecordModelOutputAsync(Encoding.UTF8.GetBytes("x")))
            .Should().ThrowAsync<SigillException>().WithMessage("*different certificate*");
        run.IsBroken.Should().BeTrue();
        run.Artifacts.Should().HaveCount(1, "the foreign-signed event is never appended");
    }

    [Fact]
    public async Task ControlArtifactWithoutTimestamp_FailsTheStart()
    {
        using var client = Client(new StubSealer { DropTimestamps = true });
        await FluentActions.Invoking(() => Start(client))
            .Should().ThrowAsync<SigillException>().WithMessage("*Control Artifact must be timestamped*");
    }

    [Fact]
    public async Task SubMillisecondTimes_CannotSplitRecorderAndVerifier()
    {
        var times = new Queue<DateTimeOffset>(new[]
        {
            new DateTimeOffset(2026, 10, 1, 8, 59, 0, TimeSpan.Zero),                  // control artifact
            new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero).AddTicks(9_000),   // run_start :00.0009
            new DateTimeOffset(2026, 10, 1, 9, 5, 0, TimeSpan.Zero).AddTicks(1_000),   // 300 s later, :00.0001
            new DateTimeOffset(2026, 10, 1, 9, 6, 0, TimeSpan.Zero),
        });
        using var client = Client(new StubSealer());
        var run = await AgentRun.StartCoreAsync(client, Agent(), Options(new AgentTimestampPolicy { EverySeconds = 300 }),
            () => times.Dequeue(), CancellationToken.None);
        var step = await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("x"));
        step.Envelope["step"]!["timestamp"]!.GetValue<string>().Should().Be("required");
        step.Envelope["step"]!["eventTime"]!.GetValue<string>().Should().Be("2026-10-01T09:05:00.000Z");
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task Callbacks_ArriveInChainOrder_EvenWhenEventsAreRecordedConcurrently()
    {
        using var client = Client(new StubSealer());
        var delivered = new List<int>();
        var run = await Start(client, Options() with
        {
            OnArtifactSealed = async (a, _) =>
            {
                if (a.Seq == 1) await Task.Delay(300); // the first event's persistence is slow
                lock (delivered) delivered.Add(a.Seq ?? -1);
            },
        });
        var first = run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("a"));
        await Task.Delay(50);
        var second = run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("b"));
        await Task.WhenAll(first, second);
        delivered.Should().Equal(-1, 0, 1, 2);
    }

    [Fact]
    public async Task Callback_MayCallBackIntoTheRun()
    {
        using var client = Client(new StubSealer());
        AgentRun? run = null;
        var anchored = new List<AgentRunArtifact>();
        run = await Start(client, Options() with
        {
            OnArtifactSealed = async (a, ct) =>
            {
                if (a.StepType == "tool_call") anchored.Add(await run!.CheckpointAsync("after-write", ct));
            },
        });
        var call = run.RecordToolCallAsync("close_ticket", Encoding.UTF8.GetBytes("{}"), operation: "write");
        (await Task.WhenAny(call, Task.Delay(TimeSpan.FromSeconds(10)))).Should().BeSameAs(call, "a callback must not deadlock the run");
        anchored.Should().ContainSingle().Which.StepType.Should().Be("checkpoint");
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    public static IEnumerable<object[]> RejectedEvents() => new[]
    {
        new object[] { "approval decision outside approved/rejected" },
        new object[] { "object with an unknown role" },
        new object[] { "reserved step member" },
        new object[] { "unknown step member" },
        new object[] { "unknown step type" },
        new object[] { "run_end through RecordAsync" },
    };

    [Theory]
    [MemberData(nameof(RejectedEvents))]
    public async Task Recorder_RefusesEventsTheVerifierWouldReject_WithoutBreakingTheRun(string which)
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client);
        var sealedBefore = sealer.Requests.Count;
        Func<Task> act = which switch
        {
            "approval decision outside approved/rejected" => () => run.RecordHumanApprovalAsync("maybe"),
            "object with an unknown role" => () => run.RecordAsync("retrieval", new[] { new AgentRunObject { Role = "weird", Bytes = new byte[] { 1 } } }),
            "reserved step member" => () => run.RecordAsync("retrieval", fields: new JsonObject { ["finalSeq"] = 3 }),
            "unknown step member" => () => run.RecordAsync("retrieval", fields: new JsonObject { ["parentRun"] = "x" }),
            "unknown step type" => () => run.RecordAsync("custom"),
            _ => () => run.RecordAsync("run_end"),
        };
        await act.Should().ThrowAsync<ArgumentException>();
        sealer.Requests.Should().HaveCount(sealedBefore);
        run.IsBroken.Should().BeFalse();
        await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("still fine"));
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public void Artifact_RejectsNullParts()
    {
        var act = () => new AgentRunArtifact(new JsonObject(), new JsonObject(), null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public async Task RetainedPayloads_UpgradeObjectsToOk()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, Options() with { RetainPayloads = true });
        await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("Done."));
        var bundle = await run.FinishAsync();
        bundle.Payloads.Should().ContainKeys(run.ControlArtifact.ObjectDigests.Keys);

        var result = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.Checks.Values.Should().OnlyContain(s => s == "ok");
    }

    [Fact]
    public async Task EveryEventsCadence_StampsTheNthEvent()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, Options(new AgentTimestampPolicy { EveryEvents = 3 }));
        for (var i = 0; i < 5; i++) await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("x" + i));
        var bundle = await run.FinishAsync();

        // seq: 0 start, 1..5 outputs, 6 end → stamped at seq 2, 5 (cadence) and 6 (run_end).
        bundle.Artifacts.Select(a => a.Envelope["step"]!["timestamp"]!.GetValue<string>())
            .Should().Equal("none", "none", "required", "none", "none", "required", "required");
        (await AgentRunVerifier.VerifyAsync(bundle, StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task SealingFailure_BreaksTheChain_AndTheBundleIsNeverFinalized()
    {
        using var client = Client(new StubSealer { FailOnCall = 2 }); // control, run_start, then the tool call fails
        var run = await Start(client);

        await run.Invoking(r => r.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"))).Should().ThrowAsync<SigillException>();
        run.IsBroken.Should().BeTrue();
        await run.Invoking(r => r.RecordModelOutputAsync(Encoding.UTF8.GetBytes("x"))).Should().ThrowAsync<InvalidOperationException>();
        await run.Invoking(r => r.FinishAsync()).Should().ThrowAsync<InvalidOperationException>();

        (await AgentRunVerifier.VerifyAsync(run.ToBundle(), StubVerify)).Verdict.Should().Be("run_open");
    }

    [Fact]
    public async Task RequiredTimestampMissing_FailsTheEvent()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client);
        sealer.DropTimestamps = true;

        await run.Invoking(r => r.FinishAsync()).Should().ThrowAsync<SigillException>().WithMessage("*timestamp is required*");
        run.IsBroken.Should().BeTrue();
        run.IsFinished.Should().BeFalse();
    }

    [Fact]
    public async Task RunEndCallbackFailure_StillLeavesTheRunFinished()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, Options() with
        {
            OnArtifactSealed = (a, _) => a.StepType == "run_end" ? throw new IOException("disk full") : Task.CompletedTask,
        });

        await run.Invoking(r => r.FinishAsync()).Should().ThrowAsync<IOException>();
        run.IsFinished.Should().BeTrue();
        run.IsBroken.Should().BeFalse();
        await run.Invoking(r => r.RecordModelOutputAsync(Encoding.UTF8.GetBytes("after the end"))).Should().ThrowAsync<InvalidOperationException>();

        var bundle = run.ToBundle();
        bundle.Artifacts.Count(a => a.StepType == "run_end").Should().Be(1);
        (await AgentRunVerifier.VerifyAsync(bundle, StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task OrdinaryEventCallbackFailure_LeavesTheRunUsable()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, Options() with
        {
            OnArtifactSealed = (a, _) => a.StepType == "tool_call" ? throw new IOException("disk full") : Task.CompletedTask,
        });

        await run.Invoking(r => r.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"))).Should().ThrowAsync<IOException>();
        run.IsBroken.Should().BeFalse();
        await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("ok"));
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task ControlEvaluation_RefusesAnythingButARunEnd()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client);
        await FluentActions.Invoking(() => ControlEvaluation.SealAsync(client, new ControlEvaluationRequest
        {
            CertificateId = VerifierCert, VerifierId = "urn:example:verifier", VerifierVersion = "1",
            ControlArtifact = run.ControlArtifact, RunEnd = run.Artifacts[0],
            ObservedState = new[] { AgentRunObject.Text("observed-state", "x") },
            Controls = new[] { new ControlResult("c", "PASS") }, Overall = "PASS",
        })).Should().ThrowAsync<ArgumentException>().WithMessage("*run_end*");
    }

    [Fact]
    public async Task SignHashes_SendsTimestampFalse_OnlyWhenOptedOut()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var hex = EnvelopeHashing.HashHex(Encoding.UTF8.GetBytes("envelope"));
        await client.SignObjectHashesAsync(hex, Array.Empty<SignedObjectDigest>(), Cert);
        await client.SignObjectHashesAsync(hex, Array.Empty<SignedObjectDigest>(), Cert, new ObjectSignOptions { Timestamp = false });
        sealer.Requests[0].ContainsKey("timestamp").Should().BeFalse();
        sealer.Requests[1]["timestamp"]!.GetValue<bool>().Should().BeFalse();
    }

    [Fact]
    public void BlindVerdict_MapsTheVerifyObjectsResponse()
    {
        var response = JsonNode.Parse("""
        {"objects":{"signatureValid":true,"complete":true,
          "objects":[{"par":"urn:sigill:envelope","supplied":true,"hashMatch":true}],
          "missing":[],"unreferenced":[],
          "underlying":{"timestamp":{"genTime":"2026-10-01T09:00:00Z","tsaName":"Example TSA","signatureValid":true},
                        "certificate":{"subject":"CN=Seal","issuer":"CN=CA","notAfter":"2028-01-01T00:00:00Z","isSelfSigned":false}}}}
        """)!.AsObject();
        var v = BlindObjectsVerdict.FromVerifyObjectsResponse(response);
        v.SignatureValid.Should().BeTrue();
        v.Objects.Should().ContainSingle().Which.Should().Be(("urn:sigill:envelope", true));
        v.Timestamp.Should().Be(new SignatureTimestampInfo("2026-10-01T09:00:00Z", "Example TSA", true));
        v.Certificate!.Trust.Should().Be("issuer_distinct");
    }
}
