// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// AgentExecutionProfileV1: the cross-language vectors (spec/test-vectors/agent-run)
// verified through the stub verifier, and the recorder end-to-end against a
// fake sealing endpoint that signs with the same stub. HTTP is faked; hashes
// and chain digests are real.

using System;
using System.Collections.Generic;
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
    private static string Sha256Hex(byte[] b) => EnvelopeHashing.HashHex(b);

    private static JsonObject StubSign(string envelopeHashHex, IEnumerable<(string Uri, string Hex)> objects, bool timestamp, string genTime)
    {
        var pars = new JsonArray { "urn:sigill:envelope" };
        var hashV = new JsonArray { B64U(Convert.FromHexString(envelopeHashHex)) };
        foreach (var (uri, hex) in objects) { pars.Add(uri); hashV.Add(B64U(Convert.FromHexString(hex))); }
        var prot = B64U(JsonCanonicalizer.Canonicalize(
            new JsonObject { ["alg"] = "ES256", ["sigD"] = new JsonObject { ["pars"] = pars, ["hashV"] = hashV } }.ToJsonString()));
        var entry = new JsonObject { ["protected"] = prot, ["signature"] = B64U(SHA256.HashData(Encoding.ASCII.GetBytes(prot))) };
        if (timestamp) entry["header"] = new JsonObject { ["stubTimestamp"] = new JsonObject { ["genTime"] = genTime, ["valid"] = true } };
        return new JsonObject { ["signatures"] = new JsonArray { entry } };
    }

    private static Task<BlindObjectsVerdict> StubVerify(JsonObject signature, IReadOnlyDictionary<string, string> digests, CancellationToken _)
    {
        var entry = signature["signatures"]!.AsArray().OfType<JsonObject>().First(e =>
            !(JsonNode.Parse(AgentExecutionProfile.Base64UrlDecode(e["protected"]!.GetValue<string>()))!["alg"]!
                .GetValue<string>().StartsWith("ML-DSA", StringComparison.OrdinalIgnoreCase)));
        var prot = entry["protected"]!.GetValue<string>();
        var sigD = JsonNode.Parse(AgentExecutionProfile.Base64UrlDecode(prot))!["sigD"]!;
        var pars = sigD["pars"]!.AsArray().Select(n => n!.GetValue<string>()).ToList();
        var hashV = sigD["hashV"]!.AsArray().Select(n => Convert.ToHexString(AgentExecutionProfile.Base64UrlDecode(n!.GetValue<string>())).ToLowerInvariant()).ToList();
        var valid = entry["signature"]!.GetValue<string>() == B64U(SHA256.HashData(Encoding.ASCII.GetBytes(prot)));
        var objects = pars.Select((p, i) => (p, digests.TryGetValue(p, out var d) && d == hashV[i])).ToList();
        SignatureTimestampInfo? ts = null;
        if (entry["header"]?["stubTimestamp"] is JsonObject st)
            ts = new SignatureTimestampInfo(st["genTime"]!.GetValue<string>(), "Stub TSA", st["valid"]!.GetValue<bool>());
        return Task.FromResult(new BlindObjectsVerdict
        {
            SignatureValid = valid,
            Complete = valid && objects.All(o => o.Item2),
            Objects = objects,
            Missing = pars.Where(p => !digests.ContainsKey(p)).ToList(),
            Unreferenced = digests.Keys.Where(k => !pars.Contains(k)).ToList(),
            Timestamp = ts,
            Certificate = new SignerCertificateInfo("CN=Stub Signer", "CN=Stub CA", "2030-01-01T00:00:00Z", "issuer_distinct"),
        });
    }

    // ── Vectors ──────────────────────────────────────────────────────────────

    [Fact]
    public void ChainDigest_MatchesVectors()
    {
        var cases = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "chain-digest.json")))!.AsArray();
        cases.Should().HaveCount(3);
        foreach (var c in cases)
            AgentExecutionProfile.ChainDigest(c!["signature"]!.AsObject())
                .Should().Be(c["expected"]!.GetValue<string>(), c["name"]!.GetValue<string>());
    }

    [Fact]
    public void ConfigurationDigest_MatchesVector()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "config-digest.json")))!;
        byte[] B(string k) => Convert.FromBase64String(v[k]!.GetValue<string>());
        AgentExecutionProfile.ConfigurationDigest(B("agentManifest"), new AgentConfiguration
        {
            InstructionSet = B("instructionSet"), ToolManifest = B("toolManifest"),
            ModelConfig = B("modelConfig"), ExecutionPolicy = B("executionPolicy"),
        }).Should().Be(v["expected"]!.GetValue<string>());
        AgentExecutionProfile.ConfigurationDigest(B("agentManifest"), new AgentConfiguration
        {
            InstructionSet = B("instructionSet"), ToolManifest = B("toolManifest"), ExecutionPolicy = B("executionPolicy"),
        }).Should().Be(v["expectedWithoutModelConfig"]!.GetValue<string>());
    }

    public static IEnumerable<object[]> RunVectors() =>
        Directory.GetFiles(Path.Combine(SpecRoot.TestVectorsDir, "agent-run", "runs"), "*.json")
            .OrderBy(f => f, StringComparer.Ordinal).Select(f => new object[] { Path.GetFileName(f) });

    [Theory]
    [MemberData(nameof(RunVectors))]
    public async Task RunVector_ReproducesExpectedVerdict(string file)
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", file)))!;
        var bundle = AgentRunBundle.Parse(v["bundle"]);
        var expected = v["expected"]!;

        var result = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);

        result.Verdict.Should().Be(expected["verdict"]!.GetValue<string>(), string.Join("\n", result.Findings));
        foreach (var kv in expected["checks"]!.AsObject())
            result.Checks[kv.Key].Should().Be(kv.Value!.GetValue<string>(), $"check '{kv.Key}' — {string.Join(" | ", result.Findings)}");
        result.Checks.Should().HaveCount(9);
        result.MissingSeqs.Should().Equal(expected["missingSeqs"]!.AsArray().Select(n => n!.GetValue<int>()));
        result.Fingerprint.Should().Be(expected["fingerprint"]?.GetValue<string>(), "null when the evidence is not valid I-JSON");
        foreach (var f in expected["findingsContain"]!.AsArray())
            result.Findings.Should().Contain(x => x.Contains(f!.GetValue<string>()));
        if (result.Verdict != "run_invalid") result.Findings.Should().BeEmpty();
    }

    [Fact]
    public void Bundle_RoundTripsThroughJson()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", "02-finalized-with-payloads.json")))!;
        var bundle = AgentRunBundle.Parse(v["bundle"]);
        var again = AgentRunBundle.Parse(bundle.ToJsonString());
        AgentRunVerifier.Fingerprint(again).Should().Be(v["expected"]!["fingerprint"]!.GetValue<string>());
        again.Payloads.Should().HaveCount(bundle.Payloads.Count);
    }

    [Fact]
    public void Bundle_ParseIsStrict_AndListsEveryProblem()
    {
        var bad = new JsonObject
        {
            ["profile"] = "SomethingElse",
            ["artifacts"] = new JsonArray
            {
                new JsonObject { ["envelope"] = new JsonObject(), ["signature"] = new JsonObject(), ["objectDigests"] = new JsonObject { ["urn:x"] = "ABC" } },
                "not an object",
            },
            ["payloads"] = new JsonObject { ["urn:y"] = "%%%" },
        };
        var act = () => AgentRunBundle.Parse(bad);
        var ex = act.Should().Throw<AgentRunBundleFormatException>().Which;
        ex.Errors.Should().HaveCount(5);
        ex.Errors.Should().Contain(e => e.Contains("unsupported profile"));
        ex.Errors.Should().Contain(e => e.Contains("unsupported bundleVersion"));
        ex.Errors.Should().Contain(e => e.Contains("64-char hex"));
        ex.Errors.Should().Contain(e => e.Contains("artifacts[1]: not an object"));
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
    public void RunVectors_AreAllPresent() =>
        RunVectors().Should().HaveCount(30);

    [Fact]
    public async Task MalformedEnvelope_IsAnInvalidVerdict_NeverAnException()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(VectorsDir, "runs", "01-finalized-digests-only.json")))!;
        v["bundle"]!["artifacts"]![1]!["envelope"]!["chain"] = "seq one";
        var result = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(v["bundle"]), StubVerify);
        result.Verdict.Should().Be("run_invalid");
        result.Checks["envelope"].Should().Be("bad");
        result.Findings.Should().Contain(f => f.Contains("chain is not an object"));
    }

    // ── Recorder ─────────────────────────────────────────────────────────────

    /// <summary>A sign-hashes endpoint that signs with the stub and records every request.</summary>
    private sealed class StubSealer : HttpMessageHandler
    {
        public List<JsonObject> Requests { get; } = new();
        public int FailOnCall { get; set; } = -1;
        public bool DropTimestamps { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            request.RequestUri!.AbsolutePath.Should().Be("/seal/sign-hashes");
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject();
            Requests.Add(body);
            if (Requests.Count - 1 == FailOnCall)
                return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("busy") };
            var stamp = body["timestamp"]?.GetValue<bool>() ?? true;
            stamp &= !DropTimestamps;
            var sig = StubSign(body["envelopeHashHex"]!.GetValue<string>(),
                body["objects"]!.AsArray().Select(o => (o!["uri"]!.GetValue<string>(), o["hashHex"]!.GetValue<string>())),
                stamp, "2026-10-01T09:00:00Z");
            var res = new JsonObject
            {
                ["signature"] = sig, ["operationId"] = Guid.NewGuid().ToString(), ["format"] = stamp ? "jades-b-t" : "jades-b-b",
                ["timestampedBy"] = stamp ? "Stub TSA" : null, ["qualified"] = false, ["pqc"] = false,
            };
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(res.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }

    private static readonly Guid Cert = Guid.Parse("11111111-2222-3333-4444-555555555555");

    private static AgentDefinition Agent(string instructions = "You triage support tickets.") => new()
    {
        AgentId = "urn:example:agent:triage",
        AgentVersion = "1.0.0",
        Model = new AgentModelRef("example-ai", "example-model-1"),
        TenantId = "tenant-example",
        Configuration = new AgentConfiguration
        {
            InstructionSet = Encoding.UTF8.GetBytes(instructions),
            ToolManifest = Encoding.UTF8.GetBytes("""{"tools":["lookup_ticket","close_ticket"]}"""),
            ModelConfig = Encoding.UTF8.GetBytes("""{"temperature":0}"""),
            ExecutionPolicy = Encoding.UTF8.GetBytes("""{"allow":["lookup_ticket","close_ticket"]}"""),
        },
    };

    private static SigillClient Client(StubSealer sealer) =>
        new(new HttpClient(sealer) { BaseAddress = new Uri("https://api.example") });

    /// <summary>A clock that advances one minute per reading.</summary>
    private static Func<DateTimeOffset> Clock()
    {
        var t = new DateTimeOffset(2026, 10, 1, 9, 0, 0, TimeSpan.Zero);
        return () => (t = t.AddMinutes(1));
    }

    private static readonly byte[] Secret = Encoding.UTF8.GetBytes("customer 4411: Jane Doe cannot log in");

    [Fact]
    public async Task RecordedRun_VerifiesAsFinalized_AndNoContentEverTravels()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var sealedSteps = new List<string?>();
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions
        {
            CertificateId = Cert,
            StartObjects = new[] { new AgentRunObject { Kind = "user-turn", Role = "prompt", Bytes = Secret, ContentType = "text/plain" } },
            OnArtifactSealed = (a, _) => { sealedSteps.Add(a.StepType); return Task.CompletedTask; },
        }, Clock(), CancellationToken.None);
        await run.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("""{"ticket":"4411"}"""));
        await run.RecordToolResultAsync("lookup_ticket", Encoding.UTF8.GetBytes("""{"status":"open"}"""));
        await run.RecordToolCallAsync("close_ticket", Encoding.UTF8.GetBytes("""{"ticket":"4411"}"""), consequential: true);
        await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("Closed."));
        var bundle = await run.FinishAsync("completed", new JsonObject { ["inputTokens"] = 10 });

        var result = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(bundle.ToJsonString()), StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.Checks.Values.Should().OnlyContain(s => s == "ok" || s == "warn");
        result.Checks["objects"].Should().Be("warn", "no payloads retained by default");
        result.Disposition.Should().Be("completed");
        result.Identity.Linked.Should().BeTrue();
        sealedSteps.Should().Equal("run_start", "tool_call", "tool_result", "tool_call", "model_output", "run_end");

        // Blind contract: one identity seal + six steps, digests and opaque URIs only.
        sealer.Requests.Should().HaveCount(7);
        var wire = string.Join("\n", sealer.Requests.Select(r => r.ToJsonString()));
        // (Only strings that cannot occur by chance in a digest or UUID.)
        wire.Should().NotContain("Jane Doe").And.NotContain("ticket").And.NotContain("triage support");
        bundle.Payloads.Should().BeEmpty();
        bundle.ToJsonString().Should().NotContain("Jane Doe");

        // Timestamps: identity, consequential call and run_end stamped; the rest B-B.
        sealer.Requests.Select(r => r["timestamp"]?.GetValue<bool>() ?? true)
            .Should().Equal(true, false, false, false, true, false, true);

        // Schema conformance of what the recorder builds (v2: evidenceId / parentEvidenceId are bare UUIDs).
        foreach (var a in bundle.Artifacts.Append(bundle.AgentIdentity!))
        {
            Guid.TryParse(a.Envelope["evidenceId"]!.GetValue<string>(), out _).Should().BeTrue();
            if (a.Envelope["activity"]!["parentEvidenceId"] is { } parent) Guid.TryParse(parent.GetValue<string>(), out _).Should().BeTrue();
            a.Envelope["actor"]!["type"]!.GetValue<string>().Should().Be("agent");
        }
    }

    [Fact]
    public async Task AuthorizationAndHumanApprovalFlow_VerifiesAsFinalized()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions { CertificateId = Cert }, Clock(), CancellationToken.None);
        var auth = await run.RecordAuthorizationAsync(
            new AgentAuthorization { Decision = "allowed", PolicyId = "support-tools-v1", Reason = "write requires approval" },
            tool: "close_ticket", operation: "write");
        var approval = await run.RecordHumanApprovalAsync("approved",
            receipt: Encoding.UTF8.GetBytes("""{"decision":"approved"}"""),
            identityAssertion: Encoding.UTF8.GetBytes("eyJhbGciOiJFUzI1NiJ9.x.y"),
            approverRef: "urn:example:approver:42", actionEvidenceId: auth.EvidenceId);
        await run.RecordToolCallAsync("close_ticket", Encoding.UTF8.GetBytes("""{"ticket":"4411"}"""), operation: "write",
            authorization: new AgentAuthorization { Decision = "allowed", PolicyId = "support-tools-v1" }, consequential: true);
        var bundle = await run.FinishAsync();

        var ext = approval.Envelope["extensions"]![AgentExecutionProfile.ExtensionKey]!;
        ext["approval"]!.ToJsonString().Should().Be(
            $$"""{"decision":"approved","approverRef":"urn:example:approver:42","actionEvidenceId":"{{auth.EvidenceId}}"}""");
        ext["timestamp"]!.GetValue<string>().Should().Be("required", "an approval is consequential by default");
        ext["objectKinds"]!.AsObject().Select(kv => kv.Value!.GetValue<string>()).Should()
            .BeEquivalentTo("approval-receipt", "identity-assertion");
        var call = bundle.Artifacts[3].Envelope["extensions"]![AgentExecutionProfile.ExtensionKey]!;
        call["tool"]!.ToJsonString().Should().Be("""{"name":"close_ticket","operation":"write"}""");
        call["authorization"]!.ToJsonString().Should().Be("""{"decision":"allowed","policyId":"support-tools-v1"}""");

        var result = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        string.Join("\n", sealer.Requests.Select(r => r.ToJsonString())).Should().NotContain("eyJhbGciOiJFUzI1NiJ9");
    }

    [Fact]
    public async Task InvalidAuthorizationDecision_IsRejectedBeforeSealing()
    {
        using var client = Client(new StubSealer());
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions { CertificateId = Cert }, Clock(), CancellationToken.None);
        await run.Invoking(r => r.RecordAuthorizationAsync(new AgentAuthorization { Decision = "maybe" }))
            .Should().ThrowAsync<ArgumentException>();
        run.IsBroken.Should().BeFalse();
    }

    [Fact]
    public async Task RunWithoutModelConfig_VerifiesAsFinalized()
    {
        using var client = Client(new StubSealer());
        var agent = Agent() with
        {
            Configuration = new AgentConfiguration
            {
                InstructionSet = Encoding.UTF8.GetBytes("You triage."),
                ToolManifest = Encoding.UTF8.GetBytes("{}"),
                ExecutionPolicy = Encoding.UTF8.GetBytes("{}"),
            },
        };
        var run = await AgentRun.StartCoreAsync(client, agent, new AgentRunOptions { CertificateId = Cert }, Clock(), CancellationToken.None);
        run.Artifacts[0].Envelope["extensions"]![AgentExecutionProfile.ExtensionKey]!["objectKinds"]!.AsObject()
            .Select(kv => kv.Value!.GetValue<string>()).Should().NotContain("model-config");
        var result = await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.Checks["identity"].Should().Be("ok");
    }

    [Fact]
    public async Task RetainedPayloads_UpgradeObjectsToOk()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions { CertificateId = Cert, RetainPayloads = true },
            Clock(), CancellationToken.None);
        await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("Done."));
        var bundle = await run.FinishAsync();

        var result = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.Checks.Values.Should().OnlyContain(s => s == "ok");
    }

    [Fact]
    public async Task EveryEventsCadence_StampsTheNthStep()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions
        {
            CertificateId = Cert, TimestampPolicy = new AgentTimestampPolicy { EveryEvents = 3, EverySeconds = 0 },
        }, Clock(), CancellationToken.None);
        for (var i = 0; i < 5; i++) await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("x" + i));
        var bundle = await run.FinishAsync();

        // seq: 0 start, 1..5 outputs, 6 end → stamped at seq 2, 5 (cadence) and 6 (run_end).
        bundle.Artifacts.Select(a => a.Envelope["extensions"]![AgentExecutionProfile.ExtensionKey]!["timestamp"]!.GetValue<string>())
            .Should().Equal("none", "none", "required", "none", "none", "required", "required");
        (await AgentRunVerifier.VerifyAsync(bundle, StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task SealingFailure_BreaksTheChain_AndTheBundleIsNeverFinalized()
    {
        var sealer = new StubSealer { FailOnCall = 2 }; // identity, run_start, then the tool call fails
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions { CertificateId = Cert }, Clock(), CancellationToken.None);

        var act = () => run.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"));
        await act.Should().ThrowAsync<SigillException>();
        run.IsBroken.Should().BeTrue();
        await run.Invoking(r => r.RecordModelOutputAsync(Encoding.UTF8.GetBytes("x"))).Should().ThrowAsync<InvalidOperationException>();
        await run.Invoking(r => r.FinishAsync()).Should().ThrowAsync<InvalidOperationException>();

        var result = await AgentRunVerifier.VerifyAsync(run.ToBundle(), StubVerify);
        result.Verdict.Should().Be("run_open");
    }

    [Fact]
    public async Task RequiredTimestampMissing_FailsTheStep()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions { CertificateId = Cert }, Clock(), CancellationToken.None);
        sealer.DropTimestamps = true;

        await run.Invoking(r => r.FinishAsync()).Should().ThrowAsync<SigillException>().WithMessage("*timestamp is required*");
        run.IsBroken.Should().BeTrue();
        run.IsFinished.Should().BeFalse();
    }

    [Fact]
    public async Task IdentityRecord_IsReused_AndRejectedForAnotherConfiguration()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var identity = await AgentRun.RegisterIdentityAsync(client, Agent(), Cert);

        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions { CertificateId = Cert, Identity = identity },
            Clock(), CancellationToken.None);
        sealer.Requests.Should().HaveCount(2, "the identity record is not sealed again");
        run.Identity.Should().BeSameAs(identity);
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Checks["identity"].Should().Be("ok");

        var act = () => AgentRun.StartAsync(client, Agent("A different instruction set."),
            new AgentRunOptions { CertificateId = Cert, Identity = identity });
        await act.Should().ThrowAsync<ArgumentException>().WithMessage("*different agent configuration*");
    }

    [Fact]
    public async Task RunEndCallbackFailure_StillLeavesTheRunFinished()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions
        {
            CertificateId = Cert,
            OnArtifactSealed = (a, _) => a.StepType == "run_end" ? throw new IOException("disk full") : Task.CompletedTask,
        }, Clock(), CancellationToken.None);

        await run.Invoking(r => r.FinishAsync()).Should().ThrowAsync<IOException>();
        run.IsFinished.Should().BeTrue();
        run.IsBroken.Should().BeFalse();
        await run.Invoking(r => r.RecordModelOutputAsync(Encoding.UTF8.GetBytes("after the end"))).Should().ThrowAsync<InvalidOperationException>();
        await run.Invoking(r => r.FinishAsync()).Should().ThrowAsync<InvalidOperationException>();

        var bundle = run.ToBundle();
        bundle.Artifacts.Count(a => a.StepType == "run_end").Should().Be(1);
        (await AgentRunVerifier.VerifyAsync(bundle, StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task OrdinaryStepCallbackFailure_LeavesTheRunUsable()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions
        {
            CertificateId = Cert,
            OnArtifactSealed = (a, _) => a.StepType == "tool_call" ? throw new IOException("disk full") : Task.CompletedTask,
        }, Clock(), CancellationToken.None);

        await run.Invoking(r => r.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"))).Should().ThrowAsync<IOException>();
        run.IsBroken.Should().BeFalse();
        run.IsFinished.Should().BeFalse();
        await run.RecordModelOutputAsync(Encoding.UTF8.GetBytes("ok"));
        (await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task ReservedStepTypes_AreRejected()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), new AgentRunOptions { CertificateId = Cert }, Clock(), CancellationToken.None);
        await run.Invoking(r => r.RecordAsync("run_end")).Should().ThrowAsync<ArgumentException>();
        run.IsBroken.Should().BeFalse();
    }

    [Fact]
    public async Task SignHashes_SendsTimestampFalse_OnlyWhenOptedOut()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var hex = Sha256Hex(Encoding.UTF8.GetBytes("envelope"));
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
