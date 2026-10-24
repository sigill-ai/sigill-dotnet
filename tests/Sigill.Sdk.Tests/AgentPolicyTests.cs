// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// Agent Policy Control Set v1 (spec/agent-policy-control-set-v1.md): the digests against the
// cross-language vector, structural validation, and the policy options of AgentRun.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    private static string PolicyVectorDir => Path.Combine(SpecRoot.TestVectorsDir, "11-policy-control-set");
    private static byte[] PolicyDoc => File.ReadAllBytes(Path.Combine(PolicyVectorDir, "control-set.json"));
    private static JsonNode PolicyExpected => JsonNode.Parse(File.ReadAllText(Path.Combine(PolicyVectorDir, "expected.json")))!;

    private static byte[] Mutate(Action<JsonObject> change)
    {
        var doc = JsonNode.Parse(PolicyDoc)!.AsObject();
        change(doc);
        return Encoding.UTF8.GetBytes(doc.ToJsonString());
    }

    [Fact]
    public void PolicyDigests_MatchTheVector()
    {
        var d = AgentPolicy.ComputeDigests(PolicyDoc);
        d.ApprovalScopeDigest.Should().Be(PolicyExpected["approvalScopeDigest"]!.GetValue<string>());
        d.CedarDigest.Should().Be(PolicyExpected["cedarDigest"]!.GetValue<string>());
        EnvelopeHashing.HashHex(PolicyDoc).Should().Be(PolicyExpected["objectSha256"]!.GetValue<string>());
        var schema = JsonNode.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "spec", "agent-policy-cedar-schema-v1.json")))!;
        EnvelopeHashing.HashHex(AgentProfiles.Canonical(schema)).Should().Be(PolicyExpected["schemaSha256"]!.GetValue<string>());
    }

    [Fact]
    public void ApprovalScope_IgnoresIdAndVersion_ButCoversEverythingElse()
    {
        var versionOnly = File.ReadAllBytes(Path.Combine(PolicyVectorDir, "control-set-version-only.json"));
        AgentPolicy.ComputeDigests(versionOnly).ApprovalScopeDigest
            .Should().Be(PolicyExpected["versionOnlyApprovalScopeDigest"]!.GetValue<string>())
            .And.Be(AgentPolicy.ComputeDigests(PolicyDoc).ApprovalScopeDigest);
        // Removing a private control or raising the idle limit weakens oversight: a new scope (test 9a/9b).
        var baseline = AgentPolicy.ComputeDigests(PolicyDoc);
        var noPrivate = AgentPolicy.ComputeDigests(Mutate(d => d["privateControls"] = new JsonArray()));
        noPrivate.ApprovalScopeDigest.Should().NotBe(baseline.ApprovalScopeDigest);
        noPrivate.CedarDigest.Should().Be(baseline.CedarDigest, "the rules did not change");
        AgentPolicy.ComputeDigests(Mutate(d => d["coverage"]!["idleSeconds"] = 3600)).ApprovalScopeDigest
            .Should().NotBe(baseline.ApprovalScopeDigest);
    }

    [Fact]
    public void Validate_AcceptsTheVector_AndNamesEveryProblem()
    {
        AgentPolicy.Validate(PolicyDoc).Should().BeEmpty();
        AgentPolicy.Validate(Mutate(d => d["extra"] = 1)).Should().Contain(e => e.Contains("unknown member 'extra'"));
        AgentPolicy.Validate(Mutate(d => d["cedar"]!["policies"]!["staticPolicies"]!["max-steps"]!["effect"] = "permit"))
            .Should().Contain(e => e.Contains("'max-steps' must be forbid"));
        AgentPolicy.Validate(Mutate(d => d["cedar"]!["policies"]!["staticPolicies"]!["max-steps"]!["annotations"]!["id"] = "other"))
            .Should().Contain(e => e.Contains("@id(\"max-steps\")"));
        AgentPolicy.Validate(Mutate(d => d["cedar"]!["schemaSha256"] = "ABC")).Should().Contain(e => e.Contains("schemaSha256"));
        AgentPolicy.Validate(Mutate(d => d["privateControls"] = new JsonArray(new JsonObject { ["id"] = "a" }, new JsonObject { ["id"] = "a" })))
            .Should().Contain(e => e.Contains("unique"));
        AgentPolicy.Validate(Mutate(d => d["coverage"]!["idleSeconds"] = -1)).Should().Contain(e => e.Contains("idleSeconds"));
        AgentPolicy.Validate(Encoding.UTF8.GetBytes("""{"id":"a","id":"b","version":"1","controls":[]}"""))
            .Should().ContainSingle(e => e.Contains("not an I-JSON object"), "a repeated name is not I-JSON");
    }

    [Fact]
    public void Validate_RejectsEveryInvalidVector_WithoutThrowing()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(PolicyVectorDir, "invalid.json")))!;
        foreach (var c in v["cases"]!.AsArray())
        {
            var bytes = Encoding.UTF8.GetBytes(c!["document"]!.GetValue<string>());
            var errors = AgentPolicy.Validate(bytes);
            errors.Should().Contain(e => e.Contains(c["error"]!.GetValue<string>()), c["name"]!.GetValue<string>());
            FluentActions.Invoking(() => AgentPolicy.ComputeDigests(bytes)).Should().Throw<ArgumentException>(c["name"]!.GetValue<string>());
        }
    }

    [Fact]
    public void Validate_RefusesIntegersJavaScriptCannotRead()
    {
        // 2^53 + 1: a browser re-evaluating the policy would read a different number.
        var doc = Mutate(d => d["cedar"]!["policies"]!["staticPolicies"]!["max-steps"]!["conditions"] =
            JsonNode.Parse("""[{"kind":"when","body":{">":{"left":{".":{"left":{"Var":"context"},"attr":"stepsSoFar"}},"right":{"Value":9007199254740993}}}}]"""));
        AgentPolicy.Validate(doc).Should().ContainSingle(e => e.Contains("2^53-1"));
    }

    [Fact]
    public void ControlSetFromDocument_KeepsTheBytes()
    {
        var cs = AgentPolicy.ControlSetFromDocument(PolicyDoc);
        cs.Id.Should().Be("acme-support-agent-controls");
        cs.Version.Should().Be("3");
        cs.ContentType.Should().Be(AgentPolicy.ControlSetContentType);
        cs.Content.Should().Equal(PolicyDoc);
        FluentActions.Invoking(() => AgentPolicy.ControlSetFromDocument(Mutate(d => d.Remove("controls"))))
            .Should().Throw<ArgumentException>().WithMessage("*controls must be an array*");
    }

    /// <summary>Routes index uploads to a recorder; everything else to the stub sealer.</summary>
    private sealed class IndexRecorder(StubSealer sealer) : DelegatingHandler(sealer)
    {
        public List<JsonObject> Uploads { get; } = new();
        public HttpStatusCode Status { get; set; } = HttpStatusCode.Created;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath != "/api/agent-evidence/artifacts") return await base.SendAsync(request, ct);
            Uploads.Add(JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject());
            var body = Status == HttpStatusCode.Created
                ? new JsonObject { ["status"] = "indexed", ["runId"] = "0e0e0e0e-0000-0000-0000-000000000001" }
                : new JsonObject { ["code"] = "control_set_invalid", ["message"] = "no" };
            return new HttpResponseMessage(Status) { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }

    private static AgentRunOptions PolicyOptions() => Options() with { ControlSet = AgentPolicy.ControlSetFromDocument(PolicyDoc) };

    [Fact]
    public async Task PolicyAndAttestedEvaluations_SealAndVerify_AsControlEvaluationV2()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, PolicyOptions());
        await run.RecordToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), operation: "read", useId: "c1");
        await run.RecordToolResultAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        await run.RecordToolCallAsync("crm.delete_customer", Encoding.UTF8.GetBytes("{}"), operation: "delete", consequential: true, useId: "c2");
        await run.RecordToolResultAsync("crm.delete_customer", Encoding.UTF8.GetBytes("{}"), useId: "c2");
        var bundle = await run.FinishAsync("completed");

        sealer.Cert = CertV;
        var rules = new[]
        {
            new PolicyRuleResult("allowed-tools", "FAIL", new[] { "3" }),
            new PolicyRuleResult("consequential-needs-approval", "FAIL", new[] { "3" }),
            new PolicyRuleResult("max-steps", "PASS"),
            new PolicyRuleResult("no-unpaired-consequential", "PASS"),
        };
        var partial = ControlEvaluation.PreparePolicy(new PolicyEvaluationRequest
        {
            CertificateId = VerifierCert, EvaluatorId = "urn:example:policy-evaluator", EvaluatorVersion = "1.0.0",
            ControlArtifact = run.ControlArtifact, ControlSetDocument = PolicyDoc, Events = bundle.Artifacts.Take(3).ToList(),
            Rules = rules.Select(r => r with { Result = "PASS", Where = null }).ToList(), PolicyStatus = "unapproved",
            Engine = "cedar-policy@4.14.0", PrivateControlsReported = "pending",
        }, Clock());
        partial.Envelope["policy"]!["state"]!.GetValue<string>().Should().Be("partial");
        var first = await ControlEvaluation.SealAsync(client, partial, VerifierCert);

        var prepared = ControlEvaluation.PreparePolicy(new PolicyEvaluationRequest
        {
            CertificateId = VerifierCert, EvaluatorId = "urn:example:policy-evaluator", EvaluatorVersion = "1.0.0",
            ControlArtifact = run.ControlArtifact, ControlSetDocument = PolicyDoc, Events = bundle.Artifacts,
            Rules = rules, PolicyStatus = "unapproved", Engine = "cedar-policy@4.14.0", PrivateControlsReported = "reported",
            Supersedes = new EvaluationReference(first.EvidenceId!, first.SignatureSha256!),
        }, Clock());
        prepared.Envelope["overall"]!.GetValue<string>().Should().Be("FAIL", "overall is derived from the rules");
        var final = await ControlEvaluation.SealAsync(client, prepared, VerifierCert);

        sealer.Cert = CertA; // the producer seals its own private-control results with the run's certificate
        var attestedPrep = ControlEvaluation.PrepareAttested(new AttestedEvaluationRequest
        {
            CertificateId = VerifierCert, ProducerId = "urn:example:harness", ProducerVersion = "1.0.0",
            ControlArtifact = run.ControlArtifact, RunEnd = bundle.Artifacts[^1], ControlSetDocument = PolicyDoc,
            Controls = new[] { new ControlResult("no-card-numbers-in-replies", "PASS") },
        }, Clock());
        var attested = await ControlEvaluation.SealAsync(client, attestedPrep, VerifierCert);

        var payloads = partial.Payloads.Concat(prepared.Payloads).Concat(attestedPrep.Payloads)
            .GroupBy(kv => kv.Key).ToDictionary(g => g.Key, g => g.First().Value);
        bundle = bundle.WithEvaluations(first, final, attested).WithPayloads(payloads);
        var result = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(bundle.ToJsonString()), StubVerify);

        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.Evaluations.Should().HaveCount(3);
        foreach (var e in result.Evaluations) e.Valid.Should().BeTrue(string.Join(" | ", e.Findings));
        result.Evaluations[0].Should().Match<AgentEvaluationVerdict>(e => e.Kind == "policy" && e.PolicyState == "partial" && !e.Current);
        result.Evaluations[1].Should().Match<AgentEvaluationVerdict>(e => e.Kind == "policy" && e.FactsMatch == true
            && e.PolicyDigestsMatch == true && e.Current && e.Overall == "FAIL" && !e.ResultsRecomputed);
        result.Evaluations[2].Kind.Should().Be("attested");
        payloads.Keys.Should().Contain(run.ControlArtifact.Envelope["objects"]!.AsArray()
            .Select(o => o!["uri"]!.GetValue<string>()).Where(u => payloads.ContainsKey(u)), "the control set travels as a payload");
    }

    [Fact]
    public void PreparePolicy_RefusesWhatWouldNotVerify()
    {
        var control = new AgentRunArtifact(new JsonObject(), new JsonObject(), new Dictionary<string, string>());
        var request = new PolicyEvaluationRequest
        {
            CertificateId = VerifierCert, EvaluatorId = "e", EvaluatorVersion = "1", ControlArtifact = control,
            ControlSetDocument = Encoding.UTF8.GetBytes("{}"), Events = Array.Empty<AgentRunArtifact>(),
            Rules = Array.Empty<PolicyRuleResult>(), PolicyStatus = "unapproved", Engine = "cedar-policy@4.14.0",
        };
        FluentActions.Invoking(() => ControlEvaluation.PreparePolicy(request)).Should().Throw<ArgumentException>().WithMessage("*policy control set*");
    }

    [Fact]
    public async Task DisclosePolicy_UploadsTheControlArtifactAndDocument_Only()
    {
        var sealer = new StubSealer();
        var index = new IndexRecorder(sealer);
        using var client = new SigillClient(new HttpClient(index) { BaseAddress = new Uri("https://api.example") });
        var run = await Start(client, PolicyOptions() with { DisclosePolicy = true });
        await run.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        await run.FinishAsync("completed");

        index.Uploads.Should().ContainSingle("only the Control Artifact is shared — execution events are not");
        var up = index.Uploads[0];
        up["envelope"]!["schemaName"]!.GetValue<string>().Should().Be(AgentProfiles.ControlArtifactSchema);
        Convert.FromBase64String(up["controlSet"]!.GetValue<string>()).Should().Equal(PolicyDoc);
        up["objectDigests"]!.AsObject().Should().HaveCount(run.ControlArtifact.ObjectDigests.Count);
        run.PolicyDisclosure!.Succeeded.Should().BeTrue();
        run.PolicyDisclosure.RunId.Should().NotBeNull();
    }

    [Fact]
    public async Task DisclosePolicy_Failure_NeverFailsTheRun()
    {
        var sealer = new StubSealer();
        var index = new IndexRecorder(sealer) { Status = HttpStatusCode.UnprocessableEntity };
        using var client = new SigillClient(new HttpClient(index) { BaseAddress = new Uri("https://api.example") });
        var run = await Start(client, PolicyOptions() with { DisclosePolicy = true });
        run.PolicyDisclosure!.Status.Should().Be("failed");
        run.PolicyDisclosure.Error.Should().Contain("422").And.Contain("control_set_invalid");
        var bundle = await run.FinishAsync("completed");
        bundle.Artifacts.Should().HaveCount(2);
    }

    [Fact]
    public async Task DisclosePolicy_RequiresAPolicyControlSet_AndAMalformedPolicyIsNeverSealed()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        await FluentActions.Awaiting(() => Start(client, Options() with { DisclosePolicy = true }))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*DisclosePolicy requires*");
        var bad = Options() with
        {
            ControlSet = new AgentControlSet
            {
                Id = "acme-support-agent-controls", Version = "3", ContentType = AgentPolicy.ControlSetContentType,
                Content = Mutate(d => d["cedar"]!["policies"]!["staticPolicies"]!["max-steps"]!["effect"] = "permit"),
            },
        };
        await FluentActions.Awaiting(() => Start(client, bad)).Should().ThrowAsync<ArgumentException>().WithMessage("*must be forbid*");
        var mislabelled = PolicyOptions() with { ControlSet = PolicyOptions().ControlSet with { Version = "4" } };
        await FluentActions.Awaiting(() => Start(client, mislabelled)).Should().ThrowAsync<ArgumentException>().WithMessage("*must equal the document*");
        sealer.Requests.Should().BeEmpty("nothing is sealed before the control set is valid");
    }

    [Fact]
    public async Task QualifiedFor_StampsOnlyTheChosenArtifactsQualified()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, Options() with { QualifiedFor = QualifiedArtifacts.ControlArtifact | QualifiedArtifacts.RunEnd });
        await run.CheckpointAsync();
        await run.FinishAsync("completed");
        static bool Q(JsonObject r) => r["qualified"]?.GetValue<bool>() ?? false;
        sealer.Requests.Select(Q).Should().Equal(true, false, false, true); // control, run_start, checkpoint, run_end
    }
}

public class PolicyFactsVectorTests
{
    private static string Dir => Path.Combine(SpecRoot.TestVectorsDir, "12-policy-evaluation");

    public static IEnumerable<object[]> Runs() =>
        Directory.GetFiles(Path.Combine(Dir, "runs"), "*.json").Select(p => new object[] { Path.GetFileNameWithoutExtension(p) });

    [Theory]
    [MemberData(nameof(Runs))]
    public void BuildFacts_IsByteExactWithTheVector(string run)
    {
        var input = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir, "runs", run + ".json")))!;
        var events = input["events"]!.AsArray().Select(e => e!.AsObject()).Reverse(); // any order
        var facts = AgentPolicy.BuildFacts(input["agentId"]!.GetValue<string>(), input["correlationId"]!.GetValue<string>(), events);

        Encoding.UTF8.GetString(facts.Bytes).Should().Be(File.ReadAllText(Path.Combine(Dir, "expected", run + ".facts.json")));
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir, "expected", run + ".results.json")))!;
        facts.Sha256.Should().Be(expected["factsSha256"]!.GetValue<string>());
        facts.ThroughSeq.Should().Be(expected["throughSeq"]!.GetValue<int>());
        facts.RunLevel.Should().Be(expected["runLevel"]!.GetValue<bool>());
        facts.MissingSeqs.Should().Equal(expected["missingSeqs"]!.AsArray().Select(m => m!.GetValue<int>()));
    }

    [Fact]
    public void BuildFacts_RefusesTwoEventsWithTheSameSeq()
    {
        var e = JsonNode.Parse("""{"chain":{"seq":0},"step":{"type":"run_start"}}""")!.AsObject();
        var act = () => AgentPolicy.BuildFacts("a", "r", new[] { e, e.DeepClone().AsObject() });
        act.Should().Throw<ArgumentException>().WithMessage("*seq 0*");
    }
}
