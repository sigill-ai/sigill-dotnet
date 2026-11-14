// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// ControlEvaluation v3 (spec/control-evaluation-v3.md): a policy evaluation of a run under a v2 control set — facts v2 and the
// enforcement comparison — prepared, sealed and verified; and the evaluations a verifier must reject.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    /// <summary>
    /// A run recorded under vector 13's enforcing control set (one call refused, one allowed) and a sealed v3 policy evaluation of
    /// it, optionally changed before sealing.
    /// </summary>
    private async Task<(AgentRunBundle Bundle, JsonObject Enforcement)> EvaluatedEnforcedRun(Action<JsonObject>? mutate = null, byte[]? doc = null,
        IPolicyEngine? evaluator = null)
    {
        evaluator ??= TestEngine.Shared;
        doc ??= DocV13;
        var (run, sealer, client) = await StartGuarded(doc);
        using var owned = client;
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>();
        await run.InvokeToolAsync("crm.update_address", Utf8("{}"), _ => System.Threading.Tasks.Task.FromResult(Utf8("{}")), definition: Utf8("crm.update_address definition"));
        var bundle = await run.FinishAsync();

        var enforcement = AgentPolicy.CompareEnforcement(run.ControlArtifact, bundle.Artifacts, doc, evaluator);
        var facts = AgentPolicy.BuildFactsV2(SupportAgent().AgentId, run.CorrelationId, bundle.Artifacts, doc);
        var evaluated = AgentPolicy.Evaluate(doc, facts.Bytes, evaluator);
        var declaresPrivate = JsonNode.Parse(doc)!["privateControls"] is JsonArray pc && pc.Count > 0;
        var prepared = ControlEvaluation.PreparePolicy(new PolicyEvaluationRequest
        {
            CertificateId = VerifierCert, EvaluatorId = "urn:example:policy-evaluator", EvaluatorVersion = "1.0.0",
            ControlArtifact = run.ControlArtifact, ControlSetDocument = doc, Events = bundle.Artifacts,
            Rules = evaluated.Rules, PolicyStatus = "unapproved", Engine = evaluated.Engine, Enforcement = enforcement,
            PrivateControlsReported = declaresPrivate ? "pending" : null,
        }, Clock());
        if (mutate is not null)
        {
            var changed = (JsonObject)prepared.Envelope.DeepClone();
            mutate(changed);
            prepared = prepared with { Envelope = changed, EnvelopeHashHex = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(changed)) };
        }
        sealer.Cert = CertV;
        var evaluation = await ControlEvaluation.SealAsync(client, prepared, VerifierCert);
        return (AgentRunBundle.Parse(bundle.WithEvaluations(evaluation).WithPayloads(prepared.Payloads).ToJsonString()), enforcement);
    }

    [Fact]
    public async Task AV3PolicyEvaluation_IsPrepared_Sealed_AndVerified_WithTheComparisonRecomputed()
    {
        var (bundle, enforcement) = await EvaluatedEnforcedRun();
        var envelope = bundle.Evaluations[0].Envelope;
        envelope["schemaVersion"]!.GetValue<string>().Should().Be("3");
        envelope["policy"]!["evaluator"]!["factsVersion"]!.GetValue<string>().Should().Be("2");
        envelope["policy"]!["enforcement"]!.ToJsonString().Should().Be(enforcement.ToJsonString());
        enforcement["result"]!.GetValue<string>().Should().Be("as_required");
        enforcement["decisions"]!.AsArray().Should().ContainSingle();

        var result = await AgentRunVerifier.VerifyWithEngineAsync(bundle, StubVerify, TestEngine.Shared);
        var e = result.Evaluations.Single();
        e.Valid.Should().BeTrue(string.Join(" | ", e.Findings));
        (e.SchemaVersion, e.Kind, e.FactsMatch, e.PolicyDigestsMatch, e.ResultsRecomputed, e.EnforcementRecomputed).Should().Be(("3", "policy", true, true, true, true));
        (e.EnforcementComparison, e.EnforcementResult).Should().Be(("performed", "as_required"));
        EvaluationNotes(result).Should().BeEmpty();

        // Without the core the comparison is checked as far as it can be, not recomputed, and a note says so.
        var blindResult = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        var blind = blindResult.Evaluations.Single();
        (blind.Valid, blind.ResultsRecomputed, blind.EnforcementRecomputed).Should().Be((true, false, false));
        (blind.EnforcementComparison, blind.EnforcementResult).Should().Be(("performed", "as_required"));
        EvaluationNotes(blindResult).Should().Equal("evaluation 0: its enforcement comparison was not recomputed: no engine was given.");
    }

    /// <summary>The official core under another version name: an evaluator whose core is not the one the guard recorded.</summary>
    private sealed class Renamed(string version) : IPolicyEngine
    {
        public string Version => version;
        public JsonObject Authorize(JsonObject call) => TestEngine.Shared.Authorize(call);
        public JsonObject Validate(JsonObject call) => TestEngine.Shared.Validate(call);
    }

    [Fact]
    public async Task ANotPerformedComparison_IsNeverRecomputed_AndEveryMissedRecomputationIsNoted()
    {
        var other = new Renamed("99.0.0");
        var (bundle, enforcement) = await EvaluatedEnforcedRun(evaluator: other);
        System.Text.Encoding.UTF8.GetString(AgentProfiles.Canonical(enforcement)).Should().Be("""{"comparison":"not_performed","notPerformed":"engine_unavailable","recordedEngine":"cedar-policy@4.14.0"}""");

        var blindResult = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        var blind = blindResult.Evaluations.Single();
        (blind.Valid, blind.EnforcementRecomputed, blind.EnforcementComparison, blind.EnforcementResult).Should().Be((true, false, "not_performed", (string?)null));
        EvaluationNotes(blindResult).Should().Equal("evaluation 0: its enforcement comparison was not recomputed: no engine was given.");

        // With another core both missed recomputations reach the caller, the results' and the comparison's.
        var mismatched = await AgentRunVerifier.VerifyWithEngineAsync(bundle, StubVerify, TestEngine.Shared);
        mismatched.Evaluations.Single().EnforcementRecomputed.Should().BeFalse();
        EvaluationNotes(mismatched).Should().Equal(
            "evaluation 0: its results were not recomputed: it names the engine cedar-policy@99.0.0, the verifier has cedar-policy@4.14.0.",
            "evaluation 0: its enforcement comparison was not recomputed: it names the engine cedar-policy@99.0.0, the verifier has cedar-policy@4.14.0.");

        // Even holding the named core: not_performed has nothing to reproduce, so it is not recomputed — and not a pass.
        var named = (await AgentRunVerifier.VerifyWithEngineAsync(bundle, StubVerify, other)).Evaluations.Single();
        (named.Valid, named.ResultsRecomputed, named.EnforcementRecomputed, named.EnforcementResult).Should().Be((true, true, false, (string?)null));
    }

    [Fact]
    public async Task ARuleLessControlSet_GivesAnEvaluationWithoutRulesOrCedarDigests()
    {
        var ruleLess = JsonNode.Parse(DocV13)!.AsObject();
        ruleLess.Remove("cedar");
        var doc = DocBytes(ruleLess);
        var (run, sealer, client) = await StartGuarded(doc);
        using var owned = client;
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("crm.read_customer", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>();
        var bundle = await run.FinishAsync();
        var enforcement = AgentPolicy.CompareEnforcement(run.ControlArtifact, bundle.Artifacts, doc, TestEngine.Shared);
        var evaluated = AgentPolicy.Evaluate(doc, AgentPolicy.BuildFactsV2(SupportAgent().AgentId, run.CorrelationId, bundle.Artifacts, doc).Bytes, TestEngine.Shared);
        (evaluated.Rules.Count, evaluated.Overall).Should().Be((0, "PASS"));
        var prepared = ControlEvaluation.PreparePolicy(new PolicyEvaluationRequest
        {
            CertificateId = VerifierCert, EvaluatorId = "e", EvaluatorVersion = "1", ControlArtifact = run.ControlArtifact, ControlSetDocument = doc,
            Events = bundle.Artifacts, Rules = evaluated.Rules, PolicyStatus = "unapproved", Engine = evaluated.Engine, Enforcement = enforcement,
            PrivateControlsReported = "pending",
        }, Clock());
        var policy = prepared.Envelope["policy"]!.AsObject();
        (policy.ContainsKey("cedarDigest"), policy["evaluator"]!.AsObject().ContainsKey("schemaSha256")).Should().Be((false, false));
        prepared.Envelope["controls"]!.AsArray().Should().BeEmpty();
        sealer.Cert = CertV;
        var sealedOne = await ControlEvaluation.SealAsync(client, prepared, VerifierCert);
        var verdict = (await AgentRunVerifier.VerifyWithEngineAsync(AgentRunBundle.Parse(bundle.WithEvaluations(sealedOne).WithPayloads(prepared.Payloads).ToJsonString()),
            StubVerify, TestEngine.Shared)).Evaluations.Single();
        verdict.Valid.Should().BeTrue(string.Join(" | ", verdict.Findings));
    }

    private static byte[] DocBytes(JsonObject doc) => Utf8(doc.ToJsonString());

    // The evaluations a verifier must reject (ControlEvaluation v3 §7), each sealed over the same recorded run.
    public static IEnumerable<object[]> WrongComparisons() => new (string Name, string Expect)[]
    {
        ("recorded-not-from-chain", "recorded outcome the chain does not give"),
        ("decisions-empty", "has a recorded outcome but no decision"),
        ("result-not-from-decisions", "result does not follow from the decisions"),
        ("performed-with-another-core", "performed with a core other than"),
        ("unavailable-with-the-evaluators-core", "engine_unavailable, but the recorded engine is the evaluator's"),
        ("findings-of-the-wrong-class", "do not fit its outcome"),
        ("chain-inconsistent-without-cause", "the prefix gives no reason chain_inconsistent"),
        ("recorded-engine-wrong", "recordedEngine is not the core"),
        ("as-required-claimed-for-a-missing-refusal", "is as_required, but what was due is not what the chain records"), // vector x02 needs the core
        ("as-required-where-due-is-not-recorded", "is as_required, but what was due is not what the chain records"),
        ("as-required-with-another-reason", "is as_required, but what was due is not what the chain records"),
        ("not-checkable-without-an-unavailable-record", "is not_checkable, but the chain records no unavailable core there"),
    }.Select(x => new object[] { x.Name, x.Expect });

    [Theory]
    [MemberData(nameof(WrongComparisons))]
    public async Task AWrongComparison_MakesTheEvaluationInvalid(string name, string expect)
    {
        var (bundle, _) = await EvaluatedEnforcedRun(env =>
        {
            var m = env["policy"]!["enforcement"]!.AsObject();
            var first = m["decisions"]!.AsArray()[0]!.AsObject();
            switch (name)
            {
                case "recorded-not-from-chain": first["recorded"] = "halted"; first["outcome"] = "over_enforced"; first["findings"] = new JsonArray("unfounded_halt"); m["result"] = "over_enforced"; break;
                case "decisions-empty": m["decisions"] = new JsonArray(); break;
                case "result-not-from-decisions": m["result"] = "let_through"; break;
                case "performed-with-another-core": env["policy"]!["evaluator"]!["engine"] = "cedar-policy@4.13.0"; break;
                case "unavailable-with-the-evaluators-core": m.Remove("decisions"); m.Remove("result"); m["comparison"] = "not_performed"; m["notPerformed"] = "engine_unavailable"; break;
                case "findings-of-the-wrong-class": first["outcome"] = "over_enforced"; first["findings"] = new JsonArray("halt_missing"); m["result"] = "over_enforced"; break;
                case "chain-inconsistent-without-cause": m.Remove("decisions"); m.Remove("result"); m["comparison"] = "not_performed"; m["notPerformed"] = "chain_inconsistent"; break;
                case "recorded-engine-wrong": m["recordedEngine"] = "cedar-policy@4.13.0"; break;
                case "as-required-claimed-for-a-missing-refusal": first["dueRules"] = new JsonArray("read-loop-limit"); break;
                case "as-required-where-due-is-not-recorded": first["due"] = "halted"; break;
                case "as-required-with-another-reason": first["dueReason"] = "unknown_tool"; first.Remove("dueRules"); break;
                case "not-checkable-without-an-unavailable-record": first["outcome"] = "not_checkable"; m["result"] = "not_checkable"; break;
            }
        });
        var result = await AgentRunVerifier.VerifyWithEngineAsync(bundle, StubVerify, TestEngine.Shared);
        var e = result.Evaluations.Single();
        e.Valid.Should().BeFalse();
        e.Findings.Should().Contain(f => f.Contains(expect, StringComparison.Ordinal), string.Join(" | ", e.Findings));
        e.EnforcementRecomputed.Should().BeFalse();
    }

    [Fact]
    public async Task PreparePolicy_HoldsTheVersionsApart()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, Options() with { ControlSet = AgentPolicy.ControlSetFromDocument(PolicyDoc) });
        var bundle = await run.FinishAsync();
        PolicyEvaluationRequest Request(byte[] doc, JsonObject? enforcement) => new()
        {
            CertificateId = VerifierCert, EvaluatorId = "e", EvaluatorVersion = "1", ControlArtifact = run.ControlArtifact, ControlSetDocument = doc,
            Events = bundle.Artifacts, Rules = Array.Empty<PolicyRuleResult>(), PolicyStatus = "unapproved", Engine = "cedar-policy@4.14.0",
            Enforcement = enforcement, PrivateControlsReported = "pending",
        };
        FluentActions.Invoking(() => ControlEvaluation.PreparePolicy(Request(PolicyDoc, new JsonObject { ["comparison"] = "performed" })))
            .Should().Throw<ArgumentException>().WithMessage("Enforcement belongs to a policy evaluation of a v2 control set*");

        var (v2run, _, c2) = await StartGuarded();
        using var owned = c2;
        var v2bundle = await v2run.FinishAsync();
        FluentActions.Invoking(() => ControlEvaluation.PreparePolicy(Request(DocV13, null) with { ControlArtifact = v2run.ControlArtifact, Events = v2bundle.Artifacts }))
            .Should().Throw<ArgumentException>().WithMessage("A policy evaluation of a v2 control set carries the enforcement comparison*");
        var rules = AgentPolicy.Evaluate(DocV13, AgentPolicy.BuildFactsV2(SupportAgent().AgentId, v2run.CorrelationId, v2bundle.Artifacts, DocV13).Bytes,
            TestEngine.Shared).Rules;
        FluentActions.Invoking(() => ControlEvaluation.PreparePolicy(Request(DocV13, new JsonObject { ["comparison"] = "performed", ["decisions"] = new JsonArray(), ["result"] = "let_through" })
                with { ControlArtifact = v2run.ControlArtifact, Events = v2bundle.Artifacts, Rules = rules }))
            .Should().Throw<ArgumentException>().WithMessage("*result does not follow from the decisions*");
    }

    [Fact]
    public async Task AV1ControlSet_StillGivesControlEvaluationV2()
    {
        var bundle = await EvaluatedRun(e => e.Rules);
        var env = bundle.Evaluations[0].Envelope;
        (env["schemaVersion"]!.GetValue<string>(), env["policy"]!["evaluator"]!["factsVersion"]!.GetValue<string>(), env["policy"]!.AsObject().ContainsKey("enforcement"))
            .Should().Be(("2", "1", false));
        (await VerifyWith(bundle, TestEngine.Shared)).Evaluations.Single().Valid.Should().BeTrue();
    }

    [Fact]
    public void TheCoreFreeChecks_OnChainsThatAreNotCompared()
    {
        static JsonObject Ev(int seq, string type, Action<JsonObject>? step = null)
        {
            var s = new JsonObject { ["type"] = type };
            step?.Invoke(s);
            return new JsonObject { ["schemaVersion"] = "4", ["chain"] = new JsonObject { ["seq"] = seq }, ["step"] = s };
        }
        var record = new Action<JsonObject>(s => { s["decision"] = "denied"; s["tool"] = new JsonObject { ["name"] = "search.web", ["useId"] = "c1" };
            s["rules"] = new JsonArray("no-web-search"); s["enforcer"] = new JsonObject { ["engine"] = "cedar-policy@4.14.0", ["factsVersion"] = "2", ["reason"] = "rule" }; });
        var tool = new Action<JsonObject>(s => s["tool"] = new JsonObject { ["name"] = "search.web", ["useId"] = "c1" });
        var executed = new List<JsonObject> { Ev(0, "run_start"), Ev(1, "tool_call", tool), Ev(2, "authorization", record), Ev(3, "tool_result", tool), Ev(4, "run_end") };
        var performed = JsonNode.Parse("""{"comparison":"performed","recordedEngine":"cedar-policy@4.14.0","decisions":[{"seq":1,"due":"refused","dueReason":"rule","dueRules":["no-web-search"],"recorded":"refused","outcome":"as_required"}],"result":"as_required"}""")!.AsObject();
        AgentRunVerifier.EnforcementMemberProblem(performed, "cedar-policy@4.14.0", executed).Should().Contain("chain_inconsistent");
        var notCompared = JsonNode.Parse("""{"comparison":"not_performed","notPerformed":"chain_inconsistent","recordedEngine":"cedar-policy@4.14.0"}""")!.AsObject();
        AgentRunVerifier.EnforcementMemberProblem(notCompared, "cedar-policy@4.14.0", executed).Should().BeNull();
        var consistent = executed.Take(3).Append(Ev(3, "run_end")).ToList();
        AgentRunVerifier.EnforcementMemberProblem(notCompared, "cedar-policy@4.14.0", consistent).Should().Contain("no reason chain_inconsistent");
        AgentRunVerifier.EnforcementMemberProblem(performed, "cedar-policy@4.14.0", consistent).Should().BeNull();
        var reversed = (JsonObject)performed.DeepClone();
        reversed["decisions"]!.AsArray().Add(JsonNode.Parse("""{"seq":0,"due":"none","recorded":"none","outcome":"as_required"}"""));
        AgentRunVerifier.EnforcementMemberProblem(reversed, "cedar-policy@4.14.0", consistent).Should().Contain("ascend");
    }

    /// <summary>What the released 0.15.0 prepared for this v1 policy evaluation (evidenceId, createdAt and the facts URI fixed).</summary>
    private const string V1EvaluationOf015 = """
{"schemaName":"ControlEvaluation","schemaVersion":"2","kind":"policy","evidenceId":"fixed","createdAt":"fixed","actor":{"type":"verifier","id":"urn:example:policy-evaluator","version":"1.0.0"},"activity":{"name":"pin","correlationId":"urn:uuid:00000000-0000-4000-8000-000000000016"},"subject":{"controlArtifactSignatureSha256":"0fcd568a5cb9bdb4677b69354b11ee415af8f784519cff3da49a26f84eaee7f2","throughSignatureSha256":"7f1ee17eb6d4b1815c8c0580dfb7ca0d3d5c3cde523da817ef7d3b1e96f6d5b8","runEndSignatureSha256":"7f1ee17eb6d4b1815c8c0580dfb7ca0d3d5c3cde523da817ef7d3b1e96f6d5b8"},"controlSet":{"id":"acme-support-agent-controls","version":"3"},"controls":[{"id":"allowed-tools","result":"PASS"},{"id":"consequential-needs-approval","result":"PASS"},{"id":"max-steps","result":"PASS"},{"id":"no-unpaired-consequential","result":"PASS"}],"overall":"PASS","evaluatedAt":"2026-11-02T10:30:00.000Z","objects":[{"uri":"objects/control-set","role":"control-set","contentType":"application/vnd.sigill.control-set\u002Bjson"},{"uri":"objects/facts","role":"evaluation-facts","contentType":"application/json","sizeBytes":1395}],"policy":{"approvalScopeDigest":"d80d93d858b7117a234a438b987dec90b33014bc9193a14daaf89e8b4ec9d343","cedarDigest":"bc1d126277a604e2f04d7b8a6b186b9eed4bc80feff3b569565521ad893a528c","policyStatus":"unapproved","evaluator":{"engine":"cedar-policy@4.14.0","factsVersion":"1","schemaSha256":"3bb5de5a78da26341ee26e240acb96015d20e4da303af32311520950ab1daf73"},"prefix":{"throughSeq":2,"finalSeq":2,"missingSeqs":[]},"state":"finalized","privateControlsReported":"pending"}}
""";

    [Fact]
    public void AV1PolicyEvaluation_IsByteForByteWhatTheLastReleasePrepared()
    {
        static JsonObject Jws(string tag) => new()
        {
            ["signatures"] = new JsonArray(new JsonObject
            {
                ["protected"] = "eyJhbGciOiJFUzI1NiJ9",
                ["signature"] = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(tag)).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            }),
        };
        var doc = PolicyDoc;
        var d = JsonNode.Parse(doc)!.AsObject();
        var control = new AgentRunArtifact(new JsonObject
        {
            ["schemaName"] = "AgentControlArtifact", ["agent"] = new JsonObject { ["id"] = "urn:example:agent:pin", ["version"] = "1" },
            ["activity"] = new JsonObject { ["name"] = "pin", ["correlationId"] = "urn:uuid:00000000-0000-4000-8000-000000000016" },
            ["controlSet"] = new JsonObject { ["id"] = d["id"]!.GetValue<string>(), ["version"] = d["version"]!.GetValue<string>() },
            ["objects"] = new JsonArray(new JsonObject { ["uri"] = "objects/control-set", ["role"] = "control-set", ["contentType"] = AgentPolicy.ControlSetContentType }),
        }, Jws("control"), new Dictionary<string, string> { ["objects/control-set"] = EnvelopeHashing.HashHex(doc) });
        AgentRunArtifact Ev(int seq, JsonObject step) => new(new JsonObject
        {
            ["schemaVersion"] = "1", ["chain"] = new JsonObject { ["seq"] = seq }, ["step"] = step,
            ["activity"] = new JsonObject { ["correlationId"] = "urn:uuid:00000000-0000-4000-8000-000000000016" }, ["objects"] = new JsonArray(),
        }, Jws($"event {seq}"), new Dictionary<string, string>());
        var events = new[]
        {
            Ev(0, new JsonObject { ["type"] = "run_start" }),
            Ev(1, new JsonObject { ["type"] = "tool_call", ["consequential"] = true, ["tool"] = new JsonObject { ["name"] = "crm.delete_customer", ["operation"] = "delete" } }),
            Ev(2, new JsonObject { ["type"] = "run_end", ["finalSeq"] = 2, ["runDisposition"] = "completed" }),
        };
        var rules = d["cedar"]!["policies"]!["staticPolicies"]!.AsObject().Select(kv => new PolicyRuleResult(kv.Key, "PASS")).ToList();
        var prepared = ControlEvaluation.PreparePolicy(new PolicyEvaluationRequest
        {
            CertificateId = Guid.Parse("66666666-7777-8888-9999-000000000000"), EvaluatorId = "urn:example:policy-evaluator", EvaluatorVersion = "1.0.0",
            ControlArtifact = control, ControlSetDocument = doc, Events = events, Rules = rules, PolicyStatus = "unapproved",
            Engine = "cedar-policy@4.14.0", PrivateControlsReported = "pending", EvaluatedAt = new DateTimeOffset(2026, 11, 2, 10, 30, 0, TimeSpan.Zero),
        });
        var envelope = (JsonObject)prepared.Envelope.DeepClone();
        envelope["evidenceId"] = "fixed";
        envelope["createdAt"] = "fixed";
        foreach (var o in envelope["objects"]!.AsArray().OfType<JsonObject>().Where(o => o["role"]!.GetValue<string>() == "evaluation-facts")) o["uri"] = "objects/facts";
        envelope.ToJsonString().Should().Be(V1EvaluationOf015);
        string.Join(",", prepared.ObjectDigests.Values.OrderBy(x => x, StringComparer.Ordinal))
            .Should().Be("bf91bb753529de5265075880291b5804b1da549b7804b8685b70ad99a4e441d1,f6a431203e596786a2d422a60eaf04b7a3cbda1f8d55bd5dedea02ff4bdefd9c", "the control set and the facts v1 bytes are unchanged");
    }
}
