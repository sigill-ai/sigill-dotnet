// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// Vector 15 (spec/test-vectors/15-policy-enforcement-evaluation): the enforcement comparison of ControlEvaluation v3 over
// vector 14's guard runs and the runs in which the guard did less, or more, than required; the v3 schema; and the
// evaluations a verifier must reject.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    private static string Dir15 => Path.Combine(SpecRoot.TestVectorsDir, "15-policy-enforcement-evaluation");
    private static JsonObject Load15(string rel) => JsonNode.Parse(File.ReadAllText(Path.Combine(Dir15, rel)))!.AsObject();

    public static IEnumerable<object[]> Vector15Cases() =>
        Directory.GetFiles(Path.Combine(Dir15, "expected"), "*.json").Where(p => !p.EndsWith(".facts.json", StringComparison.Ordinal))
            .Select(Path.GetFileNameWithoutExtension).OrderBy(n => n, StringComparer.Ordinal).Select(n => new object[] { n! });

    /// <summary>The run of a case: vector 14's for "14-…", else vector 15's.</summary>
    private static JsonObject Run15(string name) =>
        name.StartsWith("14-", StringComparison.Ordinal) ? LoadV14($"runs/{name[3..]}.json") : Load15($"runs/{name}.json");

    /// <summary>The run's control set: vector 13's with the run's enforcement, or the variant the run names.</summary>
    private static byte[] ControlSet15(JsonObject run) => AgentProfiles.Str(run["controlSet"]) is { } v and not "13"
        ? File.ReadAllBytes(Path.Combine(Dir15, $"control-set-{v}.json"))
        : PolicyEnforcementVectorTests.ControlSetOf(run);

    private static AgentRunArtifact Control15(JsonObject run, byte[] controlSet)
    {
        var objects = new JsonArray();
        var digests = new Dictionary<string, string>();
        void Add(string role, string hex, string type)
        {
            var uri = $"objects/control-{role}";
            objects.Add(new JsonObject { ["uri"] = uri, ["role"] = role, ["contentType"] = type });
            digests[uri] = hex;
        }
        foreach (var (role, hex) in run["configuration"]!.AsObject()) Add(role, hex!.GetValue<string>(), "application/json");
        Add("control-set", EnvelopeHashing.HashHex(controlSet), AgentPolicy.ControlSetContentType);
        return new AgentRunArtifact(new JsonObject
        {
            ["schemaName"] = "AgentControlArtifact", ["agent"] = new JsonObject { ["id"] = run["agentId"]!.DeepClone() }, ["objects"] = objects,
        }, new JsonObject(), digests);
    }

    private static List<AgentRunArtifact> Events15(JsonObject run) => run["events"]!.AsArray().Select(e => new AgentRunArtifact(
        e!["envelope"]!.DeepClone().AsObject(), new JsonObject(),
        e["objectDigests"]!.AsObject().ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>()))).ToList();

    [Fact]
    public void Vector15_IsComplete()
    {
        Vector15Cases().Should().HaveCount(95);
        Directory.GetFiles(Path.Combine(Dir15, "invalid-evaluations"), "*.json").Should().HaveCount(12);
    }

    [Theory]
    [MemberData(nameof(Vector15Cases))]
    public void Vector15_FactsResultsFindingsAndComparison_AreTheVectors(string name)
    {
        var run = Run15(name);
        var expected = Load15($"expected/{name}.json");
        var doc = ControlSet15(run);
        var digests = AgentPolicy.ComputeDigests(doc);
        digests.ApprovalScopeDigest.Should().Be(expected["approvalScopeDigest"]!.GetValue<string>());
        digests.CedarDigest.Should().Be(expected["cedarDigest"]?.GetValue<string>());

        var events = Events15(run);
        var through = expected["prefix"]!["throughSeq"]!.GetValue<int>();
        var missing = expected["prefix"]!["missingSeqs"]!.AsArray().Select(m => m!.GetValue<int>()).ToList();
        var prefix = events.Where(e => e.Seq <= through).OrderBy(e => e.Seq).ToList();

        // Facts v2 of the evaluated prefix, byte for byte (vector 14's own facts for its runs).
        var facts = AgentPolicy.BuildFactsV2(run["agentId"]!.GetValue<string>(), run["correlationId"]!.GetValue<string>(), prefix, doc, missing);
        var factsFile = name.StartsWith("14-", StringComparison.Ordinal)
            ? Path.Combine(SpecRoot.TestVectorsDir, "14-policy-enforcement", "expected", name[3..] + ".facts.json")
            : Path.Combine(Dir15, "expected", name + ".facts.json");
        facts.Bytes.Should().Equal(File.ReadAllBytes(factsFile));
        facts.Sha256.Should().Be(expected["factsSha256"]!.GetValue<string>());

        // Per-rule results and overall, with the official core.
        var evaluated = AgentPolicy.Evaluate(doc, facts.Bytes, TestEngine.Shared);
        evaluated.Engine.Should().Be(expected["evaluatorEngine"]!.GetValue<string>());
        // The ids are a set (ControlEvaluation v2 §3); the vector lists them sorted.
        var controls = new JsonArray(evaluated.Rules.OrderBy(r => r.Id, StringComparer.Ordinal).Select(r =>
        {
            var j = new JsonObject { ["id"] = r.Id, ["result"] = r.Result };
            if (r.Where is { Count: > 0 } w) j["where"] = new JsonArray(w.Select(x => (JsonNode?)x).ToArray());
            return (JsonNode?)j;
        }).ToArray());
        Jcs(controls).Should().Be(Jcs(expected["controls"]!));
        evaluated.Overall.Should().Be(expected["overall"]!.GetValue<string>());

        // Agent Enforcement v1 §5 findings of the prefix; the evaluator holds the control set.
        var found = AgentRunVerifier.EnforcementFindings(prefix.Select(e => e.Envelope).ToList(), AgentPolicy.ControlSetContentType, doc)
            .Select(f => $"{f.Code}:{string.Join(",", f.Seqs)}");
        found.Should().Equal(expected["enforcementFindings"]!.AsArray()
            .Select(f => $"{f!["code"]!.GetValue<string>()}:{string.Join(",", f["seqs"]!.AsArray().Select(x => x!.GetValue<int>()))}"));

        // The enforcement member, byte for byte, from the events in any order.
        var member = AgentPolicy.CompareEnforcement(Control15(run, doc), events.AsEnumerable().Reverse(), doc, TestEngine.Shared);
        Jcs(member).Should().Be(Jcs(expected["enforcement"]!));
    }

    [Fact]
    public void Vector15_Envelopes_AreAcceptedAndRejectedByTheV3Schema()
    {
        var v = Load15("envelopes.json");
        v["valid"]!.AsArray().Should().HaveCount(11);
        v["invalid"]!.AsArray().Should().HaveCount(24);
        foreach (var c in v["valid"]!.AsArray())
            EnvelopeSchema.Validate(c!["envelope"]!.AsObject(), AgentProfiles.ControlEvaluationSchemaV3).Should().BeEmpty(c["name"]!.GetValue<string>());
        foreach (var c in v["invalid"]!.AsArray())
            EnvelopeSchema.Validate(c!["envelope"]!.AsObject(), AgentProfiles.ControlEvaluationSchemaV3).Should().NotBeEmpty(c["name"]!.GetValue<string>());
    }

    /// <summary>RFC 6902 add / replace / remove on a JSON document (the subset the vector uses).</summary>
    private static void Patch(JsonObject document, JsonArray operations)
    {
        foreach (var op in operations.Select(o => o!.AsObject()))
        {
            var path = op["path"]!.GetValue<string>().Split('/').Skip(1).Select(t => t.Replace("~1", "/").Replace("~0", "~")).ToList();
            JsonNode parent = document;
            foreach (var token in path.Take(path.Count - 1))
                parent = parent is JsonArray a ? a[int.Parse(token, System.Globalization.CultureInfo.InvariantCulture)]! : parent[token]!;
            var last = path[^1];
            var kind = op["op"]!.GetValue<string>();
            if (parent is JsonArray array)
            {
                var index = last == "-" ? array.Count : int.Parse(last, System.Globalization.CultureInfo.InvariantCulture);
                switch (kind)
                {
                    case "add": array.Insert(index, op["value"]!.DeepClone()); break;
                    case "replace": array[index] = op["value"]!.DeepClone(); break;
                    case "remove": array.RemoveAt(index); break;
                    default: throw new NotSupportedException(kind);
                }
            }
            else
            {
                var obj = parent.AsObject();
                switch (kind)
                {
                    case "add": case "replace":
                        if (kind == "replace" && !obj.ContainsKey(last)) throw new InvalidOperationException($"replace of a missing member {last}");
                        obj[last] = op["value"]!.DeepClone(); break;
                    case "remove":
                        if (!obj.Remove(last)) throw new InvalidOperationException($"remove of a missing member {last}");
                        break;
                    default: throw new NotSupportedException(kind);
                }
            }
        }
    }

    /// <summary>The run of a case as a stub-signed bundle, with the honest v3 policy evaluation of it, optionally patched before sealing.</summary>
    private async Task<AgentRunBundle> EvaluatedVectorRun(string name, JsonArray? patch)
    {
        var run = Run15(name);
        var doc = ControlSet15(run);
        var bundle = SignedVectorBundle(run, (PolicyCt, doc));
        var control = bundle.ControlArtifact!;
        var enforcement = AgentPolicy.CompareEnforcement(control, bundle.Artifacts, doc, TestEngine.Shared);
        var facts = AgentPolicy.BuildFactsV2(run["agentId"]!.GetValue<string>(), run["correlationId"]!.GetValue<string>(), bundle.Artifacts, doc);
        var evaluated = AgentPolicy.Evaluate(doc, facts.Bytes, TestEngine.Shared);
        var declaresPrivate = JsonNode.Parse(doc)!["privateControls"] is JsonArray pc && pc.Count > 0;
        var prepared = ControlEvaluation.PreparePolicy(new PolicyEvaluationRequest
        {
            CertificateId = VerifierCert, EvaluatorId = "urn:example:policy-evaluator", EvaluatorVersion = "1.0.0",
            ControlArtifact = control, ControlSetDocument = doc, Events = bundle.Artifacts, Rules = evaluated.Rules,
            PolicyStatus = "unapproved", Engine = evaluated.Engine, Enforcement = enforcement, PrivateControlsReported = declaresPrivate ? "pending" : null,
        }, Clock());
        if (patch is not null)
        {
            var changed = (JsonObject)prepared.Envelope.DeepClone();
            Patch(changed, patch);
            prepared = prepared with { Envelope = changed, EnvelopeHashHex = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(changed)) };
        }
        using var client = Client(new StubSealer { Cert = CertV, GenTime = () => "2026-11-02T12:00:00Z" });
        var evaluation = await ControlEvaluation.SealAsync(client, prepared, VerifierCert);
        return AgentRunBundle.Parse(bundle.WithEvaluations(evaluation).WithPayloads(bundle.Payloads.Concat(prepared.Payloads)
            .GroupBy(kv => kv.Key).ToDictionary(g => g.Key, g => g.First().Value)).ToJsonString());
    }

    public static IEnumerable<object[]> InvalidEvaluations() =>
        Directory.GetFiles(Path.Combine(Dir15, "invalid-evaluations"), "*.json").Select(Path.GetFileNameWithoutExtension)
            .OrderBy(n => n, StringComparer.Ordinal).Select(n => new object[] { n! });

    // What this verifier says for each `because` of the vector.
    private static readonly Dictionary<string, string> RejectedWith = new(StringComparer.Ordinal)
    {
        ["x01-recorded-not-from-chain"] = "recorded outcome the chain does not give",
        ["x02-comparison-does-not-recompute"] = "its enforcement comparison does not recompute",
        ["x03-result-not-from-decisions"] = "result does not follow from the decisions",
        ["x04-performed-with-another-core"] = "performed with a core other than the one the enforcement records name",
        ["x05-engine-unavailable-with-the-same-core"] = "engine_unavailable, but the recorded engine is the evaluator's",
        ["x06-decisions-not-ascending"] = "decisions do not ascend by seq",
        ["x07-finding-of-the-wrong-class"] = "do not fit its outcome over_enforced",
        ["x08-no-finding-of-the-outcomes-class"] = "do not fit its outcome let_through",
        ["x09-inconsistent-chain-compared"] = "not performed on this prefix (chain_inconsistent)",
        ["x10-chain-inconsistent-claimed"] = "the prefix gives no reason chain_inconsistent",
        ["x11-cedar-digest-without-cedar"] = "approvalScopeDigest or cedarDigest does not recompute",
        ["x11-controls-empty-with-rules"] = "is not reported",
    };

    [Theory]
    [MemberData(nameof(InvalidEvaluations))]
    public async Task Vector15_AVerifierRejectsTheEvaluation_AndTheHonestOneVerifies(string name)
    {
        var x = Load15($"invalid-evaluations/{name}.json");
        var runName = x["run"]!.GetValue<string>();

        var honest = (await AgentRunVerifier.VerifyWithEngineAsync(await EvaluatedVectorRun(runName, null), StubVerify, TestEngine.Shared)).Evaluations.Single();
        honest.Valid.Should().BeTrue(string.Join(" | ", honest.Findings));
        honest.EnforcementRecomputed.Should().BeTrue();

        var patched = await EvaluatedVectorRun(runName, x["patch"]!.AsArray());
        var withEngine = (await AgentRunVerifier.VerifyWithEngineAsync(patched, StubVerify, TestEngine.Shared)).Evaluations.Single();
        withEngine.Valid.Should().BeFalse();
        withEngine.Findings.Should().Contain(f => f.Contains(RejectedWith[name], StringComparison.Ordinal), string.Join(" | ", withEngine.Findings));
        if (x["needsEngine"]!.GetValue<bool>()) return;
        var blind = (await AgentRunVerifier.VerifyAsync(patched, StubVerify)).Evaluations.Single();
        blind.Valid.Should().BeFalse("the rule needs no core");
        blind.Findings.Should().Contain(f => f.Contains(RejectedWith[name], StringComparison.Ordinal), string.Join(" | ", blind.Findings));
    }
}
