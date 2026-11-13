// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// The Cedar engine (Sigill.Sdk.Policy): the pinned module, strict validation, evaluation against vectors 12 and 14, and
// offline recomputation of a policy evaluation by the run verifier. No guard: nothing here decides before a tool call.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using FluentAssertions;
using Sigill.Sdk.Policy;
using Xunit;
using Xunit.Abstractions;

namespace Sigill.Sdk.Tests;

internal static class TestEngine
{
    /// <summary>One engine for the suite: compiling the module once is the expensive part.</summary>
    public static CedarEngine Shared { get; } = new();

    public static byte[] Module()
    {
        using var stream = typeof(CedarEngine).Assembly.GetManifestResourceStream("Sigill.Sdk.Policy.sigill_cedar.wasm")!;
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    public static byte[] Bytes(JsonNode node) => Encoding.UTF8.GetBytes(node.ToJsonString());
}

public class CedarEngineTests(ITestOutputHelper output)
{
    private static string Dir12 => Path.Combine(SpecRoot.TestVectorsDir, "12-policy-evaluation");
    private static byte[] Doc11 => File.ReadAllBytes(Path.Combine(SpecRoot.TestVectorsDir, "11-policy-control-set", "control-set.json"));

    /// <summary>An authorize call of vector 12's rules for one request of its facts.</summary>
    private static JsonObject Call(string run, int index)
    {
        var request = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir12, "expected", run + ".facts.json")))!["requests"]![index]!.AsObject();
        request.Remove("seq");
        request["schema"] = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "spec", "agent-policy-cedar-schema-v1.json")));
        request["validateRequest"] = true;
        request["policies"] = JsonNode.Parse(Doc11)!["cedar"]!["policies"]!.DeepClone();
        request["entities"] = new JsonArray();
        return request;
    }

    [Fact]
    public void TheEmbeddedModule_IsThePinnedFile()
    {
        EnvelopeHashing.HashHex(TestEngine.Module()).Should().Be("a0cd395067e77a157116f6b25bcdb612d34c61d1a4446918d75da1a07c80d1f3")
            .And.Be(CedarEngine.ModuleSha256);
        TestEngine.Module().Length.Should().Be(3_855_655);
    }

    [Fact]
    public void ATamperedModule_IsRefused()
    {
        var tampered = TestEngine.Module();
        tampered[tampered.Length / 2] ^= 0x01;
        using var engine = new CedarEngine(tampered, CedarEngine.MemoryLimitBytes);
        FluentActions.Invoking(() => engine.Version).Should().Throw<PolicyEngineException>()
            .WithMessage("The policy engine module is not the bundled sigill_cedar.wasm (its SHA-256 differs); it is not run.");
        FluentActions.Invoking(() => engine.Authorize(Call("01-clean", 0))).Should().Throw<PolicyEngineException>();
    }

    [Fact]
    public void Version_IsThePinnedCedarCore()
    {
        TestEngine.Shared.Version.Should().Be("4.14.0").And.Be(CedarEngine.CoreVersion);
    }

    [Fact]
    public void ARequestTheEngineRejects_IsAnAnswer_NotAnException()
    {
        var call = Call("01-clean", 1);
        call["resource"] = new JsonObject { ["type"] = "Step", ["id"] = "1" }; // tool_call applies to Tool only
        var answer = TestEngine.Shared.Authorize(call);
        answer["type"]!.GetValue<string>().Should().Be("failure");
        TestEngine.Shared.Authorize(Call("01-clean", 1))["type"]!.GetValue<string>().Should().Be("success");
    }

    [Fact]
    public async Task ConcurrentUse_GivesTheSameAnswers()
    {
        var calls = Enumerable.Range(0, 8).Select(i => Call("02-rogue", i)).ToList();
        var expected = calls.Select(c => TestEngine.Shared.Authorize(c).ToJsonString()).ToList();
        var answers = await Task.WhenAll(Enumerable.Range(0, 32).Select(t => Task.Run(() =>
            Enumerable.Range(0, 20).Select(i => (Index: (t + i) % calls.Count,
                Answer: TestEngine.Shared.Authorize((JsonObject)calls[(t + i) % calls.Count].DeepClone()).ToJsonString())).ToList())));
        foreach (var (index, answer) in answers.SelectMany(a => a)) answer.Should().Be(expected[index]);
        expected[3].Should().Contain("allowed-tools", "seq 3 of the rogue run calls a forbidden tool");
    }

    [Fact]
    public void MemoryCap_TrapsAsPolicyEngineException_AndTheEngineRecovers()
    {
        CedarEngine.MemoryLimitBytes.Should().Be(256L * 1024 * 1024);
        // The same mechanism at a smaller cap, so the test does not need gigabytes: an input larger than the cap.
        using var engine = new CedarEngine(TestEngine.Module(), 32L * 1024 * 1024);
        var huge = Call("01-clean", 0);
        huge["context"]!["operation"] = new string('x', 40 * 1024 * 1024);
        FluentActions.Invoking(() => engine.Authorize(huge)).Should().Throw<PolicyEngineException>();
        engine.Authorize(Call("01-clean", 0))["type"]!.GetValue<string>().Should().Be("success", "a new instance replaces the trapped one");
    }

    [Fact]
    public void AnEvaluationOf2000Requests_IsTimed()
    {
        var facts = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir12, "expected", "02-rogue.facts.json")))!.AsObject();
        var template = facts["requests"]!.AsArray().Where(r => r!["seq"]!.GetValueKind() == System.Text.Json.JsonValueKind.Number).ToList();
        var requests = new JsonArray();
        for (var i = 0; i < 2000; i++)
        {
            var r = template[i % template.Count]!.DeepClone();
            r["seq"] = i;
            requests.Add(r);
        }
        facts["requests"] = requests;
        TestEngine.Shared.Version.Should().NotBeEmpty(); // loaded outside the timing
        var watch = Stopwatch.StartNew();
        var result = AgentPolicy.Evaluate(Doc11, TestEngine.Bytes(facts), TestEngine.Shared);
        watch.Stop();
        output.WriteLine($"2000 requests evaluated in {watch.ElapsedMilliseconds} ms");
        result.Requests.Should().HaveCount(2000);
        result.Overall.Should().Be("FAIL");
    }
}

public class PolicyEngineVectorTests
{
    private static string Dir12 => Path.Combine(SpecRoot.TestVectorsDir, "12-policy-evaluation");
    private static string Dir14 => Path.Combine(SpecRoot.TestVectorsDir, "14-policy-enforcement");
    private static byte[] Doc11 => File.ReadAllBytes(Path.Combine(SpecRoot.TestVectorsDir, "11-policy-control-set", "control-set.json"));
    private static byte[] Doc13 => PolicyControlSetV2VectorTests.Doc;

    public static IEnumerable<object[]> Runs12() =>
        Directory.GetFiles(Path.Combine(Dir12, "runs"), "*.json").Select(p => new object[] { Path.GetFileNameWithoutExtension(p) });

    public static IEnumerable<object[]> Cases14() =>
        Directory.GetFiles(Path.Combine(Dir14, "runs"), "*.json").Select(p => new object[] { Path.GetFileNameWithoutExtension(p) });

    private static IEnumerable<string> Strings(JsonNode? array) => array!.AsArray().Select(x => x!.GetValue<string>());

    [Theory]
    [MemberData(nameof(Runs12))]
    public void Evaluate_GivesVector12sResults(string run)
    {
        var facts = File.ReadAllBytes(Path.Combine(Dir12, "expected", run + ".facts.json"));
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir12, "expected", run + ".results.json")))!;
        var result = AgentPolicy.Evaluate(Doc11, facts, TestEngine.Shared);

        result.Engine.Should().Be(expected["engine"]!.GetValue<string>());
        result.Overall.Should().Be(expected["overall"]!.GetValue<string>());
        result.Rules.Select(r => r.Id).Should().Equal(expected["controls"]!.AsArray().Select(c => c!["id"]!.GetValue<string>()));
        foreach (var (rule, want) in result.Rules.Zip(expected["controls"]!.AsArray()))
        {
            rule.Result.Should().Be(want!["result"]!.GetValue<string>(), rule.Id);
            if (want["where"] is null) rule.Where.Should().BeNull(rule.Id);
            else rule.Where.Should().Equal(Strings(want["where"]), rule.Id);
        }
    }

    [Theory]
    [MemberData(nameof(Cases14))]
    public void Evaluate_GivesVector14sDiagnostics_PerEvent(string name)
    {
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir14, "expected", name + ".json")))!;
        var facts = File.ReadAllBytes(Path.Combine(Dir14, "expected", name + ".facts.json"));
        // The case's control set differs from vector 13's in enforcement only, which no result depends on.
        var result = AgentPolicy.Evaluate(Doc13, facts, TestEngine.Shared);

        var want = expected["events"]!.AsArray().Select(e => (Seq: e!["seq"]!.GetValue<int>().ToString(System.Globalization.CultureInfo.InvariantCulture), D: e["diagnostics"]!))
            .Append((Seq: "run", D: expected["runLevel"]!["diagnostics"]!)).ToList();
        result.Requests.Select(r => r.Seq).Should().Equal(want.Select(w => w.Seq));
        foreach (var (got, (seq, d)) in result.Requests.Zip(want))
        {
            got.Reason.Should().Equal(Strings(d["reason"]), $"reason at {seq}");
            got.Errors.Should().Equal(Strings(d["errors"]), $"errors at {seq}");
        }
        // The per-rule results follow (the vector lists them by sorted id).
        result.Overall.Should().Be(expected["overall"]!.GetValue<string>());
        result.Rules.OrderBy(r => r.Id, StringComparer.Ordinal).Select(r => $"{r.Result}@{string.Join(",", r.Where ?? Array.Empty<string>())}")
            .Should().Equal(expected["controls"]!.AsArray().Select(c => $"{c!["result"]}@{string.Join(",", c["where"] is { } w ? Strings(w) : Array.Empty<string>())}"));
    }

    [Fact]
    public void RuleErrors_AreIntegerOverflowErrors_NotTraps()
    {
        var facts = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir14, "expected", "10-rule-error.facts.json")))!;
        var request = facts["requests"]!.AsArray().First(r => r!["seq"]!.GetValueKind() == System.Text.Json.JsonValueKind.Number
            && r["action"]!["id"]!.GetValue<string>() == "tool_call")!.AsObject().DeepClone().AsObject();
        request.Remove("seq");
        request["schema"] = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "spec", "agent-policy-cedar-schema-v2.json")));
        request["validateRequest"] = true;
        request["policies"] = JsonNode.Parse(Doc13)!["cedar"]!["policies"]!.DeepClone();
        request["entities"] = facts["entities"]!.DeepClone();
        var errors = TestEngine.Shared.Authorize(request)["response"]!["diagnostics"]!["errors"]!.AsArray();
        errors.Select(e => e!["policyId"]!.GetValue<string>()).Should().Equal("export-weight");
        errors[0]!["error"]!["message"]!.GetValue<string>().Should().StartWith("integer overflow");
    }

    [Fact]
    public void Evaluate_RefusesFactsOfTheOtherVersion()
    {
        var v1Facts = File.ReadAllBytes(Path.Combine(Dir12, "expected", "01-clean.facts.json"));
        FluentActions.Invoking(() => AgentPolicy.Evaluate(Doc13, v1Facts, TestEngine.Shared)).Should().Throw<ArgumentException>().WithMessage("The facts are not a factsVersion 2 document (a v2 control set).*");
        FluentActions.Invoking(() => AgentPolicy.Evaluate(Doc11, Encoding.UTF8.GetBytes("[]"), TestEngine.Shared)).Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Evaluate_ARequestTheEngineRefuses_FailsTheEvaluation()
    {
        var facts = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir12, "expected", "01-clean.facts.json")))!;
        facts["requests"]![1]!["resource"] = new JsonObject { ["type"] = "Step", ["id"] = "1" }; // not a Tool
        FluentActions.Invoking(() => AgentPolicy.Evaluate(Doc11, TestEngine.Bytes(facts), TestEngine.Shared))
            .Should().Throw<PolicyEngineException>().WithMessage("The policy engine refused request 1: *");
    }

    // ── strict validation: the same cases in both ports

    private static byte[] Mutate(byte[] doc, Action<JsonObject> change)
    {
        var d = JsonNode.Parse(doc)!.AsObject();
        change(d);
        return TestEngine.Bytes(d);
    }

    private static JsonObject Rules(JsonObject d) => d["cedar"]!["policies"]!["staticPolicies"]!.AsObject();

    private static JsonNode ApprovalGreaterThan(int n) =>
        JsonNode.Parse("""[{"kind":"when","body":{">":{"left":{".":{"left":{"Var":"context"},"attr":"approval"}},"right":{"Value":""" + n + "}}}}]")!;

    [Fact]
    public void ValidateStrict_AcceptsVector11_AgainstSchemaV1_AndVector13_AgainstSchemaV2()
    {
        AgentPolicy.ValidateStrict(Doc11, TestEngine.Shared).Should().BeEmpty();
        AgentPolicy.ValidateStrict(Doc13, TestEngine.Shared).Should().BeEmpty();
    }

    private static string NotStrict(string schema, string id, string message) =>
        $"policy '{id}' does not validate against Cedar schema {schema} in strict mode: for policy `{id}`, {message}";

    /// <summary>(name, document, whether Validate alone finds a problem, the exact problems ValidateStrict adds).</summary>
    public static IEnumerable<object[]> StrictCases() => new[]
    {
        new object[] { "a-v1-type-error-in-condition", Mutate(Doc11, d => Rules(d)["max-steps"]!["conditions"] = ApprovalGreaterThan(20)), false,
            new[] { NotStrict("v1", "max-steps", "unexpected type: expected Long but saw String") } },
        new object[] { "b-v2-type-error-in-condition", Mutate(Doc13, d => Rules(d)["no-web-search"]!["conditions"] = ApprovalGreaterThan(3)), false,
            new[] { NotStrict("v2", "no-web-search", "unexpected type: expected Long but saw String") } },
        new object[] { "c-v2-entity-violates-schema", Mutate(Doc13, d => d["cedar"]!["entities"]![2]!["attrs"]!["consequential"] = "yes"), true,
            new[] { "cedar.entities do not conform to Cedar schema v2: entity does not conform to the schema: in attribute `consequential` on "
                + "`Tool::\"crm.read_customer\"`, type mismatch: value was expected to have type bool, but it actually has type string: `\"yes\"`" } },
        new object[] { "d-v1-schema-digest-of-schema-v2", Mutate(Doc11, d => d["cedar"]!["schemaSha256"] = AgentPolicy.CedarSchemaV2Sha256), false,
            new[] { "cedar.schemaSha256 must be the SHA-256 of JCS(agent-policy-cedar-schema-v1.json)" } },
        new object[] { "e-v2-rules-in-a-v1-document", Mutate(Doc11, d => d["cedar"]!["policies"] = JsonNode.Parse(Doc13)!["cedar"]!["policies"]!.DeepClone()), false,
            new[]
            {
                NotStrict("v1", "export-weight", "attribute `toolCallsSoFar` in context for Action::\"tool_call\" not found"),
                NotStrict("v1", "halt-refund-loop", "attribute `callsOfThisTool` in context for Action::\"tool_call\" not found"),
                NotStrict("v1", "halt-retrieval-after-denial", "attribute `denialsSoFar` in context for Action::\"retrieval\" not found"),
                NotStrict("v1", "no-web-search", "unrecognized entity type `AgentGroup`"),
                NotStrict("v1", "preview-weight", "attribute `toolCallsSoFar` in context for Action::\"tool_call\" not found"),
                NotStrict("v1", "read-loop-limit", "attribute `callsOfThisTool` in context for Action::\"tool_call\" not found"),
                NotStrict("v1", "restricted-needs-bound-approval", "unrecognized entity type `ToolGroup`"),
                NotStrict("v1", "shadow-repeat-read", "attribute `callsOfThisTool` in context for Action::\"tool_call\" not found"),
            } },
        // Only warnings in the core (no applicable action; an impossible policy): strict validation fails on errors only.
        new object[] { "f-v1-warnings-only-rule-passes", Mutate(Doc11, d => Rules(d)["call-on-step"] = JsonNode.Parse(
            """{"effect":"forbid","principal":{"op":"All"},"action":{"op":"==","entity":{"type":"Action","id":"tool_call"}},"resource":{"op":"==","entity":{"type":"Step","id":"0"}},"conditions":[],"annotations":{"id":"call-on-step"}}""")),
            false, Array.Empty<string>() },
        // run_start applies only to Step resources, which have no attribute consequential (Tool has).
        new object[] { "g-v2-attribute-the-actions-resource-type-lacks", Mutate(Doc13, d =>
            {
                var rule = Rules(d)["no-web-search"]!;
                rule["action"] = JsonNode.Parse("""{"op":"==","entity":{"type":"Action","id":"run_start"}}""");
                rule["resource"] = JsonNode.Parse("""{"op":"All"}""");
                rule["conditions"] = JsonNode.Parse("""[{"kind":"when","body":{".":{"left":{"Var":"resource"},"attr":"consequential"}}}]""");
            }), false,
            new[] { NotStrict("v2", "no-web-search", "attribute `consequential` on entity type `Step` not found") } },
    };

    [Theory]
    [MemberData(nameof(StrictCases))]
    public void ValidateStrict_AddsExactlyTheCoresProblems(string name, byte[] document, bool structural, string[] added)
    {
        var plain = AgentPolicy.Validate(document);
        (plain.Count > 0).Should().Be(structural, name);
        AgentPolicy.ValidateStrict(document, TestEngine.Shared).Should().Equal(plain.Concat(added), name);
    }
}

/// <summary>Regression tests from the security review: the number corpus, the module's imports and stable strict validation.</summary>
public class PolicyEngineSecurityTests
{
    private static byte[] Doc11 => File.ReadAllBytes(Path.Combine(SpecRoot.TestVectorsDir, "11-policy-control-set", "control-set.json"));
    private static string Dir12 => Path.Combine(SpecRoot.TestVectorsDir, "12-policy-evaluation");

    private static string Rule(string id, string condition) =>
        "{\"effect\":\"forbid\",\"principal\":{\"op\":\"All\"},\"action\":{\"op\":\"All\"},\"resource\":{\"op\":\"All\"},"
        + "\"conditions\":[{\"kind\":\"when\",\"body\":" + condition + "}],\"annotations\":{\"id\":\"" + id + "\"}}";

    private static byte[] Doc(Func<string, string> change)
    {
        var text = Encoding.UTF8.GetString(Doc11);
        var changed = change(text);
        changed.Should().NotBe(text);
        return Encoding.UTF8.GetBytes(changed);
    }

    private static byte[] Number(string literal) => Doc(t => ReplaceFirst(t, "\"Value\": 20", "\"Value\": " + literal));

    private static byte[] WithRule(string id, string condition) =>
        Doc(t => ReplaceFirst(t, "\"staticPolicies\": {", "\"staticPolicies\": {\"" + id + "\": " + Rule(id, condition) + ","));

    private static string ReplaceFirst(string text, string old, string replacement)
    {
        var at = text.IndexOf(old, StringComparison.Ordinal);
        return at < 0 ? text : text.Substring(0, at) + replacement + text.Substring(at + old.Length);
    }

    private const string Operation = """{".":{"left":{"Var":"context"},"attr":"operation"}}""";

    /// <summary>The reviewer's corpus: vector 11 with number and string variants (the same texts in both ports).</summary>
    private static Dictionary<string, byte[]> Docs() => new()
    {
        ["v11"] = Doc11,
        ["num_neg0"] = Number("-0"),
        ["num_20.0"] = Number("20.0"),
        ["num_2e1"] = Number("2e1"),
        ["num_max_safe"] = Number("9007199254740991"),
        ["num_min_safe"] = Number("-9007199254740991"),
        // The same string as a JSON escape (e) and raw; a non-BMP tool id raw and as an escaped surrogate pair.
        ["str_escaped"] = WithRule("esc", "{\"==\":{\"left\":" + Operation + ",\"right\":{\"Value\":\"d\\u0065lete\"}}}"),
        ["str_raw"] = WithRule("esc", "{\"==\":{\"left\":" + Operation + ",\"right\":{\"Value\":\"delete\"}}}"),
        ["str_non_bmp_tool"] = WithRule("emoji", "{\"==\":{\"left\":{\"Var\":\"resource\"},\"right\":{\"Value\":{\"__entity\":{\"type\":\"Tool\",\"id\":\"\U0001F600\"}}}}}"),
        ["str_non_bmp_escaped"] = WithRule("emoji", "{\"==\":{\"left\":{\"Var\":\"resource\"},\"right\":{\"Value\":{\"__entity\":{\"type\":\"Tool\",\"id\":\"\\ud83d\\ude00\"}}}}}"),
        ["long_overflow"] = WithRule("ovf", """{">":{"left":{"+":{"left":{"Value":9007199254740991},"right":{"Value":9007199254740991}}},"right":{"Value":0}}}"""),
    };

    private static Dictionary<string, byte[]> Facts()
    {
        var clean = File.ReadAllBytes(Path.Combine(Dir12, "expected", "01-clean.facts.json"));
        var ops = JsonNode.Parse(clean)!.AsObject();
        var call = ops["requests"]!.AsArray().First(r => r!["action"]!["id"]!.GetValue<string>() == "tool_call")!;
        var delete = call.DeepClone();
        delete["seq"] = 1;
        delete["context"]!["operation"] = "delete";
        var emoji = call.DeepClone();
        emoji["seq"] = 2;
        emoji["resource"] = new JsonObject { ["type"] = "Tool", ["id"] = "😀" };
        ops["requests"] = new JsonArray(delete, emoji);
        return new() { ["01-clean"] = clean, ["ops"] = EnvelopeHashing.Canonicalize(ops) };
    }

    /// <summary>The reference evaluator's answers (cedar-wasm 4.14.0 on the parsed documents): overall, then rule:result@where by id.</summary>
    private static readonly Dictionary<string, string> Reference = new()
    {
        ["v11|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["v11|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["num_neg0|01-clean"] = "FAIL allowed-tools:PASS;consequential-needs-approval:PASS;max-steps:FAIL@1,2,3,4,run;no-unpaired-consequential:PASS",
        ["num_neg0|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;max-steps:FAIL@1,2;no-unpaired-consequential:PASS",
        ["num_20.0|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["num_20.0|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["num_2e1|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["num_2e1|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["num_max_safe|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["num_max_safe|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["num_min_safe|01-clean"] = "FAIL allowed-tools:PASS;consequential-needs-approval:PASS;max-steps:FAIL@0,1,2,3,4,run;no-unpaired-consequential:PASS",
        ["num_min_safe|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;max-steps:FAIL@1,2;no-unpaired-consequential:PASS",
        ["str_escaped|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;esc:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["str_escaped|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;esc:FAIL@1;max-steps:PASS;no-unpaired-consequential:PASS",
        ["str_raw|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;esc:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["str_raw|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;esc:FAIL@1;max-steps:PASS;no-unpaired-consequential:PASS",
        ["str_non_bmp_tool|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;emoji:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["str_non_bmp_tool|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;emoji:FAIL@2;max-steps:PASS;no-unpaired-consequential:PASS",
        ["str_non_bmp_escaped|01-clean"] = "PASS allowed-tools:PASS;consequential-needs-approval:PASS;emoji:PASS;max-steps:PASS;no-unpaired-consequential:PASS",
        ["str_non_bmp_escaped|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;emoji:FAIL@2;max-steps:PASS;no-unpaired-consequential:PASS",
        ["long_overflow|01-clean"] = "FAIL allowed-tools:PASS;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS;ovf:FAIL@0,1,2,3,4,run",
        ["long_overflow|ops"] = "FAIL allowed-tools:FAIL@2;consequential-needs-approval:PASS;max-steps:PASS;no-unpaired-consequential:PASS;ovf:FAIL@1,2",
    };

    [Fact]
    public void TheNumberAndStringCorpus_GivesTheReferencesAnswers()
    {
        var docs = Docs();
        var facts = Facts();
        var matched = 0;
        foreach (var (name, doc) in docs)
        {
            AgentPolicy.ValidateStrict(doc, TestEngine.Shared).Should().BeEmpty(name);
            matched++;
            foreach (var (factsName, factsBytes) in facts)
            {
                var r = AgentPolicy.Evaluate(doc, factsBytes, TestEngine.Shared);
                var got = r.Overall + " " + string.Join(";", r.Rules.OrderBy(x => x.Id, StringComparer.Ordinal)
                    .Select(x => $"{x.Id}:{x.Result}" + (x.Where is { } w ? "@" + string.Join(",", w) : "")));
                got.Should().Be(Reference[$"{name}|{factsName}"], $"{name}|{factsName}");
                matched++;
            }
        }
        matched.Should().Be(33);
        // Not integral: refused by the core, as by the reference.
        FluentActions.Invoking(() => AgentPolicy.Evaluate(Number("1.5"), facts["01-clean"], TestEngine.Shared))
            .Should().Throw<PolicyEngineException>().Which.Refused.Should().BeTrue();
    }

    [Theory]
    [InlineData("9007199254740993.0", false)]
    [InlineData("9.007199254740993e15", false)]
    [InlineData("-9007199254740992.0", false)]
    [InlineData("9007199254740991.0", true)]
    [InlineData("20.0", true)]
    [InlineData("2e1", true)]
    [InlineData("1e2", true)]
    [InlineData("0e999", true)]
    [InlineData("0.0e20", true)]
    [InlineData("-0e400", true)]
    [InlineData("0.000000000000000001e20", true)]
    [InlineData("1e16", false)]
    [InlineData("1e400", false)]
    [InlineData("1e999999999", false)]
    [InlineData("90071992547409930e-1", false)]
    [InlineData("-9007199254740992", false)]
    [InlineData("9007199254740991.5", true)] // not integral: not this rule's business
    [InlineData("1e-400", true)]
    [InlineData("1.5", true)]
    public void IntegralNumbersBeyondTheSafeRange_AreInvalidHoweverWritten(string literal, bool valid)
    {
        // The Cedar core would read 9007199254740993.0 as 9007199254740992: the approved literal is not the evaluated value.
        var problems = AgentPolicy.Validate(Number(literal));
        if (valid) problems.Should().BeEmpty(literal);
        else problems.Should().Equal("the document is not an I-JSON object (no repeated names, integers within ±2^53-1, no lone surrogates)");
    }

    [Fact]
    public void TheModule_ImportsOnlyTheFiveWasiFunctions()
    {
        using var engine = new Wasmtime.Engine();
        using var module = Wasmtime.Module.FromBytes(engine, "sigill_cedar", TestEngine.Module());
        module.Imports.Select(i => $"{i.ModuleName}.{i.Name}").OrderBy(x => x, StringComparer.Ordinal).Should().Equal(
            "wasi_snapshot_preview1.environ_get", "wasi_snapshot_preview1.environ_sizes_get", "wasi_snapshot_preview1.fd_write",
            "wasi_snapshot_preview1.proc_exit", "wasi_snapshot_preview1.random_get");
    }

    [Fact]
    public void StrictValidation_IsTheSameOnEveryInstance()
    {
        // The core's validation errors come in an order that follows its random seed; the SDK's list must not.
        var d = JsonNode.Parse(Doc11)!.AsObject();
        var rules = d["cedar"]!["policies"]!["staticPolicies"]!.AsObject();
        for (var i = 0; i < 12; i++)
        {
            var r = JsonNode.Parse(Rule($"bad{i}", "{\"==\":{\"left\":{\".\":{\"left\":{\"Var\":\"context\"},\"attr\":\"nope" + i + "\"}},\"right\":{\"Value\":" + i + "}}}"))!;
            r["action"] = new JsonObject { ["op"] = "==", ["entity"] = new JsonObject { ["type"] = "Action", ["id"] = $"unknown{i}" } };
            rules[$"bad{i}"] = r;
        }
        var doc = TestEngine.Bytes(d);
        var lists = Enumerable.Range(0, 3).Select(_ =>
        {
            using var fresh = new CedarEngine();
            return string.Join("\n", AgentPolicy.ValidateStrict(doc, fresh));
        }).ToList();
        lists[0].Should().NotBeEmpty();
        lists.Distinct().Should().ContainSingle();
    }

    [Fact]
    public void Evaluate_RefusesFactsWithOtherEntities_AndASeqThatIsNoIntegerOrRun()
    {
        var dir14 = Path.Combine(SpecRoot.TestVectorsDir, "14-policy-enforcement", "expected");
        var facts = JsonNode.Parse(File.ReadAllBytes(Path.Combine(dir14, "01-allowed-call.facts.json")))!;
        facts["entities"]!.AsArray().RemoveAt(0);
        FluentActions.Invoking(() => AgentPolicy.Evaluate(PolicyControlSetV2VectorTests.Doc, TestEngine.Bytes(facts), TestEngine.Shared))
            .Should().Throw<ArgumentException>().WithMessage("The facts carry other entities than the control set.*");
        foreach (var seq in new JsonNode?[] { "x", 1.5, true, null })
        {
            var v1 = JsonNode.Parse(File.ReadAllBytes(Path.Combine(Dir12, "expected", "01-clean.facts.json")))!;
            v1["requests"]![0]!["seq"] = seq;
            FluentActions.Invoking(() => AgentPolicy.Evaluate(Doc11, TestEngine.Bytes(v1), TestEngine.Shared))
                .Should().Throw<ArgumentException>().WithMessage("The facts are not a factsVersion 1 document (a v1 control set).*");
        }
    }

    /// <summary>T2: a rule the structural check accepts and the core cannot parse.</summary>
    internal static byte[] Unparseable => Doc(t => ReplaceFirst(t, "\"staticPolicies\": {",
        "\"staticPolicies\": {\"nonsense\": " + Rule("nonsense", """{"nonsense":{}}""") + ","));

    [Fact]
    public void ARuleTheCoreCannotParse_IsRefused()
    {
        AgentPolicy.Validate(Unparseable).Should().BeEmpty();
        AgentPolicy.ValidateStrict(Unparseable, TestEngine.Shared).Should().ContainSingle()
            .Which.Should().StartWith("cedar.policies cannot be validated against Cedar schema v1: ");
        var facts = File.ReadAllBytes(Path.Combine(Dir12, "expected", "01-clean.facts.json"));
        FluentActions.Invoking(() => AgentPolicy.Evaluate(Unparseable, facts, TestEngine.Shared)).Should().Throw<PolicyEngineException>()
            .Which.Should().Match<PolicyEngineException>(e => e.Refused && e.Message.StartsWith("The policy engine refused request 0: "));
    }
}

public partial class AgentRunTests
{
    /// <summary>
    /// A recorded run under a v1 control set (vector 11's by default) and sealed policy evaluations of it: the given rules
    /// (from vector 11's results over the run), the named engine, an optional change to the prepared envelope.
    /// </summary>
    private async Task<AgentRunBundle> EvaluatedRun(Func<PolicyEvaluationResult, IReadOnlyList<PolicyRuleResult>> rules, string? engine = null,
        Action<JsonObject>? mutate = null, byte[]? doc = null, int copies = 1)
    {
        doc ??= PolicyDoc;
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, Options() with { ControlSet = AgentPolicy.ControlSetFromDocument(doc) });
        await run.RecordToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), operation: "read", useId: "c1");
        await run.RecordToolResultAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        await run.RecordToolCallAsync("crm.delete_customer", Encoding.UTF8.GetBytes("{}"), operation: "delete", consequential: true, useId: "c2");
        var bundle = await run.FinishAsync("completed");

        var facts = AgentPolicy.BuildFacts(Agent().AgentId, bundle.CorrelationId!, bundle.Artifacts.Select(a => a.Envelope));
        var evaluated = AgentPolicy.Evaluate(PolicyDoc, facts.Bytes, TestEngine.Shared);
        sealer.Cert = CertV;
        var evaluations = new List<AgentRunArtifact>();
        var payloads = new Dictionary<string, byte[]>();
        for (var i = 0; i < copies; i++)
        {
            var prepared = ControlEvaluation.PreparePolicy(new PolicyEvaluationRequest
            {
                CertificateId = VerifierCert, EvaluatorId = "urn:example:policy-evaluator", EvaluatorVersion = "1.0.0",
                ControlArtifact = run.ControlArtifact, ControlSetDocument = doc, Events = bundle.Artifacts,
                Rules = rules(evaluated), PolicyStatus = "unapproved", Engine = engine ?? evaluated.Engine, PrivateControlsReported = "pending",
            }, Clock());
            if (mutate is not null)
            {
                var changed = (JsonObject)prepared.Envelope.DeepClone();
                mutate(changed);
                prepared = prepared with { Envelope = changed, EnvelopeHashHex = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(changed)) };
            }
            evaluations.Add(await ControlEvaluation.SealAsync(client, prepared, VerifierCert));
            foreach (var (uri, bytes) in prepared.Payloads) payloads[uri] = bytes;
        }
        return AgentRunBundle.Parse(bundle.WithEvaluations(evaluations.ToArray()).WithPayloads(payloads).ToJsonString());
    }

    private static Task<AgentRunVerificationResult> VerifyWith(AgentRunBundle bundle, IPolicyEngine engine) =>
        AgentRunVerifier.VerifyWithEngineAsync(bundle, StubVerify, engine);

    private static IEnumerable<string> EvaluationNotes(AgentRunVerificationResult r) => r.Notes.Where(n => n.StartsWith("evaluation", StringComparison.Ordinal));

    [Fact]
    public async Task Verifier_WithAnEngine_RecomputesASealedPolicyEvaluation()
    {
        var bundle = await EvaluatedRun(e => e.Rules);
        var result = await VerifyWith(bundle, TestEngine.Shared);
        var e = result.Evaluations.Should().ContainSingle().Subject;
        e.Valid.Should().BeTrue(string.Join(" | ", e.Findings));
        e.ResultsRecomputed.Should().BeTrue();
        e.Overall.Should().Be("FAIL", "crm.delete_customer is not an allowed tool");
        EvaluationNotes(result).Should().BeEmpty();
    }

    [Fact]
    public async Task Verifier_WithAnEngine_FindsATamperedRuleResult()
    {
        var bundle = await EvaluatedRun(e => e.Rules.Select(r => r.Id == "allowed-tools" ? new PolicyRuleResult(r.Id, "PASS") : r).ToList());
        var e = (await VerifyWith(bundle, TestEngine.Shared)).Evaluations.Single();
        e.Valid.Should().BeFalse();
        e.ResultsRecomputed.Should().BeFalse();
        e.Findings.Should().Equal("evaluation 0: its results do not recompute: rule 'allowed-tools' is FAIL at 3 with cedar-policy@4.14.0, not PASS.");
    }

    [Fact]
    public async Task Verifier_WithAnEngine_FindsATamperedWhere_AndATamperedOverall()
    {
        var where = await EvaluatedRun(e => e.Rules.Select(r => r.Id == "allowed-tools" ? r with { Where = new[] { "2" } } : r).ToList());
        var w = (await VerifyWith(where, TestEngine.Shared)).Evaluations.Single();
        w.Valid.Should().BeFalse();
        w.Findings.Should().Equal("evaluation 0: its results do not recompute: rule 'allowed-tools' is FAIL at 3 with cedar-policy@4.14.0, not FAIL at 2.");

        var overall = await EvaluatedRun(e => e.Rules, mutate: env => env["overall"] = "PASS");
        var o = (await VerifyWith(overall, TestEngine.Shared)).Evaluations.Single();
        o.Valid.Should().BeFalse();
        o.ResultsRecomputed.Should().BeFalse();
        o.Findings.Should().Equal("evaluation 0: overall is PASS, but its controls give FAIL.",
            "evaluation 0: its results do not recompute: overall is FAIL with cedar-policy@4.14.0, not PASS.");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Verifier_ARepeatedControlId_IsNeverRecomputed(bool trueFirst)
    {
        PolicyRuleResult? truth = null;
        var bundle = await EvaluatedRun(e => { truth = e.Rules[0]; return e.Rules; }, mutate: env =>
        {
            static JsonObject Json(PolicyRuleResult r) => r.Where is null ? new JsonObject { ["id"] = r.Id, ["result"] = r.Result }
                : new JsonObject { ["id"] = r.Id, ["result"] = r.Result, ["where"] = new JsonArray(r.Where.Select(x => (JsonNode?)x).ToArray()) };
            var lie = new PolicyRuleResult(truth!.Id, "PASS");
            var rest = env["controls"]!.AsArray().Where(x => x!["id"]!.GetValue<string>() != truth.Id).Select(x => x!.DeepClone());
            env["controls"] = new JsonArray(new JsonNode?[] { Json(trueFirst ? truth : lie), Json(trueFirst ? lie : truth) }.Concat(rest).ToArray());
        });
        var result = await VerifyWith(bundle, TestEngine.Shared);
        var e = result.Evaluations.Single();
        e.Valid.Should().BeFalse();
        e.ResultsRecomputed.Should().BeFalse();
        e.Findings.Should().Equal("evaluation 0: control 'allowed-tools' is reported more than once.");
        EvaluationNotes(result).Should().BeEmpty();
    }

    [Fact]
    public async Task Verifier_WithoutAnEngine_TakesTheResultsOnTrust()
    {
        var bundle = await EvaluatedRun(e => e.Rules.Select(r => r.Id == "allowed-tools" ? new PolicyRuleResult(r.Id, "PASS") : r).ToList());
        var result = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        result.Evaluations.Single().Valid.Should().BeTrue("the claimed results are taken on trust without an engine");
        result.Evaluations.Single().ResultsRecomputed.Should().BeFalse();
        EvaluationNotes(result).Should().BeEmpty();
    }

    [Fact]
    public async Task Verifier_WithAnotherEngineVersion_DoesNotRecompute_AndSaysSo()
    {
        // A false result under another version is not judged: it is a note.
        var bundle = await EvaluatedRun(e => e.Rules.Select(r => r.Id == "allowed-tools" ? new PolicyRuleResult(r.Id, "PASS") : r).ToList(),
            engine: "cedar-policy@4.13.0");
        var result = await VerifyWith(bundle, TestEngine.Shared);
        var e = result.Evaluations.Single();
        e.Valid.Should().BeTrue(string.Join(" | ", e.Findings));
        e.ResultsRecomputed.Should().BeFalse();
        EvaluationNotes(result).Should().Equal(
            "evaluation 0: its results were not recomputed: it names the engine cedar-policy@4.13.0, the verifier has cedar-policy@4.14.0.");
    }

    private sealed class ThrowingEngine(Exception error) : IPolicyEngine
    {
        public string Version => "4.14.0";
        public JsonObject Authorize(JsonObject call) => throw error;
        public JsonObject Validate(JsonObject call) => throw error;
    }

    [Fact]
    public async Task Verifier_WithAFailingEngine_DoesNotRecompute_AndSaysSo()
    {
        var bundle = await EvaluatedRun(e => e.Rules);
        foreach (var (error, note) in new (Exception, string)[]
        {
            (new PolicyEngineException("The policy engine failed (cedar_authorize): trap."), "The policy engine failed (cedar_authorize): trap"),
            (new InvalidOperationException("not this kind of engine"), "not this kind of engine"),
        })
        {
            var result = await VerifyWith(bundle, new ThrowingEngine(error));
            var e = result.Evaluations.Single();
            e.Valid.Should().BeTrue(string.Join(" | ", e.Findings));
            e.ResultsRecomputed.Should().BeFalse();
            EvaluationNotes(result).Should().Equal($"evaluation 0: its results were not recomputed: {note}.");
        }
    }

    private sealed class ScriptedEngine(string answer) : IPolicyEngine
    {
        public string Version => "4.14.0";
        public JsonObject Authorize(JsonObject call) => JsonNode.Parse(answer)!.AsObject();
        public JsonObject Validate(JsonObject call) => JsonNode.Parse(answer)!.AsObject();
    }

    [Fact]
    public async Task Verifier_AnAnswerItCannotUse_IsANote_ARefusalAFinding()
    {
        var bundle = await EvaluatedRun(e => e.Rules);
        foreach (var answer in new[]
        {
            """{"type":"success","response":{"decision":"deny","diagnostics":{"reason":[1],"errors":[]}}}""",
            """{"type":"success","response":{"decision":"deny","diagnostics":{"reason":[],"errors":[{"policyId":null}]}}}""",
            """{"type":"maybe"}""",
        })
        {
            var result = await VerifyWith(bundle, new ScriptedEngine(answer));
            var e = result.Evaluations.Single();
            e.Valid.Should().BeTrue(answer);
            e.ResultsRecomputed.Should().BeFalse();
            EvaluationNotes(result).Should().Equal("evaluation 0: its results were not recomputed: The policy engine's answer is not an isAuthorized answer.");
        }
        var refused = await VerifyWith(bundle, new ScriptedEngine("""{"type":"failure","errors":[{"message":"no."}]}"""));
        refused.Evaluations.Single().Findings.Should().Equal("evaluation 0: its results cannot be recomputed: The policy engine refused request 0: no.");
    }

    [Fact]
    public async Task Verifier_ARequestTheNamedEngineRefuses_IsAFinding()
    {
        var bundle = await EvaluatedRun(e => e.Rules.Append(new PolicyRuleResult("nonsense", "PASS")).ToList(), doc: PolicyEngineSecurityTests.Unparseable);
        var result = await VerifyWith(bundle, TestEngine.Shared);
        var e = result.Evaluations.Single();
        e.Valid.Should().BeFalse();
        e.ResultsRecomputed.Should().BeFalse();
        e.Findings.Should().ContainSingle().Which.Should().StartWith("evaluation 0: its results cannot be recomputed: The policy engine refused request 0: ")
            .And.EndWith(".").And.NotEndWith("..");
        EvaluationNotes(result).Should().BeEmpty();
    }

    [Fact]
    public async Task Verifier_RecomputesWithinOneBudget_InBundleOrder()
    {
        var bundle = await EvaluatedRun(e => e.Rules, copies: 2);
        var requests = 6; // seq 0-4 and the run-level request
        var result = await AgentRunVerifier.VerifyWithEngineAsync(bundle, StubVerify, TestEngine.Shared, (long)PolicyDoc.Length * requests);
        result.Evaluations.Select(e => e.ResultsRecomputed).Should().Equal(true, false);
        result.Evaluations.Should().OnlyContain(e => e.Valid);
        EvaluationNotes(result).Should().Equal("evaluation 1: its results were not recomputed: the recomputation budget of this verification is used up.");
        AgentRunVerifier.RecomputeBudget.Should().Be(536_870_912);
    }
}
