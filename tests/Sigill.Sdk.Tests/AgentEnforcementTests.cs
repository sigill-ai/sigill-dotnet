// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// Agent Policy Control Set v2 and Agent Enforcement v1 (Execution Evidence v4): validation, digests and effective
// effects against vector 13, facts v2 and the verifier findings against vector 14, and the tool-call lifecycle of the
// recorder. This release records and verifies; it does not decide (no guard).

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

public class PolicyControlSetV2VectorTests
{
    internal static string Dir13 => Path.Combine(SpecRoot.TestVectorsDir, "13-policy-control-set-v2");
    internal static byte[] Doc => File.ReadAllBytes(Path.Combine(Dir13, "control-set.json"));
    private static JsonNode Expected => JsonNode.Parse(File.ReadAllText(Path.Combine(Dir13, "expected.json")))!;

    [Fact]
    public void Digests_AndSchemaDigest_MatchTheVector()
    {
        AgentPolicy.Validate(Doc).Should().BeEmpty();
        var d = AgentPolicy.ComputeDigests(Doc);
        d.ApprovalScopeDigest.Should().Be(Expected["approvalScopeDigest"]!.GetValue<string>());
        d.CedarDigest.Should().Be(Expected["cedarDigest"]!.GetValue<string>());
        EnvelopeHashing.HashHex(Doc).Should().Be(Expected["objectSha256"]!.GetValue<string>());
        // The embedded schema v2 is the spec copy.
        var spec = JsonNode.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "spec", "agent-policy-cedar-schema-v2.json")))!;
        AgentPolicy.CedarSchemaV2Sha256.Should().Be(EnvelopeHashing.HashHex(AgentProfiles.Canonical(spec)))
            .And.Be(Expected["schemaSha256"]!.GetValue<string>());
    }

    [Fact]
    public void Enforcement_GivesEachRulesEffectiveEffect_WithDefaultsApplied()
    {
        var e = AgentPolicy.Enforcement(Doc);
        (e.Mode, e.DefaultEffect, e.UnknownTools, e.OnRuleError, e.HaltAfterDenials).Should().Be(("enforce", "deny", "deny", "deny", 0L));
        e.LockedConfiguration.Should().ContainSingle().Which.Key.Should().Be("tool-manifest");
        e.RuleEffects.Keys.OrderBy(k => k, StringComparer.Ordinal).Should().Equal(Expected["ruleIds"]!.AsArray().Select(x => x!.GetValue<string>()));
        foreach (var kv in Expected["effects"]!.AsObject()) e.RuleEffects[kv.Key].Should().Be(kv.Value!.GetValue<string>(), kv.Key);

        // Only mode is required; observe makes every rule observe whatever its annotation.
        var minimal = JsonNode.Parse(Doc)!.AsObject();
        minimal["enforcement"] = new JsonObject { ["mode"] = "observe" };
        var observe = AgentPolicy.Enforcement(Encoding.UTF8.GetBytes(minimal.ToJsonString()));
        (observe.DefaultEffect, observe.UnknownTools, observe.OnRuleError, observe.HaltAfterDenials).Should().Be(("deny", "allow", "deny", 0L));
        observe.LockedConfiguration.Should().BeEmpty();
        observe.RuleEffects.Values.Should().OnlyContain(v => v == "observe");
        // A v1 document has no enforcement: observe, the v1 behaviour.
        AgentPolicy.Enforcement(File.ReadAllBytes(Path.Combine(SpecRoot.TestVectorsDir, "11-policy-control-set", "control-set.json")))
            .Should().Match<PolicyEnforcement>(x => x.Mode == "observe" && x.RuleEffects.Values.All(v => v == "observe"));
    }

    [Fact]
    public void Validate_RejectsEveryInvalidVector_WithoutThrowing()
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(Dir13, "invalid.json")))!;
        v["cases"]!.AsArray().Should().HaveCount(35);
        v["cases"]!.AsArray().Select(c => c!["name"]!.GetValue<string>()).Should().Contain(new[] { "cedar-unknown-member", "utf16le", "nested-deeper-than-64" });
        foreach (var c in v["cases"]!.AsArray())
        {
            var bytes = c!["documentBase64"] is { } b64 ? Convert.FromBase64String(b64.GetValue<string>())
                : Encoding.UTF8.GetBytes(c["document"]!.GetValue<string>());
            var errors = AgentPolicy.Validate(bytes);
            errors.Should().Contain(e => e.Contains(c["error"]!.GetValue<string>()), c["name"]!.GetValue<string>());
            FluentActions.Invoking(() => AgentPolicy.ComputeDigests(bytes)).Should().Throw<ArgumentException>(c["name"]!.GetValue<string>());
        }
    }

    private static byte[] Nested(int levels) => // the outermost object is level 1
        Encoding.UTF8.GetBytes("{\"a\":" + new string('[', levels - 1) + new string(']', levels - 1) + "}");

    [Fact]
    public void StrictParse_AcceptsExactly64Levels_AndNamesWhyItRefuses()
    {
        AgentPolicy.Parse(Nested(64), out var ok).Should().NotBeNull(ok);
        AgentPolicy.Parse(Nested(65), out var deep).Should().BeNull();
        deep.Should().Be("the document exceeds the nesting depth of 64 levels");
        AgentPolicy.Parse(Encoding.UTF8.GetBytes("{\"zz\":" + new string('[', 200_000) + new string(']', 200_000) + "}"), out deep).Should().BeNull();
        deep.Should().Contain("depth");

        const string utf8 = "the document is not UTF-8 without a byte-order mark";
        const string ijson = "the document is not an I-JSON object (no repeated names, integers within ±2^53-1, no lone surrogates)";
        foreach (var (bytes, why) in new (byte[], string)[]
        {
            (new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes("{}")).ToArray(), utf8),
            (Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("{}")).ToArray(), utf8),   // UTF-16LE: FF FE is not UTF-8
            (Encoding.Unicode.GetBytes("{}"), ijson),   // without its BOM it is valid UTF-8 (NUL bytes), but not JSON
            (new byte[] { (byte)'{', (byte)'"', 0xED, 0xB0, 0x80, (byte)'"', (byte)':', (byte)'1', (byte)'}' }, utf8), // an encoded surrogate
            (Encoding.UTF8.GetBytes("""{"a":1,"a":1}"""), ijson),
            (Encoding.UTF8.GetBytes("""{"a":9007199254740992}"""), ijson),   // 2^53: beyond ±(2^53 − 1)
            (Encoding.UTF8.GetBytes("""{"a":"\udc00"}"""), ijson),          // an escaped lone surrogate
            (Encoding.UTF8.GetBytes("""{"a":NaN}"""), ijson),
            (Encoding.UTF8.GetBytes("[]"), ijson),
        })
        {
            AgentPolicy.Parse(bytes, out var problem).Should().BeNull(why);
            problem.Should().Be(why);
        }
        AgentPolicy.Parse(Encoding.UTF8.GetBytes("""{"a":9007199254740991,"b":-9007199254740991}"""), out _).Should().NotBeNull();
    }

    [Fact]
    public void RuleIdsAndDigests_DoNotMatchBeforeAFinalNewline()
    {
        var doc = JsonNode.Parse(Doc)!.AsObject();
        doc["cedar"]!["schemaSha256"] = doc["cedar"]!["schemaSha256"]!.GetValue<string>() + "\n";
        AgentPolicy.Validate(Encoding.UTF8.GetBytes(doc.ToJsonString())).Should().Contain(e => e.Contains("schemaSha256"));
    }
}

public class PolicyEnforcementVectorTests
{
    private static string Dir => Path.Combine(SpecRoot.TestVectorsDir, "14-policy-enforcement");
    private static JsonNode Load(string path) => JsonNode.Parse(File.ReadAllText(Path.Combine(Dir, path)))!;

    public static IEnumerable<object[]> Runs() =>
        Directory.GetFiles(Path.Combine(Dir, "runs"), "*.json").OrderBy(p => p, StringComparer.Ordinal).Select(p => new object[] { Path.GetFileNameWithoutExtension(p) });

    public static IEnumerable<object[]> FindingsRuns() =>
        Directory.GetFiles(Path.Combine(Dir, "findings"), "*.json").OrderBy(p => p, StringComparer.Ordinal).Select(p => new object[] { Path.GetFileNameWithoutExtension(p) });

    /// <summary>Vector 13's control set with the run's enforcement (README).</summary>
    internal static byte[] ControlSetOf(JsonNode run)
    {
        var doc = JsonNode.Parse(PolicyControlSetV2VectorTests.Doc)!.AsObject();
        doc["enforcement"] = run["enforcement"]!.DeepClone();
        return Encoding.UTF8.GetBytes(doc.ToJsonString());
    }

    private static AgentRunArtifact Artifact(JsonNode e) => new(e["envelope"]!.DeepClone().AsObject(), new JsonObject(),
        e["objectDigests"]!.AsObject().ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>()));

    private static string Jcs(JsonNode n) => Encoding.UTF8.GetString(AgentProfiles.Canonical(n));

    [Fact]
    public void Vector_IsComplete()
    {
        Runs().Should().HaveCount(35);
        FindingsRuns().Should().HaveCount(14);
    }

    [Theory]
    [MemberData(nameof(Runs))]
    public void FactsV2_AreTheVectorsRequests(string name)
    {
        var run = Load($"runs/{name}.json");
        var expected = Load($"expected/{name}.json");
        var cs = ControlSetOf(run);
        AgentPolicy.ComputeDigests(cs).ApprovalScopeDigest.Should().Be(expected["approvalScopeDigest"]!.GetValue<string>());

        var events = run["events"]!.AsArray().Select(e => Artifact(e!)).Reverse(); // any order
        var facts = AgentPolicy.BuildFactsV2(run["agentId"]!.GetValue<string>(), run["correlationId"]!.GetValue<string>(), events, cs);

        // Control Set v2 §8 "Facts document": the exact JCS bytes and their digest.
        facts.Bytes.Should().Equal(File.ReadAllBytes(Path.Combine(Dir, "expected", name + ".facts.json")));
        facts.Sha256.Should().Be(expected["factsSha256"]!.GetValue<string>());
        var doc = JsonNode.Parse(facts.Bytes)!;
        doc["factsVersion"]!.GetValue<string>().Should().Be("2");
        Jcs(doc["entities"]!).Should().Be(Jcs(JsonNode.Parse(PolicyControlSetV2VectorTests.Doc)!["cedar"]!["entities"]!));
        facts.RunLevel.Should().BeTrue();
        var requests = doc["requests"]!.AsArray();
        var want = expected["events"]!.AsArray().Select(e => e!["request"]!).Append(expected["runLevel"]!["request"]!).ToList();
        requests.Should().HaveCount(want.Count);
        for (var i = 0; i < want.Count; i++)
        {
            var r = requests[i]!.DeepClone().AsObject();
            r["seq"]!.ToJsonString().Should().Be(i < want.Count - 1 ? i.ToString(System.Globalization.CultureInfo.InvariantCulture) : "\"run\"");
            r.Remove("seq");
            Jcs(r).Should().Be(Jcs(want[i]), $"request {(i < want.Count - 1 ? i.ToString(System.Globalization.CultureInfo.InvariantCulture) : "run")}");
        }
    }

    [Fact]
    public void FactsV2_AlwaysCarryEntities_EmptyWithoutAny()
    {
        var doc = JsonNode.Parse(PolicyControlSetV2VectorTests.Doc)!.AsObject();
        doc["cedar"]!.AsObject().Remove("entities");
        var run = Load("runs/01-allowed-call.json");
        var facts = AgentPolicy.BuildFactsV2(run["agentId"]!.GetValue<string>(), run["correlationId"]!.GetValue<string>(),
            run["events"]!.AsArray().Select(e => Artifact(e!)), Encoding.UTF8.GetBytes(doc.ToJsonString()));
        JsonNode.Parse(facts.Bytes)!["entities"]!.ToJsonString().Should().Be("[]");
    }

    [Theory]
    [MemberData(nameof(Runs))]
    public void GuardRuns_HaveNoFindings(string name)
    {
        var run = Load($"runs/{name}.json");
        var envs = run["events"]!.AsArray().Select(e => e!["envelope"]!.AsObject()).ToList();
        AgentRunVerifier.EnforcementFindings(envs, AgentPolicy.ControlSetContentType, ControlSetOf(run)).Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(FindingsRuns))]
    public void FindingsRuns_ProduceExactlyTheirFindings(string name)
    {
        var run = Load($"findings/{name}.json");
        var envs = run["events"]!.AsArray().Select(e => e!["envelope"]!.AsObject()).ToList();
        var found = AgentRunVerifier.EnforcementFindings(envs, run["controlSetContentType"]?.GetValue<string>(), SuppliedControlSet(run));
        found.Select(f => $"{f.Code}:{string.Join(",", f.Seqs)}").Should().Equal(ExpectedFindings(run));
    }

    internal static byte[]? SuppliedControlSet(JsonNode run) =>
        run["controlSetBase64"] is { } b ? Convert.FromBase64String(b.GetValue<string>()) : null;

    internal static IEnumerable<string> ExpectedFindings(JsonNode run) => run["findings"]!.AsArray()
        .Select(f => $"{f!["code"]!.GetValue<string>()}:{string.Join(",", f["seqs"]!.AsArray().Select(s => s!.GetValue<int>()))}");

    [Fact]
    public void Envelopes_AreAcceptedAndRejectedByTheSchemaOfTheirVersion()
    {
        var v = Load("envelopes.json");
        foreach (var c in v["valid"]!.AsArray())
        {
            var env = c!["envelope"]!.AsObject();
            EnvelopeSchema.Validate(env, AgentProfiles.ExecutionSchemaFor(env)).Should().BeEmpty(c["name"]!.GetValue<string>());
        }
        foreach (var c in v["invalid"]!.AsArray())
        {
            var env = c!["envelope"]!.AsObject();
            EnvelopeSchema.Validate(env, AgentProfiles.ExecutionSchemaFor(env)).Should().NotBeEmpty(c["name"]!.GetValue<string>());
        }
    }
}

public partial class AgentRunTests
{
    // Vector 13's control set in observe mode: an enforcing control set needs the guard (AgentGuardTests).
    private static AgentRunOptions PolicyV2Options() =>
        Options() with { ControlSet = AgentPolicy.ControlSetFromDocument(ObserveV2Doc) };

    internal static byte[] ObserveV2Doc
    {
        get
        {
            var doc = JsonNode.Parse(PolicyControlSetV2VectorTests.Doc)!.AsObject();
            doc["enforcement"]!["mode"] = "observe";
            return Encoding.UTF8.GetBytes(doc.ToJsonString());
        }
    }

    private static readonly byte[] RefundArgs = Encoding.UTF8.GetBytes("""{"amount":120,"order":"o-1"}""");

    [Fact]
    public async Task V2PolicyRun_RecordsV4_AndTheLifecyclePairsEachCallWithItsResult()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, PolicyV2Options());

        var call = await run.BeginToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("""{"customer":"c-1"}"""),
            operation: "read", definition: Encoding.UTF8.GetBytes("crm.read_customer definition"));
        Guid.TryParse(call.UseId, out _).Should().BeTrue("a useId is generated");
        call.Artifact.Envelope["step"]!["tool"]!["useId"]!.GetValue<string>().Should().Be(call.UseId);
        call.Artifact.Envelope["objects"]!.AsArray().Select(o => o!["role"]!.GetValue<string>()).Should().Equal("tool-arguments", "tool-definition");
        var result = await call.CompleteAsync(Encoding.UTF8.GetBytes("""{"ok":true}"""));
        result.Envelope["step"]!["tool"]!.ToJsonString().Should().Be(new JsonObject { ["name"] = "crm.read_customer", ["useId"] = call.UseId }.ToJsonString());

        // Rejected before sealing, and the run stays usable.
        var sealedBefore = sealer.Requests.Count;
        await FluentActions.Awaiting(() => call.CompleteAsync(Encoding.UTF8.GetBytes("{}"))).Should().ThrowAsync<InvalidOperationException>();
        await FluentActions.Awaiting(() => run.RecordToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: call.UseId))
            .Should().ThrowAsync<ArgumentException>()
            .WithMessage($"use_id '{call.UseId}' is already used by a tool_call of this run; a retry is a new call with a new use id (enforcement §3.2).");
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: call.UseId))
            .Should().ThrowAsync<ArgumentException>();
        await FluentActions.Awaiting(() => run.RecordToolResultAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}")))
            .Should().ThrowAsync<ArgumentException>().WithMessage("*useId is required*");
        // Only the guard of a later release seals enforcement records.
        await FluentActions.Awaiting(() => run.RecordAsync("authorization", fields: new JsonObject
        {
            ["decision"] = "denied", ["enforcer"] = new JsonObject { ["engine"] = "cedar-policy@4.14.0", ["factsVersion"] = "2", ["reason"] = "unavailable" },
        })).Should().ThrowAsync<ArgumentException>().WithMessage("*reserved*");
        sealer.Requests.Should().HaveCount(sealedBefore);
        run.IsBroken.Should().BeFalse();

        var generated = await run.RecordToolCallAsync("search.web", Encoding.UTF8.GetBytes("{}"));
        Guid.TryParse(generated.Envelope["step"]!["tool"]!["useId"]!.GetValue<string>(), out _).Should().BeTrue();

        // A bound approval: rejected by use id for the first refund, approved by tool and arguments for the retry.
        var refund = await run.BeginToolCallAsync("payments.refund", RefundArgs, consequential: true);
        var expires = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero).AddTicks(12_345);
        var rejection = await run.RecordHumanApprovalAsync("rejected", approver: "urn:example:approver:1", covers: refund.Covers());
        var approval = await run.RecordHumanApprovalAsync("approved", approver: "urn:example:approver:1",
            covers: ApprovalCovers.ForArguments("payments.refund", RefundArgs, expires));
        rejection.Envelope["step"]!["covers"]!.ToJsonString().Should().Be(new JsonObject
        {
            ["tool"] = "payments.refund", ["argumentsSha256"] = EnvelopeHashing.HashHex(RefundArgs), ["useId"] = refund.UseId,
        }.ToJsonString());
        approval.Envelope["step"]!["covers"]!["expiresAt"]!.GetValue<string>().Should().Be("2030-01-01T00:00:00.001Z");
        approval.Envelope["step"]!["covers"]!.AsObject().ContainsKey("useId").Should().BeFalse();
        var retry = await run.BeginToolCallAsync("payments.refund", RefundArgs, consequential: true);
        await retry.CompleteAsync(Encoding.UTF8.GetBytes("""{"ok":true}"""));
        var bundle = await run.FinishAsync("completed");

        bundle.Artifacts.Select(a => a.Envelope["schemaVersion"]!.GetValue<string>()).Should().OnlyContain(v => v == "4");
        var verdict = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(bundle.ToJsonString()), StubVerify);
        verdict.Verdict.Should().Be("run_finalized", string.Join("\n", verdict.Findings));
        verdict.Checks["enforcement"].Should().Be("ok");

        // Facts v2 from the signed digests: the rejection is sticky by tool and arguments, so the retry is rejected too.
        var facts = JsonNode.Parse(AgentPolicy.BuildFactsV2(Agent().AgentId, run.CorrelationId, bundle.Artifacts, PolicyV2Options().ControlSet.Content).Bytes)!;
        string ApprovalAt(int seq) => facts["requests"]![seq]!["context"]!["approval"]!.GetValue<string>();
        (ApprovalAt(refund.Artifact.Seq!.Value), ApprovalAt(retry.Artifact.Seq!.Value)).Should().Be(("none", "rejected"));
        // The unpaired first refund counts at run level (no enforcement record denied it).
        facts["requests"]!.AsArray()[^1]!["context"]!["unpairedConsequential"]!.GetValue<int>().Should().Be(1);
    }

    [Fact]
    public async Task ApprovalForArguments_BindsTheNextCallOnce()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, PolicyV2Options());
        await run.RecordHumanApprovalAsync("approved", covers: ApprovalCovers.ForArguments("payments.refund", RefundArgs));
        var first = await run.BeginToolCallAsync("payments.refund", RefundArgs);
        var second = await run.BeginToolCallAsync("payments.refund", RefundArgs);
        var bundle = await run.FinishAsync("aborted");
        var facts = JsonNode.Parse(AgentPolicy.BuildFactsV2(Agent().AgentId, run.CorrelationId, bundle.Artifacts, PolicyV2Options().ControlSet.Content).Bytes)!;
        facts["requests"]![first.Artifact.Seq!.Value]!["context"]!["approval"]!.GetValue<string>().Should().Be("bound");
        facts["requests"]![second.Artifact.Seq!.Value]!["context"]!["approval"]!.GetValue<string>().Should().Be("unbound", "one approval binds one call");
    }

    [Fact]
    public async Task CompletingConcurrently_SealsOneResult()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, PolicyV2Options());
        var call = await run.BeginToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"));
        var attempts = Enumerable.Range(0, 4).Select(_ => Task.Run(() => call.CompleteAsync(Encoding.UTF8.GetBytes("{}")))).ToList();
        await Task.WhenAny(Task.WhenAll(attempts));
        attempts.Count(t => t.Status == TaskStatus.RanToCompletion).Should().Be(1);
        attempts.Where(t => t.IsFaulted).Should().OnlyContain(t => t.Exception!.InnerException is InvalidOperationException);
        run.Artifacts.Count(a => a.StepType == "tool_result").Should().Be(1);
    }

    [Fact]
    public async Task V1Run_LifecyclePairsWithAGeneratedUseId_ButDefinitionAndCoversAreV4Only()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client);
        var call = await run.BeginToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"));
        var result = await call.CompleteAsync(Encoding.UTF8.GetBytes("{}"));
        result.Envelope["step"]!["tool"]!["useId"]!.GetValue<string>().Should().Be(call.UseId);
        (await run.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"))).Envelope["step"]!["tool"]!.AsObject()
            .ContainsKey("useId").Should().BeFalse("v1–v3 runs are unchanged");
        var sealedBefore = sealer.Requests.Count;
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("{}"), definition: new byte[] { 1 }))
            .Should().ThrowAsync<InvalidOperationException>();
        await FluentActions.Awaiting(() => run.RecordHumanApprovalAsync("approved", covers: call.Covers()))
            .Should().ThrowAsync<InvalidOperationException>();
        sealer.Requests.Should().HaveCount(sealedBefore);
        var bundle = await run.FinishAsync();
        bundle.Artifacts.Should().OnlyContain(a => a.Envelope["schemaVersion"]!.GetValue<string>() == "1");
        var verdict = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        verdict.Verdict.Should().Be("run_finalized");
        verdict.Checks.Should().NotContainKey("enforcement");
    }

    [Fact]
    public async Task V4Run_RefusesOrphanAndSecondResults_OnEveryPath_BeforeSealing()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, PolicyV2Options());
        var call = await run.BeginToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        var before = sealer.Requests.Count;
        var result = new JsonObject { ["tool"] = new JsonObject { ["name"] = "crm.read_customer", ["useId"] = "never-called" } };
        var objects = new[] { new AgentRunObject { Role = "tool-result", Bytes = new byte[] { 1 }, ContentType = "application/json" } };
        await FluentActions.Awaiting(() => run.RecordToolResultAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: "never-called"))
            .Should().ThrowAsync<ArgumentException>().WithMessage("No tool_call of this run with use_id 'never-called' awaits a result.*");
        await FluentActions.Awaiting(() => run.RecordAsync("tool_result", objects, result)).Should().ThrowAsync<ArgumentException>();
        sealer.Requests.Should().HaveCount(before);

        await run.RecordToolResultAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        before = sealer.Requests.Count;
        await FluentActions.Awaiting(() => call.CompleteAsync(Encoding.UTF8.GetBytes("{}")))
            .Should().ThrowAsync<ArgumentException>().WithMessage("The tool_call with use_id 'c1' already has its result.*");
        result["tool"]!["useId"] = "c1";
        await FluentActions.Awaiting(() => run.RecordAsync("tool_result", objects, result)).Should().ThrowAsync<ArgumentException>();
        sealer.Requests.Should().HaveCount(before);
        run.IsBroken.Should().BeFalse();
        var verdict = await AgentRunVerifier.VerifyAsync(await run.FinishAsync(), StubVerify);
        verdict.Verdict.Should().Be("run_finalized", string.Join("\n", verdict.Findings));
        verdict.Checks["enforcement"].Should().Be("ok");
    }

    [Fact]
    public async Task HaltedChild_IsRecordedByAV4ParentOnly()
    {
        using var client = Client(new StubSealer());
        var v4 = await Start(client, PolicyV2Options());
        var d = await v4.DelegateAsync("urn:example:agent:child");
        (await v4.CompleteDelegationAsync(d.ChildCorrelationId, new string('a', 64), "halted"))
            .Envelope["step"]!["delegation"]!["childDisposition"]!.GetValue<string>().Should().Be("halted");
        var v3 = await Start(client, Options() with { RecordsModelCalls = true });
        var d3 = await v3.DelegateAsync("urn:example:agent:child");
        await FluentActions.Awaiting(() => v3.CompleteDelegationAsync(d3.ChildCorrelationId, new string('a', 64), "halted"))
            .Should().ThrowAsync<ArgumentException>();
        v3.IsBroken.Should().BeFalse();
    }

    [Fact]
    public async Task RecordHumanApprovalAsync_WithAPositionalNull_StillMeansTheReceipt()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client);
        (await run.RecordHumanApprovalAsync("approved", null)).Envelope["step"]!.AsObject().ContainsKey("covers").Should().BeFalse();
    }

    // ── Date-times are truncated to microseconds, never rounded (H4) ──

    [Theory]
    [InlineData("2026-11-02T10:00:00.99999999Z", "2026-11-02T10:00:00.999999")]
    [InlineData("2026-11-02T10:00:00.999999999Z", "2026-11-02T10:00:00.999999")]
    [InlineData("2026-11-02T10:00:01.00000001Z", "2026-11-02T10:00:01.000000")]
    [InlineData("2026-11-02T11:00:00.9999995+01:00", "2026-11-02T10:00:00.999999")]
    public void DateTimes_AreTruncated(string text, string utc)
    {
        EnvelopeSchema.TryParseDateTime(text, out var at).Should().BeTrue();
        at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff", System.Globalization.CultureInfo.InvariantCulture).Should().Be(utc);
        (at.Ticks % 10).Should().Be(0);
    }

    [Theory]
    [InlineData("2026-11-02T10:00:00Z\n")]
    [InlineData("2026-11-02T10:00:00+14:01")]
    [InlineData("2026-11-02T10:00:00-14:30")]
    [InlineData("٢٠٢٦-11-02T10:00:00Z")]
    public void DateTimes_OutsideTheCommonForm_AreRefused(string text) => EnvelopeSchema.TryParseDateTime(text, out _).Should().BeFalse();

    private static List<AgentRunArtifact> ApprovalRun(string eventTime, JsonObject covers, JsonObject? callTool = null)
    {
        var args = Encoding.UTF8.GetBytes("{}");
        AgentRunArtifact Event(int seq, JsonObject step, params (string Role, byte[] Bytes)[] objects)
        {
            var arr = new JsonArray();
            var digests = new Dictionary<string, string>();
            foreach (var (role, bytes) in objects)
            {
                var uri = $"objects/{seq}-{role}";
                arr.Add(new JsonObject { ["uri"] = uri, ["role"] = role, ["contentType"] = "application/json" });
                digests[uri] = EnvelopeHashing.HashHex(bytes);
            }
            return new AgentRunArtifact(new JsonObject { ["schemaVersion"] = "4", ["chain"] = new JsonObject { ["seq"] = seq }, ["step"] = step, ["objects"] = arr },
                new JsonObject(), digests);
        }
        return new List<AgentRunArtifact>
        {
            Event(0, new JsonObject { ["type"] = "run_start", ["eventTime"] = "2026-11-02T09:59:59.000Z" }),
            Event(1, new JsonObject { ["type"] = "human_approval", ["eventTime"] = "2026-11-02T09:59:59.500Z", ["decision"] = covers["decision"]!.GetValue<string>(),
                ["covers"] = covers["covers"]!.DeepClone() }),
            Event(2, new JsonObject { ["type"] = "tool_call", ["eventTime"] = eventTime,
                ["tool"] = callTool ?? new JsonObject { ["name"] = "payments.refund", ["useId"] = "c1" } }, ("tool-arguments", args)),
        };
    }

    private static string ApprovalOf(List<AgentRunArtifact> events) =>
        JsonNode.Parse(AgentPolicy.BuildFactsV2("a", "r", events, PolicyControlSetV2VectorTests.Doc).Bytes)!["requests"]![2]!["context"]!["approval"]!.GetValue<string>();

    private static JsonObject Approval(string decision, JsonObject covers) => new() { ["decision"] = decision, ["covers"] = covers };

    private static JsonObject Covering(string? tool = "payments.refund") => tool is null
        ? new JsonObject { ["argumentsSha256"] = EnvelopeHashing.HashHex(Encoding.UTF8.GetBytes("{}")) }
        : new JsonObject { ["tool"] = tool, ["argumentsSha256"] = EnvelopeHashing.HashHex(Encoding.UTF8.GetBytes("{}")) };

    [Theory]
    [InlineData("2026-11-02T10:00:00.99999999Z", "bound")]   // rounding would make it 10:00:01, the expiry
    [InlineData("2026-11-02T10:00:00.999999999Z", "bound")]
    [InlineData("2026-11-02T10:00:01Z", "unbound")]
    [InlineData("2026-11-02T10:00:01.00000001Z", "unbound")]
    public void Expiry_ComparesTruncatedInstants(string eventTime, string approval)
    {
        var covers = Covering();
        covers["expiresAt"] = "2026-11-02T10:00:01.000Z";
        ApprovalOf(ApprovalRun(eventTime, Approval("approved", covers))).Should().Be(approval);
    }

    [Fact]
    public void MalformedMembers_EqualNothing()
    {
        const string at = "2026-11-02T10:00:00.000Z";
        // A call without a tool name is not bound by an approval without a tool, nor rejected by a non-string use id.
        ApprovalOf(ApprovalRun(at, Approval("approved", Covering(null)), new JsonObject { ["useId"] = "c1" })).Should().Be("unbound");
        var rejectByUseId = Covering("other.tool");
        rejectByUseId["useId"] = 5;
        ApprovalOf(ApprovalRun(at, Approval("rejected", rejectByUseId), new JsonObject { ["name"] = "payments.refund" })).Should().Be("unbound");
        var approveWithUseId = Covering();
        approveWithUseId["useId"] = 5;
        ApprovalOf(ApprovalRun(at, Approval("approved", approveWithUseId), new JsonObject { ["name"] = "payments.refund" })).Should().Be("unbound");
        var badExpiry = Covering();
        badExpiry["expiresAt"] = "tomorrow";
        ApprovalOf(ApprovalRun(at, Approval("approved", badExpiry))).Should().Be("unbound");
        // A tool that is not an object is absent: callsOfThisTool 0, and no exception.
        var events = ApprovalRun(at, Approval("approved", Covering()));
        events[2].Envelope["step"]!["tool"] = "payments.refund";
        var facts = JsonNode.Parse(AgentPolicy.BuildFactsV2("a", "r", events, PolicyControlSetV2VectorTests.Doc).Bytes)!;
        facts["requests"]![2]!["context"]!["callsOfThisTool"]!.GetValue<int>().Should().Be(0);
        facts["requests"]![2]!["context"]!["toolCallsSoFar"]!.GetValue<int>().Should().Be(1);
    }

    // ── The public verifier over vector 14, end to end (signed control-set bytes supplied) ──

    private static string V14 => Path.Combine(SpecRoot.TestVectorsDir, "14-policy-enforcement");
    private static JsonObject LoadV14(string rel) => JsonNode.Parse(File.ReadAllText(Path.Combine(V14, rel)))!.AsObject();
    private const string PolicyCt = AgentPolicy.ControlSetContentType;

    /// <summary>The vector's envelopes re-chained and stub-signed under a stub Control Artifact that binds the given control set.</summary>
    private static AgentRunBundle SignedVectorBundle(JsonObject run, (string Ct, byte[] Bytes)? controlSet,
        string controlGenTime = "2026-11-02T09:59:59Z", string runEndGenTime = "2026-11-02T11:00:00Z", string? eventTime = null)
    {
        var roles = new Dictionary<string, string>();
        if (run["configuration"] is JsonObject conf) foreach (var (k, v) in conf) roles[k] = v!.GetValue<string>();
        roles["control-set"] = EnvelopeHashing.HashHex(controlSet?.Bytes ?? PolicyControlSetV2VectorTests.Doc);
        var objects = new JsonArray();
        var digests = new Dictionary<string, string>();
        var payloads = new Dictionary<string, byte[]>();
        foreach (var (role, hex) in roles)
        {
            var uri = "objects/" + Guid.NewGuid();
            objects.Add(new JsonObject { ["uri"] = uri, ["role"] = role, ["contentType"] = role == "control-set" ? controlSet?.Ct ?? PolicyCt : "application/json" });
            digests[uri] = hex;
            if (role == "control-set" && controlSet is { } c) payloads[uri] = c.Bytes;
        }
        var ctl = new JsonObject
        {
            ["schemaName"] = "AgentControlArtifact", ["schemaVersion"] = "1", ["evidenceId"] = Guid.NewGuid().ToString(),
            ["createdAt"] = "2026-11-02T09:59:59Z", ["actor"] = new JsonObject { ["type"] = "agent", ["id"] = run["agentId"]!.GetValue<string>() },
            ["activity"] = new JsonObject { ["name"] = "support-session", ["correlationId"] = run["correlationId"]!.GetValue<string>() },
            ["agent"] = new JsonObject { ["id"] = run["agentId"]!.GetValue<string>(), ["version"] = "1" },
            ["controlSet"] = new JsonObject { ["id"] = "acme-support-agent-controls", ["version"] = "4" },
            ["timestampPolicy"] = new AgentTimestampPolicy().ToJson(), ["objects"] = objects,
        };
        var ctlSig = StubSign(EnvelopeHashing.HashHex(AgentProfiles.Canonical(ctl)),
            objects.Select(o => (o!["uri"]!.GetValue<string>(), digests[o["uri"]!.GetValue<string>()], (string?)o["contentType"]!.GetValue<string>())),
            AgentProfiles.ControlArtifactContentType, true, controlGenTime, CertA);
        var control = new AgentRunArtifact(ctl, ctlSig, digests);
        var events = new List<AgentRunArtifact>();
        string? prev = null;
        foreach (var e in run["events"]!.AsArray())
        {
            var env = e!["envelope"]!.DeepClone().AsObject();
            if (eventTime is not null) env["step"]!["eventTime"] = eventTime;
            if (prev is null) env["binds"]!["controlArtifactSignatureSha256"] = control.SignatureSha256;
            else env["chain"]!["prevSignatureSha256"] = prev;
            if (env["step"]!["type"]!.GetValue<string>() == "run_end") env["step"]!["finalPrevSignatureSha256"] = prev;
            var od = e["objectDigests"]!.AsObject().ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>());
            var sig = StubSign(EnvelopeHashing.HashHex(AgentProfiles.Canonical(env)),
                env["objects"]!.AsArray().Select(o => (o!["uri"]!.GetValue<string>(), od[o["uri"]!.GetValue<string>()], (string?)o["contentType"]!.GetValue<string>())),
                AgentProfiles.ExecutionEvidenceContentType, env["step"]!["type"]!.GetValue<string>() == "run_end", runEndGenTime, CertA);
            events.Add(new AgentRunArtifact(env, sig, od));
            prev = AgentProfiles.SignatureSha256(sig);
        }
        return new AgentRunBundle(run["correlationId"]!.GetValue<string>(), control, events, null, payloads);
    }

    public static IEnumerable<object[]> GuardRuns() => PolicyEnforcementVectorTests.Runs();
    public static IEnumerable<object[]> FindingsVectorRuns() => PolicyEnforcementVectorTests.FindingsRuns();

    [Theory]
    [MemberData(nameof(GuardRuns))]
    public async Task GuardRuns_VerifyWithAnOkEnforcementCheck(string name)
    {
        var run = LoadV14($"runs/{name}.json");
        var result = await AgentRunVerifier.VerifyAsync(SignedVectorBundle(run, (PolicyCt, PolicyEnforcementVectorTests.ControlSetOf(run))), StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.Checks["enforcement"].Should().Be("ok");
        result.EnforcementFindings.Should().BeEmpty();
    }

    [Theory]
    [MemberData(nameof(FindingsVectorRuns))]
    public async Task FindingsRuns_ThroughThePublicVerifier(string name)
    {
        var run = LoadV14($"findings/{name}.json");
        var bytes = PolicyEnforcementVectorTests.SuppliedControlSet(run);
        var supplied = bytes is null ? ((string, byte[])?)null : (run["controlSetContentType"]!.GetValue<string>(), bytes);
        var result = await AgentRunVerifier.VerifyAsync(SignedVectorBundle(run, supplied), StubVerify);
        var expected = PolicyEnforcementVectorTests.ExpectedFindings(run).ToList();
        result.EnforcementFindings.Select(f => $"{f.Code}:{string.Join(",", f.Seqs)}").Should().Equal(expected);
        var v4 = run["events"]!.AsArray().All(e => e!["envelope"]!["schemaVersion"]!.GetValue<string>() == "4");
        if (expected.Count > 0)
        {
            result.Checks["enforcement"].Should().Be("bad");
            result.Verdict.Should().Be("run_invalid");
            result.Findings.Should().Contain(f => f.StartsWith("enforcement: ", StringComparison.Ordinal) && f.Contains($"({expected[0].Split(':')[0]}; seq "));
        }
        else if (v4) result.Checks["enforcement"].Should().Be("ok");
        else result.Checks.Should().NotContainKey("enforcement", "a v1–v3 run without a mismatch keeps its nine checks");
    }

    [Fact]
    public async Task FindingText_IsThePortsCommonWording()
    {
        var result = await AgentRunVerifier.VerifyAsync(SignedVectorBundle(LoadV14("findings/f2-orphan-result.json"), null), StubVerify);
        result.Findings.Should().Contain("enforcement: a tool_result whose useId no earlier tool_call used (orphan_result; seq 1).");
        var f9 = LoadV14("findings/f9-evidence-version-mismatch.json");
        result = await AgentRunVerifier.VerifyAsync(SignedVectorBundle(f9, (PolicyCt, PolicyEnforcementVectorTests.SuppliedControlSet(f9)!)), StubVerify);
        result.Findings.Should().Contain("enforcement: the policy control set does not parse strictly as a v1 document, but the events are not all schemaVersion 4 (evidence_version_mismatch; seq 0, 1, 2, 3).");
    }

    // ── Regression tests from the security review's proofs ──

    private static readonly byte[] DocV2 = PolicyControlSetV2VectorTests.Doc;

    public static IEnumerable<object[]> NonStrictV2Docs() => new[]
    {
        new object[] { "dup member", Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(DocV2).Replace("\"schemaVersion\": \"2\",", "\"schemaVersion\": \"2\", \"schemaVersion\": \"2\",")) },
        new object[] { "bigint", Encoding.UTF8.GetBytes("{\"zz\": 9007199254740993," + Encoding.UTF8.GetString(DocV2).TrimStart()[1..]) },
        new object[] { "BOM", new byte[] { 0xEF, 0xBB, 0xBF }.Concat(DocV2).ToArray() },
        new object[] { "UTF-16", Encoding.Unicode.GetBytes(Encoding.UTF8.GetString(DocV2)) },
        new object[] { "deep", Encoding.UTF8.GetBytes("{\"zz\":" + new string('[', 200_000) + new string(']', 200_000) + "}") },
    };

    [Theory]
    [MemberData(nameof(NonStrictV2Docs))]
    public async Task V3RunUnderAPolicyControlSetThatIsNotStrict_FailsClosed(string variant, byte[] doc)
    {
        var run = LoadV14("findings/f9-evidence-version-mismatch.json");
        var result = await AgentRunVerifier.VerifyAsync(SignedVectorBundle(run, (PolicyCt, doc)), StubVerify);
        result.Verdict.Should().Be("run_invalid", variant);
        result.EnforcementFindings.Should().ContainSingle().Which.Code.Should().Be("evidence_version_mismatch");
        AgentPolicy.Validate(doc).Should().NotBeEmpty();
    }

    [Fact]
    public async Task ProducerCannotSealAGuardLookingDenial_WithRulesInsteadOfEnforcer()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, PolicyV2Options());
        await run.BeginToolCallAsync("search.web", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        await FluentActions.Awaiting(() => run.RecordAsync("authorization", fields: new JsonObject
        {
            ["decision"] = "denied", ["rules"] = new JsonArray("no-web-search"),
            ["tool"] = new JsonObject { ["name"] = "search.web", ["useId"] = "c1" },
        })).Should().ThrowAsync<ArgumentException>().WithMessage("*reserved*rules*");
    }

    [Fact]
    public async Task ForgingAttempts_AreRefusedBeforeSealing()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, PolicyV2Options());
        await run.BeginToolCallAsync("search.web", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        var before = sealer.Requests.Count;
        var enforcer = new JsonObject { ["engine"] = "cedar-policy@4.14.0", ["factsVersion"] = "2", ["reason"] = "rule" };
        var attempts = new Func<Task>[]
        {
            () => run.FinishAsync("halted"),
            () => run.RecordAsync("run_end"),
            () => run.RecordAsync("Run_end"),
            () => run.RecordAsync("authorization", fields: new JsonObject { ["decision"] = "denied", ["Enforcer"] = enforcer.DeepClone() }),
            () => run.RecordAsync("authorization", fields: new JsonObject { ["decision"] = "denied", ["еnforcer"] = enforcer.DeepClone() }),
            () => run.RecordAsync("human_approval", fields: new JsonObject { ["decision"] = "approved", ["covers"] = new JsonObject { ["tool"] = "x", ["argumentsSha256"] = new string('a', 64) } }),
            () => run.RecordAsync("checkpoint", fields: new JsonObject { ["runDisposition"] = "halted" }),
            () => run.RecordAsync("tool_result", new[] { new AgentRunObject { Role = "tool-definition", Bytes = new byte[] { 1 }, ContentType = "application/json" } },
                new JsonObject { ["tool"] = new JsonObject { ["name"] = "search.web", ["useId"] = "c1" } }),
        };
        foreach (var a in attempts) await FluentActions.Awaiting(a).Should().ThrowAsync<Exception>();
        sealer.Requests.Count.Should().Be(before);
        run.IsBroken.Should().BeFalse();
    }

    [Fact]
    public async Task LoneSurrogateUseId_IsNeverSealed()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, PolicyV2Options());
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("x", Encoding.UTF8.GetBytes("{}"), useId: new string('\uDC00', 300)))
            .Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public void UniqueItems_IsLinear_AndSkippedPastMaxItems()
    {
        var env = LoadV14("findings/f4-executed-after-denial.json")["events"]![2]!["envelope"]!.DeepClone().AsObject();
        env["step"]!["rules"] = new JsonArray(Enumerable.Range(0, 4000).Select(i => (JsonNode?)JsonValue.Create("r" + i)).ToArray());
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var errors = EnvelopeSchema.Validate(env, AgentProfiles.ExecutionSchemaFor(env));
        sw.Elapsed.TotalSeconds.Should().BeLessThan(0.5);
        errors.Should().Contain(e => e.Contains("at most 256 items")).And.NotContain(e => e.Contains("non-unique"));
        env["step"]!["rules"] = new JsonArray("r1", "r1");
        EnvelopeSchema.Validate(env, AgentProfiles.ExecutionSchemaFor(env)).Should().Contain(e => e.Contains("non-unique"));
    }

    [Fact]
    public void Patterns_DoNotMatchBeforeAFinalNewline()
    {
        var env = LoadV14("findings/f4-executed-after-denial.json")["events"]![2]!["envelope"]!.DeepClone().AsObject();
        EnvelopeSchema.Validate(env, AgentProfiles.ExecutionSchemaFor(env)).Should().BeEmpty();
        env["step"]!["enforcer"]!["engine"] = "cedar-policy@4.14.0\n";
        EnvelopeSchema.Validate(env, AgentProfiles.ExecutionSchemaFor(env)).Should().Contain(e => e.Contains("engine"));
    }

    [Fact]
    public async Task TwoThousandEventRun_VerifiesAndBuildsFacts()
    {
        var run = LoadV14("findings/f1-clean.json");
        var src = run["events"]!.AsArray();
        var evs = new JsonArray { src[0]!.DeepClone() };
        for (var i = 0; i < 999; i++)
            foreach (var t in new[] { src[1]!, src[2]! })
            {
                var e = t.DeepClone();
                e["envelope"]!["step"]!["tool"]!["useId"] = "u" + i;
                evs.Add(e);
            }
        evs.Add(src[^1]!.DeepClone());
        for (var i = 0; i < evs.Count; i++)
        {
            evs[i]!["envelope"]!["chain"]!["seq"] = i;
            if (evs[i]!["envelope"]!["step"]!["type"]!.GetValue<string>() == "run_end") evs[i]!["envelope"]!["step"]!["finalSeq"] = i;
        }
        run["events"] = evs;
        var bundle = SignedVectorBundle(run, (PolicyCt, DocV2));
        var v = await AgentRunVerifier.VerifyAsync(bundle, StubVerify);
        v.Verdict.Should().Be("run_finalized", string.Join("\n", v.Findings));
        AgentPolicy.BuildFactsV2(run["agentId"]!.GetValue<string>(), run["correlationId"]!.GetValue<string>(), bundle.Artifacts, DocV2)
            .RunLevel.Should().BeTrue();
    }

    [Fact]
    public void RecordHumanApprovalAsync_KeepsItsSignature_ForCompiledCallers() =>
        typeof(AgentRun).GetMethod(nameof(AgentRun.RecordHumanApprovalAsync), new[]
        {
            typeof(string), typeof(byte[]), typeof(byte[]), typeof(string), typeof(string), typeof(string), typeof(string),
            typeof(System.Threading.CancellationToken),
        }).Should().NotBeNull();

    [Fact]
    public void PreparePolicy_RefusesAV2ControlSet_UntilItsEvaluationIsSpecified()
    {
        var request = new PolicyEvaluationRequest
        {
            CertificateId = VerifierCert, EvaluatorId = "e", EvaluatorVersion = "1",
            ControlArtifact = new AgentRunArtifact(new JsonObject(), new JsonObject(), new Dictionary<string, string>()),
            ControlSetDocument = PolicyControlSetV2VectorTests.Doc, Events = Array.Empty<AgentRunArtifact>(),
            Rules = Array.Empty<PolicyRuleResult>(), PolicyStatus = "unapproved", Engine = "cedar-policy@4.14.0",
        };
        FluentActions.Invoking(() => ControlEvaluation.PreparePolicy(request)).Should().Throw<ArgumentException>().WithMessage("*v2 control set*");
    }

    // The security review's closure proof (v4_times_9999, v4_times_0001, ctl_gen_0001, plus ctl_gen_9999): timestamps and
    // event times at the ends of the representable range give a verdict, never an exception from the seal-time checks.
    [Theory]
    [InlineData("9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z", "9999-12-31T23:59:59.999Z")]
    [InlineData("0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z")]
    [InlineData("0001-01-01T00:00:00Z", "2026-11-02T11:00:00Z", null)]
    [InlineData("9999-12-31T23:59:59Z", "2026-11-02T11:00:00Z", null)]
    public async Task SealTimeChecks_AtTheEndsOfTheRange_GiveAVerdict(string controlGen, string runEndGen, string? eventTime)
    {
        var result = await AgentRunVerifier.VerifyAsync(
            SignedVectorBundle(LoadV14("findings/f1-clean.json"), (PolicyCt, DocV2), controlGen, runEndGen, eventTime), StubVerify);
        result.Verdict.Should().Be("run_finalized", string.Join("\n", result.Findings));
        result.ControlSealedBeforeRun.Should().NotBeNull();
        result.EventTimesPlausible.Should().NotBeNull();
    }

    [Fact]
    public async Task V4Run_RefusesAResultThatNamesAnotherTool_BeforeSealing()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, PolicyV2Options());
        await run.BeginToolCallAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: "c1");
        var before = sealer.Requests.Count;
        const string text = "The tool_call with use_id 'c1' was made to tool 'crm.read_customer'; its result cannot name another tool.";
        await FluentActions.Awaiting(() => run.RecordToolResultAsync("search.web", Encoding.UTF8.GetBytes("{}"), useId: "c1"))
            .Should().ThrowAsync<ArgumentException>().WithMessage(text);
        await FluentActions.Awaiting(() => run.RecordAsync("tool_result",
                new[] { new AgentRunObject { Role = "tool-result", Bytes = new byte[] { 1 }, ContentType = "application/json" } },
                new JsonObject { ["tool"] = new JsonObject { ["name"] = "search.web", ["useId"] = "c1" } }))
            .Should().ThrowAsync<ArgumentException>().WithMessage(text);
        sealer.Requests.Should().HaveCount(before);
        await run.RecordToolResultAsync("crm.read_customer", Encoding.UTF8.GetBytes("{}"), useId: "c1"); // still open, still usable
    }

    [Fact]
    public void UniqueItems_ComparesNumbersByValue()
    {
        var env = LoadV14("findings/f4-executed-after-denial.json")["events"]![2]!["envelope"]!.DeepClone().AsObject();
        string[] Errors(string items)
        {
            var e = (JsonObject)env.DeepClone();
            e["step"]!["rules"] = JsonNode.Parse(items);
            return EnvelopeSchema.Validate(e, AgentProfiles.ExecutionSchemaFor(e)).Where(x => x.Contains("non-unique")).ToArray();
        }
        Errors("[1, 1.0]").Should().ContainSingle();
        Errors("[1, 1e0]").Should().ContainSingle();
        Errors("[0, -0]").Should().ContainSingle();
        Errors("[0, 0.0]").Should().ContainSingle();
        Errors("[1, 2]").Should().BeEmpty();
    }

    [Theory]
    [InlineData("0001-01-01T00:00:00+14:00")]
    [InlineData("9999-12-31T23:59:59-14:00")]
    public async Task EventTimesOutsideYears1To9999_AreInvalidInEverySchemaVersion_AndNeverThrow(string eventTime)
    {
        EnvelopeSchema.TryParseDateTime(eventTime, out _).Should().BeFalse();
        var run = LoadV14("findings/f9-evidence-version-mismatch.json"); // v3 events
        var start = run["events"]![0]!["envelope"]!.AsObject();
        foreach (var version in new[] { "1", "2", "3", "4" })
        {
            var env = (JsonObject)start.DeepClone();
            env["schemaVersion"] = version;
            env["step"]!["eventTime"] = eventTime;
            EnvelopeSchema.Validate(env, AgentProfiles.ExecutionSchemaFor(env)).Should().Contain(e => e.Contains("eventTime"), version);
        }
        run["events"]![1]!["envelope"]!["step"]!["eventTime"] = eventTime;
        var result = await AgentRunVerifier.VerifyAsync(SignedVectorBundle(run, null), StubVerify);
        result.Verdict.Should().Be("run_invalid");
        result.Checks["envelope"].Should().Be("bad");
    }
}
