// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// The guard (Agent Policy Control Set v2 §7, Agent Enforcement v1): vector 14 driven end to end through the recorder with the
// official Cedar core, the incremental facts against the evaluator's, and what a caller sees: denials, halts, refused starts,
// callbacks, the event budget, sealing failures and concurrency.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 2, 10, 0, 0, TimeSpan.Zero);
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    private static byte[] DocV13 => PolicyControlSetV2VectorTests.Doc;

    /// <summary>Vector 14's agent: its id is in AgentGroup "tier1"; its configuration is what lockedConfiguration pins.</summary>
    private static AgentDefinition SupportAgent(string toolManifest = "tool-manifest v1") => new()
    {
        AgentId = "urn:example:agent:support", AgentVersion = "1",
        Configuration = new AgentConfiguration
        {
            InstructionSet = Utf8("instruction-set v1"), ToolManifest = Utf8(toolManifest), ExecutionPolicy = Utf8("execution-policy v1"),
        },
    };

    /// <summary>Vector 14's times: the Control Artifact a second before run_start at T0, then one second per event; the stub TSA reads the same clock.</summary>
    private static (Func<DateTimeOffset> Clock, Func<string> GenTime) VectorClock()
    {
        var t = T0.AddSeconds(-2);
        return (() => t = t.AddSeconds(1), () => t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
    }

    private static AgentRunOptions GuardOptions(byte[] controlSet, IPolicyEngine engine, Action<EnforcementEvent>? onEvent = null) => new()
    {
        CertificateId = Cert, Activity = "support-session", ControlSet = AgentPolicy.ControlSetFromDocument(controlSet),
        Enforcement = new AgentEnforcement(engine) { OnEvent = onEvent },
    };

    private static async Task<(AgentRun Run, StubSealer Sealer, SigillClient Client)> StartGuarded(byte[]? controlSet = null, IPolicyEngine? engine = null,
        Action<EnforcementEvent>? onEvent = null, Func<AgentRunOptions, AgentRunOptions>? with = null)
    {
        var (clock, genTime) = VectorClock();
        var sealer = new StubSealer { GenTime = genTime };
        var client = Client(sealer);
        var options = GuardOptions(controlSet ?? DocV13, engine ?? TestEngine.Shared, onEvent);
        var run = await AgentRun.StartCoreAsync(client, SupportAgent(), with?.Invoke(options) ?? options, clock, CancellationToken.None);
        return (run, sealer, client);
    }

    private static Task<AgentRunVerificationResult> VerifyGuarded(AgentRun run) =>
        AgentRunVerifier.VerifyWithEngineAsync(run.ToBundle(), StubVerify, TestEngine.Shared);

    private static byte[] WithRule(string id, Action<JsonObject> change)
    {
        var doc = JsonNode.Parse(DocV13)!.AsObject();
        change(doc["cedar"]!["policies"]!["staticPolicies"]![id]!.AsObject());
        return Utf8(doc.ToJsonString());
    }

    private static byte[] WithEnforcement(Action<JsonObject> change)
    {
        var doc = JsonNode.Parse(DocV13)!.AsObject();
        change(doc["enforcement"]!.AsObject());
        return Utf8(doc.ToJsonString());
    }

    /// <summary>The Cedar core, except that it fails for the listed actions — or for everything, loading included.</summary>
    private sealed class FailingEngine(IPolicyEngine? inner, IReadOnlyCollection<string>? actions = null) : IPolicyEngine
    {
        public string Version => inner?.Version ?? throw new PolicyEngineException("The policy engine could not be loaded: test");
        public JsonObject Validate(JsonObject call) => inner?.Validate(call) ?? throw new PolicyEngineException("The policy engine could not be loaded: test");
        public JsonObject Authorize(JsonObject call) =>
            inner is null || actions?.Contains(call["action"]!["id"]!.GetValue<string>()) == true
                ? throw new PolicyEngineException("The policy engine failed (cedar_authorize): test trap") : inner.Authorize(call);
    }

    /// <summary>An engine that matches the given rules for each request and validates everything: cheap enough for 2,000 events.</summary>
    private sealed class StubEngine(Func<JsonObject, IEnumerable<string>> matches) : IPolicyEngine
    {
        public string Version => "4.14.0";
        public JsonObject Validate(JsonObject call) => new() { ["type"] = "success", ["validationErrors"] = new JsonArray(), ["validationWarnings"] = new JsonArray() };
        public JsonObject Authorize(JsonObject call)
        {
            var matched = matches(call).ToList();
            return new JsonObject
            {
                ["type"] = "success",
                ["response"] = new JsonObject
                {
                    ["decision"] = matched.Count > 0 ? "deny" : "allow",
                    ["diagnostics"] = new JsonObject
                    {
                        ["reason"] = new JsonArray(matched.Append("sigill:baseline-permit").Select(r => (JsonNode?)r).ToArray()), ["errors"] = new JsonArray(),
                    },
                },
            };
        }
    }

    // ── Vector 14, end to end through the recorder ──

    private static string Rules(IEnumerable<string> rules) => string.Join(",", rules);

    [Theory]
    [MemberData(nameof(GuardRuns))]
    public async Task Vector14_TheGuardSealsTheVectorsRun(string name)
    {
        var source = LoadV14("cases.json");
        var c = source["cases"]!.AsArray().Select(x => x!.AsObject()).Single(x => x["name"]!.GetValue<string>() == name);
        var args = source["arguments"]!.AsObject();
        var vector = LoadV14($"runs/{name}.json");
        var expected = LoadV14($"expected/{name}.json");
        var doc = PolicyEnforcementVectorTests.ControlSetOf(vector);
        var failing = c["actions"]!.AsArray().Where(a => a!["engineFails"]?.GetValue<bool>() == true).Select(a => a!["type"]!.GetValue<string>()).ToList();
        IPolicyEngine engine = c["engineFailsAtStart"]?.GetValue<bool>() == true ? new FailingEngine(null)
            : failing.Count > 0 ? new FailingEngine(TestEngine.Shared, failing) : TestEngine.Shared;
        var definitions = JsonNode.Parse(DocV13)!["cedar"]!["entities"]!.AsArray()
            .Where(e => e!["attrs"]!["definitionSha256"] is not null).Select(e => e!["uid"]!["id"]!.GetValue<string>()).ToHashSet();

        var (clock, genTime) = VectorClock();
        var sealer = new StubSealer { GenTime = genTime };
        using var client = Client(sealer);
        var reported = new List<EnforcementEvent>();
        var raised = new List<string>();
        AgentRun run;
        try
        {
            run = await AgentRun.StartCoreAsync(client, SupportAgent(c["configuration"]?["tool-manifest"]?.GetValue<string>() ?? "tool-manifest v1"),
                GuardOptions(doc, engine, reported.Add), clock, CancellationToken.None);
        }
        catch (StartRefusedException e)
        {
            run = e.Run;
            raised.Add($"start_refused:{e.Reason}");
        }

        var calls = new Dictionary<string, ToolCall>();
        var notExecuted = new List<string>();
        var discarded = 0;
        foreach (var a in c["actions"]!.AsArray().Select(x => x!.AsObject()))
        {
            var type = a["type"]!.GetValue<string>();
            var useId = a["useId"]?.GetValue<string>();
            var tool = a["tool"]?.GetValue<string>();
            async Task Act()
            {
                switch (type)
                {
                    case "tool_call":
                        var definition = a.ContainsKey("definition") ? (a["definition"] is { } d ? Utf8(d.GetValue<string>()) : null)
                            : definitions.Contains(tool!) ? Utf8($"{tool} definition") : null;
                        calls[useId!] = await run.BeginToolCallAsync(tool!, Utf8(args[a["args"]!.GetValue<string>()]!.GetValue<string>()),
                            consequential: a["consequential"]?.GetValue<bool>() == true, useId: useId, definition: definition);
                        break;
                    case "tool_result":
                        if (calls.TryGetValue(useId!, out var call)) await call.CompleteAsync(Utf8("""{"ok":true}"""));
                        else await run.RecordToolResultAsync(tool!, Utf8("""{"ok":true}"""), useId: useId);
                        break;
                    case "human_approval":
                        var cv = a["covers"]!;
                        var expires = cv["expiresAt"]?.GetValue<string>() is { } x ? DateTimeOffset.Parse(x, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal) : (DateTimeOffset?)null;
                        await run.RecordHumanApprovalAsync(a["decision"]!.GetValue<string>(), receipt: Utf8("{}"), approver: "urn:example:approver:1",
                            covers: new ApprovalCovers(cv["tool"]!.GetValue<string>(), EnvelopeHashing.HashHex(Utf8(args[cv["args"]!.GetValue<string>()]!.GetValue<string>())),
                                cv["useId"]?.GetValue<string>(), expires));
                        break;
                    case "retrieval": await run.RecordRetrievalAsync(Utf8("context")); break;
                    case "model_output": await run.RecordModelOutputAsync(Utf8("output")); break;
                    case "delegation": await run.DelegateAsync(a["childAgentId"]!.GetValue<string>(), Utf8("""{"task":"review"}""")); break;
                    case "delegation_result":
                        var child = run.Artifacts.Last(e => e.StepType == "delegation").Envelope["step"]!["delegation"]!["childCorrelationId"]!.GetValue<string>();
                        await run.CompleteDelegationAsync(child, new string('a', 64), "completed");
                        break;
                    case "run_end": await run.FinishAsync(); break;
                    default: throw new InvalidOperationException(type);
                }
            }

            if (run.IsHalted)
            {
                // Every action after a halt is refused; finishing returns the bundle and seals nothing.
                discarded++;
                var before = sealer.Requests.Count;
                if (type == "run_end") (await run.FinishAsync()).Artifacts.Should().HaveCount(run.Artifacts.Count);
                else await FluentActions.Awaiting(Act).Should().ThrowAsync<RunHaltedException>();
                sealer.Requests.Should().HaveCount(before);
                continue;
            }
            if (type == "tool_result" && !calls.ContainsKey(useId!))
            {
                notExecuted.Add(useId!);
                await FluentActions.Awaiting(Act).Should().ThrowAsync<ArgumentException>().WithMessage($"The tool_call with use_id '{useId}' was denied; it has no result.");
                continue;
            }
            try { await Act(); }
            catch (PolicyDeniedException e) { raised.Add($"{(e.Halted ? "halted" : "denied")}:tool_call:{e.UseId}:{e.Reason}:{Rules(e.Rules)}"); }
            catch (RunHaltedException e) { raised.Add($"halted:{run.Artifacts[e.Seq].StepType}:{e.Seq}:{e.Reason}:{Rules(e.Rules)}"); }
        }

        // The chain: the vector's step types, and every guard event equal in what the guard decides.
        var produced = run.Artifacts;
        var want = vector["events"]!.AsArray().Select(e => e!["envelope"]!["step"]!.AsObject()).ToList();
        produced.Select(a => a.StepType).Should().Equal(want.Select(s => s["type"]!.GetValue<string>()));
        static string Decided(JsonNode step) => new JsonObject(new[] { "decision", "tool", "rules", "enforcer", "runDisposition" }
            .Where(k => step[k] is not null).Select(k => KeyValuePair.Create(k, (JsonNode?)step[k]!.DeepClone()))).ToJsonString();
        for (var i = 0; i < want.Count; i++)
            if (want[i]["type"]!.GetValue<string>() is "authorization" or "run_end")
                Decided(produced[i].Envelope["step"]!).Should().Be(Decided(want[i]), $"seq {i}");
        run.IsHalted.Should().Be(want[^1]["runDisposition"]!.GetValue<string>() == "halted");

        // What the producer was told, per decided event.
        var outcomes = expected["events"]!.AsArray().Where(e => e!["sealedBy"]!.GetValue<string>() == "producer"
            && e["outcome"]?.GetValue<string>() is "denied" or "halted").Select(e =>
        {
            var seq = e!["seq"]!.GetValue<int>();
            var type = e["type"]!.GetValue<string>();
            var rules = Rules(e["rules"]?.AsArray().Select(r => r!.GetValue<string>()) ?? Array.Empty<string>());
            var reason = e["reason"]!.GetValue<string>();
            return type == "run_start" ? $"start_refused:{reason}"
                : type == "tool_call" ? $"{e["outcome"]!.GetValue<string>()}:tool_call:{want[seq]["tool"]!["useId"]!.GetValue<string>()}:{reason}:{rules}"
                : $"halted:{type}:{seq}:{reason}:{rules}";
        }).ToList();
        raised.Should().Equal(outcomes);
        reported.Where(e => e.Kind != "observed").Select(e => e.Kind).Should().Equal(outcomes.Select(o => o.Split(':')[0]));
        notExecuted.Should().Equal(expected["notExecuted"]!.AsArray().Select(u => u!.GetValue<string>()));
        discarded.Should().Be(expected["discarded"]!.GetValue<int>());

        // The run's facts are the vector's requests, event by event.
        var facts = JsonNode.Parse(AgentPolicy.BuildFactsV2(SupportAgent().AgentId, run.CorrelationId, produced, doc).Bytes)!["requests"]!.AsArray();
        var requests = expected["events"]!.AsArray().Select(e => e!["request"]!).ToList();
        for (var i = 0; i < requests.Count; i++)
        {
            var r = facts[i]!.DeepClone().AsObject();
            r.Remove("seq");
            Jcs(r).Should().Be(Jcs(requests[i]), $"request {i}");
        }

        var verdict = await VerifyGuarded(run);
        verdict.Verdict.Should().Be("run_finalized", string.Join("\n", verdict.Findings));
        verdict.Checks["enforcement"].Should().Be("ok");
        verdict.EnforcementFindings.Should().BeEmpty();
        verdict.Findings.Should().BeEmpty();
    }

    private static string Jcs(JsonNode n) => Encoding.UTF8.GetString(AgentProfiles.Canonical(n));

    [Theory]
    [MemberData(nameof(GuardRuns))]
    public void IncrementalFacts_AreTheEvaluatorsRequest_ForEveryEvent(string name)
    {
        var run = LoadV14($"runs/{name}.json");
        var expected = LoadV14($"expected/{name}.json")["events"]!.AsArray();
        var doc = PolicyEnforcementVectorTests.ControlSetOf(run);
        var agentId = run["agentId"]!.GetValue<string>();
        var events = run["events"]!.AsArray().Select(e => new AgentRunArtifact(e!["envelope"]!.DeepClone().AsObject(), new JsonObject(),
            e["objectDigests"]!.AsObject().ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>()))).ToList();
        var state = new AgentPolicy.FactsState(agentId, v2: true, isChildRun: false);
        for (var i = 0; i < events.Count; i++)
        {
            var incremental = state.Next(i, events[i].Envelope, events[i].ObjectDigests);
            var batch = JsonNode.Parse(AgentPolicy.BuildFactsV2(agentId, run["correlationId"]!.GetValue<string>(), events.Take(i + 1), doc).Bytes)!["requests"]![i]!;
            Jcs(incremental).Should().Be(Jcs(batch), $"{name} seq {i}");
            incremental.Remove("seq");
            Jcs(incremental).Should().Be(Jcs(expected[i]!["request"]!), $"{name} seq {i}");
        }
    }

    // ── Switching it on ──

    [Fact]
    public async Task EnforcingControlSet_WithoutEnforcement_IsACallerError_AndNothingIsSealed()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(),
                GuardOptions(DocV13, TestEngine.Shared) with { Enforcement = null }, Clock(), CancellationToken.None))
            .Should().ThrowAsync<ArgumentException>().WithMessage("The control set enforces its policy: pass enforcement with a policy engine.*");
        sealer.Requests.Should().BeEmpty();
    }

    [Theory]
    [InlineData("enforce")]
    [InlineData("observe")]
    public async Task WithEnforcement_TheControlSetIsValidatedStrictly_BeforeAnythingIsSealed(string mode)
    {
        var doc = Encoding.UTF8.GetString(WithEnforcement(e => e["mode"] = mode)).Replace("\"attr\":\"callsOfThisTool\"", "\"attr\":\"callsOfThatTool\"");
        AgentPolicy.Validate(Utf8(doc)).Should().BeEmpty();
        var sealer = new StubSealer();
        using var client = Client(sealer);
        await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(), GuardOptions(Utf8(doc), TestEngine.Shared), Clock(), CancellationToken.None))
            .Should().ThrowAsync<ArgumentException>().WithMessage("Invalid policy control set: *strict mode*");
        sealer.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task ObserveModeAndV1ControlSets_SealNoRecord_NeverRaise_AndReportMatches()
    {
        var reported = new List<EnforcementEvent>();
        var (run, _, client) = await StartGuarded(ObserveV2Doc, onEvent: reported.Add);
        using (client)
        {
            var call = await run.BeginToolCallAsync("search.web", Utf8("""{"q":"x"}"""));      // denied in enforce mode
            await call.CompleteAsync(Utf8("{}"));
            await run.RecordRetrievalAsync(Utf8("context"));
            await run.InvokeToolAsync("fs.delete", Utf8("{}"), _ => Task.FromResult(Utf8("{}")));    // an unknown tool
            await run.FinishAsync();
            run.Artifacts.Should().NotContain(a => a.StepType == "authorization");
            reported.Should().ContainSingle().Which.Should().Be(new EnforcementEvent("observed", null, reported[0].Rules, "search.web", call.UseId, call.Artifact.Seq!.Value));
            reported[0].Rules.Should().Equal("no-web-search");
            (await VerifyGuarded(run)).Verdict.Should().Be("run_finalized");
        }

        var v1 = File.ReadAllBytes(Path.Combine(SpecRoot.TestVectorsDir, "11-policy-control-set", "control-set.json"));
        var sealer = new StubSealer();
        using var c1 = Client(sealer);
        var r1 = await AgentRun.StartCoreAsync(c1, Agent(), Options() with
        {
            ControlSet = AgentPolicy.ControlSetFromDocument(v1), Enforcement = new AgentEnforcement(TestEngine.Shared),
        }, Clock(), CancellationToken.None);
        await r1.RecordToolCallAsync("crm.delete_customer", Utf8("{}"), operation: "delete", consequential: true);
        await r1.RecordToolCallAsync("search.web", Utf8("{}"));
        var bundle = await r1.FinishAsync();
        bundle.Artifacts.Should().OnlyContain(a => a.StepType != "authorization" && a.Envelope["schemaVersion"]!.GetValue<string>() == "1");
    }

    [Fact]
    public async Task AShadowRule_IsReportedThroughOnEventOnly()
    {
        var reported = new List<EnforcementEvent>();
        var (run, _, client) = await StartGuarded(onEvent: reported.Add);
        using var owned = client;
        var definition = Utf8("crm.read_customer definition");
        await run.InvokeToolAsync("crm.read_customer", Utf8("{}"), _ => Task.FromResult(Utf8("{}")), definition: definition);
        var second = await run.BeginToolCallAsync("crm.read_customer", Utf8("{}"), definition: definition);
        reported.Should().ContainSingle().Which.Should().Match<EnforcementEvent>(e =>
            e.Kind == "observed" && e.Rules.SequenceEqual(new[] { "shadow-repeat-read" }) && e.Seq == second.Artifact.Seq);
        run.Artifacts.Should().NotContain(a => a.StepType == "authorization");
    }

    // ── What the caller sees ──

    [Fact]
    public async Task ApprovalFlow_DeniedThenApprovedWithCovers_ThenTheRetryIsAllowed()
    {
        var reported = new List<EnforcementEvent>();
        var (run, sealer, client) = await StartGuarded(onEvent: reported.Add);
        using var owned = client;
        var ran = 0;
        Task<byte[]> Refund(CancellationToken ct) { ran++; return Task.FromResult(Utf8("""{"ok":true}""")); }

        var denied = (await FluentActions.Awaiting(() => run.InvokeToolAsync("payments.refund", RefundArgs, Refund, consequential: true, useId: "refund-1"))
            .Should().ThrowAsync<PolicyDeniedException>()).Which;
        (denied.Reason, denied.Tool, denied.UseId, denied.Halted, denied.Seq).Should().Be(("rule", "payments.refund", "refund-1", false, 1));
        denied.Rules.Should().Equal("restricted-needs-bound-approval");
        denied.Record.Should().BeSameAs(run.Artifacts[2]);
        denied.Message.Should().Be("The policy denied the call of tool 'payments.refund' (use_id 'refund-1', seq 1): reason rule, rules restricted-needs-bound-approval.");
        ran.Should().Be(0);
        reported.Should().Equal(new EnforcementEvent("denied", "rule", reported[0].Rules, "payments.refund", "refund-1", 1));

        // A denied call has no result, on every path; the run stays usable.
        var before = sealer.Requests.Count;
        await FluentActions.Awaiting(() => run.RecordToolResultAsync("payments.refund", Utf8("{}"), useId: "refund-1"))
            .Should().ThrowAsync<ArgumentException>().WithMessage("The tool_call with use_id 'refund-1' was denied; it has no result.");
        await FluentActions.Awaiting(() => run.RecordAsync("tool_result", new[] { new AgentRunObject { Role = "tool-result", Bytes = new byte[] { 1 }, ContentType = "application/json" } },
            new JsonObject { ["tool"] = new JsonObject { ["name"] = "payments.refund", ["useId"] = "refund-1" } })).Should().ThrowAsync<ArgumentException>();
        sealer.Requests.Should().HaveCount(before);

        await run.RecordHumanApprovalAsync("approved", approver: "urn:example:approver:7", covers: ApprovalCovers.ForArguments("payments.refund", RefundArgs));
        (await run.InvokeToolAsync("payments.refund", RefundArgs, Refund, consequential: true)).Should().Equal(Utf8("""{"ok":true}"""));
        ran.Should().Be(1);
        run.IsHalted.Should().BeFalse();
        await run.FinishAsync();
        var verdict = await VerifyGuarded(run);
        verdict.Verdict.Should().Be("run_finalized", string.Join("\n", verdict.Findings));
        verdict.Checks["enforcement"].Should().Be("ok");
    }

    [Fact]
    public async Task AHaltOnANonToolEvent_RaisesRunHalted_AndEveryLaterCallToo_AndFinishReturnsTheBundle()
    {
        var reported = new List<EnforcementEvent>();
        var (run, sealer, client) = await StartGuarded(onEvent: reported.Add);
        using var owned = client;
        var cancelled = false;
        using var registration = run.HaltedToken.Register(() => cancelled = true);
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>();
        run.HaltedToken.IsCancellationRequested.Should().BeFalse("a denial alone does not halt");

        var halted = (await FluentActions.Awaiting(() => run.RecordRetrievalAsync(Utf8("context"))).Should().ThrowAsync<RunHaltedException>()).Which;
        (halted.Reason, halted.Seq).Should().Be(("rule", 3));
        halted.Rules.Should().Equal("halt-retrieval-after-denial");
        halted.Message.Should().Be("The policy halted the run at seq 3: reason rule, rules halt-retrieval-after-denial.");
        (run.IsHalted, run.IsFinished, run.IsBroken, cancelled).Should().Be((true, true, false, true));
        reported.Select(e => e.Kind).Should().Equal("denied", "halted");

        var before = sealer.Requests.Count;
        foreach (var attempt in new Func<Task>[]
        {
            () => run.BeginToolCallAsync("crm.update_address", Utf8("{}")), () => run.RecordModelOutputAsync(Utf8("x")),
            () => run.CheckpointAsync(), () => run.DelegateAsync("urn:example:agent:reviewer"),
            () => run.InvokeToolAsync("crm.update_address", Utf8("{}"), _ => throw new InvalidOperationException("must not run")),
        })
            (await FluentActions.Awaiting(attempt).Should().ThrowAsync<RunHaltedException>()).Which.Seq.Should().Be(3);
        var bundle = await run.FinishAsync("completed");
        sealer.Requests.Should().HaveCount(before);
        bundle.Artifacts[^1].Envelope["step"]!["runDisposition"]!.GetValue<string>().Should().Be("halted");
        bundle.Artifacts.Should().HaveCount(6);
        (await VerifyGuarded(run)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task HaltAfterDenials_TheDenialThatReachesTheLimitHalts()
    {
        var (run, _, client) = await StartGuarded(WithEnforcement(e => e["haltAfterDenials"] = 2));
        using var owned = client;
        (await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>()).Which.Halted.Should().BeFalse();
        var second = (await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>()).Which;
        second.Halted.Should().BeTrue();
        second.Message.Should().EndWith("reason rule, rules no-web-search; the run is halted.");
        run.Artifacts.Select(a => a.StepType).Should().Equal("run_start", "tool_call", "authorization", "tool_call", "authorization", "run_end");
    }

    [Fact]
    public async Task AHaltRuleOnDelegation_HaltsTheParent_AndAChildOfAHaltedParentIsNotStarted()
    {
        // no-delegation as deny has no effect on a delegation (§7.3), so the run delegates; it halts later.
        var (run, sealer, client) = await StartGuarded(WithRule("no-delegation", r => r["annotations"]!["effect"] = "deny"));
        using var owned = client;
        var delegation = await run.DelegateAsync("urn:example:agent:reviewer");
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>();
        await FluentActions.Awaiting(() => run.RecordRetrievalAsync(Utf8("context"))).Should().ThrowAsync<RunHaltedException>();
        var before = sealer.Requests.Count;
        await FluentActions.Awaiting(() => AgentRun.StartChildAsync(client, SupportAgent() with { AgentId = "urn:example:agent:reviewer" },
            GuardOptions(DocV13, TestEngine.Shared), delegation)).Should().ThrowAsync<RunHaltedException>();
        await FluentActions.Awaiting(() => run.CompleteDelegationAsync(delegation.ChildCorrelationId, new string('a', 64), "aborted"))
            .Should().ThrowAsync<RunHaltedException>();
        sealer.Requests.Should().HaveCount(before);

        // Under vector 13's control set the delegation itself halts the run, and no delegation is handed out (vector case 30).
        var (halting, _, c2) = await StartGuarded();
        using var owned2 = c2;
        await FluentActions.Awaiting(() => halting.DelegateAsync("urn:example:agent:reviewer")).Should().ThrowAsync<RunHaltedException>()
            .Where(e => e.Rules.SequenceEqual(new[] { "no-delegation" }));
    }

    [Theory]
    [InlineData("locked")]
    [InlineData("engine")]
    public async Task ARefusedStart_SealsTheRefusal_AndHandsBackTheClosedRun(string why)
    {
        var reported = new List<EnforcementEvent>();
        var (clock, genTime) = VectorClock();
        var sealer = new StubSealer { GenTime = genTime };
        using var client = Client(sealer);
        var refused = (await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(why == "locked" ? "tool-manifest v2" : "tool-manifest v1"),
            GuardOptions(DocV13, why == "locked" ? TestEngine.Shared : new FailingEngine(null), reported.Add), clock, CancellationToken.None))
            .Should().ThrowAsync<StartRefusedException>()).Which;
        var reason = why == "locked" ? "configuration_locked" : "unavailable";
        refused.Reason.Should().Be(reason);
        refused.Message.Should().Be($"The policy refused the start of the run: reason {reason}.");
        refused.Run.IsHalted.Should().BeTrue();
        refused.Run.Artifacts.Select(a => a.StepType).Should().Equal("run_start", "authorization", "run_end");
        refused.Run.Artifacts[1].Envelope["step"]!["enforcer"]!["engine"]!.GetValue<string>().Should().Be("cedar-policy@4.14.0");
        reported.Should().Equal(new EnforcementEvent("start_refused", reason, Array.Empty<string>(), null, null, 0));
        reported[0].Rules.Should().BeEmpty();
        var before = sealer.Requests.Count;
        (await refused.Run.FinishAsync()).Artifacts.Should().HaveCount(3);
        sealer.Requests.Should().HaveCount(before);
        (await VerifyGuarded(refused.Run)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task EngineFailureMidRun_IsUnavailable_AndHalts()
    {
        var (run, _, client) = await StartGuarded(engine: new FailingEngine(TestEngine.Shared, new[] { "tool_call" }));
        using var owned = client;
        var e = (await FluentActions.Awaiting(() => run.BeginToolCallAsync("crm.update_address", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>()).Which;
        (e.Reason, e.Halted, e.Rules.Count).Should().Be(("unavailable", true, 0));
        run.IsHalted.Should().BeTrue();
        (await VerifyGuarded(run)).Checks["enforcement"].Should().Be("ok");
    }

    [Theory]
    [InlineData(0)]   // the tool_call itself
    [InlineData(1)]   // the enforcement record after it
    [InlineData(2)]   // the halting run_end after the record
    public async Task ASealingFailure_BreaksTheRun_AndTheToolNeverRuns(int failAt)
    {
        var sealedSeqs = new List<int?>();
        var (run, sealer, client) = await StartGuarded(WithEnforcement(e => e["haltAfterDenials"] = 1),
            with: o => o with { OnArtifactSealed = (a, _) => { sealedSeqs.Add(a.Seq); return Task.CompletedTask; } });
        using var owned = client;
        sealer.FailOnCall = sealer.Requests.Count + failAt;
        var ran = false;
        var thrown = (await FluentActions.Awaiting(() => run.InvokeToolAsync("search.web", Utf8("{}"), _ => { ran = true; return Task.FromResult(Utf8("{}")); }))
            .Should().ThrowAsync<Exception>()).Which;
        thrown.Should().NotBeOfType<PolicyDeniedException>();
        ran.Should().BeFalse();
        (run.IsBroken, run.IsHalted).Should().Be((true, false));
        run.Artifacts.Should().HaveCount(1 + failAt);
        sealedSeqs.Should().Equal(Enumerable.Range(-1, 1 + failAt + 1).Select(i => (int?)(i == -1 ? null : i)), "every sealed event is delivered");
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("crm.update_address", Utf8("{}"))).Should().ThrowAsync<InvalidOperationException>();
        await FluentActions.Awaiting(() => run.FinishAsync()).Should().ThrowAsync<InvalidOperationException>();
    }

    [Fact]
    public async Task ConcurrentCalls_EveryRecordDirectlyFollowsItsCall()
    {
        var (run, _, client) = await StartGuarded();
        using var owned = client;
        var definition = Utf8("crm.update_address definition");
        var attempts = Enumerable.Range(0, 32).Select(i => Task.Run(() => i % 2 == 0
            ? run.BeginToolCallAsync("search.web", Utf8($$"""{"q":{{i}}}"""), useId: $"c{i}")
            : run.BeginToolCallAsync("crm.update_address", Utf8($$"""{"n":{{i}}}"""), definition: definition, useId: $"c{i}"))).ToList();
        try { await Task.WhenAll(attempts); } catch (PolicyDeniedException) { }
        attempts.Count(t => t.IsFaulted && t.Exception!.InnerException is PolicyDeniedException).Should().Be(16);
        attempts.Count(t => t.Status == TaskStatus.RanToCompletion).Should().Be(16);
        var events = run.Artifacts;
        events.Count(a => a.StepType == "authorization").Should().Be(16);
        foreach (var record in events.Where(a => a.StepType == "authorization"))
        {
            var call = events[record.Seq!.Value - 1];
            call.StepType.Should().Be("tool_call");
            call.Envelope["step"]!["tool"]!.ToJsonString().Should().Be(record.Envelope["step"]!["tool"]!.ToJsonString());
        }
        await run.FinishAsync();
        var verdict = await VerifyGuarded(run);
        verdict.Verdict.Should().Be("run_finalized", string.Join("\n", verdict.Findings));
        verdict.EnforcementFindings.Should().BeEmpty();
    }

    [Fact]
    public async Task Callbacks_RunInSealOrder_BeforeTheDenialIsRaised_AndAFailingOneNeverHidesIt()
    {
        var order = new List<string>();
        var failEvent = false;
        var (run, _, client) = await StartGuarded(onEvent: e => { order.Add($"event:{e.Kind}:{e.Seq}"); if (failEvent) throw new InvalidOperationException("callback failed"); },
            with: o => o with { OnArtifactSealed = (a, _) => { order.Add($"sealed:{a.Seq}"); return Task.CompletedTask; } });
        using var owned = client;
        try { await run.BeginToolCallAsync("search.web", Utf8("{}")); }
        catch (PolicyDeniedException) { order.Add("raised"); }
        order.Should().Equal("sealed:", "sealed:0", "sealed:1", "sealed:2", "event:denied:1", "raised");

        failEvent = true;
        var denied = (await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>()).Which;
        denied.InnerException.Should().BeOfType<InvalidOperationException>().Which.Message.Should().Be("callback failed");
        run.IsBroken.Should().BeFalse();
        // After an allowed event a failing callback propagates as an OnArtifactSealed failure does; the event is sealed.
        var definition = Utf8("crm.read_customer definition");
        await run.BeginToolCallAsync("crm.read_customer", Utf8("{}"), definition: definition);
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("crm.read_customer", Utf8("{}"), definition: definition))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("callback failed");
        run.Artifacts[^1].StepType.Should().Be("tool_call");
        await run.FinishAsync();
    }

    [Fact]
    public async Task MessagesAndEvents_NeverCarryArgumentsOrResults()
    {
        var reported = new List<EnforcementEvent>();
        var (run, sealer, client) = await StartGuarded(onEvent: reported.Add);
        using var owned = client;
        var secret = Utf8("""{"amount":120,"note":"SECRET-4411 Jane Doe"}""");
        var messages = new List<string>();
        try { await run.InvokeToolAsync("payments.refund", secret, _ => Task.FromResult(secret), consequential: true); }
        catch (PolicyDeniedException e) { messages.Add(e.Message); messages.AddRange(e.Rules); }
        await run.InvokeToolAsync("crm.update_address", secret, _ => Task.FromResult(secret), definition: Utf8("crm.update_address definition"));
        await run.BeginToolCallAsync("search.web", secret).ContinueWith(t => messages.Add(t.Exception!.InnerException!.Message));
        try { await run.RecordRetrievalAsync(secret); }
        catch (RunHaltedException e) { messages.Add(e.Message); }
        messages.Should().HaveCount(4);
        var everything = string.Join("\n", messages.Concat(reported.Select(e => e.ToString())).Concat(run.Artifacts.Select(a => a.Envelope.ToJsonString()))
            .Concat(sealer.Requests.Select(r => r.ToJsonString())));
        everything.Should().NotContain("SECRET").And.NotContain("Jane");
    }

    // ── The event budget ──

    [Fact]
    public async Task EventBudget_KeepsRoomForARecordAndAHalt()
    {
        var (run, _, client) = await StartGuarded(engine: new StubEngine(_ => Array.Empty<string>()));
        using (client)
        {
            while (run.Artifacts.Count < AgentRunBundle.MaxArtifacts - 2) await run.RecordModelOutputAsync(Utf8("x"));
            await FluentActions.Awaiting(() => run.RecordModelOutputAsync(Utf8("x"))).Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("The run has 1998 events; the rest of the bundle limit of 2000 is reserved for run_end, the guard's enforcement record(s) and 0 delegation result(s).");
            (await run.FinishAsync()).Artifacts.Should().HaveCount(AgentRunBundle.MaxArtifacts - 1);
        }

        // The last event the budget admits halts the run: its record and run_end still fit.
        var (halting, _, c2) = await StartGuarded(engine: new StubEngine(call =>
            call["action"]!["id"]!.GetValue<string>() == "retrieval" ? new[] { "halt-retrieval-after-denial" } : Array.Empty<string>()));
        using var owned2 = c2;
        while (halting.Artifacts.Count < AgentRunBundle.MaxArtifacts - 3) await halting.RecordModelOutputAsync(Utf8("x"));
        await FluentActions.Awaiting(() => halting.RecordRetrievalAsync(Utf8("x"))).Should().ThrowAsync<RunHaltedException>();
        var bundle = await halting.FinishAsync();
        bundle.Artifacts.Should().HaveCount(AgentRunBundle.MaxArtifacts);
        var verdict = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(bundle.ToJsonString()), StubVerify);
        verdict.Verdict.Should().Be("run_finalized", string.Join("\n", verdict.Findings));
    }

    [Fact]
    public async Task EventBudget_ADeniedCallThenAHaltingDelegationResult_StillFits()
    {
        // A tool_call keeps room for its record and a halt: with one slot only, the denied call below would leave the halting
        // delegation_result (never budget-checked) a record and a run_end beyond the bundle limit.
        var (run, _, client) = await StartGuarded(engine: new StubEngine(call => call["action"]!["id"]!.GetValue<string>() switch
        {
            "tool_call" => new[] { "no-web-search" }, "delegation_result" => new[] { "no-delegation" }, _ => Array.Empty<string>(),
        }));
        using var owned = client;
        var delegation = await run.DelegateAsync("urn:example:agent:reviewer");
        while (run.Artifacts.Count < AgentRunBundle.MaxArtifacts - 4) await run.RecordModelOutputAsync(Utf8("x"));
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("The run has 1996 events; the rest of the bundle limit of 2000 is reserved for run_end, the guard's enforcement record(s) and 1 delegation result(s).");
        await run.RecordModelOutputAsync(Utf8("x"));   // any other event still has its one slot
        await FluentActions.Awaiting(() => run.CompleteDelegationAsync(delegation.ChildCorrelationId, new string('a', 64), "aborted"))
            .Should().ThrowAsync<RunHaltedException>();
        var bundle = await run.FinishAsync();
        bundle.Artifacts.Should().HaveCount(AgentRunBundle.MaxArtifacts);
        (await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(bundle.ToJsonString()), StubVerify)).Verdict.Should().Be("run_finalized");
    }

    [Fact]
    public async Task TheProducersRunEnd_IsNotEvaluated()
    {
        var actions = new List<string>();
        var (run, _, client) = await StartGuarded(engine: new StubEngine(call =>
        {
            actions.Add(call["action"]!["id"]!.GetValue<string>());
            return new[] { "no-unpaired-consequential" };   // matches everything evaluated: each evaluation is reported
        }), onEvent: e => actions.Add("observed:" + e.Seq));
        using var owned = client;
        await run.FinishAsync();
        actions.Should().Equal("run_start", "run_start", "observed:0");   // strict validation's entity check, then run_start; no run_end
    }

    // ── Model calls ──

    private sealed class CountingProvider(string body) : HttpMessageHandler
    {
        public int Sent { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Sent++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    [Fact]
    public async Task AHaltOnARecordedModelCall_ReachesTheCaller_AndNoFurtherModelCallIsSent()
    {
        var (run, _, client) = await StartGuarded(engine: new FailingEngine(TestEngine.Shared, new[] { "model_output" }),
            with: o => o with { RecordsModelCalls = true });
        using var owned = client;
        var errors = new List<Exception>();
        var provider = new CountingProvider("""{"id":"msg_01","type":"message","model":"claude-sonnet-5","usage":{"input_tokens":1,"output_tokens":1}}""");
        using var http = new HttpClient(new ModelCallHandler(run, provider, errors.Add));
        Task<HttpResponseMessage> Post() => http.PostAsync("https://api.anthropic.com/v1/messages", new StringContent("""{"model":"claude-sonnet-5"}""", Encoding.UTF8, "application/json"));
        (await FluentActions.Awaiting(Post).Should().ThrowAsync<RunHaltedException>()).Which.Reason.Should().Be("unavailable");
        await FluentActions.Awaiting(Post).Should().ThrowAsync<RunHaltedException>();
        provider.Sent.Should().Be(1);
        errors.Should().BeEmpty();
        run.Artifacts.Select(a => a.StepType).Should().Equal("run_start", "model_output", "authorization", "run_end");
    }
}
