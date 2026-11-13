// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// The guard after its code and security reviews: malformed engine answers fail closed, an engine failing at start refuses
// it, the start gate checks the sealed bytes, the engine cannot change later decisions, a guard fault breaks the run,
// delegation equality, and the parity tests shared with the Python port.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    /// <summary>Answers a <c>tool_call</c> of search.web with <paramref name="answer"/> (a fresh copy each time), everything else well formed.</summary>
    private sealed class ShapeEngine(string? answer, bool validateRaises = false) : IPolicyEngine
    {
        public string Version => "4.14.0";

        public JsonObject Validate(JsonObject call) => validateRaises ? throw new PolicyEngineException("validate trapped")
            : new JsonObject { ["type"] = "success", ["validationErrors"] = new JsonArray(), ["validationWarnings"] = new JsonArray() };

        public JsonObject Authorize(JsonObject call) =>
            call["policies"]!["staticPolicies"]!.AsObject().Count == 0 ? ProbeAnswer()
            : call["action"]!["id"]!.GetValue<string>() == "tool_call" && call["resource"]!["id"]!.GetValue<string>() == "search.web"
                ? (answer is null ? null! : JsonNode.Parse(answer)!.AsObject())
                : JsonNode.Parse("""{"type":"success","response":{"decision":"allow","diagnostics":{"reason":["sigill:baseline-permit"],"errors":[]}}}""")!.AsObject();
    }

    // H1: one shape only. (An answer that is a JSON array cannot be expressed: IPolicyEngine returns a JsonObject; a response
    // that is an array is the nearest case.)
    public static IEnumerable<object?[]> MalformedAnswers() => new[]
    {
        """{"type":"success","response":{"diagnostics":{"reason":"no-web-search","errors":[]}}}""",
        """{"type":"success","response":{"diagnostics":{"reason":{"no-web-search":1},"errors":[]}}}""",
        """{"type":"success","response":{"diagnostics":{"reason":["no-web-search",5],"errors":[]}}}""",
        """{"type":"success","response":{"diagnostics":{"errors":[]}}}""",
        """{"type":"success","response":{"diagnostics":{"reason":[],"errors":"no-web-search"}}}""",
        """{"type":"success","response":{"diagnostics":{"reason":[],"errors":["no-web-search"]}}}""",
        """{"type":"success","response":{"diagnostics":{"reason":[],"errors":[{"policyId":5}]}}}""",
        """{"type":"success","response":{}}""",
        """{"type":"success"}""",
        """{"type":"ok","response":{"diagnostics":{"reason":["no-web-search"],"errors":[]}}}""",
        """{"type":"success","response":[]}""",
        """{"type":"success","response":{"diagnostics":{"reason":[],"errors":[]}}}""",
        """{"type":"success","response":{"decision":"permit","diagnostics":{"reason":[],"errors":[]}}}""",
        """{"type":"success","response":{"decision":"deny","diagnostics":{"reason":["sigill:baseline-permit"],"errors":[]}}}""",
        """{"type":"success","response":{"decision":"allow","diagnostics":{"reason":["no-web-search","sigill:baseline-permit"],"errors":[]}}}""",
        // R1: an id that is not a policy of the call.
        """{"type":"success","response":{"decision":"deny","diagnostics":{"reason":["nonexistent-rule","sigill:baseline-permit"],"errors":[]}}}""",
        """{"type":"success","response":{"decision":"allow","diagnostics":{"reason":["nonexistent-rule","sigill:baseline-permit"],"errors":[]}}}""",
        """{"type":"success","response":{"decision":"allow","diagnostics":{"reason":["sigill:baseline-permit"],"errors":[{"policyId":"nonexistent-rule","error":{"message":"x"}}]}}}""",
        null,
    }.Select(a => new object?[] { a });

    [Theory]
    [MemberData(nameof(MalformedAnswers))]
    public async Task AMalformedEngineAnswer_IsUnavailable_TheCallIsDenied_AndTheRunHalts(string? answer)
    {
        var engine = new ShapeEngine(answer);
        var (run, _, client) = await StartGuarded(engine: engine);
        using var owned = client;
        var ran = false;
        var denied = (await FluentActions.Awaiting(() => run.InvokeToolAsync("search.web", Utf8("{}"), _ => { ran = true; return Task.FromResult(Utf8("{}")); }))
            .Should().ThrowAsync<PolicyDeniedException>()).Which;
        (denied.Reason, denied.Halted, ran, run.IsHalted).Should().Be(("unavailable", true, false, true));

        // The evaluator uses the same check.
        var facts = File.ReadAllBytes(Path.Combine(V14, "expected", "02-denied-by-rule.facts.json"));
        FluentActions.Invoking(() => AgentPolicy.Evaluate(DocV13, facts, engine)).Should().Throw<PolicyEngineException>()
            .WithMessage("The policy engine's answer is not an isAuthorized answer.");
    }

    [Fact]
    public async Task EnforceMode_AnEngineWhoseValidationFails_RefusesTheStart()
    {
        var (clock, genTime) = VectorClock();
        using var client = Client(new StubSealer { GenTime = genTime });
        var refused = (await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(),
            GuardOptions(DocV13, new ShapeEngine(null, validateRaises: true)), clock, CancellationToken.None)).Should().ThrowAsync<StartRefusedException>()).Which;
        refused.Reason.Should().Be("unavailable");
        refused.Run.Artifacts.Select(a => a.StepType).Should().Equal("run_start", "authorization", "run_end");
    }

    [Fact]
    public async Task ObserveMode_AnEngineFailingAtStart_IsRaisedAsAPolicyEngineException_BeforeSealing()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var failing = new StubEngine(_ => throw new InvalidOperationException("boom"));
        var e = (await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(), GuardOptions(ObserveV2Doc, failing), Clock(), CancellationToken.None))
            .Should().ThrowAsync<PolicyEngineException>()).Which;
        e.Message.Should().Be("The policy engine failed: boom");
        e.InnerException.Should().BeOfType<InvalidOperationException>();
        await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(), GuardOptions(ObserveV2Doc, new ShapeEngine(null, validateRaises: true)),
            Clock(), CancellationToken.None)).Should().ThrowAsync<PolicyEngineException>().WithMessage("validate trapped");
        sealer.Requests.Should().BeEmpty();
    }

    private sealed class HookHandler(Action<int> hook) : DelegatingHandler
    {
        private int _n;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            hook(_n++);
            return base.SendAsync(request, ct);
        }
    }

    /// <summary>W1 (security proof P3_MutatedConfigurationDuringTheControlArtifactSeal): the gate checks what is sealed.</summary>
    [Fact]
    public async Task ACallerMutatingItsConfigurationDuringTheSeal_ChangesNothing()
    {
        var manifest = Utf8("tool-manifest v2");   // the locked digest is that of "tool-manifest v1", the same length
        var doc = (byte[])DocV13.Clone();
        var agent = SupportAgent() with { Configuration = SupportAgent().Configuration! with { ToolManifest = manifest } };
        var sealer = new StubSealer();
        using var client = new SigillClient(new HttpClient(new HookHandler(n =>
        {
            if (n != 0) return;
            Utf8("tool-manifest v1").CopyTo(manifest, 0);
            Array.Clear(doc, 0, doc.Length);
        }) { InnerHandler = sealer }) { BaseAddress = new Uri("https://api.example") });
        var refused = (await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, agent, GuardOptions(doc, TestEngine.Shared), Clock(), CancellationToken.None))
            .Should().ThrowAsync<StartRefusedException>()).Which;
        refused.Reason.Should().Be("configuration_locked");
        var signed = sealer.Requests[0]["objects"]!.AsArray().Select(o => o!["hashHex"]!.GetValue<string>()).OrderBy(x => x);
        refused.Run.ControlArtifact.ObjectDigests.Values.OrderBy(x => x).Should().Equal(signed);
        refused.Run.ControlArtifact.ObjectDigests.Values.Should().Contain(EnvelopeHashing.HashHex(Utf8("tool-manifest v2")))
            .And.Contain(EnvelopeHashing.HashHex(DocV13));
        (await VerifyGuarded(refused.Run)).Verdict.Should().Be("run_finalized");
    }

    /// <summary>The Cedar core, except that it deletes a rule from the call it is given (once, or for one resource).</summary>
    private sealed class MutatingEngine(Func<JsonObject, bool> when) : IPolicyEngine
    {
        public string Version => TestEngine.Shared.Version;
        public JsonObject Validate(JsonObject call) => TestEngine.Shared.Validate(call);

        public JsonObject Authorize(JsonObject call)
        {
            if (when(call)) call["policies"]!["staticPolicies"]!.AsObject().Remove("no-web-search");
            return TestEngine.Shared.Authorize(call);
        }
    }

    [Fact]
    public async Task AnEngineThatChangesItsInput_ChangesNoLaterDecision()
    {
        var (run, _, client) = await StartGuarded(engine: new MutatingEngine(c => c["resource"]!["id"]!.GetValue<string>() == "ledger.preview"));
        using var owned = client;
        await run.InvokeToolAsync("ledger.preview", Utf8("{}"), _ => Task.FromResult(Utf8("{}")));
        (await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>())
            .Which.Rules.Should().Equal("no-web-search");

        var first = true;
        var mutating = new MutatingEngine(_ => { var f = first; first = false; return f; });
        var facts = File.ReadAllBytes(Path.Combine(V14, "expected", "02-denied-by-rule.facts.json"));
        AgentPolicy.Evaluate(DocV13, facts, mutating).Rules.Single(r => r.Id == "no-web-search").Result.Should().Be("FAIL");
    }

    [Fact]
    public async Task AFaultInsideTheGuard_BreaksTheRun()
    {
        var (run, _, client) = await StartGuarded();
        using var owned = client;
        run.Guard!.Fault = _ => throw new InvalidOperationException("guard fault");
        await FluentActions.Awaiting(() => run.InvokeToolAsync("search.web", Utf8("{}"), _ => throw new InvalidOperationException("must not run")))
            .Should().ThrowAsync<InvalidOperationException>().WithMessage("guard fault");
        (run.IsBroken, run.Artifacts[^1].StepType).Should().Be((true, "tool_call"));
        await FluentActions.Awaiting(() => run.RecordModelOutputAsync(Utf8("x"))).Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*broken*");
    }

    [Fact]
    public async Task Delegations_WithTheSameValues_AreEqual()
    {
        var (run, _, client) = await StartGuarded(WithRule("no-delegation", r => r["annotations"]!["effect"] = "deny"));
        using var owned = client;
        var d = await run.DelegateAsync("urn:example:agent:reviewer");
        var rebuilt = new AgentDelegation(d.ParentCorrelationId, d.DelegationSignatureSha256, d.ChildCorrelationId, d.ChildAgentId) { Artifact = d.Artifact };
        rebuilt.Should().Be(d);
        rebuilt.GetHashCode().Should().Be(d.GetHashCode());
    }

    [Fact]
    public async Task AHaltRuleOnRunStart_RefusesTheStart()
    {
        var (clock, genTime) = VectorClock();
        using var client = Client(new StubSealer { GenTime = genTime });
        var refused = (await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(),
                GuardOptions(WithRule("no-delegation", r => r["action"]!["entity"]!["id"] = "run_start"), TestEngine.Shared), clock, CancellationToken.None))
            .Should().ThrowAsync<StartRefusedException>()).Which;
        refused.Reason.Should().Be("rule");
        refused.Run.Artifacts[1].Envelope["step"]!["rules"]!.ToJsonString().Should().Be("""["no-delegation"]""");
    }

    // ── R4: strict validation fails closed on a malformed engine answer ──

    /// <summary>The Cedar core, except that its validate answer or its answer to the entities probe is the given one (null: a null answer).</summary>
    private sealed class StrictShapeEngine(string? validate, string? probe, bool replaceValidate, bool replaceProbe) : IPolicyEngine
    {
        public string Version => TestEngine.Shared.Version;
        public JsonObject Validate(JsonObject call) => replaceValidate ? (validate is null ? null! : JsonNode.Parse(validate)!.AsObject()) : TestEngine.Shared.Validate(call);
        public JsonObject Authorize(JsonObject call) => replaceProbe && call["policies"]!["staticPolicies"]!.AsObject().Count == 0
            ? (probe is null ? null! : JsonNode.Parse(probe)!.AsObject()) : TestEngine.Shared.Authorize(call);
    }

    // (An answer that is a JSON array cannot be expressed: IPolicyEngine returns a JsonObject; a null answer is the nearest case.)
    public static IEnumerable<object?[]> MalformedStrictAnswers() => new object?[][]
    {
        new object?[] { "validate", """{"type":"success"}""", "The policy engine's answer is not a validate answer." },
        new object?[] { "validate", """{"type":"success","validationErrors":"not-an-array"}""", "The policy engine's answer is not a validate answer." },
        new object?[] { "validate", """{"type":"success","validationErrors":["no-web-search"]}""", "The policy engine's answer is not a validate answer." },
        new object?[] { "validate", """{"type":"success","validationErrors":[{"error":{"message":"m"}}]}""", "The policy engine's answer is not a validate answer." },
        new object?[] { "validate", """{"type":"success","validationErrors":[{"policyId":"no-web-search","error":"m"}]}""", "The policy engine's answer is not a validate answer." },
        new object?[] { "validate", """{"type":"ok","validationErrors":[]}""", "The policy engine's answer is not a validate answer." },
        new object?[] { "validate", null, "The policy engine's answer is not a validate answer." },
        new object?[] { "probe", """{"type":"success"}""", "The policy engine's answer is not an isAuthorized answer." },
        new object?[] { "probe", """{"type":"success","response":{"decision":"deny","diagnostics":{"reason":"no-web-search","errors":[]}}}""", "The policy engine's answer is not an isAuthorized answer." },
        new object?[] { "probe", """{"type":"success","response":{"decision":"deny","diagnostics":{"reason":["no-web-search"],"errors":[]}}}""", "The policy engine's answer is not an isAuthorized answer." },
    };

    [Theory]
    [MemberData(nameof(MalformedStrictAnswers))]
    public async Task AMalformedStrictValidationAnswer_IsAnEngineFailure_AndRefusesAnEnforcedStart(string which, string? answer, string text)
    {
        var engine = new StrictShapeEngine(answer, answer, which == "validate", which == "probe");
        FluentActions.Invoking(() => AgentPolicy.ValidateStrict(DocV13, engine)).Should().Throw<PolicyEngineException>().WithMessage(text);

        var (clock, genTime) = VectorClock();
        var sealer = new StubSealer { GenTime = genTime };
        using var client = Client(sealer);
        var refused = (await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(), GuardOptions(DocV13, engine), clock, CancellationToken.None))
            .Should().ThrowAsync<StartRefusedException>()).Which;
        refused.Reason.Should().Be("unavailable");
        refused.Run.Artifacts.Select(a => a.StepType).Should().Equal("run_start", "authorization", "run_end");
        sealer.Requests.Should().HaveCount(4, "the Control Artifact, run_start, the record and run_end; nothing else");
        await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, SupportAgent(), GuardOptions(ObserveV2Doc, engine), Clock(), CancellationToken.None))
            .Should().ThrowAsync<PolicyEngineException>().WithMessage(text);
        sealer.Requests.Should().HaveCount(4);
    }

    // ── R2: no tool starts after a halt ──

    /// <summary>Vector 13's policy; the callback of the tool_call with use id "a1" records a delegation, which no-delegation halts on.</summary>
    private static async Task<(AgentRun Run, SigillClient Client)> HaltingFromTheCallsCallback(bool fromOnEvent = false)
    {
        AgentRun? run = null;
        async Task Delegate()
        {
            try { await run!.DelegateAsync("urn:example:agent:reviewer"); }
            catch (RunHaltedException) { }
        }
        var (started, _, client) = await StartGuarded(
            onEvent: e => { if (fromOnEvent && e.UseId == "a1") Delegate().GetAwaiter().GetResult(); },
            with: o => o with { OnArtifactSealed = async (a, _) => { if (!fromOnEvent && a.StepType == "tool_call" && a.Envelope["step"]!["tool"]!["useId"]!.GetValue<string>() == "a1") await Delegate(); } });
        run = started;
        return (run, client);
    }

    private static async Task AssertHaltedAfterTheCall(AgentRun run, RunHaltedException raised)
    {
        run.Artifacts.Select(a => a.StepType).Should().EndWith(new[] { "tool_call", "delegation", "authorization", "run_end" });
        var later = (await FluentActions.Awaiting(() => run.RecordModelOutputAsync(Utf8("x"))).Should().ThrowAsync<RunHaltedException>()).Which;
        (raised.Reason, raised.Seq, raised.Record, raised.Message).Should().Be((later.Reason, later.Seq, later.Record, later.Message));
        raised.Rules.Should().Equal(later.Rules).And.Equal("no-delegation");
        await FluentActions.Awaiting(() => run.RecordToolResultAsync("ledger.preview", Utf8("{}"), useId: "a1")).Should().ThrowAsync<RunHaltedException>();
        var verdict = await VerifyGuarded(run);
        verdict.Verdict.Should().Be("run_finalized", string.Join("\n", verdict.Findings));
        verdict.Checks["enforcement"].Should().Be("ok");
        verdict.Findings.Should().BeEmpty();
    }

    [Theory]
    [InlineData("invoke")]
    [InlineData("begin")]
    [InlineData("record")]
    public async Task AnAllowedCall_IsNotStarted_WhenItsCallbackHaltsTheRun(string through)
    {
        var (run, client) = await HaltingFromTheCallsCallback();
        using var owned = client;
        var ran = false;   // ledger.preview: known, without a definition, and no rule denies it
        Func<Task> act = through switch
        {
            "invoke" => () => run.InvokeToolAsync("ledger.preview", Utf8("{}"), _ => { ran = true; return Task.FromResult(Utf8("{}")); }, useId: "a1"),
            "begin" => () => run.BeginToolCallAsync("ledger.preview", Utf8("{}"), useId: "a1"),
            _ => () => run.RecordToolCallAsync("ledger.preview", Utf8("{}"), useId: "a1"),
        };
        var raised = (await FluentActions.Awaiting(act).Should().ThrowAsync<RunHaltedException>()).Which;
        ran.Should().BeFalse();
        await AssertHaltedAfterTheCall(run, raised);
    }

    [Fact]
    public async Task TheGenericRecordOfAToolCall_MakesTheSameReCheck()
    {
        var (run, client) = await HaltingFromTheCallsCallback();
        using var owned = client;
        var raised = (await FluentActions.Awaiting(() => run.RecordAsync("tool_call",
                new[] { new AgentRunObject { Role = "tool-arguments", Bytes = Utf8("{}"), ContentType = "application/json" } },
                new JsonObject { ["tool"] = new JsonObject { ["name"] = "ledger.preview", ["useId"] = "a1" } }))
            .Should().ThrowAsync<RunHaltedException>()).Which;
        await AssertHaltedAfterTheCall(run, raised);
    }

    // ── R6: in an enforced run the model-call handler does not let the agent go on after a failure ──

    private const string ModelReply = """{"id":"msg_01","type":"message","model":"claude-sonnet-5","usage":{"input_tokens":1,"output_tokens":1}}""";

    private static async Task<(AgentRun Run, StubSealer Sealer, SigillClient Client)> ModelCallRun(string mode, IPolicyEngine engine) => mode switch
    {
        "enforce" => await StartGuarded(engine: engine, with: o => o with { RecordsModelCalls = true }),
        "observe" => await StartGuarded(ObserveV2Doc, engine, with: o => o with { RecordsModelCalls = true }),
        _ => await StartGuarded(ObserveV2Doc, engine, with: o => o with { RecordsModelCalls = true, Enforcement = null }),
    };

    private static Task<HttpResponseMessage> PostModelCall(HttpClient http) =>
        http.PostAsync("https://api.anthropic.com/v1/messages", new StringContent("""{"model":"claude-sonnet-5"}""", Encoding.UTF8, "application/json"));

    [Theory]
    [InlineData(true)]    // the engine fails on the model_output and sealing the unavailable record fails
    [InlineData(false)]   // sealing the model_output itself fails
    public async Task EnforcedRun_ARecordingFailure_IsRaised_AndNoFurtherModelRequestIsSent(bool engineAndRecord)
    {
        var engine = engineAndRecord ? new FailingEngine(TestEngine.Shared, new[] { "model_output" }) : (IPolicyEngine)TestEngine.Shared;
        var (run, sealer, client) = await ModelCallRun("enforce", engine);
        using var owned = client;
        var errors = new List<Exception>();
        var provider = new CountingProvider(ModelReply);
        using var http = new HttpClient(new ModelCallHandler(run, provider, e => { errors.Add(e); throw new InvalidOperationException("onError failed"); }));
        sealer.FailOnCall = sealer.Requests.Count + (engineAndRecord ? 1 : 0);

        var raised = (await FluentActions.Awaiting(() => PostModelCall(http)).Should().ThrowAsync<Exception>()).Which;
        raised.Should().NotBeOfType<RunHaltedException>().And.NotBeOfType<InvalidOperationException>("the sealing failure is raised, not onError's");
        errors.Should().ContainSingle().Which.Should().BeSameAs(raised);
        run.IsBroken.Should().BeTrue();
        await FluentActions.Awaiting(() => PostModelCall(http)).Should().ThrowAsync<InvalidOperationException>().WithMessage("*broken*");
        provider.Sent.Should().Be(1);
    }

    [Theory]
    [InlineData("observe", true)]
    [InlineData("observe", false)]
    [InlineData("none", true)]
    [InlineData("none", false)]
    public async Task OtherRuns_ARecordingFailure_GoesToOnError_AndTheCallsGoOn(string mode, bool engineFails)
    {
        var engine = engineFails ? new FailingEngine(TestEngine.Shared, new[] { "model_output" }) : (IPolicyEngine)TestEngine.Shared;
        var (run, sealer, client) = await ModelCallRun(mode, engine);
        using var owned = client;
        var errors = new List<Exception>();
        var provider = new CountingProvider(ModelReply);
        using var http = new HttpClient(new ModelCallHandler(run, provider, errors.Add));
        sealer.FailOnCall = sealer.Requests.Count + (engineFails ? 1 : 0);
        (await PostModelCall(http)).IsSuccessStatusCode.Should().BeTrue();
        (await PostModelCall(http)).IsSuccessStatusCode.Should().BeTrue();
        provider.Sent.Should().Be(2);
        errors.Should().NotBeEmpty();
        run.IsHalted.Should().BeFalse();
    }

    [Fact]
    public async Task AnObservedCall_IsNotStarted_WhenOnEventHaltsTheRun()
    {
        var (run, client) = await HaltingFromTheCallsCallback(fromOnEvent: true);
        using var owned = client;
        var definition = Utf8("crm.read_customer definition");
        await run.InvokeToolAsync("crm.read_customer", Utf8("{}"), _ => Task.FromResult(Utf8("{}")), definition: definition);
        var ran = false;   // the second read matches the shadow rule: observed, and OnEvent records the halting delegation
        var raised = (await FluentActions.Awaiting(() => run.InvokeToolAsync("crm.read_customer", Utf8("{}"),
            _ => { ran = true; return Task.FromResult(Utf8("{}")); }, definition: definition, useId: "a1")).Should().ThrowAsync<RunHaltedException>()).Which;
        ran.Should().BeFalse();
        run.Artifacts.Select(a => a.StepType).Should().EndWith(new[] { "tool_call", "delegation", "authorization", "run_end" });
        raised.Rules.Should().Equal("no-delegation");
        (await VerifyGuarded(run)).Findings.Should().BeEmpty();
    }

    [Fact]
    public async Task ACallHeldInItsCallback_WhileAnotherThreadHaltsTheRun_IsNotStarted()
    {
        AgentRun? run = null;
        var inCallback = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var (started, _, client) = await StartGuarded(with: o => o with
        {
            OnArtifactSealed = async (a, _) =>
            {
                if (a.StepType != "tool_call" || a.Envelope["step"]!["tool"]!["useId"]!.GetValue<string>() != "a1") return;
                inCallback.SetResult(true);
                try { await Task.Delay(Timeout.Infinite, run!.HaltedToken); }   // held until thread B's halt is sealed
                catch (OperationCanceledException) { }
            },
        });
        run = started;
        using var owned = client;
        var ran = false;
        var a = Task.Run(() => run.InvokeToolAsync("crm.update_address", Utf8("{}"), _ => { ran = true; return Task.FromResult(Utf8("{}")); },
            definition: Utf8("crm.update_address definition"), useId: "a1"));
        await inCallback.Task;
        var b = Task.Run(() => run.DelegateAsync("urn:example:agent:reviewer"));
        await FluentActions.Awaiting(() => a).Should().ThrowAsync<RunHaltedException>();
        await FluentActions.Awaiting(() => b).Should().ThrowAsync<RunHaltedException>();
        ran.Should().BeFalse();
        (await VerifyGuarded(run)).Findings.Should().BeEmpty();
    }

    // ── Parity tests (T1–T3) ──

    [Fact]
    public async Task AHaltRuleMatchingTheProducersRunEnd_HasNoEffect()
    {
        var doc = WithRule("no-delegation", r => r["action"]!["entity"]!["id"] = "run_end");
        AgentPolicy.ValidateStrict(doc, TestEngine.Shared).Should().BeEmpty();
        var reported = new List<EnforcementEvent>();
        var (run, _, client) = await StartGuarded(doc, onEvent: reported.Add);
        using var owned = client;
        var bundle = await run.FinishAsync();
        bundle.Artifacts.Select(a => a.StepType).Should().Equal("run_start", "run_end");
        bundle.Artifacts[^1].Envelope["step"]!["runDisposition"]!.GetValue<string>().Should().Be("completed");
        (run.IsHalted, reported.Count).Should().Be((false, 0));
    }

    [Fact]
    public async Task AnObservedEventOnAToolResult_NamesItsTool()
    {
        var reported = new List<EnforcementEvent>();
        var (run, _, client) = await StartGuarded(WithRule("shadow-repeat-read", r => r["action"]!["entity"]!["id"] = "tool_result"), onEvent: reported.Add);
        using var owned = client;
        var definition = Utf8("crm.read_customer definition");
        await run.InvokeToolAsync("crm.read_customer", Utf8("{}"), _ => Task.FromResult(Utf8("{}")), definition: definition, useId: "r1");
        await run.InvokeToolAsync("crm.read_customer", Utf8("{}"), _ => Task.FromResult(Utf8("{}")), definition: definition, useId: "r2");
        var result = run.Artifacts[^1];
        result.StepType.Should().Be("tool_result");
        reported.Should().ContainSingle().Which.Should().Be(new EnforcementEvent("observed", null, reported[0].Rules, "crm.read_customer", "r2", result.Seq!.Value));
        reported[0].Rules.Should().Equal("shadow-repeat-read");
    }

    [Fact]
    public async Task ARuleLessEnforcingControlSet_DeniesEveryToolAsUnknown()
    {
        var doc = JsonNode.Parse(DocV13)!.AsObject();
        doc.Remove("cedar");
        var (run, _, client) = await StartGuarded(Utf8(doc.ToJsonString()));
        using var owned = client;
        var ran = false;
        var denied = (await FluentActions.Awaiting(() => run.InvokeToolAsync("crm.read_customer", Utf8("{}"), _ => { ran = true; return Task.FromResult(Utf8("{}")); }))
            .Should().ThrowAsync<PolicyDeniedException>()).Which;
        (denied.Reason, denied.Rules.Count, denied.Halted, ran).Should().Be(("unknown_tool", 0, false, false));
    }
}
