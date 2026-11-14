// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// Delivery of a run to the organisation's evidence index (AgentRunOptions.DeliverRun, AgentRun.Delivery,
// SigillClient.DeliverAgentRunAsync), against a fake index in front of the stub sealer.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    /// <summary>
    /// The index endpoint: records every upload attempt; by default takes a new artifact (201 indexed) and one it has (200
    /// exists), as the server does. <see cref="Answer"/> scripts other answers; <see cref="Down"/> fails the transport.
    /// </summary>
    private sealed class DeliveryIndex(StubSealer sealer) : DelegatingHandler(sealer)
    {
        private readonly HashSet<string> _have = new(StringComparer.Ordinal);

        public List<JsonObject> Attempts { get; } = new();
        public List<string> Indexed { get; } = new();
        public Func<JsonObject, (HttpStatusCode Status, string Body, string ContentType)?>? Answer { get; set; }
        public Func<JsonObject, HttpResponseMessage?>? Respond { get; set; }
        public bool Down { get; set; }
        public TimeSpan Delay { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath != "/api/agent-evidence/artifacts") return await base.SendAsync(request, ct);
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!.AsObject();
            lock (Attempts) Attempts.Add(body);
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, ct);
            if (Down) throw new HttpRequestException("connection refused");
            if (Respond?.Invoke(body) is { } response) return response;
            if (Answer?.Invoke(body) is { } a)
                return new HttpResponseMessage(a.Status) { Content = new StringContent(a.Body, Encoding.UTF8, a.ContentType) };
            bool fresh;
            lock (Attempts)
            {
                fresh = _have.Add(body["envelope"]!["evidenceId"]!.GetValue<string>());
                if (fresh) Indexed.Add(Label(body));
            }
            var answer = new JsonObject { ["status"] = fresh ? "indexed" : "exists", ["runId"] = "0e0e0e0e-0000-0000-0000-000000000001", ["artifactId"] = Guid.NewGuid().ToString() };
            return new HttpResponseMessage(fresh ? HttpStatusCode.Created : HttpStatusCode.OK) { Content = new StringContent(answer.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }

    private static string Label(JsonObject upload) => upload["envelope"]!["schemaName"]!.GetValue<string>() == AgentProfiles.ControlArtifactSchema
        ? "control" : $"{upload["envelope"]!["chain"]!["seq"]}:{upload["envelope"]!["step"]!["type"]}";

    private static (HttpStatusCode, string, string) Error(HttpStatusCode status, string code) =>
        (status, new JsonObject { ["code"] = code, ["message"] = "no" }.ToJsonString(), "application/json");

    private static async Task<(AgentRun Run, DeliveryIndex Index, SigillClient Client)> StartDelivered(AgentRunOptions? options = null,
        DeliveryIndex? index = null, AgentDefinition? agent = null, Func<TimeSpan>? indexClock = null)
    {
        index ??= new DeliveryIndex(new StubSealer());
        var client = new SigillClient(new HttpClient(index) { BaseAddress = new Uri("https://api.example") });
        var run = await AgentRun.StartCoreAsync(client, agent ?? Agent(), options ?? Options() with { DeliverRun = true }, Clock(),
            CancellationToken.None, indexClock: indexClock);
        return (run, index, client);
    }

    private static string[] Chain(AgentRun run) =>
        new[] { "control" }.Concat(run.Artifacts.Select(a => $"{a.Seq}:{a.StepType}")).ToArray();

    [Fact]
    public async Task Delivery_UploadsTheChainInOrder_IncludingTheGuardsRecordAndAHaltedRunEnd()
    {
        var (run, index, client) = await StartDelivered(GuardOptions(WithEnforcement(e => e["haltAfterDenials"] = 1), TestEngine.Shared)
            with { DeliverRun = true }, agent: SupportAgent());
        using var owned = client;
        await run.InvokeToolAsync("crm.update_address", Utf8("{}"), _ => Task.FromResult(Utf8("{}")), definition: Utf8("crm.update_address definition"));
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>();
        await run.FinishAsync();

        index.Indexed.Should().Equal(Chain(run));
        index.Indexed.Should().EndWith(new[] { "4:authorization", "5:run_end" });
        index.Attempts[^1]["envelope"]!["step"]!["runDisposition"]!.GetValue<string>().Should().Be("halted");
        index.Attempts.Should().OnlyContain(u => u["controlSet"] == null, "the policy document travels only with DisclosePolicy");
        run.Delivery.Should().Be(new AgentRunDelivery("delivered", 7, 0, Guid.Parse("0e0e0e0e-0000-0000-0000-000000000001"), null));
    }

    [Fact]
    public async Task WithoutDeliverRun_NothingIsUploaded_AndDisclosePolicyAloneIsUnchanged()
    {
        var index = new DeliveryIndex(new StubSealer());
        var (run, _, client) = await StartDelivered(Options(), index);
        using (client)
        {
            await run.RecordToolCallAsync("lookup_ticket", Utf8("{}"));
            await run.FinishAsync();
            index.Attempts.Should().BeEmpty();
            run.Delivery.Should().BeNull();
        }

        var disclose = new DeliveryIndex(new StubSealer());
        var (r2, _, c2) = await StartDelivered(PolicyOptions() with { DisclosePolicy = true }, disclose);
        using var owned = c2;
        await r2.RecordToolCallAsync("lookup_ticket", Utf8("{}"), useId: "c1");
        await r2.FinishAsync();
        disclose.Attempts.Select(Label).Should().Equal("control");
        Convert.FromBase64String(disclose.Attempts[0]["controlSet"]!.GetValue<string>()).Should().Equal(PolicyDoc);
        (r2.PolicyDisclosure!.Succeeded, r2.Delivery).Should().Be((true, (AgentRunDelivery?)null));
    }

    [Fact]
    public async Task WithDisclosePolicy_TheDocumentTravelsWithTheControlArtifactsDelivery()
    {
        var (run, index, client) = await StartDelivered(PolicyOptions() with { DisclosePolicy = true, DeliverRun = true });
        using var owned = client;
        await run.RecordToolCallAsync("lookup_ticket", Utf8("{}"), useId: "c1");
        await run.FinishAsync();
        index.Attempts.Select(Label).Should().Equal(Chain(run), "one upload per artifact: the document is not sent twice");
        Convert.FromBase64String(index.Attempts[0]["controlSet"]!.GetValue<string>()).Should().Equal(PolicyDoc);
        index.Attempts.Skip(1).Should().OnlyContain(u => u["controlSet"] == null);
        run.PolicyDisclosure!.Status.Should().Be("indexed");
    }

    [Fact]
    public async Task WithDisclosePolicy_AControlArtifactTheIndexHasAlready_IsDisclosedAsIndexed()
    {
        var index = new DeliveryIndex(new StubSealer());
        index.Answer = u => Label(u) == "control"
            ? (HttpStatusCode.OK, """{"status":"exists","runId":"0e0e0e0e-0000-0000-0000-000000000001"}""", "application/json") : null;
        var (run, _, client) = await StartDelivered(PolicyOptions() with { DisclosePolicy = true, DeliverRun = true }, index);
        using var owned = client;
        run.PolicyDisclosure.Should().Be(new AgentIndexResult("indexed", Guid.Parse("0e0e0e0e-0000-0000-0000-000000000001")));
    }

    [Fact]
    public async Task TheUploadFollowsAFailingHook_InTheSameTurn()
    {
        var index = new DeliveryIndex(new StubSealer());
        var sealedSeen = new List<int>();
        var failing = Options() with
        {
            DeliverRun = true,
            OnArtifactSealed = (a, _) =>
            {
                lock (index.Attempts) sealedSeen.Add(index.Attempts.Count);   // what the index had when the hook ran
                throw new InvalidOperationException("hook failed");
            },
        };
        var client = new SigillClient(new HttpClient(index) { BaseAddress = new Uri("https://api.example") });
        using var owned = client;
        var run = (await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, Agent(), failing, Clock(), CancellationToken.None))
            .Should().ThrowAsync<AgentRunCallbackException>()).Which.Run;
        await FluentActions.Awaiting(() => run.RecordModelOutputAsync(Utf8("x"))).Should().ThrowAsync<InvalidOperationException>().WithMessage("hook failed");
        sealedSeen.Should().Equal(new[] { 0, 1, 2 }, "each hook runs before its own artifact's upload");
        index.Indexed.Should().Equal(Chain(run), "a failing hook does not stop the delivery");
    }

    [Fact]
    public async Task ARefusedPolicyDocument_IsDroppedFromTheControlArtifact_AndTheStepsFollow()
    {
        var index = new DeliveryIndex(new StubSealer());
        index.Answer = u => u["controlSet"] is not null ? Error(HttpStatusCode.UnprocessableEntity, "control_set_invalid") : null;
        var (run, _, client) = await StartDelivered(PolicyOptions() with { DisclosePolicy = true, DeliverRun = true }, index);
        using var owned = client;
        await run.RecordModelOutputAsync(Utf8("x"));
        await run.FinishAsync();
        index.Attempts.Take(2).Select(u => (Label(u), u["controlSet"] is not null)).Should().Equal(("control", true), ("control", false));
        index.Indexed.Should().Equal(Chain(run));
        run.PolicyDisclosure!.Status.Should().Be("failed");
        run.PolicyDisclosure.Error.Should().Be("control artifact: 422 control_set_invalid");
        run.Delivery!.Status.Should().Be("delivered");
    }

    [Fact]
    public async Task AConflict_IsRetriedOnce_ATwiceConflictedArtifactIsHeld()
    {
        var conflicts = new Dictionary<string, int>();
        var index = new DeliveryIndex(new StubSealer());
        var now = TimeSpan.FromHours(1);
        index.Answer = u =>
        {
            var label = Label(u);
            var limit = label == "1:model_output" ? 1 : label == "2:model_output" ? 2 : 0;
            conflicts[label] = conflicts.TryGetValue(label, out var n) ? n + 1 : 1;
            return conflicts[label] <= limit ? Error(HttpStatusCode.Conflict, "conflict") : null;
        };
        var (run, _, client) = await StartDelivered(index: index, indexClock: () => now);
        using var owned = client;
        await run.RecordModelOutputAsync(Utf8("once"));
        run.Delivery!.Status.Should().Be("delivered", "one conflict: the second upload wins");
        await run.RecordModelOutputAsync(Utf8("twice"));
        run.Delivery.Should().Match<AgentRunDelivery>(d => d.Status == "pending" && d.Delivered == 3 && d.Pending == 1 && d.Error == "seq 2: 409 conflict");
        now += TimeSpan.FromSeconds(6);
        await run.RecordModelOutputAsync(Utf8("after the back-off"));
        run.Delivery!.Status.Should().Be("delivered");
        index.Indexed.Should().Equal(Chain(run));
    }

    [Theory]
    [InlineData("seq_conflict", "application/json", "seq 1: 409 seq_conflict")]
    [InlineData(null, "text/html", "seq 1: 409")]
    public async Task AFinalConflict_OrAConflictWithoutACode_IsRejected(string? code, string contentType, string error)
    {
        var index = new DeliveryIndex(new StubSealer());
        index.Answer = u => Label(u) == "1:model_output"
            ? (HttpStatusCode.Conflict, code is null ? "<html><body>409</body></html>" : new JsonObject { ["code"] = code }.ToJsonString(), contentType) : null;
        var (run, _, client) = await StartDelivered(index: index);
        using var owned = client;
        await run.RecordModelOutputAsync(Utf8("x"));
        await run.RecordModelOutputAsync(Utf8("y"));
        await run.FinishAsync();
        run.Delivery.Should().Be(new AgentRunDelivery("rejected", 2, 3, Guid.Parse("0e0e0e0e-0000-0000-0000-000000000001"), error));
        index.Attempts.Select(Label).Should().Equal("control", "0:run_start", "1:model_output");
        run.IsBroken.Should().BeFalse();
    }

    [Fact]
    public async Task AnUnreachableIndex_HoldsTheUploads_TheRunGoesOn_AndTheCursorResumesAfterTheBackoff()
    {
        var index = new DeliveryIndex(new StubSealer());
        var now = TimeSpan.FromHours(1);
        var (run, _, client) = await StartDelivered(index: index, indexClock: () => now);
        using var owned = client;
        index.Answer = _ => (HttpStatusCode.ServiceUnavailable, "busy", "text/plain");
        await run.RecordModelOutputAsync(Utf8("1"));
        var attempts = index.Attempts.Count;
        await run.RecordModelOutputAsync(Utf8("2"));   // within the back-off: nothing is tried
        index.Attempts.Should().HaveCount(attempts);
        run.Delivery.Should().Match<AgentRunDelivery>(d => d.Status == "pending" && d.Delivered == 2 && d.Pending == 2 && d.Error == "seq 1: 503");

        index.Answer = null;
        now += TimeSpan.FromSeconds(6);
        await run.RecordModelOutputAsync(Utf8("3"));   // after it: the cursor resumes, in chain order
        index.Indexed.Should().Equal(Chain(run));

        index.Down = true;
        await run.RecordModelOutputAsync(Utf8("4"));   // a transport failure is held too; never raised
        attempts = index.Attempts.Count;
        await run.RecordModelOutputAsync(Utf8("5"));
        index.Attempts.Should().HaveCount(attempts, "the back-off doubles: 10 s now");
        index.Down = false;
        var bundle = await run.FinishAsync();          // the run_end turn ignores the back-off
        index.Indexed.Should().Equal(Chain(run));
        run.Delivery!.Status.Should().Be("delivered");
        bundle.Artifacts.Should().HaveCount(7);
        run.IsBroken.Should().BeFalse();
    }

    [Fact]
    public async Task FinishOnAHaltedRun_MakesOneMoreAttempt_PastTheBackoff()
    {
        var index = new DeliveryIndex(new StubSealer());
        var now = TimeSpan.FromHours(1);
        var (run, _, client) = await StartDelivered(GuardOptions(WithEnforcement(e => e["haltAfterDenials"] = 1), TestEngine.Shared)
            with { DeliverRun = true }, index, SupportAgent(), () => now);
        using var owned = client;
        index.Down = true;   // the halt's own final turn finds the index down
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>();
        run.Delivery!.Status.Should().Be("pending");
        index.Down = false;
        var bundle = await run.FinishAsync();   // within the back-off; nothing is sealed, the delivery catches up
        bundle.Artifacts.Should().HaveCount(4);
        index.Indexed.Should().Equal(Chain(run));
        run.Delivery!.Status.Should().Be("delivered");
    }

    [Fact]
    public async Task ADeadIndex_NeverFailsTheRun_FinishReturnsTheBundle()
    {
        var index = new DeliveryIndex(new StubSealer()) { Down = true };
        var (run, _, client) = await StartDelivered(index: index);
        using var owned = client;
        await run.RecordToolCallAsync("lookup_ticket", Utf8("{}"));
        var bundle = await run.FinishAsync();
        bundle.Artifacts.Should().HaveCount(3);
        run.Delivery.Should().Be(new AgentRunDelivery("pending", 0, 4, null, "control artifact: HttpRequestException"));
    }

    [Fact]
    public async Task ARefusal_IsRejected_AndNothingFollowsAutomatically()
    {
        var index = new DeliveryIndex(new StubSealer());
        index.Answer = u => Label(u) == "2:model_output" ? Error(HttpStatusCode.UnprocessableEntity, "run_limit") : null;
        var (run, _, client) = await StartDelivered(index: index);
        using var owned = client;
        await run.RecordModelOutputAsync(Utf8("1"));
        await run.RecordModelOutputAsync(Utf8("2"));
        await run.RecordModelOutputAsync(Utf8("3"));
        await run.FinishAsync();
        index.Indexed.Should().Equal("control", "0:run_start", "1:model_output");
        run.Delivery.Should().Match<AgentRunDelivery>(d => d.Status == "rejected" && d.Delivered == 3 && d.Pending == 3 && d.Error == "seq 2: 422 run_limit");
    }

    [Fact]
    public async Task EnforceMode_TheGuardsDenialIsRaised_WhileTheIndexIsDown_AndTheRunIsNotBroken()
    {
        var index = new DeliveryIndex(new StubSealer()) { Down = true };
        var (run, _, client) = await StartDelivered(GuardOptions(DocV13, TestEngine.Shared) with { DeliverRun = true }, index, SupportAgent());
        using var owned = client;
        (await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>())
            .Which.InnerException.Should().BeNull("a delivery failure is not a callback failure either");
        (run.IsBroken, run.IsHalted).Should().Be((false, false));
        await run.InvokeToolAsync("crm.update_address", Utf8("{}"), _ => Task.FromResult(Utf8("{}")), definition: Utf8("crm.update_address definition"));
        index.Down = false;
        await run.FinishAsync();
        index.Indexed.Should().Equal(Chain(run));
    }

    [Fact]
    public async Task ConcurrentTasks_AndAnEventRecordedInAHook_StayInChainOrder()
    {
        AgentRun? run = null;
        var hooked = 0;
        var index = new DeliveryIndex(new StubSealer());
        var (started, _, client) = await StartDelivered(Options() with
        {
            DeliverRun = true,
            OnArtifactSealed = async (a, _) =>
            {
                if (a.StepType == "model_output" && Interlocked.Exchange(ref hooked, 1) == 0) await run!.CheckpointAsync("from the hook");
            },
        }, index);
        run = started;
        using var owned = client;
        await Task.WhenAll(Enumerable.Range(0, 16).Select(i => Task.Run(() => i % 2 == 0
            ? run.RecordModelOutputAsync(Utf8($"{i}"))
            : run.RecordToolCallAsync("lookup_ticket", Utf8($"{{\"n\":{i}}}")))));
        await run.FinishAsync();
        run.Artifacts.Should().Contain(a => a.StepType == "checkpoint");
        index.Attempts.Select(Label).Should().Equal(Chain(run), "every artifact once, in chain order");
    }

    [Fact]
    public async Task CatchUp_IsIdempotent_WorksOnAPartialBundle_SkipsEvaluations_AndStopsAtTheFirstFailure()
    {
        var sealer = new StubSealer();
        var index = new DeliveryIndex(sealer);
        using var client = new SigillClient(new HttpClient(index) { BaseAddress = new Uri("https://api.example") });
        var run = await AgentRun.StartCoreAsync(client, Agent(), Options(), Clock(), CancellationToken.None);
        await run.RecordModelOutputAsync(Utf8("1"));
        await run.RecordModelOutputAsync(Utf8("2"));
        var bundle = await run.FinishAsync();
        index.Attempts.Should().BeEmpty();

        var evaluation = new AgentRunArtifact(new JsonObject { ["schemaName"] = "ControlEvaluation" }, new JsonObject(), new Dictionary<string, string>());
        var first = await client.DeliverAgentRunAsync(bundle.WithEvaluations(evaluation));
        first.Should().Be(new AgentRunDelivery("delivered", 5, 0, Guid.Parse("0e0e0e0e-0000-0000-0000-000000000001"), null));
        (await client.DeliverAgentRunAsync(bundle)).Should().Be(first, "twice is the same: the index answers exists");
        index.Attempts.Should().HaveCount(10).And.OnlyContain(u => u["envelope"]!["schemaName"]!.GetValue<string>() != "ControlEvaluation");
        index.Indexed.Should().Equal(Chain(run));

        var partial = new AgentRunBundle(bundle.CorrelationId, null, bundle.Artifacts.Reverse().Take(2).ToList());
        (await client.DeliverAgentRunAsync(partial)).Should().Match<AgentRunDelivery>(d => d.Status == "delivered" && d.Delivered == 2);
        index.Attempts.TakeLast(2).Select(Label).Should().Equal("2:model_output", "3:run_end");

        index.Answer = u => Label(u) == "2:model_output" ? Error(HttpStatusCode.BadRequest, "envelope_too_large") : null;
        var before = index.Attempts.Count;
        (await client.DeliverAgentRunAsync(bundle)).Should().Be(new AgentRunDelivery("rejected", 3, 2, Guid.Parse("0e0e0e0e-0000-0000-0000-000000000001"), "seq 2: 400 envelope_too_large"));
        index.Attempts.Skip(before).Select(Label).Should().Equal("control", "0:run_start", "1:model_output", "2:model_output");
        index.Down = true;
        (await client.DeliverAgentRunAsync(bundle)).Should().Match<AgentRunDelivery>(d => d.Status == "pending" && d.Delivered == 0 && d.Pending == 5);
    }

    /// <summary>A client of another kind: any call fails (none must be made).</summary>
    public class ForeignClient : DispatchProxy
    {
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args) => throw new InvalidOperationException("no call expected");
    }

    [Fact]
    public async Task DeliverRun_WithAClientThatCannotDeliver_IsRefusedBeforeAnythingIsSealed()
    {
        var foreign = DispatchProxy.Create<ISigillAiEvidenceClient, ForeignClient>();
        await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(foreign, Agent(), Options() with { DeliverRun = true }, Clock(), CancellationToken.None))
            .Should().ThrowAsync<ArgumentException>().WithMessage("DeliverRun requires a SigillClient: only the SDK's own client delivers to the evidence index.*");
    }
}
