// Licensed to Sigill under the Apache License, Version 2.0.

using System;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

/// <summary>Agent Model Calls v1: model calls with the provider's own identifiers, sealed as schemaVersion 3.</summary>
public partial class AgentRunTests
{
    private static readonly byte[] Prompt = Encoding.UTF8.GetBytes("""{"messages":[{"role":"user","content":"Customer Jane Doe asks for a payout"}]}""");
    private static readonly byte[] Reply = Encoding.UTF8.GetBytes("""{"content":[{"type":"text","text":"Approve 1200 for Jane Doe"}]}""");

    private static ModelCall AnthropicCall(string msg = "msg_01XyZ8kq3VcR2mWd9TfLpA7e") => new()
    {
        Model = new ModelInfo("anthropic", "claude-sonnet-5-20261015", Requested: "claude-sonnet-5"),
        VendorRefs = new[] { new VendorRef("anthropic", "message", msg), new VendorRef("anthropic", "request", "req_011CabcQx7Nn4Tz2Pf8Rk1Ws") },
        Usage = new ModelUsage(InputTokens: 2960, OutputTokens: 488, StopReason: "tool_use"),
    };

    [Fact]
    public async Task ModelCalls_SealAsVersion3_WithTheProvidersIds_AndOnlyDigestsTravel()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), Options() with { RecordsModelCalls = true }, Clock(), CancellationToken.None);
        await run.RecordModelCallAsync(AnthropicCall(), Prompt, Reply);
        await run.RecordToolCallAsync("claims.approve_payout", Encoding.UTF8.GetBytes("""{"amount":1200}"""), "update", consequential: true);
        await run.RecordModelCallAsync(new ModelCall { VendorRefs = new[] { new VendorRef("openai", "response", "resp_68a1f0c2") } });
        await run.FinishAsync();

        run.Artifacts.Select(a => a.Envelope["schemaVersion"]!.GetValue<string>()).Should().OnlyContain(v => v == "3");
        var step = run.Artifacts.First(a => a.Envelope["step"]!["type"]!.GetValue<string>() == "model_output").Envelope["step"]!;
        step["model"]!["served"]!.GetValue<string>().Should().Be("claude-sonnet-5-20261015");
        step["vendorRefs"]![1]!["id"]!.GetValue<string>().Should().Be("req_011CabcQx7Nn4Tz2Pf8Rk1Ws");
        step["usage"]!["outputTokens"]!.GetValue<long>().Should().Be(488);
        sealer.Requests.Should().OnlyContain(rq => !rq.ToJsonString().Contains("Jane Doe"));   // digests only

        var r = await AgentRunVerifier.VerifyAsync(run.ToBundle(), StubVerify);
        r.Verdict.Should().Be("run_finalized", string.Join("; ", r.Findings));
        (r.ModelCalls, r.ModelCallsWithVendorRefs).Should().Be((2, 2));
    }

    [Fact]
    public async Task ModelCalls_NeedTheOption_AndInvalidIdentifiersAreRefusedBeforeSealing()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var v1 = await AgentRun.StartCoreAsync(client, Agent(), Options(), Clock(), CancellationToken.None);
        await FluentActions.Awaiting(() => v1.RecordModelCallAsync(AnthropicCall())).Should().ThrowAsync<InvalidOperationException>();
        // The members are reserved: they cannot be smuggled into another step or a v1 run through RecordAsync.
        await FluentActions.Awaiting(() => v1.RecordAsync("model_output", fields: new JsonObject { ["vendorRefs"] = new JsonArray() }))
            .Should().ThrowAsync<ArgumentException>();

        var v3 = await AgentRun.StartCoreAsync(client, Agent(), Options() with { RecordsModelCalls = true }, Clock(), CancellationToken.None);
        var before = sealer.Requests.Count;
        await FluentActions.Awaiting(() => v3.RecordModelCallAsync(AnthropicCall("msg with space"))).Should().ThrowAsync<ArgumentException>();
        await FluentActions.Awaiting(() => v3.RecordModelCallAsync(AnthropicCall(new string('x', 256)))).Should().ThrowAsync<ArgumentException>();
        await FluentActions.Awaiting(() => v3.RecordModelCallAsync(new ModelCall { VendorRefs = new[] { new VendorRef("anthropic", "invoice", "x") } }))
            .Should().ThrowAsync<ArgumentException>();
        await FluentActions.Awaiting(() => v3.RecordModelCallAsync(new ModelCall { Model = new ModelInfo("Anthropic", "m") }))
            .Should().ThrowAsync<ArgumentException>();                                         // provider must be lowercase
        sealer.Requests.Count.Should().Be(before);                                                // nothing was sealed
        await v3.RecordModelCallAsync(AnthropicCall());                                           // and the run stays usable
    }

    [Fact]
    public async Task ARunMixingVersion3WithVersion2_IsInvalid()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var v3 = await AgentRun.StartCoreAsync(client, Agent(), Options() with { RecordsModelCalls = true }, Clock(), CancellationToken.None);
        await v3.RecordModelCallAsync(AnthropicCall());
        await v3.FinishAsync();
        var bundle = JsonNode.Parse(v3.ToBundle().ToJsonString())!;
        // Rewriting the version breaks the signature too; the version rule is reported on its own as well.
        bundle["artifacts"]![0]!["envelope"]!["schemaVersion"] = "2";
        var r = await AgentRunVerifier.VerifyAsync(AgentRunBundle.Parse(bundle.ToJsonString()), StubVerify);
        r.Verdict.Should().Be("run_invalid");
        r.Findings.Should().Contain(f => f.Contains("mix schemaVersion"));
    }
}
