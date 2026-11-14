// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// Delivery against an index that answers in unexpected ways: what counts as accepted, redirects, long and slow answers,
// the time budgets, server strings, and what never leaves the machine.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    public static IEnumerable<object[]> AnswersThatAreNotAcceptance() => new (int Status, string Body, string Type)[]
    {
        (200, "<html>Sign in to continue</html>", "text/html"),
        (204, "", "text/plain"),
        (202, """{"status":"queued"}""", "application/json"),
        (200, """{"code":"rejected","message":"not stored"}""", "application/json"),
        (200, """{"status":"indexed"}""", "application/json"),                                   // no runId
        (201, """{"status":"indexed","runId":"not-a-uuid"}""", "application/json"),
        (200, new string('[', 200_000), "application/json"),
        (301, "", "text/plain"), (302, "", "text/plain"), (304, "", "text/plain"), (307, "", "text/plain"), (308, "", "text/plain"),
    }.Select(a => new object[] { a.Status, a.Body, a.Type });

    [Theory]
    [MemberData(nameof(AnswersThatAreNotAcceptance))]
    public async Task OnlyTheIndexsAcceptanceCounts_AnyOtherAnswerIsRejected(int status, string body, string type)
    {
        var index = new DeliveryIndex(new StubSealer());
        index.Answer = u => Label(u) is "control" or "1:model_output" ? ((HttpStatusCode)status, body, type) : null;
        var (run, _, client) = await StartDelivered(PolicyOptions() with { DisclosePolicy = true, DeliverRun = true }, index);
        using var owned = client;
        await run.RecordModelOutputAsync(Utf8("x"));
        await run.FinishAsync();
        run.Delivery.Should().Be(new AgentRunDelivery("rejected", 0, 4, null, $"control artifact: {status} unexpected_response"));
        run.PolicyDisclosure.Should().Be(new AgentIndexResult("failed", Error: $"control artifact: {status} unexpected_response"));
        index.Attempts.Select(Label).Should().Equal("control");
    }

    [Fact]
    public async Task AnAnswerLongerThan64KiB_IsNotRead_AndIsRejected()
    {
        var index = new DeliveryIndex(new StubSealer());
        index.Answer = u => Label(u) == "1:model_output"
            ? (HttpStatusCode.Created, """{"status":"indexed","runId":"0e0e0e0e-0000-0000-0000-000000000001","pad":""" + "\"" + new string('a', 70_000) + "\"}", "application/json")
            : null;
        var (run, _, client) = await StartDelivered(index: index);
        using var owned = client;
        await run.RecordModelOutputAsync(Utf8("x"));
        run.Delivery!.Should().Match<AgentRunDelivery>(d => d.Status == "rejected" && d.Error == "seq 1: 201 unexpected_response");
    }

    [Fact]
    public async Task A503WithALongPage_StaysPending_AndIsRetriedAfterTheBackoff()
    {
        var index = new DeliveryIndex(new StubSealer());
        var now = TimeSpan.FromHours(1);
        var page = "<html>" + new string('x', 100 * 1024) + "</html>";
        index.Answer = u => Label(u) == "1:model_output" ? (HttpStatusCode.ServiceUnavailable, page, "text/html") : null;
        var (run, _, client) = await StartDelivered(index: index, indexClock: () => now);
        using var owned = client;
        await run.RecordModelOutputAsync(Utf8("x"));
        run.Delivery.Should().Be(new AgentRunDelivery("pending", 2, 1, Guid.Parse("0e0e0e0e-0000-0000-0000-000000000001"), "seq 1: 503"));
        index.Answer = null;
        now += TimeSpan.FromSeconds(6);
        await run.RecordModelOutputAsync(Utf8("y"));
        run.Delivery!.Status.Should().Be("delivered");
        index.Indexed.Should().Equal(Chain(run));
    }

    [Fact]
    public async Task ADeadIndex_CostsOneUploadLimit_ThenTheBackoffHolds_WhenTheLimitIsTheWholeTurn()
    {
        var index = new DeliveryIndex(new StubSealer());
        var now = TimeSpan.FromHours(1);
        var (run, _, client) = await StartDelivered(index: index, indexClock: () => now);
        using var owned = client;
        run.IndexLimits = new AgentRunIndex.Limits(TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(300), TimeSpan.FromSeconds(1));
        index.Delay = TimeSpan.FromSeconds(30);   // never answers within the limit
        var before = index.Attempts.Count;
        for (var i = 0; i < 4; i++) await run.RecordModelOutputAsync(Utf8($"{i}"));
        index.Attempts.Should().HaveCount(before + 1, "the timed-out attempt had its full limit: a back-off holds the next three");
        run.Delivery!.Error.Should().Be("seq 1: TimeoutException");
        now += TimeSpan.FromSeconds(6);
        index.Delay = TimeSpan.Zero;
        await run.RecordModelOutputAsync(Utf8("after the back-off"));
        run.Delivery!.Status.Should().Be("delivered");
    }

    [Fact]
    public async Task DisclosePolicyAlone_ATricklingAnswerEndsAtTheUploadLimit_AndTheRunStarts()
    {
        var index = new DeliveryIndex(new StubSealer())
        {
            Respond = _ => new HttpResponseMessage(HttpStatusCode.Created) { Content = new StreamContent(new TrickleStream(TimeSpan.FromMilliseconds(500))) },
        };
        var client = new SigillClient(new HttpClient(index) { BaseAddress = new Uri("https://api.example") });
        using var owned = client;
        var watch = Stopwatch.StartNew();
        var run = await AgentRun.StartCoreAsync(client, Agent(), PolicyOptions() with { DisclosePolicy = true }, Clock(), CancellationToken.None);
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(15));
        run.PolicyDisclosure.Should().Be(new AgentIndexResult("failed", Error: "TimeoutException"));
        run.Artifacts.Should().ContainSingle(a => a.StepType == "run_start");
    }

    [Fact]
    public async Task ServerText_NeverReachesTheError()
    {
        var hostile = "x\r\n\u001b[2Kstatus=delivered" + new string('A', 10_000);
        var index = new DeliveryIndex(new StubSealer());
        index.Answer = u => Label(u) == "1:retrieval"
            ? (HttpStatusCode.UnprocessableEntity, new JsonObject { ["code"] = hostile, ["message"] = "secret detail" }.ToJsonString(), "application/json")
            : null;
        var (run, _, client) = await StartDelivered(index: index);
        using var owned = client;
        await run.RecordRetrievalAsync(Utf8("r"));
        run.Delivery!.Error.Should().Be("seq 1: 422");
        var (r2, _, c2) = await StartDelivered(index: new DeliveryIndex(new StubSealer())
            { Answer = u => Label(u) == "1:model_output" ? Error(HttpStatusCode.UnprocessableEntity, "Not_lower") : null });
        using var o2 = c2;
        await r2.RecordModelOutputAsync(Utf8("x"));
        r2.Delivery!.Error.Should().Be("seq 1: 422", "a code outside ^[a-z0-9_]{1,64}$ is not kept");
        // A transport failure is named by its type only, never by its message.
        var (r3, _, c3) = await StartDelivered(index: new DeliveryIndex(new StubSealer()) { Down = true });
        using var o3 = c3;
        r3.Delivery!.Error.Should().Be("control artifact: HttpRequestException");
    }

    // ── Time budgets ──

    [Fact]
    public async Task AnOrdinaryTurn_StopsAtItsBudget_AndTheRestWaitsWithoutABackoff()
    {
        var index = new DeliveryIndex(new StubSealer());
        var now = TimeSpan.FromHours(1);
        var (run, _, client) = await StartDelivered(index: index, indexClock: () => now);
        using var owned = client;
        run.IndexLimits = new AgentRunIndex.Limits(TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(800), TimeSpan.FromSeconds(2));
        index.Answer = _ => (HttpStatusCode.ServiceUnavailable, "busy", "text/plain");
        await run.RecordModelOutputAsync(Utf8("held"));
        index.Answer = null;
        for (var i = 0; i < 40; i++) await run.RecordModelOutputAsync(Utf8($"{i}"));   // within the back-off: held
        now += TimeSpan.FromSeconds(6);
        index.Delay = TimeSpan.FromMilliseconds(100);
        var watch = Stopwatch.StartNew();
        await run.RecordModelOutputAsync(Utf8("one call"));
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2), "one ordinary call stays within its budget");
        var d = run.Delivery!;
        (d.Status, d.Delivered > 2, d.Pending > 20).Should().Be(("pending", true, true));
        d.Error.Should().EndWith(": time budget used up");
        var delivered = d.Delivered;
        await run.RecordModelOutputAsync(Utf8("next call"));   // no back-off: the next turn carries on
        run.Delivery!.Delivered.Should().BeGreaterThan(delivered);
        index.Indexed.Should().Equal(Chain(run).Take(index.Indexed.Count));
    }

    [Fact]
    public async Task TheFinalTurn_StopsAtItsBudget_AndReportsPending()
    {
        var index = new DeliveryIndex(new StubSealer());
        var (run, _, client) = await StartDelivered(index: index);
        using var owned = client;
        run.IndexLimits = new AgentRunIndex.Limits(TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(50), TimeSpan.FromSeconds(1));
        index.Delay = TimeSpan.FromMilliseconds(100);
        for (var i = 0; i < 30; i++) await run.RecordModelOutputAsync(Utf8($"{i}"));
        var watch = Stopwatch.StartNew();
        var bundle = await run.FinishAsync();
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2.5));
        bundle.Artifacts.Should().HaveCount(32);
        run.Delivery!.Should().Match<AgentRunDelivery>(d => d.Status == "pending" && d.Pending > 0 && d.Error!.EndsWith(": time budget used up"));
    }

    /// <summary>A body that arrives one byte at a time.</summary>
    private sealed class TrickleStream(TimeSpan every) : Stream
    {
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            await Task.Delay(every, ct);
            buffer[offset] = (byte)' ';
            return 1;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            await Task.Delay(every, ct);
            buffer.Span[0] = (byte)' ';
            return 1;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    [Fact]
    public async Task ASlowAnswer_IsCutAtTheUploadsDeadline()
    {
        var index = new DeliveryIndex(new StubSealer());
        index.Respond = u => Label(u) == "1:model_output"
            ? new HttpResponseMessage(HttpStatusCode.Created) { Content = new StreamContent(new TrickleStream(TimeSpan.FromMilliseconds(300))) }
            : null;
        var (run, _, client) = await StartDelivered(index: index);
        using var owned = client;
        run.IndexLimits = new AgentRunIndex.Limits(TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
        var watch = Stopwatch.StartNew();
        await run.RecordModelOutputAsync(Utf8("x"));
        watch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2.5));
        run.Delivery!.Should().Match<AgentRunDelivery>(d => d.Status == "pending" && d.Error == "seq 1: TimeoutException");
    }

    // ── Redirects, over the network ──

    /// <summary>A one-answer HTTP server on the loopback interface; records what it receives.</summary>
    private sealed class LoopbackServer : IDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        public int Port { get; }
        public List<string> Received { get; } = new();

        public LoopbackServer(string answer)
        {
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    TcpClient connection;
                    try { connection = await _listener.AcceptTcpClientAsync(); }
                    catch { return; }
                    _ = Task.Run(async () =>
                    {
                        using (connection)
                            try
                            {
                                var stream = connection.GetStream();
                                var buffer = new byte[65536];
                                var n = await stream.ReadAsync(buffer);
                                lock (Received) Received.Add(Encoding.Latin1.GetString(buffer, 0, n));
                                await stream.WriteAsync(Encoding.Latin1.GetBytes(answer));
                                await Task.Delay(100);
                            }
                            catch { /* the client went away */ }
                    });
                }
            });
        }

        public void Dispose() => _listener.Stop();
    }

    [Theory]
    [InlineData(301)]
    [InlineData(302)]
    [InlineData(303)]
    [InlineData(307)]
    [InlineData(308)]
    public async Task ARedirect_IsNotFollowed_AndTheOtherHostReceivesNothing(int status)
    {
        using var other = new LoopbackServer("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 6\r\nConnection: close\r\n\r\n<html>");
        using var index = new LoopbackServer($"HTTP/1.1 {status} Moved\r\nLocation: http://127.0.0.1:{other.Port}/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var client = new SigillClient("an-api-key", $"http://127.0.0.1:{index.Port}");
        var bundle = new AgentRunBundle(null, new AgentRunArtifact(new JsonObject { ["schemaName"] = "AgentControlArtifact", ["evidenceId"] = "e" },
            new JsonObject(), new Dictionary<string, string>()), Array.Empty<AgentRunArtifact>());
        var result = await client.DeliverAgentRunAsync(bundle);
        await Task.Delay(200);
        result.Should().Be(new AgentRunDelivery("rejected", 0, 1, null, $"control artifact: {status} unexpected_response"));
        index.Received.Should().ContainSingle();
        other.Received.Should().BeEmpty();
    }

    [Theory]
    [InlineData(307)]
    [InlineData(308)]
    public async Task ACallersClientThatFollowsARedirect_GetsTheAnswerRejected_NeverDelivered(int status)
    {
        using var other = new LoopbackServer("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 67\r\nConnection: close\r\n\r\n"
            + """{"status":"indexed","runId":"0e0e0e0e-0000-0000-0000-000000000001"}""");
        using var index = new LoopbackServer($"HTTP/1.1 {status} Moved\r\nLocation: http://127.0.0.1:{other.Port}/api/agent-evidence/artifacts\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        using var http = new HttpClient { BaseAddress = new Uri($"http://127.0.0.1:{index.Port}") };   // follows redirects, as a default client does
        using var client = new SigillClient(http);
        var bundle = new AgentRunBundle(null, new AgentRunArtifact(new JsonObject { ["schemaName"] = "AgentControlArtifact", ["evidenceId"] = "e" },
            new JsonObject(), new Dictionary<string, string>()), Array.Empty<AgentRunArtifact>());
        var result = await client.DeliverAgentRunAsync(bundle);
        result.Should().Be(new AgentRunDelivery("rejected", 0, 1, null, "control artifact: 201 unexpected_response"));
        other.Received.Should().ContainSingle("the redirect was followed by the caller's client");
    }

    // ── The guard is sound whatever the index does ──

    [Theory]
    [InlineData("down")]
    [InlineData("503")]
    [InlineData("422")]
    [InlineData("html200")]
    [InlineData("garbage")]
    public async Task TheGuardDeniesAndHalts_WhateverTheIndexAnswers(string mode)
    {
        var index = new DeliveryIndex(new StubSealer());
        if (mode == "down") index.Down = true;
        else index.Answer = _ => mode switch
        {
            "503" => (HttpStatusCode.ServiceUnavailable, "x", "text/plain"),
            "422" => Error(HttpStatusCode.UnprocessableEntity, "nope"),
            "html200" => (HttpStatusCode.OK, "<html>", "text/html"),
            _ => (HttpStatusCode.Conflict, "\u0000\u0001{", "application/json"),
        };
        var (run, _, client) = await StartDelivered(GuardOptions(WithEnforcement(e => e["haltAfterDenials"] = 1), TestEngine.Shared)
            with { DeliverRun = true }, index, SupportAgent());
        using var owned = client;
        await FluentActions.Awaiting(() => run.BeginToolCallAsync("search.web", Utf8("{}"))).Should().ThrowAsync<PolicyDeniedException>();
        await FluentActions.Awaiting(() => run.RecordRetrievalAsync(Utf8("x"))).Should().ThrowAsync<RunHaltedException>();
        await run.FinishAsync();
        (run.Artifacts[^1].StepType, run.IsHalted, run.IsBroken).Should().Be(("run_end", true, false));
        run.Delivery!.Status.Should().NotBe("delivered");
    }

    // ── Only envelopes, signatures and digests leave the machine ──

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task NoPayloadLeavesTheMachine_OnlyThePolicyDocumentWhenDisclosed(bool disclose)
    {
        var markers = Enumerable.Range(0, 10).Select(i => $"PAYLOAD-MARKER-{i}-5e1d").ToArray();
        var index = new DeliveryIndex(new StubSealer());
        var options = (disclose ? PolicyOptions() : Options()) with
        {
            DeliverRun = true, DisclosePolicy = disclose, RetainPayloads = true, Delegating = true,
            StartObjects = new[] { AgentRunObject.Text("model-input", markers[9]) },
        };
        var client = new SigillClient(new HttpClient(index) { BaseAddress = new Uri("https://api.example") });
        using var owned = client;
        var run = await AgentRun.StartCoreAsync(client, Agent(), options, Clock(), CancellationToken.None);
        await run.RecordToolCallAsync("lookup_ticket", Utf8(markers[0]), useId: "c1");
        await run.RecordToolResultAsync("lookup_ticket", Utf8(markers[1]), useId: "c1");
        await run.RecordAsync("model_output", new[] { AgentRunObject.Text("model-input", markers[2]), AgentRunObject.Text("model-output", markers[3]) });
        await run.RecordHumanApprovalAsync("approved", receipt: Utf8(markers[4]), identityAssertion: Utf8(markers[5]), approver: "ref-1", detail: "ok");
        await run.RecordRetrievalAsync(Utf8(markers[7]), detail: "d");
        var delegation = await run.DelegateAsync(Agent().AgentId, Utf8(markers[6]));
        var child = await AgentRun.StartCoreAsync(client, Agent(), Options() with { DeliverRun = true, RetainPayloads = true, Activity = "child" },
            Clock(), CancellationToken.None, delegation);
        await child.RecordToolCallAsync("lookup_ticket", Utf8(markers[0]), useId: "k1");
        await child.RecordToolResultAsync("lookup_ticket", Utf8(markers[8]), useId: "k1");
        await child.FinishAsync();
        await run.CompleteDelegationAsync(child);
        var bundle = await run.FinishAsync();
        (run.Delivery!.Status, child.Delivery!.Status).Should().Be(("delivered", "delivered"));

        var configuration = Agent().Configuration!;
        var secrets = markers.Select(Utf8).Concat(new[] { configuration.InstructionSet!, configuration.ToolManifest!, configuration.ModelConfig!,
            configuration.ExecutionPolicy!, options.BaselineState! }).ToList();
        var document = options.ControlSet.Content;
        var relaxed = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        string[] Forms(byte[] b) => new[]
        {
            Encoding.UTF8.GetString(b), Convert.ToBase64String(b).TrimEnd('='), Convert.ToHexString(b).ToLowerInvariant(),
            Convert.ToBase64String(new byte[] { 0 }.Concat(b).ToArray())[4..^4], Convert.ToBase64String(new byte[] { 0, 0 }.Concat(b).ToArray())[4..^4],
        };
        bool Carries(string text, byte[] b) => Forms(b).Any(f => text.Contains(f, StringComparison.Ordinal));

        var live = index.Attempts.Count;
        foreach (var upload in index.Attempts)
        {
            var text = upload.ToJsonString(relaxed);
            upload.Select(kv => kv.Key).Should().BeSubsetOf(new[] { "envelope", "signature", "objectDigests", "controlSet" });
            secrets.Where(b => Carries(text, b)).Should().BeEmpty();
            var parentControl = Label(upload) == "control" && upload["envelope"]!["activity"]!["name"]!.GetValue<string>() != "child";
            if (disclose && parentControl) Convert.FromBase64String(upload["controlSet"]!.GetValue<string>()).Should().Equal(document);
            else { upload["controlSet"].Should().BeNull(); Carries(text, document).Should().BeFalse(); }
        }
        // Catch-up from a saved bundle that carries every payload: still only envelopes, signatures and digests.
        var saved = AgentRunBundle.Parse(bundle.ToJsonString());
        saved.Payloads.Should().NotBeEmpty();
        (await client.DeliverAgentRunAsync(saved)).Status.Should().Be("delivered");
        foreach (var upload in index.Attempts.Skip(live))
        {
            var text = upload.ToJsonString(relaxed);
            upload.Select(kv => kv.Key).Should().BeEquivalentTo(new[] { "envelope", "signature", "objectDigests" });
            secrets.Append(document).Where(b => Carries(text, b)).Should().BeEmpty();
        }
    }
}
