// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Agent Delegation v1: the run-tree vectors (spec/test-vectors/agent-run-tree) through the
// stub verifier, and the recorder's delegation API end-to-end against the stub sealer.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    private static string TreeVectorsDir => Path.Combine(SpecRoot.TestVectorsDir, "agent-run-tree", "trees");

    public static IEnumerable<object[]> TreeVectors() =>
        Directory.GetFiles(TreeVectorsDir, "*.json").Select(f => new object[] { Path.GetFileName(f) }).OrderBy(f => (string)f[0]);

    [Fact]
    public void TreeVectors_AreAllPresent() => TreeVectors().Should().HaveCount(35);

    private static AgentRunTreeOptions? TreeOptions(JsonNode? o) => o is null ? null : new AgentRunTreeOptions
    {
        ExpectedRootCorrelationId = o["expectedRootCorrelationId"]?.GetValue<string>(),
        ExpectedSigners = (o["expectedSigners"] as JsonObject)?.ToDictionary(
            kv => kv.Key, kv => (IReadOnlyCollection<string>)kv.Value!.AsArray().Select(x => x!.GetValue<string>()).ToList()),
    };

    private static async Task<AgentRunTreeVerificationResult> VerifyTreeVector(string file)
    {
        var v = JsonNode.Parse(File.ReadAllText(Path.Combine(TreeVectorsDir, file)))!;
        var tree = AgentRunTreeBundle.Parse(v["tree"]!.ToJsonString());
        return await AgentRunTreeVerifier.VerifyAsync(tree, StubVerify, TreeOptions(v["options"]));
    }

    [Theory]
    [MemberData(nameof(TreeVectors))]
    public async Task TreeVector_ReproducesExpectedResult(string file)
    {
        var expected = JsonNode.Parse(File.ReadAllText(Path.Combine(TreeVectorsDir, file)))!["expected"]!;
        var r = await VerifyTreeVector(file);

        r.Verdict.Should().Be(expected["verdict"]!.GetValue<string>(), string.Join("; ", r.Findings.Select(f => f.Detail)));
        r.Findings.Select(f => f.Code).Distinct().OrderBy(c => c, StringComparer.Ordinal)
            .Should().Equal(expected["findings"]!.AsArray().Select(x => x!.GetValue<string>()));
        r.OpenReasons.Select(f => f.Code).Distinct().OrderBy(c => c, StringComparer.Ordinal)
            .Should().Equal(expected["openReasons"]!.AsArray().Select(x => x!.GetValue<string>()));
        r.Fingerprint.Should().Be(expected["fingerprint"]?.GetValue<string>());
        if (expected["root"] is { } root && !r.Findings.Any(f => f.Code == "limit_exceeded"))
            r.RootCorrelationId.Should().Be(root.GetValue<string>());

        var runs = expected["runs"]!.AsObject();
        if (runs.Count > 0)
            foreach (var run in r.Runs)
                run.Result!.Verdict.Should().Be(runs[run.CorrelationId!]!.GetValue<string>(), $"run {run.CorrelationId}");
        static string Key(string p, string c, string b, string k) => $"{p} → {c}: {b}/{k}";
        r.Edges.Select(e => Key(e.ParentCorrelationId, e.ChildCorrelationId, e.Binding, e.Completion)).OrderBy(x => x, StringComparer.Ordinal)
            .Should().Equal(expected["edges"]!.AsArray().Select(e => Key(e!["parent"]!.GetValue<string>(), e["child"]!.GetValue<string>(),
                e["binding"]!.GetValue<string>(), e["completion"]!.GetValue<string>())).OrderBy(x => x, StringComparer.Ordinal));
        if (expected["affiliations"] is JsonObject aff)
            foreach (var kv in aff)
                r.Runs.Single(x => x.CorrelationId == kv.Key).Affiliation.Should().Be(kv.Value!.GetValue<string>());
    }

    [Fact]
    public async Task TreeFingerprint_IgnoresRunOrder_AndCoversLaterEvaluations()
    {
        var finalized = await VerifyTreeVector("01-finalized.json");
        (await VerifyTreeVector("70-reordered.json")).Fingerprint.Should().Be(finalized.Fingerprint);
        var evaluated = await VerifyTreeVector("60-later-evaluation.json");
        evaluated.Verdict.Should().Be(finalized.Verdict);
        evaluated.Fingerprint.Should().NotBe(finalized.Fingerprint);
    }

    [Fact]
    public void TreeBundle_RoundTrips_AndRefusesDuplicateNames()
    {
        var json = JsonNode.Parse(File.ReadAllText(Path.Combine(TreeVectorsDir, "01-finalized.json")))!["tree"]!.ToJsonString();
        var tree = AgentRunTreeBundle.Parse(json);
        AgentRunTreeBundle.Parse(tree.ToJsonString()).Runs.Should().HaveCount(3);
        var dup = json.Replace("{\"format\":\"AgentRunTreeBundle\"", "{\"format\":\"AgentRunTreeBundle\",\"format\":\"AgentRunTreeBundle\"");
        dup.Should().NotBe(json);
        FluentActions.Invoking(() => AgentRunTreeBundle.Parse(dup)).Should().Throw<AgentRunBundleFormatException>();
    }

    // ── The recorder's delegation API ───────────────────────────────────────

    private static AgentDefinition Named(string id) => Agent() with { AgentId = id };

    private static AgentRunOptions Delegating() => Options() with { Delegating = true };

    [Fact]
    public async Task RecordedTree_VerifiesAsFinalized_AndOnlyDigestsTravel()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var parent = await AgentRun.StartCoreAsync(client, Agent(), Delegating(), Clock(), CancellationToken.None);
        await parent.RecordToolCallAsync("lookup_ticket", Encoding.UTF8.GetBytes("""{"ticket":"4411"}"""), "read");
        var delegation = await parent.DelegateAsync("urn:example:agent:researcher", Secret, useId: "toolu_1");
        var child = await AgentRun.StartCoreAsync(client, Named("urn:example:agent:researcher"), Options(), Clock(),
            CancellationToken.None, delegation);
        await child.RecordToolCallAsync("search", Encoding.UTF8.GetBytes("""{"q":"reset"}"""), "read");
        await child.FinishAsync();
        await parent.CompleteDelegationAsync(child);
        await parent.FinishAsync();

        child.CorrelationId.Should().Be(delegation.ChildCorrelationId);
        parent.Artifacts.Concat(child.Artifacts).Select(a => a.Envelope["schemaVersion"]!.GetValue<string>()).Should().OnlyContain(v => v == "2");
        var start = child.Artifacts[0].Envelope["binds"]!;
        start["parentDelegationSignatureSha256"]!.GetValue<string>().Should().Be(delegation.DelegationSignatureSha256);
        start["parentCorrelationId"]!.GetValue<string>().Should().Be(parent.CorrelationId);
        sealer.Requests.Should().OnlyContain(rq => !rq.ToJsonString().Contains("Jane Doe"));

        var tree = new AgentRunTreeBundle(parent.CorrelationId, new[] { parent.ToBundle(), child.ToBundle() });
        var r = await AgentRunTreeVerifier.VerifyAsync(tree, StubVerify);
        r.Verdict.Should().Be("tree_finalized", string.Join("; ", r.Findings.Select(f => f.Detail)));
        r.RootCorrelationId.Should().Be(parent.CorrelationId);
        r.Edges.Should().ContainSingle().Which.Should().Match<AgentRunTreeEdge>(e =>
            e.Binding == "mutually_bound" && e.Completion == "result_bound" && e.ChildAgentId == "urn:example:agent:researcher");
        r.Runs.Single(x => x.CorrelationId == child.CorrelationId).Depth.Should().Be(1);
        r.Fingerprint.Should().NotBeNull();
    }

    [Fact]
    public async Task Parent_CannotCloseCompleted_WithAnOpenDelegation_ButMayAbort()
    {
        using var client = Client(new StubSealer());
        var parent = await AgentRun.StartCoreAsync(client, Agent(), Delegating(), Clock(), CancellationToken.None);
        var delegation = await parent.DelegateAsync("urn:example:agent:researcher");
        parent.OutstandingDelegations.Should().Equal(delegation.ChildCorrelationId);
        await FluentActions.Awaiting(() => parent.FinishAsync()).Should().ThrowAsync<InvalidOperationException>();
        parent.IsBroken.Should().BeFalse();
        await parent.FinishAsync("aborted");

        var r = await AgentRunTreeVerifier.VerifyAsync(new AgentRunTreeBundle(null, new[] { parent.ToBundle() }), StubVerify);
        r.Verdict.Should().Be("tree_open");
        r.Edges.Single().Binding.Should().Be("child_missing");
        r.OpenReasons.Select(o => o.Code).Should().Equal("parent_terminated");
    }

    [Fact]
    public async Task DelegationApi_RefusesWhatWouldNotVerify()
    {
        using var client = Client(new StubSealer());
        var plain = await Start(client);
        await FluentActions.Awaiting(() => plain.DelegateAsync("urn:example:agent:x")).Should().ThrowAsync<InvalidOperationException>();
        await FluentActions.Awaiting(() => plain.RecordAsync("delegation")).Should().ThrowAsync<ArgumentException>();
        await FluentActions.Awaiting(() => plain.RecordAsync("tool_call", fields: new JsonObject { ["delegation"] = new JsonObject() }))
            .Should().ThrowAsync<ArgumentException>();

        var parent = await AgentRun.StartCoreAsync(client, Agent(), Delegating(), Clock(), CancellationToken.None);
        await FluentActions.Awaiting(() => parent.DelegateAsync("urn:example:agent:x", childCorrelationId: parent.CorrelationId))
            .Should().ThrowAsync<ArgumentException>();
        var d = await parent.DelegateAsync("urn:example:agent:researcher");
        await FluentActions.Awaiting(() => parent.DelegateAsync("urn:example:agent:researcher", childCorrelationId: d.ChildCorrelationId))
            .Should().ThrowAsync<ArgumentException>();
        await FluentActions.Awaiting(() => AgentRun.StartCoreAsync(client, Named("urn:example:agent:other"), Options(), Clock(),
            CancellationToken.None, d)).Should().ThrowAsync<ArgumentException>();

        var child = await AgentRun.StartCoreAsync(client, Named("urn:example:agent:researcher"), Options(), Clock(), CancellationToken.None, d);
        await FluentActions.Awaiting(() => parent.CompleteDelegationAsync(child)).Should().ThrowAsync<InvalidOperationException>();
        await child.FinishAsync("failed");
        await parent.CompleteDelegationAsync(child);
        await FluentActions.Awaiting(() => parent.CompleteDelegationAsync(child)).Should().ThrowAsync<InvalidOperationException>();
        await FluentActions.Awaiting(() => parent.CompleteDelegationAsync("urn:uuid:never", new string('a', 64), "completed"))
            .Should().ThrowAsync<InvalidOperationException>();
        parent.IsBroken.Should().BeFalse();
        await parent.FinishAsync();

        var r = await AgentRunTreeVerifier.VerifyAsync(new AgentRunTreeBundle(null, new[] { child.ToBundle(), parent.ToBundle() }), StubVerify);
        r.Verdict.Should().Be("tree_finalized");
        r.Edges.Single().ChildDisposition.Should().Be("failed");
    }

    [Fact]
    public async Task EventBudget_KeepsRoomForEveryResultAndRunEnd()
    {
        using var client = Client(new StubSealer());
        var parent = await AgentRun.StartCoreAsync(client, Agent(), Delegating(), Clock(), CancellationToken.None);
        var first = await parent.DelegateAsync("urn:example:agent:researcher");
        var second = await parent.DelegateAsync("urn:example:agent:researcher");
        var note = Encoding.UTF8.GetBytes("ok");
        while (true)
        {
            try { await parent.RecordModelOutputAsync(note); }
            catch (InvalidOperationException) { break; }
        }
        // Two results and run_end are reserved: the run stops three short of the bundle limit.
        parent.Artifacts.Should().HaveCount(AgentRunBundle.MaxArtifacts - 3);
        parent.IsBroken.Should().BeFalse();
        await FluentActions.Awaiting(() => parent.DelegateAsync("urn:example:agent:researcher")).Should().ThrowAsync<InvalidOperationException>();

        foreach (var d in new[] { first, second })
        {
            var child = await AgentRun.StartCoreAsync(client, Named(d.ChildAgentId), Options(), Clock(), CancellationToken.None, d);
            await child.FinishAsync();
            await parent.CompleteDelegationAsync(child);
        }
        var bundle = await parent.FinishAsync();
        bundle.Artifacts.Should().HaveCount(AgentRunBundle.MaxArtifacts);
    }
}
