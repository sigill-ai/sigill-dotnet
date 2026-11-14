// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// The caller's free text in an envelope is bounded (common rules §9): detail, activity name, approver, object metadata.
// Refused at record time before anything is sealed; the same check is public for a receiving index.

using System;
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
    private const string Astral = "\U0001F600";   // one code point, two UTF-16 units, four UTF-8 bytes

    [Theory]
    [InlineData("x")]
    [InlineData(Astral)]
    public async Task Detail_AtTheLimitIsSealed_OneOverIsRefusedBeforeSealingAndUploading(string unit)
    {
        var (run, index, client) = await StartDelivered();
        using var owned = client;
        var sealedBefore = run.Artifacts.Count;
        (await run.CheckpointAsync(string.Concat(Enumerable.Repeat(unit, AgentProfiles.MaxDetailLength))))
            .Envelope["step"]!["detail"]!.GetValue<string>().Length.Should().Be(AgentProfiles.MaxDetailLength * unit.Length);
        var attempts = index.Attempts.Count;
        var over = string.Concat(Enumerable.Repeat(unit, AgentProfiles.MaxDetailLength + 1));
        foreach (var attempt in new Func<Task>[]
        {
            () => run.CheckpointAsync(over),
            () => run.RecordRetrievalAsync(Utf8("{}"), detail: over),
            () => run.RecordAuthorizationAsync(new AgentAuthorization { Decision = "allowed", Detail = over }),
            () => run.RecordAsync("checkpoint", fields: new JsonObject { ["detail"] = over }),
            () => run.FinishAsync(detail: over),
        })
        {
            var e = (await FluentActions.Awaiting(attempt).Should().ThrowAsync<ArgumentException>()).Which;
            e.Message.Should().Be("step.detail is longer than 512 characters; nothing was sealed.");
        }
        (run.Artifacts.Count, index.Attempts.Count, run.IsBroken).Should().Be((sealedBefore + 1, attempts, false));
        await run.FinishAsync();
    }

    [Theory]
    [InlineData("a")]
    [InlineData(Astral)]
    public async Task ActivityName_AtTheLimitStarts_OneOverIsRefusedBeforeAnythingIsSealed(string unit)
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var atLimit = string.Concat(Enumerable.Repeat(unit, AgentProfiles.MaxActivityNameLength));
        (await Start(client, Options() with { Activity = atLimit })).ControlArtifact.Envelope["activity"]!["name"]!.GetValue<string>().Should().Be(atLimit);
        var before = sealer.Requests.Count;
        var e = (await FluentActions.Awaiting(() => Start(client, Options() with { Activity = atLimit + unit })).Should().ThrowAsync<ArgumentException>()).Which;
        e.Message.Should().Be("activity.name is longer than 255 characters; nothing was sealed.").And.NotContain(atLimit);
        sealer.Requests.Should().HaveCount(before);
    }

    [Fact]
    public async Task Approver_AtTheLimitIsSealed_OneOverIsRefused()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client, PolicyV2Options());
        var atLimit = string.Concat(Enumerable.Repeat(Astral, AgentProfiles.MaxApproverLength));
        await run.RecordHumanApprovalAsync("approved", approver: atLimit);
        var before = sealer.Requests.Count;
        foreach (var attempt in new Func<Task>[]
        {
            () => run.RecordHumanApprovalAsync("approved", approver: atLimit + "x"),
            () => run.RecordBoundApprovalAsync("approved", ApprovalCovers.ForArguments("t", Utf8("{}")), approver: atLimit + "x"),
        })
            (await FluentActions.Awaiting(attempt).Should().ThrowAsync<ArgumentException>()).Which.Message
                .Should().Be("step.approver is longer than 255 characters; nothing was sealed.");
        sealer.Requests.Should().HaveCount(before);
    }

    [Fact]
    public async Task TheCheck_OnEnvelopesTheSdkBuilt_NullAtEachLimit_TheMessageOneOver_AndNeverThrows()
    {
        using var client = Client(new StubSealer());
        var run = await Start(client, PolicyV2Options() with { Activity = new string('a', AgentProfiles.MaxActivityNameLength) });
        var approval = await run.RecordHumanApprovalAsync("approved", approver: new string('p', AgentProfiles.MaxApproverLength),
            detail: new string('d', AgentProfiles.MaxDetailLength));
        var call = await run.RecordToolCallAsync("t", Utf8("{}"));
        foreach (var e in new[] { run.ControlArtifact.Envelope, approval.Envelope, call.Envelope })
            AgentProfiles.CheckFreeTextLimits(e).Should().BeNull();

        JsonObject With(JsonObject e, Action<JsonObject> change) { var c = (JsonObject)e.DeepClone(); change(c); return c; }
        AgentProfiles.CheckFreeTextLimits(With(run.ControlArtifact.Envelope, c => c["activity"]!["name"] = new string('a', 256)))
            .Should().Be("activity.name is longer than 255 characters");
        AgentProfiles.CheckFreeTextLimits(With(approval.Envelope, c => c["step"]!["detail"] = new string('d', 513)))
            .Should().Be("step.detail is longer than 512 characters");
        AgentProfiles.CheckFreeTextLimits(With(approval.Envelope, c => c["step"]!["approver"] = new string('p', 256)))
            .Should().Be("step.approver is longer than 255 characters");

        // metadata in bytes: canonical JSON {"n":"…"} is 8 bytes of frame; é is two UTF-8 bytes.
        JsonObject Metadata(int bytes) => With(call.Envelope, c => c["objects"]![0]!["metadata"] = new JsonObject
        {
            ["n"] = new string('é', (bytes - 8) / 2) + new string('x', (bytes - 8) % 2),
        });
        Encoding.UTF8.GetByteCount(Metadata(2048)["objects"]![0]!["metadata"]!.ToJsonString(new System.Text.Json.JsonSerializerOptions
            { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping })).Should().Be(2048);
        AgentProfiles.CheckFreeTextLimits(Metadata(2048)).Should().BeNull();
        AgentProfiles.CheckFreeTextLimits(Metadata(2049)).Should().Be("objects[0].metadata is larger than 2048 bytes");
        AgentProfiles.CheckFreeTextLimits(With(run.ControlArtifact.Envelope, c => c["objects"]![1]!["metadata"] = new JsonObject { ["n"] = new string('x', 2041) }))
            .Should().Be("objects[1].metadata is larger than 2048 bytes");

        // extensions in bytes, like metadata: {"x":{"n":"…"}} is 14 bytes of frame.
        JsonObject Extensions(int bytes) => With(call.Envelope, c => c["extensions"] = new JsonObject
        {
            ["x"] = new JsonObject { ["n"] = new string('é', (bytes - 14) / 2) + new string('x', (bytes - 14) % 2) },
        });
        AgentProfiles.CheckFreeTextLimits(Extensions(2048)).Should().BeNull();
        AgentProfiles.CheckFreeTextLimits(Extensions(2049)).Should().Be("extensions is larger than 2048 bytes");
        AgentProfiles.CheckFreeTextLimits(With(run.ControlArtifact.Envelope, c => c["extensions"] = new JsonObject { ["x"] = new JsonObject { ["n"] = new string('x', 2035) } }))
            .Should().Be("extensions is larger than 2048 bytes");
        AgentProfiles.CheckFreeTextLimits(With(call.Envelope, c => c["extensions"] = JsonValue.Create(new string('x', 5000)))).Should().BeNull("not an object");
        AgentProfiles.CheckFreeTextLimits(With(call.Envelope, c => c["extensions"] = new JsonArray(JsonValue.Create(new string('x', 5000))))).Should().BeNull("not an object");

        // Malformed or foreign shapes are not this check's business.
        foreach (var odd in new JsonNode?[]
        {
            null, new JsonArray(), JsonValue.Create("envelope"), JsonNode.Parse("""{"activity":"x","step":[1],"objects":{}}"""),
            JsonNode.Parse("""{"activity":{"name":5},"step":{"detail":{"a":1},"approver":null},"objects":[3,{"metadata":null}]}"""),
        })
            AgentProfiles.CheckFreeTextLimits(odd).Should().BeNull();
        (AgentProfiles.MaxDetailLength, AgentProfiles.MaxActivityNameLength, AgentProfiles.MaxApproverLength, AgentProfiles.MaxObjectMetadataBytes,
            AgentProfiles.MaxExtensionsBytes).Should().Be((512, 255, 255, 2048, 2048));
    }

    [Fact]
    public async Task DecisionAndContentType_AtTheLimitAreSealed_OneOverIsRefused()
    {
        var sealer = new StubSealer();
        using var client = Client(sealer);
        var run = await Start(client);
        var atLimit = string.Concat(Enumerable.Repeat(Astral, 255));
        await run.RecordAuthorizationAsync(new AgentAuthorization { Decision = atLimit });
        await run.RecordToolCallAsync("t", Utf8("{}"), contentType: atLimit);
        var before = sealer.Requests.Count;
        (await FluentActions.Awaiting(() => run.RecordAuthorizationAsync(new AgentAuthorization { Decision = atLimit + "x" })).Should().ThrowAsync<ArgumentException>())
            .Which.Message.Should().Be("step.decision is longer than 255 characters; nothing was sealed.");
        (await FluentActions.Awaiting(() => run.RecordToolCallAsync("t", Utf8("{}"), contentType: atLimit + "x")).Should().ThrowAsync<ArgumentException>())
            .Which.Message.Should().Be("objects[0].contentType is longer than 255 characters; nothing was sealed.");
        (await FluentActions.Awaiting(() => Start(client, Options() with { BaselineStateContentType = atLimit + "x" })).Should().ThrowAsync<ArgumentException>())
            .Which.Message.Should().StartWith("objects[").And.EndWith("].contentType is longer than 255 characters; nothing was sealed.");
        sealer.Requests.Should().HaveCount(before);
        (AgentProfiles.MaxDecisionLength, AgentProfiles.MaxContentTypeLength).Should().Be((255, 255));
    }

    [Fact]
    public void TheCheck_NeverThrows_OnValuesThatAreNotStrings()
    {
        foreach (var value in new JsonNode?[] { JsonValue.Create(Guid.NewGuid()), JsonValue.Create(DateTimeOffset.UtcNow), JsonValue.Create('x'), JsonValue.Create(DateTime.UtcNow), JsonValue.Create(double.NaN) })
        {
            var envelope = new JsonObject
            {
                ["activity"] = new JsonObject { ["name"] = value!.DeepClone() },
                ["step"] = new JsonObject { ["detail"] = value.DeepClone(), ["approver"] = value.DeepClone(), ["decision"] = value.DeepClone() },
                ["objects"] = new JsonArray(new JsonObject { ["contentType"] = value.DeepClone(), ["metadata"] = new JsonObject { ["v"] = value.DeepClone() } }),
                ["extensions"] = new JsonObject { ["v"] = value.DeepClone() },
            };
            FluentActions.Invoking(() => AgentProfiles.CheckFreeTextLimits(envelope)).Should().NotThrow();
        }
    }

    // The bytes of a bound are those of the canonical (JCS) form: escapes as JCS writes them.
    [Theory]
    [InlineData("é", 1020, true)]
    [InlineData("é", 1021, false)]
    [InlineData("\U0001F600", 510, true)]
    [InlineData("\U0001F600", 511, false)]
    [InlineData("\u0001", 340, true)]
    [InlineData("\u0001", 341, false)]
    [InlineData("<", 2040, true)]
    [InlineData("<", 2041, false)]
    [InlineData("\u2028", 680, true)]
    [InlineData("\u2028", 681, false)]
    public void ExtensionsBytes_AreCountedInCanonicalForm(string fill, int count, bool within)
    {
        var text = System.Text.RegularExpressions.Regex.Unescape(fill.Replace("\\U0001F600", "\uD83D\uDE00"));
        var envelope = new JsonObject { ["extensions"] = new JsonObject { ["k"] = string.Concat(Enumerable.Repeat(text, count)) } };
        (AgentProfiles.CheckFreeTextLimits(envelope) is null).Should().Be(within);
    }
}
