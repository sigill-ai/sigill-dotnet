using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>Byggernes egne regler, med falsk forsegler.</summary>
public class AgentRunTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 16, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Referansekjoringen_med_falsk_forsegler_verifiserer_bundet_og_avsluttet()
    {
        var run = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), T0);
        var result = await new ControlledRunVerifier().VerifyAsync(run.All(), run.Payloads);

        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
        result.Binding.Should().Be(Bindings.Bound);
        result.Issues.Should().BeEmpty();
    }

    [Fact]
    public async Task Kjoringen_avviser_hendelser_etter_run_end_og_flytter_ikke_seq()
    {
        var sealer = new FakeArtifactSealer();
        var run = await ReferenceRun.BuildAsync(sealer, T0);
        var agentRun = new AgentRun(sealer, "customer-address-change", run.CorrelationId, "contract-agent");
        await agentRun.StartAsync(run.ControlArtifact, T0);
        await agentRun.FinishAsync(AgentProfiles.Dispositions.Aborted, T0.AddSeconds(1));

        var act = () => agentRun.RecordAsync(AgentProfiles.Steps.ToolCall, T0.AddSeconds(2));
        await act.Should().ThrowAsync<SigillException>();
        agentRun.NextSeq.Should().Be(2);
    }

    [Fact]
    public async Task Feilet_forsegling_lager_ikke_hull_i_kjeden()
    {
        var failing = new FailingSealer(new FakeArtifactSealer(), failOnCall: 2);
        var run = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), T0);
        var agentRun = new AgentRun(failing, "customer-address-change", run.CorrelationId, "contract-agent");
        await agentRun.StartAsync(run.ControlArtifact, T0);

        var act = () => agentRun.RecordAsync(AgentProfiles.Steps.Retrieval, T0.AddSeconds(1));
        await act.Should().ThrowAsync<InvalidOperationException>();
        agentRun.NextSeq.Should().Be(1);

        var next = await agentRun.RecordAsync(AgentProfiles.Steps.Retrieval, T0.AddSeconds(2));
        next.Seq.Should().Be(1);
    }

    [Fact]
    public async Task Start_krever_et_Control_Artifact_med_samme_correlationId()
    {
        var sealer = new FakeArtifactSealer();
        var run = await ReferenceRun.BuildAsync(sealer, T0);
        var agentRun = new AgentRun(sealer, "customer-address-change", "urn:uuid:" + Guid.NewGuid(), "contract-agent");

        var act = () => agentRun.StartAsync(run.ControlArtifact, T0);
        await act.Should().ThrowAsync<SigillException>().WithMessage("*correlationId*");
    }

    private sealed class FailingSealer(IArtifactSealer inner, int failOnCall) : IArtifactSealer
    {
        private int _calls;
        public Task<System.Text.Json.Nodes.JsonObject> SealAsync(string envelopeHashHex, IReadOnlyList<SignedObjectDigest> objects, string envelopeContentType, CancellationToken cancellationToken = default)
        {
            if (++_calls == failOnCall) throw new InvalidOperationException("platform nede");
            return inner.SealAsync(envelopeHashHex, objects, envelopeContentType, cancellationToken);
        }
    }
}

public class ControlArtifactRoleTests
{
    [Fact]
    public async Task Baseline_state_forsegles_i_Control_Artifact_og_kan_finnes_igjen()
    {
        var run = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), new DateTimeOffset(2026, 9, 16, 8, 0, 0, TimeSpan.Zero));
        var uri = run.ControlArtifact.UriOfRole(AgentProfiles.Roles.BaselineState);

        uri.Should().NotBeNull();
        var signed = run.ControlArtifact.SignedObjects.Single(o => o.Uri == uri);
        signed.HashHex.Should().Be(EnvelopeHashing.HashHex(run.Payloads[uri!]));
    }
}
