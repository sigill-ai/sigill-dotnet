using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>
/// Kjernepåstanden: kontrollgrunnlaget var låst før kjøringen. Bindingen via
/// signaturhash beviser rekkefølgen logisk; sigTst beviser den i tid, med
/// platformens klokke. Verifikatoren må skille «forseglet før» fra «laget
/// etterpå og bundet inn».
/// </summary>
public class SealTimeOrderTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 16, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Seal_tiden_leses_fra_sigTst_i_det_ekte_artefaktet()
    {
        var (artifacts, _) = Vector10.Load();
        var control = artifacts.Single(a => a.ContentType == AgentProfiles.ControlArtifactContentType);
        var runStart = artifacts.Single(a => a.StepType == AgentProfiles.Steps.RunStart);

        control.SealTime.Should().NotBeNull();
        runStart.SealTime.Should().NotBeNull();
        // Hele sekunder: TSA-ene i poolen gir ulik presisjon (36.113 mot 36 i vektor 10).
        control.SealTime!.Value.ToUnixTimeSeconds().Should().BeLessThanOrEqualTo(runStart.SealTime!.Value.ToUnixTimeSeconds());
        control.SealTime.Value.Year.Should().Be(2026);
    }

    [Fact]
    public async Task Kontrollgrunnlag_forseglet_foer_run_start_bestaar()
    {
        var run = await ReferenceRun.BuildAsync(new FakeArtifactSealer { Clock = T0 }, T0);
        var result = await new ControlledRunVerifier().VerifyAsync(run.All(), run.Payloads);

        result.ControlSealedBeforeRun.Should().BeTrue();
        result.SealOrderValid.Should().BeTrue();
        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
    }

    [Fact]
    public async Task Kontrollgrunnlag_laget_etterpaa_og_bundet_inn_avvises()
    {
        // Samme sealer, men klokken stilles slik at Control Artifact får et senere
        // tidsstempel enn run_start. Bindingen er ellers korrekt.
        var sealer = new FakeArtifactSealer { Clock = T0.AddMinutes(10) };
        var correlationId = "urn:uuid:" + Guid.NewGuid();
        var controlSet = new DetachedObject(AgentProfiles.Roles.ControlSet, "{}"u8.ToArray(), "application/json");
        var control = await new ControlArtifactBuilder
        {
            ActorId = "urn:acme:harness", ActivityName = "x", CorrelationId = correlationId,
            AgentId = "a", AgentVersion = "1", ControlSetId = "cs", ControlSetVersion = "1", CreatedAt = T0,
        }.SealAsync(new[] { controlSet }, sealer);

        sealer.Clock = T0;
        var agentRun = new AgentRun(sealer, "x", correlationId, "a");
        await agentRun.StartAsync(control, T0);
        await agentRun.FinishAsync(AgentProfiles.Dispositions.Completed, T0.AddSeconds(1));

        var payloads = new Dictionary<string, byte[]> { [controlSet.Uri] = controlSet.Bytes };
        var result = await new ControlledRunVerifier().VerifyAsync(new[] { control }.Concat(agentRun.Artifacts).ToList(), payloads);

        result.Binding.Should().Be(Bindings.Bound, "hashen stemmer, det er tiden som avslører det");
        result.ChainValid.Should().BeTrue();
        result.ControlSealedBeforeRun.Should().BeFalse();
        result.RunVerdict.Should().Be(RunVerdicts.Invalid);
        result.Issues.Should().Contain(i => i.Contains("ikke låst før kjøringen"));
    }

    [Fact]
    public async Task Uten_sigTst_kan_rekkefoelgen_ikke_bevises_og_det_sies()
    {
        var run = await ReferenceRun.BuildAsync(new FakeArtifactSealer { Clock = T0 }, T0);
        var stripped = run.All().Select(a =>
        {
            var signature = a.Signature.DeepClone().AsObject();
            ((System.Text.Json.Nodes.JsonObject)signature["signatures"]![0]!).Remove("header");
            return new AgentArtifact(a.Envelope, signature);
        }).ToList();

        var result = await new ControlledRunVerifier().VerifyAsync(stripped, run.Payloads);

        result.ControlSealedBeforeRun.Should().BeNull();
        result.SealOrderValid.Should().BeNull();
        result.Issues.Should().Contain(i => i.Contains("Seal-tid (sigTst) mangler"));
    }
}
