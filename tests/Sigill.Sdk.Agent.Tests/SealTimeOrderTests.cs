using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>
/// Seal-tiden som forsvar i dybden. Bindingen beviser rekkefølgen: run_start
/// binder kontrollens signatur, som finnes først etter forsegling. En TSA-tid i
/// strid med det er et avvik hos platform eller TSA, ikke hos produsenten, og
/// rapporteres uten å endre utfallet. Tider langs kjeden sammenlignes ikke.
/// </summary>
public class SealTimeOrderTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 16, 8, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Seal_tid_og_accuracy_leses_fra_sigTst_i_det_ekte_artefaktet()
    {
        var (artifacts, _) = Vector10.Load();
        var control = artifacts.Single(a => a.ContentType == AgentProfiles.ControlArtifactContentType);
        var runStart = artifacts.Single(a => a.StepType == AgentProfiles.Steps.RunStart);

        control.SealTime.Should().NotBeNull();
        runStart.SealTime.Should().NotBeNull();
        control.SealAccuracy.Should().Be(TimeSpan.FromMilliseconds(500), "Microsoft-TSA oppgir 500 ms");
        runStart.SealAccuracy.Should().Be(TimeSpan.FromSeconds(1));
        // Ulik presisjon fra ulike TSA-er: 36.113 mot 36. Derfor hele sekunder.
        control.SealTime!.Value.ToUnixTimeSeconds().Should().BeLessThanOrEqualTo(runStart.SealTime!.Value.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task Ekte_kjoring_bestaar_tidskontrollen()
    {
        var (artifacts, payloads) = Vector10.Load();
        var result = await new ControlledRunVerifier().VerifyAsync(artifacts, payloads);
        result.ControlSealedBeforeRun.Should().BeTrue();
    }

    [Fact]
    public async Task TSA_tid_i_strid_med_bindingen_rapporteres_uten_aa_endre_utfallet()
    {
        // Kan bare oppstå hvis tidsstemplet er feil: run_start binder kontrollens
        // signatur, så kontrollen fantes først. Testklokken tvinger frem tilstanden.
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

        result.Binding.Should().Be(Bindings.Bound);
        result.ChainValid.Should().BeTrue();
        result.ControlSealedBeforeRun.Should().BeFalse();
        result.RunVerdict.Should().Be(RunVerdicts.Finalized, "rekkefølgen er bevist av bindingen; tidsavviket er platformens");
        result.Issues.Should().ContainSingle().Which.Should().Contain("avvik hos platform eller TSA");
    }

    [Fact]
    public async Task Klokkeavvik_innenfor_ett_sekund_gir_ikke_avvik()
    {
        // To raske segl fra to TSA-er med litt ulik klokke: kontrollen stemples 900 ms "etter" run_start.
        var sealer = new FakeArtifactSealer { Clock = T0.AddMilliseconds(900) };
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

        var result = await new ControlledRunVerifier().VerifyAsync(new[] { control }.Concat(agentRun.Artifacts).ToList(),
            new Dictionary<string, byte[]> { [controlSet.Uri] = controlSet.Bytes });

        result.ControlSealedBeforeRun.Should().BeTrue();
        result.Issues.Should().BeEmpty();
    }

    [Fact]
    public async Task EventTime_etter_seal_tid_rapporteres_uten_aa_endre_utfallet()
    {
        // Produsentens klokke påstår at hendelsen skjedde ti minutter etter at den ble forseglet.
        var sealer = new FakeArtifactSealer { Clock = T0 };
        var correlationId = "urn:uuid:" + Guid.NewGuid();
        var controlSet = new DetachedObject(AgentProfiles.Roles.ControlSet, "{}"u8.ToArray(), "application/json");
        var control = await new ControlArtifactBuilder
        {
            ActorId = "urn:acme:harness", ActivityName = "x", CorrelationId = correlationId,
            AgentId = "a", AgentVersion = "1", ControlSetId = "cs", ControlSetVersion = "1", CreatedAt = T0,
        }.SealAsync(new[] { controlSet }, sealer);
        var agentRun = new AgentRun(sealer, "x", correlationId, "a");
        await agentRun.StartAsync(control, T0.AddMinutes(10));
        await agentRun.FinishAsync(AgentProfiles.Dispositions.Completed, T0.AddMinutes(10));

        var result = await new ControlledRunVerifier().VerifyAsync(new[] { control }.Concat(agentRun.Artifacts).ToList(),
            new Dictionary<string, byte[]> { [controlSet.Uri] = controlSet.Bytes });

        result.EventTimesPlausible.Should().BeFalse();
        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
        result.Issues.Should().Contain(i => i.Contains("produsentens klokke"));

        var honest = await ReferenceRun.BuildAsync(new FakeArtifactSealer { Clock = T0.AddSeconds(5) }, T0);
        (await new ControlledRunVerifier().VerifyAsync(honest.All(), honest.Payloads)).EventTimesPlausible.Should().BeTrue();
    }

    [Fact]
    public async Task Uten_sigTst_kan_tiden_ikke_kontrolleres_og_det_sies()
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
        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
        result.Issues.Should().ContainSingle().Which.Should().Contain("Seal-tid (sigTst) mangler");
    }
}
