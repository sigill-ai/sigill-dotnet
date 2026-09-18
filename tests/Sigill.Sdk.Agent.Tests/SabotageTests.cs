using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>
/// Sabotasjetestene fra notatet 8.3 som prøvekjøringen dekker, kjørt på
/// lagrede filer uten platform. Kjede, binding og fullstendighet kontrolleres
/// på ekte; signaturgyldighet er ikke tilgjengelig uten platform og er null.
/// </summary>
public class SabotageTests : IAsyncLifetime
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 16, 8, 0, 0, TimeSpan.Zero);
    private string _dir = "";
    private List<AgentArtifact> _artifacts = new();
    private Dictionary<string, byte[]> _payloads = new();

    public async Task InitializeAsync()
    {
        var run = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), T0);
        _dir = run.WriteTo(Path.Combine(Path.GetTempPath(), "sigill-agent-tests", Guid.NewGuid().ToString("N")));
        (_artifacts, _payloads) = ReferenceRun.ReadFrom(_dir);
    }

    public Task DisposeAsync()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
        return Task.CompletedTask;
    }

    private static Task<ControlledRunResult> Verify(IEnumerable<AgentArtifact> artifacts, Dictionary<string, byte[]> payloads) =>
        new ControlledRunVerifier().VerifyAsync(artifacts.ToList(), payloads);

    [Fact]
    public async Task Referansekjoringen_er_komplett_uendret_og_bundet()
    {
        _artifacts.Should().HaveCount(9, "ett Control Artifact, sju hendelser og én evaluering");
        var result = await Verify(_artifacts, _payloads);

        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
        result.ChainValid.Should().BeTrue();
        result.ObjectsComplete.Should().BeTrue();
        result.MissingObjects.Should().BeEmpty();
        result.Binding.Should().Be(Bindings.Bound);
        result.ControlArtifact.Should().Be("verified");
        result.SignaturesValid.Should().BeNull("ingen platform i denne testen");
        result.FinalSeq.Should().Be(6);
        result.RunDisposition.Should().Be("completed");
        result.Evaluations.Should().ContainSingle();
        result.Evaluations[0].SubjectBound.Should().BeTrue();
        result.Evaluations[0].ControlSetDigestMatches.Should().BeTrue();
        result.Evaluations[0].Overall.Should().Be("FAIL");
        result.Evaluations[0].Controls.Should().HaveCount(4);
        result.Issues.Should().BeEmpty();
    }

    [Fact]
    public async Task Slettet_hendelse_seq_3_gir_brutt_kjede_og_run_invalid()
    {
        var withoutSeq3 = _artifacts.Where(a => a.Seq != 3).ToList();
        var result = await Verify(withoutSeq3, _payloads);

        result.ChainValid.Should().BeFalse();
        result.RunVerdict.Should().Be(RunVerdicts.Invalid);
        result.Issues.Should().Contain(i => i.Contains("seq 3"));
    }

    [Fact]
    public async Task Fjernet_run_end_gir_run_open_med_alt_annet_gront()
    {
        var withoutRunEnd = _artifacts.Where(a => a.StepType != AgentProfiles.Steps.RunEnd).ToList();
        var result = await Verify(withoutRunEnd, _payloads);

        result.RunVerdict.Should().Be(RunVerdicts.Open);
        result.ChainValid.Should().BeTrue();
        result.ObjectsComplete.Should().BeTrue();
        result.Binding.Should().Be(Bindings.Bound);
        result.Evaluations[0].SubjectBound.Should().BeFalse("run_end evalueringen peker på er ikke levert");
    }

    [Fact]
    public async Task Byttet_Control_Artifact_gir_run_only_og_ubundet_evaluering()
    {
        var other = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), T0.AddDays(1));
        var swapped = _artifacts.Where(a => a.ContentType != AgentProfiles.ControlArtifactContentType).ToList();
        var foreignControl = AgentArtifact.Parse(other.ControlArtifact.ToJsonString());
        // Samme correlationId som kjøringen, så det er bindingen og ikke grupperingen som avviser.
        foreignControl.Envelope["activity"]!["correlationId"] = _artifacts[0].CorrelationId;
        var forged = new AgentArtifact(foreignControl.Envelope, foreignControl.Signature);
        swapped.Insert(0, forged);
        var payloads = new Dictionary<string, byte[]>(_payloads);
        foreach (var (uri, bytes) in other.Payloads) payloads[uri] = bytes;

        var result = await Verify(swapped, payloads);

        result.Binding.Should().Be(Bindings.RunOnly);
        result.Evaluations[0].SubjectBound.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Contains("matcher ikke hashV[0]"), "konvolutten ble endret etter signering");
    }

    [Fact]
    public async Task Fremmed_hendelse_rapporteres_og_holdes_utenfor()
    {
        var other = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), T0.AddDays(1));
        var mixed = _artifacts.Append(other.Events[2]).ToList();
        var result = await Verify(mixed, _payloads);

        result.ForeignArtifacts.Should().ContainSingle();
        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
    }

    [Fact]
    public async Task Kjoringen_avviser_hendelser_etter_run_end()
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
}
