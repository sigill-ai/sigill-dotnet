using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>
/// Klasse 2-vektorer: den intakte kjøringen og de åtte sabotasjetestene fra
/// notatet 8.3, kjørt uten platform på kopier av testvektor 10. Kjede,
/// binding, konvoluttintegritet og fullstendighet kontrolleres på ekte;
/// signaturgyldighet krever platform og er null.
/// </summary>
public class VerificationVectorTests
{
    private static Task<ControlledRunResult> Verify(IEnumerable<AgentArtifact> artifacts, IReadOnlyDictionary<string, byte[]> payloads) =>
        new ControlledRunVerifier().VerifyAsync(artifacts.ToList(), payloads);

    [Fact]
    public async Task Intakt_sett_gir_forventet_resultat()
    {
        var (artifacts, payloads) = Vector10.Load();
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(Vector10.Dir, "expected-result.json")))!;

        var result = await Verify(artifacts, payloads);

        result.ControlArtifact.Should().Be(expected["controlArtifact"]!.GetValue<string>());
        result.RunVerdict.Should().Be(expected["runVerdict"]!.GetValue<string>());
        result.ChainValid.Should().Be(expected["chainValid"]!.GetValue<bool>());
        result.SignaturesValid.Should().BeNull();
        result.ObjectsComplete.Should().Be(expected["objectsComplete"]!.GetValue<bool>());
        result.MissingObjects.Should().BeEmpty();
        result.Binding.Should().Be(expected["binding"]!.GetValue<string>());
        result.ControlSealedBeforeRun.Should().Be(expected["controlSealedBeforeRun"]!.GetValue<bool>());
        result.SealOrderValid.Should().Be(expected["sealOrderValid"]!.GetValue<bool>());
        result.ForeignArtifacts.Should().BeEmpty();
        result.Issues.Should().BeEmpty();
        result.FinalSeq.Should().Be(expected["finalSeq"]!.GetValue<int>());
        result.RunDisposition.Should().Be(expected["runDisposition"]!.GetValue<string>());
        var evaluation = result.Evaluations.Should().ContainSingle().Subject;
        var expectedEvaluation = (JsonObject)expected["evaluations"]![0]!;
        evaluation.Verifier.Should().Be(expectedEvaluation["verifier"]!.GetValue<string>());
        evaluation.VerifierVersion.Should().Be(expectedEvaluation["verifierVersion"]!.GetValue<string>());
        evaluation.Overall.Should().Be(expectedEvaluation["overall"]!.GetValue<string>());
        evaluation.SubjectBound.Should().BeTrue();
        evaluation.ControlSetDigestMatches.Should().BeTrue();
        evaluation.Controls.Should().HaveCount(4);
    }

    [Fact]
    public async Task Sabotasje_1_endret_byte_i_tool_arguments()
    {
        var (artifacts, payloads) = Vector10.Load();
        var toolCall = artifacts.Single(a => a.StepType == AgentProfiles.Steps.ToolCall);
        var uri = toolCall.UriOfRole(AgentProfiles.Roles.ToolArguments)!;
        var tampered = new Dictionary<string, byte[]>(payloads, StringComparer.Ordinal);
        tampered[uri] = payloads[uri].ToArray();
        tampered[uri][0] ^= 0x01;

        var result = await Verify(artifacts, tampered);

        result.ObjectsComplete.Should().BeFalse();
        result.MissingObjects.Should().ContainSingle().Which.Should().Be(uri);
        result.RunVerdict.Should().Be(RunVerdicts.Invalid, "steg 2 feilet");
        result.ChainValid.Should().BeTrue("kjeden i seg selv er hel");
    }

    [Fact]
    public async Task Sabotasje_2_slettet_hendelse_seq_3()
    {
        var (artifacts, payloads) = Vector10.Load();
        var result = await Verify(artifacts.Where(a => a.Seq != 3), payloads);

        result.ChainValid.Should().BeFalse();
        result.RunVerdict.Should().Be(RunVerdicts.Invalid);
    }

    [Fact]
    public async Task Sabotasje_3_omstokket_seq_1_og_4()
    {
        var (artifacts, payloads) = Vector10.Load();
        var swapped = artifacts.Select(a => a.Seq switch
        {
            1 => Renumbered(a, 4),
            4 => Renumbered(a, 1),
            _ => a,
        }).ToList();

        var result = await Verify(swapped, payloads);

        result.ChainValid.Should().BeFalse();
        result.RunVerdict.Should().Be(RunVerdicts.Invalid);
        result.Issues.Should().Contain(i => i.Contains("hashV[0]"), "omnummerering endrer konvolutten etter signering");
    }

    [Fact]
    public async Task Sabotasje_4_avkuttet_kjoring_uten_run_end()
    {
        var (artifacts, payloads) = Vector10.Load();
        var result = await Verify(artifacts.Where(a => a.StepType != AgentProfiles.Steps.RunEnd), payloads);

        result.RunVerdict.Should().Be(RunVerdicts.Open);
        result.ChainValid.Should().BeTrue();
        result.ObjectsComplete.Should().BeTrue();
        result.Binding.Should().Be(Bindings.Bound);
        result.Evaluations.Single().SubjectBound.Should().BeFalse("run_end evalueringen peker på er ikke levert");
    }

    [Fact]
    public async Task Sabotasje_5_innsatt_hendelse_fra_annen_kjoring()
    {
        var (artifacts, payloads) = Vector10.Load();
        var other = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), DateTimeOffset.UtcNow);
        var result = await Verify(artifacts.Append(other.Events[2]), payloads);

        result.ForeignArtifacts.Should().ContainSingle();
        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
        result.Issues.Should().ContainSingle().Which.Should().Contain("annen correlationId");
    }

    [Fact]
    public async Task Sabotasje_6_byttet_kontrollgrunnlag()
    {
        var (artifacts, payloads) = Vector10.Load();
        var correlationId = artifacts[0].CorrelationId!;
        var other = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), DateTimeOffset.UtcNow);
        var forged = other.ControlArtifact.Envelope.DeepClone().AsObject();
        forged["activity"]!["correlationId"] = correlationId;
        var replaced = artifacts.Where(a => a.ContentType != AgentProfiles.ControlArtifactContentType)
            .Prepend(new AgentArtifact(forged, other.ControlArtifact.Signature)).ToList();
        var merged = new Dictionary<string, byte[]>(payloads, StringComparer.Ordinal);
        foreach (var (uri, bytes) in other.Payloads) merged[uri] = bytes;

        var result = await Verify(replaced, merged);

        result.Binding.Should().Be(Bindings.RunOnly);
        result.Evaluations.Single().SubjectBound.Should().BeFalse();
    }

    [Fact]
    public async Task Sabotasje_7_forfalsket_evaluering_med_feil_subject()
    {
        var (artifacts, payloads) = Vector10.Load();
        var evaluation = artifacts.Single(a => a.ContentType == AgentProfiles.ControlEvaluationContentType);
        var forgedEnvelope = evaluation.Envelope.DeepClone().AsObject();
        forgedEnvelope["subject"]!["runEndSignatureSha256"] = new string('0', 64);
        forgedEnvelope["overall"] = AgentProfiles.Results.Pass;
        var forged = new AgentArtifact(forgedEnvelope, evaluation.Signature);

        var result = await Verify(artifacts.Where(a => !ReferenceEquals(a, evaluation)).Append(forged), payloads);

        var reported = result.Evaluations.Single();
        reported.SubjectBound.Should().BeFalse();
        reported.Overall.Should().Be("PASS", "gjengis uendret, men ubundet");
        result.Issues.Should().Contain(i => i.Contains("hashV[0]"), "en endret konvolutt matcher ikke sin signatur");
    }

    [Fact]
    public async Task Sabotasje_8_byttet_kontrollsett_i_evalueringen()
    {
        var (artifacts, payloads) = Vector10.Load();
        var evaluation = artifacts.Single(a => a.ContentType == AgentProfiles.ControlEvaluationContentType);
        var controlSetUri = evaluation.UriOfRole(AgentProfiles.Roles.ControlSet)!;
        // Et annet kontrollsett forsegles som eget artefakt; dets digest legges inn i evalueringens signatur.
        var other = await ReferenceRun.BuildAsync(new FakeArtifactSealer(), DateTimeOffset.UtcNow,
            controlSetJson: """{"id":"customer-write-v5","version":"5","controls":["address-equals-requested"]}""");
        var otherControlSetUri = other.Evaluation.UriOfRole(AgentProfiles.Roles.ControlSet)!;
        var otherDigest = other.Evaluation.SignedObjects.Single(o => o.Uri == otherControlSetUri).HashHex;
        var resigned = FakeArtifactSealer.WithReplacedObjectDigest(evaluation, controlSetUri, otherDigest);
        var tampered = new Dictionary<string, byte[]>(payloads, StringComparer.Ordinal) { [controlSetUri] = other.Payloads[otherControlSetUri] };

        var result = await Verify(artifacts.Where(a => !ReferenceEquals(a, evaluation)).Append(resigned), tampered);

        var reported = result.Evaluations.Single();
        reported.ControlSetDigestMatches.Should().BeFalse();
        result.Issues.Should().Contain(i => i.Contains("annen digest"));
    }

    private static AgentArtifact Renumbered(AgentArtifact a, int seq)
    {
        var envelope = a.Envelope.DeepClone().AsObject();
        envelope["chain"]!["seq"] = seq;
        return new AgentArtifact(envelope, a.Signature);
    }
}
