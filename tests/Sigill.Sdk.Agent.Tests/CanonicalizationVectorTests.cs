using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>Klasse 1-vektorer: kanoniske bytes og konvolutthash må være byteidentiske med det som er sjekket inn.</summary>
public class CanonicalizationVectorTests
{
    [Theory]
    [MemberData(nameof(Vector10.ArtifactNames), MemberType = typeof(Vector10))]
    public void Kanoniske_bytes_og_hash_matcher_vektoren(string fileName)
    {
        var artifact = AgentArtifact.Parse(File.ReadAllText(Path.Combine(Vector10.Dir, "artifacts", fileName)));
        var stem = fileName.Split('.')[0];
        var expectedBytes = File.ReadAllBytes(Path.Combine(Vector10.Dir, "canonical", $"{stem}.canonical.json"));
        var expectedHex = File.ReadAllText(Path.Combine(Vector10.Dir, "canonical", $"{stem}.envelope-hash.txt")).Trim();

        EnvelopeHashing.Canonicalize(artifact.Envelope).Should().Equal(expectedBytes);
        artifact.EnvelopeHashHex.Should().Be(expectedHex);
    }

    [Theory]
    [MemberData(nameof(Vector10.ArtifactNames), MemberType = typeof(Vector10))]
    public void Konvolutthashen_er_den_signerte_hashV0(string fileName)
    {
        var artifact = AgentArtifact.Parse(File.ReadAllText(Path.Combine(Vector10.Dir, "artifacts", fileName)));
        var signedEnvelope = artifact.SignedObjects.Single(o => o.Uri == AgentProfiles.EnvelopeUri);
        signedEnvelope.HashHex.Should().Be(artifact.EnvelopeHashHex);
        signedEnvelope.ContentType.Should().Be(artifact.ContentType);
    }

    [Fact]
    public void Profilene_skilles_paa_ctys0()
    {
        var (artifacts, _) = Vector10.Load();
        artifacts.Count(a => a.ContentType == AgentProfiles.ControlArtifactContentType).Should().Be(1);
        artifacts.Count(a => a.ContentType == AgentProfiles.ExecutionEvidenceContentType).Should().Be(7);
        artifacts.Count(a => a.ContentType == AgentProfiles.ControlEvaluationContentType).Should().Be(1);
    }
}
