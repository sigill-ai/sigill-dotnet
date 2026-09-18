using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>
/// Prøvekjøringen mot testmiljøet. Krever SIGILL_API_KEY og
/// SIGILL_SEAL_CERTIFICATE_ID (samme navn som demo-backendens .env);
/// SIGILL_BASE_URL kan overstyre api.sigill.ai. Uten nøkkel hopper testen over
/// og sier det høyt.
/// </summary>
public class EndToEndTests
{
    private readonly ITestOutputHelper _output;

    public EndToEndTests(ITestOutputHelper output) => _output = output;

    [Fact]
    public async Task En_kjoring_ende_til_ende_mot_testmiljoet()
    {
        var apiKey = Environment.GetEnvironmentVariable("SIGILL_API_KEY");
        var certificate = Environment.GetEnvironmentVariable("SIGILL_SEAL_CERTIFICATE_ID");
        if (string.IsNullOrWhiteSpace(apiKey) || !Guid.TryParse(certificate, out var certificateId))
        {
            const string melding = "HOPPET OVER: ende-til-ende-testen krever SIGILL_API_KEY og SIGILL_SEAL_CERTIFICATE_ID i miljøet.";
            _output.WriteLine(melding);
            Console.Error.WriteLine(melding);
            return;
        }
        var baseUrl = Environment.GetEnvironmentVariable("SIGILL_BASE_URL") ?? SigillClient.DefaultBaseUrl;

        var client = new SigillClient(apiKey, baseUrl);
        var sealer = new SigillArtifactSealer(client, certificateId, qualified: false);
        var run = await ReferenceRun.BuildAsync(sealer, DateTimeOffset.UtcNow);

        var outDir = Path.Combine(AppContext.BaseDirectory, "artifacts", run.CorrelationId.Replace("urn:uuid:", ""));
        run.WriteTo(outDir);
        // SIGILL_AGENT_WRITE_VECTOR=<repo-rot>: fornyer spec/test-vectors/10-agent-controlled-run fra denne kjøringen.
        // Spesifikasjonen er et øyeblikksbilde av koden; dette er knappen som tar bildet på nytt.
        var repoRoot = Environment.GetEnvironmentVariable("SIGILL_AGENT_WRITE_VECTOR");
        if (!string.IsNullOrWhiteSpace(repoRoot))
        {
            var vectorDir = Path.Combine(repoRoot, "spec", "test-vectors", "10-agent-controlled-run");
            foreach (var stale in Directory.GetFiles(Path.Combine(vectorDir, "artifacts"))) File.Delete(stale);
            foreach (var stale in Directory.GetFiles(Path.Combine(vectorDir, "objects"))) File.Delete(stale);
            run.WriteTo(vectorDir);
            Directory.Move(Path.Combine(vectorDir, "objects.json"), Path.Combine(vectorDir, "objects.json.tmp"));
            foreach (var f in Directory.GetFiles(vectorDir, "*.json").Where(f => !f.EndsWith("expected-result.json", StringComparison.Ordinal)))
                File.Move(f, Path.Combine(vectorDir, "artifacts", Path.GetFileName(f)), overwrite: true);
            File.Move(Path.Combine(vectorDir, "objects.json.tmp"), Path.Combine(vectorDir, "objects.json"), overwrite: true);
            _output.WriteLine($"Vektor 10 fornyet i {vectorDir}; kjør _generate.py og _validate.py.");
        }
        _output.WriteLine($"Artefaktene ligger i {outDir}");
        Console.Error.WriteLine($"Artefaktene ligger i {outDir}");

        var (artifacts, payloads) = ReferenceRun.ReadFrom(outDir);
        var result = await new ControlledRunVerifier(client).VerifyAsync(artifacts, payloads);
        _output.WriteLine(System.Text.Json.JsonSerializer.Serialize(result, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        }));

        result.SignaturesValid.Should().BeTrue();
        result.ObjectsComplete.Should().BeTrue();
        result.ChainValid.Should().BeTrue();
        result.RunVerdict.Should().Be(RunVerdicts.Finalized);
        result.Binding.Should().Be(Bindings.Bound);
        result.ControlArtifact.Should().Be("verified");
        result.Evaluations.Should().ContainSingle().Which.SubjectBound.Should().BeTrue();
        result.Issues.Should().BeEmpty();
    }
}
