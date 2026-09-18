using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>Leser testvektor 10 (den ekte kjøringen) fra utmappen.</summary>
internal static class Vector10
{
    public static string Dir => Path.Combine(AppContext.BaseDirectory, "spec", "test-vectors", "10-agent-controlled-run");

    public static (List<AgentArtifact> Artifacts, Dictionary<string, byte[]> Payloads) Load()
    {
        var artifacts = Directory.GetFiles(Path.Combine(Dir, "artifacts"), "*.json")
            .OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => AgentArtifact.Parse(File.ReadAllText(f)))
            .ToList();
        var index = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(Dir, "objects.json")))!;
        var payloads = index.ToDictionary(p => p.Key, p => File.ReadAllBytes(Path.Combine(Dir, p.Value!.GetValue<string>())), StringComparer.Ordinal);
        return (artifacts, payloads);
    }

    public static IEnumerable<object[]> ArtifactNames() =>
        Directory.GetFiles(Path.Combine(Dir, "artifacts"), "*.json").OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => new object[] { Path.GetFileName(f) });
}
