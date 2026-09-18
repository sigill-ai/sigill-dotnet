using System.Text;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>
/// Skjermbildets kjøring: customer-address-change, contract-agent v17,
/// kontrollsett customer-write-v4, sju hendelser, overall FAIL på status-unchanged.
/// </summary>
public sealed class ReferenceRun
{
    public required AgentArtifact ControlArtifact { get; init; }
    public required IReadOnlyList<AgentArtifact> Events { get; init; }
    public required AgentArtifact Evaluation { get; init; }
    public required Dictionary<string, byte[]> Payloads { get; init; }
    public required string CorrelationId { get; init; }

    public List<AgentArtifact> All() => new[] { ControlArtifact }.Concat(Events).Append(Evaluation).ToList();

    public static async Task<ReferenceRun> BuildAsync(IArtifactSealer sealer, DateTimeOffset t0, string controlSetJson = DefaultControlSet)
    {
        var correlationId = $"urn:uuid:{Guid.NewGuid()}";
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        DetachedObject Obj(string role, string content, string contentType)
        {
            var o = new DetachedObject(role, Encoding.UTF8.GetBytes(content), contentType);
            payloads[o.Uri] = o.Bytes;
            return o;
        }

        var controlSet = Obj(AgentProfiles.Roles.ControlSet, controlSetJson, "application/json");
        var control = await new ControlArtifactBuilder
        {
            ActorId = "urn:acme:harness:prod",
            ActivityName = "customer-address-change",
            CorrelationId = correlationId,
            AgentId = "contract-agent",
            AgentVersion = "17",
            ControlSetId = "customer-write-v4",
            ControlSetVersion = "4",
            CreatedAt = t0,
        }.SealAsync(new[]
        {
            Obj(AgentProfiles.Roles.InstructionSet, "Endre adresse. Ikke annet.", "text/plain"),
            Obj(AgentProfiles.Roles.ToolManifest, """{"tools":["crm.update_customer"]}""", "application/json"),
            Obj(AgentProfiles.Roles.ExecutionPolicy, """{"allowedFields":["address"]}""", "application/json"),
            controlSet,
            Obj(AgentProfiles.Roles.Authority, "eyJhbGciOiJub25lIn0.eyJkZWxlZ2F0ZWRCeSI6InVybjphY21lOnVzZXI6NDEiLCJzY29wZXMiOlsiY3VzdG9tZXIuYWRkcmVzcy53cml0ZSJdfQ.", "application/jwt"),
        }, sealer);

        var run = new AgentRun(sealer, "customer-address-change", correlationId, "contract-agent");
        await run.StartAsync(control, t0.AddSeconds(5));
        await run.RecordAsync(AgentProfiles.Steps.ToolCall, t0.AddSeconds(6),
            new JsonObject { ["tool"] = new JsonObject { ["name"] = "crm.update_customer", ["operation"] = "update" } },
            new[] { Obj(AgentProfiles.Roles.ToolArguments, """{"id":"c-1017","address":"Nygata 4"}""", "application/json") });
        await run.RecordAsync(AgentProfiles.Steps.Authorization, t0.AddSeconds(6),
            new JsonObject { ["decision"] = "allow_with_human_approval", ["policyId"] = "customer-write-policy-v2" });
        await run.RecordAsync(AgentProfiles.Steps.HumanApproval, t0.AddSeconds(31),
            new JsonObject { ["decision"] = "approved", ["approver"] = "urn:acme:user:41" },
            new[] { Obj(AgentProfiles.Roles.ApprovalReceipt, """{"approved":true,"boundActionHash":"…"}""", "application/json") });
        await run.RecordAsync(AgentProfiles.Steps.ToolResult, t0.AddSeconds(32), null,
            new[] { Obj(AgentProfiles.Roles.ToolResult, """{"updated":true}""", "application/json") });
        await run.RecordAsync(AgentProfiles.Steps.ModelOutput, t0.AddSeconds(34), null,
            new[] { Obj(AgentProfiles.Roles.ModelOutput, "Adressen er oppdatert til Nygata 4.", "text/plain") });
        var runEnd = await run.FinishAsync(AgentProfiles.Dispositions.Completed, t0.AddSeconds(35));

        var evaluation = await new ControlEvaluationBuilder
        {
            VerifierId = "urn:acme:verifier:crm-state",
            VerifierVersion = "1.3.0",
            ActivityName = "customer-address-change",
            CorrelationId = correlationId,
            RunEndSignatureSha256 = runEnd.SignatureSha256,
            ControlArtifactSignatureSha256 = control.SignatureSha256,
            ControlSetId = "customer-write-v4",
            ControlSetVersion = "4",
            Controls = new[]
            {
                new ControlResult("address-equals-requested", AgentProfiles.Results.Pass),
                new ControlResult("account-number-unchanged", AgentProfiles.Results.Pass),
                new ControlResult("credit-limit-unchanged", AgentProfiles.Results.Pass),
                new ControlResult("status-unchanged", AgentProfiles.Results.Fail, "status endret fra active til suspended"),
            },
            Overall = AgentProfiles.Results.Fail,
            EvaluatedAt = t0.AddSeconds(58),
            CreatedAt = t0.AddSeconds(60),
        }.SealAsync(
            Obj(AgentProfiles.Roles.ObservedState, """{"address":"Nygata 4","accountNumber":"1234.56.78903","creditLimit":50000,"status":"suspended"}""", "application/json"),
            new DetachedObject(AgentProfiles.Roles.ControlSet, controlSet.Bytes, controlSet.ContentType, controlSet.Uri),
            sealer);

        return new ReferenceRun
        {
            ControlArtifact = control,
            Events = run.Artifacts,
            Evaluation = evaluation,
            Payloads = payloads,
            CorrelationId = correlationId,
        };
    }

    public const string DefaultControlSet =
        """{"id":"customer-write-v4","version":"4","controls":["address-equals-requested","account-number-unchanged","credit-limit-unchanged","status-unchanged"]}""";

    /// <summary>Skriver artefaktene og objektene som filer, så mennesker kan åpne dem.</summary>
    public string WriteTo(string directory)
    {
        Directory.CreateDirectory(directory);
        var objectsDir = Path.Combine(directory, "objects");
        Directory.CreateDirectory(objectsDir);
        File.WriteAllText(Path.Combine(directory, "00-control-artifact.agent-control.json"), ControlArtifact.ToJsonString());
        foreach (var e in Events)
            File.WriteAllText(Path.Combine(directory, $"{10 + e.Seq:00}-{e.StepType}.agent-execution.json"), e.ToJsonString());
        File.WriteAllText(Path.Combine(directory, "90-control-evaluation.control-evaluation.json"), Evaluation.ToJsonString());
        var index = new JsonObject();
        foreach (var (uri, bytes) in Payloads)
        {
            var file = uri.Replace("urn:uuid:", "") + ".bin";
            File.WriteAllBytes(Path.Combine(objectsDir, file), bytes);
            index[uri] = "objects/" + file;
        }
        File.WriteAllText(Path.Combine(directory, "objects.json"), index.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return directory;
    }

    public static (List<AgentArtifact> Artifacts, Dictionary<string, byte[]> Payloads) ReadFrom(string directory)
    {
        var artifacts = Directory.GetFiles(directory, "*.json")
            .Where(f => Path.GetFileName(f) != "objects.json")
            .OrderBy(f => f, StringComparer.Ordinal)
            .Select(f => AgentArtifact.Parse(File.ReadAllText(f)))
            .ToList();
        var index = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(directory, "objects.json")))!;
        var payloads = index.ToDictionary(p => p.Key, p => File.ReadAllBytes(Path.Combine(directory, p.Value!.GetValue<string>())), StringComparer.Ordinal);
        return (artifacts, payloads);
    }
}
