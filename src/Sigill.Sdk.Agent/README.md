# Sigill.Sdk.Agent (preview)

Evidence for a **controlled agent run** as three sibling profiles of
`AiEvidenceEnvelopeV2`, sealed through Sigill's blind `sign-hashes`
contract. Sigill receives digests and opaque URIs, never the envelope or the
content.

| Phase | Type | What it seals |
|---|---|---|
| Before | `ControlArtifactBuilder` | instructions, tool manifest, policy, control set, authority |
| During | `AgentRun` | one artifact per event, chained by `seq` + `prevSignatureSha256`, closed by `run_end` |
| After | `ControlEvaluationBuilder` | observed state and per-control results, bound to `run_end` and the Control Artifact |

`ControlledRunVerifier` checks a set of artifacts: envelope integrity,
object completeness, chain, finalization, binding and evaluation subject.
Signature validity goes through `VerifyObjectHashesAsync` when a client is
given. It never evaluates controls itself.

Specifications and test vectors live in `spec/` of
[sigill-dotnet](https://github.com/sigill-ai/sigill-dotnet):
`agent-profiles-common-v1.md`, `agent-control-artifact-v1.md`,
`agent-execution-evidence-v1.md`, `control-evaluation-v1.md`.

```csharp
var sealer = new SigillArtifactSealer(client, certificateId);
var control = await new ControlArtifactBuilder { /* … */ }.SealAsync(objects, sealer);
var run = new AgentRun(sealer, "customer-address-change", control.CorrelationId!, "contract-agent");
await run.StartAsync(control, DateTimeOffset.UtcNow);
await run.RecordAsync(AgentProfiles.Steps.ToolCall, DateTimeOffset.UtcNow, details, toolArguments);
var runEnd = await run.FinishAsync(AgentProfiles.Dispositions.Completed, DateTimeOffset.UtcNow);
var result = await new ControlledRunVerifier(client).VerifyAsync(artifacts, payloads);
```

This package is experimental and may be withdrawn. Apache-2.0.
