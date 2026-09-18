# AgentControlArtifact v1 — Specification

> **Snapshot, not source of truth.** While the initiative may still be
> withdrawn, the code in `src/Sigill.Sdk.Agent` is the truth and this
> document is a snapshot of it. Test vector 10 is regenerated from the code
> (`SIGILL_AGENT_WRITE_VECTOR`); the prose and schemas are updated to match,
> never the other way round. Owner decision 2026-09-18.

**Content type:** `application/vnd.sigill.agent-control+json`
**Schema:** [`agent-control-artifact-v1.schema.json`](./agent-control-artifact-v1.schema.json)
**Common rules:** [`agent-profiles-common-v1.md`](./agent-profiles-common-v1.md)

The Control Artifact seals *what applied* before an agent run started: the
instructions, the tool manifest, the execution policy, the control set the
run will be evaluated against, and the authority the agent acted under. All
of it stays with the producer; the artifact binds digests.

## 1. Envelope

```json
{
  "schemaName": "AgentControlArtifact",
  "schemaVersion": "1",
  "evidenceId": "urn:uuid:…",
  "createdAt": "2026-09-16T08:00:00Z",
  "actor": { "id": "urn:acme:harness:prod", "type": "system" },
  "activity": { "name": "customer-address-change", "correlationId": "urn:uuid:<run>" },
  "agent": { "id": "contract-agent", "version": "17", "identityRef": "urn:…" },
  "controlSet": { "id": "customer-write-v4", "version": "4" },
  "objects": [
    { "uri": "urn:uuid:…", "role": "instruction-set",  "contentType": "text/plain" },
    { "uri": "urn:uuid:…", "role": "tool-manifest",    "contentType": "application/json" },
    { "uri": "urn:uuid:…", "role": "execution-policy", "contentType": "application/json" },
    { "uri": "urn:uuid:…", "role": "control-set",      "contentType": "application/json" },
    { "uri": "urn:uuid:…", "role": "authority",        "contentType": "application/jwt" }
  ]
}
```

## 2. Profile fields

| Field | Required | Rule |
|---|---|---|
| `agent.id` | yes | Stable identifier of the agent, below tenant level. Not a display name. |
| `agent.version` | yes | The agent configuration version that ran. |
| `agent.identityRef` | no | Reference to an identity assertion held by the producer (AgentID, SPIFFE, …). |
| `controlSet.id`, `controlSet.version` | yes | Identifies the control set; the content is the `control-set` object. |

## 3. Object roles

Closed set: `instruction-set`, `tool-manifest`, `execution-policy`,
`control-set`, `authority`, `baseline-state`. Exactly one `control-set`
object is REQUIRED; it is what the Control Evaluation is later compared
against. Each other role appears at most once. `objects[]` MUST NOT be
empty.

`baseline-state` is the target's state as read **before** the run, sealed
with the control basis. Every "unchanged" control (account number, credit
limit, status) rests on it: the verifier compares `observed-state` after the
run against `baseline-state` from before, and both digests are sealed with
independent timestamps. Without it, "unchanged" is the verifier's word
alone. The role is defined now because the role set is closed and adding it
later would cost a schema and vector change; the SDK does nothing with its
content.

## 4. Timing

The Control Artifact MUST be sealed before `run_start` is sealed. This is
provable, not asserted: `run_start` carries `signatureSha256` of the Control
Artifact, which exists only after sealing. `sigTst` on both artifacts gives
the order in time.
