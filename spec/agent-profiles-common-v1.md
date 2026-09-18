# Agent Evidence Profiles v1 — Common Rules

> **Snapshot, not source of truth.** While the initiative may still be
> withdrawn, the code in `src/Sigill.Sdk.Agent` is the truth and this
> document is a snapshot of it. Test vector 10 is regenerated from the code
> (`SIGILL_AGENT_WRITE_VECTOR`); the prose and schemas are updated to match,
> never the other way round. Owner decision 2026-09-18.

**Status:** v1, experimental. Produced on the `initiativ/agenteksekvering`
branch; may be withdrawn. Field names are frozen for v1 by this document.

This document holds the rules shared by the three sibling profiles that
together describe one controlled agent run:

| Phase | Profile | Content type (`sigD.ctys[0]`) | Count per run |
|---|---|---|---|
| Before | [Agent Control Artifact](./agent-control-artifact-v1.md) | `application/vnd.sigill.agent-control+json` | one |
| During | [Agent Execution Evidence](./agent-execution-evidence-v1.md) | `application/vnd.sigill.agent-execution+json` | one per event |
| After | [Control Evaluation](./control-evaluation-v1.md) | `application/vnd.sigill.control-evaluation+json` | one per evaluation |

They are **sibling profiles** of [`AiEvidenceEnvelopeV2`](./ai-evidence-envelope-v2.md)
in the sense of its §2: each is its own content type with its own schema,
sealed through the identical blind mechanism (`POST /seal/sign-hashes`),
never an `extensions` block. Everything in v2 §4 (canonicalization), §5 (JAdES
binding), §6 (artifact container) and §8 (what Sigill receives) applies
unchanged. This document only adds what the three profiles share.

## 1. Family core

Every profile envelope carries the v2 family core:

| Field | Rule |
|---|---|
| `schemaName` | Profile constant: `AgentControlArtifact`, `AgentExecutionEvidence` or `ControlEvaluation`. |
| `schemaVersion` | `"1"`. |
| `evidenceId` | `urn:uuid:<uuid>`. URN form, as these profiles are always cross-referenced by URI. |
| `createdAt` | RFC 3339 UTC, second precision, `Z` suffix. The producer's clock; the seal time is proven by `sigTst`. |
| `actor` | `{ type, id, version? }`. `type` is `user | service | system | agent` for the first two profiles and `verifier` for Control Evaluation. |
| `activity` | `{ name, correlationId }`. **Both required.** `correlationId` is the run identifier; every artifact of one run carries the same value. |
| `objects[]` | Detached objects, index-aligned with `sigD.pars[1…]` exactly as v2 §3.1 and §5.2 prescribe. Each profile defines its own closed set of `role` values. |
| `extensions` | Optional, producer-private, as v2 §2. |

Schemas are `additionalProperties: false` throughout. The only open fields
are `extensions` and per-object `metadata`.

## 2. The binding rule (normative)

All references between artifacts use one mechanism:

> **signatureSha256(A)** = lowercase hex SHA-256 over the base64url-decoded
> JWS Signature Value of the *classical* signature entry of artifact A.

The classical entry is the first `signatures[]` element whose protected
`alg` does not start with `ML-DSA`. The PQC entry, when present, never
participates in binding.

The rule is used in three places, and a verifier implements it once:

| Reference | Field | Points to |
|---|---|---|
| Chain link | `chain.prevSignatureSha256` | the previous Execution Evidence artifact |
| Run to controls | `binds.controlArtifactSignatureSha256` | the run's Control Artifact |
| Evaluation to run | `subject.runEndSignatureSha256`, `subject.controlArtifactSignatureSha256` | the `run_end` artifact and the Control Artifact |

This fixes the preimage that v2 §3.4 left RECOMMENDED. Because the value is
derived from the signature, a binding can only be produced after the target
has been sealed, which is what makes "sealed before the first event"
provable.

## 3. Detached objects

Everything under `objects[]` stays with the producer (v2 §3.1). `uri` SHOULD
be `urn:uuid:<uuid>`; it is opaque and never dereferenced. `contentType`
SHOULD be set. The same object MAY appear in several artifacts (the control
set appears in both the Control Artifact and the Control Evaluation); when it
does, the URI and the digest MUST be identical in each.

## 4. Verification of a controlled run

A run verifier takes a set of artifacts and the detached objects the holder
can supply, and reports the following, in this order. Later steps run even
when earlier ones fail, so the report is complete.

1. **Per artifact:** the envelope's canonical hash equals `hashV[0]`; the
   signature and `sigTst` verify (via `POST /seal/verify-objects` or any
   TS 119 182-1 validator); every supplied object matches its `hashV` entry.
   → `signaturesValid`, `timestampsValid`, `objectsComplete`, `missingObjects[]`.
2. **Grouping:** artifacts are classified by `sigD.ctys[0]` and grouped by
   `activity.correlationId`. Artifacts with another `correlationId` are
   reported as *foreign* and excluded, never silently dropped.
3. **Chain:** Execution Evidence sorted by `chain.seq`; `seq` starts at 0,
   is contiguous, the first is `run_start` without `prevSignatureSha256`,
   and every later `prevSignatureSha256` equals `signatureSha256` of the
   previous artifact. → `chainValid`.
4. **Finalization:** the last artifact is `run_end`, its `step.finalSeq`
   equals its own `chain.seq`, and `step.finalPrevSignatureSha256` equals
   `signatureSha256` of the second-to-last artifact.
5. **Run verdict:** any failure in steps 1, 3 or 4 → `run_invalid`; no
   `run_end` → `run_open`; otherwise `run_finalized`.
6. **Binding:** `run_start.binds.controlArtifactSignatureSha256` equals
   `signatureSha256` of a supplied Control Artifact → `bound`; a run without
   its Control Artifact → `run_only`; a Control Artifact without a run →
   `control_only`; neither → `unbound`.
7. **Seal time, as defense in depth:** the `sigTst` genTime of the bound
   Control Artifact is not later than that of `run_start`, within the
   TSTInfo `accuracy` each TSA states and at one-second granularity →
   `controlSealedBeforeRun`. Step 6 already proves the order: `run_start`
   binds the Control Artifact's signature, which exists only after sealing,
   so with an honest platform the control's timestamp cannot be later. A
   `false` here therefore points at the platform or a TSA, not at the
   producer, and does not change the run verdict; it is reported as an
   issue. Missing `sigTst` gives `null` and an explicit issue. Seal times
   are **not** compared along the chain: `prevSignatureSha256` proves that
   order already, and TSA pools with failover (vector 10 was stamped by six
   TSAs with accuracies of 500 ms, 1 s and unspecified) would produce false
   negatives on fast runs.
8. **Evaluations:** for each Control Evaluation, `subject` matches the run's
   `run_end` and the bound Control Artifact → `subjectBound`; the
   `control-set` object digest equals the one in the Control Artifact →
   `controlSetDigestMatches`; likewise for `baseline-state` when both carry
   it → `baselineDigestMatches`. `overall` and `controls[]` are reported
   **unchanged**. The verifier never evaluates controls.

### 4.1 What verification does not say

The one thing neither binding nor seal time can detect: the agent acts
first, and control basis and chain are sealed afterwards. Binding and time
are then both consistent. Only tying the seals to the external effect
exposes it. Two lean forms exist: the harness waits for the seal of
`tool_call`, `authorization` and `human_approval` before the tool runs
(normative, changes the producer), or the verifier includes the target
record's modification time in `observed-state` and checks that the
`tool_call` seal time lies before it (one check in the verifier component,
no SDK change). The second is the one that proves something; it belongs
to the verifier component, which is where `observed-state` is produced.

A `run_finalized` run with `overall: PASS` means: *the control basis was
sealed before the first event, all recorded events are unchanged and in the
recorded order, the run was closed, and the named verifier reported PASS
against the pre-sealed control set.* It does not say the run was good, that
every event was captured, that `eventTime` is true, or that the verifier
measured correctly.

## 5. Test vectors

[`test-vectors/10-agent-controlled-run/`](./test-vectors/10-agent-controlled-run/)
holds one complete run sealed by the Sigill test tenant: nine artifacts, the
detached objects, the canonical bytes and envelope hash of every envelope, and
the expected offline verification result. The eight sabotage cases from the
design note are exercised by the SDK tests against that set.
