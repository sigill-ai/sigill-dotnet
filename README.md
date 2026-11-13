# Sigill.Sdk (.NET)

[![NuGet](https://img.shields.io/nuget/v/Sigill.Sdk.svg)](https://www.nuget.org/packages/Sigill.Sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Tamper-evident **AI evidence envelopes** for .NET. Build an `AiEvidenceEnvelopeV1`
record of any AI generation, seal it with an RFC 3161 timestamp via
[Sigill](https://sigill.ai), and verify it offline at any later point.

The cryptographic primitives — RFC 8785 canonical JSON, SHA-256 hash binding,
RFC 3161 timestamp parsing — are all handled inside the SDK. Your application
hands it a prompt, response, and metadata; gets back a sealed envelope. Apps don't
need to implement canonicalization, hash binding, or timestamp protocol logic
themselves.

For the underlying spec — what's in an envelope, what gets hashed in what order,
what "valid" means — see [`spec/README.md`](spec/README.md). The same spec ships in
this repo's sibling: the [Python SDK at sigill-python](https://github.com/sigill-ai/sigill-python).
Identical test vectors, byte-compatible output.

## Install

```
dotnet add package Sigill.Sdk
```

Targets `net8.0`, `net9.0`, and `netstandard2.1`. Single dependency on
`System.Security.Cryptography.Pkcs` for RFC 3161 token parsing — built into the
runtime since .NET Core 2.1.

## 30-second example

```csharp
using Sigill.Sdk;

await using var client = new SigillClient(apiKey: "sigill_..."); // Settings → API Keys at sigill.ai

var envelope = new EnvelopeBuilder()
    .WithPurpose(category: "summarization", businessContext: "support-ticket-summary")
    .WithActor(type: "service", id: "svc-support-summarizer", tenantId: "tenant-acme")
    .WithActivity(name: "ticket.summarize", correlationId: "trace-abc-123")
    .WithModel(provider: "anthropic", name: "claude-opus-4-7",
               parameters: new JsonObject { ["max_tokens"] = 1024, ["temperature"] = 0.2 })
    .WithPromptInline("Summarize the following support ticket in three bullet points.")
    .WithOutputInline("Customer reports login fails after password reset.")
    .Build();

SealedAiEvidenceEnvelope sealed_ = await client.SealAsync(envelope);
// sealed_.EnvelopeHashHex                ← SHA-256 of canonical JSON
// sealed_.Json["proofs"]![0]!["tsrBase64"] ← RFC 3161 timestamp from Sigill

// ...persist sealed_.Json somewhere durable...

// Later — re-verify cryptographically. Anyone with the sealed envelope can do this:
AiEvidenceVerificationResult result = await client.VerifyAsync(sealed_);
Debug.Assert(result.IsValid);
Console.WriteLine($"Stamped at {result.Timestamps[0].GenTime} by {result.Timestamps[0].TsaName}");
```

That's the whole hot path. Everything below is detail you only reach for when you
need it.

## Keeping PII out of the envelope

For sensitive prompts and responses, store **hash references** in the envelope
instead of the content itself. The SDK hashes the bytes you supply, records the
hash in the envelope, and the original bytes are yours to keep, redact, or delete.

```csharp
var promptBytes = Encoding.UTF8.GetBytes(
    "Classify identity doc. Subject: Jane Doe, born 1985-03-14.");
var responseBytes = Encoding.UTF8.GetBytes(
    """{"document_type":"passport","confidence":0.97}""");

var envelope = new EnvelopeBuilder()
    .WithPurpose(category: "classification",
                 regulatoryBasis: new[] { "EU-AI-Act:Annex-III" })
    .WithActor(type: "user", id: "user-9b2f1a", tenantId: "tenant-acme")
    .WithActivity(name: "kyc.classify")
    .WithModel(provider: "anthropic", name: "claude-opus-4-7")
    .WithPromptRef("prompt", contentType: "text/plain")
    .WithOutputRef("output", contentType: "application/json")
    .WithPolicyMetadata(new JsonObject
    {
        ["redactionApplied"] = true,
        ["redactionPolicy"] = "pii-redaction-v3",
    })
    .Build();

var sealed_ = await client.SealAsync(envelope, externalPayloads: new()
{
    ["prompt"] = promptBytes,
    ["output"] = responseBytes,
});
// The envelope now contains SHA-256("prompt bytes") and SHA-256("response bytes")
// under prompt.hash and output.hash. The bytes themselves are NOT stored.
```

When you later need to audit, supply the bytes again — verify confirms they hash
to the same registered values:

```csharp
var result = await client.VerifyAsync(sealed_, new()
{
    ["prompt"] = promptBytes,
    ["output"] = responseBytes,
});
Debug.Assert(result.IsValid);
```

If the bytes have been deleted or modified, verification reports exactly which
`ref` is missing or wrong:

```csharp
var result = await client.VerifyAsync(sealed_,
    new() { ["prompt"] = promptBytes }); // 'output' deliberately omitted
// result.IsValid       -> false
// result.Issues[0].Kind   -> VerificationIssueKind.HashMismatch
// result.Issues[0].Target -> "output"
// result.Issues[0].Message -> "payload_not_supplied: external bytes for ref 'output' …"
```

## CAdES document sealing

For workflows where you need to cryptographically seal a specific file or JSON blob
(not a full AI evidence envelope), the SDK supports **CAdES detached signatures**
(`.p7s`). This is the right choice when you want a compact, verifiable proof that a
particular document was sealed by a named Sigill certificate at a specific moment.

```csharp
using Sigill.Sdk;

// Obtain a certificate ID from the Sigill dashboard (Settings → Certificates).
var certId = Guid.Parse("5f498b84-65e2-404c-8791-65d70e3f385b");

var document = """{"decision": "approved", "amount": 42000}"""u8.ToArray();

// Seal: only the SHA-256 hash of the document is sent to Sigill — the document
// itself never leaves your system.
byte[] p7s = await client.SealCadesAsync(document, certId, label: "decision.json");

// p7s is a standard PKCS#7 / CMS detached signature (.p7s). Store it alongside
// the document — you need both to verify later.

// Verify: again, only the hash is transmitted — the document stays local.
CadesVerifyResult result = await client.VerifyCadesAsync(document, p7s);

Debug.Assert(result.IsValid);
Console.WriteLine(result.Signer);   // CN=Sigill Platform Seal, O=SIGILL AS, …
Console.WriteLine(result.Trust);    // "trusted_chain"
Console.WriteLine(result.GenTime);  // "2026-06-25T16:49:04Z"
```

### Post-quantum (hybrid) sealing

Pass `pqc: true` to add a post-quantum **ML-DSA-87** (FIPS 204) signer alongside
the classical one — a single `.p7s` with two independently-verifiable signatures
(RFC 5652 §5.1 + RFC 9882). Content still never leaves your system (only SHA-256
and SHA-512 digests are sent).

```csharp
byte[] p7s = await client.SealCadesAsync(document, certId, label: "decision.json", pqc: true);

CadesVerifyResult result = await client.VerifyCadesAsync(document, p7s);
Debug.Assert(result.IsValid);                     // classical signer — the legal instrument
if (result.PostQuantum is { } pqc)
{
    Console.WriteLine(pqc.Algorithm);             // "ml-dsa-87"
    Console.WriteLine(pqc.SignatureValid);        // true
    Console.WriteLine(pqc.ContentBound);          // "yes"
    Console.WriteLine(pqc.Trusted);               // "not_evaluated" (self-signed platform cert)
}
```

`IsValid` reflects the classical signer only — the post-quantum signer is
additive (quantum-resistant protection, not a qualified/legal upgrade), and is
reported separately via `result.PostQuantum`.

`CadesVerifyResult` properties:

| Property | Type | Meaning |
|---|---|---|
| `IsValid` | `bool` | `HashMatch && SignatureValid && Error is null` |
| `HashMatch` | `bool` | Document hash matches the value embedded in the `.p7s` |
| `SignatureValid` | `bool` | RSA/ECDSA signature over signed attributes is valid |
| `Signer` | `string?` | Subject DN of the signing certificate |
| `Trust` | `string?` | `"trusted_chain"`, `"self_signed"`, `"dev_ca"`, … |
| `TsaName` | `string?` | TSA that issued the embedded timestamp |
| `GenTime` | `string?` | Timestamp generation time (ISO 8601) |
| `Qualified` | `bool` | Whether the embedded timestamp is eIDAS-qualified |
| `Error` | `string?` | Set when `IsValid` is `false` |
| `Warnings` | `IReadOnlyList<string>` | Non-fatal issues found during verification |

If you also hold an external `.tsr` file (e.g. from a separate timestamping step),
pass it as `tsr:`:

```csharp
var result = await client.VerifyCadesAsync(document, p7s, tsr: tsrBytes);
```

## JAdES sealing for JSON

For JSON and JSONL content — API payloads, agent logs, AI evidence — prefer
**JAdES** (ETSI TS 119 182-1), the ETSI signature format for JSON. Same
detached, hash-only model as CAdES: only digests are transmitted, and the
returned `.jades.json` artifact verifies against the exact original bytes
(re-serializing the JSON breaks it by design).

```csharp
var log = File.ReadAllBytes("agent-log.json");

byte[] jades = await client.SealJadesAsync(log, certId,
    label: "agent-log.json", contentType: "application/json");
// store agent-log.json.jades.json alongside the log

JadesVerifyResult result = await client.VerifyJadesAsync(log, jades);
Debug.Assert(result.IsValid);
```

`pqc: true` works here too — the ML-DSA-87 signer is added as a second JWS
`signatures[]` entry (RFC 9964). `JadesVerifyResult` has the same fields as
`CadesVerifyResult`.

To seal an AI evidence envelope with a JAdES organisation seal in addition to
its RFC 3161 proof, sign the canonical bytes:

```csharp
var sealed_ = await client.SealAsync(input, payloads);
byte[] canonical = EnvelopeHashing.Canonicalize(sealed_.Json);  // full sealed envelope, proofs included
byte[] jades = await client.SealJadesAsync(canonical, certId,
    label: "envelope.jades.json", contentType: "application/json");
```

### Object references (AiEvidenceEnvelopeV2 v2.1)

ETSI TS 119 182-1 §5.2.8.3.1 requires each `sigD.pars` entry to resolve to a
*locator*, so object URIs are relative references: when you omit `Uri`, the
SDK generates `objects/<uuid>`, and a `Uri` you set must match the
[production profile](spec/ai-evidence-envelope-v2.md#31-objects--the-payload-descriptions)
(segments of `A–Z a–z 0–9 . _ ~ -` separated by `/`; no `urn:`, no URLs, no
filenames with personal data). `sigill-envelope.json` and `urn:sigill:envelope`
are reserved for the envelope.

Verification reads both envelope references — `sigill-envelope.json` and the
`urn:sigill:envelope` of seals made before v2.1 — from each signature itself,
so old evidence and runs that straddle an upgrade keep verifying. To show the
form, classify the signed reference:

```csharp
EnvelopeReferenceForm form = EnvelopeReferences.Classify(signedPars0);
if (form == EnvelopeReferenceForm.LegacyUrn)
    Console.WriteLine(EnvelopeReferences.LegacyDiagnostic); // informational, never a failure
```

## PAdES PDF sealing — the PDF never leaves your machine

For PDFs, the SDK produces an embedded **PAdES** signature (ETSI EN 319 142-1)
without uploading the document. It assembles the PDF signature revision locally,
sends Sigill only the ByteRange SHA-256 digest, embeds the returned CMS, and —
when the certificate chain supports it — upgrades the seal to **B-LT/B-LTA** by
writing the Document Security Store and a document timestamp, all locally.

```csharp
var pdf = await File.ReadAllBytesAsync("contract.pdf");

PadesSealResult result = await client.SealPadesAsync(pdf, certId, new PadesSealOptions
{
    Label = "contract.pdf",
    Qualified = false,             // true → eIDAS-qualified timestamps throughout
    SignerName = "ACME Corp AS",   // recommended: your seal cert's subject CN —
                                   // lands in /Name, what Acrobat shows before
                                   // validation runs (otherwise "Unknown")
    Reason = "Approved",           // optional, lands in the PDF /Reason field
});

await File.WriteAllBytesAsync("contract_sealed.pdf", result.SealedPdf);
Console.WriteLine(result.Format);          // "pades-b-lta" | "pades-b-lt" | "pades-b-t" | "pades-bes"
Console.WriteLine(result.TimestampedBy);   // TSA name, or null if no timestamp could be embedded
```

The sealed PDF validates like any server-produced PAdES seal (Adobe, DSS,
`POST /seal/verify`). Verification requires the PDF and stays server-side.

### Unsupported PDFs and the upload fallback

The local parser handles xref-table PDFs, xref-stream PDFs (PDF 1.5+), and
FlateDecode object streams. When it cannot handle a document's structure,
`SealPadesAsync` throws `SigillPdfUnsupportedException` **before anything is
transmitted** — with the default settings the privacy guarantee is absolute:
nothing but digests ever leaves your machine.

If your data policy permits it, opt in to the server-side fallback and such
documents are sealed by uploading them to `POST /seal/sign` instead (identical
PAdES output, but the PDF is transmitted to Sigill):

```csharp
var result = await client.SealPadesAsync(pdf, certId, new PadesSealOptions
{
    AllowUploadFallback = true,   // default false
});
```

Post-quantum hybrid sealing is not offered for PAdES — the baseline profile
allows a single `SignerInfo` per signature. For an ML-DSA-87 hybrid seal over a
PDF, use `SealCadesAsync(pdf, certId, pqc: true)` and keep the detached `.p7s`
alongside the file.

### Crash-safe sealing: the two-phase flow

`SealPadesAsync` prepares, signs, and embeds in one call. If your pipeline can
die between the server signing (the seal is minted and billed) and your process
persisting the result, use the two-phase flow with the tenant's **Store PAdES
seal data** setting (Settings → Preferences, off by default):

```csharp
PreparedPadesPdf checkpoint = client.PreparePades(pdf);
Save(checkpoint.Bytes);                       // your checkpoint — plain bytes

var result = await client.SealPreparedPadesAsync(checkpoint.Bytes, certId);
// ... process dies before result.SealedPdf was persisted? Resume later:

byte[]? cms = await client.GetSealCmsAsync(operationId);  // escrowed CMS
byte[] sealed = SigillClient.CompletePades(Load(), cms!); // offline recovery
```

`CompletePades` needs no network and recovers a **valid sealed PDF at the
level the CMS carries** — B-T when the signature timestamp succeeded, else
B-BES. LTV material (the DSS and the archival DocTimeStamp that `Ltv = true`
would have appended) is **not reconstructed** on the resume path: with
`Ltv = false` the recovery is byte-identical to the uninterrupted flow; with
the default LTV ladder it recovers the B-T seal, and B-LT/B-LTA can be reached
later by re-sealing. Without the escrow setting, a signing response lost
before embedding cannot be recovered at all.

## Evidence lifecycle: tags, CI gates, and audit packages

Every seal and stamp is an **evidence** in the Sigill evidence store — with a
renewal horizon, verification history, and a custody log. The SDK exposes the
lifecycle surface an automated caller needs:

```csharp
// Tag at creation — the grouping/filter dimension of the evidence store
// (≤10 per evidence, ≤40 chars). Available on every seal method.
await client.SealCadesAsync(artifact, certId, tags: new[] { "release-4.2", "backend" });

// CI gate: does evidence exist, and how close is the renewal horizon?
EvidenceRecord? rec = await client.GetEvidenceRecordAsync(artifact);
if (rec is null) throw new Exception("artifact was never sealed");
Console.WriteLine(rec.CertNotAfter);   // the horizon — fail the build when too close

// Public existence check (no API key needed) — consent-gated: null unless the
// evidence owner opted in to public lookups. Third-party release verification.
PublicLookupResult? found = await client.LookupAsync(artifact);

// Everything an auditor needs, independently verifiable offline:
// tokens, certificates, verification report, custody log, SHA-256 manifest.
byte[] zip = await client.ExportAuditPackageAsync(rec.TransactionId);
```

Expiry-reminder policy can be set per evidence at creation on every seal
method: `reminders: "on"` (with `reminderDays: 30/60/90/180`), `"off"` (muted),
or the default `"inherit"`.

## Agent runs: verifiable multi-step execution

For agents that call tools, retrieve context and act over several steps, a
single envelope is not enough: you need to show which controls applied before
the run, which security-relevant events were captured and in what order, and
that nothing captured was changed or removed afterwards. Three sibling
profiles of the v2 envelope ([common rules](spec/agent-profiles-common-v1.md))
cover one controlled run:

| Phase | Profile | What it seals |
|---|---|---|
| Before | [Control Artifact](spec/agent-control-artifact-v1.md) | configuration, control set, baseline, timestamp policy |
| During | [Execution Evidence](spec/agent-execution-evidence-v1.md) | one artifact per event, chained by signature |
| During | [Model Calls](spec/agent-model-calls-v1.md) (execution `schemaVersion "3"`) | per model call: the model that served it and the provider's own ids for the call, so the provider can confirm it against its logs; prompts and responses as digests only |
| During | [Enforcement (draft)](spec/agent-enforcement-v1.md) (execution `schemaVersion "4"`) | the guard's denials and halts before the action, recomputable from the [policy control set v2](spec/agent-policy-control-set-v2.md) |
| After | [Control Evaluation](spec/control-evaluation-v1.md), [v2 (draft)](spec/control-evaluation-v2.md) | what an independent verifier observed, and each control's result; v2 adds policy evaluations (reproducible from the run's facts) and the producer's own attested results |

To record model calls, start the run with `RecordsModelCalls = true` and put
`ModelCallHandler` under any provider client that accepts an `HttpClient`
(Anthropic, OpenAI, Azure OpenAI, Amazon Bedrock, Gemini API, Vertex AI). Values
come from the provider's response; for any other provider call `RecordModelCallAsync`.

```csharp
var http = new HttpClient(new ModelCallHandler(run, new HttpClientHandler()));
```

Conversations with hosted assistants recorded on the user's side (the Sigill browser
extension) use the same profiles under the [client-observed conventions](spec/agent-client-observed-v1.md).

```csharp
var agent = new AgentDefinition
{
    AgentId = "urn:example:agent:support-triage",   // opaque — no personal data
    AgentVersion = "2.4.0",
    Configuration = new AgentConfiguration
    {
        InstructionSet  = systemPromptBytes,
        ToolManifest    = toolSchemasJson,
        ExecutionPolicy = allowlistAndLimitsJson,
        ModelConfig     = modelAndSamplingJson,
    },
};

// Seals the Control Artifact (timestamped), then run_start, which binds it.
var run = await client.StartAgentRunAsync(agent, new AgentRunOptions
{
    CertificateId = certId,
    Activity = "support-ticket-close",
    ControlSet = new AgentControlSet { Id = "ticket-close-v2", Version = "2", Content = controlSetJson },
    BaselineState = ticketBeforeJson,      // what "unchanged" controls are checked against
});

await run.RecordToolCallAsync("lookup_ticket", argsJson, operation: "read", useId: "call-1");
await run.RecordToolResultAsync("lookup_ticket", resultJson, useId: "call-1");

// A write that needs a human: the policy decision, the approval, then the call.
await run.RecordAuthorizationAsync(new AgentAuthorization
    { Decision = "allow_with_human_approval", PolicyId = "support-tools-v1" });
await run.RecordHumanApprovalAsync("approved",
    receipt: approvalReceiptJson,          // bound by digest; bytes stay with you
    identityAssertion: approverIdToken,    // e.g. the IdP token of the approver
    approver: "urn:example:approver:42");  // opaque — never a name or e-mail
await run.RecordToolCallAsync("close_ticket", argsJson, operation: "write", consequential: true);

await run.RecordModelOutputAsync(answerBytes);
AgentRunBundle bundle = await run.FinishAsync("completed");   // run_end, timestamped
```

An independent verifier then reads the target's state and seals its
evaluation, with its own certificate:

```csharp
var evaluation = await verifierClient.SealControlEvaluationAsync(new ControlEvaluationRequest
{
    CertificateId = verifierCertId,
    VerifierId = "urn:example:verifier:ticket-state", VerifierVersion = "1.3.0",
    ControlArtifact = run.ControlArtifact, RunEnd = bundle.Artifacts[^1],
    ObservedState = new[] { AgentRunObject.Json("observed-state", ticketAfter) },
    Controls = new[] { new ControlResult("ticket-closed", "PASS"), new ControlResult("owner-unchanged", "PASS") },
    Overall = "PASS",
});
File.WriteAllText("run.json", bundle.WithEvaluations(evaluation).ToJsonString());
```

Later, anyone holding the bundle can verify it:

```csharp
var result = await client.VerifyAgentRunAsync(AgentRunBundle.Parse(File.ReadAllText("run.json")));
// result.Verdict     -> "run_finalized" | "run_open" | "run_invalid"
// result.Checks      -> correlation, sequence, chain, envelope, signatures,
//                       timestamps, objects, finalization, control: ok | warn | bad
// result.Binding     -> "bound" | "run_only" | "control_only" | "unbound"
// result.Findings    -> exactly what failed, e.g. "Sequence gap: no artifact for seq 2 (deleted or withheld)."
// result.Evaluations -> per evaluation: Valid (read this one), the parts it is made of — SubjectBound,
//                       ControlSetDigestMatches, BaselineDigestMatches, SignatureValid, TimestampValid,
//                       ObjectsComplete — and Overall exactly as the verifier claimed it
Console.WriteLine(result.Scope); // what a verdict does — and does not — establish
```

What to know:

- **Content never leaves your machine.** Sealing and verification send digests
  and opaque URNs only. A bundle carries digests by default; set
  `RetainPayloads` (or use `bundle.WithPayloads(...)`) only when the recipient
  may read the content — supplying payloads upgrades the `objects` check from
  "digests match" to "content matches".
- **Seal every event, timestamp to wrap up.** Every event is signed and
  chained; by default RFC 3161 timestamps go only on the Control Artifact,
  `run_end` and each Control Evaluation — three for a whole run. The policy is
  signed into the Control Artifact, so the verifier knows which events had to
  carry one. Opt into more with `AgentTimestampPolicy { Consequential = true }`
  (every consequential event), `EveryEvents` / `EverySeconds` (a cadence),
  `AgentTimestampPolicy.PerEvent`, `requireTimestamp: true` on one event, or
  `run.CheckpointAsync()` from a timer while a long run is idle.
- **One certificate per run.** The Control Artifact and every event must be
  sealed with the same certificate; the verifier fails a run that mixes
  signers, so events forged by anyone else cannot be appended. Pin your
  certificates' thumbprints with
  `client.VerifyAgentRunAsync(bundle, expectedSigners: new[] { thumbprint })`
  (`result.Signer` shows the run's), and the verifier's with
  `expectedEvaluationSigners`.
- **Keep the Control Artifact with the run.** `run_start` binds it, so a
  bundle without it fails the `control` check: leaving it out must not hide a
  stricter policy or a broken control basis.
- **What the default does not prove.** Events without a timestamp could be
  rewritten by anyone able to seal with the run's certificate until `run_end`
  is timestamped; `result.Scope` says so. Timestamp consequential events to
  narrow that window.
- **Timestamps count only from a trusted TSA.** The signature service reports
  each timestamp's TSA trust; until it reports `trusted_chain` or `qualified`,
  the result carries a "TSA trust not established" warning.
- **Evaluations never change the run verdict.** They are reported on their
  own, and the SDK evaluates no controls: `Overall` is the named verifier's
  claim (a policy evaluation's rules can be recomputed: see
  [Policy engine](#policy-engine)). Read it only when `Valid` is true — the evaluation is then
  signed over its own envelope, timestamped, intact, and bound to this run's
  `run_end`, Control Artifact and pre-sealed control set.
- **Persist as you go.** `OnArtifactSealed` runs after each artifact is sealed,
  in order. A sealing failure stops the chain; the partial bundle
  (`run.ToBundle()`) verifies as open or invalid, never as finalized.
- **Bring your own verifier.** `AgentRunVerifier.VerifyAsync(bundle, verifier)`
  accepts any `BlindObjectsVerifier`; `AgentRunVerifier.Remote(client)` is the
  blind endpoint used above.

### Sub-agents: run trees

An agent that starts sub-agents records each one as its own run, bound to the
parent in both directions ([Agent Delegation v1](spec/agent-delegation-v1.md)).
Children may run concurrently and under their own certificate and controls.

```csharp
var parent = await client.StartAgentRunAsync(agent, options with { Delegating = true });

// The parent declares the child before it starts; only the instruction's digest is sealed.
AgentDelegation delegation = await parent.DelegateAsync("urn:example:agent:security-reviewer",
    instruction: taskBytes, useId: "call-7");

// The child's run_start binds the parent's delegation event.
var child = await client.StartChildAgentRunAsync(reviewerAgent, reviewerOptions, delegation);
await child.RecordToolCallAsync("repo.read_file", argsJson, operation: "read");
await child.FinishAsync("completed");

await parent.CompleteDelegationAsync(child);   // binds the child's run_end
await parent.FinishAsync("completed");

var tree = new AgentRunTreeBundle(parent.CorrelationId, new[] { parent.ToBundle(), child.ToBundle() });
var result = await client.VerifyAgentRunTreeAsync(tree);
// result.Verdict -> "tree_finalized" | "tree_open" | "tree_invalid"
// result.Edges   -> per delegation: mutually_bound | child_missing | parent_missing | unbound,
//                   and result_bound | result_mismatch | result_unresolved | no_result
// result.Runs    -> every run with its own verdict, which the tree never changes
```

- **A withheld child is detected.** The parent's `delegation_result` names the
  child's `run_end`; a tree that leaves the child out, swaps it, or edits it is
  `tree_invalid`.
- **Close what you open.** A parent cannot close `completed` while a delegation
  has no result; close it `aborted` or `failed` instead, and the tree reports
  "parent terminated; evidence incomplete". The recorder keeps one event slot
  per open delegation, plus `run_end`, inside the 2,000-event bundle limit.
- **Attribution needs a policy.** Pass `AgentRunTreeOptions.ExpectedSigners`
  (`agent.id` → certificate thumbprints) and `ExpectedRoot…` to bind the tree to
  what you expected; without them a shared certificate proves consistency, not
  who ran each sub-agent.

### Policy enforcement (draft): tool calls and bound approvals

A run whose control set is a [policy control set v2](spec/agent-policy-control-set-v2.md)
(`AgentPolicy.ControlSetFromDocument`, with `"schemaVersion": "2"`) is recorded as
execution `schemaVersion "4"` ([Agent Enforcement v1](spec/agent-enforcement-v1.md)): every
tool call has a `useId` and every result names its call. Only the guard (below) writes an
enforcement record or a halted `run_end`; `RecordAsync` refuses those members. The verifier
adds the `enforcement` check for v4 runs (results without a call, a second result, reused
use ids, misplaced or unrecorded decisions), and reports `evidence_version_mismatch` when a
run under a v2 policy control set is not v4.

Record a call and its result as one lifecycle:

```csharp
ToolCall call = await run.BeginToolCallAsync("crm.read_customer", argsJson, operation: "read",
    definition: toolManifestEntry);   // optional: binds the tool's definition by digest
byte[] result = await ReadCustomerAsync(argsJson);
await call.CompleteAsync(result);      // same tool and useId; a second completion is refused
```

Bind an approval to the call it is for: its tool and the digest of its exact arguments,
optionally its `useId` and an expiry. One approval binds at most one call, and a
rejection is sticky for the run:

```csharp
await run.RecordHumanApprovalAsync("approved", approver: "urn:example:approver:42",
    covers: ApprovalCovers.ForArguments("payments.refund", refundArgs, expiresAt: DateTimeOffset.UtcNow.AddMinutes(15)));
ToolCall refund = await run.BeginToolCallAsync("payments.refund", refundArgs, consequential: true);
// Or covers: call.Covers() for one sealed call exactly, including its useId.
```

`AgentPolicy.Validate` checks a v2 document (entities, enforcement settings, annotations,
the schema v2 digest; strict Cedar validation needs a Cedar engine, below), `AgentPolicy.Enforcement`
gives its effective settings and each rule's effect, and `AgentPolicy.BuildFactsV2` builds
the facts v2 a guard and an evaluator evaluate.

### Policy engine

The package `Sigill.Sdk.Policy` adds `CedarEngine`: the official [Cedar](https://github.com/cedar-policy/cedar)
policy core, `cedar-policy` 4.14.0, compiled to one WebAssembly module (sha256
`a0cd395067e77a157116f6b25bcdb612d34c61d1a4446918d75da1a07c80d1f3`, built reproducibly from
[`engine/`](engine/README.md)) and run in-process with [Wasmtime](https://wasmtime.dev). The module is
embedded in the package and refused if its digest differs; it has no filesystem, network, clock or
environment, and at most 256 MiB of memory. `Sigill.Sdk` itself has no dependency on it: the methods
below take any `IPolicyEngine`.

```sh
dotnet add package Sigill.Sdk.Policy
```

```csharp
using Sigill.Sdk.Policy;

var engine = new CedarEngine();   // loads on first use; share one instance between threads

// Everything Validate checks, plus Cedar's strict validation of the rules against the schema of the
// document's version (and, for v2, of cedar.entities against schema v2).
IReadOnlyList<string> problems = AgentPolicy.ValidateStrict(controlSetBytes, engine);

// Per-rule results over a run's facts: PASS / FAIL / INDETERMINATE with where, overall, the engine id
// ("cedar-policy@4.14.0") and per request the rules that matched or errored.
PolicyFacts facts = AgentPolicy.BuildFacts(agentId, correlationId, events);
PolicyEvaluationResult evaluated = AgentPolicy.Evaluate(controlSetBytes, facts.Bytes, engine);

// Verify a run and recompute each policy evaluation of a v1 control set from its sealed facts:
// ResultsRecomputed is true when they match; results that differ make the evaluation invalid.
var result = await client.VerifyAgentRunWithEngineAsync(bundle, engine);
```

An evaluation made with another Cedar version, or beyond the verification's recomputation budget, is
not recomputed (a note says so); a request the engine refuses makes the evaluation invalid. A failure
inside the engine is a `PolicyEngineException`, and never makes the verifier throw. The engine runs where
Wasmtime ships native libraries: Linux (glibc), macOS and Windows on x64 and arm64.

### Enforcement (draft): deny a tool call, halt a run

With a policy engine the run gets a guard ([Control Set v2 §7](spec/agent-policy-control-set-v2.md)): after
each event is sealed it evaluates the event's facts, and under `enforcement.mode: "enforce"` it denies a tool
call or halts the run **before the agent acts**, and seals that decision in the run's chain as an
enforcement record (and, for a halt, a `run_end` with `runDisposition: "halted"`).

```csharp
using var engine = new CedarEngine();
var run = await client.StartAgentRunAsync(agent, new AgentRunOptions
{
    CertificateId = certId, Activity = "support-session",
    ControlSet = AgentPolicy.ControlSetFromDocument(controlSetBytes),
    Enforcement = new AgentEnforcement(engine) { OnEvent = e => log.Information("guard {Kind} {Reason}", e.Kind, e.Reason) },
});

try
{
    // Begins the call; runs the tool only if the guard allows it; seals its result.
    byte[] result = await run.InvokeToolAsync("payments.refund", argsJson, ct => RefundAsync(argsJson, ct), consequential: true);
}
catch (PolicyDeniedException denied)   // denied.Reason, .Rules, .Tool, .UseId, .Seq, .Record, .Halted
{
    // The tool did not run. A retry is a new call (a new use id): e.g. after a human approves exactly this call
    // with RecordHumanApprovalAsync(..., covers: ApprovalCovers.ForArguments("payments.refund", argsJson)).
}
```

- **Switching it on.** A control set whose `enforcement.mode` is `enforce` requires `Enforcement`: starting
  without one is an `ArgumentException`, before anything is sealed. With `Enforcement`, the control set is
  validated strictly (`AgentPolicy.ValidateStrict`) before anything is sealed. With `mode: "observe"`, a v1
  control set or no policy control set, the guard never denies or halts and seals nothing; matching rules are
  only reported to `OnEvent` (kind `observed`, naming the tool on a `tool_call` or `tool_result`), as are
  `effect: observe` (shadow) rules in enforce mode. The producer's own `run_end` is not evaluated. In observe mode
  an engine that fails at start raises a `PolicyEngineException` before anything is sealed; later failures are silent.
- **A denied call.** `BeginToolCallAsync`, `RecordToolCallAsync` and `InvokeToolAsync` raise
  `PolicyDeniedException` after the call and its record (and the halt, when it halts) are sealed. No `ToolCall`
  is returned, and a result for that use id is refused.
- **A halt.** A `halt` rule, `haltAfterDenials`, or an engine that fails halts the run. The recording call that
  caused it raises `RunHaltedException`; so does every later recording call (a call allowed just before the halt is
  not started: `BeginToolCallAsync`, `RecordToolCallAsync` and `InvokeToolAsync` raise it too), and `ModelCallHandler` sends no
  further model call. In an enforced run `ModelCallHandler` also raises a failure to record a model call (after `onError`)
  and sends nothing once the run is broken or finished. `IsHalted` is true and `HaltedToken` is cancelled: pass it to the agent's other work.
  `FinishAsync` returns the halted run's bundle without sealing anything. A `halt` rule on `delegation` hands out
  no delegation at all.
- **A refused start.** A locked configuration that differs, or an engine that cannot load, refuses the start:
  `StartAsync` raises `StartRefusedException`; its `Run` is the closed run (Control Artifact, `run_start`, the
  record, the halted `run_end`).
- **Callbacks.** `OnEvent` runs after the evidence is sealed, outside the run's lock, in seal order, and before
  the exception reaches the caller. A failing callback never breaks the run or hides a denial (it becomes the
  denial's inner exception).
- **Nothing leaves.** Records, messages and events name the tool alias, use id, rule ids, reason and seq only;
  never arguments, results or definitions. The engine sees facts and the control set, not content.

Three runnable examples are in [`examples/Sigill.Sdk.Examples`](examples/Sigill.Sdk.Examples) (scripted agents,
no model calls, under the example's own control set): `loop`, an agent that keeps retrying a forbidden call until
the run is halted; `graph`, two branches recording concurrently on one run (one denied, one finishing) and a
delegated child run; `approval`, a call denied, approved with `covers`, retried and allowed. Each prints what the
guard decided and the verification of the run with the engine:

```sh
SIGILL_API_KEY=… SIGILL_CERTIFICATE_ID=… dotnet run --project examples/Sigill.Sdk.Examples -- loop
# SIGILL_BASE_URL selects another endpoint; SIGILL_CA_BUNDLE (a PEM file) makes only that CA trusted for it.
```

**What enforcement does and does not show.**

- Enforcement is done by the producer's own SDK, in the producer's process. The evidence shows what that guard
  decided; it cannot show that a producer did not bypass it.
- A stop means the SDK refused the call, not that the tool could not be reached another way.
- That a denied tool did not run is not proven by the evidence: the evidence shows that the call was denied
  and that no result was recorded for it.
- Anyone with the control set and the signed events can recompute each decision with the Cedar core named in
  the record — except a record with reason `unavailable` (the engine failed), which cannot be recomputed.
- A tool that is already executing when another event halts the run is not stopped by the SDK; its result is not sealed.
- Model calls the SDK cannot recognise or parse are not recorded, so no rule sees them.
- The run's state is checked once more after the call's callbacks have run and, in `InvokeToolAsync`, immediately before
  the function is called; a halt sealed by another thread after that check does not stop the function.
- An engine that does not answer holds the run: there is no timeout on a decision.
- A child run is refused after its parent halted only when it is started from the delegation object the parent
  returned in the same process.

## Error handling

Producer-time errors throw; verification errors are collected. This split is
deliberate: when sealing, you have a single in-flight operation that either works
or doesn't. When verifying, an audit UI wants every problem at once, not just the
first.

| When | Surface | Spec §7 kind |
|---|---|---|
| `SealAsync()` — every TSA Sigill tried failed | `SigillTimestampUnavailableException` (with `Failures`) | `timestamp_unavailable` |
| `SealAsync()` — caller pre-declared a hash that doesn't match supplied bytes | `SigillHashMismatchException` | `hash_mismatch` |
| `SealAsync()` — input contains values JCS rejects (NaN, Infinity) | `SigillCanonicalizationException` | `canonicalization_failed` |
| `VerifyAsync()` — anything wrong | `result.Issues`, `result.IsValid == false` | per-issue `Kind` field |

All of these inherit from `SigillException`. A typical seal-with-fallback:

```csharp
try
{
    var sealed_ = await client.SealAsync(envelope, externalPayloads: payloads);
    await Persist(sealed_);
}
catch (SigillTimestampUnavailableException ex)
{
    // All TSAs in our rotation failed. Persist unsealed, seal asynchronously.
    logger.LogWarning("TSA outage: {Attempts} attempts, failures={@Failures}",
        ex.AttemptsTried, ex.Failures);
    await PersistForAsyncSealing(envelope, payloads);
}
```

## Integration patterns

A common pattern is to call the SDK from a response post-processor that runs
after every model call. Two scenarios:

**Inline path (no PII)**: the prompt and response are non-sensitive enough to
store verbatim. Build the envelope inline, seal, persist:

```csharp
public sealed class AiEvidenceLogger
{
    private readonly ISigillAiEvidenceClient _sigill;
    private readonly IEvidenceStore _store;

    public async Task LogAsync(AiCallContext ctx, ModelInvocation call, ModelResponse resp)
    {
        var envelope = new EnvelopeBuilder()
            .WithPurpose(category: ctx.PurposeCategory)
            .WithActor(type: "service", id: ctx.ServiceId, tenantId: ctx.TenantId)
            .WithActivity(name: ctx.ActivityName, correlationId: ctx.TraceId)
            .WithModel(provider: call.Provider, name: call.ModelName,
                       parameters: call.ParametersAsJson)
            .WithPromptInline(call.PromptText)
            .WithOutputInline(resp.OutputText)
            .Build();

        var sealed_ = await _sigill.SealAsync(envelope);
        await _store.WriteAsync(ctx.TraceId, sealed_.Json);
    }
}
```

**PII path**: the prompt or response carries personal data. Hash-reference them
in the envelope; store the bytes separately under your normal data-retention
policy. When you delete them later (right-to-erasure, retention expiry), the
sealed envelope still proves the call happened, just not what was in it.

Register `SigillClient` once at startup with `IHttpClientFactory`:

```csharp
services.AddHttpClient<ISigillAiEvidenceClient, SigillClient>(http =>
{
    http.BaseAddress = new Uri("https://api.sigill.ai");
    http.DefaultRequestHeaders.Authorization =
        new AuthenticationHeaderValue("Bearer", configuration["Sigill:ApiKey"]);
});
```

## Cross-language interop

This SDK and the [Python SDK at sigill-python](https://github.com/sigill-ai/sigill-python)
share the same spec, JSON Schema, and test vectors. An envelope sealed by either
SDK verifies with either SDK — the canonical bytes are byte-identical.

The interop guarantee is enforced by tests: both test suites read the same files
under [`spec/test-vectors/`](spec/test-vectors/) and assert that their canonical
output matches the committed reference bytes. The `spec/` directory in this repo
is a vendored copy of the canonical source; both repos hold byte-identical
copies, and the CI in each repo will fail if its copy drifts from what the
canonicalizer produces.

The same holds for agent runs: both verifiers reproduce every shared
agent-run vector — verdict, checks, binding, findings and warnings — so a run
recorded with either SDK verifies identically with the other. The run-tree vectors
([`agent-run-tree/`](spec/test-vectors/agent-run-tree/README.md)) pin the
delegation rules the same way; this SDK reproduces all of them, and the Python
SDK follows.

## Pinning a specific TSA

By default, `SealAsync()` uses Sigill's `auto` mode — round-robin across the TSAs
you have enabled, with automatic failover. That's the recommended setting for
production. If you need to record that a *specific* TSA produced the timestamp
(compliance reason, specific policy OID), pass it explicitly:

```csharp
var sealed_ = await client.SealAsync(envelope, options: new SealOptions
{
    TsaSlug = "skid-ecc",      // eIDAS Qualified TSA from SK ID Solutions
    Qualified = true,
});
```

Available slugs and their properties: see
[Sigill's TSA documentation](https://docs.sigill.ai).

## Lower-level surface

The SDK exposes its primitives in case you need them outside the seal/verify
flow:

```csharp
using Sigill.Sdk;

// Canonicalize a JSON object per RFC 8785
byte[] canonical = EnvelopeHashing.Canonicalize(jsonObj);

// Compute the envelope hash per spec §4 (strips integrity.envelopeHash + proofs)
var (digestHex, canonicalBytes) = EnvelopeHashing.ComputeEnvelopeHash(envelopeJson);

// Hash arbitrary bytes
string hex = EnvelopeHashing.HashHex(someBytes, "SHA-256");
```

This is what every test vector is built from, and it's what the cross-language
interop guarantee comes down to.

## What this SDK is not

It is not a substitute for **TSA chain validation**. The SDK confirms the TSR's
embedded message-imprint matches your envelope, but it does not — by design in v1
— validate the TSA's certificate chain back to a trust anchor. Sigill's
`POST /tsa/verify` endpoint does that server-side. v2 of this SDK will provide a
pluggable trust policy.

## Verifying a release

Every release is sealed with Sigill before it is published: the `.nupkg` and
`.snupkg` each get a detached CAdES seal (`.p7s`) with a qualified (eIDAS) RFC 3161 timestamp and
a post-quantum hybrid signature (ML-DSA-87 strengthens the classic seal). The
seals are attached to the [GitHub release](https://github.com/sigill-ai/sigill-dotnet/releases).
nuget.org adds its own repository signature inside the package, so the file it
serves differs from the one we built; that file is sealed too
(`Sigill.Sdk.<version>.nuget-org.nupkg.p7s`). To check a download, put the
file and the matching `.p7s` into [sigill.ai/verify](https://sigill.ai/verify).

## Development

```
git clone https://github.com/sigill-ai/sigill-dotnet.git
cd sigill-dotnet
dotnet test
```

CI runs `net8.0` and `net9.0` on Ubuntu and Windows.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
