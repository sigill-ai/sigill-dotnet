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
    Qualified = false,        // true → eIDAS-qualified timestamps throughout
    Reason = "Approved",      // optional, lands in the PDF /Reason field
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

## Development

```
git clone https://github.com/sigill-ai/sigill-dotnet.git
cd sigill-dotnet
dotnet test
```

CI runs `net8.0` and `net9.0` on Ubuntu and Windows.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
