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
