// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Sigill.Sdk.Internal;

namespace Sigill.Sdk;

/// <summary>
/// Concrete <see cref="ISigillAiEvidenceClient"/> that talks to Sigill via HTTP.
///
/// Construct once per process; the underlying <see cref="HttpClient"/> is reusable.
/// Pass an existing <see cref="HttpClient"/> to participate in DI / Polly /
/// <c>IHttpClientFactory</c>; otherwise the client manages its own.
/// </summary>
public sealed class SigillClient : ISigillAiEvidenceClient, IDisposable
{
    /// <summary>Default Sigill API base URL.</summary>
    public const string DefaultBaseUrl = "https://api.sigill.ai";

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;

    /// <summary>Construct a client with an API key (or JWT). Owns its own HttpClient.</summary>
    public SigillClient(string apiKey, string baseUrl = DefaultBaseUrl, TimeSpan? timeout = null)
    {
        if (string.IsNullOrWhiteSpace(apiKey)) throw new ArgumentException("apiKey is required", nameof(apiKey));
        _http = new HttpClient { BaseAddress = new Uri(baseUrl), Timeout = timeout ?? TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _ownsHttp = true;
    }

    /// <summary>
    /// Construct using a caller-managed HttpClient — the <c>IHttpClientFactory</c>
    /// path. The Authorization header MUST be set on the supplied client.
    /// </summary>
    public SigillClient(HttpClient http)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        if (_http.BaseAddress is null) throw new ArgumentException("HttpClient must have BaseAddress set.", nameof(http));
        _ownsHttp = false;
    }

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    // ============================================================== seal

    /// <inheritdoc/>
    public async Task<SealedAiEvidenceEnvelope> SealAsync(
        AiEvidenceEnvelopeInput input,
        IReadOnlyDictionary<string, byte[]>? externalPayloads = null,
        SealOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        options ??= new SealOptions();
        externalPayloads ??= new Dictionary<string, byte[]>();

        // Deep-clone so the caller's input is never mutated.
        var env = (JsonObject)JsonNode.Parse(input.Json.ToJsonString())!;

        // 1. Populate hash references from supplied bytes.
        PopulatePayloadHashes(env, externalPayloads);

        // 2. integrity.canonicalization MUST be set before hashing (it's part of the
        // canonical bytes). envelopeHash and proofs MUST NOT be present yet.
        var integrity = env["integrity"] as JsonObject ?? new JsonObject();
        integrity["canonicalization"] = "RFC8785";
        integrity.Remove("envelopeHash");
        env["integrity"] = integrity;
        env.Remove("proofs");

        // 3. Hash the canonical envelope.
        var (digestHex, canonicalBytes) = EnvelopeHashing.ComputeEnvelopeHash(env);
        ((JsonObject)env["integrity"]!)["envelopeHash"] = new JsonObject
        {
            ["alg"] = "SHA-256",
            ["hex"] = digestHex,
        };

        // 4. Stamp via Sigill /tsa/stamp. Default label to activity.name when not supplied.
        if (options.Label is null && env["activity"]?["name"]?.GetValue<string>() is string activityName)
            options = options with { Label = activityName };
        var proof = await StampAsync(canonicalBytes, options, cancellationToken).ConfigureAwait(false);
        env["proofs"] = new JsonArray(proof);

        return new SealedAiEvidenceEnvelope(env, canonicalBytes, digestHex);
    }

    private async Task<JsonObject> StampAsync(byte[] canonicalBytes, SealOptions options, CancellationToken ct)
    {
        var requestBody = new JsonObject
        {
            ["tsaSlug"] = options.TsaSlug,
            ["fileBase64"] = Convert.ToBase64String(canonicalBytes),
            ["qualified"] = options.Qualified,
        };
        if (options.Label is not null) requestBody["label"] = options.Label;

        using var resp = await _http.PostAsJsonAsync("/tsa/stamp", requestBody, ct).ConfigureAwait(false);

        if (resp.StatusCode == HttpStatusCode.BadGateway)
        {
            // Per Sigill API: 502 with {message, attemptsTried, failures: [{tsa, errorClass, statusCode, message, latencyMs}]}.
            JsonObject? body = null;
            try { body = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct).ConfigureAwait(false))!; }
            catch { /* leave null */ }
            var failures = ParseFailures(body);
            var attempts = body?["attemptsTried"]?.GetValue<int>() ?? failures.Count;
            var msg = body?["message"]?.GetValue<string>() ?? "All enabled TSAs failed.";
            throw new SigillTimestampUnavailableException(msg, failures, attempts);
        }

        resp.EnsureSuccessStatusCode();

        var data = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: ct).ConfigureAwait(false))!;
        var proof = new JsonObject
        {
            ["type"] = "rfc3161",
            ["tsrBase64"] = data["tsrBase64"]!.GetValue<string>(),
        };
        if (data["tsaName"] is JsonNode tsaName) proof["tsaName"] = tsaName.GetValue<string>();
        if (data["genTime"] is JsonNode genTime) proof["genTime"] = genTime.GetValue<string>();
        if (data["serial"] is JsonNode serial) proof["serial"] = serial.GetValue<string>();
        if (data["qualified"] is JsonNode q) proof["qualified"] = q.GetValue<bool>();
        if (data["policyOid"] is JsonNode policy)
        {
            // policyOid may be present-but-null (server convention). Skip it in that case.
            try { proof["policyOid"] = policy.GetValue<string>(); }
            catch (System.InvalidOperationException) { /* JSON null — fine */ }
            catch (System.FormatException) { /* JSON null — fine */ }
        }
        return proof;
    }

    private static List<TsaFailure> ParseFailures(JsonObject? body)
    {
        var list = new List<TsaFailure>();
        if (body?["failures"] is JsonArray arr)
        {
            foreach (var item in arr.OfType<JsonObject>())
            {
                int? statusCode = null;
                if (item["statusCode"] is JsonValue sv && sv.TryGetValue<int>(out var sc)) statusCode = sc;

                list.Add(new TsaFailure(
                    Tsa: item["tsa"]?.GetValue<string>() ?? "unknown",
                    ErrorClass: item["errorClass"]?.GetValue<string>() ?? "unknown",
                    StatusCode: statusCode,
                    Message: item["message"]?.GetValue<string>() ?? "",
                    LatencyMs: item["latencyMs"]?.GetValue<long>() ?? 0));
            }
        }
        return list;
    }

    private static void PopulatePayloadHashes(JsonObject env, IReadOnlyDictionary<string, byte[]> external)
    {
        foreach (var (path, node) in EnumeratePayloadRefs(env))
        {
            if (node["inline"] is not null) continue;
            var refId = node["ref"]?.GetValue<string>();
            if (refId is null || !external.TryGetValue(refId, out var bytes)) continue;

            var alg = node["hash"]?["alg"]?.GetValue<string>() ?? "SHA-256";
            var actual = EnvelopeHashing.HashHex(bytes, alg);

            var existing = node["hash"]?["hex"]?.GetValue<string>();
            if (!string.IsNullOrEmpty(existing) && existing != actual)
                throw new SigillHashMismatchException(refId, existing!, actual);

            node["hash"] = new JsonObject
            {
                ["alg"] = alg,
                ["hex"] = actual,
                ["sizeBytes"] = bytes.Length,
            };
        }
    }

    // ============================================================ verify

    /// <inheritdoc/>
    public Task<AiEvidenceVerificationResult> VerifyAsync(
        SealedAiEvidenceEnvelope envelope,
        IReadOnlyDictionary<string, byte[]>? externalPayloads = null,
        CancellationToken cancellationToken = default)
    {
        if (envelope is null) throw new ArgumentNullException(nameof(envelope));
        externalPayloads ??= new Dictionary<string, byte[]>();

        var result = new AiEvidenceVerificationResult();
        var env = envelope.Json;

        // 1. Recompute envelope hash.
        var registered = env["integrity"]?["envelopeHash"] as JsonObject;
        byte[] canonicalBytes;
        try
        {
            var alg = registered?["alg"]?.GetValue<string>() ?? "SHA-256";
            var (computed, bytes) = EnvelopeHashing.ComputeEnvelopeHash(env, alg);
            result.EnvelopeHashHex = computed;
            canonicalBytes = bytes;

            if (registered?["hex"]?.GetValue<string>() is not string registeredHex)
            {
                result.AddIssue(new VerificationIssue(
                    Kind: VerificationIssueKind.HashMismatch,
                    Target: "envelope",
                    Message: "Envelope has no integrity.envelopeHash"));
            }
            else if (registeredHex != computed)
            {
                result.AddIssue(new VerificationIssue(
                    Kind: VerificationIssueKind.HashMismatch,
                    Target: "envelope",
                    Message: "envelope_hash_does_not_match: envelope content has been modified",
                    Expected: registeredHex,
                    Actual: computed));
            }
        }
        catch (Exception ex)
        {
            result.AddIssue(new VerificationIssue(
                Kind: VerificationIssueKind.CanonicalizationFailed,
                Target: "envelope",
                Message: "Cannot canonicalize envelope: " + ex.Message));
            return Task.FromResult(result);
        }

        // 2. Walk payload refs.
        foreach (var (path, node) in EnumeratePayloadRefs(env))
        {
            if (node["hash"] is not JsonObject hashNode) continue; // inline-only ref — covered by envelope hash
            var refId = node["ref"]?.GetValue<string>();
            if (refId is null)
            {
                result.AddIssue(new VerificationIssue(
                    Kind: VerificationIssueKind.HashMismatch,
                    Target: path,
                    Message: "payloadRef has 'hash' but no 'ref'; cannot resolve external bytes"));
                continue;
            }
            var expectedHex = hashNode["hex"]?.GetValue<string>() ?? string.Empty;
            if (!externalPayloads.TryGetValue(refId, out var bytes))
            {
                result.AddIssue(new VerificationIssue(
                    Kind: VerificationIssueKind.HashMismatch,
                    Target: refId,
                    Message: $"payload_not_supplied: external bytes for ref '{refId}' were not provided to VerifyAsync()",
                    Expected: expectedHex));
                continue;
            }
            var alg = hashNode["alg"]?.GetValue<string>() ?? "SHA-256";
            var actualHex = EnvelopeHashing.HashHex(bytes, alg);
            if (actualHex != expectedHex)
            {
                result.AddIssue(new VerificationIssue(
                    Kind: VerificationIssueKind.HashMismatch,
                    Target: refId,
                    Message: $"digest_does_not_match: supplied bytes for ref '{refId}' hash to a different value",
                    Expected: expectedHex,
                    Actual: actualHex));
            }
        }

        // 3. Walk proofs.
        var proofs = env["proofs"] as JsonArray;
        if (proofs is null || proofs.Count == 0)
        {
            result.AddIssue(new VerificationIssue(
                Kind: VerificationIssueKind.TimestampUnavailable,
                Target: "proofs",
                Message: "Envelope has no proofs[]; was sealed without a timestamp."));
        }
        else
        {
            for (int i = 0; i < proofs.Count; i++)
            {
                VerifyProof(proofs[i] as JsonObject, i, canonicalBytes, result);
            }
        }

        return Task.FromResult(result);
    }

    private static void VerifyProof(JsonObject? proof, int index, byte[] canonicalBytes, AiEvidenceVerificationResult result)
    {
        var target = $"proofs[{index}]";
        if (proof is null)
        {
            result.AddIssue(new VerificationIssue(VerificationIssueKind.InvalidProof, target, "proof is not an object"));
            return;
        }
        var type = proof["type"]?.GetValue<string>();
        if (type != "rfc3161")
        {
            result.AddIssue(new VerificationIssue(
                Kind: VerificationIssueKind.InvalidProof,
                Target: target,
                Message: $"unsupported proof type '{type}'; v1 supports 'rfc3161'"));
            return;
        }

        var tsrB64 = proof["tsrBase64"]?.GetValue<string>();
        if (tsrB64 is null)
        {
            result.AddIssue(new VerificationIssue(VerificationIssueKind.InvalidProof, target, "proof.tsrBase64 missing"));
            return;
        }

        ParsedTimestamp parsed;
        try { parsed = TsrParser.Parse(tsrB64); }
        catch (SigillInvalidProofException ex)
        {
            result.AddIssue(new VerificationIssue(VerificationIssueKind.InvalidProof, target, ex.Message));
            return;
        }

        // Confirm the TSA's message-imprint = HashAlg(canonical envelope bytes).
        var expectedImprint = EnvelopeHashing.HashHex(canonicalBytes, parsed.HashAlgorithm);
        if (parsed.HashedMessageHex != expectedImprint)
        {
            result.AddIssue(new VerificationIssue(
                Kind: VerificationIssueKind.InvalidProof,
                Target: target,
                Message: "TSR message-imprint does not match envelope canonical bytes",
                Expected: expectedImprint,
                Actual: parsed.HashedMessageHex));
        }

        // Mirror the qualified flag from the proof envelope into the result.
        var qualified = proof["qualified"]?.GetValue<bool>() ?? false;
        result.Timestamps.Add(parsed with { Qualified = qualified });
    }

    // ============================================================ shared

    private static IEnumerable<(string Path, JsonObject Node)> EnumeratePayloadRefs(JsonObject env)
    {
        // Top-level slots known to hold payloadRefs.
        foreach (var key in new[] { "prompt", "output" })
        {
            if (env[key] is JsonObject obj && LooksLikePayloadRef(obj))
                yield return (key, obj);
        }
        foreach (var arrKey in new[] { "inputs", "retrievedContext", "outputArtifacts" })
        {
            if (env[arrKey] is JsonArray arr)
            {
                for (int i = 0; i < arr.Count; i++)
                {
                    if (arr[i] is JsonObject item && LooksLikePayloadRef(item))
                        yield return ($"{arrKey}[{i}]", item);
                }
            }
        }
    }

    private static bool LooksLikePayloadRef(JsonObject obj) =>
        obj["inline"] is not null || obj["hash"] is not null || obj["ref"] is not null;
}
