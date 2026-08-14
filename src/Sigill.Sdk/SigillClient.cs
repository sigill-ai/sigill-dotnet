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

        // 4. Stamp via Sigill /tsa/stamp-hash. Only the SHA-256 digest is transmitted —
        // the canonical bytes never leave the machine. RFC 3161 compliant.
        // Default label to activity.name when not supplied.
        if (options.Label is null && env["activity"]?["name"]?.GetValue<string>() is string activityName)
            options = options with { Label = activityName };
        var proof = await StampAsync(digestHex, options, cancellationToken).ConfigureAwait(false);
        env["proofs"] = new JsonArray(proof);

        return new SealedAiEvidenceEnvelope(env, canonicalBytes, digestHex);
    }

    // ========================================================== seal cades

    /// <inheritdoc/>
    public async Task<byte[]> SealCadesAsync(
        byte[] data,
        Guid certificateId,
        string? label = null,
        bool qualified = false,
        bool pqc = false,
        IReadOnlyList<string>? tags = null,
        string? reminders = null,
        int? reminderDays = null,
        CancellationToken cancellationToken = default)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        var hashHex = EnvelopeHashing.HashHex(data);
        var requestBody = new JsonObject
        {
            ["hashHex"] = hashHex,
            ["certificateId"] = certificateId.ToString(),
            ["qualified"] = qualified,
        };
        if (label is not null) requestBody["label"] = label;
        if (tags is { Count: > 0 }) requestBody["tags"] = new JsonArray(tags.Select(t => (JsonNode)t).ToArray());
        if (reminders is not null) requestBody["reminders"] = reminders;
        if (reminderDays is not null) requestBody["reminderDays"] = reminderDays;
        if (pqc)
        {
            // Hybrid seal: the ML-DSA-87 signer commits to SHA-512 of the same content.
            requestBody["pqc"] = true;
            requestBody["hashHex512"] = EnvelopeHashing.HashHex(data, "SHA-512");
        }

        using var resp = await _http.PostAsJsonAsync("/seal/sign-hash", requestBody, cancellationToken).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        return await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }

    // ========================================================== seal pades

    /// <inheritdoc/>
    public async Task<PadesSealResult> SealPadesAsync(
        byte[] pdf,
        Guid certificateId,
        PadesSealOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (pdf is null) throw new ArgumentNullException(nameof(pdf));
        options ??= new PadesSealOptions();

        // 1. Assemble the signature revision locally: placeholder /Contents slot,
        // ByteRange, and the digests over the signed ranges. Only these digests
        // are ever transmitted.
        PdfIncrementalSigner.PreparedPdf prep;
        try
        {
            prep = PdfIncrementalSigner.Prepare(
                pdf, DateTime.UtcNow, options.Reason, options.Location);
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or KeyNotFoundException)
        {
            if (!options.AllowUploadFallback)
                throw new SigillPdfUnsupportedException(ex.Message, ex);
            // Explicit opt-in: server-side sealing with the full parser. This is
            // the one code path in the SDK that transmits the PDF itself.
            return await SealPadesByUploadAsync(pdf, certificateId, options, cancellationToken).ConfigureAwait(false);
        }

        return await SealPreparedCoreAsync(prep, certificateId, options, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Phase 1 of the two-phase delegated PAdES flow: assemble the placeholder
    /// signature revision locally and return it as a persistable checkpoint.
    /// Persist <see cref="PreparedPadesPdf.Bytes"/>, then call
    /// <see cref="SealPreparedPadesAsync"/> — a pipeline that crashes after the
    /// server signed can finish later from the checkpoint plus the escrowed CMS
    /// (<see cref="GetSealCmsAsync"/> + <see cref="CompletePades"/>).
    /// <para>
    /// Throws <see cref="SigillPdfUnsupportedException"/> when the local parser
    /// cannot handle the PDF's structure; the two-phase flow has no upload
    /// fallback — use <see cref="SealPadesAsync"/> with
    /// <see cref="PadesSealOptions.AllowUploadFallback"/> for that.
    /// </para>
    /// </summary>
    public PreparedPadesPdf PreparePades(byte[] pdf, string? reason = null, string? location = null)
    {
        if (pdf is null) throw new ArgumentNullException(nameof(pdf));
        try
        {
            var prep = PdfIncrementalSigner.Prepare(pdf, DateTime.UtcNow, reason, location);
            return new PreparedPadesPdf(prep.Bytes, EnvelopeHashing.ToLowerHex(prep.DocumentHash));
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or KeyNotFoundException)
        {
            throw new SigillPdfUnsupportedException(ex.Message, ex);
        }
    }

    /// <summary>
    /// Phase 2 of the two-phase delegated PAdES flow: sign a prepared revision
    /// (from <see cref="PreparePades"/>, possibly persisted and reloaded) and
    /// finish the seal locally. Everything is re-derived from the prepared
    /// bytes; equivalent to <see cref="SealPadesAsync"/> minus the local
    /// preparation and the upload fallback.
    /// </summary>
    public Task<PadesSealResult> SealPreparedPadesAsync(
        byte[] preparedPdf,
        Guid certificateId,
        PadesSealOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (preparedPdf is null) throw new ArgumentNullException(nameof(preparedPdf));
        var prep = PdfIncrementalSigner.Recover(preparedPdf);
        return SealPreparedCoreAsync(prep, certificateId, options ?? new PadesSealOptions(), cancellationToken);
    }

    /// <summary>
    /// Finish a delegated PAdES seal offline: embed a CMS — typically re-fetched
    /// from escrow via <see cref="GetSealCmsAsync"/> — into a prepared revision
    /// persisted by <see cref="PreparePades"/>. No network access; the result is
    /// the sealed PDF at the level the CMS carries (B-T when timestamped, else
    /// B-BES). LTV upgrades are not re-applied on this path — re-seal via the
    /// normal flow when B-LT/B-LTA is required.
    /// </summary>
    public static byte[] CompletePades(byte[] preparedPdf, byte[] cms)
    {
        if (preparedPdf is null) throw new ArgumentNullException(nameof(preparedPdf));
        if (cms is null) throw new ArgumentNullException(nameof(cms));
        var prep = PdfIncrementalSigner.Recover(preparedPdf);
        return PdfIncrementalSigner.Embed(prep, cms);
    }

    /// <summary>
    /// Shared signing core for <see cref="SealPadesAsync"/> and
    /// <see cref="SealPreparedPadesAsync"/>: digest → sign-pades-hash → embed →
    /// optional DSS + DocTimeStamp.
    /// </summary>
    private async Task<PadesSealResult> SealPreparedCoreAsync(
        PdfIncrementalSigner.PreparedPdf prep,
        Guid certificateId,
        PadesSealOptions options,
        CancellationToken cancellationToken)
    {
        // 2. hash → Sigill → CMS (+ LTV material for the DSS).
        var requestBody = new JsonObject
        {
            ["hashHex"] = EnvelopeHashing.ToLowerHex(prep.DocumentHash),
            ["certificateId"] = certificateId.ToString(),
            ["qualified"] = options.Qualified,
        };
        if (options.Label is not null) requestBody["label"] = options.Label;
        if (options.Reminders is not null) requestBody["reminders"] = options.Reminders;
        if (options.ReminderDays is not null) requestBody["reminderDays"] = options.ReminderDays;
        if (options.Tags is { Count: > 0 })
            requestBody["tags"] = new JsonArray(options.Tags.Select(t => (JsonNode)t).ToArray());

        using var resp = await _http.PostAsJsonAsync("/seal/sign-pades-hash", requestBody, cancellationToken).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        var body = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;

        var cms = Convert.FromBase64String(body["cmsBase64"]!.GetValue<string>());
        var operationId   = Guid.Parse(body["operationId"]!.GetValue<string>());
        var timestampedBy = body["timestampedBy"]?.GetValue<string>();
        var qualified     = body["qualified"]?.GetValue<bool>() ?? false;

        var certDers = ReadDerArray(body["certChainDers"]);
        var ocspDers = ReadDerArray(body["ocspDers"]);

        // 3. Embed the CMS into the reserved slot.
        var signedPdf = PdfIncrementalSigner.Embed(prep, cms);

        // 4. Optional LTV: DSS (B-LT) + DocTimeStamp (B-LTA), both assembled
        // locally. Mirrors the server-side /seal/sign pipeline: the DocTimeStamp
        // is best-effort — a timestamp failure leaves a valid B-LT PDF.
        bool hasDss = false, hasDocTs = false;
        if (options.Ltv && (certDers.Length > 0 || ocspDers.Length > 0))
        {
            signedPdf = PdfIncrementalSigner.AppendDss(signedPdf, certDers, ocspDers, cms);
            hasDss = true;

            try
            {
                var dtPrep = PdfIncrementalSigner.PrepareDocTimestamp(signedPdf, DateTime.UtcNow);
                var stampBody = new JsonObject
                {
                    ["tsaSlug"] = "auto",
                    ["hashHex"] = EnvelopeHashing.ToLowerHex(dtPrep.DocumentHash),
                    ["qualified"] = options.Qualified,
                    // Ties the archival DocTimeStamp to its seal operation so the
                    // platform's evidence view can track — and archival-restamp —
                    // the token that governs the B-LTA horizon. Older platforms
                    // without the field simply ignore it.
                    ["sealOperationId"] = operationId.ToString(),
                };
                if (options.Label is not null) stampBody["label"] = options.Label;
                if (options.Reminders is not null) stampBody["reminders"] = options.Reminders;
                if (options.ReminderDays is not null) stampBody["reminderDays"] = options.ReminderDays;

                using var dtResp = await _http.PostAsJsonAsync("/tsa/stamp-hash", stampBody, cancellationToken).ConfigureAwait(false);
                dtResp.EnsureSuccessStatusCode();
                var dtData = (await dtResp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;
                var tokenDer = Convert.FromBase64String(dtData["tokenBase64"]!.GetValue<string>());

                signedPdf = PdfIncrementalSigner.EmbedDocTimestamp(dtPrep, tokenDer);
                hasDocTs = true;
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                // B-LT is still a valid, LTV-enabled seal; the archival timestamp
                // can be added later by re-sealing or via the server-side path.
            }
        }

        // Same format ladder as the server-side /seal/sign PDF branch.
        var format = timestampedBy is null ? "pades-bes"
            : !hasDss   ? "pades-b-t"
            : !hasDocTs ? "pades-b-lt"
            : "pades-b-lta";

        return new PadesSealResult(
            SealedPdf:     signedPdf,
            OperationId:   operationId,
            Format:        format,
            TimestampedBy: timestampedBy,
            Qualified:     qualified);
    }

    /// <summary>
    /// Upload fallback (opt-in via <see cref="PadesSealOptions.AllowUploadFallback"/>):
    /// server-side PAdES sealing through <c>POST /seal/sign</c>. Same output
    /// levels as the delegated path; the server handles DSS + DocTimeStamp.
    /// </summary>
    private async Task<PadesSealResult> SealPadesByUploadAsync(
        byte[] pdf, Guid certificateId, PadesSealOptions options, CancellationToken ct)
    {
        using var form = new MultipartFormDataContent();
        var filePart = new ByteArrayContent(pdf);
        filePart.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        form.Add(filePart, "file", options.Label ?? "document.pdf");
        form.Add(new StringContent(certificateId.ToString()), "certificateId");
        form.Add(new StringContent(options.Qualified ? "true" : "false"), "qualified");
        if (options.Label is not null)    form.Add(new StringContent(options.Label), "label");
        if (options.Reason is not null)   form.Add(new StringContent(options.Reason), "reason");
        if (options.Location is not null) form.Add(new StringContent(options.Location), "location");
        if (options.Reminders is not null)
            form.Add(new StringContent(options.Reminders), "reminders");
        if (options.ReminderDays is not null)
            form.Add(new StringContent(options.ReminderDays.Value.ToString(System.Globalization.CultureInfo.InvariantCulture)), "reminderDays");
        if (options.Tags is { Count: > 0 })
            foreach (var tag in options.Tags)
                form.Add(new StringContent(tag), "tags");

        using var resp = await _http.PostAsync("/seal/sign", form, ct).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        static string? Header(HttpResponseMessage r, string name) =>
            r.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() : null;

        var tsaName = Header(resp, "X-Seal-Timestamped-By");
        return new PadesSealResult(
            SealedPdf:     await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false),
            OperationId:   Guid.TryParse(Header(resp, "X-Seal-Operation-Id"), out var opId) ? opId : Guid.Empty,
            Format:        Header(resp, "X-Seal-Format") ?? "pades-bes",
            TimestampedBy: tsaName is null or "none" ? null : tsaName,
            Qualified:     string.Equals(Header(resp, "X-Seal-Qualified"), "true", StringComparison.OrdinalIgnoreCase));
    }

    // ========================================================== evidence

    /// <summary>
    /// Download the escrowed signature object for a seal operation
    /// (<c>GET /seal/operations/{id}/p7s</c>). For PAdES operations this is the
    /// /Contents CMS — the input to <see cref="CompletePades"/>; for CAdES/JAdES
    /// it is the detached .p7s / JWS. Returns null when nothing is stored for
    /// the operation (the tenant setting was off, or the id is unknown).
    /// </summary>
    public async Task<byte[]?> GetSealCmsAsync(Guid operationId, CancellationToken cancellationToken = default)
    {
        using var resp = await _http.GetAsync($"/seal/operations/{operationId}/p7s", cancellationToken).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Fetch the newest evidence record for an artifact's SHA-256 hex digest, as
    /// recorded for the authenticated tenant. Returns null when the tenant holds
    /// no record for the hash. The CI-gate primitive: check existence and how
    /// close <see cref="EvidenceRecord.CertNotAfter"/> (the renewal horizon) is.
    /// </summary>
    public async Task<EvidenceRecord?> GetEvidenceRecordAsync(string hashHex, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hashHex)) throw new ArgumentException("hashHex is required", nameof(hashHex));

        using var resp = await _http.GetAsync($"/api/transactions/by-hash/{hashHex.ToLowerInvariant()}", cancellationToken).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        resp.EnsureSuccessStatusCode();
        var b = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;

        return new EvidenceRecord(
            TransactionId: Guid.Parse(b["id"]!.GetValue<string>()),
            Hash:          b["hash"]!.GetValue<string>(),
            HashAlgorithm: b["alg"]?.GetValue<string>(),
            GenTime:       ReadDate(b["genTime"]),
            CreatedAt:     ReadDate(b["createdAt"]) ?? default,
            TsaName:       b["tsaName"]?.GetValue<string>(),
            Label:         b["label"]?.GetValue<string>(),
            CertNotBefore: ReadDate(b["certNotBefore"]),
            CertNotAfter:  ReadDate(b["certNotAfter"]),
            IsRestamp:     b["isRestamp"]?.GetValue<bool>() ?? false,
            HasTsr:        b["hasTsr"]?.GetValue<bool>() ?? false);
    }

    /// <summary>Convenience overload: hashes the artifact bytes locally (SHA-256) first.</summary>
    public Task<EvidenceRecord?> GetEvidenceRecordAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return GetEvidenceRecordAsync(EnvelopeHashing.HashHex(data), cancellationToken);
    }

    /// <summary>
    /// Public existence check (<c>GET /api/lookup/{hash}</c>, no auth required):
    /// has this artifact been timestamped, by anyone who chose to disclose it?
    /// Discoverability is opt-in per tenant/evidence, so null means "no publicly
    /// disclosed record" — deliberately indistinguishable from "never stamped".
    /// Third-party verification of published artifacts (releases, git objects).
    /// </summary>
    public async Task<PublicLookupResult?> LookupAsync(string hashHex, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(hashHex)) throw new ArgumentException("hashHex is required", nameof(hashHex));

        using var resp = await _http.GetAsync($"/api/lookup/{hashHex.ToLowerInvariant()}", cancellationToken).ConfigureAwait(false);
        if (resp.StatusCode == HttpStatusCode.NotFound) return null;
        resp.EnsureSuccessStatusCode();
        var b = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;

        static PublicLookupRecord MapRecord(JsonObject r) => new(
            TransactionId: Guid.Parse(r["id"]!.GetValue<string>()),
            Hash:          r["hash"]!.GetValue<string>(),
            HashAlgorithm: r["alg"]?.GetValue<string>(),
            GenTime:       ReadDate(r["genTime"]),
            CreatedAt:     ReadDate(r["createdAt"]) ?? default,
            TsaName:       r["tsaName"]?.GetValue<string>(),
            CertNotBefore: ReadDate(r["certNotBefore"]),
            CertNotAfter:  ReadDate(r["certNotAfter"]),
            IsRestamp:     r["isRestamp"]?.GetValue<bool>() ?? false);

        var records = new List<PublicLookupRecord>();
        if (b["records"] is JsonArray arr)
            foreach (var item in arr.OfType<JsonObject>())
                records.Add(MapRecord(item));

        return new PublicLookupResult(
            Count:   b["count"]?.GetValue<int>() ?? records.Count,
            Latest:  MapRecord((JsonObject)b["latest"]!),
            Records: records);
    }

    /// <summary>Convenience overload: hashes the artifact bytes locally (SHA-256) first.</summary>
    public Task<PublicLookupResult?> LookupAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return LookupAsync(EnvelopeHashing.HashHex(data), cancellationToken);
    }

    /// <summary>
    /// Download the evidence's audit package
    /// (<c>GET /api/transactions/{id}/audit-package.zip</c>): every token of the
    /// restamp chain, embedded certificates, the latest verification report, the
    /// custody log, the stored detached signature when present, and a SHA-256
    /// manifest — independently verifiable offline with standard tools.
    /// </summary>
    public async Task<byte[]> ExportAuditPackageAsync(Guid transactionId, CancellationToken cancellationToken = default)
    {
        using var resp = await _http.GetAsync($"/api/transactions/{transactionId}/audit-package.zip", cancellationToken).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
        return await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }

    private static DateTimeOffset? ReadDate(JsonNode? node)
    {
        var s = node?.GetValue<string>();
        return s is null ? null : DateTimeOffset.Parse(s, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal);
    }

    private static byte[][] ReadDerArray(JsonNode? node)
    {
        if (node is not JsonArray arr || arr.Count == 0) return Array.Empty<byte[]>();
        var result = new List<byte[]>(arr.Count);
        foreach (var item in arr)
            if (item?.GetValue<string>() is string b64)
                result.Add(Convert.FromBase64String(b64));
        return result.ToArray();
    }

    // ======================================================== verify cades

    /// <inheritdoc/>
    public async Task<CadesVerifyResult> VerifyCadesAsync(
        byte[] data,
        byte[] p7s,
        byte[]? tsr = null,
        CancellationToken cancellationToken = default)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (p7s  is null) throw new ArgumentNullException(nameof(p7s));

        var requestBody = new JsonObject
        {
            ["hashHex"]   = EnvelopeHashing.HashHex(data),
            // Always supply SHA-512 so a hybrid seal's ML-DSA content binding is
            // actually checked (contentBound: "yes"/"no" rather than "not_checked").
            // Ignored by the server for classical-only seals.
            ["hashHex512"] = EnvelopeHashing.HashHex(data, "SHA-512"),
            ["p7sBase64"] = Convert.ToBase64String(p7s),
        };
        if (tsr is not null) requestBody["tsrBase64"] = Convert.ToBase64String(tsr);

        using var resp = await _http.PostAsJsonAsync("/seal/verify-hash", requestBody, cancellationToken).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        var body = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;
        var m = MapDetachedVerify(body["cades"] as JsonObject ?? new JsonObject());

        return new CadesVerifyResult(
            IsValid:        m.HashMatch && m.SignatureValid && m.Error is null,
            HashMatch:      m.HashMatch,
            SignatureValid: m.SignatureValid,
            Signer:         m.Signer,
            Trust:          m.Trust,
            TsaName:        m.TsaName,
            GenTime:        m.GenTime,
            Qualified:      m.Qualified,
            Error:          m.Error,
            Warnings:       m.Warnings,
            PostQuantum:    m.PostQuantum);
    }

    // ========================================================== seal jades

    /// <inheritdoc/>
    public async Task<byte[]> SealJadesAsync(
        byte[] data,
        Guid certificateId,
        string? label = null,
        bool qualified = false,
        bool pqc = false,
        string? contentType = null,
        IReadOnlyList<string>? tags = null,
        string? reminders = null,
        int? reminderDays = null,
        CancellationToken cancellationToken = default)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        var requestBody = new JsonObject
        {
            ["hashHex"] = EnvelopeHashing.HashHex(data),
            ["certificateId"] = certificateId.ToString(),
            ["qualified"] = qualified,
            ["format"] = "jades",
        };
        if (label is not null) requestBody["label"] = label;
        if (contentType is not null) requestBody["contentType"] = contentType;
        if (tags is { Count: > 0 }) requestBody["tags"] = new JsonArray(tags.Select(t => (JsonNode)t).ToArray());
        if (reminders is not null) requestBody["reminders"] = reminders;
        if (reminderDays is not null) requestBody["reminderDays"] = reminderDays;
        if (pqc)
        {
            // Hybrid seal: the ML-DSA-87 signer commits to SHA-512 of the same content.
            requestBody["pqc"] = true;
            requestBody["hashHex512"] = EnvelopeHashing.HashHex(data, "SHA-512");
        }

        using var resp = await _http.PostAsJsonAsync("/seal/sign-hash", requestBody, cancellationToken).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        return await resp.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
    }

    // ======================================================== verify jades

    /// <inheritdoc/>
    public async Task<JadesVerifyResult> VerifyJadesAsync(
        byte[] data,
        byte[] jades,
        byte[]? tsr = null,
        CancellationToken cancellationToken = default)
    {
        if (data  is null) throw new ArgumentNullException(nameof(data));
        if (jades is null) throw new ArgumentNullException(nameof(jades));

        // /seal/verify-hash routes on the artifact bytes (JSON text → JAdES,
        // DER → CAdES); p7sBase64 doubles as the artifact carrier.
        var requestBody = new JsonObject
        {
            ["hashHex"]    = EnvelopeHashing.HashHex(data),
            ["hashHex512"] = EnvelopeHashing.HashHex(data, "SHA-512"),
            ["p7sBase64"]  = Convert.ToBase64String(jades),
        };
        if (tsr is not null) requestBody["tsrBase64"] = Convert.ToBase64String(tsr);

        using var resp = await _http.PostAsJsonAsync("/seal/verify-hash", requestBody, cancellationToken).ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();

        var body = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;
        var m = MapDetachedVerify(body["jades"] as JsonObject ?? new JsonObject());

        return new JadesVerifyResult(
            IsValid:        m.HashMatch && m.SignatureValid && m.Error is null,
            HashMatch:      m.HashMatch,
            SignatureValid: m.SignatureValid,
            Signer:         m.Signer,
            Trust:          m.Trust,
            TsaName:        m.TsaName,
            GenTime:        m.GenTime,
            Qualified:      m.Qualified,
            Error:          m.Error,
            Warnings:       m.Warnings,
            PostQuantum:    m.PostQuantum);
    }

    // ================================================== AI evidence v2 (blind)

    private static readonly HashSet<string> V2Roles =
        new(StringComparer.Ordinal) { "prompt", "input", "context", "output", "artifact", "log" };

    /// <inheritdoc/>
    public async Task<AiEvidenceV2Artifact> SealEvidenceV2Async(
        JsonObject envelope,
        IReadOnlyList<AiEvidenceV2Payload> payloads,
        Guid certificateId,
        EvidenceV2SealOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (envelope is null) throw new ArgumentNullException(nameof(envelope));
        payloads ??= Array.Empty<AiEvidenceV2Payload>();
        options ??= new EvidenceV2SealOptions();

        // Identity defaults — caller-supplied values win.
        envelope = (JsonObject)envelope.DeepClone();
        envelope["schemaName"] ??= "AiEvidenceEnvelope";
        envelope["schemaVersion"] ??= "2";
        envelope["evidenceId"] ??= Guid.NewGuid().ToString();
        envelope["createdAt"] ??= DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

        // objects[] is OWNED by the SDK: derived from the payloads in order, so
        // the envelope's list and the signed sigD pars[1…] are byte-exactly
        // aligned by construction (spec §5.2) and every URI is opaque-safe.
        var seenUris = new HashSet<string>(StringComparer.Ordinal);
        var envelopeObjects = new JsonArray();
        var requestObjects = new List<SignedObjectDigest>();
        foreach (var p in payloads)
        {
            if (p.Bytes is null) throw new ArgumentNullException(nameof(payloads), "payload Bytes is required");
            if (!V2Roles.Contains(p.Role))
                throw new SigillException($"Invalid payload role '{p.Role}' — expected one of: {string.Join(", ", V2Roles)}.");
            var uri = string.IsNullOrWhiteSpace(p.Uri) ? $"urn:uuid:{Guid.NewGuid()}" : p.Uri.Trim();
            if (string.Equals(uri, AiEvidenceV2Artifact.EnvelopeUri, StringComparison.Ordinal))
                throw new SigillException($"'{AiEvidenceV2Artifact.EnvelopeUri}' is reserved for the envelope itself.");
            if (!seenUris.Add(uri))
                throw new SigillException($"Duplicate payload URI '{uri}' — URIs are compared byte-exactly and must be unique.");

            var envObj = new JsonObject { ["uri"] = uri, ["role"] = p.Role };
            if (p.ContentType is not null) envObj["contentType"] = p.ContentType;
            if (p.Encoding is not null) envObj["encoding"] = p.Encoding;
            envObj["sizeBytes"] = p.Bytes.Length;
            if (p.Metadata is not null) envObj["metadata"] = (JsonObject)p.Metadata.DeepClone();
            envelopeObjects.Add(envObj);

            requestObjects.Add(new SignedObjectDigest
            {
                Uri = uri,
                HashHex = EnvelopeHashing.HashHex(p.Bytes),
                HashHex512 = options.Pqc ? EnvelopeHashing.HashHex(p.Bytes, "SHA-512") : null,
                ContentType = p.ContentType,
            });
        }
        envelope["objects"] = envelopeObjects;

        // The envelope is hashed AS-IS (no v1 field-stripping — spec §4).
        var canonical = EnvelopeHashing.Canonicalize(envelope);
        var envelopeHashHex = EnvelopeHashing.HashHex(canonical);

        // Delegate to the profile-agnostic tier. EnvelopeContentType stays
        // unset on purpose: the AI-evidence profile is pinned to its own cty
        // (the platform default) — that is the profile discriminator (spec §5.2).
        var result = await SignObjectHashesAsync(
            envelopeHashHex,
            requestObjects,
            certificateId,
            new ObjectSignOptions
            {
                EnvelopeHashHex512 = options.Pqc ? EnvelopeHashing.HashHex(canonical, "SHA-512") : null,
                Qualified = options.Qualified,
                Pqc = options.Pqc,
                Label = options.Label,
                Tags = options.Tags,
                Reminders = options.Reminders,
                ReminderDays = options.ReminderDays,
            },
            cancellationToken).ConfigureAwait(false);

        // The artifact exists only here — Sigill never saw the envelope.
        return new AiEvidenceV2Artifact(envelope, result.Signature, envelopeHashHex);
    }

    /// <inheritdoc/>
    public async Task<SignHashesResult> SignObjectHashesAsync(
        string envelopeHashHex,
        IReadOnlyList<SignedObjectDigest> objects,
        Guid certificateId,
        ObjectSignOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        objects ??= Array.Empty<SignedObjectDigest>();
        options ??= new ObjectSignOptions();

        if (!IsHex(envelopeHashHex, 64))
            throw new SigillException("envelopeHashHex must be 64 hex characters (SHA-256 of the canonical envelope).");
        if (options.Pqc && !IsHex(options.EnvelopeHashHex512, 128))
            throw new SigillException("Pqc requires EnvelopeHashHex512 — 128 hex characters (SHA-512 of the same canonical envelope).");
        if (objects.Count > MaxSignHashesObjects)
            throw new SigillException($"objects[] is capped at {MaxSignHashesObjects} entries per seal.");

        var seenUris = new HashSet<string>(StringComparer.Ordinal);
        var requestObjects = new JsonArray();
        foreach (var o in objects)
        {
            var uri = o.Uri?.Trim() ?? "";
            if (uri.Length == 0)
                throw new SigillException("Every object needs a non-empty opaque URI.");
            if (string.Equals(uri, AiEvidenceV2Artifact.EnvelopeUri, StringComparison.Ordinal))
                throw new SigillException($"'{AiEvidenceV2Artifact.EnvelopeUri}' is reserved for the envelope itself.");
            if (!seenUris.Add(uri))
                throw new SigillException($"Duplicate object URI '{uri}' — URIs are compared byte-exactly and must be unique.");
            if (!IsHex(o.HashHex, 64))
                throw new SigillException($"Object '{uri}': hashHex must be 64 hex characters (SHA-256).");
            if (options.Pqc && !IsHex(o.HashHex512, 128))
                throw new SigillException($"Object '{uri}': Pqc requires hashHex512 — 128 hex characters (SHA-512).");

            var reqObj = new JsonObject { ["uri"] = uri, ["hashHex"] = o.HashHex };
            if (options.Pqc) reqObj["hashHex512"] = o.HashHex512;
            if (o.ContentType is not null) reqObj["contentType"] = o.ContentType;
            requestObjects.Add(reqObj);
        }

        var requestBody = new JsonObject
        {
            ["envelopeHashHex"] = envelopeHashHex,
            ["certificateId"] = certificateId.ToString(),
            ["objects"] = requestObjects,
            ["qualified"] = options.Qualified,
        };
        if (options.EnvelopeContentType is not null) requestBody["envelopeContentType"] = options.EnvelopeContentType;
        if (options.Pqc)
        {
            requestBody["pqc"] = true;
            requestBody["envelopeHashHex512"] = options.EnvelopeHashHex512;
        }
        if (options.Label is not null) requestBody["label"] = options.Label;
        if (options.Tags is { Count: > 0 }) requestBody["tags"] = new JsonArray(options.Tags.Select(t => (JsonNode)t).ToArray());
        if (options.Reminders is not null) requestBody["reminders"] = options.Reminders;
        if (options.ReminderDays is not null) requestBody["reminderDays"] = options.ReminderDays;

        using var resp = await _http.PostAsJsonAsync("/seal/sign-hashes", requestBody, cancellationToken).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            var detail = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            throw new SigillException($"Blind sealing failed ({(int)resp.StatusCode}): {detail}");
        }
        var body = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;
        if (body["signature"] is not JsonObject signature)
            throw new SigillException("The sealing response did not carry a JWS signature object.");

        return new SignHashesResult
        {
            Signature     = (JsonObject)signature.DeepClone(),
            OperationId   = Guid.TryParse(body["operationId"]?.GetValue<string>(), out var opId) ? opId : Guid.Empty,
            Format        = body["format"]?.GetValue<string>(),
            TimestampedBy = body["timestampedBy"]?.GetValue<string>(),
            Qualified     = body["qualified"]?.GetValue<bool>() ?? false,
            Pqc           = body["pqc"]?.GetValue<bool>() ?? false,
        };
    }

    /// <summary>Mirror of the platform's per-seal object cap.</summary>
    internal const int MaxSignHashesObjects = 128;

    private static bool IsHex(string? s, int length)
    {
        if (s is null || s.Length != length) return false;
        foreach (var c in s)
            if (!System.Uri.IsHexDigit(c)) return false;
        return true;
    }

    /// <inheritdoc/>
    public async Task<EvidenceV2VerificationResult> VerifyEvidenceV2Async(
        AiEvidenceV2Artifact artifact,
        IReadOnlyDictionary<string, byte[]>? payloads = null,
        IReadOnlyList<string>? requiredRoles = null,
        CancellationToken cancellationToken = default)
    {
        if (artifact is null) throw new ArgumentNullException(nameof(artifact));
        payloads ??= new Dictionary<string, byte[]>();

        // Hashing anonymity: only digests travel. The envelope digest is just
        // the entry for urn:sigill:envelope, recomputed locally with JCS.
        var canonical = EnvelopeHashing.Canonicalize(artifact.Envelope);
        var digests = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AiEvidenceV2Artifact.EnvelopeUri] = EnvelopeHashing.HashHex(canonical),
        };
        foreach (var (uri, bytes) in payloads)
            digests[uri] = EnvelopeHashing.HashHex(bytes);

        // Hybrid seals are both-required (spec §7): when the JWS carries an
        // ML-DSA signer, the SHA-512 map travels too — otherwise the platform
        // honestly reports pqc: not_checked and complete: false.
        Dictionary<string, string>? digests512 = null;
        if (HasMlDsaSigner(artifact.Signature))
        {
            digests512 = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [AiEvidenceV2Artifact.EnvelopeUri] = EnvelopeHashing.HashHex(canonical, "SHA-512"),
            };
            foreach (var (uri, bytes) in payloads)
                digests512[uri] = EnvelopeHashing.HashHex(bytes, "SHA-512");
        }

        // The cryptographic dimension is the profile-agnostic tier's job …
        var core = await VerifyObjectHashesAsync(
            artifact.Signature, digests, digests512, tsrBase64: null, cancellationToken).ConfigureAwait(false);

        // … and the envelope-layer checks below are this profile's (spec §7.1).
        var issues = new List<string>();
        var verdicts = new List<EvidenceV2ObjectVerdict>();
        var signedUris = new List<string>();
        foreach (var v in core.Objects)
        {
            signedUris.Add(v.Uri);
            verdicts.Add(new EvidenceV2ObjectVerdict(v.Uri, v.ContentType, v.Supplied, v.HashMatch));
        }

        // Envelope-layer checks — the SDK's job, on the SDK's copy (spec §7.1).
        // 1:1 order-preserving alignment between objects[] and pars[1…].
        var envelopeUris = (artifact.Envelope["objects"] as JsonArray ?? new JsonArray())
            .OfType<JsonObject>().Select(o => o["uri"]?.GetValue<string>() ?? "").ToList();
        var signedPayloadUris = signedUris.Where(u => u != AiEvidenceV2Artifact.EnvelopeUri).ToList();
        var alignmentOk = envelopeUris.Count == signedPayloadUris.Count
            && !envelopeUris.Where((u, i) => !string.Equals(u, signedPayloadUris[i], StringComparison.Ordinal)).Any();
        if (!alignmentOk)
            issues.Add("The envelope's objects[] do not align 1:1 (in order) with the signed sigD object list.");

        // Role coverage: the role must exist in the envelope AND its payload
        // must have been supplied and verified.
        var missingRoles = new List<string>();
        if (requiredRoles is { Count: > 0 })
        {
            var verifiedUris = new HashSet<string>(
                verdicts.Where(v => v.Supplied && v.HashMatch).Select(v => v.Uri), StringComparer.Ordinal);
            foreach (var role in requiredRoles)
            {
                var covered = (artifact.Envelope["objects"] as JsonArray ?? new JsonArray())
                    .OfType<JsonObject>()
                    .Any(o => string.Equals(o["role"]?.GetValue<string>(), role, StringComparison.Ordinal)
                           && verifiedUris.Contains(o["uri"]?.GetValue<string>() ?? ""));
                if (!covered) missingRoles.Add(role);
            }
            if (missingRoles.Count > 0)
                issues.Add($"Required role(s) not covered by a verified payload: {string.Join(", ", missingRoles)}.");
        }

        // The hybrid dimension (including the defensive not_checked fallback
        // when the verifier returned no pqc verdict) is handled by the
        // profile-agnostic tier — its issues carry over verbatim.
        issues.AddRange(core.Issues);

        return new EvidenceV2VerificationResult
        {
            SignatureValid = core.SignatureValid,
            Complete       = core.Complete,
            Pqc            = core.Pqc,
            ObjectCount    = core.ObjectCount,
            SuppliedCount  = core.SuppliedCount,
            MatchedCount   = core.MatchedCount,
            Objects        = verdicts,
            Missing        = core.Missing.ToList(),
            Unreferenced   = core.Unreferenced.ToList(),
            AlignmentOk    = alignmentOk,
            MissingRoles   = missingRoles,
            Issues         = issues,
            Raw            = core.Raw,
        };
    }

    /// <inheritdoc/>
    public async Task<ObjectsVerificationResult> VerifyObjectHashesAsync(
        JsonObject signature,
        IReadOnlyDictionary<string, string>? digests = null,
        IReadOnlyDictionary<string, string>? digests512 = null,
        string? tsrBase64 = null,
        CancellationToken cancellationToken = default)
    {
        if (signature is null) throw new ArgumentNullException(nameof(signature));

        var requestBody = new JsonObject { ["signature"] = signature.DeepClone() };
        if (digests is not null)
        {
            var d = new JsonObject();
            foreach (var (uri, hex) in digests) d[uri] = hex;
            requestBody["digests"] = d;
        }
        if (digests512 is not null)
        {
            var d = new JsonObject();
            foreach (var (uri, hex) in digests512) d[uri] = hex;
            requestBody["digests512"] = d;
        }
        if (tsrBase64 is not null) requestBody["tsrBase64"] = tsrBase64;

        var hybrid = HasMlDsaSigner(signature);

        using var resp = await _http.PostAsJsonAsync("/seal/verify-objects", requestBody, cancellationToken).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            var detail = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            throw new SigillException($"Blind verification failed ({(int)resp.StatusCode}): {detail}");
        }
        var body = (await resp.Content.ReadFromJsonAsync<JsonObject>(cancellationToken: cancellationToken).ConfigureAwait(false))!;
        var r = body["objects"] as JsonObject ?? new JsonObject();

        var verdicts = new List<SignedObjectVerdict>();
        if (r["objects"] is JsonArray objArr)
            foreach (var o in objArr.OfType<JsonObject>())
                verdicts.Add(new SignedObjectVerdict(
                    o["par"]?.GetValue<string>() ?? "",
                    o["contentType"]?.GetValue<string>(),
                    o["supplied"]?.GetValue<bool>() ?? false,
                    o["hashMatch"]?.GetValue<bool>() ?? false));

        // Defensive on the hybrid dimension: the SDK detected the ML-DSA signer
        // itself, so a response with no pqc verdict (older or third-party
        // verifier build) must NEVER let the classical verdict stand in for the
        // hybrid one — that is the exact masquerade the both-required rule
        // forbids. Missing pqc on a hybrid JWS ⇒ not_checked.
        var issues = new List<string>();
        var pqc = r["pqc"]?.GetValue<string>() ?? (hybrid ? "not_checked" : "absent");
        if (hybrid && r["pqc"] is null)
            issues.Add("Hybrid seal: the verifier returned no pqc verdict — treat the ML-DSA commitment as not checked.");
        else if (pqc is "not_checked" or "failed")
            issues.Add($"Hybrid seal: the ML-DSA commitment is '{pqc}'.");
        if (hybrid && digests512 is null)
            issues.Add("Hybrid seal: no SHA-512 digests were supplied — the ML-DSA commitment cannot verify without them.");
        if (r["warnings"] is JsonArray warnArr)
            foreach (var w in warnArr) if (w?.GetValue<string>() is string s) issues.Add(s);

        return new ObjectsVerificationResult
        {
            SignatureValid = r["signatureValid"]?.GetValue<bool>() ?? false,
            Complete       = r["complete"]?.GetValue<bool>() ?? false,
            Pqc            = pqc,
            ObjectCount    = r["objectCount"]?.GetValue<int>() ?? 0,
            SuppliedCount  = r["suppliedCount"]?.GetValue<int>() ?? 0,
            MatchedCount   = r["matchedCount"]?.GetValue<int>() ?? 0,
            Objects        = verdicts,
            Missing        = (r["missing"] as JsonArray ?? new JsonArray()).Select(m => m?.GetValue<string>() ?? "").ToList(),
            Unreferenced   = (r["unreferenced"] as JsonArray ?? new JsonArray()).Select(u => u?.GetValue<string>() ?? "").ToList(),
            Issues         = issues,
            Raw            = body,
        };
    }

    /// <summary>Does the General JWS carry an ML-DSA (hybrid) signature entry?</summary>
    private static bool HasMlDsaSigner(JsonObject signature)
    {
        if (signature["signatures"] is not JsonArray entries) return false;
        foreach (var e in entries.OfType<JsonObject>())
        {
            var protB64 = e["protected"]?.GetValue<string>();
            if (protB64 is null) continue;
            try
            {
                var padded = protB64.Replace('-', '+').Replace('_', '/')
                    .PadRight((protB64.Length + 3) / 4 * 4, '=');
                var header = JsonNode.Parse(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(padded)));
                if (header?["alg"]?.GetValue<string>()?.StartsWith("ML-DSA", StringComparison.Ordinal) == true)
                    return true;
            }
            catch { /* unparseable entry — not evidence of a hybrid signer */ }
        }
        return false;
    }

    private sealed record DetachedVerifyFields(
        bool HashMatch, bool SignatureValid, string? Signer, string? Trust,
        string? TsaName, string? GenTime, bool Qualified, string? Error,
        List<string> Warnings, PqcVerifyInfo? PostQuantum);

    /// <summary>
    /// Shared field extraction for the CAdES and JAdES branches of
    /// <c>/seal/verify-hash</c> — the two verifiers report the same dimensions.
    /// </summary>
    private static DetachedVerifyFields MapDetachedVerify(JsonObject node)
    {
        var cert = node["certificate"] as JsonObject ?? new JsonObject();
        var ts   = node["timestamp"]   as JsonObject ?? new JsonObject();

        var qualSrc = ts["qualificationSource"]?.GetValue<string>() ?? "none";

        var warnings = new List<string>();
        if (node["warnings"] is JsonArray wa)
            foreach (var w in wa) if (w?.GetValue<string>() is string s) warnings.Add(s);

        PqcVerifyInfo? postQuantum = null;
        if (node["postQuantum"] is JsonObject pq && (pq["present"]?.GetValue<bool>() ?? false))
        {
            postQuantum = new PqcVerifyInfo(
                Present:        true,
                Valid:          pq["valid"]?.GetValue<bool>() ?? false,
                SignatureValid: pq["signatureValid"]?.GetValue<bool>() ?? false,
                ContentBound:   pq["contentBound"]?.GetValue<string>() ?? "not_checked",
                Trusted:        pq["trusted"]?.GetValue<string>() ?? "not_evaluated",
                Algorithm:      pq["algorithm"]?.GetValue<string>() ?? "ml-dsa-87");
        }

        return new DetachedVerifyFields(
            HashMatch:      node["hashMatch"]?.GetValue<bool>() ?? false,
            SignatureValid: node["signatureValid"]?.GetValue<bool>() ?? false,
            Signer:         cert["subject"]?.GetValue<string>(),
            Trust:          cert["trust"]?.GetValue<string>(),
            TsaName:        ts["tsaName"]?.GetValue<string>(),
            GenTime:        ts["genTime"]?.GetValue<string>(),
            Qualified:      qualSrc is not null && qualSrc != "none",
            Error:          node["error"]?.GetValue<string>(),
            Warnings:       warnings,
            PostQuantum:    postQuantum);
    }

    private async Task<JsonObject> StampAsync(string hashHex, SealOptions options, CancellationToken ct)
    {
        var requestBody = new JsonObject
        {
            ["tsaSlug"] = options.TsaSlug,
            ["hashHex"] = hashHex,
            ["qualified"] = options.Qualified,
        };
        if (options.Label is not null) requestBody["label"] = options.Label;
        if (options.Tags is { Count: > 0 })
            requestBody["tags"] = new JsonArray(options.Tags.Select(t => (JsonNode)t).ToArray());

        using var resp = await _http.PostAsJsonAsync("/tsa/stamp-hash", requestBody, ct).ConfigureAwait(false);

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
