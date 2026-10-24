// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Sigill.Sdk.Internal;

namespace Sigill.Sdk;

/// <summary>
/// Checks one artifact's signature over the supplied digests — the v2
/// object-level verdict (spec v2 §7). Only digests are passed; the default
/// implementation is the blind <c>POST /seal/verify-objects</c> endpoint
/// (<see cref="AgentRunVerifier.Remote"/>).
/// </summary>
public delegate Task<BlindObjectsVerdict> BlindObjectsVerifier(
    JsonObject signature, IReadOnlyDictionary<string, string> digests, CancellationToken cancellationToken);

/// <summary>The cryptographic verdict over one multi-object signature.</summary>
public sealed record BlindObjectsVerdict
{
    public required bool SignatureValid { get; init; }
    public required bool Complete { get; init; }

    /// <summary>Per signed URI (including the envelope reference, <c>sigD.pars[0]</c>): did the supplied digest match?</summary>
    public required IReadOnlyList<(string Uri, bool HashMatch)> Objects { get; init; }

    public IReadOnlyList<string> Missing { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Unreferenced { get; init; } = Array.Empty<string>();
    public SignatureTimestampInfo? Timestamp { get; init; }
    public SignerCertificateInfo? Certificate { get; init; }
    public string? Error { get; init; }

    /// <summary>The hybrid (ML-DSA) dimension: absent | verified | failed | not_checked.</summary>
    public string Pqc { get; init; } = "absent";

    /// <summary>Maps the <c>objects</c> member of a <c>/seal/verify-objects</c> response.</summary>
    public static BlindObjectsVerdict FromVerifyObjectsResponse(JsonObject response)
    {
        var r = response["objects"] as JsonObject ?? new JsonObject();
        var underlying = r["underlying"] as JsonObject;
        SignatureTimestampInfo? ts = null;
        if (underlying?["timestamp"] is JsonObject t)
            ts = new SignatureTimestampInfo(
                AgentProfiles.Str(t["genTime"]), AgentProfiles.Str(t["tsaName"]), AgentProfiles.IsTrue(t["signatureValid"]),
                AgentProfiles.Str(t["trust"]));
        SignerCertificateInfo? cert = null;
        if (underlying?["certificate"] is JsonObject c)
            cert = new SignerCertificateInfo(
                AgentProfiles.Str(c["subject"]) ?? "", AgentProfiles.Str(c["issuer"]) ?? "",
                AgentProfiles.Str(c["notAfter"]) ?? "",
                // The signature service's chain verdict (trusted_chain, platform, valid_untrusted_chain, …);
                // older services only report isSelfSigned.
                AgentProfiles.Str(c["trust"]) ?? (AgentProfiles.IsTrue(c["isSelfSigned"]) ? "self_signed" : "issuer_distinct"));
        return new BlindObjectsVerdict
        {
            SignatureValid = AgentProfiles.IsTrue(r["signatureValid"]),
            Complete = AgentProfiles.IsTrue(r["complete"]),
            Objects = (r["objects"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
                .Select(o => (AgentProfiles.Str(o["par"]) ?? "", AgentProfiles.IsTrue(o["hashMatch"]))).ToList(),
            Missing = Strings(r["missing"]),
            Unreferenced = Strings(r["unreferenced"]),
            Timestamp = ts,
            Certificate = cert,
            Error = AgentProfiles.Str(r["error"]),
            Pqc = AgentProfiles.Str(r["pqc"]) ?? "absent",
        };
    }

    private static IReadOnlyList<string> Strings(JsonNode? node) =>
        (node as JsonArray ?? new JsonArray()).Select(AgentProfiles.Str).OfType<string>().ToList();
}

/// <summary>
/// The signature timestamp of one artifact. <c>Trust</c> is the signature service's verdict on the TSA:
/// trusted_chain | qualified (trusted) | untrusted | unknown, or null when the service does not report it.
/// </summary>
public sealed record SignatureTimestampInfo(string? GenTime, string? TsaName, bool SignatureValid, string? Trust = null);

/// <summary>
/// The signer certificate of one artifact. <c>Trust</c> is the signature
/// service's chain verdict: trusted_chain | platform | valid_untrusted_chain | self_signed | …
/// </summary>
public sealed record SignerCertificateInfo(string Subject, string Issuer, string NotAfter, string Trust);

/// <summary>Per-object outcome within one artifact.</summary>
public sealed record AgentObjectVerdict(
    string Uri, string Role, string? ContentType, int? SizeBytes, string HashHex,
    bool Signed, bool Retained, bool HashMatch);

/// <summary>Per-event outcome.</summary>
public sealed record AgentStepVerdict
{
    public required int Seq { get; init; }
    public required string StepType { get; init; }
    public string? EvidenceId { get; init; }
    public string? PrevSignatureSha256 { get; init; }
    public string? SignatureSha256 { get; init; }
    public string? ActorId { get; init; }
    public string? ActorVersion { get; init; }
    public string? EventTime { get; init; }
    public bool Consequential { get; init; }
    public string? TimestampDeclared { get; init; }
    public bool SignatureValid { get; init; }
    public string? Signer { get; init; }
    public bool TimestampRequired { get; init; }
    public bool TimestampPresent { get; init; }
    public bool? TimestampValid { get; init; }
    public string? TimestampGenTime { get; init; }
    public string? TsaName { get; init; }
    public bool ObjectsComplete { get; init; }
    public bool ChainLinkValid { get; init; }
    public string? Error { get; init; }
    public SignerCertificateInfo? Certificate { get; init; }
    public IReadOnlyList<AgentObjectVerdict> Objects { get; init; } = Array.Empty<AgentObjectVerdict>();
}

/// <summary>Timestamp coverage of the run (common rules §4).</summary>
public sealed record AgentRunTimestampSummary(
    int Artifacts, int Required, int Present, int Valid, bool AnchorValid,
    AgentTimestampPolicy? Policy, bool PolicySigned);

/// <summary>Outcome of the Control Artifact check.</summary>
public sealed record AgentControlVerdict
{
    public bool Present { get; init; }
    public string? EvidenceId { get; init; }
    public string? SignatureSha256 { get; init; }
    public bool SignatureValid { get; init; }
    public bool ObjectsComplete { get; init; }
    public bool TimestampValid { get; init; }
    public string? TimestampGenTime { get; init; }
    public string? Signer { get; init; }
    public bool WellFormed { get; init; }

    /// <summary>The first event's <c>binds.controlArtifactSignatureSha256</c> is this artifact's <c>signatureSha256</c>.</summary>
    public bool Bound { get; init; }
    public string? ControlSetId { get; init; }
    public string? ControlSetVersion { get; init; }
    public string? AgentId { get; init; }
    public string? AgentVersion { get; init; }
    public SignerCertificateInfo? Certificate { get; init; }
    public IReadOnlyList<AgentObjectVerdict> Objects { get; init; } = Array.Empty<AgentObjectVerdict>();
}

/// <summary>
/// One Control Evaluation, reported on its own and never merged into the run
/// verdict (common rules §8). <see cref="Overall"/> and <see cref="Controls"/>
/// are the verifier's claims, unchanged: the SDK never evaluates controls.
/// </summary>
public sealed record AgentEvaluationVerdict
{
    public string? EvidenceId { get; init; }
    public string? VerifierId { get; init; }
    public string? VerifierVersion { get; init; }

    /// <summary>Its <c>subject</c> names this run's <c>run_end</c> and Control Artifact.</summary>
    public bool SubjectBound { get; init; }

    /// <summary>Same control set (id, version, URI and digest) as the Control Artifact.</summary>
    public bool ControlSetDigestMatches { get; init; }

    /// <summary>Same baseline (URI and digest) as the Control Artifact; null unless the evaluation carries one.</summary>
    public bool? BaselineDigestMatches { get; init; }

    /// <summary>
    /// The one field to read: a valid, timestamped, well-formed evaluation of this run, every object of it
    /// intact, against the pre-sealed control set (and baseline, when carried). Only then is
    /// <see cref="Overall"/> the named verifier's claim about this run.
    /// </summary>
    public bool Valid { get; init; }

    /// <summary>Valid signature over this very envelope, with an established signer (and an expected one, when given).</summary>
    public bool SignatureValid { get; init; }
    public bool TimestampValid { get; init; }
    public string? TimestampGenTime { get; init; }
    public bool ObjectsComplete { get; init; }
    public bool WellFormed { get; init; }
    public string? Signer { get; init; }
    public SignerCertificateInfo? Certificate { get; init; }
    public string? Overall { get; init; }
    public IReadOnlyList<ControlResult> Controls { get; init; } = Array.Empty<ControlResult>();
    public IReadOnlyList<string> Findings { get; init; } = Array.Empty<string>();

    /// <summary>"1" or "2".</summary>
    public string? SchemaVersion { get; init; }

    /// <summary>v2: state | policy | attested (<c>spec/control-evaluation-v2.md</c>); null for v1.</summary>
    public string? Kind { get; init; }

    /// <summary>policy: approved_before_run | approved_after_start | unapproved, as the evaluator states it.</summary>
    public string? PolicyStatus { get; init; }

    /// <summary>policy: finalized | partial.</summary>
    public string? PolicyState { get; init; }

    /// <summary>policy: the facts rebuilt from this run's signed events equal the sealed facts byte for byte (§4.5); null when not checked.</summary>
    public bool? FactsMatch { get; init; }

    /// <summary>policy: approvalScopeDigest and cedarDigest recompute from the sealed control set; null when not checked.</summary>
    public bool? PolicyDigestsMatch { get; init; }

    /// <summary>
    /// policy: the per-rule results were recomputed with a Cedar engine (§4.6). This SDK has no Cedar engine, so it
    /// is always false: the facts are checked, the results are the evaluator's.
    /// </summary>
    public bool ResultsRecomputed { get; init; }

    /// <summary>
    /// The role in the seal's <c>srAts.claimed</c> "sealed for" attribute (§8), e.g. <c>urn:sigill:role:policy-evaluator</c>.
    /// Meaningful only together with the signer: a shared service certificate's operator emits it for its own statements only.
    /// </summary>
    public string? SealedFor { get; init; }

    /// <summary>policy: the approval requires qualified time across the evidence (§4.7).</summary>
    public bool QualifiedTimestampsRequired { get; init; }

    /// <summary>
    /// policy, when required: every timestamp the run and the approval rest on is qualified, as the evaluator determined
    /// (§4.7); null when not required. The SDK checks the claim's shape and its binding to the approval, not the TSAs.
    /// </summary>
    public bool? QualifiedTimestampsMet { get; init; }

    /// <summary>The evidenceId this evaluation supersedes (§6), when it names one.</summary>
    public string? Supersedes { get; init; }

    /// <summary>No other valid evaluation of the same kind and control set supersedes it (§6).</summary>
    public bool Current { get; init; } = true;
}

/// <summary>The run-level result (common rules §8).</summary>
public sealed record AgentRunVerificationResult
{
    /// <summary>run_finalized | run_open | run_invalid.</summary>
    public required string Verdict { get; init; }

    /// <summary>The nine checks (correlation, sequence, chain, envelope, signatures, timestamps, objects, finalization, control): ok | warn | bad.</summary>
    public required IReadOnlyDictionary<string, string> Checks { get; init; }

    /// <summary>bound | run_only | control_only | unbound.</summary>
    public required string Binding { get; init; }

    public required IReadOnlyList<string> Findings { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }

    /// <summary>
    /// Informational notes — currently the legacy envelope reference diagnostic (AiEvidenceEnvelopeV2 §5.4). Never a
    /// warning: notes do not affect <see cref="Verdict"/>, <see cref="Checks"/> or <see cref="Warnings"/>.
    /// </summary>
    public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();
    public string? Disposition { get; init; }
    public string? AgentId { get; init; }
    public string? AgentVersion { get; init; }
    public string? CorrelationId { get; init; }
    public required IReadOnlyList<int> MissingSeqs { get; init; }
    public required AgentRunTimestampSummary Timestamps { get; init; }
    public required IReadOnlyList<SignerCertificateInfo> Certificates { get; init; }
    public required AgentControlVerdict Control { get; init; }
    public required IReadOnlyList<AgentStepVerdict> Artifacts { get; init; }
    public required IReadOnlyList<AgentEvaluationVerdict> Evaluations { get; init; }

    /// <summary>Deterministic fingerprint of everything the verdict depends on (§8.2); null when the evidence is not valid I-JSON.</summary>
    public required string? Fingerprint { get; init; }

    /// <summary>The run's signer: <c>x5t#S256</c> of its signing certificate (§3).</summary>
    public string? Signer { get; init; }

    /// <summary>Seal time, defence in depth (§8): the Control Artifact's timestamp is not later than run_start's. Null when not comparable.</summary>
    public bool? ControlSealedBeforeRun { get; init; }

    /// <summary>No timestamped event claims an eventTime later than its own seal time (with allowance). Null when nothing is comparable.</summary>
    public bool? EventTimesPlausible { get; init; }

    /// <summary>What a verdict does and does not establish. Show it next to the verdict.</summary>
    public string Scope => AgentRunVerifier.Scope;

    public bool IsFinalized => Verdict == "run_finalized";
}

/// <summary>
/// Verifies an agent run bundle (common rules §8). The envelopes are read
/// locally; each artifact's signature is checked over digests only, by the
/// supplied <see cref="BlindObjectsVerifier"/>.
/// </summary>
public static class AgentRunVerifier
{
    public const string Scope =
        "run_finalized means: the control basis was sealed before the first event, all recorded events are unchanged " +
        "since run_end was timestamped and are in the recorded order, and the run was closed under one signer; a Control " +
        "Evaluation's result is the named verifier's claim against the pre-sealed control set. It does not establish " +
        "that every event was captured, that producer-claimed event times are true, that no other run took place, that " +
        "the verifier measured correctly, or — unless expected signers were given — who produced the run. Events without " +
        "a timestamp could have been rewritten by anyone able to seal with the run's certificate until run_end was " +
        "timestamped.";

    private const int MaxMissingListed = 64;
    private static readonly TimeSpan SealTimeAllowance = TimeSpan.FromSeconds(6); // 5 s skew + up to 1 s TSA accuracy
    private static readonly HashSet<string> TrustedChains = new(StringComparer.Ordinal) { "trusted_chain", "platform" };
    private static readonly HashSet<string> TrustedTsa = new(StringComparer.Ordinal) { "trusted_chain", "qualified" };
    private static readonly HashSet<string> Dispositions = new(StringComparer.Ordinal) { "completed", "failed", "aborted" };

    /// <summary>
    /// The blind <c>POST /seal/verify-objects</c> endpoint as a <see cref="BlindObjectsVerifier"/>. It
    /// verifies each signature against <c>x5c[0]</c> of the protected header that names the signer, which
    /// §3 requires of any verifier plugged in here. Only SHA-256 digests are sent, so a hybrid (ML-DSA)
    /// seal reports <c>pqc: not_checked</c> and fails <c>signatures</c>; the recorder never requests one.
    /// </summary>
    public static BlindObjectsVerifier Remote(ISigillAiEvidenceClient client)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        return async (signature, digests, ct) =>
        {
            var r = await client.VerifyObjectHashesAsync(signature, digests, null, null, ct).ConfigureAwait(false);
            return BlindObjectsVerdict.FromVerifyObjectsResponse(r.Raw);
        };
    }

    // ── Typed signed artifact ────────────────────────────────────────────────

    private sealed record SignedObject(string Uri, string Role, string? ContentType, int? SizeBytes);

    private sealed class Signed
    {
        public JsonObject Env = null!;
        public JsonObject Jws = null!;
        public string? EvidenceId, CorrelationId, ActorId, ActorVersion, DeclaredPrev, Binds, TimestampDeclared;
        public int? Seq;
        public string StepType = "?";
        public DateTimeOffset? EventTime;
        public bool Consequential;
        public List<SignedObject> Objects = new();

        /// <summary>Schema and §1 problems. They fail <c>envelope</c>, never <c>signatures</c>.</summary>
        public List<string> Conformance = new();
    }

    private static (Signed? Sa, string? Error) ParseSigned(JsonObject envelope, JsonObject signature, string schemaName)
    {
        string? S(JsonNode? n) => AgentProfiles.Str(n);
        if (!IsIJson(envelope) || !IsIJson(signature)) return (null, "envelope or signature is not valid I-JSON");
        var sa = new Signed { Env = envelope, Jws = signature, Conformance = EnvelopeSchema.Validate(envelope, schemaName) };
        sa.EvidenceId = S(envelope["evidenceId"]);
        sa.CorrelationId = S((envelope["activity"] as JsonObject)?["correlationId"]);
        var actor = envelope["actor"] as JsonObject;
        sa.ActorId = S(actor?["id"]);
        sa.ActorVersion = S(actor?["version"]);
        if (envelope["chain"] is JsonObject chain)
        {
            if (chain["seq"] is JsonNode raw && !(raw is JsonValue rv && rv.TryGetValue<bool>(out _)) && AgentProfiles.Int(raw) is >= 0 and var seq)
                sa.Seq = seq;
            sa.DeclaredPrev = S(chain["prevSignatureSha256"]);
        }
        if (envelope["step"] is JsonObject step)
        {
            sa.StepType = S(step["type"]) ?? "?";
            if (EnvelopeSchema.TryParseDateTime(S(step["eventTime"]), out var at)) sa.EventTime = at;
            sa.Consequential = AgentProfiles.IsTrue(step["consequential"]);
            sa.TimestampDeclared = S(step["timestamp"]);
        }
        sa.Binds = S((envelope["binds"] as JsonObject)?["controlArtifactSignatureSha256"]);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in (envelope["objects"] as JsonArray ?? new JsonArray()).OfType<JsonObject>())
        {
            if (S(o["uri"]) is not { } uri) continue;
            if (EnvelopeReferences.IsReserved(uri)) { sa.Conformance.Add("objects[] uses the reserved envelope URI"); continue; }
            if (!seen.Add(uri)) { sa.Conformance.Add($"objects[] lists '{uri}' more than once"); continue; }
            sa.Objects.Add(new SignedObject(uri, S(o["role"]) ?? "?", S(o["contentType"]), AgentProfiles.Int(o["sizeBytes"])));
        }
        return (sa, null);
    }

    private static bool IsIJson(JsonNode node)
    {
        if (!AgentProfiles.IsIJson(node)) return false;
        try { EnvelopeHashing.HashHex(AgentProfiles.Canonical(node)); return true; }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    private static string NormalizeId(string id) =>
        (id.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase) ? id.Substring(9) : id).ToLowerInvariant();

    private const string SealedForMediaType = "application/vnd.sigill.sealed-for";

    /// <summary>The "sealed for" role of the classical signature's protected header (CE v2 §8), or null.</summary>
    private static string? SealedForOf(JsonObject jws)
    {
        try { return SealedForCore(jws); }
        catch (Exception ex) when (ex is FormatException or JsonException or ArgumentException or InvalidOperationException) { return null; }
    }

    private static string? SealedForCore(JsonObject jws)
    {
        foreach (var e in (jws["signatures"] as JsonArray ?? new JsonArray { jws }).OfType<JsonObject>())
        {
            if (AgentProfiles.Str(e["protected"]) is not { } p) continue;
            JsonObject? header;
            try { header = JsonNode.Parse(Base64UrlDecode(p)) as JsonObject; }
            catch (Exception ex) when (ex is FormatException or JsonException) { continue; }
            if (AgentProfiles.Str(header?["alg"]) is { } alg && alg.StartsWith("ML-DSA", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var claim in ((header?["srAts"] as JsonObject)?["claimed"] as JsonArray ?? new JsonArray()).OfType<JsonObject>())
                if (AgentProfiles.Str(claim["mediaType"]) == SealedForMediaType && claim["qVals"] is JsonArray q && q.Count == 1)
                    return AgentProfiles.Str(q[0]);
            return null;
        }
        return null;
    }

    private static byte[] Base64UrlDecode(string s)
    {
        var b = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(b.PadRight(b.Length + (4 - b.Length % 4) % 4, '='));
    }

    /// <summary>CE v2 §4.2: a policy evaluation names the Control Artifact, the event at throughSeq and, when finalized, run_end.</summary>
    private static bool PolicySubjectBound(JsonObject env, JsonObject? subject, List<Signed> events, string? ctlSig, string? runEndSig)
    {
        if (ctlSig is null || AgentProfiles.Str(subject?["controlArtifactSignatureSha256"]) != ctlSig) return false;
        var through = AgentProfiles.Int(env["policy"]?["prefix"]?["throughSeq"]);
        var at = events.FirstOrDefault(e => e.Seq is { } s && s == through);
        if (at is null || AgentProfiles.Str(subject?["throughSignatureSha256"]) != AgentProfiles.SignatureSha256(at.Jws)) return false;
        return AgentProfiles.Str(env["policy"]?["state"]) != "finalized"
            || (runEndSig is not null && AgentProfiles.Str(subject?["runEndSignatureSha256"]) == runEndSig);
    }

    /// <summary>Supplied object bytes are untrusted: an I-JSON object, or null (never an exception).</summary>
    private static JsonObject? ParseObject(byte[]? b)
    {
        if (b is null) return null;
        try
        {
            using (var d = JsonDocument.Parse(b))
                if (AgentProfiles.FindDuplicateName(d.RootElement) is not null) return null;
            return JsonNode.Parse(b) is JsonObject o && AgentProfiles.IsIJson(o) ? o : null;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException) { return null; }
    }

    private sealed class EvaluationV2Check
    {
        public List<string> Findings = new();
        public bool? FactsMatch, DigestsMatch, QualifiedMet;
        public bool QualifiedRequired;
        public string? PolicyStatus, State;
    }

    private static readonly Dictionary<string, int> ResultRank = new(StringComparer.Ordinal) { ["PASS"] = 0, ["INDETERMINATE"] = 1, ["FAIL"] = 2 };

    /// <summary>The kind-specific rules of <c>spec/control-evaluation-v2.md</c> §2–§5. Schema conformance is checked elsewhere.</summary>
    private static EvaluationV2Check CheckEvaluationV2(Signed sa, ArtifactCheck c, IReadOnlyDictionary<string, byte[]> payloads,
        Signed? ctl, List<Signed> events, string label)
    {
        var r = new EvaluationV2Check();
        void Bad(string m) => r.Findings.Add($"{label}: {m}.");
        var env = sa.Env;
        var kind = AgentProfiles.Str(env["kind"]);
        var controls = (env["controls"] as JsonArray ?? new JsonArray()).OfType<JsonObject>().ToList();

        // §2: overall follows from the controls.
        var worst = controls.Select(x => AgentProfiles.Str(x["result"]) ?? "").Where(ResultRank.ContainsKey)
            .Aggregate("PASS", (a, b) => ResultRank[b] > ResultRank[a] ? b : a);
        if (AgentProfiles.Str(env["overall"]) != worst) Bad($"overall is {AgentProfiles.Str(env["overall"])}, but its controls give {worst}");
        var ids = controls.Select(x => AgentProfiles.Str(x["id"]) ?? "").ToList();
        foreach (var dup in ids.GroupBy(x => x).Where(g => g.Count() > 1)) Bad($"control '{dup.Key}' is reported more than once");
        foreach (var x in controls)
        {
            var hasWhere = x["where"] is not null;
            var pass = AgentProfiles.Str(x["result"]) == "PASS";
            if (kind != "policy" && hasWhere) Bad($"control '{AgentProfiles.Str(x["id"])}' carries where, which only a policy evaluation may");
            if (kind == "policy" && hasWhere == pass) Bad($"control '{AgentProfiles.Str(x["id"])}': where must be present exactly when the result is not PASS");
        }

        // The bytes of a signed object: only when supplied and equal to what the signature confirmed.
        byte[]? Bytes(string role)
        {
            var o = sa.Objects.FirstOrDefault(x => x.Role == role);
            if (o is null || !payloads.TryGetValue(o.Uri, out var b)) return null;
            if (c.SignedDigest(o.Uri) != EnvelopeHashing.HashHex(b)) { Bad($"the supplied {role} bytes are not the signed ones"); return null; }
            return b;
        }
        JsonObject? Doc(byte[]? b) => ParseObject(b);
        static IEnumerable<string> IdsOf(JsonNode? arr) => (arr as JsonArray ?? new JsonArray())
            .Select(x => x is JsonObject o ? AgentProfiles.Str(o["id"]) : AgentProfiles.Str(x)).OfType<string>();
        void SameIds(IEnumerable<string> expected, string what)
        {
            var want = new HashSet<string>(expected, StringComparer.Ordinal);
            var got = new HashSet<string>(ids, StringComparer.Ordinal);
            foreach (var m in want.Except(got).OrderBy(x => x, StringComparer.Ordinal)) Bad($"{what} '{m}' is not reported");
            foreach (var m in got.Except(want).OrderBy(x => x, StringComparer.Ordinal)) Bad($"control '{m}' is not one of the control set's {what}s");
        }

        var csBytes = Bytes("control-set");
        var cs = Doc(csBytes);
        switch (kind)
        {
            case "state":
                if (cs is not null) SameIds(IdsOf(cs["controls"]), "state control"); // digests-only bundles keep v1 behaviour
                break;
            case "attested":
                if (cs is null) { Bad("the control-set object is not supplied, so it cannot be checked that every private control was reported"); break; }
                SameIds(IdsOf(cs["privateControls"]), "private control");
                break;
            case "policy":
                CheckPolicy(env, csBytes, cs, Bytes("evaluation-facts"), Bytes("policy-approval"), sa, ctl, events, r, Bad, SameIds);
                break;
        }
        return r;
    }

    private static void CheckPolicy(JsonObject env, byte[]? csBytes, JsonObject? cs, byte[]? factsBytes, byte[]? approvalBytes,
        Signed sa, Signed? ctl, List<Signed> events, EvaluationV2Check r, Action<string> bad, Action<IEnumerable<string>, string> sameIds)
    {
        var policy = env["policy"] as JsonObject;
        r.PolicyStatus = AgentProfiles.Str(policy?["policyStatus"]);
        r.State = AgentProfiles.Str(policy?["state"]);
        if (csBytes is null || cs is null) { bad("the control-set object is not supplied, so the evaluation cannot be checked"); return; }
        if (sa.Objects.FirstOrDefault(o => o.Role == "control-set")?.ContentType != AgentPolicy.ControlSetContentType)
            bad("its control set is not a policy control set");
        if (AgentPolicy.Validate(csBytes).Count > 0 || cs["cedar"] is not JsonObject cedar) { bad("its control set is not a valid policy control set with Cedar rules"); return; }

        var digests = AgentPolicy.ComputeDigests(csBytes);
        r.DigestsMatch = digests.ApprovalScopeDigest == AgentProfiles.Str(policy?["approvalScopeDigest"])
            && digests.CedarDigest == AgentProfiles.Str(policy?["cedarDigest"]);
        if (r.DigestsMatch == false) bad("approvalScopeDigest or cedarDigest does not recompute from its control set");
        if (AgentProfiles.Str(policy?["evaluator"]?["schemaSha256"]) != AgentProfiles.Str(cedar["schemaSha256"]))
            bad("evaluator.schemaSha256 is not the control set's cedar.schemaSha256");
        sameIds((cedar["policies"]?["staticPolicies"] as JsonObject ?? new JsonObject()).Select(kv => kv.Key), "rule");
        var declaresPrivate = cs["privateControls"] is JsonArray pcs && pcs.Count > 0;
        if (declaresPrivate != (policy?["privateControlsReported"] is not null))
            bad("privateControlsReported must be present exactly when the control set declares private controls");

        // Prefix (§4.2).
        var prefix = policy?["prefix"] as JsonObject;
        var through = AgentProfiles.Int(prefix?["throughSeq"]) ?? -2;
        var missing = (prefix?["missingSeqs"] as JsonArray ?? new JsonArray()).Select(AgentProfiles.Int).ToList();
        var missingOk = missing.All(m => m is not null) && missing.Zip(missing.Skip(1), (a, b) => a < b).All(x => x)
            && (missing.Count == 0 || missing[0] == through + 1);
        if (!missingOk) bad("prefix.missingSeqs must be ascending, start right after throughSeq and repeat nothing");
        var prefixEvents = events.Where(e => e.Seq is { } s && s <= through).ToList();
        var contiguous = through >= -1 && prefixEvents.Count == through + 1 && prefixEvents.Select(e => e.Seq).Distinct().Count() == through + 1;
        var runEnd = prefixEvents.FirstOrDefault(e => e.StepType == "run_end");
        var finalSeq = prefix?["finalSeq"] is JsonValue fv && fv.GetValueKind() != JsonValueKind.Null ? AgentProfiles.Int(fv) : null;
        if (finalSeq != AgentProfiles.Int((runEnd?.Env["step"] as JsonObject)?["finalSeq"]))
            bad("prefix.finalSeq is not the evaluated run_end's finalSeq");
        var finalized = runEnd is not null && missing.Count == 0;
        if ((r.State == "finalized") != finalized) bad($"state is {r.State}, but the evaluated prefix is {(finalized ? "finalized" : "partial")}");

        // Facts (§4.5): rebuilt from the signed events, byte for byte.
        if (factsBytes is null) bad("the evaluation-facts object is not supplied, so the facts cannot be rebuilt");
        else if (!contiguous) bad($"the bundle lacks events of the evaluated prefix seq 0…{through}");
        else if (AgentProfiles.Str(ctl?.Env["agent"]?["id"]) is not { } agentId || sa.CorrelationId is null) bad("the agent id or correlationId the facts depend on is missing");
        else if (missingOk)
        {
            var rebuilt = AgentPolicy.BuildFacts(agentId, sa.CorrelationId, prefixEvents.Select(e => e.Env), missing.Select(m => m!.Value).ToList());
            r.FactsMatch = rebuilt.Bytes.AsSpan().SequenceEqual(factsBytes);
            if (r.FactsMatch == false) bad("its facts are not the facts of this run's signed events");
            else
            {
                var seqs = new HashSet<string>((JsonNode.Parse(factsBytes)!["requests"] as JsonArray ?? new JsonArray())
                    .Select(q => q?["seq"] is JsonValue v && v.GetValueKind() == JsonValueKind.String ? v.GetValue<string>() : AgentProfiles.Int(q?["seq"])?.ToString(System.Globalization.CultureInfo.InvariantCulture))
                    .OfType<string>(), StringComparer.Ordinal);
                foreach (var w in (env["controls"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
                    .SelectMany(x => (x["where"] as JsonArray ?? new JsonArray()).Select(AgentProfiles.Str)).OfType<string>().Distinct())
                    if (!seqs.Contains(w)) bad($"where names request '{w}', which is not in its facts");
            }
        }

        // Approval (§4.4) and required qualified time (§4.7).
        var timestamps = policy?["timestamps"] as JsonObject;
        if (r.PolicyStatus == "unapproved")
        {
            if (timestamps is not null) bad("timestamps is present, but no approval requires qualified time");
            return;
        }
        var approval = ParseObject(approvalBytes);
        if (approval is null) { bad($"policyStatus is {r.PolicyStatus}, but the approval record is not supplied"); return; }
        var requiresQualified = AgentProfiles.Str(approval["timestamps"]) == "qualified";
        if (requiresQualified != (timestamps is not null))
            bad("timestamps must be present exactly when the approval record requires qualified time");
        if (timestamps is not null)
        {
            r.QualifiedRequired = true;
            var where = (timestamps["where"] as JsonArray ?? new JsonArray()).Select(AgentProfiles.Str).OfType<string>().ToList();
            var met = timestamps["met"] is JsonValue mv && mv.GetValueKind() == JsonValueKind.True;
            if (met != (where.Count == 0)) bad("timestamps.met does not follow from timestamps.where");
            // Order: approval, control, events by seq, run_end — each at most once, events inside the evaluated prefix.
            static int Rank(string w) => w switch { "approval" => -3, "control" => -2, "run_end" => int.MaxValue, _ => int.Parse(w, CultureInfo.InvariantCulture) };
            var ranks = where.Select(Rank).ToList();
            if (ranks.Zip(ranks.Skip(1), (a, b) => a < b).Any(x => !x)) bad("timestamps.where is not in order or repeats an entry");
            if (where.Where(w => w is not ("approval" or "control" or "run_end")).Any(w => int.Parse(w, CultureInfo.InvariantCulture) > through))
                bad("timestamps.where names an event outside the evaluated prefix");
            if (where.Contains("run_end") && r.State != "finalized") bad("timestamps.where names run_end, but the evaluated prefix has none");
            r.QualifiedMet = met && where.Count == 0;
        }
        if (AgentProfiles.Str(approval["schemaName"]) != "AgentPolicyApproval" || AgentProfiles.Str(approval["decision"]) != "approved")
            bad("its policy-approval object is not an approval record");
        if (AgentProfiles.Str(approval["approvalScopeDigest"]) != AgentProfiles.Str(policy?["approvalScopeDigest"]))
            bad("the approval record approves another approval scope");
        if (AgentProfiles.Str(approval["agentId"]) != AgentProfiles.Str(ctl?.Env["agent"]?["id"]))
            bad("the approval record is for another agent");
    }

    /// <summary>§6.4: never seal an envelope the verifier would reject. Throws ArgumentException.</summary>
    internal static void Prevalidate(JsonObject envelope, string schemaName)
    {
        if (!IsIJson(envelope)) throw new ArgumentException("the envelope is not valid I-JSON");
        var errs = EnvelopeSchema.Validate(envelope, schemaName);
        if (errs.Count > 0) throw new ArgumentException("the artifact would not verify: " + string.Join("; ", errs));
    }

    /// <summary>The signed content type (<c>sigD.ctys[0]</c>) differs from the profile's; null when it matches or the header is unreadable.</summary>
    private static string? ContentTypeProblem(JsonObject jws, string expected)
    {
        var classical = AgentProfiles.ClassicalEntries(jws);
        if (classical.Count != 1 || classical[0].Header is not { } header) return null; // the signer check reports it
        var cty = ((header["sigD"] as JsonObject)?["ctys"] as JsonArray)?.FirstOrDefault();
        var actual = AgentProfiles.Str(cty);
        return actual == expected ? null : $"its signed content type (sigD.ctys[0]) is '{actual ?? "absent"}', not '{expected}'";
    }

    /// <summary>
    /// §1 / v2 §5.2: the signed <c>sigD</c> must list the envelope's objects in order — <c>pars[0]</c> the
    /// envelope, <c>pars[i+1]</c> = <c>objects[i].uri</c>, one <c>hashV</c> and one <c>ctys</c> entry each, and
    /// <c>ctys[i+1]</c> = <c>objects[i].contentType</c> ("" when absent). A blind verifier matches digests by URI
    /// and never sees the envelope, so only the profile layer can check this. Null when it holds or the header is
    /// unreadable (the signer check reports that).
    /// </summary>
    private static string? LayoutProblem(JsonObject envelope, JsonObject jws)
    {
        var classical = AgentProfiles.ClassicalEntries(jws);
        if (classical.Count != 1 || classical[0].Header is not { } header) return null;
        if (header["sigD"] is not JsonObject sigD) return "the signature carries no sigD object";
        var objects = (envelope["objects"] as JsonArray ?? new JsonArray()).Select(o => o as JsonObject).ToList();
        var pars = (sigD["pars"] as JsonArray)?.Select(AgentProfiles.Str).ToList();
        // pars[0] is one of the two envelope references, read from this very signature (v2 §5.2 rule 2).
        var expected = new List<string?> { pars?.FirstOrDefault() };
        expected.AddRange(objects.Select(o => AgentProfiles.Str(o?["uri"])));
        if (pars is null || EnvelopeReferences.Classify(pars.FirstOrDefault()) == EnvelopeReferenceForm.Invalid
            || !pars.SequenceEqual(expected))
            return "sigD.pars is not the envelope followed by objects[] in order";
        if (sigD["hashV"] is not JsonArray hashV || hashV.Count != pars.Count)
            return "sigD.hashV does not have one entry per signed object";
        if (sigD["ctys"] is not JsonArray ctys || ctys.Count != pars.Count)
            return "sigD.ctys does not have one entry per signed object";
        if (EnvelopeReferences.PqcParsMismatch(jws))
            return "the ML-DSA signature's sigD.pars differ from the classical signature's";
        for (var i = 0; i < objects.Count; i++)
        {
            var signedType = AgentProfiles.Str(ctys[i + 1]);
            var envelopeType = AgentProfiles.Str(objects[i]?["contentType"]) ?? "";
            if (signedType != envelopeType)
                return $"sigD.ctys[{i + 1}] is '{signedType}', but objects[{i}].contentType is '{envelopeType}'";
        }
        return null;
    }

    // ── One artifact ─────────────────────────────────────────────────────────

    private sealed class ArtifactCheck
    {
        public bool SignatureValid, ObjectsComplete, TimestampPresent, EnvelopeCovered;
        public bool? TimestampValid;
        public string? GenTime, TsaName, TsaTrust, Error;
        public SignerCertificateInfo? Certificate;
        public List<AgentObjectVerdict> Objects = new();
        public List<string> Findings = new();

        /// <summary>URIs whose supplied digest the signature service confirmed against the signed hashV.</summary>
        public HashSet<string> Confirmed = new(StringComparer.Ordinal);

        /// <summary>The digest of a signed object, only when the signature confirmed it.</summary>
        public string? SignedDigest(string uri) =>
            Confirmed.Contains(uri) ? Objects.FirstOrDefault(o => o.Signed && o.Uri == uri)?.HashHex : null;

        public bool AllRetained => Objects.Where(o => o.Signed).All(o => o.Retained);
        public bool TimestampOk => TimestampPresent && TimestampValid == true;
    }

    private static async Task<ArtifactCheck> CheckArtifactAsync(
        Signed sa, AgentRunArtifact art, IReadOnlyDictionary<string, byte[]> payloads,
        BlindObjectsVerifier blind, string label, CancellationToken ct)
    {
        var c = new ArtifactCheck();
        var digests = new Dictionary<string, string>(StringComparer.Ordinal);
        var objOk = true;
        foreach (var so in sa.Objects)
        {
            art.ObjectDigests.TryGetValue(so.Uri, out var supplied);
            if (payloads.TryGetValue(so.Uri, out var payload))
            {
                var hex = EnvelopeHashing.HashHex(payload);
                if (supplied is not null && supplied != hex)
                {
                    c.Findings.Add($"{label}: supplied payload for '{so.Uri}' does not match its supplied digest.");
                    objOk = false;
                }
                digests[so.Uri] = hex;
                c.Objects.Add(new AgentObjectVerdict(so.Uri, so.Role, so.ContentType, so.SizeBytes, hex, true, true, true));
            }
            else if (supplied is not null)
            {
                digests[so.Uri] = supplied;
                c.Objects.Add(new AgentObjectVerdict(so.Uri, so.Role, so.ContentType, so.SizeBytes, supplied, true, false, true));
            }
            else
            {
                c.Objects.Add(new AgentObjectVerdict(so.Uri, so.Role, so.ContentType, so.SizeBytes, "", true, false, false));
                c.Findings.Add($"{label}: signed object '{so.Uri}' ({so.Role}) was not supplied (no digest, no payload).");
                objOk = false;
            }
        }
        foreach (var kv in art.ObjectDigests)
        {
            if (sa.Objects.Any(o => o.Uri == kv.Key)) continue;
            c.Objects.Add(new AgentObjectVerdict(kv.Key, "?", null, null, kv.Value, false, payloads.ContainsKey(kv.Key), false));
            c.Findings.Add($"{label}: supplied object '{kv.Key}' is not covered by the signature (unsigned data in the record).");
            objOk = false;
        }
        try
        {
            var envelopeKey = EnvelopeReferences.DigestKeyFor(sa.Jws, lenient: true);
            digests[envelopeKey] = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(sa.Env));
            var r = await blind(sa.Jws, digests, ct).ConfigureAwait(false)
                ?? throw new SigillException("blind verifier returned no result");
            c.SignatureValid = r.SignatureValid;
            if (r.Pqc is not ("absent" or "verified"))
            {
                c.SignatureValid = false;
                c.Findings.Add($"{label}: the hybrid seal's ML-DSA commitment is '{r.Pqc}'.");
            }
            c.Error = r.Error;
            c.ObjectsComplete = r.Complete && r.Unreferenced.Count == 0 && r.Missing.Count == 0 && objOk;
            foreach (var m in r.Missing) c.Findings.Add($"{label}: the signature covers '{m}' but the envelope does not list it.");
            foreach (var u in r.Unreferenced) c.Findings.Add($"{label}: the envelope lists '{u}' but the signature does not cover it.");
            for (var i = 0; i < c.Objects.Count; i++)
            {
                var o = c.Objects[i];
                if (!o.Signed) continue;
                var hit = r.Objects.Where(x => x.Uri == o.Uri).Select(x => (bool?)x.HashMatch).FirstOrDefault();
                if (hit == true) c.Confirmed.Add(o.Uri);
                if (hit == false)
                {
                    c.Objects[i] = o with { HashMatch = false };
                    c.Findings.Add($"{label}: object '{o.Uri}' ({o.Role}) no longer matches its signed digest.");
                }
            }
            var env = r.Objects.Where(x => x.Uri == envelopeKey).Select(x => (bool?)x.HashMatch).FirstOrDefault();
            c.EnvelopeCovered = env == true;
            if (env != true)
            {
                c.ObjectsComplete = false;
                c.Findings.Add($"{label}: the signature does not cover this envelope.");
            }
            if (LayoutProblem(sa.Env, sa.Jws) is { } layout)
            {
                c.ObjectsComplete = false;
                c.Findings.Add($"{label}: the signature and envelope disagree on the object list: {layout}.");
            }
            if (r.Timestamp is { } ts)
            {
                c.TimestampPresent = true;
                c.TimestampValid = ts.SignatureValid;
                c.GenTime = ts.GenTime;
                c.TsaName = ts.TsaName;
                c.TsaTrust = ts.Trust;
            }
            c.Certificate = r.Certificate;
            if (!c.SignatureValid)
                c.Findings.Add($"{label}: signature invalid{(r.Error is not null ? " — " + r.Error : "")}.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            c.Error = ex.Message;
            c.Findings.Add($"{label}: verification failed — {ex.Message}");
        }
        return c;
    }

    private static DateTimeOffset? Time(string? s) => EnvelopeSchema.TryParseDateTime(s, out var t) ? t : null;

    // ── The run ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Verifies a run bundle (common rules §8). Never throws for malformed evidence: that is an invalid verdict.
    /// <paramref name="expectedSigners"/>: <c>x5t#S256</c> thumbprints of the certificates the producer seals
    /// with (§3); when given, a run signed by anyone else fails. <paramref name="expectedEvaluationSigners"/>
    /// does the same for Control Evaluations.
    /// </summary>
    public static async Task<AgentRunVerificationResult> VerifyAsync(
        AgentRunBundle bundle, BlindObjectsVerifier verifier, IReadOnlyCollection<string>? expectedSigners = null,
        IReadOnlyCollection<string>? expectedEvaluationSigners = null, CancellationToken cancellationToken = default)
    {
        if (bundle is null) throw new ArgumentNullException(nameof(bundle));
        if (verifier is null) throw new ArgumentNullException(nameof(verifier));

        var findings = new List<string>();
        var warnings = new List<string>();
        var checks = new Dictionary<string, string>(StringComparer.Ordinal);

        Signed? ctl = null;
        string? ctlError = null;
        if (bundle.ControlArtifact is { } ca)
            (ctl, ctlError) = ParseSigned(ca.Envelope, ca.Signature, AgentProfiles.ControlArtifactSchema);

        var parsed = bundle.Artifacts.Select((a, i) =>
        {
            var (sa, error) = ParseSigned(a.Envelope, a.Signature, AgentProfiles.ExecutionSchemaFor(a.Envelope));
            return (Art: a, Index: i, Sa: sa, Error: error);
        }).ToList();
        var arts = parsed.OrderBy(p => p.Sa?.Seq ?? int.MaxValue).ThenBy(p => p.Index).ToList();
        var good = arts.Where(p => p.Sa is not null).Select(p => p.Sa!).ToList();
        var starts = good.Where(s => s.StepType == "run_start").ToList();
        // The reference event: run_start, else the first event. Binding, signer and actor are judged against it.
        var reference = starts.Count == 1 ? starts[0] : good.FirstOrDefault();
        string Label(Signed s) => s.Seq is int q ? $"seq {q}" : "an event without seq";
        var referenceLabel = reference is null ? "" : reference.StepType == "run_start" ? "run_start" : Label(reference);

        // ── correlation: the run identifier comes only from the signed envelopes, never from the bundle.
        var correlation = !string.IsNullOrEmpty(reference?.CorrelationId) ? reference!.CorrelationId
            : good.Select(s => s.CorrelationId).FirstOrDefault(c => !string.IsNullOrEmpty(c));
        var corrOk = true;
        foreach (var s in good.Where(s => string.IsNullOrEmpty(s.CorrelationId)))
        {
            corrOk = false;
            findings.Add($"{Label(s)}: no signed correlationId (activity.correlationId).");
        }
        if (good.Any(s => !string.IsNullOrEmpty(s.CorrelationId) && s.CorrelationId != correlation))
        {
            corrOk = false;
            findings.Add("An event's signed correlationId does not belong to this run (cross-run splice).");
        }
        checks["correlation"] = corrOk ? "ok" : "bad";

        // ── sequence
        var missing = new List<int>();
        var seqOk = true;
        var expected = 0;
        foreach (var p in arts)
        {
            if (p.Sa is null) { seqOk = false; continue; }
            if (p.Sa.Seq is not int sq) { seqOk = false; findings.Add($"{p.Sa.StepType}: no valid chain.seq in the signed envelope."); continue; }
            if (sq < expected) { seqOk = false; findings.Add($"Duplicate signed seq {sq}."); continue; }
            while (expected < sq && missing.Count < MaxMissingListed) { missing.Add(expected); expected++; }
            if (expected < sq) { seqOk = false; findings.Add($"Sequence gap too large to list (signed seq jumps to {sq})."); }
            expected = sq + 1;
        }
        if (missing.Count > 0)
        {
            seqOk = false;
            findings.Add($"Sequence gap: no artifact for seq {string.Join(", ", missing)} (deleted or withheld).");
        }
        if (arts.Count > 0)
        {
            if (starts.Count == 0) { seqOk = false; findings.Add("The run has no run_start."); }
            else if (starts.Count > 1) { seqOk = false; findings.Add($"More than one run_start (seq {string.Join(", ", starts.Select(s => s.Seq))})."); }
            else if (starts[0].Seq != 0) { seqOk = false; findings.Add("run_start is not at seq 0."); }
        }
        checks["sequence"] = seqOk ? "ok" : "bad";

        // ── the signed timestamp policy, from the Control Artifact (§4)
        AgentTimestampPolicy? policy = null;
        var policyOk = true;
        var policySigned = false;
        if (ctl is not null)
        {
            if (!ctl.Env.ContainsKey("timestampPolicy"))
            {
                policy = new AgentTimestampPolicy();
                warnings.Add("The Control Artifact signs no timestampPolicy: the run is judged under the default policy.");
            }
            else if (AgentTimestampPolicy.FromJson(ctl.Env["timestampPolicy"]) is { } signed)
            {
                policy = signed;
                policySigned = true;
            }
            else
            {
                policyOk = false;
                policy = new AgentTimestampPolicy();
                findings.Add("control artifact: the signed timestampPolicy is malformed.");
            }
        }

        // ── one signer per run (§3): the reference event's, else the first that has one, else the Control Artifact's
        var runSigner = (reference is not null ? new[] { reference } : Array.Empty<Signed>()).Concat(good)
            .Select(s => AgentProfiles.SignerOf(s.Jws).Thumbprint).FirstOrDefault(t => t is not null)
            ?? (ctl is not null ? AgentProfiles.SignerOf(ctl.Jws).Thumbprint : null);
        bool chainOk = true, envOk = true, sigOk = true, tsOk = true, objOk = true, objWarn = false, laterBindsOk = true;
        if (runSigner is not null && expectedSigners is not null && !expectedSigners.Contains(runSigner))
        {
            sigOk = false;
            findings.Add($"The run's signer (x5t#S256 {runSigner}) is not among the expected signers.");
        }

        int tsRequired = 0, tsPresent = 0, tsValid = 0;
        var anchorValid = false;
        var certificates = new List<SignerCertificateInfo>();
        void AddCertificate(SignerCertificateInfo? cert)
        {
            if (cert is not null && !certificates.Any(x => x.Subject == cert.Subject && x.Issuer == cert.Issuer)) certificates.Add(cert);
        }
        var verdicts = new List<AgentStepVerdict>();
        string? prevSigHash = null;
        var prevSeq = -1;
        var coverage = new AgentProfiles.TimestampCoverage(policy);
        var timeline = new List<(int Seq, DateTimeOffset? EventTime, DateTimeOffset? SealedAt)>();
        var sealedObjects = new List<(string Label, ArtifactCheck Check)>();
        var stamped = new List<(string Label, ArtifactCheck Check)>(); // events, in seq order

        foreach (var p in arts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (p.Sa is not { } sa)
            {
                envOk = false; sigOk = false; objOk = false; chainOk = false;
                findings.Add($"artifacts[{p.Index}]: {p.Error}");
                verdicts.Add(new AgentStepVerdict { Seq = -1, StepType = "?", Error = p.Error });
                prevSigHash = null;
                continue;
            }
            var seq = sa.Seq ?? -1;
            var label = Label(sa);
            if (sa.Conformance.Count > 0)
            {
                envOk = false;
                foreach (var e in sa.Conformance) findings.Add($"{label}: {e}.");
            }
            if (reference is not null && (sa.ActorId != reference.ActorId || sa.ActorVersion != reference.ActorVersion))
            {
                envOk = false;
                findings.Add($"{label}: signed actor/version ({sa.ActorId}, {sa.ActorVersion}) differs from {referenceLabel} ({reference.ActorId}, {reference.ActorVersion}).");
            }
            var (signer, signerProblem) = AgentProfiles.SignerOf(sa.Jws);
            if (signerProblem is not null)
            {
                sigOk = false;
                findings.Add($"{label}: {signerProblem}.");
            }
            else if (signer != runSigner)
            {
                sigOk = false;
                findings.Add($"{label}: signed by a different certificate than the run (x5t#S256 {signer}).");
            }
            if (ContentTypeProblem(sa.Jws, AgentProfiles.ExecutionEvidenceContentType) is { } ctyProblem)
            {
                sigOk = false;
                findings.Add($"{label}: {ctyProblem}.");
            }
            if (!ReferenceEquals(sa, reference) && sa.Binds is not null && sa.Binds != reference?.Binds)
            {
                laterBindsOk = false;
                findings.Add($"{label} binds another control artifact than {referenceLabel}.");
            }

            bool linkOk;
            if (seq == 0)
            {
                linkOk = sa.DeclaredPrev is null;
                if (!linkOk) findings.Add("seq 0 must not carry prevSignatureSha256.");
            }
            else if (seq < 0 || prevSeq != seq - 1 || prevSigHash is null) linkOk = false;
            else
            {
                linkOk = sa.DeclaredPrev == prevSigHash;
                if (!linkOk) findings.Add($"{label}: prevSignatureSha256 does not match the signature of seq {prevSeq}.");
            }
            if (!linkOk) chainOk = false;

            var required = coverage.Next(seq, sa.StepType, sa.Consequential, sa.TimestampDeclared == "required", sa.EventTime);
            if (required) tsRequired++;

            var c = await CheckArtifactAsync(sa, p.Art, bundle.Payloads, verifier, label, cancellationToken).ConfigureAwait(false);
            findings.AddRange(c.Findings);
            if (!c.AllRetained) objWarn = true;
            sealedObjects.Add((label, c));
            stamped.Add((label, c));
            if (!c.SignatureValid) sigOk = false;
            if (!c.ObjectsComplete) objOk = false;
            if (c.TimestampPresent) { tsPresent++; if (c.TimestampValid == true) tsValid++; }
            if (required && !c.TimestampOk)
            {
                tsOk = false;
                findings.Add($"{label} ({sa.StepType}): a timestamp is required here by the signed policy and it is {(c.TimestampPresent ? "invalid" : "missing")}.");
            }
            else if (c.TimestampPresent && c.TimestampValid == false)
            {
                tsOk = false;
                findings.Add($"{label}: timestamp invalid.");
            }
            if (sa.StepType == "run_end" && c.TimestampOk && c.SignatureValid) anchorValid = true;
            timeline.Add((seq, sa.EventTime, c.TimestampOk ? Time(c.GenTime) : null));
            AddCertificate(c.Certificate);

            verdicts.Add(new AgentStepVerdict
            {
                Seq = seq, StepType = sa.StepType, EvidenceId = sa.EvidenceId, PrevSignatureSha256 = sa.DeclaredPrev,
                SignatureSha256 = AgentProfiles.SignatureSha256(sa.Jws), ActorId = sa.ActorId, ActorVersion = sa.ActorVersion,
                EventTime = sa.EventTime is { } et ? AgentProfiles.FormatTime(et) : null,
                Consequential = sa.Consequential, TimestampDeclared = sa.TimestampDeclared,
                SignatureValid = c.SignatureValid, Signer = signer, TimestampRequired = required, TimestampPresent = c.TimestampPresent,
                TimestampValid = c.TimestampValid, TimestampGenTime = c.GenTime, TsaName = c.TsaName,
                ObjectsComplete = c.ObjectsComplete, ChainLinkValid = linkOk, Error = c.Error,
                Certificate = c.Certificate, Objects = c.Objects,
            });
            prevSigHash = AgentProfiles.SignatureSha256(sa.Jws);
            prevSeq = seq;
        }

        // ── delegation §3.1: the execution artifacts of one run are all v1 or all v2, never mixed
        var versions = good.Select(g => AgentProfiles.Str(g.Env["schemaVersion"])).Distinct(StringComparer.Ordinal).ToList();
        if (versions.Count > 1)
        {
            envOk = false;
            findings.Add($"The run's execution artifacts mix schemaVersion {string.Join(" and ", versions.OrderBy(v => v, StringComparer.Ordinal))}; one run uses one version.");
        }

        // ── the Control Artifact
        var controlOk = laterBindsOk;
        string binding;
        AgentControlVerdict control;
        ArtifactCheck? ctlCheck = null;
        var ctlSig = bundle.ControlArtifact is { } cart ? AgentProfiles.SignatureSha256(cart.Signature) : null;
        if (bundle.ControlArtifact is null)
        {
            // run_start must bind a Control Artifact, so a bundle without one is incomplete. Leaving it out must
            // not turn an invalid run into a finalized one (it may hide a stricter policy or a broken basis).
            binding = good.Count > 0 ? "run_only" : "unbound";
            controlOk = false;
            findings.Add(reference?.Binds is { } bound
                ? $"{referenceLabel} binds Control Artifact {bound}, which was not supplied."
                : $"No Control Artifact supplied, and {(reference is null ? "no event" : referenceLabel)} binds none.");
            control = new AgentControlVerdict();
        }
        else if (ctl is null)
        {
            controlOk = false; envOk = false;
            findings.Add($"control artifact: {ctlError}");
            binding = "unbound";
            control = new AgentControlVerdict { Present = true };
        }
        else
        {
            const string label = "control artifact";
            foreach (var e in ctl.Conformance) { envOk = false; findings.Add($"{label}: {e}."); }
            var (signer, signerProblem) = AgentProfiles.SignerOf(ctl.Jws);
            if (signerProblem is not null) { sigOk = false; findings.Add($"{label}: {signerProblem}."); }
            else if (signer != runSigner)
            {
                sigOk = false;
                findings.Add($"{label}: signed by a different certificate than the run (x5t#S256 {signer}).");
            }
            if (ContentTypeProblem(ctl.Jws, AgentProfiles.ControlArtifactContentType) is { } ctyProblem)
            {
                sigOk = false;
                findings.Add($"{label}: {ctyProblem}.");
            }
            ctlCheck = await CheckArtifactAsync(ctl, bundle.ControlArtifact, bundle.Payloads, verifier, label, cancellationToken).ConfigureAwait(false);
            findings.AddRange(ctlCheck.Findings);
            if (!ctlCheck.AllRetained) objWarn = true;
            sealedObjects.Insert(0, (label, ctlCheck));
            if (!ctlCheck.ObjectsComplete) { objOk = false; controlOk = false; }
            if (!ctlCheck.SignatureValid) { sigOk = false; controlOk = false; }
            if (!ctlCheck.TimestampOk)
            {
                controlOk = false;
                findings.Add($"{label}: a timestamp is required and it is {(ctlCheck.TimestampPresent ? "invalid" : "missing")}.");
            }
            AddCertificate(ctlCheck.Certificate);
            if (correlation is not null && ctl.CorrelationId != correlation)
            {
                controlOk = false;
                findings.Add($"{label}: its signed correlationId is not the run's.");
            }
            var agentId = AgentProfiles.Str((ctl.Env["agent"] as JsonObject)?["id"]);
            var agentVersion = AgentProfiles.Str((ctl.Env["agent"] as JsonObject)?["version"]);
            if (reference is not null && (agentId != reference.ActorId || (reference.ActorVersion is not null && agentVersion != reference.ActorVersion)))
            {
                controlOk = false;
                findings.Add($"{label}: its agent ({agentId}, {agentVersion}) is not the run's actor ({reference.ActorId}, {reference.ActorVersion}).");
            }
            var bound = false;
            if (reference is null) binding = "control_only";
            else if (reference.Binds is null || reference.Binds != ctlSig)
            {
                controlOk = false;
                binding = "unbound";
                findings.Add($"{referenceLabel}: binds.controlArtifactSignatureSha256 is not the signatureSha256 of the supplied Control Artifact.");
            }
            else { binding = "bound"; bound = true; }
            control = new AgentControlVerdict
            {
                Present = true, EvidenceId = ctl.EvidenceId, SignatureSha256 = ctlSig, SignatureValid = ctlCheck.SignatureValid,
                ObjectsComplete = ctlCheck.ObjectsComplete, TimestampValid = ctlCheck.TimestampOk, TimestampGenTime = ctlCheck.GenTime,
                Signer = signer, WellFormed = ctl.Conformance.Count == 0, Bound = bound,
                ControlSetId = AgentProfiles.Str((ctl.Env["controlSet"] as JsonObject)?["id"]),
                ControlSetVersion = AgentProfiles.Str((ctl.Env["controlSet"] as JsonObject)?["version"]),
                AgentId = agentId, AgentVersion = agentVersion, Certificate = ctlCheck.Certificate, Objects = ctlCheck.Objects,
            };
        }
        checks["control"] = controlOk ? "ok" : "bad";

        // ── seal time, defence in depth (§8): warnings only
        var ctlAt = ctlCheck is { TimestampOk: true } ? Time(ctlCheck.GenTime) : null;
        bool? sealedBeforeRun = null;
        if (ctlAt is { } controlTime && timeline.FirstOrDefault(t => t.SealedAt is not null) is { SealedAt: { } firstAt } first)
        {
            sealedBeforeRun = controlTime <= firstAt + TimeSpan.FromSeconds(1); // TSAs state up to 1 s accuracy
            if (sealedBeforeRun == false)
                warnings.Add($"The Control Artifact's timestamp is later than the run's first timestamp (seq {first.Seq}): the control basis may not have been sealed before the run.");
        }
        // Every eventTime must lie between the Control Artifact's timestamp and the first timestamp at or after
        // its own seq (its own, or the next one: the chain makes it exist before that), within the allowance.
        bool? plausible = null;
        var early = new List<int>();
        var late = new List<int>();
        for (var i = 0; i < timeline.Count; i++)
        {
            if (timeline[i].EventTime is not { } claimed) continue;
            if (ctlAt is { } lower)
            {
                plausible ??= true;
                if (claimed < lower - SealTimeAllowance) early.Add(timeline[i].Seq);
            }
            if (timeline.Skip(i).Select(t => t.SealedAt).FirstOrDefault(t => t is not null) is { } upper)
            {
                plausible ??= true;
                if (claimed > upper + SealTimeAllowance) late.Add(timeline[i].Seq);
            }
        }
        if (early.Count > 0 || late.Count > 0) plausible = false;
        if (early.Count > 0)
            warnings.Add($"eventTime earlier than the Control Artifact's timestamp {ctlCheck!.GenTime} (seq {string.Join(", ", early)}).");
        if (late.Count > 0)
            warnings.Add($"eventTime later than the timestamp that bounds it (seq {string.Join(", ", late)}).");

        // ── §5: one URI names one content throughout the run (Control Artifact and events)
        var firstSeen = new Dictionary<string, (string Label, string Digest)>(StringComparer.Ordinal);
        foreach (var (label, check) in sealedObjects)
            foreach (var o in check.Objects.Where(o => o.Signed && o.HashHex.Length > 0))
            {
                if (!firstSeen.TryGetValue(o.Uri, out var seen)) { firstSeen[o.Uri] = (label, o.HashHex); continue; }
                if (seen.Digest == o.HashHex) continue;
                objOk = false;
                findings.Add($"Object '{o.Uri}' is signed with different content in {seen.Label} and {label}.");
            }

        // ── every payload must be a signed object of some artifact (§7)
        var evalParsed = bundle.Evaluations.Select(e => ParseSigned(e.Envelope, e.Signature, AgentProfiles.EvaluationSchemaFor(e.Envelope))).ToList();
        var signedUris = new HashSet<string>(
            good.SelectMany(s => s.Objects).Concat(ctl?.Objects ?? new List<SignedObject>())
                .Concat(evalParsed.Where(e => e.Sa is not null).SelectMany(e => e.Sa!.Objects)).Select(o => o.Uri),
            StringComparer.Ordinal);
        foreach (var uri in bundle.Payloads.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            if (signedUris.Contains(uri)) continue;
            objOk = false;
            findings.Add($"Supplied payload '{uri}' is not a signed object of any artifact (unsigned data in the record).");
        }
        checks["chain"] = chainOk ? "ok" : "bad";
        checks["envelope"] = envOk ? "ok" : "bad";
        checks["signatures"] = sigOk ? "ok" : "bad";
        checks["objects"] = !objOk ? "bad" : objWarn ? "warn" : "ok";

        // ── finalization
        var ends = good.Where(s => s.StepType == "run_end").ToList();
        var end = ends.LastOrDefault();
        string? disposition = null;
        if (end is null) checks["finalization"] = "warn";
        else
        {
            var finOk = true;
            if (ends.Count > 1)
            {
                finOk = false;
                findings.Add($"More than one run_end (seq {string.Join(", ", ends.Select(e => e.Seq))}).");
            }
            var endStep = end.Env["step"] as JsonObject;
            disposition = AgentProfiles.Str(endStep?["runDisposition"]);
            if (disposition is null || !Dispositions.Contains(disposition))
            {
                finOk = false;
                findings.Add($"run_end carries no valid runDisposition (got '{disposition ?? "none"}').");
            }
            if (!ReferenceEquals(good.LastOrDefault(), end))
            {
                finOk = false;
                findings.Add("run_end is not the last artifact of the chain.");
            }
            var finalSeq = AgentProfiles.Int(endStep?["finalSeq"]);
            if (finalSeq is null || finalSeq != end.Seq)
            {
                finOk = false;
                findings.Add($"run_end's finalSeq is {finalSeq?.ToString(CultureInfo.InvariantCulture) ?? "absent"}, not its own seq {end.Seq}.");
            }
            var finalPrev = AgentProfiles.Str(endStep?["finalPrevSignatureSha256"]);
            if (finalPrev is null || finalPrev != end.DeclaredPrev)
            {
                finOk = false;
                findings.Add("run_end's finalPrevSignatureSha256 is not its own chain.prevSignatureSha256.");
            }
            if (!anchorValid) finOk = false;
            checks["finalization"] = finOk ? "ok" : "bad";
        }
        checks["timestamps"] = !tsOk || !policyOk ? "bad" : !anchorValid || ctl is null ? "warn" : "ok";

        // ── evaluations: reported on their own, never merged into the run verdict
        var evaluations = new List<AgentEvaluationVerdict>();
        var evaluationChecks = new List<(string Label, ArtifactCheck Check)>();
        var runEndSig = end is not null ? AgentProfiles.SignatureSha256(end.Jws) : null;
        List<SignedObject> WithRole(Signed s, string role) => s.Objects.Where(o => o.Role == role).ToList();
        for (var i = 0; i < bundle.Evaluations.Count; i++)
        {
            var art = bundle.Evaluations[i];
            var (sa, error) = evalParsed[i];
            var label = $"evaluation {i}";
            if (sa is null)
            {
                evaluations.Add(new AgentEvaluationVerdict { Findings = new[] { $"{label}: {error}" } });
                continue;
            }
            var ef = sa.Conformance.Select(e => $"{label}: {e}.").ToList();
            var c = await CheckArtifactAsync(sa, art, bundle.Payloads, verifier, label, cancellationToken).ConfigureAwait(false);
            evaluationChecks.Add((label, c));
            ef.AddRange(c.Findings);
            // An evaluation's claim is its envelope: a valid signature over another envelope is no claim at all.
            var signatureValid = c.SignatureValid && c.EnvelopeCovered;
            var (signer, signerProblem) = AgentProfiles.SignerOf(sa.Jws);
            if (signerProblem is not null) { signatureValid = false; ef.Add($"{label}: {signerProblem}."); }
            else if (expectedEvaluationSigners is not null && !expectedEvaluationSigners.Contains(signer!))
            {
                signatureValid = false;
                ef.Add($"{label}: its signer (x5t#S256 {signer}) is not among the expected evaluation signers.");
            }
            if (ContentTypeProblem(sa.Jws, AgentProfiles.ControlEvaluationContentType) is { } ctyProblem)
            {
                signatureValid = false;
                ef.Add($"{label}: {ctyProblem}.");
            }
            if (signer is not null && signer == runSigner)
                warnings.Add($"{label} is signed by the run's own certificate; an independent verifier should seal with its own.");
            if (expectedEvaluationSigners is null && c.Certificate is { } ec && !TrustedChains.Contains(ec.Trust))
                warnings.Add($"{label}: its signing certificate does not chain to a trusted root (trust: {ec.Trust}) and no expected evaluation signers were given.");
            if (!c.TimestampOk) ef.Add($"{label}: a timestamp is required and it is {(c.TimestampPresent ? "invalid" : "missing")}.");

            var subject = sa.Env["subject"] as JsonObject;
            var isV2 = AgentProfiles.Str(sa.Env["schemaVersion"]) == "2";
            var kind = isV2 ? AgentProfiles.Str(sa.Env["kind"]) : null;
            var subjectBound = kind == "policy"
                ? sa.Conformance.Count == 0 && PolicySubjectBound(sa.Env, subject, good, ctlSig, runEndSig) && (correlation is null || sa.CorrelationId == correlation)
                : runEndSig is not null && ctlSig is not null
                    && AgentProfiles.Str(subject?["runEndSignatureSha256"]) == runEndSig
                    && AgentProfiles.Str(subject?["controlArtifactSignatureSha256"]) == ctlSig
                    && (correlation is null || sa.CorrelationId == correlation);
            if (!subjectBound) ef.Add($"{label}: its subject does not name this run's run_end and Control Artifact.");

            var controlSetMatches = false;
            bool? baselineMatches = null;
            if (ctl is not null && bundle.ControlArtifact is { } ctlArt)
            {
                var eSet = WithRole(sa, "control-set");
                var cSet = WithRole(ctl, "control-set");
                // Only digests both signatures confirmed count: the bundle's objectDigests are unsigned.
                controlSetMatches = eSet.Count == 1 && cSet.Count == 1 && eSet[0].Uri == cSet[0].Uri
                    && c.SignedDigest(eSet[0].Uri) is { } eh && eh == ctlCheck!.SignedDigest(cSet[0].Uri)
                    && JsonNode.DeepEquals(sa.Env["controlSet"], ctl.Env["controlSet"]);
                var eBase = WithRole(sa, "baseline-state");
                var cBase = WithRole(ctl, "baseline-state");
                if (eBase.Count > 0)
                    baselineMatches = eBase.Count == 1 && cBase.Count == 1 && eBase[0].Uri == cBase[0].Uri
                        && c.SignedDigest(eBase[0].Uri) is { } bh && bh == ctlCheck!.SignedDigest(cBase[0].Uri);
            }
            if (!controlSetMatches) ef.Add($"{label}: its control set is not the one sealed in the Control Artifact.");
            var subjectRunEnd = AgentProfiles.Str(subject?["runEndSignatureSha256"]);
            if (ctlSig is not null && AgentProfiles.Str(subject?["controlArtifactSignatureSha256"]) == ctlSig
                && subjectRunEnd is not null && subjectRunEnd != runEndSig)
                warnings.Add($"{label} names run_end {subjectRunEnd} of this control basis, which is not in the bundle: events may have been withheld.");
            if (baselineMatches == false) ef.Add($"{label}: its baseline is not the one sealed in the Control Artifact.");
            // Kind rules read typed fields, so they run on a schema-valid envelope only; a non-conforming one is never valid anyway.
            var v2 = isV2 && sa.Conformance.Count == 0 ? CheckEvaluationV2(sa, c, bundle.Payloads, ctl, good, label) : null;
            if (v2 is not null) ef.AddRange(v2.Findings);

            evaluations.Add(new AgentEvaluationVerdict
            {
                EvidenceId = sa.EvidenceId, VerifierId = sa.ActorId, VerifierVersion = sa.ActorVersion,
                SubjectBound = subjectBound, ControlSetDigestMatches = controlSetMatches, BaselineDigestMatches = baselineMatches,
                SignatureValid = signatureValid, TimestampValid = c.TimestampOk, TimestampGenTime = c.GenTime,
                Valid = signatureValid && c.TimestampOk && c.ObjectsComplete && sa.Conformance.Count == 0
                    && subjectBound && controlSetMatches && baselineMatches != false && (v2 is null || v2.Findings.Count == 0),
                SchemaVersion = AgentProfiles.Str(sa.Env["schemaVersion"]), Kind = kind,
                PolicyStatus = v2?.PolicyStatus, PolicyState = v2?.State, FactsMatch = v2?.FactsMatch,
                PolicyDigestsMatch = v2?.DigestsMatch, SealedFor = SealedForOf(sa.Jws),
                QualifiedTimestampsRequired = v2?.QualifiedRequired ?? false, QualifiedTimestampsMet = v2?.QualifiedMet,
                Supersedes = AgentProfiles.Str((sa.Env["supersedes"] as JsonObject)?["evidenceId"]),
                ObjectsComplete = c.ObjectsComplete, WellFormed = sa.Conformance.Count == 0, Signer = signer,
                Certificate = c.Certificate, Overall = AgentProfiles.Str(sa.Env["overall"]),
                Controls = (sa.Env["controls"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
                    .Select(x => new ControlResult(AgentProfiles.Str(x["id"]) ?? "", AgentProfiles.Str(x["result"]) ?? "",
                        AgentProfiles.Str(x["detail"]))).ToList(),
                Findings = ef,
            });
        }

        // v2 §6: evaluations are append-only; the current one of a kind is the one no valid evaluation supersedes.
        var superseded = new HashSet<string>(evaluations.Where(e => e.Valid && e.Supersedes is not null)
            .Select(e => NormalizeId(e.Supersedes!)), StringComparer.Ordinal);
        for (var i = 0; i < evaluations.Count; i++)
            if (evaluations[i].EvidenceId is { } id && superseded.Contains(NormalizeId(id)))
                evaluations[i] = evaluations[i] with { Current = false };
        foreach (var g in evaluations.Where(e => e.Valid && e.Current && e.Kind is not null).GroupBy(e => e.Kind).Where(g => g.Count() > 1))
            warnings.Add($"{g.Count()} valid {g.Key} evaluations each claim to be current: none supersedes the others.");

        // A timestamp proves time only if its TSA is trusted (§8); the signature service reports that per timestamp.
        var timestamped = (ctlCheck is not null ? new[] { ("control artifact", ctlCheck) } : Array.Empty<(string, ArtifactCheck)>())
            .Concat(stamped).Concat(evaluationChecks)
            .Where(x => x.Item2.TimestampOk && !TrustedTsa.Contains(x.Item2.TsaTrust ?? "")).ToList();
        if (timestamped.Count > 0)
            warnings.Add($"TSA trust not established for the timestamps of: {string.Join(", ", timestamped.Select(x => x.Item1))} " +
                $"(trust: {string.Join(", ", timestamped.Select(x => x.Item2.TsaTrust ?? "not reported").Distinct())}).");

        // §3: consistency is not identity. Without pinned signers, say so unless the chain is trusted.
        if (expectedSigners is null)
            foreach (var trust in certificates.Select(c => c.Trust).Where(t => !TrustedChains.Contains(t)).Distinct())
                warnings.Add($"The signing certificate does not chain to a trusted root (trust: {trust}) and no expected signers were given: the run is consistent, but the verdict does not establish who produced it.");

        var verdict = checks.Values.Contains("bad") ? "run_invalid" : end is not null ? "run_finalized" : "run_open";
        // The reference form is reported, never judged (v2 §5.4): a note, not a warning, and no check state changes.
        var allSignatures = new[] { bundle.ControlArtifact }.Where(a => a is not null).Select(a => a!.Signature)
            .Concat(bundle.Artifacts.Select(a => a.Signature)).Concat(bundle.Evaluations.Select(e => e.Signature)).ToList();
        var legacy = allSignatures.Count(j => EnvelopeReferences.StrictEnvelopeReference(j) == EnvelopeReferences.LegacyReference);
        var notes = legacy > 0
            ? new List<string> { $"{legacy} of {allSignatures.Count} artifact(s): {EnvelopeReferences.LegacyDiagnostic}." }
            : new List<string>();
        return new AgentRunVerificationResult
        {
            Notes = notes,
            Verdict = verdict,
            Checks = checks,
            Binding = binding,
            Findings = findings,
            Warnings = warnings,
            Disposition = disposition,
            AgentId = reference?.ActorId,
            AgentVersion = reference?.ActorVersion,
            CorrelationId = correlation,
            MissingSeqs = missing,
            Timestamps = new AgentRunTimestampSummary(arts.Count, tsRequired, tsPresent, tsValid, anchorValid, policy, policySigned),
            Certificates = certificates,
            Control = control,
            Artifacts = verdicts,
            Evaluations = evaluations,
            Fingerprint = SafeFingerprint(bundle),
            Signer = runSigner,
            ControlSealedBeforeRun = sealedBeforeRun,
            EventTimesPlausible = plausible,
        };
    }

    private static string? SafeFingerprint(AgentRunBundle bundle)
    {
        try { return Fingerprint(bundle); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; } // not valid I-JSON (§8.2)
    }

    /// <summary>The deterministic bundle fingerprint (common rules §8.2).</summary>
    /// <exception cref="ArgumentException">The evidence is not valid I-JSON: the fingerprint is undefined.</exception>
    public static string Fingerprint(AgentRunBundle bundle)
    {
        if (bundle is null) throw new ArgumentNullException(nameof(bundle));
        var every = bundle.Artifacts.Concat(bundle.Evaluations)
            .Concat(bundle.ControlArtifact is { } c ? new[] { c } : Array.Empty<AgentRunArtifact>());
        foreach (var a in every)
            if (!AgentProfiles.IsIJson(a.Envelope) || !AgentProfiles.IsIJson(a.Signature))
                throw new ArgumentException("The fingerprint is undefined for evidence that is not valid I-JSON (§8.2).");
        static JsonObject One(AgentRunArtifact a, int? seq = null)
        {
            var d = new JsonObject();
            foreach (var kv in a.ObjectDigests.OrderBy(k => k.Key, StringComparer.Ordinal)) d[kv.Key] = kv.Value;
            var o = new JsonObject();
            if (seq is int s) o["seq"] = s;
            o["e"] = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(a.Envelope));
            o["s"] = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(a.Signature));
            o["d"] = d;
            return o;
        }
        static string E(JsonObject o) => AgentProfiles.Str(o["e"])!;
        var arts = bundle.Artifacts.Select(a =>
            {
                var raw = (a.Envelope["chain"] as JsonObject)?["seq"];
                var seq = raw is not null && !(raw is JsonValue rv && rv.TryGetValue<bool>(out _)) && AgentProfiles.Int(raw) is >= 0 and var sq ? sq : -1;
                return (Seq: seq, Node: One(a, seq));
            })
            .OrderBy(x => x.Seq).ThenBy(x => E(x.Node), StringComparer.Ordinal)
            .Select(x => (JsonNode)x.Node).ToArray();
        var evals = bundle.Evaluations.Select(e => One(e)).OrderBy(E, StringComparer.Ordinal).Select(x => (JsonNode)x).ToArray();
        var payloads = bundle.Payloads.Keys.OrderBy(k => k, StringComparer.Ordinal)
            .Select(uri => (JsonNode)new JsonObject { ["uri"] = uri, ["sha256"] = EnvelopeHashing.HashHex(bundle.Payloads[uri]) })
            .ToArray();
        var root = new JsonObject
        {
            ["format"] = AgentProfiles.BundleFormat,
            ["artifacts"] = new JsonArray(arts),
            ["control"] = bundle.ControlArtifact is null ? null : One(bundle.ControlArtifact),
            ["evaluations"] = new JsonArray(evals),
            ["payloads"] = new JsonArray(payloads),
        };
        return EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(root));
    }
}
