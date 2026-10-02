// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
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

    /// <summary>Per signed URI (including <c>urn:sigill:envelope</c>): did the supplied digest match?</summary>
    public required IReadOnlyList<(string Uri, bool HashMatch)> Objects { get; init; }

    public IReadOnlyList<string> Missing { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Unreferenced { get; init; } = Array.Empty<string>();
    public SignatureTimestampInfo? Timestamp { get; init; }
    public SignerCertificateInfo? Certificate { get; init; }
    public string? Error { get; init; }

    /// <summary>Maps the <c>objects</c> member of a <c>/seal/verify-objects</c> response.</summary>
    public static BlindObjectsVerdict FromVerifyObjectsResponse(JsonObject response)
    {
        var r = response["objects"] as JsonObject ?? new JsonObject();
        var underlying = r["underlying"] as JsonObject;
        SignatureTimestampInfo? ts = null;
        if (underlying?["timestamp"] is JsonObject t)
            ts = new SignatureTimestampInfo(
                AgentExecutionProfile.Str(t["genTime"]), AgentExecutionProfile.Str(t["tsaName"]),
                AgentExecutionProfile.IsTrue(t["signatureValid"]));
        SignerCertificateInfo? cert = null;
        if (underlying?["certificate"] is JsonObject c)
            cert = new SignerCertificateInfo(
                AgentExecutionProfile.Str(c["subject"]) ?? "", AgentExecutionProfile.Str(c["issuer"]) ?? "",
                AgentExecutionProfile.Str(c["notAfter"]) ?? "",
                AgentExecutionProfile.IsTrue(c["isSelfSigned"]) ? "self_signed" : "issuer_distinct");
        return new BlindObjectsVerdict
        {
            SignatureValid = AgentExecutionProfile.IsTrue(r["signatureValid"]),
            Complete = AgentExecutionProfile.IsTrue(r["complete"]),
            Objects = (r["objects"] as JsonArray ?? new JsonArray()).OfType<JsonObject>()
                .Select(o => (AgentExecutionProfile.Str(o["par"]) ?? "", AgentExecutionProfile.IsTrue(o["hashMatch"]))).ToList(),
            Missing = Strings(r["missing"]),
            Unreferenced = Strings(r["unreferenced"]),
            Timestamp = ts,
            Certificate = cert,
            Error = AgentExecutionProfile.Str(r["error"]),
        };
    }

    private static IReadOnlyList<string> Strings(JsonNode? node) =>
        (node as JsonArray ?? new JsonArray()).Select(AgentExecutionProfile.Str).OfType<string>().ToList();
}

/// <summary>The signature timestamp of one artifact.</summary>
public sealed record SignatureTimestampInfo(string? GenTime, string? TsaName, bool SignatureValid);

/// <summary>The signer certificate of one artifact. <c>Trust</c>: self_signed | issuer_distinct.</summary>
public sealed record SignerCertificateInfo(string Subject, string Issuer, string NotAfter, string Trust);

/// <summary>Per-object outcome within one artifact.</summary>
public sealed record AgentObjectVerdict(
    string Uri, string Kind, string Role, string? ContentType, int? SizeBytes, string HashHex,
    bool Signed, bool Retained, bool HashMatch);

/// <summary>Per-step outcome.</summary>
public sealed record AgentStepVerdict
{
    public required int Seq { get; init; }
    public required string StepType { get; init; }
    public required string EvidenceId { get; init; }
    public string? ParentEvidenceId { get; init; }
    public string? PrevSignatureSha256 { get; init; }
    public required string ActorId { get; init; }
    public string? AgentVersion { get; init; }
    public string? EventTime { get; init; }
    public bool Consequential { get; init; }
    public string TimestampDeclared { get; init; } = "unspecified";
    public bool SignatureValid { get; init; }
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

/// <summary>Timestamp coverage of the run (spec §5).</summary>
public sealed record AgentRunTimestampSummary(
    int Artifacts, int Required, int Present, int Valid, bool AnchorValid,
    string Profile, int EveryEvents, int EverySeconds, bool PolicySigned);

/// <summary>Outcome of the identity record check.</summary>
public sealed record AgentIdentityVerdict
{
    public bool Declared { get; init; }
    public bool Present { get; init; }
    public bool SignatureValid { get; init; }
    public bool ObjectsComplete { get; init; }
    public bool TimestampValid { get; init; }
    public bool WellFormed { get; init; }
    public bool Linked { get; init; }
    public bool KindsComplete { get; init; }
    public bool ConfigMatches { get; init; }
    public bool ConfigDigestValid { get; init; }
    public bool ActorMatches { get; init; }
    public string? EvidenceId { get; init; }
    public string? ActorId { get; init; }
    public string? AgentVersion { get; init; }
    public string? ConfigSha256 { get; init; }
    public SignerCertificateInfo? Certificate { get; init; }
    public IReadOnlyList<AgentObjectVerdict> Objects { get; init; } = Array.Empty<AgentObjectVerdict>();
}

/// <summary>The run-level result (spec §8).</summary>
public sealed record AgentRunVerificationResult
{
    /// <summary>run_finalized | run_open | run_invalid.</summary>
    public required string Verdict { get; init; }

    /// <summary>The nine checks (correlation, sequence, chain, envelope, signatures, timestamps, objects, finalization, identity): ok | warn | bad.</summary>
    public required IReadOnlyDictionary<string, string> Checks { get; init; }

    public required IReadOnlyList<string> Findings { get; init; }
    public required IReadOnlyList<string> Warnings { get; init; }
    public string? Disposition { get; init; }
    public string? AgentId { get; init; }
    public string? AgentVersion { get; init; }
    public string? CorrelationId { get; init; }
    public required IReadOnlyList<int> MissingSeqs { get; init; }
    public required AgentRunTimestampSummary Timestamps { get; init; }
    public required IReadOnlyList<SignerCertificateInfo> Certificates { get; init; }
    public required AgentIdentityVerdict Identity { get; init; }
    public required IReadOnlyList<AgentStepVerdict> Artifacts { get; init; }

    /// <summary>Deterministic fingerprint of everything the verdict depends on (spec §8.1); null when the evidence is not valid I-JSON.</summary>
    public required string? Fingerprint { get; init; }

    /// <summary>What a verdict does and does not establish. Show it next to the verdict.</summary>
    public string Scope => AgentRunVerifier.Scope;

    public bool IsFinalized => Verdict == "run_finalized";
}

/// <summary>
/// Verifies an AgentExecutionProfileV1 run bundle (spec §8). The envelopes are
/// read locally; each artifact's signature is checked over digests only, by
/// the supplied <see cref="BlindObjectsVerifier"/>.
/// </summary>
public static class AgentRunVerifier
{
    public const string Scope =
        "Verifies the supplied record: integrity and capture order of what was sealed, under the signatures and " +
        "timestamps shown. Does not establish that every event was captured, that producer-claimed event times " +
        "are true, or that no other run took place.";

    private const int MaxMissingListed = 64;
    private static readonly HashSet<string> Dispositions = new(StringComparer.Ordinal) { "completed", "failed", "aborted" };

    /// <summary>The blind <c>POST /seal/verify-objects</c> endpoint as a <see cref="BlindObjectsVerifier"/>.</summary>
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

    private sealed record SignedObject(string Uri, string Role, string? ContentType, int? SizeBytes, string Kind);

    private sealed class Signed
    {
        public JsonObject Env = null!;
        public JsonObject Jws = null!;
        public JsonObject Ext = null!;
        public string EvidenceId = "";
        public string? CorrelationId;
        public string? Parent;
        public int? Seq;
        public string? DeclaredPrev;
        public string StepType = "";
        public string ActorId = "";
        public string? AgentVersion;
        public DateTimeOffset? EventTime;
        public bool Consequential;
        public string TimestampDeclared = "unspecified";
        public List<SignedObject> Objects = new();
        public JsonObject? TimestampPolicy;
        public string? AgentIdentityEvidenceId;
        public string? ConfigSha256;
        public bool IsIdentity;
        /// <summary>§2 / v2-schema problems. They fail <c>envelope</c> (or <c>identity</c>), never <c>signatures</c>.</summary>
        public List<string> Conformance = new();
    }

    /// <summary>The complete v2 schema (optional sections included when present) plus the §2 profile conventions.</summary>
    private static List<string> CheckConformance(JsonObject env, JsonObject ext, string stepType, bool isIdentity)
    {
        string? S(JsonNode? n) => AgentExecutionProfile.Str(n);
        var errs = EnvelopeSchema.ValidateEnvelopeV2(env);
        var expectedCategory = isIdentity ? "agent-identity" : "agent-execution";
        if (S(env["purpose"]?["category"]) is { } category && category != expectedCategory)
            errs.Add($"purpose.category must be '{expectedCategory}'");
        var actor = env["actor"] as JsonObject;
        if (S(actor?["type"]) is { } actorType && actorType != "agent") errs.Add("actor.type must be 'agent'");
        if (S((env["activity"] as JsonObject)?["name"]) is { } name && name != (isIdentity ? "agent_identity" : stepType))
            errs.Add(isIdentity ? "activity.name must be 'agent_identity'" : "activity.name must equal the step type");

        if (ext.ContainsKey("consequential") && !(ext["consequential"] is JsonValue cv && cv.TryGetValue<bool>(out _)))
            errs.Add("consequential is not a boolean");
        if (ext.ContainsKey("timestamp") && S(ext["timestamp"]) is not ("required" or "none"))
            errs.Add("timestamp must be 'required' or 'none'");
        if (ext.ContainsKey("agentVersion") && S(ext["agentVersion"]) is null) errs.Add("agentVersion is not a string");
        if (ext.ContainsKey("objectKinds") && !(ext["objectKinds"] is JsonObject ok && ok.All(kv => S(kv.Value) is not null)))
            errs.Add("objectKinds is not an object of strings");

        if (isIdentity)
        {
            if (env.ContainsKey("chain")) errs.Add("the identity record must not carry chain");
            if (S(ext["agentId"]) is not { } agentId || agentId != S(actor?["id"])) errs.Add("agentId must equal actor.id");
        }
        return errs;
    }

    private static (Signed? Sa, string? Error) ParseSigned(JsonObject envelope, JsonObject signature)
    {
        string? S(JsonNode? n) => AgentExecutionProfile.Str(n);
        if (!IsIJson(envelope) || !IsIJson(signature)) return (null, "envelope or signature is not valid I-JSON");
        if (S(envelope["schemaName"]) != "AiEvidenceEnvelope" || S(envelope["schemaVersion"]) != "2")
            return (null, "envelope is not an AiEvidenceEnvelope v2");
        var evidenceId = S(envelope["evidenceId"]);
        var actorId = S(envelope["actor"] is JsonObject actor ? actor["id"] : null);
        if (string.IsNullOrEmpty(evidenceId) || string.IsNullOrEmpty(actorId))
            return (null, "envelope lacks evidenceId or actor.id");
        if (envelope["extensions"] is not JsonObject extensions) return (null, "extensions is not an object");
        if (extensions[AgentExecutionProfile.ExtensionKey] is not JsonObject ext)
            return (null, $"envelope carries no {AgentExecutionProfile.ExtensionKey} extension");
        var stepType = S(ext["stepType"]) ?? (S(ext["recordType"]) is { } rt ? "record:" + rt : null);
        if (string.IsNullOrEmpty(stepType)) return (null, "extension.stepType / recordType missing or not a string");
        var isIdentity = S(ext["recordType"]) == "agent-identity";

        int? seq = null;
        string? declaredPrev = null;
        if (envelope.ContainsKey("chain"))
        {
            if (envelope["chain"] is not JsonObject chain) return (null, "chain is not an object");
            seq = AgentExecutionProfile.Int(chain["seq"]);
            if (seq is null or < 0) return (null, "chain.seq missing, negative or not an integer");
            if (chain.ContainsKey("prevSignatureSha256"))
            {
                declaredPrev = S(chain["prevSignatureSha256"]);
                if (declaredPrev is null) return (null, "chain.prevSignatureSha256 is not a string");
            }
        }

        if (envelope["objects"] is not JsonArray objs) return (null, "objects is not an array");
        var kinds = ext["objectKinds"] as JsonObject;
        var objects = new List<SignedObject>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in objs)
        {
            var o = node as JsonObject;
            var uri = S(o?["uri"]);
            var role = S(o?["role"]);
            if (string.IsNullOrEmpty(uri) || string.IsNullOrEmpty(role)) return (null, "an object lacks uri or role");
            if (uri == AgentExecutionProfile.EnvelopeUri) return (null, "objects[] uses the reserved envelope URI");
            if (!seen.Add(uri!)) return (null, $"duplicate object URI '{uri}' in the signed envelope");
            objects.Add(new SignedObject(uri!, role!, S(o!["contentType"]), AgentExecutionProfile.Int(o["sizeBytes"]),
                S(kinds?[uri!]) ?? "?"));
        }

        DateTimeOffset? eventTime = null;
        if (ext.ContainsKey("eventTime"))
        {
            if (!EnvelopeSchema.TryParseDateTime(S(ext["eventTime"]), out var parsed))
                return (null, "extension.eventTime is not a date-time");
            eventTime = parsed;
        }

        var activity = envelope["activity"] as JsonObject;
        return (new Signed
        {
            Env = envelope, Jws = signature, Ext = ext, EvidenceId = evidenceId!, ActorId = actorId!,
            CorrelationId = S(activity?["correlationId"]), Parent = S(activity?["parentEvidenceId"]),
            Seq = seq, DeclaredPrev = declaredPrev, StepType = stepType!, AgentVersion = S(ext["agentVersion"]),
            EventTime = eventTime, Consequential = AgentExecutionProfile.IsTrue(ext["consequential"]),
            TimestampDeclared = S(ext["timestamp"]) ?? "unspecified", Objects = objects,
            TimestampPolicy = ext["timestampPolicy"] as JsonObject,
            AgentIdentityEvidenceId = S(ext["agentIdentityEvidenceId"]), ConfigSha256 = S(ext["configSha256"]),
            IsIdentity = isIdentity, Conformance = CheckConformance(envelope, ext, stepType!, isIdentity),
        }, null);
    }

    private static bool IsIJson(JsonNode node)
    {
        try { EnvelopeHashing.HashHex(AgentExecutionProfile.Canonical(node)); return true; }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    // ── One artifact ─────────────────────────────────────────────────────────

    private sealed class ArtifactCheck
    {
        public bool SignatureValid, ObjectsComplete, TimestampPresent;
        public bool? TimestampValid;
        public string? GenTime, TsaName, Error;
        public SignerCertificateInfo? Certificate;
        public List<AgentObjectVerdict> Objects = new();
        public List<string> Findings = new();
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
                    c.Findings.Add($"{label}: supplied payload for '{so.Kind}' does not match its supplied digest.");
                digests[so.Uri] = hex;
                c.Objects.Add(new AgentObjectVerdict(so.Uri, so.Kind, so.Role, so.ContentType, so.SizeBytes, hex, true, true, true));
            }
            else if (supplied is not null)
            {
                digests[so.Uri] = supplied;
                c.Objects.Add(new AgentObjectVerdict(so.Uri, so.Kind, so.Role, so.ContentType, so.SizeBytes, supplied, true, false, true));
            }
            else
            {
                c.Objects.Add(new AgentObjectVerdict(so.Uri, so.Kind, so.Role, so.ContentType, so.SizeBytes, "", true, false, false));
                c.Findings.Add($"{label}: signed object '{so.Kind}' was not supplied (no digest, no payload).");
                objOk = false;
            }
        }
        foreach (var kv in art.ObjectDigests)
        {
            if (sa.Objects.Any(o => o.Uri == kv.Key)) continue;
            c.Objects.Add(new AgentObjectVerdict(kv.Key, "?", "?", null, null, kv.Value, false, payloads.ContainsKey(kv.Key), false));
            c.Findings.Add($"{label}: supplied object '{kv.Key}' is not covered by the signature (unsigned data in the record).");
            objOk = false;
        }
        try
        {
            digests[AgentExecutionProfile.EnvelopeUri] = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(sa.Env));
            var r = await blind(sa.Jws, digests, ct).ConfigureAwait(false)
                ?? throw new SigillException("blind verifier returned no result");
            c.SignatureValid = r.SignatureValid;
            c.Error = r.Error;
            c.ObjectsComplete = r.Complete && r.Unreferenced.Count == 0 && r.Missing.Count == 0 && objOk;
            foreach (var m in r.Missing) c.Findings.Add($"{label}: the signature covers '{m}' but the envelope does not list it.");
            foreach (var u in r.Unreferenced) c.Findings.Add($"{label}: the envelope lists '{u}' but the signature does not cover it.");
            for (var i = 0; i < c.Objects.Count; i++)
            {
                var o = c.Objects[i];
                if (!o.Signed) continue;
                var hit = r.Objects.Where(x => x.Uri == o.Uri).Select(x => (bool?)x.HashMatch).FirstOrDefault();
                if (hit == false)
                {
                    c.Objects[i] = o with { HashMatch = false };
                    c.Findings.Add($"{label}: object '{o.Kind}' no longer matches its signed digest.");
                }
            }
            var env = r.Objects.Where(x => x.Uri == AgentExecutionProfile.EnvelopeUri).Select(x => (bool?)x.HashMatch).FirstOrDefault();
            if (env != true)
            {
                c.ObjectsComplete = false;
                c.Findings.Add($"{label}: the signature does not cover this envelope.");
            }
            if (r.Timestamp is { } ts)
            {
                c.TimestampPresent = true;
                c.TimestampValid = ts.SignatureValid;
                c.GenTime = ts.GenTime;
                c.TsaName = ts.TsaName;
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

    // ── The run ──────────────────────────────────────────────────────────────

    /// <summary>Verifies a run bundle (spec §8). Never throws for malformed evidence: that is an invalid verdict.</summary>
    public static async Task<AgentRunVerificationResult> VerifyAsync(
        AgentRunBundle bundle, BlindObjectsVerifier verifier, CancellationToken cancellationToken = default)
    {
        if (bundle is null) throw new ArgumentNullException(nameof(bundle));
        if (verifier is null) throw new ArgumentNullException(nameof(verifier));

        var findings = new List<string>();
        var warnings = new List<string>();
        var checks = new Dictionary<string, string>(StringComparer.Ordinal);

        var parsed = bundle.Artifacts.Select((a, i) =>
        {
            var (sa, error) = ParseSigned(a.Envelope, a.Signature);
            return (Art: a, Index: i, Sa: sa, Error: error);
        }).ToList();
        var arts = parsed.OrderBy(p => p.Sa?.Seq ?? p.Index).ThenBy(p => p.Index).ToList();
        // The run identifier comes only from the signed envelopes, never from the bundle.
        var correlation = arts.Select(p => p.Sa?.CorrelationId).FirstOrDefault(c => !string.IsNullOrEmpty(c));
        var corrOk = true;
        foreach (var p in arts.Where(p => p.Sa is not null && string.IsNullOrEmpty(p.Sa.CorrelationId)))
        {
            corrOk = false;
            findings.Add($"seq {p.Sa!.Seq ?? p.Index}: no signed correlationId (activity.correlationId).");
        }
        if (arts.Any(p => !string.IsNullOrEmpty(p.Sa?.CorrelationId) && p.Sa!.CorrelationId != correlation))
        {
            corrOk = false;
            findings.Add("An artifact's signed correlationId does not belong to this run (cross-run splice).");
        }
        checks["correlation"] = corrOk ? "ok" : "bad";

        var missing = new List<int>();
        var seqOk = true;
        var expected = 0;
        foreach (var p in arts)
        {
            if (p.Sa is null) { seqOk = false; continue; }
            if (p.Sa.Seq is not int sq) { seqOk = false; findings.Add($"{p.Sa.StepType}: no chain.seq in the signed envelope."); continue; }
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
        var starts = arts.Select(p => p.Sa).Where(s => s?.StepType == "run_start").ToList();
        if (starts.Count == 0) { seqOk = false; findings.Add("The run has no run_start."); }
        else if (starts.Count > 1) { seqOk = false; findings.Add($"More than one run_start (seq {string.Join(", ", starts.Select(s => s!.Seq))})."); }
        else if (starts[0]!.Seq != 0) { seqOk = false; findings.Add("run_start is not at seq 0."); }
        checks["sequence"] = seqOk ? "ok" : "bad";

        var start = starts.FirstOrDefault();
        JsonObject? policy = null;
        var policyOk = true;
        if (start is not null)
        {
            var raw = start.Ext["timestampPolicy"];
            string? problem = null;
            if (!start.Ext.ContainsKey("timestampPolicy")) problem = "run_start carries no signed timestamp policy.";
            else if (raw is not JsonObject rp) problem = "run_start: the signed timestamp policy is malformed (not an object).";
            else if (AgentExecutionProfile.Str(rp["profile"]) is not ("throughput" or "per-event"))
                problem = $"run_start: the signed timestamp policy is malformed (unknown profile '{AgentExecutionProfile.Str(rp["profile"]) ?? rp["profile"]?.ToJsonString() ?? "None"}').";
            else if (AgentExecutionProfile.Int(rp["everyEvents"]) is not >= 0 || AgentExecutionProfile.Int(rp["everySeconds"]) is not >= 0)
                problem = "run_start: the signed timestamp policy is malformed (everyEvents/everySeconds must be non-negative integers).";
            else if (!(rp["runStart"] is JsonValue rs && rs.TryGetValue<bool>(out _)))
                problem = "run_start: the signed timestamp policy is malformed (runStart must be a boolean).";
            else if (!AgentExecutionProfile.IsTrue(rp["runEnd"]) || !AgentExecutionProfile.IsTrue(rp["consequential"]))
                problem = "run_start: the signed timestamp policy is malformed (runEnd and consequential must be true).";
            else if (start.Ext.ContainsKey("assuranceProfile") && AgentExecutionProfile.Str(start.Ext["assuranceProfile"]) != AgentExecutionProfile.Str(rp["profile"]))
                problem = "run_start: assuranceProfile differs from the signed timestamp policy's profile.";
            if (problem is null) policy = (JsonObject)raw!;
            else { policyOk = false; findings.Add(problem); }
        }
        var profile = policy is not null ? AgentExecutionProfile.Str(policy["profile"])! : "unknown";
        var everyEvents = policy is not null ? AgentExecutionProfile.Int(policy["everyEvents"])!.Value : 0;
        var everySeconds = policy is not null ? AgentExecutionProfile.Int(policy["everySeconds"])!.Value : 0;
        var stampRunStart = policy is not null && AgentExecutionProfile.IsTrue(policy["runStart"]);

        bool chainOk = true, envOk = true, sigOk = true, tsOk = true, objOk = true, objWarn = false, actorOk = true;
        int tsRequired = 0, tsPresent = 0, tsValid = 0;
        var anchorValid = false;
        var certificates = new List<SignerCertificateInfo>();
        var verdicts = new List<AgentStepVerdict>();
        string? prevSigHash = null, prevEvidenceId = null;
        var prevSeq = -1;
        var coverage = new AgentExecutionProfile.TimestampCoverage(profile, everyEvents, everySeconds, stampRunStart);
        var actorId = start?.ActorId ?? arts.Select(p => p.Sa?.ActorId).FirstOrDefault(a => a is not null);
        var agentVersion = start?.AgentVersion;

        foreach (var p in arts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (p.Sa is not { } sa)
            {
                envOk = false; sigOk = false; objOk = false;
                findings.Add($"artifacts[{p.Index}]: {p.Error}");
                verdicts.Add(new AgentStepVerdict { Seq = p.Index, StepType = "?", EvidenceId = "?", ActorId = "?", Error = p.Error });
                prevSigHash = null; prevEvidenceId = null;
                continue;
            }
            var seq = sa.Seq ?? p.Index;
            if (sa.Conformance.Count > 0)
            {
                envOk = false;
                foreach (var e in sa.Conformance) findings.Add($"seq {seq}: {e}.");
            }
            if (sa.ActorId != actorId || (agentVersion is not null && sa.AgentVersion != agentVersion))
            {
                actorOk = false;
                findings.Add($"seq {seq}: signed actor/version ({sa.ActorId}, {sa.AgentVersion}) differs from run_start ({actorId}, {agentVersion}).");
            }
            bool linkOk;
            if (seq == 0)
            {
                linkOk = sa.DeclaredPrev is null;
                if (!linkOk) findings.Add("seq 0 must not carry prevSignatureSha256.");
            }
            else if (prevSeq != seq - 1 || prevSigHash is null) linkOk = false;
            else
            {
                linkOk = sa.DeclaredPrev == prevSigHash;
                if (!linkOk) findings.Add($"seq {seq}: prevSignatureSha256 does not match the signature of seq {prevSeq}.");
            }
            if (!linkOk) chainOk = false;
            if (seq > 0 && prevEvidenceId is not null && sa.Parent != prevEvidenceId)
                warnings.Add($"seq {seq}: parentEvidenceId is not the previous artifact (semantic link only; not an integrity failure).");

            var required = coverage.Next(seq, sa.StepType, sa.Consequential, sa.TimestampDeclared == "required", sa.EventTime);
            if (required) tsRequired++;

            var c = await CheckArtifactAsync(sa, p.Art, bundle.Payloads, verifier, $"seq {seq}", cancellationToken).ConfigureAwait(false);
            findings.AddRange(c.Findings);
            if (c.Objects.Any(o => o.Signed && !o.Retained)) objWarn = true;
            if (!c.SignatureValid) sigOk = false;
            if (!c.ObjectsComplete) objOk = false;
            if (c.TimestampPresent) { tsPresent++; if (c.TimestampValid == true) tsValid++; }
            if (required && c.TimestampValid != true)
            {
                tsOk = false;
                findings.Add($"seq {seq} ({sa.StepType}): a timestamp is required here by the signed policy and it is {(c.TimestampPresent ? "invalid" : "missing")}.");
            }
            else if (c.TimestampPresent && c.TimestampValid == false)
            {
                tsOk = false;
                findings.Add($"seq {seq}: timestamp invalid.");
            }
            if (sa.StepType == "run_end" && c.TimestampValid == true && c.SignatureValid) anchorValid = true;
            if (c.Certificate is { } cert && !certificates.Any(x => x.Subject == cert.Subject && x.Issuer == cert.Issuer))
                certificates.Add(cert);

            verdicts.Add(new AgentStepVerdict
            {
                Seq = seq, StepType = sa.StepType, EvidenceId = sa.EvidenceId, ParentEvidenceId = sa.Parent,
                PrevSignatureSha256 = sa.DeclaredPrev, ActorId = sa.ActorId, AgentVersion = sa.AgentVersion,
                EventTime = sa.EventTime is { } et ? AgentExecutionProfile.FormatTime(et) : null,
                Consequential = sa.Consequential, TimestampDeclared = sa.TimestampDeclared,
                SignatureValid = c.SignatureValid, TimestampRequired = required, TimestampPresent = c.TimestampPresent,
                TimestampValid = c.TimestampValid, TimestampGenTime = c.GenTime, TsaName = c.TsaName,
                ObjectsComplete = c.ObjectsComplete, ChainLinkValid = linkOk, Error = c.Error,
                Certificate = c.Certificate, Objects = c.Objects,
            });
            prevSigHash = AgentExecutionProfile.ChainDigest(sa.Jws);
            prevSeq = seq;
            prevEvidenceId = sa.EvidenceId;
        }
        if (!actorOk) envOk = false;

        var idSa = bundle.AgentIdentity is { } ida ? ParseSigned(ida.Envelope, ida.Signature).Sa : null;
        var signedUris = new HashSet<string>(
            arts.Where(p => p.Sa is not null).SelectMany(p => p.Sa!.Objects).Concat(idSa?.Objects ?? new List<SignedObject>())
                .Select(o => o.Uri), StringComparer.Ordinal);
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

        var ends = arts.Select(p => p.Sa).Where(s => s?.StepType == "run_end").ToList();
        var end = ends.LastOrDefault();
        string? disposition = null;
        if (end is null) checks["finalization"] = "warn";
        else
        {
            var finOk = true;
            if (ends.Count > 1)
            {
                finOk = false;
                findings.Add($"More than one run_end (seq {string.Join(", ", ends.Select(e => e!.Seq))}).");
            }
            disposition = AgentExecutionProfile.Str(end.Ext["runDisposition"]);
            if (disposition is null || !Dispositions.Contains(disposition))
            {
                finOk = false;
                findings.Add($"run_end carries no valid runDisposition (got '{disposition ?? "none"}').");
            }
            var last = arts.Select(p => p.Sa).LastOrDefault(s => s is not null);
            if (!ReferenceEquals(last, end)) { finOk = false; findings.Add("run_end is not the last artifact of the chain."); }
            var head = arts.Select(p => p.Sa).LastOrDefault(s => s?.Seq is not null && end.Seq is not null && s.Seq < end.Seq);
            if (head is null) { finOk = false; findings.Add("run_end has no preceding artifact."); }
            else
            {
                var finalSeq = AgentExecutionProfile.Int(end.Ext["finalSeq"]);
                if (finalSeq != head.Seq)
                {
                    finOk = false;
                    findings.Add($"run_end commits to finalSeq {finalSeq?.ToString(CultureInfo.InvariantCulture) ?? "none"}, observed {head.Seq}.");
                }
                var finalPrev = AgentExecutionProfile.Str(end.Ext["finalPrevSignatureSha256"]);
                if (finalPrev is null || finalPrev != AgentExecutionProfile.ChainDigest(head.Jws))
                {
                    finOk = false;
                    findings.Add("run_end chain-head commitment does not match the observed head.");
                }
            }
            if (!anchorValid) finOk = false;
            checks["finalization"] = finOk ? "ok" : "bad";
        }
        checks["timestamps"] = !tsOk || !policyOk ? "bad" : anchorValid ? "ok" : "warn";

        var startArt = arts.FirstOrDefault(p => p.Sa is not null && ReferenceEquals(p.Sa, start)).Art;
        var (identity, idFindings) = await VerifyIdentityAsync(bundle, start, startArt, verifier, cancellationToken).ConfigureAwait(false);
        findings.AddRange(idFindings);
        if (!identity.Declared && !identity.Present)
        {
            checks["identity"] = "warn";
            warnings.Add("run_start declares no agent identity record.");
        }
        else if (!identity.Present) checks["identity"] = "bad";
        else checks["identity"] = identity.WellFormed && identity.Linked && identity.KindsComplete
            && identity.ConfigMatches && identity.ConfigDigestValid && identity.ActorMatches
            && identity.SignatureValid && identity.ObjectsComplete && identity.TimestampValid ? "ok" : "bad";

        var verdict = checks.Values.Contains("bad") ? "run_invalid" : end is not null ? "run_finalized" : "run_open";
        return new AgentRunVerificationResult
        {
            Verdict = verdict,
            Checks = checks,
            Findings = findings,
            Warnings = warnings,
            Disposition = disposition,
            AgentId = actorId,
            AgentVersion = agentVersion,
            CorrelationId = correlation,
            MissingSeqs = missing,
            Timestamps = new AgentRunTimestampSummary(arts.Count, tsRequired, tsPresent, tsValid, anchorValid,
                profile, everyEvents, everySeconds, policy is not null),
            Certificates = certificates,
            Identity = identity,
            Artifacts = verdicts,
            Fingerprint = SafeFingerprint(bundle),
        };
    }

    private static string? SafeFingerprint(AgentRunBundle bundle)
    {
        try { return Fingerprint(bundle); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; } // not valid I-JSON (§8.1)
    }

    private static async Task<(AgentIdentityVerdict, List<string>)> VerifyIdentityAsync(
        AgentRunBundle bundle, Signed? start, AgentRunArtifact? startArt, BlindObjectsVerifier blind, CancellationToken ct)
    {
        var findings = new List<string>();
        var declared = start?.AgentIdentityEvidenceId;
        if (bundle.AgentIdentity is null)
        {
            if (declared is not null) findings.Add($"run_start references identity record {declared}, but the bundle does not include it.");
            return (new AgentIdentityVerdict { Declared = declared is not null, EvidenceId = declared }, findings);
        }
        var (sa, error) = ParseSigned(bundle.AgentIdentity.Envelope, bundle.AgentIdentity.Signature);
        if (sa is null)
        {
            findings.Add("Identity record: " + error);
            return (new AgentIdentityVerdict { Declared = declared is not null, Present = true }, findings);
        }
        var wellFormed = sa.IsIdentity && sa.Conformance.Count == 0;
        if (!sa.IsIdentity) findings.Add("Identity record: recordType is not 'agent-identity'.");
        foreach (var e in sa.Conformance) findings.Add($"Identity record: {e}.");
        var linked = start is not null && start.Parent == sa.EvidenceId && declared == sa.EvidenceId;
        if (!linked) findings.Add("run_start does not reference the identity record (parentEvidenceId / agentIdentityEvidenceId).");
        var actorMatches = start is not null && start.ActorId == sa.ActorId && start.AgentVersion == sa.AgentVersion;
        if (!actorMatches) findings.Add("Identity record's signed agent/version differ from run_start's.");

        // Effective digest per kind; false when a kind in `exact` appears more than once.
        (Dictionary<string, string> Digests, bool Unique) DigestsByKind(Signed s, AgentRunArtifact? art, string label, IReadOnlyList<string> exact)
        {
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            var unique = true;
            if (art is null) return (d, unique);
            var counts = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var so in s.Objects)
            {
                counts[so.Kind] = counts.TryGetValue(so.Kind, out var n) ? n + 1 : 1;
                var hex = bundle.Payloads.TryGetValue(so.Uri, out var payload) ? EnvelopeHashing.HashHex(payload)
                    : art.ObjectDigests.TryGetValue(so.Uri, out var h) ? h : null;
                if (hex is not null && !d.ContainsKey(so.Kind)) d[so.Kind] = hex;
            }
            foreach (var kind in exact)
                if (counts.TryGetValue(kind, out var n) && n > 1)
                {
                    unique = false;
                    findings.Add($"{label}: more than one signed object of kind '{kind}'.");
                }
            return (d, unique);
        }
        var (idD, idUnique) = DigestsByKind(sa, bundle.AgentIdentity, "Identity record", AgentExecutionProfile.IdentityKinds);
        var (stD, stUnique) = start is not null
            ? DigestsByKind(start, startArt, "run_start", AgentExecutionProfile.ConfigurationKinds)
            : (new Dictionary<string, string>(), true);
        var missingKinds = AgentExecutionProfile.IdentityKinds.Where(k => !idD.ContainsKey(k)).ToList();
        foreach (var k in missingKinds) findings.Add($"Identity record: no signed object of kind '{k}'.");
        var kindsComplete = idUnique && stUnique && missingKinds.Count == 0;
        var configMatches = AgentExecutionProfile.ConfigurationKinds.All(k =>
            idD.TryGetValue(k, out var a) && stD.TryGetValue(k, out var b) && a == b);
        if (!configMatches)
            findings.Add("run_start's instruction set / tool manifest / model config / execution policy do not match the identity record's.");
        var configDigestValid = false;
        if (new[] { "agent-manifest" }.Concat(AgentExecutionProfile.ConfigurationKinds).All(idD.ContainsKey))
        {
            var recomputed = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(new JsonObject
            {
                ["agentManifest"] = idD["agent-manifest"], ["instructionSet"] = idD["instruction-set"],
                ["toolManifest"] = idD["tool-manifest"], ["modelConfig"] = idD["model-config"],
                ["executionPolicy"] = idD["execution-policy"],
            }));
            configDigestValid = recomputed == sa.ConfigSha256;
        }
        if (!configDigestValid) findings.Add("Identity record: configSha256 does not match the digest of its configuration objects.");

        var c = await CheckArtifactAsync(sa, bundle.AgentIdentity, bundle.Payloads, blind, "identity record", ct).ConfigureAwait(false);
        findings.AddRange(c.Findings);
        var timestampValid = c.TimestampPresent && c.TimestampValid == true;
        if (!timestampValid) findings.Add($"Identity record: timestamp {(c.TimestampPresent ? "invalid" : "missing")}.");
        return (new AgentIdentityVerdict
        {
            Declared = declared is not null, Present = true, SignatureValid = c.SignatureValid,
            ObjectsComplete = c.ObjectsComplete, TimestampValid = timestampValid, WellFormed = wellFormed,
            Linked = linked, KindsComplete = kindsComplete, ConfigMatches = configMatches,
            ConfigDigestValid = configDigestValid, ActorMatches = actorMatches, EvidenceId = sa.EvidenceId,
            ActorId = sa.ActorId, AgentVersion = sa.AgentVersion, ConfigSha256 = sa.ConfigSha256,
            Certificate = c.Certificate, Objects = c.Objects,
        }, findings);
    }

    /// <summary>The deterministic bundle fingerprint (spec §8.1).</summary>
    public static string Fingerprint(AgentRunBundle bundle)
    {
        if (bundle is null) throw new ArgumentNullException(nameof(bundle));
        static JsonObject One(AgentRunArtifact a)
        {
            var d = new JsonObject();
            foreach (var kv in a.ObjectDigests.OrderBy(k => k.Key, StringComparer.Ordinal)) d[kv.Key] = kv.Value;
            return new JsonObject
            {
                ["e"] = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(a.Envelope)),
                ["s"] = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(a.Signature)),
                ["d"] = d,
            };
        }
        var arts = bundle.Artifacts.Select(a =>
            {
                var o = One(a);
                var seq = ParseSigned(a.Envelope, a.Signature).Sa?.Seq ?? -1;
                var withSeq = new JsonObject { ["seq"] = seq };
                foreach (var kv in o.ToList()) { o.Remove(kv.Key); withSeq[kv.Key] = kv.Value; }
                return (Seq: seq, E: AgentExecutionProfile.Str(withSeq["e"])!, Node: withSeq);
            })
            .OrderBy(x => x.Seq).ThenBy(x => x.E, StringComparer.Ordinal)
            .Select(x => (JsonNode)x.Node).ToArray();
        var payloads = bundle.Payloads.Keys.OrderBy(k => k, StringComparer.Ordinal)
            .Select(uri => (JsonNode)new JsonObject { ["uri"] = uri, ["sha256"] = EnvelopeHashing.HashHex(bundle.Payloads[uri]) })
            .ToArray();
        var root = new JsonObject
        {
            ["profile"] = bundle.Profile,
            ["artifacts"] = new JsonArray(arts),
            ["identity"] = bundle.AgentIdentity is null ? null : One(bundle.AgentIdentity),
            ["payloads"] = new JsonArray(payloads),
        };
        return EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(root));
    }
}
