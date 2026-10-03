// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>
/// Records one controlled agent run under the Agent Evidence Profiles v1
/// (<c>spec/agent-profiles-common-v1.md</c>). Starting a run seals the
/// Control Artifact (configuration, control set, timestamp policy), then
/// <c>run_start</c>, which binds it. Every later event is sealed blind
/// (digests and opaque URIs only) and chained to the previous event's
/// signature, so a verifier detects removed, reordered, inserted or spliced
/// events.
///
/// <code>
/// var run = await AgentRun.StartAsync(client, agent, new AgentRunOptions
/// {
///     CertificateId = certId, Activity = "support-ticket-close", ControlSet = controls,
/// });
/// await run.RecordToolCallAsync("lookup_ticket", argsJson, operation: "read");
/// await run.RecordToolResultAsync("lookup_ticket", resultJson);
/// await run.RecordModelOutputAsync(answer);
/// AgentRunBundle bundle = await run.FinishAsync("completed");
/// </code>
///
/// Under the default policy only the Control Artifact and <c>run_end</c> are
/// timestamped; every other event is sealed B-B (common rules §4). Events are
/// sealed one at a time, in call order; calls may come from any thread. A
/// sealing failure throws and stops the chain (§6): later calls throw
/// <see cref="InvalidOperationException"/>, and the bundle so far verifies as
/// open or invalid, never as finalized.
/// </summary>
public sealed class AgentRun
{
    private static readonly HashSet<string> ReservedStepFields = new(StringComparer.Ordinal)
    {
        "type", "eventTime", "consequential", "timestamp", "finalSeq", "finalPrevSignatureSha256", "runDisposition",
    };

    private readonly ISigillAiEvidenceClient _client;
    private readonly AgentDefinition _agent;
    private readonly AgentRunOptions _options;
    private readonly Func<DateTimeOffset> _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<AgentRunArtifact> _artifacts = new();
    private readonly Dictionary<string, byte[]> _payloads = new(StringComparer.Ordinal);
    private AgentProfiles.TimestampCoverage _coverage;
    private string? _prevSignatureSha256;
    private string? _signer;
    private bool _broken;
    private bool _finished;

    /// <summary>The run identifier (<c>activity.correlationId</c>).</summary>
    public string CorrelationId { get; }

    /// <summary>The run's Control Artifact, sealed before <c>run_start</c>.</summary>
    public AgentRunArtifact ControlArtifact { get; private set; } = null!;

    /// <summary>The sealed events so far, in chain order.</summary>
    public IReadOnlyList<AgentRunArtifact> Artifacts
    {
        get { lock (_artifacts) return _artifacts.ToArray(); }
    }

    /// <summary>A sealing failure stopped the chain.</summary>
    public bool IsBroken => _broken;

    /// <summary><c>run_end</c> has been sealed.</summary>
    public bool IsFinished => _finished;

    private AgentRun(ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options, Func<DateTimeOffset> clock)
    {
        _client = client;
        _agent = agent;
        _options = options;
        _clock = clock;
        CorrelationId = options.CorrelationId ?? "urn:uuid:" + Guid.NewGuid();
        _coverage = new AgentProfiles.TimestampCoverage(options.TimestampPolicy);
    }

    /// <summary>
    /// Opens a run: seals the Control Artifact (always timestamped), then
    /// <c>run_start</c> binding it.
    /// </summary>
    public static Task<AgentRun> StartAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options, CancellationToken cancellationToken = default) =>
        StartCoreAsync(client, agent, options, () => DateTimeOffset.UtcNow, cancellationToken);

    internal static async Task<AgentRun> StartCoreAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options,
        Func<DateTimeOffset> clock, CancellationToken cancellationToken)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        if (agent is null) throw new ArgumentNullException(nameof(agent));
        if (options is null) throw new ArgumentNullException(nameof(options));
        if (options.ControlSet is null) throw new ArgumentException("ControlSet is required.", nameof(options));
        ValidatePolicy(options.TimestampPolicy);

        var run = new AgentRun(client, agent, options, clock);
        var now = AgentProfiles.Truncate(clock());
        var objects = new List<AgentRunObject>();
        var config = agent.Configuration ?? new AgentConfiguration();
        void Add(string role, byte[]? bytes, string contentType)
        {
            if (bytes is not null) objects.Add(new AgentRunObject { Role = role, Bytes = bytes, ContentType = contentType });
        }
        Add("instruction-set", config.InstructionSet, "text/plain");
        Add("tool-manifest", config.ToolManifest, "application/json");
        Add("execution-policy", config.ExecutionPolicy, "application/json");
        Add("model-config", config.ModelConfig, "application/json");
        Add("control-set", options.ControlSet.Content, options.ControlSet.ContentType);
        Add("authority", options.Authority, options.AuthorityContentType);
        Add("baseline-state", options.BaselineState, options.BaselineStateContentType);

        var actor = options.ControlActor ?? new AgentRunActor("agent", agent.AgentId, agent.AgentVersion);
        var actorJson = new JsonObject { ["type"] = actor.Type, ["id"] = actor.Id };
        if (actor.Version is not null) actorJson["version"] = actor.Version;
        var agentJson = new JsonObject { ["id"] = agent.AgentId, ["version"] = agent.AgentVersion };
        if (agent.IdentityRef is not null) agentJson["identityRef"] = agent.IdentityRef;
        var envelope = new JsonObject
        {
            ["schemaName"] = AgentProfiles.ControlArtifactSchema,
            ["schemaVersion"] = "1",
            ["evidenceId"] = Guid.NewGuid().ToString(),
            ["createdAt"] = AgentProfiles.FormatTime(now),
            ["actor"] = actorJson,
            ["activity"] = new JsonObject { ["name"] = options.Activity, ["correlationId"] = run.CorrelationId },
            ["agent"] = agentJson,
            ["controlSet"] = new JsonObject { ["id"] = options.ControlSet.Id, ["version"] = options.ControlSet.Version },
            ["timestampPolicy"] = options.TimestampPolicy.ToJson(),
            ["objects"] = ObjectsBlock(objects),
        };
        AgentRunVerifier.Prevalidate(envelope, AgentProfiles.ControlArtifactSchema);

        var result = await SealAsync(client, envelope, objects, AgentProfiles.ControlArtifactContentType,
            options.CertificateId, timestamp: true, options.Qualified, cancellationToken).ConfigureAwait(false);
        if (result.TimestampedBy is null)
            throw new SigillException("The Control Artifact must be timestamped, but the seal carries no timestamp.");
        var (signer, problem) = AgentProfiles.SignerOf(result.Signature);
        if (problem is not null)
            throw new SigillException($"The sealing service returned a signature whose signer cannot be established: {problem}.");
        run._signer = signer;
        run.ControlArtifact = new AgentRunArtifact(envelope, result.Signature, Digests(objects));
        if (options.RetainPayloads)
            foreach (var o in objects) run._payloads[o.Uri] = o.Bytes;
        await run.NotifyAsync(run.ControlArtifact, -1, cancellationToken).ConfigureAwait(false);

        var start = await run.SealEventAsync("run_start", options.StartObjects ?? Array.Empty<AgentRunObject>(),
            new JsonObject(), consequential: false, cancellationToken).ConfigureAwait(false);
        await run.NotifyAsync(start, 0, cancellationToken).ConfigureAwait(false);
        return run;
    }

    // ── Events ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Seals one event. <paramref name="fields"/> adds the type-specific step
    /// fields (<c>tool</c>, <c>decision</c>, <c>policyId</c>, <c>approver</c>,
    /// <c>detail</c>) — keep them free of personal data.
    /// <paramref name="consequential"/> marks an external side effect (a
    /// write-class tool call, a delivered message); it is timestamped when the
    /// signed policy says <c>consequential: true</c>.
    /// <paramref name="requireTimestamp"/> timestamps this event even when the
    /// policy would not (a producer may require more, never less).
    /// </summary>
    /// <exception cref="ArgumentException">The event would not verify; nothing was sealed and the run stays usable.</exception>
    public async Task<AgentRunArtifact> RecordAsync(
        string stepType, IReadOnlyList<AgentRunObject>? objects = null, JsonObject? fields = null,
        bool consequential = false, bool requireTimestamp = false, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(stepType)) throw new ArgumentException("stepType is required.", nameof(stepType));
        if (stepType is "run_start" or "run_end")
            throw new ArgumentException($"'{stepType}' is sealed by StartAsync / FinishAsync.", nameof(stepType));
        var reserved = fields?.Select(kv => kv.Key).Where(ReservedStepFields.Contains).OrderBy(k => k, StringComparer.Ordinal).ToList();
        if (reserved is { Count: > 0 })
            throw new ArgumentException("fields uses reserved step member(s): " + string.Join(", ", reserved), nameof(fields));
        AgentRunArtifact artifact;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureOpen();
            var step = (JsonObject?)fields?.DeepClone() ?? new JsonObject();
            if (requireTimestamp) step["timestamp"] = "required";
            artifact = await SealEventAsync(stepType, objects ?? Array.Empty<AgentRunObject>(), step, consequential, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
        await NotifyAsync(artifact, artifact.Seq!.Value, cancellationToken).ConfigureAwait(false);
        return artifact;
    }

    /// <summary>Retrieved context (RAG) the agent read.</summary>
    public Task<AgentRunArtifact> RecordRetrievalAsync(byte[] context, string contentType = "text/plain",
        string? detail = null, CancellationToken cancellationToken = default) =>
        RecordAsync("retrieval", new[] { Obj("retrieved-context", context, contentType) }, Detail(new JsonObject(), detail),
            cancellationToken: cancellationToken);

    /// <summary>
    /// A tool call the agent decided to make. <paramref name="operation"/>
    /// classifies it (e.g. <c>read</c>, <c>update</c>); mark write-class calls
    /// <paramref name="consequential"/>. <paramref name="useId"/> correlates the
    /// call with its result.
    /// </summary>
    public Task<AgentRunArtifact> RecordToolCallAsync(string tool, byte[] arguments, string? operation = null,
        bool consequential = false, string contentType = "application/json", string? useId = null,
        CancellationToken cancellationToken = default) =>
        RecordAsync("tool_call", new[] { Obj("tool-arguments", arguments, contentType) },
            new JsonObject { ["tool"] = ToolBlock(tool, operation, useId) }, consequential, cancellationToken: cancellationToken);

    /// <summary>The result a tool returned — context for the model's next turn.</summary>
    public Task<AgentRunArtifact> RecordToolResultAsync(string tool, byte[] result,
        string contentType = "application/json", string? useId = null, CancellationToken cancellationToken = default) =>
        RecordAsync("tool_result", new[] { Obj("tool-result", result, contentType) },
            new JsonObject { ["tool"] = ToolBlock(tool, null, useId) }, cancellationToken: cancellationToken);

    /// <summary>A policy decision taken before an action, e.g. "this write needs approval".</summary>
    public Task<AgentRunArtifact> RecordAuthorizationAsync(AgentAuthorization authorization,
        CancellationToken cancellationToken = default)
    {
        if (authorization is null) throw new ArgumentNullException(nameof(authorization));
        var fields = new JsonObject { ["decision"] = authorization.Decision };
        if (authorization.PolicyId is not null) fields["policyId"] = authorization.PolicyId;
        return RecordAsync("authorization", fields: Detail(fields, authorization.Detail), cancellationToken: cancellationToken);
    }

    /// <summary>
    /// A human approval: <paramref name="decision"/> is <c>approved</c> or
    /// <c>rejected</c>. <paramref name="approver"/> is an opaque identifier —
    /// never a name or e-mail address. What the approval covers (the receipt)
    /// and an identity assertion (e.g. an IdP token) are bound as detached
    /// objects; their bytes stay local.
    /// </summary>
    public Task<AgentRunArtifact> RecordHumanApprovalAsync(string decision, byte[]? receipt = null,
        byte[]? identityAssertion = null, string? approver = null, string? detail = null,
        string receiptContentType = "application/json", string identityAssertionContentType = "application/jwt",
        CancellationToken cancellationToken = default)
    {
        var fields = new JsonObject { ["decision"] = decision };
        if (approver is not null) fields["approver"] = approver;
        var objects = new List<AgentRunObject>();
        if (receipt is not null) objects.Add(Obj("approval-receipt", receipt, receiptContentType));
        if (identityAssertion is not null) objects.Add(Obj("identity-assertion", identityAssertion, identityAssertionContentType));
        return RecordAsync("human_approval", objects, Detail(fields, detail), cancellationToken: cancellationToken);
    }

    /// <summary>What the model produced.</summary>
    public Task<AgentRunArtifact> RecordModelOutputAsync(byte[] output, string contentType = "text/plain",
        bool consequential = false, CancellationToken cancellationToken = default) =>
        RecordAsync("model_output", new[] { Obj("model-output", output, contentType) }, consequential: consequential,
            cancellationToken: cancellationToken);

    /// <summary>
    /// Anchors the chain head with a timestamped <c>checkpoint</c> — e.g. from
    /// a timer while a long run is idle, so the head does not wait for
    /// <c>run_end</c> to be anchored.
    /// </summary>
    public Task<AgentRunArtifact> CheckpointAsync(string? detail = null, CancellationToken cancellationToken = default) =>
        RecordAsync("checkpoint", fields: Detail(new JsonObject(), detail), requireTimestamp: true,
            cancellationToken: cancellationToken);

    /// <summary>
    /// Seals <c>run_end</c> (always timestamped), closing the run, and returns
    /// the bundle. <paramref name="disposition"/>: completed | failed | aborted.
    /// </summary>
    public async Task<AgentRunBundle> FinishAsync(
        string disposition = "completed", string? detail = null, CancellationToken cancellationToken = default)
    {
        if (disposition is not ("completed" or "failed" or "aborted"))
            throw new ArgumentException("disposition must be completed, failed or aborted.", nameof(disposition));
        AgentRunArtifact artifact;
        AgentRunBundle bundle;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureOpen();
            int seq;
            lock (_artifacts) seq = _artifacts.Count;
            // finalSeq is run_end's own seq, finalPrev its own chain link (§11): closure is checkable on its own.
            var step = new JsonObject
            {
                ["finalSeq"] = seq,
                ["finalPrevSignatureSha256"] = _prevSignatureSha256,
                ["runDisposition"] = disposition,
            };
            artifact = await SealEventAsync("run_end", Array.Empty<AgentRunObject>(), Detail(step, detail),
                consequential: false, cancellationToken).ConfigureAwait(false);
            bundle = ToBundle();
        }
        finally { _gate.Release(); }
        await NotifyAsync(artifact, artifact.Seq!.Value, cancellationToken).ConfigureAwait(false);
        return bundle;
    }

    /// <summary>The run as a bundle — available at any point, including after a failure.</summary>
    public AgentRunBundle ToBundle()
    {
        Dictionary<string, byte[]> payloads;
        lock (_artifacts) payloads = new Dictionary<string, byte[]>(_payloads, StringComparer.Ordinal);
        return new AgentRunBundle(CorrelationId, ControlArtifact, Artifacts, null, payloads);
    }

    // ── Sealing ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Builds, validates and seals one event. Call with the gate held (or
    /// before the run is published); the callback is the caller's job.
    /// </summary>
    private async Task<AgentRunArtifact> SealEventAsync(
        string stepType, IReadOnlyList<AgentRunObject> objects, JsonObject fields, bool consequential, CancellationToken ct)
    {
        var now = AgentProfiles.Truncate(_clock()); // the decision below must use the signed, truncated time
        int seq;
        lock (_artifacts) seq = _artifacts.Count;
        var coverage = _coverage.Clone(); // committed only once the event is sealed
        var declared = AgentProfiles.Str(fields["timestamp"]) == "required";
        var stamp = coverage.Next(seq, stepType, consequential, declared, now);

        var step = new JsonObject
        {
            ["type"] = stepType,
            ["eventTime"] = AgentProfiles.FormatTime(now),
            ["consequential"] = consequential,
            ["timestamp"] = stamp ? "required" : "none",
        };
        foreach (var kv in fields.ToList())
        {
            if (kv.Key == "timestamp") continue;
            fields.Remove(kv.Key);
            step[kv.Key] = kv.Value;
        }
        var actor = new JsonObject { ["type"] = "agent", ["id"] = _agent.AgentId, ["version"] = _agent.AgentVersion };
        if (_agent.TenantId is not null) actor["tenantId"] = _agent.TenantId;
        var chain = new JsonObject { ["seq"] = seq };
        if (seq > 0) chain["prevSignatureSha256"] = _prevSignatureSha256;
        var envelope = new JsonObject
        {
            ["schemaName"] = AgentProfiles.ExecutionEvidenceSchema,
            ["schemaVersion"] = "1",
            ["evidenceId"] = Guid.NewGuid().ToString(),
            ["createdAt"] = AgentProfiles.FormatTime(now),
            ["actor"] = actor,
            ["activity"] = new JsonObject { ["name"] = _options.Activity, ["correlationId"] = CorrelationId },
            ["chain"] = chain,
            ["step"] = step,
        };
        if (seq == 0)
            envelope["binds"] = new JsonObject { ["controlArtifactSignatureSha256"] = ControlArtifact.SignatureSha256 };
        envelope["objects"] = ObjectsBlock(objects);
        var digests = Digests(objects);
        AgentRunVerifier.Prevalidate(envelope, AgentProfiles.ExecutionEvidenceSchema); // throws before anything is sealed

        try
        {
            var result = await SealAsync(_client, envelope, objects, AgentProfiles.ExecutionEvidenceContentType,
                _options.CertificateId, stamp, _options.Qualified, ct).ConfigureAwait(false);
            if (stamp && result.TimestampedBy is null)
                throw new SigillException($"{stepType}: a timestamp is required by the run's policy, but the seal carries none.");
            var (signer, problem) = AgentProfiles.SignerOf(result.Signature);
            if (problem is not null)
                throw new SigillException($"The sealing service returned a signature whose signer cannot be established: {problem}.");
            if (signer != _signer)
                throw new SigillException("The event was sealed with a different certificate than the run's Control Artifact (certificate rotated?); a run has one signer.");

            var artifact = new AgentRunArtifact(envelope, result.Signature, digests);
            _prevSignatureSha256 = artifact.SignatureSha256
                ?? throw new SigillException("The seal returned no classical signature to chain to.");
            _coverage = coverage;
            lock (_artifacts)
            {
                _artifacts.Add(artifact);
                if (stepType == "run_end") _finished = true; // committed with the append, before any caller code runs
                if (_options.RetainPayloads)
                    foreach (var o in objects) _payloads[o.Uri] = o.Bytes;
            }
            return artifact;
        }
        catch (Exception)
        {
            _broken = true;
            throw;
        }
    }

    /// <summary>
    /// Runs the callback outside the gate, so it may call back into the run, and
    /// in order (the Control Artifact as -1, then each seq): concurrent events
    /// wait their turn, so a crash can leave the persisted prefix short, never
    /// with a hole. An event recorded from inside a callback is delivered
    /// immediately (it is next in order, and waiting would deadlock on the
    /// callback that recorded it). The artifact is already sealed; a failing
    /// callback is the caller's error and does not break the run.
    /// </summary>
    private async Task NotifyAsync(AgentRunArtifact artifact, int seq, CancellationToken ct)
    {
        if (!InCallback.Value) await WaitForTurnAsync(seq).ConfigureAwait(false);
        try
        {
            if (_options.OnArtifactSealed is { } callback)
            {
                InCallback.Value = true; // flows into the callback only, not back to our caller
                await callback(artifact, ct).ConfigureAwait(false);
            }
        }
        finally { Advance(seq); }
    }

    private static readonly AsyncLocal<bool> InCallback = new();
    private readonly object _notifyLock = new();
    private readonly Dictionary<int, TaskCompletionSource<bool>> _notifyWaiters = new();
    private int _nextNotify = -1;

    private Task WaitForTurnAsync(int seq)
    {
        lock (_notifyLock)
        {
            if (_nextNotify >= seq) return Task.CompletedTask;
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _notifyWaiters[seq] = tcs;
            return tcs.Task;
        }
    }

    private void Advance(int seq)
    {
        List<TaskCompletionSource<bool>> ready;
        lock (_notifyLock)
        {
            if (seq + 1 > _nextNotify) _nextNotify = seq + 1;
            ready = _notifyWaiters.Where(kv => kv.Key <= _nextNotify).Select(kv => kv.Value).ToList();
            foreach (var key in _notifyWaiters.Keys.Where(k => k <= _nextNotify).ToList()) _notifyWaiters.Remove(key);
        }
        foreach (var t in ready) t.TrySetResult(true);
    }

    // No operation label: only digests, opaque URIs and content types reach the sealing service (§6).
    internal static async Task<SignHashesResult> SealAsync(
        ISigillAiEvidenceClient client, JsonObject envelope, IReadOnlyList<AgentRunObject> objects, string profileContentType,
        Guid certificateId, bool timestamp, bool qualified, CancellationToken ct)
    {
        var digests = objects.Select(o => new SignedObjectDigest
        {
            Uri = o.Uri,
            HashHex = EnvelopeHashing.HashHex(o.Bytes),
            ContentType = o.ContentType,
        }).ToList();
        return await client.SignObjectHashesAsync(
            EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(envelope)),
            digests,
            certificateId,
            new ObjectSignOptions { Timestamp = timestamp, Qualified = qualified && timestamp, EnvelopeContentType = profileContentType },
            ct).ConfigureAwait(false);
    }

    internal static JsonArray ObjectsBlock(IEnumerable<AgentRunObject> objects) =>
        new(objects.Select(o => (JsonNode)new JsonObject
        {
            ["uri"] = o.Uri,
            ["role"] = o.Role,
            ["contentType"] = o.ContentType,
            ["sizeBytes"] = o.Bytes.Length,
        }).ToArray());

    internal static IReadOnlyDictionary<string, string> Digests(IReadOnlyList<AgentRunObject> objects)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var o in objects)
        {
            if (o.Bytes is null) throw new ArgumentException($"Object '{o.Uri}' has no bytes.");
            if (d.ContainsKey(o.Uri)) throw new ArgumentException($"Duplicate object URI '{o.Uri}'.");
            d[o.Uri] = EnvelopeHashing.HashHex(o.Bytes);
        }
        return d;
    }

    private void EnsureOpen()
    {
        if (_broken) throw new InvalidOperationException("The run's chain is broken by an earlier sealing failure; no further events can be sealed.");
        if (_finished) throw new InvalidOperationException("The run is finished.");
    }

    private static void ValidatePolicy(AgentTimestampPolicy p)
    {
        if (p is null) throw new ArgumentNullException(nameof(p));
        if (p.Profile is not ("throughput" or "per-event"))
            throw new ArgumentException("TimestampPolicy.Profile must be 'throughput' or 'per-event'.");
        if (p.EveryEvents < 0 || p.EverySeconds < 0)
            throw new ArgumentException("TimestampPolicy cadence values must be zero or positive.");
    }

    private static JsonObject ToolBlock(string name, string? operation, string? useId)
    {
        if (string.IsNullOrEmpty(name)) throw new ArgumentException("tool name is required.", nameof(name));
        var block = new JsonObject { ["name"] = name };
        if (operation is not null) block["operation"] = operation;
        if (useId is not null) block["useId"] = useId;
        return block;
    }

    private static JsonObject Detail(JsonObject fields, string? detail)
    {
        if (detail is not null) fields["detail"] = detail;
        return fields;
    }

    private static AgentRunObject Obj(string role, byte[] bytes, string contentType) =>
        new() { Role = role, Bytes = bytes ?? throw new ArgumentNullException(nameof(bytes)), ContentType = contentType };
}

/// <summary>
/// Seals a Control Evaluation (<c>spec/control-evaluation-v1.md</c>): what an
/// independent verifier observed after a run and how each control came out.
/// Always timestamped. Seal it with the verifier's own certificate.
/// </summary>
public static class ControlEvaluation
{
    /// <exception cref="ArgumentException">The evaluation would not verify; nothing was sealed.</exception>
    public static Task<AgentRunArtifact> SealAsync(
        ISigillAiEvidenceClient client, ControlEvaluationRequest request, CancellationToken cancellationToken = default) =>
        SealCoreAsync(client, request, () => DateTimeOffset.UtcNow, cancellationToken);

    internal static async Task<AgentRunArtifact> SealCoreAsync(
        ISigillAiEvidenceClient client, ControlEvaluationRequest request, Func<DateTimeOffset> clock, CancellationToken ct)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        if (request is null) throw new ArgumentNullException(nameof(request));
        var control = request.ControlArtifact ?? throw new ArgumentException("ControlArtifact is required.", nameof(request));
        if (request.RunEnd?.StepType != "run_end") throw new ArgumentException("RunEnd must be the run's run_end artifact.", nameof(request));
        var controlSig = control.SignatureSha256 ?? throw new ArgumentException("The Control Artifact carries no classical signature.", nameof(request));
        var runEndSig = request.RunEnd.SignatureSha256 ?? throw new ArgumentException("run_end carries no classical signature.", nameof(request));

        // The control set and baseline are referred to by the Control Artifact's own URI and digest; no bytes needed.
        JsonObject? ControlObject(string role) =>
            (control.Envelope["objects"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault(o => AgentProfiles.Str(o["role"]) == role);
        var objects = new JsonArray();
        var digests = new Dictionary<string, string>(StringComparer.Ordinal);
        var seal = new List<SignedObjectDigest>();
        void Reuse(JsonObject o)
        {
            var uri = AgentProfiles.Str(o["uri"])!;
            if (!control.ObjectDigests.TryGetValue(uri, out var hex))
                throw new ArgumentException($"The Control Artifact carries no digest for its '{AgentProfiles.Str(o["role"])}' object.", nameof(request));
            objects.Add(o.DeepClone());
            digests[uri] = hex;
            seal.Add(new SignedObjectDigest { Uri = uri, HashHex = hex, ContentType = AgentProfiles.Str(o["contentType"]) });
        }
        foreach (var o in request.ObservedState ?? Array.Empty<AgentRunObject>())
        {
            if (o.Role != "observed-state") throw new ArgumentException("ObservedState objects must have role 'observed-state'.", nameof(request));
            foreach (var node in AgentRun.ObjectsBlock(new[] { o })) objects.Add(node!.DeepClone());
            if (digests.ContainsKey(o.Uri)) throw new ArgumentException($"Duplicate object URI '{o.Uri}'.", nameof(request));
            digests[o.Uri] = EnvelopeHashing.HashHex(o.Bytes);
            seal.Add(new SignedObjectDigest { Uri = o.Uri, HashHex = digests[o.Uri], ContentType = o.ContentType });
        }
        Reuse(ControlObject("control-set") ?? throw new ArgumentException("The Control Artifact carries no control-set object.", nameof(request)));
        if (request.IncludeBaseline && ControlObject("baseline-state") is { } baseline) Reuse(baseline);

        var now = AgentProfiles.Truncate(clock());
        var envelope = new JsonObject
        {
            ["schemaName"] = AgentProfiles.ControlEvaluationSchema,
            ["schemaVersion"] = "1",
            ["evidenceId"] = Guid.NewGuid().ToString(),
            ["createdAt"] = AgentProfiles.FormatTime(now),
            ["actor"] = new JsonObject { ["type"] = "verifier", ["id"] = request.VerifierId, ["version"] = request.VerifierVersion },
            ["activity"] = control.Envelope["activity"]?.DeepClone(),
            ["subject"] = new JsonObject { ["runEndSignatureSha256"] = runEndSig, ["controlArtifactSignatureSha256"] = controlSig },
            ["controlSet"] = control.Envelope["controlSet"]?.DeepClone(),
            ["controls"] = new JsonArray((request.Controls ?? Array.Empty<ControlResult>()).Select(c =>
            {
                var j = new JsonObject { ["id"] = c.Id, ["result"] = c.Result };
                if (c.Detail is not null) j["detail"] = c.Detail;
                return (JsonNode)j;
            }).ToArray()),
            ["overall"] = request.Overall,
            ["evaluatedAt"] = AgentProfiles.FormatTime(AgentProfiles.Truncate(request.EvaluatedAt ?? now)),
            ["objects"] = objects,
        };
        AgentRunVerifier.Prevalidate(envelope, AgentProfiles.ControlEvaluationSchema);

        var result = await client.SignObjectHashesAsync(
            EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(envelope)), seal, request.CertificateId,
            new ObjectSignOptions
            {
                Timestamp = true, Qualified = request.Qualified, EnvelopeContentType = AgentProfiles.ControlEvaluationContentType,
            }, ct).ConfigureAwait(false);
        if (result.TimestampedBy is null)
            throw new SigillException("A Control Evaluation must be timestamped, but the seal carries no timestamp.");
        return new AgentRunArtifact(envelope, result.Signature, digests);
    }
}
