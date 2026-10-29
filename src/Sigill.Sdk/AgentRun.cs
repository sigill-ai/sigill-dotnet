// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
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
        "delegation", "model", "vendorRefs", "usage",
    };

    private readonly ISigillAiEvidenceClient _client;
    private readonly AgentDefinition _agent;
    private readonly AgentRunOptions _options;
    private readonly Func<DateTimeOffset> _clock;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<AgentRunArtifact> _artifacts = new();
    private readonly Dictionary<string, byte[]> _payloads = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _sealedDigests = new(StringComparer.Ordinal);
    private AgentProfiles.TimestampCoverage _coverage;
    private string? _prevSignatureSha256;
    private string? _signer;
    private bool _broken;
    private bool _finished;
    private readonly string _schemaVersion;
    private readonly AgentDelegation? _parent;
    // delegation §4: open delegations (child correlationId → delegation seq) and those already resolved.
    private readonly Dictionary<string, int> _outstanding = new(StringComparer.Ordinal);
    private readonly HashSet<string> _resolved = new(StringComparer.Ordinal);

    /// <summary>The run identifier (<c>activity.correlationId</c>).</summary>
    public string CorrelationId { get; }

    /// <summary>The run's Control Artifact, sealed before <c>run_start</c>.</summary>
    public AgentRunArtifact ControlArtifact { get; private set; } = null!;

    /// <summary>Outcome of <see cref="AgentRunOptions.DisclosePolicy"/>; null when the policy was not shared.</summary>
    public AgentIndexResult? PolicyDisclosure { get; private set; }

    /// <summary>The sealed events so far, in chain order.</summary>
    public IReadOnlyList<AgentRunArtifact> Artifacts
    {
        get { lock (_artifacts) return _artifacts.ToArray(); }
    }

    /// <summary>A sealing failure stopped the chain.</summary>
    public bool IsBroken => _broken;

    /// <summary><c>run_end</c> has been sealed.</summary>
    public bool IsFinished => _finished;

    /// <summary>Delegations sealed but not yet resolved by a <c>delegation_result</c>.</summary>
    public IReadOnlyCollection<string> OutstandingDelegations
    {
        get { lock (_artifacts) return _outstanding.Keys.ToArray(); }
    }

    private AgentRun(ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options, Func<DateTimeOffset> clock,
        AgentDelegation? parent = null)
    {
        _client = client;
        _agent = agent;
        _options = options;
        _clock = clock;
        _parent = parent;
        _schemaVersion = options.RecordsModelCalls ? "3" : options.Delegating || parent is not null ? "2" : "1";
        CorrelationId = parent?.ChildCorrelationId ?? options.CorrelationId ?? "urn:uuid:" + Guid.NewGuid();
        _coverage = new AgentProfiles.TimestampCoverage(options.TimestampPolicy);
    }

    /// <summary>
    /// Opens a run: seals the Control Artifact (always timestamped), then
    /// <c>run_start</c> binding it.
    /// </summary>
    public static Task<AgentRun> StartAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options, CancellationToken cancellationToken = default) =>
        StartCoreAsync(client, agent, options, () => DateTimeOffset.UtcNow, cancellationToken);

    /// <summary>
    /// Opens a child run for a delegation the parent sealed (<c>spec/agent-delegation-v1.md</c> §4 rule 2):
    /// the child's Control Artifact, then its <c>run_start</c> binding both the Control Artifact and the
    /// parent's <c>delegation</c>. The child's correlationId is the one the parent declared, and its
    /// <see cref="AgentDefinition.AgentId"/> must be the declared <c>childAgentId</c>. Call it before the
    /// child acts: the child must do nothing before its <c>run_start</c> is sealed.
    /// </summary>
    public static Task<AgentRun> StartChildAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options, AgentDelegation delegation,
        CancellationToken cancellationToken = default) =>
        StartCoreAsync(client, agent, options, () => DateTimeOffset.UtcNow, cancellationToken, delegation);

    internal static async Task<AgentRun> StartCoreAsync(
        ISigillAiEvidenceClient client, AgentDefinition agent, AgentRunOptions options,
        Func<DateTimeOffset> clock, CancellationToken cancellationToken, AgentDelegation? parent = null)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        if (agent is null) throw new ArgumentNullException(nameof(agent));
        if (options is null) throw new ArgumentNullException(nameof(options));
        if (options.ControlSet is null) throw new ArgumentException("ControlSet is required.", nameof(options));
        ValidatePolicy(options.TimestampPolicy);
        ValidateControlSet(options);
        if (parent is not null)
        {
            if (string.IsNullOrEmpty(parent.ChildCorrelationId) || string.IsNullOrEmpty(parent.ParentCorrelationId)
                || string.IsNullOrEmpty(parent.DelegationSignatureSha256))
                throw new ArgumentException("The delegation is incomplete.", nameof(parent));
            if (options.CorrelationId is not null && options.CorrelationId != parent.ChildCorrelationId)
                throw new ArgumentException("A child run's correlationId is the one its parent declared.", nameof(options));
            if (parent.ChildAgentId != agent.AgentId)
                throw new ArgumentException($"The parent delegated to '{parent.ChildAgentId}', not '{agent.AgentId}'.", nameof(agent));
        }

        var run = new AgentRun(client, agent, options, clock, parent);
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
            options.CertificateId, timestamp: true, options.Qualified || options.QualifiedFor.HasFlag(QualifiedArtifacts.ControlArtifact),
            cancellationToken).ConfigureAwait(false);
        if (result.TimestampedBy is null)
            throw new SigillException("The Control Artifact must be timestamped, but the seal carries no timestamp.");
        var (signer, problem) = AgentProfiles.SignerOf(result.Signature);
        if (problem is not null)
            throw new SigillException($"The sealing service returned a signature whose signer cannot be established: {problem}.");
        run._signer = signer;
        run.ControlArtifact = new AgentRunArtifact(envelope, result.Signature, Digests(objects));
        foreach (var kv in run.ControlArtifact.ObjectDigests) run._sealedDigests[kv.Key] = kv.Value;
        if (options.RetainPayloads)
            foreach (var o in objects) run._payloads[o.Uri] = o.Bytes;

        // Seal run_start before any callback runs, so a failing callback cannot strand a sealed control basis.
        var start = await run.SealEventAsync("run_start", options.StartObjects ?? Array.Empty<AgentRunObject>(),
            new JsonObject(), consequential: false, cancellationToken).ConfigureAwait(false);
        if (options.DisclosePolicy)
        {
            // Sharing is a side channel: it never fails the run (the evidence is in the producer's bundle either way).
            try
            {
                run.PolicyDisclosure = client is SigillClient sigill
                    ? await sigill.IndexAgentArtifactAsync(run.ControlArtifact, options.ControlSet.Content, cancellationToken).ConfigureAwait(false)
                    : new AgentIndexResult("failed", Error: "Only SigillClient can share a policy with the evidence index.");
            }
            catch (Exception ex) { run.PolicyDisclosure = new AgentIndexResult("failed", Error: ex.Message); }
        }
        // Both are delivered even when the first callback fails: later events wait for their turn in order.
        Exception? failure = null;
        foreach (var (artifact, seq) in new[] { (run.ControlArtifact, -1), (start, 0) })
        {
            // Every failure — a cancellation included — surfaces with the started run attached.
            try { await run.NotifyAsync(artifact, seq, cancellationToken).ConfigureAwait(false); }
            catch (Exception ex) { failure ??= ex; }
        }
        if (failure is not null) throw new AgentRunCallbackException(run, failure);
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
        if (stepType is "delegation" or "delegation_result")
            throw new ArgumentException($"'{stepType}' is sealed by DelegateAsync / CompleteDelegationAsync.", nameof(stepType));
        var reserved = fields?.Select(kv => kv.Key).Where(ReservedStepFields.Contains).OrderBy(k => k, StringComparer.Ordinal).ToList();
        if (reserved is { Count: > 0 })
            throw new ArgumentException("fields uses reserved step member(s): " + string.Join(", ", reserved), nameof(fields));
        return await RecordInternalAsync(stepType, objects, fields, consequential, cancellationToken, requireTimestamp).ConfigureAwait(false);
    }

    /// <summary>Seals one event whose step members are already checked (reserved members only from this class).</summary>
    private async Task<AgentRunArtifact> RecordInternalAsync(string stepType, IReadOnlyList<AgentRunObject>? objects, JsonObject? fields,
        bool consequential, CancellationToken cancellationToken, bool requireTimestamp = false)
    {
        AgentRunArtifact artifact;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureOpen();
            // Keep the last slot for run_end, and one per open delegation for its result (delegation §4 rule 6),
            // so a bundle always fits AgentRunBundle.MaxArtifacts and can finish.
            lock (_artifacts)
                if (_artifacts.Count >= AgentRunBundle.MaxArtifacts - 1 - _outstanding.Count)
                    throw new InvalidOperationException(_outstanding.Count == 0
                        ? $"The run has {_artifacts.Count} events; only run_end fits within the bundle limit of {AgentRunBundle.MaxArtifacts}. Finish the run."
                        : $"The run has {_artifacts.Count} events; the rest of the bundle limit of {AgentRunBundle.MaxArtifacts} is reserved for run_end and {_outstanding.Count} delegation result(s).");
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

    /// <summary>
    /// One model call with the provider's own identifiers (Agent Model Calls v1): a <c>model_output</c> step carrying
    /// <c>model</c>, <c>vendorRefs</c> and <c>usage</c>, with the request and response as digest-only objects (their
    /// content never leaves the producer). Requires <see cref="AgentRunOptions.RecordsModelCalls"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The run was not started with <see cref="AgentRunOptions.RecordsModelCalls"/>.</exception>
    public Task<AgentRunArtifact> RecordModelCallAsync(ModelCall call, byte[]? request = null, byte[]? response = null,
        string requestContentType = "application/json", string responseContentType = "application/json",
        bool consequential = false, CancellationToken cancellationToken = default)
    {
        if (call is null) throw new ArgumentNullException(nameof(call));
        if (_schemaVersion != "3")
            throw new InvalidOperationException("This run was not started with RecordsModelCalls = true; model calls use schemaVersion 3 throughout.");
        var step = new JsonObject();
        if (call.Model is { } m)
        {
            var model = new JsonObject { ["provider"] = m.Provider, ["served"] = m.Served };
            if (m.Requested is not null) model["requested"] = m.Requested;
            if (m.Deployment is not null) model["deployment"] = m.Deployment;
            if (m.Region is not null) model["region"] = m.Region;
            step["model"] = model;
        }
        if (call.VendorRefs.Count > 0)
            step["vendorRefs"] = new JsonArray(call.VendorRefs.Select(r => (JsonNode?)new JsonObject { ["provider"] = r.Provider, ["kind"] = r.Kind, ["id"] = r.Id }).ToArray());
        if (call.Usage is { } u)
        {
            var usage = new JsonObject();
            if (u.InputTokens is { } i) usage["inputTokens"] = i;
            if (u.OutputTokens is { } o) usage["outputTokens"] = o;
            if (u.CacheReadTokens is { } cr) usage["cacheReadTokens"] = cr;
            if (u.CacheWriteTokens is { } cw) usage["cacheWriteTokens"] = cw;
            if (u.StopReason is not null) usage["stopReason"] = u.StopReason;
            if (usage.Count > 0) step["usage"] = usage;
        }
        var objects = new List<AgentRunObject>();
        if (request is not null) objects.Add(Obj("model-input", request, requestContentType));
        if (response is not null) objects.Add(Obj("model-output", response, responseContentType));
        return RecordInternalAsync("model_output", objects, step, consequential, cancellationToken);
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
            lock (_artifacts)
                if (disposition == "completed" && _outstanding.Count > 0)
                    throw new InvalidOperationException(
                        $"{_outstanding.Count} delegation(s) have no result: record them first, or close the run as aborted or failed (delegation §4 rule 5).");
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

    // ── Delegation (spec/agent-delegation-v1.md) ─────────────────────────────

    /// <summary>
    /// Seals a <c>delegation</c> event declaring a child run (§3.2, §4 rule 1): call it before the child
    /// starts, then open the child with <see cref="StartChildAsync"/> and the returned
    /// <see cref="AgentDelegation"/>. <paramref name="instruction"/> is what the child is asked to do; only
    /// its digest is sealed (role <c>delegation-input</c>). Mark <paramref name="consequential"/> when the
    /// child is granted write authority. Requires <see cref="AgentRunOptions.Delegating"/> (or a child run).
    /// </summary>
    /// <exception cref="InvalidOperationException">The run does not delegate, or the event budget is reserved (§4 rule 6).</exception>
    public async Task<AgentDelegation> DelegateAsync(
        string childAgentId, byte[]? instruction = null, string instructionContentType = "text/plain", string? useId = null,
        bool consequential = false, string? childCorrelationId = null, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(childAgentId)) throw new ArgumentException("childAgentId is required.", nameof(childAgentId));
        if (_schemaVersion is not ("2" or "3"))
            throw new InvalidOperationException("This run was not started with Delegating = true; a run that delegates uses schemaVersion 2 (or 3) throughout.");
        var child = childCorrelationId ?? "urn:uuid:" + Guid.NewGuid();
        if (child.Length == 0 || child == CorrelationId)
            throw new ArgumentException("A run cannot delegate to itself.", nameof(childCorrelationId));
        AgentRunArtifact artifact;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureOpen();
            lock (_artifacts)
            {
                if (_outstanding.ContainsKey(child) || _resolved.Contains(child))
                    throw new ArgumentException($"'{child}' is already delegated by this run (§4 rule 10).", nameof(childCorrelationId));
                // This event, a result for every open delegation including this one, and run_end must fit.
                if (_artifacts.Count + 1 + _outstanding.Count + 1 + 1 > AgentRunBundle.MaxArtifacts)
                    throw new InvalidOperationException(
                        $"No room for another delegation: the bundle limit of {AgentRunBundle.MaxArtifacts} is reserved for run_end and the results of {_outstanding.Count} open delegation(s).");
            }
            var block = new JsonObject { ["childCorrelationId"] = child, ["childAgentId"] = childAgentId };
            if (useId is not null) block["useId"] = useId;
            var objects = instruction is null
                ? Array.Empty<AgentRunObject>()
                : new[] { Obj("delegation-input", instruction, instructionContentType) };
            artifact = await SealEventAsync("delegation", objects, new JsonObject { ["delegation"] = block }, consequential,
                cancellationToken).ConfigureAwait(false);
            lock (_artifacts) _outstanding[child] = artifact.Seq!.Value;
        }
        finally { _gate.Release(); }
        await NotifyAsync(artifact, artifact.Seq!.Value, cancellationToken).ConfigureAwait(false);
        return new AgentDelegation(CorrelationId, artifact.SignatureSha256!, child, childAgentId) { Artifact = artifact };
    }

    /// <summary>
    /// Seals the <c>delegation_result</c> for a finished child run in this process (§4 rule 3).
    /// </summary>
    public Task<AgentRunArtifact> CompleteDelegationAsync(AgentRun child, CancellationToken cancellationToken = default)
    {
        if (child is null) throw new ArgumentNullException(nameof(child));
        if (!child.IsFinished) throw new InvalidOperationException("The child run is not finished: seal its run_end first (§4 rule 3).");
        var end = child.Artifacts[^1];
        var disposition = AgentProfiles.Str(end.Envelope["step"]?["runDisposition"])!;
        return CompleteDelegationAsync(child.CorrelationId, end.SignatureSha256!, disposition, cancellationToken);
    }

    /// <summary>
    /// Seals the <c>delegation_result</c> for a child that ran elsewhere: its correlationId, the
    /// <c>signatureSha256</c> of its sealed <c>run_end</c> and that <c>run_end</c>'s disposition (§3.2).
    /// One result per delegation, whatever the child's disposition.
    /// </summary>
    public async Task<AgentRunArtifact> CompleteDelegationAsync(
        string childCorrelationId, string childRunEndSignatureSha256, string childDisposition,
        CancellationToken cancellationToken = default)
    {
        if (childDisposition is not ("completed" or "failed" or "aborted"))
            throw new ArgumentException("childDisposition must be completed, failed or aborted.", nameof(childDisposition));
        AgentRunArtifact artifact;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureOpen();
            lock (_artifacts)
                if (!_outstanding.ContainsKey(childCorrelationId))
                    throw new InvalidOperationException(_resolved.Contains(childCorrelationId)
                        ? $"'{childCorrelationId}' already has its result (§4 rule 4)."
                        : $"This run never delegated to '{childCorrelationId}'.");
            var block = new JsonObject
            {
                ["childCorrelationId"] = childCorrelationId,
                ["childRunEndSignatureSha256"] = childRunEndSignatureSha256,
                ["childDisposition"] = childDisposition,
            };
            artifact = await SealEventAsync("delegation_result", Array.Empty<AgentRunObject>(),
                new JsonObject { ["delegation"] = block }, consequential: false, cancellationToken).ConfigureAwait(false);
            lock (_artifacts)
            {
                _outstanding.Remove(childCorrelationId);
                _resolved.Add(childCorrelationId);
            }
        }
        finally { _gate.Release(); }
        await NotifyAsync(artifact, artifact.Seq!.Value, cancellationToken).ConfigureAwait(false);
        return artifact;
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
            ["schemaVersion"] = _schemaVersion,
            ["evidenceId"] = Guid.NewGuid().ToString(),
            ["createdAt"] = AgentProfiles.FormatTime(now),
            ["actor"] = actor,
            ["activity"] = new JsonObject { ["name"] = _options.Activity, ["correlationId"] = CorrelationId },
            ["chain"] = chain,
            ["step"] = step,
        };
        if (seq == 0)
        {
            var binds = new JsonObject { ["controlArtifactSignatureSha256"] = ControlArtifact.SignatureSha256 };
            if (_parent is not null)
            {
                binds["parentDelegationSignatureSha256"] = _parent.DelegationSignatureSha256;
                binds["parentCorrelationId"] = _parent.ParentCorrelationId;
            }
            envelope["binds"] = binds;
        }
        envelope["objects"] = ObjectsBlock(objects);
        var digests = Digests(objects);
        CheckUriReuse(digests);
        AgentRunVerifier.Prevalidate(envelope, AgentProfiles.ExecutionSchemaFor(envelope)); // throws before anything is sealed

        try
        {
            var result = await SealAsync(_client, envelope, objects, AgentProfiles.ExecutionEvidenceContentType,
                _options.CertificateId, stamp,
                _options.Qualified || (stepType == "run_end" && _options.QualifiedFor.HasFlag(QualifiedArtifacts.RunEnd)), ct).ConfigureAwait(false);
            if (stamp && result.TimestampedBy is null)
                throw new SigillException($"{stepType}: a timestamp is required by the run's policy, but the seal carries none.");
            var (signer, problem) = AgentProfiles.SignerOf(result.Signature);
            if (problem is not null)
                throw new SigillException($"The sealing service returned a signature whose signer cannot be established: {problem}.");
            if (signer != _signer)
                throw new SigillException("The event was sealed with a different certificate than the run's Control Artifact (certificate rotated?); a run has one signer.");

            var artifact = new AgentRunArtifact(envelope, result.Signature, digests);
            lock (_artifacts) foreach (var kv in digests) _sealedDigests[kv.Key] = kv.Value;
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

    /// <summary>§5: a URI used again in this run must name the same content (the verifier fails it otherwise).</summary>
    private void CheckUriReuse(IReadOnlyDictionary<string, string> digests)
    {
        lock (_artifacts)
            foreach (var kv in digests)
                if (_sealedDigests.TryGetValue(kv.Key, out var earlier) && earlier != kv.Value)
                    throw new ArgumentException($"Object URI '{kv.Key}' was already sealed in this run with different content.");
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

    /// <summary>A policy control set is checked before anything is sealed: a malformed policy must never become the run's control basis.</summary>
    private static void ValidateControlSet(AgentRunOptions o)
    {
        if (o.ControlSet.ContentType != AgentPolicy.ControlSetContentType)
        {
            if (o.DisclosePolicy)
                throw new ArgumentException($"DisclosePolicy requires a control set of type {AgentPolicy.ControlSetContentType} (AgentPolicy.ControlSetFromDocument).", nameof(o));
            return;
        }
        var errors = AgentPolicy.Validate(o.ControlSet.Content);
        if (errors.Count > 0) throw new ArgumentException("Invalid policy control set: " + string.Join("; ", errors), nameof(o));
        var doc = JsonNode.Parse(o.ControlSet.Content)!;
        if (doc["id"]!.GetValue<string>() != o.ControlSet.Id || doc["version"]!.GetValue<string>() != o.ControlSet.Version)
            throw new ArgumentException("ControlSet.Id and Version must equal the document's id and version.", nameof(o));
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
/// An <see cref="AgentRunOptions.OnArtifactSealed"/> callback failed while the
/// run was starting. The run itself started: the Control Artifact and
/// <c>run_start</c> are sealed, and <see cref="Run"/> carries on from there.
/// </summary>
public sealed class AgentRunCallbackException : SigillException
{
    public AgentRun Run { get; }

    public AgentRunCallbackException(AgentRun run, Exception inner)
        : base("The run started, but an OnArtifactSealed callback failed: " + inner.Message, inner) => Run = run;
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
        var reused = new HashSet<string>(StringComparer.Ordinal);
        void Reuse(JsonObject o)
        {
            var uri = AgentProfiles.Str(o["uri"])!;
            reused.Add(uri);
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
                ReusedUris = reused,
            }, ct).ConfigureAwait(false);
        if (result.TimestampedBy is null)
            throw new SigillException("A Control Evaluation must be timestamped, but the seal carries no timestamp.");
        return new AgentRunArtifact(envelope, result.Signature, digests);
    }

    private static readonly Dictionary<string, int> Rank = new(StringComparer.Ordinal) { ["PASS"] = 0, ["INDETERMINATE"] = 1, ["FAIL"] = 2 };
    private static readonly HashSet<string> Statuses = new(StringComparer.Ordinal) { "approved_before_run", "approved_after_start", "unapproved" };

    /// <summary>
    /// Builds a policy evaluation (<c>spec/control-evaluation-v2.md</c> §4) ready to sign. Nothing is sent.
    /// </summary>
    /// <exception cref="ArgumentException">The evaluation would not verify.</exception>
    public static PreparedEvaluation PreparePolicy(PolicyEvaluationRequest request) => PreparePolicy(request, () => DateTimeOffset.UtcNow);

    internal static PreparedEvaluation PreparePolicy(PolicyEvaluationRequest request, Func<DateTimeOffset> clock)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        var control = request.ControlArtifact ?? throw new ArgumentException("ControlArtifact is required.", nameof(request));
        var doc = request.ControlSetDocument ?? throw new ArgumentException("ControlSetDocument is required.", nameof(request));
        var problems = AgentPolicy.Validate(doc);
        if (problems.Count > 0) throw new ArgumentException("Invalid policy control set: " + string.Join("; ", problems), nameof(request));
        var policyDoc = (JsonObject)JsonNode.Parse(doc)!;
        if (policyDoc["cedar"] is not JsonObject cedar) throw new ArgumentException("The control set carries no Cedar rules.", nameof(request));
        var (csUri, csNode) = ControlSetObject(control, doc, request);
        if (AgentProfiles.Str(csNode["contentType"]) != AgentPolicy.ControlSetContentType)
            throw new ArgumentException("The Control Artifact's control set is not a policy control set.", nameof(request));
        if (!Statuses.Contains(request.PolicyStatus ?? "")) throw new ArgumentException($"Unknown policy status '{request.PolicyStatus}'.", nameof(request));
        if ((request.PolicyStatus == "unapproved") != (request.ApprovalRecord is null))
            throw new ArgumentException("ApprovalRecord is required exactly when the policy status is not unapproved.", nameof(request));
        var declaresPrivate = policyDoc["privateControls"] is JsonArray pc && pc.Count > 0;
        if (declaresPrivate != (request.PrivateControlsReported is not null))
            throw new ArgumentException("PrivateControlsReported is required exactly when the control set declares private controls.", nameof(request));

        var agentId = AgentProfiles.Str(control.Envelope["agent"]?["id"]) ?? throw new ArgumentException("The Control Artifact names no agent.", nameof(request));
        var correlationId = AgentProfiles.Str(control.Envelope["activity"]?["correlationId"]) ?? throw new ArgumentException("The Control Artifact has no correlationId.", nameof(request));
        var events = (request.Events ?? Array.Empty<AgentRunArtifact>()).OrderBy(e => AgentProfiles.Int(e.Envelope["chain"]?["seq"])).ToList();
        if (events.Count == 0) throw new ArgumentException("Events must hold the evaluated prefix, starting at seq 0.", nameof(request));
        var facts = AgentPolicy.BuildFacts(agentId, correlationId, events.Select(e => e.Envelope), request.MissingSeqs ?? Array.Empty<int>());
        if (facts.MissingSeqs.Count > 0 && facts.MissingSeqs[0] != facts.ThroughSeq + 1)
            throw new ArgumentException("MissingSeqs must start right after the evaluated prefix.", nameof(request));
        var last = events[^1];
        var runEnd = events.FirstOrDefault(e => e.StepType == "run_end");
        var finalized = runEnd is not null && facts.MissingSeqs.Count == 0;

        var rules = request.Rules ?? Array.Empty<PolicyRuleResult>();
        var ruleIds = (cedar["policies"]?["staticPolicies"] as JsonObject)!.Select(kv => kv.Key).ToList();
        if (!new HashSet<string>(ruleIds, StringComparer.Ordinal).SetEquals(rules.Select(r => r.Id)) || rules.Count != ruleIds.Count)
            throw new ArgumentException("Rules must hold exactly one result per Cedar rule of the control set.", nameof(request));
        foreach (var r in rules)
        {
            if (!Rank.ContainsKey(r.Result)) throw new ArgumentException($"Rule '{r.Id}': unknown result '{r.Result}'.", nameof(request));
            if ((r.Result == "PASS") != (r.Where is null || r.Where.Count == 0))
                throw new ArgumentException($"Rule '{r.Id}': Where is required exactly when the result is not PASS.", nameof(request));
        }

        var now = AgentProfiles.Truncate(clock());
        var factsUri = EnvelopeReferences.NewObjectUri();
        var objects = new JsonArray { csNode.DeepClone() };
        var seal = new List<SignedObjectDigest> { new() { Uri = csUri, HashHex = control.ObjectDigests[csUri], ContentType = AgentPolicy.ControlSetContentType } };
        var digests = new Dictionary<string, string>(StringComparer.Ordinal) { [csUri] = control.ObjectDigests[csUri] };
        var payloads = new Dictionary<string, byte[]>(StringComparer.Ordinal) { [csUri] = doc };
        void Add(string uri, string role, string contentType, byte[] bytes)
        {
            var hex = EnvelopeHashing.HashHex(bytes);
            objects.Add(new JsonObject { ["uri"] = uri, ["role"] = role, ["contentType"] = contentType, ["sizeBytes"] = bytes.Length });
            seal.Add(new SignedObjectDigest { Uri = uri, HashHex = hex, ContentType = contentType });
            digests[uri] = hex;
            payloads[uri] = bytes;
        }
        Add(factsUri, "evaluation-facts", "application/json", facts.Bytes);
        if (request.ApprovalRecord is { } approval)
            Add(EnvelopeReferences.NewObjectUri(), "policy-approval", "application/vnd.sigill.policy-approval+json", approval);

        var digestsOfPolicy = AgentPolicy.ComputeDigests(doc);
        var subject = new JsonObject
        {
            ["controlArtifactSignatureSha256"] = control.SignatureSha256 ?? throw new ArgumentException("The Control Artifact carries no classical signature.", nameof(request)),
            ["throughSignatureSha256"] = last.SignatureSha256 ?? throw new ArgumentException("An event carries no classical signature.", nameof(request)),
        };
        if (finalized) subject["runEndSignatureSha256"] = runEnd!.SignatureSha256;
        var policy = new JsonObject
        {
            ["approvalScopeDigest"] = digestsOfPolicy.ApprovalScopeDigest,
            ["cedarDigest"] = digestsOfPolicy.CedarDigest,
            ["policyStatus"] = request.PolicyStatus,
            ["evaluator"] = new JsonObject { ["engine"] = request.Engine, ["factsVersion"] = AgentPolicy.FactsVersion, ["schemaSha256"] = AgentProfiles.Str(cedar["schemaSha256"]) },
            ["prefix"] = new JsonObject
            {
                ["throughSeq"] = facts.ThroughSeq,
                ["finalSeq"] = runEnd is null ? null : JsonValue.Create(AgentProfiles.Int(runEnd.Envelope["step"]?["finalSeq"])),
                ["missingSeqs"] = new JsonArray(facts.MissingSeqs.Select(m => (JsonNode?)m).ToArray()),
            },
            ["state"] = finalized ? "finalized" : "partial",
        };
        if (request.PrivateControlsReported is { } reported) policy["privateControlsReported"] = reported;
        // §4.7: present exactly when the approval record requires qualified time.
        JsonObject? approvalDoc = null;
        if (request.ApprovalRecord is { } rec)
        {
            try { approvalDoc = JsonNode.Parse(rec) as JsonObject; }
            catch (JsonException) { }
            if (approvalDoc is null) throw new ArgumentException("ApprovalRecord is not a JSON object.", nameof(request));
        }
        var requiresQualified = AgentProfiles.Str(approvalDoc?["timestamps"]) == "qualified";
        if (requiresQualified != (request.NotQualified is not null))
            throw new ArgumentException("NotQualified is required exactly when the approval record requires qualified timestamps.", nameof(request));
        if (request.NotQualified is { } notQualified)
            policy["timestamps"] = new JsonObject
            {
                ["required"] = "qualified", ["met"] = notQualified.Count == 0,
                ["where"] = new JsonArray(notQualified.Select(w => (JsonNode?)w).ToArray()),
            };
        var envelope = Envelope("policy", "verifier", request.EvaluatorId, request.EvaluatorVersion, control, subject, now, request.EvaluatedAt,
            rules.Select(r =>
            {
                var j = new JsonObject { ["id"] = r.Id, ["result"] = r.Result };
                if (r.Where is { Count: > 0 } w) j["where"] = new JsonArray(w.Select(x => (JsonNode?)x).ToArray());
                if (r.Detail is not null) j["detail"] = r.Detail;
                return j;
            }), rules.Select(r => r.Result), objects, request.Supersedes);
        envelope["policy"] = policy;
        return Prepared(envelope, seal, new[] { csUri }, digests, payloads) with { RequiresQualifiedTimestamp = requiresQualified };
    }

    /// <summary>Builds an attested evaluation (<c>spec/control-evaluation-v2.md</c> §5) ready to sign. Nothing is sent.</summary>
    /// <exception cref="ArgumentException">The evaluation would not verify.</exception>
    public static PreparedEvaluation PrepareAttested(AttestedEvaluationRequest request) => PrepareAttested(request, () => DateTimeOffset.UtcNow);

    internal static PreparedEvaluation PrepareAttested(AttestedEvaluationRequest request, Func<DateTimeOffset> clock)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        var control = request.ControlArtifact ?? throw new ArgumentException("ControlArtifact is required.", nameof(request));
        if (request.RunEnd?.StepType != "run_end") throw new ArgumentException("RunEnd must be the run's run_end artifact.", nameof(request));
        var doc = request.ControlSetDocument ?? throw new ArgumentException("ControlSetDocument is required.", nameof(request));
        var (csUri, csNode) = ControlSetObject(control, doc, request);
        var declared = (JsonNode.Parse(doc)?["privateControls"] as JsonArray ?? new JsonArray())
            .Select(x => AgentProfiles.Str(x?["id"])).OfType<string>().ToList();
        var controls = request.Controls ?? Array.Empty<ControlResult>();
        if (declared.Count == 0) throw new ArgumentException("The control set declares no private controls.", nameof(request));
        if (!new HashSet<string>(declared, StringComparer.Ordinal).SetEquals(controls.Select(c => c.Id)) || controls.Count != declared.Count)
            throw new ArgumentException("Controls must hold exactly one result per declared private control.", nameof(request));
        if (controls.Any(c => !Rank.ContainsKey(c.Result))) throw new ArgumentException("A control has an unknown result.", nameof(request));

        var subject = new JsonObject
        {
            ["controlArtifactSignatureSha256"] = control.SignatureSha256 ?? throw new ArgumentException("The Control Artifact carries no classical signature.", nameof(request)),
            ["runEndSignatureSha256"] = request.RunEnd.SignatureSha256 ?? throw new ArgumentException("run_end carries no classical signature.", nameof(request)),
        };
        var envelope = Envelope("attested", "producer", request.ProducerId, request.ProducerVersion, control, subject,
            AgentProfiles.Truncate(clock()), request.EvaluatedAt,
            controls.Select(c =>
            {
                var j = new JsonObject { ["id"] = c.Id, ["result"] = c.Result };
                if (c.Detail is not null) j["detail"] = c.Detail;
                return j;
            }), controls.Select(c => c.Result), new JsonArray { csNode.DeepClone() }, request.Supersedes);
        if (request.EvaluatorId is not null || request.EvaluatorVersion is not null)
        {
            var a = new JsonObject();
            if (request.EvaluatorId is not null) a["evaluatorId"] = request.EvaluatorId;
            if (request.EvaluatorVersion is not null) a["evaluatorVersion"] = request.EvaluatorVersion;
            envelope["attested"] = a;
        }
        var hex = control.ObjectDigests[csUri];
        return Prepared(envelope, new[] { new SignedObjectDigest { Uri = csUri, HashHex = hex, ContentType = AgentProfiles.Str(csNode["contentType"]) } },
            new[] { csUri }, new Dictionary<string, string>(StringComparer.Ordinal) { [csUri] = hex },
            new Dictionary<string, byte[]>(StringComparer.Ordinal) { [csUri] = doc });
    }

    /// <summary>Signs a prepared evaluation through the blind sealing endpoint, always timestamped.</summary>
    public static async Task<AgentRunArtifact> SealAsync(ISigillAiEvidenceClient client, PreparedEvaluation prepared, Guid certificateId,
        bool qualified = false, CancellationToken cancellationToken = default)
    {
        if (client is null) throw new ArgumentNullException(nameof(client));
        if (prepared is null) throw new ArgumentNullException(nameof(prepared));
        var result = await client.SignObjectHashesAsync(prepared.EnvelopeHashHex, prepared.Objects, certificateId,
            new ObjectSignOptions
            {
                // §4.7: an evaluation under a qualified-time requirement is itself qualified — never a best-effort stamp.
                Timestamp = true, Qualified = qualified || prepared.RequiresQualifiedTimestamp, EnvelopeContentType = AgentProfiles.ControlEvaluationContentType,
                ReusedUris = prepared.ReusedUris,
            }, cancellationToken).ConfigureAwait(false);
        if (result.TimestampedBy is null)
            throw new SigillException("A Control Evaluation must be timestamped, but the seal carries no timestamp.");
        return Complete(prepared, result.Signature);
    }

    /// <summary>The evaluation artifact, once <paramref name="signature"/> (a JAdES JWS over the prepared hashes) exists.</summary>
    public static AgentRunArtifact Complete(PreparedEvaluation prepared, JsonObject signature) =>
        new(prepared.Envelope, signature, prepared.ObjectDigests);

    private static (string Uri, JsonObject Node) ControlSetObject(AgentRunArtifact control, byte[] doc, object request)
    {
        var node = (control.Envelope["objects"] as JsonArray)?.OfType<JsonObject>().FirstOrDefault(o => AgentProfiles.Str(o["role"]) == "control-set")
            ?? throw new ArgumentException("The Control Artifact carries no control-set object.", nameof(request));
        var uri = AgentProfiles.Str(node["uri"])!;
        if (!control.ObjectDigests.TryGetValue(uri, out var hex) || hex != EnvelopeHashing.HashHex(doc))
            throw new ArgumentException("ControlSetDocument is not the control set sealed in the Control Artifact.", nameof(request));
        return (uri, node);
    }

    private static JsonObject Envelope(string kind, string actorType, string actorId, string actorVersion, AgentRunArtifact control,
        JsonObject subject, DateTimeOffset now, DateTimeOffset? evaluatedAt, IEnumerable<JsonObject> controls, IEnumerable<string> results,
        JsonArray objects, EvaluationReference? supersedes)
    {
        var envelope = new JsonObject
        {
            ["schemaName"] = AgentProfiles.ControlEvaluationSchema,
            ["schemaVersion"] = "2",
            ["kind"] = kind,
            ["evidenceId"] = Guid.NewGuid().ToString(),
            ["createdAt"] = AgentProfiles.FormatTime(now),
            ["actor"] = new JsonObject { ["type"] = actorType, ["id"] = actorId, ["version"] = actorVersion },
            ["activity"] = control.Envelope["activity"]?.DeepClone(),
            ["subject"] = subject,
            ["controlSet"] = control.Envelope["controlSet"]?.DeepClone(),
            ["controls"] = new JsonArray(controls.Select(c => (JsonNode?)c).ToArray()),
            ["overall"] = results.Aggregate("PASS", (a, b) => Rank[b] > Rank[a] ? b : a), // §2: derived, never asserted
            ["evaluatedAt"] = AgentProfiles.FormatTime(AgentProfiles.Truncate(evaluatedAt ?? now)),
            ["objects"] = objects,
        };
        if (supersedes is not null)
            envelope["supersedes"] = new JsonObject { ["evidenceId"] = supersedes.EvidenceId, ["signatureSha256"] = supersedes.SignatureSha256 };
        return envelope;
    }

    private static PreparedEvaluation Prepared(JsonObject envelope, IReadOnlyList<SignedObjectDigest> seal, IReadOnlyCollection<string> reused,
        Dictionary<string, string> digests, Dictionary<string, byte[]> payloads)
    {
        AgentRunVerifier.Prevalidate(envelope, AgentProfiles.ControlEvaluationSchemaV2);
        return new PreparedEvaluation
        {
            Envelope = envelope, EnvelopeHashHex = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(envelope)),
            Objects = seal, ReusedUris = reused, ObjectDigests = digests, Payloads = payloads,
        };
    }
}
