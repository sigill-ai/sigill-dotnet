// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>
/// The agent's configuration, bound into the Control Artifact
/// (<c>spec/agent-control-artifact-v1.md</c> §3). Every part is optional.
/// The bytes stay local; only their digests are sealed. They are usually
/// confidential — share them only with parties entitled to read them.
/// </summary>
public sealed record AgentConfiguration
{
    /// <summary>The stable instruction set (system prompt), without per-run context. Role <c>instruction-set</c>.</summary>
    public byte[]? InstructionSet { get; init; }

    /// <summary>The tool manifest: which tools exist and their schemas. Role <c>tool-manifest</c>.</summary>
    public byte[]? ToolManifest { get; init; }

    /// <summary>What the agent is allowed to do: scope, allowlists, approval rules, limits. Role <c>execution-policy</c>.</summary>
    public byte[]? ExecutionPolicy { get; init; }

    /// <summary>Model configuration (model, sampling parameters, limits). Role <c>model-config</c>.</summary>
    public byte[]? ModelConfig { get; init; }
}

/// <summary>The agent whose runs are recorded.</summary>
public sealed record AgentDefinition
{
    /// <summary>Stable, opaque agent identifier (<c>actor.id</c> of every event). Not a display name, no personal data.</summary>
    public required string AgentId { get; init; }

    /// <summary>The agent configuration version that runs (<c>actor.version</c>, <c>agent.version</c>).</summary>
    public required string AgentVersion { get; init; }

    public AgentConfiguration Configuration { get; init; } = new();

    /// <summary>Optional reference to an identity assertion the producer holds (<c>agent.identityRef</c>).</summary>
    public string? IdentityRef { get; init; }

    /// <summary>Optional <c>actor.tenantId</c> on every event.</summary>
    public string? TenantId { get; init; }
}

/// <summary>
/// The control set the run will be evaluated against (role <c>control-set</c>).
/// A Control Evaluation later refers to this same object by URI and digest.
/// </summary>
public sealed record AgentControlSet
{
    public required string Id { get; init; }
    public required string Version { get; init; }
    public required byte[] Content { get; init; }
    public string ContentType { get; init; } = "application/json";
}

/// <summary>Who seals the Control Artifact (its <c>actor</c>), e.g. the harness that starts the agent.</summary>
public sealed record AgentRunActor(string Type, string Id, string? Version = null);

/// <summary>
/// One detached object of an event: what the agent read, called or produced.
/// The bytes are hashed locally and never transmitted.
/// </summary>
public sealed record AgentRunObject
{
    /// <summary>The profile role, e.g. <c>model-input</c>, <c>tool-arguments</c>, <c>model-output</c>.</summary>
    public required string Role { get; init; }

    public required byte[] Bytes { get; init; }

    public string ContentType { get; init; } = "application/octet-stream";

    /// <summary>Opaque URI; generated as <c>urn:uuid:</c> when omitted. No personal data.</summary>
    public string Uri { get; init; } = "urn:uuid:" + Guid.NewGuid();

    /// <summary>A UTF-8 text object.</summary>
    public static AgentRunObject Text(string role, string text, string contentType = "text/plain") =>
        new() { Role = role, Bytes = Encoding.UTF8.GetBytes(text), ContentType = contentType };

    /// <summary>A JSON object, serialized in canonical (JCS) form so equal values hash equally.</summary>
    public static AgentRunObject Json(string role, JsonNode value) =>
        new() { Role = role, Bytes = AgentProfiles.Canonical(value), ContentType = "application/json" };
}

/// <summary>A policy decision taken before an action (an <c>authorization</c> event).</summary>
public sealed record AgentAuthorization
{
    /// <summary>The decision, in the producer's vocabulary: e.g. <c>allowed</c>, <c>allow_with_human_approval</c>, <c>denied</c>.</summary>
    public required string Decision { get; init; }

    public string? PolicyId { get; init; }

    /// <summary>Optional free text (<c>step.detail</c>). No personal data.</summary>
    public string? Detail { get; init; }
}

/// <summary>
/// The signed timestamp policy (common rules §4), locked in the Control
/// Artifact. The default seals every event B-B and timestamps only to wrap
/// up: the Control Artifact, <c>run_end</c> and each Control Evaluation.
/// </summary>
public sealed record AgentTimestampPolicy
{
    /// <summary>"throughput" (default) or "per-event".</summary>
    public string Profile { get; init; } = "throughput";

    /// <summary>Require a timestamp on the N-th event since the last one. 0 = off.</summary>
    public int EveryEvents { get; init; }

    /// <summary>Require a timestamp on the first event this many seconds after the last one. 0 = off.</summary>
    public int EverySeconds { get; init; }

    /// <summary>Timestamp every event marked consequential.</summary>
    public bool Consequential { get; init; }

    /// <summary>Every event timestamped: for low-volume, high-consequence agents.</summary>
    public static AgentTimestampPolicy PerEvent { get; } = new() { Profile = "per-event" };

    internal JsonObject ToJson() => new()
    {
        ["profile"] = Profile,
        ["everyEvents"] = EveryEvents,
        ["everySeconds"] = EverySeconds,
        ["consequential"] = Consequential,
    };

    /// <summary>The policy a signed <c>timestampPolicy</c> member states, or null when it is malformed.</summary>
    internal static AgentTimestampPolicy? FromJson(JsonNode? node)
    {
        if (node is not JsonObject o || o.Count != 4) return null;
        if (AgentProfiles.Str(o["profile"]) is not ("throughput" or "per-event") ||
            AgentProfiles.Int(o["everyEvents"]) is not >= 0 || AgentProfiles.Int(o["everySeconds"]) is not >= 0 ||
            !(o["consequential"] is JsonValue c && c.TryGetValue<bool>(out _)) ||
            o["everyEvents"] is JsonValue ee && ee.TryGetValue<bool>(out _) ||
            o["everySeconds"] is JsonValue es && es.TryGetValue<bool>(out _))
            return null;
        return new AgentTimestampPolicy
        {
            Profile = AgentProfiles.Str(o["profile"])!,
            EveryEvents = AgentProfiles.Int(o["everyEvents"])!.Value,
            EverySeconds = AgentProfiles.Int(o["everySeconds"])!.Value,
            Consequential = AgentProfiles.IsTrue(o["consequential"]),
        };
    }
}

/// <summary>Options for <see cref="AgentRun.StartAsync"/>.</summary>
public sealed record AgentRunOptions
{
    /// <summary>The Sigill seal certificate that signs the Control Artifact and every event (one signer per run).</summary>
    public required Guid CertificateId { get; init; }

    /// <summary>The activity the run performs (<c>activity.name</c>), e.g. <c>customer-address-change</c>.</summary>
    public required string Activity { get; init; }

    /// <summary>The control set the run will be evaluated against.</summary>
    public required AgentControlSet ControlSet { get; init; }

    /// <summary>
    /// The target's state as read before the run (role <c>baseline-state</c>):
    /// what every "unchanged" control rests on. Optional.
    /// </summary>
    public byte[]? BaselineState { get; init; }

    public string BaselineStateContentType { get; init; } = "application/json";

    /// <summary>The authority the agent acts under, e.g. a delegation token (role <c>authority</c>). Optional.</summary>
    public byte[]? Authority { get; init; }

    public string AuthorityContentType { get; init; } = "application/jwt";

    /// <summary>Who seals the Control Artifact. Default: the agent itself (<c>type: agent</c>).</summary>
    public AgentRunActor? ControlActor { get; init; }

    public AgentTimestampPolicy TimestampPolicy { get; init; } = new();

    /// <summary>The run identifier (<c>activity.correlationId</c>). Default: a new <c>urn:uuid:</c>.</summary>
    public string? CorrelationId { get; init; }

    /// <summary>Objects bound into <c>run_start</c>, e.g. the request (role <c>model-input</c>).</summary>
    public IReadOnlyList<AgentRunObject>? StartObjects { get; init; }

    /// <summary>
    /// Keep payload bytes in memory so <see cref="AgentRun.ToBundle"/> can
    /// include them. Off by default: a digests-only bundle reveals no content.
    /// </summary>
    public bool RetainPayloads { get; init; }

    /// <summary>Request eIDAS-qualified timestamps where a timestamp is taken.</summary>
    public bool Qualified { get; init; }

    /// <summary>
    /// Called after each artifact is sealed — the Control Artifact first, then
    /// every event strictly in chain order (concurrent events wait their turn).
    /// Persist it here so a crash leaves a shorter prefix, never a hole. It runs
    /// outside the run's lock and may call back into the run; an event recorded
    /// from inside the callback is delivered at once (waiting would deadlock),
    /// so it can arrive ahead of an event another thread sealed meanwhile. An
    /// exception propagates to the caller of that event; the run itself stays
    /// usable.
    /// </summary>
    public Func<AgentRunArtifact, CancellationToken, Task>? OnArtifactSealed { get; init; }
}

/// <summary>
/// One sealed artifact of any of the three profiles: the v2
/// <c>{envelope, signature}</c> pair plus each object's SHA-256, keyed by URI.
/// </summary>
public sealed record AgentRunArtifact(
    JsonObject Envelope,
    JsonObject Signature,
    IReadOnlyDictionary<string, string> ObjectDigests)
{
    public JsonObject Envelope { get; init; } = Envelope ?? throw new ArgumentNullException(nameof(Envelope));
    public JsonObject Signature { get; init; } = Signature ?? throw new ArgumentNullException(nameof(Signature));
    public IReadOnlyDictionary<string, string> ObjectDigests { get; init; } =
        ObjectDigests ?? throw new ArgumentNullException(nameof(ObjectDigests));

    /// <summary><c>AgentControlArtifact</c>, <c>AgentExecutionEvidence</c> or <c>ControlEvaluation</c>.</summary>
    public string? SchemaName => AgentProfiles.Str(Envelope["schemaName"]);

    /// <summary><c>chain.seq</c> of an event; null for the other profiles.</summary>
    public int? Seq => AgentProfiles.Int(Envelope["chain"]?["seq"]);

    /// <summary><c>step.type</c> of an event; null for the other profiles.</summary>
    public string? StepType => AgentProfiles.Str(Envelope["step"]?["type"]);

    /// <summary>The artifact's <c>evidenceId</c>.</summary>
    public string? EvidenceId => AgentProfiles.Str(Envelope["evidenceId"]);

    /// <summary>The binding digest other artifacts refer to this one by (common rules §2).</summary>
    public string? SignatureSha256 => AgentProfiles.SignatureSha256(Signature);

    internal JsonObject ToJson()
    {
        var digests = new JsonObject();
        foreach (var kv in ObjectDigests) digests[kv.Key] = kv.Value;
        return new JsonObject
        {
            ["envelope"] = Envelope.DeepClone(),
            ["signature"] = Signature.DeepClone(),
            ["objectDigests"] = digests,
        };
    }
}

/// <summary>One control's result in a Control Evaluation.</summary>
public sealed record ControlResult(string Id, string Result, string? Detail = null);

/// <summary>
/// What an independent verifier observed after a run, and how each control came
/// out (<c>spec/control-evaluation-v1.md</c>). See <see cref="ControlEvaluation.SealAsync"/>.
/// </summary>
public sealed record ControlEvaluationRequest
{
    /// <summary>The verifier's own seal certificate — SHOULD differ from the run's.</summary>
    public required Guid CertificateId { get; init; }

    /// <summary>Stable identifier of the verifier component (<c>actor.id</c>).</summary>
    public required string VerifierId { get; init; }

    public required string VerifierVersion { get; init; }

    /// <summary>The run's Control Artifact; its control set (and baseline) are referred to by URI and digest.</summary>
    public required AgentRunArtifact ControlArtifact { get; init; }

    /// <summary>The run's <c>run_end</c> artifact.</summary>
    public required AgentRunArtifact RunEnd { get; init; }

    /// <summary>The state read after the run (role <c>observed-state</c>); at least one.</summary>
    public required IReadOnlyList<AgentRunObject> ObservedState { get; init; }

    public required IReadOnlyList<ControlResult> Controls { get; init; }

    /// <summary>PASS, FAIL or INDETERMINATE — asserted by the verifier, never derived.</summary>
    public required string Overall { get; init; }

    /// <summary>When the state was read. Default: now.</summary>
    public DateTimeOffset? EvaluatedAt { get; init; }

    /// <summary>Also bind the Control Artifact's <c>baseline-state</c>, when it has one (default on).</summary>
    public bool IncludeBaseline { get; init; } = true;

    public bool Qualified { get; init; }
}
