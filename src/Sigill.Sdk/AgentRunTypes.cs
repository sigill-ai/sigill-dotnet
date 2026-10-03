// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>The model an agent runs on, bound into every step's envelope.</summary>
public sealed record AgentModelRef(string Provider, string Name, string? DeploymentId = null);

/// <summary>
/// The agent's configuration (spec §3.2): the objects every <c>run_start</c>
/// and identity record bind (the model configuration is optional). The bytes stay local; only their
/// digests are sealed. They are usually confidential — share them only with
/// parties entitled to read them.
/// </summary>
public sealed record AgentConfiguration
{
    /// <summary>The stable instruction set (system prompt), without per-run context.</summary>
    public required byte[] InstructionSet { get; init; }

    /// <summary>The tool manifest: which tools exist and their schemas.</summary>
    public required byte[] ToolManifest { get; init; }

    /// <summary>Optional model configuration (sampling parameters, limits).</summary>
    public byte[]? ModelConfig { get; init; }

    /// <summary>What the agent is allowed to do: scope, allowlists, approval rules, limits.</summary>
    public required byte[] ExecutionPolicy { get; init; }
}

/// <summary>The agent whose runs are recorded.</summary>
public sealed record AgentDefinition
{
    /// <summary>Stable, opaque agent identifier bound as <c>actor.id</c> (e.g. <c>urn:example:agent:triage</c>). No personal data.</summary>
    public required string AgentId { get; init; }

    /// <summary>The agent build (release tag or commit).</summary>
    public required string AgentVersion { get; init; }

    public required AgentModelRef Model { get; init; }

    public required AgentConfiguration Configuration { get; init; }

    /// <summary>Optional human-readable name, recorded in the agent manifest.</summary>
    public string? DisplayName { get; init; }

    /// <summary>Optional <c>actor.tenantId</c>.</summary>
    public string? TenantId { get; init; }

    /// <summary>Optional <c>purpose.businessContext</c>.</summary>
    public string? BusinessContext { get; init; }

    /// <summary>
    /// Agent manifest bytes. When null the SDK derives a canonical manifest
    /// from <see cref="AgentId"/>, <see cref="AgentVersion"/>,
    /// <see cref="DisplayName"/> and <see cref="Model"/>.
    /// </summary>
    public byte[]? Manifest { get; init; }
}

/// <summary>
/// One detached object of a step: what the agent read, called or produced.
/// The bytes are hashed locally and never transmitted.
/// </summary>
public sealed record AgentRunObject
{
    /// <summary>Profile kind (spec §3.5), e.g. <c>tool-arguments</c>, <c>assistant-reply</c>.</summary>
    public required string Kind { get; init; }

    /// <summary>v2 role: prompt | input | context | output | artifact | log.</summary>
    public required string Role { get; init; }

    public required byte[] Bytes { get; init; }

    public string ContentType { get; init; } = "application/octet-stream";

    /// <summary>Opaque URI; generated as <c>urn:uuid:</c> when omitted. No personal data.</summary>
    public string Uri { get; init; } = "urn:uuid:" + Guid.NewGuid();

    /// <summary>A UTF-8 text object.</summary>
    public static AgentRunObject Text(string kind, string role, string text, string contentType = "text/plain") =>
        new() { Kind = kind, Role = role, Bytes = Encoding.UTF8.GetBytes(text), ContentType = contentType };

    /// <summary>A JSON object, serialized in canonical (JCS) form so equal values hash equally.</summary>
    public static AgentRunObject Json(string kind, string role, JsonNode value) =>
        new() { Kind = kind, Role = role, Bytes = AgentExecutionProfile.Canonical(value), ContentType = "application/json" };
}

/// <summary>A policy decision taken before an action (spec §3.4).</summary>
public sealed record AgentAuthorization
{
    /// <summary><c>allowed</c> or <c>denied</c>.</summary>
    public required string Decision { get; init; }

    public string? PolicyId { get; init; }
    public string? Reason { get; init; }

    internal JsonObject ToJson()
    {
        if (Decision is not ("allowed" or "denied"))
            throw new ArgumentException("Authorization decision must be 'allowed' or 'denied'.");
        var json = new JsonObject { ["decision"] = Decision };
        if (PolicyId is not null) json["policyId"] = PolicyId;
        if (Reason is not null) json["reason"] = Reason;
        return json;
    }
}

/// <summary>
/// The signed timestamp policy (spec §5). <c>throughput</c> signs and chains
/// every step and timestamps <c>run_end</c>, checkpoints, consequential steps
/// and the cadence; <c>per-event</c> timestamps every step.
/// </summary>
public sealed record AgentTimestampPolicy
{
    /// <summary>"throughput" (default) or "per-event".</summary>
    public string Profile { get; init; } = "throughput";

    /// <summary>Require a timestamp on the N-th step since the last one. 0 = off.</summary>
    public int EveryEvents { get; init; } = 10;

    /// <summary>Require a timestamp on the first step this many seconds after the last one. 0 = off.</summary>
    public int EverySeconds { get; init; } = 300;

    /// <summary>Also timestamp <c>run_start</c>.</summary>
    public bool RunStart { get; init; }

    /// <summary>Every step timestamped: for low-volume, high-consequence agents.</summary>
    public static AgentTimestampPolicy PerEvent { get; } = new() { Profile = "per-event" };

    internal JsonObject ToJson() => new()
    {
        ["profile"] = Profile,
        ["everyEvents"] = EveryEvents,
        ["everySeconds"] = EverySeconds,
        ["runStart"] = RunStart,
        ["runEnd"] = true,
        ["consequential"] = true,
    };
}

/// <summary>Options for <see cref="AgentRun.StartAsync"/>.</summary>
public sealed record AgentRunOptions
{
    /// <summary>The Sigill seal certificate that signs every step.</summary>
    public required Guid CertificateId { get; init; }

    /// <summary>
    /// A previously registered identity record for this exact configuration.
    /// When null, a new one is registered at start. Reuse it across runs
    /// while the configuration is unchanged.
    /// </summary>
    public AgentRunArtifact? Identity { get; init; }

    /// <summary>Opaque identifier of who registers a new identity record. No personal data.</summary>
    public string? RegisteredBy { get; init; }

    public AgentTimestampPolicy TimestampPolicy { get; init; } = new();

    /// <summary>The run identifier (<c>activity.correlationId</c>). Default: a new <c>urn:uuid:</c>.</summary>
    public string? CorrelationId { get; init; }

    /// <summary>Objects bound into <c>run_start</c> after the configuration (e.g. the user's request).</summary>
    public IReadOnlyList<AgentRunObject>? StartObjects { get; init; }

    /// <summary>
    /// Keep payload bytes in memory so <see cref="AgentRun.ToBundle"/> can
    /// include them. Off by default: a digests-only bundle reveals no content.
    /// </summary>
    public bool RetainPayloads { get; init; }

    /// <summary>Request eIDAS-qualified timestamps where a timestamp is required.</summary>
    public bool Qualified { get; init; }

    /// <summary>
    /// Called after each artifact is sealed, in chain order, before the next
    /// step can be sealed — persist it here so a crash loses nothing. An
    /// exception propagates to the caller; the run itself stays usable.
    /// </summary>
    public Func<AgentRunArtifact, CancellationToken, Task>? OnArtifactSealed { get; init; }
}

/// <summary>
/// One sealed artifact of a run (or the identity record): the v2
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

    /// <summary><c>chain.seq</c>, or null for the identity record.</summary>
    public int? Seq => AgentExecutionProfile.Int(Envelope["chain"]?["seq"]);

    /// <summary>The signed step type.</summary>
    public string? StepType => AgentExecutionProfile.Str(Envelope["extensions"]?[AgentExecutionProfile.ExtensionKey]?["stepType"]);

    /// <summary>The artifact's <c>evidenceId</c>.</summary>
    public string? EvidenceId => AgentExecutionProfile.Str(Envelope["evidenceId"]);

    /// <summary>The chain digest the next step links to (spec §4).</summary>
    public string? ChainDigest => AgentExecutionProfile.ChainDigest(Signature);

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
