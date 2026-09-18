// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk.Agent;

/// <summary>FØR: kontrollgrunnlaget forseglet før første hendelse (notatet 5.1).</summary>
public sealed class ControlArtifactBuilder
{
    public required string ActorId { get; init; }
    public string ActorType { get; init; } = "system";
    public required string ActivityName { get; init; }
    public string CorrelationId { get; init; } = $"urn:uuid:{Guid.NewGuid()}";
    public required string AgentId { get; init; }
    public required string AgentVersion { get; init; }
    public string? AgentIdentityRef { get; init; }
    public required string ControlSetId { get; init; }
    public required string ControlSetVersion { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }

    public Task<AgentArtifact> SealAsync(
        IReadOnlyList<DetachedObject> objects,
        IArtifactSealer sealer,
        CancellationToken cancellationToken = default)
    {
        if (objects is null || objects.Count == 0)
            throw new SigillException("Et Control Artifact uten detached objects binder ingenting.");

        var envelope = Envelopes.Core(
            AgentProfiles.ControlArtifactSchema,
            CreatedAt ?? DateTimeOffset.UtcNow,
            new JsonObject { ["id"] = ActorId, ["type"] = ActorType },
            new JsonObject { ["name"] = ActivityName, ["correlationId"] = CorrelationId });

        var agent = new JsonObject { ["id"] = AgentId, ["version"] = AgentVersion };
        if (AgentIdentityRef is not null) agent["identityRef"] = AgentIdentityRef;
        envelope["agent"] = agent;
        envelope["controlSet"] = new JsonObject { ["id"] = ControlSetId, ["version"] = ControlSetVersion };

        return Envelopes.SealAsync(envelope, objects, AgentProfiles.ControlArtifactContentType, sealer, cancellationToken);
    }
}
