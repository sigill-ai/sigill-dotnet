// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk.Agent;

public sealed record ControlResult(string Id, string Result, string? Detail = null);

/// <summary>
/// ETTER: verifierens kontrollresultat, bundet til run_end og Control
/// Artifact (notatet 5.3). Byggeren regner ikke ut <c>overall</c>; verifieren
/// påstår, SDK-et forsegler.
/// </summary>
public sealed class ControlEvaluationBuilder
{
    public required string VerifierId { get; init; }
    public required string VerifierVersion { get; init; }
    public required string ActivityName { get; init; }
    public required string CorrelationId { get; init; }
    public required string RunEndSignatureSha256 { get; init; }
    public required string ControlArtifactSignatureSha256 { get; init; }
    public required string ControlSetId { get; init; }
    public required string ControlSetVersion { get; init; }
    public required IReadOnlyList<ControlResult> Controls { get; init; }
    public required string Overall { get; init; }
    public required DateTimeOffset EvaluatedAt { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }

    public Task<AgentArtifact> SealAsync(
        DetachedObject observedState,
        DetachedObject controlSet,
        IArtifactSealer sealer,
        CancellationToken cancellationToken = default)
    {
        if (observedState is null) throw new ArgumentNullException(nameof(observedState));
        if (controlSet is null) throw new ArgumentNullException(nameof(controlSet));
        if (observedState.Role != AgentProfiles.Roles.ObservedState)
            throw new SigillException($"Observert tilstand må ha rollen '{AgentProfiles.Roles.ObservedState}'.");
        if (controlSet.Role != AgentProfiles.Roles.ControlSet)
            throw new SigillException($"Kontrollsettet må ha rollen '{AgentProfiles.Roles.ControlSet}'.");
        if (!IsResult(Overall)) throw new SigillException($"Ugyldig overall '{Overall}'.");
        if (Controls.Count == 0) throw new SigillException("En evaluering uten kontroller sier ingenting.");
        foreach (var control in Controls)
            if (!IsResult(control.Result)) throw new SigillException($"Ugyldig resultat '{control.Result}' for kontrollen '{control.Id}'.");

        var envelope = Envelopes.Core(
            AgentProfiles.ControlEvaluationSchema,
            CreatedAt ?? DateTimeOffset.UtcNow,
            new JsonObject { ["id"] = VerifierId, ["type"] = "verifier", ["version"] = VerifierVersion },
            new JsonObject { ["name"] = ActivityName, ["correlationId"] = CorrelationId });
        envelope["subject"] = new JsonObject
        {
            ["runEndSignatureSha256"] = RunEndSignatureSha256,
            ["controlArtifactSignatureSha256"] = ControlArtifactSignatureSha256,
        };
        envelope["controlSet"] = new JsonObject { ["id"] = ControlSetId, ["version"] = ControlSetVersion };
        envelope["controls"] = new JsonArray(Controls.Select(c =>
        {
            var node = new JsonObject { ["id"] = c.Id, ["result"] = c.Result };
            if (c.Detail is not null) node["detail"] = c.Detail;
            return (JsonNode)node;
        }).ToArray());
        envelope["overall"] = Overall;
        envelope["evaluatedAt"] = Json.Timestamp(EvaluatedAt);

        return Envelopes.SealAsync(
            envelope, new[] { observedState, controlSet }, AgentProfiles.ControlEvaluationContentType, sealer, cancellationToken);
    }

    private static bool IsResult(string value) =>
        value is AgentProfiles.Results.Pass or AgentProfiles.Results.Fail or AgentProfiles.Results.Indeterminate;
}
