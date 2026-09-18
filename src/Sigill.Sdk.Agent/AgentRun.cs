// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk.Agent;

/// <summary>
/// UNDER: ett artefakt per hendelse, lenket med <c>chain.seq</c> og
/// <c>prevSignatureSha256</c>, bundet til Control Artifact i <c>run_start</c>
/// og lukket med <c>run_end</c> (notatet 5.2 og 4.3). Lever i én prosess;
/// gjenopptak fra lagret tilstand er utenfor prøvekjøringen.
/// </summary>
public sealed class AgentRun
{
    private readonly IArtifactSealer _sealer;
    private readonly string _actorId;
    private readonly string _actorType;
    private readonly List<AgentArtifact> _artifacts = new();
    private readonly object _gate = new();
    private bool _sealing;

    public AgentRun(IArtifactSealer sealer, string activityName, string correlationId, string actorId, string actorType = "agent")
    {
        _sealer = sealer ?? throw new ArgumentNullException(nameof(sealer));
        if (string.IsNullOrWhiteSpace(activityName)) throw new ArgumentException("activityName er påkrevd.", nameof(activityName));
        if (string.IsNullOrWhiteSpace(correlationId)) throw new ArgumentException("correlationId er påkrevd.", nameof(correlationId));
        if (string.IsNullOrWhiteSpace(actorId)) throw new ArgumentException("actorId er påkrevd.", nameof(actorId));
        ActivityName = activityName;
        CorrelationId = correlationId;
        _actorId = actorId;
        _actorType = actorType;
    }

    public string ActivityName { get; }
    public string CorrelationId { get; }
    public int NextSeq { get; private set; }
    public string? PrevSignatureSha256 { get; private set; }
    public string? ControlArtifactSignatureSha256 { get; private set; }
    public bool Started => NextSeq > 0;
    public bool Finished { get; private set; }
    public IReadOnlyList<AgentArtifact> Artifacts => _artifacts;

    public Task<AgentArtifact> StartAsync(AgentArtifact controlArtifact, DateTimeOffset eventTime, CancellationToken cancellationToken = default)
    {
        if (controlArtifact is null) throw new ArgumentNullException(nameof(controlArtifact));
        if (Started) throw new SigillException("Kjøringen er allerede startet.");
        if (!string.Equals(controlArtifact.ContentType, AgentProfiles.ControlArtifactContentType, StringComparison.Ordinal))
            throw new SigillException($"run_start må binde et Control Artifact, ikke '{controlArtifact.ContentType ?? "ukjent"}'.");
        if (!string.Equals(controlArtifact.CorrelationId, CorrelationId, StringComparison.Ordinal))
            throw new SigillException("Control Artifact har en annen correlationId enn kjøringen.");

        var binds = controlArtifact.SignatureSha256;
        var step = new JsonObject { ["type"] = AgentProfiles.Steps.RunStart, ["eventTime"] = Json.Timestamp(eventTime) };
        return SealStepAsync(step, binds, Array.Empty<DetachedObject>(), eventTime, cancellationToken);
    }

    public Task<AgentArtifact> RecordAsync(
        string stepType,
        DateTimeOffset eventTime,
        JsonObject? stepDetails = null,
        IReadOnlyList<DetachedObject>? objects = null,
        CancellationToken cancellationToken = default)
    {
        if (!Started) throw new SigillException("Kall StartAsync før hendelser registreres.");
        if (Finished) throw new SigillException("Kjøringen er avsluttet; ingen flere hendelser kan registreres.");
        if (stepType is AgentProfiles.Steps.RunStart or AgentProfiles.Steps.RunEnd)
            throw new SigillException($"'{stepType}' registreres gjennom StartAsync og FinishAsync.");
        if (stepType is not (AgentProfiles.Steps.Retrieval or AgentProfiles.Steps.ToolCall or AgentProfiles.Steps.Authorization
            or AgentProfiles.Steps.HumanApproval or AgentProfiles.Steps.ToolResult or AgentProfiles.Steps.ModelOutput))
            throw new SigillException($"Ukjent hendelsestype '{stepType}'.");

        var step = new JsonObject { ["type"] = stepType, ["eventTime"] = Json.Timestamp(eventTime) };
        if (stepDetails is not null)
            foreach (var pair in stepDetails)
                if (pair.Key is not ("type" or "eventTime")) step[pair.Key] = pair.Value?.DeepClone();

        return SealStepAsync(step, ControlArtifactSignatureSha256!, objects ?? Array.Empty<DetachedObject>(), eventTime, cancellationToken);
    }

    public Task<AgentArtifact> FinishAsync(string runDisposition, DateTimeOffset eventTime, CancellationToken cancellationToken = default)
    {
        if (!Started) throw new SigillException("Kjøringen er ikke startet.");
        if (Finished) throw new SigillException("Kjøringen er allerede avsluttet.");
        if (runDisposition is not (AgentProfiles.Dispositions.Completed or AgentProfiles.Dispositions.Aborted or AgentProfiles.Dispositions.Failed))
            throw new SigillException($"Ugyldig runDisposition '{runDisposition}'.");

        var step = new JsonObject
        {
            ["type"] = AgentProfiles.Steps.RunEnd,
            ["eventTime"] = Json.Timestamp(eventTime),
            ["finalSeq"] = NextSeq,
            ["finalPrevSignatureSha256"] = PrevSignatureSha256,
            ["runDisposition"] = runDisposition,
        };
        return SealStepAsync(step, ControlArtifactSignatureSha256!, Array.Empty<DetachedObject>(), eventTime, cancellationToken, finishes: true);
    }

    private async Task<AgentArtifact> SealStepAsync(
        JsonObject step, string controlArtifactSignatureSha256, IReadOnlyList<DetachedObject> objects,
        DateTimeOffset createdAt, CancellationToken cancellationToken, bool finishes = false)
    {
        lock (_gate)
        {
            if (_sealing) throw new SigillException("En hendelse forsegles allerede; hendelser i samme kjøring registreres én om gangen.");
            _sealing = true;
        }
        try
        {
            var seq = NextSeq;
            var chain = new JsonObject { ["seq"] = seq };
            if (seq > 0) chain["prevSignatureSha256"] = PrevSignatureSha256;

            var envelope = Envelopes.Core(
                AgentProfiles.ExecutionEvidenceSchema,
                createdAt,
                new JsonObject { ["id"] = _actorId, ["type"] = _actorType },
                new JsonObject { ["name"] = ActivityName, ["correlationId"] = CorrelationId });
            envelope["chain"] = chain;
            envelope["step"] = step;
            envelope["binds"] = new JsonObject { ["controlArtifactSignatureSha256"] = controlArtifactSignatureSha256 };

            var artifact = await Envelopes.SealAsync(
                envelope, objects, AgentProfiles.ExecutionEvidenceContentType, _sealer, cancellationToken).ConfigureAwait(false);

            // Tilstanden flyttes først når forseglingen lyktes; en feil lager aldri hull.
            PrevSignatureSha256 = artifact.SignatureSha256;
            ControlArtifactSignatureSha256 = controlArtifactSignatureSha256;
            NextSeq = seq + 1;
            if (finishes) Finished = true;
            _artifacts.Add(artifact);
            return artifact;
        }
        finally
        {
            lock (_gate) _sealing = false;
        }
    }
}
