// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk.Agent;

/// <summary>
/// Avgjør om et sett artefakter er en komplett, uendret og bundet kjøring,
/// i kontrollrekkefølgen fra notatet 6.2. Evaluerer aldri kontrollene selv.
/// Med en platformklient kontrolleres signaturene der; uten kontrolleres kun
/// det som kan avledes lokalt fra signaturens sigD og de leverte objektene.
/// </summary>
public sealed class ControlledRunVerifier
{
    private readonly ISigillAiEvidenceClient? _platform;

    public ControlledRunVerifier(ISigillAiEvidenceClient? platform = null)
    {
        _platform = platform;
    }

    public async Task<ControlledRunResult> VerifyAsync(
        IReadOnlyList<AgentArtifact> artifacts,
        IReadOnlyDictionary<string, byte[]> payloads,
        CancellationToken cancellationToken = default)
    {
        if (artifacts is null) throw new ArgumentNullException(nameof(artifacts));
        payloads ??= new Dictionary<string, byte[]>();
        var issues = new List<string>();

        // Steg 1 og 2: signatur og fullstendighet per artefakt.
        var status = new Dictionary<AgentArtifact, ArtifactStatus>();
        foreach (var artifact in artifacts)
            status[artifact] = await CheckArtifactAsync(artifact, payloads, cancellationToken).ConfigureAwait(false);

        var missingObjects = status.Values.SelectMany(s => s.Missing).Distinct(StringComparer.Ordinal).ToList();
        var objectsComplete = status.Values.All(s => s.Complete);
        bool? signaturesValid = _platform is null ? null : status.Values.All(s => s.SignatureValid == true);
        foreach (var pair in status.Where(p => !p.Value.EnvelopeMatchesSignature))
            issues.Add($"Konvolutten i {Label(pair.Key)} matcher ikke hashV[0] i signaturen.");

        // Steg 3: klassifiser og grupper på correlationId.
        var controls = artifacts.Where(a => a.ContentType == AgentProfiles.ControlArtifactContentType).ToList();
        var executions = artifacts.Where(a => a.ContentType == AgentProfiles.ExecutionEvidenceContentType).ToList();
        var evaluations = artifacts.Where(a => a.ContentType == AgentProfiles.ControlEvaluationContentType).ToList();
        foreach (var unknown in artifacts.Except(controls).Except(executions).Except(evaluations))
            issues.Add($"{Label(unknown)} har ukjent profil '{unknown.ContentType ?? "ingen"}'.");

        var correlationId = executions.FirstOrDefault(a => a.StepType == AgentProfiles.Steps.RunStart)?.CorrelationId
            ?? executions.FirstOrDefault()?.CorrelationId
            ?? controls.FirstOrDefault()?.CorrelationId;
        var foreign = new List<string>();
        foreach (var a in executions.Concat(evaluations).Concat(controls).Where(a => a.CorrelationId != correlationId))
            foreign.Add(Label(a));
        executions = executions.Where(a => a.CorrelationId == correlationId).OrderBy(a => a.Seq ?? int.MaxValue).ToList();
        evaluations = evaluations.Where(a => a.CorrelationId == correlationId).ToList();
        controls = controls.Where(a => a.CorrelationId == correlationId).ToList();
        if (foreign.Count > 0) issues.Add($"{foreign.Count} artefakt(er) med annen correlationId er holdt utenfor.");

        // Steg 4: kjeden.
        var chainValid = executions.Count > 0;
        for (var i = 0; i < executions.Count; i++)
        {
            var a = executions[i];
            if (a.Seq != i) { chainValid = false; issues.Add($"Forventet seq {i}, fant {a.Seq?.ToString() ?? "ingen"} i {Label(a)}."); }
            if (i == 0)
            {
                if (a.StepType != AgentProfiles.Steps.RunStart) { chainValid = false; issues.Add("Første hendelse er ikke run_start."); }
                if (a.PrevSignatureSha256 is not null) { chainValid = false; issues.Add("run_start har prevSignatureSha256; skal være fraværende."); }
                continue;
            }
            var expected = executions[i - 1].SignatureSha256;
            if (!string.Equals(a.PrevSignatureSha256, expected, StringComparison.Ordinal))
            {
                chainValid = false;
                issues.Add($"prevSignatureSha256 i seq {a.Seq} matcher ikke signaturen til seq {executions[i - 1].Seq}.");
            }
        }
        if (executions.Count == 0) issues.Add("Ingen Execution Evidence funnet.");

        // Steg 5: run_end.
        var runEnd = executions.LastOrDefault(a => a.StepType == AgentProfiles.Steps.RunEnd);
        var runEndValid = runEnd is not null;
        if (runEnd is not null)
        {
            var last = executions[executions.Count - 1];
            if (!ReferenceEquals(runEnd, last)) { runEndValid = false; issues.Add("Det finnes hendelser etter run_end."); }
            var finalSeq = Json.ReadInt(runEnd.Envelope["step"]?["finalSeq"]);
            if (finalSeq != runEnd.Seq) { runEndValid = false; issues.Add($"finalSeq {finalSeq?.ToString() ?? "mangler"} matcher ikke run_end sin seq {runEnd.Seq}."); }
            var finalPrev = Json.ReadString(runEnd.Envelope["step"]?["finalPrevSignatureSha256"]);
            var secondToLast = executions.Count >= 2 ? executions[executions.Count - 2].SignatureSha256 : null;
            if (!string.Equals(finalPrev, secondToLast, StringComparison.Ordinal)) { runEndValid = false; issues.Add("finalPrevSignatureSha256 matcher ikke nest siste artefakt."); }
        }
        var stepsFailed = !objectsComplete || signaturesValid == false || !chainValid
            || status.Values.Any(s => !s.EnvelopeMatchesSignature) || (runEnd is not null && !runEndValid);
        var runVerdict = stepsFailed ? RunVerdicts.Invalid : runEnd is null ? RunVerdicts.Open : RunVerdicts.Finalized;

        // Steg 6: binding til kontrollgrunnlaget.
        var runStart = executions.FirstOrDefault(a => a.StepType == AgentProfiles.Steps.RunStart);
        var bindsTo = Json.ReadString(runStart?.Envelope["binds"]?["controlArtifactSignatureSha256"]);
        var boundControl = controls.FirstOrDefault(c => string.Equals(c.SignatureSha256, bindsTo, StringComparison.Ordinal));
        var binding = executions.Count > 0
            ? (boundControl is not null ? Bindings.Bound : Bindings.RunOnly)
            : (controls.Count > 0 ? Bindings.ControlOnly : Bindings.Unbound);
        if (binding == Bindings.RunOnly) issues.Add("run_start binder et Control Artifact som ikke er levert.");

        // Steg 7: seal-tid som forsvar i dybden. Bindingen i steg 6 beviser at Control
        // Artifact fantes før run_start ble signert; en TSA-tid som sier noe annet er en
        // feil hos platform eller TSA, ikke hos produsenten, og endrer ikke utfallet.
        // Toleranse: TSTInfo accuracy der den er oppgitt, og hele sekunder fordi
        // TSA-ene i poolen gir ulik presisjon (vektor 10: seks TSA-er, 36.113 mot 36).
        bool? controlSealedBeforeRun = null;
        if (boundControl is not null && runStart is not null)
        {
            if (boundControl.SealTime is null || runStart.SealTime is null)
                issues.Add("Seal-tid (sigTst) mangler på Control Artifact eller run_start; tidsrekkefølgen kan ikke kontrolleres.");
            else
            {
                var controlEarliest = Seconds(boundControl.SealTime - (boundControl.SealAccuracy ?? TimeSpan.Zero));
                var runLatest = Seconds(runStart.SealTime + (runStart.SealAccuracy ?? TimeSpan.Zero));
                controlSealedBeforeRun = controlEarliest <= runLatest;
                if (controlSealedBeforeRun == false)
                    issues.Add($"TSA-tiden på Control Artifact ({boundControl.SealTime:O}) ligger etter run_start ({runStart.SealTime:O}) selv om run_start binder dens signatur: avvik hos platform eller TSA.");
            }
        }
        var controlArtifact = controls.Count == 0 ? "missing"
            : controls.All(c => status[c].Complete && status[c].SignatureValid != false && status[c].EnvelopeMatchesSignature) ? "verified"
            : "invalid";

        // Steg 7: evalueringene gjengis, bindes, og kontrollsettets digest sammenlignes.
        var controlSetHash = boundControl is null ? null : HashOfRole(boundControl, AgentProfiles.Roles.ControlSet);
        var evaluationResults = new List<EvaluationResult>();
        foreach (var evaluation in evaluations)
        {
            var subject = evaluation.Envelope["subject"] as JsonObject;
            var subjectBound = runEnd is not null && boundControl is not null
                && string.Equals(Json.ReadString(subject?["runEndSignatureSha256"]), runEnd.SignatureSha256, StringComparison.Ordinal)
                && string.Equals(Json.ReadString(subject?["controlArtifactSignatureSha256"]), boundControl.SignatureSha256, StringComparison.Ordinal);
            var evaluationControlSetHash = HashOfRole(evaluation, AgentProfiles.Roles.ControlSet);
            bool? digestMatches = controlSetHash is null || evaluationControlSetHash is null
                ? null
                : string.Equals(controlSetHash, evaluationControlSetHash, StringComparison.Ordinal);
            if (!subjectBound) issues.Add($"Evalueringen {Label(evaluation)} er ikke bundet til denne kjøringens run_end og Control Artifact.");
            if (digestMatches == false) issues.Add($"Kontrollsettet i {Label(evaluation)} har en annen digest enn i Control Artifact.");
            evaluationResults.Add(new EvaluationResult
            {
                EvidenceId = Json.ReadString(evaluation.Envelope["evidenceId"]) ?? "",
                Verifier = Json.ReadString(evaluation.Envelope["actor"]?["id"]),
                VerifierVersion = Json.ReadString(evaluation.Envelope["actor"]?["version"]),
                Overall = Json.ReadString(evaluation.Envelope["overall"]),
                Controls = evaluation.Envelope["controls"]?.DeepClone() as JsonArray ?? new JsonArray(),
                SubjectBound = subjectBound,
                ControlSetDigestMatches = digestMatches,
            });
        }

        return new ControlledRunResult
        {
            ControlArtifact = controlArtifact,
            RunVerdict = runVerdict,
            ChainValid = chainValid,
            SignaturesValid = signaturesValid,
            TimestampsValid = null,
            ObjectsComplete = objectsComplete,
            MissingObjects = missingObjects,
            Binding = binding,
            ControlSealedBeforeRun = controlSealedBeforeRun,
            Evaluations = evaluationResults,
            ForeignArtifacts = foreign,
            Issues = issues,
            CorrelationId = correlationId,
            FinalSeq = runEnd?.Seq,
            RunDisposition = Json.ReadString(runEnd?.Envelope["step"]?["runDisposition"]),
        };
    }

    private async Task<ArtifactStatus> CheckArtifactAsync(
        AgentArtifact artifact, IReadOnlyDictionary<string, byte[]> payloads, CancellationToken cancellationToken)
    {
        var signed = artifact.SignedObjects;
        var envelopeEntry = signed.FirstOrDefault(o => o.Uri == AgentProfiles.EnvelopeUri);
        var envelopeMatches = envelopeEntry is not null
            && string.Equals(envelopeEntry.HashHex, artifact.EnvelopeHashHex, StringComparison.Ordinal);

        var missing = new List<string>();
        foreach (var o in signed.Where(o => o.Uri != AgentProfiles.EnvelopeUri))
        {
            if (!payloads.TryGetValue(o.Uri, out var bytes)
                || !string.Equals(EnvelopeHashing.HashHex(bytes), o.HashHex, StringComparison.Ordinal))
                missing.Add(o.Uri);
        }

        if (_platform is null)
            return new ArtifactStatus(envelopeMatches, signed.Count > 0 && missing.Count == 0, null, missing);

        var digests = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AgentProfiles.EnvelopeUri] = artifact.EnvelopeHashHex,
        };
        foreach (var o in signed.Where(o => o.Uri != AgentProfiles.EnvelopeUri))
            if (payloads.TryGetValue(o.Uri, out var bytes)) digests[o.Uri] = EnvelopeHashing.HashHex(bytes);

        var result = await _platform.VerifyObjectHashesAsync(artifact.Signature, digests, null, null, cancellationToken)
            .ConfigureAwait(false);
        var platformMissing = result.Missing.Concat(result.Objects.Where(o => o.Supplied && !o.HashMatch).Select(o => o.Uri));
        return new ArtifactStatus(
            envelopeMatches,
            result.Complete,
            result.SignatureValid,
            missing.Concat(platformMissing).Distinct(StringComparer.Ordinal).ToList());
    }

    private static long Seconds(DateTimeOffset? time) => time!.Value.ToUnixTimeSeconds();

    private static string? HashOfRole(AgentArtifact artifact, string role)
    {
        var uri = artifact.UriOfRole(role);
        return uri is null ? null : artifact.SignedObjects.FirstOrDefault(o => o.Uri == uri)?.HashHex;
    }

    private static string Label(AgentArtifact a) =>
        a.StepType is not null ? $"{a.StepType} (seq {a.Seq?.ToString() ?? "?"})"
        : a.SchemaName ?? a.ContentType ?? "artefakt";

    private sealed record ArtifactStatus(bool EnvelopeMatchesSignature, bool Complete, bool? SignatureValid, IReadOnlyList<string> Missing);
}
