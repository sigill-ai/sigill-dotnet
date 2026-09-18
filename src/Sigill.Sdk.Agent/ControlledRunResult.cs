// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Collections.Generic;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent;

/// <summary>
/// Resultatflaten fra notatet 6.1. Feltnavnene er beholdt for sporbarhet til
/// notatet; i prosa brukes «utfall». Verdiene er små strenger, ikke enum-er,
/// så resultatet kan serialiseres rett ut til en klient.
/// </summary>
public sealed class ControlledRunResult
{
    /// <summary>verified | missing | invalid</summary>
    public required string ControlArtifact { get; init; }
    /// <summary>run_finalized | run_open | run_invalid</summary>
    public required string RunVerdict { get; init; }
    public required bool ChainValid { get; init; }
    /// <summary>Null når ingen platform var tilgjengelig for signaturkontroll.</summary>
    public required bool? SignaturesValid { get; init; }
    /// <summary>Ikke kontrollert i prøvekjøringen; alltid null.</summary>
    public required bool? TimestampsValid { get; init; }
    public required bool ObjectsComplete { get; init; }
    public required IReadOnlyList<string> MissingObjects { get; init; }
    /// <summary>bound | control_only | run_only | unbound</summary>
    public required string Binding { get; init; }
    public required IReadOnlyList<EvaluationResult> Evaluations { get; init; }
    public required IReadOnlyList<string> ForeignArtifacts { get; init; }
    public required IReadOnlyList<string> Issues { get; init; }
    public string? CorrelationId { get; init; }
    public int? FinalSeq { get; init; }
    public string? RunDisposition { get; init; }
}

public sealed class EvaluationResult
{
    public required string EvidenceId { get; init; }
    public required string? Verifier { get; init; }
    public required string? VerifierVersion { get; init; }
    public required string? Overall { get; init; }
    public required JsonArray Controls { get; init; }
    public required bool SubjectBound { get; init; }
    /// <summary>Null når kontrollsettet ikke er levert som objekt i begge artefakter.</summary>
    public required bool? ControlSetDigestMatches { get; init; }
}

public static class RunVerdicts
{
    public const string Finalized = "run_finalized";
    public const string Open = "run_open";
    public const string Invalid = "run_invalid";
}

public static class Bindings
{
    public const string Bound = "bound";
    public const string ControlOnly = "control_only";
    public const string RunOnly = "run_only";
    public const string Unbound = "unbound";
}
