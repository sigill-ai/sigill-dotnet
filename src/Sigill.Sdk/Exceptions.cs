// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;

namespace Sigill.Sdk;

/// <summary>Base class for all errors raised by the Sigill SDK.</summary>
public class SigillException : Exception
{
    public SigillException(string message) : base(message) { }
    public SigillException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// A policy engine (<see cref="IPolicyEngine"/>) could not be loaded, or could not answer a call (for example a trap
/// inside the engine, or its memory limit reached). A call the engine answers with <c>"type": "failure"</c> is an answer,
/// not this exception, except that <see cref="AgentPolicy.Evaluate"/> raises it for one, with <see cref="Refused"/> set.
/// </summary>
public sealed class PolicyEngineException : SigillException
{
    public PolicyEngineException(string message) : base(message) { }
    public PolicyEngineException(string message, Exception inner) : base(message, inner) { }

    /// <summary>A request refused by the engine: <see cref="Refused"/> is true.</summary>
    public PolicyEngineException(string message, bool refused) : base(message) => Refused = refused;

    /// <summary>
    /// True when the engine answered and refused a request (<c>type: failure</c>, raised by <see cref="AgentPolicy.Evaluate"/>):
    /// the policy or request cannot be evaluated at all. False for a trap, a load failure or any other failure of the engine.
    /// </summary>
    public bool Refused { get; }
}

/// <summary>
/// The guard denied a tool call (<c>spec/agent-policy-control-set-v2.md</c> §7.2): the <c>tool_call</c> and the enforcement
/// record are sealed, and so is <c>run_end</c> when the denial halts the run. Do not run the tool; a retry is a new call with
/// a new use id. Raised after the evidence is sealed; an <see cref="AgentEnforcement.OnEvent"/> or
/// <see cref="AgentRunOptions.OnArtifactSealed"/> failure is its <see cref="Exception.InnerException"/>.
/// </summary>
public sealed class PolicyDeniedException : SigillException
{
    internal PolicyDeniedException(string reason, IReadOnlyList<string> rules, string tool, string useId, int seq, AgentRunArtifact record,
        bool halted, Exception? inner)
        : base($"The policy denied the call of tool '{tool}' (use_id '{useId}', seq {seq}): {EnforcementText.Describe(reason, rules)}"
            + (halted ? "; the run is halted." : "."), inner!)
    {
        Reason = reason;
        Rules = rules;
        Tool = tool;
        UseId = useId;
        Seq = seq;
        Record = record;
        Halted = halted;
    }

    /// <summary><c>rule</c>, <c>rule_error</c>, <c>unknown_tool</c>, <c>tool_changed</c> or <c>unavailable</c>.</summary>
    public string Reason { get; }

    /// <summary>The record's rule ids (empty unless the reason is <c>rule</c> or <c>rule_error</c>).</summary>
    public IReadOnlyList<string> Rules { get; }

    public string Tool { get; }
    public string UseId { get; }

    /// <summary>The seq of the denied <c>tool_call</c>.</summary>
    public int Seq { get; }

    /// <summary>The sealed enforcement record.</summary>
    public AgentRunArtifact Record { get; }

    /// <summary>The denial also halted the run.</summary>
    public bool Halted { get; }
}

/// <summary>
/// The run is halted (<c>spec/agent-policy-control-set-v2.md</c> §7): raised by the recording call whose event the guard
/// halted the run after, once the record and <c>run_end</c> are sealed, and by every later recording call. The properties name
/// the decision that halted the run. <see cref="AgentRun.FinishAsync"/> still returns the bundle.
/// </summary>
public sealed class RunHaltedException : SigillException
{
    internal RunHaltedException(string reason, IReadOnlyList<string> rules, int seq, AgentRunArtifact record, Exception? inner = null)
        : base($"The policy halted the run at seq {seq}: {EnforcementText.Describe(reason, rules)}.", inner!)
    {
        Reason = reason;
        Rules = rules;
        Seq = seq;
        Record = record;
    }

    public string Reason { get; }
    public IReadOnlyList<string> Rules { get; }

    /// <summary>The seq of the event the run was halted after.</summary>
    public int Seq { get; }

    /// <summary>The sealed enforcement record.</summary>
    public AgentRunArtifact Record { get; }
}

/// <summary>
/// The guard refused to start the run (<c>spec/agent-policy-control-set-v2.md</c> §7.4): the Control Artifact,
/// <c>run_start</c>, the enforcement record and a halted <c>run_end</c> are sealed. <see cref="Run"/> is the closed run.
/// </summary>
public sealed class StartRefusedException : SigillException
{
    internal StartRefusedException(string reason, IReadOnlyList<string> rules, AgentRun run, Exception? inner)
        : base($"The policy refused the start of the run: reason {reason}.", inner!)
    {
        Reason = reason;
        Run = run;
    }

    /// <summary><c>configuration_locked</c>, <c>unavailable</c> or <c>rule</c> (a halt rule on <c>run_start</c>).</summary>
    public string Reason { get; }

    /// <summary>The halted run; <see cref="AgentRun.FinishAsync"/> or <see cref="AgentRun.ToBundle"/> gives its bundle.</summary>
    public AgentRun Run { get; }
}

internal static class EnforcementText
{
    /// <summary>The reason and rule ids of a decision (the Python port's text): never arguments, results or definitions.</summary>
    public static string Describe(string reason, IReadOnlyList<string> rules) =>
        $"reason {reason}" + (rules.Count > 0 ? $", rules {string.Join(", ", rules)}" : "");
}

/// <summary>
/// The envelope cannot be canonicalized. Typical causes: input contains values
/// JCS rejects (NaN, Infinity), the top-level value is not an object, or the
/// JSON is malformed.
/// </summary>
public sealed class SigillCanonicalizationException : SigillException
{
    public SigillCanonicalizationException(string message) : base(message) { }
    public SigillCanonicalizationException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// A pre-declared payload hash does not match the supplied bytes. Raised at
/// <see cref="SigillClient.SealAsync(AiEvidenceEnvelopeInput, IReadOnlyDictionary{string, byte[]}?, SealOptions?, System.Threading.CancellationToken)"/> time.
///
/// During verification, hash mismatches are reported as
/// <see cref="VerificationIssue"/> entries inside an
/// <see cref="AiEvidenceVerificationResult"/> rather than thrown.
/// </summary>
public sealed class SigillHashMismatchException : SigillException
{
    public string Reference { get; }
    public string Expected { get; }
    public string Actual { get; }

    public SigillHashMismatchException(string @ref, string expected, string actual)
        : base($"Pre-declared hash for ref '{@ref}' ({expected}) does not match supplied bytes ({actual})")
    {
        Reference = @ref;
        Expected = expected;
        Actual = actual;
    }
}

/// <summary>A proof (e.g. RFC 3161 TSR) cannot be parsed or its signature is invalid.</summary>
public sealed class SigillInvalidProofException : SigillException
{
    public SigillInvalidProofException(string message) : base(message) { }
    public SigillInvalidProofException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// Sigill returned 502 — every TSA in the auto-rotation failed. The structured
/// failure list is on <see cref="Failures"/>. The envelope was NOT sealed; the
/// caller decides whether to retry, fall back, or surface to a human.
/// </summary>
public sealed class SigillTimestampUnavailableException : SigillException
{
    public IReadOnlyList<TsaFailure> Failures { get; }
    public int AttemptsTried { get; }

    public SigillTimestampUnavailableException(string message, IReadOnlyList<TsaFailure> failures, int attempts)
        : base(message)
    {
        Failures = failures;
        AttemptsTried = attempts;
    }
}

/// <summary>
/// The local PDF parser cannot handle this PDF's structure (e.g. an object
/// stream with an exotic filter or /Predictor, or a pathological page tree).
/// The document is fine — it just needs the server-side path: upload it to
/// <c>POST /seal/sign</c>, either manually or by opting in to
/// <see cref="PadesSealOptions.AllowUploadFallback"/>. Note that path
/// transmits the PDF to Sigill; by default the SDK never does so.
/// </summary>
public sealed class SigillPdfUnsupportedException : SigillException
{
    public SigillPdfUnsupportedException(string message, Exception inner)
        : base(message + " — this PDF's structure is not supported by local (hash-only) sealing. " +
               "Seal it server-side via POST /seal/sign, or opt in with PadesSealOptions.AllowUploadFallback " +
               "(that path transmits the PDF to Sigill).", inner) { }
}

/// <summary>One entry in the failure list returned by Sigill on a 502.</summary>
public sealed record TsaFailure(
    string Tsa,
    string ErrorClass,
    int? StatusCode,
    string Message,
    long LatencyMs);

/// <summary>
/// Marker type for the inline-content privacy advisory.
///
/// <see cref="EnvelopeBuilder.WithPromptInline"/> and <see cref="EnvelopeBuilder.WithOutputInline"/>
/// carry <c>[Obsolete]</c> (CS0618) to warn that content is transmitted to Sigill.
/// For sensitive content, use <see cref="EnvelopeBuilder.WithPromptRef"/> /
/// <see cref="EnvelopeBuilder.WithOutputRef"/> and supply the raw bytes via
/// <c>externalPayloads</c> at seal time — Sigill will only see the hash.
///
/// Suppress with <c>#pragma warning disable CS0618</c> when inline content is genuinely non-sensitive.
/// </summary>
public sealed class InlineContentWarning { }
