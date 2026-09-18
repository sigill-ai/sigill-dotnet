// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

namespace Sigill.Sdk.Agent;

/// <summary>
/// Faste verdier for de tre søsterprofilene. Feltnavn og verdier følger
/// realiseringsnotatet kap. 4.2 og 5 som de står; de låses først i TASK-0002.
/// </summary>
public static class AgentProfiles
{
    public const string SchemaVersion = "1";

    public const string ControlArtifactContentType = "application/vnd.sigill.agent-control+json";
    public const string ExecutionEvidenceContentType = "application/vnd.sigill.agent-execution+json";
    public const string ControlEvaluationContentType = "application/vnd.sigill.control-evaluation+json";

    public const string ControlArtifactSchema = "AgentControlArtifact";
    public const string ExecutionEvidenceSchema = "AgentExecutionEvidence";
    public const string ControlEvaluationSchema = "ControlEvaluation";

    public const string EnvelopeUri = AiEvidenceV2Artifact.EnvelopeUri;

    public static class Steps
    {
        public const string RunStart = "run_start";
        public const string Retrieval = "retrieval";
        public const string ToolCall = "tool_call";
        public const string Authorization = "authorization";
        public const string HumanApproval = "human_approval";
        public const string ToolResult = "tool_result";
        public const string ModelOutput = "model_output";
        public const string RunEnd = "run_end";
    }

    public static class Dispositions
    {
        public const string Completed = "completed";
        public const string Aborted = "aborted";
        public const string Failed = "failed";
    }

    public static class Results
    {
        public const string Pass = "PASS";
        public const string Fail = "FAIL";
        public const string Indeterminate = "INDETERMINATE";
    }

    public static class Roles
    {
        public const string InstructionSet = "instruction-set";
        public const string ToolManifest = "tool-manifest";
        public const string ExecutionPolicy = "execution-policy";
        public const string ControlSet = "control-set";
        public const string Authority = "authority";
        public const string BaselineState = "baseline-state";
        public const string ToolArguments = "tool-arguments";
        public const string ToolResult = "tool-result";
        public const string ApprovalReceipt = "approval-receipt";
        public const string IdentityAssertion = "identity-assertion";
        public const string RetrievedContext = "retrieved-context";
        public const string ModelOutput = "model-output";
        public const string ModelInput = "model-input";
        public const string ObservedState = "observed-state";
    }
}
