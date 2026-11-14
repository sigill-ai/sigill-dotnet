// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>
/// The rules of delivering a run's artifacts to the organisation's evidence index (<see cref="AgentRunOptions.DeliverRun"/>,
/// <see cref="SigillClient.DeliverAgentRunAsync"/>): what an answer means, the timeouts and the back-off. One upload per
/// artifact, in chain order; the index takes an artifact it already has again (<c>exists</c>), so delivery can be repeated.
/// </summary>
internal static class AgentRunIndex
{
    public static readonly TimeSpan UploadTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan FinalBudget = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan FirstBackoff = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan LastBackoff = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The index's answer to one upload; <paramref name="Http"/> is null when no answer arrived (a transport failure or a timeout:
    /// <paramref name="Failure"/> names the exception type, <paramref name="Reason"/> carries its message).
    /// </summary>
    public sealed record Answer(int? Http, string? Code, string? Status, Guid? RunId, string? Reason, string? Failure = null)
    {
        public bool Accepted => Http is >= 200 and < 300;

        /// <summary>A concurrent upload of the same artifact won: try again.</summary>
        public bool Conflict => Http == 409 && Code == "conflict";

        /// <summary>The policy document was refused (and with it the Control Artifact's upload).</summary>
        public bool ControlSetRejected => Http is >= 400 and < 500 && Code is { } c && c.StartsWith("control_set_", StringComparison.Ordinal);

        /// <summary>The index will not take this artifact: no automatic attempt follows. Everything else that fails is held for later.</summary>
        public bool Final => Http is >= 400 and < 500 and not (408 or 429) && !Conflict;

        /// <summary>"&lt;where&gt;: &lt;status&gt; &lt;code or reason phrase&gt;", or for a transport failure "&lt;where&gt;: &lt;exception type&gt;: &lt;message&gt;".</summary>
        public string? ErrorAt(AgentRunArtifact artifact)
        {
            if (Accepted) return null;
            var where = artifact.Seq is { } seq ? $"seq {seq}" : "control artifact";
            return Http is { } h ? $"{where}: {h} {Code ?? Reason}" : $"{where}: {Failure}: {Reason}";
        }
    }

    /// <summary>One artifact: uploaded, and once more when a concurrent upload of it won.</summary>
    public static async Task<Answer> UploadAsync(SigillClient client, AgentRunArtifact artifact, byte[]? controlSetDocument,
        CancellationToken ct, CancellationToken budget = default)
    {
        var answer = await client.IndexUploadAsync(artifact, controlSetDocument, ct, budget).ConfigureAwait(false);
        return answer.Conflict ? await client.IndexUploadAsync(artifact, controlSetDocument, ct, budget).ConfigureAwait(false) : answer;
    }
}
