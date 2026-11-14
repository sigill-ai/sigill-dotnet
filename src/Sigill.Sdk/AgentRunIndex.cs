// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>
/// The rules of delivering a run's artifacts to the organisation's evidence index (<see cref="AgentRunOptions.DeliverRun"/>,
/// <see cref="SigillClient.DeliverAgentRunAsync"/>): what an answer means, the time limits and the back-off. One upload per
/// artifact, in chain order; the index takes an artifact it already has again (<c>exists</c>), so delivery can be repeated.
/// </summary>
internal static class AgentRunIndex
{
    /// <summary>The time limits of a run's delivery. Tests use shorter ones.</summary>
    /// <param name="Upload">One upload, from the request to the end of the answer.</param>
    /// <param name="Turn">Every upload of an ordinary turn together.</param>
    /// <param name="Final">Every upload of the final turn together (<c>run_end</c>, finishing a halted run).</param>
    public sealed record Limits(TimeSpan Upload, TimeSpan Turn, TimeSpan Final)
    {
        public static readonly Limits Default = new(UploadTimeout, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30));
    }

    public static readonly TimeSpan UploadTimeout = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan FirstBackoff = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan LastBackoff = TimeSpan.FromMinutes(5);

    /// <summary>At most this much of an answer's body is read; a longer one is not an answer of the index.</summary>
    public const int MaxAnswerBytes = 64 * 1024;

    /// <summary>The words of an answer this SDK cannot read as the index's.</summary>
    public const string UnexpectedResponse = "unexpected_response";

    private static readonly Regex CodePattern = new(@"^[a-z0-9_]{1,64}\z", RegexOptions.CultureInvariant);

    /// <summary>A monotonic clock for the back-off (it does not move with the wall clock).</summary>
    public static TimeSpan Monotonic() => TimeSpan.FromSeconds(Stopwatch.GetTimestamp() / (double)Stopwatch.Frequency);

    /// <summary>
    /// The index's answer to one upload. <paramref name="Http"/> is null when no answer arrived; <paramref name="Failure"/> then
    /// names what happened in the SDK's own words (an exception type). <paramref name="Code"/> is the server's code only when it
    /// matches <c>^[a-z0-9_]{1,64}$</c>; nothing else the server sends is kept.
    /// </summary>
    public sealed record Answer(int? Http, string? Code, string? Status, Guid? RunId, string? Failure, bool Unreadable = false)
    {
        /// <summary>Accepted only as the index accepts: 200 or 201 with a JSON body whose status is indexed or exists and whose runId is a UUID.</summary>
        public bool Accepted => Http is 200 or 201 && Status is "indexed" or "exists" && RunId is not null && !Unreadable;

        /// <summary>A concurrent upload of the same artifact won: try again.</summary>
        public bool Conflict => Http == 409 && Code == "conflict";

        /// <summary>The policy document was refused (and with it the Control Artifact's upload).</summary>
        public bool ControlSetRejected => Http is >= 400 and < 500 && Code is { } c && c.StartsWith("control_set_", StringComparison.Ordinal);

        /// <summary>
        /// The index will not take this artifact, or answered in a way that is not the index's (any other 2xx, a 3xx, a body
        /// too long to read): no automatic attempt follows. Everything else that fails is held for later.
        /// </summary>
        public bool Final => !Accepted && Http is int h && (Unexpected || (h is >= 400 and < 500 and not (408 or 429) && !Conflict));

        // The status decides first, the body only refines it: an over-long body makes a 2xx unexpected, never a 408, 429 or 5xx final.
        private bool Unexpected => Http is >= 200 and < 400 && !Accepted;

        /// <summary>"&lt;status&gt; &lt;code&gt;", "&lt;status&gt; unexpected_response", or the SDK's word for a failure without an answer.</summary>
        public string? ErrorText => Accepted ? null
            : Http is int h ? $"{h} {(Unexpected || Code is null ? UnexpectedResponse : Code)}" : Failure;

        public static Answer Failed(string failure) => new(null, null, null, null, failure);

        /// <summary>An answer from its status and the bytes read of its body (null: longer than <see cref="MaxAnswerBytes"/>).</summary>
        public static Answer From(int http, byte[]? body)
        {
            if (body is null) return new Answer(http, null, null, null, null, Unreadable: true);
            JsonObject? json = null;
            try { json = JsonNode.Parse(body) as JsonObject; }
            catch (Exception) { /* not JSON (an HTML page, an empty body): only the status counts */ }
            var code = AgentProfiles.Str(json?["code"]);
            return new Answer(http, code is not null && CodePattern.IsMatch(code) ? code : null, AgentProfiles.Str(json?["status"]),
                Guid.TryParse(AgentProfiles.Str(json?["runId"]), out var runId) ? runId : null, null);
        }
    }

    /// <summary>"control artifact: " or "seq &lt;n&gt;: ": where an error happened.</summary>
    public static string Where(AgentRunArtifact artifact) => artifact.Seq is { } seq ? $"seq {seq}: " : "control artifact: ";

    /// <summary>The body, at most <see cref="MaxAnswerBytes"/>; null when it is longer (the rest is not read).</summary>
    public static async Task<byte[]?> ReadAtMostAsync(HttpContent content, CancellationToken ct)
    {
#if NETSTANDARD2_1
        using var stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
#else
        using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#endif
        var buffer = new byte[MaxAnswerBytes + 1];
        var read = 0;
        while (read < buffer.Length)
        {
#if NETSTANDARD2_1
            var n = await stream.ReadAsync(buffer, read, buffer.Length - read, ct).ConfigureAwait(false);
#else
            var n = await stream.ReadAsync(buffer.AsMemory(read), ct).ConfigureAwait(false);
#endif
            if (n == 0) break;
            read += n;
        }
        if (read > MaxAnswerBytes) return null;
        Array.Resize(ref buffer, read);
        return buffer;
    }

    /// <summary>One artifact: uploaded, and once more when a concurrent upload of it won; both within <paramref name="timeout"/> each.</summary>
    public static async Task<Answer> UploadAsync(SigillClient client, AgentRunArtifact artifact, byte[]? controlSetDocument,
        TimeSpan timeout, CancellationToken ct)
    {
        var answer = await client.IndexUploadAsync(artifact, controlSetDocument, timeout, ct).ConfigureAwait(false);
        return answer.Conflict ? await client.IndexUploadAsync(artifact, controlSetDocument, timeout, ct).ConfigureAwait(false) : answer;
    }
}
