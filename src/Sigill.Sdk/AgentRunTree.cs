// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Sigill.Sdk.Internal;

namespace Sigill.Sdk;

/// <summary>
/// A run tree as one container (<c>spec/agent-delegation-v1.md</c> §6.1): a root run and every run it
/// delegated to, each an ordinary <see cref="AgentRunBundle"/>. <see cref="RootCorrelationId"/> and the
/// order of <see cref="Runs"/> are hints for humans; the verifier derives the tree from signed envelopes.
/// </summary>
public sealed class AgentRunTreeBundle
{
    public const string Format = "AgentRunTreeBundle";
    public const string Version = "1";

    /// <summary>§6.1 limits. Exceeding one makes the tree <c>tree_invalid</c>; the parser does not refuse them.</summary>
    public const int MaxRuns = 256;
    public const int MaxDepth = 8;
    public const int MaxArtifacts = 20_000;
    public const int MaxPayloadEntries = 50_000;
    public const long MaxPayloadBytes = 512L * 1024 * 1024;

    private const int MaxNesting = AgentRunBundle.MaxDepth + 2; // the tree adds runs[] around each run bundle

    public string? RootCorrelationId { get; }
    public IReadOnlyList<AgentRunBundle> Runs { get; }

    public AgentRunTreeBundle(string? rootCorrelationId, IReadOnlyList<AgentRunBundle> runs)
    {
        RootCorrelationId = rootCorrelationId;
        Runs = runs ?? throw new ArgumentNullException(nameof(runs));
    }

    public JsonObject ToJson() => new()
    {
        ["format"] = Format,
        ["bundleVersion"] = Version,
        ["rootCorrelationId"] = RootCorrelationId,
        ["runs"] = new JsonArray(Runs.Select(r => (JsonNode)r.ToJson()).ToArray()),
    };

    public string ToJsonString(bool indented = true) =>
        ToJson().ToJsonString(new JsonSerializerOptions { WriteIndented = indented });

    /// <exception cref="AgentRunBundleFormatException">The container is malformed.</exception>
    public static AgentRunTreeBundle Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 1024 });
            if (Nesting(doc.RootElement) > MaxNesting)
                throw new AgentRunBundleFormatException(new[] { $"tree bundle nests deeper than {MaxNesting} levels" });
            if (AgentProfiles.FindDuplicateName(doc.RootElement) is { } dup)
                throw new AgentRunBundleFormatException(new[] { $"tree bundle repeats a duplicate member name '{dup}'" });
        }
        catch (JsonException ex) { throw new AgentRunBundleFormatException(new[] { "tree bundle is not valid JSON: " + ex.Message }); }
        return Parse(JsonNode.Parse(json));
    }

    public static AgentRunTreeBundle Parse(JsonNode? node)
    {
        if (node is not JsonObject input) throw new AgentRunBundleFormatException(new[] { "tree bundle must be a JSON object" });
        var errors = new List<string>();
        if (AgentProfiles.Str(input["format"]) != Format)
            errors.Add($"unsupported format '{AgentProfiles.Str(input["format"]) ?? "None"}' (expected {Format})");
        if (AgentProfiles.Str(input["bundleVersion"]) != Version)
            errors.Add($"unsupported bundleVersion '{AgentProfiles.Str(input["bundleVersion"]) ?? "None"}' (expected {Version})");
        var runs = new List<AgentRunBundle>();
        if (input["runs"] is not JsonArray arr) errors.Add("runs[] missing or not an array");
        else
            for (var i = 0; i < arr.Count; i++)
            {
                try { runs.Add(AgentRunBundle.Parse(arr[i])); }
                catch (AgentRunBundleFormatException ex) { errors.AddRange(ex.Errors.Select(e => $"runs[{i}]: {e}")); }
            }
        if (errors.Count > 0) throw new AgentRunBundleFormatException(errors);
        return new AgentRunTreeBundle(AgentProfiles.Str(input["rootCorrelationId"]), runs);
    }

    private static int Nesting(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object => 1 + e.EnumerateObject().Select(p => Nesting(p.Value)).DefaultIfEmpty(0).Max(),
        JsonValueKind.Array => 1 + e.EnumerateArray().Select(Nesting).DefaultIfEmpty(0).Max(),
        _ => 0,
    };
}

/// <summary>What the relying party expects of a tree (§5, §6.7). All optional.</summary>
public sealed record AgentRunTreeOptions
{
    /// <summary>The root run's correlationId.</summary>
    public string? ExpectedRootCorrelationId { get; init; }

    /// <summary>The <c>signatureSha256</c> of the root's <c>run_end</c>.</summary>
    public string? ExpectedRootRunEndSignatureSha256 { get; init; }

    /// <summary>The root's signer (<c>x5t#S256</c>).</summary>
    public string? ExpectedRootSigner { get; init; }

    /// <summary>
    /// Attribution policy for one organisation context (§5): <c>agent.id</c> → expected signers
    /// (<c>x5t#S256</c>). A run whose agent is listed and whose signer is not fails <c>signatures</c>.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyCollection<string>>? ExpectedSigners { get; init; }

    /// <summary>Expected signers of Control Evaluations, passed to every run.</summary>
    public IReadOnlyCollection<string>? ExpectedEvaluationSigners { get; init; }
}

/// <summary>One finding of the tree layer: a §6.3 code and what it is about.</summary>
public sealed record AgentRunTreeFinding(string Code, string Detail);

/// <summary>One run of the tree, with its own verdict (§6.2; the tree never changes it).</summary>
public sealed record AgentRunTreeRun
{
    public string? CorrelationId { get; init; }
    public string? AgentId { get; init; }

    /// <summary>The parent named by this run's <c>run_start</c>; null for a root.</summary>
    public string? ParentCorrelationId { get; init; }

    /// <summary>Distance from the root through edges; null when unreachable.</summary>
    public int? Depth { get; init; }

    /// <summary>confirmed | unknown | mismatch — against the attribution policy (§5).</summary>
    public string Affiliation { get; init; } = "unknown";

    /// <summary>The run's own verification; null when a limit stopped verification (§6.1).</summary>
    public AgentRunVerificationResult? Result { get; init; }
}

/// <summary>One delegation edge (§6.4).</summary>
public sealed record AgentRunTreeEdge
{
    public required string ParentCorrelationId { get; init; }
    public required string ChildCorrelationId { get; init; }
    public string? ChildAgentId { get; init; }

    /// <summary>Seq of the parent's <c>delegation</c>; null when the parent declares none.</summary>
    public int? DelegationSeq { get; init; }

    /// <summary>Seq of the parent's <c>delegation_result</c>; null when there is none.</summary>
    public int? ResultSeq { get; init; }

    /// <summary>mutually_bound | child_missing | parent_missing | unbound.</summary>
    public required string Binding { get; init; }

    /// <summary>result_bound | result_mismatch | result_unresolved | no_result.</summary>
    public required string Completion { get; init; }

    /// <summary>The disposition the parent's <c>delegation_result</c> records.</summary>
    public string? ChildDisposition { get; init; }
}

/// <summary>The tree verdict (§6.5) with every run, edge and finding.</summary>
public sealed record AgentRunTreeVerificationResult
{
    /// <summary>tree_finalized | tree_open | tree_invalid.</summary>
    public required string Verdict { get; init; }

    /// <summary>The root derived from signed envelopes; null when there is not exactly one.</summary>
    public string? RootCorrelationId { get; init; }

    public required IReadOnlyList<AgentRunTreeRun> Runs { get; init; }
    public required IReadOnlyList<AgentRunTreeEdge> Edges { get; init; }
    public required IReadOnlyList<AgentRunTreeFinding> Findings { get; init; }

    /// <summary>Why the tree is open (§6.5 step 8): run_open | delegation_pending | parent_terminated, each with its subject.</summary>
    public required IReadOnlyList<AgentRunTreeFinding> OpenReasons { get; init; }

    /// <summary>The §6.8 tree fingerprint; null when a run fingerprint is null or no root can be derived.</summary>
    public string? Fingerprint { get; init; }

    public string Scope => AgentRunTreeVerifier.Scope;

    public bool IsFinalized => Verdict == "tree_finalized";
}

/// <summary>
/// Verifies a run tree (<c>spec/agent-delegation-v1.md</c> §6): every run on its own (common rules §8),
/// then the structure and the delegation edges between them, from signed envelopes only.
/// </summary>
public static class AgentRunTreeVerifier
{
    public const string Scope =
        "tree_finalized means: the root's control basis was sealed first; each child's run_start was sealed after its " +
        "parent's delegation signature existed; each child's run_end signature existed before its parent's " +
        "delegation_result was sealed; and the signed envelopes of every run are unchanged since the root's run_end was " +
        "timestamped. It does not prove that every sub-agent the system started was recorded, when any child actually " +
        "acted, that children did only what the parent intended, that evaluations are complete, or who operates a shared " +
        "certificate.";

    private sealed class Summary
    {
        public required int Index;
        public required AgentRunBundle Bundle;
        public string? Correlation, AgentId, ParentCorrelation, ParentDelegationSig, RunEndSig, RunEndDisposition;
        public bool HasStart, IsChild;
        public List<(int Seq, string Sig, string Child, string? AgentId)> Delegations = new();
        public List<(int Seq, string Child, string? RunEndSig, string? Disposition)> Results = new();
        public int? Depth;
    }

    public static async Task<AgentRunTreeVerificationResult> VerifyAsync(
        AgentRunTreeBundle tree, BlindObjectsVerifier verifier, AgentRunTreeOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        if (tree is null) throw new ArgumentNullException(nameof(tree));
        if (verifier is null) throw new ArgumentNullException(nameof(verifier));
        options ??= new AgentRunTreeOptions();
        var findings = new List<AgentRunTreeFinding>();
        void Find(string code, string detail) => findings.Add(new AgentRunTreeFinding(code, detail));

        // ── §6.1 limits, before anything else
        var runs = tree.Runs;
        var artifacts = runs.Sum(r => (long)r.Artifacts.Count);
        var payloadEntries = runs.Sum(r => (long)r.Payloads.Count);
        var payloadBytes = runs.Sum(r => r.Payloads.Values.Sum(v => (long)v.Length));
        if (runs.Count is 0 or > AgentRunTreeBundle.MaxRuns)
            Find("limit_exceeded", $"{runs.Count} runs (1–{AgentRunTreeBundle.MaxRuns} allowed).");
        if (artifacts > AgentRunTreeBundle.MaxArtifacts)
            Find("limit_exceeded", $"{artifacts} execution artifacts in the tree (at most {AgentRunTreeBundle.MaxArtifacts}).");
        if (payloadEntries > AgentRunTreeBundle.MaxPayloadEntries)
            Find("limit_exceeded", $"{payloadEntries} payload entries in the tree (at most {AgentRunTreeBundle.MaxPayloadEntries}).");
        if (payloadBytes > AgentRunTreeBundle.MaxPayloadBytes)
            Find("limit_exceeded", $"{payloadBytes} payload bytes in the tree (at most {AgentRunTreeBundle.MaxPayloadBytes}).");
        if (findings.Count > 0) return Stopped(findings, runs.Select((r, i) => Summarize(r, i)).ToList());

        // ── structure, from signed envelopes (§6.3)
        var sums = runs.Select((r, i) => Summarize(r, i)).ToList();
        var byCorr = new Dictionary<string, Summary>(StringComparer.Ordinal);
        foreach (var g in sums.Where(s => s.Correlation is not null).GroupBy(s => s.Correlation!, StringComparer.Ordinal))
        {
            byCorr[g.Key] = g.First();
            if (g.Count() > 1) Find("duplicate_run", $"{g.Count()} supplied runs sign correlationId {g.Key}.");
        }
        var roots = sums.Where(s => s.HasStart && !s.IsChild).ToList();
        if (roots.Count == 0) Find("no_root", "No supplied run's run_start is free of a parent binding.");
        else if (roots.Count > 1)
            Find("multiple_roots", $"{roots.Count} runs are roots: {string.Join(", ", roots.Select(r => r.Correlation ?? "?"))}.");
        var root = roots.Count == 1 ? roots[0] : null;

        foreach (var s in sums)
        {
            if (s.Correlation is null) continue;
            if (s.Delegations.Any(d => d.Child == s.Correlation))
                Find("self_delegation", $"{s.Correlation} declares itself as a child.");
            if (s.IsChild && s.ParentCorrelation == s.Correlation)
                Find("self_delegation", $"{s.Correlation} names itself as its parent.");
            foreach (var g in s.Delegations.GroupBy(d => d.Child, StringComparer.Ordinal).Where(g => g.Count() > 1))
                Find("duplicate_delegation", $"{s.Correlation} declares child {g.Key} in {g.Count()} delegation events.");
            foreach (var r in s.Results)
            {
                var decl = s.Delegations.Where(d => d.Child == r.Child).Select(d => (int?)d.Seq).FirstOrDefault();
                if (decl is null) Find("orphan_result", $"{s.Correlation} seq {r.Seq} reports a result for {r.Child}, which it never delegated to.");
                else if (r.Seq < decl) Find("result_before_delegation", $"{s.Correlation} seq {r.Seq} reports a result for {r.Child} before its delegation (seq {decl}).");
            }
            foreach (var g in s.Results.GroupBy(r => r.Child, StringComparer.Ordinal).Where(g => g.Count() > 1))
                Find("duplicate_result", $"{s.Correlation} reports {g.Count()} results for {g.Key}.");
        }
        foreach (var g in sums.Where(s => s.Correlation is not null)
                     .SelectMany(s => s.Delegations.Select(d => (Parent: s.Correlation!, d.Child)))
                     .GroupBy(x => x.Child, StringComparer.Ordinal))
        {
            var parents = g.Select(x => x.Parent).Distinct(StringComparer.Ordinal).ToList();
            if (parents.Count > 1) Find("child_two_parents", $"{g.Key} is declared by {string.Join(" and ", parents)}.");
        }
        foreach (var s in sums)
            foreach (var d in s.Delegations)
                if (byCorr.TryGetValue(d.Child, out var child) && child.AgentId != d.AgentId)
                    Find("agent_mismatch", $"{s.Correlation} seq {d.Seq} delegates to agent {d.AgentId}, but {d.Child} is agent {child.AgentId ?? "unknown"}.");

        // Cycles through parent bindings.
        var onCycle = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in sums.Where(s => s.Correlation is not null && s.IsChild))
        {
            var seen = new List<string> { s.Correlation! };
            var cur = s;
            while (cur.IsChild && cur.ParentCorrelation is { } p && byCorr.TryGetValue(p, out var next) && next.Correlation != cur.Correlation)
            {
                var at = seen.IndexOf(p);
                if (at >= 0) { foreach (var c in seen.Skip(at)) onCycle.Add(c); break; }
                seen.Add(p);
                cur = next;
            }
        }
        if (onCycle.Count > 0) Find("cycle", $"Parent bindings form a cycle through {string.Join(", ", onCycle.OrderBy(c => c, StringComparer.Ordinal))}.");

        // Reachability and depth from the root (declared children, and runs binding a reachable parent).
        if (root is not null)
        {
            root.Depth = 0;
            var queue = new Queue<Summary>(new[] { root });
            while (queue.Count > 0)
            {
                var cur = queue.Dequeue();
                var next = cur.Delegations.Select(d => byCorr.GetValueOrDefault(d.Child))
                    .Concat(sums.Where(s => s.IsChild && s.ParentCorrelation is not null && s.ParentCorrelation == cur.Correlation));
                foreach (var n in next)
                    if (n is not null && n.Depth is null) { n.Depth = cur.Depth + 1; queue.Enqueue(n); }
            }
            foreach (var s in sums.Where(s => s.Depth is null))
                Find("unreachable_run", $"{s.Correlation ?? $"runs[{s.Index}]"} is not reachable from the root {root.Correlation}.");
            if (sums.Max(s => s.Depth ?? 0) is var depth && depth > AgentRunTreeBundle.MaxDepth)
            {
                Find("limit_exceeded", $"The tree is {depth} levels deep (at most {AgentRunTreeBundle.MaxDepth}).");
                return Stopped(findings, sums, root.Correlation);
            }
        }

        // ── every run on its own (§6.2)
        var results = new Dictionary<Summary, AgentRunVerificationResult>();
        foreach (var s in sums)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyCollection<string>? expected = null;
            if (s.AgentId is not null && options.ExpectedSigners?.TryGetValue(s.AgentId, out var e) == true) expected = e;
            results[s] = await AgentRunVerifier.VerifyAsync(s.Bundle, verifier, expected, options.ExpectedEvaluationSigners,
                cancellationToken).ConfigureAwait(false);
        }

        // ── §6.7 expected root
        if (options.ExpectedRootCorrelationId is not null || options.ExpectedRootRunEndSignatureSha256 is not null
            || options.ExpectedRootSigner is not null)
        {
            var problems = new List<string>();
            if (root is null) problems.Add("no root could be derived");
            else
            {
                if (options.ExpectedRootCorrelationId is { } c && root.Correlation != c) problems.Add($"its correlationId is {root.Correlation}, not {c}");
                if (options.ExpectedRootRunEndSignatureSha256 is { } h && root.RunEndSig != h) problems.Add("its run_end is not the expected one");
                if (options.ExpectedRootSigner is { } sg && results[root].Signer != sg) problems.Add("it is not signed by the expected signer");
            }
            if (problems.Count > 0) Find("unexpected_root", "The derived root does not match the expected root: " + string.Join("; ", problems) + ".");
        }

        // ── edges (§6.4)
        var edges = new List<AgentRunTreeEdge>();
        foreach (var p in sums.Where(s => s.Correlation is not null))
            foreach (var d in p.Delegations)
            {
                var child = byCorr.GetValueOrDefault(d.Child);
                var binding = child is null ? "child_missing"
                    : child.IsChild && child.ParentDelegationSig == d.Sig && child.ParentCorrelation == p.Correlation && child.AgentId == d.AgentId
                        ? "mutually_bound" : "unbound";
                var result = p.Results.Where(r => r.Child == d.Child && r.Seq > d.Seq).OrderBy(r => r.Seq).Select(r => ((int Seq, string Child, string? RunEndSig, string? Disposition)?)r).FirstOrDefault();
                var completion = result is not { } r ? "no_result"
                    : child?.RunEndSig is null ? "result_unresolved"
                    : r.RunEndSig == child.RunEndSig && r.Disposition == child.RunEndDisposition ? "result_bound" : "result_mismatch";
                edges.Add(new AgentRunTreeEdge
                {
                    ParentCorrelationId = p.Correlation!, ChildCorrelationId = d.Child, ChildAgentId = d.AgentId,
                    DelegationSeq = d.Seq, ResultSeq = result?.Seq, Binding = binding, Completion = completion,
                    ChildDisposition = result?.Disposition,
                });
            }
        foreach (var c in sums.Where(s => s.IsChild && s.Correlation is not null && s.ParentCorrelation is not null))
        {
            if (edges.Any(e => e.ParentCorrelationId == c.ParentCorrelation && e.ChildCorrelationId == c.Correlation)) continue;
            edges.Add(new AgentRunTreeEdge
            {
                ParentCorrelationId = c.ParentCorrelation!, ChildCorrelationId = c.Correlation!, ChildAgentId = c.AgentId,
                Binding = byCorr.ContainsKey(c.ParentCorrelation!) ? "unbound" : "parent_missing", Completion = "no_result",
            });
        }

        // ── §6.5 decision
        string? Closed(string parent) => byCorr.TryGetValue(parent, out var s) && results.TryGetValue(s, out var r) && r.Verdict != "run_invalid"
            ? r.Disposition : byCorr.TryGetValue(parent, out var s2) ? s2.RunEndDisposition : null;
        var openReasons = new List<AgentRunTreeFinding>();
        string verdict;
        if (findings.Count > 0) verdict = "tree_invalid";
        else if (results.Values.Any(r => r.Verdict == "run_invalid")) verdict = "tree_invalid";
        else if (edges.Any(e => e.Binding is "unbound" or "parent_missing" || e.Completion == "result_mismatch")) verdict = "tree_invalid";
        else if (edges.Any(e => e.Completion == "result_unresolved" || (e.Binding == "child_missing" && Closed(e.ParentCorrelationId) == "completed")))
            verdict = "tree_invalid";
        else if (edges.Any(e => e.Completion == "no_result" && Closed(e.ParentCorrelationId) == "completed")) verdict = "tree_invalid";
        else if (results.Values.All(r => r.Verdict == "run_finalized") && edges.All(e => e.Binding == "mutually_bound" && e.Completion == "result_bound"))
            verdict = "tree_finalized";
        else
        {
            verdict = "tree_open";
            foreach (var s in sums.Where(s => results[s].Verdict == "run_open"))
                openReasons.Add(new AgentRunTreeFinding("run_open", $"{s.Correlation} has no run_end yet."));
            foreach (var e in edges.Where(e => e.Completion == "no_result" || e.Binding == "child_missing"))
            {
                var closed = Closed(e.ParentCorrelationId);
                if (closed is null)
                    openReasons.Add(new AgentRunTreeFinding("delegation_pending", $"{e.ParentCorrelationId} → {e.ChildCorrelationId}: no result yet."));
                else if (closed is "aborted" or "failed")
                    openReasons.Add(new AgentRunTreeFinding("parent_terminated",
                        $"{e.ParentCorrelationId} closed {closed} with {e.ChildCorrelationId} unresolved: parent terminated; evidence incomplete."));
            }
        }

        var treeRuns = sums.Select(s => new AgentRunTreeRun
        {
            CorrelationId = s.Correlation, AgentId = s.AgentId, ParentCorrelationId = s.IsChild ? s.ParentCorrelation : null,
            Depth = s.Depth, Result = results[s], Affiliation = Affiliation(s, results[s], options),
        }).ToList();
        return new AgentRunTreeVerificationResult
        {
            Verdict = verdict, RootCorrelationId = root?.Correlation, Runs = treeRuns, Edges = edges,
            Findings = findings, OpenReasons = openReasons,
            Fingerprint = Fingerprint(root?.Correlation, treeRuns),
        };
    }

    private static string Affiliation(Summary s, AgentRunVerificationResult r, AgentRunTreeOptions o)
    {
        if (s.AgentId is null || o.ExpectedSigners?.TryGetValue(s.AgentId, out var expected) != true) return "unknown";
        return r.Signer is not null && expected!.Contains(r.Signer) ? "confirmed" : "mismatch";
    }

    private static AgentRunTreeVerificationResult Stopped(List<AgentRunTreeFinding> findings, List<Summary> sums, string? root = null) => new()
    {
        Verdict = "tree_invalid",
        RootCorrelationId = root,
        Runs = sums.Select(s => new AgentRunTreeRun { CorrelationId = s.Correlation, AgentId = s.AgentId,
            ParentCorrelationId = s.IsChild ? s.ParentCorrelation : null, Depth = s.Depth }).ToList(),
        Edges = Array.Empty<AgentRunTreeEdge>(),
        Findings = findings,
        OpenReasons = Array.Empty<AgentRunTreeFinding>(),
    };

    /// <summary>The §6.8 tree fingerprint over the derived root and every run's §8.2 fingerprint.</summary>
    private static string? Fingerprint(string? root, IReadOnlyList<AgentRunTreeRun> runs)
    {
        if (root is null || runs.Any(r => r.CorrelationId is null || r.Result?.Fingerprint is null)) return null;
        var list = runs.OrderBy(r => r.CorrelationId, StringComparer.Ordinal).ThenBy(r => r.Result!.Fingerprint, StringComparer.Ordinal)
            .Select(r => (JsonNode)new JsonObject { ["c"] = r.CorrelationId, ["f"] = r.Result!.Fingerprint }).ToArray();
        var node = new JsonObject
        {
            ["format"] = AgentRunTreeBundle.Format, ["bundleVersion"] = AgentRunTreeBundle.Version,
            ["root"] = root, ["runs"] = new JsonArray(list),
        };
        return EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(node));
    }

    /// <summary>What one run says about the tree, read from its envelopes without any cryptography.</summary>
    private static Summary Summarize(AgentRunBundle bundle, int index)
    {
        // Malformed evidence never throws here: a member of the wrong JSON type reads as absent.
        static string? S(JsonNode? root, params string[] path)
        {
            var n = root;
            foreach (var key in path) n = (n as JsonObject)?[key];
            return AgentProfiles.Str(n);
        }
        var s = new Summary { Index = index, Bundle = bundle };
        var events = bundle.Artifacts
            .Select(a => (Art: a, Seq: AgentProfiles.Int((a.Envelope["chain"] as JsonObject)?["seq"])))
            .OrderBy(x => x.Seq ?? int.MaxValue).ToList();
        var start = events.FirstOrDefault(x => S(x.Art.Envelope, "step", "type") == "run_start").Art;
        s.Correlation = S(start?.Envelope, "activity", "correlationId")
            ?? events.Select(x => S(x.Art.Envelope, "activity", "correlationId")).FirstOrDefault(c => !string.IsNullOrEmpty(c))
            ?? S(bundle.ControlArtifact?.Envelope, "activity", "correlationId");
        if (start is not null)
        {
            s.HasStart = true;
            s.ParentCorrelation = S(start.Envelope, "binds", "parentCorrelationId");
            s.ParentDelegationSig = S(start.Envelope, "binds", "parentDelegationSignatureSha256");
            s.IsChild = s.ParentCorrelation is not null || s.ParentDelegationSig is not null;
        }
        s.AgentId = S(bundle.ControlArtifact?.Envelope, "agent", "id") ?? S(start?.Envelope, "actor", "id");
        foreach (var (art, seq) in events)
        {
            if (seq is not int q || art.Envelope["step"] is not JsonObject step) continue;
            var type = S(step, "type");
            if (type == "delegation" && S(step, "delegation", "childCorrelationId") is { } child
                && AgentProfiles.SignatureSha256(art.Signature) is { } sig)
                s.Delegations.Add((q, sig, child, S(step, "delegation", "childAgentId")));
            else if (type == "delegation_result" && S(step, "delegation", "childCorrelationId") is { } rc)
                s.Results.Add((q, rc, S(step, "delegation", "childRunEndSignatureSha256"), S(step, "delegation", "childDisposition")));
            else if (type == "run_end")
            {
                s.RunEndSig = AgentProfiles.SignatureSha256(art.Signature);
                s.RunEndDisposition = S(step, "runDisposition");
            }
        }
        return s;
    }
}
