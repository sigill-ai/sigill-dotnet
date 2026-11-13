// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Text;

namespace Sigill.Sdk.Examples;

/// <summary>
/// Three scripted agents under <c>control-set.json</c> (enforce mode): no model calls, so every run is the same. Each prints what
/// the guard decided and the run's verification, and returns the verifications (the parent's first).
/// </summary>
public static class EnforcementScenarios
{
    public static readonly IReadOnlyList<string> Names = new[] { "loop", "graph", "approval" };

    private static readonly AgentDefinition Support = new()
    {
        AgentId = "urn:example:agent:support", AgentVersion = "1.0.0",
        Configuration = new AgentConfiguration
        {
            InstructionSet = Utf8("You help customers with their orders."), ToolManifest = Utf8("""{"tools":["docs.search","fs.delete","payments.refund"]}"""),
        },
    };

    private static readonly AgentDefinition Researcher = new()
    {
        AgentId = "urn:example:agent:researcher", AgentVersion = "1.0.0",
        Configuration = new AgentConfiguration { InstructionSet = Utf8("You look things up."), ToolManifest = Utf8("""{"tools":["docs.search"]}""") },
    };

    /// <summary>The examples' control set, exact bytes.</summary>
    public static byte[] ControlSet()
    {
        using var stream = typeof(EnforcementScenarios).Assembly.GetManifestResourceStream("Sigill.Sdk.Examples.control-set.json")!;
        using var copy = new MemoryStream();
        stream.CopyTo(copy);
        return copy.ToArray();
    }

    public static async Task<IReadOnlyList<AgentRunVerificationResult>> RunAsync(string name, SigillClient client, Guid certificateId,
        IPolicyEngine engine, BlindObjectsVerifier verifier, TextWriter output)
    {
        var s = new Scenario(client, certificateId, engine, verifier, TextWriter.Synchronized(output));
        return name switch
        {
            "loop" => await s.LoopAsync(),
            "graph" => await s.GraphAsync(),
            "approval" => await s.ApprovalAsync(),
            _ => throw new ArgumentException($"Unknown scenario '{name}': {string.Join(", ", Names)}.", nameof(name)),
        };
    }

    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);

    private sealed class Scenario(SigillClient client, Guid certificateId, IPolicyEngine engine, BlindObjectsVerifier verifier, TextWriter output)
    {
        private AgentRunOptions Options(string activity) => new()
        {
            CertificateId = certificateId, Activity = activity, ControlSet = AgentPolicy.ControlSetFromDocument(ControlSet()),
            Enforcement = new AgentEnforcement(engine)
            {
                OnEvent = e => output.WriteLine($"  guard: {e.Kind} seq {e.Seq}{(e.Tool is null ? "" : $" {e.Tool}")}"
                    + $"{(e.Reason is null ? "" : $" ({e.Reason})")}{(e.Rules.Count == 0 ? "" : $" [{string.Join(", ", e.Rules)}]")}"),
            },
        };

        private static Task<byte[]> Tool(string result) => Task.FromResult(Utf8(result));

        /// <summary>(a) An agent that keeps retrying a forbidden call: each retry is a new call, denied, until the third denial halts the run.</summary>
        public async Task<IReadOnlyList<AgentRunVerificationResult>> LoopAsync()
        {
            output.WriteLine("loop: an agent retries a forbidden call");
            var run = await AgentRun.StartAsync(client, Support, Options("cleanup"));
            for (var attempt = 1; !run.IsHalted; attempt++)
            {
                try
                {
                    await run.InvokeToolAsync("fs.delete", Utf8("""{"path":"/var/log/app"}"""),
                        _ => throw new InvalidOperationException("never runs: the guard denies it"), consequential: true);
                }
                catch (PolicyDeniedException e)
                {
                    output.WriteLine($"  attempt {attempt}: denied ({e.Reason}: {string.Join(", ", e.Rules)}){(e.Halted ? ", run halted" : "")}");
                }
            }
            try { await run.RecordModelOutputAsync(Utf8("Deleting anyway.")); }
            catch (RunHaltedException) { output.WriteLine("  the agent's next step is refused: the run is halted"); }
            return new[] { await Close("loop", run) };
        }

        /// <summary>(b) A graph-shaped agent: two branches record concurrently on one run, one is denied, the other finishes; then a delegated child run.</summary>
        public async Task<IReadOnlyList<AgentRunVerificationResult>> GraphAsync()
        {
            output.WriteLine("graph: two branches on one run, then a delegated researcher");
            var run = await AgentRun.StartAsync(client, Support, Options("order-help"));
            async Task Research()
            {
                foreach (var q in new[] { """{"q":"refund policy"}""", """{"q":"delivery times"}""" })
                    await run.InvokeToolAsync("docs.search", Utf8(q), _ => Tool("""{"hits":3}"""), operation: "read");
                output.WriteLine("  branch research: done");
            }
            async Task Cleanup()
            {
                try { await run.InvokeToolAsync("fs.delete", Utf8("""{"path":"/tmp/order-cache"}"""), _ => Tool("""{"ok":true}"""), consequential: true); }
                catch (PolicyDeniedException e) { output.WriteLine($"  branch cleanup: denied ({e.Reason}: {string.Join(", ", e.Rules)}), branch stopped"); }
            }
            await Task.WhenAll(Task.Run(Research), Task.Run(Cleanup));

            var delegation = await run.DelegateAsync(Researcher.AgentId, Utf8("""{"task":"find the return address"}"""));
            var child = await AgentRun.StartChildAsync(client, Researcher, Options("order-help"), delegation);
            await child.InvokeToolAsync("docs.search", Utf8("""{"q":"return address"}"""), _ => Tool("""{"hits":1}"""), operation: "read");
            var childResult = await Close("graph child", child);
            await run.CompleteDelegationAsync(child);
            return new[] { await Close("graph", run), childResult };
        }

        /// <summary>(c) An approval flow: a refund is denied for lack of approval, a human approves exactly that call (covers), the retry is allowed.</summary>
        public async Task<IReadOnlyList<AgentRunVerificationResult>> ApprovalAsync()
        {
            output.WriteLine("approval: a refund needs a bound approval");
            var run = await AgentRun.StartAsync(client, Support, Options("refund"));
            var refund = Utf8("""{"amount":120,"order":"o-1"}""");
            try { await run.InvokeToolAsync("payments.refund", refund, _ => Tool("""{"refunded":true}"""), consequential: true); }
            catch (PolicyDeniedException e) { output.WriteLine($"  refund denied ({e.Reason}: {string.Join(", ", e.Rules)}); asking a human"); }
            await run.RecordHumanApprovalAsync("approved", approver: "urn:example:approver:1",
                covers: ApprovalCovers.ForArguments("payments.refund", refund));
            var result = await run.InvokeToolAsync("payments.refund", refund, _ => Tool("""{"refunded":true}"""), consequential: true);
            output.WriteLine($"  retry allowed: {Encoding.UTF8.GetString(result)}");
            return new[] { await Close("approval", run) };
        }

        private async Task<AgentRunVerificationResult> Close(string name, AgentRun run)
        {
            var bundle = await run.FinishAsync();   // a halted run is closed already: this returns its bundle
            var result = await AgentRunVerifier.VerifyWithEngineAsync(bundle, verifier, engine);
            var end = bundle.Artifacts[^1].Envelope["step"]?["runDisposition"]?.GetValue<string>();
            output.WriteLine($"{name}: {bundle.Artifacts.Count} events, {bundle.Artifacts.Count(a => a.StepType == "authorization")} enforcement record(s), run {end}");
            output.WriteLine($"{name}: verification {result.Verdict}, enforcement check {(result.Checks.TryGetValue("enforcement", out var c) ? c : "-")}");
            foreach (var f in result.Findings) output.WriteLine($"  finding: {f}");
            return result;
        }
    }
}
