// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// The enforcement comparison (ControlEvaluation v3 §4–§6): what a v2 control set required of the guard after each event,
// against what the chain records. Vector 14's guard runs must compare with no finding; hand-built chains cover the findings,
// the prefix rules and the engine rules until the comparison's own vector set lands.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public class EnforcementComparisonTests
{
    private static string Dir14 => Path.Combine(SpecRoot.TestVectorsDir, "14-policy-enforcement");
    private static JsonObject Load(string rel) => JsonNode.Parse(File.ReadAllText(Path.Combine(Dir14, rel)))!.AsObject();
    private static readonly JsonObject Arguments = Load("cases.json")["arguments"]!.AsObject();
    private const string Agent = "urn:example:agent:support";
    private const string Engine = "cedar-policy@4.14.0";
    private const string Correlation = "urn:uuid:00000000-0000-4000-8000-150000000001";

    private static string Jcs(JsonNode n) => Encoding.UTF8.GetString(AgentProfiles.Canonical(n));
    private static byte[] Utf8(string s) => Encoding.UTF8.GetBytes(s);
    private static string Hex(string s) => EnvelopeHashing.HashHex(Utf8(s));

    /// <summary>A Control Artifact with the given object digests (role → digest) and the control set.</summary>
    private static AgentRunArtifact Control(byte[] controlSet, IReadOnlyDictionary<string, string>? configuration = null)
    {
        var roles = new Dictionary<string, string>(configuration ?? new Dictionary<string, string>
        {
            ["instruction-set"] = Hex("instruction-set v1"), ["tool-manifest"] = Hex("tool-manifest v1"), ["execution-policy"] = Hex("execution-policy v1"),
        }) { ["control-set"] = EnvelopeHashing.HashHex(controlSet) };
        var objects = new JsonArray();
        var digests = new Dictionary<string, string>();
        foreach (var (role, hex) in roles)
        {
            var uri = $"objects/control-{role}";
            objects.Add(new JsonObject { ["uri"] = uri, ["role"] = role, ["contentType"] = role == "control-set" ? AgentPolicy.ControlSetContentType : "application/json" });
            digests[uri] = hex;
        }
        var envelope = new JsonObject
        {
            ["schemaName"] = "AgentControlArtifact", ["schemaVersion"] = "1",
            ["agent"] = new JsonObject { ["id"] = Agent, ["version"] = "1" },
            ["activity"] = new JsonObject { ["correlationId"] = Correlation }, ["objects"] = objects,
        };
        return new AgentRunArtifact(envelope, new JsonObject(), digests);
    }

    private static byte[] Doc(Action<JsonObject>? change = null)
    {
        var doc = JsonNode.Parse(PolicyControlSetV2VectorTests.Doc)!.AsObject();
        change?.Invoke(doc);
        return Utf8(doc.ToJsonString());
    }

    private static readonly HashSet<string> Bound = JsonNode.Parse(PolicyControlSetV2VectorTests.Doc)!["cedar"]!["entities"]!.AsArray()
        .Where(e => e!["attrs"]!["definitionSha256"] is not null).Select(e => e!["uid"]!["id"]!.GetValue<string>()).ToHashSet();

    /// <summary>A chain built by hand, event by event, as the vector's generator builds them.</summary>
    private sealed class Chain
    {
        public List<AgentRunArtifact> Events { get; } = new();

        public Chain Add(string type, Action<JsonObject>? step = null, params (string Role, string Bytes)[] objects)
        {
            var seq = Events.Count;
            var s = new JsonObject { ["type"] = type, ["eventTime"] = $"2026-11-02T10:00:{seq:00}.000Z" };
            step?.Invoke(s);
            var arr = new JsonArray();
            var digests = new Dictionary<string, string>();
            foreach (var (role, bytes) in objects)
            {
                var uri = $"objects/{seq}-{role}";
                arr.Add(new JsonObject { ["uri"] = uri, ["role"] = role, ["contentType"] = "application/json" });
                digests[uri] = Hex(bytes);
            }
            var envelope = new JsonObject
            {
                ["schemaName"] = "AgentExecutionEvidence", ["schemaVersion"] = "4",
                ["actor"] = new JsonObject { ["type"] = "agent", ["id"] = Agent },
                ["activity"] = new JsonObject { ["name"] = "support-session", ["correlationId"] = Correlation },
                ["chain"] = new JsonObject { ["seq"] = seq }, ["step"] = s, ["objects"] = arr,
            };
            Events.Add(new AgentRunArtifact(envelope, new JsonObject(), digests));
            return this;
        }

        public Chain Start(Action<JsonObject>? step = null) => Add("run_start", step);

        public Chain Call(string tool, string useId, string args, bool consequential = false, string? definition = "default")
        {
            var objects = new List<(string, string)> { ("tool-arguments", Arguments[args]!.GetValue<string>()) };
            var def = definition == "default" ? (Bound.Contains(tool) ? $"{tool} definition" : null) : definition;
            if (def is not null) objects.Add(("tool-definition", def));
            return Add("tool_call", s =>
            {
                s["tool"] = new JsonObject { ["name"] = tool, ["useId"] = useId };
                if (consequential) s["consequential"] = true;
            }, objects.ToArray());
        }

        public Chain Result(string tool, string useId) => Add("tool_result", s => s["tool"] = new JsonObject { ["name"] = tool, ["useId"] = useId },
            ("tool-result", """{"ok":true}"""));

        public Chain Record(string reason, string[]? rules = null, string? tool = null, string? useId = null, string engine = Engine) =>
            Add("authorization", s =>
            {
                s["decision"] = "denied";
                if (tool is not null) s["tool"] = new JsonObject { ["name"] = tool, ["useId"] = useId };
                if (rules is not null) s["rules"] = new JsonArray(rules.Select(r => (JsonNode?)r).ToArray());
                s["enforcer"] = new JsonObject { ["engine"] = engine, ["factsVersion"] = "2", ["reason"] = reason };
            });

        public Chain End(string disposition = "completed") => Add("run_end", s =>
        {
            s["finalSeq"] = Events.Count;
            s["runDisposition"] = disposition;
        });
    }

    private static JsonObject Compare(Chain chain, byte[]? doc = null, IReadOnlyDictionary<string, string>? configuration = null) =>
        AgentPolicy.CompareEnforcement(Control(doc ?? Doc(), configuration), chain.Events, doc ?? Doc(), TestEngine.Shared);

    /// <summary>Decisions in one line each: "seq due[/reason[rules]] recorded outcome [findings]".</summary>
    private static string[] Decisions(JsonObject member) => (member["decisions"] as JsonArray ?? new JsonArray()).Select(d =>
    {
        var reason = d!["dueReason"] is { } r ? "/" + r.GetValue<string>() : "";
        var rules = d["dueRules"] is JsonArray a ? "[" + string.Join(",", a.Select(x => x!.GetValue<string>())) + "]" : "";
        var findings = d["findings"] is JsonArray f ? " " + string.Join(",", f.Select(x => x!.GetValue<string>())) : "";
        return $"{d["seq"]} {d["due"]}{reason}{rules} {d["recorded"]?.GetValue<string>() ?? "?"} {d["outcome"]}{findings}";
    }).ToArray();

    // ── Vector 14's guard runs: what the guard did is what was due ──

    public static IEnumerable<object[]> GuardRuns() => PolicyEnforcementVectorTests.Runs();

    [Theory]
    [MemberData(nameof(GuardRuns))]
    public void EveryGuardRun_ComparesWithoutAFinding_AndTheDueOutcomeIsTheGuards(string name)
    {
        var run = Load($"runs/{name}.json");
        var expected = Load($"expected/{name}.json");
        var doc = PolicyEnforcementVectorTests.ControlSetOf(run);
        var configuration = run["configuration"]!.AsObject().ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>());
        var events = run["events"]!.AsArray().Select(e => new AgentRunArtifact(e!["envelope"]!.DeepClone().AsObject(), new JsonObject(),
            e["objectDigests"]!.AsObject().ToDictionary(kv => kv.Key, kv => kv.Value!.GetValue<string>()))).ToList();
        var member = AgentPolicy.CompareEnforcement(Control(doc, configuration), events.AsEnumerable().Reverse(), doc, TestEngine.Shared);

        var unavailable = name is "18-start-engine-unavailable" or "28-engine-failure-tool-call" or "29-engine-failure-non-tool";
        member["comparison"]!.GetValue<string>().Should().Be("performed");
        member["result"]!.GetValue<string>().Should().Be(unavailable ? "not_checkable" : "as_required");
        var hasRecord = events.Any(e => AgentPolicy.IsEnforcementRecord(e.Envelope));
        (member["recordedEngine"]?.GetValue<string>()).Should().Be(hasRecord ? Engine : null);

        // The generator's guard outcome per producer event: denied = refused, halted = halted.
        var guard = expected["events"]!.AsArray().Where(e => e!["sealedBy"]!.GetValue<string>() == "producer"
            && e["outcome"]?.GetValue<string>() is "denied" or "halted").Select(e =>
        {
            var reason = e!["reason"]!.GetValue<string>();
            var rules = reason is "rule" or "rule_error" ? "[" + string.Join(",", e["rules"]!.AsArray().Select(r => r!.GetValue<string>())) + "]" : "";
            var recorded = e["outcome"]!.GetValue<string>() == "halted" ? "halted" : "refused";
            return reason == "unavailable"
                ? $"{e["seq"]} none {recorded} not_checkable"
                : $"{e["seq"]} {recorded}/{reason}{rules} {recorded} as_required";
        }).ToArray();
        Decisions(member).Should().Equal(guard);
    }

    // ── Hand-built chains (the draft's cases) ──

    [Fact]
    public void ARefusalThatIsMissing_IsLetThrough_AndNoCoreIsRecorded()
    {
        var m = Compare(new Chain().Start().Call("search.web", "call-1", "Q").Result("search.web", "call-1").End());
        Decisions(m).Should().Equal("1 refused/rule[no-web-search] none let_through refusal_missing");
        (m["result"]!.GetValue<string>(), m.ContainsKey("recordedEngine")).Should().Be(("let_through", false));
    }

    [Fact]
    public void LetThroughFindings_OnePerKind()
    {
        Decisions(Compare(new Chain().Start().Call("fs.delete", "call-1", "P", true).Result("fs.delete", "call-1").End()))
            .Should().Equal("1 refused/unknown_tool none let_through unknown_tool_allowed");
        Decisions(Compare(new Chain().Start().Call("crm.update_address", "call-1", "D", true, "another definition").Result("crm.update_address", "call-1").End()))
            .Should().Equal("1 refused/tool_changed none let_through refusal_missing");
        Decisions(Compare(new Chain().Start().Call("ledger.export", "call-1", "L").Result("ledger.export", "call-1").End()))
            .Should().Equal("1 refused/rule_error[export-weight] none let_through refusal_missing");
        Decisions(Compare(new Chain().Start().Call("crm.read_customer", "call-1", "C").Result("crm.read_customer", "call-1").End(),
                configuration: new Dictionary<string, string> { ["tool-manifest"] = Hex("tool-manifest v2") }))
            .Should().Equal("0 halted/configuration_locked none let_through configuration_not_enforced");
        Decisions(Compare(new Chain().Start().Call("search.web", "call-1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "call-1")
                .Add("retrieval").Add("model_output").End()))
            .Should().Equal("1 refused/rule[no-web-search] refused as_required", "3 halted/rule[halt-retrieval-after-denial] none let_through halt_missing");
        Decisions(Compare(new Chain().Start().Call("fs.wipe", "call-1", "P", true).Result("fs.wipe", "call-1").End()))
            .Should().Equal("1 halted/unknown_tool none let_through unknown_tool_allowed,halt_missing");
        Decisions(Compare(new Chain().Start().Add("delegation").Add("delegation_result").End()))
            .Should().Equal("1 halted/rule[no-delegation] none let_through halt_missing");
    }

    [Fact]
    public void TheDenialCount_IsAtLeast_OnTheRecordedChain()
    {
        var doc = Doc(d => d["enforcement"]!["haltAfterDenials"] = 2);
        Decisions(Compare(new Chain().Start()
                .Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1")
                .Call("search.web", "c2", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c2")
                .Call("search.web", "c3", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c3").End(), doc))
            .Should().Equal("1 refused/rule[no-web-search] refused as_required",
                "3 halted/rule[no-web-search] refused let_through halt_missing", "5 halted/rule[no-web-search] refused let_through halt_missing");
        // A record that was not due counts as a denial: it brings the halt one denial earlier.
        Decisions(Compare(new Chain().Start()
                .Call("crm.read_customer", "c1", "C").Record("rule", new[] { "read-loop-limit" }, "crm.read_customer", "c1")
                .Call("search.web", "c2", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c2").End("halted"), doc))
            .Should().Equal("1 none refused over_enforced unfounded_record", "3 halted/rule[no-web-search] halted as_required");
    }

    [Fact]
    public void OverEnforcedFindings()
    {
        Decisions(Compare(new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1").End("halted")))
            .Should().Equal("1 refused/rule[no-web-search] halted over_enforced unfounded_halt");
        Decisions(Compare(new Chain().Start().Call("fs.wipe", "c1", "P", true).Record("rule", new[] { "halt-fs-wipe" }, "fs.wipe", "c1").End("halted")))
            .Should().Equal("1 halted/unknown_tool halted over_enforced reason_mismatch");
        Decisions(Compare(new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search", "read-loop-limit" }, "search.web", "c1").End()))
            .Should().Equal("1 refused/rule[no-web-search] refused over_enforced rules_mismatch");
        // A record with rules: [] is the same as one without rules.
        Decisions(Compare(new Chain().Start().Call("fs.delete", "c1", "P", true).Record("unknown_tool", Array.Empty<string>(), "fs.delete", "c1").End()))
            .Should().Equal("1 refused/unknown_tool refused as_required");
        // In observe mode nothing is due: a record is unfounded, and the rule still FAILs elsewhere.
        Decisions(Compare(new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1").End(),
                Doc(d => d["enforcement"]!["mode"] = "observe")))
            .Should().Equal("1 none refused over_enforced unfounded_record");
    }

    [Fact]
    public void Unavailable_IsNotCheckable_ExceptWhereTheConfigurationLockWasDue()
    {
        var m = Compare(new Chain().Start().Call("search.web", "c1", "Q").Record("unavailable", null, "search.web", "c1").End("halted"));
        Decisions(m).Should().Equal("1 refused/rule[no-web-search] halted not_checkable");
        m["result"]!.GetValue<string>().Should().Be("not_checkable");
        Decisions(Compare(new Chain().Start().Record("unavailable").End("halted"),
                configuration: new Dictionary<string, string> { ["tool-manifest"] = Hex("tool-manifest v2") }))
            .Should().Equal("0 halted/configuration_locked halted over_enforced reason_mismatch");
    }

    [Fact]
    public void TheEngineRules()
    {
        var other = Compare(new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1", "cedar-policy@99.0.0").End());
        Jcs(other).Should().Be("""{"comparison":"not_performed","notPerformed":"engine_unavailable","recordedEngine":"cedar-policy@99.0.0"}""");
        var two = Compare(new Chain().Start()
            .Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1")
            .Call("search.web", "c2", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c2", "cedar-policy@99.0.0").End());
        Jcs(two).Should().Be("""{"comparison":"not_performed","notPerformed":"engine_inconsistent"}""");
    }

    [Fact]
    public void AChainThatContradictsItself_IsNotCompared()
    {
        var executed = new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1")
            .Result("search.web", "c1").End();
        Jcs(Compare(executed)).Should().Be("""{"comparison":"not_performed","notPerformed":"chain_inconsistent","recordedEngine":"cedar-policy@4.14.0"}""");
        var late = new Chain().Start().Call("search.web", "c1", "Q").Add("model_output").Record("rule", new[] { "no-web-search" }, "search.web", "c1").End();
        Compare(late)["notPerformed"]!.GetValue<string>().Should().Be("chain_inconsistent");
        var unrecordedHalt = new Chain().Start().Call("search.web", "c1", "Q").End("halted");
        Jcs(Compare(unrecordedHalt)).Should().Be("""{"comparison":"not_performed","notPerformed":"chain_inconsistent"}""");
        var continued = new Chain().Start().Call("crm.read_customer", "c1", "C").Record("unavailable", null, "crm.read_customer", "c1").Add("model_output").End();
        Compare(continued)["notPerformed"]!.GetValue<string>().Should().Be("chain_inconsistent");
        // Under a v2 control set an event that is not v4 can hold no record (evidence_version_mismatch).
        var v3 = new Chain().Start().Call("search.web", "c1", "Q").End();
        v3.Events[1].Envelope["schemaVersion"] = "3";
        Jcs(Compare(v3)).Should().Be("""{"comparison":"not_performed","notPerformed":"chain_inconsistent"}""");
    }

    [Fact]
    public void OpenEvents_ArePending_AndAGapEndsThePrefix()
    {
        Decisions(Compare(new Chain().Start().Call("search.web", "c1", "Q"))).Should().Equal("1 refused/rule[no-web-search] ? pending");
        // A prefix that ends on a halting record: not continued_after_halt, the decided event is pending with recorded refused.
        var m = Compare(new Chain().Start().Call("search.web", "c1", "Q").Record("unavailable", null, "search.web", "c1"));
        (m["comparison"]!.GetValue<string>(), m["result"]!.GetValue<string>()).Should().Be(("performed", "pending"));
        Decisions(m).Should().Equal("1 refused/rule[no-web-search] refused pending");
        Decisions(Compare(new Chain().Start().Call("crm.read_customer", "c1", "C", definition: "crm.read_customer definition"))).Should().BeEmpty();
        // Seq 3 missing: the prefix is 0…2, and nothing is asserted about the call at seq 4.
        var gap = new Chain().Start().Call("crm.read_customer", "c1", "C").Result("crm.read_customer", "c1").Add("checkpoint")
            .Call("search.web", "c2", "Q").Result("search.web", "c2").End();
        gap.Events.RemoveAt(3);
        var g = Compare(gap);
        (Decisions(g).Length, g["result"]!.GetValue<string>()).Should().Be((0, "as_required"));
        // The same call as the first, decidable because the run ended.
        Decisions(Compare(new Chain().Start().Call("search.web", "c1", "Q").End())).Should().Equal("1 refused/rule[no-web-search] none let_through refusal_missing");
    }

    [Fact]
    public void ARuleLessControlSet_IsStillCompared()
    {
        var doc = Doc(d => d.Remove("cedar"));
        var m = Compare(new Chain().Start().Call("crm.read_customer", "c1", "C").Result("crm.read_customer", "c1").End(), doc);
        Decisions(m).Should().Equal("1 refused/unknown_tool none let_through unknown_tool_allowed");
        Decisions(Compare(new Chain().Start().Call("crm.read_customer", "c1", "C").Record("unknown_tool", null, "crm.read_customer", "c1").End(), doc))
            .Should().Equal("1 refused/unknown_tool refused as_required");
    }

    [Fact]
    public void WithoutAnEnforcementMember_NothingIsDue()
    {
        var m = Compare(new Chain().Start().Call("search.web", "c1", "Q").Result("search.web", "c1").End(), Doc(d => d.Remove("enforcement")));
        Jcs(m).Should().Be("""{"comparison":"performed","decisions":[],"result":"as_required"}""");
    }

    [Fact]
    public void TheMember_IsByteStable_AndNeedsNoPayload()
    {
        var chain = new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1")
            .Add("retrieval").Record("rule", new[] { "halt-retrieval-after-denial" }).End("halted");
        var first = Jcs(Compare(chain));
        Jcs(Compare(chain)).Should().Be(first);
        first.Should().Be("""{"comparison":"performed","decisions":[{"due":"refused","dueReason":"rule","dueRules":["no-web-search"],"outcome":"as_required","recorded":"refused","seq":1},{"due":"halted","dueReason":"rule","dueRules":["halt-retrieval-after-denial"],"outcome":"as_required","recorded":"halted","seq":3}],"recordedEngine":"cedar-policy@4.14.0","result":"as_required"}""");
    }

    [Fact]
    public void ARunsOwnControlSetOnly()
    {
        var chain = new Chain().Start().End();
        FluentActions.Invoking(() => AgentPolicy.CompareEnforcement(Control(Doc()), chain.Events, Doc(d => d["version"] = "5"), TestEngine.Shared))
            .Should().Throw<ArgumentException>().WithMessage("The control set is not the one the Control Artifact seals.*");
        var v1 = File.ReadAllBytes(Path.Combine(SpecRoot.TestVectorsDir, "11-policy-control-set", "control-set.json"));
        FluentActions.Invoking(() => AgentPolicy.CompareEnforcement(Control(v1), chain.Events, v1, TestEngine.Shared))
            .Should().Throw<ArgumentException>().WithMessage("*v2 policy control set*");
    }

    // ── Input errors: what the comparison cannot read is the caller's mistake, never a comparison ──

    private sealed class ScriptedEngine(Func<JsonObject, JsonObject> authorize, Func<string>? version = null) : IPolicyEngine
    {
        public string Version => version is null ? TestEngine.Shared.Version : version();
        public JsonObject Authorize(JsonObject call) => authorize(call);
        public JsonObject Validate(JsonObject call) => TestEngine.Shared.Validate(call);
    }

    [Fact]
    public void InputItCannotRead_IsAnArgumentException()
    {
        var doc = Doc();
        var chain = new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1").End();
        JsonObject Run(AgentRunArtifact control, IEnumerable<AgentRunArtifact> events) => AgentPolicy.CompareEnforcement(control, events, doc, TestEngine.Shared);
        AgentRunArtifact Changed(Action<JsonObject> change)
        {
            var c = Control(doc);
            var env = (JsonObject)c.Envelope.DeepClone();
            change(env);
            return c with { Envelope = env };
        }
        List<AgentRunArtifact> WithRecord(JsonNode? engine)
        {
            var events = chain.Events.Select(e => e with { Envelope = (JsonObject)e.Envelope.DeepClone() }).ToList();
            var enforcer = events[2].Envelope["step"]!["enforcer"]!.AsObject();
            if (engine is null) enforcer.Remove("engine"); else enforcer["engine"] = engine;
            return events;
        }

        FluentActions.Invoking(() => Run(Control(doc), WithRecord(null))).Should().Throw<ArgumentException>().WithMessage("the enforcement record at seq 2 has no enforcer.engine*");
        FluentActions.Invoking(() => Run(Control(doc), WithRecord(JsonValue.Create(4)))).Should().Throw<ArgumentException>().WithMessage("*seq 2 has no enforcer.engine*");
        FluentActions.Invoking(() => Run(Changed(e => e["activity"]!.AsObject().Remove("correlationId")), chain.Events))
            .Should().Throw<ArgumentException>().WithMessage("*names no agent or correlationId*");
        FluentActions.Invoking(() => Run(Changed(e => e["objects"]!.AsArray().Add(e["objects"]!.AsArray().Single(o => o!["role"]!.GetValue<string>() == "control-set")!.DeepClone())), chain.Events))
            .Should().Throw<ArgumentException>().WithMessage("*exactly one control-set object*");
        FluentActions.Invoking(() => Run(Changed(e => e["objects"]!.AsArray().Add(new JsonObject { ["uri"] = "objects/other", ["role"] = "tool-manifest", ["contentType"] = "application/json" })), chain.Events))
            .Should().Throw<ArgumentException>().WithMessage("The Control Artifact carries more than one tool-manifest object.*");
        // The verifier's core-free path reads the same rule (it reports a finding, with or without an engine).
        AgentPolicy.ComparisonInputProblem(Changed(e => e["objects"]!.AsArray().Add(new JsonObject { ["uri"] = "objects/other", ["role"] = "tool-manifest", ["contentType"] = "application/json" })).Envelope,
            chain.Events.Select(e => e.Envelope).ToList()).Should().Be("The Control Artifact carries more than one tool-manifest object.");
        AgentPolicy.ComparisonInputProblem(Control(doc).Envelope, WithRecord(null).Select(e => e.Envelope).ToList())
            .Should().Be("the enforcement record at seq 2 has no enforcer.engine");
        AgentPolicy.ComparisonInputProblem(Control(doc).Envelope, chain.Events.Select(e => e.Envelope).ToList()).Should().BeNull();
        AgentPolicy.ComparisonInputProblem(Changed(e => e["activity"]!.AsObject().Remove("correlationId")).Envelope, chain.Events.Select(e => e.Envelope).ToList())
            .Should().Be("The Control Artifact names no agent or correlationId.");
        AgentPolicy.ComparisonInputProblem(Changed(e => e["objects"] = new JsonArray()).Envelope, chain.Events.Select(e => e.Envelope).ToList())
            .Should().Be("The Control Artifact must carry exactly one control-set object.");
        // Also a role the control set does not lock.
        FluentActions.Invoking(() => Run(Changed(e => e["objects"]!.AsArray().Add(new JsonObject { ["uri"] = "objects/other", ["role"] = "instruction-set", ["contentType"] = "application/json" })), chain.Events))
            .Should().Throw<ArgumentException>().WithMessage("*more than one instruction-set object*");
        FluentActions.Invoking(() => Run(Control(doc), chain.Events.Append(chain.Events[1]))).Should().Throw<ArgumentException>().WithMessage("*two events claim seq 1*");
        var unnumbered = chain.Events[1] with { Envelope = (JsonObject)chain.Events[1].Envelope.DeepClone() };
        unnumbered.Envelope.Remove("chain");
        FluentActions.Invoking(() => Run(Control(doc), chain.Events.Append(unnumbered))).Should().Throw<ArgumentException>().WithMessage("*no chain.seq*");
    }

    [Fact]
    public void WhateverTheEngineThrows_IsAPolicyEngineException_TheRunLevelRequestIncluded()
    {
        var doc = Doc();
        var chain = new Chain().Start().Call("crm.read_customer", "c1", "C").Result("crm.read_customer", "c1").End();
        JsonObject Run(IPolicyEngine engine) => AgentPolicy.CompareEnforcement(Control(doc), chain.Events, doc, engine);

        FluentActions.Invoking(() => Run(new ScriptedEngine(_ => throw new InvalidOperationException("trap"))))
            .Should().Throw<PolicyEngineException>().WithMessage("The policy engine failed: trap").Which.Refused.Should().BeFalse();
        // The records name a core, so its version is asked: what that throws is surfaced too.
        var recorded = new Chain().Start().Call("search.web", "c1", "Q").Record("rule", new[] { "no-web-search" }, "search.web", "c1").End();
        FluentActions.Invoking(() => AgentPolicy.CompareEnforcement(Control(doc), recorded.Events, doc, new ScriptedEngine(TestEngine.Shared.Authorize, () => throw new InvalidOperationException("no version"))))
            .Should().Throw<PolicyEngineException>().WithMessage("The policy engine failed: no version");
        // An engine that refuses only the run-level request ends the comparison as one that refuses any other.
        static bool IsRun(JsonObject call) => call["action"]?["id"]?.GetValue<string>() == "run";
        var refusesRun = new ScriptedEngine(call => IsRun(call) ? JsonNode.Parse("""{"type":"failure","errors":[{"message":"no."}]}""")!.AsObject() : TestEngine.Shared.Authorize(call));
        FluentActions.Invoking(() => Run(refusesRun)).Should().Throw<PolicyEngineException>().WithMessage("The policy engine refused request run: no.").Which.Refused.Should().BeTrue();
        var throwsOnRun = new ScriptedEngine(call => IsRun(call) ? throw new InvalidOperationException("run trap") : TestEngine.Shared.Authorize(call));
        FluentActions.Invoking(() => Run(throwsOnRun)).Should().Throw<PolicyEngineException>().WithMessage("The policy engine failed: run trap");
        // A run without any record: the comparison is performed, so it names the evaluator's core and reads its version.
        FluentActions.Invoking(() => Run(new ScriptedEngine(TestEngine.Shared.Authorize, () => throw new InvalidOperationException("no version"))))
            .Should().Throw<PolicyEngineException>().WithMessage("The policy engine failed: no version");
        // Without run_end there is no run-level request.
        var open = new Chain().Start().Call("crm.read_customer", "c1", "C");
        AgentPolicy.CompareEnforcement(Control(doc), open.Events, doc, refusesRun)["comparison"]!.GetValue<string>().Should().Be("performed");
    }
}
