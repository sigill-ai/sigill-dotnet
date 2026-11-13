// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// The enforcement examples (examples/Sigill.Sdk.Examples) against the stub signer and the Cedar core.

using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Sigill.Sdk.Examples;
using Xunit;

namespace Sigill.Sdk.Tests;

public partial class AgentRunTests
{
    [Fact]
    public void ExamplesControlSet_IsStrictlyValid_AndEnforces()
    {
        AgentPolicy.ValidateStrict(EnforcementScenarios.ControlSet(), TestEngine.Shared).Should().BeEmpty();
        AgentPolicy.Enforcement(EnforcementScenarios.ControlSet()).Mode.Should().Be("enforce");
    }

    [Theory]
    [InlineData("loop", 1, "run halted")]
    [InlineData("graph", 2, "branch research: done")]
    [InlineData("approval", 1, "retry allowed: {\"refunded\":true}")]
    public async Task Examples_RunAgainstTheStubSigner_AndVerify(string name, int runs, string says)
    {
        var sealer = new StubSealer { GenTime = () => DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) };
        using var client = Client(sealer);
        var output = new StringWriter();
        var results = await EnforcementScenarios.RunAsync(name, client, Cert, TestEngine.Shared, StubVerify, output);
        var text = output.ToString();
        results.Should().HaveCount(runs);
        results.Should().OnlyContain(r => r.Verdict == "run_finalized" && r.Checks["enforcement"] == "ok", text);
        text.Should().Contain(says).And.NotContain("finding:");
        switch (name)
        {
            case "loop":
                text.Should().Contain("attempt 3: denied (rule: no-file-deletion), run halted").And.Contain("the agent's next step is refused");
                break;
            case "graph":
                text.Should().Contain("branch cleanup: denied (rule: no-file-deletion), branch stopped");
                text.Split('\n').Count(l => l.Contains("guard: denied")).Should().Be(1);
                break;
            case "approval":
                text.Should().Contain("refund denied (rule: refund-needs-approval)");
                break;
        }
    }
}
