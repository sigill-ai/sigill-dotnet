// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.IO;
using System.Text.Json.Nodes;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

public class EnvelopeBuilderTests
{
    [Fact]
    public void Minimal_envelope_builds_with_all_required_fields()
    {
        var env = new EnvelopeBuilder()
            .WithPurpose("x")
            .WithActor("service", "s")
            .WithActivity("a")
            .WithModel("p", "n")
            .Build();

        foreach (var field in new[] { "schemaName", "schemaVersion", "evidenceId", "createdAt",
                                      "purpose", "actor", "activity", "model" })
        {
            env.Json[field].Should().NotBeNull($"required field '{field}' must be present");
        }
        env.Json["schemaName"]!.GetValue<string>().Should().Be("AiEvidenceEnvelope");
        env.Json["schemaVersion"]!.GetValue<string>().Should().Be("1");
    }

    [Fact]
    public void Missing_required_fields_throw_with_descriptive_message()
    {
        var b = new EnvelopeBuilder().WithPurpose("x");
        var act = () => b.Build();
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*missing required field*actor*activity*model*");
    }

    [Fact]
    public void Inline_prompt_has_correct_shape()
    {
        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("a").WithModel("p", "n")
            .WithPromptInline("hi", "text/plain")
            .Build();

        var prompt = (JsonObject)env.Json["prompt"]!;
        prompt["contentType"]!.GetValue<string>().Should().Be("text/plain");
        prompt["encoding"]!.GetValue<string>().Should().Be("utf-8");
        prompt["inline"]!.GetValue<string>().Should().Be("hi");
    }

    [Fact]
    public void Ref_prompt_has_correct_shape()
    {
        var env = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("a").WithModel("p", "n")
            .WithPromptRef("prompt-001")
            .Build();

        var prompt = (JsonObject)env.Json["prompt"]!;
        prompt["ref"]!.GetValue<string>().Should().Be("prompt-001");
        prompt["contentType"]!.GetValue<string>().Should().Be("text/plain");
        prompt["encoding"]!.GetValue<string>().Should().Be("utf-8");
        prompt["inline"].Should().BeNull();
        prompt["hash"].Should().BeNull();
    }

    [Fact]
    public void Build_returns_independent_snapshot()
    {
        var b = new EnvelopeBuilder()
            .WithPurpose("x").WithActor("user", "u").WithActivity("a").WithModel("p1", "n1");
        var env1 = b.Build();
        b.WithModel("p2", "n2");
        var env2 = b.Build();

        env1.Json["model"]!["provider"]!.GetValue<string>().Should().Be("p1");
        env2.Json["model"]!["provider"]!.GetValue<string>().Should().Be("p2");
    }

    [Fact]
    public void Invalid_actor_type_throws()
    {
        var b = new EnvelopeBuilder();
        var act = () => b.WithActor("admin", "u");
        act.Should().Throw<ArgumentException>().WithMessage("*user|service|system*");
    }

    [Fact]
    public void Builder_reproduces_test_vector_01()
    {
        var vec = Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call");
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;

        var processing = (JsonObject)expected["processingMetadata"]!.DeepClone();
        var policy = (JsonObject)expected["policyMetadata"]!.DeepClone();
        var modelParams = (JsonObject)expected["model"]!["parameters"]!.DeepClone();

        var env = new EnvelopeBuilder()
            .WithEvidenceId(expected["evidenceId"]!.GetValue<string>())
            .WithCreatedAt(expected["createdAt"]!.GetValue<string>())
            .WithPurpose(
                category: expected["purpose"]!["category"]!.GetValue<string>(),
                businessContext: expected["purpose"]!["businessContext"]!.GetValue<string>())
            .WithActor(
                type: expected["actor"]!["type"]!.GetValue<string>(),
                id: expected["actor"]!["id"]!.GetValue<string>(),
                tenantId: expected["actor"]!["tenantId"]!.GetValue<string>())
            .WithActivity(
                name: expected["activity"]!["name"]!.GetValue<string>(),
                correlationId: expected["activity"]!["correlationId"]!.GetValue<string>())
            .WithModel(
                provider: expected["model"]!["provider"]!.GetValue<string>(),
                name: expected["model"]!["name"]!.GetValue<string>(),
                parameters: modelParams)
            .WithPromptInline(expected["prompt"]!["inline"]!.GetValue<string>())
            .WithOutputInline(expected["output"]!["inline"]!.GetValue<string>())
            .WithProcessingMetadata(processing)
            .WithPolicyMetadata(policy)
            .Build();

        // Compare canonical bytes — that's the contract that matters
        var ours = EnvelopeHashing.Canonicalize(env.Json);

        var theirs = (JsonObject)expected.DeepClone();
        if (theirs["integrity"] is JsonObject integ) integ.Remove("envelopeHash");
        theirs.Remove("proofs");
        var theirsBytes = EnvelopeHashing.Canonicalize(theirs);

        // The builder doesn't populate integrity by itself — strip from theirs too
        // Actually our builder doesn't add integrity at all, so for this comparison
        // we need to ensure both envelopes have the same shape. Build a side-by-side
        // canonicalization that ignores the integrity slot.
        var ourObj = (JsonObject)JsonNode.Parse(ours)!;
        var theirObj = (JsonObject)JsonNode.Parse(theirsBytes)!;
        ourObj.Remove("integrity");
        theirObj.Remove("integrity");
        EnvelopeHashing.Canonicalize(ourObj).Should().Equal(EnvelopeHashing.Canonicalize(theirObj));
    }
}
