// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using Sigill.Sdk.Internal;

namespace Sigill.Sdk;

/// <summary>
/// Fluent builder for an <see cref="AiEvidenceEnvelopeInput"/>.
///
/// The builder enforces the spec's required fields: <see cref="Build"/> throws
/// <see cref="InvalidOperationException"/> if any of <c>purpose</c>, <c>actor</c>,
/// <c>activity</c>, <c>model</c> are missing. <c>schemaName</c>, <c>schemaVersion</c>,
/// <c>evidenceId</c>, <c>createdAt</c> are populated automatically (the latter two
/// are overrideable via <see cref="WithEvidenceId"/> / <see cref="WithCreatedAt(string)"/>
/// for deterministic-output tests).
/// </summary>
public sealed class EnvelopeBuilder
{
    private readonly JsonObject _env = new()
    {
        ["schemaName"] = "AiEvidenceEnvelope",
        ["schemaVersion"] = "1",
        ["evidenceId"] = Guid.NewGuid().ToString(),
        ["createdAt"] = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
    };

    // -- identity ---------------------------------------------------------

    public EnvelopeBuilder WithEvidenceId(string id) { _env["evidenceId"] = id; return this; }
    public EnvelopeBuilder WithCreatedAt(string iso8601) { _env["createdAt"] = iso8601; return this; }
    public EnvelopeBuilder WithCreatedAt(DateTimeOffset ts) =>
        WithCreatedAt(ts.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"));

    // -- context ----------------------------------------------------------

    public EnvelopeBuilder WithPurpose(string category, string? businessContext = null, IEnumerable<string>? regulatoryBasis = null)
    {
        var p = new JsonObject { ["category"] = category };
        if (businessContext is not null) p["businessContext"] = businessContext;
        if (regulatoryBasis is not null) p["regulatoryBasis"] = new JsonArray(regulatoryBasis.Select(x => JsonValue.Create(x)).Cast<JsonNode?>().ToArray());
        _env["purpose"] = p;
        return this;
    }

    public EnvelopeBuilder WithActor(string type, string id, string? tenantId = null, string? displayHint = null)
    {
        if (type is not "user" and not "service" and not "system")
            throw new ArgumentException($"actor.type must be one of user|service|system; got '{type}'", nameof(type));
        var a = new JsonObject { ["type"] = type, ["id"] = id };
        if (tenantId is not null) a["tenantId"] = tenantId;
        if (displayHint is not null) a["displayHint"] = displayHint;
        _env["actor"] = a;
        return this;
    }

    public EnvelopeBuilder WithActivity(string name, string? correlationId = null, string? parentEvidenceId = null)
    {
        var a = new JsonObject { ["name"] = name };
        if (correlationId is not null) a["correlationId"] = correlationId;
        if (parentEvidenceId is not null) a["parentEvidenceId"] = parentEvidenceId;
        _env["activity"] = a;
        return this;
    }

    // -- AI call ----------------------------------------------------------

    public EnvelopeBuilder WithModel(string provider, string name, string? version = null, string? deploymentId = null, JsonObject? parameters = null)
    {
        var m = new JsonObject { ["provider"] = provider, ["name"] = name };
        if (version is not null) m["version"] = version;
        if (deploymentId is not null) m["deploymentId"] = deploymentId;
        if (parameters is not null) m["parameters"] = parameters.CloneObject();
        _env["model"] = m;
        return this;
    }

    /// <summary>Set <c>prompt</c> to the inline UTF-8 text. Use only for non-PII content.</summary>
    public EnvelopeBuilder WithPromptInline(string text, string contentType = "text/plain")
    {
        _env["prompt"] = new JsonObject
        {
            ["contentType"] = contentType,
            ["encoding"] = "utf-8",
            ["inline"] = text,
        };
        return this;
    }

    /// <summary>Declare <c>prompt</c> as a hash reference. The bytes are supplied at SealAsync time.</summary>
    public EnvelopeBuilder WithPromptRef(string @ref, string contentType = "text/plain", string encoding = "utf-8")
    {
        _env["prompt"] = new JsonObject { ["ref"] = @ref, ["contentType"] = contentType, ["encoding"] = encoding };
        return this;
    }

    public EnvelopeBuilder WithOutputInline(string text, string contentType = "text/plain")
    {
        _env["output"] = new JsonObject
        {
            ["contentType"] = contentType,
            ["encoding"] = "utf-8",
            ["inline"] = text,
        };
        return this;
    }

    public EnvelopeBuilder WithOutputRef(string @ref, string contentType = "text/plain", string encoding = "utf-8")
    {
        _env["output"] = new JsonObject { ["ref"] = @ref, ["contentType"] = contentType, ["encoding"] = encoding };
        return this;
    }

    public EnvelopeBuilder WithRetrievedContext(JsonArray items) { _env["retrievedContext"] = items.CloneArray(); return this; }
    public EnvelopeBuilder WithSourceTrace(JsonArray items) { _env["sourceTrace"] = items.CloneArray(); return this; }
    public EnvelopeBuilder WithInputs(JsonArray items) { _env["inputs"] = items.CloneArray(); return this; }
    public EnvelopeBuilder WithOutputArtifacts(JsonArray items) { _env["outputArtifacts"] = items.CloneArray(); return this; }

    // -- operational ------------------------------------------------------

    public EnvelopeBuilder WithProcessingMetadata(JsonObject metadata) { _env["processingMetadata"] = metadata.CloneObject(); return this; }
    public EnvelopeBuilder WithPolicyMetadata(JsonObject metadata) { _env["policyMetadata"] = metadata.CloneObject(); return this; }

    // -- escape hatch -----------------------------------------------------

    /// <summary>
    /// Set an arbitrary top-level field. Use sparingly — preferred path is to add a
    /// typed builder method. Provided so callers aren't blocked when the schema
    /// gains a field before the builder does.
    /// </summary>
    public EnvelopeBuilder Set(string field, JsonNode value) { _env[field] = value.CloneNode()!; return this; }

    // -- finalize ---------------------------------------------------------

    private static readonly string[] Required = { "schemaName", "schemaVersion", "evidenceId", "createdAt", "purpose", "actor", "activity", "model" };

    public AiEvidenceEnvelopeInput Build()
    {
        var missing = Required.Where(f => _env[f] is null).ToArray();
        if (missing.Length > 0)
        {
            throw new InvalidOperationException(
                $"Cannot build envelope: missing required field(s) [{string.Join(", ", missing)}]. " +
                "Use WithPurpose / WithActor / WithActivity / WithModel.");
        }
        // Return a deep clone so subsequent builder calls don't leak into the result.
        var snapshot = (JsonObject)JsonNode.Parse(_env.ToJsonString())!;
        return new AiEvidenceEnvelopeInput(snapshot);
    }
}
