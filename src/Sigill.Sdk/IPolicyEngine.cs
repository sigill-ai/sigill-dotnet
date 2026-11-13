// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json.Nodes;

namespace Sigill.Sdk;

/// <summary>
/// A Cedar policy engine: the calls and answers are the JSON objects of <c>@cedar-policy/cedar-wasm</c>'s
/// <c>isAuthorized</c> and <c>validate</c>. The package <c>Sigill.Sdk.Policy</c> provides <c>CedarEngine</c>, the official
/// Cedar core. An implementation must be safe to share between threads, and reports a failure to load or to answer as
/// <see cref="PolicyEngineException"/>. Its inputs are control sets, facts and the Cedar schema — never tool arguments
/// or results.
/// </summary>
public interface IPolicyEngine
{
    /// <summary>The Cedar core's version, e.g. <c>4.14.0</c>; evidence names the engine <c>cedar-policy@&lt;Version&gt;</c>.</summary>
    string Version { get; }

    /// <summary>An <c>isAuthorized</c> call; the answer is <c>{"type":"success","response":…}</c> or <c>{"type":"failure","errors":[…]}</c>.</summary>
    JsonObject Authorize(JsonObject call);

    /// <summary>A <c>validate</c> call; the answer is <c>{"type":"success","validationErrors":[…],…}</c> or <c>{"type":"failure",…}</c>.</summary>
    JsonObject Validate(JsonObject call);
}
