// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.Text.Json.Nodes;

namespace Sigill.Sdk.Internal;

/// <summary>
/// JsonNode helpers. Specifically: a polyfill for <c>DeepClone()</c>, which is
/// only available on .NET 8+. For netstandard2.1 we fall back to a JSON
/// parse/serialize round-trip — slower but semantically equivalent for the
/// envelope shapes we produce (no metadata, no comments, no JsonNodeOptions).
/// </summary>
internal static class JsonNodeExtensions
{
#if NET8_0_OR_GREATER
    public static JsonNode? CloneNode(this JsonNode? node) => node?.DeepClone();
    public static JsonObject CloneObject(this JsonObject obj) => (JsonObject)obj.DeepClone();
    public static JsonArray CloneArray(this JsonArray arr) => (JsonArray)arr.DeepClone();
#else
    public static JsonNode? CloneNode(this JsonNode? node) =>
        node is null ? null : JsonNode.Parse(node.ToJsonString());
    public static JsonObject CloneObject(this JsonObject obj) =>
        (JsonObject)JsonNode.Parse(obj.ToJsonString())!;
    public static JsonArray CloneArray(this JsonArray arr) =>
        (JsonArray)JsonNode.Parse(arr.ToJsonString())!;
#endif
}
