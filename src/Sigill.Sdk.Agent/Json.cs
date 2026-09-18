// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Globalization;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent;

internal static class Json
{
    public static string? ReadString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;

    public static int? ReadInt(JsonNode? node) =>
        node is JsonValue value && int.TryParse(value.ToJsonString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var i) ? i : null;

    public static string Timestamp(DateTimeOffset time) =>
        time.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
