// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sigill.Sdk.Internal;

/// <summary>
/// Validation against the AI evidence v2 JSON Schema, embedded from
/// <c>spec/ai-evidence-envelope-v2.schema.json</c>. Implements exactly the
/// keywords that schema uses (type, required, properties,
/// additionalProperties, const, enum, items, minLength, minimum, pattern,
/// format, local $ref); a schema using anything else is rejected at load
/// time rather than silently half-checked. Messages match the Python SDK
/// byte for byte; the agent-run vectors pin them.
/// </summary>
internal static class EnvelopeSchema
{
    private const string ResourceName = "Sigill.Sdk.ai-evidence-envelope-v2.schema.json";

    private static readonly HashSet<string> Supported = new(StringComparer.Ordinal)
    {
        "$schema", "$id", "$defs", "$ref", "title", "description", "type", "required", "properties",
        "additionalProperties", "const", "enum", "items", "minLength", "minimum", "pattern", "format",
    };

    private static readonly Regex Ident = new("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant);
    private static readonly Regex Uuid = new(
        "^(urn:uuid:)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant);
    private static readonly Regex UriReference = new(
        @"^([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$", RegexOptions.CultureInvariant);
    private static readonly Regex DateTimePattern = new(
        @"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant);

    private static readonly Lazy<JsonObject> Schema = new(Load);

    private static JsonObject Load()
    {
        using var stream = typeof(EnvelopeSchema).Assembly.GetManifestResourceStream(ResourceName)
            ?? throw new InvalidOperationException($"Embedded schema '{ResourceName}' is missing.");
        using var reader = new StreamReader(stream);
        var schema = JsonNode.Parse(reader.ReadToEnd())!.AsObject();
        CheckKeywords(schema);
        return schema;
    }

    private static void CheckKeywords(JsonObject node)
    {
        var unknown = node.Select(kv => kv.Key).Where(k => !Supported.Contains(k)).ToList();
        if (unknown.Count > 0) throw new InvalidOperationException("unsupported JSON Schema keyword(s): " + string.Join(", ", unknown));
        foreach (var key in new[] { "properties", "$defs" })
            if (node[key] is JsonObject map)
                foreach (var kv in map) if (kv.Value is JsonObject sub) CheckKeywords(sub);
        foreach (var key in new[] { "items", "additionalProperties" })
            if (node[key] is JsonObject sub) CheckKeywords(sub);
    }

    /// <summary>RFC 3339 date-time; fractional seconds of any length.</summary>
    internal static bool TryParseDateTime(string? s, out DateTimeOffset value)
    {
        value = default;
        return s is not null && DateTimePattern.IsMatch(s)
            && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value);
    }

    /// <summary>Every violation of the AI evidence v2 envelope schema.</summary>
    public static List<string> ValidateEnvelopeV2(JsonNode? envelope)
    {
        var errs = new List<string>();
        Validate(envelope, Schema.Value, Schema.Value, "", errs);
        return errs;
    }

    // ── JSON kinds without depending on how the node was created ────────────

    private enum Kind { Null, Object, Array, String, Boolean, Integer, Number }

    private static Kind KindOf(JsonNode? node, out double number)
    {
        number = 0;
        switch (node)
        {
            case null: return Kind.Null;
            case JsonObject: return Kind.Object;
            case JsonArray: return Kind.Array;
        }
        var v = (JsonValue)node;
        if (v.TryGetValue<JsonElement>(out var el))
            switch (el.ValueKind)
            {
                case JsonValueKind.String: return Kind.String;
                case JsonValueKind.True or JsonValueKind.False: return Kind.Boolean;
                case JsonValueKind.Null: return Kind.Null;
                case JsonValueKind.Number:
                    number = el.GetDouble();
                    return number == Math.Floor(number) && !double.IsInfinity(number) ? Kind.Integer : Kind.Number;
            }
        if (v.TryGetValue<string>(out _)) return Kind.String;
        if (v.TryGetValue<bool>(out _)) return Kind.Boolean;
        if (v.TryGetValue<int>(out var i)) { number = i; return Kind.Integer; }
        if (v.TryGetValue<long>(out var l)) { number = l; return Kind.Integer; }
        if (v.TryGetValue<double>(out var d)) { number = d; return d == Math.Floor(d) && !double.IsInfinity(d) ? Kind.Integer : Kind.Number; }
        if (v.TryGetValue<decimal>(out var m)) { number = (double)m; return m == decimal.Floor(m) ? Kind.Integer : Kind.Number; }
        if (v.TryGetValue<float>(out var f)) { number = f; return f == Math.Floor(f) ? Kind.Integer : Kind.Number; }
        return Kind.Number;
    }

    private static bool TypeOk(Kind kind, string type) => type switch
    {
        "object" => kind == Kind.Object,
        "array" => kind == Kind.Array,
        "string" => kind == Kind.String,
        "boolean" => kind == Kind.Boolean,
        "integer" => kind == Kind.Integer,
        "number" => kind is Kind.Integer or Kind.Number,
        "null" => kind == Kind.Null,
        _ => false,
    };

    private static bool FormatOk(string value, string format) => format switch
    {
        "date-time" => TryParseDateTime(value, out _),
        "uuid" => Uuid.IsMatch(value), // urn:uuid accepted for compatibility (profile §2)
        "uri-reference" => UriReference.IsMatch(value),
        _ => true,
    };

    private static string Child(string path, string key)
    {
        var seg = Ident.IsMatch(key) ? "." + key : $"['{key}']";
        return path.Length == 0 ? seg.TrimStart('.') : path + seg;
    }

    private static string Label(string path) => path.Length == 0 ? "envelope" : path;

    private static string NumberText(double n) =>
        n == Math.Floor(n) ? ((long)n).ToString(CultureInfo.InvariantCulture) : n.ToString("R", CultureInfo.InvariantCulture);

    private static string EnumText(JsonNode? e) =>
        e is JsonValue v && v.TryGetValue<string>(out var s) ? s : e?.ToJsonString() ?? "None";

    private static void Validate(JsonNode? instance, JsonObject schema, JsonObject root, string path, List<string> errs)
    {
        if (AgentExecutionProfile.Str(schema["$ref"]) is { } reference)
        {
            const string prefix = "#/$defs/";
            if (!reference.StartsWith(prefix, StringComparison.Ordinal))
                throw new InvalidOperationException($"unsupported $ref '{reference}'");
            Validate(instance, root["$defs"]![reference.Substring(prefix.Length)]!.AsObject(), root, path, errs);
            return;
        }

        var kind = KindOf(instance, out var number);
        if (AgentExecutionProfile.Str(schema["type"]) is { } type && !TypeOk(kind, type))
        {
            errs.Add($"{Label(path)} must be of type {type}");
            return;
        }
        if (schema.ContainsKey("const") && !JsonNode.DeepEquals(instance, schema["const"]))
            errs.Add($"{Label(path)} must equal {schema["const"]!.ToJsonString()}");
        if (schema["enum"] is JsonArray values && !values.Any(e => JsonNode.DeepEquals(instance, e)))
            errs.Add($"{Label(path)} must be one of {string.Join(", ", values.Select(EnumText))}");
        if (kind == Kind.String && AgentExecutionProfile.Str(instance) is { } s)
        {
            if (AgentExecutionProfile.Int(schema["minLength"]) is int minLength && s.Length < minLength)
                errs.Add($"{Label(path)} is shorter than {minLength}");
            if (AgentExecutionProfile.Str(schema["pattern"]) is { } pattern && !Regex.IsMatch(s, pattern, RegexOptions.CultureInvariant))
                errs.Add($"{Label(path)} does not match {pattern}");
            if (AgentExecutionProfile.Str(schema["format"]) is { } format && !FormatOk(s, format))
                errs.Add($"{Label(path)} is not a valid {format}");
        }
        if (kind is Kind.Integer or Kind.Number && schema["minimum"] is { } minNode)
        {
            KindOf(minNode, out var minimum);
            if (number < minimum) errs.Add($"{Label(path)} must be >= {NumberText(minimum)}");
        }
        if (instance is JsonArray arr && schema["items"] is JsonObject items)
            for (var i = 0; i < arr.Count; i++)
                Validate(arr[i], items, root, path.Length == 0 ? $"[{i}]" : $"{path}[{i}]", errs);
        if (instance is JsonObject obj)
        {
            if (schema["required"] is JsonArray required)
                foreach (var key in required.Select(AgentExecutionProfile.Str).OfType<string>())
                    if (!obj.ContainsKey(key)) errs.Add($"{Label(path)} is missing required member '{key}'");
            var props = schema["properties"] as JsonObject;
            var additional = schema["additionalProperties"];
            foreach (var kv in obj)
            {
                if (props?[kv.Key] is JsonObject propSchema) Validate(kv.Value, propSchema, root, Child(path, kv.Key), errs);
                else if (additional is JsonValue av && av.TryGetValue<bool>(out var allowed) && !allowed)
                    errs.Add($"{Label(path)} has unknown member '{kv.Key}'");
                else if (additional is JsonObject addSchema) Validate(kv.Value, addSchema, root, Child(path, kv.Key), errs);
            }
        }
    }
}
