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
/// Validation against the Agent Evidence Profiles v1 JSON Schemas, embedded
/// from <c>spec/*.schema.json</c>. Implements exactly the keywords those
/// schemas use (type, required, properties, additionalProperties, const,
/// enum, items, minItems, minLength, minimum, pattern, format, allOf, anyOf,
/// not, if/then/else, contains/minContains/maxContains, local $ref); a schema
/// using anything else is rejected at load time rather than silently
/// half-checked. Messages match the Python SDK byte for byte; the agent-run
/// vectors pin them.
/// </summary>
internal static class EnvelopeSchema
{
    private static readonly Dictionary<string, string> Resources = new(StringComparer.Ordinal)
    {
        [AgentProfiles.ControlArtifactSchema] = "Sigill.Sdk.agent-control-artifact-v1.schema.json",
        [AgentProfiles.ExecutionEvidenceSchema] = "Sigill.Sdk.agent-execution-evidence-v1.schema.json",
        [AgentProfiles.ControlEvaluationSchema] = "Sigill.Sdk.control-evaluation-v1.schema.json",
    };

    private static readonly HashSet<string> Supported = new(StringComparer.Ordinal)
    {
        "$schema", "$id", "$defs", "$ref", "title", "description", "type", "required", "properties",
        "additionalProperties", "const", "enum", "items", "minItems", "minLength", "minimum", "pattern", "format",
        "allOf", "anyOf", "not", "if", "then", "else", "contains", "minContains", "maxContains",
    };

    private static readonly Regex Ident = new("^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant);
    private static readonly Regex Uuid = new(
        "^(urn:uuid:)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant);
    private static readonly Regex UriReference = new(
        @"^([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$", RegexOptions.CultureInvariant);
    private static readonly Regex DateTimePattern = new(
        @"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$", RegexOptions.CultureInvariant);

    private static readonly Dictionary<string, Lazy<JsonObject>> Schemas = Resources.ToDictionary(
        kv => kv.Key, kv => new Lazy<JsonObject>(() => Load(kv.Value)), StringComparer.Ordinal);

    private static JsonObject Load(string resourceName)
    {
        using var stream = typeof(EnvelopeSchema).Assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded schema '{resourceName}' is missing.");
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
        foreach (var key in new[] { "items", "additionalProperties", "not", "if", "then", "else", "contains" })
            if (node[key] is JsonObject sub) CheckKeywords(sub);
        foreach (var key in new[] { "allOf", "anyOf" })
            if (node[key] is JsonArray list)
                foreach (var sub in list.OfType<JsonObject>()) CheckKeywords(sub);
    }

    /// <summary>RFC 3339 date-time; fractional seconds of any length.</summary>
    internal static bool TryParseDateTime(string? s, out DateTimeOffset value)
    {
        value = default;
        return s is not null && DateTimePattern.IsMatch(s)
            && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out value);
    }

    /// <summary>A UUID; the <c>urn:uuid:</c> form is accepted (common rules §1).</summary>
    internal static bool IsUuid(string? s) => s is not null && Uuid.IsMatch(s);

    /// <summary>Every violation of the named profile's schema (<c>AgentControlArtifact</c>, …).</summary>
    public static List<string> Validate(JsonNode? envelope, string schemaName)
    {
        var schema = Schemas[schemaName].Value;
        var errs = new List<string>();
        Validate(envelope, schema, schema, "", errs);
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
        if (AgentProfiles.Str(schema["$ref"]) is { } reference)
        {
            const string prefix = "#/$defs/";
            if (!reference.StartsWith(prefix, StringComparison.Ordinal))
                throw new InvalidOperationException($"unsupported $ref '{reference}'");
            Validate(instance, root["$defs"]![reference.Substring(prefix.Length)]!.AsObject(), root, path, errs);
            return;
        }

        var kind = KindOf(instance, out var number);
        if (AgentProfiles.Str(schema["type"]) is { } type && !TypeOk(kind, type))
        {
            errs.Add($"{Label(path)} must be of type {type}");
            return;
        }
        if (schema.ContainsKey("const") && !JsonNode.DeepEquals(instance, schema["const"]))
            errs.Add($"{Label(path)} must equal {schema["const"]!.ToJsonString()}");
        if (schema["enum"] is JsonArray values && !values.Any(e => JsonNode.DeepEquals(instance, e)))
            errs.Add($"{Label(path)} must be one of {string.Join(", ", values.Select(EnumText))}");
        if (kind == Kind.String && AgentProfiles.Str(instance) is { } s)
        {
            if (AgentProfiles.Int(schema["minLength"]) is int minLength && s.Length < minLength)
                errs.Add($"{Label(path)} is shorter than {minLength}");
            if (AgentProfiles.Str(schema["pattern"]) is { } pattern && !Regex.IsMatch(s, pattern, RegexOptions.CultureInvariant))
                errs.Add($"{Label(path)} does not match {pattern}");
            if (AgentProfiles.Str(schema["format"]) is { } format && !FormatOk(s, format))
                errs.Add($"{Label(path)} is not a valid {format}");
        }
        if (kind is Kind.Integer or Kind.Number && schema["minimum"] is { } minNode)
        {
            KindOf(minNode, out var minimum);
            if (number < minimum) errs.Add($"{Label(path)} must be >= {NumberText(minimum)}");
        }
        if (instance is JsonArray arr)
        {
            if (AgentProfiles.Int(schema["minItems"]) is int minItems && arr.Count < minItems)
                errs.Add($"{Label(path)} must have at least {minItems} item{(minItems == 1 ? "" : "s")}");
            if (schema["items"] is JsonObject items)
                for (var i = 0; i < arr.Count; i++)
                    Validate(arr[i], items, root, path.Length == 0 ? $"[{i}]" : $"{path}[{i}]", errs);
            if (schema["contains"] is JsonObject contains)
            {
                var matches = arr.Count(x => IsValid(x, contains, root));
                var min = AgentProfiles.Int(schema["minContains"]) ?? 1;
                var max = AgentProfiles.Int(schema["maxContains"]);
                if (matches < min) errs.Add($"{Label(path)} must contain at least {min} {Describe(contains)}");
                if (max is int m && matches > m) errs.Add($"{Label(path)} must contain at most {m} {Describe(contains)}");
            }
        }
        if (instance is JsonObject obj)
        {
            if (schema["required"] is JsonArray required)
                foreach (var key in required.Select(AgentProfiles.Str).OfType<string>())
                    if (!obj.ContainsKey(key)) errs.Add($"{Label(path)} is missing required member '{key}'");
            var props = schema["properties"] as JsonObject;
            var additional = schema["additionalProperties"];
            foreach (var kv in obj)
            {
                if (props?[kv.Key] is JsonObject propSchema) Validate(kv.Value, propSchema, root, Child(path, kv.Key), errs);
                else if (props?.ContainsKey(kv.Key) == true) { /* declared with a non-object schema: nothing to check */ }
                else if (additional is JsonValue av && av.TryGetValue<bool>(out var allowed) && !allowed)
                    errs.Add($"{Label(path)} has unknown member '{kv.Key}'");
                else if (additional is JsonObject addSchema) Validate(kv.Value, addSchema, root, Child(path, kv.Key), errs);
            }
        }
        if (schema["allOf"] is JsonArray allOf)
            foreach (var sub in allOf.OfType<JsonObject>()) Validate(instance, sub, root, path, errs);
        if (schema["anyOf"] is JsonArray anyOf && !anyOf.OfType<JsonObject>().Any(sub => IsValid(instance, sub, root)))
            errs.Add($"{Label(path)} must match at least one of the allowed shapes");
        if (schema["not"] is JsonObject not && IsValid(instance, not, root))
            errs.Add($"{Label(path)} {DescribeNot(not)}");
        if (schema["if"] is JsonObject cond)
        {
            var branch = IsValid(instance, cond, root) ? schema["then"] : schema["else"];
            if (branch is JsonObject b) Validate(instance, b, root, path, errs);
        }
    }

    private static bool IsValid(JsonNode? instance, JsonObject schema, JsonObject root)
    {
        var errs = new List<string>();
        Validate(instance, schema, root, "", errs);
        return errs.Count == 0;
    }

    /// <summary>"item with role \"control-set\"" for a contains schema that pins one member, else "matching item".</summary>
    private static string Describe(JsonObject contains)
    {
        if (contains["properties"] is JsonObject props && props.Count == 1)
        {
            var (name, sub) = props.First();
            if (sub is JsonObject s && s.ContainsKey("const"))
                return $"item with {name} {s["const"]!.ToJsonString()}";
        }
        return "matching item";
    }

    /// <summary>The members a <c>not</c> forbids, for the shapes the profiles use (required, anyOf of required).</summary>
    private static string DescribeNot(JsonObject not)
    {
        static IEnumerable<string> Names(JsonObject s) =>
            (s["required"] as JsonArray ?? new JsonArray()).Select(AgentProfiles.Str).OfType<string>();
        if (not.Count == 1 && not["required"] is JsonArray)
            return "must not carry " + string.Join(", ", Names(not).Select(n => $"'{n}'"));
        if (not.Count == 1 && not["anyOf"] is JsonArray alts && alts.All(a => a is JsonObject o && o.Count == 1 && o["required"] is JsonArray))
            return "must not carry any of " + string.Join(", ", alts.OfType<JsonObject>().SelectMany(Names).Select(n => $"'{n}'"));
        return "must not match the disallowed shape";
    }
}
