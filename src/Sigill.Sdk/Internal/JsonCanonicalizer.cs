// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace Sigill.Sdk.Internal;

/// <summary>
/// RFC 8785 (JSON Canonicalization Scheme) canonicalizer.
///
/// Implementation notes:
///
///  - Top-level input MUST be a JSON object or array. Per RFC 8785 §3.2.4
///    canonicalization is only defined for these.
///  - Object keys are sorted by UTF-16 code-unit order (RFC 8785 §3.2.3),
///    not by codepoint order. For BMP-only keys these coincide; for keys
///    containing supplementary characters they differ. We do the right thing
///    by comparing key strings ordinally — .NET strings ARE UTF-16 sequences,
///    so <see cref="StringComparer.Ordinal"/> gives exactly the spec ordering.
///  - Numbers are formatted via ECMAScript Number.prototype.toString
///    semantics (RFC 8785 §3.2.2.3). For the integer subset that envelopes
///    care about (token counts, durations, ints) this reduces to plain
///    invariant integer formatting. Non-integer doubles are formatted with
///    "R" round-trip and post-processed to match ECMAScript output.
///  - Strings are escaped per RFC 8259 §7 minimal escaping rules.
///
/// This implementation is intentionally minimal and self-contained — no
/// transitive dependencies, no number-formatting library required. It is
/// validated against the cyberphone/json-canonicalization reference test
/// vectors via the cross-language interop tests in
/// tests/Sigill.Sdk.Tests/CanonicalizationVectorTests.cs.
/// </summary>
internal static class JsonCanonicalizer
{
    /// <summary>
    /// Canonicalize a <see cref="JsonElement"/> to RFC 8785 UTF-8 bytes.
    /// </summary>
    public static byte[] Canonicalize(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object && element.ValueKind != JsonValueKind.Array)
        {
            throw new SigillCanonicalizationException(
                $"RFC 8785 only canonicalizes objects or arrays at the top level; got {element.ValueKind}.");
        }
        var sb = new StringBuilder(capacity: 256);
        Serialize(element, sb);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>
    /// Convenience overload: canonicalize JSON text.
    /// </summary>
    public static byte[] Canonicalize(string jsonText)
    {
        using var doc = JsonDocument.Parse(jsonText);
        return Canonicalize(doc.RootElement);
    }

    private static void Serialize(JsonElement element, StringBuilder sb)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                SerializeObject(element, sb);
                break;
            case JsonValueKind.Array:
                SerializeArray(element, sb);
                break;
            case JsonValueKind.String:
                SerializeString(element.GetString()!, sb);
                break;
            case JsonValueKind.Number:
                SerializeNumber(element, sb);
                break;
            case JsonValueKind.True:
                sb.Append("true");
                break;
            case JsonValueKind.False:
                sb.Append("false");
                break;
            case JsonValueKind.Null:
                sb.Append("null");
                break;
            default:
                throw new SigillCanonicalizationException(
                    $"Unsupported JsonValueKind {element.ValueKind} encountered during canonicalization.");
        }
    }

    private static void SerializeObject(JsonElement obj, StringBuilder sb)
    {
        // Per RFC 8785 §3.2.3: sort by UTF-16 code-unit order. .NET strings ARE
        // UTF-16 sequences, so StringComparer.Ordinal is a code-unit-by-code-unit
        // comparison and matches the spec exactly.
        var entries = new List<KeyValuePair<string, JsonElement>>();
        foreach (var prop in obj.EnumerateObject())
        {
            entries.Add(new KeyValuePair<string, JsonElement>(prop.Name, prop.Value));
        }
        entries.Sort((a, b) => string.CompareOrdinal(a.Key, b.Key));

        sb.Append('{');
        for (int i = 0; i < entries.Count; i++)
        {
            if (i > 0) sb.Append(',');
            SerializeString(entries[i].Key, sb);
            sb.Append(':');
            Serialize(entries[i].Value, sb);
        }
        sb.Append('}');
    }

    private static void SerializeArray(JsonElement arr, StringBuilder sb)
    {
        sb.Append('[');
        bool first = true;
        foreach (var item in arr.EnumerateArray())
        {
            if (!first) sb.Append(',');
            first = false;
            Serialize(item, sb);
        }
        sb.Append(']');
    }

    private static void SerializeString(string s, StringBuilder sb)
    {
        // RFC 8259 §7 minimal escaping — same rules JCS specifies.
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"':  sb.Append("\\\""); break;
                case '\b': sb.Append("\\b");  break;
                case '\f': sb.Append("\\f");  break;
                case '\n': sb.Append("\\n");  break;
                case '\r': sb.Append("\\r");  break;
                case '\t': sb.Append("\\t");  break;
                default:
                    if (c < 0x20)
                    {
                        // \u00XX
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
    }

    private static void SerializeNumber(JsonElement num, StringBuilder sb)
    {
        // For the JSON-numeric values our envelopes use (integers and doubles),
        // RFC 8785 §3.2.2.3 mandates ECMAScript Number.prototype.toString
        // formatting. Strategy:
        //
        //  1. If the original token is an exact integer that fits in long, format
        //     it as a plain integer with no exponent (ES toString of integers
        //     matches plain decimal up to ~15 significant digits).
        //  2. Otherwise parse as double, reject NaN/Infinity (I-JSON forbids them),
        //     and emit using a routine that mimics ECMAScript's Number.toString.
        //
        // .NET's "R" round-trip format produces results that differ from
        // ECMAScript output in some edge cases (notably scientific notation
        // boundaries). We reformat to match ES.
        //
        // Note on TryGetInt64 vs raw text: TryGetInt64 returns false for tokens
        // like "1.0" or "1e2" even when they represent integer values, which
        // would push them to the double path. The double-path formatter handles
        // them correctly (1.0 → "1") so this is fine, but as a fast path we also
        // accept any token whose raw text is a plain decimal integer.

        if (num.TryGetInt64(out long l))
        {
            sb.Append(l.ToString(CultureInfo.InvariantCulture));
            return;
        }

        if (!num.TryGetDouble(out double d))
        {
            throw new SigillCanonicalizationException(
                $"Number {num.GetRawText()} cannot be represented as a finite IEEE 754 double.");
        }
        if (double.IsNaN(d) || double.IsInfinity(d))
        {
            throw new SigillCanonicalizationException(
                "NaN/Infinity is not valid JSON and cannot be canonicalized.");
        }
        sb.Append(EcmaScriptNumberToString(d));
    }

    /// <summary>
    /// Format <paramref name="d"/> the way ECMAScript Number.prototype.toString
    /// would, per RFC 8785 §3.2.2.3.
    ///
    /// Reference: ECMA-262 §7.1.12.1 (NumberToString) / §22.1.3.6.
    /// </summary>
    internal static string EcmaScriptNumberToString(double d)
    {
        if (d == 0.0)
        {
            // ES says toString(0) is "0" regardless of sign; RFC 8785 echoes this.
            return "0";
        }

        // Negative numbers: emit '-' and operate on the absolute value.
        if (d < 0)
        {
            return "-" + EcmaScriptNumberToString(-d);
        }

        // Use "R" round-trip to get a decimal representation we can post-process.
        // "R" guarantees Parse(Format(d)) == d on all .NET runtimes from .NET Core 3+.
        string r = d.ToString("R", CultureInfo.InvariantCulture);

        // Decompose into mantissa and exponent.
        // Possible forms from "R": "123", "0.5", "1.5E-05", "1E+21", "-1", etc.
        // We've already stripped the sign above.
        int eIdx = r.IndexOfAny(new[] { 'E', 'e' });
        string mantissa;
        int exponent;
        if (eIdx >= 0)
        {
            mantissa = r.Substring(0, eIdx);
            exponent = int.Parse(r.Substring(eIdx + 1), CultureInfo.InvariantCulture);
        }
        else
        {
            mantissa = r;
            exponent = 0;
        }

        // Split mantissa on '.' to get digits and a decimal point position.
        int dotIdx = mantissa.IndexOf('.');
        string intPart;
        string fracPart;
        if (dotIdx >= 0)
        {
            intPart = mantissa.Substring(0, dotIdx);
            fracPart = mantissa.Substring(dotIdx + 1);
        }
        else
        {
            intPart = mantissa;
            fracPart = "";
        }

        // Combine into a digit-string s and a decimal-point exponent k such that
        // d == 0.<s> * 10^k (using s as a digit string with no leading zeros and
        // no trailing zeros — trailing zeros in the fractional part are
        // insignificant and must be dropped, otherwise we'd format 1.0 as "1.0"
        // instead of ECMAScript's "1").
        //
        // Trim trailing zeros from the combined digit string before computing k,
        // but only those that come from the fractional part — trailing zeros in
        // the integer part are significant and must be preserved (e.g. 100 keeps
        // both zeros).
        string fracTrimmed = fracPart.TrimEnd('0');
        string allDigitsRaw = intPart + fracTrimmed;
        string allDigits = allDigitsRaw.TrimStart('0');
        if (allDigits.Length == 0)
        {
            // Pure zero (we already short-circuited d==0 above; this guards 1e-400 underflow).
            return "0";
        }

        // k = exponent of the decimal point such that d = 0.allDigits * 10^k.
        // intPart digit count is the magnitude of the leading digit position.
        // After trimming leading zeros from (intPart+fracTrimmed), shift k accordingly.
        int trimmedLeading = allDigitsRaw.Length - allDigits.Length;
        int k = intPart.Length + exponent - trimmedLeading;

        // Now decide how to format per ES rules:
        //
        //   - Let n = number of digits in allDigits.
        //   - If k <= n and k > 0:
        //         "ddd.ddd" — digits with the decimal point inserted at position k.
        //         If k == n, no fractional part.
        //   - If 0 < k <= n and the value is integer (no frac digits): plain int.
        //   - If -5 < k <= 0: "0.000ddd" (k zeros after the decimal point).
        //   - If k > n: emit allDigits followed by (k-n) zeros — pure integer.
        //   - Otherwise: scientific notation "d.dddE+exp" or "dE+exp".
        //
        // However ES toString never emits scientific for k > n if the integer fits.
        // The actual ES rule (ECMA-262 §7.1.12.1):
        //
        //   * If k <= n and n - k <= 21: emit as integer (or with trailing zeros).
        //   * If 0 < k <= 21: emit "ddd.ddd".
        //   * If -6 < k <= 0: emit "0.000ddd".
        //   * Else: scientific with "e" lowercase, exponent printed as "+N" / "-N".
        int n = allDigits.Length;
        if (k <= 0)
        {
            if (k > -6)
            {
                // 0.{(-k zeros)}{digits}
                return "0." + new string('0', -k) + allDigits;
            }
        }
        else if (k <= 21)
        {
            if (k >= n)
            {
                // Integer with possibly trailing zeros.
                return allDigits + new string('0', k - n);
            }
            // Decimal with embedded point.
            return allDigits.Substring(0, k) + "." + allDigits.Substring(k);
        }

        // Scientific: a[.bcd]e±exponent, where exponent = k-1.
        string sci;
        if (n == 1)
        {
            sci = allDigits;
        }
        else
        {
            sci = allDigits[0] + "." + allDigits.Substring(1);
        }
        int sciExp = k - 1;
        sci += "e" + (sciExp >= 0 ? "+" : "") + sciExp.ToString(CultureInfo.InvariantCulture);
        return sci;
    }
}
