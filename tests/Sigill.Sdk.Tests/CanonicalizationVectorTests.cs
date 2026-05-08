// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

/// <summary>
/// THE cross-language interop tests. The committed canonical.json files in
/// spec/test-vectors/*/ are produced by the Python reference using the cyberphone
/// `jcs` library; this test asserts our .NET canonicalizer produces byte-identical
/// output for the same input. If this ever fails, either the spec moved or one of
/// the SDKs drifted — both are release-blocking.
/// </summary>
public class CanonicalizationVectorTests
{
    [Theory]
    [InlineData("01-complete-ai-call")]
    [InlineData("02-pii-redacted")]
    public void Canonical_bytes_match_committed_vector(string vectorName)
    {
        var vec = Path.Combine(SpecRoot.TestVectorsDir, vectorName);
        var expectedJsonObj = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;
        var expectedCanonical = File.ReadAllBytes(Path.Combine(vec, "canonical.json"));

        // Strip integrity.envelopeHash and proofs (per spec §4) and canonicalize.
        if (expectedJsonObj["integrity"] is JsonObject integrity) integrity.Remove("envelopeHash");
        expectedJsonObj.Remove("proofs");

        var actual = EnvelopeHashing.Canonicalize(expectedJsonObj);
        actual.Should().Equal(expectedCanonical, "canonical bytes must match committed reference");
    }

    [Theory]
    [InlineData("01-complete-ai-call")]
    [InlineData("02-pii-redacted")]
    public void Envelope_hash_matches_committed_vector(string vectorName)
    {
        var vec = Path.Combine(SpecRoot.TestVectorsDir, vectorName);
        var expected = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;
        var expectedHex = File.ReadAllText(Path.Combine(vec, "envelope-hash.txt")).Trim();

        var (hex, _) = EnvelopeHashing.ComputeEnvelopeHash(expected);
        hex.Should().Be(expectedHex);
    }

    [Theory]
    [InlineData("01-complete-ai-call")]
    [InlineData("02-pii-redacted")]
    public void Committed_canonical_bytes_hash_to_committed_envelope_hash(string vectorName)
    {
        // Sanity: catches drift if someone hand-edits one but not the other.
        var vec = Path.Combine(SpecRoot.TestVectorsDir, vectorName);
        var canonical = File.ReadAllBytes(Path.Combine(vec, "canonical.json"));
        var expectedHex = File.ReadAllText(Path.Combine(vec, "envelope-hash.txt")).Trim();
        EnvelopeHashing.HashHex(canonical).Should().Be(expectedHex);
    }

    [Fact]
    public void Envelope_hash_is_independent_of_proofs()
    {
        // Adding proofs after sealing must not change envelopeHash. That's the whole
        // point of stripping proofs before hashing — it lets you append archival
        // re-stamps without invalidating earlier proofs.
        var vec = Path.Combine(SpecRoot.TestVectorsDir, "01-complete-ai-call");
        var env = (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(vec, "expected.json")))!;
        var (h1, _) = EnvelopeHashing.ComputeEnvelopeHash(env);

        env["proofs"] = new JsonArray(
            new JsonObject { ["type"] = "rfc3161", ["tsrBase64"] = "AAAA", ["tsaName"] = "DigiCert" },
            new JsonObject { ["type"] = "rfc3161", ["tsrBase64"] = "BBBB", ["tsaName"] = "Sectigo" });
        var (h2, _) = EnvelopeHashing.ComputeEnvelopeHash(env);
        h2.Should().Be(h1);
    }

    [Fact]
    public void Key_order_in_input_does_not_affect_canonical_output()
    {
        var a = JsonNode.Parse("""{"b":2,"a":1,"c":{"y":2,"x":1}}""")!.AsObject();
        var b = JsonNode.Parse("""{"c":{"x":1,"y":2},"a":1,"b":2}""")!.AsObject();
        EnvelopeHashing.Canonicalize(a).Should().Equal(EnvelopeHashing.Canonicalize(b));
    }

    [Fact]
    public void Unicode_keys_and_values_canonicalize_deterministically()
    {
        var a = JsonNode.Parse("""{"unicode":"Tjørstad","asciiKey":"value"}""")!.AsObject();
        var canonical = Encoding.UTF8.GetString(EnvelopeHashing.Canonicalize(a));
        // asciiKey sorts before unicode in code-unit order
        canonical.Should().Be("""{"asciiKey":"value","unicode":"Tjørstad"}""");
    }

    [Fact]
    public void Canonicalize_rejects_top_level_non_object_or_array()
    {
        // RFC 8785 §3.2.4: top level must be object or array.
        var s = JsonDocument.Parse("\"hi\"").RootElement;
        var act = () => JsonCanonicalizer.Canonicalize(s);
        act.Should().Throw<SigillCanonicalizationException>();
    }

    // ---- ECMAScript number formatting smoke tests ---------------------------

    [Theory]
    [InlineData(0.0, "0")]
    [InlineData(-0.0, "0")]
    [InlineData(1.0, "1")]
    [InlineData(-1.0, "-1")]
    [InlineData(42.0, "42")]
    [InlineData(0.5, "0.5")]
    [InlineData(1.5, "1.5")]
    [InlineData(9007199254740991.0, "9007199254740991")]  // 2^53 - 1
    public void EcmaScript_number_to_string_matches_spec(double d, string expected)
    {
        JsonCanonicalizer.EcmaScriptNumberToString(d).Should().Be(expected);
    }
}
