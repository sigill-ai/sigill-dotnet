// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Sigill.Sdk.Internal;

/// <summary>
/// Thin wrapper around <see cref="Rfc3161TimestampToken"/> that pulls out the
/// fields the verifier needs. We DO NOT chain-validate the TSA cert — that
/// requires a trust anchor policy and is intentionally out of scope for v1.
/// What we do verify is that the TSR parses, contains a TSTInfo with a
/// recognizable hash algorithm, and embeds a message-imprint we can compare
/// against the envelope's canonical bytes.
/// </summary>
internal static class TsrParser
{
    public static ParsedTimestamp Parse(string tsrBase64)
    {
        if (string.IsNullOrWhiteSpace(tsrBase64))
            throw new SigillInvalidProofException("tsrBase64 is empty");

        byte[] bytes;
        try { bytes = Convert.FromBase64String(tsrBase64); }
        catch (FormatException ex) { throw new SigillInvalidProofException("tsrBase64 is not valid base64", ex); }

        Rfc3161TimestampToken token;
        try
        {
            // TryDecode false → bad token; an exception path is uncommon but possible.
            if (!Rfc3161TimestampToken.TryDecode(bytes, out var t, out _))
                throw new SigillInvalidProofException("TSR is not a well-formed RFC 3161 TimeStampToken");
            token = t!;
        }
        catch (CryptographicException ex)
        {
            throw new SigillInvalidProofException("TSR could not be parsed as RFC 3161 TimeStampToken", ex);
        }

        var info = token.TokenInfo;
        var alg = OidToHashName(info.HashAlgorithmId.Value ?? string.Empty);
        if (alg is null)
            throw new SigillInvalidProofException($"TSR uses unsupported hash algorithm OID '{info.HashAlgorithmId.Value}'");

        var imprint = info.GetMessageHash().ToArray();
        var hex = EnvelopeHashing.ToLowerHex(imprint);
        var serial = EnvelopeHashing.ToLowerHex(info.GetSerialNumber().ToArray());

        // Best-effort signing-cert subject CN, for diagnostics.
        string? tsaName = null;
        try
        {
            // The cert collection is on the SignedCms; pick any cert with EKU=timestamping
            // and use its subject CN.
            var cms = token.AsSignedCms();
            foreach (X509Certificate2 cert in cms.Certificates)
            {
                tsaName = ExtractCommonName(cert.Subject);
                if (tsaName is not null) break;
            }
        }
        catch
        {
            // tsaName is informational; never let extraction failure abort parsing.
        }

        return new ParsedTimestamp(
            TsaName: tsaName,
            GenTime: info.Timestamp,
            Serial: serial,
            HashAlgorithm: alg,
            HashedMessageHex: hex,
            Qualified: false,                       // set externally from the proof envelope field
            PolicyOid: info.PolicyId?.Value);
    }

    private static string? OidToHashName(string oid) => oid switch
    {
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        _ => null,
    };

    private static string? ExtractCommonName(string distinguishedName)
    {
        // X509Certificate2.Subject is a comma-separated DN; parse out CN= robustly enough.
        // If the CN itself contains commas it'll be quoted — handle that.
        const string cnPrefix = "CN=";
        var idx = distinguishedName.IndexOf(cnPrefix, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;
        var rest = distinguishedName.Substring(idx + cnPrefix.Length);
        if (rest.StartsWith("\"", StringComparison.Ordinal))
        {
            var endQuote = rest.IndexOf('"', 1);
            return endQuote > 0 ? rest.Substring(1, endQuote - 1) : null;
        }
        var endComma = rest.IndexOf(',');
        return endComma > 0 ? rest.Substring(0, endComma).Trim() : rest.Trim();
    }
}
