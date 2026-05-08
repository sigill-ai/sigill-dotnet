// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Synthetic RFC 3161 TimeStampToken builder for tests.
//
// We DO NOT hit a real TSA in tests — that's flaky and slow. Instead this builds a
// well-formed TimeStampToken (CMS SignedData over a TSTInfo) using BouncyCastle's
// TSP utilities and a self-signed throwaway TSA cert. The token parses cleanly with
// .NET's Rfc3161TimestampToken.TryDecode and lets the verification tests exercise
// the proof-checking paths without any network.

using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;

namespace Sigill.Sdk.Tests;

internal static class TsrFactory
{
    private static readonly object _lock = new();
    private static AsymmetricCipherKeyPair? _keyPair;
    private static X509Certificate? _cert;

    /// <summary>Get (or lazily generate) the throwaway TSA identity used for fixtures.</summary>
    public static (AsymmetricCipherKeyPair Key, X509Certificate Cert) EnsureIdentity()
    {
        lock (_lock)
        {
            if (_keyPair is not null && _cert is not null)
                return (_keyPair, _cert);

            // RSA-2048 keypair
            var gen = new RsaKeyPairGenerator();
            gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            _keyPair = gen.GenerateKeyPair();

            // Self-signed cert with EKU = id-kp-timeStamping (1.3.6.1.5.5.7.3.8) — required
            // for any TSP cert.
            var subject = new X509Name("CN=Sigill SDK Test TSA, O=Sigill SDK Tests");
            var serial = BigIntegers.CreateRandomBigInteger(64, new SecureRandom());
            var notBefore = DateTime.UtcNow.AddMinutes(-5);
            var notAfter = DateTime.UtcNow.AddDays(365);

            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(serial);
            certGen.SetIssuerDN(subject);
            certGen.SetSubjectDN(subject);
            certGen.SetNotBefore(notBefore);
            certGen.SetNotAfter(notAfter);
            certGen.SetPublicKey(_keyPair.Public);
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));

            var sigFactory = new Asn1SignatureFactory("SHA256WithRSA", _keyPair.Private);
            _cert = certGen.Generate(sigFactory);

            return (_keyPair, _cert);
        }
    }

    /// <summary>
    /// Construct a DER-encoded RFC 3161 TimeStampToken whose message-imprint is
    /// <paramref name="messageImprint"/>. Returns the bytes that go into
    /// <c>proofs[].tsrBase64</c> after base64 encoding.
    /// </summary>
    public static byte[] MakeTsr(byte[] messageImprint, string hashAlg = "SHA-256", DateTime? genTime = null)
    {
        var (keyPair, cert) = EnsureIdentity();
        var actualGenTime = genTime ?? DateTime.UtcNow;
        var serial = BigIntegers.CreateRandomBigInteger(64, new SecureRandom());

        var hashOid = hashAlg switch
        {
            "SHA-256" => "2.16.840.1.101.3.4.2.1",
            "SHA-384" => "2.16.840.1.101.3.4.2.2",
            "SHA-512" => "2.16.840.1.101.3.4.2.3",
            _ => throw new ArgumentException($"unsupported hash algorithm: {hashAlg}", nameof(hashAlg)),
        };

        // Build a TimeStampRequest first — the easy way to use BC's TimeStampTokenGenerator.
        var reqGen = new TimeStampRequestGenerator();
        reqGen.SetCertReq(true);
        var req = reqGen.Generate(hashOid, messageImprint, serial);

        // Generate the response (which contains the token).
        var tokenGen = new TimeStampTokenGenerator(keyPair.Private, cert, hashOid, "1.2.3.4.5");
        var certs = X509StoreFactory.Create("Certificate/Collection",
            new X509CollectionStoreParameters(new List<X509Certificate> { cert }));
        tokenGen.SetCertificates(certs);

        var responseGen = new TimeStampResponseGenerator(tokenGen, TspAlgorithms.Allowed);
        var response = responseGen.Generate(req, serial, actualGenTime);
        var token = response.TimeStampToken
            ?? throw new InvalidOperationException("TimeStampToken not produced (status=" + response.Status + ")");

        return token.GetEncoded();
    }
}
