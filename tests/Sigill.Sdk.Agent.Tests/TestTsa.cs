using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>Lager RFC 3161-tokens med valgt genTime, så tidsrekkefølgen kan testes uten platform. Speiler kjernens TsrFactory.</summary>
internal static class TestTsa
{
    private static readonly object Lock = new();
    private static AsymmetricCipherKeyPair? _key;
    private static X509Certificate? _cert;

    public static byte[] Token(byte[] messageImprintSha256, DateTimeOffset genTime)
    {
        var (key, cert) = Identity();
        var serial = BigIntegers.CreateRandomBigInteger(64, new SecureRandom());
        const string sha256 = "2.16.840.1.101.3.4.2.1";
        var request = new TimeStampRequestGenerator().Generate(sha256, messageImprintSha256, serial);
        var tokenGen = new TimeStampTokenGenerator(key.Private, cert, sha256, "1.2.3.4.5");
        tokenGen.SetCertificates(new SingletonStore(cert));
        var response = new TimeStampResponseGenerator(tokenGen, TspAlgorithms.Allowed).Generate(request, serial, genTime.UtcDateTime);
        return (response.TimeStampToken ?? throw new InvalidOperationException(response.GetStatusString())).GetEncoded();
    }

    private static (AsymmetricCipherKeyPair, X509Certificate) Identity()
    {
        lock (Lock)
        {
            if (_key is not null && _cert is not null) return (_key, _cert);
            var gen = new RsaKeyPairGenerator();
            gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            _key = gen.GenerateKeyPair();
            var name = new X509Name("CN=Sigill.Sdk.Agent Test TSA");
            var certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(BigIntegers.CreateRandomBigInteger(64, new SecureRandom()));
            certGen.SetIssuerDN(name);
            certGen.SetSubjectDN(name);
            certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
            certGen.SetNotAfter(DateTime.UtcNow.AddDays(365));
            certGen.SetPublicKey(_key.Public);
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeID.id_kp_timeStamping));
            _cert = certGen.Generate(new Asn1SignatureFactory("SHA256WithRSA", _key.Private));
            return (_key, _cert);
        }
    }

    private sealed class SingletonStore(X509Certificate item) : IStore<X509Certificate>
    {
        public IEnumerable<X509Certificate> EnumerateMatches(ISelector<X509Certificate>? selector)
        {
            if (selector is null || selector.Match(item)) yield return item;
        }
    }
}
