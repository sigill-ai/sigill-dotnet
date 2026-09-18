using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Sigill.Sdk.Agent.Tests;

/// <summary>
/// Lager en JWS med samme form som platformens: protected header med sigD
/// (pars, hashV, ctys) og en signaturverdi. Signaturen er ikke kryptografisk
/// gyldig; den er deterministisk avledet av konvolutthashen, slik at kjede og
/// binding kan testes uten platform.
/// </summary>
public sealed class FakeArtifactSealer : IArtifactSealer
{
    public int Calls { get; private set; }

    /// <summary>Klokken tidsstempelet (sigTst) får. Settes av testen for å styre tidsrekkefølgen.</summary>
    /// <remarks>Standard ligger fem minutter etter referansekjøringens faste tidslinje, så en falsk kjøring forsegles etter hendelsene, som en ærlig produsent.</remarks>
    public DateTimeOffset Clock { get; set; } = new(2026, 9, 16, 8, 5, 0, TimeSpan.Zero);

    public Task<JsonObject> SealAsync(
        string envelopeHashHex, IReadOnlyList<SignedObjectDigest> objects, string envelopeContentType,
        CancellationToken cancellationToken = default)
    {
        Calls++;
        var pars = new JsonArray { AgentProfiles.EnvelopeUri };
        var hashV = new JsonArray { B64Url(Convert.FromHexString(envelopeHashHex)) };
        var ctys = new JsonArray { envelopeContentType };
        foreach (var o in objects)
        {
            pars.Add(o.Uri);
            hashV.Add(B64Url(Convert.FromHexString(o.HashHex)));
            ctys.Add(o.ContentType ?? "");
        }
        var header = new JsonObject
        {
            ["alg"] = "ES256",
            ["b64"] = false,
            ["crit"] = new JsonArray { "sigD", "b64" },
            ["sigD"] = new JsonObject
            {
                ["mId"] = "http://uri.etsi.org/19182/ObjectIdByURIHash",
                ["pars"] = pars,
                ["hashM"] = "S256",
                ["hashV"] = hashV,
                ["ctys"] = ctys,
            },
        };
        var protectedB64 = B64Url(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var signatureValue = SHA256.HashData(Encoding.UTF8.GetBytes("fake-signer:" + envelopeHashHex + ":" + Calls));
        var sigTst = new JsonObject
        {
            ["sigTst"] = new JsonObject
            {
                ["tstTokens"] = new JsonArray { new JsonObject { ["val"] = Convert.ToBase64String(TestTsa.Token(SHA256.HashData(signatureValue), Clock)) } },
            },
        };
        var signature = new JsonObject
        {
            ["signatures"] = new JsonArray
            {
                new JsonObject
                {
                    ["protected"] = protectedB64,
                    ["header"] = new JsonObject { ["etsiU"] = new JsonArray { B64Url(Encoding.UTF8.GetBytes(sigTst.ToJsonString())) } },
                    ["signature"] = B64Url(signatureValue),
                },
            },
        };
        Clock = Clock.AddSeconds(1);
        return Task.FromResult(signature);
    }

    /// <summary>
    /// Kopi av et artefakt der digesten for ett objekt i sigD.hashV er byttet ut og
    /// signaturverdien lagd på nytt: en forfalsket evaluering som binder et annet kontrollsett.
    /// </summary>
    public static AgentArtifact WithReplacedObjectDigest(AgentArtifact artifact, string uri, string newHashHex)
    {
        var entry = Binding.ClassicalEntry(artifact.Signature)!;
        var header = Binding.ProtectedHeader(entry)!;
        var pars = (JsonArray)header["sigD"]!["pars"]!;
        var hashV = (JsonArray)header["sigD"]!["hashV"]!;
        var index = pars.Select((p, i) => (p, i)).First(t => t.p!.GetValue<string>() == uri).i;
        hashV[index] = B64Url(Convert.FromHexString(newHashHex));
        var protectedB64 = B64Url(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var signature = new JsonObject
        {
            ["signatures"] = new JsonArray
            {
                new JsonObject { ["protected"] = protectedB64, ["signature"] = B64Url(SHA256.HashData(Encoding.UTF8.GetBytes(protectedB64))) },
            },
        };
        return new AgentArtifact(artifact.Envelope.DeepClone().AsObject(), signature);
    }

    private static string B64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
