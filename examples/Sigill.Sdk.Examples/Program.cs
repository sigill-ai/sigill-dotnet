// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

// dotnet run --project examples/Sigill.Sdk.Examples -- loop|graph|approval
// Environment: SIGILL_BASE_URL (optional), SIGILL_API_KEY, SIGILL_CERTIFICATE_ID, SIGILL_CA_BUNDLE (optional: a PEM file of the
// private CA that issued the endpoint's TLS certificate; then only that bundle is trusted).

using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Sigill.Sdk;
using Sigill.Sdk.Examples;
using Sigill.Sdk.Policy;

if (args.Length != 1 || !EnforcementScenarios.Names.Contains(args[0]))
{
    Console.Error.WriteLine($"usage: dotnet run --project examples/Sigill.Sdk.Examples -- {string.Join("|", EnforcementScenarios.Names)}");
    return 2;
}
static string Env(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } v ? v
    : throw new InvalidOperationException($"Set {name}.");

var handler = new HttpClientHandler();
if (Environment.GetEnvironmentVariable("SIGILL_CA_BUNDLE") is { Length: > 0 } bundle)
{
    var roots = new X509Certificate2Collection();
    roots.ImportFromPemFile(bundle);
    handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
    {
        // The host name must still match; the chain must end in the bundle, and only there.
        if (certificate is null || (errors & ~SslPolicyErrors.RemoteCertificateChainErrors) != SslPolicyErrors.None) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(certificate);
    };
}
using var http = new HttpClient(handler)
{
    BaseAddress = new Uri(Environment.GetEnvironmentVariable("SIGILL_BASE_URL") is { Length: > 0 } url ? url : SigillClient.DefaultBaseUrl),
    Timeout = TimeSpan.FromSeconds(60),
};
http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Env("SIGILL_API_KEY"));
http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
using var client = new SigillClient(http);
using var engine = new CedarEngine();

var results = await EnforcementScenarios.RunAsync(args[0], client, Guid.Parse(Env("SIGILL_CERTIFICATE_ID")), engine,
    AgentRunVerifier.Remote(client), Console.Out);
return results.All(r => r.Verdict == "run_finalized") ? 0 : 1;
