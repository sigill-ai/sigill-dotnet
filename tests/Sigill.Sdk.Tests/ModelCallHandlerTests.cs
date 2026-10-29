// Licensed to Sigill under the Apache License, Version 2.0.

using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Xunit;

namespace Sigill.Sdk.Tests;

/// <summary>ModelCallHandler: model calls recorded from the provider's own response, the content kept local.</summary>
public partial class AgentRunTests
{
    private sealed class Provider(string body, string contentType = "application/json", params (string, string)[] headers) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, contentType) };
            foreach (var (k, v) in headers) r.Headers.TryAddWithoutValidation(k, v);
            return Task.FromResult(r);
        }
    }

    private static async Task<(AgentRun Run, StubSealer Sealer, string Reply)> Through(string url, string requestJson, Provider provider, Action<Exception>? onError = null)
    {
        var sealer = new StubSealer();
        var client = Client(sealer);
        var run = await AgentRun.StartCoreAsync(client, Agent(), Options() with { RecordsModelCalls = true }, Clock(), CancellationToken.None);
        using var http = new HttpClient(new ModelCallHandler(run, provider, onError));
        var reply = await (await http.PostAsync(url, new StringContent(requestJson, Encoding.UTF8, "application/json"))).Content.ReadAsStringAsync();
        return (run, sealer, reply);
    }

    private static JsonNode? ModelStep(AgentRun run) =>
        run.Artifacts.Select(a => a.Envelope["step"]).FirstOrDefault(s => s!["type"]!.GetValue<string>() == "model_output");

    [Fact]
    public async Task Handler_RecordsAnAnthropicCall_FromTheResponse_AndThePromptStaysLocal()
    {
        const string body = """{"id":"msg_01XyZ8kq3VcR2mWd9TfLpA7e","type":"message","model":"claude-sonnet-5-20261015","stop_reason":"tool_use","usage":{"input_tokens":2960,"output_tokens":488,"cache_read_input_tokens":1200},"content":[{"type":"text","text":"Approve for Jane Doe"}]}""";
        var (run, sealer, reply) = await Through("https://api.anthropic.com/v1/messages", """{"model":"claude-sonnet-5","messages":[{"role":"user","content":"Jane Doe"}]}""",
            new Provider(body, headers: ("request-id", "req_011CabcQx7Nn4Tz2Pf8Rk1Ws")));
        reply.Should().Be(body);                                                       // the caller gets the response unchanged
        var step = ModelStep(run)!;
        step["model"]!["provider"]!.GetValue<string>().Should().Be("anthropic");
        step["model"]!["served"]!.GetValue<string>().Should().Be("claude-sonnet-5-20261015");
        step["model"]!["requested"]!.GetValue<string>().Should().Be("claude-sonnet-5");
        step["vendorRefs"]!.AsArray().Select(r => (r!["kind"]!.GetValue<string>(), r["id"]!.GetValue<string>()))
            .Should().Equal(("message", "msg_01XyZ8kq3VcR2mWd9TfLpA7e"), ("request", "req_011CabcQx7Nn4Tz2Pf8Rk1Ws"));
        step["usage"]!["cacheReadTokens"]!.GetValue<long>().Should().Be(1200);
        sealer.Requests.Should().OnlyContain(rq => !rq.ToJsonString().Contains("Jane Doe"));
    }

    [Fact]
    public async Task Handler_RecordsOpenAiAndBedrockCalls()
    {
        var (openai, _, _) = await Through("https://api.openai.com/v1/chat/completions", """{"model":"gpt-6"}""",
            new Provider("""{"id":"chatcmpl-9x","model":"gpt-6-2026-09-01","choices":[{"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}""",
                headers: ("x-request-id", "req_abc123")));
        var o = ModelStep(openai)!;
        o["vendorRefs"]![0]!["kind"]!.GetValue<string>().Should().Be("completion");
        o["usage"]!["stopReason"]!.GetValue<string>().Should().Be("stop");

        var (bedrock, _, _) = await Through("https://bedrock-runtime.eu-north-1.amazonaws.com/model/eu.anthropic.claude-sonnet-5-v1%3A0/converse", "{}",
            new Provider("""{"stopReason":"end_turn","usage":{"inputTokens":7,"outputTokens":3}}""", headers: ("x-amzn-requestid", "4b0a8d3e-1f2c-4d5e-9a7b-0c1d2e3f4a5b")));
        var b = ModelStep(bedrock)!;
        (b["model"]!["served"]!.GetValue<string>(), b["model"]!["region"]!.GetValue<string>()).Should().Be(("eu.anthropic.claude-sonnet-5-v1:0", "eu-north-1"));
        b["vendorRefs"]![0]!["id"]!.GetValue<string>().Should().Be("4b0a8d3e-1f2c-4d5e-9a7b-0c1d2e3f4a5b");
    }

    [Theory]
    [InlineData("https://acme.openai.azure.com/openai/deployments/gpt-6-prod/chat/completions?api-version=2026-06-01")]
    [InlineData("https://acme.cognitiveservices.azure.com/openai/deployments/gpt-6-prod/chat/completions?api-version=2026-06-01")]
    [InlineData("https://acme.services.ai.azure.com/openai/deployments/gpt-6-prod/chat/completions?api-version=2026-06-01")]
    public async Task Handler_RecordsAzureOpenAi_OnEveryAzureAiDomain(string url)
    {
        var (run, _, _) = await Through(url, "{}",
            new Provider("""{"id":"chatcmpl-AZ1","model":"gpt-6-2026-09-01","choices":[{"finish_reason":"stop"}]}""", headers: ("apim-request-id", "6f1e2d3c-aaaa-bbbb-cccc-0123456789ab")));
        var step = ModelStep(run)!;
        (step["model"]!["provider"]!.GetValue<string>(), step["model"]!["deployment"]!.GetValue<string>()).Should().Be(("azure-openai", "gpt-6-prod"));
        step["vendorRefs"]!.AsArray().Select(r => r!["kind"]!.GetValue<string>()).Should().Equal("completion", "request");
    }

    [Fact]
    public async Task Handler_RecordsGoogleGenerateContent_OnTheGeminiApiAndVertex()
    {
        const string body = """{"responseId":"mT4xaKXyJ8-tz7IPq9GJ","modelVersion":"gemini-3.0-pro-001","candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":4,"cachedContentTokenCount":8}}""";
        var (gemini, _, _) = await Through("https://generativelanguage.googleapis.com/v1beta/models/gemini-3.0-pro:generateContent", "{}", new Provider(body));
        var g = ModelStep(gemini)!;
        (g["model"]!["provider"]!.GetValue<string>(), g["model"]!["served"]!.GetValue<string>(), g["model"]!["requested"]!.GetValue<string>())
            .Should().Be(("google", "gemini-3.0-pro-001", "gemini-3.0-pro"));
        (g["vendorRefs"]![0]!["kind"]!.GetValue<string>(), g["vendorRefs"]![0]!["id"]!.GetValue<string>()).Should().Be(("response", "mT4xaKXyJ8-tz7IPq9GJ"));
        (g["usage"]!["cacheReadTokens"]!.GetValue<long>(), g["usage"]!["stopReason"]!.GetValue<string>()).Should().Be((8, "STOP"));

        var (vertex, _, _) = await Through("https://europe-west4-aiplatform.googleapis.com/v1/projects/acme/locations/europe-west4/publishers/google/models/gemini-3.0-pro:generateContent", "{}", new Provider(body));
        var v = ModelStep(vertex)!;
        (v["model"]!["provider"]!.GetValue<string>(), v["model"]!["region"]!.GetValue<string>()).Should().Be(("google-vertex", "europe-west4"));
    }

    [Fact]
    public async Task Handler_PassesOtherRequestsThrough_RecordsStreamsByHeader_AndNeverFailsTheCall()
    {
        var (other, _, _) = await Through("https://example.com/api", "{}", new Provider("""{"id":"x"}"""));
        ModelStep(other).Should().BeNull();

        var (stream, _, _) = await Through("https://api.anthropic.com/v1/messages", """{"model":"claude-sonnet-5","stream":true}""",
            new Provider("event: message_start\ndata: {}\n\n", "text/event-stream", ("request-id", "req_stream1")));
        var s = ModelStep(stream)!;
        s["vendorRefs"]!.AsArray().Should().ContainSingle().Which!["id"]!.GetValue<string>().Should().Be("req_stream1");

        Exception? seen = null;
        var (bad, _, reply) = await Through("https://api.anthropic.com/v1/messages", "{}", new Provider("[not an object"), e => seen = e);
        reply.Should().Be("[not an object");                                         // the model call itself is untouched
        ModelStep(bad).Should().BeNull();                                             // nothing the provider said: nothing recorded
        seen.Should().BeNull();
    }
}
