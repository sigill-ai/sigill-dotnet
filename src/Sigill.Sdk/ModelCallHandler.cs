// Licensed to Sigill under the Apache License, Version 2.0.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk;

/// <summary>
/// Records every model call made through an <see cref="HttpClient"/> as an Agent Model Calls v1 step, with the
/// provider's own identifiers taken from its response. Put it under any provider SDK that accepts an
/// <see cref="HttpClient"/>:
/// <code>
/// var http = new HttpClient(new ModelCallHandler(run, new HttpClientHandler()));
/// var anthropic = new AnthropicClient(new() { HttpClient = http });   // or an OpenAI / Bedrock client
/// </code>
/// Recognised: the Anthropic Messages API, OpenAI Responses and Chat Completions (also via Azure OpenAI), the
/// Amazon Bedrock Runtime Converse / InvokeModel APIs and Google's generateContent (Gemini API and Vertex AI). For any
/// other provider, or a gateway in front of one, call <see cref="AgentRun.RecordModelCallAsync"/> directly. Other requests pass through unrecorded. The request and response
/// bodies are sealed as digests only; their content never leaves the process. A streamed response (server-sent events)
/// is recorded with the identifiers in its headers only. The run must be started with
/// <see cref="AgentRunOptions.RecordsModelCalls"/>. A failure to record never fails the model call: it is reported to
/// <c>onError</c>.
/// </summary>
public sealed class ModelCallHandler : DelegatingHandler
{
    private readonly AgentRun _run;
    private readonly Action<Exception>? _onError;

    public ModelCallHandler(AgentRun run, HttpMessageHandler inner, Action<Exception>? onError = null) : base(inner)
    {
        _run = run ?? throw new ArgumentNullException(nameof(run));
        _onError = onError;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var api = Classify(request);
        if (api is null) return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        byte[]? requestBody = null;
        if (request.Content is not null)
        {
            requestBody = await request.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            var replay = new ByteArrayContent(requestBody);
            foreach (var h in request.Content.Headers) replay.Headers.TryAddWithoutValidation(h.Key, h.Value);
            request.Content = replay;
        }
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        try
        {
            var streamed = response.Content.Headers.ContentType?.MediaType == "text/event-stream";
            byte[]? responseBody = null;
            if (!streamed)
            {
                responseBody = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
                var replay = new ByteArrayContent(responseBody);
                foreach (var h in response.Content.Headers) replay.Headers.TryAddWithoutValidation(h.Key, h.Value);
                response.Content = replay;
            }
            var call = ModelCallParser.Parse(api.Value, request, requestBody, response, responseBody);
            if (call is not null)
                await _run.RecordModelCallAsync(call, requestBody, responseBody, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _onError?.Invoke(ex);
        }
        return response;
    }

    internal enum Api { Anthropic, OpenAi, AzureOpenAi, Bedrock, Gemini, Vertex }

    internal static Api? Classify(HttpRequestMessage request)
    {
        var uri = request.RequestUri;
        if (uri is null || request.Method != HttpMethod.Post) return null;
        var host = uri.Host.ToLowerInvariant();
        var path = uri.AbsolutePath;
        if (host == "api.anthropic.com" && path.EndsWith("/messages", StringComparison.Ordinal)) return Api.Anthropic;
        if (host == "api.openai.com" && (path.EndsWith("/responses", StringComparison.Ordinal) || path.EndsWith("/chat/completions", StringComparison.Ordinal))) return Api.OpenAi;
        // Azure OpenAI resources live under all three Azure AI domains; only the /openai/ API is OpenAI-shaped.
        if ((host.EndsWith(".openai.azure.com", StringComparison.Ordinal) || host.EndsWith(".cognitiveservices.azure.com", StringComparison.Ordinal)
             || host.EndsWith(".services.ai.azure.com", StringComparison.Ordinal)) && path.Contains("/openai/", StringComparison.Ordinal)) return Api.AzureOpenAi;
        if (path.EndsWith(":generateContent", StringComparison.Ordinal))
        {
            if (host == "generativelanguage.googleapis.com") return Api.Gemini;
            if (host == "aiplatform.googleapis.com" || host.EndsWith("-aiplatform.googleapis.com", StringComparison.Ordinal)) return Api.Vertex;
        }
        if (host.StartsWith("bedrock-runtime.", StringComparison.Ordinal) && host.EndsWith(".amazonaws.com", StringComparison.Ordinal)
            && path.StartsWith("/model/", StringComparison.Ordinal)) return Api.Bedrock;
        return null;
    }
}

/// <summary>Reads a provider's response into a <see cref="ModelCall"/> (Agent Model Calls v1 §7). Values only from the response; the request supplies <c>requested</c>.</summary>
internal static class ModelCallParser
{
    public static ModelCall? Parse(ModelCallHandler.Api api, HttpRequestMessage request, byte[]? requestBody, HttpResponseMessage response, byte[]? responseBody)
    {
        var req = TryJson(requestBody);
        var res = TryJson(responseBody);
        string? Header(string name) => response.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() : null;
        string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0 ? s : null;
        long? Long(JsonNode? n) => n is JsonValue v && v.TryGetValue<long>(out var l) ? l : null;
        var refs = new List<VendorRef>();
        void Ref(string provider, string kind, string? id)
        {
            if (id is not null && id.Length <= 255 && id.All(c => c is > ' ' and <= '~') && refs.Count < 8) refs.Add(new VendorRef(provider, kind, id));
        }

        switch (api)
        {
            case ModelCallHandler.Api.Anthropic:
            {
                Ref("anthropic", "message", Str(res?["id"]));
                Ref("anthropic", "request", Header("request-id"));
                var served = Str(res?["model"]);
                var u = res?["usage"] as JsonObject;
                return Build(served is null ? null : new ModelInfo("anthropic", served, Str(req?["model"])), refs,
                    new ModelUsage(Long(u?["input_tokens"]), Long(u?["output_tokens"]), Long(u?["cache_read_input_tokens"]),
                        Long(u?["cache_creation_input_tokens"]), Str(res?["stop_reason"])));
            }
            case ModelCallHandler.Api.OpenAi:
            case ModelCallHandler.Api.AzureOpenAi:
            {
                var provider = api == ModelCallHandler.Api.OpenAi ? "openai" : "azure-openai";
                var id = Str(res?["id"]);
                Ref(provider, id?.StartsWith("chatcmpl", StringComparison.Ordinal) == true ? "completion" : "response", id);
                Ref(provider, "request", Header(api == ModelCallHandler.Api.OpenAi ? "x-request-id" : "apim-request-id"));
                var served = Str(res?["model"]);
                var u = res?["usage"] as JsonObject;
                var stop = (res?["choices"] is JsonArray { Count: > 0 } choices ? Str((choices[0] as JsonObject)?["finish_reason"]) : null) ?? Str(res?["status"]);
                var deployment = api == ModelCallHandler.Api.AzureOpenAi ? DeploymentOf(request.RequestUri!.AbsolutePath) : null;
                return Build(served is null ? null : new ModelInfo(provider, served, Str(req?["model"]), deployment), refs,
                    new ModelUsage(Long(u?["prompt_tokens"] ?? u?["input_tokens"]), Long(u?["completion_tokens"] ?? u?["output_tokens"]),
                        StopReason: stop));
            }
            case ModelCallHandler.Api.Bedrock:
            {
                Ref("aws-bedrock", "request", Header("x-amzn-requestid") ?? Header("x-amzn-request-id"));
                Ref("aws-bedrock", "message", Str(res?["id"]));
                var segments = request.RequestUri!.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                var modelId = segments.Length > 1 ? Uri.UnescapeDataString(segments[1]) : null;
                var region = request.RequestUri.Host.Split('.') is { Length: > 2 } h ? h[1] : null;
                // The model the provider names in its response when it does (InvokeModel with an Anthropic body), else the
                // model id the request addressed — Bedrock routes to exactly that id or inference profile.
                var served = Str(res?["model"]) ?? (modelId?.StartsWith("arn:", StringComparison.Ordinal) == true ? modelId[(modelId.LastIndexOf('/') + 1)..] : modelId);
                var u = res?["usage"] as JsonObject;
                return Build(served is null ? null : new ModelInfo("aws-bedrock", served, null, Fit(modelId, 255), region), refs,
                    new ModelUsage(Long(u?["inputTokens"] ?? u?["input_tokens"]), Long(u?["outputTokens"] ?? u?["output_tokens"]),
                        StopReason: Str(res?["stopReason"]) ?? Str(res?["stop_reason"])));
            }
            case ModelCallHandler.Api.Gemini:
            case ModelCallHandler.Api.Vertex:
            {
                var provider = api == ModelCallHandler.Api.Gemini ? "google" : "google-vertex";
                Ref(provider, "response", Str(res?["responseId"]));
                // .../models/{model}:generateContent; Vertex also names the region: .../locations/{region}/...
                var segments = request.RequestUri!.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                int Index(string name) => Array.IndexOf(segments, name);
                var requested = Index("models") is var m and >= 0 && m + 1 < segments.Length ? segments[m + 1].Split(':')[0] : null;
                var region = api == ModelCallHandler.Api.Vertex && Index("locations") is var l and >= 0 && l + 1 < segments.Length ? segments[l + 1] : null;
                var served = Str(res?["modelVersion"]);
                var u = res?["usageMetadata"] as JsonObject;
                var stop = res?["candidates"] is JsonArray { Count: > 0 } candidates ? Str((candidates[0] as JsonObject)?["finishReason"]) : null;
                return Build(served is null ? null : new ModelInfo(provider, served, requested, Region: region), refs,
                    new ModelUsage(Long(u?["promptTokenCount"]), Long(u?["candidatesTokenCount"]), Long(u?["cachedContentTokenCount"]), StopReason: stop));
            }
        }
        return null;
    }

    private static ModelCall? Build(ModelInfo? model, List<VendorRef> refs, ModelUsage usage)
    {
        // Values are recorded exactly as the provider returned them or not at all: one that does not fit the schema is
        // left out, never shortened (a shortened model name would be a different statement).
        if (model is not null)
            model = Fit(model.Served, 128) is null || Fit(model.Region, 32) is null && model.Region is not null ? null
                : model with { Requested = Fit(model.Requested, 128), Deployment = Fit(model.Deployment, 255) };
        usage = usage with { StopReason = Fit(usage.StopReason, 64) };
        var hasUsage = usage.InputTokens is not null || usage.OutputTokens is not null || usage.CacheReadTokens is not null
            || usage.CacheWriteTokens is not null || usage.StopReason is not null;
        if (model is null && refs.Count == 0) return null;   // nothing the provider said about this call
        return new ModelCall { Model = model, VendorRefs = refs, Usage = hasUsage ? usage : null };
    }

    private static string? DeploymentOf(string path)
    {
        var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var i = Array.IndexOf(parts, "deployments");
        return i >= 0 && i + 1 < parts.Length ? Fit(parts[i + 1], 255) : null;
    }

    private static string? Fit(string? s, int max) => s is { Length: > 0 } && s.Length <= max ? s : null;

    // Only a JSON object is read; anything else (an array, a scalar, not JSON) gives no values.
    private static JsonObject? TryJson(byte[]? body)
    {
        if (body is null || body.Length == 0) return null;
        try { return JsonNode.Parse(body) as JsonObject; } catch (JsonException) { return null; }
    }
}
