// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace Sigill.Sdk.Agent;

internal static class Envelopes
{
    public static JsonObject Core(string schemaName, DateTimeOffset createdAt, JsonObject actor, JsonObject activity) => new()
    {
        ["schemaName"] = schemaName,
        ["schemaVersion"] = AgentProfiles.SchemaVersion,
        ["evidenceId"] = $"urn:uuid:{Guid.NewGuid()}",
        ["createdAt"] = Json.Timestamp(createdAt),
        ["actor"] = actor,
        ["activity"] = activity,
    };

    /// <summary>
    /// Legger objects[] i konvolutten i samme rekkefølge som digestlisten, hasher
    /// konvolutten og forsegler. Rekkefølgen er det som gjør sigD.pars[1…] og
    /// envelope.objects[] indeksjusterte (envelope-v2 §5.2).
    /// </summary>
    public static async Task<AgentArtifact> SealAsync(
        JsonObject envelope,
        IReadOnlyList<DetachedObject> objects,
        string contentType,
        IArtifactSealer sealer,
        CancellationToken cancellationToken)
    {
        if (sealer is null) throw new ArgumentNullException(nameof(sealer));
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in objects)
            if (!seen.Add(o.Uri))
                throw new SigillException($"To detached objects har samme URI '{o.Uri}'.");

        envelope["objects"] = new JsonArray(objects.Select(o => (JsonNode)o.ToEnvelopeEntry()).ToArray());
        var envelopeHashHex = EnvelopeHashing.HashHex(EnvelopeHashing.Canonicalize(envelope));
        var signature = await sealer.SealAsync(
            envelopeHashHex, objects.Select(o => o.ToDigest()).ToList(), contentType, cancellationToken)
            .ConfigureAwait(false);
        return new AgentArtifact(envelope, signature);
    }
}
