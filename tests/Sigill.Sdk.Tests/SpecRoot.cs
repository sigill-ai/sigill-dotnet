// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.IO;

namespace Sigill.Sdk.Tests;

/// <summary>
/// Test vectors live at <c>spec/</c> at the repository root and are copied into
/// the test project's output directory at build time (see csproj &lt;Content&gt;).
/// </summary>
internal static class SpecRoot
{
    public static string TestVectorsDir =>
        Path.Combine(AppContext.BaseDirectory, "spec", "test-vectors");

    public static string SchemaPath =>
        Path.Combine(AppContext.BaseDirectory, "spec", "ai-evidence-envelope-v1.schema.json");
}
