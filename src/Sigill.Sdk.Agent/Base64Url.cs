// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;

namespace Sigill.Sdk.Agent;

internal static class Base64Url
{
    public static byte[] Decode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/')
            .PadRight((value.Length + 3) / 4 * 4, '=');
        return Convert.FromBase64String(padded);
    }

    public static string Encode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
