// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Cross-repo golden vectors for the PDF incremental signer. This SDK's
// Internal/PdfIncrementalSigner is a port of the platform signer, and delegated
// PAdES sealing depends on all implementations producing byte-identical output.
// The same constants are pinned in the platform repo
// (tests/PdfSignerGoldenVectorTests.cs) and the python SDK
// (tests/test_pdf_golden_vectors.py). A failure here means the ports have
// drifted — fix all three repos in the same change set.

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public class PdfSignerGoldenVectorTests
{
    private static readonly byte[] Pdf = Encoding.ASCII.GetBytes(
        "%PDF-1.4\n" +
        "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
        "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
        "xref\n0 4\n0000000000 65535 f \n" +
        "trailer\n<< /Size 4 /Root 1 0 R >>\n" +
        "startxref\n9\n%%EOF\n");

    private static readonly DateTime T1 = new(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);

    private static byte[] Pattern(int len, int mod) =>
        Enumerable.Range(0, len).Select(i => (byte)(i % mod)).ToArray();

    private static string Sha(byte[] b)
    {
        using var sha = SHA256.Create();
        return string.Concat(sha.ComputeHash(b).Select(x => x.ToString("x2")));
    }

    [Fact]
    public void Signer_output_matches_cross_repo_golden_vectors()
    {
        var cms   = Pattern(900, 251);
        var cert  = Pattern(300, 13);
        var ocsp  = Pattern(200, 17);
        var token = Pattern(400, 23);

        var prep = PdfIncrementalSigner.Prepare(Pdf, T1, "Golden Vector", "Golden", "Vector (X)");
        Sha(prep.Bytes).Should().Be("b5d39c763dd5a7e9fc24dad7b070e00b9f0c6c40658c714dca99690b54a6b712");
        string.Concat(prep.DocumentHash.Select(x => x.ToString("x2")))
            .Should().Be("ff51dc7d56810a178dcbc05a43c1cdb34b4f75a0d50351d47ae19faac6a5c83c");

        var embedded = PdfIncrementalSigner.Embed(prep, cms);
        Sha(embedded).Should().Be("cf39c8cc8375423558f89d70efd5f490b473297fee6a4c49fc16794b252603f8");

        var dss = PdfIncrementalSigner.AppendDss(embedded, new[] { cert }, new[] { ocsp }, cms);
        Sha(dss).Should().Be("4640e64a37264e912f331539751f220ba8ac73ddcfc489adad61060d4b01da87");

        var dt = PdfIncrementalSigner.PrepareDocTimestamp(dss);
        Sha(dt.Bytes).Should().Be("ac259ce36157a452883e48b63f7e5819c1fa10b7d7e594aa0802772a8150ae74");
        string.Concat(dt.DocumentHash.Select(x => x.ToString("x2")))
            .Should().Be("811393190bf59d619c02ae2e69b4a6eda7d63007f1554074875c23e8c3b17b24");

        var final = PdfIncrementalSigner.EmbedDocTimestamp(dt, token);
        Sha(final).Should().Be("fb4fa1d61ec7a178a005fb9314ecf9650f4a12b111d483be4bf45c507751bdc5");
    }
}
