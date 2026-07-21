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
    private static readonly DateTime T2 = new(2026, 1, 2, 3, 4, 6, DateTimeKind.Utc);

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

        var prep = PdfIncrementalSigner.Prepare(Pdf, T1, "Golden", "Vector (X)");
        Sha(prep.Bytes).Should().Be("03ccfbecd8e840624613d05687b0e3a99530593b361d11f6de0461d2eb6fcde5");
        string.Concat(prep.DocumentHash.Select(x => x.ToString("x2")))
            .Should().Be("47266535eedf3ff5f91439055ed9048f171279cf6fe2209cc0d4bf0e2ddbb7e2");

        var embedded = PdfIncrementalSigner.Embed(prep, cms);
        Sha(embedded).Should().Be("fe12166e8359c77615becf76b0be828fa65ef591f5d42b0669f61f6a686b882b");

        var dss = PdfIncrementalSigner.AppendDss(embedded, new[] { cert }, new[] { ocsp }, cms);
        Sha(dss).Should().Be("d2d8ac0179883b29edad8d18f3c0ef69db7613c45bfdb878f6acb043097256d3");

        var dt = PdfIncrementalSigner.PrepareDocTimestamp(dss, T2);
        Sha(dt.Bytes).Should().Be("6756707d60d22f50ee34a3850c5a48bd0f67db9de8adfc41b5ee47d4f79fd913");
        string.Concat(dt.DocumentHash.Select(x => x.ToString("x2")))
            .Should().Be("e6270386b20cfe1a67e2c12e7ae99e2f3e1d223844e6870f09fbfad17cea6148");

        var final = PdfIncrementalSigner.EmbedDocTimestamp(dt, token);
        Sha(final).Should().Be("bd088853743d90d82ee4cdb79aaa1d4fc2f9543ed12078ff0ab58c00c33bdb51");
    }
}
