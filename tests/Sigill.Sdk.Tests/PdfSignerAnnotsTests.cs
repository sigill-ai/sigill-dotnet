// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Regression tests for the page /Annots handling in the PDF signer port.
//
// PowerPoint/Office exporters commonly emit the page's annotation array as an
// indirect object (/Annots 9 0 R). The signer used to miss that form and
// append a SECOND /Annots key to the page dictionary — duplicate dictionary
// keys are undefined behaviour per ISO 32000-1 §7.3.7, and a last-wins parser
// silently drops every pre-existing annotation from the sealed document.
//
// Mirrors the platform's tests/PdfIncrementalSignerAnnotsTests.cs and the
// python SDK's tests/test_pdf_annots.py. The fixture is assembled
// programmatically so its xref offsets and startxref are byte-accurate — a
// structurally valid PDF, not just signer-parseable text.

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public class PdfSignerAnnotsTests
{
    private static readonly DateTime T1 = new(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);

    /// <summary>
    /// Minimal but structurally valid PDF: correct xref entry offsets, correct
    /// startxref, one page whose /Annots is an INDIRECT reference to object 5,
    /// which holds one link annotation (object 4).
    /// </summary>
    private static byte[] BuildIndirectAnnotsPdf()
    {
        var sb = new StringBuilder("%PDF-1.4\n");
        var offsets = new Dictionary<int, int>();

        void Obj(int id, string body)
        {
            offsets[id] = sb.Length;
            sb.Append($"{id} 0 obj\n{body}\nendobj\n");
        }

        Obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        Obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        Obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots 5 0 R >>");
        Obj(4, "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] >>");
        Obj(5, "[4 0 R]");

        int xrefPos = sb.Length;
        sb.Append("xref\n0 6\n0000000000 65535 f \n");
        for (int id = 1; id <= 5; id++)
            sb.Append($"{offsets[id]:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 6 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefPos}\n%%EOF\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    [Fact]
    public void Fixture_IsStructurallyValid()
    {
        AssertXrefChainResolves(Encoding.ASCII.GetString(BuildIndirectAnnotsPdf()));
    }

    [Fact]
    public void Prepare_IndirectAnnots_PatchesArrayObjectNotPage()
    {
        var pdf  = BuildIndirectAnnotsPdf();
        var prep = PdfIncrementalSigner.Prepare(pdf, T1);
        var text = Encoding.GetEncoding(28591).GetString(prep.Bytes);
        var increment = text[pdf.Length..];

        // The array object is re-emitted with the old annot preserved and the
        // new signature widget appended (widget id 7 = MaxObjectId 5 + sig 6).
        increment.Should().Contain("5 0 obj\n[4 0 R 7 0 R]");

        // The page dictionary is NOT re-emitted, so no duplicate /Annots key
        // can exist: exactly one /Annots across the whole file, still the
        // indirect reference in the original page dict.
        Regex.Matches(text, @"/Annots").Should().HaveCount(1);
        Regex.Matches(text, @"/Annots\s+5\s+0\s+R").Should().HaveCount(1);
        increment.Should().NotContain("3 0 obj");

        // Every xref section in the signed output resolves to a real object
        // header at the recorded byte offset.
        AssertXrefChainResolves(text);
    }

    [Fact]
    public void Prepare_SigDict_CarriesSignerName()
    {
        var pdf  = BuildIndirectAnnotsPdf();
        var prep = PdfIncrementalSigner.Prepare(pdf, T1, "Golden Vector");
        var increment = Encoding.GetEncoding(28591).GetString(prep.Bytes)[pdf.Length..];
        increment.Should().Contain("/Name (Golden Vector)");
    }

    [Fact]
    public void Prepare_WithoutSignerName_OmitsNameKey()
    {
        var pdf  = BuildIndirectAnnotsPdf();
        var prep = PdfIncrementalSigner.Prepare(pdf, T1);
        var increment = Encoding.GetEncoding(28591).GetString(prep.Bytes)[pdf.Length..];
        increment.Should().NotContain("/Name");
    }

    [Fact]
    public void PrepareDocTimestamp_DictHasNoMEntry()
    {
        var pdf      = BuildIndirectAnnotsPdf();
        var prep     = PdfIncrementalSigner.Prepare(pdf, T1);
        var embedded = PdfIncrementalSigner.Embed(prep, new byte[] { 1, 2, 3 });
        var dt       = PdfIncrementalSigner.PrepareDocTimestamp(embedded);

        var text = Encoding.GetEncoding(28591).GetString(dt.Bytes);
        var increment = text[embedded.Length..];
        var dtDict = Regex.Match(increment, @"<< /Type /DocTimeStamp.*?>>", RegexOptions.Singleline);
        dtDict.Success.Should().BeTrue();
        // EN 319 142-1 §5.4.3: /M should not be present — readers take the
        // time from the token's genTime.
        dtDict.Value.Should().NotContain("/M (");

        AssertXrefChainResolves(text);
    }

    /// <summary>
    /// Follow every xref table in the file and require that every in-use
    /// entry's offset lands on "N 0 obj" for the declared object number.
    /// </summary>
    private static void AssertXrefChainResolves(string text)
    {
        var sections = Regex.Matches(text, @"(?<=^|\n)xref\r?\n");
        sections.Should().NotBeEmpty("the file must contain at least one xref table");

        foreach (Match section in sections)
        {
            int pos = section.Index + section.Length;
            while (true)
            {
                var header = Regex.Match(text[pos..], @"^(\d+)\s+(\d+)\r?\n");
                if (!header.Success) break;
                int start = int.Parse(header.Groups[1].Value);
                int count = int.Parse(header.Groups[2].Value);
                pos += header.Length;

                for (int i = 0; i < count; i++)
                {
                    var entry = text.Substring(pos, 20);
                    pos += 20;
                    if (entry[17] != 'n') continue; // free entry
                    int off = int.Parse(entry[..10]);
                    var expected = $"{start + i} 0 obj";
                    text.Substring(off, expected.Length).Should().Be(expected,
                        $"xref entry for object {start + i} points at offset {off}");
                }
            }
        }

        // startxref of the LAST revision must point at an xref keyword.
        var sx = Regex.Match(text, @"startxref\s+(\d+)\s*%%EOF", RegexOptions.RightToLeft);
        sx.Success.Should().BeTrue();
        text.Substring(int.Parse(sx.Groups[1].Value), 4).Should().Be("xref");
    }
}
