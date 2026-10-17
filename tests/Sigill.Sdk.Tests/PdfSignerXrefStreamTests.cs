// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0
//
// Incremental updates on cross-reference-stream PDFs.
//
// PDF 1.5+ writers commonly replace the classic "xref" table with a
// cross-reference STREAM (an object << /Type /XRef ... >> at startxref). The
// signer used to append a classic table to such documents; its trailer's /Prev
// then pointed at a cross-reference stream, a mixed chain that strict readers
// (Adobe Acrobat among them) refuse to follow — the signature shows as invalid.
// Every revision the signer appends must use the base document's format.
//
// Mirrors the python SDK's tests/test_pdf_xref_stream.py; the golden vector
// below is pinned with the same constants there (tests/test_pdf_golden_vectors.py).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using FluentAssertions;
using Sigill.Sdk.Internal;
using Xunit;

namespace Sigill.Sdk.Tests;

public class PdfSignerXrefStreamTests
{
    private static readonly DateTime T1 = new(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
    private static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

    /// <summary>A minimal but structurally valid PDF whose only cross-reference
    /// section is a cross-reference STREAM (object 4) — no classic table.</summary>
    internal static byte[] BuildXrefStreamPdf()
    {
        var bytes   = new List<byte>();
        var offsets = new Dictionary<int, int>();
        void Ascii(string s) => bytes.AddRange(Encoding.ASCII.GetBytes(s));
        void Obj(int id, string body) { offsets[id] = bytes.Count; Ascii($"{id} 0 obj\n{body}\nendobj\n"); }

        Ascii("%PDF-1.5\n");
        Obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        Obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        Obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");

        int xrefPos = bytes.Count;
        // /W [1 4 2]; entries for objects 0..4 (object 4 is this stream itself).
        (int Type, long Off, int Gen)[] e =
        {
            (0, 0, 65535), (1, offsets[1], 0), (1, offsets[2], 0), (1, offsets[3], 0), (1, xrefPos, 0),
        };
        var data = new byte[e.Length * 7];
        for (int i = 0; i < e.Length; i++)
        {
            int p = i * 7; uint o = (uint)e[i].Off;
            data[p] = (byte)e[i].Type;
            data[p + 1] = (byte)(o >> 24); data[p + 2] = (byte)(o >> 16);
            data[p + 3] = (byte)(o >> 8);  data[p + 4] = (byte)o;
            data[p + 5] = (byte)(e[i].Gen >> 8); data[p + 6] = (byte)e[i].Gen;
        }
        Ascii($"4 0 obj\n<< /Type /XRef /Size 5 /Root 1 0 R /W [1 4 2] /Index [0 5] /Length {data.Length} >>\nstream\n");
        bytes.AddRange(data);
        Ascii("\nendstream\nendobj\n");
        Ascii($"startxref\n{xrefPos}\n%%EOF\n");
        return bytes.ToArray();
    }

    private static byte[] BuildClassicPdf()
    {
        var sb = new StringBuilder("%PDF-1.4\n");
        var offsets = new Dictionary<int, int>();
        void Obj(int id, string body) { offsets[id] = sb.Length; sb.Append($"{id} 0 obj\n{body}\nendobj\n"); }
        Obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        Obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        Obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        int xrefPos = sb.Length;
        sb.Append("xref\n0 4\n0000000000 65535 f \n");
        for (int id = 1; id <= 3; id++) sb.Append($"{offsets[id]:D10} 00000 n \n");
        sb.Append("trailer\n<< /Size 4 /Root 1 0 R >>\n");
        sb.Append($"startxref\n{xrefPos}\n%%EOF\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    private static byte[] Pattern(int len, int mod) =>
        Enumerable.Range(0, len).Select(i => (byte)(i % mod)).ToArray();

    private static string Hex(byte[] b) => string.Concat(b.Select(x => x.ToString("x2")));

    private static string Sha(byte[] b)
    {
        using var sha = SHA256.Create();
        return Hex(sha.ComputeHash(b));
    }

    // ── reading helpers ─────────────────────────────────────────────────────

    private static long LastStartXref(byte[] pdf)
    {
        var m = Regex.Match(Latin1.GetString(pdf), @"startxref\s+(\d+)\s*%%EOF", RegexOptions.RightToLeft);
        m.Success.Should().BeTrue();
        return long.Parse(m.Groups[1].Value);
    }

    private sealed record XrefStream(int Id, int Size, long? Prev, int[] Index,
        Dictionary<int, (int Type, long Off, int Gen)> Entries);

    /// <summary>Parse the (unfiltered) cross-reference stream object at <paramref name="pos"/>.</summary>
    private static XrefStream ReadXrefStream(byte[] pdf, long pos)
    {
        var t = Latin1.GetString(pdf);
        var head = Regex.Match(t.Substring((int)pos), @"^(\d+) 0 obj\s*<<(.*?)>>\s*stream\r?\n", RegexOptions.Singleline);
        head.Success.Should().BeTrue($"an xref stream object is expected at {pos}");
        var d = head.Groups[2].Value;
        d.Should().MatchRegex(@"/Type\s*/XRef\b").And.NotContain("/Filter");
        var w     = Regex.Match(d, @"/W\s*\[([^\]]*)\]").Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(int.Parse).ToArray();
        int size  = int.Parse(Regex.Match(d, @"/Size\s+(\d+)").Groups[1].Value);
        var im    = Regex.Match(d, @"/Index\s*\[([^\]]*)\]");
        var index = im.Success ? im.Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(int.Parse).ToArray() : new[] { 0, size };
        int len   = int.Parse(Regex.Match(d, @"/Length\s+(\d+)").Groups[1].Value);
        var pm    = Regex.Match(d, @"/Prev\s+(\d+)");

        int dataStart = (int)pos + head.Length;
        t.Substring(dataStart + len, 10).Should().Be("\nendstream");
        int row = w.Sum();
        int count = 0;
        for (int i = 1; i < index.Length; i += 2) count += index[i];
        len.Should().Be(row * count, "/Length must match /W x /Index");

        var entries = new Dictionary<int, (int, long, int)>();
        int k = 0;
        for (int s = 0; s < index.Length; s += 2)
            for (int n = 0; n < index[s + 1]; n++, k++)
            {
                var f = new long[3];
                int p = dataStart + k * row;
                for (int c = 0; c < 3; c++)
                {
                    long v = w[c] == 0 ? 1 : 0;
                    for (int b = 0; b < w[c]; b++) v = (v << 8) | pdf[p + b];
                    f[c] = v; p += w[c];
                }
                entries[index[s] + n] = ((int)f[0], f[1], (int)f[2]);
            }
        return new XrefStream(int.Parse(head.Groups[1].Value), size,
            pm.Success ? long.Parse(pm.Groups[1].Value) : null, index, entries);
    }

    /// <summary>Follow startxref → /Prev → … through cross-reference streams only,
    /// requiring every in-use entry to land on "N 0 obj" for its own number.</summary>
    private static List<(long Pos, XrefStream X)> WalkChain(byte[] pdf)
    {
        var t = Latin1.GetString(pdf);
        var chain = new List<(long, XrefStream)>();
        long? pos = LastStartXref(pdf);
        while (pos is long p)
        {
            t.Substring((int)p, 4).Should().NotBe("xref", "a classic table must not appear in a stream chain");
            var x = ReadXrefStream(pdf, p);
            foreach (var (id, (type, off, _)) in x.Entries)
                if (type == 1)
                    t.Substring((int)off).Should().StartWith($"{id} 0 obj", $"entry for object {id} must land on its header");
            chain.Add((p, x));
            pos = x.Prev;
        }
        return chain;
    }

    private static int[] ByteRange(byte[] pdf)
    {
        var m = Regex.Match(Latin1.GetString(pdf), @"/ByteRange\s*\[(\d+) (\d+) (\d+) (\d+)\s*\]", RegexOptions.RightToLeft);
        m.Success.Should().BeTrue();
        return Enumerable.Range(1, 4).Select(i => int.Parse(m.Groups[i].Value)).ToArray();
    }

    private static byte[] RangeDigest(byte[] pdf, int[] br)
    {
        using var sha = SHA256.Create();
        sha.TransformBlock(pdf, br[0], br[1], null, 0);
        sha.TransformFinalBlock(pdf, br[2], br[3]);
        return sha.Hash!;
    }

    // ── tests ───────────────────────────────────────────────────────────────

    [Fact]
    public void Classic_base_still_emits_classic_table()
    {
        var pdf = BuildClassicPdf();
        var inc = Latin1.GetString(PdfIncrementalSigner.Prepare(pdf, T1).Bytes)[pdf.Length..];
        inc.Should().Contain("\nxref\n").And.NotContain("/Type /XRef");
    }

    [Fact]
    public void Startxref_at_non_xref_object_stays_classic()
    {
        // A startxref that points at an ordinary object (approximate offsets in
        // hand-made PDFs) keeps the classic format — only an object that really
        // is /Type /XRef switches the output to a stream.
        var text = Latin1.GetString(BuildClassicPdf());
        int catalog = text.IndexOf("1 0 obj", StringComparison.Ordinal);
        var bogus = Latin1.GetBytes(Regex.Replace(text, @"startxref\n\d+\n", $"startxref\n{catalog}\n"));
        var inc = Latin1.GetString(PdfIncrementalSigner.Prepare(bogus, T1).Bytes)[bogus.Length..];
        inc.Should().Contain("\nxref\n").And.NotContain("/Type /XRef");
    }

    [Fact]
    public void Prepare_on_xref_stream_base_appends_xref_stream()
    {
        var pdf    = BuildXrefStreamPdf();
        long baseSx = LastStartXref(pdf);
        var prep   = PdfIncrementalSigner.Prepare(pdf, T1, "Signer");
        var outp   = prep.Bytes;
        var inc    = Latin1.GetString(outp)[pdf.Length..];

        inc.Should().Contain("/Type /XRef").And.NotContain("\nxref\n").And.NotContain("trailer");

        long newSx = LastStartXref(outp);
        newSx.Should().BeGreaterThan(pdf.Length);
        var x = ReadXrefStream(outp, newSx);

        // Base max object number is 4 (its own xref stream): signature 5,
        // field 6, new AcroForm 7, so the new cross-reference stream is object 8.
        x.Id.Should().Be(8);
        x.Size.Should().Be(9);
        x.Prev.Should().Be(baseSx);
        x.Index.Should().Equal(1, 1, 3, 1, 5, 1, 6, 1, 7, 1, 8, 1);
        x.Entries[8].Should().Be((1, newSx, 0));
        var text = Latin1.GetString(outp);
        foreach (var (id, (type, off, gen)) in x.Entries)
        {
            type.Should().Be(1); gen.Should().Be(0);
            off.Should().BeGreaterOrEqualTo(pdf.Length);
            text.Substring((int)off).Should().StartWith($"{id} 0 obj\n");
        }
        text.Should().EndWith($"startxref\n{newSx}\n%%EOF\n");

        var br = ByteRange(outp);
        br[0].Should().Be(0);
        (br[2] + br[3]).Should().Be(outp.Length);
        outp[br[1]].Should().Be((byte)'<');
        outp[br[2] - 1].Should().Be((byte)'>');
        prep.ContentsHexOffset.Should().Be(br[1] + 1);
        prep.DocumentHash.Should().Equal(RangeDigest(outp, br));
        PdfIncrementalSigner.Recover(outp).DocumentHash.Should().Equal(prep.DocumentHash);
    }

    [Fact]
    public void Full_B_LTA_chain_on_xref_stream_base_round_trips()
    {
        var pdf    = BuildXrefStreamPdf();
        var cms    = Pattern(900, 251);
        var signed = PdfIncrementalSigner.Embed(PdfIncrementalSigner.Prepare(pdf, T1, "Signer"), cms);
        var dss    = PdfIncrementalSigner.AppendDss(signed, new[] { Pattern(300, 13) }, new[] { Pattern(200, 17) }, cms);
        var dt     = PdfIncrementalSigner.PrepareDocTimestamp(dss);
        var final  = PdfIncrementalSigner.EmbedDocTimestamp(dt, Pattern(400, 23));

        Latin1.GetString(final).Should().NotContain("\nxref\n");
        var chain = WalkChain(final);
        chain.Select(c => c.Pos).Should().Equal(
            LastStartXref(dt.Bytes), LastStartXref(dss), LastStartXref(signed), LastStartXref(pdf));

        var ids = chain.Select(c => c.X.Id).ToArray();
        ids.Should().BeInDescendingOrder().And.OnlyHaveUniqueItems();
        foreach (var (_, x) in chain.Take(3)) x.Size.Should().Be(x.Id + 1);

        var br = ByteRange(final);
        br[0].Should().Be(0);
        (br[2] + br[3]).Should().Be(final.Length);
        dt.DocumentHash.Should().Equal(RangeDigest(final, br));
    }

    [Fact]
    public void Xref_stream_base_matches_cross_repo_golden_vectors()
    {
        // Same inputs as PdfSignerGoldenVectorTests, on the xref-stream fixture.
        var pdf   = BuildXrefStreamPdf();
        var cms   = Pattern(900, 251);
        var token = Pattern(400, 23);
        Sha(pdf).Should().Be("f1453825b415c460ef1cc3fb4803c2a6bad0a8fc99cead5f13ed286f889f7ccb");

        var prep = PdfIncrementalSigner.Prepare(pdf, T1, "Golden Vector", "Golden", "Vector (X)");
        Sha(prep.Bytes).Should().Be("7525b1739ee2d3d1684cabef5afda8d4a556fd5923e4a9763ba8e56980e0b75f");
        Hex(prep.DocumentHash).Should().Be("74f0fbcf173edf47607bc019f343d941f60ad900cc85763bbe1565b45a04500a");

        var embedded = PdfIncrementalSigner.Embed(prep, cms);
        Sha(embedded).Should().Be("5cb46d3b0d407355f4098b6809d83d10541cc8b5b1cb9c429380ecfa35338825");

        var dss = PdfIncrementalSigner.AppendDss(embedded, new[] { Pattern(300, 13) }, new[] { Pattern(200, 17) }, cms);
        Sha(dss).Should().Be("3d48f64fd256131d06597730184d6ff9a8cf5f53c99e01b8be431cf8bfd11736");

        var dt = PdfIncrementalSigner.PrepareDocTimestamp(dss);
        Sha(dt.Bytes).Should().Be("d8bae000cce77ec1760da90607d1ab2e9e605cc57d83593c65c5512d33f6b4eb");
        Hex(dt.DocumentHash).Should().Be("01ba2ea5fe8aee72611c068e383bb32996d351685b45db6246a3d3c7f015d257");

        var final = PdfIncrementalSigner.EmbedDocTimestamp(dt, token);
        Sha(final).Should().Be("1f678126c36df68081749989c442021d60868a9812b91670200264f0bf4c3c07");
    }
}
