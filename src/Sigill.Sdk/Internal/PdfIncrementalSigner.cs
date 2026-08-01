// Licensed to Sigill under the Apache License, Version 2.0.
// SPDX-License-Identifier: Apache-2.0

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Sigill.Sdk.Internal;

/// <summary>
/// Client-side half of Sigill's delegated PAdES signing: appends an
/// ETSI.CAdES.detached signature revision to an existing PDF using the
/// incremental update model, computing the ByteRange digest locally so only a
/// hash ever has to reach Sigill. The CMS itself is built server-side
/// (<c>POST /seal/sign-pades-hash</c>) and embedded here.
///
/// Ported from the platform's <c>Sigill.Api.Signing.PdfIncrementalSigner</c>,
/// minus the signed-attributes digest computation (server-side, where the
/// signer certificate lives). Works with traditional xref-table PDFs, modern
/// xref-stream PDFs (PDF 1.5+), and PDFs whose key structural objects are
/// packed into compressed object streams (ObjStm).
///
/// Two-pass:
///   var prep   = PdfIncrementalSigner.Prepare(bytes, now);
///   byte[] cms = /* POST hash → Sigill → CMS */;
///   byte[] signed = PdfIncrementalSigner.Embed(prep, cms);
/// </summary>
internal static class PdfIncrementalSigner
{
    /// <summary>Reserved /Contents slot for the (RSA + TST + OCSP) CMS.</summary>
    internal const int DefaultCmsReservedBytes = 16_384;

    // Latin-1 keeps a 1:1 byte↔char mapping so binary-ish PDF content survives
    // the string round-trip. Encoding.Latin1 is .NET 5+; code page 28591 is the
    // same encoding and available on netstandard2.1.
    private static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

    internal sealed record PreparedPdf(
        byte[] Bytes,
        int    ContentsHexOffset,
        int    ContentsHexLength,
        byte[] DocumentHash);

    // ─── Pass 1: Prepare ──────────────────────────────────────────────────────

    internal static PreparedPdf Prepare(
        byte[]   originalPdf,
        DateTime signingTime,
        string?  reason           = null,
        string?  location         = null,
        int      cmsReservedBytes = DefaultCmsReservedBytes)
    {
        var s = ParseStructure(originalPdf);

        int next   = s.MaxObjectId + 1;
        int sigId  = next++;
        int fldId  = next++;
        int pageId = s.Page1Id;
        int catId  = s.CatalogId;
        int afId   = s.AcroFormId > 0 ? s.AcroFormId : next++;

        long baseOff = originalPdf.Length;
        var  inc     = new StringBuilder();
        var  offmap  = new Dictionary<int, long>();

        void AppendObj(int id, string body)
        {
            offmap[id] = baseOff + inc.Length;
            inc.Append($"{id} 0 obj\n{body}\nendobj\n");
        }

        var emptyHex = new string('0', cmsReservedBytes * 2);
        const string brTpl = "[0000000000 0000000000 0000000000 0000000000]";

        var sb = new StringBuilder();
        // /SubFilter /ETSI.CAdES.detached — the PAdES-compliant subfilter. The
        // server-built CMS carries signing-certificate-v2, which is what Adobe's
        // PAdES validation rules expect with this subfilter.
        sb.Append("<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached\n");
        sb.Append($"/ByteRange {brTpl}\n/Contents <{emptyHex}>\n/M ({FmtDate(signingTime)})\n");
        if (reason   != null) sb.Append($"/Reason ({PdfEsc(reason)})\n");
        if (location != null) sb.Append($"/Location ({PdfEsc(location)})\n");
        sb.Append(">>");
        AppendObj(sigId, sb.ToString());

        AppendObj(fldId,
            $"<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0]\n" +
            $"/FT /Sig /T (Sigill-Seal-1) /V {sigId} 0 R /P {pageId} 0 R /F 132 >>");

        AppendObj(pageId, AddAnnotToPage(s.Page1Content, fldId));

        AppendObj(afId, s.AcroFormContent != null
            ? AddFieldToAcroForm(s.AcroFormContent, fldId)
            : $"<< /Fields [{fldId} 0 R] /SigFlags 3 >>");

        AppendObj(catId, AddAcroFormToCatalog(s.CatalogContent, afId));

        long xrefPos = baseOff + inc.Length;
        var xsb = new StringBuilder("xref\n");
        foreach (var kv in offmap.OrderBy(x => x.Key))
            xsb.Append($"{kv.Key} 1\n{kv.Value:D10} 00000 n \n");
        xsb.Append($"trailer\n<< /Size {next} /Root {catId} 0 R /Prev {s.StartXref} >>\n");
        xsb.Append($"startxref\n{xrefPos}\n%%EOF\n");

        var incBytes = Latin1.GetBytes(inc + xsb.ToString());
        var full     = new byte[originalPdf.Length + incBytes.Length];
        originalPdf.CopyTo(full, 0);
        incBytes.CopyTo(full, originalPdf.Length);

        var needle = Encoding.ASCII.GetBytes($"<{emptyHex}>");
        int angle  = ByteFind(full, needle, originalPdf.Length);
        if (angle < 0) throw new InvalidOperationException("Cannot locate /Contents placeholder");

        // PAdES/ISO 32000 convention: the /Contents hex blob AND its angle
        // brackets are excluded from hashing — the declared ByteRange must
        // sandwich '<' + hex + '>' exactly. See the platform signer for the
        // full derivation; this must stay byte-identical with it.
        int hexOff = angle + 1;
        int hexLen = cmsReservedBytes * 2;
        int r1 = 0, r1Len = angle;
        int r2 = hexOff + hexLen + 1, r2Len = full.Length - r2;

        var brVal   = $"[{r1} {r1Len} {r2} {r2Len}]";
        var brBytes = Encoding.ASCII.GetBytes(brVal.PadRight(brTpl.Length));
        int brOff   = ByteFind(full, Encoding.ASCII.GetBytes(brTpl), originalPdf.Length);
        if (brOff >= 0) brBytes.CopyTo(full, brOff);

        var docHash = HashRanges(full, r1, r1Len, r2, r2Len);
        return new PreparedPdf(full, hexOff, hexLen, docHash);
    }

    // ─── Recover: rebuild a PreparedPdf from persisted bytes ─────────────────

    /// <summary>
    /// Reconstruct a <see cref="PreparedPdf"/> from prepared bytes persisted by a
    /// caller — the crash-resume path. The placeholder revision's finalized
    /// /ByteRange carries the real offsets, so the /Contents slot and the document
    /// hash are re-derived exactly; no state beyond the bytes themselves is needed.
    /// </summary>
    internal static PreparedPdf Recover(byte[] preparedBytes)
    {
        // The placeholder signature revision is the newest incremental update,
        // so its /ByteRange is the last one in the file.
        var text  = Latin1.GetString(preparedBytes);
        int brKey = text.LastIndexOf("/ByteRange", StringComparison.Ordinal);
        if (brKey < 0)
            throw new InvalidOperationException("Not a prepared PDF: no /ByteRange found");
        int open  = text.IndexOf('[', brKey);
        int close = open < 0 ? -1 : text.IndexOf(']', open);
        if (close < 0)
            throw new InvalidOperationException("Not a prepared PDF: malformed /ByteRange");

        var parts = text[(open + 1)..close].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 4 ||
            !int.TryParse(parts[0], out var r1)  || !int.TryParse(parts[1], out var r1Len) ||
            !int.TryParse(parts[2], out var r2)  || !int.TryParse(parts[3], out var r2Len))
            throw new InvalidOperationException("Not a prepared PDF: /ByteRange still a template or unparseable");

        // The declared ranges must sandwich '<' + hex + '>' exactly and cover
        // the whole file — anything else means the bytes are not a finalized
        // placeholder revision from Prepare().
        int hexOff = r1Len + 1;
        int hexLen = r2 - r1Len - 2;
        if (r1 != 0 || hexLen <= 0 || r2 + r2Len != preparedBytes.Length ||
            preparedBytes[r1Len] != (byte)'<' || preparedBytes[r2 - 1] != (byte)'>')
            throw new InvalidOperationException("Prepared bytes do not carry a finalized placeholder revision");

        var docHash = HashRanges(preparedBytes, r1, r1Len, r2, r2Len);
        return new PreparedPdf(preparedBytes, hexOff, hexLen, docHash);
    }

    // ─── Pass 2: Embed ────────────────────────────────────────────────────────

    internal static byte[] Embed(PreparedPdf prep, byte[] cmsDer)
    {
        if (cmsDer.Length * 2 > prep.ContentsHexLength)
            throw new InvalidOperationException(
                $"CMS ({cmsDer.Length}B) > reserved slot ({prep.ContentsHexLength / 2}B)");
        var final = (byte[])prep.Bytes.Clone();
        var hex   = ToLowerHex(cmsDer).PadRight(prep.ContentsHexLength, '0');
        Encoding.ASCII.GetBytes(hex).CopyTo(final, prep.ContentsHexOffset);
        return final;
    }

    // ─── Pass 3: DSS (PAdES-LTV) ─────────────────────────────────────────────

    /// <summary>
    /// Appends a Document Security Store dictionary as a third incremental
    /// update (PAdES-LTV, ISO 32000-2 §12.8.4.3.3), carrying the certificate
    /// chain and OCSP responses returned by <c>/seal/sign-pades-hash</c>. When
    /// <paramref name="signatureCmsDer"/> is provided a /VRI subdictionary is
    /// written keyed by SHA-1(CMS) per ETSI TS 102 778-4 §4.3.
    /// </summary>
    internal static byte[] AppendDss(
        byte[] signedPdf, byte[][] certDers, byte[][] ocspDers, byte[]? signatureCmsDer = null)
    {
        if (certDers.Length == 0 && ocspDers.Length == 0) return signedPdf;

        var s    = ParseStructure(signedPdf);
        int next = s.MaxObjectId + 1;

        // Binary chunks + offset map kept separate so DER stream data is never
        // passed through a string encoder.
        var chunks = new List<byte[]>();
        var offmap = new Dictionary<int, long>();
        long pos   = signedPdf.Length;

        void Emit(int id, byte[] chunk)
        {
            offmap[id] = pos;
            chunks.Add(chunk);
            pos += chunk.Length;
        }

        static byte[] StreamObj(int id, byte[] data)
        {
            var hdr = Encoding.ASCII.GetBytes($"{id} 0 obj\n<< /Length {data.Length} >>\nstream\n");
            var ftr = Encoding.ASCII.GetBytes("\nendstream\nendobj\n");
            var buf = new byte[hdr.Length + data.Length + ftr.Length];
            hdr.CopyTo(buf, 0);
            data.CopyTo(buf, hdr.Length);
            ftr.CopyTo(buf, hdr.Length + data.Length);
            return buf;
        }

        var certIds = certDers.Select(_ => next++).ToArray();
        var ocspIds = ocspDers.Select(_ => next++).ToArray();

        for (int i = 0; i < certDers.Length; i++) Emit(certIds[i], StreamObj(certIds[i], certDers[i]));
        for (int i = 0; i < ocspDers.Length; i++) Emit(ocspIds[i], StreamObj(ocspIds[i], ocspDers[i]));

        int dssId = next++;
        var certRefs = string.Join(" ", certIds.Select(id => $"{id} 0 R"));
        var ocspRefs = string.Join(" ", ocspIds.Select(id => $"{id} 0 R"));

        var dssSb = new StringBuilder("<< /Type /DSS");
        if (certIds.Length > 0) dssSb.Append($"\n/Certs [{certRefs}]");
        if (ocspIds.Length > 0) dssSb.Append($"\n/OCSPs [{ocspRefs}]");

        // /VRI links cert + OCSP data to this specific signature; without it,
        // Adobe and other strict validators report "LTV validation failed".
        if (signatureCmsDer is not null)
        {
            using var sha1 = SHA1.Create();
            var vriKey = ToUpperHex(sha1.ComputeHash(signatureCmsDer));
            dssSb.Append($"\n/VRI << /{vriKey} <<");
            if (certIds.Length > 0) dssSb.Append($" /Cert [{certRefs}]");
            if (ocspIds.Length > 0) dssSb.Append($" /OCSP [{ocspRefs}]");
            dssSb.Append(" >> >>");
        }

        dssSb.Append("\n>>");
        Emit(dssId, Encoding.ASCII.GetBytes($"{dssId} 0 obj\n{dssSb}\nendobj\n"));

        int catId      = s.CatalogId;
        var newCatBody = AddDssToCatalog(s.CatalogContent, dssId);
        Emit(catId, Encoding.ASCII.GetBytes($"{catId} 0 obj\n{newCatBody}\nendobj\n"));

        long xrefPos = pos;
        var xsb = new StringBuilder("xref\n");
        foreach (var kv in offmap.OrderBy(x => x.Key))
            xsb.Append($"{kv.Key} 1\n{kv.Value:D10} 00000 n \n");
        xsb.Append($"trailer\n<< /Size {next} /Root {catId} 0 R /Prev {s.StartXref} >>\n");
        xsb.Append($"startxref\n{xrefPos}\n%%EOF\n");
        var xrefBytes = Encoding.ASCII.GetBytes(xsb.ToString());

        var result = new byte[signedPdf.Length + (int)(pos - signedPdf.Length) + xrefBytes.Length];
        signedPdf.CopyTo(result, 0);
        int off = signedPdf.Length;
        foreach (var chunk in chunks) { chunk.CopyTo(result, off); off += chunk.Length; }
        xrefBytes.CopyTo(result, off);
        return result;
    }

    private static string AddDssToCatalog(string cat, int dssId)
    {
        var m = Regex.Match(cat, @"/DSS\s+\d+\s+\d+\s+R");
        if (m.Success) return cat.Replace(m.Value, $"/DSS {dssId} 0 R");
        int dd = cat.LastIndexOf(">>", StringComparison.Ordinal);
        return cat[..dd] + $"\n/DSS {dssId} 0 R\n>>";
    }

    // ─── Pass 4: DocTimeStamp (PAdES B-LTA) ──────────────────────────────────

    // TST tokens are ~2-4 KB; 8 KB is generous headroom.
    private const int TstReservedBytes = 8_192;

    internal sealed record PreparedDocTimestamp(
        byte[] Bytes,
        int    ContentsHexOffset,
        int    ContentsHexLength,
        byte[] DocumentHash);

    /// <summary>
    /// Appends a DocTimeStamp signature field as a fourth incremental update
    /// (PAdES B-LTA). The returned <see cref="PreparedDocTimestamp.DocumentHash"/>
    /// is the SHA-256 ByteRange digest to send to <c>/tsa/stamp-hash</c>; embed
    /// the returned TimeStampToken with <see cref="EmbedDocTimestamp"/>.
    /// </summary>
    internal static PreparedDocTimestamp PrepareDocTimestamp(byte[] signedPdf, DateTime now)
    {
        var s    = ParseStructure(signedPdf);
        int next = s.MaxObjectId + 1;
        int sigId  = next++;
        int fldId  = next++;
        int pageId = s.Page1Id;
        int catId  = s.CatalogId;
        int afId   = s.AcroFormId > 0 ? s.AcroFormId : next++;

        long baseOff = signedPdf.Length;
        var  inc     = new StringBuilder();
        var  offmap  = new Dictionary<int, long>();

        void AppendObj(int id, string body)
        {
            offmap[id] = baseOff + inc.Length;
            inc.Append($"{id} 0 obj\n{body}\nendobj\n");
        }

        var emptyHex = new string('0', TstReservedBytes * 2);
        const string brTpl = "[0000000000 0000000000 0000000000 0000000000]";

        // /SubFilter /ETSI.RFC3161 identifies this as a document timestamp; the
        // /Contents slot holds the raw TimeStampToken DER.
        AppendObj(sigId,
            $"<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161\n" +
            $"/ByteRange {brTpl}\n/Contents <{emptyHex}>\n/M ({FmtDate(now)})\n>>");

        AppendObj(fldId,
            $"<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0]\n" +
            $"/FT /Sig /T (Sigill-DocTS-1) /V {sigId} 0 R /P {pageId} 0 R /F 132 >>");

        AppendObj(pageId, AddAnnotToPage(s.Page1Content, fldId));

        AppendObj(afId, s.AcroFormContent != null
            ? AddFieldToAcroForm(s.AcroFormContent, fldId)
            : $"<< /Fields [{fldId} 0 R] /SigFlags 3 >>");

        AppendObj(catId, AddAcroFormToCatalog(s.CatalogContent, afId));

        long xrefPos = baseOff + inc.Length;
        var xsb = new StringBuilder("xref\n");
        foreach (var kv in offmap.OrderBy(x => x.Key))
            xsb.Append($"{kv.Key} 1\n{kv.Value:D10} 00000 n \n");
        xsb.Append($"trailer\n<< /Size {next} /Root {catId} 0 R /Prev {s.StartXref} >>\n");
        xsb.Append($"startxref\n{xrefPos}\n%%EOF\n");

        var incBytes = Latin1.GetBytes(inc + xsb.ToString());
        var full = new byte[signedPdf.Length + incBytes.Length];
        signedPdf.CopyTo(full, 0);
        incBytes.CopyTo(full, signedPdf.Length);

        var needle = Encoding.ASCII.GetBytes($"<{emptyHex}>");
        int angle  = ByteFind(full, needle, signedPdf.Length);
        if (angle < 0) throw new InvalidOperationException("Cannot locate DocTimeStamp /Contents placeholder");

        int hexOff = angle + 1;
        int hexLen = TstReservedBytes * 2;
        int r1 = 0, r1Len = angle;
        int r2 = hexOff + hexLen + 1, r2Len = full.Length - r2;

        var brVal   = $"[{r1} {r1Len} {r2} {r2Len}]";
        var brBytes = Encoding.ASCII.GetBytes(brVal.PadRight(brTpl.Length));
        int brOff   = ByteFind(full, Encoding.ASCII.GetBytes(brTpl), signedPdf.Length);
        if (brOff >= 0) brBytes.CopyTo(full, brOff);

        var docHash = HashRanges(full, r1, r1Len, r2, r2Len);
        return new PreparedDocTimestamp(full, hexOff, hexLen, docHash);
    }

    internal static byte[] EmbedDocTimestamp(PreparedDocTimestamp prep, byte[] tstDer)
    {
        if (tstDer.Length > TstReservedBytes)
            throw new InvalidOperationException(
                $"TST ({tstDer.Length}B) > reserved slot ({TstReservedBytes}B)");
        var final = (byte[])prep.Bytes.Clone();
        var hex   = ToLowerHex(tstDer).PadRight(prep.ContentsHexLength, '0');
        Encoding.ASCII.GetBytes(hex).CopyTo(final, prep.ContentsHexOffset);
        return final;
    }

    // ─── PDF structure parser ─────────────────────────────────────────────────

    private sealed record Struct(int MaxObjectId, int CatalogId, string CatalogContent,
        int Page1Id, string Page1Content, int AcroFormId, string? AcroFormContent, long StartXref);

    private static Struct ParseStructure(byte[] pdf)
    {
        var t = Latin1.GetString(pdf);

        // Find startxref (last occurrence — handles incremental updates)
        var sxm = Regex.Match(t, @"startxref\s+(\d+)\s*%%EOF",
            RegexOptions.RightToLeft | RegexOptions.Singleline);
        if (!sxm.Success) throw new InvalidOperationException("startxref not found in PDF");
        long sx = long.Parse(sxm.Groups[1].Value);

        // Object discovery: top-level "N 0 obj" offsets plus objects unpacked
        // from /Type /ObjStm streams. Last write wins so incremental updates
        // override originals correctly.
        var offsets    = ScanObjects(t);
        var compressed = ScanCompressedObjects(pdf, t, offsets);

        // Most recent /Root reference (trailer dicts are never compressed).
        var rootM = Regex.Match(t, @"/Root\s+(\d+)\s+\d+\s+R", RegexOptions.RightToLeft);
        if (!rootM.Success) throw new InvalidOperationException("/Root not found in PDF");
        int catId = int.Parse(rootM.Groups[1].Value);
        var cat   = GetObj(t, offsets, compressed, catId);

        var pagesM = Regex.Match(cat, @"/Pages\s+(\d+)\s+\d+\s+R");
        if (!pagesM.Success) throw new InvalidOperationException("/Pages not found in catalog");
        var pages = GetObj(t, offsets, compressed, int.Parse(pagesM.Groups[1].Value));

        int p1Id = WalkToFirstLeafPage(t, offsets, compressed, pages);
        var p1   = GetObj(t, offsets, compressed, p1Id);

        int afId = 0; string? afContent = null;
        var am = Regex.Match(cat, @"/AcroForm\s+(\d+)\s+\d+\s+R");
        if (am.Success && int.TryParse(am.Groups[1].Value, out int aid))
        {
            afId = aid;
            afContent = GetObj(t, offsets, compressed, aid);
        }

        int maxId = Math.Max(
            offsets.Keys.DefaultIfEmpty(0).Max(),
            compressed.Keys.DefaultIfEmpty(0).Max());

        return new Struct(maxId, catId, cat, p1Id, p1, afId, afContent, sx);
    }

    private static int WalkToFirstLeafPage(string t,
        Dictionary<int, int> offsets,
        Dictionary<int, string> compressed,
        string node)
    {
        // Loop guarded — if a malicious or corrupt PDF cycles, bail.
        for (int hop = 0; hop < 64; hop++)
        {
            var kidsM = Regex.Match(node, @"/Kids\s*\[\s*(\d+)");
            if (!kidsM.Success) throw new InvalidOperationException("/Kids not found in Pages node");
            int kidId = int.Parse(kidsM.Groups[1].Value);
            var kid   = GetObj(t, offsets, compressed, kidId);
            if (Regex.IsMatch(kid, @"/Type\s*/Page\b(?!s)")) return kidId;
            node = kid;
        }
        throw new InvalidOperationException("Page tree deeper than 64 levels — refusing to descend");
    }

    private static Dictionary<int, int> ScanObjects(string t)
    {
        var d  = new Dictionary<int, int>();
        var rx = Regex.Matches(t, @"(?<![.\d])(\d+)\s+0\s+obj[\s<\[]");
        foreach (Match m in rx)
        {
            if (int.TryParse(m.Groups[1].Value, out int id) && id > 0)
                d[id] = m.Index; // overwrite — later definition takes precedence
        }
        return d;
    }

    private static Dictionary<int, string> ScanCompressedObjects(
        byte[] pdf, string t, Dictionary<int, int> topLevelOffsets)
    {
        var result = new Dictionary<int, string>();

        foreach (var kv in topLevelOffsets)
        {
            var objStmId  = kv.Key;
            var headerOff = kv.Value;

            var hdrRx = new Regex($@"\b{objStmId}\s+0\s+obj\b");
            var hm = hdrRx.Match(t, headerOff);
            if (!hm.Success) continue;
            int dictStart = hm.Index + hm.Length;

            int streamKw = t.IndexOf("stream", dictStart, StringComparison.Ordinal);
            if (streamKw < 0) continue;
            string dictText = t[dictStart..streamKw];

            if (!Regex.IsMatch(dictText, @"/Type\s*/ObjStm")) continue;

            int n     = ParseIntField(dictText, "N");
            int first = ParseIntField(dictText, "First");
            int len   = ParseIntField(dictText, "Length");

            // Filter must be FlateDecode (allow array form like [/FlateDecode]).
            // /Predictor on ObjStm is legal per spec but unseen in the wild —
            // fail loudly so the caller can fall back to server-side sealing.
            if (!Regex.IsMatch(dictText, @"/Filter\s*(\[\s*)?/FlateDecode"))
                throw new NotSupportedException(
                    $"Object stream {objStmId} uses unsupported filter — only FlateDecode is supported");
            if (Regex.IsMatch(dictText, @"/Predictor\s+[2-9]"))
                throw new NotSupportedException(
                    $"Object stream {objStmId} uses /Predictor — not supported");

            int dataStart = streamKw + "stream".Length;
            if (dataStart < pdf.Length && pdf[dataStart] == '\r') dataStart++;
            if (dataStart < pdf.Length && pdf[dataStart] == '\n') dataStart++;

            if (dataStart + len > pdf.Length)
                throw new InvalidOperationException(
                    $"Object stream {objStmId} declares /Length {len} but file is too short");

            byte[] decoded = FlateDecode(pdf, dataStart, len);
            string decodedText = Latin1.GetString(decoded);

            string headerSlice = decodedText[..Math.Min(first, decodedText.Length)];
            var ints = Regex.Matches(headerSlice, @"\d+");
            if (ints.Count < n * 2)
                throw new InvalidOperationException(
                    $"Object stream {objStmId} header has {ints.Count} ints, expected at least {n * 2}");

            for (int i = 0; i < n; i++)
            {
                int id     = int.Parse(ints[i * 2].Value);
                int relOff = int.Parse(ints[i * 2 + 1].Value);
                int bodyStart = first + relOff;
                int bodyEnd;
                if (i + 1 < n)
                    bodyEnd = first + int.Parse(ints[(i + 1) * 2 + 1].Value);
                else
                    bodyEnd = decodedText.Length;
                if (bodyStart < 0 || bodyEnd > decodedText.Length || bodyStart > bodyEnd)
                    continue; // malformed entry, skip
                result[id] = decodedText[bodyStart..bodyEnd].Trim();
            }
        }

        return result;
    }

    private static int ParseIntField(string dict, string name)
    {
        var m = Regex.Match(dict, $@"/{name}\s+(\d+)");
        if (!m.Success)
            throw new InvalidOperationException($"ObjStm dict missing /{name}");
        return int.Parse(m.Groups[1].Value);
    }

    /// <summary>
    /// FlateDecode = zlib-wrapped deflate: skip the 2-byte zlib header that
    /// DeflateStream doesn't understand; the trailing Adler-32 is simply not
    /// consumed.
    /// </summary>
    private static byte[] FlateDecode(byte[] src, int offset, int length)
    {
        using var ms  = new MemoryStream(src, offset + 2, length - 2);
        using var def = new DeflateStream(ms, CompressionMode.Decompress);
        using var outMs = new MemoryStream();
        def.CopyTo(outMs);
        return outMs.ToArray();
    }

    private static string GetObj(string t,
        Dictionary<int, int> offs,
        Dictionary<int, string> compressed,
        int id)
    {
        if (offs.TryGetValue(id, out int off))
        {
            var objRx = new Regex($@"\b{id}\s+0\s+obj\b");
            var om    = objRx.Match(t, off);
            if (!om.Success)
                throw new InvalidOperationException($"Object {id} header not found from offset {off}");
            int s = om.Index + om.Length;
            while (s < t.Length && (t[s] == ' ' || t[s] == '\n' || t[s] == '\r')) s++;
            int e = t.IndexOf("endobj", s, StringComparison.Ordinal);
            if (e < 0) throw new InvalidOperationException($"endobj missing for object {id}");
            return t[s..e].Trim();
        }
        if (compressed.TryGetValue(id, out var body))
            return body;
        throw new KeyNotFoundException(
            $"Object {id} not found in PDF (not top-level, not in any object stream)");
    }

    // ─── PDF object patchers ──────────────────────────────────────────────────

    private static string AddAnnotToPage(string p, int fldId)
    {
        var m = Regex.Match(p, @"/Annots\s*\[\s*");
        if (m.Success) { int c = p.IndexOf(']', m.Index + m.Length); return p[..c] + $" {fldId} 0 R" + p[c..]; }
        int dd = p.LastIndexOf(">>", StringComparison.Ordinal);
        return p[..dd] + $"\n/Annots [{fldId} 0 R]\n>>";
    }

    private static string AddFieldToAcroForm(string af, int fldId)
    {
        var m = Regex.Match(af, @"/Fields\s*\[\s*");
        string r;
        if (m.Success) { int c = af.IndexOf(']', m.Index + m.Length); r = af[..c] + $" {fldId} 0 R" + af[c..]; }
        else { int dd = af.LastIndexOf(">>", StringComparison.Ordinal); r = af[..dd] + $"\n/Fields [{fldId} 0 R]\n>>"; }
        if (!r.Contains("/SigFlags")) { int dd = r.LastIndexOf(">>", StringComparison.Ordinal); r = r[..dd] + "\n/SigFlags 3\n>>"; }
        return r;
    }

    private static string AddAcroFormToCatalog(string cat, int afId)
    {
        var m = Regex.Match(cat, @"/AcroForm\s+\d+\s+\d+\s+R");
        if (m.Success) return cat.Replace(m.Value, $"/AcroForm {afId} 0 R");
        int dd = cat.LastIndexOf(">>", StringComparison.Ordinal);
        return cat[..dd] + $"\n/AcroForm {afId} 0 R\n>>";
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static byte[] HashRanges(byte[] full, int r1, int r1Len, int r2, int r2Len)
    {
        using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha256.AppendData(full, r1, r1Len);
        sha256.AppendData(full, r2, r2Len);
        return sha256.GetHashAndReset();
    }

    private static string FmtDate(DateTime dt) =>
        $"D:{dt.ToUniversalTime():yyyyMMddHHmmss}+00'00'";

    private static string PdfEsc(string s) =>
        s.Replace("\\", "\\\\").Replace("(", "\\(").Replace(")", "\\)");

    private static int ByteFind(byte[] hay, byte[] needle, int from = 0)
    {
        for (int i = from; i <= hay.Length - needle.Length; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Length && ok; j++)
                if (hay[i + j] != needle[j]) ok = false;
            if (ok) return i;
        }
        return -1;
    }

    private static string ToLowerHex(byte[] bytes)
    {
        var c = new char[bytes.Length * 2];
        int i = 0;
        foreach (var b in bytes)
        {
            c[i++] = "0123456789abcdef"[b >> 4];
            c[i++] = "0123456789abcdef"[b & 0xF];
        }
        return new string(c);
    }

    private static string ToUpperHex(byte[] bytes)
    {
        var c = new char[bytes.Length * 2];
        int i = 0;
        foreach (var b in bytes)
        {
            c[i++] = "0123456789ABCDEF"[b >> 4];
            c[i++] = "0123456789ABCDEF"[b & 0xF];
        }
        return new string(c);
    }
}
