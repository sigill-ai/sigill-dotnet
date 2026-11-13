"""Writes THIRD-PARTY-NOTICES.md for sigill_cedar.wasm: the crates compiled into it and the Rust toolchain components
linked into it (run by notices.sh, which collects the inputs in <work>).
usage: python notices.py <work> <rust image> <output.md>"""
import hashlib
import html
import json
import re
import sys
import urllib.request
from pathlib import Path

WORK, IMAGE, OUT = sys.argv[1:4]
CRATES, SRC = f"{WORK}/crates.txt", f"{WORK}/src"
# Licences that only ask for attribution. Anything else stops the run: it needs a person, not this script.
PERMISSIVE = {"0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "ISC", "MIT",
              "Unicode-3.0", "Unicode-DFS-2016", "Unlicense", "Zlib", "LLVM-exception"}
# The Cedar crates do not ship the NOTICE of their repository; this is NOTICE at the commit they were published from.
CEDAR_REPO = "https://github.com/cedar-policy/cedar"
CEDAR_COMMIT = "5e54be8a16f3f346eb542e4feca587bfb962ebd1"
CEDAR_NOTICE = "Copyright Cedar Contributors\n"
LICENSE_FILE = re.compile(r"(?i)^(licen[cs]e|unlicense)([-._].*)?$")
NOTICE_FILE = re.compile(r"(?i)^notice([-._].*)?$")
FILE_IDS = (("APACHE", "Apache-2.0"), ("MIT", "MIT"), ("ZLIB", "Zlib"), ("UNICODE", "Unicode-3.0"), ("UNLICENSE", "Unlicense"))


def norm(text):
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    return "\n".join(lines).strip("\n") + "\n"


def fence(text):
    assert "```" not in text
    return f"```text\n{text}```\n"


def add(groups, key, text, label):
    # Texts that differ only in whitespace (line wrapping, indentation) are one text; the first one is printed.
    group = groups.setdefault((key, " ".join(text.split())), [norm(text), []])
    group[1].append(label)


def ids_of(lic):
    return sorted(set(re.findall(r"[A-Za-z0-9.+-]+", lic)) - {"OR", "AND", "WITH"})


def version_key(v):
    return [int(p) if p.isdigit() else p for p in re.split(r"[.+-]", v)]


def tree_lines(path):
    """cargo tree lines "name vX[ (path)]|licence|repository" -> (name, version, in_tree, licence, repository)."""
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = re.fullmatch(r"(\S+) v(\S+)((?: \([^)]*\))*)\|(.*)\|(.*)", line.strip())
        if not m:
            sys.exit(f"unexpected cargo tree line: {line!r}")
        name, version, paren, lic, repo = m.groups()
        yield name, version, "(/" in paren, lic.replace("/", " OR "), repo  # Cargo's legacy "A/B" means "A OR B"


# ── Rust toolchain components ──────────────────────────────────────────────────────────────────────────────────
# The pinned toolchain these constants were checked against; another one needs them checked again.
RUSTC = "rustc 1.100.0 (0ef1bc386 2026-11-09)"
# wasm32-wasip1's self-contained wasi-libc (crt1-reactor.o, libc.a): Rust 1.100.0's dist build takes it from wasi-sdk-34
# (rust-lang/rust 1.100.0, src/ci/docker/host-x86_64/dist-various-2/Dockerfile), i.e. wasi-libc at its tag wasi-sdk-34.
# The toolchain ships no licence texts for it, so they come from that commit, pinned by digest.
WASI_LIBC = ("wasi-sdk-34", "2e6fb9d8ee0cdf9e431fbcabe8af3115de000a13")
WASI_LIBC_RAW = f"https://raw.githubusercontent.com/WebAssembly/wasi-libc/{WASI_LIBC[1]}/"
WASI_LIBC_FILES = {
    "LICENSE": "2711a8b5a5cdfef0e639f96c1aca12ae23d7d64a02d0507f1bdf14d2b27bbc3a",
    "LICENSE-APACHE-LLVM": "268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5",
    "LICENSE-APACHE": "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2",
    "LICENSE-MIT": "23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3",
    "libc-top-half/musl/COPYRIGHT": "b870108ec5e7790e9f9919064f1b9421d62d5f9b0e6c230c6adf7ea2da62e97b",
    "libc-bottom-half/cloudlibc/LICENSE": "c8b789cf5a746611e6300a0cc7750dbf92b61912a709d04e639245f7290656d0",
    "dlmalloc/src/malloc.c": "9e7ce51d813331ae87ef235f6ca2d5ce2167692e30bb51a173513e3754a67f8f",
}
# dlmalloc's notice points to CC0 1.0 without carrying its text: the SPDX licence list's copy.
CC0 = ("https://raw.githubusercontent.com/spdx/license-list-data/v3.27.0/text/CC0-1.0.txt",
       "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499")
# The parts of wasi-libc (its LICENSE file) and the texts that go with each.
WASI_PARTS = {
    "wasi-libc": ("Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
                  ["LICENSE", "LICENSE-APACHE-LLVM", "LICENSE-APACHE", "LICENSE-MIT"]),
    "musl (libc-top-half/musl)": ("MIT", ["libc-top-half/musl/COPYRIGHT"]),
    "cloudlibc (libc-bottom-half/cloudlibc)": ("BSD-2-Clause", ["libc-bottom-half/cloudlibc/LICENSE"]),
    "dlmalloc": ("CC0-1.0", ["dlmalloc/src/malloc.c"]),
}
# Each object the linker takes from wasi-libc -> the parts whose sources have a file of that name (at the commit).
WASI_MEMBERS = {
    "crt1-reactor.o": ["wasi-libc"], "__wasilibc_real": ["wasi-libc"], "__wasilibc_initialize_environ": ["wasi-libc"],
    "errno": ["wasi-libc", "cloudlibc (libc-bottom-half/cloudlibc)"],
    "write": ["cloudlibc (libc-bottom-half/cloudlibc)", "musl (libc-top-half/musl)"],
    "_Exit": ["cloudlibc (libc-bottom-half/cloudlibc)", "musl (libc-top-half/musl)"],
    "abort": ["wasi-libc", "musl (libc-top-half/musl)"], "getcwd": ["wasi-libc", "musl (libc-top-half/musl)"],
    "sbrk": ["wasi-libc", "musl (libc-top-half/musl)"], "dlmalloc": ["dlmalloc"],
    **{m: ["musl (libc-top-half/musl)"] for m in ("getenv", "clearenv", "sysconf", "memcmp", "strchrnul", "strcpy",
                                                    "stpcpy", "strdup", "strerror_r", "strerror", "__lctrans", "libc",
                                                    "strlen", "strncmp")},
}
# In-tree code of the standard library that carries its own licence files in rust-src (included into core, std and
# compiler_builtins with #[path]).
IN_TREE_FILES = {
    "core (core::arch)": ("library/stdarch/crates/core_arch", ["LICENSE-APACHE", "LICENSE-MIT"]),
    "core (core::simd)": ("library/portable-simd/crates/core_simd", ["LICENSE-APACHE", "LICENSE-MIT"]),
    "std (backtrace)": ("library/backtrace", ["LICENSE-APACHE", "LICENSE-MIT"]),
    "compiler_builtins": ("library/compiler-builtins", ["LICENSE.txt", "libm/LICENSE.txt"]),
}


def fetch(url, sha256):
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != sha256:
        sys.exit(f"{url} is not the pinned text (sha256 differs)")
    return data.decode("utf-8")


def in_tree_statement(page):
    """The in-tree entries of COPYRIGHT-library.html, in order, with their nesting (an exception of the entry above)."""
    part = page[page.index('id="in-tree-files"'):page.index('id="out-of-tree-dependencies"')]
    entries, depth = [], 0
    for m in re.finditer(r"<div\b|</div>|<b>(File/Directory|License|Copyright):</b>(.*?)</p>", part, re.S):
        if m.group(0).startswith("<div"):
            depth += 1
        elif m.group(0) == "</div>":
            depth -= 1
        else:
            value = " ".join(html.unescape(re.sub(r"<[^>]+>", "", m.group(2))).split())
            if m.group(1) == "File/Directory":
                entries.append({"depth": depth, "path": value, "License": "", "Copyright": []})
            elif m.group(1) == "License":
                entries[-1]["License"] = value
            else:
                entries[-1]["Copyright"].append(value)
    return entries


def toolchain_section(bad):
    """The "Rust toolchain components" section (lines), its licences checked into bad."""
    rustc = Path(f"{WORK}/rustc-version.txt").read_text(encoding="utf-8").strip()
    if rustc != RUSTC:
        sys.exit(f"the toolchain is {rustc!r}, not {RUSTC!r}: check WASI_LIBC, IN_TREE_FILES and the rest again")
    tc = Path(f"{WORK}/toolchain")
    page = (tc / "COPYRIGHT-library.html").read_text(encoding="utf-8")
    sysroot = {re.sub(r"^lib|-[0-9a-f]+\.(rlib|rmeta)$", "", f) for f in
               Path(f"{WORK}/sysroot-libs.txt").read_text(encoding="utf-8").split()}
    linked = Path(f"{WORK}/linked.txt").read_text(encoding="utf-8").split()
    members = sorted({re.sub(r"\.c\.obj$", "", m) for m in re.findall(r"libc\.a\(([^)]*)\)", " ".join(linked))}
                     | {m.rsplit("/", 1)[1] for m in linked if m.endswith(".o")})
    rlibs = sorted({re.sub(r"^.*/lib|-[0-9a-f]+\.rlib$", "", m) for m in linked if m.endswith(".rlib")})
    std = sorted(tree_lines(f"{WORK}/std-crates.txt"), key=lambda c: (c[0], version_key(c[1])))
    names = {c[0].replace("-", "_") for c in std}
    if not names <= sysroot or not set(rlibs) <= names:
        sys.exit(f"standard library crates {sorted(names - sysroot)} not in the sysroot, or linked {rlibs} not in them")
    if unknown := [m for m in members if m not in WASI_MEMBERS]:
        sys.exit(f"wasi-libc objects {unknown} are linked but not mapped in WASI_MEMBERS")

    texts, rows = {}, []  # texts: (_, collapsed) -> [text, [source, ...]]
    in_tree = in_tree_statement(page)
    for name, version, local, lic, repo in std:
        if not set(ids_of(lic)) <= PERMISSIVE:
            bad.append(f"{name} {version} (Rust standard library): {lic}")
        if local:
            rows.append(f"| {name} | {version} (in-tree) | {lic} | `share/doc/rust`, rust-src `library/` |")
            continue
        vendored = tc / "library" / "vendor" / f"{name}-{version}"
        files = sorted(p for p in vendored.iterdir() if p.is_file() and LICENSE_FILE.match(p.name)) if vendored.is_dir() else []
        for p in files + sorted(p for p in vendored.iterdir() if p.is_file() and NOTICE_FILE.match(p.name)):
            add(texts, "", p.read_text(encoding="utf-8"), f"{name} {version}: rust-src `library/vendor/{vendored.name}/{p.name}`")
        if files:
            rows.append(f"| {name} | {version} | {lic} | rust-src `library/vendor/{vendored.name}` |")
            continue
        # Shipped without licence files: those of its repository at the commit it was published from, pinned.
        vcs = json.loads((vendored / ".cargo_vcs_info.json").read_text(encoding="utf-8"))["git"]["sha1"]
        pinned = UPSTREAM.get((name, version))
        if not pinned or pinned[0] != vcs:
            sys.exit(f"{name} {version} ships no licence file: pin its repository's licence texts in UPSTREAM")
        for file, sha in pinned[2].items():
            add(texts, "", fetch(f"{pinned[1]}/{vcs}/{file}", sha), f"{name} {version}: `{file}` of its repository at {vcs}")
        rows.append(f"| {name} | {version} | {lic} | its repository at `{vcs[:12]}` (none in the toolchain) |")
    ids = sorted({i for e in in_tree for i in ids_of(e["License"])})
    bad.extend(f"Rust standard library in-tree: {i}" for i in ids if i not in PERMISSIVE)
    for i in ids:
        add(texts, "", (tc / "licenses" / f"{i}.txt").read_text(encoding="utf-8"), f"`share/doc/rust/licenses/{i}.txt`")
    for part, (base, files) in IN_TREE_FILES.items():
        for f in files:
            add(texts, "", (tc / base / f).read_text(encoding="utf-8"), f"{part}: rust-src `{base}/{f}`")

    parts = {p: sorted(m for m in members if p in WASI_MEMBERS[m]) for p in WASI_PARTS}
    for part, (lic, files) in WASI_PARTS.items():
        if parts[part] and not set(ids_of(lic)) <= PERMISSIVE:
            bad.append(f"{part} (wasi-libc): {lic}")
        for f in files if parts[part] else []:
            text = fetch(WASI_LIBC_RAW + f, WASI_LIBC_FILES[f])
            if f.endswith("malloc.c"):  # the notice: the file's first paragraph
                text = text.split("\n\n", 1)[0].removeprefix("/*\n")
                add(texts, "", fetch(*CC0), f"{part}: CC0 1.0 as its notice names it (SPDX licence list v3.27.0)")
            note = " (its opening notice)" if f.endswith("malloc.c") else ""
            add(texts, "", text, f"{part}: `{f}` of wasi-libc at {WASI_LIBC[1]}{note}")

    out = ["## Rust toolchain components", "",
           f"The recipe builds with `{IMAGE}`", f"(`{rustc}`). Besides the crates above, the linker puts into the module the",
           "Rust standard library for `wasm32-wasip1` — the crates below, inputs to the link-time optimisation, which keeps",
           "what is used (`compiler_builtins` is linked as compiled) — and, from the target's bundled wasi-libc,",
           "`crt1-reactor.o` and these `libc.a` objects:", ", ".join(f"`{m}`" for m in members if m != "crt1-reactor.o") + ".",
           "The licence texts below are those the toolchain ships (`share/doc/rust` and the `rust-src` component), except",
           "where a line says otherwise.", "", "### Rust standard library", "",
           "| Crate | Version | Licence | Texts from |", "|---|---|---|---|", *rows, "",
           "The in-tree code, as the toolchain's `share/doc/rust/COPYRIGHT-library.html` states it (an indented entry is",
           "an exception of the one above):", ""]
    for e in in_tree:
        where = f"`{e['path']}`" if e["path"] else "(no path given)"
        out.append("  " * (e["depth"] - 1) + f"- {where}: {e['License']}" + "".join(f"; Copyright {c}" for c in e["Copyright"]))
    out += ["", "### wasi-libc", "",
            f"wasi-libc at its tag `{WASI_LIBC[0]}` (commit `{WASI_LIBC[1]}`), the wasi-sdk release Rust 1.100.0's",
            "distribution build uses. The toolchain ships no licence texts for it; they are taken from that commit. An object",
            "whose file name exists in more than one part is listed under each.", "",
            "| Part | Licence | Linked objects |", "|---|---|---|"]
    out += [f"| {p} | {WASI_PARTS[p][0]} | " + ", ".join(f"`{m}`" for m in parts[p]) + " |" for p in WASI_PARTS if parts[p]]
    out += ["", "### Licence texts and notices of the toolchain components", ""]
    for text, sources in texts.values():
        out += ["From " + "; ".join(sources) + ":", "", fence(text)]
    return out, len(std)


# Out-of-tree standard library crates whose rust-src copy has no licence file: (name, version) ->
# (commit, raw URL base, {file: sha256}) of their repository.
UPSTREAM = {
    ("wasip1", "1.0.0"): ("e55b3b02fcda2a016f5df14573ff05c5b1e313d6",
                          "https://raw.githubusercontent.com/bytecodealliance/wasi-rs",
                          {"LICENSE-Apache-2.0_WITH_LLVM-exception": "268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5",
                           "LICENSE-APACHE": "a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2",
                           "LICENSE-MIT": "23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3"}),
}

crates = {(name, version): (lic, repo) for name, version, _, lic, repo in tree_lines(CRATES)
          if name != "sigill-cedar"}  # the module's own crate

bad, texts, unfiled, notices = [], {}, {}, {}
for (name, version), (lic, repo) in sorted(crates.items(), key=lambda kv: (kv[0][0], version_key(kv[0][1]))):
    label = f"{name} {version}"
    ids = ids_of(lic)
    if not ids or not set(ids) <= PERMISSIVE:
        bad.append(f"{label}: {lic or '(no licence declared)'}")
    src = Path(SRC) / f"{name}-{version}"
    files = sorted(p for p in src.iterdir() if p.is_file() and LICENSE_FILE.match(p.name))
    for p in files:
        upper = p.name.upper()
        lid = next((i for k, i in FILE_IDS if k in upper), ids[0] if len(ids) == 1 else lic)
        add(texts, lid, p.read_text(encoding="utf-8"), label)
    for i in ids if not files else []:
        unfiled.setdefault(i, []).append(label)
    for p in sorted(p for p in src.iterdir() if p.is_file() and NOTICE_FILE.match(p.name)):
        add(notices, f"`{p.name}` of the crate", p.read_text(encoding="utf-8"), label)
    if repo.rstrip("/") == CEDAR_REPO:
        vcs = json.loads((src / ".cargo_vcs_info.json").read_text(encoding="utf-8"))["git"]["sha1"]
        if vcs != CEDAR_COMMIT:
            sys.exit(f"{label} is from Cedar commit {vcs}: update CEDAR_COMMIT and CEDAR_NOTICE in notices.py")
        add(notices, f"`NOTICE` of {CEDAR_REPO} at commit {CEDAR_COMMIT} (not in the published crate)",
            CEDAR_NOTICE, label)

toolchain, std_count = toolchain_section(bad)
if bad:
    sys.exit("NOT A PERMISSIVE LICENCE — stop and have it reviewed:\n  " + "\n  ".join(bad))
missing = sorted(set(unfiled) - {lid for lid, _ in texts})
if missing:
    sys.exit(f"no licence text found for {missing}")

out = ["# Third-party notices", "",
       "`sigill_cedar.wasm`, the policy engine module embedded in the `Sigill.Sdk.Policy` NuGet package and in the",
       "`sigill-sdk` Python distributions, is the official [Cedar](https://github.com/cedar-policy/cedar) policy core",
       "(`cedar-policy` 4.14.0) and its Rust dependencies, compiled to WebAssembly (`wasm32-wasip1`). The recipe and",
       "`Cargo.lock` are in [`engine/`](https://github.com/sigill-ai/sigill-dotnet/tree/main/engine) of sigill-dotnet;",
       "`engine/notices.sh` regenerates this file. Below: every crate compiled into the module, the Rust toolchain",
       "components linked into it, the NOTICE files, and the full licence texts. Licences are SPDX expressions as the",
       "crates and components declare them (Cargo's legacy `A/B` is written `A OR B`).", "", f"## Crates ({len(crates)})", "",
       "| Crate | Version | Licence | Repository |", "|---|---|---|---|"]
for (name, version), (lic, repo) in sorted(crates.items(), key=lambda kv: (kv[0][0], version_key(kv[0][1]))):
    out.append(f"| {name} | {version} | {lic} | {repo or '—'} |")
out += ["", "## NOTICE files", ""]
for (source, _), (text, users) in sorted(notices.items(), key=lambda kv: kv[1][1]):
    out += [", ".join(users) + f" — {source}:", "", fence(text)]
out += ["## Licence texts", ""]
for lid in sorted({lid for lid, _ in texts}):
    out += [f"### {lid}", ""]
    if lid in unfiled:
        out += ["Also the licence of " + ", ".join(unfiled[lid]) + " (no licence file in the crate).", ""]
    for _, (text, users) in sorted(((k, v) for k, v in texts.items() if k[0] == lid), key=lambda kv: kv[1][1]):
        out += ["As shipped by " + ", ".join(users) + ":", "", fence(text)]
out += toolchain
Path(OUT).write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
print(f"{len(crates)} crates, {len(texts)} licence texts, {len(notices)} notices; {std_count} standard library crates")
