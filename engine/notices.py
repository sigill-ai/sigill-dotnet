"""Writes THIRD-PARTY-NOTICES.md for the crates compiled into sigill_cedar.wasm (run by notices.sh).
usage: python notices.py <crates.txt> <cargo registry src dir> <output.md>
crates.txt: `cargo tree --target wasm32-wasip1 --edges normal,no-proc-macro --prefix none --format "{p}|{l}|{r}"`."""
import json
import re
import sys
from pathlib import Path

CRATES, SRC, OUT = sys.argv[1:4]
# Licences that only ask for attribution. Anything else stops the run: it needs a person, not this script.
PERMISSIVE = {"0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "CC0-1.0", "ISC", "MIT",
              "Unicode-3.0", "Unicode-DFS-2016", "Unlicense", "Zlib"}
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


def version_key(v):
    return [int(p) if p.isdigit() else p for p in re.split(r"[.+-]", v)]


crates = {}
for line in Path(CRATES).read_text(encoding="utf-8").splitlines():
    m = re.fullmatch(r"(\S+) v(\S+)(?: \([^)]*\))*\|(.*)\|(.*)", line.strip())
    if not m:
        sys.exit(f"unexpected cargo tree line: {line!r}")
    name, version, lic, repo = m.groups()
    if name != "sigill-cedar":  # the module's own crate
        crates[(name, version)] = (lic.replace("/", " OR "), repo)  # Cargo's legacy "A/B" means "A OR B"

bad, texts, unfiled, notices = [], {}, {}, {}
for (name, version), (lic, repo) in sorted(crates.items(), key=lambda kv: (kv[0][0], version_key(kv[0][1]))):
    label = f"{name} {version}"
    ids = sorted(set(re.findall(r"[A-Za-z0-9.+-]+", lic)) - {"OR", "AND", "WITH"})
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
       "`engine/notices.sh` regenerates this file. Below: every crate compiled into the module, the NOTICE files, and",
       "the full licence texts. Licences are SPDX expressions as the crates declare them (Cargo's legacy `A/B` is",
       "written `A OR B`).", "", f"## Crates ({len(crates)})", "",
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
Path(OUT).write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
print(f"{len(crates)} crates, {len(texts)} licence texts, {len(notices)} notices")
