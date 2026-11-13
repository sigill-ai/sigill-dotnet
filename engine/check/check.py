"""Conformance check of sigill_cedar.wasm against @cedar-policy/cedar-wasm 4.14.0 reference answers.
usage: python check.py <sigill_cedar.wasm> <cases.json> <ref-answers.json>"""
import hashlib
import importlib.metadata
import json
import sys

import wasmtime

WASM, CASES, REF = sys.argv[1:4]
WASI = "wasi_snapshot_preview1"
EXPECTED_IMPORTS = sorted((WASI, n) for n in ("environ_get", "environ_sizes_get", "fd_write", "proc_exit", "random_get"))


class Cedar:
    def __init__(self, engine, module):
        linker = wasmtime.Linker(engine)
        linker.define_wasi()
        self.store = wasmtime.Store(engine)
        self.store.set_wasi(wasmtime.WasiConfig())  # no args, env, preopened dirs or inherited stdio
        ex = linker.instantiate(self.store, module).exports(self.store)
        if "_initialize" in ex:
            ex["_initialize"](self.store)
        self.ex, self.mem = ex, ex["memory"]

    def _take(self, p, len_ptr):
        n = int.from_bytes(self.mem.read(self.store, len_ptr, len_ptr + 4), "little")
        out = bytes(self.mem.read(self.store, p, p + n))
        self.ex["cedar_free"](self.store, p, n)
        return out

    def version(self):
        n = self.ex["cedar_alloc"](self.store, 4)
        try:
            return self._take(self.ex["cedar_version"](self.store, n), n).decode()
        finally:
            self.ex["cedar_free"](self.store, n, 4)

    def call(self, fn, call):  # returns the raw answer bytes
        data = json.dumps(call, separators=(",", ":")).encode()
        p = self.ex["cedar_alloc"](self.store, len(data) + 4)  # input, then 4 bytes for out_len
        try:
            self.mem.write(self.store, data, p)
            return self._take(self.ex[fn](self.store, p, len(data), p + len(data)), p + len(data))
        finally:
            self.ex["cedar_free"](self.store, p, len(data) + 4)


def sort_answer(a):  # the same sort the module applies before serialising
    d = a.get("response", {}).get("diagnostics")
    if d:
        d["reason"].sort()
        d["errors"].sort(key=lambda e: e["policyId"])
    return a


def unordered_validation(a):  # validate answers are NOT sorted by the module: their list order follows the hash seed
    for k in ("validationErrors", "validationWarnings", "otherWarnings"):
        if k in a:
            a[k].sort(key=lambda x: json.dumps(x, sort_keys=True))
    return a


fails = []
def expect(ok, what):
    if not ok:
        fails.append(what)

engine = wasmtime.Engine()
module = wasmtime.Module.from_file(engine, WASM)
imports = sorted((i.module, i.name) for i in module.imports)
expect(imports == EXPECTED_IMPORTS, f"imports {imports}")

cases, ref = json.load(open(CASES)), json.load(open(REF))
a, b = Cedar(engine, module), Cedar(engine, module)  # two instances = two hash seeds
expect(a.version() == ref["version"], f"cedar_version {a.version()!r} != reference {ref['version']!r}")

got = {}
for op, fn in (("authorize", "cedar_authorize"), ("validate", "cedar_validate")):
    got[op] = []
    for c, want in zip(cases[op], ref[op], strict=True):
        label = f"{op} {c.get('group', c.get('name'))} {c.get('seq', '')}"
        raw = a.call(fn, c["call"])
        ans = json.loads(raw)
        if op == "authorize":
            expect(raw == b.call(fn, c["call"]), f"{label}: bytes differ between instances")
            expect(ans == sort_answer(want), f"{label}: differs from reference\n  got  {raw[:300]}")
        else:
            expect(unordered_validation(json.loads(raw)) == unordered_validation(want), f"{label}: differs from reference\n  got  {raw[:300]}")
        got[op].append((c, ans))

# Named behaviours (also covered by the raw comparison above; asserted so a reference change cannot hide them)
by = {(c.get("group"), c.get("seq")): x for c, x in got["authorize"]}
for seq in ("1", "5"):
    e = by[("extra/overflow", seq)]["response"]["diagnostics"]["errors"]
    expect(e and all("overflow" in x["error"]["message"] for x in e), f"overflow {seq}: expected overflow errors, got {e}")
expect(by[("extra/overflow", "0")]["response"]["diagnostics"]["errors"] == [], "overflow 0: expected no error")
reasons = {t: by[("extra/hierarchy", t)]["response"]["diagnostics"]["reason"] for t in ("pay.refund", "fx.convert", "crm.read_customer", "not.in.entities")}
permit = ["sigill:baseline-permit"]
expect(reasons == {"pay.refund": ["no-money", "no-payments"], "fx.convert": ["no-money"], "crm.read_customer": permit, "not.in.entities": permit}, f"hierarchy {reasons}")
expect(by[("extra/bad-request", "wrong-resource-type")]["type"] == "failure", "bad request: expected type failure")
val = {c["name"]: x for c, x in got["validate"]}
expect(val["v11/control-set"]["type"] == "success" and val["v11/control-set"]["validationErrors"] == [], "strict validate: control set must be accepted")
expect(val["extra/hierarchy-on-v1-schema"]["type"] == "success" and len(val["extra/hierarchy-on-v1-schema"]["validationErrors"]) > 0, "strict validate: hierarchy policies on v1 schema must be rejected")

print(f"module sha256={hashlib.sha256(open(WASM, 'rb').read()).hexdigest()} cedar_version={a.version()} wasmtime={importlib.metadata.version('wasmtime')}")
print(f"imports: {', '.join(n for _, n in imports)}")
print(f"authorize={len(cases['authorize'])} validate={len(cases['validate'])} failures={len(fails)}")
for f in fails:
    print("FAIL", f)
sys.exit(1 if fails else 0)
