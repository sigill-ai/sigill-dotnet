# engine: the Cedar policy core as one WebAssembly module

`sigill_cedar.wasm` is the official [Cedar](https://github.com/cedar-policy/cedar) policy engine
(`cedar-policy` 4.14.0), compiled to `wasm32-wasip1` behind a small C ABI. The .NET and Python SDKs load this
exact file in-process with [Wasmtime](https://wasmtime.dev) and pin its sha256, so both SDKs evaluate policies
with the same bytes, on every platform Wasmtime supports.

Calls and answers are the JSON objects of `cedar_policy::ffi` — the same shapes as
`@cedar-policy/cedar-wasm`'s `isAuthorized` and `validate`. The module has no filesystem, network or clock.

## Artifact

| | |
|---|---|
| File | `dist/sigill_cedar.wasm`, 3,855,655 bytes |
| sha256 | `a0cd395067e77a157116f6b25bcdb612d34c61d1a4446918d75da1a07c80d1f3` |
| Cedar core | `cedar-policy =4.14.0`, feature `partial-eval` (as `@cedar-policy/cedar-wasm` 4.14.0); `Cargo.lock` committed |
| Toolchain | `rust:1.100.0-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37` |
| Profile | release, `opt-level = "s"`, LTO, `codegen-units = 1`, stripped; build paths remapped |
| WASI imports | `random_get`, `environ_get`, `environ_sizes_get`, `fd_write`, `proc_exit` |

The SDKs embed this exact file. A rebuild with the pinned toolchain and `Cargo.lock` gives the same bytes.

## ABI

All lengths are bytes; every pointer the module returns is freed by the host with `cedar_free(ptr, len)`.

| Export | Meaning |
|---|---|
| `cedar_alloc(len) -> ptr` | Allocate `len` bytes for an input. |
| `cedar_free(ptr, len)` | Free an input or an output. |
| `cedar_authorize(ptr, len, out_len_ptr) -> ptr` | UTF-8 JSON call in, JSON answer out (length written to `out_len_ptr`, a 32-bit little-endian slot). |
| `cedar_validate(ptr, len, out_len_ptr) -> ptr` | As above, for policy validation. |
| `cedar_version(out_len_ptr) -> ptr` | The core's SDK version, e.g. `4.14.0` (= cedar-wasm `getCedarVersion()`). |

Call `_initialize` once after instantiation if the module exports it. Configure WASI with no arguments, no environment,
no preopened directories and no inherited stdio. A malformed call returns a `{"type":"failure",…}` answer; a Cedar
evaluation error (for example a `Long` overflow) is reported in `diagnostics.errors`, not as a trap.

**Determinism.** In an authorize answer, `response.diagnostics.reason` is sorted and `response.diagnostics.errors` is
sorted by `policyId`, so an answer's bytes do not depend on the instance. Validate answers are returned as the core
produces them: the order of `validationErrors` can differ between instances; compare them as a set.
A Rust panic inside the module traps the instance; discard it and instantiate again.

## Build and check

The scripts run everything in Docker, one container at a time, and leave no containers or volumes behind. Cargo's
registry, `target/` and the check's work files go to `$SIGILL_CEDAR_CACHE` (a directory outside the repository).

```sh
SIGILL_CEDAR_CACHE=$HOME/.cache/sigill-cedar ./build.sh   # -> dist/sigill_cedar.wasm, dist/sigill_cedar.wasm.sha256
SIGILL_CEDAR_CACHE=$HOME/.cache/sigill-cedar ./check.sh   # exits non-zero on any mismatch
SIGILL_CEDAR_CACHE=$HOME/.cache/sigill-cedar ./notices.sh # -> ../THIRD-PARTY-NOTICES.md
```

`notices.sh` regenerates [`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md) (sorted, byte-stable): the crates
compiled into the module for `wasm32-wasip1` (normal dependencies; proc-macros and build scripts run on the build host
and are not in it), their licence texts and NOTICE files. It stops on any licence that is not permissive. Both SDKs
ship that file with the module: run it after any change to `Cargo.lock`, and copy the file to the Python SDK as well.

`check.sh` runs the cases in `check/cases.json` (67 authorize, 10 strict validate: the policy-evaluation test vectors,
`Long` overflow, entity hierarchy with `resource in ToolGroup::"…"`, a rejected request, accepted and rejected policy
sets) through `@cedar-policy/cedar-wasm` 4.14.0 on `node:22`, then through the module on `python:3.12-slim` with
`wasmtime` 50.0.1. Every authorize answer must equal the reference after the sort above and be byte-identical across
two instances; every validate answer must equal the reference; `cedar_version` must equal `getCedarVersion()`; and the
module may import only the WASI functions listed above.
