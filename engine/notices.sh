#!/bin/sh
# Regenerates ../THIRD-PARTY-NOTICES.md: the crates compiled into sigill_cedar.wasm for wasm32-wasip1 (normal
# dependencies, no proc-macros or build scripts: those run on the build host), the Rust toolchain components linked
# into it (the standard library and the target's wasi-libc), their licences and NOTICE files.
# The pinned Rust container lists the crates and the standard library's crates, and links the module once more with
# the linker tracing its inputs (the result must be the shipped module); python:3.12-slim writes the file. One
# container at a time, nothing left in Docker. Cargo's registry (the crate sources) lives in $SIGILL_CEDAR_CACHE,
# shared with build.sh.
set -eu
cd "$(dirname "$0")"
ENGINE=$PWD
CACHE=${SIGILL_CEDAR_CACHE:-$HOME/.cache/sigill-cedar}
IMAGE=rust:1.100.0-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37
WORK=$CACHE/notices
NAME=sigill-cedar-notices-$$
rm -rf "$WORK" && mkdir -p "$WORK" "$CACHE/registry"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT INT TERM

docker run --rm --name "$NAME" -v "$ENGINE":/src:ro -v "$CACHE/registry":/usr/local/cargo/registry -v "$WORK":/work \
  -w /src "$IMAGE" sh -euc '
    tree() { cargo tree --locked "$@" --edges normal,no-proc-macro --prefix none --format "{p}|{l}|{r}" \
      | sed "s/ (\*)\$//" | LC_ALL=C sort -u; }
    tree --target wasm32-wasip1 > /work/crates.txt
    rustup target add wasm32-wasip1 >/dev/null 2>&1
    SYS=$(rustc --print sysroot)
    rustc --version > /work/rustc-version.txt
    mkdir /work/toolchain && cp -r "$SYS/share/doc/rust/COPYRIGHT-library.html" "$SYS/share/doc/rust/licenses" /work/toolchain/
    ls "$SYS/lib/rustlib/wasm32-wasip1/lib" > /work/sysroot-libs.txt
    # What the linker puts into the module: build.sh plus --trace, in a fresh /target (build paths reach the module),
    # before rust-src is installed (it changes the standard library paths in the module).
    RUSTFLAGS="--remap-path-prefix=/usr/local/cargo/registry/src=/cargo --remap-path-prefix=/src=/sigill-cedar -C link-arg=--trace" \
      CARGO_TARGET_DIR=/target cargo build --locked --release --target wasm32-wasip1 2> /tmp/build.log
    (cd /target/wasm32-wasip1/release && sha256sum -c /src/sigill_cedar.wasm.sha256 >&2)
    grep -o -E "self-contained/[A-Za-z0-9_.-]+\.(o|a\([^)]*\))|/wasm32-wasip1/lib/lib[a-z_]+-[0-9a-f]+\.rlib" /tmp/build.log \
      | LC_ALL=C sort -u > /work/linked.txt
    # The standard library of this toolchain, as the dist build configures it (the backtrace and panic-unwind
    # features: their crates are in the target sysroot). RUSTC_BOOTSTRAP only lets cargo read its manifests.
    rustup component add rust-src >/dev/null 2>&1
    cp -r "$SYS/lib/rustlib/src/rust/library" /tmp/library
    (cd /tmp && find library -type f \( -iname "licen*" -o -iname "copyright*" -o -iname "notice*" -o -iname "copying*" \
      -o -name .cargo_vcs_info.json \) -exec cp --parents {} /work/toolchain/ \;)
    (cd /tmp/library && RUSTC_BOOTSTRAP=1 tree -p std --features std/backtrace,std/panic-unwind --target wasm32-wasip1) \
      > /work/std-crates.txt
    ln -s /usr/local/cargo/registry/src/index.crates.io-* /work/src'

docker run --rm --name "$NAME" -v "$ENGINE":/engine:ro -v "$CACHE/registry":/usr/local/cargo/registry:ro -v "$WORK":/work \
  python:3.12-slim python -I /engine/notices.py /work "$IMAGE" /work/THIRD-PARTY-NOTICES.md

cp "$WORK/THIRD-PARTY-NOTICES.md" ../THIRD-PARTY-NOTICES.md
