#!/bin/sh
# Regenerates ../THIRD-PARTY-NOTICES.md: the crates compiled into sigill_cedar.wasm for wasm32-wasip1 (normal
# dependencies, no proc-macros or build scripts: those run on the build host), their licences and NOTICE files.
# Pinned Rust container lists the crates, python:3.12-slim writes the file; one container at a time, nothing left
# in Docker. Cargo's registry (the crate sources) lives in $SIGILL_CEDAR_CACHE, shared with build.sh.
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
    cargo tree --locked --target wasm32-wasip1 --edges normal,no-proc-macro --prefix none --format "{p}|{l}|{r}" \
      | sed "s/ (\*)\$//" | LC_ALL=C sort -u > /work/crates.txt
    ln -s /usr/local/cargo/registry/src/index.crates.io-* /work/src'

docker run --rm --name "$NAME" -v "$ENGINE":/engine:ro -v "$CACHE/registry":/usr/local/cargo/registry:ro -v "$WORK":/work \
  python:3.12-slim python -I /engine/notices.py /work/crates.txt /work/src /work/THIRD-PARTY-NOTICES.md

cp "$WORK/THIRD-PARTY-NOTICES.md" ../THIRD-PARTY-NOTICES.md
