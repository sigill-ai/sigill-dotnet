#!/bin/sh
# Builds dist/sigill_cedar.wasm in a pinned Rust container and writes dist/sigill_cedar.wasm.sha256.
# Cargo registry and target/ live in $SIGILL_CEDAR_CACHE (outside the repo); nothing is left in Docker.
set -eu
cd "$(dirname "$0")"
ENGINE=$PWD
CACHE=${SIGILL_CEDAR_CACHE:-$HOME/.cache/sigill-cedar}
IMAGE=rust:1.100.0-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37
NAME=sigill-cedar-build-$$
mkdir -p "$CACHE/registry" "$CACHE/target" dist
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT INT TERM

# Fixed mount points + path remapping keep build paths out of the module (and identical between machines).
docker run --rm --name "$NAME" \
  -v "$ENGINE":/src:ro -v "$ENGINE/dist":/out \
  -v "$CACHE/registry":/usr/local/cargo/registry -v "$CACHE/target":/target \
  -e CARGO_TARGET_DIR=/target \
  -e RUSTFLAGS="--remap-path-prefix=/usr/local/cargo/registry/src=/cargo --remap-path-prefix=/src=/sigill-cedar" \
  -w /src "$IMAGE" sh -euc '
    rustup target add wasm32-wasip1
    cargo build --locked --release --target wasm32-wasip1
    cp /target/wasm32-wasip1/release/sigill_cedar.wasm /out/
    cd /out && sha256sum sigill_cedar.wasm > sigill_cedar.wasm.sha256 && cat sigill_cedar.wasm.sha256'
