#!/bin/sh
# Conformance check: reference answers from @cedar-policy/cedar-wasm 4.14.0 (node:22), then dist/sigill_cedar.wasm
# under the Python wasmtime package (python:3.12-slim). One container at a time; nothing is left in Docker.
set -eu
cd "$(dirname "$0")"
ENGINE=$PWD
CACHE=${SIGILL_CEDAR_CACHE:-$HOME/.cache/sigill-cedar}
WORK=$CACHE/check
NAME=sigill-cedar-check-$$
rm -rf "$WORK" && mkdir -p "$WORK/ref" "$CACHE/npm" "$CACHE/pip"
trap 'docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT INT TERM

docker run --rm --name "$NAME" -v "$ENGINE/check":/check:ro -v "$WORK":/work -v "$CACHE/npm":/root/.npm -e npm_config_update_notifier=false \
  -w /work/ref node:22 sh -euc '
    cp /check/package.json /check/package-lock.json . && npm ci --no-audit --no-fund --ignore-scripts --loglevel=error
    node /check/ref.mjs /check/cases.json /work/ref-answers.json'

docker run --rm --name "$NAME" -v "$ENGINE/check":/check:ro -v "$ENGINE/dist":/dist:ro -v "$WORK":/work \
  -v "$CACHE/pip":/root/.cache/pip -e PIP_DISABLE_PIP_VERSION_CHECK=1 -e PIP_ROOT_USER_ACTION=ignore \
  python:3.12-slim sh -euc '
    pip install -q wasmtime==50.0.1
    python -I /check/check.py /dist/sigill_cedar.wasm /check/cases.json /work/ref-answers.json'
