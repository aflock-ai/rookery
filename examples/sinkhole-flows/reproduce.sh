#!/usr/bin/env bash
# reproduce.sh — real end-to-end reproduction of the `sinkhole-flows` attestor.
#
# WHY THIS IS A LIVE-ONLY EXAMPLE (not a hermetic catalog fixture):
#   sinkhole-flows is PostProduct and reads a HARDCODED absolute path,
#   /flows/out.jsonl, that is written ONLY by the pip-witness mitmproxy
#   "sinkhole" sidecar while a `pip install` runs through it. The predicate
#   embeds the raw captured HTTP(S) flows (timestamps, headers, request/response
#   bodies) and a sha256 of the live capture file — all of which vary per run.
#   There is no recordable artifact the hermetic replay harness could inject and
#   cross-check, so this attestor is proven by THIS reproduction instead.
#
# STATUS: this recipe is derived from the attestor source
#   (plugins/attestors/sinkhole-flows/sinkhole-flows.go) and the pip-witness
#   sidecar's interface. pip-witness is TestifySec's own tool
#   (https://github.com/testifysec/pip-witness, Apache-2.0) but is a SEPARATE
#   repo; this script has NOT been executed end-to-end inside this catalog (the
#   sidecar + mitmproxy CA setup live outside the rookery tree). Run it where
#   pip-witness is available to regenerate a real attestation.
set -euo pipefail

# --- 0. Inputs you control --------------------------------------------------
PKG_NAME="${PIPW_PACKAGE_NAME:-requests}"
PKG_VERSION="${PIPW_PACKAGE_VERSION:-2.32.3}"
SCAN_ID="${PIPW_SCAN_ID:-$(printf '%s-%s' "$PKG_NAME" "$PKG_VERSION")}"
# The sinkhole writes captured flows here; the attestor reads this EXACT path.
FLOWS_DIR="${FLOWS_DIR:-/tmp/pipw-flows}"          # host side of the /flows bind mount
CILOCK="${CILOCK:-cilock}"                          # a cilock-all built from this tree

# --- 1. Stand up the pip-witness sinkhole sidecar ---------------------------
# pip-witness runs a mitmproxy addon that intercepts pip's HTTPS traffic and
# appends one JSON line per flow to out.jsonl. See the pip-witness README for
# the canonical compose/CA setup; the essential contract is:
#   - a mitmproxy sidecar with the pip-witness addon loaded
#   - its CA cert trusted inside the pip container
#   - HTTPS_PROXY/REQUESTS_CA_BUNDLE pointed at the sidecar
#   - the sidecar's flows directory bind-mounted so out.jsonl lands in $FLOWS_DIR
mkdir -p "$FLOWS_DIR"
#   git clone https://github.com/testifysec/pip-witness && cd pip-witness
#   docker compose up -d sinkhole         # writes $FLOWS_DIR/out.jsonl

# --- 2. Run the real pip install THROUGH the sinkhole -----------------------
# This is the live event the attestor witnesses. Every package-index and wheel
# fetch is captured to out.jsonl by the mitmproxy addon.
#   docker run --rm \
#     -e HTTPS_PROXY=http://sinkhole:8080 \
#     -e REQUESTS_CA_BUNDLE=/certs/pipw-ca.pem \
#     --network pipw-net \
#     python:3.12-slim \
#     pip install "${PKG_NAME}==${PKG_VERSION}"

# --- 3. Attest the captured flows with cilock -------------------------------
# sinkhole-flows is PostProduct: it opens /flows/out.jsonl, filters by
# PIPW_SCAN_ID, and emits subjects pip://NAME@VERSION,
# pipw-sinkhole-scan://SCAN_ID, and pipw-sinkhole-flows-file://SCAN_ID
# (digest = sha256 of the captured out.jsonl). The flows dir MUST be mounted at
# /flows so the hardcoded FlowsPath resolves.
PIPW_PACKAGE_NAME="$PKG_NAME" \
PIPW_PACKAGE_VERSION="$PKG_VERSION" \
PIPW_SCAN_ID="$SCAN_ID" \
  "$CILOCK" run \
    --step sinkhole-flows-capture \
    --workload manual \
    --signer-file-key-path "${KEY_PEM:-/tmp/key.pem}" \
    --attestations product,sinkhole-flows \
    --enable-archivista=false \
    --outfile "$(dirname "$0")/attestation.json" \
    -- /bin/true
# (Run cilock in a context where $FLOWS_DIR is bind-mounted to /flows.)

echo "Wrote $(dirname "$0")/attestation.json — verify the DSSE signature and"
echo "confirm the pip://, pipw-sinkhole-scan://, pipw-sinkhole-flows-file:// subjects."
