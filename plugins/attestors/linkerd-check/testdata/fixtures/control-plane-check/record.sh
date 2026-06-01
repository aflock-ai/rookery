#!/usr/bin/env bash
# Re-record this fixture from a REAL `linkerd check -o json` run under cilock. The
# fixture is the recorded output of a real run against a LIVE cluster with Linkerd
# actually installed — NOT a hand-authored sample — so re-record when linkerd
# changes and commit the diff (the version/hash in fixture.yaml is the staleness
# signal).
#
# This fixture needs a live Kubernetes cluster with the Linkerd control plane
# installed, so it is NOT hermetically re-runnable in CI. The committed
# linkerd-check.json IS the real check output; the catalog harness replays it
# hermetically. This script is the operator recipe for refreshing it.
#
# Requires:
#   - k3d (tested with v5.8.3) + Docker running
#   - linkerd CLI on PATH (tested stable-2.14.10)
#   - a cilock built with the linkerd-check attestor
#     (e.g. `go build ./presets/all/cmd/cilock-all`)
#   CILOCK=/path/to/cilock-all ./record.sh
#
# What it does:
#   1. create a disposable k3d cluster, install the Linkerd CRDs + control plane,
#      wait for the control-plane rollout;
#   2. record `linkerd check -o json > ./linkerd-check.json` under cilock from a
#      REPO-LOCAL .record-work workdir;
#   3. copy the product + recorded attestation into the fixture dir;
#   4. tear the cluster down.
#
# Notes:
# - REPO-LOCAL .record-work workdir (never mktemp / never /tmp) so no absolute
#   temp path leaks into the attestation, and an ephemeral ed25519 key per run.
# - The linkerd-check attestor is POSTPRODUCT: it scans the products for the
#   `linkerd check -o json` report. The wrapped command is a real `linkerd check`
#   invocation; cilock captures its command-run + the product file as evidence and
#   the attestor normalizes the report into the signed summary.
# - The check is wrapped in `sh -c '... > linkerd-check.json'` so the product is
#   written with a RELATIVE filename in the workdir (no absolute home path), and
#   the recorded command-run argv is exactly ["sh","-c", <script>].
# - `|| true` neutralizes ONLY the exit code: `linkerd check` exits non-zero when
#   any check warns/errors, which cilock would treat as a fatal command failure
#   and DROP the command-run attestation (losing the recorded argv). `|| true`
#   keeps the exit at 0 WITHOUT touching the JSON — every check result, warnings
#   and errors included, is intact in linkerd-check.json.
# - --attestations linkerd-check is MINIMAL on purpose: it omits the environment
#   attestor (which would dump host/env into the public attestation) and the git
#   attestor (the workdir is not a repo). cilock still adds command-run + product.
# - LINKERD_CLUSTER_NAME is intentionally left UNSET so no cluster: subject and no
#   cluster_name predicate field is emitted — the recorded evidence stays free of
#   any environment-derived name. The contract's cluster: subject is conditional.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
CLUSTER="${LC_CLUSTER:-lc-fixture}"
KCFG="${KUBECONFIG_FILE:-$HERE/.record-work/kubeconfig.yaml}"

WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"
cleanup() { rm -rf "$WORK"; k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== create k3d cluster $CLUSTER + install linkerd ==="
k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
k3d cluster create "$CLUSTER" --wait \
  --kubeconfig-update-default=false --kubeconfig-switch-context=false
k3d kubeconfig get "$CLUSTER" > "$KCFG"
export KUBECONFIG="$KCFG"
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -
kubectl -n linkerd rollout status deploy --timeout=240s

echo "=== record linkerd check under cilock ==="
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  KUBECONFIG="$KCFG" "$CILOCK" run --step linkerd-check-scan --workload manual \
    --signer-file-key-path key.pem \
    --outfile attestation.json --attestations linkerd-check --enable-archivista=false \
    -- sh -c 'linkerd check -o json > linkerd-check.json || true' )

cp "$WORK/linkerd-check.json" "$HERE/linkerd-check.json"
cp "$WORK/attestation.json"   "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(linkerd version --client --short 2>/dev/null)\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v linkerd)" | awk '{print $1}')\""
