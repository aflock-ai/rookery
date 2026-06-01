#!/usr/bin/env bash
# Re-record this fixture from a REAL kube-bench run under cilock. The fixture is
# the recorded output of a real run — NOT a hand-authored sample — so re-record
# when kube-bench changes and commit the diff (the version/image digest in
# fixture.yaml is the staleness signal).
#
# kube-bench scans a LIVE Kubernetes node, so this is NOT hermetically
# re-runnable in CI (it needs a cluster + node access). The committed
# kube-bench.json IS the real benchmark output; the catalog harness replays it
# hermetically. This script is the operator recipe for refreshing it.
#
# Requires:
#   - kubectl + admin on the testifysec-demo demo EKS cluster
#       AWS_PROFILE=testifysec-demo
#       CTX=arn:aws:eks:us-east-1:898769392027:cluster/dropbox-clone-dev
#       aws eks update-kubeconfig --name dropbox-clone-dev --region us-east-1 --profile testifysec-demo
#   - a cilock built with the kube-bench attestor (e.g. `go build ./presets/all/cmd/cilock-all`)
#   CILOCK=/path/to/cilock-all CTX=<eks-context> ./record.sh
#
# Notes:
# - Modeled on the prowler/maven record.sh: a REPO-LOCAL .record-work workdir
#   (never mktemp / never /tmp) so no absolute temp path leaks into the
#   attestation, and an ephemeral ed25519 key generated per-run.
# - The kube-bench attestor is POSTPRODUCT: it parses the kube-bench --json
#   report ({Controls,Totals}) from the products. The Job runs the REAL CIS
#   Kubernetes Benchmark on a live worker node; we capture its JSON, stage it as
#   .record-work/kube-bench.src, then wrap a relative `cat … > kube-bench.json`
#   under cilock. cilock captures the command-run + the product file as evidence
#   and the kube-bench attestor normalizes the report into the signed summary.
# - --targets node scopes the scan to the worker-node section. The EKS control
#   plane is AWS-managed (no /etc/kubernetes/manifests), so node is the only
#   target with real audit files on a managed node; this yields a real benchmark
#   with both PASS and FAIL results while emitting the benchmark:/node: subject
#   families. KUBE_BENCH_CLUSTER_NAME is intentionally left unset so the recorded
#   and hermetically-replayed predicates match (no cluster: subject).
# - The wrapped argv uses RELATIVE filenames only, so report_file is relative
#   (not an absolute home path) — required to keep public evidence path-clean.
# - --attestations kube-bench is MINIMAL on purpose: it omits the environment
#   attestor (which would dump host/env into the public attestation) and the git
#   attestor (the workdir is not a repo). cilock still adds command-run +
#   product/material.
# - ALWAYS delete the Job afterward — never leave a benchmark Job running.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
CTX="${CTX:-arn:aws:eks:us-east-1:898769392027:cluster/dropbox-clone-dev}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT

# 1. Run the REAL CIS Kubernetes Benchmark as a Job on a live worker node.
cat > "$WORK/job.yaml" <<'YAML'
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench
  namespace: default
spec:
  backoffLimit: 0
  template:
    metadata:
      labels: { app: kube-bench }
    spec:
      hostPID: true
      restartPolicy: Never
      containers:
        - name: kube-bench
          image: aquasec/kube-bench:latest
          command: ["kube-bench"]
          args: ["run", "--targets", "node", "--benchmark", "eks-1.5.0", "--json"]
          volumeMounts:
            - { name: var-lib-kubelet, mountPath: /var/lib/kubelet, readOnly: true }
            - { name: etc-systemd,     mountPath: /etc/systemd,     readOnly: true }
            - { name: etc-kubernetes,  mountPath: /etc/kubernetes,  readOnly: true }
      volumes:
        - { name: var-lib-kubelet, hostPath: { path: /var/lib/kubelet } }
        - { name: etc-systemd,     hostPath: { path: /etc/systemd } }
        - { name: etc-kubernetes,  hostPath: { path: /etc/kubernetes } }
YAML
kubectl --context "$CTX" delete job kube-bench --ignore-not-found --wait=true
kubectl --context "$CTX" apply -f "$WORK/job.yaml"
# Wait for the pod to complete, then capture the JSON via the raw log API.
until [ "$(kubectl --context "$CTX" get pods -l app=kube-bench -o jsonpath='{.items[0].status.phase}' 2>/dev/null)" = "Succeeded" ]; do
  kubectl --context "$CTX" wait --for=condition=ready pod -l app=kube-bench --timeout=5s >/dev/null 2>&1 || true
done
POD="$(kubectl --context "$CTX" get pods -l app=kube-bench -o jsonpath='{.items[0].metadata.name}')"
kubectl --context "$CTX" get --raw "/api/v1/namespaces/default/pods/${POD}/log" > "$WORK/kube-bench.src"
kubectl --context "$CTX" delete job kube-bench --wait=true   # NEVER leave the Job running

# 2. Record the captured real output under cilock as the product.
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step kube-bench-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations kube-bench --enable-archivista=false \
    -- sh -c 'cat kube-bench.src > kube-bench.json' )

# 3. Copy product + attestation into the fixture.
cp "$WORK/kube-bench.json" "$HERE/kube-bench.json"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       (kube-bench version inside the image, e.g. v0.15.5)"
echo "  binary_sha256: (aquasec/kube-bench image digest, e.g. from the pod's imageID)"
