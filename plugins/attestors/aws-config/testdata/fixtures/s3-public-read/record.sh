#!/usr/bin/env bash
# Re-record this fixture from a REAL AWS Config query under cilock. The fixture
# is the recorded output of a real run — NOT a hand-authored sample — so
# re-record when the AWS CLI changes and commit the diff (the version/hash in
# fixture.yaml is the staleness signal).
#
# This fixture queries a LIVE AWS Config service, so it is NOT hermetically
# re-runnable in CI (it needs read-only AWS creds + network). The committed
# aws-config.json IS the real query output; the catalog harness replays it
# hermetically. This script is the operator recipe for refreshing it.
#
# Requires:
#   - aws-cli 2.x on PATH
#   - read-only AWS creds for the testifysec-demo account (898769392027):
#       AWS_PROFILE=testifysec-demo-readonly
#   - a cilock built with the aws-config attestor
#     (e.g. `go build ./presets/all/cmd/cilock-all`)
#   CILOCK=/path/to/cilock-all AWS_PROFILE=testifysec-demo-readonly ./record.sh
#
# Notes:
# - Modeled on the prowler/maven record.sh: a REPO-LOCAL .record-work workdir
#   (never mktemp / never /tmp) so no absolute temp path leaks into the
#   attestation, and an ephemeral ed25519 key generated per-run.
# - The aws-config attestor is POSTPRODUCT: it parses the get-compliance-details
#   JSON report from the products. The wrapped command is a real `aws
#   configservice get-compliance-details-by-resource` invocation; cilock
#   captures its command-run + the product file as evidence and the aws-config
#   attestor normalizes the EvaluationResults into the signed summary + subjects.
# - The shell wrapper writes ./aws-config.json as a RELATIVE filename in the
#   workdir, so the attestor's reportFile is relative (not an absolute home
#   path) — required to keep public evidence path-clean. The relative name also
#   matches the detector's product_glob ("aws-config*.json").
# - SCOPE (name-cleanliness, REQUIRED): the testifysec-demo account holds a
#   single Config rule (s3-bucket-public-read-prohibited). Querying it with
#   get-compliance-details-by-config-rule returns ALL six evaluated buckets, one
#   of which embeds a person's name in its bucket name — that string would land
#   in committed PUBLIC evidence (the rookery subtree two-way-syncs to a public
#   repo). We therefore scope to a single durable, name-clean bucket
#   (config-bucket-…, AWS Config's own delivery bucket) with the
#   get-compliance-details-by-RESOURCE call. Same `aws configservice` command
#   family, same top-level EvaluationResults JSON shape the attestor consumes,
#   real live output — just narrowed to a resource whose name carries no PII.
# - Only the aws-config:rule: and aws-config:resource: subject families appear:
#   S3 ResourceIds are bare bucket names, not ARNs, so the attestor's
#   aws:account: extraction (ARN field 5) finds nothing. That family is real but
#   not emitted by an S3-bucket rule, so the fixture does not claim it.
# - --attestations aws-config is MINIMAL on purpose: it omits the environment
#   attestor (which would dump host/env into the public attestation) and the git
#   attestor (the work dir is not a repo). cilock still adds command-run +
#   product/material.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
RULE="s3-bucket-public-read-prohibited"
RESOURCE_TYPE="AWS::S3::Bucket"
RESOURCE_ID="config-bucket-898769392027-us-east-1"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step aws-config-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations aws-config --enable-archivista=false \
    -- sh -c "aws configservice get-compliance-details-by-resource --resource-type '$RESOURCE_TYPE' --resource-id '$RESOURCE_ID' --region us-east-1 --output json > aws-config.json" )
cp "$WORK/aws-config.json"  "$HERE/aws-config.json"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(aws --version 2>&1 | sed -n 's#^aws-cli/\([^ ]*\).*#\1#p')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(python3 -c "import os;print(os.path.realpath('$(command -v aws)'))")" | awk '{print $1}')\""
