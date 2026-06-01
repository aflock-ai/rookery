#!/usr/bin/env bash
# Re-record this fixture from a REAL Steampipe run under cilock. The fixture is
# the recorded output of a real run — NOT a hand-authored sample — so re-record
# when Steampipe / the aws plugin changes and commit the diff (the version/hash
# in fixture.yaml is the staleness signal).
#
# This fixture queries a LIVE AWS account, so it is NOT hermetically re-runnable
# in CI (it needs read-only AWS creds + network + the steampipe service). The
# committed steampipe-output.json IS the real query result; the catalog harness
# replays it hermetically. This script is the operator recipe for refreshing it.
#
# Requires:
#   - steampipe v2.4.2 on PATH with the turbot/aws plugin installed
#   - the steampipe aws connection pointed at the read-only demo profile:
#       ~/.steampipe/config/aws.spc -> profile = "testifysec-demo-readonly"
#     (the aws plugin reads ~/.aws; AWS_PROFILE alone is not honored by the
#      steampipe service, the connection's profile= is what selects the account)
#   - read-only creds for the testifysec-demo account (898769392027)
#   - a cilock built with the steampipe attestor (`go build ./presets/all/cmd/cilock-all`)
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes:
# - Modeled on the prowler/maven record.sh: a REPO-LOCAL .record-work workdir
#   (never mktemp / never /tmp) so no absolute temp path leaks into the
#   attestation, and an ephemeral ed25519 key generated per-run.
# - The steampipe attestor is POSTPRODUCT: it consumes the JSON the steampipe
#   query produced. `steampipe query` writes to STDOUT, so the wrapped command is
#   `sh -c '... > steampipe-output.json'` to land a RELATIVE product file in the
#   workdir (a relative name keeps absolute home paths out of public evidence).
# - --attestor-steampipe-plugin aws is REQUIRED: it is the subject-convention
#   routing key. Without it the attestor emits zero subjects (the bug this
#   fixture proves is fixed). --attestor-steampipe-{sql,id} stamp the predicate
#   frontmatter for auditor review / routing.
# - We do NOT set --attestor-steampipe-export, so the predicate EMBEDS in the
#   signed collection (attestation.json) — the catalog cross-check reads it from
#   there. Export() now defaults false (was hardcoded true).
# - The query selects a benign column set (account_id, arn, name) of IAM users.
#   In the demo account the only IAM user is `catalog-evidence-ro`; no
#   person-named resource lands in the committed public evidence.
# - --attestations steampipe is MINIMAL on purpose: it omits the environment
#   attestor (which would dump host/env into the public attestation) and the git
#   attestor (the workdir is not a repo). cilock still adds command-run +
#   product/material.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
SQL='select account_id, arn, name from aws_iam_user order by name'
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step steampipe-query --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations steampipe --enable-archivista=false \
    --attestor-steampipe-plugin aws \
    --attestor-steampipe-id aws-iam-users \
    --attestor-steampipe-sql "$SQL" \
    -- sh -c "steampipe query \"$SQL\" --output json > steampipe-output.json" )
cp "$WORK/steampipe-output.json" "$HERE/steampipe-output.json"
cp "$WORK/attestation.json"      "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(steampipe --version 2>/dev/null | awk '/Steampipe/{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v steampipe)" | awk '{print $1}')\""
