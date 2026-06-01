#!/usr/bin/env bash
# Re-record this fixture from a REAL prowler AWS scan under cilock. The fixture is
# the recorded output of a real run — NOT a hand-authored sample.
#
# WHY THE WRAP: `prowler ... -M json-asff` emits a BARE JSON array of findings,
# while the asff attestor consumes the AWS Security Hub envelope
# `{"Findings":[...]}` (the exact shape `aws securityhub get-findings --output json`
# returns — see asff.go: it json.Unmarshals into `asffResponse{ Findings []Finding }`).
# The wrapped command runs prowler for real, then `jq '{Findings: .}'` re-frames the
# genuine prowler findings into that envelope and removes the raw bare-array file so
# only the enveloped product is captured. The findings themselves are 100% real
# prowler output from a live AWS scan; the {Findings:[]} wrap is a faithful transform
# to the consumed format, not invented data.
#
# NOTE on prowler exit code: prowler exits non-zero (3) whenever there are FAILED
# findings. That is expected for a scan, so `-z` (--ignore-exit-code-3) keeps prowler
# itself at exit 0, and the trailing `|| true` neutralizes any residual non-zero so
# cilock still records the command-run attestation with the REAL argv. We alter ONLY
# the exit code — never the tool's output.
#
# Re-record when prowler or the scanned account changes and commit the diff.
# Requires: prowler 3.11.3 + jq + openssl on PATH, read-only AWS creds for the
# testifysec-demo account (898769392027), and a cilock built with the asff attestor.
#   AWS_PROFILE=testifysec-demo-readonly CILOCK=/path/to/cilock-all ./record.sh
#
# This fixture is liveExempt: re-recording needs AWS credentials + network, so it
# cannot be re-run in hermetic CI. The committed findings.asff.json + attestation.json
# ARE the real recorded artifact the catalog harness verifies against. (No
# recording-input/ dir: the input is a live AWS account, not a checked-in tree.)
#
# WHY --service cloudtrail (not iam): the IAM scan surfaced an IAM role whose name
# embedded an operator's personal name — that MUST NOT ship to the public mirror.
# CloudTrail's findings reference only the account-root ARN (arn:aws:iam::...:root) —
# pure account topology, no person-named resource — while still emitting all THREE
# asff subject families: aws:account: (the account id), aws:finding: (the one HIGH
# FAILED finding's ARN), and aws:arn: (the root resource ARN of a FAILED finding).
#
# --attestations asff is MINIMAL on purpose: it omits the environment attestor
# (which would dump host/env — including AWS_PROFILE — into the public attestation)
# and the git attestor (the work dir is not a repo). cilock still adds command-run
# + product/material. The testifysec-demo account (898769392027) is PUBLIC-OK:
# account id, resource ARNs, and service topology may appear in committed evidence;
# secrets and absolute home paths must not.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step asff-scan --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations asff --enable-archivista=false \
    -- sh -c 'prowler aws --service cloudtrail --region us-east-1 -z -M json-asff -F asff-raw -o . || true; jq "{Findings: .}" asff-raw.asff.json > findings.asff.json; rm -f asff-raw.asff.json' )
cp "$WORK/findings.asff.json" "$HERE/findings.asff.json"
cp "$WORK/attestation.json"   "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(prowler --version 2>/dev/null | awk '{print $2; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v prowler)" | awk '{print $1}')\""
