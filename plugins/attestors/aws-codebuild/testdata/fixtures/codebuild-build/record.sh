#!/usr/bin/env bash
# Re-record this fixture from a REAL AWS CodeBuild run under cilock. The fixture
# is the recorded output of a real run — NOT a hand-authored sample — so
# re-record when cilock / the aws-codebuild attestor changes and commit the diff
# (the version/binary_sha256 in fixture.yaml is the staleness signal).
#
# aws-codebuild is a PreMaterial attestor: it reads CODEBUILD_* env vars only
# (no OIDC, no JWT). It additionally makes a best-effort codebuild:BatchGetBuilds
# API call when AWS creds are ambient; that run is logged-and-continue, so the
# committed evidence here is the env-only predicate (deterministic across runs).
#
# This fixture needs a REAL CodeBuild environment, which only exists inside a
# CodeBuild job — so it is NOT hermetically re-runnable in CI. The committed
# attestation.json IS the real signed collection; the catalog harness replays
# the captured env hermetically (testkit env mode) and cross-checks it.
#
# Requires:
#   - AWS admin in the testifysec-demo account (898769392027), us-east-1
#       export AWS_PROFILE=testifysec-demo AWS_REGION=us-east-1
#   - a linux/amd64 cilock built FROM THIS TREE (so the recorded evidence matches
#     the attestor code under test — the binary must include the same
#     project-name-from-ARN derivation the hermetic replay uses):
#       (cd presets/all && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
#         go build -trimpath -o /tmp/cilock ./cmd/cilock-all)
#     (-trimpath keeps absolute build paths out of the binary / evidence.)
#
# Recipe (what produced the committed evidence):
#   1. Create an S3 bucket; upload the cilock binary to s3://<bucket>/cilock.
#   2. Create a CodeBuild service role trusting codebuild.amazonaws.com with a
#      policy allowing logs:*, s3:GetObject/PutObject on the bucket, and
#      codebuild:BatchGetBuilds.
#   3. Create a CodeBuild project (NO_ARTIFACTS, image
#      aws/codebuild/amazonlinux2-x86_64-standard:5.0, computeType
#      BUILD_GENERAL1_SMALL). Use a GITHUB source pointed at the PUBLIC
#      octocat/Hello-World repo so CodeBuild populates
#      CODEBUILD_RESOLVED_SOURCE_VERSION + CODEBUILD_SOURCE_REPO_URL (needed for
#      the codebuild-source-version subject), with this inline buildspec:
#
#        version: 0.2
#        phases:
#          build:
#            commands:
#              - aws s3 cp s3://<bucket>/cilock /tmp/cilock && chmod +x /tmp/cilock
#              - openssl genpkey -algorithm ed25519 -out key.pem
#              - /tmp/cilock run --step codebuild-capture --workload manual \
#                  --signer-file-key-path key.pem --attestations aws-codebuild \
#                  --enable-archivista=false --outfile attestation.json -- true
#              # dump ONLY the CODEBUILD_* vars the attestor reads, MINUS secrets:
#              - env | grep -E '^CODEBUILD_' \
#                  | grep -vEi 'token|secret|_key|password|webhook|AWS_(ACCESS|SECRET|SESSION)' \
#                  | sort > codebuild-env.txt
#              - aws s3 cp attestation.json  s3://<bucket>/out/attestation.json
#              - aws s3 cp codebuild-env.txt s3://<bucket>/out/codebuild-env.txt
#
#   4. aws codebuild start-build --project-name <project>; poll batch-get-builds
#      until buildStatus == SUCCEEDED (~3 min).
#   5. Fetch s3://<bucket>/out/attestation.json + codebuild-env.txt.
#   6. Copy attestation.json here. Transcribe the CODEBUILD_* vars the attestor
#      reads into fixture.yaml setup.env (BUILD_ID, BUILD_ARN, BUILD_NUMBER,
#      PROJECT_ARN, RESOLVED_SOURCE_VERSION, SOURCE_REPO_URL, AWS_REGION). Replace
#      CODEBUILD_INITIATOR with a benign value (the live initiator is a person SSO
#      identity) and keep build_info.initiator in expect.redact.
#   7. Update recording.binary_sha256 to the sha256 of the cilock binary used.
#   8. TEARDOWN (cost hygiene): delete the CodeBuild project, the service role
#      (delete-role-policy then delete-role), and empty + delete the S3 bucket.
#
# Subjects emitted by the real run (verified in attestation.json):
#   codebuild-build-id:<CODEBUILD_BUILD_ID>
#   codebuild-project:<name from CODEBUILD_PROJECT_ARN>
#   codebuild-source-version:<CODEBUILD_RESOLVED_SOURCE_VERSION>
#
# This script is the operator recipe, not an automated re-runner — capturing a
# real CodeBuild environment requires standing up the project above.
set -euo pipefail
echo "This is a documentation recipe; see the comments above for the exact steps."
echo "aws-codebuild evidence must be captured from inside a real CodeBuild job."
exit 0
