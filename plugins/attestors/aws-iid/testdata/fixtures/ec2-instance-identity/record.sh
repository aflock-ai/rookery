#!/usr/bin/env bash
# Records the aws-iid (registered name "aws") fixture from a REAL EC2 node.
#
# The aws-iid attestor is PreMaterial: it reads the EC2 Instance Metadata
# Service (IMDS, 169.254.169.254) and emits the signed instance identity
# document. Its predicate carries the RAW document bytes (rawiid), the RAW AWS
# signature (rawsig), and the regional-CA public key (publickey).
#
# The two committed files in this directory are those exact raw bytes:
#   instance-identity-document.json  <- the IMDS instance-identity/document
#   instance-identity-signature      <- the IMDS instance-identity/signature
# captured FROM A LIVE EC2 NODE (so the attestor's real RSA signature
# verification — rsa.VerifyPKCS1v15 against the embedded us-east-1 AWS CA cert —
# passes against genuine AWS evidence). The testkit http-mock driver serves them
# back over an httptest server (AWS_EC2_METADATA_SERVICE_ENDPOINT) so the run is
# fully hermetic: no live cloud, no network.
#
# Captured node (PUBLIC-OK demo topology; no secrets):
#   account:   898769392027 (testifysec demo)
#   instance:  i-0fafd8cc5598d3834
#   image:     ami-0a23644f1ead7eb05
#   region:    us-east-1 (us-east-1b)
#   privateIp: 10.0.58.222
#
# To re-capture, ON THE EC2 INSTANCE ITSELF (IMDSv2):
#
#   TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
#     -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
#   curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
#     http://169.254.169.254/latest/dynamic/instance-identity/document \
#     > instance-identity-document.json
#   curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
#     http://169.254.169.254/latest/dynamic/instance-identity/signature \
#     > instance-identity-signature
#
# (The originally-committed bytes were lifted verbatim from a real cilock
# `aws`-attestor run's rawiid/rawsig predicate fields — see the project handoff
# evidence file — which are byte-identical to the IMDS responses above.)
#
# Do NOT hand-edit instance-identity-document.json: a single changed byte makes
# the AWS signature fail to verify, which is exactly the red-team anchor the
# catalog test relies on.
echo "This fixture is captured on a live EC2 node — see the header comment for the curl commands." >&2
exit 0
