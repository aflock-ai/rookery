#!/usr/bin/env bash
# Re-record this fixture from a REAL GCE VM. The evidence here was NOT
# hand-authored — it was captured by running cilock ON a Google Compute Engine
# instance, because the GCP instance identity token is ONLY issued by the
# metadata server ON a GCE VM (there is no other way to mint one).
#
#   project: gen-lang-client-0763719579   (billing-enabled testifysec project)
#   instance: cilock-gcpiit-fixture       (e2-micro, debian-12, us-central1-a)
#
# Capture procedure (run once, then the VM is destroyed):
#
#   # 1. Launch a minimal VM (the ONLY place a real IIT can be minted):
#   gcloud compute instances create cilock-gcpiit-fixture \
#     --zone us-central1-a --machine-type e2-micro \
#     --image-family debian-12 --image-project debian-cloud
#
#   # 2. Build cilock-all for the VM's arch from THIS tree and copy it up:
#   (cd presets/all && GOWORK=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
#       go build -o /tmp/cilock ./cmd/cilock-all)   # sha256 -> recording.binary_sha256
#   gcloud compute scp /tmp/cilock cilock-gcpiit-fixture:~/cilock --zone us-central1-a
#
#   # 3. ON the VM, capture the three files (co-temporal so the token's kid is
#   #    present in the JWKS — Google rotates signing keys):
#   MD='http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=witness-node-attestor&format=full&licenses=TRUE'
#   curl -s -H 'Metadata-Flavor: Google' "$MD"       > identity-token   # bare JWT string
#   curl -s https://www.googleapis.com/oauth2/v3/certs > gcp-jwks.json   # the signing keys
#   ./cilock run -s gcp-iit-capture --attestations gcp-iit \
#     --enable-archivista=false --signer-debug-enabled -o attestation.json -- true
#
#   # 4. Pull the three files back and commit them here, then TEAR DOWN the VM:
#   gcloud compute instances delete cilock-gcpiit-fixture --zone us-central1-a --quiet
#
# WHY THE TOKEN REPLAYS EVEN THOUGH IT IS NOW EXPIRED (by design):
#   The gcp-iit attestor delegates JWT handling to the jwt attestor, which
#   verifies the token SIGNATURE against the JWKS but does NOT validate exp/nbf.
#   This is intentional: the attestor's job is to RECORD the identity claims as
#   they were when cilock ran. Whether those claims were time-valid is a
#   VERIFICATION-TIME concern enforced by policy (a witness/TSA timestamp on the
#   attestation establishes when it was captured; a policy checks the claims'
#   time window against that). So a recorded (now-expired) token, verified
#   against the JWKS captured alongside it (the signing key is present by kid),
#   replays faithfully. identity-token therefore holds an EXPIRED IIT JWT —
#   claims-only evidence, not a live credential.
#
#   The five subject families all come from the JWT claims (the
#   google.compute_engine block), NOT from separate metadata fetches: those only
#   fire on the GKE / workload-identity branch (when the `google` claim is
#   absent). A plain GCE VM's token carries the `google` claim, so the attestor
#   performs exactly ONE metadata HTTP call (the identity token) plus the JWKS
#   fetch — the two endpoints fixture.yaml mocks.
#
# Files: identity-token (raw token endpoint response, an expired IIT JWT),
# gcp-jwks.json (the JWKS the signature verifies against), attestation.json (the
# real recorded cilock collection — the canonical evidence the harness
# cross-checks), fixture.yaml.
echo "This fixture is recorded from a real GCE VM; see the comment above."
echo "It is not re-runnable locally (needs a live GCE instance to mint the IIT)."
