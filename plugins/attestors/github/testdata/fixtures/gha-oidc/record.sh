#!/usr/bin/env bash
# Re-record this fixture from a REAL GitHub Actions run. The evidence here was
# NOT hand-authored — it was captured by running cilock inside GitHub Actions:
#
#   repo:     testifysec/cilock-ci-fixtures  (throwaway capture repo)
#   workflow: .github/workflows/capture-github.yml
#   permissions: { contents: read, id-token: write }   # id-token mints the real OIDC token
#   steps:
#     - curl -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
#         "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=witness"            > oidc-token.json
#     - curl https://token.actions.githubusercontent.com/.well-known/jwks > jwks.json
#     - cilock run --attestations github --enable-archivista=false \
#         --signer-file-key-path key.pem --outfile attestation.json -- true
#   then `actions/upload-artifact` the four files; download + commit them here.
#
# WHY THE TOKEN REPLAYS EVEN THOUGH IT IS NOW EXPIRED (by design):
#   The github attestor delegates JWT handling to the jwt attestor, which
#   verifies the token SIGNATURE against the JWKS but does NOT validate exp/nbf.
#   This is intentional: the attestor's job is to RECORD the OIDC claims as they
#   were when the workflow ran. Whether those claims were time-valid is a
#   VERIFICATION-TIME concern enforced by policy — a witness/TSA timestamp on the
#   attestation establishes when it was captured, and a policy checks the claims'
#   time window against that. So a recorded (now-expired) token, verified against
#   the JWKS captured alongside it (the signing key is present by kid), replays
#   faithfully. oidc-token.json therefore holds an EXPIRED OIDC JWT — claims-only
#   evidence, not a live credential.
#
# Files: oidc-token.json (raw token endpoint response), jwks.json (the JWKS the
# signature verifies against), attestation.json (the real recorded cilock
# collection — the canonical evidence the harness cross-checks), fixture.yaml.
echo "This fixture is recorded from a real GitHub Actions run; see the comment above."
echo "It is not re-runnable locally (needs a GHA runner with id-token: write)."
