#!/usr/bin/env bash
# Re-record this fixture from a REAL GitLab CI run. The evidence here was NOT
# hand-authored — it was captured by running cilock inside a real GitLab CI job
# on a self-hosted gitlab-ce instance stood up locally in Docker (no SaaS
# account, no live credential committed). The instance was torn down after
# capture; everything here is claims-only / public-topology evidence.
#
#   1. Boot gitlab-ce + a registered gitlab-runner (docker executor) on a shared
#      docker network so the runner resolves the instance by hostname `gitlab`:
#
#        docker network create gitlab-net
#        docker run -d --name gitlab --hostname gitlab --network gitlab-net \
#          -p 8929:80 --shm-size 512m \
#          -e GITLAB_OMNIBUS_CONFIG="external_url 'http://gitlab'; \
#              gitlab_rails['initial_root_password']='<a-strong-random-pw>'; \
#              prometheus_monitoring['enable']=false; gitlab_kas['enable']=false; \
#              registry['enable']=false; nginx['listen_port']=80" \
#          gitlab/gitlab-ce:latest
#        # wait for http://localhost:8929 to serve 200, then mint a root PAT:
#        PAT=$(docker exec gitlab gitlab-rails runner \
#          'u=User.find_by_username("root"); \
#           t=u.personal_access_tokens.create!(scopes:["api"],name:"cap"); \
#           t.set_token("<a-strong-random-pat>"); t.save!; puts t.token')
#        # create a project + a project runner (GitLab 16+ flow):
#        curl -H "PRIVATE-TOKEN: $PAT" -X POST http://localhost:8929/api/v4/projects \
#          --data-urlencode name=rookery-gitlab-capture --data-urlencode visibility=private
#        RT=$(curl -H "PRIVATE-TOKEN: $PAT" -X POST \
#          http://localhost:8929/api/v4/user/runners \
#          --data-urlencode runner_type=project_type --data-urlencode project_id=1 \
#          --data-urlencode run_untagged=true | jq -r .token)
#        docker run -d --name gitlab-runner --network gitlab-net \
#          -v /var/run/docker.sock:/var/run/docker.sock \
#          -v /tmp/cilock:/opt/cilock:ro gitlab/gitlab-runner:latest
#        docker exec gitlab-runner gitlab-runner register --non-interactive \
#          --url http://gitlab/ --token "$RT" --executor docker \
#          --docker-image debian:stable-slim --docker-network-mode gitlab-net \
#          --docker-volumes /tmp/cilock:/opt/cilock:ro
#
#   2. Build a linux cilock-all FROM THIS TREE (so the recorded evidence matches
#      the attestor code under test). Match the runner's arch; the committed
#      evidence used GOOS=linux GOARCH=arm64:
#        (cd presets/all && go build -trimpath -o /tmp/cilock ./cmd/cilock-all)
#        # binary_sha256 in fixture.yaml is sha256 of THIS binary.
#
#   3. Commit a .gitlab-ci.yml to the project that mints a real OIDC token and
#      runs the gitlab attestor alone (GitLab 17.0 removed the auto-injected
#      CI_JOB_JWT, so the job mints one via the id_tokens keyword and exports it
#      under that name — the var the attestor reads by default):
#
#        capture:
#          image: debian:stable-slim
#          id_tokens: { CAPTURE_ID_TOKEN: { aud: witness } }
#          script:
#            - apt-get update -qq && apt-get install -y -qq openssl ca-certificates
#            - export CI_JOB_JWT="$CAPTURE_ID_TOKEN"
#            - cp /opt/cilock ./cilock && chmod +x ./cilock
#            - openssl genpkey -algorithm ed25519 -out key.pem
#            - ./cilock run --step gitlab-capture --workload manual -a gitlab \
#                --enable-archivista=false -k key.pem -o attestation.json -- true
#            - env | grep -E '^CI_' \
#                | grep -vEi 'token|secret|_key|password|job_jwt|registry_user|deploy' \
#                | sort > ci-env.txt
#            - printf '%s' "$CI_JOB_JWT" > oidc-token.txt
#          artifacts: { paths: [attestation.json, ci-env.txt, oidc-token.txt], when: always }
#
#   4. Wait for the pipeline to SUCCEED; download the artifacts. Fetch the JWKS
#      the token verifies against from the SAME instance:
#        curl http://localhost:8929/oauth/discovery/keys > jwks.json
#
#   5. Copy attestation.json + jwks.json here. Transcribe the CI_* vars the
#      attestor reads into fixture.yaml setup.env (SERVER_URL, SERVER_HOST,
#      CONFIG_PATH, JOB_ID, JOB_IMAGE, JOB_NAME, JOB_STAGE, JOB_URL, PIPELINE_ID,
#      PIPELINE_URL, PROJECT_ID, PROJECT_URL, RUNNER_ID), and put the raw OIDC
#      token under setup.env.CI_JOB_JWT. Map WITNESS_GITLAB_JWKS_URL -> jwks.json
#      via setup.options.endpoints.
#
#   6. Update recording.binary_sha256 to the sha256 of the cilock binary used.
#
#   7. TEARDOWN (the evidence must outlive the instance, not the reverse):
#        docker rm -f gitlab gitlab-runner; docker network rm gitlab-net
#
# WHY THE TOKEN REPLAYS DETERMINISTICALLY: the gitlab attestor delegates JWT
# handling to the jwt attestor, which verifies the token SIGNATURE against the
# JWKS but does NOT validate exp/nbf (claims-only recording; time-validity is a
# verification-time policy concern anchored to the attestation's own
# witness/TSA timestamp). The recorded CI_JOB_JWT IS the token embedded in
# attestation.json (same jti/exp), so the hermetic replay reproduces the
# recorded jwt.claims byte-for-byte; only jwt.verifiedBy.jwksUrl (the http-mock
# stub's localhost port) is volatile and is redacted.
#
# Subjects emitted by the real run (verified in attestation.json):
#   pipelineurl:<CI_PIPELINE_URL>
#   joburl:<CI_JOB_URL>
#   projecturl:<CI_PROJECT_URL>
#
# This script is the operator recipe, not an automated re-runner — capturing a
# real GitLab CI environment requires standing up the gitlab-ce + runner above.
set -euo pipefail
echo "This is a documentation recipe; see the comments above for the exact steps."
echo "gitlab evidence must be captured from inside a real GitLab CI job."
exit 0
