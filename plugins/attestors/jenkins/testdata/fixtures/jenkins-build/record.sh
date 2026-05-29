#!/usr/bin/env bash
# Re-record this fixture from a REAL Jenkins pipeline run under cilock. The
# fixture is the recorded output of a real run — NOT a hand-authored sample — so
# re-record when cilock / the jenkins attestor changes and commit the diff (the
# version/binary_sha256 in fixture.yaml is the staleness signal).
#
# jenkins is a PreMaterial attestor and PURE ENV: it gates on JENKINS_URL and
# reads BUILD_ID, BUILD_NUMBER, BUILD_TAG, BUILD_URL, EXECUTOR_NUMBER, JAVA_HOME,
# JENKINS_URL, JOB_NAME, NODE_NAME, WORKSPACE. No OIDC, no JWT, no API call — so
# the predicate is deterministic and the catalog harness replays the captured env
# hermetically (testkit env mode) and cross-checks it against attestation.json.
#
# This fixture needs a REAL Jenkins environment (those env vars only exist inside
# a Jenkins build), so it is NOT hermetically re-runnable in CI. The committed
# attestation.json IS the real signed (ed25519) collection.
#
# Requires: Docker + a linux/amd64 cilock built FROM THIS TREE (so the recorded
# evidence matches the attestor code under test):
#   (cd presets/all && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
#     go build -trimpath -o /tmp/cilock-jenkins ./cmd/cilock-all)
#   shasum -a 256 /tmp/cilock-jenkins   # -> recording.binary_sha256
# (Runs under qemu binfmt on arm64 hosts; the jenkins/jenkins:lts image is arm64
# but Docker emulates the amd64 binary transparently.)
#
# Recipe (what produced the committed evidence):
#   1. mkdir /tmp/jenkins-cap && cp /tmp/cilock-jenkins /tmp/jenkins-cap/cilock
#   2. docker run -d --name jenkins-fixture -p 18080:8080 \
#        -e JAVA_OPTS="-Djenkins.install.runSetupWizard=false" \
#        -v /tmp/jenkins-cap:/cap jenkins/jenkins:lts
#      (setup wizard off => no security realm => REST API open, but CSRF crumb
#       still required: fetch /crumbIssuer/api/json with a cookie jar and reuse
#       the same jar + Jenkins-Crumb header on every POST.)
#   3. Wait for GET /login -> 200.
#   4. Configure the Jenkins root URL (else Jenkins does NOT inject JENKINS_URL
#      and the attestor returns ErrNotJenkins). POST to /scriptText:
#        import jenkins.model.JenkinsLocationConfiguration
#        def loc = JenkinsLocationConfiguration.get()
#        loc.setUrl("http://localhost:18080/"); loc.save()
#   5. Create a freestyle job via POST /createItem?name=jenkins-fixture-capture
#      (Content-Type: application/xml) with config.xml (committed here) whose
#      Execute-shell build step runs:
#        openssl genpkey -algorithm ed25519 -out key.pem
#        /cap/cilock run --step jenkins-capture --workload manual \
#          --signer-file-key-path key.pem --attestations jenkins \
#          --enable-archivista=false --outfile attestation.json -- true
#        # dump ONLY the Jenkins-injected vars the attestor reads, MINUS secrets:
#        env | grep -E '^(BUILD_|JENKINS_|JOB_|NODE_|EXECUTOR_|WORKSPACE=|JAVA_HOME=)' \
#          | grep -vEi 'token|secret|password|api_key' | sort > jenkins-env.txt
#   6. POST /job/jenkins-fixture-capture/build; poll
#      /job/jenkins-fixture-capture/<n>/api/json until result == SUCCESS.
#   7. docker cp the workspace's attestation.json + jenkins-env.txt out.
#   8. Copy attestation.json + jenkins-env.txt here. Transcribe the ten vars the
#      attestor reads from jenkins-env.txt into fixture.yaml setup.env verbatim.
#   9. Update recording.binary_sha256 to the sha256 of the cilock binary used.
#  10. TEARDOWN: docker rm -f jenkins-fixture (destroys the build's ed25519 key
#      with the container). Scrub key.pem from any staging dir.
#
# Subjects emitted by the real run (verified in attestation.json):
#   pipelineurl:<BUILD_URL>     (sha256 of the BUILD_URL string)
#   jenkinsurl:<JENKINS_URL>    (sha256 of the JENKINS_URL string)
#
# This script is the operator recipe, not an automated re-runner — capturing a
# real Jenkins environment requires standing up the controller above.
set -euo pipefail
echo "This is a documentation recipe; see the comments above for the exact steps."
echo "jenkins evidence must be captured from inside a real Jenkins build."
exit 0
