#!/usr/bin/env bash
# Re-record this fixture from a REAL Maven run under cilock. The fixture is the
# recorded output of a real run — NOT a hand-authored sample. The recording-input
# tree (pom.xml + src/) was itself scaffolded by a REAL Maven tool run:
#   mvn -B archetype:generate \
#     -DarchetypeGroupId=org.apache.maven.archetypes \
#     -DarchetypeArtifactId=maven-archetype-quickstart -DarchetypeVersion=1.4 \
#     -DgroupId=com.example.demo -DartifactId=trivial-app -Dversion=1.0.0 \
#     -DinteractiveMode=false
# so pom.xml (groupId/artifactId/version + the junit dependency) is genuine
# Maven output, not invented.
#
# Re-record when Maven or the recording-input changes and commit the diff.
# Requires: mvn on PATH, a populated local repo (run the archetype:generate once
# first if offline), and a cilock built with the maven attestor
# (e.g. `go build ./presets/all/cmd/cilock-all`).
#   CILOCK=/path/to/cilock-all ./record.sh
#
# Notes:
# - The maven attestor is PREMATERIAL: it parses pom.xml directly from the
#   working dir (os.Open("pom.xml")) — it does NOT consume the mvn command's
#   output. The wrapped command is a real `mvn -q -B validate` (a genuine Maven
#   invocation against the project) so the recorded evidence carries a real tool
#   run; the maven attestor captures the pom.xml that run validated.
# - `-q -B` (quiet, batch) keeps absolute paths and interactive prompts out of
#   the command-run attestor's captured stderr (committed public evidence).
# - --attestations maven is MINIMAL on purpose: it omits the environment attestor
#   (which would dump host/env into the public attestation) and the git attestor
#   (the work dir is not a repo). cilock still adds command-run + product/material.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CILOCK="${CILOCK:-cilock}"
WORK="$HERE/.record-work"; rm -rf "$WORK"; mkdir -p "$WORK"; trap 'rm -rf "$WORK"' EXIT
cp -R "$HERE/recording-input/." "$WORK/"
( cd "$WORK"
  openssl genpkey -algorithm ed25519 -out key.pem 2>/dev/null
  "$CILOCK" run --step maven-build --workload manual --signer-file-key-path key.pem \
    --outfile attestation.json --attestations maven --enable-archivista=false \
    -- mvn -q -B validate )
cp "$WORK/pom.xml" "$HERE/pom.xml"
cp "$WORK/attestation.json" "$HERE/attestation.json"
echo "re-recorded. Update fixture.yaml recording: provenance to:"
echo "  version:       \"$(mvn -version 2>/dev/null | awk '/^Apache Maven/{print $3; exit}')\""
echo "  binary_sha256: \"$(shasum -a 256 "$(command -v mvn)" | awk '{print $1}')\""
