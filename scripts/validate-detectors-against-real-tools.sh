#!/usr/bin/env bash
# Validate cilock detectors against real tool invocations.
#
# For each detector with a pre-gate argv_prefix, runs `cilock plan` with
# the real tool name + a plausible argv, and checks the detector appears
# in the fire list. Skips silently when the tool isn't on PATH.
#
# For docker's DOCKER_NO_PROVENANCE warning, also runs the rendered
# suggested_command and checks exit code zero.
#
# Run from the worktree root. Builds cilock first.

set -euo pipefail
cd "$(dirname "$0")/.."

# Prefer cilock-all (all attestors including preset-only) when present;
# fall back to canonical cilock for shipped-binary parity testing.
if [ -x cilock/cilock-all ]; then
  CILOCK=$(pwd)/cilock/cilock-all
  echo "  (using cilock-all — every plugin loaded, including preset-only ones)"
else
  if [ ! -x cilock/cilock ]; then
    (cd cilock && go build -o cilock ./cmd/cilock)
  fi
  CILOCK=$(pwd)/cilock/cilock
  echo "  (using canonical cilock — preset-only detectors will SKIP)"
fi

WS=$(mktemp -d -t cilock-validate-XXXX)
mkdir -p "$WS/.git" && touch "$WS/.git/HEAD"

pass=0
fail=0
skip=0

# Detectors intentionally excluded from canonical cilock (per
# scripts/check-canonical-attestors.sh). Their detector.yamls are
# valid; they just don't ship in the default binary, so cilock plan
# can't see them unless cilock is built with presets/all.
EXCLUDED_FROM_CANONICAL=(
  trivy
  docker-bench
  nessus
  aws-config
  asff
  structured-data
  sinkhole-flows
  falco
)

is_excluded() {
  local d="$1"
  for x in "${EXCLUDED_FROM_CANONICAL[@]}"; do
    [ "$x" = "$d" ] && return 0
  done
  return 1
}

# When using cilock-all, exclusion list is irrelevant — every plugin loads.
USING_ALL=0
if echo "$CILOCK" | grep -q "cilock-all"; then USING_ALL=1; fi

check_fires() {
  local detector="$1"; shift
  local tool="$1"; shift
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf "  SKIP %-15s (%s not installed)\n" "$detector" "$tool"
    skip=$((skip+1))
    return
  fi
  if [ $USING_ALL -eq 0 ] && is_excluded "$detector"; then
    printf "  SKIP %-15s (excluded from canonical cilock — preset-only)\n" "$detector"
    skip=$((skip+1))
    return
  fi
  local fired
  fired=$( (cd "$WS" && "$CILOCK" plan --format=json -- "$@") | jq -r ".plan.fire[].attestor" )
  if echo "$fired" | grep -qx "$detector"; then
    printf "  PASS %-15s\n" "$detector"
    pass=$((pass+1))
  else
    printf "  FAIL %-15s — fired=[%s] expected '$detector'\n" "$detector" "$(echo $fired | tr '\n' ' ')"
    fail=$((fail+1))
  fi
}

echo "=== detector fire validation (real tools, real argv) ==="

# pre-gate argv-driven detectors with installed tools
check_fires "docker" "docker" docker build -t test:1 .
check_fires "sbom" "syft" syft scan alpine:latest -o spdx-json=sbom.spdx.json
check_fires "sbom" "cdxgen" cdxgen .
check_fires "govulncheck" "govulncheck" govulncheck ./...
check_fires "trivy" "trivy" trivy fs .  # NOTE: not in canonical, will SKIP unless trivy plugin loaded
check_fires "prowler" "prowler" prowler aws
check_fires "steampipe" "steampipe" steampipe query "select 1"
check_fires "linkerd-check" "linkerd" linkerd check
check_fires "pip-install" "pip3" pip3 install requests
check_fires "oci" "crane" crane manifest alpine
check_fires "oci" "skopeo" skopeo copy docker://alpine docker://localhost/alpine
check_fires "kube-bench" "kube-bench" kube-bench
check_fires "falco" "falco" falco --version
check_fires "falco" "falcoctl" falcoctl version
check_fires "docker-bench" "docker-bench-security" docker-bench-security
check_fires "asff" "aws" aws securityhub get-findings
check_fires "aws-config" "aws" aws configservice get-compliance-details-by-config-rule

# env-driven detectors — set env in the cilock invocation
echo ""
echo "=== env-driven detectors ==="
env_check() {
  local detector="$1" envk="$2" envv="$3"
  if [ $USING_ALL -eq 0 ] && is_excluded "$detector"; then
    printf "  SKIP %-15s ($envk=$envv) — preset-only\n" "$detector"
    skip=$((skip+1))
    return
  fi
  local fired
  fired=$( (cd "$WS" && env "$envk=$envv" "$CILOCK" plan --format=json -- echo hi) | jq -r ".plan.fire[].attestor" )
  if echo "$fired" | grep -qx "$detector"; then
    printf "  PASS %-15s ($envk=$envv)\n" "$detector"
    pass=$((pass+1))
  else
    printf "  FAIL %-15s ($envk=$envv) — fired=[%s]\n" "$detector" "$(echo $fired | tr '\n' ' ')"
    fail=$((fail+1))
  fi
}
env_check github GITHUB_ACTIONS true
env_check gitlab GITLAB_CI true
env_check jenkins JENKINS_URL http://x
env_check aws-codebuild CODEBUILD_PROJECT_NAME demo
env_check sinkhole-flows PIPW_PACKAGE_NAME requests

# file-driven detectors
echo ""
echo "=== file-driven detectors ==="
file_check() {
  local detector="$1" filename="$2"
  local d=$(mktemp -d)
  mkdir -p "$d/$(dirname "$filename")" 2>/dev/null || true
  touch "$d/$filename"
  local fired
  fired=$( (cd "$d" && "$CILOCK" plan --format=json -- echo hi) | jq -r ".plan.fire[].attestor" )
  if echo "$fired" | grep -qx "$detector"; then
    printf "  PASS %-15s (cwd contains %s)\n" "$detector" "$filename"
    pass=$((pass+1))
  else
    printf "  FAIL %-15s (cwd contains %s) — fired=[%s]\n" "$detector" "$filename" "$(echo $fired | tr '\n' ' ')"
    fail=$((fail+1))
  fi
  rm -rf "$d"
}
file_check git .git/HEAD
file_check lockfiles package-lock.json
file_check lockfiles go.sum
file_check lockfiles Cargo.lock
file_check maven pom.xml

# Docker provenance suggestion — actually run the suggested command
echo ""
echo "=== suggested_command validation ==="
if command -v docker >/dev/null 2>&1; then
  D=$(mktemp -d) && mkdir -p "$D/.git" && touch "$D/.git/HEAD" && echo "FROM alpine" > "$D/Dockerfile"
  SUGGESTED=$( (cd "$D" && "$CILOCK" plan --format=json -- docker build -t test:fix .) | \
    jq -r '.plan.warnings[] | select(.code=="DOCKER_NO_PROVENANCE") | (.suggested_command | join(" "))' )
  if [ -n "$SUGGESTED" ]; then
    printf "  suggested: %s\n" "$SUGGESTED"
    if (cd "$D" && eval "$SUGGESTED") >/dev/null 2>&1; then
      printf "  PASS docker suggested_command runs successfully\n"
      pass=$((pass+1))
    else
      printf "  FAIL docker suggested_command failed\n"
      fail=$((fail+1))
    fi
  else
    printf "  SKIP docker suggested_command (no warning emitted)\n"
    skip=$((skip+1))
  fi
  rm -rf "$D"
else
  printf "  SKIP docker suggested_command (docker not installed)\n"
  skip=$((skip+1))
fi

rm -rf "$WS"

echo ""
echo "=============================================="
echo "PASS=$pass  FAIL=$fail  SKIP=$skip"
echo "=============================================="
exit $((fail > 0 ? 1 : 0))
