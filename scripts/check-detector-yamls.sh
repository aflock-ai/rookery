#!/usr/bin/env bash
# gate — CI fail-open lint target (jade lint-gate-scripts). Keep threshold
# comparisons floored and never mask failures.
# Drift guard for detector.yaml ↔ init() wiring.
#
# Rules enforced:
# 1. Every plugin with a detector.yaml must call detection.Register in
#    its main init().
# 2. Every plugin that calls detection.Register must have a detector.yaml.
# 3. Every detector.yaml must parse against the schema (via the
#    per-plugin detector_test.go's TestDetectorYAMLParses).
# 4. The YAML's `name:` must match the plugin's `Name = "..."` constant.
#
# Run from the worktree root. Exit non-zero on any drift.

set -euo pipefail
# nullglob: if the plugins glob matches nothing, expand to nothing rather than
# the literal "plugins/attestors/*/" — a moved/renamed tree must not iterate a
# bogus dir and silently pass.
shopt -s nullglob

cd "$(dirname "$0")/.."

errs=0
plugins_root="plugins/attestors"
plugin_dirs_seen=0

# Iterate every plugin dir that has any Go source.
for dir in "$plugins_root"/*/; do
  dir=${dir%/}
  plugin=$(basename "$dir")
  plugin_dirs_seen=$((plugin_dirs_seen+1))
  yaml="$dir/detector.yaml"

  # A plugin's wiring may span several .go files in the same directory.
  # Search all non-test files for the Register call and Name constant.
  go_files=$(find "$dir" -maxdepth 1 -name "*.go" ! -name "*_test.go")
  if [ -z "$go_files" ]; then
    continue
  fi

  has_yaml=0; [ -f "$yaml" ] && has_yaml=1
  has_register=0
  # shellcheck disable=SC2086
  if grep -qE '\bdetection\.Register\(' $go_files; then
    has_register=1
  fi

  # Rule 1
  if [ $has_yaml -eq 1 ] && [ $has_register -eq 0 ]; then
    echo "DRIFT: $plugin has detector.yaml but no detection.Register() call in any of $go_files" >&2
    errs=$((errs+1))
  fi
  # Rule 2
  if [ $has_register -eq 1 ] && [ $has_yaml -eq 0 ]; then
    echo "DRIFT: $plugin calls detection.Register() but has no detector.yaml" >&2
    errs=$((errs+1))
  fi

  # Rule 4 — name match
  if [ $has_yaml -eq 1 ]; then
    # shellcheck disable=SC2086
    plugin_name=$(grep -hE '^\s*Name\s+=\s+"' $go_files | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    yaml_name=$(grep -E '^name:' "$yaml" | head -1 | sed -E 's/^name:[[:space:]]*"?([^"#[:space:]]+)"?.*/\1/')
    if [ -n "$plugin_name" ] && [ "$plugin_name" != "$yaml_name" ]; then
      echo "DRIFT: $plugin: yaml name=$yaml_name but plugin Name=$plugin_name" >&2
      errs=$((errs+1))
    fi
  fi
done

# Floor: a healthy tree has real attestor plugins. Zero iterations means the
# tree moved/renamed and every rule above was vacuously satisfied — fail closed.
if [ "$plugin_dirs_seen" -eq 0 ]; then
  echo "::error::no plugin directories found under $plugins_root — tree layout changed; refusing to pass" >&2
  exit 2
fi

# Rule 3 — schema validation, deferred to per-plugin TestDetectorYAMLParses.
# Run them all in one pass.
#
# `go test -run <pattern>` exits 0 when NO test matches the pattern, so a
# renamed/deleted TestDetectorYAMLParses would silently "pass". Run with -v and
# assert the "=== RUN   TestDetectorYAMLParses" marker is present, proving the
# test actually executed for that plugin.
echo "Running detector.yaml schema tests for all plugins..."
test_failures=0
for dir in "$plugins_root"/*/; do
  dir=${dir%/}
  if [ -f "$dir/detector.yaml" ]; then
    if ! test_out=$(cd "$dir" && go test -run TestDetectorYAMLParses -v ./... 2>&1); then
      echo "DRIFT: $dir TestDetectorYAMLParses failed" >&2
      # shellcheck disable=SC2001  # per-line prefix; sed is the clear form here
      echo "$test_out" | sed 's/^/    /' >&2
      test_failures=$((test_failures+1))
    elif ! echo "$test_out" | grep -q '=== RUN[[:space:]]*TestDetectorYAMLParses'; then
      echo "DRIFT: $dir has detector.yaml but TestDetectorYAMLParses never ran (renamed/missing test)" >&2
      test_failures=$((test_failures+1))
    fi
  fi
done
errs=$((errs + test_failures))

if [ $errs -eq 0 ]; then
  yaml_count=$(find "$plugins_root" -maxdepth 2 -name "detector.yaml" | wc -l | tr -d ' ')
  echo "OK: $yaml_count detector.yaml files, all wired and parsing"
  exit 0
else
  echo "DRIFT: $errs issues" >&2
  exit 1
fi
