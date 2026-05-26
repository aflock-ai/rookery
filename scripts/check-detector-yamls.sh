#!/usr/bin/env bash
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

cd "$(dirname "$0")/.."

errs=0
plugins_root="plugins/attestors"

# Iterate every plugin dir that has any Go source.
for dir in "$plugins_root"/*/; do
  dir=${dir%/}
  plugin=$(basename "$dir")
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

# Rule 3 — schema validation, deferred to per-plugin TestDetectorYAMLParses.
# Run them all in one pass.
echo "Running detector.yaml schema tests for all plugins..."
test_failures=0
for dir in "$plugins_root"/*/; do
  dir=${dir%/}
  if [ -f "$dir/detector.yaml" ]; then
    if ! (cd "$dir" && go test -run TestDetectorYAMLParses ./... >/dev/null 2>&1); then
      echo "DRIFT: $dir TestDetectorYAMLParses failed" >&2
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
