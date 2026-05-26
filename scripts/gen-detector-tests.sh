#!/usr/bin/env bash
# Generate per-plugin detector_test.go for a list of plugin dirs. The
# generated test exercises whichever predicate paths the plugin uses:
#   - argv_prefix in pre or post → AssertPreGateFiresOnArgv / AssertPostGateFiresOnExec
#   - file_exists in pre        → AssertPreGateFiresOnFile
#   - env_set / env_equals in pre → AssertPreGateFiresInEnv
#   - product_glob in post      → AssertPostGateFiresOnProduct
#
# Always emits AssertParses (round-trip schema). Skip generation if a
# test file already exists.

set -euo pipefail

for plugin_dir in "$@"; do
  [ -d "$plugin_dir" ] || { echo "skip: $plugin_dir not a directory" >&2; continue; }
  yaml="$plugin_dir/detector.yaml"
  [ -f "$yaml" ] || { echo "skip: $plugin_dir has no detector.yaml" >&2; continue; }

  test_file="$plugin_dir/detector_test.go"
  if [ -f "$test_file" ]; then
    echo "skip: $test_file already exists"
    continue
  fi

  main_go=$(find "$plugin_dir" -maxdepth 1 -name "*.go" ! -name "*_test.go" | head -1)
  pkg=$(grep -m1 '^package ' "$main_go" | awk '{print $2}')

  # Probe the YAML for predicates we can test. This is intentionally
  # tolerant — anything we can't determine confidently, we skip.
  py_probe=$(python3 - "$yaml" <<'PY'
import sys, yaml
data = yaml.safe_load(open(sys.argv[1]))
pre = data.get('pre') or {}
post = data.get('post') or {}

def first_argv(node):
    if not isinstance(node, dict):
        return None
    if 'argv_prefix' in node:
        return node['argv_prefix']
    for k in ('any_of', 'all_of'):
        for child in (node.get(k) or []):
            r = first_argv(child)
            if r:
                return r
    return None

def first_file_exists(node):
    if not isinstance(node, dict):
        return None
    if 'file_exists' in node:
        return node['file_exists']
    for k in ('any_of', 'all_of'):
        for child in (node.get(k) or []):
            r = first_file_exists(child)
            if r:
                return r
    return None

def first_env_set(node):
    if not isinstance(node, dict):
        return None
    if 'env_set' in node:
        return node['env_set']
    if 'env_equals' in node:
        e = node['env_equals']
        return f"{e['var']}={e.get('value','')}"
    for k in ('any_of', 'all_of'):
        for child in (node.get(k) or []):
            r = first_env_set(child)
            if r:
                return r
    return None

def first_product_glob(node):
    if not isinstance(node, dict):
        return None
    if 'product_glob' in node:
        return node['product_glob']
    for k in ('any_of', 'all_of'):
        for child in (node.get(k) or []):
            r = first_product_glob(child)
            if r:
                return r
    return None

def first_exec_observed_argv(node):
    if not isinstance(node, dict):
        return None
    if 'exec_observed' in node:
        return first_argv(node['exec_observed'])
    for k in ('any_of', 'all_of'):
        for child in (node.get(k) or []):
            r = first_exec_observed_argv(child)
            if r:
                return r
    return None

pre_match = (pre.get('match') if isinstance(pre, dict) else None) or {}
post_match = (post.get('match') if isinstance(post, dict) else None) or {}

result = {
  'pre_argv': first_argv(pre_match),
  'pre_file': first_file_exists(pre_match),
  'pre_env': first_env_set(pre_match),
  'post_exec_argv': first_exec_observed_argv(post_match),
  'post_product': first_product_glob(post_match),
}
for k, v in result.items():
    if v is None:
        continue
    if isinstance(v, list):
        print(f"{k}={'|'.join(v)}")
    else:
        print(f"{k}={v}")
PY
)

  # Emit the test file.
  {
    cat <<EOF
// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ${pkg}

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection/detectiontest"
)

func TestDetectorYAMLParses(t *testing.T) {
	detectiontest.AssertParses(t, Name, detectorYAML)
}
EOF

    while IFS='=' read -r key value; do
      case "$key" in
        pre_argv)
          # Use the first argv_prefix and split into a slice literal.
          IFS='|' read -ra argv_parts <<<"$value"
          quoted=""
          for p in "${argv_parts[@]}"; do
            quoted="$quoted\"$p\","
          done
          quoted="${quoted%,}"
          cat <<EOF

func TestDetectorPreGateFiresOnArgv(t *testing.T) {
	detectiontest.AssertPreGateFiresOnArgv(t, Name, detectorYAML, []string{$quoted})
}
EOF
          ;;
        pre_file)
          cat <<EOF

func TestDetectorPreGateFiresOnFile(t *testing.T) {
	detectiontest.AssertPreGateFiresOnFile(t, Name, detectorYAML, "$value")
}
EOF
          ;;
        pre_env)
          if [[ "$value" == *=* ]]; then
            envk="${value%%=*}"
            envv="${value#*=}"
          else
            envk="$value"
            envv="presence"
          fi
          cat <<EOF

func TestDetectorPreGateFiresInEnv(t *testing.T) {
	detectiontest.AssertPreGateFiresInEnv(t, Name, detectorYAML, "$envk", "$envv")
}
EOF
          ;;
        post_exec_argv)
          IFS='|' read -ra argv_parts <<<"$value"
          quoted=""
          for p in "${argv_parts[@]}"; do
            quoted="$quoted\"$p\","
          done
          quoted="${quoted%,}"
          cat <<EOF

func TestDetectorPostGateFiresOnExec(t *testing.T) {
	detectiontest.AssertPostGateFiresOnExec(t, Name, detectorYAML, []string{$quoted})
}
EOF
          ;;
        post_product)
          # Use the first glob to derive a concrete product path. A
          # gobwas/glob pattern with `**/` requires at least one slash
          # in the matched path, so we prepend "out/" for those. For
          # root-level globs (e.g. "*.tar"), use the bare filename.
          first_glob="${value%%|*}"
          if [[ "$first_glob" == \*\*/* ]]; then
            # Strip leading "**/" and emit under out/ to satisfy the
            # "at least one slash" requirement.
            tail="${first_glob#\*\*/}"
            # Replace all remaining `*` with literal "sample" so the
            # produced path matches the glob (e.g. govulncheck*.json
            # → govulnchecksample.json).
            path="out/$(echo "$tail" | sed 's|\*|sample|g')"
          else
            # Same substitution for root-level globs.
            path=$(echo "$first_glob" | sed 's|\*|sample|g')
          fi
          cat <<EOF

func TestDetectorPostGateFiresOnProduct(t *testing.T) {
	detectiontest.AssertPostGateFiresOnProduct(t, Name, detectorYAML, "$path")
}
EOF
          ;;
      esac
    done <<<"$py_probe"

  } > "$test_file"

  echo "generated: $test_file"
done
