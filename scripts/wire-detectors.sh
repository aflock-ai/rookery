#!/usr/bin/env bash
# Wire detection.Register() into a plugin's init() and embed its
# detector.yaml. Idempotent. Run from the worktree root.
#
# Usage: ./scripts/wire-detectors.sh <plugin-dir> <main-go-file>
# Example: ./scripts/wire-detectors.sh plugins/attestors/trivy plugins/attestors/trivy/trivy.go

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <plugin-dir> <main-go-file>" >&2
  exit 1
fi

PLUGIN_DIR=$1
FILE=$2

if [ ! -f "$FILE" ]; then
  echo "main file not found: $FILE" >&2
  exit 1
fi

if [ ! -f "$PLUGIN_DIR/detector.yaml" ]; then
  echo "detector.yaml missing in $PLUGIN_DIR" >&2
  exit 1
fi

# Idempotency: bail if already wired.
if grep -q 'detection.Register' "$FILE"; then
  echo "$FILE: already wired, skipping"
  exit 0
fi

# 1) Add `_ "embed"` import. Insert after the line containing `"crypto"` if
#    present, otherwise after the `import (` line.
python3 - "$FILE" <<'PY'
import sys, re, pathlib

path = pathlib.Path(sys.argv[1])
src = path.read_text()

# Insert _ "embed" import. Find an existing stdlib import line and add
# `_ "embed"` adjacent to it. Prefer right after `"crypto"`; fall back to
# inserting on the line right after `import (`.
def insert_embed(text):
    # Already imported? (could be in some files)
    if re.search(r'^\s*_ "embed"\s*$', text, re.M):
        return text
    # Insert after `"crypto"` line if present.
    m = re.search(r'^(\s*)"crypto"\s*$', text, re.M)
    if m:
        insert = f'{m.group(1)}_ "embed"\n'
        return text[:m.end()+1] + insert + text[m.end()+1:]
    # Otherwise insert as the very first import line.
    m = re.search(r'^import \(\s*$', text, re.M)
    if not m:
        return text
    indent = "\t"
    insert = f'{indent}_ "embed"\n'
    return text[:m.end()+1] + insert + text[m.end()+1:]

# Insert detection import.
def insert_detection(text):
    if 'attestation/detection"' in text:
        return text
    m = re.search(r'^(\s*)"github\.com/aflock-ai/rookery/attestation/cryptoutil"\s*$', text, re.M)
    if m:
        insert = f'{m.group(1)}"github.com/aflock-ai/rookery/attestation/detection"\n'
        return text[:m.end()+1] + insert + text[m.end()+1:]
    # Fallback: after the bare attestation import.
    m = re.search(r'^(\s*)"github\.com/aflock-ai/rookery/attestation"\s*$', text, re.M)
    if m:
        insert = f'{m.group(1)}"github.com/aflock-ai/rookery/attestation/detection"\n'
        return text[:m.end()+1] + insert + text[m.end()+1:]
    return text

# Insert the //go:embed block right after the closing `)` of the import block.
def insert_embed_var(text):
    if '//go:embed detector.yaml' in text:
        return text
    m = re.search(r'^import \(.*?^\)\s*\n', text, re.M | re.S)
    if not m:
        return text
    insert = '\n//go:embed detector.yaml\nvar detectorYAML []byte\n'
    return text[:m.end()] + insert + text[m.end():]

# Insert `detection.Register(Name, detectorYAML)` inside init().
# We look for the init() function and add the call before its closing brace.
def insert_register(text):
    # Find init() and capture the line where it ends.
    # Walk braces from the func init() line.
    fi = re.search(r'^func init\(\)\s*\{\s*$', text, re.M)
    if not fi:
        return text
    depth = 0
    i = fi.end()
    # The line `func init() {` already has one `{` consumed by depth=1.
    depth = 1
    while i < len(text) and depth > 0:
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                # Insert before this closing brace, on its own line.
                # Find the start of the line that contains text[i].
                line_start = text.rfind('\n', 0, i) + 1
                insert = '\tdetection.Register(Name, detectorYAML)\n'
                return text[:line_start] + insert + text[line_start:]
        i += 1
    return text

src = insert_embed(src)
src = insert_detection(src)
src = insert_embed_var(src)
src = insert_register(src)

path.write_text(src)
PY

# Run gofmt to clean up; goimports to sort the import groups.
gofmt -w "$FILE"
goimports -w "$FILE"

echo "$FILE: wired"
