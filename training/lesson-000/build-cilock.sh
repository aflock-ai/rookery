#!/usr/bin/env bash
# Build cilock from this rookery checkout into ./bin, so the lesson always
# runs against the code in the same tree.
#
# Needs Go (version in the repo's .go-version).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=.exe ;; esac

mkdir -p "$HERE/bin"
(cd "$ROOT/cilock" && CGO_ENABLED=0 go build -trimpath -o "$HERE/bin/cilock$EXE" ./cmd/cilock)
echo "built $HERE/bin/cilock$EXE from $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo 'this tree')"
