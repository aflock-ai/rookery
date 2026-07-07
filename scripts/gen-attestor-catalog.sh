#!/usr/bin/env bash
# gate — CI fail-open lint target (jade lint-gate-scripts). Keep threshold
# comparisons floored and never mask failures.
# Regenerates docs/attestor-catalog.md by walking plugins/attestors/*/ and
# extracting each attestor's registered Name, RunType, and PredicateType.
#
# Run after adding a new attestor or changing a Name constant:
#   ./scripts/gen-attestor-catalog.sh
#
# Source of truth is each attestor's Go source — specifically the constants
# bound to `attestation.RegisterAttestation(name, predicateType, runType, ...)`.
# The Name (column 1) is what downstream callers pass to `--attestations`
# and `cilock-action`'s `attestations:` input — NOT the directory name.

set -e

cd "$(dirname "$0")/.."

OUT="docs/attestor-catalog.md"

phase_label() {
  case "$1" in
    PreMaterialRunType)  echo "Pre-material (environment capture)" ;;
    MaterialRunType)     echo "Material (input snapshot)" ;;
    ExecuteRunType)      echo "Execute (the wrapped step)" ;;
    ProductRunType)      echo "Product (output snapshot)" ;;
    PostProductRunType)  echo "Post-product (analysis of outputs)" ;;
    VerifyRunType)       echo "Verify (policy-time)" ;;
    *) echo "Other" ;;
  esac
}

# Collect rows as "phase|name|dir|predicate_type" into a tmp file
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

for d in plugins/attestors/*/; do
  attestor=$(basename "$d")
  name=$(grep -h -E '^\s*Name\s*=\s*"|^\s*ProductName\s*=\s*"|^const Name = "' "$d"*.go 2>/dev/null | { grep -v _test.go || true; } | head -1 | sed 's/.*"\(.*\)".*/\1/')
  if [ -z "$name" ]; then
    name=$(grep -h -E 'RegisterAttestation\s*\(' "$d"*.go 2>/dev/null | { grep -v _test.go || true; } | head -1 | sed 's/.*RegisterAttestation[A-Za-z]*(\s*\([^,]*\),.*/\1/' | tr -d ' \t"')
  fi
  runtype=$(grep -h -E '^\s*[A-Za-z]*RunType\s*=\s*attestation\.|^const RunType = attestation\.' "$d"*.go 2>/dev/null | { grep -v _test.go || true; } | head -1 | sed 's/.*attestation\.//;s/[[:space:]].*$//' | tr -d ' ')
  predtype=$(grep -h -E 'PredicateType\s*=\s*"|^\s*Type\s*=\s*"|^\s*ProductType\s*=\s*"' "$d"*.go 2>/dev/null | { grep -v _test.go || true; } | head -1 | sed 's/.*"\(.*\)".*/\1/')

  if [ -z "$name" ]; then
    echo "WARN: could not extract Name from $d" >&2
    continue
  fi

  echo "$runtype|$name|$attestor|$predtype" >> "$TMP"
done

ROW_COUNT=$(wc -l < "$TMP" | tr -d ' ')

{
  cat <<'EOF'
# Attestor catalog

This is the canonical name reference. **The name in column 1 is what you pass to `--attestations` (or `cilock-action`'s `attestations:` input).** It is NOT always the directory name — `commandrun` lives at `plugins/attestors/commandrun/` but registers itself as `command-run`, and similar splits exist for `github-action`, `aws-iid → aws`. Passing the import-path form ("commandrun") fails fast with `attestor not found`.

The table is grouped by run phase (the order in which the phase fires). Within a phase, attestors fire in registration order — for most flows that ordering is not load-bearing.

Regenerate after adding or renaming an attestor:

```
./scripts/gen-attestor-catalog.sh
```

EOF

  for phase in PreMaterialRunType MaterialRunType ExecuteRunType ProductRunType PostProductRunType VerifyRunType; do
    # Filter to rows for this phase, sorted by name. LC_ALL=C pins byte-order
    # collation so the output is identical on macOS (BSD sort) and Linux CI
    # (GNU sort) — otherwise locale-dependent ordering of '-'/'|'/'/' makes the
    # committed catalog drift vs a CI regen and trips docs-generated-check.
    rows=$(awk -F'|' -v p="$phase" '$1==p {print $0}' "$TMP" | LC_ALL=C sort -t'|' -k2)
    if [ -z "$rows" ]; then
      continue
    fi
    echo
    echo "## $(phase_label "$phase")"
    echo
    echo "| Name | Import path | Predicate type |"
    echo "|---|---|---|"
    while IFS='|' read -r r_phase r_name r_dir r_pred; do
      if [ -z "$r_pred" ]; then
        pred_md="—"
      else
        pred_md="\`$r_pred\`"
      fi
      echo "| \`$r_name\` | \`plugins/attestors/$r_dir\` | $pred_md |"
    done <<<"$rows"
  done

  cat <<'EOF'

## Notes

- **`command-run` vs `commandrun`**: the package is `commandrun`, the registered Name is `command-run`. Use the hyphenated name.
- **`github-action` vs `githubaction`**: same split.
- **`aws` vs `aws-iid`**: the package is `aws-iid` (AWS Instance Identity Document); the registered Name is `aws` because that's the source attestor for AWS-runner identity. Predicate-type lookup also resolves the `aws-iid`-shaped legacy URI to the same factory.
- **`product` vs `ProductName`**: the registry name is `product`; the constant in the package is `ProductName` (legacy naming). Pass `product`.
- **VSA attestors (`vsa`, `policyverify`)** run during `cilock verify`, not during `cilock run`. They are not added to a run by name from `--attestations`; cilock wires them automatically based on the verify mode.

## Default sets

The default `--attestations` set (`cilock/internal/options/run.go` `DefaultAttestors`) is only:

| Surface | Default `--attestations` |
|---|---|
| `cilock run` (no `--attestations`) | environment, git, platform |
| `cilock-action` (no `attestations:` input) | environment, git |

On top of that:

- **`product`, `material`, and `command-run` are always-on** — they run on every `cilock run` regardless of `--attestations` and cannot be selected by name (`command-run` warns if you try). Drop `product`/`material` with `--no-default-attestor`.
- **Context attestors auto-fire via detection** — a plugin carrying detector rules (e.g. `aws-config`, `asff`, `github-action`) fires when the workspace detection sees its matching signal, independent of `--attestations`.

When passing `--attestations`, you replace the default set (environment, git, platform) — you don't add to it. To extend rather than replace, list those defaults explicitly. The always-on and context attestors above fire either way.
EOF
} > "$OUT"

echo "Wrote $OUT ($ROW_COUNT attestors)"
