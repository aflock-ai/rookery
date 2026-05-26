#!/usr/bin/env bash
# Generate docs/detector-catalog.md from every plugin's detector.yaml.
# Walks plugins/attestors/*/detector.yaml and emits a markdown table
# grouped by gate + trace recommendation. Re-run after adding new
# detectors so the catalog stays in sync.

set -euo pipefail
cd "$(dirname "$0")/.."

OUT=docs/detector-catalog.md

python3 - <<'PY' > "$OUT"
import pathlib, yaml, sys

root = pathlib.Path("plugins/attestors")
rows = []
for ypath in sorted(root.glob("*/detector.yaml")):
    d = yaml.safe_load(open(ypath))
    rows.append({
        "name": d["name"],
        "trace": d.get("recommended_trace") or "off",
        "pre": "pre" if d.get("pre") else "",
        "post": "post" if d.get("post") else "",
        "description": d.get("description", ""),
    })

print("# Detector catalog")
print()
print("Auto-generated from `plugins/attestors/*/detector.yaml`. Run")
print("`./scripts/gen-detector-catalog.sh` to refresh.")
print()
print(f"Total: {len(rows)} detectors.")
print()
print("| Name | Gates | Trace | Description |")
print("|------|-------|-------|-------------|")
for r in sorted(rows, key=lambda x: x["name"]):
    gates = " + ".join(g for g in [r["pre"], r["post"]] if g)
    print(f"| `{r['name']}` | {gates} | `{r['trace']}` | {r['description']} |")

print()
print("## Notes")
print()
print("- `pre` matches before the wrapped command runs (static argv/env/fs/probes).")
print("- `post` matches after the command, using the exec trace + products + materials diff.")
print("- `recommended_trace` tells the runtime how much eBPF tracing the attestor benefits from:")
print("    - `off` — the attestor signs an output file; no tracing strengthens the claim.")
print("    - `light` — only child argv is captured; correlates image refs etc.")
print("    - `full` — full materials / network / file capture; needed for build-process attestations.")
PY

echo "wrote $OUT ($(wc -l < "$OUT") lines)"
