# `.provenance/` — Inlined Upstream Code Metadata

Every file in this directory is a JSON record describing one piece of code,
types, schema, or test fixture that was copied from an upstream project into
rookery. CI verifies these records on every PR.

Tracking issue: [#72](https://github.com/aflock-ai/rookery/issues/72).

## When to add an entry

You must add a `.provenance/<slug>.json` entry whenever your PR introduces:

1. A file under `plugins/attestors/*/internal/` (or `attestation/validate/`)
   whose content (>= 10 lines) derives from an upstream library.
2. A `schemas/` entry — the schema content itself is the "inlined code."
3. A generator output committed under `types_gen.go` — the entry covers the
   schema(s) it was generated from, not the generator output.
4. Test fixtures (under `*/testdata/`) copied from an upstream's test suite.

You do NOT need an entry for:

- Files you authored from scratch, even if you read upstream code while
  writing them (e.g. the OCI reference parser in
  `plugins/attestors/k8smanifest/internal/ociref/` was *based on* the
  OCI Distribution Spec, not copied from go-containerregistry).
- Standard library re-exports.
- Generated boilerplate (`zz_generated.*.go`, `*.pb.go`) where the generator
  itself doesn't ship.

If in doubt, file an entry — it's easier to remove later than to add after
an audit.

## File format

`.provenance/<slug>.json`:

```json
{
  "upstream_repo": "https://github.com/openvex/go-vex",
  "upstream_commit": "a1b2c3d4e5f6...",
  "upstream_url": "https://raw.githubusercontent.com/openvex/go-vex/<sha>/pkg/vex/vex.go",
  "license_spdx": "Apache-2.0",
  "license_url": "https://github.com/openvex/go-vex/blob/<sha>/LICENSE",
  "local_path": "plugins/attestors/vex/internal/openvex/vex_types_gen.go",
  "sha256_of_inlined_content": "<sha256 of the rookery-side file>",
  "sha256_of_upstream_content": "<sha256 of the upstream-side file>",
  "kind": "schema-derived-types",
  "notes": "Generated from openvex schema; no functional logic inlined."
}
```

Fields:

- `upstream_repo` — the repo URL, without `.git`, no trailing slash.
- `upstream_commit` — **40-char SHA, never a tag**. Tags move; SHAs don't.
- `upstream_url` — direct URL to the specific file at the recorded commit
  (or the schema source URL for `kind: schema`).
- `license_spdx` — SPDX identifier. Must be on the allowlist in
  [`NOTICE.md`](../NOTICE.md). Any value outside the list fails CI.
- `license_url` — direct URL to the LICENSE file at the recorded commit.
- `local_path` — repo-relative path to the rookery-side file the entry
  covers. The CI check verifies this file exists.
- `sha256_of_inlined_content` — SHA256 of the local file's bytes. Must
  match the file on disk; if you edit the file, you must regenerate this.
- `sha256_of_upstream_content` — SHA256 of the upstream file's bytes at
  the recorded commit. CI re-fetches and verifies.
- `kind` — one of `inlined-source`, `schema-derived-types`, `schema`,
  `test-fixture`, `validator-port`. Drives reviewer scrutiny.
- `notes` — free text. State what specifically was taken and why this
  approach over a dependency.

## CI enforcement

`scripts/check-provenance.sh` (run by the `provenance-check` CI job):

1. Validates JSON shape of every `.provenance/*.json`.
2. Verifies `license_spdx` is on the NOTICE.md allowlist.
3. Verifies `local_path` exists and its current SHA256 matches
   `sha256_of_inlined_content`.
4. Fetches `upstream_url` and verifies it matches
   `sha256_of_upstream_content`. Confirms the upstream commit's LICENSE
   file's SPDX still equals `license_spdx`.
5. Greps repo for `// inlined from`, `// copied from`, `// ported from`
   comments and asserts each appears in an entry.

Failures are loud and block the PR. To raise the LICENSE allowlist, edit
`NOTICE.md` in the same PR.

## Example: generating an entry

```bash
LOCAL=plugins/attestors/vex/internal/openvex/vex_types_gen.go
UPSTREAM_REPO=https://github.com/openvex/go-vex
UPSTREAM_COMMIT=$(git -C /tmp/go-vex rev-parse HEAD)  # 40-char SHA
UPSTREAM_PATH=pkg/vex/vex.go
UPSTREAM_URL=https://raw.githubusercontent.com/openvex/go-vex/${UPSTREAM_COMMIT}/${UPSTREAM_PATH}

cat > .provenance/openvex-vex-types.json <<EOF
{
  "upstream_repo": "${UPSTREAM_REPO}",
  "upstream_commit": "${UPSTREAM_COMMIT}",
  "upstream_url": "${UPSTREAM_URL}",
  "license_spdx": "Apache-2.0",
  "license_url": "${UPSTREAM_REPO}/blob/${UPSTREAM_COMMIT}/LICENSE",
  "local_path": "${LOCAL}",
  "sha256_of_inlined_content": "$(sha256sum ${LOCAL} | cut -d' ' -f1)",
  "sha256_of_upstream_content": "$(curl -fsSL ${UPSTREAM_URL} | sha256sum | cut -d' ' -f1)",
  "kind": "schema-derived-types",
  "notes": "Generated from go-vex's vex package types; encoding/json compatible."
}
EOF
```
