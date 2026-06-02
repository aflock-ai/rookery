# Releasing cilock — unified versioning + propagation

All four cilock release surfaces ship under **one** version (e.g. `v2.0.0-rc1`),
with the **monorepo as the source of truth**. The version is **tag-driven** — no
source file stores it; a hardcoded version string is a bug to be eliminated.

## Source of truth

`v2.0.0-rc1` is defined once: the **git tag** pushed to the rookery release
surface (`aflock-ai/rookery`, source at `subtrees/rookery`). Everything derives
from it at build time:

| Surface | How it gets the version | Edit needed to cut vX.Y.Z |
| --- | --- | --- |
| **cilock binary** (rookery) | tag → `release.yml` `${GITHUB_REF_NAME#v}` → ldflags `-X .../cilock/cli.Version` | **tag only** |
| **cilock OCI image** | tag → `ghcr.io/aflock-ai/cilock:<ver>` | **tag only** |
| **cilock-action** | tag → goreleaser `-X main.version={{.Version}}` | **tag only** (+ the `@vN` alias floats on **stable only**) |
| **cilock-docs** (cilock.dev) | catalog generated from the cilock binary; downloads/manifest from the R2 publisher | **tag only** once hardcoded version strings are de-hardcoded (see Follow-ups) |

`version.go` stays `var Version = "dev"` (the ldflags sentinel). `.go-version`
(Go toolchain) and the policy-schema `v1` in `release-v1.policy.json` are **not**
the product version — never sweep them into a version bump. The
`aflock.ai/attestations/...` predicate URIs are **identifiers, not web hosts** —
never rewrite them.

## Cutting a release

1. Land the platform-trust + version-correct release pipeline (the ldflags
   target must be `cli.Version`, not `internal/cmd.Version`, or the binary
   reports `dev`).
2. **Tag rookery** `vX.Y.Z` → `release.yml` builds + platform-signs binaries,
   image, SBOM, attestations, VSAs, signed policy.
3. **Tag cilock-action** `vX.Y.Z` (cosmetic lockstep; it self-contains its own
   binary — it does **not** download the rookery cilock).
4. **Publish to cilock.dev**: `npm run publish:release -- --dir ./dist/vX.Y.Z
   --version vX.Y.Z` (verify-then-upload: `cilock verify` gates every artifact;
   nothing unverified reaches R2). Pre-releases do **not** move `manifest.latest`.

## Propagation test matrix — "everything updates on a release cut"

After cutting `vX.Y.Z`, assert each row. Any divergence = drift.

| Artifact | Expected after release | Verify |
| --- | --- | --- |
| cilock `--version` | prints `vX.Y.Z`, **not** `dev` | extract released linux-amd64, `./cilock version` |
| binary archives | `cilock-X.Y.Z-<os>-<arch>.tar.gz` exist; no stale version | `gh release view vX.Y.Z --repo aflock-ai/rookery --json assets` |
| OCI image | `ghcr.io/aflock-ai/cilock:X.Y.Z` pushed | `docker buildx imagetools inspect ghcr.io/aflock-ai/cilock:X.Y.Z` |
| melange/APK | APK + baked binary report `X.Y.Z` | `cilock version` inside the apko image |
| SBOM + VSAs | `cilock-X.Y.Z-sbom.spdx.json`, per-platform `*.vsa.json` present | release asset list |
| cilock-action binary | `main.version` == `vX.Y.Z` | download `cilock-action_linux_amd64.tar.gz`, check version |
| cilock-action `@vX.Y.Z` | shim downloads from `releases/download/vX.Y.Z/` | smoke workflow pinned to `@vX.Y.Z`, read the shim's "Downloading…" log |
| cilock-action `@vN` alias | for an **RC**, `@vN` still points at the prior **stable** (not the RC) | `git ls-remote --tags …/cilock-action vN` → assert SHA is prior stable |
| R2 versioned objects | `vX.Y.Z/` prefix has all tarballs/attestations/SBOMs/VSAs/checksums | list R2 / hit a `cilock.dev/dl/vX.Y.Z/...` path → 200 |
| R2 `manifest.latest` | advances only on **stable** (RC leaves it unchanged) | fetch `cilock.dev/dl/manifest.json` → assert `latest` |
| `cilock.dev/install.sh` | resolves the intended version (stable; RC pinned explicitly) | run the resolution path; assert the tag + that it fetches from `cilock.dev` |
| docs "verified against" | generated from the actual binary (not hardcoded) | `npm run gen:catalog` then `git diff` shows the version, catalog-drift gate passes |
| end-to-end coherence | binary `--version`, archive name, OCI tag, R2 dir, docs catalog all read `X.Y.Z` | collect all five, assert they normalize to the same version |

## Footguns (already mitigated / to watch)

- **`@vN` alias on pre-releases** — `cilock-action/release.yml` now gates the
  major-alias float to stable tags only (`!contains(ref, '-')`) and tracks the
  tag's own major, so an RC never re-points `@v1`/`@v2` consumers.
- **`manifest.latest` on RC** — the publisher does not promote a pre-release to
  `latest`; RC users pin explicitly.
- **`/releases/latest` excludes pre-releases** — install.sh resolves "latest"
  from `cilock.dev/dl/manifest.json` (stable), not the GitHub API; RC is pinned
  via `CILOCK_VERSION`.
- **Four-surface coordination** — there is no single fan-out command; tag
  rookery + cilock-action + run the docs publish. A partial cut leaves the
  ecosystem half-on-RC. Treat the steps above as atomic-by-discipline.

## Follow-ups (de-drift cilock-docs)

cilock-docs hardcodes the binary at `v1.1.0` (installation / verify / catalog /
compatibility docs) and the action at `v1.0.x` (quickstart-ci / github-action).
These must become a templated/generated version (Docusaurus var + a
catalog-drift CI gate) so docs track the tag instead of silently lying. Tracked
separately from this versioning baseline.
