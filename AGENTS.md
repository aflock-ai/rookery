# AGENTS.md

Instructions for AI coding agents (Claude Code, Cursor, Codex, Aider, etc.) working in this repo.

Humans: this is a quick map of where things live, what to run, and what trips agents up. The full prose is in `README.md` and `CONTRIBUTING.md`.

---

## What this repo is

Rookery is a Go monorepo that produces **`cilock`** — a witness-compatible CLI for emitting and verifying SLSA / in-toto attestations — plus the underlying library and 40+ attestor plugins. Read `README.md` first if you have no context.

The CLI binary entrypoint is `cilock/cmd/cilock/main.go`. Library entrypoint is `attestation/`. Plugins live in `plugins/attestors/<name>/` and `plugins/signers/<name>/`, each as its own Go module.

---

## Repo layout (memorise this)

```
attestation/         # Core library. AttestationContext, Attestor interface, DSSE.
cilock/              # The CLI. cmd/cilock/main.go blank-imports plugins.
plugins/attestors/   # 40+ attestors. Each has its own go.mod.
plugins/signers/     # file, fulcio, kms/{aws,azure,gcp}, spiffe, vault, vault-transit.
presets/             # all/, cicd/, minimal/ — curated blank-import sets.
builder/             # Generates custom cilock binaries with chosen plugins.
compat/              # Import shims so legacy witness.dev paths still resolve.
docs/                # attestor-catalog.md is the canonical name reference.
scripts/             # CI scripts (check-dep-budget.sh, check-provenance.sh, gen-attestor-catalog.sh).
.provenance/         # JSON entries for code inlined from upstream — never edit by hand without updating the SHA.
```

`go.work` defines the workspace. The list of members is also what `MODULES` expands to in the `Makefile`.

---

## Commands you'll actually need

```bash
make build           # build every module via go.work
make test            # run all tests (no race)
make test-race       # race detector
make lint            # golangci-lint v2
make vet
make vulncheck       # govulncheck
make verify-isolated # build each module with GOWORK=off (catches accidental workspace coupling)
make docs            # regenerate docs/attestor-catalog.md from source
make tidy            # go mod tidy across every module
make help            # list everything
```

**Single-module workflow** (avoid the `for dir in` loop when iterating):
```bash
cd plugins/attestors/git
go test ./...               # uses go.work
GOWORK=off go test ./...    # isolation check
```

---

## Conventions (don't fight these)

### Commits
- **Signed commits required** on `main`. CI rejects unsigned.
- **Conventional Commits format**: `type(scope): description`. Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. CI rejects non-conventional commits on PRs.
- **Never use `--no-verify`** — pre-commit hooks exist for a reason. If a hook fails, fix the cause.
- **Never use `git rebase -i` or `git add -i`** — agents can't drive interactive prompts.

### Code
- **`os.Exit`** is allowed only in `main.go`. CI's `forbidden-patterns` job scans diffs.
- **`panic`** is allowed only in tests and `init()`. Same scanner.
- **`//nolint`** without a specific linter (e.g., `//nolint:gosec`) is rejected.
- Tests use **testify** (`require` + `assert`). Don't introduce other test frameworks.
- Comments that explain WHAT the code does are noise — well-named identifiers do that. Only write a comment when the WHY is non-obvious (hidden constraint, workaround for a specific bug, behavior that would surprise a reader).
- Don't add references to "the current task" / "added for X" / "TODO: cleanup after Y" — those belong in PR descriptions.

### Go version
All modules pin the version in `.go-version`. CI's `go-version-check` job rejects mismatches. If you bump, bump every `go.mod` + `go.work` in the same PR.

### Dependencies
- New direct deps in `cilock` are budgeted in **`.dep-budget.yaml`**. CI's `dep-budget` job blocks PRs that exceed the ceiling. If you legitimately need to raise it, bump the ceiling **in the same PR** so the new deps surface in review.
- Anything inlined from another project needs a matching entry in **`.provenance/<name>.json`** with the upstream commit SHA (40 chars, never a tag), license SPDX, and SHA256 of both upstream and local. Licenses must be on the allowlist in `NOTICE.md` (Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC — **not** MPL/GPL/LGPL).

### Predicate types
Aflock uses `https://aflock.ai/attestations/<name>/v<n>`. Legacy `witness.dev/attestations/<name>/v<n>` types are registered as aliases at CLI startup — both consume each other's chains. If you add a new attestor, register both.

---

## Attestor naming gotcha

The **directory name is not always the canonical attestor name.** The canonical name is what registers via `attestation.RegisterAttestation(Name, ...)` in each attestor's `*.go` file. Examples that bite:

| Directory | Canonical name (use this) |
|---|---|
| `plugins/attestors/commandrun` | `command-run` |
| `plugins/attestors/aws-iid` | `aws` |
| `plugins/attestors/githubaction` | `github-action` |

**The canonical name is what you pass to `--attestations`** (and to `cilock-action`'s `attestations:` input). Always cross-check against `docs/attestor-catalog.md` — that file is generated from the source of truth.

---

## Adding a new plugin

1. Create the directory: `plugins/attestors/<name>/` (or `plugins/signers/<name>/`).
2. `cd` in, `go mod init github.com/aflock-ai/rookery/plugins/attestors/<name>`.
3. Implement `attestation.Attestor` (or `signer.SignerProvider`).
4. Register both the aflock predicate type and the legacy `witness.dev` alias in an `init()`:
   ```go
   func init() {
       attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor { return New() })
   }
   ```
5. Add the module path to `go.work`.
6. Blank-import the package wherever it should ship: `cilock/cmd/cilock/main.go`, the appropriate `presets/*/imports.go`, and `builder/cmd/builder/main.go` preset map if relevant.
7. Run `make docs` to regenerate the attestor catalog.
8. Add tests using testify. Tests live next to source as `*_test.go`.

---

## Verifying your work before pushing

```bash
make build && make test && make lint && make verify-isolated
```

If `verify-isolated` fails for a module you didn't touch, suspect cross-module coupling that only the workspace was papering over. Fix it in your PR — don't ignore it.

---

## What CI runs (and what'll bite you)

See `.github/workflows/ci.yml` for the source of truth. Highlights:

- `go-version-check` — every `go.mod` matches `.go-version`.
- `lint-go`, `test-go`, `test-go-race`, `vet`, `build` — standard quality gates.
- `verify-isolated` — every module builds with `GOWORK=off`.
- `commitlint` — Conventional Commits.
- `forbidden-patterns` — diff scanner for `os.Exit`/`panic`/bare-`//nolint`/hardcoded-credential patterns.
- `dep-budget` — fails if `cilock` transitive dep count or `go.sum` size exceeds `.dep-budget.yaml`.
- `provenance-check` — verifies every `.provenance/*.json` entry against the live upstream commit.
- `ci-success` — aggregate gate; merges block until everything else is green.

---

## Things that historically tripped agents up

1. **Editing `zz_generated.deepcopy.go` by hand** — these are auto-generated from `+kubebuilder:object:generate=true` markers. Hand-edits get overwritten. They're currently committed and maintained manually for now, but if you're changing struct fields, regenerate rather than patching.
2. **Treating `compat/` as live code** — it's a thin shim layer for the legacy witness.dev import paths. Real changes go in `attestation/` or `plugins/`.
3. **Adding a plugin only to `cilock/main.go`** — it won't be in any preset's builder output. Add to `presets/*/imports.go` and `builder/cmd/builder/main.go` too if it belongs there.
4. **Bumping a single `go.mod`'s Go version** — `go-version-check` will fail. Bump every module + `.go-version` together.
5. **Inlining code without provenance** — `provenance-check` will fail. Always create the `.provenance/<name>.json` entry with the upstream commit SHA and license in the same PR.
6. **Pinning a GitHub Action by tag** — workflows here pin by 40-char commit SHA (`actions/checkout@v4` is fine because `v4` is a stable ref, but third-party actions should be SHA-pinned). When in doubt, follow the pattern in `.github/workflows/ci.yml`.
7. **Assuming `go test ./...` from the repo root works** — it doesn't; `go.work` doesn't support recursive `./...`. Use `make test` or iterate per module.

---

## Resources for deeper context

- `README.md` — high-level repo orientation
- `CONTRIBUTING.md` — signed-commit + conventional-commit setup
- `docs/attestor-catalog.md` — canonical attestor names
- `witnessfixes.md` — record of breaking-bug fixes vs upstream witness
- `NOTICE.md` — third-party code attributions and license allowlist
- `cilock/README.md` — CLI usage and flag reference
- `builder/README.md` — custom-binary build instructions
- Upstream: [`in-toto/witness`](https://github.com/in-toto/witness), [`in-toto/attestation`](https://github.com/in-toto/attestation), [SLSA spec](https://slsa.dev/)

If something here is wrong or missing, fix it in the same PR as your other changes — agents read this file every session and stale instructions waste everyone's time.
