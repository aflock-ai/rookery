# Contributing to Rookery

## Contributing as a tester

**Tests are the most valuable first contribution you can make.** A good test that
hardens existing behavior — covering an edge case, pinning down a regression,
fuzzing a parser — is welcomed before any feature work and is the fastest path to
a merged PR.

There is one hard rule that governs the contribution surface:

- **A test (or any change) that adds NO new dependencies passes automated
  validation and merges on its own merits.** It must run through CI green with
  zero added dependencies — no new Go modules, no new external tools, no new
  services.
- **Any contribution that REQUIRES a new dependency** — a Go module, an external
  tool/binary, or a runtime service — **must first be discussed with the
  maintainer team and agreed on BEFORE the dependency is added.** Open a
  [GitHub Discussion](https://github.com/aflock-ai/rookery/discussions) or comment
  on the dependency-budget tracking issue
  ([#70](https://github.com/aflock-ai/rookery/issues/70)) and get explicit
  agreement first. Dependency additions are **never merged unilaterally** — they
  are gated on maintainer approval.

This is not bureaucracy. cilock is a supply-chain integrity tool: **its own
dependency surface is part of its threat model.** Every module linked into the
binary is code your users trust transitively. CI enforces this directly — the
`dep budget` job (`.github/workflows/ci.yml`, job `dep-budget`) runs
`./scripts/check-dep-budget.sh`, which fails any PR that grows the cilock
binary's transitive module count or `go.sum` byte size beyond the ceilings
committed in `.dep-budget.yaml`. Raising a ceiling requires editing
`.dep-budget.yaml` in the same PR, which surfaces the cost in review. Budgets are
intentionally tight (current state plus small headroom) so that every new
dependency is a conscious, reviewed decision.

## Requirements

### Signed Commits

All commits to `main` must be signed. Configure Git signing before contributing:

**GPG signing:**
```bash
git config --global commit.gpgsign true
git config --global user.signingkey <YOUR_KEY_ID>
```

**SSH signing (Git 2.34+):**
```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Add your signing key to your GitHub account under Settings > SSH and GPG keys.

### Conventional Commits

All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
type(scope): description

[optional body]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

Examples:
```
feat(attestor): add new OCI attestor plugin
fix(policy): correct error message formatting in constraints
docs: update plugin development guide
chore: bump Go version to 1.26.0
```

### Go Version

All modules use the same Go version specified in `.go-version`. Do not change individual `go.mod` versions without updating all modules.

## Development

### Setup

```bash
git clone https://github.com/aflock-ai/rookery.git
cd rookery
go build ./...
go test ./...
```

### Running Lints

```bash
make lint          # golangci-lint
make vet           # go vet
make vulncheck     # vulnerability scan
make deadcode      # unreachable function detection
```

### Running Tests

```bash
make test          # all tests
make test-race     # with race detector
make test-coverage # with coverage report
```

### Building the Builder

```bash
cd builder
go run ./cmd/builder/ --preset minimal --local --output /tmp/test-binary
/tmp/test-binary attestors list
```

Available presets (`builder/cmd/builder/main.go`): `minimal` (commandrun,
environment, git, material, product + file signer), `cicd` (minimal + github,
gitlab, slsa), `all` (every signer + most attestors; a few cilock-only
plugins such as `github-review` and `apple-device` are not in the preset). See
`go run ./cmd/builder/ --help` for manifest and `--with` forms.

### Adding a New Plugin

1. Create a new directory under `plugins/attestors/<name>/` or `plugins/signers/<name>/`
2. Add a `go.mod` with `github.com/aflock-ai/rookery/plugins/attestors/<name>` module path
3. Implement the `attestation.Attestor` interface (`attestation/factory.go`) or
   the `signer.SignerProvider` interface (`attestation/signer/registry.go`)
4. Register in an `init()` function. Attestors call
   `attestation.RegisterAttestation(name, predicateType, runType, factory)`
   (`attestation/factory.go`); signers call
   `signer.Register(name, factory, opts...)` (`attestation/signer/registry.go`).
   If the attestor ships a `detector.yaml`, also call
   `detection.Register(Name, detectorYAML)` in the same `init()` (see
   `plugins/attestors/git/git.go`).
5. Add the module to `go.work` (a relative `./...` entry under `use (`)
6. Add the import path to the appropriate preset(s) in
   `builder/cmd/builder/main.go` (`var presets`)

> **Adding a plugin that pulls in a new external dependency?** That falls under
> the dependency rule above — open a discussion and get maintainer agreement
> before adding it. A self-contained plugin that links no new modules can be
> reviewed on its own merits.

### Generated documentation

Some docs under `docs/` are **generated from source — do not edit the `.md`
directly**:

- `docs/attestor-catalog.md` is generated from each attestor's registered
  `Name`/`RunType`/`PredicateType`. Regenerate with `make docs` (which runs
  `./scripts/gen-attestor-catalog.sh`).
- `docs/detector-catalog.md` is generated from `plugins/attestors/*/detector.yaml`.
  Regenerate with `./scripts/gen-detector-catalog.sh`.

When you add or rename an attestor (or change its `detector.yaml`), edit the Go
source / YAML and re-run the generator — then commit the regenerated `.md`.
