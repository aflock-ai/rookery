# Contributing to Rookery

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
/tmp/test-binary attestors
```

### Adding a New Plugin

1. Create a new directory under `plugins/attestors/<name>/` or `plugins/signers/<name>/`
2. Add a `go.mod` with `github.com/aflock-ai/rookery/plugins/attestors/<name>` module path
3. Implement the `attestation.Attestor` interface (or `signer.SignerProvider`)
4. Register via `init()` function calling `attestation.RegisterAttestation()`
5. Add the module to `go.work`
6. Add the import to `builder/cmd/builder/main.go` presets as appropriate
