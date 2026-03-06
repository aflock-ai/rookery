# Rookery

Modular attestation monorepo with plugins separated into individual Go modules.

## Layout

- `attestation/` — Core attestation library (minimal deps)
- `plugins/attestors/` — Each attestor is its own Go module
- `plugins/signers/` — Each signer is its own Go module
- `presets/` — Convenience modules that blank-import curated plugin sets
- `builder/` — Binary builder (generates custom binaries with selected plugins)
- `aflock/` — AI attestation CLI

## Development

```bash
# Uses go.work for local development
go work sync

# Build everything
make build

# Test individual module in isolation
cd plugins/attestors/git && GOWORK=off go test ./...
```

## Versioning

Path-prefixed tags (standard Go multi-module convention):
```
attestation/v0.1.0
plugins/attestors/git/v0.1.0
plugins/signers/file/v0.1.0
```
