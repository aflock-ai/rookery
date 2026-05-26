# Vendored omnitrail / omnibor (attestor-internal)

These packages are vendored copies of two single-maintainer libraries the
omnitrail attestor depends on, brought in-tree so the attestor's transitive
dependency on `github.com/edwarnicke/gitoid` is eliminated. They live under
`internal/` because they are specific to this attestor.

| package | upstream | version |
|---------|----------|---------|
| `internal/vendored/omnitrail` | `github.com/fkautz/omnitrail-go` | v0.0.0-20240613153526-999f2e7d0fc9 |
| `internal/vendored/omnibor`   | `github.com/omnibor/omnibor-go`  | v0.0.0-20230521145532-a77de61a16cd |

Upstream licenses are preserved alongside each package (`LICENSE`).

## Only change from upstream
The sole modification is the gitoid backend import:

- `github.com/edwarnicke/gitoid` → `github.com/aflock-ai/rookery/attestation/gitoid`
- `internal/vendored/omnitrail`'s import of `github.com/omnibor/omnibor-go` →
  `internal/vendored/omnibor`

`attestation/gitoid` is byte-identical to `edwarnicke/gitoid` for the API
these libraries use (`New`, `WithSha256`, `WithContentLength`, `Option`,
`GitOID.String()`), verified against ground-truth vectors in
`attestation/gitoid/gitoid_test.go` (incl. the canonical `git hash-object`
empty-blob value). All code bodies are otherwise verbatim, so the OmniBOR /
OmniTrail identifiers produced are unchanged.

## Tests
- `internal/vendored/omnibor/omnibor_test.go` is carried verbatim and passes — it
  covers the gitoid-backed OmniBOR identifier computation (the behavior that
  matters for attestation digests).
- `omnitrail-go`'s `omnitrail_test.go` is **not** carried: it compares full
  envelopes (including host POSIX ownership — `OwnerUID`/`OwnerGID`/mtime)
  against fixtures baked on the maintainer's machine, so it is not portable
  across checkouts/CI (it fails purely on owner-GID drift, never on the
  gitoid fields). The gitoid behavior we changed is covered by the gitoid
  equivalence vectors and the omnibor tests above.
