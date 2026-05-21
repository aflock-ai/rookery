# Signers

The default `cilock` binary ships a small set of signers chosen to cover the
common CI path (file-based dev signing + Fulcio keyless via OIDC) while
keeping the transitive dependency surface tight. Larger signer plugins —
cloud KMS, HashiCorp Vault, SPIFFE — are opt-in via `rookery-builder`.

Select a signer with `--signer <name>`. KMS variants attach to the `kms`
signer via a URL-scheme prefix on the key reference (e.g.
`--signer kms --signer-kms-ref awskms://...`).

## Default (shipped in `cilock`)

| Name | Import path | Use case |
|---|---|---|
| `file` | `plugins/signers/file` | Local PEM key / dev signing |
| `fulcio` | `plugins/signers/fulcio` | Keyless OIDC signing against Fulcio (sigstore) |
| `debug` | `plugins/signers/debug-signer` | No-op signer for testing/debugging |

## Opt-in via `rookery-builder`

These are present in `presets/all` but excluded from the default binary
because each one carries a heavy cloud / KMS SDK transitive cost.

| Name / Scheme | Import path | Use case |
|---|---|---|
| `kms` + `awskms://...` | `plugins/signers/kms/aws` | AWS KMS keys |
| `kms` + `azurekms://...` | `plugins/signers/kms/azure` | Azure Key Vault |
| `kms` + `gcpkms://...` | `plugins/signers/kms/gcp` | GCP KMS |
| `vault` | `plugins/signers/vault` | HashiCorp Vault PKI |
| `kms` + `hashivault://...` | `plugins/signers/vault-transit` | HashiCorp Vault Transit |
| `spiffe` | `plugins/signers/spiffe` | SPIFFE/SPIRE workload identity |

To build a custom binary with one (or more) of the above:

```
rookery-builder --preset cicd \
  --with github.com/aflock-ai/rookery/plugins/signers/kms/aws \
  --output ./cilock-aws
```

To get the full set (all attestors + all signers), use `--preset all`.
For per-plugin manifests (versions, git refs, local paths), see
`builder/examples/manifest-with-git.yaml`.

If you pass a signer flag to the default binary for a signer/scheme that
isn't registered, you'll see `signer not found` (or, for KMS, no provider
matching the reference scheme). Rebuild via the command above or switch
to a signer in the default set.
