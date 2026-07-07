# Signers

The default `cilock` binary ships a small set of signers chosen to cover the
common CI path (file-based dev signing + Fulcio keyless via OIDC) while
keeping the transitive dependency surface tight. Larger signer plugins —
cloud KMS, HashiCorp Vault, SPIFFE — are opt-in via `rookery-builder`.

## Selecting a signer

There is no `--signer <name>` flag. Each signer is selected by passing its
own `--signer-<type>-*` flags on a signing command — `cilock sign`,
`cilock run`, or `cilock attest`. (See `cilock sign --help-advanced`,
`cilock run --help-advanced`, `cilock attest --help-advanced`.)

| Signer | How to select it |
|---|---|
| File (local PEM key) | `--signer-file-key-path <path>` (short flag `-k`) |
| Fulcio (keyless) | `--signer-fulcio-*` flags, or run `cilock login` and let the platform issue a short-lived cert |
| KMS | `--signer-kms-ref <uri>` — the URI scheme picks the provider |

Examples (sign a Witness policy without contacting the hosted platform via
`--platform-url ""`):

```
# Local PEM key
cilock sign -k cosign.key -f policy.json -o policy.signed.json --platform-url ""

# AWS KMS
cilock sign -f policy.json -o policy.signed.json \
  --signer-kms-ref awskms:///alias/my-key --platform-url ""
```

KMS signers take a URI on `--signer-kms-ref`; the scheme prefix selects the
provider (`awskms://`, `azurekms://`, `gcpkms://`, `hashivault://`). Optional
KMS tuning flags: `--signer-kms-hashType` and `--signer-kms-keyVersion`.

## Default (shipped in `cilock`)

The `file`, `fulcio`, and `piv` signers are registered in the stock binary
(`cilock/cmd/cilock/main.go:67,68,74`). `piv` is pure Go (`CGO_ENABLED=0`) —
it drives the YubiKey over PC/SC via goscard/purego, so it ships in the default
static binary and only touches hardware when a `--signer-piv-*` flag is selected.

| Name | Import path | Use case |
|---|---|---|
| `file` | `plugins/signers/file` | Local PEM key / dev signing |
| `fulcio` | `plugins/signers/fulcio` | Keyless OIDC signing against Fulcio (sigstore) |
| `piv` | `plugins/signers/piv` | YubiKey PIV slot-9c hardware signing (`--signer-piv-*`) |

## Opt-in via `rookery-builder`

These are present in `presets/all` (`builder/cmd/builder/main.go:55-110`) but
excluded from the default binary because each one carries a heavy cloud / KMS
SDK transitive cost (the `debug` signer is also opt-in, registered only in
`presets/all`).

| Name / Scheme | Import path | Use case |
|---|---|---|
| `kms` + `awskms://...` | `plugins/signers/kms/aws` | AWS KMS keys |
| `kms` + `azurekms://...` | `plugins/signers/kms/azure` | Azure Key Vault |
| `kms` + `gcpkms://...` | `plugins/signers/kms/gcp` | GCP KMS |
| `kms` + `hashivault://...` | `plugins/signers/vault-transit` | HashiCorp Vault Transit |
| `vault` | `plugins/signers/vault` | HashiCorp Vault PKI |
| `spiffe` | `plugins/signers/spiffe` | SPIFFE/SPIRE workload identity |
| `debug` | `plugins/signers/debug-signer` | No-op signer for testing/debugging |

To build a custom binary with one (or more) of the above:

```
rookery-builder --preset cicd \
  --with github.com/aflock-ai/rookery/plugins/signers/kms/aws \
  --output ./cilock-aws
```

To get the full set (all attestors + all signers), use `--preset all`.
For per-plugin manifests (versions, git refs, local paths), see
`builder/examples/manifest-with-git.yaml`.

If you pass a KMS reference to a binary that doesn't have a provider for that
scheme compiled in, signing fails with
`no kms provider found for key reference: <ref>`. Rebuild via the command
above (or switch to a signer in the default set).
