---
title: Choose a signer
sidebar_position: 1
---

# How to choose a signer

CI/lock supports nine signer providers. This guide is the decision tree, pick the path that matches your environment, then jump to the relevant config detail.

## TL;DR

| Environment | Pick this | Ships in default binary? |
|---|---|---|
| Hosted CI with OIDC (GitHub Actions, GitLab CI) | **`fulcio`** (Sigstore keyless) | ✅ default |
| Local dev / smoke tests / CI without OIDC | **`file`** | ✅ default |
| Internal CI/lock development | **`debug-signer`** | builder opt-in |
| Workloads inside a SPIFFE/SPIRE service mesh | **`spiffe`** | builder opt-in |
| AWS-native, want an HSM-backed identity | **`kms/aws`** | builder opt-in |
| GCP-native | **`kms/gcp`** | builder opt-in |
| Azure-native | **`kms/azure`** | builder opt-in |
| HashiCorp Vault user with the Transit engine | **`vault-transit`** | builder opt-in |
| HashiCorp Vault user, simple key-stored mode | **`vault`** | builder opt-in |

The **default `cilock` binary** ships only `file` and `fulcio` — the two signers that cover most teams' needs while keeping the binary small. The remaining seven (including `debug-signer`) are opt-in via [`rookery-builder`](./build-a-custom-cilock):

```bash
rookery-builder --preset cicd \
  --with github.com/aflock-ai/rookery/plugins/signers/kms/aws \
  --output ./cilock
```

Same source, same flag names, same wire format — just compiled in only when you ask for them. The slim default dropped the prebuilt binary's transitive dependency tree by roughly 600 Go packages.

If `cilock --help` doesn't show the `--signer-<name>-*` flags you need, you're on the default binary and need to build a variant that includes the signer.

## The decision tree

```
Is the workload running in CI with an OIDC token available?
├── Yes → Is it inside a SPIFFE/SPIRE mesh?
│        ├── Yes → spiffe
│        └── No  → fulcio  (default for GitHub Actions, GitLab CI)
└── No  → Is it inside a cloud you already have KMS in?
         ├── AWS  → kms/aws
         ├── GCP  → kms/gcp
         ├── Azure → kms/azure
         └── No → Are you using HashiCorp Vault?
                  ├── Yes, with Transit engine → vault-transit
                  ├── Yes, key-stored          → vault
                  └── No → file (and consider whether you should be in CI at all)
```

## Why prefer keyless?

Both `fulcio` and `spiffe` issue **short-lived certificates** tied to runtime identity. There's no long-lived private key to leak, no rotation schedule to forget, no credential to exfiltrate that's useful from an attacker's laptop.

The two recent supply-chain attacks CI/lock catches at scale (Trivy March 2026, LiteLLM March 2026) both worked by exfiltrating exactly the kind of long-lived credentials that file/KMS signing requires you to store. Keyless signing eliminates that attack surface entirely for the signing keys themselves.

If you can do keyless, do keyless.

## Fulcio specifics

The Sigstore CA. Most teams using GitHub Actions or GitLab CI should pick this.

```bash
cilock run --step build \
  --signer-fulcio-url "$FULCIO_URL" \
  --signer-fulcio-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signer-fulcio-oidc-client-id sigstore \
  --signer-fulcio-token "$OIDC_TOKEN" \
  ...
```

In GitHub Actions, the `cilock-action` defaults all of this for you when `enable-sigstore: true` (the action's default). You only need `permissions: { id-token: write }` on the workflow.

For self-hosted Fulcio, set `--signer-fulcio-url` to your instance. The client defaults to HTTP/REST (`--signer-fulcio-use-http=true`); set `--signer-fulcio-use-http=false` to switch to gRPC.

## SPIFFE/SPIRE specifics

For workloads that already have SVID identities from a SPIRE agent. The signer fetches an SVID from the agent's workload API socket and uses the cert as the signing identity.

```bash
cilock run --step build \
  --signer-spiffe-socket-path "unix:///run/spire/sockets/agent.sock" \
  ...
```

The socket path must have a `unix://` or `tcp://` scheme; the bare filesystem path is not accepted.

Pair with policy `certConstraint.uris` containing your SPIFFE ID:

```json
{
  "type": "root",
  "certConstraint": {
    "commonname": "*",
    "dnsnames": ["*"],
    "emails": ["*"],
    "organizations": ["*"],
    "uris": ["spiffe://example.com/build"],
    "roots": ["*"]
  }
}
```

## KMS specifics

KMS signers use a URI-based reference scheme borrowed from Sigstore Cosign. The same URI works as the `--signer-kms-ref` flag and as the `publickeyid` in a policy:

| Provider | URI form |
|---|---|
| AWS | `awskms:///arn:aws:kms:<region>:<account>:key/<key-id>` (note the triple slash; the alternative `awskms://[endpoint]/[ID/ALIAS/ARN]` lets you target a non-default endpoint such as LocalStack) |
| GCP | `gcpkms://projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<v>` (`/versions/<v>` shorthand also accepted; the whole version suffix is optional and resolves to the key's primary version) |
| Azure | `azurekms://<vault-name>.vault.azure.net/<key>[/<key-version>]` |

```bash
cilock run --step build \
  --signer-kms-ref "awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-..." \
  ...
```

Authentication uses each cloud provider's standard credential resolution, no extra `cilock` config needed. For full flag detail (custom endpoints, profile selection, etc.) see [signing & identity](../concepts/signing-and-identity#kms-signers-uri-scheme).

For air-gapped verification where the KMS service isn't reachable from the verifier, embed the base64-encoded PEM public key directly in the policy alongside the `publickeyid` URI.

## Vault specifics

Two distinct Vault signers, two different flag namespaces, two different Vault engines. Pick by engine:

**`vault-transit`** uses Vault's [Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit) for signing-as-a-service. The key stays in Vault; CI/lock asks Vault to sign the payload digest. Configure via the `kms-hashivault` provider:

```bash
cilock run --step build \
  --signer-kms-ref "hashivault://my-signing-key" \
  --signer-kms-hashivault-addr "https://vault.internal:8200" \
  --signer-kms-hashivault-token-file /run/secrets/vault-token \
  ...
```

This calls `PUT /v1/transit/sign/<key>/<hash>` under the hood (verified by tracing a failed run against a nonexistent host).

**`vault`** uses Vault's [PKI secrets engine](https://developer.hashicorp.com/vault/docs/secrets/pki). Each invocation asks Vault to issue a short-lived X.509 certificate for the role, similar in spirit to Fulcio:

```bash
cilock run --step build \
  --signer-vault-url "https://vault.internal:8200" \
  --signer-vault-token "$VAULT_TOKEN" \
  --signer-vault-role build-signer \
  ...
```

This calls `POST /v1/pki/issue/<role>` under the hood. Pick this when you want Vault-managed identity but cert-based rather than long-lived-key-based signing.

Most teams pick `vault-transit`. Pick `vault` when you already have a Vault PKI engine standing up build identities.

## File specifics

A local PEM-format key file. Useful for local dev and CI environments without OIDC support, but **not recommended for production releases:** there's a long-lived private key to manage, rotate, and protect.

```bash
cilock run --step build \
  --signer-file-key-path ./signing.key \
  --signer-file-cert-path ./signing.crt \
  ...
```

If you find yourself using `file` in production CI, the question to ask is: why don't I have OIDC available here? GitHub Actions, GitLab CI, AWS, GCP, and Azure all expose OIDC tokens.

## Mixing signers across pipelines

Different steps can use different signers, the verifier resolves each step's collection against that step's `functionaries` independently. A common pattern:

| Step | Signer | Why |
|---|---|---|
| `build` | `fulcio` (keyless) | Runs in CI, has OIDC |
| `policy-sign` | `kms/aws` (long-lived) | Policy is signed once at policy-publish time, away from CI |
| `release-promotion` | `kms/aws` (long-lived) | Promotion gate runs as a service account, not a CI workflow |

Only one signer is supported **per `cilock run` invocation** (verified from `cilock/internal/cmd/run.go`). To use multiple signers, run CI/lock multiple times.

## Parity with Witness

The CI/lock signer surface is a **superset** of the upstream Witness signer surface; everything Witness supports, CI/lock supports with the same flag namespaces. CI/lock adds three:

| Provider | Witness | CI/lock | Notes |
|---|---|---|---|
| `file` | ✓ | ✓ | CI/lock adds `--signer-file-key-passphrase` / `--signer-file-key-passphrase-path` for encrypted PEMs. |
| `fulcio` | ✓ | ✓ | CI/lock adds `--signer-fulcio-use-http` (HTTP/REST vs. gRPC; defaults to HTTP). |
| `spiffe` | ✓ | ✓ | Identical. |
| `vault` (PKI engine) | ✓ | ✓ | Identical. |
| `kms/aws` | ✓ | ✓ | Identical. |
| `kms/gcp` | ✓ | ✓ | Identical. |
| `kms/azure` | (none) | ✓ | Cilock-only. |
| `vault-transit` (`kms/hashivault`) | (none) | ✓ | Cilock-only; uses Vault's Transit engine instead of PKI. |
| `debug-signer` | (none) | ✓ | Cilock-only; ephemeral keypair for development. |

For the five shared providers, the Witness docs are an authoritative reference; CI/lock's wire format and flag names are identical.

## See also

- [Signing & identity concept](../concepts/signing-and-identity), full mental model
- [Choose a signer for the GitHub Actions tutorial](../tutorials/github-actions-pipeline)
- [Witness KMS signer docs](https://github.com/in-toto/witness/blob/main/docs/signers/kms.md), schema-compatible upstream reference for the shared `file`, `fulcio`, `spiffe`, `vault`, `kms/{aws,gcp}` providers
