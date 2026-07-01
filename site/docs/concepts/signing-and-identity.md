---
title: Keyless CI/CD provenance signing with Fulcio & OIDC
description: How CI/lock signs in-toto attestations — keyless with Sigstore Fulcio and CI OIDC (GitHub Actions, GitLab CI) or with a file key — and how policy functionaries decide which signer is trusted to sign for each step.
sidebar_position: 4
---

# Signing & identity

A **signer** is the cryptographic identity used to sign an attestation. In policy, the signer is what gets evaluated against a **functionary:** the policy's declaration of who is allowed to sign for a given step.

The verifier's question is always:

> Does the signer of this evidence match a trusted functionary for this step?

## Signers in the `cilock` binary

Nine signer providers exist as Go modules in rookery. The default prebuilt `cilock` binary ships two of them (`file`, `fulcio`); the other seven are opt-in via [`rookery-builder`](../guides/build-a-custom-cilock).

| Signer | Type | In default binary? | When to pick it |
|---|---|---|---|
| **`fulcio`** | Keyless (Sigstore) | ✅ default | CI runs in a hosted system with an OIDC token (GitHub Actions, GitLab CI). Default for most teams. |
| **`file`** | Local key file | ✅ default | Local development, CI without OIDC. Not recommended for production releases. |
| **`debug-signer`** | Debug | builder opt-in | Development and integration testing. |
| **`spiffe`** | Keyless (SPIFFE/SPIRE) | builder opt-in | Workloads in a SPIFFE-enabled mesh that already have SVID identities. |
| **`kms/aws`** | Cloud KMS | builder opt-in | Long-lived AWS-managed identity, HSM-backed keys. |
| **`kms/gcp`** | Cloud KMS | builder opt-in | Long-lived GCP-managed identity. |
| **`kms/azure`** | Cloud KMS (Azure Key Vault) | builder opt-in | Long-lived Azure-managed identity. |
| **`vault`** | HashiCorp Vault | builder opt-in | Vault-issued signing keys. |
| **`vault-transit`** | HashiCorp Vault Transit engine | builder opt-in | Centralized signing-as-a-service via Vault Transit. |

The slim default keeps the prebuilt binary's transitive dependency tree about 600 Go packages smaller. To enable a builder-opt-in signer, run `rookery-builder --preset cicd --with github.com/aflock-ai/rookery/plugins/signers/<name>` — see [Build a custom CI/lock](../guides/build-a-custom-cilock).

For the full decision tree, see [Choose a signer](../guides/choose-a-signer).

## Keyless signing: Fulcio and SPIFFE

**[Fulcio](https://github.com/sigstore/fulcio)** is the Sigstore certificate authority. It issues short-lived signing certificates tied to CI identity by exchanging a CI runtime's OIDC token (e.g. the `id-token` GitHub Actions provides) for a certificate valid for a few minutes, long enough to sign, short enough that there's nothing meaningful to steal. No long-lived private key to manage.

**[SPIFFE/SPIRE](https://spiffe.io/)** is the alternative for workloads inside a service mesh. Identity is encoded as a SPIFFE ID URI on the certificate (e.g. `spiffe://example.com/step1`). Witness/cilock policies can require functionaries by SPIFFE URI directly, see the [policy SPIFFE example](https://github.com/in-toto/witness/blob/main/docs/concepts/policy.md).

## KMS signers (URI scheme)

KMS signers use a URI-based reference scheme borrowed from Sigstore Cosign:

- **AWS:** `awskms:///arn:aws:kms:us-east-2:111122223333:key/1234abcd-...` (note the triple slash)
  Also supports key ID, alias name, alias ARN, and custom endpoints (e.g. localstack) via `awskms://[endpoint]/[ID/ALIAS/ARN]`.
- **GCP:** `gcpkms://projects/$PROJECT/locations/$LOCATION/keyRings/$KEYRING/cryptoKeys/$KEY/cryptoKeyVersions/$KEY_VERSION`. The `cryptoKeyVersions/$VERSION` suffix (and its `versions/$VERSION` shorthand) is optional and resolves to the key's primary version when omitted.
- **Azure Key Vault:** `azurekms://<vault-name>.vault.azure.net/<key>[/<key-version>]`. The host segment is specifically the vault's DNS name, not an arbitrary URI.

Authentication uses each cloud provider's standard credential resolution. A KMS reference URI can also be used as a `publickeyid` in a policy, so the verifier knows to fetch the public key from the KMS service. For air-gapped verification, a base64-encoded PEM public key can be embedded in the policy directly.

## What the verifier checks

When `cilock verify` runs against a policy, it checks identity by asking:

- Is the signature valid for the envelope?
- Does the signer's certificate or public key match a trusted functionary for this step?
- For X.509 functionaries: do the certificate constraints (commonname, dnsnames, emails, organizations, SPIFFE URIs, trusted roots) match?

For long-term integrity, verifying a years-old signature whose certificate has long since expired, see [Timestamping](./timestamping).
