---
title: Connect to the platform
sidebar_position: 4
---

# Connect to the platform

[Your first attestation](./first-attestation) signed and verified evidence entirely on your laptop with a local key. That's the whole loop, offline. **Connecting to the TestifySec platform** adds three things a local key can't:

- **Keyless signing** — sign against the platform's Fulcio with your identity, no key file to manage or leak.
- **Storage + sharing** — attestations upload to the platform's Archivista, so policy verification, dashboards, and teammates can find them by the artifact's digest.
- **CI trust** — let a GitHub/GitLab pipeline upload keylessly, without a long-lived secret.

The one thing to understand: **signing needs no login, but _uploading_ does.** The platform derives Fulcio (signing), TSA (timestamping), and Archivista (storage) from a single `--platform-url` — but storing an attestation has to bind it to *your* tenant and product, and that binding is what a session carries.

> Throughout this page `$PLATFORM` is your platform URL — `https://platform.testifysec.com` for the hosted platform, or your own host for a self-hosted / `--standalone` instance. It's the default, so you can usually omit `--platform-url` entirely after logging in.

## 1. Log in

```bash
cilock login
```

This opens a browser approve page and stores a session credential. The approve page binds a **working tenant and product** — and if you don't have one yet, it creates a default tenant and product for you — so every attestation you upload is scoped to one. No flags needed for the hosted platform; for a self-hosted instance pass `--platform-url $PLATFORM`.

Confirm it worked:

```bash
cilock whoami
```

It prints the logged-in tenant, the bound product, and the session expiry.

## 2. (Optional) switch the working scope

If you belong to more than one tenant or want attestations under a different product, switch the binding — the cilock analog of `kubectl config use-context`:

```bash
# Pick or create a tenant/product interactively
cilock use

# Or bind a known product directly (no browser)
cilock use --product-id <uuid> --product-name acme-web
```

`cilock run` then scopes every attestation to that product without re-prompting.

## 3. Preflight before a real run

Before a multi-minute build, confirm signing **and** upload will actually work — instead of discovering a misconfiguration afterward:

```bash
cilock doctor
```

It prints a green/red checklist: logged in? platform reachable? Fulcio / TSA / Archivista resolved? upload authorized? Pass `--json` for a machine-readable report (`report.ok`) an agent can gate on.

## 4. Run with upload

Now the same `cilock run` you used locally, but keyless and uploaded:

```bash
cilock run \
  --step build \
  --platform-url "$PLATFORM" \
  --enable-archivista \
  -- go build -o myapp ./
```

cilock signs keyless against the platform Fulcio, timestamps against its TSA, and uploads the signed DSSE envelope to your tenant's Archivista. The run summary prints the `gitoid` — the address other tools (and `cilock verify --enable-archivista`) use to retrieve the evidence by subject digest, no local bundle files required.

If the upload is rejected with a `401` / `Invalid API credential`, your session expired or the run targeted a platform you're not logged in to — re-run `cilock login` (or `cilock doctor` to see exactly which check fails).

## 5. Verify against the platform's trust

Once logged in, verification needs no trust flags — cilock pulls the Fulcio roots and policy-signer identity from the platform's discovery document:

```bash
cilock verify ./myapp -p policy.json --platform-url "$PLATFORM" --enable-archivista
```

`--enable-archivista` lets verify *retrieve* the attestations by the artifact's subject digest. (Without a session, an offline verify still works — you just pass `--policy-ca-roots` and the attestation files yourself, as in [Your first attestation](./first-attestation).)

## 6. Let CI upload (trust a pipeline)

Your laptop session can't sign for a CI job — but you don't want a long-lived secret in CI either. Instead, register the pipeline's **OIDC identity** as a trusted uploader, once, as a tenant admin:

```bash
# Re-authenticate with the trust opt-in, then trust the repo's Actions
cilock login --allow-trust
cilock trust github your-org/your-repo
```

`cilock trust` creates an **OIDC federated credential** (never a stored secret): it tells the platform to trust attestations signed by that repo's GitHub Actions OIDC identity, for the same `${platform}/archivista` audience `cilock run` uploads to. After that, a workflow can upload keylessly with `enable-archivista: true` — which is exactly the step the [CI quickstart](./quickstart-ci) leaves off until you're connected.

Providers are `github` and `gitlab` (add `--host` for GHES / self-hosted GitLab, or `--issuer` + `--subject` for any other OIDC provider). See [`cilock trust`](../reference/cli#cilock-trust) for the full flag set.

## Where to next

- Wire it into a pipeline end-to-end with the [CI quickstart](./quickstart-ci) — now you can flip `enable-archivista: true`.
- For the per-command details, see the [CLI reference](../reference/cli) (`login`, `use`, `whoami`, `doctor`, `trust`, `run`, `verify`).
- To author the policies your uploaded evidence is verified against, see the [policy schema](../reference/policy-schema).
