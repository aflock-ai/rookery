---
id: verify-a-release-offline
title: Verify SLSA provenance offline (air-gapped, no platform)
description: Verify a downloaded CI/lock binary FULLY OFFLINE — using only the DSSE attestation envelopes, Fulcio + Root CA, and RFC 3161 TSA chain published alongside the binary on cilock.dev. No TestifySec platform, tenant, or Archivista access required. For air-gapped and zero-trust verifiers.
sidebar_position: 6
---

# Verify a release offline (no platform needed)

Every CI/lock release publishes its **proof alongside the binary**. You can verify a
downloaded `cilock` against the signed release policy with **no TestifySec platform,
tenant, or Archivista access** — only the files on cilock.dev and the `cilock` binary
itself. This is the path for air-gapped builds, zero-trust auditors, and anyone who
doesn't have (or want) a platform login.

> Already have a platform session? The one-liner on the [Download page](/download)
> (`cilock verify … --platform-url <host> --enable-archivista`) pulls the evidence
> online and is simpler. This page is the **offline** path — it never talks to a
> platform.

## What the release publishes for offline verify

For each release version the publisher uploads, under `https://cilock.dev/dl/<version>/`:

| File | What it is |
|---|---|
| `cilock-<version>-<os>-<arch>.tar.gz` | the binary archive |
| `cilock-<version>-<os>-<arch>.source-git.att.json` | the **source-git** step's signed DSSE envelope |
| `cilock-<version>-<os>-<arch>.build.att.json` | the **build** step's signed DSSE envelope |
| `fulcio-roots.pem` | the platform **Fulcio CA + Root CA** the signing certs chain to |
| `tsa-chain.pem` | the **RFC 3161 TSA** cert chain |
| `policy/release-policy.json` (root key) | the **signed release policy** |

Both envelopes are needed — the policy declares a `source-git` step and a `build`
step, so an offline verify must supply the evidence for both.

The `fulcio-roots.pem`/`tsa-chain.pem` files are published for cross-checking
and for verifiers **without** embedded trust. When used as trust anchors they
must come from a channel you trust independently of cilock.dev: roots fetched
from the same origin as the binary cannot authenticate that origin's output —
a compromised origin would simply publish roots matching its forged evidence.
The recipe below instead anchors on the roots embedded in your trusted verifier.

The machine-readable index of all of this is the per-version `verification` block in
[`/dl/manifest.json`](https://cilock.dev/manifest.json):

```json
{
  "version": "v3.0.0",
  "verification": {
    "policy": "policy/release-policy.json",
    "fulcioRoots": "v3.0.0/fulcio-roots.pem",
    "tsaChain": "v3.0.0/tsa-chain.pem",
    "attestations": [
      {
        "binary": "cilock-3.0.0-linux-amd64.tar.gz",
        "os": "linux", "arch": "amd64",
        "envelopes": [
          {"step": "source-git", "file": "v3.0.0/cilock-3.0.0-linux-amd64.source-git.att.json", "sha256": "…"},
          {"step": "build",      "file": "v3.0.0/cilock-3.0.0-linux-amd64.build.att.json",      "sha256": "…"}
        ]
      }
    ]
  }
}
```

## Step 1 — download the binary + verification material

Pick your version and platform. For `v3.0.0` on `linux-amd64`:

```bash
VERSION=3.0.0
PLAT=linux-amd64
BASE="https://cilock.dev/dl/v${VERSION}"

curl -fsSLO "${BASE}/cilock-${VERSION}-${PLAT}.tar.gz"
curl -fsSLO "${BASE}/cilock-${VERSION}-${PLAT}.source-git.att.json"
curl -fsSLO "${BASE}/cilock-${VERSION}-${PLAT}.build.att.json"
curl -fsSL  "https://cilock.dev/policy/release-policy.json" -o release-policy.json

tar xzf "cilock-${VERSION}-${PLAT}.tar.gz" cilock
```

Do not run the binary you just extracted as its own verifier — a compromised
origin can ship one that simply reports success, so a self-run is at most a
functional smoke check, never provenance. Verify with a `cilock` you already
trust: a prior install, a build from [rookery](/ecosystem/rookery), or another
channel. A release-built cilock embeds the platform trust roots, so with a
trusted one the root flags drop away.

## Step 2 — run the offline verify

The key flag is `--platform-url ""`. It tells `cilock` to skip **all** platform
access — no discovery doc, no Archivista lookup, no platform-derived timestamp
verifier. The downloaded files supply only the **evidence**; the trust anchors
are the platform Fulcio + TSA roots **embedded in your trusted verifier** at
release-build time (inspect them with `cilock version`):

```bash
TRUSTED_CILOCK=/path/to/a/cilock/you/already/trust   # a prior install — never ./cilock itself
"$TRUSTED_CILOCK" verify ./cilock -p release-policy.json \
  --attestations cilock-${VERSION}-${PLAT}.source-git.att.json,cilock-${VERSION}-${PLAT}.build.att.json \
  --policy-emails colek42@gmail.com \
  --policy-fulcio-oidc-issuer https://platform.testifysec.com/fulcio/oidc \
  --platform-url ""
```

What each flag does:

| Flag | Role |
|---|---|
| `-p` / `--policy` | the signed release policy the binary must satisfy |
| `-a` / `--attestations` | the two per-step DSSE envelopes (comma-separated — one file per envelope) |
| `--policy-emails` | pins the keyless policy-signer identity so a policy signed by some other Fulcio cert can't be substituted |
| `--policy-fulcio-oidc-issuer` | the platform Fulcio OIDC issuer that minted the signer cert |
| `--platform-url ""` | **opt out of all platform access** — this is what makes it offline |

A passing run exits `0` and prints `Verification succeeded`. Branch on the **exit
code**, never on grepped output:

```bash
STEM="cilock-${VERSION}-${PLAT}"
if "$TRUSTED_CILOCK" verify ./cilock -p release-policy.json \
     --attestations "${STEM}.source-git.att.json,${STEM}.build.att.json" \
     --policy-emails colek42@gmail.com \
     --policy-fulcio-oidc-issuer https://platform.testifysec.com/fulcio/oidc \
     --platform-url ""; then
  echo "release verified offline"
else
  echo "VERIFY FAILED — do not run this binary" >&2
  exit 1
fi
```

> Prefer `--offline` if you like a named flag — it's an exact alias for
> `--platform-url ""`.

## What this proves

- The binary's SHA-256 matches a subject in the **build** step's signed product
  attestation — you have the exact bytes the release pipeline produced.
- Both steps' DSSE signatures chain to the **TestifySec Platform Fulcio**, anchored
  on the Platform Root CA embedded in your trusted verifier.
- The RFC 3161 timestamps place each signature **inside** its signing cert's validity
  window, so the proof holds years later even though Fulcio certs live ~10 minutes.
- The signed release policy itself was signed by the pinned release-authority identity
  (`--policy-emails`), not some other cert.

Nothing in this chain depends on a TestifySec platform being reachable, or on you
having an account. The proof is self-contained.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `no passed collections present` | the binary doesn't match the envelopes (subject-digest mismatch) — usually mixed files from different releases | re-download the tarball **and** both `.att.json` files from the **same** `<version>` |
| `must supply a public key, CA certificates, a verifier, or a cilock built with embedded policy trust` | your verifier has no embedded trust (stock/source build — check `cilock version`) | verify with a release-built cilock you already trust, or pass `--policy-ca-roots` from an independently trusted channel |
| `failed to build chain` / cert chain errors | a `--policy-ca-roots` bundle you supplied is wrong or truncated | the bundle must contain **both** the Fulcio CA and the Root CA — and come from a channel trusted independently of the download |
| timestamp / `policy expired`-style errors | your verifier lacks embedded TSA roots and no `--policy-timestamp-servers` was given | without TSA roots the expired signing certs can't be validated as-of signing time; use a release-built trusted verifier or supply an independently trusted chain |
| `functionary mismatch` | the policy expected a different signer identity | confirm `--policy-emails` / `--policy-fulcio-oidc-issuer` match the values published for this release (see the manifest / Download page) |

## See also

- [Download CI/lock](/download) — the binaries + a copy-paste offline command generated from the live manifest
- [Verify the `cilock` binary](./verify-the-cilock-binary) — the online + container verification paths
- [Verify in a release gate](../guides/verify-in-a-release-gate) — apply the same pattern to your own artifacts
