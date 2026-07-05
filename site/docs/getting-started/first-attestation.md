---
title: Your first attestation
sidebar_position: 3
---

# Your first attestation

## Intro

This quick tutorial will walk you through a simple example of how CI/lock can be used to record a signed attestation around a build, then verify it against a signed policy. To complete it successfully, you will need the following:

- [Go](https://go.dev/doc/install) (1.22 or later is recommended)
- [openssl](https://www.openssl.org/)
- [jq](https://jqlang.github.io/jq/)
- [base64](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html) (part of GNU coreutils on Linux, builtin on macOS)

You will also need to have CI/lock installed, which can be achieved by following the [Installation](./installation) guide. Confirm with `cilock version` before continuing.

A 30-second sample project to follow along:

```bash
mkdir demo-cilock && cd demo-cilock
git init -q          # enables the git attestor (it silently skips outside a repo)
cat > main.go <<'EOF'
package main

import "fmt"

func main() { fmt.Println("Hello, cilock!") }
EOF
go mod init github.com/aflock-ai/demo-cilock
```

## 1. Create a keypair

For a local walkthrough we sign with a file-based ed25519 key. (In CI you almost always switch to keyless Sigstore signing, covered in the [CI quickstart](./quickstart-ci).)

```bash
openssl genpkey -algorithm ed25519 -outform PEM -out testkey.pem
openssl pkey -in testkey.pem -pubout > testpub.pem
```

You now have `testkey.pem` (private, used to sign) and `testpub.pem` (public, used to verify).

:::caution
`testkey.pem` is a real signing key. Add `*.pem` and `*.key` to your `.gitignore` so it never ends up in source control.
:::

## 2. Record attestations for a build step

`cilock run` wraps a command and produces a signed DSSE envelope containing one or more attestations.

```bash
cilock run \
  --step build \
  --signer-file-key-path testkey.pem \
  --outfile build.attestation.json \
  --platform-url "" \
  -- go build -o myapp ./
```

| Flag | Short | What it does |
|---|---|---|
| `--step` | `-s` | Names the step in the supply-chain lifecycle. Required, the policy verifier matches collections by step name. |
| `--signer-file-key-path` | `-k` | Path to a local PEM private key. For keyless Sigstore signing in CI, use `--signer-fulcio-url`, `--signer-fulcio-oidc-issuer`, etc. (see [signing and identity](../concepts/signing-and-identity)). |
| `--outfile` | `-o` | Where to write the signed envelope. Omit to write to stdout. |
| `--platform-url ""` | | Opts out of the hosted platform for this local tutorial. This keeps the command fully offline even if you previously ran `cilock login`. |
| `--workingdir` | `-d` | Directory the wrapped command runs in. Defaults to the current directory. |
| `--attestations` | `-a` | Attestors to record. Pass once per attestor (`-a environment -a git`) or comma-separated (`-a environment,git`). Defaults to `[environment, git, platform]`. See note below. |
| `-- <cmd>` | | Everything after `--` is the command CI/lock wraps. |

### What gets recorded

Three attestors are **always** recorded regardless of flags:

- **`material`:** SHA-256 digests of every file in the working directory before the step ran.
- **`command-run`:** the wrapped command's argv, exit code, stdout/stderr digests, and process information.
- **`product`:** SHA-256 digests of every file that changed or was added after the step ran.

Three more are recorded **by default** when `-a` is omitted:

- **`environment`:** os, hostname, username, env vars (sensitive ones filtered).
- **`git`:** commit SHA, tree hash, branch, and a snapshot of `git status`.
- **`platform`:** binds the attestation to your hosted-platform tenant/product. Recorded only when a platform session exists (after `cilock login`); it silently skips when there is none — which is why it does not appear in the output below, since this tutorial passes `--platform-url ""`.

Run `cilock attestors list` to see the full set with `(always run)` and `(default)` markers.

:::caution `-a` replaces the default, it does not extend it
Passing any `-a` overrides the `[environment, git, platform]` default. If you want those plus an extra: `-a environment -a git -a platform -a secretscan`. A single `-a secretscan` drops `environment`, `git`, and `platform` from the output. The always-run `material` / `command-run` / `product` are unaffected.

A space-separated string inside quotes (`-a "environment git"`) does not work, CI/lock treats the whole value as one attestor name.
:::

## 3. View the attestation

The output is a [DSSE](../concepts/dsse-and-in-toto) envelope wrapping an in-toto Collection. Quick top-level inspection:

```bash
jq '.payloadType, .signatures[0].keyid' build.attestation.json
# "application/vnd.in-toto+json"
# "<64-char hex keyid>"
```

The `keyid` is the SHA-256 of `testpub.pem`, and policy verification later matches against it.

To see the full structured payload:

```bash
cat build.attestation.json | jq -r .payload | base64 -d | jq
```

To narrow to the step name and attestation types:

```bash
cat build.attestation.json | jq -r .payload | base64 -d | jq '.predicate.name, (.predicate.attestations | map(.type))'
# "build"
# [
#   "https://aflock.ai/attestations/environment/v0.1",
#   "https://aflock.ai/attestations/git/v0.1",
#   "https://aflock.ai/attestations/material/v0.3",
#   "https://aflock.ai/attestations/command-run/v0.1",
#   "https://aflock.ai/attestations/product/v0.3"
# ]
```

To see the JSON schema of any specific attestor:

```bash
cilock attestors schema git
```

## 4. Create a policy file

The policy lists which attestations each step must produce and which keys are trusted to sign them. We start with a minimal policy requiring only the always-run trio:

```json title="policy.json"
{
  "expires": "2030-12-17T23:57:40-05:00",
  "steps": {
    "build": {
      "name": "build",
      "attestations": [
        {"type": "https://aflock.ai/attestations/material/v0.3", "regopolicies": []},
        {"type": "https://aflock.ai/attestations/command-run/v0.1", "regopolicies": []},
        {"type": "https://aflock.ai/attestations/product/v0.3", "regopolicies": []}
      ],
      "functionaries": [{"type": "publickey", "publickeyid": "{{PUBLIC_KEY_ID}}"}]
    }
  },
  "publickeys": {
    "{{PUBLIC_KEY_ID}}": {
      "keyid": "{{PUBLIC_KEY_ID}}",
      "key": "{{B64_PUBLIC_KEY}}"
    }
  }
}
```

For the full policy schema (multi-step pipelines, Rego rules per attestor, certificate functionaries, timestamp roots) see the [policy schema reference](../reference/policy-schema). CI/lock attestation type URIs use the `https://aflock.ai/attestations/<name>/v0.1` form, the same shape witness uses but on the `aflock.ai` namespace. Both ecosystems can verify the other's collections through the [witness compat shim](../ecosystem/witness#migration-notes).

## 5. Fill in the key ID and public key

The policy needs the SHA-256 hash of the public key (the keyid) and the base64-encoded PEM. Linux uses `sha256sum`, macOS uses `shasum -a 256`. The substitution pattern below is portable across both.

```bash
# Compute the keyid and base64-encoded public key
KEYID=$(shasum -a 256 testpub.pem 2>/dev/null | awk '{print $1}') \
  || KEYID=$(sha256sum testpub.pem | awk '{print $1}')
PUBB64=$(base64 < testpub.pem | tr -d '\n')

# Substitute both placeholders. Writing to a temp file avoids the
# GNU vs BSD sed -i incompatibility.
sed -e "s/{{PUBLIC_KEY_ID}}/${KEYID}/g" \
    -e "s|{{B64_PUBLIC_KEY}}|${PUBB64}|g" \
    policy.json > policy.json.tmp && mv policy.json.tmp policy.json
```

## 6. Sign the policy

The policy itself is a signed DSSE envelope. Whoever signs the policy controls every gate built on top of it, so keep this key safe.

```bash
cilock sign \
  -f policy.json \
  -o policy-signed.json \
  --signer-file-key-path testkey.pem \
  --platform-url ""
```

In a real setup, the policy signing key would be a separate, more strictly controlled key than the per-step attestation key. We reuse `testkey.pem` here for brevity.

:::tip Logged in already?
`cilock login` enables the hosted platform's keyless Fulcio signer for commands that do not choose another signer. In this tutorial the local file key is intentional, so keep `--platform-url ""` on the local signing commands. You can also run `cilock logout` before following the offline walkthrough.
:::

## 7. Verify the build meets the policy

`cilock verify` checks that every attestation listed in the policy was produced, signed by a trusted functionary, and satisfies any embedded Rego rules.

```bash
cilock verify \
  -p policy-signed.json \
  -a build.attestation.json \
  -f myapp \
  -k testpub.pem \
  --platform-url ""
```

| Flag | Short | What it does |
|---|---|---|
| `--policy` | `-p` | Path to the signed policy. |
| `--attestations` | `-a` | Attestation envelopes to evaluate against the policy. Repeat for multiple. |
| `--artifactfile` | `-f` | The artifact whose subject digest is being verified, CI/lock checks this digest appears in the attestation. |
| `--publickey` | `-k` | Public key that signed the policy (not the attestation). |

On success:

```
[verified-source] envelope build.attestation verifier kid=... error=<nil>
level=info msg="Verification succeeded"
level=info msg="Evidence:"
level=info msg="Step: build"
level=info msg="0: build.attestation.json"
```

Exit code is `0`. Any other exit code indicates a failure (mismatched key, missing required attestation, denied Rego rule, etc.).

To verify a directory as a subject instead of a file:

```bash
cilock verify --directory-path build/output -p policy-signed.json -a build.attestation.json -k testpub.pem
```

## 8. Common failures

- **`signature verification failed`:** the policy doesn't trust the key that signed the attestation. Add the public key to `publickeys` and reference it in the step's `functionaries`.
- **`unable to find collection for step X`:** the `--step` value in `cilock run` doesn't match a key in `policy.steps`.
- **`missing required attestation`:** the policy lists an attestation type that wasn't produced. Add the attestor to `-a` in your `cilock run`.
- **`deny: <message>`:** an embedded Rego rule denied the attestation. The message comes from the rule's `deny[msg]` output.

## 9. Where to next

You've just run the full attestation loop: build, sign, write policy, verify. From here:

- For real CI usage with keyless Sigstore signing, jump to the [5-minute CI quickstart](./quickstart-ci) or pick your platform: [GitHub Actions](../tutorials/github-actions-pipeline) and [GitLab CI](../tutorials/gitlab-ci-pipeline).
- To learn the full policy schema (multi-step pipelines, Rego rules, certificate functionaries, timestamp roots) see [policy schema](../reference/policy-schema).
- For the deeper Rego-policy walkthrough that catches the Trivy and LiteLLM playbooks, see [Defending against supply-chain attacks](../tutorials/defending-against-supply-chain-attacks).
- For the broader supply-chain motivation, see Cole Kennedy's [Preventing the Claude Code Leak with Attestation Policies](https://testifysec.com/blog/preventing-claude-code-leak-attestation-policies) and the [intro](../intro).
