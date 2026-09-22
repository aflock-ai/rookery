---
title: environment
description: The cilock environment attestor captures the host OS, hostname, username, and full process environment with sensitive values obfuscated, signing them into in-toto evidence.
sidebar_position: 5
examples_repo: 04-environment
---

Captures the host OS, hostname, username, and the full process environment (with sensitive variables obfuscated by default) at attestation time.

## What it captures

Four json-tagged fields on the `Attestor` struct:

- **`os`** — `runtime.GOOS` (e.g. `linux`, `darwin`, `windows`). No kernel version, no architecture.
- **`hostname`** — `os.Hostname()`.
- **`username`** — `user.Current().Username`.
- **`variables`** — map of every `KEY=VAL` entry returned by `os.Environ()`, after the sensitive-variable filter has been applied. Keys are always preserved; only values are touched.

Sensitive-variable filter behavior (`plugins/attestors/environment/filter.go`, `obfuscate.go`):

- The blocklist is split into two sets at runtime. Entries containing `*` are compiled as **gobwas/glob** patterns; entries without `*` become **case-insensitive exact-match** keys.
- Both the env-var key and the blocklist entry are upper-cased before comparison, so `aws_secret_key` matches `AWS_SECRET_ACCESS_KEY` and `*token*` matches `MyToken`.
- Default mode is **obfuscate**: matched values are replaced with the literal string `******`. The key still appears in `variables`.
- With `--env-filter-sensitive-vars`, matched entries are **dropped entirely** — neither key nor value appears in `variables`.
- `--env-allow-sensitive-key` excludes specific keys from the filter (exact-match only, no globs).
- **Credentials inside URL-shaped values are redacted whatever the key** (`url_credentials.go`, releases after 4.4.0). The userinfo of a URL in any value becomes `******` and the scheme, host, port and path stay, so `HTTP_PROXY=http://user:pass@proxy:3128` is recorded as `http://******@proxy:3128`. The username goes too, because a token can sit in either slot. A scheme-less `user:pass@proxy:3128`, which curl and Go read as `http://`, is redacted the same way. So is a scheme-relative `//user:pass@proxy:3128`, which Python's urllib reads as a proxy URL, to `//******@proxy:3128`. A colon-separated path list such as `PATH` or `PKG_CONFIG_PATH` is not a URL and is left alone, even when an entry holds an `@` (`/opt/homebrew/opt/python@3.11/bin`). This runs in both modes and neither `--env-disable-default-sensitive-vars` nor `--env-allow-sensitive-key` turns it off.

The default blocklist (`attestation/sensitive_env_vars.go::DefaultSensitiveEnvList`) ships these glob patterns: `*TOKEN*`, `*SECRET*`, `*API_KEY*`, `*PASSWORD*`, `*JWT*`, `*sshKey*`, `*passphrase*`. It also carries ~70 explicit keys including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GH_TOKEN`, `GOOGLE_APPLICATION_CREDENTIALS`, `CI_JOB_JWT`, `CI_JOB_JWT_V2`, `CI_JOB_TOKEN`, `VAULT_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `DOCKER_PASSWORD`, `NPM_AUTH_TOKEN`, `SLACK_TOKEN`, `SNYK_TOKEN`, `STRIPE_API_KEY`, cloud-provider keys for Heroku/DigitalOcean/Vultr/Sauce/Sentry/Percy/Twilio, and the bare key `TOKEN`.

## When to use

Always. It is one of two default-on attestors (with `git`) and provides the baseline host/identity context every downstream collection links back to. Disable it only if you are intentionally producing an environment-free predicate.

## Flags

| Flag | Default | Effect |
|---|---|---|
| `--env-filter-sensitive-vars` | `false` | Switch from obfuscation to outright removal — matched keys and values are dropped from `variables`. |
| `--env-disable-default-sensitive-vars` | `false` | Skip the built-in `DefaultSensitiveEnvList`; only `--env-add-sensitive-key` entries are sensitive. |
| `--env-add-sensitive-key` | `[]` | Repeatable. Adds keys or globs (e.g. `*INTERNAL*`) to the blocklist. |
| `--env-allow-sensitive-key` | `[]` | Repeatable. Allowlist that bypasses the filter for specific keys. No glob support. |

These four flags live on the `cilock run` command (in `cilock/internal/options/run.go`), not as `--attestor-environment-*` flags. The environment attestor registers no per-attestor flags of its own.

## Output shape

```json
{
  "os": "linux",
  "hostname": "runner-abc123",
  "username": "runner",
  "variables": {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/home/runner",
    "GH_TOKEN": "******",
    "AWS_ACCESS_KEY_ID": "******",
    "CI_JOB_JWT": "******"
  }
}
```

## Gotchas

- **The key still leaks.** In the default obfuscate mode only the value becomes `******` — `GH_TOKEN`, `AWS_ACCESS_KEY_ID`, `CI_JOB_JWT_V2` etc. remain visible in the predicate. If even the presence of a key is sensitive, use `--env-filter-sensitive-vars`.
- **cilock 4.4.0 and earlier sign URL credentials verbatim.** A proxy password in `HTTP_PROXY`, `ALL_PROXY` and their siblings lands in the predicate, because those keys match nothing on the blocklist. On those versions pass `--env-add-sensitive-key '*PROXY*'`, plus the name of any other variable that holds a credential URL.
- **URL redaction never names a host the value does not dial, and errs toward naming none.** The marker keeps `@host` only when Go, Python, WHATWG and curl read one userinfo and the same host after it. Where they do not, the URL keeps only its scheme and `******@`, in which none of them finds a host: two `@` in the authority (`https://a@evil.example@github.com/x`), a password holding `/`, `?`, `#` or `\` (`https://alice:sec/ret@github.com/acme`), or an `@` after the authority. An `@` after a `?` or `#` with no `/` before it counts too: Python's proxy parser ends the authority only at a `/` after the userinfo's `@`, so `http://u:pass@proxy-a?tail@proxy-b:3128` sends `pass@proxy-a?tail` to `proxy-b` and becomes `http://******@`. An empty userinfo does not end that search: `http://@proxy-a?u:pass@proxy-b:3128` is an empty user at `proxy-a` to Go, curl and WHATWG, sends `pass` to `proxy-b` from Python, and becomes `http://******@`. A `/` first ends the authority for every parser, so `git+https://u:pass@host/o/r.git@v1` keeps its host and path. `https://evil.example/x@proxy.golang.org` dials `evil.example` in Go, WHATWG and curl, while Python's proxy parser sends `evil.example/x` as a userinfo to `proxy.golang.org`, so it becomes `https://******@`, and so does `https://registry.npmjs.org/@scope/pkg`. A scheme-less value is held to the same rule: `evil.example:8080/x@good.example` and `DOMAIN\user:pass@proxy:8080` (which a WHATWG parser dials at `domain`) become `******@`, and so does a compound scheme that carries a credential (`jdbc:postgresql://u:pass@db/app`). One pair of matching quotes around a value (`"u:pass@proxy:3128"`, as `docker --env-file` keeps them) is looked through, with or without a scheme, so a space in a quoted URL's password does not end it. A value that holds a credential only once tabs and newlines are removed, as WHATWG removes them (`http:/<TAB>/u:pass@h`), becomes `******@`. A path list is told from a scheme-less credential by a `/` in its first entry, or a `/` or `\` that starts its second, so one without (`.:foo@1.2`) is read as `user:pass@host` and redacted. A `\` in the user does not count, because Python's urllib sends `DOMAIN\user:pass@proxy:8080` as a credential. A domain holding `;` (`dom;ain\u:\pass@proxy:8080`) is read as a Windows path list and kept; NetBIOS names cannot hold `;`. A value that opens with `//` is held to the rules of a URL with a scheme whatever its first entry looks like, so a path list that starts with a network path (`//server/share/bin:/opt/x@1/bin`) becomes `//******@`. A package URL (`pkg:npm/lodash@4.17.21`), a scoped npm alias (`npm:@scope/pkg@1.2.3`), a `mailto:` address and a full-length image digest (`docker://ghcr.io/o/img@sha256:<64 hex>`) are references, not userinfo, and are kept. Each shape is held tight: add a port, a list entry or a second `@` and the value is redacted. What shape leaves open is a proxy user literally named `mailto`, or `pkg` or `npm` with a password shaped like the rest of a reference, on a proxy with no port. A token in a query string (`?token=`, a presigned `X-Amz-Signature`) is not userinfo and is not redacted; name its variable with `--env-add-sensitive-key`.
- **Glob vs exact is decided by `*`.** A blocklist entry like `MY_SECRET` is exact-match (case-insensitive); `MY_SECRET*` is a glob. Half-baked patterns like `MY_SECRET_` will only match that literal key. There is no regex support.
- **Glob patterns are normalised to uppercase.** Mixed-case patterns like `*sshKey*` and `*passphrase*` in the default list are upper-cased at compile time, then matched against upper-cased keys — so they catch any casing.
- **Panic-safe matching.** `safeGlobMatch` recovers from `gobwas/glob` panics on adversarial patterns and treats them as non-matches; an unmatched-due-to-panic value is **not** filtered. Audit custom patterns before trusting them.
- **No kernel, no arch.** Despite what older witness docs imply, this attestor records only `runtime.GOOS` — not kernel version, not `runtime.GOARCH`. Hardware/kernel context must come from a separate attestor.
- **Shared capturer.** `Attest` writes the capturer into `AttestationContext.SetEnvironmentCapturer` so other attestors (e.g. `command-run`) apply the same filter to any environment they record.

## CLI example

Default. Captures the process's ENV vars; sensitive keys (TOKEN, KEY, SECRET, PASSWORD) are redacted to `****`.

```bash
cilock run --step my-step \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations environment \
  -- echo hi 
```

Validated. Default attestor. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/04-environment](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/04-environment).

## See also
- [Catalog row](../reference/attestor-catalog)
- Upstream: [witness/environment.md](https://github.com/in-toto/witness/blob/main/docs/attestors/environment.md)
