---
title: secretscan
description: The cilock secretscan attestor runs a Gitleaks pattern scan over every product and prior attestor's JSON, with recursive decoding, recording redacted findings into signed in-toto evidence.
sidebar_position: 22
examples_repo: 39-secretscan
---

Runs a Gitleaks pattern scan over every product and every prior attestor's JSON, with recursive base64/hex/URL decoding (default 3 layers) so secrets hidden inside encoded blobs still surface.

## What it captures

The predicate has a single top-level field, `findings`, which is always an array (empty `[]` on a clean scan). Each `Finding` carries:

- `ruleId` — Gitleaks rule that fired, lowercased.
- `description` — human-readable rule description from Gitleaks.
- `location` — either `product:<path>` for product hits or `attestation:<attestor-name>` for hits inside a prior attestor's JSON (the `commandrun` attestor expands to `attestation:commandrun:stdout`, `:stderr`, and `:json`).
- `startLine` — line number in the source (Go field `Line`, JSON tag `startLine`).
- `secret` — a `cryptoutil.DigestSet` (multi-algorithm hashes) of the actual secret value. The raw secret is never stored.
- `match` — a redacted snippet with context around the hit, truncated to `maxMatchDisplayLength` (40 chars) with `[SENSITIVE-VALUE]` standing in for the value itself.
- `entropy` — Gitleaks' Shannon-entropy score for the match.
- `encodingPath` — the decode chain that surfaced the secret, listed outermost to innermost (e.g., `["base64","hex"]` means base64-then-hex was peeled off before the secret matched). Empty/absent on direct hits.
- `locationApproximate` — `true` whenever the finding came from a decoded layer, since line numbers in decoded payloads don't map cleanly back to the source file.

Scanned products are also added as `Subjects()` under the key `product:<path>`.

## When to use

On every CI build. Findings are **always** recorded as evidence in the signed collection — recording is the attestor's job, and it happens whether or not the build is gated. Pair with `--attestor-secretscan-fail-on-detection` to *additionally* fail closed, so a leaked key blocks the run as well as being recorded against it. Without the flag, findings are recorded and the build still passes — useful for triage before turning the guard on, and the natural pairing with a verify-time policy that gates on `findings`.

## Recursive decoding

`scanBytes` in `scanner.go` walks each layer of content through three encoding scanners defined in `encoding.go`:

- **base64** — matches `[A-Za-z0-9+/]{15,}={0,2}` and the URL-safe variant; tries `StdEncoding` then falls back to `RawURLEncoding`.
- **hex** — matches `[0-9a-fA-F]{16,}` and requires even length.
- **url** — matches both consecutive `%XX` runs (3+) and tokens containing an encoded `%3D` (equals sign), then `url.QueryUnescape`s.

For each decoded payload that's long enough, the scanner recurses with `currentDepth+1`. Recursion stops at `min(maxDecodeLayers, maxScanRecursionDepth=3)` — the hard safety cap in `constants.go` is 3 regardless of flag value. Each level prepends its codec name to `encodingPath` and flags findings as `locationApproximate=true`.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--attestor-secretscan-fail-on-detection` | `false` | Fail the run if any finding is recorded OR if any per-file/per-attestor scan errored. Findings are recorded in the attestation either way. |
| `--attestor-secretscan-max-file-size-mb` | `10` | Skip files larger than this; `0` disables the limit. Also passed to Gitleaks as `MaxTargetMegaBytes`. |
| `--attestor-secretscan-max-decode-layers` | `3` | Maximum encoding layers to peel; capped at the hard recursion limit of 3. |
| `--attestor-secretscan-config-path` | (none) | Path to a custom Gitleaks TOML config (decoded with `pelletier/go-toml`). When set, manual allowlist flags are ignored. |
| `--attestor-secretscan-allowlist-regex` | (none) | Regex pattern for content to ignore. Repeatable. Ignored when `--config-path` is set. |
| `--attestor-secretscan-allowlist-stopword` | (none) | Exact string to ignore. Repeatable. Ignored when `--config-path` is set. |

## Output shape

```json
{
  "findings": [
    {
      "ruleId": "aws-access-token",
      "description": "AWS Access Token",
      "location": "product:dist/config.yaml",
      "startLine": 42,
      "secret": {
        "sha256": "…",
        "sha1": "…"
      },
      "match": "key: [SENSITIVE-VALUE]…",
      "entropy": 4.7,
      "encodingPath": ["base64"],
      "locationApproximate": true
    }
  ]
}
```

## Gotchas

- **Fail-closed is strict.** With `--fail-on-detection`, `Attest()` errors not only on findings but also on accumulated scan errors (`scanErrors`). This is intentional (per the source comment): an empty findings list from a crashed Gitleaks call is otherwise indistinguishable from a clean scan, so an attacker who could induce a crash would bypass the guard.
- **The guard never costs you the evidence.** A detected secret is reported as an `attestation.DetectionError` — "I looked, and I found something you told me to reject." The workflow keeps that attestor's payload in the signed collection, so the run exits non-zero *and* the findings are recorded for post-incident analysis and verify-time policy. A **plain** error from `Attest()` means something different and stronger: the scan COULD NOT RUN, so its incomplete payload is deliberately excluded from the collection rather than being recorded as a clean result.
- **`config-path` replaces, not merges.** Supplying a Gitleaks TOML disables the manual allowlist entirely and logs `command-line allowlists ignored`. If you need both, fold your allowlist into the TOML.
- **Post-product timing.** The lifecycle is `postproduct`, so the wrapped command has already run by the time fail-closed triggers. The guard prevents the leak from being signed and shipped, not from being executed locally. Use `cilock verify` with a policy that checks `findings == []` to gate downstream consumers.
- **No self-scan, no peer-scan.** `shouldSkipAttestor` skips the `secretscan` attestor itself and any other `postproduct` attestor to avoid races and recursion.
- **Binary products and directories are skipped** via `shouldSkipProduct` (MIME-type check), so secrets compiled into binaries won't be caught here.
- **Every product is scanned; a scanner's own report is deduplicated, never skipped.** A SARIF report (`gitleaks --report-format sarif`, …) quotes every secret it found, so scanning it naively reports each one a second time as `product:<report>`. The attestor still scans the report like any other product — nothing in it is trusted, `tool.driver.name` included — and afterwards drops a finding inside it only when the report declares a result with the same rule id **and** the same (rule id, secret sha256) was found by this scan in some other location. A secret that exists only inside a "report", however it labels itself, is a real finding and `--fail-on-detection` fires on it. Parsed reports are recorded under `consumedReports` (path, sha256 of the bytes parsed, claimed driver, result count, `deduplicated` count) and remain in `Subjects()`. The sha256 is computed at read time and must equal the product attestor's digest; if the file changed in between, or no digest is recorded, the product is treated as ordinary (scanned, nothing deduplicated).
- **Hard 3-layer recursion cap.** `maxScanRecursionDepth` in `constants.go` is 3 — setting `--max-decode-layers` higher has no effect.

## CLI example

Real secret-pattern scan against the wrapped command's outputs. Surfaces real findings (or none) and gates the build via `--attestor-secretscan-fail-on-detection`.

```bash
# secretscan is a postproduct attestor — it inspects the command's
# captured products and opened files (via the ptrace spy) for secret
# patterns. The wrapped command should be the real workload whose
# output you want scanned (a build, an install, a config render),
# not a synthetic echo.
cilock run --step build \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations secretscan,environment,git \
  --attestor-secretscan-fail-on-detection \
  -- go build -o bin/myapp ./cmd/myapp
```

Validated against a real directory tree with `--fail-on-detection` enabled. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/39-secretscan](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/39-secretscan).

## See also

- [Catalog row](../reference/attestor-catalog)
- [Concepts: secretscan attestor](../concepts/attestors#secretscan-attestor)
- [Defending against supply-chain attacks](../tutorials/defending-against-supply-chain-attacks)
- Upstream: [witness/secretscan.md](https://github.com/in-toto/witness/blob/main/docs/attestors/secretscan.md)
