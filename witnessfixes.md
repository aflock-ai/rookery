# Witness/Go-Witness Security Fixes Applied to Rookery

This document tracks all security findings from auditing the upstream `witness` and `go-witness`
repositories, open PRs/issues review, and the corresponding fixes applied to the rookery codebase.

---

## Security Audit Findings

### CRITICAL — Already Fixed in Rookery

| # | Finding | Upstream Location | Rookery Status |
|---|---------|-------------------|----------------|
| C1 | **Certificate chain corruption: intermediates assigned to roots** — `policyRoots = append(policyIntermediates, cert)` mixes intermediate certs into the root pool, weakening X.509 chain validation. | `witness-main/cmd/verify.go:146` | Already correct: `cilock/internal/cmd/verify.go:130` uses `policyIntermediates = append(policyIntermediates, cert)` |
| C2 | **Self-referential no-op in trust bundle processing** — `intermediates = append(intermediates, intermediates...)` doubles the existing slice instead of appending from the trust bundle. | `go-witness/attestation/policyverify/policyverify.go:179` | Already correct: `plugins/attestors/policyverify/policyverify.go:178` uses `intermediates = append(intermediates, trustBundle.Intermediates...)` |

### HIGH — Fixed in This Changeset

| # | Finding | File(s) Changed | Fix Description |
|---|---------|-----------------|-----------------|
| H1 | **Stdout file descriptor closed when no outfile specified** — `loadOutfile("")` returns `os.Stdout`, then callers close it, corrupting the process stdout. Subsequent writes could go to a re-opened fd, potentially leaking data. | `cilock/internal/cmd/root.go` | Added `closeOutfile()` helper that skips closing when file is `os.Stdout`. All callers updated to use it. |
| H2 | **Input file never closed in sign command** — `os.Open(so.InFilePath)` without defer close leaks the file descriptor for the entire process lifetime. | `cilock/internal/cmd/sign.go` | Added `defer inFile.Close()` and switched to `defer closeOutfile(outFile)`. |
| H3 | **Silent signer/verifier loading failures** — `loadSigners()` and `loadVerifiers()` logged errors and continued, allowing operations to proceed with fewer signers/verifiers than intended. An attacker could exploit this to bypass multi-signer requirements. | `cilock/internal/cmd/keyloader.go` | Changed both functions to return errors immediately on any failure, preventing partial trust decisions. |
| H4 | **Debug println leaking package listing to stdout** — `fmt.Println("gather RPM packages:", ...)` dumps all installed packages to stdout, potentially interfering with JSON output and leaking system info. | `plugins/attestors/system-packages/rpm.go` | Removed the debug `fmt.Println` statement. |

### MEDIUM — Fixed in This Changeset

| # | Finding | File(s) Changed | Fix Description |
|---|---------|-----------------|-----------------|
| M1 | **Wildcard x.509 certificate constraints by default** — Policy cert constraint flags (`--policy-commonname`, `--policy-dns-names`, etc.) defaulted to `"*"`, silently accepting any certificate matching the CA chain and bypassing intended identity constraints. | `cilock/internal/options/verify.go` | Changed defaults from `"*"` to empty strings. Users must now explicitly specify constraints or wildcards. |
| M2 | **No timestamp authority URL validation** — `TimestampWithUrl()` accepted any string including non-HTTPS URLs, enabling SSRF or plaintext HTTP timestamp requests that leak artifact hashes. | `attestation/timestamp/tsp.go` | Added `validateURL()` that enforces HTTPS scheme and valid host. Called before making HTTP requests. |
| M3 | **Subject digest format not validated** — `--subjects` flag accepted arbitrary strings as digest values, which could cause false matches during policy verification. | `cilock/internal/cmd/verify.go` | Added `isValidHexDigest()` validation requiring hex-encoded hashes of at least 128 bits. |
| M4 | **Symlink path traversal in file attestor** — `filepath.EvalSymlinks()` followed symlinks outside the working directory, allowing attestations to include contents of arbitrary files (e.g. `/etc/shadow`). | `attestation/file/file.go` | Added boundary check: resolved symlink targets must be within `basePath`. Out-of-bounds symlinks are skipped with a debug log. |
| M5 | **Glob pattern recompilation on every call** — `isEnvironmentVariableSensitive()` compiled glob patterns from scratch on every environment variable check, causing unnecessary allocations. | `plugins/attestors/secretscan/envscan.go` | Added `compiledGlobCache` map to cache compiled patterns across calls. |
| M6 | **Unqualified binary paths in system-packages attestor** — `rpm` and `dpkg-query` were invoked without absolute paths, vulnerable to PATH manipulation where a malicious binary could be executed instead. | `plugins/attestors/system-packages/rpm.go`, `debian.go` | Changed to `/usr/bin/rpm` and `/usr/bin/dpkg-query`. |

### HIGH — Ported from Upstream PRs

| # | Finding | File(s) Changed | Fix Description |
|---|---------|-----------------|-----------------|
| P1 | **KMS offline verification broken** (go-witness PR #649 / Issue #648) — `PublicKeyVerifiers()` returns fatal error when KMS provider is unavailable, preventing offline verification even when the policy embeds the public key. Additionally, the key ID check at line 108 always fails for KMS keys because the computed hash never matches the KMS URI. | `attestation/policy/policy.go` | KMS verifier failures now fall back to embedded public key when available. Key ID mismatch check skipped for KMS keys since the computed hash will never match the KMS URI. Verifiers stored under the policy's `key.KeyID` for consistent functionary matching. |

### Already Correct in Rookery (No Action Needed)

| Finding | Upstream Bug | Rookery Status |
|---------|-------------|----------------|
| Policy expiration treated as warning | `go-witness` logs warning but doesn't fail | `attestation/policy/policy.go:231-233` returns `ErrPolicyExpired` as a hard error |
| Intermediate cert handling in policyverify | Self-referential append (C2 above) | Correct `trustBundle.Intermediates...` usage |
| Certificate chain in verify CLI | Intermediates mixed with roots (C1 above) | Correct separate `policyRoots` and `policyIntermediates` handling |

---

## Upstream Open PRs/Issues Review

### Critical — Should Port Immediately

| Item | Repo | Type | Status |
|------|------|------|--------|
| PR #649 / Issue #648 | go-witness | Bug fix | **FIXED** — KMS offline verification broken. Rookery had the identical bug in `policy.go:108`. |
| PR #66 / Issue #65 | go-witness | Bug fix | TODO — Product include/exclude glob not working for attestation content (only subjects). |
| Issue #416 | witness | Bug fix | TODO — `artifactsFrom` fails when backrefs don't exist. Same logic exists in rookery's `attestation/policy/policy.go`. |

### High Priority — Should Port

| Item | Repo | Type | Notes |
|------|------|------|-------|
| PR #594 / Issue #588 | go-witness | Feature | Cross-step attestation data access in Rego policies. |
| PR #643 / Issue #360 | go-witness | Performance | Concurrent file attestor — 48% faster hashing. |
| PR #612 / Issue #598 | go-witness | Feature | Fulcio HTTP/REST mode for restricted networks. |
| Issue #595 | go-witness | Feature | Support standard attestation types (SLSA, cosign) in policies. |
| PR #602 | go-witness | Feature | Configurable search paths for lockfiles attestor (monorepo support). |
| PR #628 | go-witness | Feature | PreExec/PreExit hooks for commandrun (prerequisite for networktrace). |
| Issue #568 | witness | Feature | Migrate to sigstore-go for signing/verification. |

### Medium Priority — Should Port

| Item | Repo | Type | Notes |
|------|------|------|-------|
| PR #629 | go-witness | Feature | Networktrace attestor with eBPF. |
| PR #575 / Issue #574 | go-witness | Feature | AWS region cert from file (air-gapped support). |
| PR #584 / Issue #414 | go-witness | Feature | Configuration attestor. |
| PR #593 / Issue #592 | go-witness | Feature | JWKS URL override for CI attestor testing. |
| PR #514 | go-witness | Enhancement | Documentation interfaces and jsonschema tags. |
| Issue #57 | go-witness | Performance | Concurrent policy verification with timeouts. |
| Issue #140 | go-witness | Enhancement | Trust bundle format for x.509 certificates. |
| Issue #348 | go-witness | Feature | Rego inputs and bundles support. |
| Issue #340 | witness | Feature | Multi-lifecycle-stage attestors. |
| Issue #339 | witness | Feature | Encrypted private key support. |
| Issue #514/229 | witness/go-witness | Feature | PKCS#11/HSM signing support. |
| Issue #226 | witness | Feature | SCT timestamp verification. |
| Issue #700/512 | witness/go-witness | Feature | Syscall categorization and enhanced tracing. |
| Issue #5 | witness | Feature | Azure identity attestation. |

### Needs Investigation

| Item | Repo | Notes |
|------|------|-------|
| Issue #721 | witness | PEM vs raw base64 key parsing inconsistency — check rookery's `NewVerifierFromReader`. |
| Issue #695 | witness | CVE-2025-22871 Go version check. |
| Issue #704 | witness | Exclude glob in containers (likely same root cause as PR #66). |
| Issue #268 | witness | in-toto security audit findings — need to review specifics. |
| Issue #573 | witness | KMS + file cert path interaction bug. |
| Issue #282/98 | witness/go-witness | Maven version/scope resolution bug. |
| Issue #317 | witness | Git LFS support in git attestor. |
| Issue #202 | go-witness | Time unmarshaling in collections. |

### Already Fixed in Rookery

| Item | Repo | What | How |
|------|------|------|-----|
| Issue #278/130 | witness/go-witness | KMS signing | `plugins/signers/kms/` |
| Issue #170 | witness | Env var filtering | `EnvironmentCapturer` interface + filter/obfuscate |
| Issue #260 | witness | GitOID in DigestSet | `cryptoutil.DigestValue.GitOID` field |
| Issue #152 | witness | JSON Schema | All attestors implement `Schema()` |
| PR #260 | go-witness | Vault Transit | `plugins/signers/vault-transit/` |
| Issue #102 | go-witness | Symlink handling | File attestor with cycle detection |
| Issue #172/376 | go-witness | Attestor registration | Monorepo presets + legacy aliases |

### Not Applicable to Rookery

Dependency bumps (PRs #726, #725, #639, #636, #654), documentation (PR #613, Issues #682, #608, #537, #291, #283), CLI-only features (PRs #697, #711; Issues #509, #602, #542, #418, #360, #344, #329, #326, #293, #261, #266, #262, #338, #232, #233, #219, #206, #205, #240, #169, #106, #113), and already-resolved concerns (Issues #675 — covered by PR #676, #591).

---

## Files Modified

```
attestation/policy/policy.go         — P1: KMS offline verification fallback to embedded key
cilock/internal/cmd/root.go          — H1: closeOutfile helper for stdout safety
cilock/internal/cmd/sign.go          — H2: file descriptor leak fix
cilock/internal/cmd/run.go           — H1: use closeOutfile instead of direct Close
cilock/internal/cmd/keyloader.go     — H3: fail-fast on signer/verifier errors
cilock/internal/cmd/verify.go        — M3: subject digest validation
cilock/internal/options/verify.go    — M1: remove wildcard cert constraint defaults
attestation/timestamp/tsp.go         — M2: HTTPS URL validation for timestamp servers
attestation/file/file.go             — M4: symlink path traversal boundary check
plugins/attestors/secretscan/envscan.go    — M5: glob pattern compilation cache
plugins/attestors/system-packages/rpm.go   — H4+M6: remove debug println, absolute binary path
plugins/attestors/system-packages/debian.go — M6: absolute binary path
```
