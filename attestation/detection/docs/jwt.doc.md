---
title: jwt
description: The cilock jwt attestor parses a JWT, fetches a JWKS, verifies the token signature, and signs the decoded claims plus the verifying key into in-toto evidence as a generic OIDC identity proof.
sidebar_position: 15
examples_repo: 27-jwt
---

Parses a JWT, fetches a JWKS, verifies the token's signature, and records the decoded claims plus the JWK that verified it.

## What it captures

The struct exposes two top-level JSON-tagged fields:

- `claims` — the full set of decoded JWT claims, populated by `go-jose`'s `parsed.Claims(jwks, &a.Claims)` after signature verification. Stored as `map[string]interface{}`, so every claim in the token (standard registered claims plus any custom issuer-specific claims) lands here verbatim.
- `verifiedBy` (omitempty) — the JWKS coordinates that verified the signature:
  - `jwksUrl` — the URL the JWKS was fetched from.
  - `jwk` — the `jose.JSONWebKey` (kid, kty, alg, public key material, etc.) whose `kid` matched the token header.

The token itself and the configured JWKS URL are kept as unexported fields (`token`, `jwksUrl`) and are deliberately not serialized.

This attestor is also embedded inside the [`github`](./github), [`gitlab`](./gitlab), and [`gcp-iit`](./gcp-iit) attestors, which construct it via `jwt.New(jwt.WithToken(...), jwt.WithJWKSUrl(...))` to share JWT parsing, JWKS fetch, and signature-verification logic.

## When to use

Use `jwt` directly when capturing an OIDC ID token from a CI platform that does not yet have a dedicated rookery attestor (the dedicated ones — GitHub Actions, GitLab CI, GCP — embed this attestor for you). It is a generic "I held this signed token and verified it against this JWKS" attestation.

## Flags

None. The attestor is configured programmatically through functional options (`WithToken`, `WithJWKSUrl`) by its embedders; it does not register CLI flags.

## Output shape

```json
{
  "claims": {
    "iss": "https://token.actions.githubusercontent.com",
    "sub": "repo:example/repo:ref:refs/heads/main",
    "aud": "witness",
    "exp": 1700000000,
    "iat": 1699996400
  },
  "verifiedBy": {
    "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
    "jwk": {
      "use": "sig",
      "kty": "RSA",
      "kid": "...",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  }
}
```

## Gotchas

- **Empty token fails fast.** `Attest()` returns `ErrInvalidToken("")` if no token was supplied via `WithToken`; no network call is made.
- **JWKS fetch is hard-capped.** The fetch uses a `*http.Client` with a 30 s timeout, requires HTTP 200 (anything else errors with `unexpected status code from JWKS endpoint ...`), and the response body is wrapped in `io.LimitReader(resp.Body, 1<<20)` — a malicious or misconfigured JWKS endpoint cannot OOM the attestor; oversized responses fail at JSON decode.
- **Bad signature fails the attestation.** Signature verification is performed by `parsed.Claims(jwks, &a.Claims)`. If the token's signature does not validate against any key in the fetched JWKS, `Attest()` returns `error parsing claims: ...` and the attestation does not run. The `claims` field is only populated on successful verification.
- **Missing `kid` is tolerated for `verifiedBy` only.** After successful claims verification, the attestor walks the token headers for the first non-empty `kid` and looks it up in the JWKS. If no key matches, `Attest()` returns `nil` with `verifiedBy` left zero-valued — claims are still captured, but the recorded JWK is absent. (Signature verification itself has already succeeded by this point; this lookup is purely to record which JWK matched.)
- **No revocation, no expiration check, no audience check.** This attestor records what the token says; it does not enforce `exp`, `nbf`, `aud`, or issuer constraints. Policy evaluation is responsible for asserting on `claims.*`.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/27-jwt](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/27-jwt). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog)
- [`github`](./github), [`gitlab`](./gitlab), [`gcp-iit`](./gcp-iit) — all embed this attestor
- Upstream: [witness/jwt.md](https://github.com/in-toto/witness/blob/main/docs/attestors/jwt.md)
