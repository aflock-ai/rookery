---
title: github
description: The cilock github attestor fetches the GitHub Actions OIDC token, verifies it against the GitHub JWKS, and signs the decoded claims plus workflow context into in-toto evidence.
sidebar_position: 11
examples_repo: 19-github
---

Fetches the GitHub Actions OIDC ID token, verifies its signature against the GitHub JWKS, and records the decoded claims alongside a small slice of `GITHUB_*` / `RUNNER_*` workflow context.

## What it captures

The attestor first fails fast with `ErrNotGitHub` unless `GITHUB_ACTIONS=true`. It validates the workflow URL components, fetches an ID token (audience `witness`), and delegates signature verification to the embedded [`jwt`](./jwt) attestor. The token's string `repository` and `run_id` claims must match the corresponding environment variables. Other workflow fields remain observed environment data, not authenticated claims.

Top-level fields (the `json` tags on `Attestor`):

- `jwt` — full nested `jwt` attestor record, including `claims` (the entire decoded OIDC payload: `sub`, `aud`, `iss`, `repository`, `ref`, `sha`, `workflow`, `event_name`, `actor`, `job_workflow_ref`, `run_id`, `runner_environment`, etc. — whatever GitHub put in the token) and `verifiedBy` (`jwksUrl` plus the JWK that validated the signature).
- `ciconfigpath` — `GITHUB_ACTION_PATH`.
- `pipelineid` — `GITHUB_RUN_ID`.
- `pipelinename` — `GITHUB_WORKFLOW`.
- `pipelineurl` — `<GITHUB_SERVER_URL>/<GITHUB_REPOSITORY>/actions/runs/<GITHUB_RUN_ID>` (also emitted as a subject and the sole back-ref).
- `projecturl` — `<GITHUB_SERVER_URL>/<GITHUB_REPOSITORY>` (also emitted as a subject).
- `runnerid` — `RUNNER_NAME`.
- `cihost` — hostname parsed from `GITHUB_SERVER_URL`.
- `ciserverurl` — `GITHUB_SERVER_URL`.
- `runnerarch` — `RUNNER_ARCH`.
- `runneros` — `RUNNER_OS`.

The OIDC claims themselves live under `jwt.claims` — the attestor does not duplicate them at the top level.

## When to use

In any GitHub Actions workflow that grants `permissions: id-token: write`. The OIDC token is GitHub's signed assertion of *who is running, in what repo, at what ref, in what workflow*; capturing and verifying it gives downstream policy a CI-platform-rooted identity that is independent of the cilock binary and any signer it uses.

## Flags

None. Two undocumented env-var overrides exist for testing:

| Env var | Purpose |
|---|---|
| `WITNESS_GITHUB_JWKS_URL` | Override JWKS endpoint (default `https://token.actions.githubusercontent.com/.well-known/jwks`). |
| `ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN` | Set by the GitHub runner; consumed to fetch the ID token. |

Audience is hard-coded to `witness`.

## Output shape

```json
{
  "jwt": {
    "claims": {
      "sub": "repo:aflock-ai/rookery:ref:refs/heads/main",
      "aud": "witness",
      "iss": "https://token.actions.githubusercontent.com",
      "repository": "aflock-ai/rookery",
      "ref": "refs/heads/main",
      "sha": "deadbeef...",
      "workflow": "release",
      "event_name": "push",
      "actor": "colek42",
      "job_workflow_ref": "aflock-ai/rookery/.github/workflows/release.yml@refs/heads/main",
      "run_id": "1234567890",
      "runner_environment": "github-hosted"
    },
    "verifiedBy": {
      "jwksUrl": "https://token.actions.githubusercontent.com/.well-known/jwks",
      "jwk": { "kty": "RSA", "kid": "...", "n": "...", "e": "AQAB" }
    }
  },
  "pipelineid": "1234567890",
  "pipelinename": "release",
  "pipelineurl": "https://github.com/aflock-ai/rookery/actions/runs/1234567890",
  "projecturl": "https://github.com/aflock-ai/rookery",
  "ciserverurl": "https://github.com",
  "runneros": "Linux"
}
```

## Gotchas

- **Hard-fails outside Actions.** If `GITHUB_ACTIONS != "true"` the attestor returns `ErrNotGitHub` and produces no record.
- **OIDC permission required.** Without `permissions: id-token: write` on the job, `ACTIONS_ID_TOKEN_REQUEST_URL` / `ACTIONS_ID_TOKEN_REQUEST_TOKEN` will be unset and `fetchToken` will fail.
- **Signature is verified, not just decoded.** The embedded `jwt` attestor fetches the JWKS (response capped at 1 MB), parses the signed JWT, validates the signature against the matching `kid`, and only then populates `claims`. A bad signature causes `Attest()` to fail.
- **Audience is fixed.** Token requests always pass `audience=witness`; this is also the value asserted in the `aud` claim. There is no flag to change it — only the `WITNESS_GITHUB_JWKS_URL` env var, intended for test stubs.
- **Token fetch is bounded.** Token requests have a 30-second timeout and do not follow redirects. Responses over 1 MiB are rejected rather than silently truncated. The JWKS response has its own size limit.
- **Token endpoint restriction.** Requests require HTTPS on a subdomain of `actions.githubusercontent.com`, with no user information, fragment, or nonstandard port. Other endpoints, including private Enterprise Server token hosts, are not supported. Redirects cannot expand this boundary.
- **Workflow URL validation.** The server must be an HTTPS origin. Repository paths must contain two bounded, non-traversal components; run IDs must be positive canonical unsigned integers.
- **Subjects + back-refs.** Nonempty `pipelineurl` and `projecturl` are subjects; only `pipelineurl` is a back-ref. Failed attempts clear previous output and do not publish empty URL subjects.
- **Verifier trust remains separate.** Claim matching does not authenticate the environment's server URL or its JWKS override. Consumers must independently pin the expected issuer, audience, and verification keys; a caller-selected JWKS is not proof of GitHub identity.

## CLI example

Real GitHub Actions OIDC token. The attestor calls `ACTIONS_ID_TOKEN_REQUEST_URL` with the `ACTIONS_ID_TOKEN_REQUEST_TOKEN` bearer and verifies the JWT against GitHub's public JWKS.

```bash
# In a workflow with `permissions: id-token: write`:
cilock run --step github-validation \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations environment,git,github,github-action \
  -- echo "real GH Actions run $GITHUB_RUN_ID" 
```

Validated via `.github/workflows/cilock-ci-attestors.yml` in the linked repo. Captures the live OIDC token signed by `token.actions.githubusercontent.com`. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/19-github](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/19-github).

## See also

- [Catalog row](../reference/attestor-catalog)
- [`github-action`](./github-action)
- [Concepts: signing & identity](../concepts/signing-and-identity)
- Upstream: [witness/github.md](https://github.com/in-toto/witness/blob/main/docs/attestors/github.md)
