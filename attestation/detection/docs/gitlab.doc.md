---
title: gitlab
description: The cilock gitlab attestor captures GitLab CI job context plus the GitLab-issued OIDC JWT and signs it into in-toto evidence, proving an attestation came from a specific pipeline, job, and project.
sidebar_position: 13
examples_repo: 22-gitlab
---

Captures GitLab CI job context and the GitLab-issued OIDC JWT — the CI-side identity that proves "this attestation came from this pipeline, this job, this project."

## What it captures

CI/CD context read from GitLab's predefined `CI_*` environment variables, plus the decoded GitLab-issued JWT (claims + JWKS verification, recorded under the nested `jwt` field).

Struct fields (json tags):

- `jwt` — full embedded `jwt` attestor result (token claims + JWKS verification)
- `ciconfigpath` — `CI_CONFIG_PATH`
- `jobid` — `CI_JOB_ID`
- `jobimage` — `CI_JOB_IMAGE`
- `jobname` — `CI_JOB_NAME`
- `jobstage` — `CI_JOB_STAGE`
- `joburl` — `CI_JOB_URL` (also recorded as a subject)
- `pipelineid` — `CI_PIPELINE_ID`
- `pipelineurl` — `CI_PIPELINE_URL` (subject + back-reference)
- `projectid` — `CI_PROJECT_ID`
- `projecturl` — `CI_PROJECT_URL` (also recorded as a subject)
- `runnerid` — `CI_RUNNER_ID`
- `cihost` — `CI_SERVER_HOST`
- `ciserverurl` — `CI_SERVER_URL` (used to derive the JWKS URL)

`Attest()` first checks `GITLAB_CI=true` and returns `ErrNotGitlab` if unset.

## When to use

In any GitLab CI pipeline. The embedded JWT gives the verifier a GitLab-signed proof of pipeline/project/job identity that is independent of the cilock binary itself. Pair with the cilock-action GitLab template (or an equivalent `.gitlab-ci.yml` snippet) so the runner exposes a JWT env var to the attestor.

## Flags

- `--attestor-gitlab-token-env <NAME>`: record the claims of the ID token in `$NAME` only. By default the attestor finds the job's own ID token by its claims: any variable holding a JWT issued by `CI_SERVER_URL` to `CI_JOB_ID`, preferring `SIGSTORE_ID_TOKEN`. A named variable that holds no token for this job is an error.

The JWKS endpoint is `${CI_SERVER_URL}/oauth/discovery/keys`, or `WITNESS_GITLAB_JWKS_URL` when set. Programmatic options (Go API): `WithToken(string)`, `WithTokenEnvVar(string)`.

The job declares its token in `.gitlab-ci.yml`; the audience does not matter to this attestor (it records claims and sends the token nowhere), so the token cilock already signs with serves:

```yaml
id_tokens:
  SIGSTORE_ID_TOKEN:
    aud: sigstore
```

## Output shape

```json
{
  "jwt": {
    "claims": { "iss": "https://gitlab.com", "sub": "project_path:group/repo:ref_type:branch:ref:main", "...": "..." },
    "verifiedBy": { "jwksUrl": "https://gitlab.com/oauth/discovery/keys", "...": "..." }
  },
  "ciconfigpath": ".gitlab-ci.yml",
  "jobid": "9876543210",
  "jobimage": "alpine:3.20",
  "jobname": "build",
  "jobstage": "build",
  "joburl": "https://gitlab.com/group/repo/-/jobs/9876543210",
  "pipelineid": "1234567890",
  "pipelineurl": "https://gitlab.com/group/repo/-/pipelines/1234567890",
  "projectid": "42",
  "projecturl": "https://gitlab.com/group/repo",
  "runnerid": "12345",
  "cihost": "gitlab.com",
  "ciserverurl": "https://gitlab.com"
}
```

Subjects: `` `pipelineurl:<url>` ``, `` `joburl:<url>` ``, `` `projecturl:<url>` `` (SHA-256). Back-reference: `` `pipelineurl:<url>` ``.

## Gotchas

- **Not in GitLab CI**: if `GITLAB_CI` is unset or not `"true"`, the attestor returns `ErrNotGitlab` and produces no output.
- **No ID token**: a job that declares no `id_tokens:` has no signed identity on GitLab 17+ (GitLab removed `CI_JOB_JWT`). The attestor still records the `CI_*` fields and warns that no signed job claims were recorded.
- **Only this job's token**: a token whose `iss` is not `CI_SERVER_URL` or whose `job_id` is not `CI_JOB_ID` is never recorded, whatever variable holds it. On a GitLab older than 17 that still sets `CI_JOB_JWT`, that token is found the same way.
- **Self-hosted and air-gapped GitLab**: the JWKS is fetched from the job's own GitLab (`${CI_SERVER_URL}/oauth/discovery/keys`), which the runner can always reach, so capture needs no internet. Override with `WITNESS_GITLAB_JWKS_URL` for a non-standard install.
- **JWT verification failure is fatal**: if a token is present but JWKS verification fails, `Attest()` returns the underlying jwt-attestor error and no gitlab attestation is recorded.

## CLI example

See the constraint summary + reproduction recipe at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/22-gitlab](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/22-gitlab). This attestor is currently blocked or doc-only — the linked example explains why and shows the recipe to validate once the constraint is removed.

## See also

- [Catalog row](../reference/attestor-catalog)
- [GitLab component reference](../reference/gitlab-component)
- Upstream: [witness/gitlab.md](https://github.com/in-toto/witness/blob/main/docs/attestors/gitlab.md)
