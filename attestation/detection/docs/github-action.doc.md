---
title: github-action
description: The cilock github-action attestor captures GitHub Action execution metadata — reference, type, inputs/outputs, exit code, and runtime context — signed into in-toto evidence.
sidebar_position: 10
examples_repo: 20-github-action
---

Captures metadata about a GitHub Action execution — the action reference, type, inputs/outputs, exit code, and a small slice of GitHub Actions runtime context.

## What it captures

The attestor records pre-set action metadata supplied by the action runner, plus a few `GITHUB_*` env vars sampled at `Attest()` time. Unlike `command-run`, it does not itself shell out — execution happens via a runner-provided `ExecuteFunc`.

Top-level fields:

- `actionref` — action reference such as `actions/checkout@v4`. Also emitted as a subject (`actionref:<ref>`).
- `actiontype` — `javascript`, `docker`, or `composite`.
- `actionname` — `name` field from the action's `action.yml`.
- `actioninputs` — map of user-provided inputs.
- `actionoutputs` — map of captured outputs.
- `exitcode` — exit code returned by the execute function.
- `actiondir` — resolved local path of the action on disk.
- `refpinned` — true if `actionref` was pinned to a commit SHA.
- `docker` — nested `DockerContainerConfig` (populated only for docker actions): `image`, `network`, `workspace`, `entrypoint`, `envcount`, `args`.
- `runid` — from `GITHUB_RUN_ID`.
- `workflowname` — from `GITHUB_WORKFLOW`.
- `jobname` — from `GITHUB_JOB`.

The only `GITHUB_*` env vars consumed are `GITHUB_RUN_ID`, `GITHUB_WORKFLOW`, and `GITHUB_JOB`. Anything else about the workflow (event, actor, ref, sha, runner OS, repository) is **not** in this attestor — see `github` for OIDC-derived identity.

## When to use

Inside GitHub Actions workflows when an action is being executed under cilock's action runner. `cilock-action` wires this attestor in by default; you generally don't add it manually.

## Flags

None. The attestor is configured by the in-process action runner via functional options (`WithActionRef`, `WithActionType`, `WithDockerConfig`, `WithExecuteFunc`, etc.), not by CLI flags.

## Output shape

```json
{
  "actionref": "actions/checkout@v4",
  "actiontype": "javascript",
  "actionname": "Checkout",
  "actioninputs": { "ref": "main" },
  "actionoutputs": { "ref": "main" },
  "exitcode": 0,
  "actiondir": "/runner/_actions/actions/checkout/v4",
  "refpinned": false,
  "docker": {
    "image": "ghcr.io/example/action:1.2.3",
    "network": "none",
    "workspace": "/github/workspace",
    "entrypoint": "/entrypoint.sh",
    "envcount": 12,
    "args": ["--flag"]
  },
  "runid": "1234567890",
  "workflowname": "release",
  "jobname": "build"
}
```

## Gotchas

- The predicate is `aflock.ai/attestations/github-action/v0.1` — a cilock-native type, not an upstream in-toto or witness predicate.
- `Attest()` runs the `ExecuteFunc` (if set) between material and product attestors, so file-system side effects of the action are visible to `product`. If execution fails, `exitcode` is still recorded and the error is returned.
- Only `actionref` becomes a subject; if it's empty, the attestation has no subjects.
- The three `GITHUB_*` env vars are only read at `Attest()` time. Outside Actions they will simply be empty strings.

## CLI example

Real GitHub Actions runtime context. Reads canonical `GITHUB_*` env vars exposed to every Actions job and records them in a predicate.

```bash
# Same workflow as the github attestor; both are run together:
cilock run --step github-validation \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations environment,git,github,github-action \
  -- echo "real GH Actions run" 
```

Validated alongside `github` in the same workflow run. Captures real `GITHUB_RUN_ID`, `GITHUB_WORKFLOW`, `GITHUB_REPOSITORY`, `RUNNER_OS`, etc. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/20-github-action](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/20-github-action).

## See also

- [Catalog row](../reference/attestor-catalog)
- [`github`](./github) for OIDC claims
- [GitHub Action reference](../reference/github-action)
