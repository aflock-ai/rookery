---
title: configuration
description: The cilock configuration attestor captures the raw CLI flags and working directory that drove a run, signing them into in-toto evidence.
sidebar_position: 6
examples_repo: 06-configuration
---

Captures the cilock CLI flags that drove this run. cilock is args-only — there is no config file — so the flags (plus the working directory) are the complete invocation surface this attestor records.

## What it captures

The attestor reads `os.Args` directly — it does not call into cilock's option resolver, so it records the raw CLI surface, not post-resolution defaults.

- `flags` — map of flag name to value, parsed from `os.Args` up to (but not including) the `--` separator that delimits cilock args from the wrapped command. Handles `--flag value`, `-f value`, `--flag=value`, `-f=value`, and bare boolean flags (recorded as `"true"`). Leading dashes are stripped from keys.
- `working_directory` — the process working directory at attest time (`os.Getwd()`).

Environment variables are **not** captured by this attestor — see [`environment`](./environment) for that.

## When to use

Audit trails where "which flags produced this attestation" needs to be provable after the fact. Most pipelines do not need it; reach for it when a single runner invokes cilock with varying flag sets and each variant's settings must be frozen alongside its attestation.

## Flags

None.

## Output shape

```json
{
  "flags": {
    "step": "build",
    "trace": "true"
  },
  "working_directory": "/workspace"
}
```

All fields are `omitempty`; absent fields mean the corresponding source was missing or unreadable.

## Gotchas

- The flag parser is positional and naive: it does not consult cilock's option definitions. A value that happens to start with `-` (e.g. a negative number) will be treated as the next flag, not as the previous flag's value, and the previous flag will be recorded as `"true"`.
- `flags` reflects what was typed on the command line, not the resolved configuration. Defaults applied by cilock and values sourced from env vars are not merged into `flags`.
- Secrets passed as flag values (e.g. tokens) appear verbatim in `flags`; prefer env vars or file-based secret flags for sensitive values.

## CLI example

```bash
cilock run --step my-step \
  --signer-file-key-path key.pem --outfile attestation.json \
  --attestations configuration \
  -- echo hi 
```

Validated. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/06-configuration](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/06-configuration).

## See also

- [Catalog row](../reference/attestor-catalog)
- [Configuration reference](../reference/configuration)
