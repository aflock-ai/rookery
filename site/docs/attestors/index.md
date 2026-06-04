---
title: Attestors overview
sidebar_position: 0
---

# Attestors

Each CI/lock attestor captures one slice of build/run state and emits it as an in-toto predicate inside the DSSE envelope. A single `cilock run` invocation can chain many attestors together, so the resulting collection is the union of every signal you asked for.

This section has **one page per attestor** — what it captures, when to use it, available flags, output shape, and common gotchas.

For a comparative overview (predicate type, lifecycle phase, which ones ship by default), see the [Attestor catalog](../reference/attestor-catalog.md).

## Lifecycle phases (when an attestor fires)

| Phase | Fires | Examples |
|---|---|---|
| `prematerial` | Before materials are recorded | `git`, `environment`, `github`, `aws` |
| `material` | Snapshot of inputs before the wrapped command runs | `material` (always run) |
| `execute` | The wrapped command itself | `command-run` (always run), `github-action` |
| `product` | Snapshot of outputs after the command runs | `product` (always run) |
| `postproduct` | After products are recorded | `sbom`, `sarif`, `secretscan`, `slsa`, `vex`, `oci` |
| `verify` | Only inside `cilock verify` | `policyverify` |

The `material → execute → product` core fires on every `cilock run`; everything else is opt-in via `--attestations`.

## Always run

Three attestors always fire and cannot be disabled. They're the spine of the in-toto link statement CI/lock emits:

- **[material](./material.mdx)** — digests of the working directory before the command
- **[command-run](./command-run.mdx)** — the wrapped command, exit code, optional ptrace
- **[product](./product.mdx)** — digests of files changed or created after the command

## Default-on

When `--attestations` is not specified, CI/lock additionally enables:

- **[environment](./environment.mdx)** — OS, kernel, environment variables (sensitive ones filtered)
- **[git](./git.mdx)** — commit, branch, dirty status, parents, refs, remotes

To override, pass `--attestations "<comma-separated names>"`.

## Default vs. builder opt-in

Every attestor below ships in the default `cilock` binary unless its page says "**builder opt-in only**" — those exist in rookery but aren't blank-imported in the default. To add one, [build a custom CI/lock](../getting-started/installation.md#4-build-from-source).

## Naming gotcha

The directory name in `plugins/attestors/` is not always the attestor name you pass to `--attestations`. Use the canonical name (see each attestor's page, or the [catalog](../reference/attestor-catalog.md)).

| Directory | Name to use |
|---|---|
| `commandrun/` | `command-run` |
| `githubaction/` | `github-action` |
| `aws-iid/` | `aws` |
