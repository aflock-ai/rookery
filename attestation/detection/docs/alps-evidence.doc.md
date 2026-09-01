---
title: alps-evidence
description: Observe which coding-agent process appears in cilock's ancestry, with bounded version, model, sandbox, configuration, and environment context that is explicitly non-enforcing.
sidebar_position: 4
examples_repo: alps-evidence
---

`alps-evidence` records the nearest supported coding-agent process visible in
cilock's ancestry. It supports Claude Code and Codex with product-specific
inspection, plus bounded fingerprint-only observations for Cursor, Gemini CLI,
Copilot CLI, Aider, Goose, and OpenCode.

This is observational attribution, not identity. The process being described
runs as the same user and can forge its name, arguments, environment, and
files. Every predicate carries `assurance.enforcement: false` and a caveat that
states this boundary.

## Validated invocation

Run this command from inside a supported coding agent. Signing identity is a
separate ceremony and is never inferred from the observed process:

```bash
cilock run \
  --step alps-evidence-observation \
  --platform-url "$PLATFORM_URL" \
  --attestations alps-evidence,environment,git \
  -- true
```

The detector can also add `alps-evidence` during automatic planning when a
known agent marker is present. An explicit `--attestations` list is exact, so
include `alps-evidence` yourself when you want it in a manual set.

## What gets captured

- `status`: `detected`, `not-detected`, `incomplete`, or `unavailable`.
- `assurance`: the fixed non-enforcing mode and caveat.
- `invoker`: observed vendor/product, bounded version, process reference, and
  the exact fingerprint basis that matched.
- `model`, `session`, and `settings`: only when a provider can name the source;
  each value carries its own observation assurance.
- `configuration`: bounded, single-read snapshots with digests. A digest proves
  the bytes cilock read, not that the running agent loaded the file.
- `environment`: provider-allowlisted keys only. Credential-shaped keys and
  run-wide redaction rules suppress values; presence may remain.
- `ancestry` and `warnings`: a bounded, basename-only walk plus explicit gaps.

Raw argv, raw environment blocks, file contents, subjects, materials, products,
backrefs, and exports are not emitted.

## Why this shape

The attestor separates three questions that are easy to conflate:

1. What process context could cilock observe?
2. Which authenticated principal signed the evidence?
3. Did a policy accept the exact commit?

`alps-evidence` answers only the first. Fulcio/OIDC answers the second, and a
verified policy decision answers the third. A UI may label this predicate
“Observed”; it must never label it “Verified agent identity.”

## Validate it locally

```bash
cd subtrees/rookery
./examples/alps-evidence/reproduce.sh
```

The script builds the canonical in-tree cilock binary, creates an ephemeral
test-only key, runs the attestor, and checks the decoded collection for the
predicate type, status vocabulary, and `enforcement: false`. When run under a
supported agent, the expected status is `detected`; a terminal or unsupported
platform may truthfully report `not-detected` or `unavailable`.

## How a verifier consumes this

It does not. The attestor deliberately implements no `Subjecter`, `Materialer`,
`Producer`, `BackReffer`, or `Exporter` interface, so it cannot select an
artifact, connect a verification graph, or satisfy a policy requirement.

Consumers may display it as bounded audit context linked by the surrounding
collection. Any policy or UI that treats its vendor, product, model, sandbox,
or fingerprint as authenticated identity is using the predicate incorrectly.

## Notes

- Linux reads `/proc`; macOS reads `KERN_PROCARGS2`. Other platforms publish a
  signed `unavailable` observation instead of failing the wrapped command.
- The nearest recognized ancestor wins. A deeper, outer agent cannot claim
  credit for a command driven by a nearer supported agent.
- Executables and configuration files are opened once, bounded, and checked as
  regular files. Symlinked config paths are refused; legitimate symlinked agent
  executables are resolved and rebound to the opened handle.
- Every agent-influenced predicate string is capped and marked when truncated.

## Gotchas

- `detected` does not mean authenticated. A process can choose a matching name.
- A configuration-derived model is a configured default, not proof of the model
  that served a session.
- `incomplete` means some ancestry was not examinable. It must not be rendered
  as `not-detected`.
- `unavailable` is signed data and does not make `cilock run` fail.
- Do not add subjects or backrefs. That would let self-description influence
  artifact selection or policy traversal.

## FAQ

### Can Pushgate require a particular coding agent or model from this predicate?

No. The observed process controls these values. Use authenticated workload or
agent principals at the signing boundary for identity, and independently
verified evidence for enforcement.

### Does this prove a human reviewed the change?

No. Human presence requires its own interactive ceremony. A process tree, TTY,
or agent name cannot establish it.

### Why record it at all?

It provides useful fleet, debugging, and audit context without overstating its
assurance: which tools appeared in delivery loops, which settings were visible,
and where observation was incomplete.

## See also

- [Agent, policy, and provenance contract](https://pushgate.dev/docs/agent-sandbox)
- [`environment`](./environment)
- [`git`](./git)
