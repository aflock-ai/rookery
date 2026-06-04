---
title: Step categories and --step inference
description: CI/lock names each pipeline step with a category from a closed lexicon (19 core + 26 specialized + namespaced extensions). When you don't pass --step, CI/lock infers it from the wrapped command. This page explains the lexicon and the inference rules.
sidebar_position: 8
---

# Step categories and `--step` inference

Every `cilock` run records a **step** — the kind of supply-chain activity the wrapped command represents (`build`, `vulnerability-scan`, `deploy`, …). Steps come from a **closed lexicon** so attestor authors and policy authors share one vocabulary: a policy that gates on `step == "build"` matches regardless of which tool produced the evidence.

## You usually don't pass `--step`

When you omit `--step`, CI/lock **infers it** from the wrapped command via the same catalog detectors that drive [auto-detection](./auto-detection-and-defaults). `cilock run -- go build ./...` infers `--step=build`; `cilock run -- trivy fs .` infers `vulnerability-scan`. Inference uses **command-intent matches only** (argv predicates) — it ignores ambient signals like a `.git/` directory, so the step reflects what you *ran*, not what happens to be on disk.

Two failure modes are reported with stable, machine-readable codes (human text + JSON via `--diagnose`):

- **`E_STEP_INFERENCE_NO_MATCH`** — no detector matched the command. Pass `--step` explicitly.
- **`E_STEP_INFERENCE_AMBIGUOUS`** — more than one category matched. Pass `--step` to disambiguate.

## The lexicon

A detector declares its `category:` (and `primary_category:` when it serves more than one). The lexicon is tiered:

### Tier 1 — Core (19)

The lingua franca of pre-deploy attestation; every policy template should recognize these:

`source-checkout` · `ci-context` · `dependency-resolve` · `dependency-verify` · `build` · `unit-test` · `integration-test` · `code-review` · `threat-model` · `vulnerability-scan` · `secret-scan` · `compliance-scan` · `sbom-generate` · `sbom-consume` · `provenance` · `policy-eval` · `sign` · `publish` · `deploy`

### Tier 2 — Specialized (26)

Standardized but optional, for when the domain calls for it — e.g. `lint`, `image-build`, `image-scan`, `image-sign`, `package-publish`, `runtime-event`, `runtime-vulnerability-detect`, `drift-detect`, `iac-plan`, `iac-apply`, `manifest-validate`, `release-approve`, `vex-consume`, `model-train`, `model-eval`, `dataset-snapshot`, `firmware-sign`, `mobile-sign`, and more.

### Tier 3 — Extension

Open-ended, declared in a repo-local `.cilock/commands.yaml` and **namespaced** so they never collide with the standard set:

- `x-<name>` for one-off local categories (e.g. `x-game-day`, `x-data-migration`)
- `<org>.<name>` for organization conventions (e.g. `acme.dba-review`)

Tier 3 categories are not standardized and not warned on. When two organizations need the same one, that's the signal to promote it to Tier 2.

## Why a closed enum

A free-text step field fragments into `build`, `Build`, `go-build`, `compile`, … and no policy can match across pipelines. A closed lexicon makes `step` a reliable join key between the evidence an attestor emits and the policy that verifies it, and lets CI/lock auto-default `--step` from the detector that fired.

## See also

- [Auto-detection and defaults](./auto-detection-and-defaults) — the same detectors choose attestors
- [Tools / detector catalog](../tools) — each tool's category
- [Policy verification](./policy-verification) — gating on `step`
