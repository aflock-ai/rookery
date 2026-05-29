# cilock Step Category Lexicon v1

Canonical vocabulary for the `category:` field in `detector.yaml` files, used to:

1. Auto-default `--step` when the producer doesn't pass one.
2. Provide a shared lexicon between attestor authors and policy authors.

## Tier 1 — Core (19)

Every meaningful policy template should reference these. They form the lingua franca of pre-deploy attestation.

| Category | Definition | Example tools |
|---|---|---|
| `source-checkout` | Capture VCS state at the start of a pipeline run | git, jj, hg |
| `ci-context` | Identify the runner environment and OIDC identity | github-actions, gitlab-ci, jenkins, aws-codebuild, aws-iid, gcp-iit |
| `dependency-resolve` | Pin/resolve the transitive dependency set | npm ci, pip install, go mod, mvn resolve, lockfiles |
| `dependency-verify` | Verify acquired components (signature, provenance, advisory) | cosign verify-blob, sigstore-verify, pip-witness sinkhole |
| `build` | Produce the primary build artifact | go build, mvn package, cargo build, bazel |
| `unit-test` | In-process tests producing pass/fail evidence | go test, pytest, jest, junit |
| `integration-test` | Cross-component tests with external dependencies | testcontainers, playwright, cypress, k6 |
| `code-review` | Human/bot review and approval of proposed change | github-review, gerrit, gitlab MR approvals |
| `threat-model` | Architectural threat analysis and design review artifact | threagile, IriusRisk, OWASP Threat Dragon |
| `vulnerability-scan` | Find known CVEs in code, deps, or artifacts (pre-release) | trivy, govulncheck, grype, snyk, semgrep |
| `secret-scan` | Find leaked credentials in source or artifacts | gitleaks, trufflehog, detect-secrets |
| `compliance-scan` | Configuration scan against a control baseline | inspec, oscap, kube-bench, docker-bench, prowler, steampipe |
| `sbom-generate` | Produce a component inventory | syft, cdxgen, trivy sbom, mvn cyclonedx |
| `sbom-consume` | Verify an upstream SBOM against policy | dependency-track, sbomqs, scancode |
| `provenance` | Build-time provenance (how/where/from-what an artifact was built) | slsa attestor, buildx provenance, github-attestations |
| `policy-eval` | Evaluate policy (rego/sentinel/cue) over upstream evidence | conftest, opa eval, policyverify, checkov |
| `sign` | Cryptographic signature on artifacts or attestations | cosign, sigstore, gpg, notary, jarsigner |
| `publish` | Push artifacts to a registry/repository | docker push, npm publish, mvn deploy |
| `deploy` | Apply a release to a target environment | kubectl apply, helm upgrade, argocd sync, terraform apply |

## Tier 2 — Specialized (26)

Optional but standardized. Use when the domain calls for it.

| Category | Definition | Example tools |
|---|---|---|
| `lint` | Static analysis for style/correctness (non-security) | eslint, ruff, golangci-lint, shellcheck |
| `release-approve` | Human/automated authorization gate for release | github environment review, ServiceNow change |
| `archive` | Long-term preservation of artifacts and attestations | rekor, archivista, oras blob |
| `iac-plan` | Render an infrastructure change plan | terraform plan, pulumi preview, cdk diff |
| `iac-apply` | Apply infrastructure changes | terraform apply, pulumi up |
| `manifest-validate` | Validate k8s/helm/IaC manifests | helm lint, kubeval, kubeconform, datree |
| `image-build` | Build a container image specifically | docker build, buildah, kaniko, ko, jib |
| `image-scan` | Image-specific vuln/config scan | trivy image, grype, snyk container |
| `image-sign` | Sign a container image | cosign sign, notation |
| `package-publish` | Publish a library to a package registry | npm publish, twine, cargo publish, gem push |
| `runtime-event` | Production runtime security/behavior event | falco, tetragon, tracee |
| `runtime-vulnerability-detect` | CVE detection on running images or registry rescan | trivy operator, harbor scan, snyk monitor |
| `drift-detect` | Detect divergence between declared and actual state | argocd diff, terraform plan -refresh, driftctl |
| `asset-inventory` | Steady-state inventory of running components | k8s admission audit, cmdb sync |
| `vex-consume` | Ingest VEX advisories to suppress non-exploitable findings | openvex, vexctl |
| `vulnerability-disclosure` | Publish an advisory (CVE/GHSA/VEX) about own product | github security advisory, vexctl publish |
| `incident-response` | Live IR runbook execution and evidence collection | pagerduty runbooks, security playbooks |
| `rollback` | Revert a release | argocd rollback, helm rollback, kubectl rollout undo |
| `key-ceremony` | HSM rotation, secure-boot key install, PQC migration (emerging) | yubikey-attest, vendor HSM tools |
| `api-surface-check` | Detect breaking changes in public API surface | apidiff, semver-gen, openapi-diff |
| `model-train` | ML training run producing a model artifact | mlflow run, sagemaker train, kubeflow |
| `model-eval` | Evaluate model against test/safety harness | mlflow evaluate, garak, deepeval |
| `dataset-snapshot` | Pin training/eval dataset version | dvc, lakefs, mlflow datasets |
| `firmware-sign` | Sign firmware with secure-boot/HSM-backed keys | sbsign, mokutil, vendor HSM |
| `mobile-sign` | Sign mobile artifact with platform identity | xcrun codesign, gradle signingConfig, fastlane match |
| `mobile-submit` | Submit build to a mobile distribution channel | fastlane pilot/deliver, App Store Connect API |

## Tier 3 — Extension

Open-ended, declared in a repo-local `.cilock/commands.yaml`. Must be namespaced:

- `x-<name>` for one-off local categories (e.g., `x-game-day`, `x-data-migration`)
- `<org>.<name>` for organization conventions (e.g., `acme.dba-review`)

Tier 3 categories are **not warned on** by cilock and **not standardized**. When two organizations need the same one, propose promotion to Tier 2 via a PR to this document.

## Composition rules

1. **Tags, not enums.** `detector.yaml` uses `category: [list]`. A step can carry multiple categories when one exec satisfies multiple intents (e.g., `[sbom-generate, sign]` for a sign-the-SBOM step).
2. **`primary_category:` for auto-default.** When `category:` contains more than one entry, `primary_category:` (a single value, must appear in the list) determines the `--step` default. Required when ambiguous, optional when the list has one entry.
3. **Specialized beats Core for inference.** When both Tier 1 and Tier 2 categories match the observed argv, the more specific Tier 2 category wins (e.g., `image-build` over `build`).
4. **No SDLC-stage pinning.** Categories name the *kind* of step, not its pipeline position. `vulnerability-scan` can run pre-build (source SCA), post-build (artifact scan), or post-deploy (registry rescan — except that last case is `runtime-vulnerability-detect`). Stage is positional in the policy DAG.
5. **Tier 1 and Tier 2 names are reserved.** A detector.yaml that uses a Tier 1/2 name must mean what this document says it means. Repo-local extensions must use Tier 3 namespacing.
6. **Format adapters and modifiers carry no category.** Plugins that are envelope wrappers or fingerprint riders (`material`, `product`, `inclusion-proof`, `jwt`, `structured-data`, `commandrun`) MUST omit `category:` — they are not pipeline steps.

## Step name inference

When `--step` is not provided to `cilock run`, the step name is inferred as follows:

1. Run the detector engine against the observed argv.
2. Collect the union of `category:` values from all matching detectors.
3. Filter out Tier 3 (extension) categories *unless* no Tier 1/2 categories matched.
4. Prefer the most-specific match: Tier 2 > Tier 1.
5. If multiple equally-specific matches remain and any matched detector declares `primary_category:`, use that. Otherwise refuse with `E_STEP_INFERENCE_AMBIGUOUS`.
6. If no detector matched, refuse with `E_STEP_INFERENCE_NO_MATCH`.

On success, emit an info-level diagnostic (`I_STEP_INFERENCE_OK`) recording the inference chain (matched detector → category → step name) so verifiers can audit the choice.

## Adding a new category

Propose Tier 1 or Tier 2 additions via PR to this document. Acceptance criteria:

- **Tier 1**: Must apply across at least three of {web/microservices, mobile, ML/AI, embedded, IaC, data pipelines}, and represent a step nearly every policy template would reference.
- **Tier 2**: Must have at least two distinct real tools that produce evidence of this kind.
- **Tier 3**: No PR required. Define in repo-local `.cilock/commands.yaml`.

Rejection criteria:

- Pure SDLC-stage names (`pre-deploy-scan`, `post-build-verify`) — stage is positional, not categorical.
- Tool-specific names (`trivy-scan`, `cosign-sign`) — categories are tool-agnostic.

## Migration from pre-v1 categories

The pre-v1 lexicon used five informal categories (`build`, `posture-scan`, `artifact-scan`, `statement`, `runtime`). See `docs/lexicon-v1-migration.md` for the per-plugin mapping applied when this document was adopted.

## Changelog

- **v1.0** (2026-05-26) — initial lexicon. 19 Tier 1, 26 Tier 2 categories.
