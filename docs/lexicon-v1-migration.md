# Lexicon v1 Migration

Records the per-plugin `category:` migration from the pre-v1 informal vocabulary (`build`, `posture-scan`, `artifact-scan`, `statement`, `runtime`) to the canonical lexicon defined in `docs/lexicon-v1.md`.

Applied: 2026-05-26. Companion change: `attestation/detection/categories.go` closed-enum updated to the v1 lexicon; `attestation/detection/schema.go` gained `primary_category` field for multi-category detectors.

## Per-plugin mapping

| Plugin | Pre-v1 | v1 | primary_category | Rationale |
|---|---|---|---|---|
| asff | `[posture-scan]` | `[compliance-scan]` | — | mechanical rename |
| aws-codebuild | `[build]` | `[ci-context]` | — | CodeBuild captures runner identity, not the build itself |
| aws-config | `[posture-scan]` | `[compliance-scan]` | — | mechanical rename |
| aws-iid | `[build]` | `[ci-context]` | — | EC2 instance identity is runner context |
| docker | `[build]` | `[image-build]` | — | wraps `docker build` / `buildx`; image-specific is more precise than generic build |
| docker-bench | `[posture-scan]` | `[compliance-scan]` | — | mechanical rename |
| falco | `[runtime]` | `[runtime-event]` | — | clarified — events, not "runtime" generally |
| gcp-iit | `[build]` | `[ci-context]` | — | GCP instance identity token is runner context |
| git | `[build]` | `[source-checkout]` | — | VCS state capture is source-checkout, not build |
| github | `[build]` | `[ci-context]` | — | GitHub Actions environment is runner context |
| github-review | `[statement, posture-scan]` | `[code-review]` | — | review approvals are first-class in v1; `statement` collided with in-toto Statement envelope |
| gitlab | `[build]` | `[ci-context]` | — | GitLab CI environment is runner context |
| govulncheck | `[artifact-scan]` | `[vulnerability-scan]` | — | go vuln DB lookup is unambiguously vulnerability-scan |
| inspec | `[posture-scan]` | `[compliance-scan]` | — | mechanical rename |
| jenkins | `[build]` | `[ci-context]` | — | Jenkins env is runner context |
| kube-bench | `[posture-scan]` | `[compliance-scan]` | — | CIS Kubernetes benchmark is compliance |
| linkerd-check | `[posture-scan]` | `[compliance-scan]` | — | mesh health check against baseline |
| lockfiles | `[build]` | `[dependency-resolve]` | — | lockfile capture is dep resolution evidence |
| maven | `[build]` | `[build, dependency-resolve]` | `build` | maven projects build *and* resolve deps in one invocation |
| nessus | `[posture-scan]` | `[vulnerability-scan, compliance-scan]` | `vulnerability-scan` | Nessus is primarily a vuln scanner with compliance plugins |
| oci | `[build]` | `[image-build]` | — | OCI image manifest handling is image-build, not generic build |
| oscap | `[posture-scan]` | `[compliance-scan]` | — | OpenSCAP profile scan |
| pip-install | `[build]` | `[dependency-resolve]` | — | pip install is dep resolution, not build |
| prowler | `[posture-scan]` | `[compliance-scan]` | — | AWS CIS benchmark scan |
| sarif | `[artifact-scan]` | (removed) | — | format adapter; step intent comes from producing tool, not SARIF format |
| sbom | `[artifact-scan, posture-scan]` | `[sbom-generate]` | — | first-class sbom category in v1 |
| sinkhole-flows | `[build]` | `[dependency-verify]` | — | pip-witness sinkhole observes network during dep fetch to verify integrity |
| steampipe | `[posture-scan]` | `[compliance-scan]` | — | mechanical rename |
| test-results | `[artifact-scan]` | (removed) | — | format adapter for JUnit/CTRF; producer is the test command |
| trivy | `[artifact-scan, posture-scan]` | `[vulnerability-scan]` | — | trivy's primary mode is CVE scanning; config scan secondary |
| vex | `[statement]` | (removed) | — | format adapter; VEX can carry vex-consume or vulnerability-disclosure intent depending on producer |

## Decisions worth flagging for review

These migrations involved judgment calls that someone with closer knowledge of the plugin should sanity-check:

- **docker → `image-build`** (over `build`). The witness docker attestor specifically captures `docker build` / `buildx build`. Generic `build` would be wrong; `image-build` is the Tier 2 specialization that matches.
- **maven → `[build, dependency-resolve]`**. Maven invocations conflate compile + dependency resolution. Multi-category with `primary_category: build` matches how policy authors most often want to reference it. Alternative: split into a separate `maven-resolve` plugin.
- **nessus → `[vulnerability-scan, compliance-scan]`**. Nessus has plugins for both. The primary is `vulnerability-scan` because that's what most users invoke it for; compliance is the secondary mode.
- **sinkhole-flows → `dependency-verify`**. The pip-witness sinkhole observes network flows during package fetch to verify the supply chain. It's verification, not resolution. Distinct from `lockfiles` (which captures the resolved set itself).
- **github-review → `code-review`** (dropping `posture-scan`). The original `posture-scan` tag was an artifact of having no `code-review` category. With code-review now Tier 1, the dual-category is no longer needed.
- **sarif, vex, test-results → no category**. These are format adapters (`format_only: true` in their upstream block). Per `docs/lexicon-v1.md` composition rule 6, format adapters must omit `category:`. The cost: a `cilock run -a test-results -- go test` cannot auto-default `--step` and the user must pass it explicitly. The benefit: we don't claim step semantics we don't have.

## Categories no longer in use

Removed from the closed enum in `attestation/detection/categories.go`:

- `build` — replaced by tiered alternatives (`build` retained but now means *primary artifact production*, not the junk drawer)
- `posture-scan` — renamed to `compliance-scan` (jargon → plain)
- `artifact-scan` — split into `vulnerability-scan`, `secret-scan`, `sbom-generate`
- `statement` — collided with the in-toto Statement envelope term; specific cases became `code-review`, `vex-consume`, `vulnerability-disclosure`, `release-approve`
- `runtime` — renamed to `runtime-event` (specifies *what kind* of runtime evidence)

Any external consumer of the platform API that hardcoded the old names must update. Detector.yaml files outside this repo (private extensions) must migrate before they will parse against the v1 schema.

## Plugins still without a category

20 plugins ship attestors but no `detector.yaml` (listed in `docs/lexicon-v1.md` §"What's missing"). The next pass should assign categories to those, especially:

- `commandrun` → no category (it is meta — actual category comes from co-firing detectors against the wrapped argv)
- `configuration`, `environment`, `githubaction`, `githubwebhook` → `ci-context`
- `go-build` → `build`
- `secretscan` → `secret-scan`
- `slsa`, `link` → `provenance`
- `k8smanifest` → `manifest-validate`
- `system-packages` → `sbom-generate`
- `omnitrail`, `material`, `product` → no category (envelope wrappers / fingerprint riders)
- `policyverify` → `policy-eval`
- `vsa` → `release-approve`
- `inclusion-proof`, `jwt`, `structured-data` → no category (envelope/format adapters)
