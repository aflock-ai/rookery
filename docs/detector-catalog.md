# Detector catalog

Auto-generated from `plugins/attestors/*/detector.yaml`. Run
`./scripts/gen-detector-catalog.sh` to refresh.

Total: 32 detectors.

| Name | Gates | Trace | Description |
|------|-------|-------|-------------|
| `asff` | pre + post | `off` | Captures AWS Security Finding Format (ASFF) reports from AWS Security Hub (typically the output of `aws securityhub get-findings`). |
| `aws` | pre | `off` | Captures the AWS Instance Identity Document when running on EC2 (or any host that can reach the EC2 IMDS endpoint). |
| `aws-codebuild` | pre | `off` | Captures AWS CodeBuild context (project name, build ID, batch build ID, region) when running inside an AWS CodeBuild job. |
| `aws-config` | pre + post | `off` | Captures AWS Config compliance state for resources (output of `aws configservice get-compliance-details-by-config-rule` and related calls). |
| `docker` | pre + post | `full` | Captures docker build provenance, image references, and layer materials. |
| `docker-bench` | pre + post | `off` | Captures Docker Bench for Security CIS benchmark results. |
| `falco` | pre + post | `off` | Captures runtime security events from Falco (Cloud Native Computing Foundation runtime threat detection). |
| `gcp-iit` | pre | `off` | Captures the GCP Instance Identity Token / metadata server context when running on a GCE VM, GKE node, or other GCP-resident runner. |
| `git` | pre | `off` | Captures git repository state (commit, status, tags, signatures) when run inside a git checkout. |
| `github` | pre | `off` | Captures GitHub Actions runner context (workflow, job, run ID, repository, OIDC token claims) when running inside a GitHub Actions job. |
| `github-review` | pre | `off` | Snapshots GitHub PR review state for the current commit (or an explicit SHA/PR) via the GitHub REST API (token: GH_TOKEN/GITHUB_TOKEN, or `gh auth token` fallback). |
| `gitlab` | pre | `off` | Captures GitLab CI runner context (job, pipeline, project, runner, optional JWT) when running inside a GitLab CI job. |
| `go-build` | pre | `full` | Captures Go build provenance (module graph, vcs.revision, build settings) and persists a .gobuild.json sidecar per binary that survives strip(1). |
| `govulncheck` | pre + post | `off` | Captures Go call-graph-aware vulnerability scan results from `govulncheck`. |
| `inspec` | pre + post | `off` | Captures Chef InSpec compliance scan results. |
| `jenkins` | pre | `off` | Captures Jenkins runner context (job name, node, build ID, URL) when running inside a Jenkins pipeline. |
| `kube-bench` | pre + post | `off` | Captures kube-bench Kubernetes CIS benchmark results. |
| `linkerd-check` | pre + post | `off` | Captures Linkerd service mesh health checks (output of `linkerd check`). |
| `lockfiles` | pre | `off` | Captures dependency lockfile contents (npm/yarn/pnpm/go/Cargo/Python/Ruby) when present in the workspace. |
| `maven` | pre | `off` | Captures Maven project metadata (pom.xml coordinates, dependencies) when run in a Maven workspace. |
| `oci` | pre + post | `light` | Captures OCI image / artifact provenance from docker save, skopeo copy, or OCI image layouts. |
| `oscap` | pre + post | `off` | Captures OpenSCAP compliance / vulnerability scan results. |
| `pip-install` | pre + post | `full` | Captures Python package installation provenance (package name, version, resolved wheel) when `pip install` is invoked. |
| `prowler` | pre + post | `off` | Captures Prowler cloud security posture scan results (AWS / GCP / Azure). |
| `sarif` | post | `off` | Captures SARIF (Static Analysis Results Interchange Format) reports produced by scanners (CodeQL, Semgrep, Brakeman, etc.). |
| `sbom` | pre + post | `off` | Captures SPDX or CycloneDX SBOM documents produced by syft, cdxgen, or similar tools. |
| `scubagoggles` | pre + post | `off` | Captures the raw Google Workspace configuration collected by CISA ScubaGoggles (provider settings, not the verdict). |
| `sinkhole-flows` | pre | `off` | Captures HTTP(S) flows collected by the pip-witness sinkhole proxy (intended for pip install observability). |
| `steampipe` | pre + post | `off` | Captures Steampipe SQL-against-cloud-API scan results. |
| `test-results` | post | `off` | Captures JUnit XML test reports and CTRF JSON reports produced by test runners (go test -junit, pytest, jest, gradle, surefire, etc.). |
| `trivy` | pre + post | `off` | Captures Trivy vulnerability and misconfiguration scan results. |
| `vex` | post | `off` | Captures OpenVEX documents asserting vulnerability statuses (affected, not_affected, fixed, under_investigation). |

## Notes

- `pre` matches before the wrapped command runs (static argv/env/fs/probes).
- `post` matches after the command, using the exec trace + products + materials diff.
- `recommended_trace` tells the runtime how much eBPF tracing the attestor benefits from:
    - `off` — the attestor signs an output file; no tracing strengthens the claim.
    - `light` — only child argv is captured; correlates image refs etc.
    - `full` — full materials / network / file capture; needed for build-process attestations.
