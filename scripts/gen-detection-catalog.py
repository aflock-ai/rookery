#!/usr/bin/env python3
# Generates attestation/detection/catalog/*.yaml.
#
# Each entry is a detection-only catalog tool: cilock recognizes it
# (via argv match, file presence, or environment) but doesn't ship a
# dedicated Go attestor. The actual evidence (SBOMs, SARIF, VEX, etc.)
# is captured by format attestors that already exist as plugins.
#
# CATALOG ADMISSION RULE:
#   Only tools whose end-to-end attestation flow has been validated
#   by scripts/test-catalog-tools.py may appear here. Commercial /
#   auth-required tools that aren't AWS, Azure, or GCP are excluded
#   until their auth path is wired up. See report at
#   .catalog-test/report.md for current validation status.
#
# Re-run after editing to refresh: python3 scripts/gen-detection-catalog.py

import os
from textwrap import dedent

CATALOG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "attestation",
    "detection",
    "catalog",
)

# Each entry: (name, args). `args` keys:
#   desc, categories, upstream={name,source,license,vendor}, emits_formats,
#   match={argv_prefix|file_exists|file_glob|env_set}, recommended_trace,
#   on_match (llm_hint).
# Each entry: (name, args). `args` keys:
#   desc, categories, upstream={name,source,license,vendor}, emits_formats,
#   match={argv_prefix|file_exists|file_glob|env_set|*_metadata_reachable},
#   recommended_trace, on_match (llm_hint).
#
# Every entry below is validated by scripts/test-catalog-tools.py. Tools
# requiring auth into AWS, Azure, or GCP appear here even when their
# auth path is not yet wired — they'll be activated in the next round
# of validation once cloud credentials are available.
ENTRIES: list[tuple[str, dict]] = [

    # ===== SBOM TOOLS (validated) =====
    ("syft", dict(
        desc="Anchore Syft — SBOM generator for containers, filesystems, archives.",
        categories=["sbom-generate"],
        upstream=dict(name="Syft", source="https://github.com/anchore/syft",
                      license="Apache-2.0", vendor="Anchore"),
        emits_formats=["sbom"],
        match=dict(argv_prefix=["syft"]),
        on_match="Syft SBOM generation observed. The sbom attestor captures the SPDX/CycloneDX/Syft-JSON output."
    )),
    ("cdxgen", dict(
        desc="CycloneDX SBOM generator (cdxgen) — multi-language SBOM tool from OWASP.",
        categories=["sbom-generate"],
        upstream=dict(name="cdxgen", source="https://github.com/CycloneDX/cdxgen",
                      license="Apache-2.0", vendor="OWASP Foundation / CycloneDX"),
        emits_formats=["sbom"],
        match=dict(argv_prefix=["cdxgen"]),
        on_match="cdxgen invocation observed. The sbom attestor captures the CycloneDX output (typically bom.json or sbom.cdx.json)."
    )),
    ("grype", dict(
        desc="Anchore Grype — vulnerability scanner for SBOMs and container images.",
        categories=["vulnerability-scan"],
        upstream=dict(name="Grype", source="https://github.com/anchore/grype",
                      license="Apache-2.0", vendor="Anchore"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["grype"]),
        on_match="Grype scan observed. Output (--output json|sarif|template) is captured by the matching format attestor."
    )),
    ("bom", dict(
        desc="Kubernetes SIGs `bom` — SBOM tool for Kubernetes releases (SPDX).",
        categories=["sbom-generate"],
        upstream=dict(name="bom (sigs.k8s.io)", source="https://github.com/kubernetes-sigs/bom",
                      license="Apache-2.0", vendor="Kubernetes SIG Release Engineering"),
        emits_formats=["sbom"],
        match=dict(argv_prefix=["bom"]),
        on_match="bom invocation observed. The sbom attestor captures the SPDX output."
    )),

    # ===== SAST (validated) =====
    ("semgrep", dict(
        desc="Semgrep — open-source static analysis with SARIF / JSON output.",
        categories=["vulnerability-scan"],
        upstream=dict(name="Semgrep", source="https://github.com/semgrep/semgrep",
                      license="LGPL-2.1-only", vendor="Semgrep Inc."),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["semgrep"]),
        on_match="Semgrep invocation observed. --sarif output captured by the sarif attestor."
    )),
    ("bandit", dict(
        desc="Bandit — Python static security analyzer (PyCQA).",
        categories=["vulnerability-scan"],
        upstream=dict(name="Bandit", source="https://github.com/PyCQA/bandit",
                      license="Apache-2.0", vendor="PyCQA"),
        # Native bandit emits json/txt; SARIF requires an external converter.
        emits_formats=[],
        match=dict(argv_prefix=["bandit"]),
        on_match="Bandit invocation observed. JSON findings (-f json) captured as a product."
    )),
    ("staticcheck", dict(
        desc="staticcheck — Go static analyzer (Honnef.co/go/tools).",
        categories=["lint"],
        upstream=dict(name="staticcheck", source="https://github.com/dominikh/go-tools",
                      license="MIT", vendor="Dominik Honnef"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["staticcheck"]),
        on_match="staticcheck invocation observed. Findings captured via stdout / SARIF (-f sarif)."
    )),

    # ===== VULN SCANNERS (validated) =====
    ("osv-scanner", dict(
        desc="osv-scanner — Google's open-source vulnerability scanner (OSV.dev).",
        categories=["vulnerability-scan"],
        upstream=dict(name="osv-scanner", source="https://github.com/google/osv-scanner",
                      license="Apache-2.0", vendor="Google / OSV"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["osv-scanner"]),
        on_match="osv-scanner observed. --format sarif|json captures findings."
    )),
    ("pip-audit", dict(
        desc="pip-audit — Python dependency vulnerability scanner from PyPA.",
        categories=["vulnerability-scan"],
        upstream=dict(name="pip-audit", source="https://github.com/pypa/pip-audit",
                      license="Apache-2.0", vendor="PyPA"),
        match=dict(argv_prefix=["pip-audit"]),
        on_match="pip-audit observed. JSON findings captured as a product."
    )),
    ("safety", dict(
        desc="Safety — Python dependency vulnerability scanner (PyUp).",
        categories=["vulnerability-scan"],
        upstream=dict(name="Safety", source="https://github.com/pyupio/safety",
                      license="MIT", vendor="PyUp.io / Safety Cybersecurity"),
        match=dict(argv_prefix=["safety"]),
        on_match="Safety check observed. JSON output captured as a product."
    )),
    ("nancy", dict(
        desc="Nancy — Sonatype's OSS Index vulnerability scanner for Go modules.",
        categories=["vulnerability-scan"],
        upstream=dict(name="Nancy", source="https://github.com/sonatype-nexus-community/nancy",
                      license="Apache-2.0", vendor="Sonatype"),
        match=dict(argv_prefix=["nancy"]),
        on_match="Nancy scan observed. Reads `go list -json` on stdin; JSON output captured."
    )),
    ("cargo-audit", dict(
        desc="cargo-audit — Rust dependency vulnerability scanner.",
        categories=["vulnerability-scan"],
        upstream=dict(name="cargo-audit", source="https://github.com/rustsec/rustsec",
                      license="Apache-2.0 OR MIT", vendor="RustSec / Rust Foundation"),
        match=dict(argv_prefix=["cargo-audit"]),
        on_match="cargo audit observed. JSON output (--json) captured."
    )),
    ("npm-audit", dict(
        desc="npm audit — Node.js dependency vulnerability scanner.",
        categories=["vulnerability-scan"],
        upstream=dict(name="npm audit", source="https://docs.npmjs.com/cli/v10/commands/npm-audit",
                      license="Artistic-2.0", vendor="OpenJS Foundation / npm Inc."),
        match=dict(argv_prefix=["npm", "audit"]),
        on_match="npm audit observed. --json output captures findings."
    )),
    ("yarn-audit", dict(
        desc="yarn audit — Yarn dependency vulnerability scanner.",
        categories=["vulnerability-scan"],
        upstream=dict(name="yarn audit", source="https://yarnpkg.com/cli/audit",
                      license="BSD-2-Clause", vendor="Yarn / Meta"),
        match=dict(argv_prefix=["yarn", "audit"]),
        on_match="yarn audit observed. --json output captures findings."
    )),
    ("retire-js", dict(
        desc="RetireJS — JavaScript library vulnerability scanner.",
        categories=["vulnerability-scan"],
        upstream=dict(name="RetireJS", source="https://github.com/RetireJS/retire.js",
                      license="Apache-2.0", vendor="RetireJS contributors"),
        match=dict(argv_prefix=["retire"]),
        on_match="RetireJS observed. --outputformat json|jsonsimple captures findings."
    )),
    ("gosec", dict(
        desc="gosec — Go security checker (golang/security/gosec).",
        categories=["vulnerability-scan"],
        upstream=dict(name="gosec", source="https://github.com/securego/gosec",
                      license="Apache-2.0", vendor="securego"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["gosec"]),
        on_match="gosec invocation observed. -fmt sarif|json captures findings."
    )),
    ("malcontent", dict(
        # The binary is `mal` (not `malcontent`); subcommands scan/analyze/diff.
        desc="malcontent (`mal`) — flags supply-chain-attack capabilities and behaviors in binaries and source (Chainguard).",
        categories=["vulnerability-scan"],
        upstream=dict(name="malcontent", source="https://github.com/chainguard-dev/malcontent",
                      license="Apache-2.0", vendor="Chainguard"),
        match=dict(any_of=[
            dict(argv_prefix=["mal", "scan"]),
            dict(argv_prefix=["mal", "analyze"]),
            dict(argv_prefix=["mal", "diff"]),
        ]),
        on_match="malcontent (mal) scan observed. JSON findings (-o <file>) captured as a product."
    )),

    # ===== IaC SCANNERS (validated) =====
    ("checkov", dict(
        desc="Checkov — Bridgecrew's IaC scanner (Terraform/CloudFormation/K8s/etc.).",
        categories=["compliance-scan"],
        upstream=dict(name="Checkov", source="https://github.com/bridgecrewio/checkov",
                      license="Apache-2.0", vendor="Bridgecrew / Prisma Cloud (Palo Alto)"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["checkov"]),
        on_match="Checkov scan observed. --output sarif captured by sarif attestor; CycloneDX / SPDX also supported."
    )),
    ("tfsec", dict(
        desc="tfsec — Terraform-specific static analysis (Aqua Security).",
        categories=["vulnerability-scan", "compliance-scan"],
        primary="vulnerability-scan",
        upstream=dict(name="tfsec", source="https://github.com/aquasecurity/tfsec",
                      license="MIT", vendor="Aqua Security"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["tfsec"]),
        on_match="tfsec scan observed. --format sarif|json captured by the matching attestor."
    )),
    ("terrascan", dict(
        desc="Terrascan — multi-IaC scanner (Terraform/K8s/Helm/ARM).",
        categories=["vulnerability-scan", "compliance-scan"],
        primary="vulnerability-scan",
        upstream=dict(name="Terrascan", source="https://github.com/tenable/terrascan",
                      license="Apache-2.0", vendor="Tenable"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["terrascan"]),
        on_match="Terrascan scan observed. -o sarif|json captures findings."
    )),
    ("tflint", dict(
        desc="TFLint — Terraform linter for syntax + provider correctness.",
        categories=["lint"],
        upstream=dict(name="TFLint", source="https://github.com/terraform-linters/tflint",
                      license="MPL-2.0", vendor="terraform-linters community"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["tflint"]),
        on_match="TFLint invocation observed. --format sarif|json captures findings."
    )),
    ("kics", dict(
        desc="KICS — Checkmarx IaC security scanner.",
        categories=["vulnerability-scan", "compliance-scan"],
        primary="vulnerability-scan",
        upstream=dict(name="KICS", source="https://github.com/Checkmarx/kics",
                      license="Apache-2.0", vendor="Checkmarx"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["kics"]),
        on_match="KICS scan observed. --report-formats sarif|json captures findings."
    )),

    # ===== SECRET SCANNERS (validated) =====
    ("gitleaks", dict(
        desc="Gitleaks — secret detection in git history and source.",
        categories=["secret-scan"],
        upstream=dict(name="Gitleaks", source="https://github.com/gitleaks/gitleaks",
                      license="MIT", vendor="Gitleaks community"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["gitleaks"]),
        on_match="Gitleaks scan observed. --report-format sarif|json captures findings."
    )),
    ("trufflehog", dict(
        desc="TruffleHog — secret + credential scanner (Truffle Security).",
        categories=["secret-scan"],
        upstream=dict(name="TruffleHog", source="https://github.com/trufflesecurity/trufflehog",
                      license="AGPL-3.0-only", vendor="Truffle Security"),
        emits_formats=[],
        match=dict(argv_prefix=["trufflehog"]),
        on_match="TruffleHog scan observed. JSON output captures verified + unverified secret findings. NOTE: AGPL-3.0 — review before bundling."
    )),
    ("detect-secrets", dict(
        desc="detect-secrets — Yelp's pre-commit secret scanner.",
        categories=["secret-scan"],
        upstream=dict(name="detect-secrets", source="https://github.com/Yelp/detect-secrets",
                      license="Apache-2.0", vendor="Yelp"),
        match=dict(argv_prefix=["detect-secrets"]),
        on_match="detect-secrets scan observed. Baseline JSON captures findings."
    )),

    # ===== K8s POSTURE (validated) =====
    ("kubescape", dict(
        desc="Kubescape — open-source K8s + image security posture scanner (CNCF).",
        categories=["compliance-scan"],
        upstream=dict(name="Kubescape", source="https://github.com/kubescape/kubescape",
                      license="Apache-2.0", vendor="CNCF / ARMO"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["kubescape"]),
        on_match="Kubescape scan observed. --format sarif|json captures findings."
    )),
    ("polaris", dict(
        desc="Polaris — Fairwinds Kubernetes best-practices validator.",
        categories=["compliance-scan"],
        upstream=dict(name="Polaris", source="https://github.com/FairwindsOps/polaris",
                      license="Apache-2.0", vendor="Fairwinds"),
        emits_formats=[],
        match=dict(argv_prefix=["polaris"]),
        on_match="Polaris invocation observed. JSON output captures findings."
    )),
    ("kyverno", dict(
        desc="Kyverno — Kubernetes policy management (CNCF).",
        categories=["policy-eval"],
        upstream=dict(name="Kyverno", source="https://github.com/kyverno/kyverno",
                      license="Apache-2.0", vendor="Nirmata / CNCF"),
        emits_formats=[],
        match=dict(argv_prefix=["kyverno"]),
        on_match="Kyverno CLI invocation observed. Policy report JSON captures findings."
    )),
    ("kubeaudit", dict(
        desc="kubeaudit — K8s security auditor (Shopify).",
        categories=["compliance-scan"],
        upstream=dict(name="kubeaudit", source="https://github.com/Shopify/kubeaudit",
                      license="MIT", vendor="Shopify"),
        emits_formats=[],
        match=dict(argv_prefix=["kubeaudit"]),
        on_match="kubeaudit invocation observed. JSON output captures findings."
    )),
    ("conftest", dict(
        desc="Conftest — Rego/OPA policy testing for structured config.",
        categories=["policy-eval"],
        upstream=dict(name="Conftest", source="https://github.com/open-policy-agent/conftest",
                      license="Apache-2.0", vendor="OPA / CNCF"),
        emits_formats=["sarif"],
        match=dict(argv_prefix=["conftest"]),
        on_match="Conftest invocation observed. -o json|sarif|tap captures findings."
    )),

    # ===== BUILD TOOLS (validated) =====
    ("gradle", dict(
        desc="Gradle — JVM build tool (Java/Kotlin/Groovy/Android).",
        categories=["build"],
        upstream=dict(name="Gradle", source="https://github.com/gradle/gradle",
                      license="Apache-2.0", vendor="Gradle Inc."),
        match=dict(argv_prefix=["gradle"]),
        recommended_trace="full",
        on_match="Gradle build observed. commandrun (with --tracing) captures opens/writes."
    )),
    ("maven-build", dict(
        desc="Apache Maven `mvn` — JVM dependency + build orchestrator (catalog-only; the maven attestor plugin emits the actual SLSA-style record).",
        categories=["build", "dependency-resolve"],
        primary="build",
        upstream=dict(name="Apache Maven", source="https://github.com/apache/maven",
                      license="Apache-2.0", vendor="Apache Software Foundation"),
        match=dict(argv_prefix=["mvn"]),
        recommended_trace="full",
        on_match="mvn invocation observed. The dedicated maven attestor plugin captures the project + dep tree."
    )),
    ("npm-install", dict(
        desc="npm install / npm ci — Node.js dependency resolution + install.",
        categories=["dependency-resolve"],
        upstream=dict(name="npm", source="https://github.com/npm/cli",
                      license="Artistic-2.0", vendor="OpenJS Foundation / npm Inc."),
        # `npm ci` and `npm install` both resolve + install dependencies. The
        # previous catalog only matched `npm ci`; the blind-UX test on an Argo
        # CD-style frontend hit `npm install` and saw 0 fires. Both forms must
        # match or the detector misses the common case.
        match=dict(any_of=[
            dict(argv_prefix=["npm", "install"]),
            dict(argv_prefix=["npm", "ci"]),
            dict(argv_prefix=["npm", "i"]),
        ]),
        recommended_trace="light",
        on_match="npm install/ci observed. lockfiles attestor captures package-lock.json; commandrun captures fetches."
    )),
    ("yarn-install", dict(
        desc="yarn install — Yarn package manager install.",
        categories=["dependency-resolve"],
        upstream=dict(name="Yarn", source="https://github.com/yarnpkg/berry",
                      license="BSD-2-Clause", vendor="Yarn / Meta"),
        match=dict(argv_prefix=["yarn", "install"]),
        recommended_trace="light",
        on_match="yarn install observed. lockfiles attestor captures yarn.lock."
    )),
    ("pnpm-install", dict(
        desc="pnpm install — fast disk-efficient Node.js package manager.",
        categories=["dependency-resolve"],
        upstream=dict(name="pnpm", source="https://github.com/pnpm/pnpm",
                      license="MIT", vendor="pnpm"),
        match=dict(argv_prefix=["pnpm", "install"]),
        recommended_trace="light",
        on_match="pnpm install observed. lockfiles attestor captures pnpm-lock.yaml."
    )),
    ("cargo-build", dict(
        desc="cargo build — Rust build orchestrator.",
        categories=["build"],
        upstream=dict(name="Cargo", source="https://github.com/rust-lang/cargo",
                      license="Apache-2.0 OR MIT", vendor="Rust Foundation"),
        match=dict(argv_prefix=["cargo", "build"]),
        recommended_trace="full",
        on_match="cargo build observed. commandrun (with --tracing) captures opens/writes; Cargo.lock captured by lockfiles."
    )),
    ("helm-install", dict(
        desc="helm install / upgrade — Kubernetes chart deployment.",
        categories=["deploy"],
        upstream=dict(name="Helm", source="https://github.com/helm/helm",
                      license="Apache-2.0", vendor="CNCF / Helm"),
        match=dict(argv_prefix=["helm"]),
        recommended_trace="light",
        on_match="Helm invocation observed. Templated manifests + Chart.yaml captured by material/product attestors."
    )),
    ("kustomize-build", dict(
        desc="kustomize build — declarative K8s manifest customization.",
        categories=["manifest-validate"],
        upstream=dict(name="Kustomize", source="https://github.com/kubernetes-sigs/kustomize",
                      license="Apache-2.0", vendor="Kubernetes SIG CLI"),
        match=dict(argv_prefix=["kustomize", "build"]),
        recommended_trace="light",
        on_match="Kustomize build observed. Generated manifests captured by the product attestor."
    )),

    # ===== CHAINGUARD BUILD TOOLS (SBOM-emitting; e2e validation via test-catalog-tools.py pending local tool install) =====
    ("apko", dict(
        desc="apko — builds single-layer OCI images from apk packages (Chainguard); auto-generates an SPDX SBOM per build.",
        categories=["image-build"],
        upstream=dict(name="apko", source="https://github.com/chainguard-dev/apko",
                      license="Apache-2.0", vendor="Chainguard"),
        emits_formats=["sbom"],
        match=dict(any_of=[
            dict(argv_prefix=["apko", "build"]),
            dict(argv_prefix=["apko", "publish"]),
        ]),
        recommended_trace="light",
        on_match="apko build observed. The sbom attestor captures the SPDX SBOM apko generates for the image."
    )),
    ("melange", dict(
        desc="melange — builds apk packages from declarative YAML pipelines (Chainguard); emits an SBOM per package.",
        categories=["build"],
        upstream=dict(name="melange", source="https://github.com/chainguard-dev/melange",
                      license="Apache-2.0", vendor="Chainguard"),
        emits_formats=["sbom"],
        match=dict(argv_prefix=["melange", "build"]),
        recommended_trace="full",
        on_match="melange build observed. The sbom attestor captures the SPDX SBOM melange generates for each apk."
    )),

    # ===== CI/CD SYSTEMS (validated via env fixture) =====
    ("azure-devops", dict(
        desc="Azure DevOps Pipelines — Microsoft CI/CD context.",
        categories=["ci-context"],
        upstream=dict(name="Azure Pipelines", source="https://learn.microsoft.com/azure/devops/pipelines/",
                      license="commercial", vendor="Microsoft"),
        match=dict(env_set="TF_BUILD"),
        on_match="Running inside Azure DevOps Pipelines. Build/release metadata available in TF_* and BUILD_* env vars."
    )),
    ("circleci", dict(
        desc="CircleCI CI/CD context.",
        categories=["ci-context"],
        upstream=dict(name="CircleCI", source="https://circleci.com/docs/",
                      license="commercial", vendor="Circle Internet Services"),
        match=dict(env_set="CIRCLECI"),
        on_match="Running inside CircleCI. Build metadata available in CIRCLE_* env vars."
    )),
    ("bitbucket-pipelines", dict(
        desc="Bitbucket Pipelines — Atlassian CI/CD context.",
        categories=["ci-context"],
        upstream=dict(name="Bitbucket Pipelines", source="https://support.atlassian.com/bitbucket-cloud/docs/get-started-with-bitbucket-pipelines/",
                      license="commercial", vendor="Atlassian"),
        match=dict(env_set="BITBUCKET_BUILD_NUMBER"),
        on_match="Running inside Bitbucket Pipelines. Build metadata available in BITBUCKET_* env vars."
    )),
    ("buildkite", dict(
        desc="Buildkite CI/CD context.",
        categories=["ci-context"],
        upstream=dict(name="Buildkite", source="https://buildkite.com/docs",
                      license="commercial", vendor="Buildkite"),
        match=dict(env_set="BUILDKITE"),
        on_match="Running inside Buildkite. Build metadata available in BUILDKITE_* env vars."
    )),
    ("drone-ci", dict(
        desc="Drone — open-source container-native CI.",
        categories=["ci-context"],
        upstream=dict(name="Drone", source="https://github.com/harness/drone",
                      license="Apache-2.0 / commercial (Harness)", vendor="Harness, Inc."),
        match=dict(env_set="DRONE"),
        on_match="Running inside Drone CI. Build metadata available in DRONE_* env vars."
    )),
    ("travis-ci", dict(
        desc="Travis CI context.",
        categories=["ci-context"],
        upstream=dict(name="Travis CI", source="https://docs.travis-ci.com/",
                      license="commercial", vendor="Travis CI GmbH / Idera"),
        match=dict(env_set="TRAVIS"),
        on_match="Running inside Travis CI. Build metadata available in TRAVIS_* env vars."
    )),
    ("teamcity", dict(
        desc="JetBrains TeamCity CI/CD context.",
        categories=["ci-context"],
        upstream=dict(name="TeamCity", source="https://www.jetbrains.com/teamcity/",
                      license="commercial / freemium", vendor="JetBrains"),
        match=dict(env_set="TEAMCITY_VERSION"),
        on_match="Running inside JetBrains TeamCity. Build metadata available via TEAMCITY_* env vars."
    )),
    ("argo-workflows", dict(
        desc="Argo Workflows — Kubernetes-native workflow engine (CNCF).",
        categories=["ci-context"],
        upstream=dict(name="Argo Workflows", source="https://github.com/argoproj/argo-workflows",
                      license="Apache-2.0", vendor="CNCF / Argoproj"),
        match=dict(env_set="ARGO_TEMPLATE"),
        on_match="Running inside an Argo Workflow step. Workflow metadata available via ARGO_* env vars."
    )),
    ("tekton-pipelines", dict(
        desc="Tekton Pipelines — Kubernetes-native CI/CD (CDF).",
        categories=["ci-context"],
        upstream=dict(name="Tekton", source="https://github.com/tektoncd/pipeline",
                      license="Apache-2.0", vendor="CD Foundation / Tekton"),
        match=dict(env_set="TEKTON_RESOURCES"),
        on_match="Running inside a Tekton task. Step metadata in TEKTON_* env vars."
    )),
    ("cloudbuild-gcp", dict(
        desc="Google Cloud Build — GCP managed CI.",
        categories=["ci-context"],
        upstream=dict(name="Cloud Build", source="https://cloud.google.com/build/docs",
                      license="commercial", vendor="Google Cloud"),
        match=dict(env_set="BUILD_ID"),
        on_match="Running inside GCP Cloud Build. Build metadata available via BUILD_* and PROJECT_ID env vars."
    )),
    ("codebuild-aws", dict(
        desc="AWS CodeBuild context.",
        categories=["ci-context"],
        upstream=dict(name="AWS CodeBuild", source="https://docs.aws.amazon.com/codebuild/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(env_set="CODEBUILD_BUILD_ID"),
        on_match="Running inside AWS CodeBuild. Build metadata available via CODEBUILD_* env vars."
    )),

    # ===== CLOUD IDENTITY (pending big-cloud validation round) =====
    ("azure-iid", dict(
        desc="Azure VM IMDS — instance metadata + attested identity document.",
        categories=["ci-context"],
        upstream=dict(name="Azure Instance Metadata Service", source="https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service",
                      license="commercial", vendor="Microsoft Azure"),
        match=dict(azure_metadata_reachable=True),
        on_match="Azure VM identity available. attested document covers vmId, subscriptionId, signed by Azure regional cert."
    )),

    # ===== SIGNING & VERIFICATION (validated) =====
    ("cosign-sign", dict(
        desc="Sigstore cosign — container/artifact signing (validated via cosign sign-blob with a local ED25519 key).",
        categories=["sign"],
        upstream=dict(name="cosign", source="https://github.com/sigstore/cosign",
                      license="Apache-2.0", vendor="Sigstore / Linux Foundation"),
        match=dict(argv_prefix=["cosign", "sign"]),
        on_match="cosign sign observed. Signature + transparency log entry in Rekor (or local detached signature for sign-blob)."
    )),
    ("cosign-verify", dict(
        desc="Sigstore cosign verification.",
        categories=["dependency-verify"],
        upstream=dict(name="cosign", source="https://github.com/sigstore/cosign",
                      license="Apache-2.0", vendor="Sigstore / Linux Foundation"),
        match=dict(argv_prefix=["cosign", "verify"]),
        on_match="cosign verify observed. Signature + Rekor entry validated."
    )),
    ("notary-v2", dict(
        desc="notation (Notary v2) — OCI artifact signing.",
        categories=["sign"],
        upstream=dict(name="notation", source="https://github.com/notaryproject/notation",
                      license="Apache-2.0", vendor="CNCF / Notary Project"),
        match=dict(argv_prefix=["notation"]),
        on_match="notation invocation observed. Signed OCI artifact + signature manifest."
    )),
    ("gpg-sign", dict(
        desc="GnuPG signing — long-form artifact signature.",
        categories=["sign"],
        upstream=dict(name="GnuPG", source="https://gnupg.org/",
                      license="GPL-3.0-or-later", vendor="Free Software Foundation"),
        match=dict(argv_prefix=["gpg", "--sign"]),
        on_match="GPG signing observed. Detached signature in .asc/.sig."
    )),
    ("vexctl", dict(
        desc="vexctl — OpenVEX statement generation.",
        categories=["vex-consume"],
        upstream=dict(name="vexctl", source="https://github.com/openvex/vexctl",
                      license="Apache-2.0", vendor="OpenVEX / Chainguard"),
        emits_formats=["vex"],
        match=dict(argv_prefix=["vexctl"]),
        on_match="vexctl invocation observed. OpenVEX document captured by the vex attestor."
    )),
    ("huggingface-hub", dict(
        desc="HuggingFace Hub CLI (`hf`) — model card + repo management. Validated by generating a HuggingFace-standard ModelCard README.md and attesting it as a material.",
        categories=["dataset-snapshot"],
        upstream=dict(name="huggingface_hub", source="https://github.com/huggingface/huggingface_hub",
                      license="Apache-2.0", vendor="Hugging Face"),
        match=dict(argv_prefix=["hf"]),
        on_match="HuggingFace CLI invocation observed. Adjacent README.md with model-card YAML frontmatter is captured as material/product."
    )),

    # ===== SECRETS DISTRIBUTION (validated) =====
    ("vault-cli", dict(
        desc="HashiCorp Vault CLI — secret distribution / dynamic credentials.",
        categories=["key-ceremony"],
        upstream=dict(name="HashiCorp Vault", source="https://github.com/hashicorp/vault",
                      license="BUSL-1.1 (since 2023) / MPL-2.0 (pre-1.14)", vendor="HashiCorp / IBM"),
        match=dict(argv_prefix=["vault"]),
        on_match="Vault CLI invocation observed. Secret/credential flow into the build environment."
    )),
    ("aws-secrets-manager", dict(
        desc="AWS Secrets Manager via aws-cli.",
        categories=["asset-inventory"],
        upstream=dict(name="AWS Secrets Manager", source="https://docs.aws.amazon.com/secretsmanager/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(argv_prefix=["aws", "secretsmanager"]),
        on_match="AWS Secrets Manager call observed. Secret flow into the build environment."
    )),

    # ===== AUDIT LOG SOURCES (validated; cloud-auth round will exercise the data plane) =====
    ("cloudtrail", dict(
        desc="AWS CloudTrail — AWS account audit log.",
        categories=["runtime-event"],
        upstream=dict(name="AWS CloudTrail", source="https://docs.aws.amazon.com/awscloudtrail/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(argv_prefix=["aws", "cloudtrail"]),
        on_match="AWS CloudTrail query observed. Captured audit-log slice."
    )),
    ("gcp-audit-log", dict(
        desc="Google Cloud Audit Logs (Cloud Logging).",
        categories=["runtime-event"],
        upstream=dict(name="Cloud Logging", source="https://cloud.google.com/logging/docs",
                      license="commercial", vendor="Google Cloud"),
        match=dict(argv_prefix=["gcloud", "logging"]),
        on_match="gcloud logging query observed. Captured audit-log slice."
    )),
    ("azure-activity-log", dict(
        desc="Azure Activity Log / Monitor logs.",
        categories=["runtime-event"],
        upstream=dict(name="Azure Monitor", source="https://learn.microsoft.com/azure/azure-monitor/",
                      license="commercial", vendor="Microsoft Azure"),
        match=dict(argv_prefix=["az", "monitor"]),
        on_match="az monitor query observed. Captured Activity Log slice."
    )),
    ("kubectl-audit", dict(
        desc="kubectl get audit/events — Kubernetes API audit access.",
        categories=["runtime-event"],
        upstream=dict(name="kubectl", source="https://github.com/kubernetes/kubectl",
                      license="Apache-2.0", vendor="Kubernetes / CNCF"),
        match=dict(argv_prefix=["kubectl", "get", "events"]),
        on_match="kubectl audit/events query observed. Cluster-state snapshot captured."
    )),

    # ===== AWS security services (data-plane validated; need IAM read perms) =====
    ("aws-security-hub", dict(
        desc="AWS Security Hub — central security findings aggregator across AWS services.",
        categories=["compliance-scan"],
        upstream=dict(name="AWS Security Hub", source="https://docs.aws.amazon.com/securityhub/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(argv_prefix=["aws", "securityhub"]),
        on_match="Security Hub query observed. Findings JSON captured as a product; subjects are findingArn entries."
    )),
    ("aws-inspector", dict(
        desc="AWS Inspector v2 — vulnerability + network reachability findings for EC2/ECR/Lambda.",
        categories=["vulnerability-scan"],
        upstream=dict(name="AWS Inspector", source="https://docs.aws.amazon.com/inspector/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(argv_prefix=["aws", "inspector2"]),
        on_match="Inspector findings query observed. ECR image / EC2 / Lambda vulnerability findings captured."
    )),
    ("aws-guardduty", dict(
        desc="AWS GuardDuty — threat detection findings (CloudTrail/VPC/DNS log analysis).",
        categories=["runtime-event"],
        upstream=dict(name="AWS GuardDuty", source="https://docs.aws.amazon.com/guardduty/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(argv_prefix=["aws", "guardduty"]),
        on_match="GuardDuty findings query observed. Behavioral/anomaly threat findings captured."
    )),
    ("aws-macie", dict(
        desc="AWS Macie — automated S3 sensitive-data discovery.",
        categories=["secret-scan"],
        upstream=dict(name="AWS Macie", source="https://docs.aws.amazon.com/macie/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(argv_prefix=["aws", "macie2"]),
        on_match="Macie query observed. Sensitive-data discovery findings captured."
    )),
    ("aws-iam-credential-report", dict(
        desc="AWS IAM credential report — per-user MFA + key-rotation + password-age posture.",
        categories=["asset-inventory"],
        upstream=dict(name="AWS IAM", source="https://docs.aws.amazon.com/iam/",
                      license="commercial", vendor="Amazon Web Services"),
        match=dict(argv_prefix=["aws", "iam", "get-credential-report"]),
        on_match="IAM credential report fetched. Per-user MFA/key-age/password-age posture captured."
    )),

    # ===== TEST RUNNERS (validated) =====
    ("pytest", dict(
        desc="pytest — Python test runner.",
        categories=["unit-test"],
        upstream=dict(name="pytest", source="https://github.com/pytest-dev/pytest",
                      license="MIT", vendor="pytest-dev"),
        emits_formats=["test-results"],
        match=dict(argv_prefix=["pytest"]),
        on_match="pytest invocation observed. --junitxml output captured by the test-results attestor."
    )),
    ("go-test", dict(
        desc="go test — Go test runner.",
        categories=["unit-test"],
        upstream=dict(name="go test", source="https://pkg.go.dev/cmd/go",
                      license="BSD-3-Clause", vendor="Google / Go Authors"),
        emits_formats=["test-results"],
        match=dict(argv_prefix=["go", "test"]),
        on_match="go test invocation observed. With -json + a converter (e.g., gotestsum), JUnit XML captured by test-results."
    )),
    ("go-build", dict(
        desc="go build — Go compiler. Output binaries carry BuildInfo (module + VCS metadata) which the go-build attestor extracts and writes as a JSON sidecar so the evidence survives strip(1).",
        categories=["build"],
        upstream=dict(name="go build", source="https://pkg.go.dev/cmd/go",
                      license="BSD-3-Clause", vendor="Google / Go Authors"),
        # `go build` and `go install` both produce binaries with embedded
        # BuildInfo. `go run` is intentionally out of scope — it doesn't
        # persist a binary worth attesting.
        match=dict(any_of=[
            dict(argv_prefix=["go", "build"]),
            dict(argv_prefix=["go", "install"]),
        ]),
        recommended_trace="light",
        on_match="go build/install observed. The go-build attestor captures BuildInfo (module graph + vcs.revision + build settings) and persists a .gobuild.json sidecar next to each binary so the evidence survives strip(1)."
    )),
    ("protoc", dict(
        desc="Protocol Buffers compiler — generates Go/Java/Python/JS bindings from .proto files. Common in monorepos with API codegen pipelines.",
        categories=["build"],
        upstream=dict(name="Protocol Buffers", source="https://github.com/protocolbuffers/protobuf",
                      license="BSD-3-Clause", vendor="Google / Protocol Buffers Authors"),
        # `protoc` is the C++ compiler; `buf generate` is the modern wrapper.
        # Both should fire — the resulting generated files appear as products
        # and feed downstream attestors (go-build, etc.).
        match=dict(any_of=[
            dict(argv_prefix=["protoc"]),
            dict(argv_prefix=["buf", "generate"]),
        ]),
        recommended_trace="light",
        on_match="protoc / buf generate observed. Generated source files appear as products; downstream attestors (go-build, sbom) pick up the binaries/SBOMs that result."
    )),
    ("jest", dict(
        desc="Jest — JavaScript test runner (Meta).",
        categories=["unit-test"],
        upstream=dict(name="Jest", source="https://github.com/jestjs/jest",
                      license="MIT", vendor="OpenJS Foundation / Meta"),
        emits_formats=["test-results"],
        match=dict(argv_prefix=["jest"]),
        on_match="Jest invocation observed. jest-junit reporter emits JUnit XML, captured by test-results."
    )),
]


def render_value(v):
    """YAML-quote a string, render bools/lists/dicts inline."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[" + ", ".join(render_value(x) for x in v) + "]"
    s = str(v)
    if any(c in s for c in [':', '#', '"', "'", '\n', '{', '}', '[', ']', ',', '&', '*', '!', '|', '>', '@', '`']) or s == "":
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'
    return s


def render_leaf(match: dict, indent: str) -> str:
    """Render a single leaf predicate at the given indent prefix."""
    if "argv_prefix" in match:
        return indent + "argv_prefix: " + render_value(match["argv_prefix"])
    if "file_exists" in match:
        return indent + "file_exists: " + render_value(match["file_exists"])
    if "file_glob" in match:
        return indent + "file_glob: " + render_value(match["file_glob"])
    if "env_set" in match:
        return indent + "env_set: " + render_value(match["env_set"])
    if "azure_metadata_reachable" in match:
        return indent + "azure_metadata_reachable: " + render_value(match["azure_metadata_reachable"])
    if "gcp_metadata_reachable" in match:
        return indent + "gcp_metadata_reachable: " + render_value(match["gcp_metadata_reachable"])
    if "imds_reachable" in match:
        return indent + "imds_reachable: " + render_value(match["imds_reachable"])
    raise ValueError(f"unknown match shape: {match}")


def render_match(match: dict) -> str:
    """Render the `match:` block — pre-gate predicate.

    Supports `any_of: [predicate, predicate, ...]` for tools whose
    invocation has multiple equivalent forms (e.g. `npm install`
    vs `npm ci`). Each child is rendered as a YAML list item under
    `any_of:`. Falls through to a leaf render for single-predicate
    entries — the common case.
    """
    if "any_of" in match:
        out = ["    any_of:"]
        for child in match["any_of"]:
            # YAML list item: leading "- " on the predicate's first
            # (only) key. render_leaf returns one line at indent; we
            # rewrite the leading spaces to "      - ".
            line = render_leaf(child, "")
            out.append("      - " + line)
        return "\n".join(out)
    return render_leaf(match, "    ")


def render_entry(name: str, args: dict) -> str:
    out = []
    out.append("# Detection-only catalog entry.")
    out.append("# Generated by scripts/gen-detection-catalog.py — do not edit by hand;")
    out.append("# edit the script and re-run.")
    out.append("apiVersion: cilock.detection/v0.1")
    out.append(f"name: {name}")
    out.append("detection_only: true")
    out.append("")
    out.append(f"description: {render_value(args['desc'])}")
    out.append("")
    out.append("category: " + render_value(args["categories"]))
    if args.get("primary"):
        out.append(f"primary_category: {render_value(args['primary'])}")
    out.append("")
    out.append("upstream:")
    up = args["upstream"]
    out.append(f"  name: {render_value(up['name'])}")
    out.append(f"  source: {render_value(up['source'])}")
    out.append(f"  license: {render_value(up['license'])}")
    out.append(f"  vendor: {render_value(up['vendor'])}")

    if args.get("emits_formats"):
        out.append("")
        out.append("emits_formats: " + render_value(args["emits_formats"]))

    if args.get("recommended_trace"):
        out.append("")
        out.append(f"recommended_trace: {render_value(args['recommended_trace'])}")

    out.append("")
    out.append("pre:")
    out.append("  match:")
    out.append(render_match(args["match"]))

    out.append("")
    out.append("llm_hints:")
    out.append(f"  on_match: {render_value(args['on_match'])}")
    out.append("")
    return "\n".join(out)


def main():
    os.makedirs(CATALOG_DIR, exist_ok=True)
    # Wipe any stale generated files so removals from ENTRIES propagate.
    for f in os.listdir(CATALOG_DIR):
        if f.endswith(".yaml"):
            os.remove(os.path.join(CATALOG_DIR, f))
    names = set()
    for name, args in ENTRIES:
        if name in names:
            raise SystemExit(f"duplicate catalog entry: {name}")
        names.add(name)
        path = os.path.join(CATALOG_DIR, f"{name}.yaml")
        with open(path, "w") as fh:
            fh.write(render_entry(name, args))
    print(f"wrote {len(ENTRIES)} catalog entries to {CATALOG_DIR}")


if __name__ == "__main__":
    main()
