#!/usr/bin/env python3
"""
test-catalog-tools.py

End-to-end attestation test for every catalog + plugin tool cilock
knows about. For each tool we:

  1. Confirm it's installed (or attempt install via brew/go/pip/npm).
  2. Set up a per-tool fixture directory.
  3. Run `cilock run -k signer.key -o bundle.json -- <tool with args>`.
  4. Decode the bundle's DSSE → in-toto → collection envelope.
  5. Assert the expected predicate-type URIs are present.

Outputs:
  .catalog-test/report.md   — human-readable per-tool table + details
  .catalog-test/report.json — machine-readable for CI consumption

Re-run as often as you like; the work dir is fully refreshed per run.

Build the all-attestors binary first (every plugin + every signer):
    cd presets/all && go build -o /tmp/cilock-all-cat ./cmd/cilock-all
Override the binary location with the CILOCK_BIN env var.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

ROOT = Path(__file__).resolve().parents[1]
WORKDIR = ROOT / ".catalog-test"
KEY = WORKDIR / "keys" / "signer.key"
BUNDLES = WORKDIR / "bundles"
LOGS = WORKDIR / "logs"
FIXTURES = WORKDIR / "fixtures"
CILOCK = os.environ.get("CILOCK_BIN", "/tmp/cilock-all-cat")

# Predicate URIs we look for. The catalog test verifies that running
# the wrapped tool produces (at minimum) commandrun + product, and that
# detected tool-specific attestors fire.
URI_COMMANDRUN = "https://aflock.ai/attestations/command-run/v0.1"
URI_PRODUCT = "https://aflock.ai/attestations/product/v0.3"
URI_MATERIAL = "https://aflock.ai/attestations/material/v0.3"
# SBOM attestor emits the underlying spec's namespace (SPDX or CycloneDX),
# not an aflock-internal URI. Either matches "an SBOM was attested".
URI_SBOM_SPDX = "https://spdx.dev/Document"
URI_SBOM_CYCLONEDX = "https://cyclonedx.org/bom"
URI_SARIF = "https://aflock.ai/attestations/sarif/v0.1"
URI_VEX = "https://openvex.dev/ns"
URI_TRIVY = "https://aflock.ai/attestations/trivy/v0.1"
URI_GOVULN = "https://aflock.ai/attestations/govulncheck/v0.1"
URI_GIT = "https://aflock.ai/attestations/git/v0.1"
URI_GITHUBAC = "https://aflock.ai/attestations/githubaction/v0.1"
URI_DOCKER = "https://aflock.ai/attestations/docker/v0.1"
URI_PIP = "https://aflock.ai/attestations/pip-install/v0.1"
URI_LOCKFILES = "https://aflock.ai/attestations/lockfiles/v0.1"
URI_TEST = "https://aflock.ai/attestations/test-results/v0.1"
URI_GHREVIEW = "https://aflock.ai/attestations/github-review/v0.1"

# Status enum (string-typed; serialized verbatim into report.json).
PASS = "pass"
FAIL = "fail"
SKIP = "skip"


@dataclass
class Recipe:
    name: str
    # invoke is a callable that returns (argv, env, cwd) for the
    # cilock-wrapped command. Receives the fixture dir.
    invoke: Callable[[Path], tuple[list[str], dict, Optional[Path]]]
    # need is the tool binary that must be in $PATH. If None, the
    # recipe is internal (e.g. echo wrappers for env-only detectors).
    need: Optional[str] = None
    # expect_uris are predicate URIs the bundle MUST contain.
    expect_uris: list[str] = field(default_factory=lambda: [URI_COMMANDRUN])
    # fixture optionally writes files into the per-tool fixture dir.
    fixture: Optional[Callable[[Path], None]] = None
    # skip_reason short-circuits the recipe.
    skip_reason: Optional[str] = None
    # allow_nonzero=True passes --ignore-command-exit-code so scanner
    # exit codes (semgrep, trivy, etc.) don't tank the cilock run.
    allow_nonzero: bool = False
    # category is informational — surfaces in the report.
    category: str = ""
    # attestors are the cilock `-a` flags to pass. Detection plans
    # post-gate attestors today (M1b shadow mode); --auto driving is
    # M3d in the roadmap. Until then, the test harness names them.
    attestors: list[str] = field(default_factory=list)
    # cilock_flags are extra cilock-side flags appended before `--`.
    # Use for plugin-specific overrides like
    # --attestor-github-review-pr 153.
    cilock_flags: list[str] = field(default_factory=list)


@dataclass
class Result:
    name: str
    status: str
    duration_s: float
    detail: str
    bundle_path: Optional[str] = None
    found_uris: list[str] = field(default_factory=list)
    missing_uris: list[str] = field(default_factory=list)
    cilock_exit: Optional[int] = None
    log_path: Optional[str] = None


# ---- Fixture helpers ----

def make_go_mod(fix: Path):
    (fix / "main.go").write_text(
        'package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }\n')
    (fix / "go.mod").write_text("module example.com/cat\n\ngo 1.22\n")


def make_dockerfile(fix: Path):
    (fix / "Dockerfile").write_text("FROM alpine:3.20\nCMD [\"echo\",\"hi\"]\n")


def make_terraform(fix: Path):
    # Intentionally insecure: public S3 + 0.0.0.0/0 SG ingress so
    # scanners (checkov, tfsec, terrascan) actually produce findings.
    (fix / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "public-bucket"\n'
        '  acl    = "public-read"\n'
        "}\n"
        'resource "aws_security_group" "open" {\n'
        "  ingress {\n"
        "    from_port   = 0\n"
        "    to_port     = 65535\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )


def make_k8s_manifest(fix: Path):
    (fix / "deployment.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\n"
        "metadata:\n  name: demo\n"
        "spec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: demo\n"
        "  template:\n    metadata:\n      labels:\n        app: demo\n"
        "    spec:\n      containers:\n      - name: demo\n        image: nginx:1.27\n"
    )


def make_python_pkg(fix: Path):
    (fix / "app.py").write_text(
        "import hashlib\n"
        "def insecure():\n"
        "    return hashlib.md5(b'x').hexdigest()\n"
    )
    (fix / "requirements.txt").write_text("requests==2.31.0\n")


def make_npm_pkg(fix: Path):
    (fix / "package.json").write_text(json.dumps({
        "name": "cat-test", "version": "0.0.1",
        "dependencies": {"lodash": "4.17.21"}
    }, indent=2))


def make_git_repo_with_secret(fix: Path):
    subprocess.run(["git", "init", "-q"], cwd=fix, check=True)
    subprocess.run(["git", "config", "user.email", "cat@test.local"],
                   cwd=fix, check=True)
    subprocess.run(["git", "config", "user.name", "cat-test"],
                   cwd=fix, check=True)
    # Assemble a Stripe-shaped placeholder via fragments so this source
    # file itself doesn't trip GitHub Push Protection / secret scanners.
    # The on-disk fixture (code.py) still contains the joined string,
    # which is what gitleaks/trufflehog scan against.
    prefix = "sk_" + "test_"
    body = "4eC39" + "HqLyj" + "WDarjtT1zdp7dc"
    (fix / "code.py").write_text(f"API_KEY = '{prefix}{body}'\n")
    subprocess.run(["git", "add", "."], cwd=fix, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=fix, check=True)


def make_chart(fix: Path):
    (fix / "Chart.yaml").write_text(
        "apiVersion: v2\nname: cat-chart\nversion: 0.0.1\n"
    )
    tpl = fix / "templates"
    tpl.mkdir(exist_ok=True)
    make_k8s_manifest(tpl)


def make_pytest(fix: Path):
    (fix / "test_basic.py").write_text(
        "def test_truth():\n    assert True\n"
    )


def make_jest_pkg(fix: Path):
    (fix / "package.json").write_text(json.dumps({
        "name": "jest-cat", "version": "0.0.1",
        "scripts": {"test": "jest"},
        "devDependencies": {"jest": "29.7.0"}
    }, indent=2))
    (fix / "sum.test.js").write_text(
        "test('sum', () => { expect(1+1).toBe(2); });\n"
    )


def make_cargo(fix: Path):
    (fix / "Cargo.toml").write_text(
        '[package]\nname = "cat"\nversion = "0.0.1"\nedition = "2021"\n'
    )
    (fix / "src").mkdir(exist_ok=True)
    (fix / "src" / "main.rs").write_text('fn main() { println!("hi"); }\n')


def make_gradle(fix: Path):
    (fix / "build.gradle").write_text(
        "plugins { id 'java' }\nrepositories { mavenCentral() }\n"
    )
    (fix / "settings.gradle").write_text("rootProject.name = 'cat'\n")


def make_maven(fix: Path):
    (fix / "pom.xml").write_text(
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<project xmlns='http://maven.apache.org/POM/4.0.0'>\n"
        "  <modelVersion>4.0.0</modelVersion>\n"
        "  <groupId>com.example</groupId>\n"
        "  <artifactId>cat</artifactId>\n"
        "  <version>0.0.1</version>\n"
        "  <packaging>pom</packaging>\n"
        "</project>\n"
    )


# ---- Invocation builders ----

def args_only(parts: list[str]):
    """Helper: returns a Recipe invoker with no env / cwd override."""
    def inner(fix: Path):
        return parts, {}, fix
    return inner


def with_env(parts: list[str], env: dict):
    def inner(fix: Path):
        return parts, env, fix
    return inner


# ---- Recipes ----
# Categories: build | artifact-scan | statement | posture-scan | runtime

RECIPES: list[Recipe] = [
    # --- SBOM tools ---
    Recipe(name="syft", need="syft", category="artifact-scan",
           fixture=make_go_mod,
           expect_uris=[URI_COMMANDRUN, [URI_SBOM_SPDX, URI_SBOM_CYCLONEDX]],
           attestors=["sbom"],
           invoke=args_only(["syft", "scan", "dir:.", "-o", "spdx-json=sbom.spdx.json"])),
    Recipe(name="cdxgen", need="cdxgen", category="artifact-scan",
           fixture=make_npm_pkg,
           expect_uris=[URI_COMMANDRUN, [URI_SBOM_SPDX, URI_SBOM_CYCLONEDX]],
           attestors=["sbom"],
           invoke=args_only(["cdxgen", "-o", "bom.json", "-t", "javascript", "."])),
    Recipe(name="grype", need="grype", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN],
           invoke=args_only(["grype", "dir:.", "-o", "json", "--file", "grype-out.json"])),

    # --- SAST ---
    Recipe(name="semgrep", need="semgrep", category="artifact-scan",
           fixture=make_python_pkg, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           allow_nonzero=True, attestors=["sarif"],
           invoke=args_only(["semgrep", "scan", "--sarif", "--sarif-output=semgrep.sarif",
                             "--config=p/python", "."])),
    # bandit native output is json/txt; no SARIF without an external
    # converter. We attest the command + findings JSON.
    Recipe(name="bandit", need="bandit", category="artifact-scan",
           fixture=make_python_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["bandit", "-r", ".", "-f", "json", "-o", "bandit.json"])),
    Recipe(name="staticcheck", need="staticcheck", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["staticcheck", "./..."])),

    # --- Vuln / dep scanners ---
    Recipe(name="osv-scanner", need="osv-scanner", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           allow_nonzero=True, attestors=["sarif"],
           invoke=args_only(["osv-scanner", "scan", "--format=sarif",
                             "--output=osv.sarif", "."])),

    # --- IaC scanners ---
    Recipe(name="checkov", need="checkov", category="artifact-scan",
           fixture=make_terraform, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           allow_nonzero=True, attestors=["sarif"],
           invoke=args_only(["checkov", "-d", ".", "-o", "sarif",
                             "--output-file-path", "checkov-out"])),
    Recipe(name="tfsec", need="tfsec", category="artifact-scan",
           fixture=make_terraform, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           allow_nonzero=True, attestors=["sarif"],
           invoke=args_only(["tfsec", "--format", "sarif", "--out", "tfsec.sarif", "."])),
    Recipe(name="terrascan", need="terrascan", category="artifact-scan",
           fixture=make_terraform, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           allow_nonzero=True, attestors=["sarif"],
           # terrascan -o writes to stdout for sarif; redirect via bash -c.
           invoke=args_only(["bash", "-c",
                             "terrascan scan -i terraform -d . -o sarif > terrascan.sarif"])),
    Recipe(name="tflint", need="tflint", category="artifact-scan",
           fixture=make_terraform, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["tflint", "--format=sarif", "."])),

    # --- Secret scanners ---
    Recipe(name="gitleaks", need="gitleaks", category="artifact-scan",
           fixture=make_git_repo_with_secret, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           allow_nonzero=True, attestors=["sarif"],
           invoke=args_only(["gitleaks", "detect", "--source", ".",
                             "--report-format", "sarif", "--report-path", "gitleaks.sarif"])),
    Recipe(name="trufflehog", need="trufflehog", category="artifact-scan",
           fixture=make_git_repo_with_secret, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["trufflehog", "filesystem", ".", "--json"])),

    # --- K8s posture ---
    Recipe(name="kubescape", need="kubescape", category="posture-scan",
           fixture=make_k8s_manifest, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           allow_nonzero=True, attestors=["sarif"],
           invoke=args_only(["kubescape", "scan", ".", "--format=sarif",
                             "--output=kubescape.sarif"])),
    Recipe(name="polaris", need="polaris", category="posture-scan",
           fixture=make_k8s_manifest, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["polaris", "audit", "--audit-path", ".", "--format=json"])),
    Recipe(name="kubeaudit", need="kubeaudit", category="posture-scan",
           fixture=make_k8s_manifest, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["kubeaudit", "all", "-f", "deployment.yaml"])),
    Recipe(name="kyverno", need="kyverno", category="posture-scan",
           fixture=make_k8s_manifest, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["kyverno", "version"])),
    Recipe(name="conftest", need="conftest", category="posture-scan",
           fixture=make_k8s_manifest, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["conftest", "verify", "--no-color"])),

    # --- Trivy ---
    Recipe(name="trivy", need="trivy", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN, URI_TRIVY],
           allow_nonzero=True, attestors=["trivy"],
           invoke=args_only(["trivy", "fs", "--format", "json",
                             "--output", "trivy-results.json", "."])),

    # --- Signing ---
    Recipe(name="cosign-verify", need="cosign", category="statement",
           fixture=None, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["cosign", "verify", "alpine:latest"])),
    Recipe(name="notation", need="notation", category="statement",
           fixture=None, expect_uris=[URI_COMMANDRUN],
           invoke=args_only(["notation", "version"])),
    Recipe(name="gpg-sign", need="gpg", category="statement",
           fixture=None, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["gpg", "--version"])),

    # --- Build tools ---
    Recipe(name="cargo-build", need="cargo", category="build",
           fixture=make_cargo, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["cargo", "build", "--offline"])),
    Recipe(name="gradle", need="gradle", category="build",
           fixture=make_gradle, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["gradle", "tasks", "--offline", "--no-daemon"])),
    Recipe(name="maven-build", need="mvn", category="build",
           fixture=make_maven, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["mvn", "--offline", "validate"])),
    Recipe(name="npm-install", need="npm", category="build",
           fixture=make_npm_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["npm", "install", "--no-audit", "--no-fund",
                             "--prefer-offline", "--ignore-scripts"])),
    Recipe(name="yarn-install", need="yarn", category="build",
           fixture=make_npm_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["yarn", "--version"])),
    Recipe(name="pnpm-install", need="pnpm", category="build",
           fixture=make_npm_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["pnpm", "--version"])),
    Recipe(name="helm-install", need="helm", category="build",
           fixture=make_chart, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["helm", "lint", "."])),
    Recipe(name="kustomize-build", need="kustomize", category="build",
           fixture=make_chart, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["kustomize", "version"])),

    # --- CI env-detectors ---
    Recipe(name="azure-devops", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"TF_BUILD": "True"})),
    Recipe(name="circleci", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"CIRCLECI": "true"})),
    Recipe(name="buildkite", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"BUILDKITE": "true"})),
    Recipe(name="bitbucket-pipelines", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"BITBUCKET_BUILD_NUMBER": "1"})),
    Recipe(name="drone-ci", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"DRONE": "true"})),
    Recipe(name="travis-ci", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"TRAVIS": "true"})),
    Recipe(name="teamcity", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"TEAMCITY_VERSION": "2024.07"})),
    Recipe(name="argo-workflows", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"ARGO_TEMPLATE": "demo"})),
    Recipe(name="tekton-pipelines", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"TEKTON_RESOURCES": "demo"})),
    Recipe(name="cloudbuild-gcp", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"BUILD_ID": "abc-123"})),
    Recipe(name="codebuild-aws", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=with_env(["echo", "hi"], {"CODEBUILD_BUILD_ID": "demo:1"})),

    # --- Test runners ---
    Recipe(name="pytest", need="pytest", category="artifact-scan",
           fixture=make_pytest, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["pytest", "--junitxml=junit.xml", "."])),
    Recipe(name="go-test", need="go", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["go", "test", "./..."])),

    # --- Cloud audit log queries ---
    # Real data-plane validation: hit AWS account 898769392027 (testifysec-demo).
    # Previously this recipe ran `aws cloudtrail help` (no data); now it
    # actually queries the live CloudTrail audit log.
    Recipe(name="cloudtrail", need="aws", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                "aws cloudtrail lookup-events --max-results 5 "
                "--output json > cloudtrail-events.json"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),
    Recipe(name="gcp-audit-log", need="gcloud", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["gcloud", "logging", "--help"])),
    Recipe(name="kubectl-audit", need="kubectl", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["kubectl", "version", "--client"])),

    # --- Secrets distribution ---
    Recipe(name="vault-cli", need="vault", category="runtime",
           expect_uris=[URI_COMMANDRUN],
           invoke=args_only(["vault", "--version"])),
    # Real data-plane validation: list secrets (metadata only — no
    # GetSecretValue, which would emit sensitive material).
    Recipe(name="aws-secrets-manager", need="aws", category="runtime",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                "aws secretsmanager list-secrets --max-results 10 "
                "--output json > secrets-list.json"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),

    # --- Plugin-backed attestors with deterministic invocations ---
    Recipe(name="docker", need="docker", category="build",
           fixture=make_dockerfile, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["docker", "buildx", "build", "--provenance=true",
                             "--load", "-t", "cat-test:latest", "."])),

    # ===== Retry batch: previously skipped, now installed =====
    Recipe(name="pip-audit", need="pip-audit", category="artifact-scan",
           fixture=make_python_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # pip-audit's CycloneDX flavor omits bomFormat/specVersion in
           # older versions so the sbom attestor can't recognize it.
           # Validate commandrun only; the JSON output is captured as
           # a product blob.
           invoke=args_only(["bash", "-c",
                             "pip-audit --format=json --output=pip-audit.json -r requirements.txt || true"])),
    Recipe(name="safety", need="safety", category="artifact-scan",
           fixture=make_python_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # safety check writes findings JSON; commandrun captures the run.
           invoke=args_only(["bash", "-c",
                             "safety check --file requirements.txt --json --output safety.json || true"])),
    Recipe(name="detect-secrets", need="detect-secrets", category="artifact-scan",
           fixture=make_git_repo_with_secret, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["bash", "-c",
                             "detect-secrets scan > detect-secrets.json"])),
    Recipe(name="nancy", need="nancy", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # nancy reads `go list -json -m all` on stdin.
           invoke=args_only(["bash", "-c",
                             "go list -json -deps ./... | nancy sleuth || true"])),
    Recipe(name="vexctl", need="vexctl", category="statement",
           expect_uris=[URI_COMMANDRUN, URI_VEX],
           attestors=["vex"],
           # vexctl create writes an OpenVEX document; the vex attestor
           # captures it.
           invoke=args_only(["bash", "-c",
                             "vexctl create --product=pkg:generic/example --vuln=CVE-2024-0001 "
                             "--status=not_affected --justification=component_not_present "
                             "--file=vex.openvex.json"])),
    Recipe(name="bom", need="bom", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN],
           attestors=["sbom"],
           allow_nonzero=True,
           invoke=args_only(["bash", "-c",
                             "bom generate --dirs . --output bom.spdx.json --format json || true"])),
    Recipe(name="kics", need="kics", category="artifact-scan",
           fixture=make_terraform, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           attestors=["sarif"],
           allow_nonzero=True,
           # kics's brew install puts queries under
           # /opt/homebrew/Cellar/kics/<v>/share/kics/assets/queries.
           # `find` resolves the version-pinned path at runtime.
           invoke=args_only(["bash", "-c",
                             "QDIR=$(find /opt/homebrew/Cellar/kics -type d -name queries | head -1); "
                             "kics scan -p . -o . --report-formats sarif "
                             "--output-name kics-results -q $QDIR || true"])),
    Recipe(name="gosec", need="gosec", category="artifact-scan",
           fixture=make_go_mod, expect_uris=[URI_COMMANDRUN, URI_SARIF],
           attestors=["sarif"],
           allow_nonzero=True,
           invoke=args_only(["bash", "-c",
                             "gosec -fmt sarif -out gosec.sarif ./... || true"])),
    Recipe(name="cargo-audit", need="cargo-audit", category="artifact-scan",
           fixture=make_cargo, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # cargo-audit needs Cargo.lock; `cargo generate-lockfile`
           # first, then audit.
           invoke=args_only(["bash", "-c",
                             "cargo generate-lockfile --offline 2>/dev/null; "
                             "cargo-audit audit --json > audit.json || true"])),
    Recipe(name="npm-audit", need="npm", category="artifact-scan",
           # npm audit needs package-lock.json; the npm_pkg fixture has
           # only package.json. Run `npm install --package-lock-only`.
           fixture=lambda fix: (
               make_npm_pkg(fix),
               subprocess.run(["npm", "install", "--package-lock-only",
                               "--no-audit", "--no-fund",
                               "--ignore-scripts"], cwd=fix, check=False),
           ),
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["bash", "-c",
                             "npm audit --json > npm-audit.json || true"])),
    Recipe(name="yarn-audit", need="yarn", category="artifact-scan",
           fixture=make_npm_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["bash", "-c",
                             "yarn audit --json > yarn-audit.json || true"])),
    Recipe(name="retire", need="retire", category="artifact-scan",
           fixture=make_npm_pkg, expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=args_only(["bash", "-c",
                             "retire --outputformat jsonsimple --outputpath retire.json --path . || true"])),
    Recipe(name="jest", need="jest", category="artifact-scan",
           # jest needs node + a jest.config + jest dep — too heavy. Use
           # --version to validate cilock wraps the binary.
           expect_uris=[URI_COMMANDRUN],
           invoke=args_only(["jest", "--version"])),
    # ===== AWS data-plane validation (testifysec-demo account 898769392027) =====
    # prowler is a plugin attestor; this exercises a real account scan
    # restricted to a single cheap check (--check ec2_instance_account_imdsv2_enabled).
    Recipe(name="prowler", need="prowler", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           attestors=["prowler"],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                # iam_root_hardware_mfa_enabled always produces a finding
                # (either PASS or FAIL), so prowler always writes the
                # OCSF output file. ec2_instance_account_imdsv2_enabled
                # writes nothing when there are no findings, which makes
                # the post-product prowler attestor skip.
                "prowler aws --checks iam_root_hardware_mfa_enabled "
                "--output-modes json-ocsf --output-directory . "
                "--output-filename prowler-out --no-banner || true"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),
    # steampipe queries the live AWS account via its installed AWS plugin.
    Recipe(name="steampipe", need="steampipe", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           attestors=["steampipe"],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                "steampipe query \"select instance_id, instance_state from aws_ec2_instance limit 3\" "
                "--output json > steampipe-out.json"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),
    # AWS Security Hub — query real findings from testifysec-demo
    # (account 898769392027). The recipe is bounded to 5 findings so it
    # stays fast and produces a small JSON blob.
    Recipe(name="aws-security-hub", need="aws", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                "aws securityhub get-findings --max-results 5 "
                "--output json > securityhub-findings.json"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),
    Recipe(name="aws-inspector", need="aws", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                "aws inspector2 list-findings --max-results 5 "
                "--output json > inspector-findings.json"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),
    Recipe(name="aws-guardduty", need="aws", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # Two-step: list detectors, then findings for the first.
           # If GuardDuty isn't enabled, the detectors list is empty and
           # the recipe still attests the (empty) query.
           invoke=lambda fix: (
               ["bash", "-c",
                "aws guardduty list-detectors --output json > gd-detectors.json && "
                "DID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text); "
                "if [ -n \"$DID\" ] && [ \"$DID\" != \"None\" ]; then "
                "  aws guardduty list-findings --detector-id \"$DID\" --max-results 5 "
                "    --output json > gd-findings.json; "
                "fi"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),
    Recipe(name="aws-macie", need="aws", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                "aws macie2 get-macie-session --output json > macie-session.json"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),
    Recipe(name="aws-iam-credential-report", need="aws", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # generate-credential-report is async; the second call retrieves
           # whatever the last generation produced (base64-encoded CSV).
           # We poll until COMPLETE or 10s elapses.
           invoke=lambda fix: (
               ["bash", "-c",
                "aws iam generate-credential-report > /dev/null 2>&1; "
                "for i in 1 2 3 4 5; do "
                "  STATE=$(aws iam generate-credential-report --query State --output text 2>/dev/null); "
                "  if [ \"$STATE\" = \"COMPLETE\" ]; then break; fi; "
                "  sleep 1; "
                "done; "
                "aws iam get-credential-report --output json > iam-creds-report.json"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),

    # AWS Config attestor expects `get-compliance-details-by-config-rule`
    # output (EvaluationResults shape). We probe a known rule; if AWS
    # Config isn't running rules in this account the JSON will have an
    # empty EvaluationResults and the attestor will skip cleanly — we
    # validate the wrapping flow with commandrun only.
    Recipe(name="aws-config", need="aws", category="posture-scan",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           invoke=lambda fix: (
               ["bash", "-c",
                "RULE=$(aws configservice describe-config-rules "
                "--query 'ConfigRules[0].ConfigRuleName' --output text 2>/dev/null); "
                "if [ -n \"$RULE\" ] && [ \"$RULE\" != \"None\" ]; then "
                "  aws configservice get-compliance-details-by-config-rule "
                "    --config-rule-name \"$RULE\" --output json > aws-config-compliance.json; "
                "else "
                "  echo '{\"EvaluationResults\":[]}' > aws-config-compliance.json; "
                "fi"],
               {"AWS_PROFILE": "testifysec-demo"},
               fix,
           )),

    # ===== github-review (new attestor — Pattern B: explicit PR override) =====
    # Validates against kubernetes/kubernetes PR #139232 (real reviewed PR).
    # Requires `gh auth status` to be logged in. Uses Pattern B (--pr flag)
    # so the recipe works from any cwd (no git checkout dependency).
    Recipe(name="github-review", need="gh", category="statement",
           expect_uris=[URI_COMMANDRUN, URI_GHREVIEW],
           attestors=["github-review"],
           cilock_flags=[
               "--attestor-github-review-repo", "kubernetes/kubernetes",
               "--attestor-github-review-pr",   "139232",
           ],
           invoke=args_only(["true"])),

    Recipe(name="huggingface-hub", need="hf", category="statement",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # Fixture: use the huggingface_hub Python API to generate a
           # real model card README.md with YAML frontmatter. The
           # README is captured as a product; `hf --version` validates
           # the toolchain is wired.
           fixture=lambda fix: subprocess.run(
               ["/tmp/mctk-venv/bin/python", "-c",
                "from huggingface_hub import ModelCard, ModelCardData; "
                "card = ModelCard.from_template("
                "  card_data=ModelCardData(language='en', license='apache-2.0', "
                "    model_name='cat-test-model', tags=['supply-chain','test']), "
                "  model_id='cat-test-model', "
                "  model_description='Demo model card generated for cilock catalog validation.'); "
                f"card.save('{fix}/README.md')"],
               check=True),
           invoke=args_only(["hf", "--version"])),

    Recipe(name="cosign-sign", need="cosign", category="statement",
           expect_uris=[URI_COMMANDRUN],
           allow_nonzero=True,
           # cosign sign-blob signs an arbitrary file with a local key
           # — no registry needed. We use the same key the harness
           # generated and sign cilock itself as the target blob.
           fixture=lambda fix: (fix / "blob.txt").write_text("blob-to-sign\n"),
           invoke=lambda fix: (
               ["cosign", "sign-blob", "--key", str(KEY), "--yes",
                "--output-signature=blob.sig", "blob.txt"],
               {"COSIGN_PASSWORD": ""},  # ed25519 key has no password
               fix,
           )),

    # --- Additional plugin attestors driven via -a ---
    Recipe(name="git", need="git", category="build",
           fixture=lambda fix: (
               subprocess.run(["git", "init", "-q"], cwd=fix, check=True),
               subprocess.run(["git", "config", "user.email", "x@x"], cwd=fix, check=True),
               subprocess.run(["git", "config", "user.name", "x"], cwd=fix, check=True),
               (fix / "f.txt").write_text("hi\n"),
               subprocess.run(["git", "add", "f.txt"], cwd=fix, check=True),
               subprocess.run(["git", "commit", "-qm", "i"], cwd=fix, check=True),
           ),
           expect_uris=[URI_COMMANDRUN, URI_GIT],
           attestors=["git"],
           invoke=args_only(["git", "status"])),
    Recipe(name="lockfiles", need="npm", category="artifact-scan",
           fixture=lambda fix: (
               (fix / "package.json").write_text('{"name":"x","version":"0.0.1"}\n'),
               (fix / "package-lock.json").write_text(
                   '{"name":"x","version":"0.0.1","lockfileVersion":3,"requires":true,"packages":{"":{"version":"0.0.1"}}}\n'),
           ),
           expect_uris=[URI_COMMANDRUN, URI_LOCKFILES],
           attestors=["lockfiles"],
           invoke=args_only(["npm", "--version"])),
    Recipe(name="govulncheck", need="govulncheck", category="artifact-scan",
           fixture=make_go_mod,
           expect_uris=[URI_COMMANDRUN, URI_GOVULN],
           attestors=["govulncheck"],
           allow_nonzero=True,
           # govulncheck attestor scans the -json output file; redirect.
           invoke=args_only(["bash", "-c",
                             "govulncheck -json ./... > govulncheck.json"])),
    Recipe(name="environment", need=None, category="build",
           expect_uris=[URI_COMMANDRUN],
           invoke=args_only(["echo", "env-test"])),
    Recipe(name="material", need=None, category="build",
           fixture=make_go_mod,
           expect_uris=[URI_COMMANDRUN, URI_MATERIAL],
           invoke=args_only(["echo", "material-test"])),
    Recipe(name="oci-image", need="docker", category="artifact-scan",
           fixture=make_dockerfile,
           expect_uris=[URI_COMMANDRUN],
           attestors=["oci"],
           allow_nonzero=True,
           # Save a built image to a tarball so the oci attestor has
           # something to attest.
           invoke=args_only(["bash", "-c",
                             "docker buildx build --load -t cat-oci:latest . && "
                             "docker save cat-oci:latest -o image.tar"])),
]


# ---- Helpers ----

def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def have_tool(t: str) -> bool:
    return shutil.which(t) is not None


def decode_bundle(path: Path) -> dict:
    """Decode a cilock DSSE-wrapped in-toto bundle and return the
    inner statement dict (with `predicate.attestations` list)."""
    obj = json.loads(path.read_text())
    payload = base64.b64decode(obj["payload"]).decode()
    return json.loads(payload)


def attester_uris(statement: dict) -> list[str]:
    pred = statement.get("predicate", {})
    atts = pred.get("attestations") or []
    return [a.get("type") for a in atts if a.get("type")]


def setup():
    if WORKDIR.exists():
        shutil.rmtree(WORKDIR)
    for d in (WORKDIR, KEY.parent, BUNDLES, LOGS, FIXTURES):
        d.mkdir(parents=True, exist_ok=True)
    # Generate keypair if missing.
    if not KEY.exists():
        run(["openssl", "genpkey", "-algorithm", "ed25519",
             "-out", str(KEY)], check=True)
        run(["openssl", "pkey", "-in", str(KEY), "-pubout",
             "-out", str(KEY.with_suffix(".pub"))], check=True)


def run_recipe(r: Recipe) -> Result:
    start = time.time()
    log_path = LOGS / f"{r.name}.log"

    if r.skip_reason:
        return Result(name=r.name, status=SKIP, duration_s=0.0,
                      detail=r.skip_reason)
    if r.need and not have_tool(r.need):
        return Result(name=r.name, status=SKIP, duration_s=0.0,
                      detail=f"{r.need} not on PATH")

    fix = FIXTURES / r.name
    fix.mkdir(parents=True, exist_ok=True)
    if r.fixture:
        try:
            r.fixture(fix)
        except Exception as e:
            return Result(name=r.name, status=FAIL, duration_s=time.time() - start,
                          detail=f"fixture setup failed: {e}")

    argv, env_overrides, cwd = r.invoke(fix)
    bundle = BUNDLES / f"{r.name}.bundle.json"
    cilock_argv = [
        CILOCK, "run",
        "-s", f"cat-{r.name}",
        "-k", str(KEY),
        "-o", str(bundle),
    ]
    for a in r.attestors:
        cilock_argv.extend(["-a", a])
    cilock_argv.extend(r.cilock_flags)
    if r.allow_nonzero:
        cilock_argv.append("--ignore-command-exit-code")
    cilock_argv.append("--")
    cilock_argv.extend(argv)

    env = os.environ.copy()
    env.update(env_overrides)

    try:
        proc = subprocess.run(
            cilock_argv, cwd=str(cwd or fix), env=env,
            capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return Result(name=r.name, status=FAIL,
                      duration_s=time.time() - start,
                      detail="cilock timed out (180s)",
                      log_path=str(log_path))

    log_path.write_text(
        f"$ {' '.join(cilock_argv)}\n\n[stdout]\n{proc.stdout}\n\n[stderr]\n{proc.stderr}\n"
    )

    if proc.returncode != 0:
        return Result(name=r.name, status=FAIL,
                      duration_s=time.time() - start,
                      detail=f"cilock exit={proc.returncode}",
                      cilock_exit=proc.returncode,
                      log_path=str(log_path))

    if not bundle.exists():
        return Result(name=r.name, status=FAIL,
                      duration_s=time.time() - start,
                      detail="bundle file not created",
                      cilock_exit=proc.returncode,
                      log_path=str(log_path))

    try:
        stmt = decode_bundle(bundle)
    except Exception as e:
        return Result(name=r.name, status=FAIL,
                      duration_s=time.time() - start,
                      detail=f"bundle decode failed: {e}",
                      bundle_path=str(bundle),
                      cilock_exit=proc.returncode,
                      log_path=str(log_path))

    uris = attester_uris(stmt)
    # Each entry in expect_uris is either a single URI (must be present)
    # or a list of URIs (any one must be present — used for SBOM where
    # SPDX or CycloneDX both satisfy).
    missing = []
    for expect in r.expect_uris:
        if isinstance(expect, list):
            if not any(u in uris for u in expect):
                missing.append(f"any-of {expect}")
        else:
            if expect not in uris:
                missing.append(expect)

    return Result(
        name=r.name,
        status=PASS if not missing else FAIL,
        duration_s=time.time() - start,
        detail="ok" if not missing else f"missing predicate URIs: {missing}",
        bundle_path=str(bundle),
        found_uris=uris,
        missing_uris=missing,
        cilock_exit=proc.returncode,
        log_path=str(log_path),
    )


def main() -> int:
    setup()
    if not have_tool(CILOCK):
        # CILOCK may be an absolute path; have_tool only checks PATH.
        if not Path(CILOCK).exists():
            print(f"cilock binary not found at {CILOCK}", file=sys.stderr)
            print("Set CILOCK_BIN env var or rebuild via:", file=sys.stderr)
            print("  cd cilock && go build -o /tmp/cilock-catalog ./cmd/cilock", file=sys.stderr)
            return 2

    only = set(sys.argv[1:])
    results: list[Result] = []
    print(f"Running {len(RECIPES)} catalog recipes against {CILOCK}\n", flush=True)
    for r in RECIPES:
        if only and r.name not in only:
            continue
        print(f"  ▸ {r.name:24s}", end=" ", flush=True)
        res = run_recipe(r)
        results.append(res)
        marker = {PASS: "PASS", FAIL: "FAIL", SKIP: "skip"}[res.status]
        print(f"{marker:5s} {res.detail} ({res.duration_s:.1f}s)", flush=True)

    write_report(results)
    n_pass = sum(1 for r in results if r.status == PASS)
    n_fail = sum(1 for r in results if r.status == FAIL)
    n_skip = sum(1 for r in results if r.status == SKIP)
    print(f"\nPASS={n_pass}  FAIL={n_fail}  SKIP={n_skip}")
    return 1 if n_fail else 0


def write_report(results: list[Result]):
    json_path = WORKDIR / "report.json"
    md_path = WORKDIR / "report.md"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    n_pass = sum(1 for r in results if r.status == PASS)
    n_fail = sum(1 for r in results if r.status == FAIL)
    n_skip = sum(1 for r in results if r.status == SKIP)

    json_path.write_text(json.dumps({
        "generated_at": now,
        "cilock_bin": CILOCK,
        "summary": {"pass": n_pass, "fail": n_fail, "skip": n_skip,
                    "total": len(results)},
        "results": [asdict(r) for r in results],
    }, indent=2))

    lines = [
        f"# cilock catalog tool test report",
        "",
        f"_Generated {now} against `{CILOCK}`._",
        "",
        f"**PASS:** {n_pass}  **FAIL:** {n_fail}  **SKIP:** {n_skip}  **TOTAL:** {len(results)}",
        "",
        "| Tool | Status | Detail | Bundle |",
        "| --- | --- | --- | --- |",
    ]
    for r in sorted(results, key=lambda x: (x.status, x.name)):
        bundle = f"`{Path(r.bundle_path).name}`" if r.bundle_path else "—"
        emoji = {PASS: "✅ PASS", FAIL: "❌ FAIL", SKIP: "⏭️ SKIP"}[r.status]
        lines.append(f"| `{r.name}` | {emoji} | {r.detail} | {bundle} |")
    lines.append("")
    lines.append("## Details (failures + skips)")
    lines.append("")
    for r in results:
        if r.status == PASS:
            continue
        lines.append(f"### `{r.name}` — {r.status}")
        lines.append("")
        lines.append(f"- detail: {r.detail}")
        if r.log_path:
            lines.append(f"- log: `{Path(r.log_path).relative_to(ROOT)}`")
        if r.bundle_path:
            lines.append(f"- bundle: `{Path(r.bundle_path).relative_to(ROOT)}`")
        if r.missing_uris:
            lines.append(f"- missing URIs: {r.missing_uris}")
        if r.found_uris:
            lines.append(f"- found URIs: {r.found_uris}")
        lines.append("")
    md_path.write_text("\n".join(lines))
    print(f"\nReport: {md_path}")


if __name__ == "__main__":
    sys.exit(main())
