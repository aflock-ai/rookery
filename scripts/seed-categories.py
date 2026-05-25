#!/usr/bin/env python3
# Idempotent seeder for category + upstream fields in detector.yaml.
# Reads a canonical map (below), updates each plugin's detector.yaml
# with the right fields, preserves all other content.
#
# Run from worktree root: python3 scripts/seed-categories.py

import pathlib
import re
import sys

# Canonical categorization. Three-pass review.
# Pass 1 — initial categorization based on what each detector attests.
# Pass 2 — verified by reading the plugin's predicate type + description.
# Pass 3 — multi-category review for tools with legitimate dual lifecycle.
CATEGORIES = {
    # build — CI-time evidence about how the artifact came to be
    "aws":            ["build"],          # AWS Instance Identity Document (CI runner identity)
    "aws-codebuild":  ["build"],          # CodeBuild runner context
    "docker":         ["build"],          # docker image builder; output is the artifact
    "gcp-iit":        ["build"],          # GCE/GKE runner identity
    "git":            ["build"],          # source commit + worktree state
    "github":         ["build"],          # GitHub Actions runner context
    "gitlab":         ["build"],          # GitLab CI runner context
    "jenkins":        ["build"],          # Jenkins runner context
    "lockfiles":      ["build"],          # dep manifest snapshot at build start
    "maven":          ["build"],          # Maven project coordinates
    "oci":            ["build"],          # OCI image artifact produced by docker save / skopeo copy
    "pip-install":    ["build"],          # pip install provenance (package + wheel digests)
    "sinkhole-flows": ["build"],          # pip-witness sandbox flows during build

    # artifact-scan — CI-time scanner output
    "govulncheck":    ["artifact-scan"],
    "sarif":          ["artifact-scan"],
    "test-results":   ["artifact-scan"],

    # statement — release-time assertion
    "vex":            ["statement"],

    # posture-scan — production-side configuration / compliance scans
    "aws-config":     ["posture-scan"],
    "asff":           ["posture-scan"],   # AWS Security Hub findings
    "docker-bench":   ["posture-scan"],
    "inspec":         ["posture-scan"],
    "kube-bench":     ["posture-scan"],
    "linkerd-check":  ["posture-scan"],
    "nessus":         ["posture-scan"],
    "oscap":          ["posture-scan"],
    "prowler":        ["posture-scan"],
    "steampipe":      ["posture-scan"],

    # runtime — production runtime observation
    "falco":          ["runtime"],

    # multi-category: legitimate dual lifecycle usage
    "sbom":           ["artifact-scan", "posture-scan"],   # syft scanning CI build vs running image
    "trivy":          ["artifact-scan", "posture-scan"],   # CI image scan vs prod registry / live cluster
}

# Upstream tool metadata. Format-only attestors (sarif, vex, sbom, test-results)
# don't have a single upstream tool — they're file format attestors. They get
# format_only: true and point at the spec.
UPSTREAMS = {
    "aws": {
        "name": "AWS Instance Metadata Service",
        "source": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        "license": "proprietary",
        "vendor": "Amazon Web Services",
    },
    "aws-codebuild": {
        "name": "AWS CodeBuild",
        "source": "https://aws.amazon.com/codebuild/",
        "license": "proprietary",
        "vendor": "Amazon Web Services",
    },
    "aws-config": {
        "name": "AWS Config",
        "source": "https://aws.amazon.com/config/",
        "license": "proprietary",
        "vendor": "Amazon Web Services",
    },
    "asff": {
        "name": "AWS Security Finding Format (ASFF)",
        "source": "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html",
        "license": "proprietary",
        "vendor": "Amazon Web Services",
    },
    "docker": {
        "name": "Docker",
        "source": "https://github.com/moby/moby",
        "license": "Apache-2.0",
        "vendor": "Docker, Inc. / Moby",
    },
    "docker-bench": {
        "name": "Docker Bench for Security",
        "source": "https://github.com/docker/docker-bench-security",
        "license": "Apache-2.0",
        "vendor": "Docker, Inc.",
    },
    "falco": {
        "name": "Falco",
        "source": "https://github.com/falcosecurity/falco",
        "license": "Apache-2.0",
        "vendor": "The Falco Authors (CNCF)",
    },
    "gcp-iit": {
        "name": "GCP Metadata Server / Instance Identity Token",
        "source": "https://cloud.google.com/compute/docs/instances/verifying-instance-identity",
        "license": "proprietary",
        "vendor": "Google Cloud",
    },
    "git": {
        "name": "Git",
        "source": "https://git-scm.com/",
        "license": "GPL-2.0-only",
        "vendor": "Software Freedom Conservancy",
    },
    "github": {
        "name": "GitHub Actions",
        "source": "https://docs.github.com/en/actions",
        "license": "proprietary",
        "vendor": "GitHub, Inc.",
    },
    "gitlab": {
        "name": "GitLab CI/CD",
        "source": "https://docs.gitlab.com/ee/ci/",
        "license": "MIT",
        "vendor": "GitLab Inc.",
    },
    "govulncheck": {
        "name": "govulncheck",
        "source": "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
        "license": "BSD-3-Clause",
        "vendor": "The Go Authors",
    },
    "inspec": {
        "name": "Chef InSpec",
        "source": "https://github.com/inspec/inspec",
        "license": "Apache-2.0",
        "vendor": "Progress Chef",
    },
    "jenkins": {
        "name": "Jenkins",
        "source": "https://github.com/jenkinsci/jenkins",
        "license": "MIT",
        "vendor": "Jenkins Project / CD Foundation",
    },
    "kube-bench": {
        "name": "kube-bench",
        "source": "https://github.com/aquasecurity/kube-bench",
        "license": "Apache-2.0",
        "vendor": "Aqua Security",
    },
    "linkerd-check": {
        "name": "Linkerd",
        "source": "https://github.com/linkerd/linkerd2",
        "license": "Apache-2.0",
        "vendor": "Linkerd Authors (CNCF)",
    },
    "maven": {
        "name": "Apache Maven",
        "source": "https://maven.apache.org/",
        "license": "Apache-2.0",
        "vendor": "Apache Software Foundation",
    },
    "nessus": {
        "name": "Nessus",
        "source": "https://www.tenable.com/products/nessus",
        "license": "commercial",
        "vendor": "Tenable, Inc.",
    },
    "oci": {
        "name": "OCI Image Specification",
        "source": "https://github.com/opencontainers/image-spec",
        "license": "Apache-2.0",
        "vendor": "Open Container Initiative",
    },
    "oscap": {
        "name": "OpenSCAP",
        "source": "https://github.com/OpenSCAP/openscap",
        "license": "LGPL-2.1-or-later",
        "vendor": "Red Hat / OpenSCAP project",
    },
    "pip-install": {
        "name": "pip",
        "source": "https://github.com/pypa/pip",
        "license": "MIT",
        "vendor": "Python Packaging Authority",
    },
    "prowler": {
        "name": "Prowler",
        "source": "https://github.com/prowler-cloud/prowler",
        "license": "Apache-2.0",
        "vendor": "Prowler Pro / community",
    },
    "sinkhole-flows": {
        "name": "pip-witness sinkhole",
        "source": "https://github.com/testifysec/pip-witness",
        "license": "Apache-2.0",
        "vendor": "TestifySec",
    },
    "steampipe": {
        "name": "Steampipe",
        "source": "https://github.com/turbot/steampipe",
        "license": "AGPL-3.0-only",
        "vendor": "Turbot HQ Inc.",
    },
    "trivy": {
        "name": "Trivy",
        "source": "https://github.com/aquasecurity/trivy",
        "license": "Apache-2.0",
        "vendor": "Aqua Security",
    },

    # Format-only attestors — emit a file format that any tool can produce.
    "sarif": {
        "name": "SARIF (Static Analysis Results Interchange Format)",
        "source": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html",
        "license": "OASIS",
        "vendor": "OASIS / OASIS SARIF TC",
        "format_only": True,
    },
    "sbom": {
        "name": "SPDX + CycloneDX",
        "source": "https://spdx.dev/  +  https://cyclonedx.org/",
        "license": "CC-BY-3.0 / Apache-2.0",
        "vendor": "Linux Foundation / OWASP",
        "format_only": True,
    },
    "vex": {
        "name": "OpenVEX",
        "source": "https://github.com/openvex",
        "license": "CC-BY-4.0",
        "vendor": "OpenSSF",
        "format_only": True,
    },
    "test-results": {
        "name": "JUnit XML + CTRF JSON",
        "source": "https://github.com/testmoapp/junitxml  +  https://ctrf.io",
        "license": "OASIS / community",
        "vendor": "JUnit / CTRF community",
        "format_only": True,
    },
}


def render_yaml_block(detector_name: str) -> str:
    """Render the category + upstream block as YAML text."""
    cats = CATEGORIES[detector_name]
    out = "category: [" + ", ".join(cats) + "]\n"

    up = UPSTREAMS.get(detector_name)
    if up:
        out += "\nupstream:\n"
        for k in ("name", "source", "license", "vendor"):
            if k in up:
                v = up[k]
                # Quote if value contains characters yaml might choke on
                if any(c in v for c in ":#"):
                    out += f'  {k}: "{v}"\n'
                else:
                    out += f"  {k}: {v}\n"
        if up.get("format_only"):
            out += "  format_only: true\n"
    return out


def update_file(path: pathlib.Path, detector_name: str):
    src = path.read_text()
    new_block = render_yaml_block(detector_name)

    # Strip any existing category: line or block (idempotent re-run)
    src = re.sub(r"^category:\s*\[[^\]]*\]\s*\n", "", src, flags=re.M)
    src = re.sub(r"^upstream:\s*\n(?:  [^\n]*\n)+", "", src, flags=re.M)

    # Insert after the description line.
    # Locate "description: ..." (single-line value).
    m = re.search(r"^description:[^\n]*\n", src, flags=re.M)
    if not m:
        print(f"  WARN: {path}: no description line; skipping", file=sys.stderr)
        return False
    insert_at = m.end()
    new_src = src[:insert_at] + "\n" + new_block + src[insert_at:]
    # Collapse triple blank lines that can arise from the insertion.
    new_src = re.sub(r"\n{3,}", "\n\n", new_src)
    path.write_text(new_src)
    return True


def main():
    root = pathlib.Path("plugins/attestors")
    if not root.exists():
        print("run from worktree root", file=sys.stderr)
        sys.exit(2)
    updated = 0
    skipped = 0
    for name in sorted(CATEGORIES):
        ypath = root / name / "detector.yaml"
        if not ypath.exists():
            print(f"  SKIP {name}: no detector.yaml", file=sys.stderr)
            skipped += 1
            continue
        if update_file(ypath, name):
            updated += 1
            print(f"  ok   {name}")
    print(f"\n{updated} updated, {skipped} skipped")


if __name__ == "__main__":
    main()
