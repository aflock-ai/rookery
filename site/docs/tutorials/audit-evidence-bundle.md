---
title: Audit evidence bundle
sidebar_position: 7
---

# Producing an audit evidence bundle

An auditor asks: *"Show me proof that release v1.4.2 was built from main, ran the SAST scanner, produced an SBOM, didn't use unpinned actions, and was signed by an authorized identity."*

The answer should not be "let me forward you some Slack screenshots." It should be a single signed archive: every CI/lock attestation produced by the release pipeline, plus the policy that gated promotion, plus the verification report, plus a manifest telling the auditor which file answers which question. This tutorial walks through producing exactly that.

Everything below composes primitives already exercised in [the supply-chain defense tutorial](./defending-against-supply-chain-attacks), [the five-step GitHub Actions pipeline](./github-actions-pipeline), [the container signing tutorial](./sign-and-verify-container), and [the release promotion gate](./release-promotion-gate). No new CI/lock features. Just careful packaging.

## What goes in the bundle

| Section | What's in it | Comes from |
|---|---|---|
| `pipeline/` | The 5 per-step DSSE envelopes plus their products (SARIF, SBOM, binary) | The [5-step pipeline run](./github-actions-pipeline) |
| `container/` | The docker-build attestation (with `docker`, `oci`, `sbom` predicates), the OCI tarball, the image SBOM | The [container signing run](./sign-and-verify-container) |
| `gate/` | The build attestation that was the input to `cilock verify`, plus its companion public key | The [release-promotion-gate run](./release-promotion-gate) |
| `policy/` | The signed policy + the public key needed to verify the policy itself | Whatever you used at promotion time |
| `verify-report.txt` | Captured stdout/stderr of a fresh `cilock verify` run against the included attestations | Re-run at bundle-creation time |
| `MANIFEST.md` | The auditor-question table from below | Generated |
| `audit-bundle.attestation.json` | A signed attestation whose materials are every file above | `cilock run --step audit-bundle -- tar czf ...` |

The last row is the trick. By wrapping the `tar` step with `cilock run`, the bundle's contents become the materials of a new attestation. Anyone re-deriving the tarball later can hash it against `audit-bundle.attestation.json` and prove the archive hasn't been edited since.

## Step 1: Collect attestations for a release

In a real release pipeline you'd query Archivista by commit SHA. For demo-cilock we pull artifacts from the prior workflow runs:

```yaml
- name: Resolve source runs
  id: resolve
  env:
    GH_TOKEN: ${{ github.token }}
  run: |
    PIPELINE_ID=$(gh run list -R ${{ github.repository }} \
      --workflow=github-actions-pipeline.yml \
      --status=success --limit=1 --json databaseId -q '.[0].databaseId')
    CONTAINER_ID=$(gh run list -R ${{ github.repository }} \
      --workflow=sign-and-verify-container.yml \
      --status=success --limit=1 --json databaseId -q '.[0].databaseId')
    GATE_ID=$(gh run list -R ${{ github.repository }} \
      --workflow=release-promotion-gate.yml \
      --status=success --limit=1 --json databaseId -q '.[0].databaseId')
    echo "pipeline-id=$PIPELINE_ID" >> "$GITHUB_OUTPUT"
    echo "container-id=$CONTAINER_ID" >> "$GITHUB_OUTPUT"
    echo "gate-id=$GATE_ID" >> "$GITHUB_OUTPUT"

- name: Download artifacts from each source run
  env:
    GH_TOKEN: ${{ github.token }}
  run: |
    mkdir -p bundle/pipeline bundle/container bundle/gate
    gh run download ${{ steps.resolve.outputs.pipeline-id }} \
      -R ${{ github.repository }} -n pipeline-attestations -D bundle/pipeline
    gh run download ${{ steps.resolve.outputs.container-id }} \
      -R ${{ github.repository }} -n build-evidence       -D bundle/container
    gh run download ${{ steps.resolve.outputs.gate-id }} \
      -R ${{ github.repository }} -n build-bundle         -D bundle/gate
```

`gh run download` requires `permissions: actions: read` on the workflow.

## Step 2: Re-run verify against the assembled inputs

Don't trust that the gate ran. Re-run `cilock verify` from inside the bundling job and capture the output:

```bash
cd bundle/gate
KEYID=$(sha256sum signing.pub | awk '{print $1}')
PUBKEY_B64=$(base64 < signing.pub | tr -d '\n')
sed -e "s|__PUBKEY_ID__|${KEYID}|g" -e "s|__PUBKEY_B64__|${PUBKEY_B64}|g" \
    policies/policy-promotion-template.json > policy.json
cilock sign -f policy.json -o policy-signed.json -k signing.key

cilock verify \
  -p policy-signed.json -k signing.pub \
  -a build.attestation.json -f myapp \
  --enable-archivista=false 2>&1 | tee ../verify-report.txt
```

`verify-report.txt` is the human-readable receipt the auditor wants alongside the raw evidence.

## Step 3: Write the manifest

The auditor doesn't want to grep through DSSE envelopes. They want a table:

```markdown
# Release evidence manifest

| Auditor question | Evidence file | How to inspect |
|---|---|---|
| Show me the SBOM for this release. | `pipeline/build.attestation.json` | `jq -r .payload < $f \| base64 -d \| jq '.predicate.attestations[] \| select(.type \| test("cyclonedx")) \| .attestation'` |
| Prove the SAST scanner ran before this build. | `pipeline/sast.attestation.json`, `pipeline/gosec-results.sarif` | `jq ...` |
| Prove the image in production matches what was built. | `container/build.attestation.json` `oci` predicate's `imageid` | `jq ...` |
| Show that policy gated the release. | `verify-report.txt` (line: `Verification succeeded / Evidence: Step: build`) | `cat verify-report.txt` |
| Prove this bundle hasn't been edited since release. | `audit-bundle.attestation.json` (materials' digests) | `jq ...` |
```

Generate the manifest from a template so it stays in sync with the bundle contents.

## Step 4: Sign the bundle itself

Wrap the `tar` step with `cilock run` so the bundle's materials become a signed attestation:

```bash
cilock run \
  --step audit-bundle \
  -k signing.key \
  --enable-archivista=false \
  -o audit-bundle.attestation.json \
  -- tar czf release-evidence.tar.gz bundle/ verify-report.txt MANIFEST.md
```

Now the materials section of `audit-bundle.attestation.json` lists every file's sha256, and the products section lists the tarball's sha256. The bundle is a notarized record of itself.

## Step 5: Replay from a clean clone

Six months from now, the auditor downloads the bundle and runs:

```bash
#!/usr/bin/env bash
# replay-audit-bundle.sh
set -euo pipefail

BUNDLE="${1:?usage: replay-audit-bundle.sh <release-evidence.tar.gz> <audit-bundle.attestation.json> <bundle.pub>}"
ATTESTATION="${2:?see usage}"
BUNDLE_PUB="${3:?see usage}"

tar xzf "$BUNDLE"

# Confirm every bundled file's digest matches the audit-bundle attestation.
# The material attestor stores entries as { "<path>": { "sha256": "..." }, ... }
# directly under .attestation, no nested "materials" key.
jq -r .payload < "$ATTESTATION" | base64 -d \
  | jq -r '.predicate.attestations[]
           | select(.type | test("material"))
           | .attestation
           | to_entries[]
           | "\(.value.sha256)  \(.key)"' \
  > expected.sha256
sha256sum --check expected.sha256

# Re-run cilock verify against the bundled build attestation. The bundle
# carries the already-signed policy plus the public key, so no signing
# key is needed on the verifier side.
cd bundle/gate
cilock verify \
  -p policy-signed.json -k signing.pub \
  -a build.attestation.json -f myapp \
  --enable-archivista=false
```

Two checks: the bundle's contents match what the notary attestation recorded (`sha256sum --check`), and the gate policy still passes when re-run from cold storage (`cilock verify`). If either fails, the evidence has been tampered with or the policy was rewritten since the release. Either is grounds for rejection.

## The canonical auditor questions

| Question | Evidence | Predicate type |
|---|---|---|
| What source built this release? | `pipeline/build.attestation.json` subject `commithash:...` | `git` |
| Who triggered the build? | The Fulcio cert's `URI:` SAN inside the DSSE envelope | (cert chain) |
| Were any actions unpinned? | The github-action attestor's `actionref` and `refpinned` fields, per [tutorial 1](./defending-against-supply-chain-attacks) | `github-action` |
| Did the SAST scanner run? | `pipeline/sast.attestation.json` | `sarif` |
| What did the SAST scanner find? | `pipeline/gosec-results.sarif` | (raw SARIF) |
| Is there a signed SBOM? | `pipeline/build.attestation.json` predicate | `https://cyclonedx.org/bom` |
| Is the image in production the one that was built? | `container/build.attestation.json` `oci` predicate's `imageid` cross-checks the registry manifest's `.config.digest`; see [tutorial 4](./sign-and-verify-container) | `oci` |
| Was the cosign signature valid? | `container/cosign-verify.txt` (output of `cosign verify`) | (cosign) |
| Did policy gate the promotion? | `verify-report.txt` containing `Verification succeeded / Evidence: Step: build` | (`cilock` verify output) |
| Was any secret leaked through stdout? | Each step's `secretscan` predicate (if enabled); see [tutorial 1](./defending-against-supply-chain-attacks) | `secretscan` |
| Did anything covertly read credentials from disk? | Each step's `command-run` predicate's `processes[].openedfiles` (if `--trace` was on); see [tutorial 1](./defending-against-supply-chain-attacks) | `command-run` |
| Has the evidence been edited since release? | `audit-bundle.attestation.json` materials' digests vs. `sha256sum` of bundle contents | `material` |

Treat this table as the contract. If you add a new attestor in CI, add a row here so an auditor knows where to find its answer.

## What this is not

- **Not a substitute for retention policy.** GitHub Actions artifacts default to 90 days. If you want the bundle available 5 years later, push it to durable object storage (S3, GCS) at release time and record the upload as a separate `cilock run` step so the upload itself is attested.
- **Not a substitute for Archivista.** Archivista is the supply-chain-native attestation store; an evidence bundle is what you hand an auditor who doesn't speak GraphQL. Both can coexist; pull the bundle's contents from Archivista at release time.
- **Not free of the upstream limitations.** Detection is post-execution, trace is Linux-only, network egress isn't recorded. See the [trust model page](../concepts/trust-model) for the honest list.

## Further reading

- [Verify in a release gate](../guides/verify-in-a-release-gate), the operational guidance for soft-fail vs. fail-closed and where in your CD the bundle creation step belongs.
- [NIST SP 800-204D](https://csrc.nist.gov/pubs/sp/800/204/d/final), the standard that calls out signed pipeline attestations as a first-class control. Frederick Kautz of TestifySec is a co-author.
- Cole's blog [Preventing the Claude Code Leak with Attestation Policies](https://testifysec.com/blog/preventing-claude-code-leak-attestation-policies) walks through the same wrap-attest-policy-verify loop against the March 2026 Claude Code source map incident; the policy enforcement pattern is identical, just over one step instead of a release-wide bundle.
