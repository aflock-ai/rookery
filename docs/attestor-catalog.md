# Attestor catalog

This is the canonical name reference. **The name in column 1 is what you pass to `--attestations` (or `cilock-action`'s `attestations:` input).** It is NOT always the directory name — `commandrun` lives at `plugins/attestors/commandrun/` but registers itself as `command-run`, and similar splits exist for `github-action`, `aws-iid → aws`. Passing the import-path form ("commandrun") fails fast with `attestor not found`.

The table is grouped by run phase (the order in which the phase fires). Within a phase, attestors fire in registration order — for most flows that ordering is not load-bearing.

Regenerate after adding or renaming an attestor:

```
./scripts/gen-attestor-catalog.sh
```


## Pre-material (environment capture)

| Name | Import path | Predicate type |
|---|---|---|
| `aws-codebuild` | `plugins/attestors/aws-codebuild` | `https://aflock.ai/attestations/aws-codebuild/v0.1` |
| `aws` | `plugins/attestors/aws-iid` | `https://aflock.ai/attestations/aws/v0.1` |
| `configuration` | `plugins/attestors/configuration` | `https://aflock.ai/attestations/configuration/v0.2` |
| `environment` | `plugins/attestors/environment` | `https://aflock.ai/attestations/environment/v0.1` |
| `gcp-iit` | `plugins/attestors/gcp-iit` | `https://aflock.ai/attestations/gcp-iit/v0.1` |
| `github-review` | `plugins/attestors/github-review` | `https://aflock.ai/attestations/github-review/v0.1` |
| `github` | `plugins/attestors/github` | `https://aflock.ai/attestations/github/v0.1` |
| `gitlab` | `plugins/attestors/gitlab` | `https://aflock.ai/attestations/gitlab/v0.1` |
| `git` | `plugins/attestors/git` | `https://aflock.ai/attestations/git/v0.1` |
| `jenkins` | `plugins/attestors/jenkins` | `https://aflock.ai/attestations/jenkins/v0.1` |
| `jwt` | `plugins/attestors/jwt` | `https://aflock.ai/attestations/jwt/v0.1` |
| `lockfiles` | `plugins/attestors/lockfiles` | `https://aflock.ai/attestations/lockfiles/v0.1` |
| `maven` | `plugins/attestors/maven` | `https://aflock.ai/attestations/maven/v0.1` |
| `omnitrail` | `plugins/attestors/omnitrail` | `https://aflock.ai/attestations/omnitrail/v0.1` |
| `system-packages` | `plugins/attestors/system-packages` | `https://aflock.ai/attestations/system-packages/v0.1` |

## Material (input snapshot)

| Name | Import path | Predicate type |
|---|---|---|
| `material` | `plugins/attestors/material` | `https://aflock.ai/attestations/material/v0.3` |

## Execute (the wrapped step)

| Name | Import path | Predicate type |
|---|---|---|
| `command-run` | `plugins/attestors/commandrun` | `https://aflock.ai/attestations/command-run/v0.1` |
| `github-action` | `plugins/attestors/githubaction` | `https://aflock.ai/attestations/github-action/v0.1` |

## Product (output snapshot)

| Name | Import path | Predicate type |
|---|---|---|
| `product` | `plugins/attestors/product` | `https://aflock.ai/attestations/product/v0.3` |

## Post-product (analysis of outputs)

| Name | Import path | Predicate type |
|---|---|---|
| `asff` | `plugins/attestors/asff` | `https://aflock.ai/attestations/asff/v0.1` |
| `aws-config` | `plugins/attestors/aws-config` | `https://aflock.ai/attestations/aws-config/v0.1` |
| `docker-bench` | `plugins/attestors/docker-bench` | `https://aflock.ai/attestations/docker-bench/v0.1` |
| `docker` | `plugins/attestors/docker` | `https://aflock.ai/attestations/docker/v0.1` |
| `falco` | `plugins/attestors/falco` | `https://aflock.ai/attestations/falco/v0.1` |
| `githubwebhook` | `plugins/attestors/githubwebhook` | `https://aflock.ai/attestations/githubwebhook/v0.1` |
| `go-build` | `plugins/attestors/go-build` | `https://aflock.ai/attestations/go-build/v0.1` |
| `govulncheck` | `plugins/attestors/govulncheck` | `https://aflock.ai/attestations/govulncheck/v0.1` |
| `inclusion-proof` | `plugins/attestors/inclusion-proof` | `https://aflock.ai/attestations/inclusion-proof/v0.1` |
| `inspec` | `plugins/attestors/inspec` | `https://aflock.ai/attestations/inspec/v0.1` |
| `k8smanifest` | `plugins/attestors/k8smanifest` | — |
| `kube-bench` | `plugins/attestors/kube-bench` | `https://aflock.ai/attestations/kube-bench/v0.1` |
| `linkerd-check` | `plugins/attestors/linkerd-check` | `https://aflock.ai/attestations/linkerd-check/v0.1` |
| `link` | `plugins/attestors/link` | `https://in-toto.io/attestation/link/v0.3` |
| `oci` | `plugins/attestors/oci` | `https://aflock.ai/attestations/oci/v0.1` |
| `oscap` | `plugins/attestors/oscap` | `https://aflock.ai/attestations/oscap/v0.1` |
| `pip-install` | `plugins/attestors/pip-install` | `https://aflock.ai/attestations/pip-install/v0.1` |
| `prowler` | `plugins/attestors/prowler` | `https://aflock.ai/attestations/prowler/v0.1` |
| `sarif` | `plugins/attestors/sarif` | `https://aflock.ai/attestations/sarif/v0.1` |
| `sbom` | `plugins/attestors/sbom` | `https://aflock.ai/attestations/sbom/v0.1` |
| `scubagoggles` | `plugins/attestors/scubagoggles` | `https://aflock.ai/attestations/scubagoggles/v0.1` |
| `secretscan` | `plugins/attestors/secretscan` | `https://aflock.ai/attestations/secretscan/v0.1` |
| `sinkhole-flows` | `plugins/attestors/sinkhole-flows` | `https://aflock.ai/attestations/sinkhole-flows/v0.1` |
| `slsa` | `plugins/attestors/slsa` | `https://slsa.dev/provenance/v1` |
| `steampipe` | `plugins/attestors/steampipe` | `https://aflock.ai/attestations/steampipe/v0.1` |
| `structured-data` | `plugins/attestors/structured-data` | `https://aflock.ai/attestations/structured-data/v0.1` |
| `test-results` | `plugins/attestors/test-results` | `https://aflock.ai/attestations/test-results/v0.1` |
| `trivy` | `plugins/attestors/trivy` | `https://aflock.ai/attestations/trivy/v0.1` |
| `vex` | `plugins/attestors/vex` | `https://openvex.dev/ns` |

## Verify (policy-time)

| Name | Import path | Predicate type |
|---|---|---|
| `policyverify` | `plugins/attestors/policyverify` | — |
| `vsa` | `plugins/attestors/vsa` | `https://slsa.dev/verification_summary/v1` |

## Notes

- **`command-run` vs `commandrun`**: the package is `commandrun`, the registered Name is `command-run`. Use the hyphenated name.
- **`github-action` vs `githubaction`**: same split.
- **`aws` vs `aws-iid`**: the package is `aws-iid` (AWS Instance Identity Document); the registered Name is `aws` because that's the source attestor for AWS-runner identity. Predicate-type lookup also resolves the `aws-iid`-shaped legacy URI to the same factory.
- **`product` vs `ProductName`**: the registry name is `product`; the constant in the package is `ProductName` (legacy naming). Pass `product`.
- **VSA attestors (`vsa`, `policyverify`)** run during `cilock verify`, not during `cilock run`. They are not added to a run by name from `--attestations`; cilock wires them automatically based on the verify mode.

## Default sets

| Surface | Default attestors |
|---|---|
| `cilock run` (no `--attestations`) | environment, git, github, gitlab, jenkins, jwt, aws, gcp-iit, github-action, command-run, material, product |
| `cilock-action` (no `attestations:` input) | environment, git, github |

When passing `--attestations`, you replace the default — you don't add to it. To extend rather than replace, list the defaults explicitly.
