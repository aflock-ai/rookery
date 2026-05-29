---
title: jenkins
description: The cilock jenkins attestor captures Jenkins build metadata from JENKINS_/BUILD_ environment variables and signs it into in-toto evidence, binding an artifact to the pipeline run that produced it.
sidebar_position: 14
examples_repo: 23-jenkins
---

Captures Jenkins build metadata from `JENKINS_*`, `BUILD_*`, and related environment variables exported into the build's shell, binding the artifact to the pipeline run that produced it.

## What it captures

The attestor first checks for `JENKINS_URL`. If unset, it returns `ErrNotJenkins` ("not in a jenkins ci job") and contributes nothing. Otherwise it reads the following environment variables and writes them to the json-tagged fields below:

| Field (JSON) | Env var |
|---|---|
| `buildid` | `BUILD_ID` |
| `buildnumber` | `BUILD_NUMBER` |
| `buildtag` | `BUILD_TAG` |
| `pipelineurl` | `BUILD_URL` |
| `executornumber` | `EXECUTOR_NUMBER` |
| `javahome` | `JAVA_HOME` |
| `jenkinsurl` | `JENKINS_URL` |
| `jobname` | `JOB_NAME` |
| `nodename` | `NODE_NAME` |
| `workspace` | `WORKSPACE` |

Two subjects are recorded as SHA-256 digests of the literal URL strings: `` `pipelineurl:<BUILD_URL>` `` and `` `jenkinsurl:<JENKINS_URL>` ``. Only `pipelineurl:` is exposed as a back-reference for chaining.

## When to use

Use this attestor on any Jenkins-driven CI job where you want the resulting attestation to record which pipeline, job, build number, and agent node produced an artifact. Jenkins does not ship a native OIDC identity for build jobs, so this attestor only records self-reported environment variables — pair it with [`jwt`](./jwt) when a Jenkins plugin (for example, the OIDC Provider plugin) issues a verifiable token that can stand in as the functionary identity.

## Flags

None. The attestor consumes environment variables only; there are no `--attestor-jenkins-*` flags.

## Output shape

```json
{
  "buildid": "42",
  "buildnumber": "42",
  "buildtag": "jenkins-my-job-42",
  "pipelineurl": "https://jenkins.example.com/job/my-job/42/",
  "executornumber": "0",
  "javahome": "/opt/java/openjdk",
  "jenkinsurl": "https://jenkins.example.com/",
  "jobname": "my-job",
  "nodename": "built-in",
  "workspace": "/var/jenkins_home/workspace/my-job"
}
```

## Gotchas

- All fields are unverified, self-reported strings from the build environment. Anything with write access to the shell — a `sh` step, an upstream pipeline, a malicious dependency — can overwrite them before `cilock` runs. Treat this attestor as build-context metadata, not as proof of provenance.
- Detection hinges on `JENKINS_URL` being present. If a shell step unsets or shadows it (`env -i`, container with a scrubbed environment), `Attest` returns `ErrNotJenkins{}` and the attestor contributes nothing.
- On modern Jenkins, `BUILD_ID` is identical to `BUILD_NUMBER`; both fields are populated for backward compatibility and will usually match.
- Subjects are digests of the URL *strings*, not of their contents. They identify the pipeline run but do not attest that the URL resolves to anything.
- `JAVA_HOME` is recorded if present in the environment regardless of whether the job uses Java; it reflects the controller/agent JDK, not the build toolchain.
- Despite the upstream witness doc mentioning a `BUILD_USER` field, this implementation does **not** read `BUILD_USER` — the actor field is absent from the predicate.

## CLI example

Real Jenkins runtime context. Reads canonical Jenkins env vars (`BUILD_ID`, `BUILD_URL`, `JOB_NAME`, `JENKINS_URL`) exposed by the agent.

```bash
# In a Jenkins pipeline / freestyle job:
cilock run --step jenkins-validation \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations jenkins,environment \
  -- echo "captured Jenkins context" 
```

Validated by setting the canonical Jenkins env vars in shell. The attestor reads from env, no other inputs. See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/23-jenkins](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/23-jenkins).

## See also

- [Catalog row](../reference/attestor-catalog)
- [`jwt`](./jwt) for OIDC via Jenkins plugins
- Upstream: [witness/jenkins.md](https://github.com/in-toto/witness/blob/main/docs/attestors/jenkins.md)
