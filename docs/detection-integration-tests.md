# Detection — integration test plan

Most detector unit tests run against synthetic inputs (argv, env, filesystem
fixtures, injected probe results) and validate that the matcher engine
produces the right fire/skip/warning decisions. Those tests live in each
plugin's `detector_test.go`.

A subset of detectors — the cloud-metadata ones — assert behavior that
**only manifests on the actual platform**. Their unit tests inject probe
results via `detection.InjectProbeResult(name, value)` so the matcher
logic is exercised without network access, but the underlying HTTP probe
to the metadata endpoint can only be validated by running on the cloud.

This document records what to run, where to run it, and what to assert.

## Threat model summary

| Attestor | Probe | What needs cloud validation |
|---|---|---|
| `aws` | `imds_reachable` (AWS IMDSv2 token route) | HEAD against `http://169.254.169.254/latest/api/token` returns within 500ms on EC2; times out otherwise. |
| `gcp-iit` | `gcp_metadata_reachable` (GCP metadata server) | HEAD against `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google` header returns within 500ms on GCE; times out otherwise. |
| (reserved) | `azure_metadata_reachable` | HEAD against `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with `Metadata: true` header returns within 500ms on Azure VM; times out otherwise. |

> Note on naming: the AWS detector lives in the `plugins/attestors/aws-iid/`
> directory, but its `detector.yaml` registers under the attestor name
> `aws` (see `plugins/attestors/aws-iid/detector.yaml` line 2). `cilock
> attestors list` and the `cilock plan` output both call it `aws`. Use
> `aws` everywhere you select or pass the attestor; `aws-iid` is only the
> source directory.

## Integration test commands

### EC2 (aws)

```bash
# Launch a small EC2 instance (free-tier eligible). Any AMI works; the
# probe is host-os agnostic.
aws ec2 run-instances --image-id ami-XXXXXXXXXXXXXXXXX \
  --instance-type t3.micro --key-name <your-key> ...

# SSH in, install cilock, then:
cilock plan --format=json -- echo test | jq '.plan.fire[] | select(.attestor=="aws") '
# Expect a hit. The pre-gate match is imds_reachable=true.

# Force a negative: run the probe outside any cloud (or in a network
# namespace that drops 169.254.169.254). Expect no match.
```

### GCE (gcp-iit)

```bash
# Launch a small Compute Engine VM:
gcloud compute instances create cilock-iit-test \
  --machine-type=e2-micro --image-family=debian-12 ...

# SSH in, run cilock plan and confirm gcp-iit fires:
cilock plan --format=json -- echo test | jq '.plan.fire[] | select(.attestor=="gcp-iit")'
```

### Azure VM (when an azure attestor lands)

```bash
az vm create --resource-group <rg> --name cilock-azure-test \
  --image Ubuntu2204 --size Standard_B1s ...
# ssh + cilock plan as above
```

## Cross-host disambiguation

Both AWS IMDS and GCP metadata answer on `169.254.169.254`, but the
required headers differ:

- AWS IMDSv2: no `Metadata-Flavor` header, HEAD on `/latest/api/token`
- GCP: `Metadata-Flavor: Google` required
- Azure: `Metadata: true` required

The probes use the appropriate header for each cloud, so a host with
none of them returns false for all three; a host on AWS returns true
only for `imds_reachable`; etc.

## When to run

- Before any change that touches `attestation/detection/probes.go`.
- Quarterly, to catch metadata-endpoint changes from the cloud providers
  (rare but has happened — Azure changed required headers in 2018).
- When adding a new metadata-probe-based detector (Oracle Cloud, IBM
  Cloud, Hetzner, etc.).

## What unit tests cover today

`attestation/detection/probes_test.go`:

- `TestCloudMetadataProbesWithInjection` — matcher correctness for all
  three probes (imds, gcp, azure) given fixed boolean probe results.
- `TestSocketListeningProbe` — real local socket dial against a test
  listener. Cross-platform, no cloud needed.
- `TestProbeCacheOnce` — cachedProbe runs its function exactly once
  per name.

Per-plugin unit tests (`plugins/attestors/aws-iid/detector_test.go`,
`plugins/attestors/gcp-iit/detector_test.go`) inject probe results
and assert end-to-end detector firing. They cover the matcher path but
not the real HTTP behavior.

## How an LLM consumer should think about this

If you are an LLM agent running cilock on behalf of a user and the user
is "on EC2" (you can verify with a single HTTP probe), the aws
attestor will fire automatically when you invoke `cilock plan`. You do
not need to pass `-a aws` explicitly. The same applies to GCP / GCE.

If the probe fails or times out (network namespace, restricted egress,
cloud provider issue), the detector silently skips with cause `no-match`.
This is intentional: better to miss an attestation than to block the
build on a flaky metadata endpoint.
