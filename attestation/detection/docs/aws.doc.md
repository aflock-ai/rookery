---
title: aws (aws-iid)
description: The cilock aws attestor fetches the EC2 instance identity document from IMDS, verifies its RSA-SHA256 signature against the AWS region certificate, and signs the verified host identity into in-toto evidence.
sidebar_position: 16
examples_repo: 25-aws
---

Fetches the EC2 instance identity document (IID) from the AWS instance metadata service and verifies its RSA-SHA256 signature against the per-region AWS public certificate, binding a step to a specific EC2 instance, account, AMI, and private IP.

## What it captures

The attestor reads `instance-identity/document` and `instance-identity/signature` from IMDS, unmarshals the document into the AWS SDK's `imds.InstanceIdentityDocument` (embedded), and retains the raw bytes plus the public key used for verification.

Embedded IID fields (15): `devpayProductCodes`, `marketplaceProductCodes`, `availabilityZone`, `privateIp`, `version`, `region`, `instanceId`, `billingProducts`, `instanceType`, `accountId`, `pendingTime`, `imageId`, `kernelId`, `ramdiskId`, `architecture`.

Top-level fields (3): `rawiid` (raw JSON document as returned by IMDS), `rawsig` (base64 signature as returned by IMDS), and `publickey` (PEM-encoded RSA public key extracted from the AWS region certificate used for verification).

Verification: `sha256(rawiid)` is checked against `base64-decode(rawsig)` via `rsa.VerifyPKCS1v15`. The signature algorithm is RSA-SHA256 — this is the `instance-identity/signature` endpoint, not the PKCS#7 endpoint. The region certificate must use RSA; non-RSA public keys are rejected.

Subjects: `instanceid:<id>`, `accountid:<id>`, `imageid:<id>`, `privateip:<ip>` (each hashed with SHA-256).

## When to use

Add to any cilock step that runs on an EC2 instance and where you want downstream policy to constrain by AWS account, AMI, instance type, or region. Particularly useful for self-hosted GitHub Actions runners and build agents on EC2, where the IID provides cryptographic proof of host identity.

## Flags

| Flag | Description |
|---|---|
| `--attestor-aws-region-cert` | A public x509 certificate (PEM) or path to a PEM file used to verify the AWS instance identity document signature. Empty string is rejected. If unset, the attestor falls back to a bundled certificate for the IID's region. |

## Output shape

```json
{
  "devpayProductCodes": null,
  "marketplaceProductCodes": null,
  "availabilityZone": "us-east-1a",
  "privateIp": "10.0.0.42",
  "version": "2017-09-30",
  "region": "us-east-1",
  "instanceId": "i-0abcd1234ef567890",
  "billingProducts": null,
  "instanceType": "m5.large",
  "accountId": "123456789012",
  "pendingTime": "2026-05-21T15:04:05Z",
  "imageId": "ami-0123456789abcdef0",
  "kernelId": "",
  "ramdiskId": "",
  "architecture": "x86_64",
  "rawiid": "{\"accountId\":\"123456789012\", ...}",
  "rawsig": "base64-encoded-rsa-signature",
  "publickey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

## Gotchas

- **IMDSv2 by default.** The attestor builds its IMDS client via `imds.NewFromConfig(awsConfig)` with SDK defaults, which enable the token provider — calls go out as IMDSv2 (PUT `/api/token`, then GET with `X-aws-ec2-metadata-token`). The SDK transparently falls back to IMDSv1 when the token PUT fails, so hosts still on IMDSv1-only continue to work.
- **Non-EC2 hosts hard-fail the step.** `getIID()` returns `failed to get instance identity document` when IMDS is unreachable (no `169.254.169.254`, blocked by hop limit, or running outside EC2). `Attest()` surfaces this as a hard error.
- **Signature verification is mandatory.** If `Verify()` fails — bad signature, expired region cert, missing region cert for an unknown region, or non-RSA cert — the entire attestation fails. There is no opt-out.
- **Region cert source.** When `--attestor-aws-region-cert` is unset, the attestor uses the region from the loaded AWS config (or, if empty, the region inside the IID itself) to look up a certificate from an embedded map covering 36 standard regions. Unknown regions (new launches, GovCloud, China, Secret regions, etc.) must supply a cert via the flag.
- **Cert validity is checked.** The embedded certificates have `NotBefore`/`NotAfter` windows; expired or not-yet-valid certs are rejected before signature verification. Keep cilock builds current as AWS rotates region certs.
- **AWS config required.** `Attest()` calls `config.LoadDefaultConfig` when no config was injected; this can fail on hosts with no AWS configuration even where IMDS itself would have worked.

## CLI example

Real EC2 instance identity document fetched from IMDSv2, verified against the AWS-published regional certificate.

```bash
cilock run --step ec2-identity \
  --signer-file-key-path key.pem --outfile attestation.json --workingdir . \
  --attestations aws \
  --attestor-aws-region-cert /path/to/aws-us-east-1.pem \
  -- echo "captured EC2 instance identity" 
```

Validated against a real EC2 t3.small in us-east-1f. The us-east-1 cert is embedded in the attestor but must currently be passed via `--attestor-aws-region-cert` due to a setter-validation bug (filed). See the full real-data example at [https://github.com/aflock-ai/attestor-compliance-examples/tree/main/25-aws](https://github.com/aflock-ai/attestor-compliance-examples/tree/main/25-aws).

## See also

- [Catalog row](../reference/attestor-catalog)
- [`aws-codebuild`](./aws-codebuild)
- Upstream: [witness/aws.md](https://github.com/in-toto/witness/blob/main/docs/attestors/aws.md)
