# Cloud validation — proving the catalog works against real cloud APIs

The detection catalog ships with attestation recipes for AWS data-plane
services. Each recipe issues a real API call against a real AWS account
and verifies that cilock produces a signed bundle. The current
validation account is `testifysec-demo` (898769392027), profile
`testifysec-demo`.

## Setup

```bash
# 1. SSO login (one-time per session)
aws sso login --profile testifysec-demo

# 2. Generate the signing keypair (or use your own)
mkdir -p .catalog-test/keys
openssl genpkey -algorithm ed25519 -out .catalog-test/keys/signer.key
openssl pkey -in .catalog-test/keys/signer.key -pubout \
  -out .catalog-test/keys/signer.pub

# 3. Build the all-attestors binary
cd presets/all && go build -o /tmp/cilock-all-cat ./cmd/cilock-all
```

## Validated AWS recipes (testifysec-demo)

| Recipe                  | API surface                            | What gets attested                          |
| ----------------------- | -------------------------------------- | ------------------------------------------- |
| `cloudtrail`            | `aws cloudtrail lookup-events`         | Last 5 audit-log events as JSON product     |
| `aws-secrets-manager`   | `aws secretsmanager list-secrets`      | Secret names + ARNs (no values)             |
| `aws-config`            | `aws configservice get-compliance-...` | Per-rule EvaluationResults                  |
| `prowler`               | `prowler aws --checks ...`             | Posture findings in OCSF JSON               |
| `steampipe`             | `steampipe query`                      | SQL-over-API query results                  |
| `aws-security-hub`      | `aws securityhub get-findings`         | Aggregated findings from across services    |
| `aws-inspector`         | `aws inspector2 list-findings`         | Vuln + reachability findings for EC2/ECR    |
| `aws-guardduty`         | `aws guardduty list-detectors/findings`| Threat-detection findings                   |
| `aws-macie`             | `aws macie2 get-macie-session`         | Sensitive-data discovery state              |
| `aws-iam-credential-report` | `aws iam get-credential-report`    | Per-user MFA + key-age + password-age posture |

## Running

```bash
# All recipes (~80, including non-AWS)
python3 scripts/test-catalog-tools.py

# Just the AWS subset
python3 scripts/test-catalog-tools.py \
  cloudtrail aws-secrets-manager aws-config prowler steampipe \
  aws-security-hub aws-inspector aws-guardduty aws-macie \
  aws-iam-credential-report

# Report lands at:
cat .catalog-test/report.md
```

## Real findings surfaced during this PR

While validating against `testifysec-demo`, two security findings
surfaced — captured as evidence in signed bundles at
`.catalog-test/bundles/`:

### 1. Root account has `mfa_active=false` (Critical)

Detected by **two independent attestors**, providing cross-source
corroboration:

- `prowler` with `--checks iam_root_hardware_mfa_enabled` produced an
  OCSF finding with severity `Critical`.
- `aws iam get-credential-report` (the
  `aws-iam-credential-report` recipe) returned the per-user CSV
  showing `<root_account>,...,mfa_active=false`.

Both bundles are signed and ready to feed into policyverify. Remediation:
[enable hardware MFA for the root user](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-mfa.html).

### 2. GuardDuty not enabled

The `aws-guardduty` recipe returned `DetectorIds: []` — meaning
threat-detection isn't running in `us-east-1`. Recommendation: enable
GuardDuty in every region that runs workloads.

## Pending validation rounds

Tools requiring cloud-host context (not testable from a laptop):

| Tool          | Required context                          |
| ------------- | ----------------------------------------- |
| `aws-iid`     | Running on an EC2 instance (IMDS access)  |
| `gcp-iit`     | Running on a GCE instance                 |
| `azure-iid`   | Running on an Azure VM                    |
| `aws-codebuild` | Inside a CodeBuild build container      |

These can be validated by SSM-exec'ing cilock onto an EC2 host, or by
adding a one-off CodeBuild project that invokes cilock during its
phase.

## GitHub Actions integration

The same recipes work inside a GH Actions workflow runner — usually
via OIDC with [`aws-actions/configure-aws-credentials`](https://github.com/aws-actions/configure-aws-credentials).
Example:

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  attest-cloud-posture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::898769392027:role/CIlockAttestor
          aws-region: us-east-1
      - name: Attest cloud posture
        run: |
          cilock run \
            -a prowler \
            -k ${{ secrets.SIGNING_KEY_PATH }} \
            -o prowler-posture.bundle.json \
            -s prowler-posture \
            --ignore-command-exit-code \
            -- prowler aws --severity critical \
                            --output-modes json-ocsf \
                            --output-directory . \
                            --output-filename prowler
```

The OIDC role assumption produces short-lived AWS credentials in env
vars; the cilock-wrapped command sees them through the standard AWS
SDK chain.
