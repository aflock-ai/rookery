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

# 2. (Optional) Generate the signing keypair, or use your own.
#    The script auto-generates an ed25519 key at
#    .catalog-test/keys/signer.key if one isn't already present.
mkdir -p .catalog-test/keys
openssl genpkey -algorithm ed25519 -out .catalog-test/keys/signer.key
openssl pkey -in .catalog-test/keys/signer.key -pubout \
  -out .catalog-test/keys/signer.pub

# 3. Build the all-attestors binary (every plugin + every signer)
cd presets/all && go build -o /tmp/cilock-all-cat ./cmd/cilock-all
```

The script defaults to the `/tmp/cilock-all-cat` binary; override it with
the `CILOCK_BIN` env var. The base `cilock` binary does not compile in the
cloud-posture plugins (`aws-config`, `asff`) — build the all-attestors
binary above so detection can fire them.

## Validated AWS recipes (testifysec-demo)

A **recipe** is a test scenario in `scripts/test-catalog-tools.py`; an
**attestor** is a registered plugin under `plugins/attestors/`. The two
are distinct. Most cloud recipes only assert that the `command-run/v0.1`
predicate is produced — the wrapped `aws ...` call is the evidence, and
the generic command-run attestor captures it. A few recipes drive a
dedicated plugin attestor as well:

- `prowler` and `steampipe` pass an explicit `-a <attestor>`, so those
  plugins always fire.
- `aws-config` (plugin `aws-config`) and `aws-security-hub` (plugin
  `asff`) carry detector rules that auto-fire the plugin when the
  workspace detection sees the matching `aws ...` command. The recipes
  themselves only assert `command-run/v0.1`, so they pass with or without
  the plugin being present.

| Recipe                      | API surface                                                                     | Plugin attestor          | What gets attested                            |
| --------------------------- | ------------------------------------------------------------------------------- | ------------------------ | --------------------------------------------- |
| `cloudtrail`                | `aws cloudtrail lookup-events --max-results 5`                                   | none (command-run only)  | Last 5 audit-log events as JSON product       |
| `aws-secrets-manager`       | `aws secretsmanager list-secrets --max-results 10`                              | none (command-run only)  | Secret names + ARNs (no values)               |
| `aws-config`                | `aws configservice describe-config-rules` → `get-compliance-details-by-config-rule` | `aws-config` (auto)  | Per-rule EvaluationResults                    |
| `prowler`                   | `prowler aws --checks iam_root_hardware_mfa_enabled --output-modes json-ocsf`    | `prowler` (`-a prowler`) | Posture findings in OCSF JSON                 |
| `steampipe`                 | `steampipe query "select ... from aws_ec2_instance limit 3"`                     | `steampipe` (`-a steampipe`) | SQL-over-API query results                |
| `aws-security-hub`          | `aws securityhub get-findings --max-results 5`                                   | `asff` (auto)            | Security Hub findings (ASFF) across services   |
| `aws-inspector`             | `aws inspector2 list-findings --max-results 5`                                   | none (command-run only)  | Vuln + reachability findings for EC2/ECR      |
| `aws-guardduty`             | `aws guardduty list-detectors` → `list-findings`                                | none (command-run only)  | Threat-detection findings                     |
| `aws-macie`                 | `aws macie2 get-macie-session`                                                   | none (command-run only)  | Sensitive-data discovery state                |
| `aws-iam-credential-report` | `aws iam generate-credential-report` → `get-credential-report`                   | none (command-run only)  | Per-user MFA + key-age + password-age posture |

The `asff` plugin (`plugins/attestors/asff/`) is what attests AWS
Security Hub output — there is no attestor literally named
`aws-security-hub`. Its detector matches the
`aws securityhub get-findings` command (and `*.asff.json` products) and
emits the `https://aflock.ai/attestations/asff/v0.1` predicate.

## Running

```bash
# All recipes (80 total, including non-AWS) — passing no args runs them all
python3 scripts/test-catalog-tools.py

# Just the AWS subset — positional args select recipes by name
python3 scripts/test-catalog-tools.py \
  cloudtrail aws-secrets-manager aws-config prowler steampipe \
  aws-security-hub aws-inspector aws-guardduty aws-macie \
  aws-iam-credential-report

# Reports land at:
cat .catalog-test/report.md     # human-readable per-tool table + details
cat .catalog-test/report.json   # machine-readable for CI consumption
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

Host-context attestors that need a real cloud environment for full
validation (not exercisable end-to-end from a laptop):

| Attestor        | Required context                          |
| --------------- | ----------------------------------------- |
| `aws`           | Running on an EC2 instance (IMDS access)  |
| `gcp-iit`       | Running on a GCE instance                 |
| `aws-codebuild` | Inside a CodeBuild build container        |

These can be validated by SSM-exec'ing cilock onto an EC2 host, or by
adding a one-off CodeBuild project that invokes cilock during its
phase. (There is no Azure instance-identity attestor today — only the
AWS and GCP host-identity plugins above exist under
`plugins/attestors/`.)

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
