# FedRAMP 20x KSI evidence recipes

Recipes that drive the `steampipe` and `structured-data` attestors. Each
recipe captures one provider/SaaS data source, tags it against the FedRAMP
20x KSI (and supporting NIST 800-53 controls) it satisfies, and ships as
data — no new Go code per CSP.

## Layout

```
recipes/ksi/
  aws-iam-mfa.sql          # Steampipe query pack: KSI-IAM-MFA evidence
  github-branch-protect.sql# KSI-CMT-SCR + KSI-CMT-CSC
  kratos-admin.yaml        # structured-data recipe: KSI-IAM-AAM
```

## Steampipe query packs

Each `.sql` file is a single Steampipe query with YAML frontmatter as a
leading SQL comment block:

```sql
/*---
id: aws-iam-mfa
task: List human IAM users without MFA
ksis: [KSI-IAM-MFA]
nist: [ia-2, ia-2.1, ia-2.2]
plugin: aws
severity: high
---*/

select
  account_id,
  user_id,
  user_name,
  mfa_active
from aws_iam_user
where mfa_active is false;
```

The `scanKSIProjection` workflow (Phase 4) shells out to
`steampipe query --output json <file>` and feeds the result through the
`steampipe` attestor.

## structured-data recipes

YAML descriptors for sources that aren't accessible via Steampipe — a
direct REST call, a SaaS export, a customer-supplied JSON blob. Each
recipe describes the upstream call as a `commandrun` step + a
JSONPath subject query.

```yaml
id: kratos-admin
task: Capture Kratos admin identity list for KSI-IAM-AAM
ksis: [KSI-IAM-AAM]
nist: [ac-2, ia-12]
collect:
  command: ["kratos", "list", "identities", "--format", "json"]
attest:
  data-type: kratos-identity-list
  subject-query: $.identities[*].id
  subject-prefix: "kratos:identity:"
```

## Conventions

- `id` is the stable recipe identifier and becomes the subject prefix for
  cross-attestation linkage.
- `ksis` is the list of FRMR KSI ids this recipe contributes evidence to;
  the workflow uses this to route the resulting envelope.
- `nist` is the supporting 800-53 control list — kept here so the
  rookery-side recipe author and the judge-side projection workflow stay
  in agreement on the FRMR control mapping.
- Rows / subjects are deterministic: every run against the same inputs
  produces byte-identical envelopes (JCS canonical encoding + sorted
  JSONPath wildcard iteration).

## Adding a recipe

1. Drop the `.sql` or `.yaml` file in this directory.
2. Reference it from your CSP's `cilock.yaml` policy file.
3. Run `cilock run --recipe-dir subtrees/rookery/recipes/ksi/` to exercise
   it locally.
4. Open a PR — recipes ship as data, not code.

For the canonical FRMR KSI list this directory targets, see
[FRMR.documentation.json](../../../judge-api/pkg/crosswalk/data/fedramp20x/FRMR.documentation.json)
on the judge side.

## Validating the steampipe attestor end-to-end

The steampipe attestor ships with a `validate` build-tag harness that
exercises the full pipeline against a real Steampipe query output:

```sh
# 1. Capture a real Steampipe query
mkdir -p /tmp/steampipe-validate
steampipe query --output json \
    "select id, name_with_owner, visibility, is_archived
     from github_my_repository where is_archived = false limit 3" \
    > /tmp/steampipe-validate/repos.json

# 2. Exercise the attestor against it. The harness simulates the recipe
#    driver: it stamps the frontmatter (KSI ids, NIST refs, etc.) onto the
#    attestor before Attest() runs, then asserts the routing labels
#    survive onto the predicate.
go test -tags validate -v -run TestValidateAgainstRealOutput \
    github.com/aflock-ai/rookery/plugins/attestors/steampipe
```

Passing output:

```
=== RUN   TestValidateAgainstRealOutput
    steampipe_validate_test.go:160: validated: query=github-branch-protect rows=3 subjects=4 (env+per-row)
--- PASS: TestValidateAgainstRealOutput (0.00s)
```

The `validate` build tag keeps this out of regular CI (it depends on a
pre-captured file on disk).
