/*---
id: github-branch-protect
task: Capture branch-protection settings on the default branch of every repo in the target org
ksis: [KSI-CMT-SCR, KSI-CMT-CSC]
nist: [cm-3, cm-3.6, sa-15]
plugin: github
severity: high
---*/

-- KSI-CMT-SCR (source-controlled releases) + KSI-CMT-CSC (controlled
-- staging-to-production) both ride on a verifiable branch-protection
-- baseline. We capture the policy snapshot here; the rego policy in
-- judge-api/pkg/workflow/workflows/ksi consumes the result to score
-- the indicator.
select
    name as repository,
    visibility,
    default_branch_ref ->> 'name' as default_branch,
    (default_branch_ref -> 'branch_protection_rule' ->> 'requires_status_checks')::bool as requires_status_checks,
    (default_branch_ref -> 'branch_protection_rule' ->> 'requires_strict_status_checks')::bool as requires_strict_status_checks,
    (default_branch_ref -> 'branch_protection_rule' ->> 'restricts_pushes')::bool as restricts_pushes,
    (default_branch_ref -> 'branch_protection_rule' ->> 'required_approving_review_count')::int as required_reviews,
    (default_branch_ref -> 'branch_protection_rule' ->> 'dismisses_stale_reviews')::bool as dismisses_stale_reviews,
    (default_branch_ref -> 'branch_protection_rule' ->> 'requires_signatures')::bool as requires_signatures,
    archived
from
    github_my_repository
where
    archived is not true
order by
    name;
