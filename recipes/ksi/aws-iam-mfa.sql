/*---
id: aws-iam-mfa
task: List human IAM users in the target account that lack any MFA factor
ksis: [KSI-IAM-MFA]
nist: [ia-2, ia-2.1, ia-2.2]
plugin: aws
severity: high
---*/

select
    account_id,
    user_id,
    user_name,
    create_date,
    mfa_active,
    password_last_used
from
    aws_iam_user
where
    -- Exclude service accounts: AWS treats users with no password as
    -- programmatic-only, where MFA is enforced via IAM access analyzer
    -- elsewhere. KSI-IAM-MFA is specifically about human authenticators.
    password_last_used is not null
    and mfa_active is false
order by
    user_name;
