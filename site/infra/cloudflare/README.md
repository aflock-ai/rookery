# Cloudflare infrastructure as code

Everything the cilock docs analytics needs, defined as code:

| Concern | Where | Apply with |
|---|---|---|
| Pages runtime bindings (D1 `DB`, Analytics Engine `ANALYTICS`) | `../../wrangler.toml` | `wrangler pages deploy` (CI deploy workflow) |
| D1 database + schema | `../../schema.sql` | one-time bootstrap (below) |
| Access (OAuth) gate on `/dash` → `@testifysec.com` | `main.tf` (this dir) | `terraform apply` |

## 1. D1 bootstrap (one-time)
```sh
wrangler d1 create cilock-analytics                 # copy the id into ../../wrangler.toml
wrangler d1 execute cilock-analytics --remote --file=../../schema.sql
```
(Already created: database_id `629a819f-a221-4d47-8d60-1403a92b538b`.)

## 2. Access gate (this dir)
Requires an API token with **Access: Apps and Policies: Edit** (+ Access: Organizations, IdPs, and Groups: Read).
```sh
export CLOUDFLARE_API_TOKEN=...        # do NOT commit
terraform init
terraform plan
terraform apply
```
This creates the Access application for `cilock.dev/dash` and a policy allowing
only `@testifysec.com`. Cloudflare's built-in one-time-PIN covers login with no
external IdP; add a Google Workspace / OIDC provider later if desired.

> Preview testing: the policy targets the production hostname. To exercise `/dash`
> on a `*.cilock.pages.dev` preview, add that hostname as a second
> `cloudflare_access_application` (or temporarily widen `dash_hostname`).

## Token note for the deploy workflow
`wrangler pages deploy` (CI) attaches the `wrangler.toml` bindings, so the
`CLOUDFLARE_API_TOKEN` secret used by `deploy-cloudflare.yml` must include
**D1:Edit** and **Account Analytics** in addition to **Cloudflare Pages:Edit**.
