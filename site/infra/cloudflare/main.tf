terraform {
  required_version = ">= 1.5"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }
  # Configure a remote backend (e.g. S3) before applying in CI so state is shared.
  # backend "s3" { bucket = "..." key = "cilock-docs/cloudflare.tfstate" region = "us-east-1" }
}

# Auth via env: CLOUDFLARE_API_TOKEN with "Access: Apps and Policies: Edit".
provider "cloudflare" {}

# Cloudflare Access application gating the internal analytics dashboard (/dash).
# The dashboard Function (functions/dash) also fails closed on the
# Cf-Access-Authenticated-User-Email header, so /dash is 403 even before this
# applies — this resource is what makes it reachable for TestifySec identities.
resource "cloudflare_zero_trust_access_application" "dash" {
  account_id                = var.account_id
  name                      = "CI/lock Analytics Dashboard"
  domain                    = "${var.dash_hostname}/dash"
  type                      = "self_hosted"
  session_duration          = "24h"
  app_launcher_visible      = false
  auto_redirect_to_identity = false
}

# Only TestifySec identities may reach /dash. email_domain works with Cloudflare's
# built-in one-time-PIN out of the box (no external IdP required), and also with a
# configured Google Workspace / OIDC provider if one is added later.
resource "cloudflare_zero_trust_access_policy" "dash_testifysec" {
  application_id = cloudflare_zero_trust_access_application.dash.id
  account_id     = var.account_id
  name           = "Allow ${var.allowed_email_domain}"
  precedence     = 1
  decision       = "allow"

  include {
    email_domain = [var.allowed_email_domain]
  }
}
