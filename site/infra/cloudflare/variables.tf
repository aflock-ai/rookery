variable "account_id" {
  description = "Cloudflare account ID (Cole@testifysec.com's Account)"
  type        = string
  default     = "47b48ff0a37e3ceb0918a6e2e16bcbac"
}

variable "dash_hostname" {
  description = "Production hostname serving the dashboard. The Access app covers <hostname>/dash."
  type        = string
  default     = "cilock.dev"
}

variable "allowed_email_domain" {
  description = "Email domain allowed through the Access gate for /dash."
  type        = string
  default     = "testifysec.com"
}
