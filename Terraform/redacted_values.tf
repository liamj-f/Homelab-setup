# Values the resource-discovery export hardcoded that identify the account
# owner or their home network. Supplied via TF_VAR_* in CI (this repo is
# public) rather than committed as literals.

variable "oci_account_email" {
  description = "Email address of the OCI tenancy's admin/IAM user (as it appears in identity/identity-domain resources and Oracle-Tags.CreatedBy tags)"
  type        = string
}

variable "homelab_email" {
  description = "Homelab notification alias email (matches the existing HOMELAB_EMAIL value used elsewhere in this repo)"
  type        = string
}

variable "home_ip" {
  description = "CIDR of the home network's current public IP (the 14monarch.tplinkdns.com endpoint), allowed through the VM-facing NSG/WAF allowlist"
  type        = string
}
