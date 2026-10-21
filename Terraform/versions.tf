terraform {
  required_version = ">= 1.6.4"

  required_providers {
    oci = {
      source  = "oracle/oci"
      version = ">= 5.0.0"
    }
  }

  # No remote backend: plain local state (./terraform.tfstate) is fetched +
  # decrypted from, and encrypted + committed back to, the `terraform-state`
  # git branch by the CI workflow itself. See .github/workflows/terraform.yml.
}
