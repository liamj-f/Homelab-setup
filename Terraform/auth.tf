variable "user_ocid" {
  description = "OCID of the IAM user Terraform CI authenticates as"
  type        = string
}

variable "fingerprint" {
  description = "Fingerprint of the CI user's API signing key"
  type        = string
}

variable "private_key" {
  description = "PEM contents of the CI user's API signing key"
  type        = string
  sensitive   = true
}
