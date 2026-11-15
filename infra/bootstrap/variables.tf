variable "region" {
  description = "AWS region for the state bucket."
  type        = string
  default     = "us-east-1"
}

# No default on purpose: this repository is public, so the account ID is never committed.
# Supply it with a local, git-ignored *.auto.tfvars file or a TF_VAR_ environment variable.
variable "allowed_account_id" {
  description = "The only AWS account this stack may run against."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.allowed_account_id))
    error_message = "allowed_account_id must be a 12-digit AWS account ID."
  }
}

# No default on purpose: bucket names are global, and a unique suffix is chosen locally.
variable "state_bucket_name" {
  description = "Globally unique name of the Terraform state bucket."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.state_bucket_name))
    error_message = "state_bucket_name must be 3 to 63 chars: lowercase letters, digits and hyphens."
  }
}

variable "noncurrent_version_expiry_days" {
  description = "Days to keep superseded state versions before they expire."
  type        = number
  default     = 90
}
