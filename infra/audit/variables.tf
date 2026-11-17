variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

# No default on purpose: this repository is public, so the account ID is never committed.
variable "allowed_account_id" {
  description = "The only AWS account this stack may run against."
  type        = string
}

variable "github_owner" {
  description = "GitHub user or organization that owns the repository."
  type        = string
  default     = "jbgs"
}

variable "github_repo" {
  description = "GitHub repository name allowed to assume the writer role."
  type        = string
  default     = "pe-module2-foundation"
}

variable "github_owner_id" {
  description = "Immutable numeric ID of the GitHub owner, as it appears in the token subject."
  type        = string
  default     = "29926047"
}

variable "github_repo_id" {
  description = "Immutable numeric ID of the GitHub repository, as it appears in the token subject."
  type        = string
  default     = "1459148559"
}

variable "name_prefix" {
  description = "Prefix for every role, policy and resource this lab may create."
  type        = string
  default     = "pe-lab"
}

variable "retention_days" {
  description = <<-EOT
    How long a new object cannot be deleted or overwritten (Object Lock, governance mode).
    Short in a lab: a privileged administrator can still bypass governance mode to clean up, which compliance
    mode would not allow, so a longer window costs nothing in reversibility. Raise it where the records have
    to be kept.
  EOT
  type        = number
  default     = 7

  validation {
    condition     = var.retention_days >= 1
    error_message = "The retention must be at least one day."
  }
}
