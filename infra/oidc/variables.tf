variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

# No default on purpose: this repository is public, so the account ID is never committed.
variable "allowed_account_id" {
  description = "The only AWS account this stack may run against."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.allowed_account_id))
    error_message = "allowed_account_id must be a 12-digit AWS account ID."
  }
}

# No default on purpose: the bucket name is supplied locally and, in CI, from a repository variable.
variable "state_bucket_name" {
  description = "Name of the remote state bucket created by infra/bootstrap."
  type        = string
}

variable "github_owner" {
  description = "GitHub user or organization that owns the repository."
  type        = string
  default     = "jbgs"
}

variable "github_repo" {
  description = "GitHub repository name allowed to assume the roles."
  type        = string
  default     = "pe-module2-foundation"
}

# These two numbers are public: they are in the repository's page on GitHub's API
# (https://api.github.com/repos/<owner>/<repo>, fields id and owner.id).
variable "github_owner_id" {
  description = "Immutable numeric ID of the GitHub owner, as it appears in the token subject."
  type        = string
  default     = "29926047"

  validation {
    condition     = can(regex("^[0-9]+$", var.github_owner_id))
    error_message = "github_owner_id must be numeric."
  }
}

variable "github_repo_id" {
  description = "Immutable numeric ID of the GitHub repository, as it appears in the token subject."
  type        = string
  default     = "1459148559"

  validation {
    condition     = can(regex("^[0-9]+$", var.github_repo_id))
    error_message = "github_repo_id must be numeric."
  }
}

variable "name_prefix" {
  description = "Prefix for every role, policy and resource this lab may create."
  type        = string
  default     = "pe-lab"
}
