terraform {
  # use_lockfile (S3 native state locking) needs Terraform 1.10 or newer.
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Guard: refuse to run against any account other than the lab account.
  allowed_account_ids = [var.allowed_account_id]

  default_tags {
    tags = {
      Project   = "pe-module2-foundation"
      Stack     = "bootstrap"
      ManagedBy = "terraform"
    }
  }
}
