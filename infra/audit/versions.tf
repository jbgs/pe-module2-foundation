terraform {
  # use_lockfile (S3 native state locking) needs Terraform 1.10 or newer.
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # The state lives in the bucket of infra/bootstrap. Its name is passed at init time with
  # -backend-config="bucket=...", never committed.
  backend "s3" {
    key          = "audit/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  # Guard: refuse to run against any account other than the lab account.
  allowed_account_ids = [var.allowed_account_id]

  default_tags {
    tags = {
      Project   = "pe-module2-foundation"
      Stack     = "audit"
      ManagedBy = "terraform"
    }
  }
}
