terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Remote state in the bucket created by infra/bootstrap. The bucket name is not committed:
  # pass it at init time with -backend-config="bucket=<state bucket name>".
  backend "s3" {
    key          = "oidc/terraform.tfstate"
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
      Stack     = "oidc"
      ManagedBy = "terraform"
    }
  }
}
