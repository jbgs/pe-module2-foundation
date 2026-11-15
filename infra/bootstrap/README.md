# infra/bootstrap

Creates the remote state bucket used by every other stack. Applied once, with local state, and kept
separate from the disposable environment in `infra/envs/dev/`.

## Inputs (never committed)

This repository is public. Supply these two values locally in a git-ignored `bootstrap.auto.tfvars`:

```
allowed_account_id = "<12-digit lab account id>"
state_bucket_name  = "<globally unique bucket name>"
```

## Run

Always set the lab profile explicitly:

```
AWS_PROFILE=platform-engineer-user terraform -chdir=infra/bootstrap init
AWS_PROFILE=platform-engineer-user terraform -chdir=infra/bootstrap plan
```

`allowed_account_ids` in the provider makes Terraform refuse to run against any other account.

## Using the bucket

Other stacks point their backend at this bucket with S3 native locking, passing the bucket name at
`init` time so it is not committed:

```
terraform init -backend-config="bucket=<state bucket name>"
```

with `use_lockfile = true` in their `backend "s3"` block.
