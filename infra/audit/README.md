# infra/audit

The audit store: where the audit records of agent runs are kept, so that the pipeline that wrote them cannot
change them afterwards. The reasoning and the limits are in [ADR 0006](../../docs/adr/0006-audit-store.md).

| Resource | What it does |
|---|---|
| S3 bucket with Object Lock | keeps the records; versioned, encrypted, no public access, owned by the account |
| Object Lock, governance mode | a written object cannot be deleted or overwritten for `retention_days` (1 by default) |
| Bucket policy | refuses insecure transport; refuses any write that does not carry `If-None-Match: *` (write once); denies the writer everything but writing |
| `*-gha-audit-writer` role | assumable **only by runs on `main`** of this repository; may only `PutObject` under `agent-runs/` |

The role is created from a laptop with an administrator profile, like the other stacks the pipeline depends on:
the pipeline's own roles must not be able to create or loosen it. Nothing here is applied by CI. CI only formats and
validates the code (`Terraform infra/audit`).

## Apply

The bucket name contains the account ID, so it is computed and never committed. The account ID and the state bucket
name are supplied locally.

```
cd infra/audit
echo 'allowed_account_id = "<the lab account>"' > audit.auto.tfvars        # git-ignored
AWS_PROFILE=platform-engineer-user terraform init -backend-config="bucket=<state bucket name>"
AWS_PROFILE=platform-engineer-user terraform plan -out audit.tfplan
AWS_PROFILE=platform-engineer-user terraform apply audit.tfplan
```

## Read and verify what is stored

The writer cannot read; a person with an administrator profile can.

```
BUCKET=$(terraform output -raw audit_bucket)
aws s3api list-objects-v2 --bucket "$BUCKET" --prefix agent-runs/
aws s3api head-object --bucket "$BUCKET" --key agent-runs/<run>/<mode>/audit.jsonl   # shows ObjectLockMode and RetainUntilDate
aws s3 cp s3://$BUCKET/agent-runs/<run>/<mode>/audit.jsonl .
python3 agent/audit_verify.py audit.jsonl --manifest manifest.json
```

## Clean up (a deliberate act)

A lab does not need to keep records forever, and the bucket refuses to be destroyed while it holds locked objects.

1. Wait for the retention to end (1 day), or, with an administrator profile, delete each version with
   `aws s3api delete-object --bucket "$BUCKET" --key <key> --version-id <id> --bypass-governance-retention`.
2. `terraform destroy` (the bucket is created with `force_destroy = false`).

## Limits, stated

- **Governance mode, not compliance mode.** A privileged administrator can bypass governance mode (that is what the
  clean-up above does). Compliance mode would stop even that until the retention ends, and it cannot be undone, so it
  is not used in a lab. Raise `retention_days` where the records must be kept.
- Whoever administers the account (or AWS itself) is outside what this protects against. What it protects is the
  records from the pipeline, and from anyone who does not hold the bypass permission.
- Multipart uploads are refused by the write-once rule. The records are a few kilobytes, written with a single
  `PutObject`.
