# The audit store, applied and tested (2026-11-17)

`infra/audit` applied from the laptop with the personal profile, from `main`, as a saved plan: 9 added, 0 changed,
0 destroyed; a new plan converges (exit code 0). The configuration was then read from AWS itself, not from Terraform.

## Configuration, read from AWS
| | |
|---|---|
| Object Lock | Enabled, GOVERNANCE, 7 days |
| Versioning | Enabled |
| Public access | all four blocks on |
| Encryption | AES256 |
| Ownership | BucketOwnerEnforced |
| Bucket policy | DenyInsecureTransport; DenyAWriteThatCouldReplaceARecord (Null s3:if-none-match); DenyTheWriterEverythingButWriting (ArnEquals aws:PrincipalArn) |
| Writer role | trust: `sub` = the repository's `main` (immutable IDs), `aud` sts.amazonaws.com; one permission, `s3:PutObject` on `agent-runs/*`; 0 managed policies attached |

## The store, tested as an administrator (the principal with the most power)
| Test | Result |
|---|---|
| a write without `If-None-Match: *` | refused: AccessDenied |
| a first write with `If-None-Match: *` | accepted; the object is locked (GOVERNANCE, until 7 days later) |
| a second write under the same name, with the condition | refused: PreconditionFailed |
| a second write under the same name, without it | refused: AccessDenied |
| delete the locked version, no bypass | refused: AccessDenied |
| shorten the retention, no bypass | refused: AccessDenied |
| read the record back | identical to what was written |
| delete the locked version WITH the bypass permission | accepted: an administrator can, deliberately (the limit stated in ADR 0006) |

## The writer role (the IAM policy simulator, identity policy only; the role is assumable only through OIDC from main)
`s3:PutObject` under `agent-runs/`: allowed. Outside that prefix, and `GetObject`, `DeleteObject`, `DeleteObjectVersion`,
`PutObjectRetention`, `BypassGovernanceRetention`, `PutBucketPolicy`, `PutBucketObjectLockConfiguration`,
`PutBucketVersioning`: all implicitDeny (and the bucket policy denies them explicitly as well).
Not yet tested from the pipeline itself: that comes with the change that writes the records.

The apply role's reach was fixed first: see `oidc-apply-role-fix.md`.
