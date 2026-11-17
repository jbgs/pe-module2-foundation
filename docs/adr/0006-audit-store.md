# ADR 0006: where the audit records are kept

Status: accepted. Date: 2026-11-17.

## Context

[ADR 0005](0005-audit-record.md) made the audit log tamper-evident: any change to it is detected. It also said what
that is not: the head hash, which is what catches a log rewritten from start to end, is kept by the pipeline itself,
so a compromised pipeline could rewrite both. The second property of the platform, traceability, is not done until the
records are kept where the pipeline that wrote them cannot change them.

## Decision

A bucket in the lab account whose objects cannot be changed or deleted, written by a role that can do nothing else.

| Property | How |
|---|---|
| A written record cannot be deleted or overwritten | S3 Object Lock, governance mode, with a default retention (1 day in the lab). Versioning is on, as Object Lock requires |
| A record cannot be replaced by writing a new version under the same name | The bucket policy refuses any write that does not carry `If-None-Match: *`, which S3 honours only if no object with that name exists |
| The pipeline can write and nothing else | The role `pe-lab-gha-audit-writer` has one permission, `s3:PutObject`, under one prefix (`agent-runs/`). It cannot read, delete, change the lock, the versioning or the policy; the bucket policy also denies it all of that explicitly, so a permission added by mistake later would still not work |
| Only the code that a review produced writes | The role is assumable only by runs on `main`, with the immutable IDs of the owner and the repository in the subject, as the other roles. A pull request, whose workflow its author can change, never writes to the store |
| Nothing travels or rests in clear | Encryption at rest, a deny for any request not made over TLS, and no public access |

The stack is `infra/audit`. It is applied from a laptop with an administrator profile, like `bootstrap` and `oidc`,
because the pipeline's own roles must not be able to create or loosen the thing that constrains the pipeline.

## Options considered

| Option | Why not (for now) |
|---|---|
| Object Lock in **compliance** mode | The only mode that stops even an administrator until the retention ends, and it cannot be undone. Too strong to use on a lab account that has to be cleaned up |
| A **separate AWS account** for the store | The strongest separation: not even an administrator of the lab account could touch it. It costs an account and a cross-account trust. The upgrade path where a regulated client requires it |
| A third-party log or ledger service | A capability, not a product: any store with write-once, retention and a write-only identity does the job. S3 was chosen because the account already exists and nothing new has to be run |
| Keep the head hash only in the build artifact and the run summary (ADR 0005) | The pipeline itself writes both. This is what this decision replaces |

## Who can still change a record

Stated plainly, because this is the question an auditor asks first.

- **The pipeline: no.** Its role cannot delete, overwrite, shorten the retention or loosen the policy, and a second
  write under the same name is refused.
- **An administrator of the lab account: yes, deliberately.** Governance mode can be bypassed by a principal that holds
  `s3:BypassGovernanceRetention`, and an administrator can also change the bucket policy. That is what keeps the lab
  reversible. Where the records must survive an administrator, use compliance mode, or a separate account, or both.
- **AWS, and the account root: outside what this protects against.**

## Cost and reversibility

The records are a few kilobytes per run, so the store costs cents a month. Nothing here is billed by the hour. It is
reversible: after the retention ends (or with the bypass permission) the objects can be deleted and the stack
destroyed; the README has the steps. Compliance mode would not be.

## What is proven

Applied, the store is tested from both sides, and the result is recorded in `docs/proof/`: that a second write under
the same name is refused, that a write without the condition is refused, that a locked version cannot be deleted
without the bypass, and that the writer role cannot do anything but write. The test of the writer runs from the
pipeline, because that is the identity that matters.

## Consequences

- The head hash of every log can be kept in the store, apart from the pipeline that produced it. That is the
  change that follows this one.
- A copy to this bucket through a bucket policy that enforces conditional writes would be refused, and so would a
  multipart upload. The records are small and written with a single request.
- The check `Terraform infra/audit` validates the code in every pull request. Nothing is applied by CI.
