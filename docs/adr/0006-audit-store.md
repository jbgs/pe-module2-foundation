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
| A written record cannot be deleted or overwritten | S3 Object Lock, governance mode, with a default retention (7 days in the lab). Versioning is on, as Object Lock requires |
| A record cannot be replaced by writing a new version under the same name | The bucket policy refuses any write that does not carry `If-None-Match: *`, which S3 honours only if no object with that name exists |
| The pipeline can write and nothing else | The role `pe-lab-gha-audit-writer` has one permission, `s3:PutObject`, under one prefix (`agent-runs/`). It cannot read, delete, change the lock, the versioning or the policy; the bucket policy also denies it all of that explicitly (matched by a condition on the role's name, not by naming the principal, which would fail to save before the role exists and would stop matching if the role were recreated), so a permission added by mistake later would still not work |
| Only the code that a review produced writes | The role is assumable only by runs on `main`, with the immutable IDs of the owner and the repository in the subject, as the other roles. A pull request, whose workflow its author can change, never writes to the store. The job that writes must not declare a GitHub `environment:`, which would change the token's subject and stop matching |
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
| Deny every principal except a named administrator the right to delete, change the lock or change the policy | Stronger, but a wrong principal in that policy locks the administrator out of their own bucket, and the only way back is the account root. Not worth the risk in a lab; it is the first thing to add where the store is for real |

## A path found while reviewing this change

The review of this pull request asked whether the pipeline's other roles could reach the store. Checking it with the
IAM policy simulator (no change made) showed something worse than the question: the **apply role**, which runs on
`main`, was allowed `iam:AttachRolePolicy` on its own role, and `iam:UpdateAssumeRolePolicy` and `iam:DeleteRole`
on the role that writes the records. The cause is the statement that lets it manage roles with the lab prefix
(`pe-lab-*`): the apply role is itself `pe-lab-gha-apply`. The permissions boundary applies to roles it
**creates**, not to changes to roles that already exist. So a run on `main` could have attached an administrator
policy to itself, and an administrator can bypass the lock and delete the records. This is a weakness that came with
Module 2 and went unnoticed because nothing depended on it until this store did.

It is closed in `infra/oidc` by an explicit deny, which wins over any allow, on changes to the roles of the pipeline
itself (`pe-lab-gha-*`): delete, change the trust, attach or detach a policy, put or delete an inline policy, change
the boundary, tag. The dev environment never needed to manage those roles. This is applied before the store is, and
the simulator is run again afterwards.

## Who can still change a record

Stated plainly, because this is the question an auditor asks first.

- **The pipeline: no**, once the deny above is applied. Its roles cannot delete, overwrite, shorten the retention or
  loosen the policy, a second write under the same name is refused, and the role that writes cannot be edited by the
  role that applies.
- **The plan role can read the records** (its `ReadOnlyAccess` includes reading objects), and pull requests can assume
  it. Reading is not changing, and the records hold no secrets (the same data is a public build artifact), so this is
  accepted. A reader that is not the plan role is the way to restrict it.
- **An administrator of the lab account: yes, deliberately.** Governance mode can be bypassed by a principal that holds
  `s3:BypassGovernanceRetention`, and an administrator can also change the bucket policy. That is what keeps the lab
  reversible. Where the records must survive an administrator, use compliance mode, or a separate account, or both.
- **AWS, and the account root: outside what this protects against.**

## What write-once does not do

Write-once protects what has been written. It does not stop a name from being taken first. The writer may create any
new key under `agent-runs/`, and the run number that forms part of the key is predictable, so a compromised pipeline
could write a forged log under the name of a run that has not happened yet, and the honest write that follows would be
refused. This is not silent: the honest write fails with `412 Precondition Failed`, which fails the job, and the
original log is still in the build artifact for comparison. The change that writes the records also stores each
manifest under a name made from its own head hash, which cannot be predicted and cannot be taken first, so the
existence of a log with that head, at that time, can always be shown.

The retention is the window in which even a mistaken delete by an administrator is refused. It is short in a lab
(7 days) and is a setting.

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
