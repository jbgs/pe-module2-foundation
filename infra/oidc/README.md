# infra/oidc

Trust between GitHub Actions and the lab AWS account, with no long-lived credentials.

| Resource | Purpose |
|---|---|
| OIDC provider | Lets AWS validate the signed tokens GitHub issues to workflow runs |
| `*-gha-plan` role | Read-only plus the state lock; assumable by pull requests and by `main` |
| `*-gha-apply` role | Least privilege to start; assumable **only** by runs on `main` |
| `*-boundary` policy | Ceiling for every role the apply role creates, so it cannot escalate privileges |

## Why two roles

A pull request, including one from a fork, can only ever assume the plan role, so it can read and
plan but never change infrastructure. Only a run on `main`, which a reviewed merge produces, can apply.

## The condition that matters

Each trust policy pins the token `sub` claim to this repository (and, for apply, to `main`).
Without that condition, any repository on GitHub could assume the role.

## Inputs (never committed)

Supply locally in a git-ignored `oidc.auto.tfvars`:

```
allowed_account_id = "<12-digit lab account id>"
state_bucket_name  = "<state bucket created by infra/bootstrap>"
```

## Run

```
AWS_PROFILE=platform-engineer-user terraform -chdir=infra/oidc init -backend-config="bucket=<state bucket name>"
AWS_PROFILE=platform-engineer-user terraform -chdir=infra/oidc plan
```

## Widening the apply role

The apply role starts narrow. When the dev environment needs more, widen it in a reviewed pull request,
so every extra permission is visible and justified.
