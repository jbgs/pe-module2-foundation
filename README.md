# pe-module2-foundation

Platform Engineer Pathway, Module 2 (The Delivery Foundation): a small, personal lab.

A tiny containerized web service runs on AWS ECS Fargate. Everything that builds, deploys and recreates it
is code in this repository. The point is the **foundation**, not the service: it is built so the agentic
layer of Module 3 (golden path, sandboxes, guardrails, traceability) can be stood up on it fast.

> This is a personal learning project. It contains no client code, no client data, no secrets and no
> real AWS account identifiers.

## Layout

| Path | What lives here |
|---|---|
| `app/` | The minimal web service and its container definition |
| `infra/bootstrap/` | One-time Terraform for the remote state bucket (applied once, kept separate) |
| `infra/envs/dev/` | The disposable environment: registry, cluster, service |
| `.github/workflows/` | The delivery pipeline, defined as code |
| `.github/pull_request_template.md` | The review path every change goes through |
| `docs/adr/` | Architecture decision records, including the vendor-neutral tooling rationale |
| `docs/proof/` | Evidence for the hand-in (destroy and recreate, pipeline run, rollback) |

## The four components

| # | Component | Where | Proof |
|---|---|---|---|
| 1 | Everything-as-code | whole repository, pull requests with automated checks | this repository |
| 2 | Reproducible environments | `infra/` | log of destroy and recreate from code |
| 3 | Automated delivery pipeline | `.github/workflows/` | one run from commit to release, and the rollback |
| 4 | AI in the pipeline | `.github/workflows/` | a run with the AI step, held to the same checks |

## Conventions

- **No secrets and no account identifiers in the repository.** Credentials come from the environment and
  from OIDC in CI. Account IDs are passed as variables, never committed.
- **Every change goes through a pull request** from a short-lived branch. Nothing is pushed straight to `main`.
- **Conventional commits** (`feat:`, `fix:`, `docs:`, `chore:`) keep the history legible and auditable.
- **Terraform state is remote**, locked, and never committed. `*.tfvars` are never committed.

## Running locally

Use the dedicated AWS profile for this lab, and always set it explicitly:

```
AWS_PROFILE=platform-engineer-user terraform -chdir=infra/envs/dev plan
```

The container image is built in CI, so Docker is not required on a laptop.

## Status

- [x] Repository and structure
- [x] Remote state bootstrap
- [x] OIDC trust between GitHub Actions and AWS
- [x] Reproducible dev environment (applied)
- [x] Minimal service, tests and container image
- [ ] Delivery pipeline: build, plan, apply, verify, rollback (this change)
- [ ] Destroy and recreate proof
- [ ] AI in the pipeline
- [ ] Rationale and proof for the hand-in

## Pipeline secrets

The pipeline needs three repository secrets. They are secrets, not variables, because the logs of a
public repository are public and only secrets are masked there.

| Secret | What it is |
|---|---|
| `AWS_ACCOUNT_ID` | The lab AWS account ID |
| `TF_STATE_BUCKET` | Name of the remote state bucket |
| `ALLOWED_INGRESS_CIDR` | The one address allowed to reach the service, as a /32 |

Optional repository variable: `SCAN_GATE=block` makes a CRITICAL image finding stop the deploy.
