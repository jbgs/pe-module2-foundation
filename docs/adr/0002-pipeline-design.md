# ADR 0002: Pipeline design

- Status: accepted
- Scope: Platform Engineer Pathway, Module 2 personal lab

## Context

The pipeline is the spine the later modules attach their gates to. It has to be automated, observable
and reversible, defined as code, and safe in a public repository where logs are public.

## Decision

| Concern | Choice |
|---|---|
| Structure | `ci.yaml` on every pull request, `deploy.yaml` on merge to `main` and on demand |
| Credentials | OIDC only. A read-only role for pull requests, an apply role for `main` only |
| Forks | Get no secrets and no OIDC token, so they can run tests but never reach AWS |
| Public logs | The account ID, state bucket and allowed address are repository **secrets**, because only secrets are masked in logs; variables are not |
| Third-party actions | Pinned by commit SHA, with the release tag in a comment |
| Image identity | Tag is the commit SHA, immutable, so a tag always means one image |
| Switching on | The pipeline never turns the service on or off by itself; a merge keeps the current size |
| Rollback | Manual: deploy an older tag. Automatic: the ECS deployment circuit breaker |
| Verification | Through the ECS API: the running image tag must equal the requested one |
| Scan | Reported on every build; blocks on CRITICAL only when `SCAN_GATE=block`. A missing scan result is reported as **NOT SCANNED** and, with the gate on, stops the run: no result is not the same as no findings |
| Image format | Built with `--provenance=false --sbom=false`, so the tag points at a single image the registry can scan |
| Health | The task definition carries its own container health check (ECS ignores the Dockerfile one), and the verify step fails the run if a task is not healthy |
| Starting from nothing | The registry is applied first, with `-target`, so the image can be pushed before the rest of the environment exists |

## Why verification goes through the ECS API

The service accepts traffic only from an allowed address, and a hosted runner is not one. Comparing the
running image tag with the requested tag is also stronger than a health check: if the circuit breaker
rolled a bad version back, the service is healthy and stable but on the **previous** version. A health
check would report success; this check fails the run.

## Extension points for Module 3 and 4

- **Before apply:** a policy and guardrail gate. A failing gate stops the run before anything changes.
- **After the outcome is known:** the audit record (who or what changed what, which version, which approval).
- **Human gate:** a GitHub environment with required reviewers on the deploy job. It changes the token
  subject, so the apply role's trust policy is updated at the same time, in a reviewed pull request.

## A lesson from the first deploy

The first deploy reported a successful scan step, yet the registry held no scan for the image. BuildKit
had published an image index with an attestation manifest, which the registry's basic scan does not
analyse, and the step had been written to pass when the scan did not complete. Both were fixed: the image
is built without the extra manifest, and a missing scan is now reported as not scanned and, with the gate
on, stops the run. A check that passes silently when it cannot run is worse than no check.

## What the rollback covers

The deployment circuit breaker rolls back a version whose tasks cannot start or do not stay up. Before the
container health check existed, a version that started but answered with errors counted as running, and
neither the breaker nor the verify step would have noticed. With the health check, a task that stays
unhealthy is replaced and the deployment fails. A fault that the health endpoint does not exercise is still
not caught: the endpoint only proves the process answers.

## The cost of `-target`

Applying only the registry first is a bootstrap step, not a way of working. `-target` skips the dependency
graph, so it is limited to two resources that depend on nothing else, and the full apply that follows still
manages everything. The cleaner design is a separate stack for the registry, which would make the order
explicit without `-target`. That is a reasonable next step if the environment grows.

## Consequences

- **Cost safety by design.** A code change cannot start paid capacity or stop the service by accident.
- **Observable.** Every run records timestamps, so deployment frequency and lead time can be derived
  from run history, as measured in Module 1.
- **A known gap.** Pull request plans run with the read-only role but print resource identifiers in a
  public log; sensitive values are masked, identifiers are not.
