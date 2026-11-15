# ADR 0001: Repository layout and tooling choices

- Status: accepted
- Scope: Platform Engineer Pathway, Module 2 personal lab

## Context

Module 2 asks for a delivery foundation that is reproducible and automated, and that the agentic layer of
Module 3 can be built on. The lab is small and owned by one person. The tooling must be justified
vendor-neutrally: the capability transfers to whatever a client runs.

## Decision

| Concern | Choice | Why, and the neutral alternative |
|---|---|---|
| Version control and review | Git on GitHub, pull requests | Universal standard; GitLab or Bitbucket give the same pattern |
| Infrastructure as code | Terraform (declarative) | Declarative state is what makes destroy and recreate provable; OpenTofu or Pulumi are equivalent |
| Runtime | Containers on ECS Fargate | Standard OCI images, no cluster to operate; Kubernetes is the alternative when a client runs it |
| Pipeline | GitHub Actions | Defined as code next to the app; GitLab CI or Jenkins fit the same shape |
| CI to cloud trust | OIDC, no long-lived keys | Removes stored credentials from the pipeline |
| State | Remote object storage with locking, bootstrapped once | Shared, locked state avoids the problem that bites later |

Layout: `app/`, `infra/bootstrap/`, `infra/envs/dev/`, `.github/workflows/`, `docs/`. Bootstrap is separate
because the state bucket must exist before anything else can use remote state.

## Consequences

- **Review with one person.** An author cannot approve their own pull request, so a mandatory human approval
  would block all work. The reviewable path is therefore: pull request required, automated checks required,
  the plan output read, no direct push to `main`, and later an AI-assisted review as a second reader. This is a
  deliberate limit of a solo lab, not a claim that it equals a two-person review.
- **No Docker on the laptop.** Images are built in CI.
- **Public repository.** Everything is visible, so no secrets and no real account identifiers are ever
  committed; they are supplied as variables.
- **Forward compatibility.** The pipeline keeps clear extension points so Module 3 gates, guardrails and the
  audit record can attach without a rebuild.
