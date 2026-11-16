# Destroy an environment and create it again from code

The `dev` environment (`infra/envs/dev`) was destroyed and recreated from code more than once. Each destroy
removed all **19 resources** it manages: VPC, two subnets, internet gateway, route table and associations,
security groups and rules, container registry, ECS cluster, task definition and service, log group, and the
task execution role.

| Destroy log | Started (UTC) | Result |
|---|---|---|
| [`logs/destroy-20261115-212640.txt`](logs/destroy-20261115-212640.txt) | 2026-11-15 21:26 | 19 destroyed |
| [`logs/destroy-20261115-215649.txt`](logs/destroy-20261115-215649.txt) | 2026-11-15 21:56 | 19 destroyed |
| [`logs/destroy-20261116-093721.txt`](logs/destroy-20261116-093721.txt) | 2026-11-16 09:37 | 19 destroyed (the last line of the log: `Destroy complete! Resources: 19 destroyed.`) |

## How it is recreated

Not by hand: by the `Deploy` workflow, which creates the registry first, builds and pushes the image, applies
the environment and verifies that the version running is the version requested. The recreate took **4 min 48 s**
the first time and **1 min 41 s** the second time (the first one pays for creating the network and the service).

## Identical

A Terraform plan run after the recreate reported **no changes**: the environment that came back is the one the code
describes. That plan output is not in the destroy logs above; it was observed in the session and is stated here
as an observation, not as an attached log.

## What is not destroyed

The environment is disposable; the things that make it possible are not. These stay, on purpose:
the remote state bucket, the identity-federation roles the pipeline assumes and the permissions limit on them,
and the monthly budget. They live in their own stacks (`infra/bootstrap`, `infra/oidc`).

## Masking

Account numbers and the allowed source address appear as `<conta>` and `<seu-ip>`. Resource identifiers
(`vpc-…`, `sg-…`) are left as they are: the resources no longer exist.
