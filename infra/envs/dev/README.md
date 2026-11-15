# infra/envs/dev

The disposable dev environment: network, registry, logs and a Fargate service. It can be destroyed
and recreated from this code, which is how reproducibility is proven.

| File | What it defines |
|---|---|
| `network.tf` | VPC, internet gateway, two public subnets, routes, the service security group. No NAT gateway |
| `ecr.tf` | Registry with immutable tags, scan on push, and a lifecycle that keeps recent images |
| `ecs.tf` | Log group, task execution role (with the permissions boundary), cluster, task definition, service |

## Design choices

- **No NAT gateway.** It is the costly part of a VPC. Tasks get a public IP and the security group
  decides who can reach them.
- **Immutable image tags.** A tag always means the same image, so a rollback is deploying an older tag.
- **Circuit breaker with rollback.** A version that cannot start or stay healthy is reverted automatically.
- **Starts at zero tasks.** `desired_count` is 0 until an image exists, and the lab costs nothing while idle.
  A running task costs roughly 0.02 USD per hour, so tear the environment down when not working.
- **Who can reach the service is a decision.** `allowed_ingress_cidrs` has no default.

## Inputs (never committed)

Supply locally in a git-ignored `dev.auto.tfvars`; in CI they come from repository variables:

```
allowed_account_id    = "<12-digit lab account id>"
allowed_ingress_cidrs = ["<cidr that may reach the service>"]
```

## Run

```
AWS_PROFILE=platform-engineer-user terraform -chdir=infra/envs/dev init -backend-config="bucket=<state bucket name>"
AWS_PROFILE=platform-engineer-user terraform -chdir=infra/envs/dev plan
```

## Deploy and roll back

Deploying is applying with the image tag of a commit; rolling back is applying an older tag.

```
terraform apply -var image_tag=<commit sha> -var desired_count=1
```
