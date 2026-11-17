# ADR 0004: how an agent is contained

Status: accepted. Date: 2026-11-17.

## Context

Module 3 puts an agent on the platform. An agent runs code it was handed, so the first property of the platform is
containment: no single run may reach anything it should not. Containment has to be imposed by the runtime, not
by a document, and it has to be provable: an agent that tries to get out must be seen failing.

## Decision

Each action of the agent runs in its own container, started by the platform with these limits and then thrown away:

| Limit | Setting | What it stops |
|---|---|---|
| Network | `--network none` | reaching the internet or any internal system; exfiltration |
| Filesystem | `--read-only`, plus one small `tmpfs` at `/workspace` | writing anywhere but the workspace; changing the agent's own code or the policy |
| Privilege | `--cap-drop ALL`, `no-new-privileges`, an unprivileged user | `setuid`, `chroot`, `mount` and the rest |
| Processes | `--pids-limit 64` | a fork bomb |
| Memory | `--memory 128m`, no swap | a run that takes the machine down |
| CPU | `--cpus 0.5` | one run starving the others |
| Data | only `agent/synthetic`, mounted read-only | regulated data: it is never mounted, and is not in the image |

The limits are set by the platform when it starts the container. They are not in the agent's image, because
something that is restricted must not be the thing that decides the restriction.

The sandbox runs on the throwaway runner of the CI service. It costs nothing, needs no cloud credentials and is
rebuilt for every run.

## Options considered

| Option | Isolation | Cold start | Why not (for now) |
|---|---|---|---|
| A hardened container (chosen) | shares the host kernel | under a second | the weakest of the three; see the limit below |
| A container with a user-space kernel (gVisor) | the application does not talk to the host kernel directly | a little slower | more to install and to debug; the upgrade path below |
| A micro virtual machine (Firecracker, Kata) | a separate kernel | slowest of the three | needs hardware virtualisation that the throwaway runner does not offer |

## The trade-off, stated

Isolation strength against speed of iteration is the core trade-off of this layer. A container shares the kernel
with its host, so a kernel flaw is a way out, and a regulated client would not accept this alone for real
regulated data. It is acceptable here because the sandbox holds **synthetic data only**: the worst a successful
escape would reach is a disposable runner with no credentials. Speed matters because an agent that is slow to
start is an agent that people route around.

## Upgrade path

Run the same containers with a user-space kernel (gVisor's `runsc` as the Docker runtime), then a micro virtual
machine where the host allows it. Nothing else changes: the limits, the policy and the tests are the same, and
the escape test below is what shows whether the stronger runtime still holds.

## How it is proven

The workflow `Agent sandbox escape test` runs the scripted agent twice. With the policy switched on, only allowed
actions run. With the policy switched **off**, every action runs in the sandbox, including seven attempts to get
out (network, regulated data, writing outside the workspace, privileged operations, changing the policy, a process
flood, a memory flood). The run fails if any attempt works, if a legitimate action does not complete, or if the
canary planted in the regulated stand-in appears anywhere in the output. The enforcement point's own tests check
that the judge does say "no" in each of those cases.

A third run, the negative controls, removes the limits one at a time (the network, the read-only root, the
process limit, the memory limit, the unprivileged user with its capabilities, and the data boundary) and requires
the attempt that each held back to escape. A green run that has never been red proves little; this shows that
every limit is what stops its attempt. It also shows what is not separable: the three privilege settings are
removed together, so the test cannot say which of them does the work.

## Consequences

- Containment is imposed twice: the policy decides before an action runs, and the runtime stops it if the
  policy is wrong. Either layer failing alone does not let an attempt through.
- Because the policy's input is built by the platform and not by the agent, the approval of a gated action cannot
  be claimed by the agent. Where the approval comes from is the next change.
- The records of each run are a first form of the audit record, kept for 90 days as a build artifact. They are not
  yet immutable; that is the audit store's job.
- One run uses one container: the cost of a run is the cost of a few seconds of a throwaway runner.
