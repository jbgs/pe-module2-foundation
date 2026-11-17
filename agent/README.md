# The agent sandbox

A scripted agent that runs in a sandbox, a policy that judges its actions, and a test that tries to get out.

The agent is a script, not a language model: it makes the proof repeatable. It "proposes" the actions in
[`plan.json`](plan.json): four legitimate ones and seven attempts at what an agent must not do.

| Where | What |
|---|---|
| [`sandbox/`](sandbox/) | the agent's actions and the image they run in |
| [`run_agent.py`](run_agent.py) | the enforcement point: asks the policy, starts the sandbox, judges the result |
| [`synthetic/`](synthetic/) | the only data the sandbox gets (invented, read-only) |
| [`regulated-standin/`](regulated-standin/) | a file that stands in for regulated data. It is never mounted and is not in the image. It carries a canary |
| [`test_run_agent.py`](test_run_agent.py) | tests of the enforcement point (no Docker needed) |
| [`../.github/workflows/agent-sandbox.yaml`](../.github/workflows/agent-sandbox.yaml) | runs all of this on every pull request |

## Two layers

1. **The policy** ([`../policy/`](../policy/)) decides first: `allow`, `gate` or `deny`. A denied or gated action
   never runs.
2. **The sandbox** stops what the policy did not, or cannot: no network, a read-only root filesystem, no
   capabilities, limits on processes, memory and CPU, and only synthetic data. The decision to isolate, the
   options and the limit of this isolation are in [ADR 0004](../docs/adr/0004-agent-sandbox-isolation.md).

The test runs the agent in both modes. In `bypass` mode the policy is switched off and every action runs in the
sandbox, so the runtime has to stop the attempts on its own.

## What makes the run fail

- An attempt works (an "escape"), or does not run.
- A legitimate action does not complete.
- The policy lets an attempt through, or refuses a legitimate action.
- The canary from the regulated stand-in appears in any output.

An attempt that is stopped is reported as a warning, `Escape attempt blocked`, with the reason.

## Not run on a laptop

`actions.py` is made to be dangerous to run outside the sandbox: its attempts do what they say. Run it only
through `run_agent.py`, in the container. The enforcement point's tests (`python3 -m unittest discover -s agent`)
use a stand-in for the container and are safe anywhere.

## Limits

- A container shares its host's kernel. The sandbox holds synthetic data only for that reason.
- The agent is a script. Prompt injection and the other risks that need a language model are not tested here.
- The records in the `agent-run` artifact are not yet immutable and carry no approval; that is the next change.
