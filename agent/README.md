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
| [`audit.py`](audit.py), [`audit_verify.py`](audit_verify.py) | the audit record (a hash chain) and the audit gate that refuses a log that is incomplete, inconsistent or altered |
| [`test_run_agent.py`](test_run_agent.py), [`test_audit.py`](test_audit.py) | tests of the enforcement point and of the audit gate (no Docker needed) |
| [`../.github/workflows/agent-sandbox.yaml`](../.github/workflows/agent-sandbox.yaml) | runs all of this on every pull request |

## Two layers

1. **The policy** ([`../policy/`](../policy/)) decides first: `allow`, `gate` or `deny`. A denied or gated action
   never runs.
2. **The sandbox** stops what the policy did not, or cannot: no network, a read-only root filesystem, no
   capabilities, limits on processes, memory and CPU, and only synthetic data. The decision to isolate, the
   options and the limit of this isolation are in [ADR 0004](../docs/adr/0004-agent-sandbox-isolation.md).

The test runs the agent in two modes. In `enforce` the policy decides first. In `bypass` the policy is switched off
and every action runs in the sandbox, so the runtime has to stop the attempts on its own. A third run, the
negative controls, is described below.

## The test can fail

A green run proves little if it has never been red. So the job also removes the limits **one at a time** and
checks that the attempt each one holds back then **escapes**:

| Limit removed | Attempt that must then escape |
|---|---|
| `--network none` (replaced by a real network) | `network_egress` |
| `--read-only` | `write_outside_workspace` (a write to `/tmp`, which any user can make) |
| `--pids-limit` | `resource_pids` |
| `--memory` | `resource_memory` |
| the unprivileged user, `--cap-drop ALL` and `no-new-privileges` | `privileged_exec` |
| the data boundary (the stand-in mounted) | `read_regulated_data` |

This is also an honest account of what holds what. Privileged operations are refused mainly because the agent
runs as an unprivileged user; dropping the capabilities and `no-new-privileges` are defence in depth, and the
control removes all three together, so it does not tell them apart.

## The audit log

Every action the agent proposes, run or not, leaves one record: who, what, under which rules, who approved,
what happened, in which version of the code. The records are chained by hashes, so changing, removing or
reordering one is detected. The shape, and why, are in [ADR 0005](../docs/adr/0005-audit-record.md).

Each run writes `audit-<mode>.jsonl` and `audit-<mode>.manifest.json` (the head hash and the number of
records), which are kept as the `agent-run` artifact. The **audit gate** then reads them from disk and refuses a
log that is incomplete, inconsistent or altered. A second step damages the run's own log in four ways and
requires each to be refused, because a gate that has never refused anything proves nothing.

A **test of the tests**, [`mutation_check.py`](mutation_check.py), weakens the audit gate, the log writer and the publisher in 28 ways and requires the
tests to notice each one; it runs in CI.

To check a log by hand:

```
python3 agent/audit_verify.py audit-enforce.jsonl --manifest audit-enforce.manifest.json --expect agent/plan.json
```

## The audit store

On `main`, after the checks have passed, the pipeline publishes the logs to the audit store (`infra/audit`,
[ADR 0006](../docs/adr/0006-audit-store.md)) with [`publish_audit.py`](publish_audit.py). For each of the three
logs it writes three objects, each one **only if it does not exist yet**, with its SHA-256 checksum so that S3 refuses
the object if the content is not what was sent:

```
agent-runs/<run>/<mode>/audit.jsonl     the log
agent-runs/<run>/<mode>/manifest.json   the number of records and the head hash
agent-runs/heads/<head hash>.json       a pointer named after the head hash, which cannot be predicted or taken first
```

Then, **with the writer's own role**, it tries to change what it has just written (write the same name again, with
and without the condition; write outside the prefix; read it back; delete the version; delete it with the bypass of
the lock; shorten its retention), and every attempt must be refused, each with the right error. The job fails if
a write is refused (a name that is already taken is never replaced) or if the store accepts any of the attempts.

The job runs only on `main`, never declares a GitHub `environment:` (that would change the subject of the token and
stop matching the role), and is not a required check: a pull request never writes to the store.

To read a run back from the store and run the audit gate on it, with a profile that can read:

```
AUDIT_BUCKET=<bucket> python3 agent/publish_audit.py verify --run-id <run id>-<attempt>
```

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
- The log is tamper-evident, not yet immutable: someone who can rewrite the whole log can recompute the chain, and
  only the head hash (kept apart) catches it. Where the head is kept is the next change.
- No approval path exists yet, so every gated action is recorded as pending.
