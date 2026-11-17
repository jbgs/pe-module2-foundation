# The golden path

Describe what you need. Get an environment that is compliant by default. The reasoning, and what this does not do, are in
[ADR 0008](../docs/adr/0008-golden-path.md).

```
python3 golden-path/golden_path.py new "I need a sandbox for an agent to analyse churn data"
python3 golden-path/golden_path.py new "a dev environment for the service on AWS"        # asks before it starts anything paid
python3 golden-path/golden_path.py list
python3 golden-path/golden_path.py report
```

Or, without the repository on your machine: run the workflow **Golden path** from the Actions tab and type the request in the form.

## The paved roads

| Road | Makes | Cost |
|---|---|---|
| `agent-sandbox` | a folder with the synthetic data, the plan, the policy and the command to run an agent in it | none |
| `service-dev` | the development environment of Module 2, by starting the `Deploy` workflow with zero tasks | close to nothing at zero tasks; about 0.02 USD an hour with `--running` |

Each carries its compliant choices as defaults, in `paved-roads/<road>/road.json`. A road that lacks them is refused.

## What you get from `agent-sandbox`

```
<environment>/
  data/                the invented data, a copy
  plan.json            the actions the agent proposes
  policy/agent.rego    the rules that judge them
  environment.json     what it is: the road, who asked, when, the hashes of the policy and of the whole template
  README.md            what it comes with, and the command to run an agent in it
```

An environment is never overwritten, and nothing regulated is ever copied into one. `run_agent.py` checks the environment it is
given: it must exist, be the one named, be unchanged (its data and policy are hashed), and the data mounted must be the platform's own
synthetic data, byte for byte: a file renamed, or the same name with other content, is refused. To run an agent in it (Docker and `opa`
needed):

```
python3 agent/run_agent.py --mode enforce --plan <env>/plan.json --data <env>/data --policy-dir <env>/policy --environment <id> --out <env>/out
```

## What it keeps, and what it reports

Every request, covered or not, goes to a usage log (`~/.golden-path/usage.jsonl`, or `GOLDEN_PATH_USAGE`) whose records are
chained by hashes. A request is kept for good, so what looks like a secret in it (a key, a token, an e-mail address, a long number) is replaced by
`[redacted]` before it is written, and the workflow form says so. `report` shows the environments made by road, the share of requests the path covered, the requests it could
not (and what they said), the time to an environment, and, given a folder of audit logs (`--logs`), the agent runs that came from
an environment of the path and those that did not. A run counts as coming from the path only if the environment it names
appears in the usage log with the same hash. `report --store` reads every usage log in the audit store (it needs an identity that can read it),
checks each chain, and counts only those that verify. The workflow's own summary shows just the request it ran.

Two times are different things: the usage log records the work of the command itself (about 2 ms for a sandbox); the whole process,
with Python starting, is about 54 ms.

## Add a road

Add `paved-roads/<name>/road.json` with `name` (the same as the folder), `title`, `summary`, `kind` (`local` or `dispatch`),
`keywords` with positive whole weights, `defaults`, `teardown` and `cost`. `agent-sandbox` and `service-dev` show the defaults
each kind must carry. The tests refuse a road that lacks them.

## The tests of the tests

`golden-path/mutation_check.py` weakens the golden path in 23 ways (a road that gives up a default is accepted, an intent
no road covers is not recorded, an environment is overwritten, regulated data is copied, a service starts paid
infrastructure without asking, a usage log that does not verify is published, and so on) and requires the tests to notice
each one. It runs in CI.
