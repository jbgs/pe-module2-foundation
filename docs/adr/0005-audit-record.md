# ADR 0005: the audit record

Status: accepted. Date: 2026-11-17.

## Context

The second property of an agentic platform is traceability: at any moment it must be possible to say exactly what an
agent did, under which rules, and who approved it. An auditor does not read the platform's logs; they read evidence,
so the record has to be shaped for the questions an auditor asks, and it has to be emitted by the platform, not
written by hand afterwards.

## Decision

### What is recorded

Every action the agent **proposes** leaves one record, whether or not it ran. A denied attempt and a gated action
are evidence too, and often the most useful evidence. A run also writes a `run_started` record first and a
`run_finished` record last, so that a log cut short is noticed.

### The shape, mapped to what an auditor asks

| The auditor asks | Where the record answers |
|---|---|
| Who acted? | `agent.id`, and `principal`: the identity the platform authenticated (the user and the event that started the run), never anything the agent says about itself |
| What did it try to do? | `request` (the action and the tool) and `request_sha256` |
| Under which rules? | `policy`: the effect (`allow`, `gate`, `deny`), the class, the reason, the hash of the policy files and the version of the engine |
| Who approved it? | `approval`: whether one was required, its status, the approver, when, and the source of the approval. A gated action is recorded as `pending` until a person decides |
| What happened? | `execution`: whether it ran, the outcome, the detail, the duration, and the hash of the sandbox limits it ran under |
| In which version of the code? | `source`: repository, workflow, run, attempt, commit and ref |
| Was it altered afterwards? | `chain`: the hash of the previous record, and this record's own hash |

An example, shortened:

```json
{"schema": "agent-audit/1", "seq": 3, "event": "action", "run_id": "44042568154-1-enforce",
 "agent": {"id": "agent-sandbox-01", "kind": "scripted"},
 "request": {"action": "modify_policy", "tool": null},
 "policy": {"effect": "gate", "class": "human-gated", "reason": "a person must approve before this runs",
            "policy_sha256": "...", "engine": "opa 1.21.4"},
 "approval": {"required": true, "status": "pending", "approver": null, "decided_at": null, "source": null},
 "execution": {"executed": false, "outcome": "not run", "detail": "gate: ...", "flags_sha256": null},
 "chain": {"prev": "...", "sha256": "..."}}
```

### Why the record is written where the agent cannot reach it

The enforcement point (`agent/run_agent.py`) writes the record, outside the sandbox. The agent proposes actions and
never touches the log, and the input to the policy, including any approval, is built by the platform and not by the
agent. That is what lets the record be trusted: what is recorded is what the platform observed.

### Tamper-evident, and what makes it immutable

Each record carries the hash of the one before it, and the first is tied to its run. Changing, removing, adding or
reordering a record breaks every hash after it. That makes the log **tamper-evident**.

It does not make it immutable. Someone who can rewrite the whole log can recompute the whole chain, and the tests
show it: a complete rewrite passes the chain check and is caught only by the **head hash** (the hash of the last
record), which is kept in a manifest and printed in the run's summary. So the strength of the trail is exactly the
strength of the place where the head is kept. Today that is the build artifact and the run summary: out of reach of the
agent (it is in the container, and never touches them), but not out of reach of the pipeline itself, which writes
both. So the manifest protects against editing after the fact, not against a compromised pipeline. The next change
moves the head to a store that no one in the pipeline can rewrite or delete.

Every record is also written to disk the moment it exists. A run that crashes half way leaves the records of what
it already did and a log with no `run_finished`, which the gate refuses as cut short; the alternative, writing the
log at the end, would lose exactly the actions that matter most.

### What the audit gate refuses

`agent/audit_verify.py` reads the log from disk, in a separate process, and refuses it if:

- a record lacks a field its event requires;
- a hash is wrong, the chain is broken, or the records are not numbered 0, 1, 2 without a gap;
- it does not start with one `run_started` and end with one `run_finished`;
- the log says something that cannot be true: an action ran although the policy denied it, a gated action is not
  pending, a human-gated action ran without an approval from someone other than the agent, an approval is recorded
  where none is needed, an action was judged by a different policy than the run started with, the summary disagrees
  with the records;
- the number of records or the head hash does not match the manifest;
- an action of the plan is missing, unplanned, repeated or out of order.

A gate that has never refused anything proves nothing, so it is tested three ways: 53 unit tests, most of which damage
a good log and require the gate to notice; a **test of the tests**, `agent/mutation_check.py`, which weakens the
verifier and the log writer in 21 ways and requires the tests to notice each (it runs in CI, so the claim is
reproducible); and, in CI, a step that damages the run's own log in four ways and requires each to be refused.

The mutation check found, when it was first run, that four rules were covered only indirectly: because every record
is inside the hash chain, the numbering, the manifest's count, the approval status and the run identifier cannot be
wrong in a log that was merely edited; they matter for a log that was forged consistently. Each now has its own test.

What the consistency checks can and cannot do: they catch a bug, and a careless alteration. They cannot, by
themselves, catch a forger who rewrites everything consistently, because they judge the log against itself (for
example the approver is compared with the agent id that the log carries). Authenticity comes from where the log is
written and where its head is kept, not from these checks.

## What is not true yet

- **Approval.** No approval path exists, so every gated action is recorded `pending`. The field is where the approval
  from a person will go; the rules about it (a different person from the agent, a source, a time) are enforced and
  tested now.
- **Immutability.** See above: the next change.
- **A separate identity for the agent.** The agent has an id in every record, but the actions of the run still
  happen under the pipeline's identity.
- **The agent is a script.** A model-driven agent would also need the hash of its prompt, the model and the
  request id in the record, as the review trace (`ai-review-trace/1`) already carries. The schema has room for it.
- **The runner is trusted.** If the machine that runs the pipeline were compromised, it could write a false log. The
  record shows what the platform observed; it does not protect against a platform that lies.

## Consequences

- A change that cannot show a complete, consistent log fails the check `Agent sandbox escape test`, which is required.
- The records are kept for 90 days as a build artifact, and the head hash of each log is printed in the run summary.
- An auditor can verify a log offline, with the standard library and one script, without trusting the platform.
