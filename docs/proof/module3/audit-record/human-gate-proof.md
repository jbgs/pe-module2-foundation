# The human gate, with a real approval (2026-11-17)

Workflow `Agent approved run`, run 44068206838, dispatched from `main` (commit c42b06b) by `jbgs`.
The Environment `agent-approval`: required reviewer `jbgs`, "Prevent self-review" off, restricted to the `main` branch.

| Job | Result |
|---|---|
| The agent asks to export its result | success: the export waited, the log says `approval: pending`, nothing left |
| A person approves the export | waited for the reviewer, then success |
| The agent runs again, with the approval | success: the approval was read from GitHub by that job itself |
| Publish the request and the approved run | success: all nine refusals, with the writer's own role, were the right error |

## What GitHub holds (`GET /actions/runs/44068206838/approvals`)
state `approved`, user `jbgs`, environment `agent-approval`, comment "Approval agent deployment."

## The record of the approved action, read back from the audit store
- policy: `allow`, class `human-gated`, "human gate passed"
- approval: `approved` by `jbgs`, `2026-11-17T10:50:34Z` (the start of the job behind the approval)
- source: `github-environment:agent-approval`; evidence: `actions/runs/44068206838 (approver id 29926047 ...)`
- execution: ran, completed, "produced a result of 54 bytes", output sha256 `1dfad42e...3c98`
- the same run, in the same log: `modify_policy` and `deploy_dev` stay `pending` (an approval is for one action)
- the request log, written before the approval: `export_result` was `gate` / `pending` / not run
- who asked for the run: `jbgs`, event `workflow_dispatch`, commit c42b06b, agent `agent-sandbox-01`

## What left the sandbox
`synthetic churn analysis: 8 customers, 3 churned (38%)`. Its sha256 is `1dfad42e7db9c4236f1359f1d87e5a8a948cee705b07b98b0a5125991eab3c98`,
the same as the one in the record (checked from the artifact, independently of the record).

## In the store
Both logs read back from AWS pass the audit gate (`publish_audit.py verify --entry request:enforce --entry approved:enforce`).
Every object is locked (GOVERNANCE, until 2026-11-24).

Copies of the two logs, their manifests and the exported result: `~/ai-path/_evidence/module3-approved-run/`.
