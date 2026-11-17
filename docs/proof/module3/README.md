# Module 3 proof pack

The gate question: **can an agent run reach anything it should not, and can you prove exactly what every agent did and who approved it?**

Each item below is a real result from this repository, not a design. Every audit log here was re-checked with `agent/audit_verify.py`
(chain intact, head hash equal to the manifest) after being copied.

| What the hand-in asks for | Where it is |
|---|---|
| A screenshot or log of an agent blocked at a sandbox escape | [`sandbox-escape/summary-bypass.md`](sandbox-escape/summary-bypass.md): the policy layer is switched off, and the container alone blocks network, regulated data, writes outside the workspace, privilege, the process limit and memory. Run 44076018411 on `main`. |
| Proof that the test can fail | [`sandbox-escape/summary-weakening.md`](sandbox-escape/summary-weakening.md): each limit is removed in turn and the matching attempt then escapes (6 of 6). The blocks are therefore the limits' doing, not an empty test. |
| One audit record showing what the agent did and who approved it | [`audit-record/approved-audit.jsonl`](audit-record/approved-audit.jsonl), record `seq` 5: `export_result`, class human-gated, approval `approved` by `jbgs`, source `github-environment:agent-approval`, evidence `actions/runs/44068206838`. Read it with [`audit-record/human-gate-proof.md`](audit-record/human-gate-proof.md). |
| What the agent was not allowed to do before the approval | [`audit-record/request-audit.jsonl`](audit-record/request-audit.jsonl): the same action is `pending`, not run. In the approved log, `modify_policy` and `deploy_dev` stay `pending`: an approval is for one action. |
| The policy file | [`policy/agent.rego`](../../../policy/agent.rego), with its tests (`agent_test.rego`) and the OWASP Top 10 for Agentic Applications mapping ([`policy/OWASP.md`](../../../policy/OWASP.md)). Its combined hash, `29d739d62b15d726711c50314e7a491fa588df667b6053bd924a5db29e8591fd`, is the `policy_sha256` written in every record of the approved run, and it is unchanged since. |
| The records cannot be rewritten | [`store/audit-store-proof.md`](store/audit-store-proof.md) and [`store/audit-publish-proof.md`](store/audit-publish-proof.md): Object Lock, versioning, a writer role that can only create new objects, and the refusals it got when it tried to replace or shorten one. |
| Adoption is measured, from the first use | [`store/golden-path-store-proof.md`](store/golden-path-store-proof.md): two real requests through the golden path, read back from the store. |
| Why, and what it does not do | ADRs 0004 to 0008 in [`docs/adr/`](../../adr/). |

## What this does not show

Stated here so that nobody has to find it out.

- **The agent is scripted.** It proposes a fixed plan of actions. The sandbox and the policy are tested against that plan, not against a model that tries to get out.
- **One person approves their own run.** The Environment `agent-approval` has "Prevent self-review" off, because there is one account. The record says who approved, and cannot say that it was somebody other than the requester.
- **A container shares the kernel of the runner.** It is a hard boundary for these attempts, not a proof against a kernel escape.
- **The approval time is the start of the job behind it.** GitHub's approvals API gives no approval timestamp, so the record says so in its `evidence` field.
- **"Tamper-evident" is not "immutable".** The hash chain shows that a record was changed. The store's Object Lock is GOVERNANCE mode, so an administrator with the bypass permission could still remove an object. It is declared, not hidden.
- **There is one Builder.** The adoption instrument works (2 requests, 1 covered, read back from the store). It cannot yet say whether Builders choose the path.
- **The metric detects negligence, not fraud.** A hand-built folder with a matching record would pass as the path.
