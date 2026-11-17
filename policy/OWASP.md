# Mapping to the OWASP Top 10 for Agentic Applications (2026)

The ten risks and their titles are taken from the OWASP GenAI Security Project announcement of
9 December 2025 ("OWASP Top 10 for Agentic Applications"). Each row says what this platform does about the
risk, where it is enforced, and, honestly, what is not covered or not built yet.

**Status words.** *Enforced now*: in this folder and tested. *Planned*: a later change in the Module 3 plan, not
yet built. *Not applicable in v1*: the v1 agent has no such feature. *Gap*: known and not covered.

The v1 agent is a deterministic script, not a language model. That removes some risks and leaves others only
partly tested; the table says which.

| ID | Risk | What this platform does | Where | Status |
|---|---|---|---|---|
| ASI01 | Agent Goal Hijack | Whatever the goal, an action is limited by default deny and by the three classes. A hijacked goal cannot reach a forbidden or gated action without a person | policy | Enforced now (by containment, not by detecting the hijack). Gap: no prompt-injection defence, because v1 has no model to hijack |
| ASI02 | Tool Misuse | `call_approved_tool` reaches only three tools; any other tool, or none, is denied with a reason | policy | Enforced now (tested) |
| ASI03 | Identity & Privilege Abuse | An agent never approves its own action; approvers are a listed set; the sandbox holds no credentials; pipeline roles carry a permissions boundary | policy, sandbox, IAM | The rule is enforced now and tested; the authenticity of an approval is not: it depends on the enforcement point building the input (see the trust boundary in the README). Planned: that point, and a separate identity for the agent in every record |
| ASI04 | Agentic Supply Chain Vulnerabilities | Workflow actions pinned by SHA, Python requirements pinned by hash, the policy engine pinned by version and checksum | pipeline | Enforced now. Gap: no signature or SBOM check on what the sandbox runs |
| ASI05 | Unexpected Code Execution | `privileged_exec` is forbidden; the sandbox has no network, a read-only root, no capabilities and resource limits | runtime, policy | Enforced now: the policy forbids it, and the sandbox stops the attempt by itself with the policy switched off. Seven escape attempts are blocked in CI, and removing each limit in turn lets its attempt escape, so each limit is shown to matter (`agent/`, ADR 0004). Gap: a container shares its host's kernel |
| ASI06 | Memory & Context Poisoning | The v1 agent has no memory or context store | n/a | Not applicable in v1; revisit if the agent gets memory |
| ASI07 | Insecure Inter-Agent Communication | There is one agent and no channel between agents | n/a | Not applicable in v1 |
| ASI08 | Cascading Failures | Per-sandbox CPU, memory and process limits; ephemeral runs; one run at a time; the deployment circuit breaker | runtime, pipeline | Enforced now for the sandbox limits: a process flood stops at the limit and a memory flood is killed, in CI. Gap: no limits across a fleet |
| ASI09 | Human-Agent Trust Exploitation | The gate states the action, its class and the reason, and the approval is recorded with an identity; an agent cannot approve | policy, audit | The separation-of-duties rule is enforced now and tested, on the input it is given. Planned: the enforcement point that reads the approval from a source the agent cannot write, and the record. Gap: a single person can approve their own change |
| ASI10 | Rogue Agents | Default deny; ephemeral sandboxes; an audit trail that is tamper-evident; a run can be cancelled | policy, runtime, audit | Policy enforced now. Planned: the audit trail. Gap: no detection of unusual behaviour |

Nothing in this table claims more than what exists. As the later changes land (sandbox, audit record,
separate agent identity), the *Planned* rows are updated to *Enforced*, each with its proof.
