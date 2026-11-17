# Agent policy

What an agent may do on this platform, as code. The rules are in [`agent.rego`](agent.rego), the tests in
[`agent_test.rego`](agent_test.rego), and the mapping to the OWASP Top 10 for Agentic Applications in
[`OWASP.md`](OWASP.md).

## The classification

Every consequential action of an agent is evaluated before it runs. The answer is `allow`, `gate` or `deny`.

| Class | Actions | What happens |
|---|---|---|
| Autonomous | `read_synthetic_data`, `write_workspace`, `run_tests`, `call_approved_tool` | allowed, inside the sandbox |
| Human-gated | `deploy_dev`, `modify_policy` | `gate`: nothing runs until a person approves |
| Forbidden | `read_regulated_data`, `network_egress`, `write_outside_workspace`, `privileged_exec` | `deny`, and no approval unlocks it |
| Not listed | anything else | `deny` (default deny) |

**Tool-use scope.** `call_approved_tool` reaches only `formatter`, `linter` and `unit-tests`. Another tool, or
no tool at all, is denied with the reason `tool is not in the approved scope`.

**Where the human gate sits.** On anything that touches a real system (`deploy_dev`) and on anything that changes
what agents may do (`modify_policy`). An approval counts only if it is positive, comes from a listed approver, and
is not the agent itself. A missing field fails closed.

**Regulated data.** The regulated-data boundary is not a gate: it is a wall. The sandbox does not have that data
mounted and has no network, so `read_regulated_data` and `network_egress` are forbidden here and also impossible
at the runtime.

## The input and the output

```json
{"agent": "agent-sandbox-01", "action": "deploy_dev", "approval": {"approver": "jbgs", "approved": true}}
```

```json
{"effect": "allow", "class": "human-gated", "reason": "human gate passed"}
```

The `class` and the `reason` go into the audit record, so the tests check them and not only the effect.

## Run it

The version is pinned in the CI job `Policy tests` (`.github/workflows/ci.yaml`) with its checksum.

```
opa fmt --fail policy/
opa check --strict policy/
opa test policy/ -v
echo '{"agent":"a","action":"network_egress"}' | opa eval -d policy/ -I 'data.agent.policy.decision'
```

## Changing the policy

Changing this folder changes what agents may do, so it is itself a gated action: it goes through a pull request,
the required checks (including `Policy tests`) must pass, and a person merges. An agent can propose a change; it
cannot apply one.

## What the tests prove

16 tests, and the tests themselves were tested: nine deliberate weakenings of the policy (an agent that approves
its own action, an approver outside the list, a negative approval that passes, forbidden actions that stop being
classified, a gated action that becomes autonomous, a tool outside the scope that passes, a default that allows)
were each caught. Two of them were not caught at first, because the tests checked only the effect of a decision
and not its class or reason; they do now.
