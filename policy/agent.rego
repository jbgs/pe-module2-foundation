# What an agent may do on this platform, as code.
#
# Every consequential action of an agent is described as an input and evaluated here before it runs:
#
#   {"agent": "agent-sandbox-01", "action": "deploy_dev", "tool": "...", "approval": {...}}
#
# The answer has one of three effects:
#   allow  the action is autonomous, or a human gate has been passed
#   gate   a person must approve first; nothing runs until they do
#   deny   the action is forbidden, or is not in this policy at all (default deny)
#
# This file is the logical layer. It does not replace the hard boundary: the sandbox has no network and no
# regulated data mounted, so a forbidden action fails at the runtime even if this policy were wrong.
# Changing this file changes what agents may do, so it is itself a human-gated action (modify_policy).

package agent.policy

# Autonomous: the agent may do these on its own, inside the sandbox.
autonomous_actions := {
	"read_synthetic_data",
	"write_workspace",
	"run_tests",
	"call_approved_tool",
}

# Human-gated: a person must approve, because these touch a real system or change what agents may do.
human_gated_actions := {
	"deploy_dev",
	"modify_policy",
}

# Forbidden: never, and an approval does not unlock them.
forbidden_actions := {
	"read_regulated_data",
	"network_egress",
	"write_outside_workspace",
	"privileged_exec",
}

# Tool-use scope: the only tools call_approved_tool may reach.
approved_tools := {
	"formatter",
	"linter",
	"unit-tests",
}

# People who may approve a gated action. An agent never approves its own action.
approvers := {"jbgs"}

default decision := {
	"effect": "deny",
	"class": "unlisted",
	"reason": "default deny: the action is not in the policy",
}

decision := {
	"effect": "deny",
	"class": "forbidden",
	"reason": "forbidden action: no approval unlocks it",
} if {
	input.action in forbidden_actions
}

decision := {
	"effect": "allow",
	"class": "autonomous",
	"reason": "autonomous action inside the sandbox",
} if {
	input.action in autonomous_actions
	input.action != "call_approved_tool"
}

decision := {
	"effect": "allow",
	"class": "autonomous",
	"reason": "tool is in the approved scope",
} if {
	input.action == "call_approved_tool"
	tool_in_scope
}

decision := {
	"effect": "deny",
	"class": "forbidden",
	"reason": "tool is not in the approved scope",
} if {
	input.action == "call_approved_tool"
	not tool_in_scope
}

decision := {
	"effect": "allow",
	"class": "human-gated",
	"reason": "human gate passed",
} if {
	input.action in human_gated_actions
	approved
}

decision := {
	"effect": "gate",
	"class": "human-gated",
	"reason": "a person must approve before this runs",
} if {
	input.action in human_gated_actions
	not approved
}

# An approval counts only if it is positive, comes from a listed approver, and is not the agent itself.
# Anything missing makes this false, so the gate fails closed.
approved if {
	input.approval.approved == true
	input.approval.approver in approvers
	input.approval.approver != input.agent
}

# A helper rule, not an inline "not input.tool in ...": negating a path that does not exist does not
# behave as "not in scope", so a call without any tool would have fallen through to the default.
tool_in_scope if input.tool in approved_tools
