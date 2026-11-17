# Tests of the agent policy. They run in CI on every pull request (job "Policy tests").

package agent.policy_test

import data.agent.policy

agent := "agent-sandbox-01"

yes := {"approver": "jbgs", "approved": true}

# The three classes must not overlap, or one action could be allowed and denied at once.
test_classes_are_disjoint if {
	count(policy.autonomous_actions & policy.human_gated_actions) == 0
	count(policy.autonomous_actions & policy.forbidden_actions) == 0
	count(policy.human_gated_actions & policy.forbidden_actions) == 0
}

# call_approved_tool is judged by its tool, so it has its own tests below.
test_autonomous_actions_are_allowed if {
	every a in policy.autonomous_actions - {"call_approved_tool"} {
		policy.decision.effect == "allow" with input as {"agent": agent, "action": a}
	}
}

test_approved_tool_is_allowed if {
	policy.decision.effect == "allow" with input as {"agent": agent, "action": "call_approved_tool", "tool": "linter"}
}

test_tool_outside_the_scope_is_denied if {
	policy.decision.effect == "deny" with input as {"agent": agent, "action": "call_approved_tool", "tool": "curl"}
	policy.decision.reason == "tool is not in the approved scope" with input as {"agent": agent, "action": "call_approved_tool", "tool": "curl"}
	policy.decision.class == "forbidden" with input as {"agent": agent, "action": "call_approved_tool", "tool": "curl"}
}

test_tool_call_without_a_tool_is_denied if {
	policy.decision.effect == "deny" with input as {"agent": agent, "action": "call_approved_tool"}
	policy.decision.reason == "tool is not in the approved scope" with input as {"agent": agent, "action": "call_approved_tool"}
}

# The class matters as much as the effect: it is what the audit record says about why the action was denied.
test_forbidden_actions_are_denied if {
	every a in policy.forbidden_actions {
		policy.decision.effect == "deny" with input as {"agent": agent, "action": a}
		policy.decision.class == "forbidden" with input as {"agent": agent, "action": a}
	}
}

test_an_approval_does_not_unlock_a_forbidden_action if {
	every a in policy.forbidden_actions {
		policy.decision.effect == "deny" with input as {"agent": agent, "action": a, "approval": yes}
		policy.decision.class == "forbidden" with input as {"agent": agent, "action": a, "approval": yes}
	}
}

test_gated_actions_wait_for_a_person if {
	every a in policy.human_gated_actions {
		policy.decision.effect == "gate" with input as {"agent": agent, "action": a}
	}
}

test_gated_actions_pass_with_a_valid_approval if {
	every a in policy.human_gated_actions {
		policy.decision.effect == "allow" with input as {"agent": agent, "action": a, "approval": yes}
	}
}

test_a_negative_approval_does_not_pass if {
	policy.decision.effect == "gate" with input as {"agent": agent, "action": "deploy_dev", "approval": {"approver": "jbgs", "approved": false}}
}

test_an_approver_outside_the_list_does_not_pass if {
	policy.decision.effect == "gate" with input as {"agent": agent, "action": "deploy_dev", "approval": {"approver": "mallory", "approved": true}}
}

test_an_agent_cannot_approve_its_own_action if {
	policy.decision.effect == "gate" with input as {"agent": "jbgs", "action": "modify_policy", "approval": yes}
}

test_a_gate_without_an_agent_identity_fails_closed if {
	policy.decision.effect == "gate" with input as {"action": "deploy_dev", "approval": yes}
}

test_an_unlisted_action_is_denied_by_default if {
	policy.decision.effect == "deny" with input as {"agent": agent, "action": "format_disk"}
	policy.decision.class == "unlisted" with input as {"agent": agent, "action": "format_disk"}
}

test_input_without_an_action_is_denied if {
	policy.decision.effect == "deny" with input as {"agent": agent}
	policy.decision.class == "unlisted" with input as {"agent": agent}
}

# Changing the policy is human-gated: an agent can propose it, not apply it.
test_changing_the_policy_is_never_autonomous if {
	policy.decision.effect != "allow" with input as {"agent": agent, "action": "modify_policy"}
}
