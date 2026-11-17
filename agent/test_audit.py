"""Tests of the audit record and of the audit gate.

The gate is only worth something if it says "no". So most of these tests build a good log, damage it in one way,
and require the gate to notice. One of them shows a way the chain alone does NOT notice, and what does.
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import audit
import audit_verify
import run_agent

ENGINE = "opa 1.21.4"
SHA = "a" * 64
PLAN = [
    {"action": "read_synthetic_data", "kind": "legit"},
    {"action": "call_approved_tool", "tool": "linter", "kind": "legit"},
    {"action": "network_egress", "kind": "attempt"},
    {"action": "modify_policy", "kind": "attempt"},
    {"action": "deploy_dev", "kind": "gated-only"},
]
DECISIONS = {
    "read_synthetic_data": {"effect": "allow", "class": "autonomous", "reason": "ok"},
    "call_approved_tool": {"effect": "allow", "class": "autonomous", "reason": "ok"},
    "network_egress": {"effect": "deny", "class": "forbidden", "reason": "no"},
    "modify_policy": {"effect": "gate", "class": "human-gated", "reason": "a person must approve"},
    "deploy_dev": {"effect": "gate", "class": "human-gated", "reason": "a person must approve"},
}


def fake_policy(item):
    return dict(DECISIONS[item["action"]])


def fake_run(item):
    result = "completed" if item["kind"] == "legit" else "blocked"
    return {"exit": 0, "observation": {"result": result, "detail": "x"}, "text": "", "ms": 7}


def build(mode="enforce", items=None):
    items = items or PLAN
    log = run_agent.start_log(mode, json.dumps(items).encode(), SHA, ENGINE)
    for item in items:
        record, _ = run_agent.evaluate(item, mode, decide_fn=fake_policy, run_fn=fake_run)
        run_agent.audit_action(log, record, SHA, ENGINE)
    run_agent.finish_log(log)
    return log


def rechain(records):
    """What a forger who can rewrite the whole log does: recompute every hash from the start."""
    prev = audit.genesis(records[0]["run_id"])
    for index, rec in enumerate(records):
        rec["seq"] = index
        rec["chain"] = {"prev": prev}
        rec["chain"]["sha256"] = audit.record_hash(rec)
        prev = rec["chain"]["sha256"]


class Good(unittest.TestCase):
    def test_a_good_enforce_log_passes(self):
        log = build("enforce")
        self.assertEqual(audit_verify.verify(log.records, log.manifest(), PLAN), [])

    def test_a_good_bypass_log_passes(self):
        log = build("bypass")
        self.assertEqual(audit_verify.verify(log.records, log.manifest(), PLAN), [])

    def test_every_planned_action_has_exactly_one_record_even_if_it_did_not_run(self):
        log = build("enforce")
        actions = [r for r in log.records if r["event"] == "action"]
        self.assertEqual(len(actions), len(PLAN))
        self.assertEqual([r["execution"]["executed"] for r in actions], [True, True, False, False, False])

    def test_a_gated_action_is_recorded_as_waiting_for_a_person(self):
        log = build("enforce")
        gated = [r for r in log.records if r["event"] == "action" and r["policy"]["effect"] == "gate"]
        self.assertEqual(len(gated), 2)
        for rec in gated:
            self.assertEqual(rec["approval"]["status"], "pending")
            self.assertIsNone(rec["approval"]["approver"])


class Chain(unittest.TestCase):
    def test_the_chain_is_deterministic_for_the_same_content(self):
        a, b = audit.AuditLog("run-1", "enforce", now=lambda: "T"), audit.AuditLog("run-1", "enforce", now=lambda: "T")
        for log in (a, b):
            log.append("run_started", x=1, y=[1, 2])
        self.assertEqual(a.records[0]["chain"], b.records[0]["chain"])

    def test_the_hash_does_not_depend_on_the_order_of_keys(self):
        self.assertEqual(audit.canonical({"a": 1, "b": 2}), audit.canonical({"b": 2, "a": 1}))

    def test_the_first_record_is_tied_to_its_run(self):
        self.assertNotEqual(audit.genesis("run-1"), audit.genesis("run-2"))

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(ValueError):
            audit.AuditLog("run-1", "anything")


class Tampering(unittest.TestCase):
    """Each test damages a good log in one way. The gate must refuse it."""

    def setUp(self):
        self.log = build("enforce")
        self.records = copy.deepcopy(self.log.records)
        self.manifest = self.log.manifest()

    def refused(self, records, manifest=True):
        return audit_verify.verify(records, self.manifest if manifest else None, PLAN)

    def action(self, name):
        return next(r for r in self.records if r["event"] == "action" and r["request"]["action"] == name)

    def test_changing_what_happened_is_detected(self):
        self.action("network_egress")["execution"]["detail"] = "nothing happened"
        self.assertTrue(any("altered" in p for p in self.refused(self.records)))

    def test_changing_the_outcome_from_blocked_to_completed_is_detected(self):
        self.action("modify_policy")["execution"]["outcome"] = "completed"
        self.assertTrue(self.refused(self.records))

    def test_removing_a_record_from_the_middle_is_detected(self):
        del self.records[2]
        self.assertTrue(self.refused(self.records))

    def test_reordering_two_records_is_detected(self):
        self.records[2], self.records[3] = self.records[3], self.records[2]
        self.assertTrue(self.refused(self.records))

    def test_cutting_off_the_end_is_detected(self):
        self.records.pop()
        problems = self.refused(self.records)
        self.assertTrue(any("cut short" in p for p in problems))

    def test_adding_a_forged_record_at_the_end_is_detected(self):
        forged = copy.deepcopy(self.records[2])
        forged["seq"] = len(self.records)
        self.records.append(forged)
        self.assertTrue(self.refused(self.records))

    def test_moving_a_record_from_another_run_is_detected(self):
        other = build("enforce")
        other.records[1]["run_id"] = "another-run"
        self.records[1] = other.records[1]
        self.assertTrue(self.refused(self.records))

    def test_rewriting_one_record_and_fixing_only_its_own_hash_is_detected(self):
        rec = self.action("network_egress")
        rec["execution"]["detail"] = "nothing happened"
        rec["chain"]["sha256"] = audit.record_hash(rec)
        problems = self.refused(self.records)
        self.assertTrue(any("chain is broken" in p for p in problems))

    def test_a_complete_rewrite_passes_the_chain_and_is_caught_only_by_the_manifest(self):
        # The honest limit of a hash chain: someone who can rewrite the whole log can recompute the whole chain.
        self.action("network_egress")["execution"]["detail"] = "nothing happened"
        rechain(self.records)
        self.assertEqual(self.refused(self.records, manifest=False), [], "the chain alone cannot see this")
        problems = self.refused(self.records, manifest=True)
        self.assertTrue(any("head hash does not match the manifest" in p for p in problems))

    def test_an_empty_log_is_refused(self):
        self.assertTrue(audit_verify.verify([], None, PLAN))

    def test_an_unreadable_line_is_refused(self):
        self.assertTrue(audit_verify.verify([{"_unreadable_line": 3}], None, PLAN))


class Consistency(unittest.TestCase):
    """The log is chained correctly but says something that cannot be true."""

    def setUp(self):
        self.records = copy.deepcopy(build("enforce").records)

    def action(self, name):
        return next(r for r in self.records if r["event"] == "action" and r["request"]["action"] == name)

    def problems(self):
        rechain(self.records)
        return audit_verify.verify(self.records, None, PLAN)

    def test_an_action_that_ran_although_the_policy_denied_it(self):
        rec = self.action("network_egress")
        rec["execution"]["executed"] = True
        rec["execution"]["flags_sha256"] = "b" * 64
        self.assertTrue(any("ran although the policy said deny" in p for p in self.problems()))

    def test_an_action_that_ran_although_it_was_gated(self):
        rec = self.action("modify_policy")
        rec["execution"]["executed"] = True
        rec["execution"]["flags_sha256"] = "b" * 64
        self.assertTrue(any("ran although the policy said gate" in p for p in self.problems()))

    def test_an_allowed_action_with_no_record_that_it_ran(self):
        self.action("read_synthetic_data")["execution"]["executed"] = False
        self.assertTrue(any("no record that it ran" in p for p in self.problems()))

    def test_a_human_gated_action_that_ran_with_no_approval(self):
        rec = self.action("modify_policy")
        rec["policy"]["effect"] = "allow"
        rec["execution"]["executed"] = True
        rec["execution"]["flags_sha256"] = "b" * 64
        rec["approval"] = {"required": False, "status": "not_required", "approver": None, "decided_at": None,
                           "source": None, "evidence": None}
        self.assertTrue(any("without an approval" in p for p in self.problems()))

    def test_an_agent_that_approves_its_own_action(self):
        rec = self.action("modify_policy")
        rec["policy"]["effect"] = "allow"
        rec["execution"]["executed"] = True
        rec["execution"]["flags_sha256"] = "b" * 64
        rec["approval"] = {"required": True, "status": "approved", "approver": run_agent.AGENT_ID,
                           "decided_at": "2026-11-17T09:00:00Z", "source": "x", "evidence": "y"}
        self.assertTrue(any("without an approval" in p for p in self.problems()))

    def test_a_valid_human_approval_passes(self):
        rec = self.action("modify_policy")
        rec["policy"]["effect"] = "allow"
        rec["execution"]["executed"] = True
        rec["execution"]["flags_sha256"] = "b" * 64
        rec["approval"] = {"required": True, "status": "approved", "approver": "jbgs",
                           "decided_at": "2026-11-17T09:00:00Z", "source": "github-environment", "evidence": "123"}
        summary = next(r for r in self.records if r["event"] == "run_finished")["summary"]
        summary.update({"executed": summary["executed"] + 1, "allowed": summary["allowed"] + 1, "gated": summary["gated"] - 1})
        self.assertEqual(self.problems(), [])

    def test_a_gated_action_whose_approval_is_not_pending(self):
        self.action("modify_policy")["approval"]["status"] = "not_required"
        self.assertTrue(any("not recorded as pending" in p for p in self.problems()))

    def test_an_approval_on_an_action_that_needs_none(self):
        rec = self.action("network_egress")
        rec["approval"].update({"required": True, "status": "approved"})
        self.assertTrue(any("needs none" in p for p in self.problems()))

    def test_an_effect_that_does_not_fit_the_mode(self):
        self.action("read_synthetic_data")["policy"]["effect"] = "bypassed"
        self.assertTrue(any("does not fit mode" in p for p in self.problems()))

    def test_a_policy_decision_with_a_missing_field(self):
        del self.action("network_egress")["policy"]["reason"]
        self.assertTrue(any("lacks reason" in p for p in self.problems()))

    def test_an_action_judged_by_a_different_policy_than_the_run_started_with(self):
        self.action("network_egress")["policy"]["policy_sha256"] = "c" * 64
        self.assertTrue(any("different policy" in p for p in self.problems()))

    def test_a_request_that_does_not_match_its_hash(self):
        self.action("network_egress")["request"]["action"] = "run_tests"
        self.assertTrue(any("does not match its hash" in p for p in self.problems()))

    def test_a_summary_that_disagrees_with_the_records(self):
        next(r for r in self.records if r["event"] == "run_finished")["summary"]["denied"] = 0
        self.assertTrue(any("run_finished says" in p for p in self.problems()))

    def test_a_planned_action_that_was_never_recorded(self):
        self.records = [r for r in self.records if r.get("request", {}).get("action") != "network_egress"]
        finished = next(r for r in self.records if r["event"] == "run_finished")
        finished["summary"].update({"actions": 4, "denied": 0})
        self.assertTrue(any("not the actions planned" in p for p in self.problems()))

    def test_an_action_that_was_not_planned(self):
        extra = copy.deepcopy(self.action("network_egress"))
        extra["request"] = {"action": "privileged_exec", "tool": None}
        extra["request_sha256"] = audit.sha256_hex(audit.canonical(extra["request"]))
        self.records.insert(-1, extra)
        finished = next(r for r in self.records if r["event"] == "run_finished")
        finished["summary"].update({"actions": 6, "denied": 2})
        self.assertTrue(any("not the actions planned" in p for p in self.problems()))


class Command(unittest.TestCase):
    def test_the_command_passes_a_good_log_and_refuses_a_tampered_one(self):
        log = build("enforce")
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "audit.jsonl"
            manifest = Path(tmp) / "manifest.json"
            plan = Path(tmp) / "plan.json"
            good.write_text(log.text(), encoding="utf-8")
            manifest.write_text(json.dumps(log.manifest()), encoding="utf-8")
            plan.write_text(json.dumps(PLAN), encoding="utf-8")
            self.assertEqual(audit_verify.main([str(good), "--manifest", str(manifest), "--expect", str(plan)]), 0)
            bad = Path(tmp) / "bad.jsonl"
            tampered = log.text().replace('"outcome": "completed"', '"outcome": "blocked"', 1)
            self.assertNotEqual(tampered, log.text(), "the test must change something")
            bad.write_text(tampered, encoding="utf-8")
            self.assertEqual(audit_verify.main([str(bad), "--manifest", str(manifest), "--expect", str(plan)]), 1)


class Limits(unittest.TestCase):
    def test_the_limits_hash_depends_on_the_limits(self):
        self.assertNotEqual(run_agent.flags_sha256(), run_agent.flags_sha256("network"))
        self.assertNotEqual(run_agent.flags_sha256("network"), run_agent.flags_sha256("readonly"))

    def test_the_limits_in_a_record_name_no_path_of_the_machine(self):
        self.assertNotIn(str(run_agent.ROOT), " ".join(run_agent.limits_description()))


if __name__ == "__main__":
    unittest.main()
