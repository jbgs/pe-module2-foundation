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


# What a forger who can rewrite the whole log does: recompute every hash from the start.
rechain = audit.rechain


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

    def test_a_record_removed_and_the_chain_recomputed_but_not_renumbered(self):
        # The hashes are all consistent; only the numbering shows that a record is missing.
        del self.records[3]
        prev = audit.genesis(self.records[0]["run_id"])
        for rec in self.records:
            rec["chain"] = {"prev": prev}
            rec["chain"]["sha256"] = audit.record_hash(rec)
            prev = rec["chain"]["sha256"]
        problems = audit_verify.verify(self.records, None, PLAN)
        self.assertTrue(any("removed, added or moved" in p for p in problems))

    def test_a_manifest_with_the_right_head_but_the_wrong_count(self):
        forged = dict(self.manifest, records=self.manifest["records"] + 1)
        problems = audit_verify.verify(self.records, forged, PLAN)
        self.assertTrue(any("manifest counts" in p for p in problems))

    def test_a_record_of_another_run_inside_a_consistent_chain(self):
        self.records[2]["run_id"] = "another-run"
        audit.rechain(self.records)
        problems = audit_verify.verify(self.records, None, PLAN)
        self.assertTrue(any("another run or mode" in p for p in problems))

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

    def test_an_approval_that_was_not_granted_does_not_unlock_a_human_gated_action(self):
        for status in ("pending", "denied"):
            with self.subTest(status=status):
                self.records = copy.deepcopy(build("enforce").records)
                rec = self.action("modify_policy")
                rec["policy"]["effect"] = "allow"
                rec["execution"]["executed"] = True
                rec["execution"]["flags_sha256"] = "b" * 64
                rec["approval"] = {"required": True, "status": status, "approver": "jbgs",
                                   "decided_at": "2026-11-17T09:00:00Z", "source": "x", "evidence": "y"}
                self.assertTrue(any("without an approval" in p for p in self.problems()))

    def test_an_approval_that_says_nothing_about_where_it_came_from(self):
        for field in ("source", "evidence", "decided_at"):
            with self.subTest(field=field):
                self.records = copy.deepcopy(build("enforce").records)
                rec = self.action("modify_policy")
                rec["policy"]["effect"] = "allow"
                rec["execution"]["executed"] = True
                rec["execution"]["flags_sha256"] = "b" * 64
                rec["approval"] = {"required": True, "status": "approved", "approver": "jbgs",
                                   "decided_at": "2026-11-17T09:00:00Z", "source": "github-environment:x", "evidence": "run/1"}
                rec["approval"][field] = None
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


class Streaming(unittest.TestCase):
    """A run that crashes half way must leave the records of what it already did."""

    def test_every_record_is_on_disk_the_moment_it_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            sink = Path(tmp) / "audit.jsonl"
            log = audit.AuditLog("run-1", "enforce", sink=sink)
            log.append("run_started", x=1)
            self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 1)
            log.append("action", x=2)
            self.assertEqual(len(sink.read_text(encoding="utf-8").splitlines()), 2)

    def test_what_is_on_disk_is_what_the_log_holds(self):
        with tempfile.TemporaryDirectory() as tmp:
            sink = Path(tmp) / "audit.jsonl"
            log = run_agent.start_log("enforce", json.dumps(PLAN).encode(), SHA, ENGINE, Path(tmp))
            for item in PLAN:
                record, _ = run_agent.evaluate(item, "enforce", decide_fn=fake_policy, run_fn=fake_run)
                run_agent.audit_action(log, record, SHA, ENGINE)
            run_agent.finish_log(log)
            on_disk = audit_verify.load_records(Path(tmp) / "audit-enforce.jsonl")
            self.assertEqual(on_disk, log.records)
            self.assertEqual(audit_verify.verify(on_disk, log.manifest(), PLAN), [])
            self.assertEqual(sink.name, "audit.jsonl")

    def test_a_run_that_crashed_leaves_a_log_the_gate_refuses_as_cut_short(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = run_agent.start_log("enforce", json.dumps(PLAN).encode(), SHA, ENGINE, Path(tmp))
            record, _ = run_agent.evaluate(PLAN[0], "enforce", decide_fn=fake_policy, run_fn=fake_run)
            run_agent.audit_action(log, record, SHA, ENGINE)
            # the process dies here: no run_finished, no manifest
            on_disk = audit_verify.load_records(Path(tmp) / "audit-enforce.jsonl")
            self.assertEqual(len(on_disk), 2)
            self.assertEqual(on_disk[1]["request"]["action"], "read_synthetic_data")
            self.assertTrue(any("cut short" in p for p in audit_verify.verify(on_disk, None, PLAN)))


class Malformed(unittest.TestCase):
    """Input that is not a log at all is refused with a reason, not with a crash."""

    def good(self):
        return copy.deepcopy(build("enforce").records)

    def test_a_line_that_is_not_an_object(self):
        recs = self.good()
        recs[2] = ["not", "an", "object"]
        self.assertTrue(any("not an object" in p for p in audit_verify.verify(recs, None, PLAN)))

    def test_a_line_that_is_a_string(self):
        recs = self.good()
        recs[1] = "text"
        self.assertTrue(audit_verify.verify(recs, None, PLAN))

    def test_a_chain_that_is_not_an_object(self):
        recs = self.good()
        recs[1]["chain"] = "abc"
        self.assertTrue(any("chain field is malformed" in p for p in audit_verify.verify(recs, None, PLAN)))

    def test_a_chain_without_a_hash(self):
        recs = self.good()
        del recs[1]["chain"]["sha256"]
        self.assertTrue(any("chain field is malformed" in p for p in audit_verify.verify(recs, None, PLAN)))

    def test_a_request_that_is_a_list(self):
        recs = self.good()
        next(r for r in recs if r["event"] == "action")["request"] = ["read_synthetic_data"]
        self.assertTrue(any("request is not an object" in p for p in audit_verify.verify(recs, None, PLAN)))

    def test_an_unknown_event(self):
        recs = self.good()
        recs[1]["event"] = "something_else"
        self.assertTrue(audit_verify.verify(recs, None, PLAN))

    def test_a_tamper_test_does_not_crash_when_a_detail_is_empty(self):
        recs = self.good()
        next(r for r in recs if r["event"] == "action")["execution"]["detail"] = None
        audit.rechain(recs)
        manifest = {"run_id": recs[0]["run_id"], "records": len(recs), "head_sha256": recs[-1]["chain"]["sha256"]}
        with tempfile.TemporaryDirectory() as tmp:
            path, mpath = Path(tmp) / "a.jsonl", Path(tmp) / "m.json"
            path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
            mpath.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(audit_verify.main([str(path), "--manifest", str(mpath), "--tamper-test"]), 0)

    def test_the_tamper_test_refuses_to_run_without_a_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text(build("enforce").text(), encoding="utf-8")
            with self.assertRaises(SystemExit):
                audit_verify.main([str(path), "--tamper-test"])

    def test_the_command_reports_instead_of_crashing_on_a_file_of_garbage(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text('[1, 2]\n"x"\n{"a": 1}\nnot json\n', encoding="utf-8")
            self.assertEqual(audit_verify.main([str(path)]), 1)


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
