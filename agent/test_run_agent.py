"""Tests of the enforcement point. They need neither Docker nor the policy engine.

A check that has never failed proves little, so most of these tests are about the judge saying "no": an attempt
that gets out, a legitimate action that does not complete, a policy that lets an attempt through, a canary that
leaks. They also run the real policy decisions through a stub that follows the policy's rules.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import audit
import audit_verify
import run_agent

LEGIT = {"action": "read_synthetic_data", "kind": "legit"}
ATTEMPT = {"action": "network_egress", "kind": "attempt"}
GATED = {"action": "deploy_dev", "kind": "gated-only"}


def completes(item):
    return {"exit": 0, "observation": {"result": "completed", "detail": "ok"}, "text": "", "ms": 5}


def is_blocked(item):
    return {"exit": 0, "observation": {"result": "blocked", "detail": "no network"}, "text": "", "ms": 5}


def escapes(item):
    return {"exit": 0, "observation": {"result": "escaped", "detail": "connected"}, "text": "", "ms": 5}


def killed(item):
    return {"exit": 137, "observation": None, "text": "", "ms": 5}


def policy_allows(item):
    return {"effect": "allow", "class": "autonomous", "reason": "ok"}


def policy_denies(item):
    return {"effect": "deny", "class": "forbidden", "reason": "no"}


def policy_gates(item):
    return {"effect": "gate", "class": "human-gated", "reason": "a person must approve"}


def record(item, mode, decide, run):
    rec, _ = run_agent.evaluate(item, mode, decide_fn=decide, run_fn=run)
    return rec


class Classify(unittest.TestCase):
    def test_a_result_is_taken_from_the_container(self):
        self.assertEqual(run_agent.classify(ATTEMPT, is_blocked(ATTEMPT))[0], "blocked")

    def test_exit_137_means_the_limit_killed_it(self):
        self.assertEqual(run_agent.classify(ATTEMPT, killed(ATTEMPT))[0], "killed")

    def test_no_result_and_no_kill_is_an_error(self):
        self.assertEqual(run_agent.classify(ATTEMPT, {"exit": 1, "observation": None})[0], "error")


class Enforce(unittest.TestCase):
    def test_an_allowed_action_runs(self):
        rec = record(LEGIT, "enforce", policy_allows, completes)
        self.assertTrue(rec["executed"])
        self.assertEqual(rec["outcome"], "completed")

    def test_a_denied_action_does_not_run(self):
        rec = record(ATTEMPT, "enforce", policy_denies, escapes)
        self.assertFalse(rec["executed"])

    def test_a_gated_action_does_not_run(self):
        rec = record(GATED, "enforce", policy_gates, completes)
        self.assertFalse(rec["executed"])
        self.assertIn("a person must approve", rec["detail"])

    def test_the_expected_run_has_no_problems(self):
        recs = [
            record(LEGIT, "enforce", policy_allows, completes),
            record(ATTEMPT, "enforce", policy_denies, escapes),
            record(GATED, "enforce", policy_gates, completes),
        ]
        self.assertEqual(run_agent.judge("enforce", recs, False), [])

    def test_a_policy_that_allows_an_attempt_is_a_problem(self):
        recs = [record(ATTEMPT, "enforce", policy_allows, is_blocked)]
        self.assertTrue(run_agent.judge("enforce", recs, False))

    def test_a_legitimate_action_that_the_policy_denies_is_a_problem(self):
        recs = [record(LEGIT, "enforce", policy_denies, completes)]
        self.assertTrue(run_agent.judge("enforce", recs, False))


class Bypass(unittest.TestCase):
    def test_every_attempt_blocked_is_a_pass(self):
        recs = [record(LEGIT, "bypass", None, completes), record(ATTEMPT, "bypass", None, is_blocked)]
        self.assertEqual(run_agent.judge("bypass", recs, False), [])

    def test_a_kill_by_a_limit_counts_as_blocked(self):
        recs = [record({"action": "resource_memory", "kind": "attempt"}, "bypass", None, killed)]
        self.assertEqual(run_agent.judge("bypass", recs, False), [])

    def test_an_escape_fails_the_run(self):
        recs = [record(ATTEMPT, "bypass", None, escapes)]
        problems = run_agent.judge("bypass", recs, False)
        self.assertEqual(len(problems), 1)
        self.assertIn("ESCAPED", problems[0])

    def test_an_attempt_that_errors_is_not_a_pass(self):
        recs = [record(ATTEMPT, "bypass", None, lambda item: {"exit": 1, "observation": None, "text": "", "ms": 1})]
        self.assertTrue(run_agent.judge("bypass", recs, False))

    def test_a_legitimate_action_that_fails_is_a_problem(self):
        recs = [record(LEGIT, "bypass", None, is_blocked)]
        self.assertTrue(run_agent.judge("bypass", recs, False))

    def test_a_gated_only_action_is_not_run_in_bypass(self):
        rec = record(GATED, "bypass", None, escapes)
        self.assertFalse(rec["executed"])
        self.assertEqual(run_agent.judge("bypass", [rec], False), [])

    def test_a_leaked_canary_fails_the_run_even_if_everything_was_blocked(self):
        recs = [record(ATTEMPT, "bypass", None, is_blocked)]
        problems = run_agent.judge("bypass", recs, True)
        self.assertEqual(len(problems), 1)
        self.assertIn("canary", problems[0])


class Controls(unittest.TestCase):
    """The negative controls: remove one limit, and the attempt it held back must escape."""

    def control(self, weaken, action, run):
        rec, _ = run_agent.evaluate({"action": action, "kind": "attempt"}, "weakening", run_fn=lambda it: run(it))
        rec["weakened"] = weaken
        return rec

    def test_an_attempt_that_escapes_once_the_limit_is_gone_is_a_pass(self):
        rec = self.control("network", "network_egress", escapes)
        self.assertEqual(run_agent.judge_controls([rec]), [])

    def test_an_attempt_still_blocked_without_the_limit_is_a_problem(self):
        rec = self.control("network", "network_egress", is_blocked)
        problems = run_agent.judge_controls([rec])
        self.assertEqual(len(problems), 1)
        self.assertIn("not what stops it", problems[0])

    def test_a_kill_without_the_limit_is_a_problem_too(self):
        rec = self.control("memory", "resource_memory", killed)
        self.assertTrue(run_agent.judge_controls([rec]))

    def test_every_control_names_a_limit_that_can_be_removed(self):
        for weaken, action in run_agent.CONTROLS:
            self.assertTrue(weaken in run_agent.WEAKENED or weaken == "data", weaken)
            self.assertTrue(action)

    def test_removing_a_limit_changes_only_that_limit(self):
        base = run_agent.sandbox_flags()
        for weaken in run_agent.WEAKENED:
            weakened = run_agent.sandbox_flags(weaken)
            self.assertNotEqual(base, weakened, weaken)
            for other, group in run_agent.FLAG_GROUPS.items():
                if other != weaken:
                    for flag in group:
                        self.assertIn(flag, weakened, f"removing {weaken} also removed {flag}")

    def test_the_network_control_swaps_none_for_a_real_network(self):
        flags = " ".join(run_agent.sandbox_flags("network"))
        self.assertIn("--network bridge", flags)
        self.assertNotIn("--network none", flags)

    def test_the_readonly_control_removes_the_flag(self):
        self.assertNotIn("--read-only", run_agent.sandbox_flags("readonly"))

    def test_the_privilege_control_runs_as_root_with_default_capabilities(self):
        flags = " ".join(run_agent.sandbox_flags("privilege"))
        self.assertIn("--user 0", flags)
        self.assertNotIn("--cap-drop", flags)

    def test_only_the_data_control_mounts_the_regulated_stand_in(self):
        self.assertNotIn("/regulated", " ".join(run_agent.sandbox_mounts()))
        self.assertIn("/regulated", " ".join(run_agent.sandbox_mounts("data")))


class Setup(unittest.TestCase):
    def test_the_sandbox_has_no_network_and_a_read_only_root(self):
        flags = " ".join(run_agent.SANDBOX_FLAGS)
        for must in ("--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "--pids-limit", "--memory "):
            self.assertIn(must, flags)

    def test_the_regulated_stand_in_is_never_mounted(self):
        self.assertNotIn("regulated", " ".join(run_agent.SANDBOX_FLAGS))
        self.assertNotIn("regulated", str(run_agent.SYNTHETIC_DIR))

    def test_the_stand_in_carries_a_canary(self):
        self.assertRegex(run_agent.canary(), r"^CANARY-[0-9a-f]{16}$")

    def test_the_plan_names_only_known_actions(self):
        import json

        plan = json.loads((run_agent.ROOT / "agent" / "plan.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(plan), 8)
        self.assertTrue({"legit", "attempt", "gated", "gated-only"} >= {item["kind"] for item in plan})


APPROVAL = {"action": "export_result", "approver": "jbgs", "approved": True,
            "decided_at": "2026-11-17T10:05:09Z", "source": "github-environment:agent-approval",
            "evidence": "actions/runs/55"}
EXPORT = {"action": "export_result", "kind": "gated"}
MODIFY = {"action": "modify_policy", "kind": "attempt"}


def gate_policy(item, approval=None):
    """The rules of the real policy for the gated actions, for tests that need no policy engine."""
    if item["action"] in ("export_result", "modify_policy", "deploy_dev"):
        if approval and approval["approver"] in ("jbgs",) and approval["approved"] is True:
            return {"effect": "allow", "class": "human-gated", "reason": "human gate passed"}
        return {"effect": "gate", "class": "human-gated", "reason": "a person must approve before this runs"}
    return {"effect": "allow", "class": "autonomous", "reason": "ok"}


def exports(item):
    return {"exit": 0, "observation": {"result": "completed", "detail": "produced a result", "output": "8 customers"}, "text": "", "ms": 9}


class Approvals(unittest.TestCase):
    """A person's approval: it goes to the action it names, to no other, and what it unlocks is recorded."""

    def test_an_approval_is_given_to_its_own_action_and_to_no_other(self):
        seen = {}

        def decide(item, approval=None):
            seen[item["action"]] = approval
            return gate_policy(item, approval)

        run_agent.evaluate(EXPORT, "enforce", decide_fn=decide, run_fn=exports, approval=APPROVAL)
        run_agent.evaluate(MODIFY, "enforce", decide_fn=decide, run_fn=exports, approval=APPROVAL)
        self.assertEqual(seen["export_result"], APPROVAL)
        self.assertIsNone(seen["modify_policy"])

    def test_approving_the_export_does_not_unlock_another_gated_action(self):
        rec, _ = run_agent.evaluate(MODIFY, "enforce", decide_fn=gate_policy, run_fn=exports, approval=APPROVAL)
        self.assertFalse(rec["executed"])
        self.assertEqual(rec["policy"]["effect"], "gate")

    def test_without_an_approval_the_export_waits_and_nothing_runs(self):
        rec, _ = run_agent.evaluate(EXPORT, "enforce", decide_fn=gate_policy, run_fn=exports)
        self.assertFalse(rec["executed"])
        self.assertEqual(rec["policy"]["effect"], "gate")
        self.assertNotIn("approval", rec)

    def test_with_an_approval_the_export_runs_and_carries_the_approval(self):
        rec, _ = run_agent.evaluate(EXPORT, "enforce", decide_fn=gate_policy, run_fn=exports, approval=APPROVAL)
        self.assertTrue(rec["executed"])
        self.assertEqual(rec["approval"], APPROVAL)
        self.assertIn("output sha256", rec["detail"])

    def test_the_record_says_who_approved_and_where_it_came_from(self):
        log = audit.AuditLog("run-1", "enforce")
        log.append("run_started", agent={"id": run_agent.AGENT_ID}, principal={}, source={}, plan_sha256="x" * 64,
                   policy_sha256="a" * 64, policy_engine="opa", sandbox={})
        rec, _ = run_agent.evaluate(EXPORT, "enforce", decide_fn=gate_policy, run_fn=exports, approval=APPROVAL)
        out = run_agent.audit_action(log, rec, "a" * 64, "opa")
        self.assertEqual(out["approval"], {"required": True, "status": "approved", "approver": "jbgs",
                                           "decided_at": "2026-11-17T10:05:09Z",
                                           "source": "github-environment:agent-approval", "evidence": "actions/runs/55"})

    def test_a_log_with_an_approved_action_passes_the_audit_gate(self):
        plan = [EXPORT, MODIFY]
        log = run_agent.start_log("enforce", json.dumps(plan).encode(), "a" * 64, "opa")
        for item in plan:
            rec, _ = run_agent.evaluate(item, "enforce", decide_fn=gate_policy, run_fn=exports, approval=APPROVAL)
            run_agent.audit_action(log, rec, "a" * 64, "opa")
        run_agent.finish_log(log)
        self.assertEqual(audit_verify.verify(log.records, log.manifest(), plan), [])
        by_action = {r["request"]["action"]: r for r in log.records if r["event"] == "action"}
        self.assertEqual(by_action["export_result"]["approval"]["status"], "approved")
        self.assertEqual(by_action["modify_policy"]["approval"]["status"], "pending")

    def test_an_approval_file_that_is_negative_or_incomplete_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in {
                "negative": {**APPROVAL, "approved": False},
                "no approver": {**APPROVAL, "approver": ""},
                "no evidence": {**APPROVAL, "evidence": None},
                "no source": {k: v for k, v in APPROVAL.items() if k != "source"},
            }.items():
                path = Path(tmp) / f"{name}.json"
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.subTest(name), self.assertRaises(SystemExit):
                    run_agent.load_approval(str(path))
            good = Path(tmp) / "good.json"
            good.write_text(json.dumps(APPROVAL), encoding="utf-8")
            self.assertEqual(run_agent.load_approval(str(good)), APPROVAL)


class DataGuard(unittest.TestCase):
    """The sandbox is given synthetic data only, whoever asks."""

    def folder(self, tmp, name, files):
        d = Path(tmp) / name
        d.mkdir()
        for f in files:
            (d / f).write_text("x", encoding="utf-8")
        return d

    def test_a_folder_of_synthetic_data_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_agent.check_data_dir(self.folder(tmp, "data", ["churn.csv"]))

    def test_a_folder_that_looks_like_regulated_data_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, files in (("regulated-copy", ["a.csv"]), ("ok", ["customers.csv"]), ("ok2", ["regulated_export.csv"])):
                with self.subTest(name), self.assertRaises(SystemExit):
                    run_agent.check_data_dir(self.folder(tmp, name, files))

    def test_an_empty_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                run_agent.check_data_dir(self.folder(tmp, "empty", []))

    def test_the_stand_in_of_the_repository_is_refused(self):
        with self.assertRaises(SystemExit):
            run_agent.check_data_dir(run_agent.STANDIN_FILE.parent)

    def test_the_default_data_is_accepted(self):
        run_agent.check_data_dir(run_agent.SYNTHETIC_DIR)


class Environments(unittest.TestCase):
    def test_a_run_inside_an_environment_of_the_path_names_it(self):
        log = run_agent.start_log("enforce", b"[]", "a" * 64, "opa", environment="agent-sandbox-1")
        self.assertEqual(log.records[0]["environment"], {"id": "agent-sandbox-1"})

    def test_a_run_outside_the_path_says_so(self):
        log = run_agent.start_log("enforce", b"[]", "a" * 64, "opa")
        self.assertIsNone(log.records[0]["environment"])

    def test_the_log_with_an_environment_passes_the_audit_gate(self):
        plan = [{"action": "read_synthetic_data", "kind": "legit"}]
        log = run_agent.start_log("enforce", json.dumps(plan).encode(), "a" * 64, "opa", environment="e1")
        rec, _ = run_agent.evaluate(plan[0], "enforce", decide_fn=gate_policy, run_fn=exports)
        run_agent.audit_action(log, rec, "a" * 64, "opa")
        run_agent.finish_log(log)
        self.assertEqual(audit_verify.verify(log.records, log.manifest(), plan), [])


class Labels(unittest.TestCase):
    def test_a_label_is_part_of_the_run_id_so_two_logs_of_one_run_are_two_identities(self):
        a = run_agent.start_log("enforce", b"[]", "a" * 64, "opa", label="request")
        b = run_agent.start_log("enforce", b"[]", "a" * 64, "opa", label="approved")
        self.assertTrue(a.run_id.endswith("-enforce-request"))
        self.assertTrue(b.run_id.endswith("-enforce-approved"))

    def test_without_a_label_the_run_id_is_as_before(self):
        self.assertTrue(run_agent.start_log("enforce", b"[]", "a" * 64, "opa").run_id.endswith("-enforce"))


class Export(unittest.TestCase):
    """What leaves the sandbox: only an approved result, and exactly what the record hashes."""

    def test_an_approved_result_is_written_out(self):
        rec, _ = run_agent.evaluate(EXPORT, "enforce", decide_fn=gate_policy, run_fn=exports, approval=APPROVAL)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(run_agent.export_approved(Path(tmp), [rec]))
            text = (Path(tmp) / "exported-result.txt").read_text(encoding="utf-8")
        self.assertEqual(text, "8 customers\n")
        self.assertIn(audit.sha256_hex(b"8 customers"), rec["detail"])

    def test_a_result_with_no_approval_is_never_written_out(self):
        rec, _ = run_agent.evaluate(EXPORT, "bypass", run_fn=exports)  # the policy is off: it ran, but nobody approved
        self.assertTrue(rec["executed"])
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(run_agent.export_approved(Path(tmp), [rec]))
            self.assertFalse((Path(tmp) / "exported-result.txt").exists())

    def test_a_run_that_failed_its_own_checks_exports_nothing(self):
        rec, _ = run_agent.evaluate(EXPORT, "enforce", decide_fn=gate_policy, run_fn=exports, approval=APPROVAL)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(run_agent.export_if_clean(Path(tmp), [rec], ["something failed"]))
            self.assertFalse((Path(tmp) / "exported-result.txt").exists())
            self.assertTrue(run_agent.export_if_clean(Path(tmp), [rec], []))

    def test_a_pending_export_writes_nothing(self):
        rec, _ = run_agent.evaluate(EXPORT, "enforce", decide_fn=gate_policy, run_fn=exports)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(run_agent.export_approved(Path(tmp), [rec]))


class JudgeGated(unittest.TestCase):
    def rec(self, mode, approval=None):
        r, _ = run_agent.evaluate(EXPORT, mode, decide_fn=gate_policy, run_fn=exports, approval=approval)
        return r

    def test_pending_without_approval_is_what_enforce_expects(self):
        self.assertEqual(run_agent.judge("enforce", [self.rec("enforce")], False), [])

    def test_approved_and_run_is_what_enforce_expects_when_approved(self):
        self.assertEqual(run_agent.judge("enforce", [self.rec("enforce", APPROVAL)], False, {"export_result"}), [])

    def test_a_gated_action_that_ran_without_an_approval_is_a_problem(self):
        problems = run_agent.judge("enforce", [self.rec("bypass")], False)
        self.assertTrue(any("without a person's approval" in p for p in problems))

    def test_an_approved_action_that_did_not_run_is_a_problem(self):
        problems = run_agent.judge("enforce", [self.rec("enforce")], False, {"export_result"})
        self.assertTrue(any("did not run to completion" in p for p in problems))

    def test_an_approved_action_with_no_approval_attached_is_a_problem(self):
        rec = self.rec("enforce", APPROVAL)
        del rec["approval"]
        self.assertTrue(any("no approval attached" in p for p in run_agent.judge("enforce", [rec], False, {"export_result"})))

    def test_in_bypass_a_gated_action_is_only_an_action_inside_the_sandbox(self):
        self.assertEqual(run_agent.judge("bypass", [self.rec("bypass")], False), [])


@unittest.skipUnless(shutil.which(run_agent.OPA), "the policy engine is not installed")
class RealPolicy(unittest.TestCase):
    """The same questions, put to the real policy and not to a stand-in."""

    def test_the_export_waits_for_a_person(self):
        self.assertEqual(run_agent.decide(EXPORT)["effect"], "gate")

    def test_the_export_passes_with_the_approval_of_a_listed_person(self):
        self.assertEqual(run_agent.decide(EXPORT, APPROVAL)["effect"], "allow")

    def test_an_approver_who_is_not_listed_does_not_pass(self):
        self.assertEqual(run_agent.decide(EXPORT, {**APPROVAL, "approver": "mallory"})["effect"], "gate")

    def test_a_refusal_does_not_pass(self):
        self.assertEqual(run_agent.decide(EXPORT, {**APPROVAL, "approved": False})["effect"], "gate")

    def test_the_plan_runs_the_whole_way_with_the_real_policy(self):
        plan = json.loads((run_agent.ROOT / "agent" / "plan.json").read_text(encoding="utf-8"))
        run = lambda item: {"exit": 0, "observation": {"result": "completed" if item["kind"] != "attempt" else "blocked",
                                                       "detail": "x", "output": "out"}, "text": "", "ms": 1}
        records = [run_agent.evaluate(i, "enforce", run_fn=run, approval=APPROVAL)[0] for i in plan]
        self.assertEqual(run_agent.judge("enforce", records, False, {"export_result"}), [])
        effects = {r["action"]: r["policy"]["effect"] for r in records}
        self.assertEqual(effects["export_result"], "allow")
        self.assertEqual(effects["modify_policy"], "gate")
        self.assertEqual(effects["deploy_dev"], "gate")


if __name__ == "__main__":
    unittest.main()
