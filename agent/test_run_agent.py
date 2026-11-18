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
import environment
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
        self.assertTrue({"legit", "attempt", "gated", "gated-only", "contained"} >= {item["kind"] for item in plan})


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


SYNTHETIC = run_agent.ROOT / "agent" / "synthetic"
POLICY = run_agent.ROOT / "policy"


def copy_synthetic(dest: Path) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    for f in SYNTHETIC.iterdir():
        if f.is_file():
            (dest / f.name).write_bytes(f.read_bytes())
    return dest


class DataGuard(unittest.TestCase):
    """The sandbox is given synthetic data only, and the only data known to be synthetic is the platform's own."""

    def test_the_platforms_synthetic_data_is_accepted_wherever_it_is(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_agent.check_data_dir(copy_synthetic(Path(tmp) / "data"))
            # a parent folder whose name merely contains the word is not regulated data
            run_agent.check_data_dir(copy_synthetic(Path(tmp) / "unregulated" / "data"))

    def test_the_default_data_is_accepted(self):
        run_agent.check_data_dir(run_agent.SYNTHETIC_DIR)

    def test_whole_words_only(self):
        for name in ("regulated", "Regulated-copy", "customers.csv", "my_customers_2024.csv", "data/regulated/x"):
            self.assertTrue(run_agent.looks_regulated(name), name)
        for name in ("unregulated", "churn.csv", "deregulated-market", "customer.csv", "synthetic"):
            self.assertFalse(run_agent.looks_regulated(name), name)

    def test_a_folder_or_file_that_looks_like_regulated_data_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = copy_synthetic(Path(tmp) / "regulated-copy")
            with self.assertRaises(SystemExit) as caught:
                run_agent.check_data_dir(bad)
            self.assertIn("regulated data", str(caught.exception))
            ok = copy_synthetic(Path(tmp) / "ok")
            (ok / "customers.csv").write_text("x", encoding="utf-8")
            with self.assertRaises(SystemExit):
                run_agent.check_data_dir(ok)

    def test_regulated_data_under_another_name_is_refused_because_it_is_not_the_platforms_data(self):
        # The name guard alone would let this through: the stand-in's content, renamed.
        with tempfile.TemporaryDirectory() as tmp:
            disguised = Path(tmp) / "data"
            disguised.mkdir()
            (disguised / "export.csv").write_bytes(run_agent.STANDIN_FILE.read_bytes())
            with self.assertRaises(SystemExit) as caught:
                run_agent.check_data_dir(disguised)
            self.assertIn("not the platform's synthetic data", str(caught.exception))

    def test_the_right_name_with_other_content_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = copy_synthetic(Path(tmp) / "data")
            (d / "churn.csv").write_text("customer_id,tenure\nSYN-9,1\n", encoding="utf-8")
            with self.assertRaises(SystemExit):
                run_agent.check_data_dir(d)

    def test_an_extra_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = copy_synthetic(Path(tmp) / "data")
            (d / "notes.txt").write_text("hello", encoding="utf-8")
            with self.assertRaises(SystemExit):
                run_agent.check_data_dir(d)

    def test_an_empty_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "empty").mkdir()
            with self.assertRaises(SystemExit):
                run_agent.check_data_dir(Path(tmp) / "empty")

    def test_the_stand_in_of_the_repository_is_refused(self):
        with self.assertRaises(SystemExit):
            run_agent.check_data_dir(run_agent.STANDIN_FILE.parent)


class PolicyGuard(unittest.TestCase):
    """What judges the agent is the platform's policy, not whatever a caller points at."""

    def policy_dir(self, tmp, files):
        d = Path(tmp) / "policy"
        d.mkdir()
        for name, content in files.items():
            (d / name).write_bytes(content)
        return d

    def test_a_copy_of_the_platforms_policy_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_agent.check_policy_dir(self.policy_dir(tmp, {"agent.rego": (POLICY / "agent.rego").read_bytes()}))
            run_agent.check_policy_dir(self.policy_dir(Path(tmp) / "b", {}) if False else run_agent.POLICY_DIR)

    def test_a_weaker_policy_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            weaker = (POLICY / "agent.rego").read_bytes().replace(b'"effect": "deny"', b'"effect": "allow"', 1)
            with self.assertRaises(SystemExit) as caught:
                run_agent.check_policy_dir(self.policy_dir(tmp, {"agent.rego": weaker}))
            self.assertIn("not the platform's policy", str(caught.exception))

    def test_a_folder_without_agent_rego_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                run_agent.check_policy_dir(self.policy_dir(tmp, {"other.rego": b"package x"}))

    def test_an_extra_rule_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = {"agent.rego": (POLICY / "agent.rego").read_bytes(), "extra.rego": b"package agent.policy\n"}
            with self.assertRaises(SystemExit):
                run_agent.check_policy_dir(self.policy_dir(tmp, files))


class RefusedEnvironments(unittest.TestCase):
    """A run that names an environment is checked against it, and the module state is put back whatever happens."""

    def env(self, tmp, **record):
        d = Path(tmp) / "env1"
        (d / "data").mkdir(parents=True)
        (d / "policy").mkdir()
        copy_synthetic(d / "data")
        (d / "policy" / "agent.rego").write_bytes((POLICY / "agent.rego").read_bytes())
        (d / "plan.json").write_text("[]", encoding="utf-8")
        files = environment.read_files(d)
        meta = {"id": "env1", "template_sha256": environment.template_sha256(files),
                "policy_sha256": audit.sha256_hex(files["policy/agent.rego"])}
        meta.update(record)
        (d / "environment.json").write_text(json.dumps(meta), encoding="utf-8")
        return d

    def run_main(self, d, *extra):
        return run_agent.main(["--mode", "enforce", "--plan", str(d / "plan.json"), "--environment", "env1", "--out", str(d / "out"), *extra])

    def test_a_run_in_a_folder_that_is_not_an_environment_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "plan.json").write_text("[]")
            with self.assertRaises(SystemExit) as caught:
                run_agent.main(["--mode", "enforce", "--plan", str(Path(tmp) / "plan.json"), "--environment", "env1"])
            self.assertIn("no environment.json", str(caught.exception))

    def test_a_run_that_names_another_environment_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit) as caught:
                run_agent.main(["--mode", "enforce", "--plan", str(self.env(tmp) / "plan.json"), "--environment", "somebody-elses"])
            self.assertIn("not 'somebody-elses'", str(caught.exception))

    def test_an_environment_whose_data_was_changed_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self.env(tmp)
            (d / "data" / "churn.csv").write_text("changed")
            with self.assertRaises(SystemExit) as caught:
                self.run_main(d)
            self.assertIn("not as they were", str(caught.exception))

    def test_an_environment_whose_policy_was_changed_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self.env(tmp)
            (d / "policy" / "agent.rego").write_text("package agent.policy\n")
            with self.assertRaises(SystemExit):
                self.run_main(d)

    def test_an_environment_whose_policy_is_an_older_one_is_refused(self):
        # Intact, but no longer the platform's policy: it was made under another one.
        with tempfile.TemporaryDirectory() as tmp:
            d = self.env(tmp)
            old = b"package agent.policy\n# an older policy\n" + (POLICY / "agent.rego").read_bytes()
            (d / "policy" / "agent.rego").write_bytes(old)
            files = environment.read_files(d)
            meta = json.loads((d / "environment.json").read_text())
            meta.update(template_sha256=environment.template_sha256(files), policy_sha256=audit.sha256_hex(old))
            (d / "environment.json").write_text(json.dumps(meta))
            with self.assertRaises(SystemExit) as caught:
                self.run_main(d)
            self.assertIn("not the platform's policy", str(caught.exception))

    def test_a_run_that_uses_data_that_is_not_the_environments_own_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = self.env(tmp)
            elsewhere = copy_synthetic(Path(tmp) / "elsewhere")
            with self.assertRaises(SystemExit) as caught:
                self.run_main(d, "--data", str(elsewhere))
            self.assertIn("not the environment's own", str(caught.exception))

    def test_the_module_state_is_put_back_after_a_refused_run(self):
        before = (run_agent.SYNTHETIC_DIR, run_agent.POLICY_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            elsewhere = copy_synthetic(Path(tmp) / "elsewhere")
            weaker = Path(tmp) / "weaker"
            weaker.mkdir()
            (weaker / "agent.rego").write_text("package agent.policy\n")
            with self.assertRaises(SystemExit):
                run_agent.main(["--mode", "bypass", "--data", str(elsewhere), "--policy-dir", str(weaker), "--out", str(Path(tmp) / "o")])
        self.assertEqual((run_agent.SYNTHETIC_DIR, run_agent.POLICY_DIR), before)

    def test_the_state_is_put_back_even_after_a_data_folder_was_accepted(self):
        before = (run_agent.SYNTHETIC_DIR, run_agent.POLICY_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            good = copy_synthetic(Path(tmp) / "good")
            with self.assertRaises(FileNotFoundError):  # the plan does not exist: it stops after the data was taken
                run_agent.main(["--mode", "bypass", "--data", str(good), "--plan", str(Path(tmp) / "nope.json"), "--out", str(Path(tmp) / "o")])
        self.assertEqual((run_agent.SYNTHETIC_DIR, run_agent.POLICY_DIR), before)


class Environments(unittest.TestCase):
    def test_a_run_inside_an_environment_of_the_path_names_it_and_its_hash(self):
        log = run_agent.start_log("enforce", b"[]", "a" * 64, "opa", environment="agent-sandbox-1", environment_hash="h" * 64)
        self.assertEqual(log.records[0]["environment"], {"id": "agent-sandbox-1", "template_sha256": "h" * 64})

    def test_a_run_outside_the_path_says_so(self):
        log = run_agent.start_log("enforce", b"[]", "a" * 64, "opa")
        self.assertIsNone(log.records[0]["environment"])

    def test_the_log_with_an_environment_passes_the_audit_gate(self):
        plan = [{"action": "read_synthetic_data", "kind": "legit"}]
        log = run_agent.start_log("enforce", json.dumps(plan).encode(), "a" * 64, "opa", environment="e1", environment_hash="h" * 64)
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
        run = lambda item: {"exit": 0, "observation": {"result": "completed" if item["kind"] not in ("attempt", "contained") else "blocked",
                                                       "detail": "x", "output": "out"}, "text": "", "ms": 1}
        records = [run_agent.evaluate(i, "enforce", run_fn=run, approval=APPROVAL)[0] for i in plan]
        self.assertEqual(run_agent.judge("enforce", records, False, {"export_result"}), [])
        effects = {r["action"]: r["policy"]["effect"] for r in records}
        self.assertEqual(effects["export_result"], "allow")
        self.assertEqual(effects["modify_policy"], "gate")
        self.assertEqual(effects["deploy_dev"], "gate")


CONTAINED = {"action": "run_generated_code", "task": "escape", "kind": "contained"}
GENERATED = {"action": "run_generated_code", "task": "analysis", "kind": "legit"}


class GeneratedCode(unittest.TestCase):
    """Code the agent writes at run time. The policy cannot read it, so the policy allows the action and the sandbox is
    what must hold: the attempt has to run, and be stopped."""

    def test_a_contained_attempt_that_was_stopped_is_what_both_modes_expect(self):
        for mode in ("enforce", "bypass"):
            rec = record(CONTAINED, mode, policy_allows if mode == "enforce" else None, is_blocked)
            self.assertEqual(run_agent.judge(mode, [rec], False), [], mode)

    def test_a_contained_attempt_that_got_out_is_a_problem(self):
        for mode in ("enforce", "bypass"):
            rec = record(CONTAINED, mode, policy_allows if mode == "enforce" else None, escapes)
            self.assertTrue(any("ESCAPED" in p for p in run_agent.judge(mode, [rec], False)), mode)

    def test_a_contained_attempt_that_never_ran_is_a_problem(self):
        rec = record(CONTAINED, "enforce", policy_denies, is_blocked)
        problems = run_agent.judge("enforce", [rec], False)
        self.assertTrue(any("expected the policy to allow it" in p for p in problems))

    def test_a_contained_attempt_that_failed_to_run_is_a_problem(self):
        rec = record(CONTAINED, "bypass", None, completes)
        self.assertTrue(any("ESCAPED or failed to run" in p for p in run_agent.judge("bypass", [rec], False)))

    def test_a_killed_attempt_counts_as_stopped(self):
        rec = record(CONTAINED, "enforce", policy_allows, killed)
        self.assertEqual(run_agent.judge("enforce", [rec], False), [])

    def test_the_task_is_in_the_record_and_in_the_request_hash_only_when_there_is_one(self):
        log = run_agent.start_log("enforce", b"[]", "a" * 64, "opa")
        with_task = run_agent.audit_action(log, record(CONTAINED, "enforce", policy_allows, is_blocked), "a" * 64, "opa")
        without = run_agent.audit_action(log, record(LEGIT, "enforce", policy_allows, completes), "a" * 64, "opa")
        self.assertEqual(with_task["request"], {"action": "run_generated_code", "tool": None, "task": "escape"})
        self.assertEqual(without["request"], {"action": "read_synthetic_data", "tool": None})

    def test_two_tasks_of_the_same_action_are_two_different_requests(self):
        log = run_agent.start_log("enforce", b"[]", "a" * 64, "opa")
        a = run_agent.audit_action(log, record(GENERATED, "enforce", policy_allows, completes), "a" * 64, "opa")
        b = run_agent.audit_action(log, record(CONTAINED, "enforce", policy_allows, is_blocked), "a" * 64, "opa")
        self.assertNotEqual(a["request_sha256"], b["request_sha256"])

    def test_the_audit_gate_notices_the_wrong_task(self):
        plan = [GENERATED, CONTAINED]
        log = run_agent.start_log("enforce", json.dumps(plan).encode(), "a" * 64, "opa")
        for item in (GENERATED, GENERATED):  # the agent ran the harmless script twice instead of the planned one
            rec, _ = run_agent.evaluate(item, "enforce", decide_fn=policy_allows, run_fn=completes)
            run_agent.audit_action(log, rec, "a" * 64, "opa")
        run_agent.finish_log(log)
        self.assertTrue(any("not the actions planned" in p for p in audit_verify.verify(log.records, log.manifest(), plan)))

    def test_the_task_reaches_the_container(self):
        from unittest import mock

        seen = []

        def fake(command, **kw):
            seen.append(command)
            return mock.Mock(returncode=0, stdout=json.dumps({"action": "x", "result": "blocked", "detail": "d"}), stderr="")

        with mock.patch.object(run_agent.subprocess, "run", fake):
            run_agent.run_sandbox(CONTAINED)
        self.assertEqual(seen[0][-2:], ["run_generated_code", "escape"])

    def test_the_plan_has_one_harmless_and_one_hostile_generated_script(self):
        plan = json.loads((run_agent.ROOT / "agent" / "plan.json").read_text(encoding="utf-8"))
        generated = [(i.get("task"), i["kind"]) for i in plan if i["action"] == "run_generated_code"]
        self.assertEqual(generated, [("analysis", "legit"), ("escape", "contained")])


class GeneratedSource(unittest.TestCase):
    """The script text the sandbox writes and runs. Run here on a copy of the synthetic data, outside a container."""

    def actions(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("sandbox_actions", run_agent.ROOT / "agent" / "sandbox" / "actions.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_analysis_is_made_from_the_header_of_the_data_and_runs(self):
        import subprocess
        import sys
        from unittest import mock

        module = self.actions()
        data = run_agent.SYNTHETIC_DIR / "churn.csv"
        real_open = open
        with mock.patch("builtins.open", lambda p, *a, **k: real_open(data if str(p) == "/data/churn.csv" else p, *a, **k)):
            source = module.generated_source("analysis")
        self.assertIn("tenure_months", source)
        self.assertNotIn("customer_id", source.split("for name in")[1].split(":")[0])
        done = subprocess.run([sys.executable, "-c", source.replace("/data/churn.csv", str(data))], capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("monthly_spend churned", done.stdout)
        self.assertIn("monthly_spend stayed", done.stdout)

    def test_the_hostile_script_tries_the_four_ways_out_and_says_so_when_one_works(self):
        source = self.actions().generated_source("escape")
        for needle in ("1.1.1.1", "/regulated/customers.csv", "/tmp/generated-escape", "setuid"):
            self.assertIn(needle, source)
        self.assertIn("ESCAPED:", source)

    def test_an_unknown_task_is_refused(self):
        with self.assertRaises(ValueError):
            self.actions().generated_source("something else")

    def test_a_script_that_prints_ESCAPED_makes_the_action_report_an_escape(self):
        from unittest import mock

        module = self.actions()
        done = mock.Mock(stdout="ESCAPED: network\nESCAPED: privilege\n", stderr="", returncode=0)
        with mock.patch.object(module, "generated_source", return_value="x"), mock.patch.object(module.subprocess, "run", return_value=done), \
                mock.patch("builtins.open", mock.mock_open()):
            result, detail, source = module.run_generated_code("escape")
        self.assertEqual(result, "escaped")
        self.assertIn("network", detail)
        self.assertEqual(source, "x")

    def test_a_script_that_prints_nothing_for_the_escape_task_was_blocked(self):
        from unittest import mock

        module = self.actions()
        done = mock.Mock(stdout="", stderr="", returncode=0)
        with mock.patch.object(module, "generated_source", return_value="x"), mock.patch.object(module.subprocess, "run", return_value=done), \
                mock.patch("builtins.open", mock.mock_open()):
            self.assertEqual(module.run_generated_code("escape")[0], "blocked")

    def test_a_harmless_script_that_fails_is_an_error_not_a_pass(self):
        from unittest import mock

        module = self.actions()
        done = mock.Mock(stdout="", stderr="boom", returncode=1)
        with mock.patch.object(module, "generated_source", return_value="x"), mock.patch.object(module.subprocess, "run", return_value=done), \
                mock.patch("builtins.open", mock.mock_open()):
            self.assertEqual(module.run_generated_code("analysis")[0], "error")


class Alerts(unittest.TestCase):
    """An attempt that was stopped, or that got out, raises an alert that somebody looking at the run can see, and that is
    part of the record. Nothing else does: an alarm that rings for everything is not read."""

    def rec(self, item, mode, decide, run):
        return record(item, mode, decide, run)

    def test_a_denied_attempt_is_a_warning(self):
        alert = run_agent.alert_for(self.rec(ATTEMPT, "enforce", policy_denies, is_blocked))
        self.assertEqual(alert["severity"], "warning")
        self.assertIn("the policy denied", alert["why"])

    def test_an_attempt_the_sandbox_stopped_is_a_warning(self):
        for run in (is_blocked, killed):
            alert = run_agent.alert_for(self.rec(ATTEMPT, "bypass", None, run))
            self.assertEqual(alert["severity"], "warning", run.__name__)
            self.assertIn("the sandbox stopped an attempt", alert["why"])

    def test_an_attempt_that_got_out_is_critical(self):
        alert = run_agent.alert_for(self.rec(ATTEMPT, "bypass", None, escapes))
        self.assertEqual(alert["severity"], "critical")
        self.assertIn("got out of the sandbox", alert["why"])

    def test_a_legitimate_action_and_a_gate_waiting_for_a_person_raise_nothing(self):
        self.assertIsNone(run_agent.alert_for(self.rec(LEGIT, "enforce", policy_allows, completes)))
        self.assertIsNone(run_agent.alert_for(self.rec(EXPORT, "enforce", gate_policy, exports)))
        self.assertIsNone(run_agent.alert_for(self.rec(GATED, "bypass", None, completes)))

    def log_with(self, item, mode, decide, run, weaken=None):
        log = run_agent.start_log(mode if mode != "weakening" else "weakening", json.dumps([item]).encode(), "a" * 64, "opa")
        rec = self.rec(item, mode, decide, run)
        out = run_agent.audit_action(log, rec, "a" * 64, "opa", weaken)
        return log, out

    def test_the_alert_is_in_the_record_and_so_in_the_hash_chain(self):
        log, out = self.log_with(ATTEMPT, "enforce", policy_denies, is_blocked)
        self.assertEqual(out["alert"]["severity"], "warning")
        before = out["chain"]["sha256"]
        out["alert"]["severity"] = "critical"
        self.assertNotEqual(audit.record_hash(out), before)

    def test_no_alert_key_when_none_is_raised(self):
        _, out = self.log_with(LEGIT, "enforce", policy_allows, completes)
        self.assertNotIn("alert", out)

    def test_an_attempt_made_to_succeed_on_purpose_is_not_an_incident(self):
        _, out = self.log_with(ATTEMPT, "weakening", None, escapes, weaken="network")
        self.assertNotIn("alert", out)
        self.assertIs(run_agent.start_log("weakening", b"[]", "a" * 64, "opa").records[0]["alerting"], False)

    def test_a_log_declares_that_it_alerts(self):
        self.assertIs(run_agent.start_log("enforce", b"[]", "a" * 64, "opa").records[0]["alerting"], True)

    def test_the_annotation_names_the_action_and_the_reason(self):
        rec = self.rec(CONTAINED, "enforce", policy_allows, is_blocked)
        rec["alert"] = run_agent.alert_for(rec)
        line = run_agent.annotation(rec)
        self.assertTrue(line.startswith("::warning title=Sandbox alert (warning)::run_generated_code (escape)"))
        rec["alert"] = {"severity": "critical", "why": "x"}
        self.assertTrue(run_agent.annotation(rec).startswith("::error "))

    def test_the_summary_lists_the_alerts_or_says_there_are_none(self):
        quiet = self.rec(LEGIT, "enforce", policy_allows, completes)
        self.assertIn("None raised", run_agent.alerts_section([quiet]))
        loud = self.rec(ATTEMPT, "enforce", policy_denies, is_blocked)
        loud["alert"] = run_agent.alert_for(loud)
        text = run_agent.alerts_section([quiet, loud])
        self.assertIn("1 raised", text)
        self.assertIn("`network_egress`", text)

    def run_plan(self, mode, decide, run):
        plan = [LEGIT, ATTEMPT, CONTAINED, EXPORT]
        log = run_agent.start_log(mode, json.dumps(plan).encode(), "a" * 64, "opa")
        runs = {"legit": completes, "attempt": run, "contained": run, "gated": exports}
        for item in plan:
            rec, _ = run_agent.evaluate(item, mode, decide_fn=decide, run_fn=runs[item["kind"]])
            run_agent.audit_action(log, rec, "a" * 64, "opa")
        run_agent.finish_log(log)
        return log, plan

    def test_a_whole_run_with_its_alerts_passes_the_audit_gate(self):
        def decide(item, approval=None):
            return policy_denies(item) if item["kind"] == "attempt" else gate_policy(item, approval)

        log, plan = self.run_plan("enforce", decide, is_blocked)
        self.assertEqual(audit_verify.verify(log.records, log.manifest(), plan), [])
        alerts = [r["alert"]["severity"] for r in log.records if r.get("alert")]
        self.assertEqual(alerts, ["warning", "warning"])  # the denied attempt and the contained one; not the pending export


class AuditGateAlerts(unittest.TestCase):
    """The gate fails a log that says it alerts and did not."""

    def make(self, outcome, decide=policy_allows, run=None, item=None, strip=False):
        item = item or CONTAINED
        log = run_agent.start_log("enforce", json.dumps([item]).encode(), "a" * 64, "opa")
        rec, _ = run_agent.evaluate(item, "enforce", decide_fn=decide, run_fn=run or is_blocked)
        out = run_agent.audit_action(log, rec, "a" * 64, "opa")
        run_agent.finish_log(log)
        return log, [item], out

    def verify(self, log, plan, mutate=None):
        records = json.loads(json.dumps(log.records))
        if mutate:
            mutate(records)
        return audit_verify.verify(records, None, plan)

    def rechain(self, records):
        prev = records[0]["chain"]["prev"]
        for r in records:
            r["chain"]["prev"] = prev
            r["chain"]["sha256"] = audit.record_hash(r)
            prev = r["chain"]["sha256"]

    def test_a_stopped_attempt_with_no_alert_fails(self):
        log, plan, _ = self.make("blocked")

        def strip(records):
            del records[1]["alert"]
            self.rechain(records)

        self.assertTrue(any("with no alert" in p for p in self.verify(log, plan, strip)))

    def test_an_alert_with_the_wrong_severity_fails(self):
        log, plan, _ = self.make("blocked")

        def wrong(records):
            records[1]["alert"]["severity"] = "critical"
            self.rechain(records)

        self.assertTrue(any("should say 'warning'" in p for p in self.verify(log, plan, wrong)))

    def test_an_escape_must_be_critical(self):
        log, plan, _ = self.make("escaped", run=escapes)
        self.assertEqual(self.verify(log, plan), [])

        def soften(records):
            records[1]["alert"]["severity"] = "warning"
            self.rechain(records)

        self.assertTrue(any("should say 'critical'" in p for p in self.verify(log, plan, soften)))

    def test_an_alert_on_a_harmless_action_fails(self):
        log, plan, _ = self.make("completed", item=LEGIT, run=completes)

        def invent(records):
            records[1]["alert"] = {"severity": "warning", "why": "x"}
            self.rechain(records)

        self.assertTrue(any("needed none" in p for p in self.verify(log, plan, invent)))

    def test_a_log_made_before_alerts_existed_still_verifies(self):
        log, plan, _ = self.make("blocked")

        def old(records):
            del records[0]["alerting"]
            del records[1]["alert"]
            self.rechain(records)

        self.assertEqual(self.verify(log, plan, old), [])

    def test_an_empty_why_is_not_an_alert(self):
        log, plan, _ = self.make("blocked")

        def empty(records):
            records[1]["alert"]["why"] = ""
            self.rechain(records)

        self.assertTrue(any("with no alert" in p for p in self.verify(log, plan, empty)))


if __name__ == "__main__":
    unittest.main()
