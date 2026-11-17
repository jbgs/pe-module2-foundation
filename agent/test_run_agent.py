"""Tests of the enforcement point. They need neither Docker nor the policy engine.

A check that has never failed proves little, so most of these tests are about the judge saying "no": an attempt
that gets out, a legitimate action that does not complete, a policy that lets an attempt through, a canary that
leaks. They also run the real policy decisions through a stub that follows the policy's rules.
"""

import unittest

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
        self.assertTrue({"legit", "attempt", "gated-only"} >= {item["kind"] for item in plan})


if __name__ == "__main__":
    unittest.main()
