"""Tests of the step that reads who approved, from GitHub.

It must fail closed: every doubtful answer is a refusal, and the file is written only for a clear approval.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fetch_approval as fa

ENV = "agent-approval"
JOB = "A person approves the export"


def approval(state="approved", login="jbgs", env=ENV, comment="ok"):
    return {"state": state, "comment": comment, "user": {"login": login, "id": 29926047},
            "environments": [{"id": 1, "name": env, "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"}]}


JOBS = {"jobs": [{"name": "another job", "started_at": "2026-11-17T10:00:00Z"},
                 {"name": JOB, "started_at": "2026-11-17T10:05:09Z"}]}


def http(approvals, jobs=JOBS):
    def fetch(path, token, *a, **k):
        assert token == "t", "the token of the run must be used"
        return approvals if path.endswith("/approvals") else jobs
    return fetch


class Find(unittest.TestCase):
    def test_an_approved_review_of_the_environment_is_an_approval(self):
        self.assertEqual(fa.find_approval([approval()], ENV)["user"]["login"], "jbgs")

    def test_no_review_at_all_means_nobody_approved(self):
        with self.assertRaises(ValueError):
            fa.find_approval([], ENV)

    def test_a_review_of_another_environment_is_not_ours(self):
        with self.assertRaises(ValueError):
            fa.find_approval([approval(env="something-else")], ENV)

    def test_a_rejected_review_is_not_an_approval(self):
        with self.assertRaises(ValueError):
            fa.find_approval([approval(state="rejected")], ENV)

    def test_a_pending_review_is_not_an_approval(self):
        with self.assertRaises(ValueError):
            fa.find_approval([approval(state="pending")], ENV)

    def test_more_than_one_review_is_ambiguous_and_none_is_trusted(self):
        # A re-run keeps the reviews of its earlier attempts, and the API does not say in what order it lists them.
        for history in ([approval(), approval(state="rejected")], [approval(state="rejected"), approval()], [approval(), approval()]):
            with self.subTest(history=[a["state"] for a in history]), self.assertRaises(ValueError) as caught:
                fa.find_approval(history, ENV)
            self.assertIn("ambiguous", str(caught.exception))

    def test_a_review_of_another_environment_does_not_make_ours_ambiguous(self):
        self.assertEqual(fa.find_approval([approval(env="something-else"), approval()], ENV)["state"], "approved")

    def test_an_approval_that_does_not_say_who_is_refused(self):
        bad = approval()
        bad["user"] = {}
        with self.assertRaises(ValueError):
            fa.find_approval([bad], ENV)

    def test_garbage_in_the_history_is_ignored_and_not_a_crash(self):
        self.assertEqual(fa.find_approval(["x", None, 3, approval()], ENV)["state"], "approved")


class Jobs(unittest.TestCase):
    def test_the_time_is_the_start_of_the_job_behind_the_approval(self):
        self.assertEqual(fa.job_started(JOBS, JOB), "2026-11-17T10:05:09Z")

    def test_a_job_that_cannot_be_found_is_refused(self):
        with self.assertRaises(ValueError):
            fa.job_started(JOBS, "no such job")

    def test_a_job_that_has_not_started_is_refused(self):
        with self.assertRaises(ValueError):
            fa.job_started({"jobs": [{"name": JOB, "started_at": None}]}, JOB)


class Build(unittest.TestCase):
    def test_the_approval_names_one_action_and_says_where_it_came_from(self):
        result = fa.build("export_result", ENV, "55", approval(), "2026-11-17T10:05:09Z")
        self.assertEqual(result["action"], "export_result")
        self.assertEqual(result["approver"], "jbgs")
        self.assertIs(result["approved"], True)
        self.assertEqual(result["source"], f"github-environment:{ENV}")
        self.assertIn("actions/runs/55", result["evidence"])
        self.assertEqual(result["decided_at"], "2026-11-17T10:05:09Z")

    def test_a_long_comment_is_cut(self):
        self.assertLessEqual(len(fa.build("a", ENV, "1", approval(comment="x" * 5000), "t")["comment"]), 200)


class Main(unittest.TestCase):
    def run_main(self, fetch, env=None):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "a" / "approval.json"
            base = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "GITHUB_RUN_ID": "55"}
            with mock.patch.dict(os.environ, base if env is None else env, clear=True):
                code = fa.main(["--action", "export_result", "--environment", ENV, "--job-name", JOB, "--out", str(out)], fetch)
            return code, (json.loads(out.read_text()) if out.exists() else None)

    def test_a_clear_approval_writes_the_file(self):
        code, written = self.run_main(http([approval()]))
        self.assertEqual(code, 0)
        self.assertEqual(written["approver"], "jbgs")

    def test_no_approval_writes_nothing_and_fails(self):
        code, written = self.run_main(http([]))
        self.assertEqual(code, 1)
        self.assertIsNone(written)

    def test_a_rejection_writes_nothing_and_fails(self):
        code, written = self.run_main(http([approval(state="rejected")]))
        self.assertEqual((code, written), (1, None))

    def test_an_environment_without_required_reviewers_fails_closed(self):
        # With no required reviewers the job runs without anyone approving; GitHub then has no review to show.
        code, written = self.run_main(http([]))
        self.assertEqual((code, written), (1, None))

    def test_a_missing_token_fails(self):
        code, written = self.run_main(http([approval()]), env={})
        self.assertEqual((code, written), (1, None))

    def test_a_network_failure_fails_closed(self):
        import urllib.error

        def broken(path, token, *a, **k):
            raise urllib.error.URLError("no route")
        self.assertEqual(self.run_main(broken), (1, None))

    def test_the_token_of_the_run_is_used_to_ask(self):
        calls = []

        def fetch(path, token, *a, **k):
            calls.append((path, token))
            return [approval()] if path.endswith("/approvals") else JOBS
        self.run_main(fetch)
        self.assertEqual([p for p, _ in calls], ["/repos/o/r/actions/runs/55/approvals", "/repos/o/r/actions/runs/55/jobs"])


if __name__ == "__main__":
    unittest.main()
