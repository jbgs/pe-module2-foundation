"""Tests of the publishing of the audit logs, against a stand-in for the store that behaves as the real one does.

The stand-in refuses what the real bucket refuses: a write without the condition, a write to a name that is taken, a
write outside the prefix, and, for the writer, everything but writing. A permissive stand-in is also used, to show
that the check on the store can fail: a check that never fails proves nothing.
"""

import base64
import hashlib
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import audit
import audit_verify
import publish_audit as pa
import test_audit as T

BUCKET = "pe-lab-audit-123456789012"


def parse(tokens):
    flags, positional, i = {}, [], 0
    while i < len(tokens):
        token = tokens[i]
        if token.startswith("--"):
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
                flags[token] = tokens[i + 1]
                i += 2
            else:
                flags[token] = True
                i += 1
        else:
            positional.append(token)
            i += 1
    return flags, positional


class FakeS3:
    """What the real store does, for the identity that writes and for one that may read."""

    def __init__(self, role="writer", strict=True):
        self.objects, self.commands, self.role, self.strict, self._version = {}, [], role, strict, 0
        self.sent = []  # (key, the checksum sent, the bytes sent), as S3 would see them

    def run(self, command, **kwargs):
        self.commands.append(command)
        operation, (flags, positional) = command[2], parse(command[3:])
        key = flags.get("--key")
        denied = lambda code: SimpleNamespace(
            returncode=254, stdout="", stderr=f"\nAn error occurred ({code}) when calling the {operation} operation: x\n")
        ok = lambda out="": SimpleNamespace(returncode=0, stdout=out, stderr="")
        if operation == "put-object-retention":
            # The real store checks the request before it checks the permission: a date in the past is
            # InvalidArgument, which tests nothing about who may change a retention. Seen in the first real run.
            until = re.search(r"RetainUntilDate=([^,]+)", flags.get("--retention", ""))
            if not until or datetime.strptime(until.group(1), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
                return denied("InvalidArgument")
        if not self.strict:
            return self.permissive(operation, flags, positional)
        if operation == "put-object":
            if "--if-none-match" not in flags:
                return denied("AccessDenied")
            if self.role == "writer" and not key.startswith(pa.PREFIX):
                return denied("AccessDenied")
            if key in self.objects:
                return denied("PreconditionFailed")
            body = Path(flags["--body"]).read_bytes()
            self.sent.append((key, flags.get("--checksum-sha256"), body))
            if "--checksum-sha256" in flags and flags["--checksum-sha256"] != base64.b64encode(hashlib.sha256(body).digest()).decode():
                return denied("BadDigest")
            self._version += 1
            self.objects[key] = body
            return ok(json.dumps({"VersionId": f"v{self._version}"}))
        if self.role == "writer":
            return denied("AccessDenied")
        if operation == "get-object":
            if key not in self.objects:
                return denied("NoSuchKey")
            Path(positional[-1]).write_bytes(self.objects[key])
            return ok("{}")
        if operation == "head-object":
            return ok("{}") if key in self.objects else denied("404")
        return denied("AccessDenied")  # a locked version: delete and retention changes are refused

    def permissive(self, operation, flags, positional):
        if operation == "put-object":
            self.objects[flags["--key"]] = Path(flags["--body"]).read_bytes()
            return SimpleNamespace(returncode=0, stdout=json.dumps({"VersionId": "v1"}), stderr="")
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")


def make_out(tmp, controls=False):
    """Three logs on disk. With controls=True the log of the controls follows the plan that the code expects."""
    import run_agent

    out = Path(tmp) / "out"
    out.mkdir()
    for mode in pa.MODES:
        if mode == "weakening" and controls:
            items = [{"action": a, "kind": "attempt"} for _, a in run_agent.CONTROLS]
            log = T.build(mode, items)
        else:
            log = T.build(mode)
        (out / f"audit-{mode}.jsonl").write_text(log.text(), encoding="utf-8")
        (out / f"audit-{mode}.manifest.json").write_text(json.dumps(log.manifest()), encoding="utf-8")
    return out


class Keys(unittest.TestCase):
    def test_the_names_of_the_objects(self):
        self.assertEqual(pa.run_key("100-1", "enforce", "audit.jsonl"), "agent-runs/100-1/enforce/audit.jsonl")
        self.assertEqual(pa.head_key("ab" * 32), "agent-runs/heads/" + "ab" * 32 + ".json")

    def test_the_bucket_is_named_from_the_account_and_can_be_overridden(self):
        self.assertEqual(pa.bucket_name({"AWS_ACCOUNT_ID": "123456789012"}), BUCKET)
        self.assertEqual(pa.bucket_name({"AWS_ACCOUNT_ID": "1", "AUDIT_BUCKET": "other"}), "other")

    def test_no_bucket_and_no_account_is_refused(self):
        with self.assertRaises(SystemExit):
            pa.bucket_name({})

    def test_the_checksum_is_the_base64_of_the_sha256(self):
        self.assertEqual(pa.checksum_b64(b"abc"), base64.b64encode(hashlib.sha256(b"abc").digest()).decode())

    def test_an_error_code_is_read_from_the_message(self):
        self.assertEqual(pa.error_code("\nAn error occurred (AccessDenied) when calling the PutObject operation: x"), "AccessDenied")
        self.assertIsNone(pa.error_code("something else"))


class Publish(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = make_out(self.tmp.name)
        self.s3 = FakeS3("writer")

    def tearDown(self):
        self.tmp.cleanup()

    def publish(self):
        return pa.publish("100-1", self.out, BUCKET, self.s3.run)

    def test_three_objects_are_written_for_each_of_the_three_logs(self):
        results = self.publish()
        self.assertEqual(len(results), 9)
        self.assertTrue(pa.publish_ok(results))
        self.assertEqual(len(self.s3.objects), 9)

    def test_the_log_and_the_manifest_are_stored_as_written(self):
        self.publish()
        for mode in pa.MODES:
            self.assertEqual(self.s3.objects[pa.run_key("100-1", mode, "audit.jsonl")], (self.out / f"audit-{mode}.jsonl").read_bytes())

    def test_every_head_pointer_is_named_after_its_own_head_hash(self):
        self.publish()
        for mode in pa.MODES:
            head = json.loads((self.out / f"audit-{mode}.manifest.json").read_text())["head_sha256"]
            pointer = json.loads(self.s3.objects[pa.head_key(head)])
            self.assertEqual(pointer["head_sha256"], head)
            self.assertEqual(pointer["log_key"], pa.run_key("100-1", mode, "audit.jsonl"))

    def test_every_write_is_conditional_and_carries_the_checksum_of_what_was_sent(self):
        self.publish()
        puts = [c for c in self.s3.commands if c[2] == "put-object"]
        self.assertEqual(len(puts), 9)
        for command in puts:
            flags, _ = parse(command[3:])
            self.assertEqual(flags["--if-none-match"], "*")
        self.assertEqual(len(self.s3.sent), 9)
        for key, checksum, body in self.s3.sent:
            # measured against the bytes the store received, which the pointer files (deleted afterwards) cannot dodge
            self.assertEqual(checksum, pa.checksum_b64(body), key)

    def test_the_checksum_sent_is_that_of_the_file(self):
        path = self.out / "audit-enforce.jsonl"
        pa.put_once(BUCKET, "agent-runs/x", path, self.s3.run)
        flags, _ = parse(self.s3.commands[-1][3:])
        self.assertEqual(flags["--checksum-sha256"], pa.checksum_b64(path.read_bytes()))

    def test_publishing_the_same_run_twice_is_refused_and_replaces_nothing(self):
        self.publish()
        before = dict(self.s3.objects)
        second = self.publish()
        self.assertFalse(pa.publish_ok(second))
        self.assertTrue(all(r["error"] == "PreconditionFailed" for r in second))
        self.assertEqual(self.s3.objects, before)

    def test_a_name_taken_first_is_refused_loudly_and_left_alone(self):
        taken = pa.run_key("100-1", "enforce", "audit.jsonl")
        self.s3.objects[taken] = b"a forged log, written first"
        results = self.publish()
        self.assertFalse(pa.publish_ok(results))
        failed = [r for r in results if not r["ok"]]
        self.assertEqual([r["key"] for r in failed], [taken])
        self.assertEqual(failed[0]["error"], "PreconditionFailed")
        self.assertEqual(self.s3.objects[taken], b"a forged log, written first")

    def test_a_head_that_was_already_recorded_is_not_a_failure(self):
        # A retry of the job reuses the artifact, so the pointer (named after the head hash) already exists.
        self.publish()
        self.s3b = FakeS3("writer")
        head = json.loads((self.out / "audit-enforce.manifest.json").read_text())["head_sha256"]
        self.s3b.objects[pa.head_key(head)] = b"a pointer written by an earlier attempt"
        results = pa.publish("100-2", self.out, BUCKET, self.s3b.run)
        self.assertTrue(pa.publish_ok(results))
        pointer = next(r for r in results if r["key"] == pa.head_key(head))
        self.assertEqual(pointer["note"], "already recorded")
        self.assertEqual(self.s3b.objects[pa.head_key(head)], b"a pointer written by an earlier attempt")

    def test_a_log_that_already_exists_is_still_a_failure_on_retry(self):
        self.publish()
        self.assertFalse(pa.publish_ok(self.publish()))

    def test_the_summary_says_when_a_head_was_already_recorded(self):
        text = pa.summary([{"key": "k", "ok": True, "note": "already recorded", "error": "PreconditionFailed",
                            "version_id": None, "checksum": "abcdefghijklmnop"}], [])
        self.assertIn("already recorded", text)

    def test_the_summary_never_names_the_bucket(self):
        text = pa.summary(self.publish(), pa.refusals(BUCKET, pa.run_key("100-1", "enforce", "audit.jsonl"), "v1", self.s3.run))
        self.assertNotIn("123456789012", text)
        self.assertNotIn("pe-lab-audit-", text)


class Refusals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = make_out(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_store_that_behaves_refuses_every_attempt_with_the_right_error(self):
        s3 = FakeS3("writer")
        results = pa.publish("100-1", self.out, BUCKET, s3.run)
        key = results[0]["key"]
        checks = pa.refusals(BUCKET, key, results[0]["version_id"], s3.run)
        self.assertEqual(len(checks), 7)
        self.assertTrue(all(c["ok"] for c in checks), [c for c in checks if not c["ok"]])

    def test_a_permissive_store_is_caught(self):
        # The negative control: a store that lets the writer change records must make this check fail.
        s3 = FakeS3("writer", strict=False)
        checks = pa.refusals(BUCKET, "agent-runs/x", "v1", s3.run)
        self.assertTrue(any(not c["ok"] for c in checks))
        self.assertTrue(all(c["got"] == "ACCEPTED" for c in checks))

    def test_the_attempt_to_shorten_the_retention_asks_for_a_date_in_the_future(self):
        s3 = FakeS3("writer")
        pa.refusals(BUCKET, "agent-runs/x", "v1", s3.run)
        command = next(c for c in s3.commands if c[2] == "put-object-retention")
        flags, _ = parse(command[3:])
        until = re.search(r"RetainUntilDate=([^,]+)", flags["--retention"]).group(1)
        self.assertGreater(datetime.strptime(until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc), datetime.now(timezone.utc))

    def test_a_store_that_fails_for_another_reason_is_not_a_refusal(self):
        broken = lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="", stderr="An error occurred (InternalError) x")
        checks = pa.refusals(BUCKET, "agent-runs/x", "v1", broken)
        self.assertTrue(all(not c["ok"] for c in checks))

    def test_a_write_to_an_existing_name_is_the_one_that_must_say_precondition_failed(self):
        s3 = FakeS3("writer")
        results = pa.publish("100-1", self.out, BUCKET, s3.run)
        checks = pa.refusals(BUCKET, results[0]["key"], results[0]["version_id"], s3.run)
        self.assertEqual(checks[0]["expected"], "PreconditionFailed")
        self.assertEqual(checks[0]["got"], "PreconditionFailed")


class WriteOnce(unittest.TestCase):
    """The rule that a name is written once holds for the manifest and the pointer, not only for the log."""

    def test_every_kind_of_object_refuses_a_second_write(self):
        s3 = FakeS3("writer")
        with tempfile.TemporaryDirectory() as tmp:
            out = make_out(tmp)
            results = pa.publish("100-1", out, BUCKET, s3.run)
            head = json.loads((out / "audit-enforce.manifest.json").read_text())["head_sha256"]
        keys = [("manifest", pa.run_key("100-1", "enforce", "manifest.json")), ("head pointer", pa.head_key(head))]
        checks = pa.write_once_checks(BUCKET, keys, s3.run)
        self.assertTrue(pa.publish_ok(results))
        self.assertEqual([c["ok"] for c in checks], [True, True])

    def test_a_store_that_lets_a_manifest_be_replaced_is_caught(self):
        checks = pa.write_once_checks(BUCKET, [("manifest", "agent-runs/x")], FakeS3("writer", strict=False).run)
        self.assertFalse(checks[0]["ok"])
        self.assertEqual(checks[0]["got"], "ACCEPTED")


class Controls(unittest.TestCase):
    def test_the_expectation_for_the_controls_comes_from_the_code(self):
        import run_agent

        self.assertEqual(pa.controls_plan(), [{"action": a} for _, a in run_agent.CONTROLS])

    def test_reading_back_checks_the_controls_log_against_that_expectation(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = make_out(tmp)
            writer = FakeS3("writer")
            pa.publish("100-1", out, BUCKET, writer.run)
            reader = FakeS3("admin")
            reader.objects = writer.objects
            # make_out builds the weakening log from the sample plan, not from the controls, so the store's copy
            # does not match what the code expects of a log of the controls: the gate must say so
            problems = pa.verify_store("100-1", BUCKET, T.PLAN, reader.run)
        self.assertTrue(any(p.startswith("weakening:") and "not the actions planned" in p for p in problems))


class Verify(unittest.TestCase):
    """Reading the logs back, with an identity that may read, and running the audit gate on them."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = make_out(self.tmp.name, controls=True)
        self.writer = FakeS3("writer")
        pa.publish("100-1", self.out, BUCKET, self.writer.run)
        self.reader = FakeS3("admin")
        self.reader.objects = self.writer.objects

    def tearDown(self):
        self.tmp.cleanup()

    def test_what_was_published_passes_the_gate_when_read_back(self):
        self.assertEqual(pa.verify_store("100-1", BUCKET, T.PLAN, self.reader.run), [])

    def test_a_log_altered_in_the_store_is_caught(self):
        key = pa.run_key("100-1", "enforce", "audit.jsonl")
        self.reader.objects[key] = self.reader.objects[key].replace(b'"outcome": "completed"', b'"outcome": "blocked"', 1)
        self.assertTrue(pa.verify_store("100-1", BUCKET, T.PLAN, self.reader.run))

    def test_a_missing_head_pointer_is_caught(self):
        head = json.loads((self.out / "audit-bypass.manifest.json").read_text())["head_sha256"]
        del self.reader.objects[pa.head_key(head)]
        problems = pa.verify_store("100-1", BUCKET, T.PLAN, self.reader.run)
        self.assertTrue(any("head pointer is missing" in p for p in problems))

    def test_an_identity_that_cannot_read_gets_a_reason_and_not_a_pass(self):
        problems = pa.verify_store("100-1", BUCKET, T.PLAN, self.writer.run)
        self.assertTrue(any("cannot read" in p for p in problems))

    def test_a_run_that_was_never_published_is_not_verified(self):
        self.assertTrue(pa.verify_store("999-1", BUCKET, T.PLAN, self.reader.run))


class Entries(unittest.TestCase):
    """A run that leaves two logs of the same mode: the request (its gate pending) and the run after the approval."""

    def make(self, tmp, name):
        directory = Path(tmp) / name
        directory.mkdir()
        log = T.build("enforce")
        (directory / "audit-enforce.jsonl").write_text(log.text(), encoding="utf-8")
        (directory / "audit-enforce.manifest.json").write_text(json.dumps(log.manifest()), encoding="utf-8")
        return directory

    def test_the_entry_syntax(self):
        self.assertEqual(pa.parse_entry("approved=agent/out-approved:enforce", True), ("approved", Path("agent/out-approved"), "enforce"))
        self.assertEqual(pa.parse_entry("approved:enforce", False), ("approved", "enforce"))

    def test_a_malformed_entry_is_refused(self):
        for text, with_dir in (("nonsense", True), ("a=b", True), ("nonsense", False)):
            with self.subTest(text), self.assertRaises(SystemExit):
                pa.parse_entry(text, with_dir)

    def test_two_logs_of_the_same_mode_are_stored_under_their_own_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            request, approved = self.make(tmp, "request"), self.make(tmp, "approved")
            s3 = FakeS3("writer")
            results = pa.publish("200-1", request, BUCKET, s3.run,
                                 entries=[("request", request, "enforce"), ("approved", approved, "enforce")])
        keys = {r["key"] for r in results if "heads/" not in r["key"]}
        self.assertEqual(keys, {pa.run_key("200-1", label, n) for label in ("request", "approved") for n in ("audit.jsonl", "manifest.json")})

    def test_the_pointer_says_under_which_name_the_log_is_stored(self):
        with tempfile.TemporaryDirectory() as tmp:
            approved = self.make(tmp, "approved")
            s3 = FakeS3("writer")
            pa.publish("200-1", approved, BUCKET, s3.run, entries=[("approved", approved, "enforce")])
        pointers = [json.loads(v) for k, v in s3.objects.items() if "heads/" in k]
        self.assertEqual([p["label"] for p in pointers], ["approved"])
        self.assertEqual(pointers[0]["log_key"], pa.run_key("200-1", "approved", "audit.jsonl"))

    def test_reading_back_the_named_logs_passes_the_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            request, approved = self.make(tmp, "request"), self.make(tmp, "approved")
            writer = FakeS3("writer")
            pa.publish("200-1", request, BUCKET, writer.run, entries=[("request", request, "enforce"), ("approved", approved, "enforce")])
        reader = FakeS3("admin")
        reader.objects = writer.objects
        self.assertEqual(pa.verify_store("200-1", BUCKET, T.PLAN, reader.run, entries=[("request", "enforce"), ("approved", "enforce")]), [])

    def test_a_named_log_that_is_missing_is_reported_under_its_name(self):
        reader = FakeS3("admin")
        problems = pa.verify_store("200-1", BUCKET, T.PLAN, reader.run, entries=[("approved", "enforce")])
        self.assertTrue(any(p.startswith("approved:") and "cannot read" in p for p in problems))


if __name__ == "__main__":
    unittest.main()
