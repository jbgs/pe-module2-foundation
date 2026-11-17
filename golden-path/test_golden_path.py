"""Tests of the golden path.

The path is only worth something if it refuses what it must: a road without the compliant defaults, an intent it cannot
match, an environment that already exists, regulated data anywhere near an environment. So most of these tests are about
the refusals, and about the record the path keeps of what it was asked for.
"""

import copy
import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import golden_path as gp

NOW = datetime(2026, 11, 17, 12, 0, 0, tzinfo=timezone.utc)
SANDBOX_INTENT = "I need a sandbox for an agent to analyse churn data"
SERVICE_INTENT = "I need a dev environment for the service on AWS"


def args(**kw):
    base = dict(intent=SANDBOX_INTENT, dest="", name=None, usage="", source="cli", dry_run=False, yes=False, running=False)
    base.update(kw)
    return SimpleNamespace(**base)


class Roads(unittest.TestCase):
    def setUp(self):
        self.roads = gp.load_roads()

    def test_both_paved_roads_are_there_and_carry_the_defaults(self):
        self.assertEqual(sorted(self.roads), ["agent-sandbox", "service-dev"])
        for name, road in self.roads.items():
            with self.subTest(name):
                self.assertEqual(gp.check_road(road), [])

    def test_the_sandbox_road_is_contained_by_default(self):
        d = self.roads["agent-sandbox"]["defaults"]
        self.assertEqual((d["network"], d["root_filesystem"], d["capabilities"], d["data"]),
                         ("none", "read-only", "none", "synthetic only"))

    def test_a_road_that_gives_up_a_default_is_refused(self):
        for key in ("network", "root_filesystem", "capabilities", "data"):
            with self.subTest(key):
                road = copy.deepcopy(self.roads["agent-sandbox"])
                road["defaults"][key] = "open"
                self.assertTrue(any(key in p for p in gp.check_road(road)))

    def test_a_road_that_does_not_state_its_audit_or_policy_is_refused(self):
        for key in ("policy", "audit"):
            road = copy.deepcopy(self.roads["agent-sandbox"])
            del road["defaults"][key]
            self.assertTrue(any(key in p for p in gp.check_road(road)), key)
        for key in ("network_exposure", "rollback", "state", "size", "audit"):
            road = copy.deepcopy(self.roads["service-dev"])
            del road["defaults"][key]
            self.assertTrue(any(key in p for p in gp.check_road(road)), key)

    def test_a_road_with_a_missing_part_is_refused(self):
        for key in gp.REQUIRED_ROAD_KEYS:
            road = copy.deepcopy(self.roads["agent-sandbox"])
            del road[key]
            self.assertTrue(gp.check_road(road), key)

    def test_a_road_of_an_unknown_kind_is_refused(self):
        road = copy.deepcopy(self.roads["agent-sandbox"])
        road["kind"] = "magic"
        self.assertTrue(gp.check_road(road))

    def test_a_road_that_starts_a_workflow_must_name_it(self):
        road = copy.deepcopy(self.roads["service-dev"])
        del road["workflow"]
        self.assertTrue(any("workflow" in p for p in gp.check_road(road)))

    def test_a_road_whose_folder_does_not_match_its_name_is_refused(self):
        road = copy.deepcopy(self.roads["agent-sandbox"])
        road["_dir"] = "somewhere-else"
        self.assertTrue(any("does not match" in p for p in gp.check_road(road)))

    def test_a_keyword_needs_a_positive_whole_weight(self):
        for bad in (0, -1, 1.5, "3"):
            road = copy.deepcopy(self.roads["agent-sandbox"])
            road["keywords"]["x"] = bad
            self.assertTrue(gp.check_road(road), bad)

    def test_the_service_road_leaves_the_size_at_zero_by_default(self):
        self.assertIn("zero tasks", self.roads["service-dev"]["defaults"]["size"])
        self.assertEqual(gp.dispatch_command(self.roads["service-dev"], running=False)[-1], "desired_count=0")
        self.assertEqual(gp.dispatch_command(self.roads["service-dev"], running=True)[-1], "desired_count=1")


class Matching(unittest.TestCase):
    def setUp(self):
        self.roads = gp.load_roads()

    def road(self, intent):
        return gp.choose(intent, self.roads)["road"]

    def test_a_sandbox_request_gets_the_sandbox(self):
        for intent in (SANDBOX_INTENT, "an isolated sandbox for agents with fake data", "Sandbox for my AGENT"):
            self.assertEqual(self.road(intent), "agent-sandbox", intent)

    def test_a_service_request_gets_the_service_environment(self):
        for intent in (SERVICE_INTENT, "deploy the service to a dev environment on aws", "a development environment on ECS"):
            self.assertEqual(self.road(intent), "service-dev", intent)

    def test_what_no_road_covers_is_not_covered(self):
        for intent in ("order me a pizza", "a kubernetes cluster with a service mesh", "", "   ", "data"):
            result = gp.choose(intent, self.roads)
            self.assertIsNone(result["road"], intent)
            self.assertEqual(result["reason"], "not_covered")

    def test_a_request_that_two_roads_cover_equally_is_ambiguous(self):
        both = "a sandbox agent environment dev service"
        result = gp.choose(both, self.roads)
        self.assertIsNone(result["road"])
        self.assertEqual(result["reason"], "ambiguous")

    def test_matching_is_by_whole_words(self):
        self.assertIsNone(gp.choose("agentless sandboxed devils", self.roads)["road"])

    def test_the_answer_says_what_matched(self):
        result = gp.choose(SANDBOX_INTENT, self.roads)
        self.assertIn("sandbox", result["matched"])
        self.assertGreaterEqual(result["scores"]["agent-sandbox"], gp.MIN_SCORE)

    def test_a_single_weak_word_is_not_enough(self):
        self.assertIsNone(gp.choose("churn", self.roads)["road"])


class Environment(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name)
        self.road = gp.load_roads()["agent-sandbox"]

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, **kw):
        return gp.create_local(self.road, kw.pop("intent", SANDBOX_INTENT), self.dest, kw.pop("name", None), NOW, "jbgs")

    def test_an_environment_is_made_with_what_an_agent_needs(self):
        record = self.make()
        env = self.dest / record["id"]
        for relative in ("data/churn.csv", "plan.json", "policy/agent.rego", "README.md", "environment.json"):
            self.assertTrue((env / relative).exists(), relative)

    def test_the_data_is_the_synthetic_data_and_nothing_else(self):
        record = self.make()
        copied = sorted(p.name for p in (self.dest / record["id"] / "data").iterdir())
        self.assertEqual(copied, sorted(p.name for p in gp.synthetic_files()))
        for name in copied:
            self.assertEqual((self.dest / record["id"] / "data" / name).read_bytes(), (gp.ROOT / "agent" / "synthetic" / name).read_bytes())

    def test_regulated_data_is_never_in_an_environment(self):
        record = self.make()
        canary = re.search(r"CANARY-[0-9a-f]{16}", (gp.ROOT / "agent" / "regulated-standin" / "customers.csv").read_text()).group(0)
        for path in (self.dest / record["id"]).rglob("*"):
            if path.is_file():
                self.assertNotIn("customers", path.name)
                self.assertNotIn(canary, path.read_text(encoding="utf-8", errors="ignore"), str(path))

    def test_regulated_data_among_the_files_to_copy_is_refused_even_if_something_put_it_there(self):
        from unittest import mock

        regulated = gp.ROOT / "agent" / "regulated-standin" / "customers.csv"
        with mock.patch.object(gp, "synthetic_files", return_value=[regulated]):
            with self.assertRaises(gp.Refused) as caught:
                self.make()
        self.assertIn("regulated", str(caught.exception))
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_the_environment_says_what_it_is_and_what_it_comes_with(self):
        record = self.make()
        on_disk = json.loads((self.dest / record["id"] / "environment.json").read_text())
        self.assertEqual(on_disk, record)
        self.assertEqual(record["road"], "agent-sandbox")
        self.assertEqual(record["created_by"], "jbgs")
        self.assertEqual(record["defaults"]["network"], "none")
        self.assertRegex(record["policy_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(record["template_sha256"], r"^[0-9a-f]{64}$")

    def test_the_policy_hash_is_that_of_the_policy_that_was_copied(self):
        record = self.make()
        copied = (self.dest / record["id"] / "policy" / "agent.rego").read_bytes()
        self.assertEqual(record["policy_sha256"], gp.audit.sha256_hex(copied))
        self.assertEqual(copied, (gp.ROOT / "policy" / "agent.rego").read_bytes())

    def test_the_same_request_makes_the_same_template(self):
        first = self.make(name="a")
        second = self.make(name="b")
        self.assertEqual(first["policy_sha256"], second["policy_sha256"])

    def test_an_environment_that_exists_is_never_overwritten(self):
        record = self.make()
        (self.dest / record["id"] / "marker").write_text("mine")
        with self.assertRaises(gp.Refused):
            self.make()
        self.assertEqual((self.dest / record["id"] / "marker").read_text(), "mine")

    def test_the_id_is_made_from_the_road_the_time_and_the_request(self):
        self.assertRegex(self.make()["id"], r"^agent-sandbox-20261117-120000-[0-9a-f]{8}$")

    def test_a_name_that_is_not_usable_is_refused(self):
        for bad in ("../escape", "A Capital", "with space", "-dash", "a/b"):
            with self.subTest(bad), self.assertRaises(gp.Refused):
                gp.create_local(self.road, SANDBOX_INTENT, self.dest, bad, NOW, "x")

    def test_a_part_of_a_word_is_not_regulated_data(self):
        for name in ("regulated", "my-customers", "Customers.csv"):
            self.assertTrue(gp.looks_regulated(name), name)
        for name in ("unregulated", "deregulated", "customer", "churn.csv"):
            self.assertFalse(gp.looks_regulated(name), name)

    def test_without_a_name_one_is_made_and_never_an_empty_one(self):
        self.assertTrue(self.make(name=None)["id"])

    def test_the_environment_can_be_verified_and_a_change_is_seen(self):
        record = self.make()
        env = self.dest / record["id"]
        self.assertEqual(gp.environment.verify(env, record["id"]), [])
        self.assertEqual(gp.environment.template_of(env), record["template_sha256"])
        (env / "data" / "churn.csv").write_text("changed")
        self.assertTrue(gp.environment.verify(env, record["id"]))

    def test_the_plan_and_readme_may_change_without_breaking_the_environment(self):
        record = self.make()
        env = self.dest / record["id"]
        (env / "plan.json").write_text("[]")
        (env / "README.md").write_text("notes")
        self.assertEqual(gp.environment.verify(env, record["id"]), [])

    def test_the_hash_of_the_template_is_the_one_the_enforcement_point_computes(self):
        record = self.make()
        files = gp.environment.read_files(self.dest / record["id"])
        self.assertEqual(gp.environment.template_sha256(files), record["template_sha256"])

    def test_what_looks_like_a_secret_is_not_kept_in_the_record_or_the_readme(self):
        intent = SANDBOX_INTENT + " key sk-ant-abc123DEF and github_pat_ABCDEF123 mail ana@example.com acct 123456789012"
        record = self.make(intent=intent)
        env = self.dest / record["id"]
        kept = record["intent"] + (env / "README.md").read_text() + (env / "environment.json").read_text()
        for leaked in ("sk-ant-abc123DEF", "github_pat_ABCDEF123", "ana@example.com", "123456789012"):
            self.assertNotIn(leaked, kept)
        self.assertIn("[redacted]", record["intent"])

    def test_redaction_keeps_an_ordinary_request_and_limits_its_length(self):
        self.assertEqual(gp.redact(SANDBOX_INTENT), SANDBOX_INTENT)
        self.assertEqual(len(gp.redact("a" * 500)), 200)

    def test_nothing_is_made_next_to_regulated_data(self):
        with self.assertRaises(gp.Refused):
            gp.create_local(self.road, SANDBOX_INTENT, self.dest / "regulated-stuff", "ok", NOW, "x")

    def test_the_readme_has_the_command_that_runs_an_agent_in_it(self):
        record = self.make()
        text = (self.dest / record["id"] / "README.md").read_text()
        self.assertIn(f"--environment {record['id']}", text)
        self.assertIn("--data", text)
        self.assertIn("--policy-dir", text)
        self.assertIn("**network**: none", text)

    def test_a_long_request_is_cut_in_the_record(self):
        self.assertLessEqual(len(self.make(intent="x " * 500)["intent"]), 200)


class UsageLogging(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "u" / "usage.jsonl"
        self.log = gp.UsageLog(self.path, lambda: NOW)

    def tearDown(self):
        self.tmp.cleanup()

    def fill(self, n=4):
        for i in range(n):
            self.log.append("environment_created", id=f"e{i}", road="agent-sandbox", duration_ms=10 + i)

    def test_records_are_chained_and_verify(self):
        self.fill()
        self.assertEqual(gp.UsageLog.verify(self.path), [])
        self.assertEqual([r["seq"] for r in gp.UsageLog.load(self.path)], [0, 1, 2, 3])

    def test_a_new_instance_carries_on_the_same_chain(self):
        self.fill(2)
        gp.UsageLog(self.path, lambda: NOW).append("intent_not_covered", intent="x")
        self.assertEqual(gp.UsageLog.verify(self.path), [])
        self.assertEqual(len(gp.UsageLog.load(self.path)), 3)

    def edit(self, change):
        records = gp.UsageLog.load(self.path)
        change(records)
        self.path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records), encoding="utf-8")

    def test_an_altered_record_is_detected(self):
        self.fill()
        self.edit(lambda r: r[1].update(duration_ms=1))
        self.assertTrue(any("altered" in p for p in gp.UsageLog.verify(self.path)))

    def test_a_removed_record_is_detected(self):
        self.fill()
        self.edit(lambda r: r.pop(1))
        self.assertTrue(gp.UsageLog.verify(self.path))

    def test_reordered_records_are_detected(self):
        self.fill()
        self.edit(lambda r: r.insert(1, r.pop(2)))
        self.assertTrue(gp.UsageLog.verify(self.path))

    def rechain(self, records, keep_seq=True):
        """What a forger who rewrites the whole log does: recompute the hash of every record."""
        prev = gp.GENESIS
        for index, rec in enumerate(records):
            if not keep_seq:
                rec["seq"] = index
            rec["prev"] = prev
            rec["sha256"] = gp.audit.sha256_hex(gp.audit.canonical({k: v for k, v in rec.items() if k != "sha256"}))
            prev = rec["sha256"]

    def test_a_record_removed_with_every_hash_recomputed_is_caught_by_the_numbering(self):
        # Consistent hashes everywhere: only the numbering shows that a record is missing.
        self.fill()
        self.edit(lambda r: (r.pop(1), self.rechain(r)))
        self.assertTrue(any("removed, added or moved" in p for p in gp.UsageLog.verify(self.path)))

    def test_a_record_that_does_not_follow_the_one_before_is_caught_even_if_its_own_hash_is_right(self):
        self.fill()

        def forge(records):
            records[2]["prev"] = "0" * 64
            records[2]["sha256"] = gp.audit.sha256_hex(gp.audit.canonical({k: v for k, v in records[2].items() if k != "sha256"}))
            # the records after it are fixed too, so only the broken link itself remains
            prev = records[2]["sha256"]
            for rec in records[3:]:
                rec["prev"] = prev
                rec["sha256"] = gp.audit.sha256_hex(gp.audit.canonical({k: v for k, v in rec.items() if k != "sha256"}))
                prev = rec["sha256"]

        self.edit(forge)
        self.assertTrue(any("chain is broken" in p for p in gp.UsageLog.verify(self.path)))

    def test_a_log_that_cannot_be_read_is_reported(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("not json\n")
        self.assertTrue(gp.UsageLog.verify(self.path))

    def test_the_first_record_points_at_the_genesis(self):
        self.fill(1)
        self.assertEqual(gp.UsageLog.load(self.path)[0]["prev"], gp.GENESIS)


class Commands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "envs"
        self.usage = Path(self.tmp.name) / "usage.jsonl"
        self.said = []
        self.ran = []

    def tearDown(self):
        self.tmp.cleanup()

    def runner(self, code=0):
        def run(command, **kw):
            self.ran.append(command)
            return SimpleNamespace(returncode=code, stdout="", stderr="boom" if code else "")
        return run

    def new(self, code=0, **kw):
        kw.setdefault("dest", str(self.dest))
        kw.setdefault("usage", str(self.usage))
        return gp.cmd_new(args(**kw), runner=self.runner(code), now=lambda: NOW, out=self.said.append)

    def events(self):
        return [r["event"] for r in gp.UsageLog.load(self.usage)] if self.usage.exists() else []

    def test_a_request_the_path_covers_makes_an_environment_and_is_recorded(self):
        self.assertEqual(self.new(), 0)
        self.assertEqual(self.events(), ["environment_created"])
        made = gp.UsageLog.load(self.usage)[0]
        self.assertEqual(made["road"], "agent-sandbox")
        self.assertIsInstance(made["duration_ms"], int)
        self.assertTrue((self.dest / made["id"] / "environment.json").exists())

    def test_the_answer_says_what_it_understood_and_what_it_comes_with(self):
        self.new()
        text = "\n".join(self.said)
        self.assertIn("Understood: A sandbox for an agent", text)
        self.assertIn("network: none", text)
        self.assertIn("To tear it down", text)

    def test_a_request_the_path_does_not_cover_is_refused_and_recorded(self):
        self.assertEqual(self.new(intent="order me a pizza"), 2)
        self.assertEqual(self.events(), ["intent_not_covered"])
        miss = gp.UsageLog.load(self.usage)[0]
        self.assertEqual(miss["intent"], "order me a pizza")
        self.assertEqual(miss["reason"], "not_covered")
        self.assertFalse(self.dest.exists())
        self.assertIn("recorded", "\n".join(self.said))

    def test_an_ambiguous_request_is_refused_and_recorded(self):
        self.assertEqual(self.new(intent="a sandbox agent environment dev service"), 2)
        self.assertEqual(gp.UsageLog.load(self.usage)[0]["reason"], "ambiguous")

    def test_a_dry_run_makes_nothing_and_records_nothing(self):
        self.assertEqual(self.new(dry_run=True), 0)
        self.assertFalse(self.dest.exists())
        self.assertEqual(self.events(), [])

    def test_a_road_that_lost_its_defaults_is_refused_and_recorded(self):
        roads = gp.load_roads()
        roads["agent-sandbox"]["defaults"]["network"] = "bridge"
        code = gp.cmd_new(args(dest=str(self.dest), usage=str(self.usage)), runner=self.runner(), now=lambda: NOW, roads=roads, out=self.said.append)
        self.assertEqual(code, 1)
        self.assertEqual(self.events(), ["road_refused"])
        self.assertFalse(self.dest.exists())

    def test_an_environment_that_exists_is_refused(self):
        self.new(name="mine")
        self.assertEqual(self.new(name="mine"), 1)
        self.assertEqual(self.events(), ["environment_created"])

    def test_the_service_road_asks_before_starting_paid_infrastructure(self):
        self.assertEqual(self.new(intent=SERVICE_INTENT), 0)
        self.assertEqual(self.ran, [])
        self.assertEqual(self.events(), ["environment_planned"])
        text = "\n".join(self.said)
        self.assertIn("Cost:", text)
        self.assertIn("--yes", text)
        self.assertIn("desired_count=0", text)

    def test_the_service_road_with_yes_starts_the_workflow_with_zero_tasks(self):
        self.assertEqual(self.new(intent=SERVICE_INTENT, yes=True), 0)
        self.assertEqual(self.ran, [["gh", "workflow", "run", "deploy.yaml", "--ref", "main", "-f", "desired_count=0"]])
        made = gp.UsageLog.load(self.usage)[0]
        self.assertEqual((made["event"], made["desired_count"]), ("environment_dispatched", 0))

    def test_a_task_is_left_running_only_when_asked(self):
        self.new(intent=SERVICE_INTENT, yes=True, running=True)
        self.assertEqual(self.ran[0][-1], "desired_count=1")
        self.assertEqual(gp.UsageLog.load(self.usage)[0]["desired_count"], 1)

    def test_a_workflow_that_cannot_be_started_is_recorded_as_a_failure(self):
        self.assertEqual(self.new(code=1, intent=SERVICE_INTENT, yes=True), 1)
        self.assertEqual(self.events(), ["dispatch_failed"])

    def test_the_list_says_which_roads_are_compliant(self):
        gp.cmd_list(None, out=self.said.append)
        self.assertEqual(sum("[compliant]" in line for line in self.said), 2)

    def test_the_list_says_which_road_is_refused(self):
        roads = gp.load_roads()
        roads["agent-sandbox"]["defaults"]["data"] = "anything"
        gp.cmd_list(None, roads=roads, out=self.said.append)
        self.assertTrue(any("REFUSED" in line for line in self.said))

    def test_the_actor_is_a_name_and_never_the_machine(self):
        self.assertEqual(gp.actor_from_env({"GITHUB_ACTOR": "jbgs"}), "jbgs")
        self.assertEqual(gp.actor_from_env({}), "local")


class Report(unittest.TestCase):
    def usage(self):
        return [
            {"event": "environment_created", "road": "agent-sandbox", "duration_ms": 120},
            {"event": "environment_created", "road": "agent-sandbox", "duration_ms": 80},
            {"event": "environment_dispatched", "road": "service-dev", "duration_ms": 900},
            {"event": "intent_not_covered", "intent": "a kubernetes cluster"},
        ]

    def test_what_was_made_and_what_was_missed(self):
        report = gp.build_report(self.usage(), [])
        self.assertEqual(report["environments_made"], 3)
        self.assertEqual(report["by_road"], {"agent-sandbox": 2, "service-dev": 1})
        self.assertEqual(report["intents_not_covered"], ["a kubernetes cluster"])
        self.assertEqual(report["asked"], 4)
        self.assertEqual(report["covered_share"], 0.75)

    def test_a_request_that_was_understood_and_is_waiting_for_a_yes_counts_as_covered(self):
        usage = self.usage() + [{"event": "environment_planned", "road": "service-dev"}]
        report = gp.build_report(usage, [])
        self.assertEqual((report["environments_made"], report["environments_planned"], report["asked"]), (3, 1, 5))
        self.assertEqual(report["covered_share"], 0.8)
        self.assertIn("waiting for a yes:       1", gp.format_report(report))

    def test_the_time_to_an_environment(self):
        report = gp.build_report(self.usage(), [])
        self.assertEqual((report["median_ms"], report["max_ms"]), (120, 900))

    def test_a_report_with_no_use_says_so_and_does_not_divide_by_zero(self):
        report = gp.build_report([], [])
        self.assertIsNone(report["median_ms"])
        self.assertIsNone(report["covered_share"])
        self.assertIsNone(report["path_share_of_runs"])
        self.assertIn("n/a", gp.format_report(report))

    def runs(self):
        return [
            {"source": {"workflow": "Agent sandbox"}, "environment": None},            # tests the platform
            {"source": {"workflow": "Agent approved run"}, "environment": None},       # tests the platform
            {"source": {"workflow": "Golden path"}, "environment": {"id": "x"}},       # tests the platform
            {"source": {"workflow": "local"}, "environment": {"id": "agent-sandbox-1", "template_sha256": "h1"}},
            {"source": {"workflow": "local"}, "environment": {"id": "agent-sandbox-2", "template_sha256": "h2"}},
            {"source": {"workflow": "local"}, "environment": None},                    # going around the path
        ]

    def made(self):
        return [{"event": "environment_created", "road": "agent-sandbox", "template_sha256": h} for h in ("h1", "h2")]

    def test_runs_that_go_around_the_path_are_counted_and_the_platform_tests_are_not(self):
        report = gp.build_report(self.made(), self.runs())
        self.assertEqual((report["agent_runs_via_the_path"], report["agent_runs_outside_the_path"], report["platform_test_runs"]), (2, 1, 3))
        self.assertEqual(report["agent_runs_naming_an_unknown_environment"], 0)
        self.assertEqual(report["path_share_of_runs"], 0.67)

    def test_a_run_naming_an_environment_the_path_never_made_is_not_counted_as_the_path(self):
        runs = [{"source": {"workflow": "local"}, "environment": {"id": "made-up", "template_sha256": "zzz"}},
                {"source": {"workflow": "local"}, "environment": {"id": "agent-sandbox-1"}},  # no hash at all
                {"source": {"workflow": "local"}, "environment": {"id": "agent-sandbox-1", "template_sha256": "h1"}}]
        report = gp.build_report(self.made(), runs)
        self.assertEqual((report["agent_runs_via_the_path"], report["agent_runs_naming_an_unknown_environment"]), (1, 2))
        self.assertEqual(report["path_share_of_runs"], 0.33)

    def test_with_no_usage_log_no_run_can_count_as_the_path(self):
        report = gp.build_report([], self.runs()[3:5])
        self.assertEqual((report["agent_runs_via_the_path"], report["agent_runs_naming_an_unknown_environment"]), (0, 2))

    def test_the_text_shows_the_signals(self):
        text = gp.format_report(gp.build_report(self.usage() + self.made(), self.runs()))
        for needle in ("Environments made through the path: 5", "'a kubernetes cluster'", "going around the path", "path share 67%"):
            self.assertIn(needle, text)

    def test_run_starts_are_read_from_a_folder_of_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "a.jsonl").write_text(
                json.dumps({"event": "run_started", "environment": {"id": "e"}}) + "\n"
                + json.dumps({"event": "action"}) + "\n" + "garbage\n" + json.dumps({"event": "run_started"}) + "\n")
            self.assertEqual(len(gp.read_run_starts(Path(tmp))), 2)

    def test_a_report_refuses_a_usage_log_that_does_not_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = gp.UsageLog(Path(tmp) / "u.jsonl", lambda: NOW)
            log.append("environment_created", id="a", road="agent-sandbox", duration_ms=1)
            log.append("environment_created", id="b", road="agent-sandbox", duration_ms=1)
            text = (Path(tmp) / "u.jsonl").read_text().replace('"duration_ms": 1', '"duration_ms": 9', 1)
            (Path(tmp) / "u.jsonl").write_text(text)
            said = []
            code = gp.cmd_report(SimpleNamespace(usage=[str(Path(tmp) / "u.jsonl")], logs=None), out=said.append)
            self.assertEqual(code, 1)
            self.assertIn("does not verify", said[0])


class StoreReport(unittest.TestCase):
    """The count across all requests is made from the audit store, and only from logs whose chain verifies."""

    def logs(self, tmp):
        good = Path(tmp) / "good.jsonl"
        gl = gp.UsageLog(good, lambda: NOW)
        gl.append("environment_created", id="a", road="agent-sandbox", duration_ms=5, template_sha256="h1")
        bad = Path(tmp) / "bad.jsonl"
        bl = gp.UsageLog(bad, lambda: NOW)
        bl.append("environment_created", id="b", road="agent-sandbox", duration_ms=1)
        bl.append("environment_created", id="c", road="agent-sandbox", duration_ms=1)
        bad.write_text(bad.read_text().replace('"duration_ms": 1', '"duration_ms": 9', 1))
        return {"agent-runs/golden-path/1-1/usage.jsonl": good, "agent-runs/golden-path/2-1/usage.jsonl": bad}

    def runner(self, files, list_fails=False):
        def run(command, **kw):
            if "list-objects-v2" in command:
                if list_fails:
                    return SimpleNamespace(returncode=254, stdout="", stderr="An error occurred (AccessDenied) when calling")
                body = {"Contents": [{"Key": k} for k in files] + [{"Key": "agent-runs/golden-path/1-1/other.txt"}]}
                return SimpleNamespace(returncode=0, stdout=json.dumps(body), stderr="")
            key = command[command.index("--key") + 1]
            Path(command[-1]).write_bytes(files[key].read_bytes())
            return SimpleNamespace(returncode=0, stdout="{}", stderr="")
        return run

    def test_only_logs_that_verify_are_counted_and_the_rest_are_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            records, problems = gp.fetch_store_usage("b", self.runner(self.logs(tmp)))
        self.assertEqual([r["id"] for r in records], ["a"])
        self.assertEqual(len(problems), 1)
        self.assertIn("2-1", problems[0])

    def test_a_store_that_cannot_be_listed_gives_no_figures_and_says_why(self):
        records, problems = gp.fetch_store_usage("b", self.runner({}, list_fails=True))
        self.assertEqual(records, [])
        self.assertIn("AccessDenied", problems[0])

    def test_the_report_from_the_store_counts_what_verifies(self):
        import os
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            said = []
            with mock.patch.dict(os.environ, {"AUDIT_BUCKET": "b"}, clear=True):
                code = gp.cmd_report(SimpleNamespace(usage=[], logs=None, store=True), out=said.append, runner=self.runner(self.logs(tmp)))
        self.assertEqual(code, 0)
        text = "\n".join(said)
        self.assertIn("Not counted", text)
        self.assertIn("Environments made through the path: 1", text)


class Publish(unittest.TestCase):
    def test_a_usage_log_that_does_not_verify_is_not_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "u.jsonl"
            path.write_text("not json\n")
            said, ran = [], []
            code = gp.cmd_publish(SimpleNamespace(usage=str(path), run_id="9-1"), runner=lambda *a, **k: ran.append(a), out=said.append)
            self.assertEqual(code, 1)
            self.assertEqual(ran, [])

    def test_a_good_usage_log_is_written_once_under_the_prefix_of_the_records(self):
        import os
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            log = gp.UsageLog(Path(tmp) / "u.jsonl", lambda: NOW)
            log.append("environment_created", id="a", road="agent-sandbox", duration_ms=1)
            seen = []

            def runner(command, **kw):
                seen.append(command)
                return SimpleNamespace(returncode=0, stdout=json.dumps({"VersionId": "v1"}), stderr="")

            with mock.patch.dict(os.environ, {"AWS_ACCOUNT_ID": "123456789012"}, clear=True):
                code = gp.cmd_publish(SimpleNamespace(usage=str(Path(tmp) / "u.jsonl"), run_id="9-1"), runner=runner, out=lambda *_: None)
        self.assertEqual(code, 0)
        flags = " ".join(seen[0])
        self.assertIn("--key agent-runs/golden-path/9-1/usage.jsonl", flags)
        self.assertIn("--if-none-match *", flags)


class WorkflowSafety(unittest.TestCase):
    def test_what_a_builder_types_is_never_put_into_a_command(self):
        # A value typed in a form must reach a script as a variable, never be pasted into the text of a command:
        # that is how a request becomes a command line.
        text = (gp.ROOT / ".github" / "workflows" / "golden-path.yaml").read_text(encoding="utf-8")
        pasted = [line for line in text.splitlines() if "${{ inputs." in line and not line.lstrip().startswith("#")]
        self.assertEqual([line.strip() for line in pasted], ["INTENT: ${{ inputs.intent }}"], pasted)
        self.assertIn('new "${INTENT}"', text)

    def test_only_the_publishing_job_can_reach_aws_and_it_declares_no_environment(self):
        text = (gp.ROOT / ".github" / "workflows" / "golden-path.yaml").read_text(encoding="utf-8")
        self.assertEqual(text.count("id-token: write"), 1)
        self.assertNotRegex(text, r"(?m)^\s+environment:")
        self.assertIn("if: github.ref == 'refs/heads/main'", text)

if __name__ == "__main__":
    unittest.main()
