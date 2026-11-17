#!/usr/bin/env python3
"""The golden path: describe what you need, get an environment that is compliant by default.

    golden_path.py new "I need a sandbox for an agent to analyse churn data"
    golden_path.py list
    golden_path.py report [--usage FILE ...] [--logs DIR]

A Builder says what they need in their own words. The platform matches it to one of a few paved roads, shows what it
understood and what the environment comes with, and makes it. There is no ticket and no one to wait for.

Matching is deterministic: keywords with weights, no model. An intent that no road covers, or that two roads cover
equally, is refused and recorded as such. That record is the most honest sign of adoption there is: it says what the
path is missing, before a Builder goes and builds it by hand.

Each paved road carries the compliant choices as defaults (road.json). A road without them is refused, here and by a
test, so a road cannot be added that quietly gives them up. Every use, every miss and every duration is written to a
usage log whose records are chained by hashes.

Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ROADS_DIR = HERE / "paved-roads"
sys.path.insert(0, str(ROOT / "agent"))

import audit  # noqa: E402  (the same canonical form and hashes as the audit record)
import environment  # noqa: E402  (what makes an environment what it says it is)

USAGE_SCHEMA = "golden-path-usage/1"
ENV_SCHEMA = "golden-path-environment/1"
MIN_SCORE = 3
GENESIS = audit.sha256_hex(f"{USAGE_SCHEMA}|genesis".encode("utf-8"))
# Workflows that test the platform itself: their runs are not Builders using, or avoiding, the path.
PLATFORM_TEST_WORKFLOWS = ("Agent sandbox", "Agent approved run", "Golden path")

REQUIRED_ROAD_KEYS = ("name", "title", "summary", "kind", "keywords", "defaults", "teardown", "cost")
REQUIRED_DEFAULTS = {
    "local": {"network": "none", "root_filesystem": "read-only", "capabilities": "none", "data": "synthetic only"},
    "dispatch": {"root_filesystem": "read-only", "data": "synthetic only"},
}
REQUIRED_PRESENT = {
    "local": ("policy", "audit"),
    "dispatch": ("network_exposure", "rollback", "state", "size", "audit"),
}


class Refused(Exception):
    """Something the path will not do, with the reason."""


# What a Builder types is kept, for good, in a store that cannot be edited. Things that look like a secret or a personal
# identifier are removed before it is kept: the point of keeping a request is what it asks for, never what it leaks.
SECRET_SHAPES = re.compile(
    r"sk-ant-[A-Za-z0-9_\-]+|github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{12,}|"
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|\b\d{9,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)


def redact(intent: str, limit: int = 200) -> str:
    return SECRET_SHAPES.sub("[redacted]", intent)[:limit]


def looks_regulated(name: str) -> bool:
    """Whole words only: a folder called `unregulated` is not regulated data."""
    return bool({"regulated", "customers"} & set(re.split(r"[^a-z0-9]+", name.lower())))


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------------------------------------
# The paved roads
# ---------------------------------------------------------------------------------------------------------


def load_roads(roads_dir: Path = ROADS_DIR) -> dict[str, dict]:
    roads = {}
    for path in sorted(roads_dir.glob("*/road.json")):
        road = json.loads(path.read_text(encoding="utf-8"))
        road["_dir"] = path.parent.name
        roads[road.get("name", path.parent.name)] = road
    return roads


def check_road(road: dict) -> list[str]:
    """A road is compliant if it carries the defaults. A road that does not is refused, never created from."""
    problems = [f"lacks {key}" for key in REQUIRED_ROAD_KEYS if not road.get(key)]
    if problems:
        return problems
    kind = road["kind"]
    if kind not in REQUIRED_DEFAULTS:
        return [f"unknown kind {kind!r}"]
    if road.get("_dir") and road["_dir"] != road["name"]:
        problems.append(f"the folder {road['_dir']!r} does not match the name {road['name']!r}")
    defaults = road["defaults"]
    for key, value in REQUIRED_DEFAULTS[kind].items():
        if defaults.get(key) != value:
            problems.append(f"the default {key} must be {value!r}, and is {defaults.get(key)!r}")
    problems += [f"the default {key} is not stated" for key in REQUIRED_PRESENT[kind] if not defaults.get(key)]
    if kind == "dispatch" and not road.get("workflow"):
        problems.append("a road that starts a workflow must name it")
    if not all(isinstance(weight, int) and weight > 0 for weight in road["keywords"].values()):
        problems.append("every keyword needs a positive whole weight")
    return problems


def words(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def score(intent: str, road: dict) -> tuple[int, list[str]]:
    padded = f" {words(intent)} "
    matched = [phrase for phrase in road["keywords"] if f" {words(phrase)} " in padded]
    return sum(road["keywords"][phrase] for phrase in matched), matched


def choose(intent: str, roads: dict[str, dict]) -> dict:
    """Match an intent to one road, or say why it cannot be matched."""
    scored = sorted(((score(intent, road), name) for name, road in roads.items()), key=lambda item: (-item[0][0], item[1]))
    scores = {name: s[0] for s, name in scored}
    (best, matched), name = scored[0]
    second = scored[1][0][0] if len(scored) > 1 else 0
    if best < MIN_SCORE:
        return {"road": None, "reason": "not_covered", "scores": scores,
                "detail": f"no paved road covers this: the best score is {best} and the minimum is {MIN_SCORE}"}
    if best - second < 1:
        return {"road": None, "reason": "ambiguous", "scores": scores,
                "detail": "two roads cover this equally well: say which of them you mean"}
    return {"road": name, "reason": "matched", "matched": matched, "scores": scores}


# ---------------------------------------------------------------------------------------------------------
# The usage log
# ---------------------------------------------------------------------------------------------------------


class UsageLog:
    """What the path is used for, and what it is asked for and cannot give. Records are chained by hashes."""

    def __init__(self, path, now=utc_now):
        self.path = Path(path)
        self._now = now

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return -1, GENESIS
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return -1, GENESIS
        last = json.loads(lines[-1])
        return last["seq"], last["sha256"]

    def append(self, event: str, **fields) -> dict:
        seq, prev = self._tail()
        record = {"schema": USAGE_SCHEMA, "seq": seq + 1, "timestamp": stamp(self._now()), "event": event, **fields}
        record["prev"] = prev
        record["sha256"] = audit.sha256_hex(audit.canonical({k: v for k, v in record.items() if k != "sha256"}))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    @staticmethod
    def load(path) -> list[dict]:
        return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]

    @staticmethod
    def verify(path) -> list[str]:
        problems, prev = [], GENESIS
        try:
            records = UsageLog.load(path)
        except (OSError, ValueError) as exc:
            return [f"the usage log cannot be read ({type(exc).__name__})"]
        for index, rec in enumerate(records):
            if not isinstance(rec, dict) or rec.get("schema") != USAGE_SCHEMA:
                problems.append(f"record {index}: not a usage record")
                continue
            if rec.get("seq") != index:
                problems.append(f"record {index}: numbered {rec.get('seq')}: a record was removed, added or moved")
            if rec.get("prev") != prev:
                problems.append(f"record {index}: the chain is broken here")
            body = {k: v for k, v in rec.items() if k != "sha256"}
            if audit.sha256_hex(audit.canonical(body)) != rec.get("sha256"):
                problems.append(f"record {index}: the record was altered")
            prev = rec.get("sha256")
        return problems


# ---------------------------------------------------------------------------------------------------------
# Making an environment
# ---------------------------------------------------------------------------------------------------------


def sha8(text: str) -> str:
    return audit.sha256_hex(text.encode("utf-8"))[:8]


def environment_id(road: str, intent: str, moment: datetime) -> str:
    return f"{road}-{moment:%Y%m%d-%H%M%S}-{sha8(intent)}"


def synthetic_files(root: Path = ROOT) -> list[Path]:
    directory = root / "agent" / "synthetic"
    files = sorted(p for p in directory.iterdir() if p.is_file())
    if not files:
        raise Refused("there is no synthetic data to copy")
    return files


def render_readme(env_id: str, road: dict, intent: str) -> str:
    lines = [f"# {road['title']}", "", f"Environment `{env_id}`, made by the golden path.", "", f"> {intent[:200]}", "",
             "## What it comes with", ""]
    lines += [f"- **{key.replace('_', ' ')}**: {value}" for key, value in road["defaults"].items()]
    lines += ["", "## Run an agent in it", "", "```",
              f"python3 agent/run_agent.py --mode enforce --plan {env_id}/plan.json --data {env_id}/data "
              f"--policy-dir {env_id}/policy --environment {env_id} --out {env_id}/out",
              "```", "", "Needs Docker and the policy engine (`opa`). The same environment, with an agent run, is in CI as the",
              "workflow `Agent sandbox`.", "", "## Tear it down", "", road["teardown"] + ".", ""]
    return "\n".join(lines)


def create_local(road: dict, intent: str, dest: Path, name: str | None, moment: datetime, actor: str, root: Path = ROOT) -> dict:
    env_id = name or environment_id(road["name"], intent, moment)
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", env_id):
        raise Refused(f"{env_id!r} is not a usable name: use lowercase letters, digits, dots, dashes and underscores")
    target = dest / env_id
    if target.exists():
        raise Refused(f"{target} already exists: the path never overwrites an environment")
    if any(looks_regulated(part) for part in target.parts):
        raise Refused("an environment is never made next to regulated data")
    files = {"data/" + p.name: p.read_bytes() for p in synthetic_files(root)}
    files["plan.json"] = (root / "agent" / "plan.json").read_bytes()
    files["policy/agent.rego"] = (root / "policy" / "agent.rego").read_bytes()
    if any(looks_regulated(key) for key in files):
        raise Refused("regulated data must never be copied into an environment")
    intent = redact(intent)
    files["README.md"] = render_readme(env_id, road, intent).encode("utf-8")
    template_sha = environment.template_sha256(files)
    record = {
        "schema": ENV_SCHEMA, "id": env_id, "road": road["name"], "intent": intent, "created_by": actor,
        "created_at": stamp(moment), "defaults": road["defaults"],
        "policy_sha256": audit.sha256_hex(files["policy/agent.rego"]), "template_sha256": template_sha, "files": sorted(files),
    }
    files["environment.json"] = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    for relative, content in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return record


def dispatch_command(road: dict, running: bool) -> list[str]:
    return ["gh", "workflow", "run", road["workflow"], "--ref", "main", "-f", f"desired_count={'1' if running else '0'}"]


# ---------------------------------------------------------------------------------------------------------
# The commands
# ---------------------------------------------------------------------------------------------------------


def actor_from_env(env=None) -> str:
    """A name that says who, and not which machine: the platform's own account name, or `local`."""
    return (os.environ if env is None else env).get("GITHUB_ACTOR") or "local"


def describe(road: dict, choice: dict) -> list[str]:
    lines = [f"Understood: {road['title']}  (matched: {', '.join(choice.get('matched', []))})", "", "It comes with:"]
    lines += [f"  - {key.replace('_', ' ')}: {value}" for key, value in road["defaults"].items()]
    return lines


def cmd_new(args, runner=subprocess.run, now=utc_now, roads: dict | None = None, out=print) -> int:
    started = time.monotonic()
    roads = load_roads() if roads is None else roads
    log = UsageLog(args.usage, now)
    actor, raw_intent = actor_from_env(), (args.intent or "").strip()
    intent = redact(raw_intent)  # what is kept is the request without what looks like a secret
    choice = choose(raw_intent, roads)
    if choice["road"] is None:
        log.append("intent_not_covered", intent=intent, reason=choice["reason"], detail=choice["detail"],
                   scores=choice["scores"], by=actor, source=args.source)
        out(f"The path does not cover this: {choice['detail']}.")
        out("Paved roads: " + ", ".join(f"{n} ({r['title']})" for n, r in roads.items()))
        out("This request was recorded: it tells the platform what the path is missing.")
        return 2
    road = roads[choice["road"]]
    problems = check_road(road)
    if problems:
        log.append("road_refused", road=road["name"], problems=problems, by=actor, source=args.source)
        out(f"The road {road['name']!r} is refused, because it does not carry the compliant defaults: {'; '.join(problems)}")
        return 1
    for line in describe(road, choice):
        out(line)
    out("")
    if road["kind"] == "local":
        if args.dry_run:
            out("Dry run: nothing was made.")
            return 0
        try:
            record = create_local(road, intent, Path(args.dest), args.name, now(), actor)
        except Refused as exc:
            out(f"Refused: {exc}")
            return 1
        log.append("environment_created", id=record["id"], road=road["name"], intent=intent, by=actor, source=args.source,
                   duration_ms=int((time.monotonic() - started) * 1000), policy_sha256=record["policy_sha256"],
                   template_sha256=record["template_sha256"])
        out(f"Made {Path(args.dest) / record['id']} in {int((time.monotonic() - started) * 1000)} ms.")
        out(f"See {Path(args.dest) / record['id'] / 'README.md'} for how to run an agent in it.")
        out(f"To tear it down: {road['teardown']}.")
        return 0
    command = dispatch_command(road, args.running)
    out(f"Cost: {road['cost']}.")
    out(f"To tear it down: {road['teardown']}.")
    if not args.yes:
        log.append("environment_planned", road=road["name"], intent=intent, by=actor, source=args.source, command=command)
        out("It starts paid infrastructure, so it asks first. This would run: " + " ".join(command))
        out("Add --yes to run it" + (" (with --running to leave a task running)." if not args.running else "."))
        return 0
    done = runner(command, capture_output=True, text=True, check=False)
    duration = int((time.monotonic() - started) * 1000)
    if done.returncode != 0:
        log.append("dispatch_failed", road=road["name"], by=actor, source=args.source, duration_ms=duration)
        out("The workflow could not be started: " + (done.stderr or "").strip()[:200])
        return 1
    log.append("environment_dispatched", road=road["name"], intent=intent, by=actor, source=args.source, duration_ms=duration,
               desired_count=1 if args.running else 0)
    out(f"The {road['workflow']} workflow was started ({'one task' if args.running else 'zero tasks'}); follow it with `gh run watch`.")
    return 0


def cmd_list(args, roads: dict | None = None, out=print) -> int:
    for name, road in (load_roads() if roads is None else roads).items():
        problems = check_road(road)
        out(f"{name}: {road['title']} [{'compliant' if not problems else 'REFUSED: ' + '; '.join(problems)}]")
        out(f"    {road['summary']}")
    return 0


def build_report(usage: list[dict], started_logs: list[dict]) -> dict:
    """What the path is used for, what it is asked for and cannot give, and who goes around it."""
    made = [r for r in usage if r.get("event") in ("environment_created", "environment_dispatched")]
    planned = [r for r in usage if r.get("event") == "environment_planned"]  # understood, and waiting for a "yes"
    misses = [r for r in usage if r.get("event") == "intent_not_covered"]
    durations = sorted(r["duration_ms"] for r in made if isinstance(r.get("duration_ms"), int))
    by_road: dict[str, int] = {}
    for record in made:
        by_road[record["road"]] = by_road.get(record["road"], 0) + 1
    # A run counts as coming from the path only if the environment it names was made by the path: its hash is in the usage log.
    made_templates = {r["template_sha256"] for r in usage if r.get("event") == "environment_created" and r.get("template_sha256")}
    via, outside, tests, unverified = 0, 0, 0, 0
    for run in started_logs:
        workflow = (run.get("source") or {}).get("workflow")
        claimed = run.get("environment") or {}
        if workflow in PLATFORM_TEST_WORKFLOWS:
            tests += 1
        elif claimed.get("id") and claimed.get("template_sha256") in made_templates:
            via += 1
        elif claimed.get("id"):
            unverified += 1  # it names an environment that the usage log has never seen
        else:
            outside += 1
    asked = len(made) + len(planned) + len(misses)
    return {
        "environments_made": len(made), "environments_planned": len(planned), "by_road": by_road,
        "intents_not_covered": [m.get("intent") for m in misses],
        "asked": asked, "covered_share": round((len(made) + len(planned)) / asked, 2) if asked else None,
        "median_ms": int(statistics.median(durations)) if durations else None, "max_ms": durations[-1] if durations else None,
        "agent_runs_via_the_path": via, "agent_runs_outside_the_path": outside, "platform_test_runs": tests,
        "agent_runs_naming_an_unknown_environment": unverified,
        "path_share_of_runs": round(via / (via + outside + unverified), 2) if (via + outside + unverified) else None,
    }


def format_report(report: dict) -> str:
    def pct(value):
        return "n/a" if value is None else f"{round(value * 100)}%"

    lines = ["Golden path: adoption", "",
             f"Environments made through the path: {report['environments_made']}  {report['by_road'] or ''}",
             f"Understood, waiting for a yes:       {report['environments_planned']}",
             f"Intents the path did not cover:      {len(report['intents_not_covered'])} of {report['asked']} asked ({pct(report['covered_share'])} covered)"]
    lines += [f"    - {intent!r}" for intent in report["intents_not_covered"]]
    median = "n/a" if report["median_ms"] is None else f"{report['median_ms']} ms (longest {report['max_ms']} ms)"
    lines += [f"Time to an environment, median:     {median}", "",
              f"Agent runs that came from an environment of the path: {report['agent_runs_via_the_path']}",
              f"Agent runs that did not (going around the path):      {report['agent_runs_outside_the_path']}   path share {pct(report['path_share_of_runs'])}",
              f"Agent runs naming an environment the path never made:  {report['agent_runs_naming_an_unknown_environment']}",
              f"Runs that test the platform itself (not counted):      {report['platform_test_runs']}"]
    return "\n".join(lines)


def read_run_starts(logs_dir: Path) -> list[dict]:
    starts = []
    for path in sorted(Path(logs_dir).rglob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if isinstance(record, dict) and record.get("event") == "run_started":
                starts.append(record)
    return starts


def fetch_store_usage(bucket: str, runner=subprocess.run) -> tuple[list[dict], list[str]]:
    """Every usage log in the audit store, each checked on its own chain. Needs an identity that can read the store."""
    import tempfile

    import publish_audit

    code, out, err = publish_audit.aws(["list-objects-v2", "--bucket", bucket, "--prefix", f"{publish_audit.PREFIX}golden-path/",
                                        "--output", "json"], runner)
    if code != 0:
        return [], [f"the audit store cannot be listed ({publish_audit.error_code(err) or 'error'})"]
    try:
        keys = [o["Key"] for o in (json.loads(out or "{}").get("Contents") or []) if o["Key"].endswith("/usage.jsonl")]
    except (ValueError, KeyError, TypeError):
        return [], ["the listing of the audit store cannot be read"]
    records, problems = [], []
    with tempfile.TemporaryDirectory() as tmp:
        for index, key in enumerate(keys):
            target = Path(tmp) / f"{index}.jsonl"
            code, _, err = publish_audit.aws(["get-object", "--bucket", bucket, "--key", key, str(target)], runner)
            if code != 0:
                problems.append(f"{key}: cannot be read ({publish_audit.error_code(err) or 'error'})")
                continue
            bad = UsageLog.verify(target)
            if bad:
                problems.append(f"{key}: {bad[0]}")
                continue
            records += UsageLog.load(target)
    return records, problems


def cmd_report(args, out=print, runner=subprocess.run) -> int:
    usage = []
    if getattr(args, "store", False):
        import publish_audit

        records, problems = fetch_store_usage(publish_audit.bucket_name(), runner)
        for problem in problems:
            out(f"Not counted: {problem}")
        usage += records
    for path in args.usage:
        if Path(path).exists():
            problems = UsageLog.verify(path)
            if problems:
                out(f"The usage log {path} does not verify: {problems[0]}")
                return 1
            usage += UsageLog.load(path)
    starts = read_run_starts(Path(args.logs)) if args.logs else []
    out(format_report(build_report(usage, starts)))
    return 0


def cmd_publish(args, runner=subprocess.run, out=print) -> int:
    """Write the usage log to the audit store, so that adoption is counted centrally and cannot be edited afterwards."""
    import publish_audit

    problems = UsageLog.verify(args.usage)
    if problems:
        out(f"Refusing to publish a usage log that does not verify: {problems[0]}")
        return 1
    bucket = publish_audit.bucket_name()
    result = publish_audit.put_once(bucket, f"{publish_audit.PREFIX}golden-path/{args.run_id}/usage.jsonl", Path(args.usage), runner)
    out(f"usage log {'written' if result['ok'] else 'NOT written (' + str(result['error']) + ')'}: {result['key']}")
    return 0 if result["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default_usage = os.environ.get("GOLDEN_PATH_USAGE") or str(Path.home() / ".golden-path" / "usage.jsonl")
    sub = parser.add_subparsers(dest="command", required=True)
    new = sub.add_parser("new", help="make an environment from a description of what you need")
    new.add_argument("intent", help="what you need, in your own words")
    new.add_argument("--dest", default=str(HERE / "environments"))
    new.add_argument("--name", help="a name for the environment (default: made from the road, the time and the request)")
    new.add_argument("--usage", default=default_usage)
    new.add_argument("--source", default="cli", help="where the request came from: cli or workflow")
    new.add_argument("--dry-run", action="store_true")
    new.add_argument("--yes", action="store_true", help="run what starts paid infrastructure")
    new.add_argument("--running", action="store_true", help="for a service: leave one task running (it costs)")
    sub.add_parser("list")
    rep = sub.add_parser("report")
    rep.add_argument("--usage", action="append", default=[], help="a usage log (repeatable)")
    rep.add_argument("--logs", help="a folder of audit logs: agent runs with and without an environment are counted")
    rep.add_argument("--store", action="store_true",
                     help="add every usage log in the audit store (needs an identity that can read it)")
    pub = sub.add_parser("publish")
    pub.add_argument("--usage", required=True)
    pub.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    if args.command == "new":
        return cmd_new(args)
    if args.command == "list":
        return cmd_list(args)
    if args.command == "report":
        args.usage = args.usage or ([] if args.store else [default_usage])
        return cmd_report(args)
    return cmd_publish(args)


if __name__ == "__main__":
    sys.exit(main())
