#!/usr/bin/env python3
"""A test of the tests: weaken the audit gate on purpose, and require the tests to notice.

Each mutant is a copy of the audit code with one rule switched off (the chain is no longer checked, an agent may
approve its own action, the manifest is ignored, and so on). The tests are run against it. A mutant that the tests
do not catch is a rule that nobody is checking.

    python3 agent/mutation_check.py

Exit status 0 means every mutant was caught. Standard library only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (file, what is weakened, the code as it is, the code weakened)
MUTANTS = [
    ("audit_verify.py", "the chain link (prev) is not checked", 'if rec["chain"].get("prev") != expected_prev:', "if False:"),
    ("audit_verify.py", "the content hash is not checked", 'elif audit.record_hash(rec) != rec["chain"].get("sha256"):', "elif False:"),
    ("audit_verify.py", "the numbering is not checked", 'if rec["seq"] != index:', "if False:"),
    (
        "audit_verify.py",
        "a log cut short is accepted",
        'if records[-1]["event"] != "run_finished" or sum(r["event"] == "run_finished" for r in records) != 1:',
        "if False:",
    ),
    ("audit_verify.py", "the manifest head hash is ignored", 'if manifest.get("head_sha256") != records[-1]["chain"]["sha256"]:', "if False:"),
    ("audit_verify.py", "the manifest count is ignored", 'if manifest.get("records") != len(records):', "if False:"),
    ("audit_verify.py", "an action that ran although it was denied", 'if effect in ("gate", "deny"):', "if False:"),
    ("audit_verify.py", "an agent may approve its own action", 'and approval["approver"] != agent_id\n', "\n"),
    ("audit_verify.py", "a human-gated action needs no approval", 'and approval["status"] == "approved"\n', "\n"),
    ("audit_verify.py", "a gated action need not be pending", 'if not ok:\n            problems.append(f"{where}: gated, but', 'if False:\n            problems.append(f"{where}: gated, but'),
    ("audit_verify.py", "a different policy mid-run is accepted", 'if policy["policy_sha256"] != policy_sha:', "if False:"),
    (
        "audit_verify.py",
        "a request that does not match its hash is accepted",
        'if audit.sha256_hex(audit.canonical(rec["request"])) != rec["request_sha256"]:',
        "if False:",
    ),
    ("audit_verify.py", "the run summary is not compared with the records", "if summary[key] != value:", "if False:"),
    ("audit_verify.py", "the plan is not compared with the records", "if got != wanted:", "if False:"),
    ("audit_verify.py", "an effect that does not fit the mode is accepted", 'if (mode == "enforce") == (effect == "bypassed"):', "if False:"),
    ("audit_verify.py", "an allowed action with no record of running is accepted", 'elif effect == "allow":', "elif False:"),
    ("audit_verify.py", "a record from another run is accepted", 'if rec["run_id"] != run_id or rec["mode"] != mode:', "if False:"),
    ("audit_verify.py", "a line that is not an object is not reported", "if not isinstance(rec, dict):", "if False:"),
    (
        "audit_verify.py",
        "a malformed chain field is not reported",
        'if not isinstance(chain, dict) or not all(isinstance(chain.get(k), str) for k in ("prev", "sha256")):',
        "if False:",
    ),
    ("audit.py", "records are no longer written to disk as they happen", "if self.sink:\n            with open(", "if False:\n            with open("),
    ("publish_audit.py", "a write is no longer conditional (it could replace a record)", '            "--if-none-match", "*",\n', ""),
    ("publish_audit.py", "the checksum is not sent with the write", '            "--checksum-sha256", checksum,\n', ""),
    ("publish_audit.py", "a failed write is not reported", 'return all(r["ok"] for r in results)', "return True"),
    (
        "publish_audit.py",
        "the head pointer is not written",
        'recorded = put_once(bucket, head_key(manifest["head_sha256"]), pointer, runner)',
        'recorded = {"key": "", "ok": True, "error": None, "version_id": None, "checksum": ""}',
    ),
    ("publish_audit.py", "an accepted attempt to change a record counts as refused", "            ok = got == expected\n", "            ok = True\n"),
    (
        "publish_audit.py",
        "reading back does not run the audit gate",
        'problems += [f"{mode_label}: {p}" for p in audit_verify.verify(records, manifest, expect)]',
        "problems += []",
    ),
    ("publish_audit.py", "a missing head pointer is not reported", 'if code != 0:\n                    problems.append(f"{mode_label}: the head pointer is missing', 'if False:\n                    problems.append(f"{mode_label}: the head pointer is missing'),
    ("publish_audit.py", "a head that was already recorded is a failure, so a retry cannot succeed", 'recorded["ok"], recorded["note"] = True, "already recorded"', 'pass'),
    ("publish_audit.py", "the log of the controls is not checked against the code's expectation", 'else controls_plan()', 'else None'),
    ("publish_audit.py", "a manifest that can be replaced is not caught", '"ok": got == "PreconditionFailed"}', '"ok": True}'),
    (
        "publish_audit.py",
        "the attempt to shorten the retention uses a date in the past, so it tests nothing",
        'f"Mode=GOVERNANCE,RetainUntilDate={shorter}"',
        '"Mode=GOVERNANCE,RetainUntilDate=2020-01-01T00:00:00Z"',
    ),
    ("audit_verify.py", "an approval with no evidence of where it came from is accepted", '            and approval["evidence"]\n', "\n"),
    ("fetch_approval.py", "a rejected review is accepted as an approval", 'if last.get("state") != "approved":', "if False:"),
    ("fetch_approval.py", "a review of another environment is accepted", 'e.get("name") == environment', "True"),
    ("fetch_approval.py", "no review at all is not refused", "if not ours:", "if False:"),
    ("fetch_approval.py", "more than one review is not treated as ambiguous", "if len(ours) > 1:", "if False:"),
    ("fetch_approval.py", "an approval with no time is accepted", "if not matches:", "if False:"),
    ("fetch_approval.py", "an approval that does not say who is accepted", "if not login:", "if False:"),
    ("run_agent.py", "an approval is given to every action, not only to the one it names", 'mine = approval if approval and approval["action"] == item["action"] else None', "mine = approval"),
    (
        "run_agent.py",
        "a gated action that ran without an approval is accepted",
        'if rec["executed"] or effect == "allow":\n                    problems.append(f"{name}: it ran, or was allowed, without',
        'if False:\n                    problems.append(f"{name}: it ran, or was allowed, without',
    ),
    ("run_agent.py", "a negative approval file is accepted", 'or approval.get("approved") is not True', "or False"),
    ("run_agent.py", "a result is exported without an approval", 'and rec.get("output") and rec.get("approval"):', 'and rec.get("output"):'),
    ("run_agent.py", "a run that failed its own checks still exports a result", "return False if problems else export_approved(out, records)", "return export_approved(out, records)"),
    ("run_agent.py", "a folder that looks like regulated data is accepted", "    if looks_regulated(path.name) or any(looks_regulated(p.relative_to(path).as_posix()) for p in files):", "    if False:"),
    ("run_agent.py", "an empty data folder is accepted", "    if not files:\n        raise SystemExit", "    if False:\n        raise SystemExit"),
    ("run_agent.py", "data that is not the platform's own is accepted", "        if known.get(p.relative_to(path).as_posix()) != audit.sha256_hex(p.read_bytes()):", "        if False:"),
    ("run_agent.py", "a policy that is not the platform's is accepted", "        if repo.get(name) != content:", "        if False:"),
    ("run_agent.py", "a policy folder without agent.rego is accepted", '    if "agent.rego" not in given:', "    if False:"),
    ("run_agent.py", "an environment is not verified before a run", "        problems = environment.verify(env_dir, args.environment)", "        problems = []"),
    ("run_agent.py", "a run may use data that is not its environment's own", "            if given and Path(given).resolve() != own.resolve():", "            if False:"),
    ("run_agent.py", "the hash of the environment is not recorded", "environment_hash = environment.template_of(env_dir)", "environment_hash = None"),
    ("environment.py", "an environment of another name is accepted", 'if record.get("id") != env_id:', "if False:"),
    ("environment.py", "an environment whose data or policy changed is accepted", "if template_sha256(files) != record.get(\"template_sha256\"):", "if False:"),
    ("environment.py", "an environment whose policy is not the recorded one is accepted", 'if policy is None or audit.sha256_hex(policy) != record.get("policy_sha256"):', "if False:"),
    ("environment.py", "a folder with no environment.json is accepted", "    if not record_path.is_file():", "    if False:"),
    ("environment.py", "the data is left out of the hash of an environment", 'HASHED = ("data/", "policy/")', 'HASHED = ("policy/",)'),
    ("run_agent.py", "a contained attempt that the policy denied is accepted", 'if mode == "enforce" and (rec["policy"] or {}).get("effect") != "allow":\n                problems.append(f"{name}: expected the policy', 'if False:\n                problems.append(f"{name}: expected the policy'),
    ("run_agent.py", "generated code that got out is accepted", 'problems.append(f"{name}: ESCAPED or failed to run ({rec[\'outcome\']}: {rec[\'detail\']})")\n        elif mode == "enforce":', 'problems.append(f"{name}: ESCAPED or failed to run ({rec[\'outcome\']}: {rec[\'detail\']})")\n        elif False:'),
    ("run_agent.py", "the task of a request is not recorded", 'if rec.get("task"):\n        request["task"]', 'if False:\n        request["task"]'),
    ("run_agent.py", "the task is not given to the container", 'if item.get("tool") or item.get("task"):', 'if item.get("tool"):'),
    ("audit_verify.py", "the audit gate ignores which task was planned", 'wanted = [(item["action"], item.get("tool"), item.get("task")) for item in plan]', 'wanted = [(item["action"], item.get("tool"), None) for item in plan]'),
    ("sandbox/actions.py", "generated code that printed ESCAPED is not reported", 'if "ESCAPED:" in printed:', "if False:"),
    ("sandbox/actions.py", "generated code that failed is reported as a pass", "    if done.returncode != 0:", "    if False:"),
    ("run_agent.py", "an escape is only a warning", '"severity": "critical", "why": "an attempt got out', '"severity": "warning", "why": "an attempt got out'),
    ("run_agent.py", "a denied attempt raises no alert", 'if (rec.get("policy") or {}).get("effect") == "deny":\n        return {"severity"', 'if False:\n        return {"severity"'),
    ("run_agent.py", "an attempt the sandbox stopped raises no alert", 'if rec["outcome"] in ("blocked", "killed"):\n        return {"severity"', 'if False:\n        return {"severity"'),
    ("run_agent.py", "an alert is not written to the record", 'if alert:\n        extra["alert"] = alert', 'if False:\n        extra["alert"] = alert'),
    ("run_agent.py", "the negative controls raise alerts", "alert = None if weaken else alert_for(rec)", "alert = alert_for(rec)"),
    ("run_agent.py", "a log does not say that it alerts", 'alerting=(mode != "weakening"),', "alerting=False,"),
    ("run_agent.py", "a critical alert is shown as a warning", 'level = "error" if alert["severity"] == "critical" else "warning"', 'level = "warning"'),
    ("run_agent.py", "the alert is not shown on the page of the run", 'if record["alert"]:\n            print(annotation(record))', 'if False:\n            print(annotation(record))'),
    ("audit_verify.py", "the audit gate does not look at alerts", "    if alerting:\n        problems += check_alert(rec, where)", "    if False:\n        problems += check_alert(rec, where)"),
    ("audit_verify.py", "a stopped attempt with no alert is accepted", 'if not isinstance(alert, dict) or not alert.get("why"):', "if False:"),
    ("audit_verify.py", "an alert with the wrong severity is accepted", 'if alert.get("severity") != wanted:', "if False:"),
    ("audit_verify.py", "an alert on a harmless action is accepted", 'return [f"{where}: an alert for something that needed none"] if alert is not None else []', "return []"),
    ("run_agent.py", "the environment of the path is not recorded", 'environment={"id": environment, "template_sha256": environment_hash} if environment else None,', "environment=None,"),
    ("audit.py", "the first record is not tied to its run", 'return sha256_hex(f"{SCHEMA}|genesis|{run_id}".encode("utf-8"))', 'return sha256_hex(b"genesis")'),
]


def run_tests(directory: Path) -> bool:
    done = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(directory)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
    )
    return done.returncode == 0


def main() -> int:
    if not run_tests(HERE):
        print("the tests do not pass on the real code: fix them before testing the tests")
        return 1
    missed, caught = [], 0
    for filename, name, old, new in MUTANTS:
        source = (HERE / filename).read_text(encoding="utf-8")
        if old not in source:
            print(f"CANNOT APPLY  {filename}: {name} (the code it weakens has changed: update this list)")
            missed.append(name)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "agent"
            shutil.copytree(HERE, copy, ignore=shutil.ignore_patterns("__pycache__", "out"))
            (copy / filename).write_text(source.replace(old, new, 1), encoding="utf-8")
            if run_tests(copy):
                print(f"NOT CAUGHT    {filename}: {name}")
                missed.append(name)
            else:
                caught += 1
                print(f"caught        {filename}: {name}")
    print(f"\n{caught} of {len(MUTANTS)} weakened versions were caught by the tests.")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
