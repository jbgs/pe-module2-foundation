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
