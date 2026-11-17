#!/usr/bin/env python3
"""A test of the tests: weaken the golden path on purpose, and require the tests to notice.

Each mutant is a copy of the golden path with one rule switched off (a road that gives up a default is accepted, an
intent that no road covers is not recorded, an environment may be overwritten, a request may start paid infrastructure
without asking, and so on). The tests are run against it. A mutant that the tests do not catch is a rule that nobody
is checking.

    python3 golden-path/mutation_check.py

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
ROOT = HERE.parent
# The golden path reads the agent, the policy and a workflow, so the copy carries them too.
SHARED = ("agent", "policy", ".github/workflows")

# (what is weakened, the code as it is, the code weakened)
MUTANTS = [
    ("a road that gives up a default is accepted", "        if defaults.get(key) != value:", "        if False:"),
    ("a road that does not state its audit or policy is accepted",
     'problems += [f"the default {key} is not stated" for key in REQUIRED_PRESENT[kind] if not defaults.get(key)]', "pass"),
    ("an intent that no road covers is matched anyway", "    if best < MIN_SCORE:", "    if False:"),
    ("an ambiguous intent is not refused", "    if best - second < 1:", "    if False:"),
    ("an intent the path cannot cover is not recorded", '        log.append("intent_not_covered",', '        (lambda *a, **k: None)("intent_not_covered",'),
    ("an existing environment is overwritten", "    if target.exists():", "    if False:"),
    ("regulated data may be copied into an environment", "if any(looks_regulated(key) for key in files):", "if False:"),
    ("an environment may be made next to regulated data", "if any(looks_regulated(part) for part in target.parts):", "if False:"),
    ("a folder is taken for regulated data by a part of a word", 'return bool({"regulated", "customers"} & set(re.split(r"[^a-z0-9]+", name.lower())))',
     'return any(w in name.lower() for w in ("regulated", "customers"))'),
    ("what looks like a secret is kept in a request", 'return SECRET_SHAPES.sub("[redacted]", intent)[:limit]', "return intent[:limit]"),
    ("a request is kept without a limit of length", 'return SECRET_SHAPES.sub("[redacted]", intent)[:limit]', 'return SECRET_SHAPES.sub("[redacted]", intent)'),
    ("a run counts as the path whatever environment it names", 'elif claimed.get("id") and claimed.get("template_sha256") in made_templates:', 'elif claimed.get("id"):'),
    ("a usage log of the store that does not verify is counted", '            if bad:\n                problems.append(f"{key}: {bad[0]}")', '            if False:\n                problems.append(f"{key}: {bad[0]}")'),
    ("a name that is not usable is accepted", 'if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", env_id):', "if False:"),
    ("a service starts paid infrastructure without asking", "    if not args.yes:", "    if False:"),
    ("a service starts with a task running by default", """f"desired_count={'1' if running else '0'}\"""", '"desired_count=1"'),
    ("a road that lost its defaults is used anyway", '    if problems:\n        log.append("road_refused"', '    if False:\n        log.append("road_refused"'),
    ("the chain of the usage log is not checked", 'if rec.get("prev") != prev:', "if False:"),
    ("an altered usage record is not detected", 'if audit.sha256_hex(audit.canonical(body)) != rec.get("sha256"):', "if False:"),
    ("the numbering of the usage log is not checked", 'if rec.get("seq") != index:', "if False:"),
    ("runs that test the platform are counted as going around the path", "if workflow in PLATFORM_TEST_WORKFLOWS:", "if False:"),
    ("a usage log that does not verify is published", '    if problems:\n        out(f"Refusing to publish', '    if False:\n        out(f"Refusing to publish'),
    ("a report is made from a usage log that does not verify", '            if problems:\n                out(f"The usage log {path} does not verify', '            if False:\n                out(f"The usage log {path} does not verify'),
]


def run_tests(directory: Path) -> bool:
    done = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(directory)],
        capture_output=True, text=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}, check=False,
    )
    return done.returncode == 0


def main() -> int:
    if not run_tests(HERE):
        print("the tests do not pass on the real code: fix them before testing the tests")
        return 1
    source = (HERE / "golden_path.py").read_text(encoding="utf-8")
    missed, caught = [], 0
    for name, old, new in MUTANTS:
        if old not in source:
            print(f"CANNOT APPLY  {name} (the code it weakens has changed: update this list)")
            missed.append(name)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for shared in SHARED:
                shutil.copytree(ROOT / shared, root / shared, ignore=shutil.ignore_patterns("__pycache__", "out*"))
            shutil.copytree(HERE, root / "golden-path", ignore=shutil.ignore_patterns("__pycache__", "environments", "out"))
            (root / "golden-path" / "golden_path.py").write_text(source.replace(old, new, 1), encoding="utf-8")
            if run_tests(root / "golden-path"):
                print(f"NOT CAUGHT    {name}")
                missed.append(name)
            else:
                caught += 1
                print(f"caught        {name}")
    print(f"\n{caught} of {len(MUTANTS)} weakened versions were caught by the tests.")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
