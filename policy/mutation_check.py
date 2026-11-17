#!/usr/bin/env python3
"""A test of the tests: weaken the agent policy on purpose, and require the tests to notice.

Each mutant is a copy of `agent.rego` with one rule weakened (an agent may approve its own action, a forbidden
action is no longer classified, the default allows, and so on). `opa test` is run against it. A mutant that the tests
do not catch is a rule that nobody is checking.

    python3 policy/mutation_check.py

Exit status 0 means every mutant was caught. Needs `opa` on the PATH, or named in OPA_BIN. Standard library only.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OPA = os.environ.get("OPA_BIN", "opa")

# (what is weakened, the code as it is, the code weakened)
MUTANTS = [
    ("an agent may approve its own action", "\tinput.approval.approver != input.agent\n", ""),
    ("an approver outside the list passes", "\tinput.approval.approver in approvers\n", ""),
    ("a negative approval passes", "\tinput.approval.approved == true\n", ""),
    ("forbidden actions are no longer classified", "\tinput.action in forbidden_actions\n}", '\tinput.action in {"x"}\n}'),
    ("modify_policy is no longer gated", '\t"export_result",\n\t"modify_policy",\n}', '\t"export_result",\n}'),
    ("export_result is no longer gated", '\t"deploy_dev",\n\t"export_result",\n', '\t"deploy_dev",\n'),
    ("an out-of-scope tool is never denied", "\tnot tool_in_scope\n", "\tfalse\n"),
    ("the default allows", '"effect": "deny",\n\t"class": "unlisted"', '"effect": "allow",\n\t"class": "unlisted"'),
    ("the tool scope check always passes", "\ttool_in_scope\n}", "\ttrue\n}"),
    ("the tool scope helper is always true", "tool_in_scope if input.tool in approved_tools", "tool_in_scope if true"),
    ("a denied tool is recorded as autonomous", '"class": "forbidden",\n\t"reason": "tool is not', '"class": "autonomous",\n\t"reason": "tool is not'),
    ("the default is classified as forbidden", '"class": "unlisted",\n\t"reason": "default deny', '"class": "forbidden",\n\t"reason": "default deny'),
]


def tests_pass(directory: Path) -> bool:
    return subprocess.run([OPA, "test", str(directory)], capture_output=True, check=False).returncode == 0


def main() -> int:
    if not tests_pass(HERE):
        print("the tests do not pass on the real policy: fix them before testing the tests")
        return 1
    source = (HERE / "agent.rego").read_text(encoding="utf-8")
    missed, caught = [], 0
    for name, old, new in MUTANTS:
        if old not in source:
            print(f"CANNOT APPLY  {name} (the code it weakens has changed: update this list)")
            missed.append(name)
            continue
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "policy"
            copy.mkdir()
            shutil.copy(HERE / "agent_test.rego", copy)
            (copy / "agent.rego").write_text(source.replace(old, new, 1), encoding="utf-8")
            if tests_pass(copy):
                print(f"NOT CAUGHT    {name}")
                missed.append(name)
            else:
                caught += 1
                print(f"caught        {name}")
    print(f"\n{caught} of {len(MUTANTS)} weakened versions were caught by the tests.")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
