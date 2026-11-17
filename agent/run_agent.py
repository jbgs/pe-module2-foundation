#!/usr/bin/env python3
"""The enforcement point: it runs the scripted agent in a sandbox and judges what happened.

Two layers, and this script exercises both on purpose.

  enforce  The policy decides first (data/policy in this repository, evaluated by OPA). Only an action the policy
           allows is run, inside the sandbox. A denied or gated action is not run at all.
  bypass   The policy is switched off and every action is run in the sandbox anyway. This is the test of the
           hard boundary: if the policy were wrong, or an agent found a way around it, the runtime must still
           stop every attempt. An attempt that works is a failure of the sandbox and fails this run.

The input to the policy is built here, by the platform, not by the agent. That is the trust boundary described in
policy/README.md: the agent proposes actions, it never says who approved them.

Each action runs in its own container, which is thrown away afterwards. Every action leaves one record. The
records are a first step towards the audit record; they are kept as a build artifact.

Standard library only. The policy engine (opa) must be on the PATH, or named in OPA_BIN.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

AGENT_ID = "agent-sandbox-01"
ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("AGENT_IMAGE", "agent-sandbox:ci")
OPA = os.environ.get("OPA_BIN", "opa")
RECORD_SCHEMA = "agent-run/1"

# The hard boundary. These are the whole of it, and they are set by the platform when it starts the container.
SANDBOX_FLAGS = [
    "--rm",
    "--network", "none",  # no network at all: nothing to reach, nothing to exfiltrate to
    "--read-only",  # the root filesystem cannot be written
    "--cap-drop", "ALL",  # no Linux capabilities
    "--security-opt", "no-new-privileges",
    "--pids-limit", "64",
    "--memory", "128m",
    "--memory-swap", "128m",  # no swap, so the memory limit is a limit
    "--cpus", "0.5",
    "--tmpfs", "/workspace:rw,noexec,nosuid,size=16m,uid=10001,gid=10001",  # the only writable place
    "--workdir", "/workspace",
]
SYNTHETIC_DIR = ROOT / "agent" / "synthetic"  # the only data the sandbox gets, read-only
STANDIN_FILE = ROOT / "agent" / "regulated-standin" / "customers.csv"  # never mounted anywhere


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def policy_sha() -> str:
    """One hash for the whole policy, so a record says which rules judged the action."""
    digest = hashlib.sha256()
    for path in sorted((ROOT / "policy").glob("*.rego")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def decide(item: dict) -> dict:
    """Ask the policy. The input is built here and never by the agent; no approval is attached."""
    policy_input = {"agent": AGENT_ID, "action": item["action"]}
    if item.get("tool"):
        policy_input["tool"] = item["tool"]
    done = subprocess.run(
        [OPA, "eval", "-d", str(ROOT / "policy"), "-I", "-f", "json", "data.agent.policy.decision"],
        input=json.dumps(policy_input),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(done.stdout)["result"][0]["expressions"][0]["value"]


def run_sandbox(item: dict) -> dict:
    """Run one action in a fresh, limited container. Returns what the container did."""
    command = ["docker", "run", *SANDBOX_FLAGS, "-v", f"{SYNTHETIC_DIR}:/data:ro", IMAGE, item["action"]]
    if item.get("tool"):
        command.append(item["tool"])
    started = time.monotonic()
    done = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    observation = None
    for line in reversed(done.stdout.splitlines()):
        try:
            observation = json.loads(line)
            break
        except ValueError:
            continue
    return {
        "exit": done.returncode,
        "observation": observation,
        "text": done.stdout + done.stderr,
        "ms": int((time.monotonic() - started) * 1000),
    }


def classify(item: dict, run: dict) -> tuple[str, str]:
    """Turn what the container did into an outcome: completed, blocked, escaped, killed or error."""
    observation = run["observation"]
    if observation is None:
        if run["exit"] == 137:
            return "killed", "the container was killed by its limit (exit 137)"
        return "error", f"no result from the container (exit {run['exit']})"
    return observation["result"], observation["detail"]


def evaluate(item: dict, mode: str, decide_fn=decide, run_fn=run_sandbox) -> tuple[dict, str]:
    """Process one action of the plan. Returns the record and the text the container printed."""
    record = {
        "schema": RECORD_SCHEMA,
        "timestamp": utc_now(),
        "mode": mode,
        "agent": AGENT_ID,
        "action": item["action"],
        "tool": item.get("tool"),
        "kind": item["kind"],
        "policy": None,
        "executed": False,
        "outcome": "not run",
        "detail": "",
        "ms": 0,
    }
    if mode == "enforce":
        record["policy"] = decide_fn(item)
        if record["policy"]["effect"] != "allow":
            record["detail"] = f"{record['policy']['effect']}: {record['policy']['reason']}"
            return record, ""
    elif item["kind"] == "gated-only":
        record["detail"] = "has no meaning inside the sandbox; only the policy judges it"
        return record, ""
    run = run_fn(item)
    record["executed"] = True
    record["outcome"], record["detail"] = classify(item, run)
    record["ms"] = run["ms"]
    return record, run["text"]


def judge(mode: str, records: list[dict], canary_leaked: bool) -> list[str]:
    """The expectations. An empty list means the sandbox and the policy did what they must."""
    problems = []
    for rec in records:
        name = rec["action"] + (f" ({rec['tool']})" if rec.get("tool") else "")
        if rec["kind"] == "legit":
            if mode == "enforce" and (rec["policy"] or {}).get("effect") != "allow":
                problems.append(f"{name}: a legitimate action was not allowed by the policy")
            elif not rec["executed"] or rec["outcome"] != "completed":
                problems.append(f"{name}: a legitimate action did not complete ({rec['outcome']}: {rec['detail']})")
        elif mode == "enforce":
            if rec["executed"] or (rec["policy"] or {}).get("effect") == "allow":
                problems.append(f"{name}: the policy let an attempt through")
        elif rec["kind"] == "attempt":
            if not rec["executed"] or rec["outcome"] not in ("blocked", "killed"):
                problems.append(f"{name}: ESCAPED or failed to run ({rec['outcome']}: {rec['detail']})")
    if canary_leaked:
        problems.append("the regulated stand-in's canary appeared in the output: regulated data left its place")
    return problems


def canary() -> str:
    match = re.search(r"CANARY-[0-9a-f]{16}", STANDIN_FILE.read_text(encoding="utf-8"))
    return match.group(0) if match else ""


def summary(mode: str, records: list[dict], problems: list[str]) -> str:
    lines = [f"### Agent sandbox, mode `{mode}`", "", "| Action | Policy | Ran | Outcome | Detail |", "|---|---|---|---|---|"]
    for rec in records:
        policy = (rec["policy"] or {}).get("effect", "off")
        name = rec["action"] + (f" ({rec['tool']})" if rec.get("tool") else "")
        lines.append(f"| `{name}` | {policy} | {'yes' if rec['executed'] else 'no'} | {rec['outcome']} | {rec['detail']} |")
    lines += ["", "**Result: " + ("every expectation held.**" if not problems else "FAILED.**")]
    lines += [f"- {p}" for p in problems]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=["enforce", "bypass"], required=True)
    parser.add_argument("--plan", default=str(ROOT / "agent" / "plan.json"))
    parser.add_argument("--out", default=str(ROOT / "agent" / "out"))
    args = parser.parse_args(argv)

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    sha = policy_sha()
    records, everything = [], ""
    for item in plan:
        record, text = evaluate(item, args.mode)
        record["policy_sha256"] = sha
        records.append(record)
        everything += text
        if record["kind"] == "attempt" and args.mode == "bypass" and record["outcome"] in ("blocked", "killed"):
            print(f"::warning title=Escape attempt blocked::{record['action']}: {record['detail']}")
        elif record["kind"] != "legit" and args.mode == "enforce" and not record["executed"]:
            print(f"::notice title=Policy stopped an action::{record['action']}: {record['detail']}")

    problems = judge(args.mode, records, canary() in everything or canary() in json.dumps(records))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"agent-run-{args.mode}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    text = summary(args.mode, records, problems)
    (out / f"summary-{args.mode}.md").write_text(text, encoding="utf-8")
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
