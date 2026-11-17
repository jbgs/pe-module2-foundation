#!/usr/bin/env python3
"""The enforcement point: it runs the scripted agent in a sandbox and judges what happened.

Two layers, and this script exercises both on purpose.

  enforce  The policy decides first (data/policy in this repository, evaluated by OPA). Only an action the policy
           allows is run, inside the sandbox. A denied or gated action is not run at all.
  bypass   The policy is switched off and every action is run in the sandbox anyway. This is the test of the
           hard boundary: if the policy were wrong, or an agent found a way around it, the runtime must still
           stop every attempt. An attempt that works is a failure of the sandbox and fails this run.
  weakening  The negative controls. Each limit is removed in turn, and the attempt it holds back must then
           escape. This shows that every limit is what stops its attempt, and that this test can fail.

The input to the policy is built here, by the platform, not by the agent. That is the trust boundary described in
policy/README.md: the agent proposes actions, it never says who approved them. A person's approval of a gated
action reaches this script as a file (--approval) that a platform step wrote after reading it from GitHub; it names
one action, and it is attached to that action and to no other.

Each action runs in its own container, which is thrown away afterwards. Every action the agent proposes, run or
not, leaves one record in an audit log whose records are chained by hashes (agent/audit.py). The log is checked
at once by the audit gate (agent/audit_verify.py) and kept as a build artifact with its manifest.

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

import audit
import audit_verify

AGENT_ID = "agent-sandbox-01"
ROOT = Path(__file__).resolve().parent.parent
IMAGE = os.environ.get("AGENT_IMAGE", "agent-sandbox:ci")
OPA = os.environ.get("OPA_BIN", "opa")
RECORD_SCHEMA = "agent-run/1"

# The hard boundary. These are the whole of it, and they are set by the platform when it starts the container.
FIXED_FLAGS = [
    "--rm",
    "--cpus", "0.5",
    "--tmpfs", "/workspace:rw,noexec,nosuid,size=16m,uid=10001,gid=10001",  # the only writable place
    "--workdir", "/workspace",
]
# Each limit is a group, so the test can take one away and check that it was the one holding something back.
FLAG_GROUPS = {
    "network": ["--network", "none"],  # no network at all: nothing to reach, nothing to exfiltrate to
    "readonly": ["--read-only"],  # the root filesystem cannot be written
    "privilege": ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"],  # no capabilities, no new privilege
    "pids": ["--pids-limit", "64"],
    "memory": ["--memory", "128m", "--memory-swap", "128m"],  # no swap, so the memory limit is a limit
}
# What each limit is replaced with when the test removes it. "privilege" becomes root with the default capabilities.
WEAKENED = {"network": ["--network", "bridge"], "readonly": [], "privilege": ["--user", "0"], "pids": [], "memory": []}
# The negative controls: remove one limit, and this attempt must then escape. If it does not, that limit is not what
# was stopping it, or the test cannot see it.
CONTROLS = [
    ("network", "network_egress"),
    ("readonly", "write_outside_workspace"),
    ("pids", "resource_pids"),
    ("memory", "resource_memory"),
    ("privilege", "privileged_exec"),
    ("data", "read_regulated_data"),
]
SYNTHETIC_DIR = ROOT / "agent" / "synthetic"  # the only data the sandbox gets, read-only
POLICY_DIR = ROOT / "policy"  # the rules that judge each action
STANDIN_FILE = ROOT / "agent" / "regulated-standin" / "customers.csv"  # never mounted anywhere (except by the control)


def sandbox_flags(weaken: str | None = None) -> list[str]:
    flags = list(FIXED_FLAGS)
    for name, group in FLAG_GROUPS.items():
        flags += WEAKENED[name] if weaken == name else group
    return flags


def sandbox_mounts(weaken: str | None = None) -> list[str]:
    mounts = ["-v", f"{SYNTHETIC_DIR}:/data:ro"]
    if weaken == "data":
        mounts += ["-v", f"{STANDIN_FILE.parent}:/regulated:ro"]
    return mounts


SANDBOX_FLAGS = sandbox_flags()


def limits_description(weaken: str | None = None) -> list[str]:
    """The limits as they go in a record: the flags, and the mounts with paths that do not depend on the machine."""
    mounts = ["-v", "agent/synthetic:/data:ro"]
    if weaken == "data":
        mounts += ["-v", "agent/regulated-standin:/regulated:ro"]
    return sandbox_flags(weaken) + mounts


def flags_sha256(weaken: str | None = None) -> str:
    return audit.sha256_hex(" ".join(limits_description(weaken)).encode("utf-8"))


def engine_version() -> str:
    try:
        done = subprocess.run([OPA, "version"], capture_output=True, text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError):
        return "opa (unavailable)"
    match = re.search(r"Version:\s*(\S+)", done.stdout)
    return f"opa {match.group(1)}" if match else "opa (unknown version)"


def image_id() -> str | None:
    try:
        done = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE],
            capture_output=True, text=True, timeout=20, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() or None


def check_data_dir(path: Path) -> None:
    """The sandbox is given synthetic data only. A folder that looks like regulated data is refused, whoever asks."""
    names = [p.name.lower() for p in path.rglob("*") if p.is_file()]
    if "regulated" in str(path).lower() or any("customers.csv" in n or "regulated" in n for n in names):
        raise SystemExit(f"refusing to mount {path}: it looks like regulated data, and the sandbox gets synthetic data only")
    if not names:
        raise SystemExit(f"refusing to mount {path}: it holds no data")


def start_log(mode: str, plan_bytes: bytes, sha: str, engine: str, out: Path | None = None, label: str | None = None,
              environment: str | None = None) -> audit.AuditLog:
    env = os.environ
    if env.get("GITHUB_RUN_ID"):
        run_id = f"{env['GITHUB_RUN_ID']}-{env.get('GITHUB_RUN_ATTEMPT', '1')}-{mode}"
    else:
        run_id = f"local-{int(time.time())}-{mode}"
    if label:
        run_id += f"-{label}"  # two logs of the same mode in one workflow run must not share an identity
    log = audit.AuditLog(run_id, mode, sink=(out / f"audit-{mode}.jsonl") if out else None)
    log.append(
        "run_started",
        agent={"id": AGENT_ID, "kind": "scripted"},
        principal=audit.principal_from_env(),
        source=audit.source_from_env(),
        plan_sha256=audit.sha256_hex(plan_bytes),
        policy_sha256=sha,
        policy_engine=engine,
        sandbox={"image_id": image_id(), "limits": limits_description(), "flags_sha256": flags_sha256()},
        # The environment of the golden path that this run belongs to. A run without one is going around the path.
        environment={"id": environment} if environment else None,
    )
    return log


def audit_action(log: audit.AuditLog, rec: dict, sha: str, engine: str, weaken: str | None = None) -> dict:
    """One action, as the audit record says it: the request, the rules that judged it, the approval, the result."""
    request = {"action": rec["action"], "tool": rec.get("tool")}
    policy = rec["policy"] or {
        "effect": "bypassed",
        "class": None,
        "reason": "the policy is switched off in this mode, to test the sandbox on its own",
    }
    policy = {**policy, "policy_sha256": sha, "engine": engine}
    gated = policy["effect"] == "gate"
    approval = {
        "required": gated,
        "status": "pending" if gated else "not_required",
        "approver": None,
        "decided_at": None,
        "source": None,
        "evidence": None,
    }
    given = rec.get("approval")
    if given and policy["effect"] == "allow" and policy.get("class") == "human-gated":
        approval = {
            "required": True,
            "status": "approved",
            "approver": given["approver"],
            "decided_at": given["decided_at"],
            "source": given["source"],
            "evidence": given["evidence"],
        }
    execution = {
        "executed": rec["executed"],
        "outcome": rec["outcome"],
        "detail": rec["detail"],
        "duration_ms": rec["ms"],
        "flags_sha256": flags_sha256(weaken) if rec["executed"] else None,
    }
    return log.append(
        "action",
        agent={"id": AGENT_ID, "kind": "scripted"},
        request=request,
        request_sha256=audit.sha256_hex(audit.canonical(request)),
        policy=policy,
        approval=approval,
        execution=execution,
    )


def finish_log(log: audit.AuditLog) -> None:
    actions = [r for r in log.records if r["event"] == "action"]
    effects = [r["policy"]["effect"] for r in actions]
    log.append(
        "run_finished",
        summary={
            "actions": len(actions),
            "executed": sum(bool(r["execution"]["executed"]) for r in actions),
            "allowed": effects.count("allow"),
            "gated": effects.count("gate"),
            "denied": effects.count("deny"),
            "bypassed": effects.count("bypassed"),
        },
    )


def write_audit(out: Path, log: audit.AuditLog) -> str:
    """The log is already on disk if it had a sink; the manifest is written once the run is finished."""
    out.mkdir(parents=True, exist_ok=True)
    if log.sink is None:
        (out / f"audit-{log.mode}.jsonl").write_text(log.text(), encoding="utf-8")
    manifest = log.manifest()
    (out / f"audit-{log.mode}.manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return f"\nAudit log: {manifest['records']} records, head `{manifest['head_sha256']}`.\n"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def policy_sha() -> str:
    """One hash for the whole policy, so a record says which rules judged the action."""
    digest = hashlib.sha256()
    for path in sorted(POLICY_DIR.glob("*.rego")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


APPROVAL_KEYS = ("action", "approver", "approved", "decided_at", "source", "evidence")


def load_approval(path: str) -> dict:
    """The approval that the platform read from GitHub. It is refused unless it is complete and positive."""
    approval = json.loads(Path(path).read_text(encoding="utf-8"))
    absent = [key for key in APPROVAL_KEYS if not approval.get(key) and key != "approved"]
    if absent or approval.get("approved") is not True:
        raise SystemExit(f"the approval file is not a complete, positive approval (missing: {absent or 'none'})")
    return approval


def decide(item: dict, approval: dict | None = None) -> dict:
    """Ask the policy. The input is built here and never by the agent. An approval is attached only if the caller
    has one for this very action."""
    policy_input = {"agent": AGENT_ID, "action": item["action"]}
    if item.get("tool"):
        policy_input["tool"] = item["tool"]
    if approval:
        policy_input["approval"] = {"approver": approval["approver"], "approved": approval["approved"]}
    done = subprocess.run(
        [OPA, "eval", "-d", str(POLICY_DIR), "-I", "-f", "json", "data.agent.policy.decision"],
        input=json.dumps(policy_input),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(done.stdout)["result"][0]["expressions"][0]["value"]


def run_sandbox(item: dict, weaken: str | None = None) -> dict:
    """Run one action in a fresh, limited container. Returns what the container did."""
    command = ["docker", "run", *sandbox_flags(weaken), *sandbox_mounts(weaken), IMAGE, item["action"]]
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


def evaluate(item: dict, mode: str, decide_fn=decide, run_fn=run_sandbox, approval: dict | None = None) -> tuple[dict, str]:
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
        # An approval names one action. It is given to that action and to no other, so approving the export of a
        # result does not unlock a change of the policy.
        mine = approval if approval and approval["action"] == item["action"] else None
        record["policy"] = decide_fn(item, mine) if mine else decide_fn(item)
        if mine and record["policy"]["effect"] == "allow" and record["policy"].get("class") == "human-gated":
            record["approval"] = mine
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
    output = (run["observation"] or {}).get("output")
    if output is not None:
        record["output"] = output
        record["detail"] += f" [output sha256 {audit.sha256_hex(output.encode('utf-8'))}]"
    return record, run["text"]


def judge(mode: str, records: list[dict], canary_leaked: bool, approved: frozenset | set = frozenset()) -> list[str]:
    """The expectations. An empty list means the sandbox and the policy did what they must."""
    problems = []
    for rec in records:
        name = rec["action"] + (f" ({rec['tool']})" if rec.get("tool") else "")
        if rec["kind"] == "gated":
            # Runs only with a person's approval. Without the policy (bypass) it is only an action inside the sandbox.
            effect = (rec["policy"] or {}).get("effect")
            if mode == "enforce" and rec["action"] in approved:
                if effect != "allow" or not rec["executed"] or rec["outcome"] != "completed":
                    problems.append(f"{name}: approved, but it did not run to completion ({effect}, {rec['outcome']})")
                if (rec.get("approval") or {}).get("action") != rec["action"]:
                    problems.append(f"{name}: it ran with no approval attached to it")
            elif mode == "enforce":
                if rec["executed"] or effect == "allow":
                    problems.append(f"{name}: it ran, or was allowed, without a person's approval")
            elif not rec["executed"] or rec["outcome"] != "completed":
                problems.append(f"{name}: did not complete inside the sandbox ({rec['outcome']}: {rec['detail']})")
        elif rec["kind"] == "legit":
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


def export_approved(out: Path, records: list[dict]) -> bool:
    """What leaves the sandbox: only a result whose export a person approved, and exactly what the record hashes."""
    for rec in records:
        if rec["action"] == "export_result" and rec["executed"] and rec["outcome"] == "completed" \
                and rec.get("output") and rec.get("approval"):
            (out / "exported-result.txt").write_text(rec["output"] + "\n", encoding="utf-8")
            return True
    return False


def export_if_clean(out: Path, records: list[dict], problems: list[str]) -> bool:
    """A result is written out only if the run passed its own checks: a run that failed them exports nothing."""
    return False if problems else export_approved(out, records)


def judge_controls(records: list[dict]) -> list[str]:
    """The negative controls: with one limit removed, the attempt it held back must now escape."""
    problems = []
    for rec in records:
        if rec["outcome"] != "escaped":
            problems.append(
                f"without `{rec['weakened']}`, {rec['action']} was still {rec['outcome']}: "
                f"that limit is not what stops it, or the test cannot see it"
            )
    return problems


def canary() -> str:
    match = re.search(r"CANARY-[0-9a-f]{16}", STANDIN_FILE.read_text(encoding="utf-8"))
    return match.group(0) if match else ""


def controls_summary(records: list[dict], problems: list[str]) -> str:
    lines = [
        "### Agent sandbox, negative controls",
        "",
        "Each limit is removed in turn. The attempt it holds back must then escape, which shows the test can fail.",
        "",
        "| Limit removed | Attempt | Outcome | Detail |",
        "|---|---|---|---|",
    ]
    for rec in records:
        lines.append(f"| `{rec['weakened']}` | `{rec['action']}` | {rec['outcome']} | {rec['detail']} |")
    lines += ["", "**Result: " + ("every limit is load-bearing.**" if not problems else "FAILED.**")]
    lines += [f"- {p}" for p in problems]
    return "\n".join(lines) + "\n"


def summary(mode: str, records: list[dict], problems: list[str]) -> str:
    lines = [f"### Agent sandbox, mode `{mode}`", "", "| Action | Policy | Ran | Outcome | Detail |", "|---|---|---|---|---|"]
    for rec in records:
        policy = (rec["policy"] or {}).get("effect", "off")
        name = rec["action"] + (f" ({rec['tool']})" if rec.get("tool") else "")
        lines.append(f"| `{name}` | {policy} | {'yes' if rec['executed'] else 'no'} | {rec['outcome']} | {rec['detail']} |")
    lines += ["", "**Result: " + ("every expectation held.**" if not problems else "FAILED.**")]
    lines += [f"- {p}" for p in problems]
    return "\n".join(lines) + "\n"


def run_controls(out: Path, sha: str, engine: str) -> int:
    plan = [{"action": action} for _, action in CONTROLS]
    log = start_log("weakening", json.dumps(plan).encode("utf-8"), sha, engine, out)
    records = []
    for weaken, action in CONTROLS:
        item = {"action": action, "kind": "attempt"}
        record, _ = evaluate(item, "weakening", run_fn=lambda it, w=weaken: run_sandbox(it, w))
        record["weakened"] = weaken
        record["policy_sha256"] = sha
        records.append(record)
        audit_action(log, record, sha, engine, weaken)
    finish_log(log)
    problems = judge_controls(records) + audit_verify.verify(log.records, log.manifest(), plan)
    out.mkdir(parents=True, exist_ok=True)
    (out / "plan-weakening.json").write_text(json.dumps(plan), encoding="utf-8")
    text = controls_summary(records, problems) + write_audit(out, log)
    (out / "summary-weakening.md").write_text(text, encoding="utf-8")
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text)
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=["enforce", "bypass", "weakening"], required=True)
    parser.add_argument("--plan", default=str(ROOT / "agent" / "plan.json"))
    parser.add_argument("--out", default=str(ROOT / "agent" / "out"))
    parser.add_argument("--approval", help="an approval of one gated action, read from GitHub by a platform step")
    parser.add_argument("--label", help="a name for this log within its workflow run (it becomes part of the run id)")
    parser.add_argument("--environment", help="the id of the golden-path environment this run belongs to")
    parser.add_argument("--data", help="the synthetic data to mount (default: agent/synthetic)")
    parser.add_argument("--policy-dir", help="the policy to judge with (default: policy/)")
    args = parser.parse_args(argv)
    if args.approval and args.mode != "enforce":
        parser.error("--approval only makes sense in enforce mode: that is where the policy decides")

    global SYNTHETIC_DIR, POLICY_DIR
    if args.data:
        SYNTHETIC_DIR = Path(args.data).resolve()
    if args.policy_dir:
        POLICY_DIR = Path(args.policy_dir).resolve()
    check_data_dir(SYNTHETIC_DIR)
    sha, engine = policy_sha(), engine_version()
    if args.mode == "weakening":
        return run_controls(Path(args.out), sha, engine)
    plan_bytes = Path(args.plan).read_bytes()
    plan = json.loads(plan_bytes.decode("utf-8"))
    approval = load_approval(args.approval) if args.approval else None
    log = start_log(args.mode, plan_bytes, sha, engine, Path(args.out), args.label, args.environment)
    records, everything = [], ""
    for item in plan:
        record, text = evaluate(item, args.mode, approval=approval)
        record["policy_sha256"] = sha
        records.append(record)
        audit_action(log, record, sha, engine)
        everything += text
        if record["kind"] == "attempt" and args.mode == "bypass" and record["outcome"] in ("blocked", "killed"):
            print(f"::warning title=Escape attempt blocked::{record['action']}: {record['detail']}")
        elif record["kind"] != "legit" and args.mode == "enforce" and not record["executed"]:
            print(f"::notice title=Policy stopped an action::{record['action']}: {record['detail']}")

    finish_log(log)
    leaked = canary() in everything or canary() in json.dumps(records) or canary() in log.text()
    approved = {approval["action"]} if approval else set()
    problems = judge(args.mode, records, leaked, approved) + audit_verify.verify(log.records, log.manifest(), plan)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    export_if_clean(out, records, problems)
    text = summary(args.mode, records, problems) + write_audit(out, log)
    (out / f"summary-{args.mode}.md").write_text(text, encoding="utf-8")
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
