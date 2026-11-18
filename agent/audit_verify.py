#!/usr/bin/env python3
"""The audit gate: refuses a log of agent actions that is incomplete, inconsistent or altered.

    audit_verify.py LOG [--manifest MANIFEST] [--expect PLAN]

Exit status 0 means the log is complete, consistent and its chain is intact. Anything else exits 1 and says why.
The checks, in the order they are made:

  structure     every record has the fields its event requires
  chain         each record's hash is right and points at the one before; the first points at its run
  order         one run_started first, one run_finished last, numbers 0, 1, 2, ... without a gap
  consistency   what the records say agrees with itself: an action ran only if the policy allowed it, a gated
                action has a pending approval, an approved one names an approver who is not the agent, and so on
  manifest      the number of records and the head hash agree with the manifest (this is what catches a log that
                was cut short or rewritten from start to end)
  expectation   every action of the plan is recorded, once, in order

Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import audit

HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMON = ("schema", "seq", "event", "run_id", "mode", "timestamp", "chain")
REQUIRED = {
    "run_started": ("agent", "principal", "source", "plan_sha256", "policy_sha256", "policy_engine", "sandbox"),
    "action": ("agent", "request", "request_sha256", "policy", "approval", "execution"),
    "run_finished": ("summary",),
}
POLICY_KEYS = ("effect", "class", "reason", "policy_sha256", "engine")
APPROVAL_KEYS = ("required", "status", "approver", "decided_at", "source", "evidence")
EXECUTION_KEYS = ("executed", "outcome", "detail", "duration_ms", "flags_sha256")
SUMMARY_KEYS = ("actions", "executed", "allowed", "gated", "denied", "bypassed")
EFFECTS = ("allow", "gate", "deny", "bypassed")


def load_records(path) -> list[dict]:
    records = []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            try:
                records.append(json.loads(line))
            except ValueError:
                records.append({"_unreadable_line": number})
    return records


def missing(obj, keys) -> list[str]:
    return [key for key in keys if not isinstance(obj, dict) or key not in obj]


ALERT_SEVERITIES = ("warning", "critical")


def check_alert(rec: dict, where: str) -> list[str]:
    """A log that says it alerts must alert on every attempt that was stopped, and say 'critical' when one got out."""
    outcome, effect = rec["execution"]["outcome"], rec["policy"]["effect"]
    alert = rec.get("alert")
    if outcome == "escaped":
        wanted = "critical"
    elif outcome in ("blocked", "killed") or effect == "deny":
        wanted = "warning"
    else:
        wanted = None
    if wanted is None:
        return [f"{where}: an alert for something that needed none"] if alert is not None else []
    if not isinstance(alert, dict) or not alert.get("why"):
        return [f"{where}: {outcome if outcome != 'not run' else effect}, with no alert"]
    if alert.get("severity") != wanted:
        return [f"{where}: the alert says {alert.get('severity')!r}, and it should say {wanted!r}"]
    return []


def check_action(rec: dict, mode: str, agent_id: str, policy_sha: str, alerting: bool = False) -> list[str]:
    where = f"seq {rec['seq']} ({(rec['request'] or {}).get('action')})"
    problems = []
    for name, keys in (("policy", POLICY_KEYS), ("approval", APPROVAL_KEYS), ("execution", EXECUTION_KEYS)):
        absent = missing(rec[name], keys)
        if absent:
            problems.append(f"{where}: {name} lacks {', '.join(absent)}")
    if problems:
        return problems
    policy, approval, execution = rec["policy"], rec["approval"], rec["execution"]
    effect = policy["effect"]
    if effect not in EFFECTS:
        return [f"{where}: unknown policy effect {effect!r}"]
    if (mode == "enforce") == (effect == "bypassed"):
        problems.append(f"{where}: effect {effect!r} does not fit mode {mode!r}")
    if audit.sha256_hex(audit.canonical(rec["request"])) != rec["request_sha256"]:
        problems.append(f"{where}: the request does not match its hash")
    if policy["policy_sha256"] != policy_sha:
        problems.append(f"{where}: judged by a different policy than the run started with")
    if not isinstance(execution["executed"], bool):
        problems.append(f"{where}: executed is not true or false")
    elif execution["executed"]:
        if effect in ("gate", "deny"):
            problems.append(f"{where}: ran although the policy said {effect}")
        if not HEX64.match(str(execution["flags_sha256"])):
            problems.append(f"{where}: ran with no record of the sandbox limits")
    elif effect == "allow":
        problems.append(f"{where}: allowed, with no record that it ran")
    gated_class = policy["class"] == "human-gated"
    if effect == "gate":
        ok = approval["required"] is True and approval["status"] == "pending" and approval["approver"] is None
        if not ok:
            problems.append(f"{where}: gated, but its approval is not recorded as pending")
    elif effect == "allow" and gated_class:
        ok = (
            approval["required"] is True
            and approval["status"] == "approved"
            and approval["approver"]
            and approval["approver"] != agent_id
            and approval["decided_at"]
            and approval["source"]
            and approval["evidence"]
        )
        if not ok:
            problems.append(f"{where}: a human-gated action ran without an approval from someone other than the agent")
    elif approval["required"] is not False or approval["status"] != "not_required":
        problems.append(f"{where}: an approval is recorded for an action that needs none")
    if alerting:
        problems += check_alert(rec, where)
    return problems


def verify(records: list[dict], manifest: dict | None = None, plan: list[dict] | None = None) -> list[str]:
    if not records:
        return ["the log is empty"]
    problems = []

    # structure
    for index, rec in enumerate(records):
        if not isinstance(rec, dict):
            problems.append(f"record {index} is not an object")
            continue
        if "_unreadable_line" in rec:
            problems.append(f"line {rec['_unreadable_line']} is not readable")
            continue
        absent = missing(rec, COMMON)
        if not absent:
            absent = missing(rec, REQUIRED.get(rec["event"], ("event is not one of the known ones",)))
        if absent:
            problems.append(f"record {index}: lacks {', '.join(absent)}")
            continue
        chain = rec["chain"]
        if not isinstance(chain, dict) or not all(isinstance(chain.get(k), str) for k in ("prev", "sha256")):
            problems.append(f"record {index}: the chain field is malformed")
        for key in ("agent", "principal", "source", "sandbox", "request", "policy", "approval", "execution", "summary"):
            if key in rec and not isinstance(rec[key], dict):
                problems.append(f"record {index}: {key} is not an object")
    if problems:
        return problems  # nothing below is safe to read from a log of this shape

    first = records[0]
    run_id, mode = first["run_id"], first["mode"]

    # chain, order, identity
    expected_prev = audit.genesis(run_id)
    for index, rec in enumerate(records):
        if rec["schema"] != audit.SCHEMA:
            problems.append(f"seq {index}: unknown schema {rec['schema']!r}")
        if rec["seq"] != index:
            problems.append(f"record {index} is numbered {rec['seq']}: a record was removed, added or moved")
        if rec["run_id"] != run_id or rec["mode"] != mode:
            problems.append(f"seq {index}: belongs to another run or mode")
        if rec["chain"].get("prev") != expected_prev:
            problems.append(f"seq {index}: the chain is broken here (it does not follow the record before)")
        elif audit.record_hash(rec) != rec["chain"].get("sha256"):
            problems.append(f"seq {index}: the record was altered (its hash does not match its content)")
        expected_prev = rec["chain"].get("sha256")
    if mode not in audit.MODES:
        problems.append(f"unknown mode {mode!r}")
    if records[0]["event"] != "run_started" or sum(r["event"] == "run_started" for r in records) != 1:
        problems.append("the log must start with exactly one run_started")
    if records[-1]["event"] != "run_finished" or sum(r["event"] == "run_finished" for r in records) != 1:
        problems.append("the log must end with exactly one run_finished (it may have been cut short)")
    if problems:
        return problems

    # consistency
    agent_id = first["agent"].get("id")
    actions = [r for r in records if r["event"] == "action"]
    for rec in actions:
        problems += check_action(rec, mode, agent_id, first["policy_sha256"], alerting=first.get("alerting") is True)
    summary = records[-1]["summary"]
    absent = missing(summary, SUMMARY_KEYS)
    if absent:
        problems.append(f"run_finished lacks {', '.join(absent)}")
    else:
        counted = {
            "actions": len(actions),
            "executed": sum(bool(r["execution"]["executed"]) for r in actions),
            "allowed": sum(r["policy"]["effect"] == "allow" for r in actions),
            "gated": sum(r["policy"]["effect"] == "gate" for r in actions),
            "denied": sum(r["policy"]["effect"] == "deny" for r in actions),
            "bypassed": sum(r["policy"]["effect"] == "bypassed" for r in actions),
        }
        for key, value in counted.items():
            if summary[key] != value:
                problems.append(f"run_finished says {summary[key]} {key}, the records show {value}")

    # manifest
    if manifest is not None:
        if manifest.get("run_id") != run_id:
            problems.append("the manifest is for another run")
        if manifest.get("records") != len(records):
            problems.append(f"the manifest counts {manifest.get('records')} records, the log has {len(records)}")
        if manifest.get("head_sha256") != records[-1]["chain"]["sha256"]:
            problems.append("the head hash does not match the manifest: the log was rewritten or replaced")

    # expectation
    if plan is not None:
        wanted = [(item["action"], item.get("tool"), item.get("task")) for item in plan]
        got = [(r["request"]["action"], r["request"].get("tool"), r["request"].get("task")) for r in actions]
        if got != wanted:
            absent = [w for w in wanted if w not in got]
            extra = [g for g in got if g not in wanted]
            problems.append(
                f"the actions recorded are not the actions planned (missing: {absent or 'none'}, "
                f"unplanned: {extra or 'none'}, or out of order)"
            )
    return problems


def tamper_test(records: list[dict], manifest: dict | None, plan: list[dict] | None) -> int:
    """Damage a good log in four ways and require the gate to refuse each. A gate that never refuses proves nothing."""
    import copy

    def altered():
        recs = copy.deepcopy(records)
        target = next(r for r in recs if r["event"] == "action")
        target["execution"]["detail"] = (target["execution"]["detail"] or "") + " (edited)"
        return recs

    def removed_in_the_middle():
        recs = copy.deepcopy(records)
        del recs[len(recs) // 2]
        return recs

    def cut_short():
        return copy.deepcopy(records)[:-1]

    def rewritten_from_start_to_end():
        recs = altered()
        audit.rechain(recs)
        return recs

    cases = [
        ("one record edited", altered()),
        ("one record removed from the middle", removed_in_the_middle()),
        ("the end of the log cut off", cut_short()),
        ("the whole log rewritten, every hash recomputed", rewritten_from_start_to_end()),
    ]
    accepted = 0
    for name, recs in cases:
        problems = verify(recs, manifest, plan)
        print(f"  {'refused ' if problems else 'ACCEPTED'}  {name}")
        accepted += not problems
    if manifest is not None and verify(rewritten_from_start_to_end(), None, plan) == []:
        print("  (without the manifest, the chain alone cannot see the rewrite: that is why the head hash is kept apart)")
    print("TAMPER TEST: " + ("every alteration was refused" if not accepted else f"{accepted} alteration(s) ACCEPTED"))
    return 1 if accepted else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log")
    parser.add_argument("--manifest")
    parser.add_argument("--expect", help="a plan.json: every action in it must be recorded, once, in order")
    parser.add_argument("--tamper-test", action="store_true", help="damage a good log in four ways; each must be refused")
    args = parser.parse_args(argv)
    records = load_records(args.log)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8")) if args.manifest else None
    plan = json.loads(Path(args.expect).read_text(encoding="utf-8")) if args.expect else None
    if args.tamper_test:
        if manifest is None:
            parser.error("--tamper-test needs --manifest: without the head hash, a log rewritten from start to end "
                         "cannot be told from a good one")
        if verify(records, manifest, plan):
            print("the log given to the tamper test is not good to begin with")
            return 1
        return tamper_test(records, manifest, plan)
    try:
        problems = verify(records, manifest, plan)
    except Exception as exc:  # noqa: BLE001 - a log that breaks the gate is a log the gate refuses
        problems = [f"the log could not be checked ({type(exc).__name__}: {exc}); it is malformed"]
    if problems:
        for problem in problems:
            print(f"::error title=Audit gate::{problem}")
        print(f"AUDIT GATE: REFUSED ({len(problems)} problem(s)) for {args.log}")
        return 1
    head = records[-1]["chain"]["sha256"]
    print(f"AUDIT GATE: passed. {len(records)} records, chain intact, head {head}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
