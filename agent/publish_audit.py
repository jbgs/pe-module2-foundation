#!/usr/bin/env python3
"""Publish the audit logs of a run to the audit store, and check that the store refuses to let them be changed.

    publish_audit.py publish --run-id RUN [--out agent/out]
    publish_audit.py verify  --run-id RUN [--plan agent/plan.json]

`publish` runs in the pipeline, on main, with the role that can only write. For each mode it writes three objects,
each one only if it does not exist yet:

  agent-runs/<run>/<mode>/audit.jsonl     the log
  agent-runs/<run>/<mode>/manifest.json   the number of records and the head hash
  agent-runs/heads/<head hash>.json       a pointer named after the head hash itself

The last one is named by content, so its name cannot be predicted and cannot be taken first: a log with that head
existed, in that store, at that time. Then, with the same role, it tries to change what it has just written (write
it again, delete it, read it, shorten its retention, write outside its prefix), and every attempt must be refused.

`verify` runs from a person's machine with a profile that can read the store: it reads the logs back and runs the
audit gate on them, and checks that each head has its pointer.

The bucket is named from the account ID (`AWS_ACCOUNT_ID`), or taken from `AUDIT_BUCKET`. It is never printed.
Standard library and the AWS CLI.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import audit
import audit_verify

PREFIX = "agent-runs/"
MODES = ("enforce", "bypass", "weakening")
ERROR = re.compile(r"An error occurred \((\w+)\)")


def bucket_name(env=None) -> str:
    env = os.environ if env is None else env
    if env.get("AUDIT_BUCKET"):
        return env["AUDIT_BUCKET"]
    if env.get("AWS_ACCOUNT_ID"):
        return f"pe-lab-audit-{env['AWS_ACCOUNT_ID']}"
    raise SystemExit("neither AUDIT_BUCKET nor AWS_ACCOUNT_ID is set")


def run_key(run_id: str, mode: str, name: str) -> str:
    return f"{PREFIX}{run_id}/{mode}/{name}"


def head_key(head: str) -> str:
    return f"{PREFIX}heads/{head}.json"


def checksum_b64(data: bytes) -> str:
    """The checksum S3 wants: SHA-256, base64. S3 refuses the object if it does not match what it received."""
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def aws(args: list[str], runner=subprocess.run) -> tuple[int, str, str]:
    done = runner(["aws", "s3api", *args], capture_output=True, text=True, check=False)
    return done.returncode, done.stdout, done.stderr


def error_code(stderr: str) -> str | None:
    match = ERROR.search(stderr or "")
    return match.group(1) if match else None


def put_once(bucket: str, key: str, path: Path, runner=subprocess.run) -> dict:
    """Write one object, only if no object with that name exists, with its checksum so S3 verifies the content."""
    checksum = checksum_b64(path.read_bytes())
    code, out, err = aws(
        [
            "put-object", "--bucket", bucket, "--key", key, "--body", str(path),
            "--if-none-match", "*",
            "--checksum-algorithm", "SHA256",
            "--checksum-sha256", checksum,
            "--output", "json",
        ],
        runner,
    )
    result = {"key": key, "ok": code == 0, "error": error_code(err), "version_id": None, "checksum": checksum}
    if code == 0:
        try:
            result["version_id"] = json.loads(out).get("VersionId")
        except ValueError:
            pass
    return result


def publish(run_id: str, out_dir: Path, bucket: str, runner=subprocess.run) -> list[dict]:
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for mode in MODES:
            log = out_dir / f"audit-{mode}.jsonl"
            manifest_path = out_dir / f"audit-{mode}.manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            log_key = run_key(run_id, mode, "audit.jsonl")
            manifest_key = run_key(run_id, mode, "manifest.json")
            results.append(put_once(bucket, log_key, log, runner))
            results.append(put_once(bucket, manifest_key, manifest_path, runner))
            pointer = Path(tmp) / f"head-{mode}.json"
            pointer.write_text(
                json.dumps(
                    {
                        "schema": "agent-audit-head/1",
                        "head_sha256": manifest["head_sha256"],
                        "records": manifest["records"],
                        "run_id": manifest["run_id"],
                        "mode": mode,
                        "log_key": log_key,
                        "manifest_key": manifest_key,
                        "commit": os.environ.get("GITHUB_SHA", "local"),
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            results.append(put_once(bucket, head_key(manifest["head_sha256"]), pointer, runner))
    return results


def publish_ok(results: list[dict]) -> bool:
    return all(r["ok"] for r in results)


def refusals(bucket: str, key: str, version_id: str, runner=subprocess.run) -> list[dict]:
    """With the writer's own identity, try to change what was just written. Each attempt must be refused."""
    with tempfile.TemporaryDirectory() as tmp:
        body = Path(tmp) / "body.txt"
        body.write_text("an attempt to change a record\n", encoding="utf-8")
        attempts = [
            ("write the same name again, with the condition", "PreconditionFailed",
             ["put-object", "--bucket", bucket, "--key", key, "--body", str(body), "--if-none-match", "*"]),
            ("write the same name again, without the condition", "AccessDenied",
             ["put-object", "--bucket", bucket, "--key", key, "--body", str(body)]),
            ("write outside the prefix of the records", "AccessDenied",
             ["put-object", "--bucket", bucket, "--key", "outside-the-prefix.txt", "--body", str(body), "--if-none-match", "*"]),
            ("read the record back", "AccessDenied",
             ["get-object", "--bucket", bucket, "--key", key, "--version-id", version_id, os.devnull]),
            ("delete the locked version", "AccessDenied",
             ["delete-object", "--bucket", bucket, "--key", key, "--version-id", version_id]),
            ("delete it with the bypass of the lock", "AccessDenied",
             ["delete-object", "--bucket", bucket, "--key", key, "--version-id", version_id, "--bypass-governance-retention"]),
            ("shorten its retention", "AccessDenied",
             ["put-object-retention", "--bucket", bucket, "--key", key, "--version-id", version_id,
              "--retention", "Mode=GOVERNANCE,RetainUntilDate=2020-01-01T00:00:00Z"]),
        ]
        results = []
        for name, expected, command in attempts:
            code, _, err = aws(command, runner)
            got = "ACCEPTED" if code == 0 else (error_code(err) or "error")
            ok = got == expected
            results.append({"attempt": name, "expected": expected, "got": got, "ok": ok})
    return results


def verify_store(run_id: str, bucket: str, plan: list[dict] | None, runner=subprocess.run) -> list[str]:
    """Read the logs back from the store and run the audit gate on them. Needs an identity that can read."""
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        for mode in MODES:
            files = {}
            for name in ("audit.jsonl", "manifest.json"):
                target = Path(tmp) / f"{mode}-{name}"
                code, _, err = aws(["get-object", "--bucket", bucket, "--key", run_key(run_id, mode, name), str(target)], runner)
                if code != 0:
                    problems.append(f"{mode}: cannot read {name} from the store ({error_code(err) or 'error'})")
                    break
                files[name] = target
            else:
                records = audit_verify.load_records(files["audit.jsonl"])
                manifest = json.loads(files["manifest.json"].read_text(encoding="utf-8"))
                expect = plan if mode != "weakening" else None
                problems += [f"{mode}: {p}" for p in audit_verify.verify(records, manifest, expect)]
                code, _, _ = aws(["head-object", "--bucket", bucket, "--key", head_key(manifest["head_sha256"])], runner)
                if code != 0:
                    problems.append(f"{mode}: the head pointer is missing from the store")
    return problems


def summary(results: list[dict], checks: list[dict]) -> str:
    lines = ["### Audit store", "", "| Object | Written | Version | Checksum (SHA-256) |", "|---|---|---|---|"]
    for r in results:
        state = "yes" if r["ok"] else f"NO ({r['error']})"
        lines.append(f"| `{r['key']}` | {state} | `{(r['version_id'] or '-')[:12]}` | `{r['checksum'][:16]}...` |")
    if checks:
        lines += ["", "With the writer's own role, every attempt to change what was written must be refused:", "",
                  "| Attempt | Expected | Got |", "|---|---|---|"]
        for c in checks:
            lines.append(f"| {c['attempt']} | {c['expected']} | {c['got']}{'' if c['ok'] else '  **WRONG**'} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    pub = sub.add_parser("publish")
    pub.add_argument("--run-id", required=True)
    pub.add_argument("--out", default="agent/out")
    pub.add_argument("--no-refusals", action="store_true")
    ver = sub.add_parser("verify")
    ver.add_argument("--run-id", required=True)
    ver.add_argument("--plan", default="agent/plan.json")
    args = parser.parse_args(argv)
    bucket = bucket_name()

    if args.command == "verify":
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8")) if Path(args.plan).exists() else None
        problems = verify_store(args.run_id, bucket, plan)
        for problem in problems:
            print(f"::error title=Audit store::{problem}")
        print("STORE VERIFIED: every log read back from the store passes the audit gate" if not problems
              else f"STORE NOT VERIFIED ({len(problems)} problem(s))")
        return 1 if problems else 0

    results = publish(args.run_id, Path(args.out), bucket)
    checks: list[dict] = []
    first = next((r for r in results if r["ok"] and r["key"].endswith("/enforce/audit.jsonl")), None)
    if publish_ok(results) and not args.no_refusals and first and first["version_id"]:
        checks = refusals(bucket, first["key"], first["version_id"])
    text = summary(results, checks)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(text)
    failed = [r for r in results if not r["ok"]]
    for r in failed:
        print(f"::error title=Audit store::{r['key']} was not written ({r['error']}). "
              f"A name that is already taken is refused, never replaced.")
    wrong = [c for c in checks if not c["ok"]]
    for c in wrong:
        print(f"::error title=Audit store::the store did not refuse: {c['attempt']} (expected {c['expected']}, got {c['got']})")
    return 1 if (failed or wrong or (not checks and not args.no_refusals)) else 0


if __name__ == "__main__":
    sys.exit(main())
