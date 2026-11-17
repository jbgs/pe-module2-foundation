"""The audit record: what an agent did, under which rules, and who approved it.

One run of the agent leaves one log: a sequence of records, each carrying the hash of the one before it. A log
starts with a `run_started` record and ends with a `run_finished` record, and has one `action` record for every
action the agent proposed, whether or not it ran. A denied or a gated attempt is evidence too.

The chain makes the log tamper-evident: changing, removing, adding or reordering a record breaks every hash after
it. It does not make the log immutable. Someone who can rewrite the whole log can recompute the whole chain, so
the hash of the last record (the head) is also written to a manifest and printed where the agent cannot reach it.
Where the head is kept is what turns tamper-evident into immutable; see docs/adr/0005-audit-record.md.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

SCHEMA = "agent-audit/1"
MANIFEST_SCHEMA = "agent-audit-manifest/1"
MODES = ("enforce", "bypass", "weakening")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(obj) -> bytes:
    """One byte string for one value, whatever the order the keys were written in."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def genesis(run_id: str) -> str:
    """The `prev` of the first record: it ties the chain to its run, so a record cannot be moved to another log."""
    return sha256_hex(f"{SCHEMA}|genesis|{run_id}".encode("utf-8"))


def record_hash(record: dict) -> str:
    """The hash of a record: everything in it except its own hash, plus the hash of the record before."""
    body = {key: value for key, value in record.items() if key != "chain"}
    return sha256_hex(canonical({"body": body, "prev": record["chain"]["prev"]}))


def principal_from_env(env=None) -> dict:
    """Who asked for this run: the identity the platform authenticated, never anything the agent says."""
    env = os.environ if env is None else env
    return {"actor": env.get("GITHUB_ACTOR", "local"), "event": env.get("GITHUB_EVENT_NAME", "local")}


def source_from_env(env=None) -> dict:
    """Which code and which run: enough to find the commit and the workflow run this record came from."""
    env = os.environ if env is None else env
    return {
        "repository": env.get("GITHUB_REPOSITORY", "local"),
        "workflow": env.get("GITHUB_WORKFLOW", "local"),
        "run_id": env.get("GITHUB_RUN_ID", "local"),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", "local"),
        "commit": env.get("GITHUB_SHA", "local"),
        "ref": env.get("GITHUB_REF", "local"),
    }


def rechain(records: list[dict]) -> None:
    """Recompute every hash from the start. This is what a forger who can rewrite the whole log would do; it is here
    so that the gate can be shown a rewrite and be seen to refuse it."""
    prev = genesis(records[0]["run_id"])
    for index, record in enumerate(records):
        record["seq"] = index
        record["chain"] = {"prev": prev}
        record["chain"]["sha256"] = record_hash(record)
        prev = record["chain"]["sha256"]


class AuditLog:
    """Builds a log, one record at a time, chaining each to the one before."""

    def __init__(self, run_id: str, mode: str, now=utc_now):
        if mode not in MODES:
            raise ValueError(f"unknown mode: {mode}")
        self.run_id = run_id
        self.mode = mode
        self._now = now
        self._prev = genesis(run_id)
        self.records: list[dict] = []

    def append(self, event: str, **fields) -> dict:
        record = {
            "schema": SCHEMA,
            "seq": len(self.records),
            "event": event,
            "run_id": self.run_id,
            "mode": self.mode,
            "timestamp": self._now(),
            **fields,
        }
        record["chain"] = {"prev": self._prev}
        record["chain"]["sha256"] = record_hash(record)
        self._prev = record["chain"]["sha256"]
        self.records.append(record)
        return record

    def text(self) -> str:
        return "".join(json.dumps(record, sort_keys=True) + "\n" for record in self.records)

    def manifest(self) -> dict:
        return {
            "schema": MANIFEST_SCHEMA,
            "run_id": self.run_id,
            "mode": self.mode,
            "records": len(self.records),
            "head_sha256": self.records[-1]["chain"]["sha256"] if self.records else None,
            "first_timestamp": self.records[0]["timestamp"] if self.records else None,
            "last_timestamp": self.records[-1]["timestamp"] if self.records else None,
        }
