#!/usr/bin/env python3
"""Read from GitHub who approved a gated job, and write the approval that the enforcement point attaches.

    fetch_approval.py --action export_result --environment agent-approval --job-name "..." --out approval.json

The approval is never supplied by the agent, and never by anything the agent can reach. It is read, with the token of
the run, from the review history of the workflow run (GET /repos/{repo}/actions/runs/{id}/approvals), which GitHub writes
when a required reviewer of the environment approves.

It fails closed. If the history holds no approval of this environment, or more than one review of it (a re-run keeps
the reviews of its earlier attempts, and the API does not say in what order it lists them), or the approval is not
`approved`, or the job
that follows the approval cannot be found, nothing is written and the exit status is not zero. That includes the case in
which the environment lost its required reviewers: then no one approved, the history is empty, and this refuses to go on.

What the API gives, and what it does not: who approved (`user.login`), the state and the comment. It gives no time for the
approval (the timestamps in the answer are those of the environment). The time recorded as `decided_at` is the start
of the job that waits behind the approval, which GitHub starts right after it. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"


def get_json(path: str, token: str, opener=urllib.request.urlopen):
    request = urllib.request.Request(
        f"{API}{path}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
    )
    with opener(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def find_approval(approvals: list, environment: str) -> dict:
    """The last approval of this environment. Anything but `approved` is not an approval."""
    ours = [
        a for a in approvals
        if isinstance(a, dict) and any(isinstance(e, dict) and e.get("name") == environment for e in a.get("environments") or [])
    ]
    if not ours:
        raise ValueError(f"no review of the environment {environment!r} in the history of this run: nobody approved")
    if len(ours) > 1:
        # The API does not say in what order it lists the reviews, and a re-run of a run keeps the reviews of its earlier
        # attempts. With more than one, which one answers this request cannot be told, so none is trusted.
        raise ValueError(f"{len(ours)} reviews of {environment!r} in the history of this run: it is ambiguous which one "
                         f"answers this request. Start a new run instead of re-running this one")
    last = ours[0]
    if last.get("state") != "approved":
        raise ValueError(f"the review of {environment!r} is {last.get('state')!r}, not approved")
    login = (last.get("user") or {}).get("login")
    if not login:
        raise ValueError("the approval does not say who approved it")
    return last


def job_started(jobs: dict, name: str) -> str:
    matches = [j for j in jobs.get("jobs", []) if j.get("name") == name and j.get("started_at")]
    if not matches:
        raise ValueError(f"the job {name!r} was not found, or has not started: its start is the time of the approval")
    return matches[-1]["started_at"]


def build(action: str, environment: str, run_id: str, approval: dict, started_at: str) -> dict:
    user = approval["user"]
    return {
        "action": action,
        "approver": user["login"],
        "approved": True,
        "decided_at": started_at,
        "source": f"github-environment:{environment}",
        "evidence": f"actions/runs/{run_id} (approver id {user.get('id')}; decided_at is the start of the job behind the approval)",
        "comment": (approval.get("comment") or "")[:200],
    }


def main(argv: list[str] | None = None, fetch=get_json) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--action", required=True, help="the one action this approval is for")
    parser.add_argument("--environment", required=True)
    parser.add_argument("--job-name", required=True, help="the job that waits behind the approval")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    token, repo, run_id = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_RUN_ID")
    if not (token and repo and run_id):
        print("::error title=Approval::GITHUB_TOKEN, GITHUB_REPOSITORY and GITHUB_RUN_ID must be set")
        return 1
    try:
        approval = find_approval(fetch(f"/repos/{repo}/actions/runs/{run_id}/approvals", token), args.environment)
        started = job_started(fetch(f"/repos/{repo}/actions/runs/{run_id}/jobs", token), args.job_name)
        result = build(args.action, args.environment, run_id, approval, started)
    except (ValueError, urllib.error.URLError, KeyError, TypeError) as exc:
        print(f"::error title=Approval::{exc}")
        return 1
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"approval read from GitHub: {result['approver']} approved {result['action']!r} ({result['source']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
