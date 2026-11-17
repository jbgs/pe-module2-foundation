"""What makes an environment of the golden path what it says it is.

An environment is made by the golden path with a record (environment.json) that names it and carries the hash of the parts
that make it compliant: the data it was given and the policy that judges the agent. A run that says it belongs to that
environment is checked against it, so the claim is more than a name: the environment has to exist, and to be as it was made.

What this does and does not stop. It stops a run that names an environment that does not exist, or that was changed after it
was made (its data or its policy). It does not stop someone who builds a folder by hand with a record that matches, and
no check on a developer's own machine could. The report goes one step further: it counts a run as coming from the path only
if the environment appears in the usage log with the same hash.

Standard library only.
"""

from __future__ import annotations

import json
from pathlib import Path

import audit

# The parts that make an environment compliant. The plan and the README may be edited: they say what the agent does and how,
# not what it is given or what judges it.
HASHED = ("data/", "policy/")


def template_sha256(files: dict[str, bytes]) -> str:
    """One hash for the compliant parts of an environment."""
    return audit.sha256_hex(audit.canonical({path: audit.sha256_hex(content) for path, content in sorted(files.items()) if path.startswith(HASHED)}))


def read_files(env_dir: Path) -> dict[str, bytes]:
    return {p.relative_to(env_dir).as_posix(): p.read_bytes() for p in sorted(env_dir.rglob("*")) if p.is_file()}


def verify(env_dir: Path, env_id: str) -> list[str]:
    """The environment must exist, be the one that is named, and be as it was made. Returns what is wrong."""
    record_path = Path(env_dir) / "environment.json"
    if not record_path.is_file():
        return [f"{env_dir} is not an environment of the golden path: it has no environment.json"]
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except ValueError:
        return ["environment.json cannot be read"]
    problems = []
    if record.get("id") != env_id:
        problems.append(f"the environment in {env_dir} is {record.get('id')!r}, not {env_id!r}")
    files = read_files(Path(env_dir))
    if template_sha256(files) != record.get("template_sha256"):
        problems.append("its data or its policy are not as they were when the environment was made")
    policy = files.get("policy/agent.rego")
    if policy is None or audit.sha256_hex(policy) != record.get("policy_sha256"):
        problems.append("its policy is not the one recorded when the environment was made")
    return problems


def template_of(env_dir: Path) -> str | None:
    """The recorded hash of an environment, for a run to write in its record."""
    try:
        return json.loads((Path(env_dir) / "environment.json").read_text(encoding="utf-8")).get("template_sha256")
    except (OSError, ValueError):
        return None
