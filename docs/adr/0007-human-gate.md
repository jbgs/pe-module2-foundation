# ADR 0007: the human gate

Status: accepted. Date: 2026-11-17.

## Context

The policy ([`policy/`](../../policy/)) has actions that need a person: `deploy_dev`, `modify_policy`, and now
`export_result`. Until now a gated action only waited: its record said `pending`, and nothing could turn that into
`approved`. A gate that nothing can open is a wall, not a gate; and a gate that the agent could open, or that opens on
the word of whoever builds the input, is no gate at all. The audit record already has a place for the approval and the
audit gate already enforces its rules (a person other than the agent, a source, a time, evidence). What was missing is
a way for a real approval to get there.

## Decision

### What is gated, and why the export

`export_result` is the action by which something **leaves the sandbox**. It is the gate the module is about: the
sandbox has no network and no regulated data, so everything inside it is contained, and a result is the one thing the
agent produces that someone will want to take out. The runtime cannot stop an export that is authorised, so the control
is a person. (In `bypass` mode, with the policy off, the export does complete inside the sandbox: that is the proof that
for this action the gate is the policy and nothing else, which is why the policy must not be skippable.)

### How a person's approval reaches the record

1. The workflow `Agent approved run` is run by hand from `main`. In its first job the agent runs under the policy, and the
   export waits: the log says `approval: pending`, and nothing leaves.
2. The next job declares the GitHub Environment `agent-approval`, which has a **required reviewer**. GitHub holds the job
   until the reviewer approves or rejects it.
3. A step then **reads from GitHub who approved**: `GET /repos/{repo}/actions/runs/{run}/approvals`, with the token of the
   run. The answer holds the environment, the state, the comment and the user who reviewed. The step writes an approval file
   with the approver (`user.login`), the action it is for, where it came from (`github-environment:agent-approval`) and the
   run that holds the evidence. The job behind the environment only checks that GitHub has a clear approval to show; the
   job that **uses** the approval reads it again from GitHub itself, so the file never travels between jobs and does not have
   to be trusted in transit.
4. The agent runs again. The enforcement point attaches the approval to the export **and to no other action**, and asks
   the policy, which allows it only if the approver is a listed approver and is not the agent.
5. The record then says `status: approved`, the approver, the time, the source and the evidence, and the result that
   left the sandbox is exactly the one whose hash the record carries.
6. Both logs, the request with its approval pending and the run that followed the approval, are written to the audit store.

### An approval is for one action

The approval names `export_result`. In the same run `modify_policy` and `deploy_dev` stay `pending`, and a test shows it:
approving the export does not unlock a change of the policy.

### It fails closed

| Situation | What happens |
|---|---|
| The environment has no required reviewers, so the job runs with nobody having approved | GitHub's history is empty; the step finds no approval, writes nothing and fails |
| The reviewer rejects | The approval job fails; nothing runs after it |
| The last review is `pending` or anything but `approved` | Refused |
| More than one review of the environment (a re-run keeps the reviews of its earlier attempts, and the API does not say in what order it lists them) | Refused as ambiguous: none is trusted. Start a new run instead of re-running |
| A review of another environment | Not counted |
| The history cannot be read, or has no time | Refused |
| The reviewer is not in the policy's list of approvers | The policy keeps the gate closed, the approved run fails its own check |
| The approval file is negative or incomplete | The enforcement point refuses to start |

## Options considered

| Option | Why not |
|---|---|
| Approve in the pull request that adds the change | A pull request approves code; here a person approves an action of a run, at the time it asks. Also, the agent that proposes the change would be the author of what is approved |
| A comment or a label that a step looks for | Anyone who can comment can write it, and the step cannot tell a person from a bot |
| An external ticket or approval system | The right answer where a client has one; it is another system to run and to trust. The Environment is native, and its answer carries an identity that GitHub has authenticated. Anywhere else, only the step that reads the approval changes |

## What this does not do, stated

- **It is one person.** The person who runs the workflow is the person who approves. The agent never approves, and the policy
  refuses an approver that is the agent, but the separation between the one who asks and the one who approves cannot exist in
  a repository with a single owner. It would need a second reviewer in the Environment, and "prevent self-review" switched on.
  Switched on in this repository it would block every approval, so it is off.
- **The API gives no time for the approval.** It gives who, the state and the comment; the timestamps in the answer are those
  of the environment. The time in the record is the start of the job that waits behind the approval, which GitHub starts
  right after it (seconds). The record says so in its evidence.
- **The reviewer approves the export, not the result.** The approval is for the action in this run, and the agent runs again
  after it. For a deterministic script that is the same result; for an agent that is not, the reviewer would need to see what
  they approve and the approval would need to name its hash. This is the next improvement.
- **Two lists must agree**: the reviewers of the Environment (in the repository settings, outside the code) and the approvers in
  the policy (in the code). If they differ, the gate does not open: it fails closed.
- **GitHub is trusted** to write the review history truthfully, and the settings of the Environment are an administrator's.
- **Re-running a run is not supported for approvals.** A re-run keeps the reviews of its earlier attempts, which the step
  refuses as ambiguous, so the way to try again is a new run. If only a failed job is re-run, the logs keep the run id
  of the attempt that produced them, while the names in the store carry the attempt that published them.

## Consequences

- A real approval, from an authenticated identity, ends up in an immutable record, which is what the gate question asks for.
- The environment is configured in the repository, and no code can set it: its reviewer, and its restriction to `main`
  (so that a branch cannot use it), are steps for a person. If it is removed, the flow stops; it does not open.
- `Agent approved run` runs only by hand: a run that waits for a person must not wait on every push.
