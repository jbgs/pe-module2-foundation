# ADR 0003: AI in the pipeline

- Status: accepted, measurement in progress
- Scope: Platform Engineer Pathway, Module 2 personal lab

## Context

Module 2 asks for AI in the delivery pipeline, built so that what AI and agents produce flows through the
same reviewed and tested path as human work, and so that the pipeline records what they did. Module 3 adds
the runtime and the guardrails on top of this.

## Decision

An AI review of every pull request, in CI, that is **advisory**: it posts one comment, and nothing else.

| Concern | Choice |
|---|---|
| What it does | Sends the diff to the model and posts a review comment (summary, risks, questions, what a diff cannot show). One comment per pull request, edited in place on each push |
| Authority | None. It cannot approve, block or merge. A person reads the diff and decides |
| Model | `claude-opus-5-5`, with adaptive thinking and medium effort. Server-side fallback is on: if a safeguard declines the request, the API re-runs it on another model inside the same call, instead of the review stopping |
| Code | A small script using the official SDK, pinned to an exact version with hashes (`.github/scripts/requirements.txt`) |
| Credentials | The API key is a repository secret. The job has no cloud credentials and no `id-token` |
| Forks | Get no secrets, so the job does not run for them |
| Size | A diff over 150 KB is not sent, and the comment says it was not reviewed. It is never truncated in silence |
| Failure | An advisory step never fails the pull request. An error, a refusal or a missing key is reported plainly, as "not reviewed" |
| Trace | Every run writes `ai-trace.json` (kept 90 days as a workflow artifact): the model asked for and served, the request id, token counts, duration, the commit, and the SHA-256 of the diff, the prompt and the output. Hashes, not content |

## Same path, no shortcut

Nothing that AI or an agent writes has a privileged way in. A change written with an AI tool is a pull
request like any other: it has to pass the same required checks and be merged by a person, and the pull
request template asks for an "AI assistance" statement. The `main` branch refuses a direct push. The review
comment is information for the reader, not an input to any gate.

## Threat model

- **The diff is untrusted text.** A pull request can contain words meant to steer the model. The prompt
  tells the model to treat the diff as data and to report instructions it finds, and the diff cannot close
  its own data block. Most important, the model's output is only ever displayed as a comment, so an
  instruction that worked would have nothing to act on.
- **Secrets in the prompt.** The review sends the diff of a public repository, which is public already. The
  key itself is never printed: every message that leaves the script is redacted for key-shaped strings.
- **The script runs from the pull request's own code.** A pull request that changes the script runs the
  changed version, with the key. Only collaborators can open a pull request from a branch of this repository,
  and here that is one person, so this is accepted. With more collaborators, the script should be run from
  the base branch instead.
- **Cost.** The workspace has a spend limit, so the worst case is bounded by the account and not by the code.

## How "speeds the pipeline" is measured

The workbook asks for AI assistance that *measurably* speeds the pipeline. In a lab with one person, a review
by AI adds time before a comment appears and does not shorten a review that nobody is waiting for, so the
claim is not assumed. It is measured, and the rule is fixed here before the data is collected.

Baseline (before the AI review existed): 10 pull requests, opened to merged, median **2.6 minutes**, range
0.2 to 9.6 minutes.

For each pull request that has an AI review, record:

1. **Added latency:** the duration of the AI job and the wall-clock time of the whole CI run, against the CI
   runs before it existed.
2. **Findings acted on:** whether the review raised something that led to a change before the merge, and
   whether that finding was correct. A finding counts only if a person confirms it was real.
3. **Lead time:** opened to merged, against the baseline.

Decision rule: the claim that AI assistance speeds the pipeline is made only if lead time does not rise and
the review finds real problems before the merge. Otherwise the claim is stated as what was measured: an
added cost of N seconds, and M real findings. Both are legitimate results, and the second is more useful than
a claim the data does not support.

### Results

To be filled with the measured data once at least five pull requests have been reviewed.

## Consequences

- The review costs cents per pull request, and the actual cost is measured from the token counts in the
  trace and not estimated.
- The trace is the first piece of the record Module 4 builds on: which prompt, which model, on which commit,
  with the output and its hash, and where the comment went. What is still missing is the link to the human
  approval, which is the merge.
