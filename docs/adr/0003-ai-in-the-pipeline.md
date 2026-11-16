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
| What it does | Sends the diff to the model and posts a review comment (summary, risks, questions, what a diff cannot show). One comment per pull request, edited in place if it runs again |
| When it runs | When a pull request is opened or reopened, and on demand (`gh workflow run ai-review.yaml -f pr_number=N`). **Not on every push**: each run reads the whole diff and costs money, so the cost would multiply with the number of pushes. The price is a review that can go stale, and the comment says which commit it read |
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
  its own data block. The model's output is only ever displayed as a comment, so no instruction can make
  the pipeline do anything.
- **The reader is what is left to act on.** An earlier version of this ADR said an injected instruction
  "has nothing to act on", and the first AI review of this very pull request pointed out that this ignores
  the person who reads the comment. A misleading review ("none found"), an @mention that notifies someone, an
  image that makes a request to a URL of someone else's choosing, or a link, all work on the reader. So the
  text is reduced to plain Markdown before it is posted (no mentions, images, links or HTML that renders),
  and the trace records whether the text was changed. This limits what an injection can do to the reader; it
  does not stop a review from being wrong, which is why it is advisory.
- **Secrets in the prompt.** The review sends the diff of a public repository, which is public already. The
  key itself is never printed: every message that leaves the script is redacted for key-shaped strings.
- **The script runs from the pull request's own code.** A pull request that changes the script, its tests
  or its requirements runs the changed version, with the key. Only collaborators can open a pull request from a branch of this repository,
  and here that is one person, so this is accepted. With more collaborators, the script should be run from
  the base branch instead.
- **Supply chain.** The SDK and everything it needs are installed from a file of exact versions with hashes,
  so what runs is exactly what was checked. Hashes pin the bytes, not where they came from: the packages
  `httpx2`, `httpcore2` and `truststore` look unusual, and are there because the SDK itself declares them
  (`httpx2` is published from the `pydantic/httpx2` project). That is a residual risk, accepted.
- **Cost.** The workspace has a spend limit, so the worst case is bounded by the account and not by the code.
- **Required checks.** `AI review (advisory)` must never be a required check: it is advisory, it costs money
  and it depends on an outside service, so requiring it would let a job that is meant to only comment block
  a merge. Its tests are a separate job in the CI workflow (`AI review script tests`), cheap and free of any
  key, and that one can be required.

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

The rule above is applied once at least five pull requests have been reviewed. What has been measured so far,
on the first one (the pull request that introduced the job), is below. It is one observation and is not a
conclusion.

| Measure | Value |
|---|---|
| Model served, fallback used | `claude-opus-5-5`, no fallback, stopped normally |
| Diff size | 67,375 bytes (about 8 times the median of the earlier pull requests, because it carried a hashed lock file and the tests) |
| Tokens, input and output | 33,106 and 5,654 (the output includes the model's reasoning, which is billed as output) |
| Cost of this review | **0.2455 USD** at 4 USD and 20 USD per million tokens |
| Time of the review step | 54 seconds |
| CI wall-clock time | **68 s** with the job, against a median of **20 s** for 6 runs without it: the job is the slowest and adds about 48 s |

Cost: the estimate made before building it (3 to 5 cents) was wrong by a factor of about five. It assumed 3.5
bytes per token, but this diff tokenised at about 2 bytes per token (hashes and YAML), and it left out the
reasoning tokens. A typical pull request is smaller, and its cost has not been measured yet.

The first review raised six risks. Checked against the code: two were real and led to a change (the comment
lookup was not tied to a bot, and the text posted to the reader was not sanitised), one was a confident
mistake (it claimed the escaping of the data block did nothing, when it replaces the closing tag by a
neutralised one; a test shows exactly one closing tag survives), one was true but by design (unusual
dependency names that the SDK declares), and two were already accepted or marginal. Checking them cost a
person's time, which counts against the claim of speed. The same run also showed a defect in the tests, which
printed workflow commands that the runner turned into false annotations.

## Consequences

- The review costs between cents and a quarter of a dollar per pull request, depending on the size of the
  diff. The first one cost 0.2455 USD. It ran again on every push at first, and the cost multiplied with the
  number of pushes, so it now runs when a pull request is opened or reopened and on demand. The cost is
  measured from the token counts in the trace, not estimated.
- The trace is the first piece of the record Module 4 builds on: which prompt, which model, on which commit,
  with the output and its hash, and where the comment went. What is still missing is the link to the human
  approval, which is the merge.
