# Proof for the Module 2 hand-in

The workbook asks for four pieces of evidence, plus a short rationale. Evidence must not contain secrets or real
account identifiers: they are masked before committing.

| # | Evidence | File | Status |
|---|---|---|---|
| 1 | Link to this repository | n/a | done |
| 2 | Destroy an environment and create it again from code (log or screenshot) | [`destroy-recreate.md`](destroy-recreate.md), [`logs/`](logs/) | done |
| 3 | One pipeline run from commit to release (screenshot) | [`pipeline-run.md`](pipeline-run.md) | note done, screenshot to add |
| 4 | How a rollback is done (screenshot or note) | [`rollback.md`](rollback.md), [`circuit-breaker/`](circuit-breaker/) | done |
| 5 | Rationale: vendor-neutral tooling and the agentic layer | [`../rationale.md`](../rationale.md) | done |

Beyond the four items:

- [`circuit-breaker/`](circuit-breaker/): the automatic rollback test, with timeline, events and logs.
- [`ai-experiment/`](ai-experiment/): five planted defects, to see whether the AI review gives earlier feedback.
  Its protocol was written before the first call.
