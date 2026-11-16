# Does the AI review give earlier feedback? Five planted defects

The protocol, with the decision rule fixed before any call, is in [`PROTOCOL.md`](PROTOCOL.md). One run per diff,
with the same prompt, model and parameters as the workflow. Nothing was posted anywhere. Diffs are in
[`diffs/`](diffs/), raw results in `D*.result.json`.

| | Planted defect | Detected | Call time | Tokens in / out |
|---|---|---|---|---|
| D1 (control) | write to `/tmp` while the root filesystem is read-only | yes, conditional (2nd risk) | 12.8 s | 658 / 999 |
| D2 | `/healthz` returns 503 unless `/app/ready` exists, which nothing creates | yes (1st risk) | 14.8 s | 663 / 1309 |
| D3 | default port 8000 while everything else uses 8080 | yes, conditional (1st risk); the most generic of the five | 11.1 s | 667 / 980 |
| D4 | `DATABASE_URL` required at start-up and not set in the task definition | yes, conditional (2nd risk) | 11.3 s | 652 / 1051 |
| D5 | ingress rule open to `0.0.0.0/0` | yes (1st risk) | 14.5 s | 794 / 1303 |

**Rule:** at least 3 of 5 detected and a median call time under 60 s. **Result:** 5 of 5, median 12.8 s
(11.1 to 14.8 s). Even without D3, 4 of 5. About 0.13 USD in total (rate inferred from earlier recorded costs).

## Limits

- Five defects, chosen and planted by me. D1 repeats the fault of an earlier pull request, so it is not independent.
- The model sees only the diff. Three of the five were flagged as "if X, this fails", which a person must confirm.
- Of 19 risk items in all, I judged 4 to be low-value noise (list in the reviews); one more (a lint warning in D4)
  I did not verify.
- The call time is the model call only, not the time from opening a pull request to the comment.
- Run-time detection was compared for D1 only (3 min 32 s after apply). The others were not measured.
- This shows earlier feedback. It does not show a faster pipeline: the review is advisory and runs apart from CI.
