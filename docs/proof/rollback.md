# How a rollback is done

There are two ways, and both were exercised.

## 1. Manual: deploy an older image

Rolling back is deploying an image tag that already exists. Run the workflow by hand and give it the tag:

```
gh workflow run deploy.yaml --ref main -f image_tag=<an existing tag> -f desired_count=1
```

The `Rollback target exists` step refuses a tag that is not in the registry, so a typo cannot deploy nothing.
The rest is the normal path (apply, then verify the version running). Measured once: **4 min 20 s**.

## 2. Automatic: the deployment circuit breaker

A version that cannot start is rolled back by the platform, with no one pressing anything, and the workflow
fails instead of reporting success. This was tested with a deliberately faulty change: it writes a file at
start-up, which works in CI (writable filesystem) and fails in the task (read-only root filesystem).

| Measured | Value |
|---|---|
| Apply to the decision to roll back | 3 min 32 s |
| The rollback itself | 43 s |
| Apply to steady state on the previous version | 4 min 15 s |
| Failures counted before giving up | 3 (observed once) |
| The task that was already serving | never restarted, stayed healthy |
| The workflow run | failed, as designed: "The service runs a different version than requested; the deployment was rolled back" |

Full timeline, events and container logs: [`circuit-breaker/summary.md`](circuit-breaker/summary.md).

## What the test also showed

- **CI did not catch the fault.** It ran the container on a writable filesystem. This is now fixed: since
  pull request #16 the job starts the container with `--read-only`, as the task definition does. A throwaway
  pull request (#17, closed without merging) carried the same fault and failed that job with
  `OSError: [Errno 30] Read-only file system: '/tmp/started-at'`, while the unit tests and the other checks passed.
- **State, code and service can disagree after an automatic rollback.** The service ran the previous version
  while the Terraform state pointed at the faulty one (a plan showed one change). Only rolling forward
  (reverting the change in code) put state, code and service back in agreement.
- **Not tested:** a version that starts but answers with errors. The task health check is defined, but I did
  not run that case.
