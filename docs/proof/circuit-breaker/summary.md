# Circuit breaker test, 2026-11-16 (UTC)

Fault: a change that writes /tmp/started-at at startup. It works where the root filesystem is writable (CI)
and fails where it is read-only (the ECS task, readonlyRootFilesystem = true). Merged on purpose, then reverted.

## Timeline
| Time | Event | Source |
|---|---|---|
| 09:20:30 | Merge of the faulty pull request | GitHub |
| 09:21:26 | The apply updates the service (task definition :10) | run 43838861796 |
| 09:21:38 / 09:22:38 / 09:23:29 / 09:24:29 | Four tasks started, each stopped with EssentialContainerExited, exit 1 (45 to 54 s each) | stopped-tasks.txt |
| 09:22:03 / 09:23:03 / 09:23:58 / 09:24:49 | `OSError: [Errno 30] Read-only file system: '/tmp/started-at'` | container-logs.txt |
| 09:24:58 | `deployment failed: tasks failed to start`, then `rolling back` (3 failures counted) | ecs-events.txt |
| 09:25:41 | `deployment completed`, steady state on the previous task definition (:9) | ecs-events.txt |
| 09:25:47 | The Verify step fails: the version running is not the one requested | runs.txt |

## Measured
- Apply to the decision to roll back: 3 min 32 s. The rollback itself: 43 s. Apply to steady state: 4 min 15 s.
- Failures counted before ECS gave up: 3 (observed once).
- The task that served throughout (started 08:54:23, before the merge) was never restarted and stayed healthy.
- The Deploy run ended in failure, as designed; its message: "The service runs a different version than requested; the deployment was rolled back".

## Roll forward
Revert merged 09:30:09. New task :11 started 09:31:24 and healthy; the old task was stopped at 09:32:49 with exit 0
(a clean shutdown on SIGTERM). Run 43840313493 succeeded in 3 min 3 s. A Terraform plan afterwards showed no changes.

## What the test also showed
- The CI did not catch the fault: it runs the container on a writable filesystem.
- The AI review of the faulty pull request flagged it as its first risk, conditionally (it could not see the task definition).
- After the automatic rollback, the Terraform state pointed at the faulty version while the service ran the previous one
  (a plan showed one change, the task definition :9 -> :10). Only rolling forward restores state, code and service.

## Limits
- One observation of each. The count of 3 failures and the timings are not claimed to be constants.
- My monitoring failed to read the tasks in 4 of 12 samples during the failure (a defect of the script, not of the
  service); the service's health in those instants rests on the neighbouring samples and on the task never restarting.
