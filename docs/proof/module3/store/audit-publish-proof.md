# The pipeline publishes the audit records to the store (2026-11-17)

Job `Publish the audit records` (workflow `Agent sandbox`), on `main` only, after every check has passed.

## The first real run (after #23): run 44052264497
The job wrote all nine objects (3 logs, 3 manifests, 3 head pointers) with the writer role, assumed through OIDC from main.
Eight of the nine attempts to change them were refused with the exact error expected. One was not: "shorten its
retention" returned InvalidArgument and not AccessDenied. The date used was in the past, and S3 refuses that as an invalid
request before it looks at the permission, so the attempt tested the request and not the role. The store was right;
the check was wrong. The job failed, as it should.

## The fix (#24), made in the order that proves it
The stand-in store in the tests was taught to check the date before the permission, as the real one does. With the old code
three tests failed, reproducing the real run. Then the code was fixed (a date one hour ahead: in the future and shorter than the
retention). 112 tests pass; the mutation check gained a weakening for it and catches all 32.

## After the fix: runs 44056277559 (commit of #24) and 44056335635 (commit of #25), both green
With the writer's own role, every attempt to change what was written is refused with the right error:

| Attempt | Expected | Got |
|---|---|---|
| write the same name again, with the condition | PreconditionFailed | PreconditionFailed |
| write the same name again, without the condition | AccessDenied | AccessDenied |
| write outside the prefix of the records | AccessDenied | AccessDenied |
| read the record back | AccessDenied | AccessDenied |
| delete the locked version | AccessDenied | AccessDenied |
| delete it with the bypass of the lock | AccessDenied | AccessDenied |
| shorten its retention | AccessDenied | AccessDenied |
| write the manifest again | PreconditionFailed | PreconditionFailed |
| write the head pointer again | PreconditionFailed | PreconditionFailed |

## Read back from AWS with an administrator profile (`publish_audit.py verify`)
All three runs stored (44052264497-1, 44056277559-1, 44056335635-1): "every log read back from the store passes the audit gate".
The store holds 6 objects per run plus 9 head pointers. Each object is locked (GOVERNANCE, until 7 days after it was written).
