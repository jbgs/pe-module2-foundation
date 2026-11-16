<!-- ai-review:v1 -->
### AI review (advisory)
> Written by an AI model from the diff of commit `fdea812`. It is **not** an approval and it does not block the merge: a person reads the diff and decides.

### Summary
- At startup, `main()` in `app/main.py` writes the current Unix epoch time, as a float string, to the fixed path `/tmp/started-at`. It does this before the HTTP server is created.
- The code comment says the timestamp is "for whoever reads the logs later", but the value goes to a local file, not to the log stream.

### Risks
- **A failed write stops the service from starting** (`app/main.py`, new lines 85–86). The `open()` call has no error handling and runs before `make_server`. If the container runs with a read-only root filesystem and has no writable `/tmp` mount, or if `/tmp` is not writable for the process user, the exception ends `main()`. The orchestrator would then restart the task in a loop. A diagnostic convenience should not be able to cause an outage.
- **The value never reaches the logs** (`app/main.py`, line 84 comment vs. lines 85–86). `/tmp` inside a container is ephemeral and is not collected by the log driver. The file disappears when the task stops, which is usually when someone wants to know the start time. Logging the timestamp to stdout/stderr would match the stated purpose and carry no filesystem risk.
- **Predictable path in a shared temp directory** (`app/main.py`, line 85). Opening a fixed name in `/tmp` with mode `"w"` follows an existing symlink and truncates its target. Inside a single-process container this is low risk. If the app ever runs on a shared host, another user could pre-create `/tmp/started-at` as a symlink to a file this process can write.
- **Multiple instances overwrite each other** (`app/main.py`, line 85). Several processes sharing a filesystem (local runs, tests, a shared volume) all write the same path. The file then holds only the last writer's time, with nothing to say which process wrote it.
- **The format is hard to read** (`app/main.py`, line 86). `str(time.time())` produces something like `1712345678.123456`, a float without a timezone. An ISO 8601 UTC string would be easier for a human or a log query to read.

### Questions
- Who or what reads `/tmp/started-at`? If nothing does, logging the start time at startup may be all this change needs.
- Does the task definition or pod spec set a read-only root filesystem, or drop write access to `/tmp`?
- Is there a reason the file is written before the server starts? Writing it after a successful bind would make the timestamp mean "started serving" rather than "process began".

### Not verified
- Whether the deployed container's filesystem, mounts and user ID allow writing to `/tmp` (for example `readonlyRootFilesystem` in ECS, `securityContext` in Kubernetes, or a non-root user in the image).
- Whether any existing tooling, health check or sidecar expects this file.
- Whether the app's tests call `main()`. If they do, they will now write to the real `/tmp` of the test host.

<sub>model: `claude-opus-5-5` · input tokens: 789 · output tokens: 1292 · 14.0 s · trace: artifact `ai-trace` of this workflow run</sub>
