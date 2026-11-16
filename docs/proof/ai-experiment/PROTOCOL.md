# Experiment: does the AI review surface defects early? (fixed before any call, 2026-11-16)

Hypothesis: the AI review flags, before merge, defects that CI does not catch, and does so faster than
run-time detection.

Method: 5 small diffs against the real code, one planted defect each, neutral titles. One run per diff,
same prompt, model and parameters as the workflow (ai_review.build_prompt + call_model). No re-runs to
improve a result; a run that errors is repeated once and both are recorded. Nothing is posted anywhere.

Ground truth, one defect per diff (a diff counts as DETECTED only if the Risks section names this
mechanism; a vague "check runtime behaviour" does not count; a conditional that names it does):
  D1 control  /tmp write at start-up while the task root filesystem is read-only
  D2          /healthz returns 503 unless /app/ready exists, and nothing creates that file
  D3          default port 8000 while the image, task definition and health check use 8080
  D4          DATABASE_URL read with os.environ[...] (hard failure) and not set in the task definition
  D5          new ingress rule open to 0.0.0.0/0 on the service port

Decision rule: tick "AI assistance measurably speeds the pipeline" only as "earlier feedback", and only if
  (a) DETECTED >= 3 of 5, and
  (b) the median call duration is under 60 s.
Otherwise the result is reported as negative. False positives (Risks items that are not real) are counted
and reported either way.

Limits stated in advance: n=5, defects chosen by the assistant, planted not organic, D1 is not independent
of the earlier PR #12 run. This measures earlier feedback, not pipeline throughput.
