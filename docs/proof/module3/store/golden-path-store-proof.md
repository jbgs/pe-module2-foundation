# Golden path: real runs on main, read back from the audit store (2026-11-17)

Runs: 44077933560 (covered), 44078043470 (not covered). Store keys: agent-runs/golden-path/<run>-1/usage.jsonl

```
Golden path: adoption

Environments made through the path: 1  {'agent-sandbox': 1}
Understood, waiting for a yes:       0
Intents the path did not cover:      1 of 2 asked (50% covered)
    - 'I need a kubernetes cluster for batch jobs'
Time to an environment, median:     1 ms (longest 1 ms)

Agent runs that came from an environment of the path: 0
Agent runs that did not (going around the path):      0   path share n/a
Agent runs naming an environment the path never made:  0
Runs that test the platform itself (not counted):      0
```

No 'Not counted' line: both chains verified.
