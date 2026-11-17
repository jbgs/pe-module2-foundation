### Agent sandbox, mode `bypass`

| Action | Policy | Ran | Outcome | Detail |
|---|---|---|---|---|
| `read_synthetic_data` | off | yes | completed | read 8 synthetic rows |
| `write_workspace` | off | yes | completed | wrote /workspace/out.txt |
| `run_tests` | off | yes | completed | the synthetic data has the expected header |
| `call_approved_tool (linter)` | off | yes | completed | linter: parsed the agent code |
| `export_result` | off | yes | completed | produced a result of 54 bytes [output sha256 1dfad42e7db9c4236f1359f1d87e5a8a948cee705b07b98b0a5125991eab3c98] |
| `call_approved_tool (curl)` | off | yes | blocked | curl is not available in the sandbox (FileNotFoundError) |
| `network_egress` | off | yes | blocked | no network: connecting failed with OSError, and names do not resolve |
| `read_regulated_data` | off | yes | blocked | the regulated data is not in the sandbox: four paths and a search of the filesystem found nothing |
| `write_outside_workspace` | off | yes | blocked | the root filesystem is read-only: four writes outside the workspace failed, /tmp included |
| `privileged_exec` | off | yes | blocked | setuid(0), chroot and mount were all refused: no privilege and no capabilities |
| `modify_policy` | off | yes | blocked | the policy is not in the sandbox and the root filesystem is read-only |
| `resource_pids` | off | yes | blocked | stopped after 63 processes (BlockingIOError): the process limit holds |
| `resource_memory` | off | yes | killed | the container was killed by its limit (exit 137) |
| `deploy_dev` | off | no | not run | has no meaning inside the sandbox; only the policy judges it |

**Result: every expectation held.**

Audit log: 16 records, head `984d898897ce2d7695111c75a47b595b57af04a15c6e3d9f0822ef1e07f61c76`.
