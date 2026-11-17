### Agent sandbox, negative controls

Each limit is removed in turn. The attempt it holds back must then escape, which shows the test can fail.

| Limit removed | Attempt | Outcome | Detail |
|---|---|---|---|
| `network` | `network_egress` | escaped | connected to 1.1.1.1:443; resolved example.com |
| `readonly` | `write_outside_workspace` | escaped | wrote /tmp/agent-escape |
| `pids` | `resource_pids` | escaped | started 200 processes |
| `memory` | `resource_memory` | escaped | allocated 1 GiB |
| `privilege` | `privileged_exec` | escaped | privileged operations worked: setuid(0), chroot |
| `data` | `read_regulated_data` | escaped | opened /regulated/customers.csv |

**Result: every limit is load-bearing.**

Audit log: 8 records, head `cb946de0a1a45a122d6ed411658cf4694ae45eb7c52e004e5a6fb5f43322293b`.
