#!/usr/bin/env python3
"""The plan of the negative controls, taken from the code.

A check of the log of the controls must not rely on a file that travelled with that log: whoever could change the
log could change the file. This prints the expectation from the code of the checkout instead.
"""

import json
import sys

import run_agent


def main() -> int:
    print(json.dumps([{"action": action} for _, action in run_agent.CONTROLS]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
