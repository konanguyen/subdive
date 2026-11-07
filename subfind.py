#!/usr/bin/env python3
"""Backwards-compatible entry point.

The tool was renamed to ``subdive``. This shim keeps old commands such as
``python subfind.py -d example.com`` working.
"""

from subdive import main

if __name__ == "__main__":
    raise SystemExit(main())
