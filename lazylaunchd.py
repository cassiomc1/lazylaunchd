#!/usr/bin/env python3
"""Top-level convenience launcher for lazylaunchd."""

from __future__ import annotations

import sys

from lazylaunchd.cli import main

if __name__ == "__main__":
    sys.exit(main())
