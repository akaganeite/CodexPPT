#!/usr/bin/env python3
"""Run Codex patch-presence batch detection."""

from __future__ import annotations

import sys
from pathlib import Path

from codex_batch.cli import parse_args
from codex_batch.orchestrator import run_batch


SCRIPT_DIR = Path(__file__).resolve().parent


def main() -> int:
    return run_batch(parse_args(SCRIPT_DIR), SCRIPT_DIR)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
