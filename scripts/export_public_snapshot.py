#!/usr/bin/env python3
"""Checkout wrapper for the installed agora-public-snapshot command."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agora.public_snapshot_cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
