#!/usr/bin/env python3
"""Checkout wrapper for the installed agora-public-inspect command."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agora.public_inspection import inspect, main  # noqa: E402,F401

if __name__ == "__main__":
    main()
