#!/usr/bin/env python3
"""Integrity-check and render existing unsigned SAB ceremony packets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agora.sab_first_verdict_approval import (  # noqa: E402
    ApprovalPacketError,
    render_operator_approval_markdown,
    verify_operator_approval_packet,
)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ApprovalPacketError(
                "approval_input_duplicate_key",
                "approval input contains a duplicate JSON key",
            )
        value[key] = child
    return value


def _load_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle, object_pairs_hook=_unique_object)
    if not isinstance(value, dict):
        raise ApprovalPacketError("input_shape_invalid", "input must be a JSON object")
    return value


def _print_json(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify or render an existing non-authorizing SAB ceremony packet; "
            "trusted packets can only be built from in-memory typed evidence"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify-unsigned-packet")
    verify.add_argument("--packet", type=Path, required=True)

    render = commands.add_parser("render-unsigned-packet")
    render.add_argument("--packet", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        packet = _load_object(args.packet)
        if args.command == "verify-unsigned-packet":
            result = verify_operator_approval_packet(packet)
            _print_json(result)
        else:
            print(render_operator_approval_markdown(packet), end="")
    except ApprovalPacketError as exc:
        _print_json({"ok": False, "error": exc.code, "detail": str(exc)})
        return 2
    except (OSError, json.JSONDecodeError):
        _print_json(
            {
                "ok": False,
                "error": "approval_input_unreadable",
                "detail": "approval input could not be read as JSON",
            }
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
