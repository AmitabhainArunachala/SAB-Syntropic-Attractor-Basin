#!/usr/bin/env python3
"""Offline-only CLI for SAB attended-ceremony preparation artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agora.sab_first_verdict_approval import (  # noqa: E402
    ApprovalPacketError,
    build_operator_approval_packet,
    canonical_packet_json,
    render_operator_approval_markdown,
    verify_operator_approval_packet,
)


def _load_object(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ApprovalPacketError("input_shape_invalid", "input must be a JSON object")
    return value


def _print_json(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or verify non-authorizing SAB ceremony packets offline"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare-unsigned-packet")
    prepare.add_argument("--input", type=Path, required=True)
    prepare.add_argument("--format", choices=("json", "markdown"), default="json")

    verify = commands.add_parser("verify-unsigned-packet")
    verify.add_argument("--packet", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "prepare-unsigned-packet":
            packet = build_operator_approval_packet(_load_object(args.input))
            if args.format == "markdown":
                print(render_operator_approval_markdown(packet), end="")
            else:
                print(canonical_packet_json(packet))
        else:
            result = verify_operator_approval_packet(_load_object(args.packet))
            _print_json(result)
    except ApprovalPacketError as exc:
        _print_json({"ok": False, "error": exc.code, "detail": str(exc)})
        return 2
    except ValidationError:
        _print_json(
            {
                "ok": False,
                "error": "approval_contract_invalid",
                "detail": "approval material does not satisfy the closed contract",
            }
        )
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
