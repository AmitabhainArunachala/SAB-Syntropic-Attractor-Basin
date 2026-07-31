#!/usr/bin/env python3
"""Independent offline verifier for SAB First Verdict Build A artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agora.sab_first_verdict_evidence import (  # noqa: E402
    EvidenceValidationError,
    open_sqlite_readonly,
    validate_checkpoint_chain,
    verify_database_snapshot,
)
from agora.sab_verdict_verify import (  # noqa: E402
    ReplayValidationError,
    verify_evidence_partition,
    verify_new_signature_table,
)


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SAB First Verdict offline verifier")
    subcommands = parser.add_subparsers(dest="command", required=True)

    snapshot = subcommands.add_parser("snapshot")
    snapshot.add_argument("--database", type=Path, required=True)
    snapshot.add_argument("--expected", type=Path, required=True)

    replay = subcommands.add_parser("replay")
    replay.add_argument("--legacy-events", type=Path, required=True)
    replay.add_argument("--new-signatures", type=Path, required=True)
    replay.add_argument("--require-artifact-type", action="append", default=[])

    database_replay = subcommands.add_parser("database-replay")
    database_replay.add_argument("--database", type=Path, required=True)
    database_replay.add_argument("--require-event-type", action="append", default=[])

    chain = subcommands.add_parser("checkpoint-chain")
    chain.add_argument("checkpoints", nargs="+", type=Path)
    chain.add_argument("--expected-head")
    chain.add_argument("--expected-tree-sha")
    chain.add_argument("--expected-database-sha256")
    chain.add_argument("--expected-lifecycle-fingerprint")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "snapshot":
            result = verify_database_snapshot(args.database, _load_json(args.expected))
            if not result["verified"]:
                raise EvidenceValidationError(
                    "snapshot_mismatch", "database does not match expected snapshot"
                )
        elif args.command == "replay":
            legacy = _load_json(args.legacy_events)
            signatures = _load_json(args.new_signatures)
            result = verify_evidence_partition(
                legacy_events=legacy,
                new_signature_records=signatures,
                required_artifact_types=args.require_artifact_type,
            )
        elif args.command == "database-replay":
            with closing(open_sqlite_readonly(args.database)) as conn:
                result = verify_new_signature_table(
                    conn,
                    required_event_types=args.require_event_type,
                )
        else:
            result = validate_checkpoint_chain(
                [_load_json(path) for path in args.checkpoints],
                expected_head=args.expected_head,
                expected_tree_sha=args.expected_tree_sha,
                expected_database_sha256=args.expected_database_sha256,
                expected_lifecycle_fingerprint=args.expected_lifecycle_fingerprint,
            )
    except (EvidenceValidationError, ReplayValidationError, OSError, ValueError) as exc:
        _print_json(
            {
                "ok": False,
                "error": getattr(exc, "code", "verification_error"),
                "detail": str(exc),
            }
        )
        return 2
    _print_json(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
