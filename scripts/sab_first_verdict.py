#!/usr/bin/env python3
"""Offline/copy-only evidence CLI for SAB First Verdict Build A."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agora.sab_first_verdict_evidence import (  # noqa: E402
    EvidenceValidationError,
    backup_database_readonly,
    preview_contract_payload,
    preview_database_readonly,
    snapshot_database,
    validate_checkpoint_chain,
)
from agora.sab_first_verdict_fixture import (  # noqa: E402
    FixtureRunnerError,
    run_copied_database_rehearsal,
)
from agora.sab_first_verdict_lifecycle import LifecycleError  # noqa: E402
from agora.sab_first_verdict_storage import (  # noqa: E402
    CopyDatabaseAttestation,
    FirstVerdictStorageError,
)


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False))


def _print_canonical_json(payload: Any) -> None:
    print(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SAB First Verdict Build A evidence runner (offline/copy-only)"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    snapshot = subcommands.add_parser(
        "snapshot", help="snapshot one explicit SQLite path"
    )
    snapshot.add_argument("--database", type=Path, required=True)

    backup = subcommands.add_parser(
        "backup",
        help="online-backup a mode=ro source to an exclusive private destination",
    )
    backup.add_argument("--source", type=Path, required=True)
    backup.add_argument("--destination", type=Path, required=True)

    preview = subcommands.add_parser(
        "preview", help="run the exact generic-wrapper preview without writing"
    )
    preview.add_argument("--database", type=Path, required=True)
    preview.add_argument(
        "--contract-only",
        action="store_true",
        help="emit only the strict sab.compost_batch_preview.v1 payload",
    )

    checkpoints = subcommands.add_parser(
        "validate-checkpoints", help="validate an ordered JSON checkpoint chain"
    )
    checkpoints.add_argument("checkpoints", nargs="+", type=Path)
    checkpoints.add_argument("--expected-head")
    checkpoints.add_argument("--expected-tree-sha")
    checkpoints.add_argument("--expected-database-sha256")
    checkpoints.add_argument("--expected-lifecycle-fingerprint")

    rehearsal = subcommands.add_parser(
        "run-rehearsal",
        help=(
            "run the signed nine-seat lifecycle only on an explicitly attested "
            "A0 copied database"
        ),
    )
    rehearsal.add_argument("--copy-database", type=Path, required=True)
    rehearsal.add_argument(
        "--forbidden-source-database",
        type=Path,
        required=True,
        help="explicit source path which the runner must never write",
    )
    rehearsal.add_argument("--a0-copy-receipt", type=Path, required=True)
    rehearsal.add_argument(
        "--a0-copy-receipt-sha256",
        required=True,
        help="externally anchored SHA-256 from the A0 checkpoint chain",
    )
    rehearsal.add_argument("--source-backup-sha256", required=True)
    rehearsal.add_argument("--expected-lifecycle-fingerprint", required=True)
    rehearsal.add_argument("--code-sha", required=True)
    rehearsal.add_argument(
        "--verify-exact-retry",
        action="store_true",
        help="replay the same in-memory signed request and require byte identity",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "snapshot":
            result = snapshot_database(args.database)
        elif args.command == "backup":
            result = backup_database_readonly(args.source, args.destination)
        elif args.command == "preview":
            result = preview_database_readonly(args.database)
            if args.contract_only:
                result = preview_contract_payload(result)
        elif args.command == "validate-checkpoints":
            result = validate_checkpoint_chain(
                [_load_json(path) for path in args.checkpoints],
                expected_head=args.expected_head,
                expected_tree_sha=args.expected_tree_sha,
                expected_database_sha256=args.expected_database_sha256,
                expected_lifecycle_fingerprint=args.expected_lifecycle_fingerprint,
            )
        else:
            receipt_path = args.a0_copy_receipt
            attestation = CopyDatabaseAttestation(
                proof_class="copied_live_db_rehearsal",
                database_path=args.copy_database,
                source_database_path=args.forbidden_source_database,
                source_backup_sha256=args.source_backup_sha256,
                expected_lifecycle_fingerprint=args.expected_lifecycle_fingerprint,
                copy_receipt_sha256=args.a0_copy_receipt_sha256,
                copy_receipt_path=receipt_path,
            )
            result = run_copied_database_rehearsal(
                attestation,
                code_sha=args.code_sha,
                verify_exact_retry=args.verify_exact_retry,
            )
            _print_canonical_json(result)
            return 0
    except (
        EvidenceValidationError,
        FirstVerdictStorageError,
        FixtureRunnerError,
        LifecycleError,
        OSError,
        sqlite3.Error,
    ) as exc:
        code = getattr(exc, "code", "evidence_error")
        _print_json({"ok": False, "error": code, "detail": str(exc)})
        return 2
    _print_json(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
