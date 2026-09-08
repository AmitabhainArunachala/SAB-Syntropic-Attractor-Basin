#!/usr/bin/env python3
"""Plan exact private publication reviews, or create a fresh approved public bundle.

The review skeleton is private and unapproved. Export requires an explicit
approval for every record in the complete selected seed closure. Originals are
published intact or the export fails; this command never silently redacts them.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agora.public_snapshot import (  # noqa: E402
    PublicSnapshotError,
    _canonical,
    _no_symlinks,
    _strict_json,
    export_empty_public_snapshot,
    export_public_snapshot,
    plan_public_snapshot,
)


@contextmanager
def _source(path_value: str):
    path = Path(path_value).absolute()
    _no_symlinks(path)
    if not path.is_file():
        raise PublicSnapshotError(
            "source_missing", "The source must be an existing regular SQLite file."
        )
    if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise PublicSnapshotError(
            "source_sidecars",
            "Use a quiescent standalone source without SQLite sidecars; no WAL content is ignored.",
        )
    with path.open("rb") as stream:
        header = stream.read(20)
    if header[:16] != b"SQLite format 3\0" or header[18:20] != b"\x01\x01":
        raise PublicSnapshotError(
            "source_format", "The source must be a standalone SQLite image without WAL dependence."
        )
    conn = sqlite3.connect(f"file:{quote(str(path), safe='/')}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    try:
        yield conn
    finally:
        conn.close()


def _write_private_review(path_value: str, review: dict) -> str:
    path = Path(path_value).absolute()
    _no_symlinks(path)
    content = (json.dumps(review, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode(
        "ascii"
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(content).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser(
        "plan",
        aliases=["inspect"],
        help="write a private exact-record review skeleton; never approves or publishes",
    )
    plan.add_argument(
        "--source", required=True, help="existing quiescent SQLite source; opened read-only"
    )
    plan.add_argument(
        "--seed-id",
        action="append",
        required=True,
        help="exact selected seed ID; repeat for multiple seeds",
    )
    plan.add_argument("--observed-at", required=True, help="fixed ISO-8601 timestamp with timezone")
    plan.add_argument(
        "--review-out", required=True, help="new private review JSON file (create-only, mode 0600)"
    )
    export = commands.add_parser(
        "export", help="create a new bundle from completed exact-record approvals"
    )
    export.add_argument(
        "--source",
        required=True,
        help="same quiescent source; any closure change invalidates prior review",
    )
    export.add_argument("--review", required=True, help="completed private review JSON")
    export.add_argument(
        "--bundle", required=True, help="new bundle directory under an existing real parent"
    )
    empty = commands.add_parser(
        "empty", help="create an explicit empty bundle offline, without any source database"
    )
    empty.add_argument(
        "--bundle", required=True, help="new bundle directory under an existing real parent"
    )
    empty.add_argument(
        "--observed-at", required=True, help="fixed ISO-8601 timestamp with timezone"
    )
    args = parser.parse_args(argv)
    try:
        if args.command in {"plan", "inspect"}:
            with _source(args.source) as conn:
                review = plan_public_snapshot(conn, args.seed_id, observed_at=args.observed_at)
            digest = _write_private_review(args.review_out, review)
            result = {
                "status": "review_required",
                "generated_skeleton_is_approval": False,
                "record_count": review["source_observation"]["record_count"],
                "private_review_sha256": digest,
            }
        else:
            if args.command == "empty":
                manifest = export_empty_public_snapshot(args.bundle, observed_at=args.observed_at)
            else:
                review_path = Path(args.review).absolute()
                _no_symlinks(review_path)
                try:
                    review = _strict_json(review_path.read_bytes())
                except (ValueError, TypeError, RecursionError) as exc:
                    raise PublicSnapshotError(
                        "review_json", "The private review is not strict JSON."
                    ) from exc
                with _source(args.source) as conn:
                    manifest = export_public_snapshot(conn, args.bundle, review)
            result = {
                "status": "created",
                "manifest_sha256": hashlib.sha256(_canonical(manifest) + b"\n").hexdigest(),
                "seed_count": len(manifest["selected_seed_ids"]),
                "publication_effect": "publication_only",
            }
        print(json.dumps(result, sort_keys=True))
        return 0
    except PublicSnapshotError as exc:
        print(
            json.dumps({"status": "rejected", "code": exc.code, "detail": str(exc)}),
            file=sys.stderr,
        )
        return 2
    except (OSError, sqlite3.Error):
        print(
            json.dumps(
                {
                    "status": "rejected",
                    "code": "file_or_database_error",
                    "detail": "The requested source or new output could not be accessed safely.",
                }
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
