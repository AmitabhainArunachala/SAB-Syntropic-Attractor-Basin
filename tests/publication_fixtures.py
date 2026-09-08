"""Offline publication of synthetic test records, never production data."""

from __future__ import annotations

import hashlib
import importlib
import sqlite3
import sys
from contextlib import contextmanager


OBSERVED_AT = "2026-09-09T00:00:00+00:00"


@contextmanager
def source_database():
    from agora.sab_seeding_api import _init_v1_tables

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_v1_tables(conn)
    try:
        yield conn
    finally:
        conn.close()


def configure_publication(source, bundle_dir, monkeypatch):
    from agora.public_snapshot import (
        export_empty_public_snapshot,
        export_public_snapshot,
        plan_public_snapshot,
    )

    bundle_dir = bundle_dir.resolve()
    source.commit()
    seed_ids = [
        row[0] for row in source.execute("SELECT seed_id FROM sab_seed_packets_v1 ORDER BY seed_id")
    ]
    if seed_ids:
        review = plan_public_snapshot(source, seed_ids, observed_at=OBSERVED_AT)
        for record in review["records"]:
            record.update(
                {
                    "decision": "approve",
                    "publication_basis": "own_work",
                    "license": "MIT",
                    "privacy_review": {"status": "approved", "reviewer": "test fixture author"},
                    "consent": {
                        "required": False,
                        "satisfied": True,
                        "basis": "No real people or private records",
                    },
                    "takedown": {
                        "owner": "SAB test maintainer",
                        "route": "https://example.org/test-fixture-corrections",
                    },
                }
            )
            for document in record["raw_json_review"].values():
                document.update({"classification": "public_original", "extensions_reviewed": True})
        export_public_snapshot(source, bundle_dir, review, observed_at=OBSERVED_AT)
    else:
        export_empty_public_snapshot(bundle_dir, observed_at=OBSERVED_AT)
    monkeypatch.setenv("SAB_PUBLIC_SNAPSHOT", str(bundle_dir))
    monkeypatch.setenv(
        "SAB_PUBLIC_SNAPSHOT_SHA256",
        hashlib.sha256((bundle_dir / "manifest.json").read_bytes()).hexdigest(),
    )
    return bundle_dir


def import_public_app(tmp_path, monkeypatch, *, mode="public_readonly"):
    monkeypatch.setenv("SAB_PUBLIC_MODE", mode)
    for name in ("SAB_SPARK_DB_PATH", "SAB_AUTHORITY_DB_PATH", "SAB_DB_PATH"):
        monkeypatch.setenv(name, str(tmp_path / "private" / "authority.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "private" / "system.key"))
    monkeypatch.delitem(sys.modules, "agora.app", raising=False)
    return importlib.import_module("agora.app")


def database_observation(module):
    """Compare stored schema and rows using only the public reader's SELECTs."""
    with module._db() as conn:
        schema = tuple(
            tuple(row)
            for row in conn.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name"
            )
        )
        data = []
        for kind, name, _, _ in schema:
            if kind == "table":
                quoted = '"' + name.replace('"', '""') + '"'
                data.append(
                    (
                        name,
                        tuple(
                            tuple(row)
                            for row in conn.execute("SELECT * FROM " + quoted + " ORDER BY rowid")
                        ),
                    )
                )
        return schema, tuple(data)
