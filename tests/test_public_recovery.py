"""A retained approval must survive backup faults without approving new bytes."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "rehearse_public_recovery.py"
SPEC = importlib.util.spec_from_file_location("rehearse_public_recovery", SCRIPT)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)


def _empty_bundle(path):
    from agora.public_snapshot import export_empty_public_snapshot

    export_empty_public_snapshot(path, observed_at="2026-09-09T00:00:00+00:00")
    return hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("fault", ["different_manifest", "damaged_database", "unexpected_member"])
def test_faulty_backup_cannot_create_a_restored_publication(tmp_path, fault):
    # App isolation tests reload agora modules after collection. Match the
    # current loader's exception class, not a stale collection-time import.
    from agora.public_snapshot import PublicSnapshotError

    bundle = tmp_path / "backup"
    approved_pin = _empty_bundle(bundle)
    if fault == "different_manifest":
        with (bundle / "manifest.json").open("ab") as stream:
            stream.write(b" ")
    elif fault == "damaged_database":
        with (bundle / "snapshot.sqlite3").open("ab") as stream:
            stream.write(b"unexpected database bytes")
    else:
        (bundle / "snapshot.sqlite3-wal").write_bytes(b"unreviewed state")
    restored = tmp_path / "restored"
    with pytest.raises(PublicSnapshotError):
        recovery._copy_bundle(bundle, restored, approved_pin)
    assert not restored.exists()


def test_restore_preserves_bytes_and_refuses_an_existing_destination(tmp_path):
    bundle = tmp_path / "backup"
    approved_pin = _empty_bundle(bundle)
    restored = tmp_path / "restored"
    result = recovery._copy_bundle(bundle, restored, approved_pin)
    assert result["retained_manifest_sha256"] == approved_pin
    for name in recovery.MEMBERS:
        assert (restored / name).read_bytes() == (bundle / name).read_bytes()
    before = {name: (restored / name).read_bytes() for name in recovery.MEMBERS}
    with pytest.raises(FileExistsError):
        recovery._copy_bundle(bundle, restored, approved_pin)
    assert {name: (restored / name).read_bytes() for name in recovery.MEMBERS} == before
