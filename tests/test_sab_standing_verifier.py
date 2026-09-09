from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agora.sab_seeding_api import _init_v1_tables  # noqa: E402
from scripts.sab_verify import STATUS_VOCAB, verify  # noqa: E402

DOGFOOD_DIR = (
    REPO_ROOT
    / "docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood"
)

NOW = datetime(2026, 7, 5, 12, 0, 0, tzinfo=timezone.utc)
FUTURE = (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
PAST = (NOW - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _seed_packet(labels=None, disclosure=None, claimant="agent_claimant"):
    packet = {
        "schema": "sab.seed_packet.v1",
        "claimant_identity": {"subject_id": claimant},
        "labels": labels or [],
    }
    if disclosure is not None:
        packet["operator_backing"] = {
            "disclosure": disclosure,
            "operator_ref": "operator_test",
        }
    return packet


def _insert_seed(conn, seed_id, state, packet, claim_id=None, packet_hash=None):
    conn.execute(
        """
        INSERT INTO sab_seed_packets_v1
            (seed_id, seed_type, title, claim_id, claimant_identity, authority_lease_id,
             state, packet_json, packet_hash, spark_projection_id,
             challenge_window_closes_at, created_at, updated_at)
        VALUES (?, 'claim', ?, ?, ?, 'lease_x', ?, ?, ?, NULL, NULL, ?, ?)
        """,
        (
            seed_id,
            f"title {seed_id}",
            claim_id or f"claim_{seed_id}",
            str(packet["claimant_identity"]["subject_id"]),
            state,
            json.dumps(packet),
            packet_hash or f"hash_{seed_id}",
            "2026-07-01T00:00:00Z",
            "2026-07-01T00:00:00Z",
        ),
    )


def _insert_lease(
    conn,
    standing_id,
    seed_id,
    status="active",
    expiry=FUTURE,
    scope="scope text",
    purpose="purpose text",
    issued_by="agent_witness",
):
    conn.execute(
        """
        INSERT INTO sab_standing_leases_v1
            (standing_id, subject_seed_id, subject_claim_id, scope, purpose, status,
             lease_json, lease_hash, expiry, revoker, challenge_path,
             issued_by, issued_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'revoker_x', ?, ?, ?, ?)
        """,
        (
            standing_id,
            seed_id,
            f"claim_{seed_id}",
            scope,
            purpose,
            status,
            json.dumps({"standing_id": standing_id}),
            f"leasehash_{standing_id}",
            expiry,
            f"/api/v1/standing/{standing_id}/challenge",
            issued_by,
            "2026-07-01T00:00:00Z",
            "2026-07-01T00:00:00Z",
        ),
    )


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "verifier_test.db"
    conn = sqlite3.connect(path)
    _init_v1_tables(conn)

    _insert_seed(conn, "seed_plain", "standing_active", _seed_packet())
    _insert_lease(conn, "standing_plain", "seed_plain")

    rehearsal_packet = _seed_packet(
        labels=["single_operator_rehearsal", "not_cross_operator_independent"],
        disclosure="same operator controls claimant, challenger, and witness in this rehearsal",
    )
    _insert_seed(conn, "seed_rehearsal", "standing_active", rehearsal_packet)
    _insert_lease(
        conn,
        "standing_rehearsal",
        "seed_rehearsal",
        scope="single_operator_rehearsal; not_cross_operator_independent",
    )

    _insert_seed(conn, "seed_stale", "standing_active", _seed_packet())
    _insert_lease(conn, "standing_stale", "seed_stale", status="active", expiry=PAST)

    _insert_seed(conn, "seed_revoked", "revoked", _seed_packet())
    _insert_lease(conn, "standing_revoked", "seed_revoked", status="revoked")

    _insert_seed(conn, "seed_challenged", "challenged", _seed_packet())

    _insert_seed(
        conn,
        "seed_by_hash",
        "witnessed",
        _seed_packet(),
        packet_hash="deadbeef" * 8,
    )

    _insert_seed(conn, "seed_selfie", "standing_active", _seed_packet(claimant="agent_same"))
    _insert_lease(conn, "standing_selfie", "seed_selfie", issued_by="agent_same")

    conn.commit()
    conn.close()
    return path


def test_recorded_active_lease_does_not_establish_current_reliance(db_path: Path) -> None:
    before = db_path.read_bytes()
    result = verify("standing_plain", db_path=db_path, now=NOW)
    assert result["status"] == "unknown"
    assert result["resolved_as"] == "standing_lease"
    assert result["source"] == "sqlite_ro"
    assert result["raw_status"] == result["recorded_status"] == "active"
    assert result["expires_at"] == FUTURE
    assert result["independence_status"] == "undisclosed"
    assert result["rehearsal_markers"] == []
    _assert_no_current_reliance(result)
    assert db_path.read_bytes() == before


def _assert_no_current_reliance(result):
    assert result["effective_reliance"] == "unestablished"
    assert result["current_use_eligible"] is False
    assert result["control_verification_status"] == "not_verified"
    assert result["historical_integrity"] == "not_verified"
    assert result["authority_effect"] == result["standing_effect"] == "none"


@pytest.mark.parametrize("status", ["active", "canon", "provisional"])
@pytest.mark.parametrize("expiry", ["", "invalid-date", "2026-08-01T00:00:00", FUTURE])
def test_recorded_promotion_needs_current_verified_control(
    db_path: Path, status: str, expiry: str
) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE sab_standing_leases_v1 SET status = ?, expiry = ? WHERE standing_id = ?",
            (status, expiry, "standing_plain"),
        )
    before = db_path.read_bytes()
    result = verify("standing_plain", db_path=db_path, now=NOW)
    assert result["status"] == "unknown"
    assert result["raw_status"] == result["recorded_status"] == status
    assert result["expires_at"] == expiry
    _assert_no_current_reliance(result)
    assert db_path.read_bytes() == before


def test_rehearsal_markers_downgrade_active_to_rehearsal_only(db_path: Path) -> None:
    result = verify("standing_rehearsal", db_path=db_path, now=NOW)
    assert result["status"] == "rehearsal_only"
    assert "single_operator_rehearsal" in result["rehearsal_markers"]
    assert result["independence_status"] == "same_operator_distinct_keys"


def test_expiry_computed_read_only_without_mutating_row(db_path: Path) -> None:
    result = verify("standing_stale", db_path=db_path, now=NOW)
    assert result["status"] == "expired"
    conn = sqlite3.connect(db_path)
    stored = conn.execute(
        "SELECT status FROM sab_standing_leases_v1 WHERE standing_id = 'standing_stale'"
    ).fetchone()[0]
    conn.close()
    assert stored == "active"  # verifier answered expired without writing


def test_revoked_lease(db_path: Path) -> None:
    result = verify("standing_revoked", db_path=db_path, now=NOW)
    assert result["status"] == "revoked"


@pytest.mark.parametrize("status", ["compost", "superseded"])
def test_terminal_history_stays_terminal(db_path: Path, status: str) -> None:
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE sab_standing_leases_v1 SET status = ? WHERE standing_id = ?",
                     (status, "standing_plain"))
    before = db_path.read_bytes()
    result = verify("standing_plain", db_path=db_path, now=NOW)
    assert result["status"] == "revoked"
    assert result["raw_status"] == result["recorded_status"] == status
    _assert_no_current_reliance(result)
    assert db_path.read_bytes() == before


def test_challenged_seed_without_lease(db_path: Path) -> None:
    result = verify("seed_challenged", db_path=db_path, now=NOW)
    assert result["status"] == "challenged"
    assert result["resolved_as"] == "seed"
    assert result["standing_id"] is None


def test_lookup_by_claim_hash(db_path: Path) -> None:
    result = verify("deadbeef" * 8, db_path=db_path, now=NOW)
    assert result["seed_id"] == "seed_by_hash"
    assert result["status"] == "unknown"  # witnessed seed, no lease issued
    assert any("no standing lease" in note for note in result["notes"])


def test_self_issued_lease_grades_independence_self(db_path: Path) -> None:
    result = verify("standing_selfie", db_path=db_path, now=NOW)
    assert result["independence_status"] == "self"
    assert result["status"] == "unknown"
    assert result["recorded_status"] == "active"
    _assert_no_current_reliance(result)


def test_nonexistent_identifier_answers_unknown(db_path: Path) -> None:
    result = verify("does_not_exist_anywhere", db_path=db_path, now=NOW)
    assert result["status"] == "unknown"
    assert result["resolved_as"] == "none"
    assert result["independence_status"] == "unknown"


def test_status_always_in_declared_vocabulary(db_path: Path) -> None:
    for ident in (
        "standing_plain",
        "standing_rehearsal",
        "standing_stale",
        "standing_revoked",
        "seed_challenged",
        "missing_id",
    ):
        result = verify(ident, db_path=db_path, now=NOW)
        assert result["status"] in STATUS_VOCAB
        _assert_no_current_reliance(result)


def _receipt(tmp_path: Path, body: dict) -> tuple[Path, Path]:
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    path = receipts / "001.response.json"
    path.write_text(json.dumps({"body": body}), encoding="utf-8")
    return receipts, path


@pytest.mark.parametrize("control", [
    None,
    {"grade": "unknown", "eligible": False},
    {"grade": "verified", "eligible": True, "expires_at": PAST},
    {"grade": "verified", "eligible": True, "expires_at": FUTURE,
     "independent_controller_count": 3, "participant_subject_ids": ["a", "b", "c"]},
])
def test_control_snapshot_cannot_establish_current_reliance(tmp_path: Path, control) -> None:
    body = {
        "standing_id": "standing_snapshot", "status": "active", "expiry": FUTURE,
        "issued_by": "agent_witness", "subject_seed_id": "seed_snapshot",
        "operator_control": control,
        "issued_under": {"tier": "active", "independent_operator_count": 3},
        "seed_packet": {"operator_backing": {"operator_id": "self-declared-a"}},
    }
    receipts, path = _receipt(tmp_path, body)
    before = path.read_bytes()
    missing_db = tmp_path / "absent.db"
    result = verify("standing_snapshot", db_path=missing_db, receipts_dir=receipts, now=NOW)
    assert result["status"] == "unknown"
    assert result["raw_status"] == result["recorded_status"] == "active"
    assert result["independence_status"] == "undisclosed"
    assert result["rehearsal_markers"] == []
    _assert_no_current_reliance(result)
    assert path.read_bytes() == before
    assert not missing_db.exists()


def test_seed_receipt_standing_active_without_a_lease_is_unknown(tmp_path: Path) -> None:
    receipts, path = _receipt(tmp_path, {"seed_id": "seed_snapshot", "state": "standing_active"})
    before = path.read_bytes()
    result = verify("seed_snapshot", db_path=tmp_path / "absent.db", receipts_dir=receipts, now=NOW)
    assert result["resolved_as"] == "seed"
    assert result["raw_status"] == result["recorded_status"] == "standing_active"
    assert result["status"] == "unknown"
    _assert_no_current_reliance(result)
    assert path.read_bytes() == before


@pytest.mark.parametrize("expiry, status", [
    (None, "unknown"), ([], "unknown"), ("invalid", "unknown"),
    ("2026-08-01T00:00:00", "unknown"), (NOW.isoformat(), "expired"),
])
def test_receipt_expiry_is_required_and_timezone_aware(tmp_path: Path, expiry, status) -> None:
    receipts, path = _receipt(tmp_path, {"standing_id": "standing_snapshot", "status": "active", "expiry": expiry})
    before = path.read_bytes()
    result = verify("standing_snapshot", db_path=tmp_path / "absent.db", receipts_dir=receipts, now=NOW)
    assert result["status"] == status
    assert result["expires_at"] == expiry
    assert result["recorded_status"] == "active"
    _assert_no_current_reliance(result)
    assert path.read_bytes() == before


def test_receipt_preserves_stored_status_and_captured_observation(tmp_path: Path) -> None:
    receipts, path = _receipt(tmp_path, {
        "standing_id": "standing_snapshot", "status": "unknown", "stored_status": "canon",
        "expiry": FUTURE,
    })
    before = path.read_bytes()
    result = verify("standing_snapshot", db_path=tmp_path / "absent.db", receipts_dir=receipts, now=NOW)
    assert result["raw_status"] == result["recorded_status"] == "canon"
    assert result["captured_status"] == "unknown"
    assert result["status"] == "unknown"
    _assert_no_current_reliance(result)
    assert path.read_bytes() == before


@pytest.mark.parametrize("compact", [False, True])
def test_cli_observes_signed_history_without_promoting_or_changing_it(tmp_path: Path, compact: bool) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    historical_lease = {
        "standing_id": "standing_cli", "status": "active", "expiry": "2100-01-01T00:00:00Z",
        "operator_control": {"grade": "verified", "eligible": True},
    }
    signed_bytes = json.dumps(historical_lease, sort_keys=True, separators=(",", ":")).encode()
    # A real historical signature still supplies no current trust policy or revocation view.
    historical_lease["signature"] = Ed25519PrivateKey.generate().sign(signed_bytes).hex()
    receipts, path = _receipt(tmp_path, historical_lease)
    before = path.read_bytes()
    missing_db = tmp_path / "not-created.db"
    args = [sys.executable, "-I", "-B", str(REPO_ROOT / "scripts" / "sab_verify.py"),
            "standing_cli", "--db", str(missing_db), "--receipts", str(receipts)]
    if compact:
        args.append("--compact")
    completed = subprocess.run(args, capture_output=True, text=True, timeout=15, check=True)
    result = json.loads(completed.stdout)
    assert result["status"] == "unknown"
    assert result["raw_status"] == result["recorded_status"] == "active"
    _assert_no_current_reliance(result)
    assert completed.stderr == ""
    lines = completed.stdout.splitlines()
    assert (len(lines) == 1) if compact else (len(lines) > 1)
    assert path.read_bytes() == before
    assert not missing_db.exists()


@pytest.mark.parametrize("payload", [[], None, {"body": {"seed_id": ["invalid"]}},
                                    {"body": {"seed_id": "seed_invalid", "seed_packet": {"operator_backing": []}}}])
def test_malformed_receipt_never_establishes_reliance(tmp_path: Path, payload) -> None:
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    path = receipts / "001.response.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()
    result = verify("seed_invalid", db_path=tmp_path / "absent.db", receipts_dir=receipts, now=NOW)
    assert result["status"] == "unknown"
    _assert_no_current_reliance(result)
    assert path.read_bytes() == before


def test_unreadable_database_is_an_unknown_observation(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"synthetic invalid sqlite bytes")
    before = path.read_bytes()
    result = verify("standing_missing", db_path=path, now=NOW)
    assert result["status"] == "unknown"
    _assert_no_current_reliance(result)
    assert path.read_bytes() == before


def test_database_path_uri_characters_remain_literal(db_path: Path, tmp_path: Path) -> None:
    path = tmp_path / "history?read-only#copy.db"
    before = db_path.read_bytes()
    path.write_bytes(before)
    files_before = set(tmp_path.iterdir())
    result = verify("standing_plain", db_path=path, now=NOW)
    assert result["raw_status"] == result["recorded_status"] == "active"
    assert result["source"] == "sqlite_ro"
    _assert_no_current_reliance(result)
    assert path.read_bytes() == before
    assert set(tmp_path.iterdir()) == files_before


@pytest.mark.skipif(not DOGFOOD_DIR.is_dir(), reason="dogfood receipts dir not present")
def test_receipts_fallback_resolves_dogfood_seed(tmp_path: Path) -> None:
    empty_db = tmp_path / "empty.db"
    conn = sqlite3.connect(empty_db)
    _init_v1_tables(conn)
    conn.commit()
    conn.close()
    result = verify(
        "sab_seed_dogfood_2026-07-05_pytest_c4f56810",
        db_path=empty_db,
        receipts_dir=DOGFOOD_DIR,
        now=NOW,
    )
    assert result["source"] == "dogfood_receipts"
    assert result["status"] == "rehearsal_only"
    assert result["independence_status"] in {"same_operator", "same_operator_distinct_keys"}
