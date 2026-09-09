"""Read-only SAB standing observation, without a current reliance grant.

Given a standing_id, seed_id, claim_id, claim_hash (seed packet_hash), or
lease_hash, answer:

    status in {active, challenged, revoked, expired, unknown, rehearsal_only}
    independence_status in {self, same_operator, same_operator_distinct_keys,
                            undisclosed, unknown}

Sources, in order:
  1. The local SQLite store (default: <repo>/data/spark.db), opened READ-ONLY
     (`file:...?mode=ro`). Expiry is computed without mutating stored history.
  2. Optional dogfood receipt JSONs (`--receipts DIR`): the numbered
     `*.response.json` snapshots written by the Demonstration Zero loop.
     Receipts are point-in-time snapshots, not the live store.

`recorded_status` and its compatibility alias `raw_status` preserve the source's
stored value. For receipts with both `stored_status` and an observed `status`,
`captured_status` also retains that observation. Neither establishes current use.
This tool does not verify historical signatures, trusted policy pins, current key
control, cohort scope, evidence or revocation. A signed snapshot cannot supply
the registry's current evaluation. Thus `effective_reliance` is `unestablished`
and `current_use_eligible` is false, including when history records active/canon.

`status` conservatively reports observable expiry, terminal/challenged history,
or rehearsal markers; otherwise it is unknown. `active` remains in the vocabulary
for compatibility but is never inferred from stored labels. Independence labels
describe disclosed relationships only: different keys, different operator
strings and absent rehearsal markers do not prove independent control.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = REPO_ROOT / "data" / "spark.db"

STATUS_VOCAB = ("active", "challenged", "revoked", "expired", "unknown", "rehearsal_only")

REHEARSAL_MARKERS = (
    "single_operator_rehearsal",
    "not_cross_operator_independent",
    "rehearsal",
)

# Recorded lease statuses -> observation vocabulary.
_LEASE_STATUS_MAP = {
    "revoked": "revoked",
    "expired": "expired",
    "challenged": "challenged",
    # Positive recorded statuses need expiry and control checks.
    # Other terminal statuses are mapped with an explicit note.
}

# Seed states -> observation vocabulary when no
# standing lease exists for the seed.
_SEED_STATE_MAP = {
    "challenged": "challenged",
    "revoked": "revoked",
    "expired": "expired",
}


def _parse_dt(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _connect_ro(db_path: Path) -> Optional[sqlite3.Connection]:
    if not db_path.is_file():
        return None
    conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def _collect_markers(*texts: Any) -> List[str]:
    found: List[str] = []
    for text in texts:
        if text is None:
            continue
        blob = json.dumps(text) if not isinstance(text, str) else text
        lower = blob.lower()
        for marker in REHEARSAL_MARKERS:
            if marker in lower and marker not in found:
                found.append(marker)
    return found


def _independence_status(
    seed_packet: Optional[Dict[str, Any]],
    claimant_identity: Optional[str],
    issuer_identity: Optional[str],
    markers: List[str],
) -> str:
    if claimant_identity and issuer_identity and claimant_identity == issuer_identity:
        return "self"
    disclosure = _operator_disclosure(seed_packet).lower()
    same_operator_disclosed = "same operator" in disclosure
    if same_operator_disclosed or "not_cross_operator_independent" in markers or (
        "single_operator_rehearsal" in markers
    ):
        if claimant_identity and issuer_identity and claimant_identity != issuer_identity:
            return "same_operator_distinct_keys"
        return "same_operator"
    # Disclosures are historical observations, never current control proofs.
    return "undisclosed"


def _operator_disclosure(seed_packet: Optional[Dict[str, Any]]) -> str:
    backing = (seed_packet or {}).get("operator_backing")
    if not isinstance(backing, dict):
        return ""
    disclosure = backing.get("disclosure")
    return disclosure if isinstance(disclosure, str) else ""


def _status_from_lease(
    raw_status: Any,
    expiry: Any,
    markers: List[str],
    now: datetime,
    notes: List[str],
) -> str:
    if not isinstance(raw_status, str):
        notes.append("recorded lease status is missing or malformed")
        return "unknown"
    if raw_status in _LEASE_STATUS_MAP:
        return _LEASE_STATUS_MAP[raw_status]
    if raw_status in ("compost", "superseded"):
        notes.append(f"raw lease status '{raw_status}' is terminal and outside the profile vocabulary; mapped to 'revoked'")
        return "revoked"
    if raw_status in ("active", "canon", "provisional"):
        expiry_dt = _parse_dt(expiry)
        if expiry_dt is None:
            notes.append("lease expiry is missing, malformed or timezone-ambiguous; current validity is unknown")
            return "unknown"
        if expiry_dt <= now:
            notes.append(
                "expiry computed at read time; the stored row may still say "
                f"'{raw_status}' because this verifier never writes"
            )
            return "expired"
        if markers:
            notes.append(
                "lease carries single-operator rehearsal markers; reported as rehearsal_only"
            )
            return "rehearsal_only"
        notes.append(
            "recorded promotion does not establish current independent control or reliance; "
            "a current trusted registry evaluation for the exact cohort and claim is required"
        )
        return "unknown"
    notes.append("unrecognized recorded lease status")
    return "unknown"


def _status_from_seed_state(state: str, markers: List[str], notes: List[str]) -> str:
    if state in _SEED_STATE_MAP:
        return _SEED_STATE_MAP[state]
    if state == "compost":
        notes.append("seed state 'compost' is outside the profile vocabulary; mapped to 'revoked'")
        return "revoked"
    if state == "standing_active" and markers:
        notes.append("seed records standing_active with rehearsal markers; reported as rehearsal_only")
        return "rehearsal_only"
    notes.append(
        f"seed exists (state='{state}') but no standing lease has been issued; "
        "standing status is unknown"
    )
    return "unknown"


def _base_result(query: str, db_path: Path) -> Dict[str, Any]:
    return {
        "query": query,
        "resolved_as": "none",
        "source": "none",
        "status": "unknown",
        "raw_status": None,
        "recorded_status": None,
        "captured_status": None,
        "effective_reliance": "unestablished",
        "current_use_eligible": False,
        "control_verification_status": "not_verified",
        "historical_integrity": "not_verified",
        "authority_effect": "none",
        "standing_effect": "none",
        "independence_status": "unknown",
        "expires_at": None,
        "standing_id": None,
        "seed_id": None,
        "claim_id": None,
        "claim_hash": None,
        "scope": None,
        "challenge_uri": None,
        "revocation_uri": None,
        "witness_event_count": None,
        "rehearsal_markers": [],
        "checked_at": None,
        "db_path": str(db_path),
        "notes": [
            "offline observation does not verify historical signatures or current operator-control eligibility; "
            "stored status, disclosures and receipt assessments do not establish current reliance"
        ],
    }


def _load_seed_packet(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    try:
        packet = json.loads(str(row["packet_json"]))
        return packet if isinstance(packet, dict) else None
    except (KeyError, ValueError, IndexError):
        return None


def _resolve_from_db(
    conn: sqlite3.Connection, identifier: str, result: Dict[str, Any], now: datetime
) -> bool:
    notes: List[str] = result["notes"]
    have_leases = _table_exists(conn, "sab_standing_leases_v1")
    have_seeds = _table_exists(conn, "sab_seed_packets_v1")
    if not have_leases and not have_seeds:
        notes.append("SAB v1 tables not present in this database")
        return False

    lease_row = None
    if have_leases:
        lease_row = conn.execute(
            "SELECT * FROM sab_standing_leases_v1 WHERE standing_id = ? OR lease_hash = ? "
            "ORDER BY id DESC LIMIT 1",
            (identifier, identifier),
        ).fetchone()

    seed_row = None
    if have_seeds:
        seed_row = conn.execute(
            "SELECT * FROM sab_seed_packets_v1 WHERE seed_id = ? OR claim_id = ? OR packet_hash = ? "
            "ORDER BY id DESC LIMIT 1",
            (identifier, identifier, identifier),
        ).fetchone()

    if lease_row is None and seed_row is not None and have_leases:
        lease_row = conn.execute(
            "SELECT * FROM sab_standing_leases_v1 WHERE subject_seed_id = ? ORDER BY id DESC LIMIT 1",
            (str(seed_row["seed_id"]),),
        ).fetchone()

    if lease_row is not None and seed_row is None and have_seeds:
        seed_row = conn.execute(
            "SELECT * FROM sab_seed_packets_v1 WHERE seed_id = ? LIMIT 1",
            (str(lease_row["subject_seed_id"]),),
        ).fetchone()

    if lease_row is None and seed_row is None:
        return False

    result["source"] = "sqlite_ro"
    seed_packet = _load_seed_packet(seed_row)

    if seed_row is not None:
        result["seed_id"] = str(seed_row["seed_id"])
        result["claim_id"] = str(seed_row["claim_id"])
        result["claim_hash"] = str(seed_row["packet_hash"])
        if _table_exists(conn, "sab_witness_events_v1"):
            result["witness_event_count"] = conn.execute(
                "SELECT COUNT(*) FROM sab_witness_events_v1 WHERE subject_seed_id = ?",
                (str(seed_row["seed_id"]),),
            ).fetchone()[0]

    claimant = str(seed_row["claimant_identity"]) if seed_row is not None else None

    if lease_row is not None:
        result["resolved_as"] = "standing_lease"
        result["standing_id"] = str(lease_row["standing_id"])
        result["raw_status"] = result["recorded_status"] = lease_row["status"]
        result["expires_at"] = lease_row["expiry"]
        result["scope"] = str(lease_row["scope"])
        result["challenge_uri"] = str(lease_row["challenge_path"]) or None
        result["revocation_uri"] = f"/api/v1/standing/{lease_row['standing_id']}/revoke"
        notes.append(
            "revocation_uri derived from the live route "
            "POST /api/v1/standing/{standing_id}/revoke; "
            "the lease itself stores a revoker identity, not a URI"
        )
        markers = _collect_markers(
            str(lease_row["scope"]),
            str(lease_row["purpose"]),
            str(lease_row["lease_json"]),
            (seed_packet or {}).get("labels"),
            _operator_disclosure(seed_packet),
        )
        result["rehearsal_markers"] = markers
        result["status"] = _status_from_lease(
            lease_row["status"], lease_row["expiry"], markers, now, notes
        )
        result["independence_status"] = _independence_status(
            seed_packet, claimant, str(lease_row["issued_by"]), markers
        )
        return True

    # Seed found, no lease.
    result["resolved_as"] = "seed"
    result["raw_status"] = result["recorded_status"] = seed_row["state"]
    markers = _collect_markers(
        (seed_packet or {}).get("labels"),
        _operator_disclosure(seed_packet),
    )
    result["rehearsal_markers"] = markers
    result["status"] = _status_from_seed_state(str(seed_row["state"]), markers, notes)
    result["independence_status"] = _independence_status(seed_packet, claimant, None, markers)
    return True


def _resolve_from_receipts(
    receipts_dir: Path, identifier: str, result: Dict[str, Any], now: datetime
) -> bool:
    notes: List[str] = result["notes"]
    matches: List[Dict[str, Any]] = []
    for path in sorted(receipts_dir.glob("*.response.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            continue
        body = payload.get("body") if isinstance(payload, dict) else None
        if not isinstance(body, dict):
            continue
        candidates = (
            body.get("standing_id"),
            body.get("seed_id"),
            body.get("claim_id"),
            body.get("subject_seed_id"),
            body.get("subject_claim_id"),
            body.get("packet_hash"),
            body.get("lease_hash"),
        )
        if identifier in candidates:
            matches.append({"path": path.name, "body": body})
    if not matches:
        return False

    latest = matches[-1]["body"]
    result["source"] = "dogfood_receipts"
    notes.append(
        f"answered from receipt snapshot(s) {[m['path'] for m in matches]} in "
        f"{receipts_dir} — receipts are point-in-time captures, not the live store"
    )
    seed_packet = latest.get("seed_packet") if isinstance(latest.get("seed_packet"), dict) else None
    claimant = latest.get("claimant_identity")
    if isinstance(claimant, dict):
        claimant = claimant.get("subject_id")

    if latest.get("standing_id"):
        result["resolved_as"] = "standing_lease"
        result["standing_id"] = latest.get("standing_id")
        result["seed_id"] = latest.get("subject_seed_id")
        result["claim_id"] = latest.get("subject_claim_id")
        result["raw_status"] = result["recorded_status"] = latest.get("stored_status", latest.get("status"))
        result["captured_status"] = latest.get("status")
        result["expires_at"] = latest.get("expiry")
        result["scope"] = latest.get("scope")
        result["challenge_uri"] = latest.get("challenge_path")
        markers = _collect_markers(
            latest.get("scope"), latest.get("purpose"), latest.get("standing_lease"),
            (seed_packet or {}).get("labels"), _operator_disclosure(seed_packet),
        )
        result["rehearsal_markers"] = markers
        result["status"] = _status_from_lease(
            result["recorded_status"], latest.get("expiry"), markers, now, notes
        )
        result["independence_status"] = _independence_status(
            seed_packet, claimant if isinstance(claimant, str) else None,
            latest.get("issued_by"), markers,
        )
        return True

    result["resolved_as"] = "seed"
    result["seed_id"] = latest.get("seed_id")
    result["claim_id"] = latest.get("claim_id")
    result["claim_hash"] = latest.get("packet_hash")
    result["raw_status"] = result["recorded_status"] = latest.get("state")
    result["captured_status"] = latest.get("state")
    markers = _collect_markers(
        (seed_packet or {}).get("labels"),
        _operator_disclosure(seed_packet),
    )
    result["rehearsal_markers"] = markers
    state = str(latest.get("state") or "")
    result["status"] = _status_from_seed_state(state, markers, notes)
    result["independence_status"] = _independence_status(
        seed_packet, claimant if isinstance(claimant, str) else None, None, markers
    )
    return True


def verify(
    identifier: str,
    db_path: Path = DEFAULT_DB,
    receipts_dir: Optional[Path] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    result = _base_result(identifier, db_path)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        result["notes"].append("observation time is invalid or timezone-ambiguous")
        return result
    result["checked_at"] = now.isoformat()

    conn = None
    try:
        conn = _connect_ro(db_path)
        if conn is None:
            result["notes"].append(f"database not found at {db_path}")
        elif _resolve_from_db(conn, identifier, result, now):
            return result
    except (sqlite3.Error, OSError, KeyError, IndexError):
        result = _base_result(identifier, db_path)
        result["checked_at"] = now.isoformat()
        result["notes"].append("database could not be read consistently; no current status established")
    finally:
        if conn is not None:
            conn.close()

    if receipts_dir is not None and receipts_dir.is_dir():
        if _resolve_from_receipts(receipts_dir, identifier, result, now):
            return result
    elif receipts_dir is not None:
        result["notes"].append(f"receipts dir not found at {receipts_dir}")

    result["notes"].append("identifier not found in any consulted source")
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only SAB standing observation; recorded status does not establish current reliance."
    )
    parser.add_argument(
        "identifier",
        help="standing_id, seed_id, claim_id, claim_hash (packet_hash), or lease_hash",
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help=f"SQLite store (default: {DEFAULT_DB})")
    parser.add_argument(
        "--receipts",
        type=Path,
        default=None,
        help="optional dir of dogfood *.response.json snapshots to consult as fallback",
    )
    parser.add_argument("--compact", action="store_true", help="single-line JSON output")
    args = parser.parse_args(argv)

    result = verify(args.identifier, db_path=args.db, receipts_dir=args.receipts)
    assert result["status"] in STATUS_VOCAB
    indent = None if args.compact else 2
    print(json.dumps(result, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
