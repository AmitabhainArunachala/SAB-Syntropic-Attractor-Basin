"""Minimal read-only SAB standing verifier.

Given a standing_id, seed_id, claim_id, claim_hash (seed packet_hash), or
lease_hash, answer:

    status in {active, challenged, revoked, expired, unknown, rehearsal_only}
    independence_status in {self, same_operator, same_operator_distinct_keys,
                            undisclosed, unknown}

Sources, in order:
  1. The local SQLite store (default: <repo>/data/spark.db), opened READ-ONLY
     (`file:...?mode=ro`). This tool never writes. Unlike the API's lazy
     `_expire_standing_if_needed` (agora/sab_seeding_api.py:1913), expiry here
     is computed at read time without mutating the row.
  2. Optional dogfood receipt JSONs (`--receipts DIR`): the numbered
     `*.response.json` snapshots written by the Demonstration Zero loop.
     Receipts are point-in-time snapshots, not the live store.

Honesty rules baked in:
  - `rehearsal_only` is reported instead of `active` whenever the lease/seed
    carries single-operator rehearsal markers. A single-operator loop is
    pipeline evidence, not cross-operator standing.
  - Independence grading follows the conservative collapse rule of
    docs/SAB_STANDING_SEMANTICS_V0.md (R2): absent operator evidence grades
    `undisclosed`, never upward. This verifier can never emit
    `cross_operator_*` because the local store persists no operator identity
    for registered agents (web_agents keeps only id/name/public_key,
    agora/app.py:1268-1275) and no endpoint calls
    `validate_witness_independence` (agora/sab_identity.py:491).
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

# Live lease statuses (agora/sab_seeding_api.py:30) -> profile vocabulary.
_LEASE_STATUS_MAP = {
    "revoked": "revoked",
    "expired": "expired",
    "challenged": "challenged",
    # "active" / "canon" handled specially (expiry + rehearsal checks).
    # "compost" handled specially (out-of-vocab, mapped with a note).
}

# Seed states (agora/sab_seeding_api.py:15-27) -> profile vocabulary when no
# standing lease exists for the seed.
_SEED_STATE_MAP = {
    "challenged": "challenged",
    "revoked": "revoked",
    "expired": "expired",
}


def _parse_dt(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _connect_ro(db_path: Path) -> Optional[sqlite3.Connection]:
    if not db_path.is_file():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
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
    disclosure = ""
    if seed_packet:
        backing = seed_packet.get("operator_backing") or {}
        disclosure = str(backing.get("disclosure") or "").lower()
    same_operator_disclosed = "same operator" in disclosure
    if same_operator_disclosed or "not_cross_operator_independent" in markers or (
        "single_operator_rehearsal" in markers
    ):
        if claimant_identity and issuer_identity and claimant_identity != issuer_identity:
            return "same_operator_distinct_keys"
        return "same_operator"
    # Conservative collapse (SAB_STANDING_SEMANTICS_V0.md R2): no verifiable
    # operator evidence in the local store -> undisclosed, never upward.
    return "undisclosed"


def _status_from_lease(
    raw_status: str,
    expiry: Optional[str],
    markers: List[str],
    now: datetime,
    notes: List[str],
) -> str:
    if raw_status in _LEASE_STATUS_MAP:
        return _LEASE_STATUS_MAP[raw_status]
    if raw_status == "compost":
        notes.append("raw lease status 'compost' is outside the profile vocabulary; mapped to 'revoked'")
        return "revoked"
    if raw_status in ("active", "canon"):
        if raw_status == "canon":
            notes.append("raw lease status 'canon' mapped to the 'active' family")
        expiry_dt = _parse_dt(expiry or "")
        if expiry_dt is not None and expiry_dt <= now:
            notes.append(
                "expiry computed at read time; the stored row may still say "
                f"'{raw_status}' because this verifier never writes"
            )
            return "expired"
        if markers:
            notes.append(
                "lease records status 'active' but carries single-operator rehearsal "
                "markers; reported as rehearsal_only, not active"
            )
            return "rehearsal_only"
        return "active"
    notes.append(f"unrecognized raw lease status '{raw_status}'")
    return "unknown"


def _status_from_seed_state(state: str, markers: List[str], notes: List[str]) -> str:
    if state in _SEED_STATE_MAP:
        return _SEED_STATE_MAP[state]
    if state == "compost":
        notes.append("seed state 'compost' is outside the profile vocabulary; mapped to 'revoked'")
        return "revoked"
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
        "notes": [],
    }


def _load_seed_packet(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    try:
        return json.loads(str(row["packet_json"]))
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
        result["raw_status"] = str(lease_row["status"])
        result["expires_at"] = str(lease_row["expiry"])
        result["scope"] = str(lease_row["scope"])
        result["challenge_uri"] = str(lease_row["challenge_path"]) or None
        result["revocation_uri"] = f"/api/v1/standing/{lease_row['standing_id']}/revoke"
        notes.append(
            "revocation_uri derived from the live route "
            "POST /api/v1/standing/{standing_id}/revoke (agora/sab_seeding_api.py:735); "
            "the lease itself stores a revoker identity, not a URI"
        )
        markers = _collect_markers(
            str(lease_row["scope"]),
            str(lease_row["purpose"]),
            str(lease_row["lease_json"]),
            (seed_packet or {}).get("labels"),
            ((seed_packet or {}).get("operator_backing") or {}).get("disclosure"),
        )
        result["rehearsal_markers"] = markers
        result["status"] = _status_from_lease(
            str(lease_row["status"]), str(lease_row["expiry"]), markers, now, notes
        )
        result["independence_status"] = _independence_status(
            seed_packet, claimant, str(lease_row["issued_by"]), markers
        )
        return True

    # Seed found, no lease.
    result["resolved_as"] = "seed"
    result["raw_status"] = str(seed_row["state"])
    markers = _collect_markers(
        (seed_packet or {}).get("labels"),
        ((seed_packet or {}).get("operator_backing") or {}).get("disclosure"),
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
        body = payload.get("body")
        if not isinstance(body, dict):
            continue
        candidates = {
            body.get("standing_id"),
            body.get("seed_id"),
            body.get("claim_id"),
            body.get("subject_seed_id"),
            body.get("subject_claim_id"),
            body.get("packet_hash"),
            body.get("lease_hash"),
        }
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
        result["raw_status"] = latest.get("status")
        result["expires_at"] = latest.get("expiry")
        result["scope"] = latest.get("scope")
        result["challenge_uri"] = latest.get("challenge_path")
        markers = _collect_markers(latest.get("scope"), latest.get("purpose"))
        result["rehearsal_markers"] = markers
        result["status"] = _status_from_lease(
            str(latest.get("status") or ""), latest.get("expiry"), markers, now, notes
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
    result["raw_status"] = latest.get("state")
    markers = _collect_markers(
        (seed_packet or {}).get("labels"),
        ((seed_packet or {}).get("operator_backing") or {}).get("disclosure"),
    )
    result["rehearsal_markers"] = markers
    state = str(latest.get("state") or "")
    if state == "standing_active":
        if markers:
            notes.append(
                "receipt shows state 'standing_active' with rehearsal markers; "
                "reported as rehearsal_only"
            )
            result["status"] = "rehearsal_only"
        else:
            result["status"] = "active"
    else:
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
    result["checked_at"] = now.isoformat()

    conn = _connect_ro(db_path)
    if conn is None:
        result["notes"].append(f"database not found at {db_path}")
    else:
        try:
            if _resolve_from_db(conn, identifier, result, now):
                return result
        finally:
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
        description="Read-only SAB standing verifier (never writes)."
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
