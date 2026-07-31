#!/usr/bin/env python3
"""
SAB spec sprint application surface.

Run with:
    uvicorn agora.app:app --reload
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import FastAPI, Form, HTTPException, Query, Request, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from .admission_policy import FAST_LANE_AUTO
from .config import SAB_VERSION, get_db_path
from .gates import ALL_GATES, evaluate_submission_gates
from .rv_signal import measure_rv_signal
from .sab_seeding_storage import init_sab_seeding_storage
from .sab_identity import AgentIdentityV1
from .witness_service import (
    PUBLICATION_WITNESS_DOMAIN,
    attach_witness_meta,
    decode_related_link_ids,
    encode_related_link_ids,
)

try:
    from nacl.encoding import HexEncoder
    from nacl.exceptions import BadSignatureError
    from nacl.signing import SigningKey, VerifyKey
except ImportError as exc:  # pragma: no cover - runtime safety
    raise RuntimeError("PyNaCl is required for agora.app") from exc


DEFAULT_SPARK_DB = get_db_path().with_name("spark.db")
SPARK_DB = Path(os.getenv("SAB_SPARK_DB_PATH", os.getenv("SAB_AUTHORITY_DB_PATH", str(DEFAULT_SPARK_DB))))
SYSTEM_KEY_PATH = Path(
    os.getenv(
        "SAB_SYSTEM_WITNESS_KEY",
        str(SPARK_DB.with_name(".sab_system_ed25519.key")),
    )
)
CANON_QUORUM = int(os.getenv("SAB_CANON_QUORUM", "3"))
APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"
SEED_CLAIMS_PATH = Path(
    os.getenv(
        "SAB_SEED_CLAIMS_PATH",
        str(REPO_ROOT / "site" / "data" / "seed_claims.json"),
    )
)
LANGUAGE_WOMB_LANE_DIR = Path(
    os.getenv(
        "SAB_LANGUAGE_WOMB_LANE_DIR",
        str(REPO_ROOT / "docs" / "lanes" / "sab-agent-seeding-v1"),
    )
)
LANGUAGE_WOMB_SEED_DOC = LANGUAGE_WOMB_LANE_DIR / "LANGUAGE_WOMB_GRAND_CHALLENGE_SEED.md"
FRONTIER_PACKET_DIR = LANGUAGE_WOMB_LANE_DIR / "contributions" / "packets"
FRONTIER_RECEIPT_DIR = LANGUAGE_WOMB_LANE_DIR / "contributions" / "receipts"
WEB_SESSION_COOKIE = "sab_web_session"
WEB_SESSION_MAX_AGE_SECONDS = int(os.getenv("SAB_WEB_SESSION_MAX_AGE_SECONDS", str(7 * 24 * 3600)))
WEB_CACHE_TTL_SECONDS = int(os.getenv("SAB_WEB_CACHE_TTL_SECONDS", "15"))
WEB_AGENT_TABLE = "web_agents"
SPARK_WITNESS_TABLE = "spark_witness_chain"

# Canonical 17-dimension profile used for UI visualization.
SAB_17_DIMENSIONS: List[Dict[str, str]] = [
    {"id": "SATYA", "label": "Satya", "source_gate": "satya"},
    {"id": "AHIMSA", "label": "Ahimsa", "source_gate": "ahimsa"},
    {"id": "ASTEYA", "label": "Asteya", "source_gate": "originality"},
    {"id": "BRAHMACHARYA", "label": "Brahmacharya", "source_gate": "relevance"},
    {"id": "APARIGRAHA", "label": "Aparigraha", "source_gate": ""},
    {"id": "SHAUCHA", "label": "Shaucha", "source_gate": "substance"},
    {"id": "SANTOSHA", "label": "Santosha", "source_gate": ""},
    {"id": "TAPAS", "label": "Tapas", "source_gate": "rate_limit"},
    {"id": "SVADHYAYA", "label": "Svadhyaya", "source_gate": "svadhyaya"},
    {"id": "ISHVARA", "label": "Ishvara", "source_gate": "isvara"},
    {"id": "WITNESS", "label": "Witness", "source_gate": "witness"},
    {"id": "CONSENT", "label": "Consent", "source_gate": ""},
    {"id": "NONVIOLENCE", "label": "Nonviolence", "source_gate": "ahimsa"},
    {"id": "TRANSPARENCY", "label": "Transparency", "source_gate": ""},
    {"id": "RECIPROCITY", "label": "Reciprocity", "source_gate": ""},
    {"id": "HUMILITY", "label": "Humility", "source_gate": ""},
    {"id": "INTEGRITY", "label": "Integrity", "source_gate": "telos_alignment"},
]

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

_WEB_SESSIONS: Dict[str, Dict[str, Any]] = {}
_WEB_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_STATS: Dict[str, int] = {"hits": 0, "misses": 0, "invalidations": 0}

_log = logging.getLogger("sab.cache")

# ---------------------------------------------------------------------------
# CSRF protection helpers
# ---------------------------------------------------------------------------

import hmac as _hmac_mod  # noqa: E402


def _csrf_token_for_session(session: Dict[str, Any]) -> str:
    """Return (or generate) a per-session CSRF token."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _verify_csrf_form_token(session: Optional[Dict[str, Any]], form_csrf: Optional[str]) -> None:
    """Raise 403 if the form CSRF token is missing/mismatched.

    New sessions (no cookie yet) are exempt -- there is no prior cookie to
    hijack.
    """
    if session is None:
        return
    expected = session.get("csrf_token", "")
    if not expected:
        return
    if not form_csrf or not _hmac_mod.compare_digest(form_csrf, expected):
        raise HTTPException(status_code=403, detail="CSRF token invalid")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _band_for_score(score: Optional[float]) -> str:
    if score is None:
        return "pending"
    if score >= 0.75:
        return "green"
    if score >= 0.45:
        return "yellow"
    return "red"


def _dimension_profile(gate_scores: Dict[str, Any]) -> List[Dict[str, Any]]:
    dimensions = gate_scores.get("dimensions", {})
    profile: List[Dict[str, Any]] = []
    for dim in SAB_17_DIMENSIONS:
        gate_key = dim.get("source_gate", "")
        gate_data = dimensions.get(gate_key, {}) if gate_key else {}
        score = gate_data.get("score")
        score_val = float(score) if isinstance(score, (int, float)) else None
        profile.append(
            {
                "id": dim["id"],
                "label": dim["label"],
                "score": score_val,
                "percent": int(round((score_val or 0.0) * 100)),
                "band": _band_for_score(score_val),
                "result": str(gate_data.get("result", "pending")),
                "reason": str(
                    gate_data.get("reason")
                    or ("Pending instrumentation in sprint runtime." if not gate_data else "Scored")
                ),
                "source_gate": gate_key or "pending",
                "is_measured": bool(gate_data),
            }
        )
    return profile


def _rv_card(gate_scores: Dict[str, Any]) -> Dict[str, Any]:
    rv_signal = gate_scores.get("rv_signal", {})
    rv_val_raw = rv_signal.get("rv")
    rv_val = float(rv_val_raw) if isinstance(rv_val_raw, (int, float)) else None
    warnings = [str(w) for w in rv_signal.get("warnings", []) if isinstance(w, str)]
    status_text = "measured"
    if rv_val is None:
        status_text = "not measured (requires GPU sidecar)"
    if "measurement_failed_status" in warnings or "measurement_failed_http" in warnings:
        status_text = "measurement unavailable (sidecar error)"
    return {
        "label": "R_V",
        "score": rv_val,
        "percent": int(round((rv_val or 0.0) * 100)),
        "mode": str(rv_signal.get("mode", "uncertain")),
        "tier": str(rv_signal.get("signal_label", "experimental")),
        "scope": str(rv_signal.get("claim_scope", "icl_adaptation_only")),
        "status_text": status_text,
        "measurement_version": str(rv_signal.get("measurement_version", "unknown")),
        "warnings": warnings,
    }


def _json_string_list(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item) for item in raw if str(item).strip()]
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            return [text]
        if isinstance(decoded, list):
            return [str(item) for item in decoded if str(item).strip()]
        if isinstance(decoded, str) and decoded.strip():
            return [decoded]
    return []


def _seed_claim_payload() -> Dict[str, Any]:
    if not SEED_CLAIMS_PATH.exists():
        return {"claims": [], "stats": {"missing": str(SEED_CLAIMS_PATH)}}
    try:
        payload = json.loads(SEED_CLAIMS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"claims": [], "stats": {"error": str(exc), "path": str(SEED_CLAIMS_PATH)}}
    if not isinstance(payload, dict):
        return {"claims": [], "stats": {"error": "seed claims payload is not an object"}}
    claims = payload.get("claims", [])
    if not isinstance(claims, list):
        payload["claims"] = []
    return payload


def _founding_seed_claim(payload: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    payload = payload if payload is not None else _seed_claim_payload()
    claims = payload.get("claims", [])
    if not isinstance(claims, list):
        return None
    for claim in claims:
        if isinstance(claim, dict) and claim.get("founding_seed") is True:
            return claim
    for claim in claims:
        if isinstance(claim, dict):
            return claim
    return None


def _seed_claim_ref(claim: Dict[str, Any]) -> str:
    return str(claim.get("claim_path") or claim.get("claim_id") or "").strip()


def _bind_seed_claim_to_spark(
    conn: sqlite3.Connection,
    *,
    spark_id: int,
    claim: Dict[str, Any],
    sublation_status: str = "linked",
) -> None:
    claim_ref = _seed_claim_ref(claim)
    if not claim_ref:
        raise ValueError("seed claim has no claim_path or claim_id")
    conn.execute(
        """
        UPDATE sparks
        SET node_coordinate = ?,
            claim_packet_ref = ?,
            artifact_refs_json = ?,
            red_team_refs_json = ?,
            witness_refs_json = ?,
            lineage_root_id = COALESCE(lineage_root_id, ?),
            sublation_status = ?,
            founding_seed = ?
        WHERE id = ?
        """,
        (
            str(claim.get("node_coordinate") or ""),
            claim_ref,
            json.dumps(_json_string_list(claim.get("artifact_refs")), sort_keys=True),
            json.dumps(_json_string_list(claim.get("red_team_refs")), sort_keys=True),
            json.dumps(_json_string_list(claim.get("witness_refs")), sort_keys=True),
            spark_id,
            sublation_status,
            1 if claim.get("founding_seed") is True else 0,
            spark_id,
        ),
    )


def _seed_spark_id(conn: sqlite3.Connection, claim: Dict[str, Any]) -> Optional[int]:
    claim_ref = _seed_claim_ref(claim)
    if not claim_ref:
        return None
    row = conn.execute(
        """
        SELECT id
        FROM sparks
        WHERE claim_packet_ref = ?
        ORDER BY
            CASE status WHEN 'canon' THEN 0 WHEN 'spark' THEN 1 ELSE 2 END,
            founding_seed DESC,
            id DESC
        LIMIT 1
        """,
        (claim_ref,),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def _cache_get(key: str) -> Optional[Any]:
    entry = _WEB_CACHE.get(key)
    if not entry:
        _CACHE_STATS["misses"] += 1
        return None
    if float(entry.get("expires_at", 0.0)) <= time.time():
        _WEB_CACHE.pop(key, None)
        _CACHE_STATS["misses"] += 1
        return None
    _CACHE_STATS["hits"] += 1
    return entry.get("value")


def _cache_set(key: str, value: Any) -> None:
    _WEB_CACHE[key] = {"value": value, "expires_at": time.time() + WEB_CACHE_TTL_SECONDS}


def _invalidate_web_cache() -> None:
    evicted = len(_WEB_CACHE)
    _WEB_CACHE.clear()
    _CACHE_STATS["invalidations"] += 1
    if evicted:
        _log.debug("web cache invalidated, evicted %d entries", evicted)


def get_cache_stats() -> Dict[str, Any]:
    """Return cache instrumentation snapshot (hits, misses, invalidations, size)."""
    return {
        **_CACHE_STATS,
        "size": len(_WEB_CACHE),
        "ttl_seconds": WEB_CACHE_TTL_SECONDS,
    }


def _cleanup_web_sessions() -> None:
    now = time.time()
    expired = [
        token
        for token, session in _WEB_SESSIONS.items()
        if float(session.get("created_at_epoch", 0.0)) + WEB_SESSION_MAX_AGE_SECONDS < now
    ]
    for token in expired:
        _WEB_SESSIONS.pop(token, None)


def _read_web_session(request: Request) -> Optional[Dict[str, Any]]:
    _cleanup_web_sessions()
    token = request.cookies.get(WEB_SESSION_COOKIE)
    if not token:
        return None
    return _WEB_SESSIONS.get(token)


def _signing_key_from_session(session: Dict[str, Any]) -> SigningKey:
    return SigningKey(str(session["private_key_hex"]).encode(), encoder=HexEncoder)


def _create_web_session(conn: sqlite3.Connection, display_name: str) -> Dict[str, Any]:
    clean_name = (display_name or "").strip()[:80] or "anonymous"
    signing_key = SigningKey.generate()
    private_key_hex = signing_key.encode(encoder=HexEncoder).decode()
    public_key_hex = signing_key.verify_key.encode(encoder=HexEncoder).decode()
    agent_id = hashlib.sha256(public_key_hex.encode()).hexdigest()[:16]
    conn.execute(
        """
        INSERT OR IGNORE INTO web_agents (id, name, public_key, created_at, witness_count, witness_accuracy)
        VALUES (?, ?, ?, ?, 0, 0.0)
        """,
        (agent_id, clean_name, public_key_hex, _utc_now()),
    )
    token = secrets.token_urlsafe(24)
    session = {
        "token": token,
        "agent_id": agent_id,
        "name": clean_name,
        "private_key_hex": private_key_hex,
        "public_key_hex": public_key_hex,
        "created_at_epoch": time.time(),
        "csrf_token": secrets.token_urlsafe(32),
    }
    _WEB_SESSIONS[token] = session
    return session


def _resolve_or_create_web_session(
    request: Request,
    conn: sqlite3.Connection,
    display_name: str,
) -> Dict[str, Any]:
    existing = _read_web_session(request)
    if existing:
        return existing
    return _create_web_session(conn, display_name)


def _set_web_session_cookie(response: RedirectResponse, session: Dict[str, Any]) -> None:
    response.set_cookie(
        key=WEB_SESSION_COOKIE,
        value=str(session["token"]),
        httponly=True,
        max_age=WEB_SESSION_MAX_AGE_SECONDS,
        samesite="lax",
    )


def _load_or_create_system_signing_key(path: Path) -> SigningKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            raise RuntimeError(f"System key file is empty: {path}")
        return SigningKey(raw.encode(), encoder=HexEncoder)

    key = SigningKey.generate()
    path.write_text(key.encode(encoder=HexEncoder).decode(), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        # Non-fatal on filesystems that do not support chmod semantics.
        pass
    return key


SYSTEM_SIGNING_KEY = _load_or_create_system_signing_key(SYSTEM_KEY_PATH)
SYSTEM_VERIFY_KEY_HEX = SYSTEM_SIGNING_KEY.verify_key.encode(encoder=HexEncoder).decode()


@contextmanager
def _db() -> sqlite3.Connection:
    SPARK_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(SPARK_DB)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


import re as _re_mod  # noqa: E402


_SAFE_IDENTIFIER = _re_mod.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _assert_safe_identifier(name: str) -> str:
    """Validate that *name* is a safe SQL identifier (defense-in-depth)."""
    if not _SAFE_IDENTIFIER.fullmatch(name):
        raise ValueError(f"Unsafe SQL identifier: {name!r}")
    return name


def _ensure_column(conn: sqlite3.Connection, table: str, col_name: str, col_def: str) -> None:
    _assert_safe_identifier(table)
    _assert_safe_identifier(col_name)
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if col_name not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    _assert_safe_identifier(table)
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    _assert_safe_identifier(table)
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table})")
    return {str(row[1]) for row in cursor.fetchall()}


def _migrate_legacy_public_tables(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, WEB_AGENT_TABLE) and _table_exists(conn, "agents"):
        cols = _table_columns(conn, "agents")
        if {"id", "public_key", "witness_count", "witness_accuracy"}.issubset(cols):
            conn.execute(f"ALTER TABLE agents RENAME TO {WEB_AGENT_TABLE}")

    if not _table_exists(conn, SPARK_WITNESS_TABLE) and _table_exists(conn, "witness_chain"):
        cols = _table_columns(conn, "witness_chain")
        if {"spark_id", "witness_id", "signature", "payload"}.issubset(cols):
            conn.execute(f"ALTER TABLE witness_chain RENAME TO {SPARK_WITNESS_TABLE}")


def init_db() -> None:
    with _db() as conn:
        cursor = conn.cursor()
        _migrate_legacy_public_tables(conn)

        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {WEB_AGENT_TABLE} (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                witness_count INTEGER DEFAULT 0,
                witness_accuracy REAL DEFAULT 0.0
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS sparks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                content_type TEXT NOT NULL,
                author_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                gate_scores TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status IN ('spark', 'canon', 'compost')),
                rv_contraction REAL,
                composite_score REAL DEFAULT 0.0
            )
            """
        )
        _ensure_column(conn, "sparks", "rv_contraction", "rv_contraction REAL")
        _ensure_column(conn, "sparks", "composite_score", "composite_score REAL DEFAULT 0.0")
        _ensure_column(conn, "sparks", "node_coordinate", "node_coordinate TEXT")
        _ensure_column(conn, "sparks", "claim_packet_ref", "claim_packet_ref TEXT")
        _ensure_column(conn, "sparks", "artifact_refs_json", "artifact_refs_json TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(conn, "sparks", "red_team_refs_json", "red_team_refs_json TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(conn, "sparks", "witness_refs_json", "witness_refs_json TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(conn, "sparks", "lineage_root_id", "lineage_root_id INTEGER")
        _ensure_column(conn, "sparks", "parent_spark_id", "parent_spark_id INTEGER")
        _ensure_column(conn, "sparks", "sublation_status", "sublation_status TEXT")
        _ensure_column(conn, "sparks", "founding_seed", "founding_seed INTEGER NOT NULL DEFAULT 0")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_sparks_status_created ON sparks(status, created_at DESC)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_sparks_claim_packet_ref ON sparks(claim_packet_ref)"
        )

        # Note: auth.py uses a different `challenges` table for login challenges.
        # We keep spark-pressure challenges separate to avoid schema collisions.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS spark_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                spark_id INTEGER NOT NULL,
                challenger_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolution TEXT NOT NULL CHECK (resolution IN ('pending', 'sustained', 'rejected'))
            )
            """
        )
        _ensure_column(conn, "spark_challenges", "resolved_at", "resolved_at TEXT")
        _ensure_column(conn, "spark_challenges", "successor_spark_id", "successor_spark_id INTEGER")
        _ensure_column(conn, "spark_challenges", "correction_artifact", "correction_artifact TEXT")
        _ensure_column(conn, "spark_challenges", "correction_content_sha256", "correction_content_sha256 TEXT")
        _ensure_column(conn, "spark_challenges", "sublation_witness_hash", "sublation_witness_hash TEXT")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_spark_challenges_spark ON spark_challenges(spark_id, created_at DESC)"
        )

        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {SPARK_WITNESS_TABLE} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                spark_id INTEGER,
                witness_id TEXT NOT NULL,
                signature TEXT NOT NULL,
                action TEXT NOT NULL,
                payload TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                witness_domain TEXT NOT NULL DEFAULT 'publication',
                witness_link_id TEXT,
                related_link_ids_json TEXT NOT NULL DEFAULT '[]',
                prev_hash TEXT,
                hash TEXT NOT NULL
            )
            """
        )
        _ensure_column(
            conn,
            SPARK_WITNESS_TABLE,
            "witness_domain",
            "witness_domain TEXT DEFAULT 'publication'",
        )
        _ensure_column(conn, SPARK_WITNESS_TABLE, "witness_link_id", "witness_link_id TEXT")
        _ensure_column(
            conn,
            SPARK_WITNESS_TABLE,
            "related_link_ids_json",
            "related_link_ids_json TEXT NOT NULL DEFAULT '[]'",
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{SPARK_WITNESS_TABLE}_spark ON {SPARK_WITNESS_TABLE}(spark_id, id ASC)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{SPARK_WITNESS_TABLE}_witness ON {SPARK_WITNESS_TABLE}(witness_id, id DESC)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{SPARK_WITNESS_TABLE}_link ON {SPARK_WITNESS_TABLE}(witness_link_id)"
        )
        init_sab_seeding_storage(conn)


def _system_sign(payload: Dict[str, Any]) -> str:
    return SYSTEM_SIGNING_KEY.sign(_canonical_bytes(payload)).signature.hex()


def _message_for_submit(author_id: str, content_sha256: str) -> bytes:
    return _canonical_bytes(
        {
            "kind": "spark_submit",
            "author_id": author_id,
            "content_sha256": content_sha256,
        }
    )


def _message_for_challenge(spark_id: int, challenger_id: str, content_sha256: str) -> bytes:
    return _canonical_bytes(
        {
            "kind": "spark_challenge",
            "spark_id": spark_id,
            "challenger_id": challenger_id,
            "content_sha256": content_sha256,
        }
    )


def _message_for_sublation(
    challenge_id: int,
    predecessor_spark_id: int,
    corrector_id: str,
    successor_content_sha256: str,
    artifact_ref_sha256: str,
    note_sha256: str,
) -> bytes:
    return _canonical_bytes(
        {
            "kind": "spark_challenge_sublation",
            "challenge_id": challenge_id,
            "predecessor_spark_id": predecessor_spark_id,
            "corrector_id": corrector_id,
            "successor_content_sha256": successor_content_sha256,
            "artifact_ref_sha256": artifact_ref_sha256,
            "note_sha256": note_sha256,
        }
    )


def _message_for_witness(spark_id: int, witness_id: str, action: str, payload_sha256: str) -> bytes:
    return _canonical_bytes(
        {
            "kind": "witness_attestation",
            "spark_id": spark_id,
            "witness_id": witness_id,
            "action": action,
            "payload_sha256": payload_sha256,
        }
    )


def _verify_agent_signature(conn: sqlite3.Connection, agent_id: str, message: bytes, signature_hex: str) -> None:
    row = conn.execute("SELECT public_key FROM web_agents WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Unknown agent: {agent_id}")

    public_key_hex = str(row["public_key"])
    try:
        verify_key = VerifyKey(public_key_hex.encode(), encoder=HexEncoder)
        verify_key.verify(message, bytes.fromhex(signature_hex))
    except (BadSignatureError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid Ed25519 signature")


def _append_witness(
    conn: sqlite3.Connection,
    *,
    spark_id: Optional[int],
    witness_id: str,
    action: str,
    payload: Dict[str, Any],
    signature_hex: str,
    witness_link_id: Optional[str] = None,
    related_link_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    timestamp = _utc_now()
    witness_link_id, payload_with_meta, normalized_related = attach_witness_meta(
        payload,
        domain=PUBLICATION_WITNESS_DOMAIN,
        action=action,
        actor_id=witness_id,
        subject_type="spark",
        subject_id=spark_id,
        origin="agora.app",
        witness_link_id=witness_link_id,
        related_link_ids=related_link_ids,
    )
    payload_json = json.dumps(payload_with_meta, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    related_link_ids_json = encode_related_link_ids(normalized_related)

    prev_row = conn.execute(
        "SELECT hash FROM spark_witness_chain WHERE spark_id IS ? ORDER BY id DESC LIMIT 1",
        (spark_id,),
    ).fetchone()
    prev_hash = str(prev_row["hash"]) if prev_row else "genesis"

    unhashed_entry = {
        "spark_id": spark_id,
        "witness_id": witness_id,
        "signature": signature_hex,
        "action": action,
        "payload": payload_json,
        "timestamp": timestamp,
        "witness_domain": PUBLICATION_WITNESS_DOMAIN,
        "witness_link_id": witness_link_id,
        "related_link_ids_json": related_link_ids_json,
        "prev_hash": prev_hash,
    }
    entry_hash = _sha256_hex(_canonical_bytes(unhashed_entry))

    conn.execute(
        """
        INSERT INTO spark_witness_chain
            (
                spark_id,
                witness_id,
                signature,
                action,
                payload,
                timestamp,
                witness_domain,
                witness_link_id,
                related_link_ids_json,
                prev_hash,
                hash
            )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            spark_id,
            witness_id,
            signature_hex,
            action,
            payload_json,
            timestamp,
            PUBLICATION_WITNESS_DOMAIN,
            witness_link_id,
            related_link_ids_json,
            prev_hash,
            entry_hash,
        ),
    )

    return {
        **unhashed_entry,
        "hash": entry_hash,
        "related_link_ids": normalized_related,
    }


def _serialize_public_witness_row(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["related_link_ids"] = decode_related_link_ids(item.get("related_link_ids_json"))
    return item


def _load_gate_scores(raw: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"dimensions": {}, "composite": 0.0}
    if not isinstance(parsed, dict):
        return {"dimensions": {}, "composite": 0.0}
    return parsed


def _with_rv_signal(gate_scores: Dict[str, Any], rv_signal: Dict[str, Any]) -> Dict[str, Any]:
    dimensions = gate_scores.get("dimensions", {})
    rv_value = rv_signal.get("rv")
    warning_set = {str(w) for w in rv_signal.get("warnings", []) if isinstance(w, str)}
    if rv_value is not None:
        rv_state = "measured"
    elif "measurement_disabled" in warning_set:
        rv_state = "disabled"
    elif any(w.startswith("measurement_failed") for w in warning_set):
        rv_state = "failed"
    else:
        rv_state = "uncertain"
    return {
        **gate_scores,
        "dimensions": dimensions,
        "rv_contraction": rv_value,
        "rv_measurement_state": rv_state,
        "rv_signal": rv_signal,
    }


def _spark_counts_for_author(conn: sqlite3.Connection, author_id: str) -> Dict[str, int]:
    now = datetime.now(timezone.utc)
    one_hour_ago = (now - timedelta(hours=1)).isoformat()
    one_day_ago = (now - timedelta(days=1)).isoformat()
    hour_count = int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM sparks WHERE author_id = ? AND created_at >= ?",
            (author_id, one_hour_ago),
        ).fetchone()["c"]
    )
    day_count = int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM sparks WHERE author_id = ? AND created_at >= ?",
            (author_id, one_day_ago),
        ).fetchone()["c"]
    )
    return {"hour": hour_count, "day": day_count}


def _pending_challenge_count(conn: sqlite3.Connection, spark_id: int) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) AS c FROM spark_challenges WHERE spark_id = ? AND resolution = 'pending'",
            (spark_id,),
        ).fetchone()["c"]
    )


def _verify_chain_rows(rows: List[sqlite3.Row]) -> bool:
    prev_hash = "genesis"
    for row in rows:
        material = {
            "spark_id": row["spark_id"],
            "witness_id": row["witness_id"],
            "signature": row["signature"],
            "action": row["action"],
            "payload": row["payload"],
            "timestamp": row["timestamp"],
            "witness_domain": row["witness_domain"],
            "witness_link_id": row["witness_link_id"],
            "related_link_ids_json": row["related_link_ids_json"],
            "prev_hash": row["prev_hash"],
        }
        expected_hash = _sha256_hex(_canonical_bytes(material))
        if row["prev_hash"] != prev_hash:
            return False
        if row["hash"] != expected_hash:
            return False
        prev_hash = row["hash"]
    return True


def _promote_if_quorum(conn: sqlite3.Connection, spark_id: int) -> Optional[Dict[str, Any]]:
    row = conn.execute("SELECT status FROM sparks WHERE id = ?", (spark_id,)).fetchone()
    if row is None:
        return None
    if str(row["status"]) == "canon":
        return None
    if _pending_challenge_count(conn, spark_id) > 0:
        return None

    witnesses = conn.execute(
        """
        SELECT DISTINCT witness_id
        FROM spark_witness_chain
        WHERE spark_id = ? AND action IN ('affirm', 'canon_affirm')
        """,
        (spark_id,),
    ).fetchall()
    if len(witnesses) < CANON_QUORUM:
        return None

    conn.execute("UPDATE sparks SET status = 'canon' WHERE id = ?", (spark_id,))
    payload = {
        "spark_id": spark_id,
        "quorum": CANON_QUORUM,
        "witness_count": len(witnesses),
    }
    signature = _system_sign(
        {
            "kind": "system_witness",
            "spark_id": spark_id,
            "action": "canon_promoted",
            "payload": payload,
        }
    )
    entry = _append_witness(
        conn,
        spark_id=spark_id,
        witness_id="system",
        action="canon_promoted",
        payload=payload,
        signature_hex=signature,
    )
    return entry


def _serialize_spark_row(row: sqlite3.Row) -> Dict[str, Any]:
    raw_gate_scores = row["gate_scores"]
    keys = set(row.keys())

    def val(name: str, default: Any = None) -> Any:
        return row[name] if name in keys else default

    claim_packet_ref = str(val("claim_packet_ref") or "")
    artifact_refs = _json_string_list(val("artifact_refs_json"))
    red_team_refs = _json_string_list(val("red_team_refs_json"))
    witness_refs = _json_string_list(val("witness_refs_json"))
    item = {
        "id": int(row["id"]),
        "content": str(row["content"] or ""),
        "content_type": str(row["content_type"] or "text"),
        "author_id": str(row["author_id"] or ""),
        "created_at": str(row["created_at"] or ""),
        "status": str(row["status"] or "spark"),
        "rv_contraction": row["rv_contraction"],
        "composite_score": float(row["composite_score"] or 0.0),
        "gate_scores": _load_gate_scores(str(raw_gate_scores) if raw_gate_scores is not None else "{}"),
        "node_coordinate": str(val("node_coordinate") or ""),
        "claim_packet_ref": claim_packet_ref,
        "claim_packet_refs": [claim_packet_ref] if claim_packet_ref else [],
        "artifact_refs": artifact_refs,
        "red_team_refs": red_team_refs,
        "witness_refs": witness_refs,
        "lineage_root_id": val("lineage_root_id"),
        "parent_spark_id": val("parent_spark_id"),
        "sublation_status": str(val("sublation_status") or ""),
        "founding_seed": bool(val("founding_seed", 0)),
    }
    return item


def _serialize_challenge_row(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["id"] = int(item["id"])
    item["spark_id"] = int(item["spark_id"])
    if item.get("successor_spark_id") is not None:
        item["successor_spark_id"] = int(item["successor_spark_id"])
    return item


def _public_witness_entry_for_replay(entry: Dict[str, Any]) -> Dict[str, Any]:
    item = dict(entry)
    payload_raw = item.get("payload", "{}")
    try:
        item["payload_obj"] = json.loads(str(payload_raw))
    except json.JSONDecodeError:
        item["payload_obj"] = {"raw": str(payload_raw)}
    return item


def _spark_chain_payload(conn: sqlite3.Connection, spark_id: int) -> Dict[str, Any]:
    spark_row = conn.execute("SELECT parent_spark_id FROM sparks WHERE id = ?", (spark_id,)).fetchone()
    challenge_spark_ids = [spark_id]
    if spark_row is not None and spark_row["parent_spark_id"] is not None:
        challenge_spark_ids.append(int(spark_row["parent_spark_id"]))
    placeholders = ",".join("?" for _ in challenge_spark_ids)
    rows = conn.execute(
        """
        SELECT id, spark_id, witness_id, signature, action, payload, timestamp,
               witness_domain, witness_link_id, related_link_ids_json, prev_hash, hash
        FROM spark_witness_chain
        WHERE spark_id = ?
        ORDER BY id ASC
        """,
        (spark_id,),
    ).fetchall()
    challenge_sql = """
        SELECT id, spark_id, challenger_id, content, created_at, resolution,
               resolved_at, successor_spark_id, correction_artifact,
               correction_content_sha256, sublation_witness_hash
        FROM spark_challenges
        WHERE spark_id IN ({placeholders})
        ORDER BY spark_id ASC, id ASC
        """.format(placeholders=placeholders)  # nosec B608
    challenge_rows = conn.execute(
        challenge_sql,
        tuple(challenge_spark_ids),
    ).fetchall()
    entries = [_serialize_public_witness_row(row) for row in rows]
    replay_entries = [_public_witness_entry_for_replay(entry) for entry in entries]
    challenges = [_serialize_challenge_row(row) for row in challenge_rows]
    return {
        "spark_id": spark_id,
        "verified": _verify_chain_rows(rows),
        "entries": entries,
        "challenges": challenges,
        "replay": {
            "attacks": challenges,
            "corrections": [
                entry
                for entry in replay_entries
                if entry["action"] in ("challenge_sublated", "sublation_successor")
            ],
            "canon_events": [entry for entry in replay_entries if entry["action"] == "canon_promoted"],
            "successor_links": [
                {
                    "challenge_id": challenge["id"],
                    "predecessor_spark_id": challenge["spark_id"],
                    "successor_spark_id": challenge.get("successor_spark_id"),
                    "sublation_witness_hash": challenge.get("sublation_witness_hash"),
                }
                for challenge in challenges
                if challenge.get("successor_spark_id") is not None
            ],
        },
    }


def _compost_why_card(conn: sqlite3.Connection, spark_id: int, gate_scores: Dict[str, Any]) -> Dict[str, str]:
    witness_row = conn.execute(
        """
        SELECT payload
        FROM spark_witness_chain
        WHERE spark_id = ? AND action = 'compost'
        ORDER BY id DESC
        LIMIT 1
        """,
        (spark_id,),
    ).fetchone()
    challenge_row = conn.execute(
        """
        SELECT content
        FROM spark_challenges
        WHERE spark_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (spark_id,),
    ).fetchone()

    reason = "Composted by witness action."
    source = "witness"
    if witness_row:
        try:
            payload = json.loads(str(witness_row["payload"]))
            payload_reason = str(payload.get("reason", "")).strip()
            if payload_reason == "ahimsa_gate_failed":
                reason = "Failed Ahimsa safety gate."
                source = "safety"
            elif payload_reason:
                reason = payload_reason.replace("_", " ")
        except json.JSONDecodeError:
            pass

    if challenge_row is not None and source != "safety":
        excerpt = str(challenge_row["content"]).strip().replace("\n", " ")
        if excerpt:
            reason = f"Challenge pressure: {excerpt[:180]}"
            source = "challenge"

    rv = _rv_card(gate_scores)
    return {
        "title": "WHY this is compost",
        "reason": reason,
        "source": source,
        "rv_note": rv["status_text"],
    }


def _web_feed_items(
    conn: sqlite3.Connection,
    *,
    status_filter: str,
    sort_mode: str,
    limit: int,
) -> List[Dict[str, Any]]:
    if status_filter == "all":
        rows = conn.execute(
            """
            SELECT
                s.*,
                (SELECT COUNT(*) FROM spark_challenges c WHERE c.spark_id = s.id) AS challenge_count,
                (SELECT COUNT(*) FROM spark_witness_chain w WHERE w.spark_id = s.id) AS witness_count
            FROM sparks s
            ORDER BY s.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT
                s.*,
                (SELECT COUNT(*) FROM spark_challenges c WHERE c.spark_id = s.id) AS challenge_count,
                (SELECT COUNT(*) FROM spark_witness_chain w WHERE w.spark_id = s.id) AS witness_count
            FROM sparks s
            WHERE s.status = ?
            ORDER BY s.created_at DESC
            LIMIT ?
            """,
            (status_filter, limit),
        ).fetchall()
    items: List[Dict[str, Any]] = []
    for row in rows:
        item = _serialize_spark_row(row)
        item["challenge_count"] = int(row["challenge_count"] or 0)
        item["witness_count"] = int(row["witness_count"] or 0)
        item["dimensions_17"] = _dimension_profile(item["gate_scores"])
        item["rv_card"] = _rv_card(item["gate_scores"])
        if item["status"] == "compost":
            item["compost_why"] = _compost_why_card(conn, item["id"], item["gate_scores"])
        items.append(item)

    if sort_mode == "most-challenged":
        items.sort(
            key=lambda item: (int(item.get("challenge_count", 0)), str(item.get("created_at", ""))),
            reverse=True,
        )
    return items


class AgentRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)
    public_key: str = Field(..., min_length=64, max_length=128)

    @field_validator("public_key")
    @classmethod
    def validate_public_key_hex(cls, value: str) -> str:
        try:
            VerifyKey(value.encode(), encoder=HexEncoder)
        except Exception as exc:
            raise ValueError("invalid Ed25519 public key (hex)") from exc
        return value


class SparkSubmitRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=12000)
    content_type: Literal["text", "code", "link"] = "text"
    author_id: str = Field(..., min_length=8, max_length=64)
    signature: str = Field(..., min_length=64)


class ChallengeCreateRequest(BaseModel):
    challenger_id: str = Field(..., min_length=8, max_length=64)
    content: str = Field(..., min_length=1, max_length=10000)
    signature: str = Field(..., min_length=64)


class ChallengeSublationRequest(BaseModel):
    corrector_id: str = Field(..., min_length=8, max_length=64)
    corrected_content: str = Field(..., min_length=1, max_length=12000)
    content_type: Literal["text", "code", "link"] = "text"
    artifact_ref: Optional[str] = Field(default=None, max_length=2000)
    note: str = Field("", max_length=1000)
    signature: str = Field(..., min_length=64)


class WitnessSignRequest(BaseModel):
    spark_id: int
    witness_id: str = Field(..., min_length=8, max_length=64)
    action: Literal[
        "affirm",
        "canon_affirm",
        "compost",
        "respond",
        "challenge_sustain",
        "challenge_reject",
    ]
    payload: Dict[str, Any] = Field(default_factory=dict)
    signature: str = Field(..., min_length=64)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="SAB Basin API",
    description="Spark -> pressure -> witness -> canon/compost lifecycle API",
    version=SAB_VERSION,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _public_agent_doc(name: str) -> FileResponse:
    path = REPO_ROOT / "site" / name
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Public agent doc not found: {name}")
    return FileResponse(path, media_type="text/markdown; charset=utf-8")


@app.get("/skill.md", include_in_schema=False)
async def public_skill_md() -> FileResponse:
    return _public_agent_doc("skill.md")


@app.get("/seed.md", include_in_schema=False)
async def public_seed_md() -> FileResponse:
    return _public_agent_doc("seed.md")


@app.get("/auth.md", include_in_schema=False)
async def public_auth_md() -> FileResponse:
    return _public_agent_doc("auth.md")


@app.get("/heartbeat.md", include_in_schema=False)
async def public_heartbeat_md() -> FileResponse:
    return _public_agent_doc("heartbeat.md")


@app.get("/rules.md", include_in_schema=False)
async def public_rules_md() -> FileResponse:
    return _public_agent_doc("rules.md")


@app.get("/schemas/sab.seed_packet.v1.schema.json", include_in_schema=False)
async def public_seed_packet_schema() -> FileResponse:
    for path in (
        REPO_ROOT / "nodes" / "schemas" / "sab.seed_packet.v1.schema.json",
        REPO_ROOT / "site" / "schemas" / "sab.seed_packet.v1.schema.json",
    ):
        if path.is_file():
            return FileResponse(path, media_type="application/schema+json")
    raise HTTPException(status_code=404, detail="Public seed packet schema not found")


from .sab_seeding_api import SabSeedingDeps, create_sab_seeding_router  # noqa: E402

app.include_router(
    create_sab_seeding_router(
        SabSeedingDeps(
            init_db=init_db,
            db=_db,
            verify_agent_signature=_verify_agent_signature,
            system_sign=_system_sign,
            utc_now=_utc_now,
            invalidate_web_cache=_invalidate_web_cache,
        )
    )
)


@app.post("/api/agents/register", status_code=status.HTTP_201_CREATED)
async def register_agent(req: AgentRegisterRequest) -> Dict[str, Any]:
    init_db()
    agent_id = hashlib.sha256(req.public_key.encode()).hexdigest()[:16]
    created_at = _utc_now()
    with _db() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO web_agents (id, name, public_key, created_at, witness_count, witness_accuracy)
            VALUES (?, ?, ?, ?, 0, 0.0)
            """,
            (agent_id, req.name, req.public_key, created_at),
        )
        row = conn.execute("SELECT * FROM web_agents WHERE id = ?", (agent_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=500, detail="failed to register agent")
    canonical_identity = AgentIdentityV1.from_public_key(
        display_name=str(row["name"]),
        public_key=str(row["public_key"]),
        created_at=datetime.fromisoformat(str(row["created_at"])),
        evidence_refs=[f"web_agents:{row['id']}"],
    )
    return {
        "id": str(row["id"]),
        "name": str(row["name"]),
        "public_key": str(row["public_key"]),
        "created_at": str(row["created_at"]),
        "identity": canonical_identity.model_dump(mode="json", by_alias=True),
    }


@app.post("/api/spark/submit", status_code=status.HTTP_201_CREATED)
async def submit_spark(req: SparkSubmitRequest) -> Dict[str, Any]:
    init_db()
    content_sha256 = _sha256_hex(req.content.encode())
    submit_message = _message_for_submit(req.author_id, content_sha256)

    with _db() as conn:
        _verify_agent_signature(conn, req.author_id, submit_message, req.signature)

        agent_row = conn.execute(
            "SELECT id, name, created_at FROM web_agents WHERE id = ?",
            (req.author_id,),
        ).fetchone()
        if agent_row is None:
            raise HTTPException(status_code=404, detail=f"Unknown agent: {req.author_id}")

        counts = _spark_counts_for_author(conn, req.author_id)
        recent_hashes = [
            _sha256_hex(str(r["content"]).encode())
            for r in conn.execute(
                """
                SELECT content
                FROM sparks
                ORDER BY id DESC
                LIMIT 50
                """
            ).fetchall()
        ]

        created_at = datetime.fromisoformat(str(agent_row["created_at"]))
        age_hours = max(0.0, (datetime.now(timezone.utc) - created_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600.0)
        gate_context = {
            "author_posts_last_hour": counts["hour"],
            "author_posts_last_day": counts["day"],
            "author_age_hours": age_hours,
            "author_reputation": 0.0,
            "recent_content_hashes": recent_hashes,
        }
        gate_scores, _, _, _ = evaluate_submission_gates(req.content, req.author_id, gate_context)
        rv_signal = measure_rv_signal(req.content)
        gate_scores = _with_rv_signal(gate_scores, rv_signal)
        admission = FAST_LANE_AUTO.decide(gate_scores)
        status_value = admission.status

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO sparks
                (content, content_type, author_id, created_at, gate_scores, status, rv_contraction, composite_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                req.content,
                req.content_type,
                req.author_id,
                _utc_now(),
                json.dumps(gate_scores, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                status_value,
                gate_scores.get("rv_contraction"),
                float(gate_scores.get("composite", 0.0)),
            ),
        )
        spark_id = int(cursor.lastrowid)

        _append_witness(
            conn,
            spark_id=spark_id,
            witness_id=req.author_id,
            action="submit",
            payload={
                "content_sha256": content_sha256,
                "content_type": req.content_type,
            },
            signature_hex=req.signature,
        )

        system_gate_signature = _system_sign(
            {
                "kind": "system_witness",
                "spark_id": spark_id,
                "action": "gate_scored",
                "payload": gate_scores,
            }
        )
        _append_witness(
            conn,
            spark_id=spark_id,
            witness_id="system",
            action="gate_scored",
            payload=gate_scores,
            signature_hex=system_gate_signature,
        )

        if status_value == "compost":
            compost_signature = _system_sign(
                {
                    "kind": "system_witness",
                    "spark_id": spark_id,
                    "action": "compost",
                    "payload": {"reason": admission.reason},
                }
            )
            _append_witness(
                conn,
                spark_id=spark_id,
                witness_id="system",
                action="compost",
                payload={"reason": admission.reason},
                signature_hex=compost_signature,
            )

        row = conn.execute("SELECT * FROM sparks WHERE id = ?", (spark_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=500, detail="spark persisted but not found")
        _invalidate_web_cache()
        return _serialize_spark_row(row)


@app.get("/api/spark/{spark_id}")
async def get_spark(spark_id: int) -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        row = conn.execute("SELECT * FROM sparks WHERE id = ?", (spark_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="spark not found")
        challenge_count = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM spark_challenges WHERE spark_id = ?",
                (spark_id,),
            ).fetchone()["c"]
        )
        witness_count = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM spark_witness_chain WHERE spark_id = ?",
                (spark_id,),
            ).fetchone()["c"]
        )
        data = _serialize_spark_row(row)
        data["challenge_count"] = challenge_count
        data["witness_count"] = witness_count
        return data


@app.post("/api/spark/{spark_id}/challenge", status_code=status.HTTP_201_CREATED)
async def challenge_spark(spark_id: int, req: ChallengeCreateRequest) -> Dict[str, Any]:
    init_db()
    content_sha256 = _sha256_hex(req.content.encode())
    challenge_message = _message_for_challenge(spark_id, req.challenger_id, content_sha256)

    with _db() as conn:
        spark = conn.execute("SELECT status FROM sparks WHERE id = ?", (spark_id,)).fetchone()
        if spark is None:
            raise HTTPException(status_code=404, detail="spark not found")

        _verify_agent_signature(conn, req.challenger_id, challenge_message, req.signature)

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO spark_challenges (spark_id, challenger_id, content, created_at, resolution)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (spark_id, req.challenger_id, req.content, _utc_now()),
        )
        challenge_id = int(cursor.lastrowid)

        _append_witness(
            conn,
            spark_id=spark_id,
            witness_id=req.challenger_id,
            action="challenge",
            payload={
                "challenge_id": challenge_id,
                "content_sha256": content_sha256,
            },
            signature_hex=req.signature,
        )

        if str(spark["status"]) == "canon":
            conn.execute("UPDATE sparks SET status = 'spark' WHERE id = ?", (spark_id,))
            demote_signature = _system_sign(
                {
                    "kind": "system_witness",
                    "spark_id": spark_id,
                    "action": "canon_challenged",
                    "payload": {"challenge_id": challenge_id},
                }
            )
            _append_witness(
                conn,
                spark_id=spark_id,
                witness_id="system",
                action="canon_challenged",
                payload={"challenge_id": challenge_id},
                signature_hex=demote_signature,
            )

        row = conn.execute(
            "SELECT id, spark_id, challenger_id, content, created_at, resolution FROM spark_challenges WHERE id = ?",
            (challenge_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=500, detail="challenge persisted but not found")
        _invalidate_web_cache()
        return dict(row)


@app.get("/api/spark/{spark_id}/chain")
async def get_spark_chain(spark_id: int) -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        return _spark_chain_payload(conn, spark_id)


@app.get("/api/spark/{spark_id}/replay")
async def replay_spark_chain(spark_id: int) -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        return _spark_chain_payload(conn, spark_id)


@app.post(
    "/api/spark/{spark_id}/challenge/{challenge_id}/sublate",
    status_code=status.HTTP_201_CREATED,
)
async def sublate_challenge(
    spark_id: int,
    challenge_id: int,
    req: ChallengeSublationRequest,
) -> Dict[str, Any]:
    init_db()
    corrected_content = req.corrected_content.strip()
    artifact_ref = (req.artifact_ref or "").strip()
    note = req.note.strip()
    if not corrected_content:
        raise HTTPException(status_code=400, detail="corrected_content is required")
    successor_content_sha256 = _sha256_hex(corrected_content.encode())
    artifact_ref_sha256 = _sha256_hex(artifact_ref.encode())
    note_sha256 = _sha256_hex(note.encode())
    sublation_message = _message_for_sublation(
        challenge_id,
        spark_id,
        req.corrector_id,
        successor_content_sha256,
        artifact_ref_sha256,
        note_sha256,
    )

    with _db() as conn:
        predecessor = conn.execute("SELECT * FROM sparks WHERE id = ?", (spark_id,)).fetchone()
        if predecessor is None:
            raise HTTPException(status_code=404, detail="spark not found")
        challenge = conn.execute(
            """
            SELECT id, spark_id, challenger_id, content, created_at, resolution
            FROM spark_challenges
            WHERE id = ? AND spark_id = ?
            """,
            (challenge_id, spark_id),
        ).fetchone()
        if challenge is None:
            raise HTTPException(status_code=404, detail="challenge not found")
        if str(challenge["resolution"]) != "pending":
            raise HTTPException(status_code=409, detail="challenge already resolved")

        _verify_agent_signature(conn, req.corrector_id, sublation_message, req.signature)

        corrector_row = conn.execute(
            "SELECT id, name, created_at FROM web_agents WHERE id = ?",
            (req.corrector_id,),
        ).fetchone()
        if corrector_row is None:
            raise HTTPException(status_code=404, detail=f"Unknown agent: {req.corrector_id}")

        counts = _spark_counts_for_author(conn, req.corrector_id)
        recent_hashes = [
            _sha256_hex(str(r["content"]).encode())
            for r in conn.execute(
                """
                SELECT content
                FROM sparks
                ORDER BY id DESC
                LIMIT 50
                """
            ).fetchall()
        ]
        created_at = datetime.fromisoformat(str(corrector_row["created_at"]))
        age_hours = max(
            0.0,
            (datetime.now(timezone.utc) - created_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600.0,
        )
        gate_context = {
            "author_posts_last_hour": counts["hour"],
            "author_posts_last_day": counts["day"],
            "author_age_hours": age_hours,
            "author_reputation": 0.0,
            "recent_content_hashes": recent_hashes,
        }
        gate_scores, _, _, _ = evaluate_submission_gates(corrected_content, req.corrector_id, gate_context)
        rv_signal = measure_rv_signal(corrected_content)
        gate_scores = _with_rv_signal(gate_scores, rv_signal)
        admission = FAST_LANE_AUTO.decide(gate_scores)
        status_value = admission.status

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO sparks
                (
                    content,
                    content_type,
                    author_id,
                    created_at,
                    gate_scores,
                    status,
                    rv_contraction,
                    composite_score,
                    node_coordinate,
                    claim_packet_ref,
                    artifact_refs_json,
                    red_team_refs_json,
                    witness_refs_json,
                    lineage_root_id,
                    parent_spark_id,
                    sublation_status,
                    founding_seed
                )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                corrected_content,
                req.content_type,
                req.corrector_id,
                _utc_now(),
                json.dumps(gate_scores, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
                status_value,
                gate_scores.get("rv_contraction"),
                float(gate_scores.get("composite", 0.0)),
                predecessor["node_coordinate"],
                predecessor["claim_packet_ref"],
                predecessor["artifact_refs_json"],
                predecessor["red_team_refs_json"],
                predecessor["witness_refs_json"],
                predecessor["lineage_root_id"] or spark_id,
                spark_id,
                "sublated",
                predecessor["founding_seed"],
            ),
        )
        successor_spark_id = int(cursor.lastrowid)
        predecessor_content_sha256 = _sha256_hex(str(predecessor["content"]).encode())
        sublation_payload = {
            "challenge_id": challenge_id,
            "predecessor_spark_id": spark_id,
            "successor_spark_id": successor_spark_id,
            "predecessor_content_sha256": predecessor_content_sha256,
            "successor_content_sha256": successor_content_sha256,
            "artifact_ref": artifact_ref or None,
            "note": note,
            "resolution": "sublated",
        }
        sublation_entry = _append_witness(
            conn,
            spark_id=spark_id,
            witness_id=req.corrector_id,
            action="challenge_sublated",
            payload=sublation_payload,
            signature_hex=req.signature,
        )

        related_links = []
        witness_link_id = sublation_entry.get("witness_link_id")
        if isinstance(witness_link_id, str) and witness_link_id:
            related_links.append(witness_link_id)
        successor_entry = _append_witness(
            conn,
            spark_id=successor_spark_id,
            witness_id=req.corrector_id,
            action="sublation_successor",
            payload={**sublation_payload, "role": "corrected_successor"},
            signature_hex=req.signature,
            related_link_ids=related_links,
        )

        system_gate_signature = _system_sign(
            {
                "kind": "system_witness",
                "spark_id": successor_spark_id,
                "action": "gate_scored",
                "payload": gate_scores,
            }
        )
        _append_witness(
            conn,
            spark_id=successor_spark_id,
            witness_id="system",
            action="gate_scored",
            payload=gate_scores,
            signature_hex=system_gate_signature,
        )

        resolved_at = _utc_now()
        conn.execute(
            """
            UPDATE spark_challenges
            SET resolution = 'sustained',
                resolved_at = ?,
                successor_spark_id = ?,
                correction_artifact = ?,
                correction_content_sha256 = ?,
                sublation_witness_hash = ?
            WHERE id = ?
            """,
            (
                resolved_at,
                successor_spark_id,
                artifact_ref or None,
                successor_content_sha256,
                str(sublation_entry["hash"]),
                challenge_id,
            ),
        )

        challenge_row = conn.execute(
            """
            SELECT id, spark_id, challenger_id, content, created_at, resolution,
                   resolved_at, successor_spark_id, correction_artifact,
                   correction_content_sha256, sublation_witness_hash
            FROM spark_challenges
            WHERE id = ?
            """,
            (challenge_id,),
        ).fetchone()
        successor_row = conn.execute("SELECT * FROM sparks WHERE id = ?", (successor_spark_id,)).fetchone()
        if challenge_row is None or successor_row is None:
            raise HTTPException(status_code=500, detail="sublation persisted but not found")

        _invalidate_web_cache()
        return {
            "challenge": _serialize_challenge_row(challenge_row),
            "sublation_status": "sublated",
            "predecessor_spark_id": spark_id,
            "successor": _serialize_spark_row(successor_row),
            "sublation_event": sublation_entry,
            "successor_event": successor_entry,
        }


@app.post("/api/witness/sign")
async def witness_sign(req: WitnessSignRequest) -> Dict[str, Any]:
    init_db()
    payload_sha = _sha256_hex(_canonical_bytes(req.payload))
    witness_message = _message_for_witness(req.spark_id, req.witness_id, req.action, payload_sha)

    with _db() as conn:
        spark = conn.execute("SELECT id, status FROM sparks WHERE id = ?", (req.spark_id,)).fetchone()
        if spark is None:
            raise HTTPException(status_code=404, detail="spark not found")

        _verify_agent_signature(conn, req.witness_id, witness_message, req.signature)

        entry = _append_witness(
            conn,
            spark_id=req.spark_id,
            witness_id=req.witness_id,
            action=req.action,
            payload=req.payload,
            signature_hex=req.signature,
        )

        conn.execute(
            """
            UPDATE web_agents
            SET witness_count = COALESCE(witness_count, 0) + 1
            WHERE id = ?
            """,
            (req.witness_id,),
        )

        if req.action in ("affirm", "canon_affirm"):
            _promote_if_quorum(conn, req.spark_id)
        elif req.action == "compost":
            conn.execute("UPDATE sparks SET status = 'compost' WHERE id = ?", (req.spark_id,))
            compost_signature = _system_sign(
                {
                    "kind": "system_witness",
                    "spark_id": req.spark_id,
                    "action": "compost",
                    "payload": req.payload,
                }
            )
            _append_witness(
                conn,
                spark_id=req.spark_id,
                witness_id="system",
                action="compost",
                payload=req.payload,
                signature_hex=compost_signature,
            )

        status_row = conn.execute("SELECT status FROM sparks WHERE id = ?", (req.spark_id,)).fetchone()
        spark_status = str(status_row["status"]) if status_row else "unknown"
        _invalidate_web_cache()

        return {
            "spark_id": req.spark_id,
            "spark_status": spark_status,
            "entry": entry,
        }


@app.get("/api/witness/{agent_id}")
async def witness_history(agent_id: str, limit: int = Query(50, ge=1, le=500)) -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        rows = conn.execute(
            """
            SELECT id, spark_id, witness_id, signature, action, payload, timestamp,
                   witness_domain, witness_link_id, related_link_ids_json, prev_hash, hash
            FROM spark_witness_chain
            WHERE witness_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (agent_id, limit),
        ).fetchall()
    return {"agent_id": agent_id, "entries": [_serialize_public_witness_row(row) for row in rows]}


def _load_feed(conn: sqlite3.Connection, *, status_value: str, limit: int, gate_name: str) -> List[Dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT * FROM sparks
        WHERE status = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (status_value, limit),
    ).fetchall()
    items = [_serialize_spark_row(row) for row in rows]

    def gate_score(item: Dict[str, Any]) -> float:
        dimensions = item.get("gate_scores", {}).get("dimensions", {})
        selected = dimensions.get(gate_name, {})
        return float(selected.get("score", 0.0))

    items.sort(key=lambda item: (gate_score(item), item.get("created_at", "")), reverse=True)
    return items


def _render_template(
    request: Request,
    template_name: str,
    context: Dict[str, Any],
    *,
    status_code: int = 200,
) -> HTMLResponse:
    payload = {"request": request, **context}
    return templates.TemplateResponse(request, template_name, payload, status_code=status_code)


def _spark_with_details(conn: sqlite3.Connection, spark_id: int) -> Optional[Dict[str, Any]]:
    row = conn.execute(
        """
        SELECT
            s.*,
            (SELECT COUNT(*) FROM spark_challenges c WHERE c.spark_id = s.id) AS challenge_count,
            (SELECT COUNT(*) FROM spark_witness_chain w WHERE w.spark_id = s.id) AS witness_count
        FROM sparks s
        WHERE s.id = ?
        """,
        (spark_id,),
    ).fetchone()
    if row is None:
        return None
    data = _serialize_spark_row(row)
    data["challenge_count"] = int(row["challenge_count"] or 0)
    data["witness_count"] = int(row["witness_count"] or 0)
    data["dimensions_17"] = _dimension_profile(data["gate_scores"])
    data["rv_card"] = _rv_card(data["gate_scores"])
    if data["status"] == "compost":
        data["compost_why"] = _compost_why_card(conn, data["id"], data["gate_scores"])
    return data


def _web_feed_context(
    conn: sqlite3.Connection,
    *,
    status_filter: str,
    sort_mode: str,
    limit: int,
) -> Dict[str, Any]:
    cache_key = f"{status_filter}:{sort_mode}:{limit}"
    cached = _cache_get(cache_key)
    if cached is None:
        items = _web_feed_items(conn, status_filter=status_filter, sort_mode=sort_mode, limit=limit)
        _cache_set(cache_key, items)
    else:
        items = cached
    return {
        "items": items,
        "status_filter": status_filter,
        "sort_mode": sort_mode,
        "limit": limit,
    }


def _read_json_object(path: Path) -> Optional[Dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _safe_repo_relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except (OSError, ValueError):
        return path.name


def _public_ref_label(ref: str) -> str:
    text = str(ref or "").strip()
    if not text:
        return ""
    marker = " sha256:"
    path_part, digest_part = (text.split(marker, 1) + [""])[:2] if marker in text else (text, "")
    try:
        ref_path = Path(path_part)
        if ref_path.is_absolute():
            try:
                label = str(ref_path.resolve().relative_to(REPO_ROOT.resolve()))
            except (OSError, ValueError):
                label = f"local:{ref_path.name}"
        else:
            label = path_part
    except (OSError, ValueError):
        label = path_part
    if digest_part:
        return f"{label} sha256:{digest_part[:12]}"
    return label


def _frontier_receipts_by_seed(receipt_dir: Path = FRONTIER_RECEIPT_DIR) -> Dict[str, Dict[str, Any]]:
    receipts: Dict[str, Dict[str, Any]] = {}
    if not receipt_dir.exists():
        return receipts
    for path in sorted(receipt_dir.glob("*.json")):
        payload = _read_json_object(path)
        if not payload:
            continue
        seed_id = str(payload.get("seed_id") or "").strip()
        if seed_id:
            payload["_receipt_path"] = _safe_repo_relative(path)
            receipts[seed_id] = payload
    return receipts


def _frontier_card_from_packet_payload(
    packet: Dict[str, Any],
    *,
    packet_path: str,
    receipt: Optional[Dict[str, Any]] = None,
    source: str = "artifact",
    state: Optional[str] = None,
    packet_hash: str = "",
    spark_projection_id: Any = None,
    challenge_window_closes_at: str = "",
    witness_head: str = "",
    challenge_count: int = 0,
    pending_challenge_count: int = 0,
    witness_event_count: int = 0,
    standing_status: str = "",
) -> Dict[str, Any]:
    claim = packet.get("claim") if isinstance(packet.get("claim"), dict) else {}
    claimant = packet.get("claimant_identity") if isinstance(packet.get("claimant_identity"), dict) else {}
    authority = packet.get("authority_lease") if isinstance(packet.get("authority_lease"), dict) else {}
    challenge = packet.get("challenge_plan") if isinstance(packet.get("challenge_plan"), dict) else {}
    witness = packet.get("witness_plan") if isinstance(packet.get("witness_plan"), dict) else {}
    signature = packet.get("signature") if isinstance(packet.get("signature"), dict) else {}
    evidence = packet.get("evidence_bundle") if isinstance(packet.get("evidence_bundle"), list) else []
    evidence_refs = [
        _public_ref_label(str(item.get("ref", "")))
        for item in evidence
        if isinstance(item, dict) and item.get("ref")
    ]
    external_actions = receipt.get("external_actions", []) if receipt else []
    if not isinstance(external_actions, list):
        external_actions = []

    return {
        "source": source,
        "seed_id": str(packet.get("seed_id") or packet_path),
        "title": str(packet.get("title") or "Untitled seed packet"),
        "status": str(state or packet.get("status") or "unknown"),
        "loop_position": str(packet.get("loop_position") or "spark"),
        "created_at": str(packet.get("created_at") or ""),
        "packet_path": packet_path,
        "packet_hash": packet_hash,
        "spark_projection_id": spark_projection_id,
        "challenge_window_closes_at": challenge_window_closes_at,
        "witness_head": witness_head,
        "receipt_path": str(receipt.get("_receipt_path", "")) if receipt else "",
        "claim_id": str(claim.get("claim_id") or ""),
        "claim_text": str(claim.get("text") or ""),
        "claim_type": str(claim.get("claim_type") or ""),
        "scope": str(claim.get("scope") or ""),
        "claimant": str(claimant.get("subject_id") or signature.get("signer") or "unknown"),
        "signer": str(signature.get("signer") or ""),
        "evidence_count": len(evidence_refs),
        "evidence_refs": evidence_refs[:4],
        "challenge_required": bool(challenge.get("required", False)),
        "challenge_window": str(challenge.get("challenge_window") or ""),
        "strongest_objections": [str(item) for item in challenge.get("strongest_objections", [])[:3]]
        if isinstance(challenge.get("strongest_objections"), list)
        else [],
        "falsification_routes": [str(item) for item in challenge.get("falsification_routes", [])[:3]]
        if isinstance(challenge.get("falsification_routes"), list)
        else [],
        "minimum_witnesses": int(witness.get("minimum_witnesses") or 0),
        "required_roles": [str(item) for item in witness.get("required_roles", [])]
        if isinstance(witness.get("required_roles"), list)
        else [],
        "authority_scope": str(authority.get("scope") or ""),
        "lease_expires_at": str(authority.get("expires_at") or ""),
        "anti_capture_rules": [str(item) for item in packet.get("anti_capture_rules", [])[:3]]
        if isinstance(packet.get("anti_capture_rules"), list)
        else [],
        "receipt_present": receipt is not None,
        "standing_effect": standing_status
        or (str(receipt.get("standing_effect") or "unknown") if receipt else "missing_receipt"),
        "external_actions_count": len(external_actions),
        "challenge_count": challenge_count,
        "pending_challenge_count": pending_challenge_count,
        "witness_event_count": witness_event_count,
    }


def _frontier_packet_card(path: Path, receipt: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    packet = _read_json_object(path)
    if not packet:
        return None
    return _frontier_card_from_packet_payload(
        packet,
        packet_path=_safe_repo_relative(path),
        receipt=receipt,
        source="artifact",
    )


def _frontier_open_questions() -> List[str]:
    return [
        "What is the smallest type system that distinguishes Attested_by, Tested_by, Reviewed_by, and Proven_by without becoming unusable?",
        "Is epistemic modality best modeled as an indexed type, an effect, a capability, a proof term, or provenance annotation?",
        "What is the minimum promotion receipt from Attested_by to Tested_by?",
        "What claims must never be promotable by model consensus alone?",
        "What existing language or proof system already solves each proposed feature?",
    ]


def _frontier_store_stats() -> Dict[str, Any]:
    try:
        from .sab_seeding_api import _init_v1_tables

        init_db()
        with _db() as conn:
            init_sab_seeding_storage(conn)
            _init_v1_tables(conn)
            seed_count = int(conn.execute("SELECT COUNT(*) AS c FROM sab_seed_packets_v1").fetchone()["c"])
            challenge_count = int(conn.execute("SELECT COUNT(*) AS c FROM sab_challenge_packets_v1").fetchone()["c"])
            pending_challenges = int(
                conn.execute("SELECT COUNT(*) AS c FROM sab_challenge_packets_v1 WHERE status = 'pending'").fetchone()[
                    "c"
                ]
            )
            witness_count = int(conn.execute("SELECT COUNT(*) AS c FROM sab_witness_events_v1").fetchone()["c"])
            standing_count = int(conn.execute("SELECT COUNT(*) AS c FROM sab_standing_leases_v1").fetchone()["c"])
            active_standing = int(
                conn.execute("SELECT COUNT(*) AS c FROM sab_standing_leases_v1 WHERE status = 'active'").fetchone()[
                    "c"
                ]
            )
    except (OSError, sqlite3.Error) as exc:
        return {
            "available": False,
            "error": str(exc),
            "seeds": 0,
            "challenges": 0,
            "pending_challenges": 0,
            "witness_events": 0,
            "standing_leases": 0,
            "active_standing": 0,
        }
    return {
        "available": True,
        "seeds": seed_count,
        "challenges": challenge_count,
        "pending_challenges": pending_challenges,
        "witness_events": witness_count,
        "standing_leases": standing_count,
        "active_standing": active_standing,
    }


def _frontier_db_seed_cards(limit: int) -> List[Dict[str, Any]]:
    cards: List[Dict[str, Any]] = []
    try:
        from .sab_seeding_api import _init_v1_tables

        init_db()
        with _db() as conn:
            init_sab_seeding_storage(conn)
            _init_v1_tables(conn)
            rows = conn.execute(
                """
                SELECT seed_id, state, packet_json, packet_hash, spark_projection_id,
                       challenge_window_closes_at, created_at
                FROM sab_seed_packets_v1
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for row in rows:
                seed_id = str(row["seed_id"])
                try:
                    packet = json.loads(str(row["packet_json"]))
                except json.JSONDecodeError:
                    continue
                challenge_count = int(
                    conn.execute(
                        "SELECT COUNT(*) AS c FROM sab_challenge_packets_v1 WHERE target_seed_id = ?",
                        (seed_id,),
                    ).fetchone()["c"]
                )
                pending_challenge_count = int(
                    conn.execute(
                        """
                        SELECT COUNT(*) AS c
                        FROM sab_challenge_packets_v1
                        WHERE target_seed_id = ? AND status = 'pending'
                        """,
                        (seed_id,),
                    ).fetchone()["c"]
                )
                witness_event_count = int(
                    conn.execute(
                        "SELECT COUNT(*) AS c FROM sab_witness_events_v1 WHERE subject_seed_id = ?",
                        (seed_id,),
                    ).fetchone()["c"]
                )
                witness_head_row = conn.execute(
                    """
                    SELECT event_hash
                    FROM sab_witness_events_v1
                    WHERE subject_seed_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (seed_id,),
                ).fetchone()
                standing_row = conn.execute(
                    """
                    SELECT status
                    FROM sab_standing_leases_v1
                    WHERE subject_seed_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (seed_id,),
                ).fetchone()
                standing_status = f"standing:{standing_row['status']}" if standing_row else "none"
                cards.append(
                    _frontier_card_from_packet_payload(
                        packet,
                        packet_path=f"sab_seed_packets_v1:{seed_id}",
                        source="store",
                        state=str(row["state"]),
                        packet_hash=str(row["packet_hash"]),
                        spark_projection_id=row["spark_projection_id"],
                        challenge_window_closes_at=str(row["challenge_window_closes_at"] or ""),
                        witness_head=str(witness_head_row["event_hash"]) if witness_head_row else "genesis",
                        challenge_count=challenge_count,
                        pending_challenge_count=pending_challenge_count,
                        witness_event_count=witness_event_count,
                        standing_status=standing_status,
                    )
                )
    except (OSError, sqlite3.Error):
        return cards
    return cards


def _frontier_board_lanes(cards: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    needs_challenge = [
        card
        for card in cards
        if card.get("challenge_required")
        and int(card.get("pending_challenge_count") or 0) == 0
        and str(card.get("status")) in {"pending_seed", "challenge_window_open"}
    ]
    needs_witness = [
        card
        for card in cards
        if int(card.get("minimum_witnesses") or 0) > int(card.get("witness_event_count") or 0)
        and str(card.get("standing_effect")) in {"none", "missing_receipt"}
    ]
    ready_to_build = [
        card
        for card in cards
        if int(card.get("evidence_count") or 0) > 0
        and (
            card.get("receipt_present")
            or str(card.get("status")) in {"corrected", "witnessed", "standing_active", "canon_candidate", "canon"}
        )
    ]
    return {
        "needs_challenge": needs_challenge[:6],
        "needs_witness": needs_witness[:6],
        "ready_to_build": ready_to_build[:6],
    }


def _frontier_snapshot(limit: int = 24) -> Dict[str, Any]:
    receipts = _frontier_receipts_by_seed()
    cards: List[Dict[str, Any]] = _frontier_db_seed_cards(limit)
    seen_seed_ids = {str(card.get("seed_id")) for card in cards}
    if FRONTIER_PACKET_DIR.exists():
        for path in sorted(FRONTIER_PACKET_DIR.glob("*.json"), key=lambda item: item.name, reverse=True):
            payload = _read_json_object(path)
            if not payload:
                continue
            seed_id = str(payload.get("seed_id") or "").strip()
            if seed_id and seed_id in seen_seed_ids:
                continue
            card = _frontier_packet_card(path, receipts.get(seed_id))
            if card:
                cards.append(card)
                seen_seed_ids.add(str(card.get("seed_id")))
    cards.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    cards = cards[:limit]

    agents = sorted({card["claimant"] for card in cards if card.get("claimant")})
    status_counts: Dict[str, int] = {}
    loop_counts: Dict[str, int] = {}
    for card in cards:
        status_counts[card["status"]] = status_counts.get(card["status"], 0) + 1
        loop_counts[card["loop_position"]] = loop_counts.get(card["loop_position"], 0) + 1
    standing_surface_count = sum(
        1
        for card in cards
        if str(card.get("standing_effect") or "").startswith("standing:")
    )
    external_action_count = sum(int(card.get("external_actions_count") or 0) for card in cards)
    store_stats = _frontier_store_stats()

    return {
        "schema": "sab.frontier_snapshot.v1",
        "generated_at": _utc_now(),
        "frontier": {
            "id": "language_womb.epistemic_authority.v1",
            "title": "Language Womb Frontier",
            "standing_question": (
                "How do we develop an AI-native programming language where epistemic modality, "
                "evidence grade, uncertainty, and authority affect typechecking and evaluation?"
            ),
            "target_rule": "Claim[Attested_by, womb] cannot satisfy Claim[Proven_by, core] without an accepted promotion proof.",
            "source_doc": _safe_repo_relative(LANGUAGE_WOMB_SEED_DOC),
            "next_question": _frontier_open_questions()[0],
        },
        "stats": {
            "packet_count": len(cards),
            "receipt_count": sum(1 for card in cards if card.get("receipt_present")),
            "agent_count": len(agents),
            "challenge_required_count": sum(1 for card in cards if card.get("challenge_required")),
            "standing_surface_count": standing_surface_count,
            "standing_grant_count": standing_surface_count,
            "external_action_count": external_action_count,
            "status_counts": status_counts,
            "loop_counts": loop_counts,
            "store": store_stats,
        },
        "board": _frontier_board_lanes(cards),
        "agents": agents,
        "contribution_protocol": [
            {"kind": "claim", "meaning": "one exact design pressure or semantic assertion"},
            {"kind": "evidence", "meaning": "a public source, local artifact pointer, test, or argument"},
            {"kind": "counterexample", "meaning": "a case that should fail if the proposed rule is wrong"},
            {"kind": "proof-step", "meaning": "a promotion rule, proof obligation, or typed transition"},
            {"kind": "synthesis", "meaning": "a narrowing that turns many deltas into the next question"},
        ],
        "open_questions": _frontier_open_questions(),
        "security_boundaries": [
            "Seed packets do not grant standing by themselves.",
            "Scheduled local agents controlled by one operator do not count as independent witnesses.",
            "The current loop is local-only: no Moltbook login, posting, voting, or outbound action.",
            "Receipt-only designs should fold back into governance unless the language semantics change before execution.",
        ],
        "packets": cards,
    }


@app.get("/api/frontier")
async def frontier_snapshot(limit: int = Query(24, ge=1, le=100)) -> Dict[str, Any]:
    return _frontier_snapshot(limit=limit)


@app.get("/frontier", response_class=HTMLResponse)
async def web_frontier(request: Request, limit: int = Query(24, ge=1, le=100)) -> HTMLResponse:
    snapshot = _frontier_snapshot(limit=limit)
    return _render_template(
        request,
        "web_frontier.html",
        {
            "snapshot": snapshot,
            "session": _read_web_session(request),
            "path_name": "/frontier",
        },
    )


@app.get("/api/feed")
async def feed(
    limit: int = Query(50, ge=1, le=200),
    gate: str = Query("satya", min_length=2, max_length=64),
) -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        items = _load_feed(conn, status_value="spark", limit=limit, gate_name=gate)
    return {"status": "spark", "sorted_by_gate": gate, "items": items}


@app.get("/api/feed/canon")
async def feed_canon(
    limit: int = Query(50, ge=1, le=200),
    gate: str = Query("satya", min_length=2, max_length=64),
) -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        items = _load_feed(conn, status_value="canon", limit=limit, gate_name=gate)
    return {"status": "canon", "sorted_by_gate": gate, "items": items}


@app.get("/api/feed/compost")
async def feed_compost(
    limit: int = Query(50, ge=1, le=200),
    gate: str = Query("satya", min_length=2, max_length=64),
) -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        items = _load_feed(conn, status_value="compost", limit=limit, gate_name=gate)
    return {"status": "compost", "sorted_by_gate": gate, "items": items}


@app.get("/api/node/status")
async def node_status() -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        total = int(conn.execute("SELECT COUNT(*) AS c FROM sparks").fetchone()["c"])
        spark_count = int(conn.execute("SELECT COUNT(*) AS c FROM sparks WHERE status = 'spark'").fetchone()["c"])
        canon_count = int(conn.execute("SELECT COUNT(*) AS c FROM sparks WHERE status = 'canon'").fetchone()["c"])
        compost_count = int(conn.execute("SELECT COUNT(*) AS c FROM sparks WHERE status = 'compost'").fetchone()["c"])
        challenge_pending = int(
            conn.execute("SELECT COUNT(*) AS c FROM spark_challenges WHERE resolution = 'pending'").fetchone()["c"]
        )
        recent_witness = [
            _serialize_public_witness_row(row)
            for row in conn.execute(
                """
                SELECT id, spark_id, witness_id, action, timestamp, witness_domain,
                       witness_link_id, related_link_ids_json
                FROM spark_witness_chain
                ORDER BY id DESC
                LIMIT 20
                """
            ).fetchall()
        ]

        gate_totals: Dict[str, float] = {}
        gate_counts: Dict[str, int] = {}
        for row in conn.execute("SELECT gate_scores FROM sparks").fetchall():
            scores = _load_gate_scores(str(row["gate_scores"]))
            dimensions = scores.get("dimensions", {})
            for gate_name, gate_data in dimensions.items():
                score_val = float(gate_data.get("score", 0.0))
                gate_totals[gate_name] = gate_totals.get(gate_name, 0.0) + score_val
                gate_counts[gate_name] = gate_counts.get(gate_name, 0) + 1

    gate_averages = {
        gate_name: round(gate_totals[gate_name] / gate_counts[gate_name], 6)
        for gate_name in gate_totals
        if gate_counts.get(gate_name, 0) > 0
    }

    return {
        "status": "healthy",
        "version": SAB_VERSION,
        "db_path": str(SPARK_DB),
        "system_verify_key": SYSTEM_VERIFY_KEY_HEX,
        "gate_count": len(ALL_GATES),
        "canon_quorum": CANON_QUORUM,
        "totals": {
            "sparks": total,
            "spark_status": spark_count,
            "canon": canon_count,
            "compost": compost_count,
            "pending_challenges": challenge_pending,
        },
        "gate_averages": gate_averages,
        "recent_witness": recent_witness,
        "timestamp": _utc_now(),
    }


@app.get("/health")
async def health() -> Dict[str, Any]:
    """Conventional public-app health probe."""
    status_payload = await node_status()
    return {
        "status": status_payload["status"],
        "version": status_payload["version"],
        "surface": "agora.app",
        "db_path": status_payload["db_path"],
        "timestamp": status_payload["timestamp"],
    }


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return await health()


@app.get("/readyz")
async def readyz() -> Dict[str, Any]:
    init_db()
    with _db() as conn:
        conn.execute("SELECT 1").fetchone()
    return {
        "status": "ready",
        "surface": "agora.app",
        "db_path": str(SPARK_DB),
        "timestamp": _utc_now(),
    }


@app.get("/api/cache/stats")
async def cache_stats() -> Dict[str, Any]:
    """Lightweight cache instrumentation endpoint."""
    return get_cache_stats()


@app.get("/", response_class=HTMLResponse)
async def web_home(
    request: Request,
    mode: str = Query("newest", pattern="^(newest|most-challenged|canon|compost)$"),
    limit: int = Query(30, ge=1, le=100),
) -> HTMLResponse:
    init_db()
    status_filter = "spark"
    sort_mode = "newest"
    if mode == "most-challenged":
        sort_mode = "most-challenged"
    elif mode == "canon":
        status_filter = "canon"
    elif mode == "compost":
        status_filter = "compost"

    with _db() as conn:
        feed_context = _web_feed_context(
            conn,
            status_filter=status_filter,
            sort_mode=sort_mode,
            limit=limit,
        )

    session = _read_web_session(request)
    return _render_template(
        request,
        "web_feed.html",
        {
            **feed_context,
            "title": "SAB Feed",
            "mode": mode,
            "path_name": "/",
            "session": session,
        },
    )


@app.get("/canon", response_class=HTMLResponse)
async def web_canon(
    request: Request,
    sort: str = Query("newest", pattern="^(newest|most-challenged)$"),
    limit: int = Query(30, ge=1, le=100),
) -> HTMLResponse:
    init_db()
    with _db() as conn:
        feed_context = _web_feed_context(
            conn,
            status_filter="canon",
            sort_mode=sort,
            limit=limit,
        )
    return _render_template(
        request,
        "web_feed.html",
        {
            **feed_context,
            "title": "Canon",
            "mode": "canon",
            "path_name": "/canon",
            "session": _read_web_session(request),
        },
    )


@app.get("/compost", response_class=HTMLResponse)
async def web_compost(
    request: Request,
    sort: str = Query("newest", pattern="^(newest|most-challenged)$"),
    limit: int = Query(30, ge=1, le=100),
) -> HTMLResponse:
    init_db()
    with _db() as conn:
        feed_context = _web_feed_context(
            conn,
            status_filter="compost",
            sort_mode=sort,
            limit=limit,
        )
    return _render_template(
        request,
        "web_feed.html",
        {
            **feed_context,
            "title": "Compost",
            "mode": "compost",
            "path_name": "/compost",
            "session": _read_web_session(request),
        },
    )


@app.get("/seed", response_class=HTMLResponse)
async def web_seed(request: Request) -> HTMLResponse:
    init_db()
    seed_payload = _seed_claim_payload()
    seed_claim = _founding_seed_claim(seed_payload)
    spark: Optional[Dict[str, Any]] = None
    challenges: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []
    replay: Optional[Dict[str, Any]] = None

    with _db() as conn:
        if seed_claim is not None:
            spark_id = _seed_spark_id(conn, seed_claim)
            if spark_id is not None:
                spark = _spark_with_details(conn, spark_id)
                challenge_spark_ids = [spark_id]
                if spark and spark.get("parent_spark_id"):
                    challenge_spark_ids.append(int(spark["parent_spark_id"]))
                placeholders = ",".join("?" for _ in challenge_spark_ids)
                challenge_sql = """
                    SELECT id, spark_id, challenger_id, content, created_at, resolution,
                           resolved_at, successor_spark_id, correction_artifact,
                           correction_content_sha256, sublation_witness_hash
                    FROM spark_challenges
                    WHERE spark_id IN ({placeholders})
                    ORDER BY spark_id ASC, id ASC
                    """.format(placeholders=placeholders)  # nosec B608
                challenge_rows = conn.execute(
                    challenge_sql,
                    tuple(challenge_spark_ids),
                ).fetchall()
                challenges = [_serialize_challenge_row(row) for row in challenge_rows]
                chain_rows = conn.execute(
                    """
                    SELECT id, spark_id, witness_id, action, payload, timestamp, prev_hash, hash
                    FROM spark_witness_chain
                    WHERE spark_id = ?
                    ORDER BY id ASC
                    """,
                    (spark_id,),
                ).fetchall()
                for row in chain_rows:
                    payload_obj: Any = {}
                    try:
                        payload_obj = json.loads(str(row["payload"]))
                    except json.JSONDecodeError:
                        payload_obj = {"raw": str(row["payload"])}
                    timeline.append(
                        {
                            "id": int(row["id"]),
                            "witness_id": str(row["witness_id"]),
                            "action": str(row["action"]),
                            "payload": payload_obj,
                            "timestamp": str(row["timestamp"]),
                            "hash": str(row["hash"]),
                            "prev_hash": str(row["prev_hash"]),
                        }
                    )
                replay = _spark_chain_payload(conn, spark_id)

    return _render_template(
        request,
        "web_seed.html",
        {
            "seed_claim": seed_claim,
            "seed_payload": seed_payload,
            "spark": spark,
            "challenges": challenges,
            "timeline": timeline,
            "replay": replay,
            "session": _read_web_session(request),
            "path_name": "/seed",
        },
    )


@app.get("/submit", response_class=HTMLResponse)
async def web_submit_get(request: Request) -> HTMLResponse:
    session = _read_web_session(request)
    csrf = _csrf_token_for_session(session) if session else ""
    return _render_template(
        request,
        "web_submit.html",
        {"session": session, "error": "", "content": "", "csrf_token": csrf, "path_name": "/submit"},
    )


@app.post("/submit", response_class=HTMLResponse)
async def web_submit_post(
    request: Request,
    content: str = Form(...),
    display_name: str = Form(""),
    content_type: Literal["text", "code", "link"] = Form("text"),
    csrf_form: str = Form("", alias="_csrf"),
) -> HTMLResponse:
    session = _read_web_session(request)
    _verify_csrf_form_token(session, csrf_form)

    body = (content or "").strip()
    if not body:
        csrf = _csrf_token_for_session(session) if session else ""
        return _render_template(
            request,
            "web_submit.html",
            {"session": session, "error": "Content is required.", "content": body, "csrf_token": csrf, "path_name": "/submit"},
            status_code=400,
        )

    init_db()
    with _db() as conn:
        session = _resolve_or_create_web_session(request, conn, display_name)

    signing_key = _signing_key_from_session(session)
    content_sha256 = _sha256_hex(body.encode())
    signature = signing_key.sign(_message_for_submit(str(session["agent_id"]), content_sha256)).signature.hex()
    submit_req = SparkSubmitRequest(
        content=body,
        content_type=content_type,
        author_id=str(session["agent_id"]),
        signature=signature,
    )
    try:
        spark = await submit_spark(submit_req)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        csrf = _csrf_token_for_session(session) if session else ""
        return _render_template(
            request,
            "web_submit.html",
            {"session": session, "error": detail, "content": body, "csrf_token": csrf, "path_name": "/submit"},
            status_code=exc.status_code,
        )

    response = RedirectResponse(url=f"/spark/{int(spark['id'])}?submitted=1", status_code=303)
    if request.cookies.get(WEB_SESSION_COOKIE) != session["token"]:
        _set_web_session_cookie(response, session)
    return response


@app.get("/spark/{spark_id}", response_class=HTMLResponse)
async def web_spark_detail(
    request: Request,
    spark_id: int,
    submitted: int = Query(0, ge=0, le=1),
) -> HTMLResponse:
    init_db()
    with _db() as conn:
        spark = _spark_with_details(conn, spark_id)
        if spark is None:
            raise HTTPException(status_code=404, detail="spark not found")
        challenge_rows = conn.execute(
            """
            SELECT id, spark_id, challenger_id, content, created_at, resolution,
                   resolved_at, successor_spark_id, correction_artifact,
                   correction_content_sha256, sublation_witness_hash
            FROM spark_challenges
            WHERE spark_id = ?
            ORDER BY id ASC
            """,
            (spark_id,),
        ).fetchall()
        challenges = [_serialize_challenge_row(row) for row in challenge_rows]

        chain_rows = conn.execute(
            """
            SELECT id, spark_id, witness_id, action, payload, timestamp, prev_hash, hash
            FROM spark_witness_chain
            WHERE spark_id = ?
            ORDER BY id ASC
            """,
            (spark_id,),
        ).fetchall()
        timeline: List[Dict[str, Any]] = []
        for row in chain_rows:
            payload_obj: Any = {}
            try:
                payload_obj = json.loads(str(row["payload"]))
            except json.JSONDecodeError:
                payload_obj = {"raw": str(row["payload"])}
            timeline.append(
                {
                    "id": int(row["id"]),
                    "witness_id": str(row["witness_id"]),
                    "action": str(row["action"]),
                    "payload": payload_obj,
                    "timestamp": str(row["timestamp"]),
                    "hash": str(row["hash"]),
                    "prev_hash": str(row["prev_hash"]),
                }
            )

    session = _read_web_session(request)
    csrf = _csrf_token_for_session(session) if session else ""
    return _render_template(
        request,
        "web_spark_detail.html",
        {
            "spark": spark,
            "challenges": challenges,
            "timeline": timeline,
            "submitted": bool(submitted),
            "session": session,
            "csrf_token": csrf,
            "path_name": "/seed" if spark.get("founding_seed") else "",
        },
    )


@app.post("/spark/{spark_id}/challenge", response_class=HTMLResponse)
async def web_challenge_post(
    request: Request,
    spark_id: int,
    content: str = Form(...),
    display_name: str = Form(""),
    csrf_form: str = Form("", alias="_csrf"),
) -> HTMLResponse:
    _verify_csrf_form_token(_read_web_session(request), csrf_form)

    body = (content or "").strip()
    if not body:
        return RedirectResponse(url=f"/spark/{spark_id}?challenge_error=1", status_code=303)

    init_db()
    with _db() as conn:
        session = _resolve_or_create_web_session(request, conn, display_name)

    signing_key = _signing_key_from_session(session)
    content_sha256 = _sha256_hex(body.encode())
    signature = signing_key.sign(
        _message_for_challenge(spark_id, str(session["agent_id"]), content_sha256)
    ).signature.hex()
    challenge_req = ChallengeCreateRequest(
        challenger_id=str(session["agent_id"]),
        content=body,
        signature=signature,
    )
    try:
        await challenge_spark(spark_id, challenge_req)
    except HTTPException:
        return RedirectResponse(url=f"/spark/{spark_id}?challenge_error=1", status_code=303)

    response = RedirectResponse(url=f"/spark/{spark_id}#challenges", status_code=303)
    if request.cookies.get(WEB_SESSION_COOKIE) != session["token"]:
        _set_web_session_cookie(response, session)
    return response


@app.post("/spark/{spark_id}/witness", response_class=HTMLResponse)
async def web_witness_post(
    request: Request,
    spark_id: int,
    action: Literal["affirm", "canon_affirm", "compost"] = Form("affirm"),
    note: str = Form(""),
    display_name: str = Form(""),
    csrf_form: str = Form("", alias="_csrf"),
) -> HTMLResponse:
    _verify_csrf_form_token(_read_web_session(request), csrf_form)
    init_db()
    with _db() as conn:
        session = _resolve_or_create_web_session(request, conn, display_name)

    payload = {
        "note": (note or "").strip()[:500],
        "source": "web_surface",
    }
    signing_key = _signing_key_from_session(session)
    payload_sha = _sha256_hex(_canonical_bytes(payload))
    signature = signing_key.sign(
        _message_for_witness(spark_id, str(session["agent_id"]), action, payload_sha)
    ).signature.hex()
    witness_req = WitnessSignRequest(
        spark_id=spark_id,
        witness_id=str(session["agent_id"]),
        action=action,
        payload=payload,
        signature=signature,
    )
    try:
        await witness_sign(witness_req)
    except HTTPException:
        return RedirectResponse(url=f"/spark/{spark_id}?witness_error=1", status_code=303)

    response = RedirectResponse(url=f"/spark/{spark_id}#timeline", status_code=303)
    if request.cookies.get(WEB_SESSION_COOKIE) != session["token"]:
        _set_web_session_cookie(response, session)
    return response


@app.get("/register", response_class=HTMLResponse)
async def web_register_get(request: Request) -> HTMLResponse:
    return _render_template(
        request,
        "web_register.html",
        {"session": _read_web_session(request), "error": "", "path_name": "/register"},
    )


@app.post("/register", response_class=HTMLResponse)
async def web_register_post(request: Request, display_name: str = Form(...)) -> HTMLResponse:
    init_db()
    with _db() as conn:
        session = _create_web_session(conn, display_name)
    response = RedirectResponse(url=f"/agent/{session['agent_id']}", status_code=303)
    _set_web_session_cookie(response, session)
    return response


@app.get("/agent/{agent_id}", response_class=HTMLResponse)
async def web_agent_profile(request: Request, agent_id: str) -> HTMLResponse:
    init_db()
    with _db() as conn:
        agent = conn.execute(
            "SELECT id, name, public_key, created_at, witness_count, witness_accuracy FROM web_agents WHERE id = ?",
            (agent_id,),
        ).fetchone()
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")

        submitted_count = int(
            conn.execute("SELECT COUNT(*) AS c FROM sparks WHERE author_id = ?", (agent_id,)).fetchone()["c"]
        )
        canon_count = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM sparks WHERE author_id = ? AND status = 'canon'",
                (agent_id,),
            ).fetchone()["c"]
        )
        compost_count = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM sparks WHERE author_id = ? AND status = 'compost'",
                (agent_id,),
            ).fetchone()["c"]
        )
        challenge_made = int(
            conn.execute(
                "SELECT COUNT(*) AS c FROM spark_challenges WHERE challenger_id = ?",
                (agent_id,),
            ).fetchone()["c"]
        )
        challenged_total = int(
            conn.execute(
                """
                SELECT COUNT(DISTINCT c.spark_id) AS c
                FROM spark_challenges c
                JOIN sparks s ON s.id = c.spark_id
                WHERE s.author_id = ?
                """,
                (agent_id,),
            ).fetchone()["c"]
        )
        challenged_survived = int(
            conn.execute(
                """
                SELECT COUNT(DISTINCT c.spark_id) AS c
                FROM spark_challenges c
                JOIN sparks s ON s.id = c.spark_id
                WHERE s.author_id = ? AND s.status != 'compost'
                """,
                (agent_id,),
            ).fetchone()["c"]
        )
        attestation_total = int(
            conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM spark_witness_chain
                WHERE witness_id = ? AND action IN ('affirm', 'canon_affirm')
                """,
                (agent_id,),
            ).fetchone()["c"]
        )
        attestation_on_canon = int(
            conn.execute(
                """
                SELECT COUNT(*) AS c
                FROM spark_witness_chain w
                JOIN sparks s ON s.id = w.spark_id
                WHERE w.witness_id = ? AND w.action IN ('affirm', 'canon_affirm') AND s.status = 'canon'
                """,
                (agent_id,),
            ).fetchone()["c"]
        )

    canon_rate = (canon_count / submitted_count) if submitted_count else None
    challenge_survival = (challenged_survived / challenged_total) if challenged_total else None
    witness_accuracy = (attestation_on_canon / attestation_total) if attestation_total else None
    reliability = [
        {"label": "Canonization Rate", "value": canon_rate},
        {"label": "Challenge Survival", "value": challenge_survival},
        {"label": "Witness Accuracy", "value": witness_accuracy},
    ]
    return _render_template(
        request,
        "web_agent_profile.html",
        {
            "agent": dict(agent),
            "stats": {
                "submitted_count": submitted_count,
                "canon_count": canon_count,
                "compost_count": compost_count,
                "challenge_made": challenge_made,
                "challenged_total": challenged_total,
                "challenged_survived": challenged_survived,
                "attestation_total": attestation_total,
                "attestation_on_canon": attestation_on_canon,
            },
            "reliability": reliability,
            "session": _read_web_session(request),
        },
    )


@app.get("/about", response_class=HTMLResponse)
async def web_about(request: Request) -> HTMLResponse:
    return _render_template(
        request,
        "web_about.html",
        {"session": _read_web_session(request), "dimensions_count": len(SAB_17_DIMENSIONS), "path_name": "/about"},
    )


def main() -> None:
    """CLI entrypoint for the public SAB web surface."""
    import uvicorn

    host = os.getenv("SAB_HOST", "127.0.0.1")
    port = int(os.getenv("SAB_PORT", "8000"))
    reload = os.getenv("SAB_RELOAD", "0") == "1"
    uvicorn.run("agora.app:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    main()
