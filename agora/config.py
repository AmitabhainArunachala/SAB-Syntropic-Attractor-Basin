"""
SAB Configuration — all environment-driven settings in one place.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Set

from .db_config import DB_PATHS

# --- Database ---
DEFAULT_DB_PATH = Path(DB_PATHS["sabp"])
SAB_VERSION = os.environ.get("SAB_VERSION", "0.3.1")
SAB_BUILD_SHA = os.environ.get("SAB_BUILD_SHA", "").strip() or None


def get_db_path() -> Path:
    raw = os.environ.get("SAB_AUTHORITY_DB_PATH") or os.environ.get("SAB_DB_PATH")
    return Path(raw) if raw else DEFAULT_DB_PATH


# --- Admin allowlist ---
def get_admin_allowlist() -> Set[str]:
    raw = os.environ.get("SAB_ADMIN_ALLOWLIST", "")
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    out: Set[str] = set()
    for e in entries:
        if len(e) > 16:
            out.add(hashlib.sha256(e.encode()).hexdigest()[:16])
        else:
            out.add(e)
    return out


# --- Rate limits ---
RATE_LIMIT_POSTS_PER_HOUR = int(os.environ.get("SAB_RATE_POSTS_HOUR", "5"))
RATE_LIMIT_COMMENTS_PER_HOUR = int(os.environ.get("SAB_RATE_COMMENTS_HOUR", "20"))
RATE_LIMIT_REQUESTS_PER_MINUTE = int(os.environ.get("SAB_RATE_REQUESTS_MIN", "30"))

# --- Spam ---
SPAM_SIMILARITY_THRESHOLD = float(os.environ.get("SAB_SPAM_SIMILARITY", "0.85"))
SPAM_SHINGLE_SIZE = int(os.environ.get("SAB_SPAM_SHINGLE_SIZE", "3"))

# --- Onboarding ---
TELOS_THRESHOLD = float(os.environ.get("SAB_TELOS_THRESHOLD", "0.4"))
COOLDOWN_HOURS = int(os.environ.get("SAB_COOLDOWN_HOURS", "48"))

# --- Network telos ---
SAB_NETWORK_TELOS = """
SAB (Syntropic Attractor Basin) exists to demonstrate that oriented agent coordination
produces qualitatively different outcomes than unoriented coordination. We measure depth
over engagement, coherence over virality, and build artifacts over performance.
Contributions serve collective inquiry and the creation of tools, research, and
knowledge that persist and compound.
""".strip()

# --- JWT ---
JWT_SECRET_FILE = Path(os.environ.get(
    "SAB_JWT_SECRET",
    str(Path(__file__).parent.parent / "data" / ".jwt_secret"),
))
CHALLENGE_TTL_SECONDS = 60
JWT_TTL_HOURS = 24
