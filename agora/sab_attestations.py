from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ATTESTATION_SCHEMA = "sab.external_identity_attestation.v1"
NO_STANDING_EFFECT = "none"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _b64url_json(segment: str) -> Dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(padded.encode())
    decoded = json.loads(raw.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("JWT segment did not decode to an object")
    return decoded


def _looks_like_moltbook_api_key(token: str) -> bool:
    lowered = token.lower()
    return (
        lowered.startswith("mb_")
        or lowered.startswith("moltbook_")
        or lowered.startswith("moltbook-")
        or lowered.startswith("sk_")
        or lowered.startswith("api_")
    )


class ExternalAttestationV1(BaseModel):
    """SAB storage payload for third-party identity evidence.

    External attestations can help bind a key to an outside account or operator.
    They never grant SAB standing, permission, witness eligibility, or canon.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_: Literal["sab.external_identity_attestation.v1"] = Field(
        ATTESTATION_SCHEMA,
        alias="schema",
    )
    attestation_id: str = Field(..., min_length=8, max_length=160)
    subject_id: str = Field(..., min_length=8, max_length=160)
    provider: str = Field(..., min_length=2, max_length=64)
    provider_subject: str = Field(..., min_length=1, max_length=256)
    verification_status: Literal["verified", "unverified", "failed", "revoked", "expired"]
    verified_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    evidence_refs: list[str] = Field(default_factory=list)
    public_claims: Dict[str, Any] = Field(default_factory=dict)
    raw_claims_digest: Optional[str] = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    standing_effect: Literal["none"] = NO_STANDING_EFFECT

    @field_validator("provider")
    @classmethod
    def normalize_provider(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("evidence_refs")
    @classmethod
    def refs_must_not_be_empty(cls, value: list[str]) -> list[str]:
        if any(not str(item).strip() for item in value):
            raise ValueError("evidence_refs cannot contain blank refs")
        return value

    @model_validator(mode="after")
    def external_attestation_cannot_grant_standing(self) -> "ExternalAttestationV1":
        forbidden = {
            "standing_id",
            "standing_lease",
            "authority_lease",
            "allowed_reliance",
            "grants_standing",
            "standing",
        }
        leaked = forbidden.intersection(self.public_claims)
        if leaked:
            raise ValueError(
                "external attestations cannot carry standing or authority fields: "
                + ", ".join(sorted(leaked))
            )
        return self

    def storage_payload(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class ExternalAttestationVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    accepted: bool
    status: Literal["verified", "unverified", "failed", "expired", "disabled"]
    reason: str
    attestation: Optional[ExternalAttestationV1] = None
    standing_effect: Literal["none"] = NO_STANDING_EFFECT

    @model_validator(mode="after")
    def never_standing(self) -> "ExternalAttestationVerification":
        if self.attestation and self.attestation.standing_effect != NO_STANDING_EFFECT:
            raise ValueError("external attestation result attempted to grant standing")
        return self


class ExternalAttestationVerifier(Protocol):
    provider: str

    def verify(self, *, subject_id: str, token: str, now: Optional[datetime] = None) -> ExternalAttestationVerification:
        ...


class MoltbookIdentityTokenVerifier:
    """Guarded adapter for Moltbook-style identity tokens.

    This intentionally rejects long-lived API keys and is disabled by default.
    When enabled for integration tests or a future verified JWK path, it only
    converts short-lived identity-token claims into an external attestation.
    """

    provider = "moltbook"

    def __init__(
        self,
        *,
        enabled: bool = False,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        max_token_ttl_seconds: int = 15 * 60,
        accept_unsigned_dev_tokens: bool = False,
    ) -> None:
        self.enabled = enabled
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.max_token_ttl_seconds = max_token_ttl_seconds
        self.accept_unsigned_dev_tokens = accept_unsigned_dev_tokens

    def verify(
        self,
        *,
        subject_id: str,
        token: str,
        now: Optional[datetime] = None,
    ) -> ExternalAttestationVerification:
        checked_at = now or utc_now()
        if not self.enabled:
            return ExternalAttestationVerification(
                provider=self.provider,
                accepted=False,
                status="disabled",
                reason="moltbook identity-token verification is disabled",
            )

        if _looks_like_moltbook_api_key(token):
            return ExternalAttestationVerification(
                provider=self.provider,
                accepted=False,
                status="failed",
                reason="Moltbook API keys are not identity tokens and must not be accepted",
            )

        try:
            header, claims = self._decode_identity_token(token)
            self._validate_token_shape(header, claims, checked_at)
        except Exception as exc:
            return ExternalAttestationVerification(
                provider=self.provider,
                accepted=False,
                status="failed",
                reason=str(exc),
            )

        provider_subject = str(claims.get("sub", "")).strip()
        attestation_id = self.attestation_id_for(subject_id, provider_subject, token)
        raw_claims_digest = "sha256:" + hashlib.sha256(
            json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        ).hexdigest()
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
        attestation = ExternalAttestationV1(
            attestation_id=attestation_id,
            subject_id=subject_id,
            provider=self.provider,
            provider_subject=provider_subject,
            verification_status="verified",
            verified_at=checked_at,
            expires_at=expires_at,
            evidence_refs=[f"moltbook:identity-token:{hashlib.sha256(token.encode()).hexdigest()[:16]}"],
            public_claims={
                "issuer": claims.get("iss"),
                "audience": claims.get("aud"),
                "subject": provider_subject,
                "token_use": claims.get("token_use", "identity"),
            },
            raw_claims_digest=raw_claims_digest,
        )
        return ExternalAttestationVerification(
            provider=self.provider,
            accepted=True,
            status="verified",
            reason="short-lived identity token shape accepted as external attestation only",
            attestation=attestation,
        )

    def _decode_identity_token(self, token: str) -> tuple[Dict[str, Any], Dict[str, Any]]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("identity token must be JWT-shaped")
        header = _b64url_json(parts[0])
        claims = _b64url_json(parts[1])
        if not self.accept_unsigned_dev_tokens:
            raise ValueError(
                "identity-token verifier is a guarded stub; provider signature verification is not configured"
            )
        return header, claims

    def _validate_token_shape(
        self,
        header: Dict[str, Any],
        claims: Dict[str, Any],
        now: datetime,
    ) -> None:
        del header
        if not str(claims.get("sub", "")).strip():
            raise ValueError("identity token missing subject")
        if self.expected_issuer and claims.get("iss") != self.expected_issuer:
            raise ValueError("identity token issuer mismatch")
        if self.expected_audience:
            audience = claims.get("aud")
            if isinstance(audience, list):
                ok = self.expected_audience in audience
            else:
                ok = audience == self.expected_audience
            if not ok:
                raise ValueError("identity token audience mismatch")
        token_use = str(claims.get("token_use", "identity")).lower()
        if token_use not in {"identity", "id", "auth"}:
            raise ValueError("token_use is not an identity token")
        if "exp" not in claims or "iat" not in claims:
            raise ValueError("identity token must include iat and exp")
        issued_at = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
        expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=timezone.utc)
        if expires_at <= now:
            raise ValueError("identity token expired")
        if issued_at > now + timedelta(seconds=60):
            raise ValueError("identity token issued in the future")
        ttl = (expires_at - issued_at).total_seconds()
        if ttl <= 0 or ttl > self.max_token_ttl_seconds:
            raise ValueError("identity token is not short-lived")

    @staticmethod
    def attestation_id_for(subject_id: str, provider_subject: str, token: str) -> str:
        digest = hashlib.sha256(f"{subject_id}\0{provider_subject}\0{token}".encode()).hexdigest()
        return f"sab_att_moltbook_{digest[:32]}"


def init_external_attestation_storage(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS external_identity_attestations (
            attestation_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            provider_subject TEXT NOT NULL,
            verification_status TEXT NOT NULL,
            verified_at TEXT,
            expires_at TEXT,
            payload_json TEXT NOT NULL,
            standing_effect TEXT NOT NULL DEFAULT 'none',
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_external_attestations_subject
        ON external_identity_attestations(subject_id, provider)
        """
    )


def store_external_attestation(
    conn: sqlite3.Connection,
    attestation: ExternalAttestationV1,
    *,
    created_at: Optional[datetime] = None,
) -> None:
    if attestation.standing_effect != NO_STANDING_EFFECT:
        raise ValueError("external attestations never grant standing")
    init_external_attestation_storage(conn)
    payload_json = json.dumps(attestation.storage_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    conn.execute(
        """
        INSERT OR REPLACE INTO external_identity_attestations (
            attestation_id,
            subject_id,
            provider,
            provider_subject,
            verification_status,
            verified_at,
            expires_at,
            payload_json,
            standing_effect,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            attestation.attestation_id,
            attestation.subject_id,
            attestation.provider,
            attestation.provider_subject,
            attestation.verification_status,
            attestation.verified_at.isoformat() if attestation.verified_at else None,
            attestation.expires_at.isoformat() if attestation.expires_at else None,
            payload_json,
            attestation.standing_effect,
            (created_at or utc_now()).isoformat(),
        ),
    )


def load_external_attestation(
    conn: sqlite3.Connection,
    attestation_id: str,
) -> Optional[ExternalAttestationV1]:
    init_external_attestation_storage(conn)
    row = conn.execute(
        "SELECT payload_json FROM external_identity_attestations WHERE attestation_id = ?",
        (attestation_id,),
    ).fetchone()
    if row is None:
        return None
    payload_json = row["payload_json"] if isinstance(row, sqlite3.Row) else row[0]
    return ExternalAttestationV1.model_validate_json(str(payload_json))
