"""Authority-gated, copy-only lifecycle activation for SAB Build A.

The module intentionally has no database discovery, application import, key
generation, provider access, or live activation path.  Callers must provide an
explicit SQLite connection whose additive first-verdict migration has already
been applied.  Every lifecycle mutation is performed under one
``BEGIN IMMEDIATE`` transaction.

The important ordering is semantic rather than documentary: a signed policy is
evaluated into ``DispositionAuthority`` before case merit, ballots, a verdict,
or an effect payload is inspected.  Only ``Authorized<Copy>`` with fixture
provenance can cross the construction boundary into a rehearsal disposition.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .sab_artifact_verdict import (
    ArtifactBallotV1,
    ArtifactCaseV1,
    ContractSignatureV1,
    CouncilVerdictV1,
    DispositionScope,
    MASTER_VISION_SEED_ID,
    OperatorCountersignV1,
    RehearsalDispositionV1,
    SeedSupersessionV1,
    SessionWriteLeaseV1,
    SignedDispositionPolicyV1,
    TrustedPolicyIssuerV1,
    canonical_json_sha256,
    canonical_json_bytes,
    evaluate_disposition_authority,
    require_rehearsal_authority,
    verify_contract_signature,
)
from .sab_first_verdict_evidence import (
    EvidenceValidationError,
    lifecycle_fingerprint as copied_database_lifecycle_fingerprint,
    observe_master_vision_state,
    witness_forest_heads,
)
from .sab_first_verdict_storage import (
    CopyDatabaseAttestation,
    ImmutableConflict,
    canonical_json_text,
    idempotency_lookup,
    record_idempotency,
    require_copy_or_fixture_connection,
)
from .sab_verdict_verify import (
    ReplayValidationError,
    signature_evidence_record_hash,
    verify_new_signature_suffix,
    verify_new_signature_table,
    verify_signature_evidence_table,
)


ACTIVATION_OPERATION = "rehearsal-disposition:correct-and-supersede:v1"
ACTIVATION_METHOD_PATH = (
    "POST",
    "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
)
FROZEN_EFFECTS = ("challenge:resolve", "seed:supersede")
MAX_ACTIVATION_CLOCK_SKEW = timedelta(seconds=60)

MUTATION_BOUNDARIES = (
    "countersign_insert",
    "target_transition",
    "successor_insert",
    "disposition_insert",
    "lineage_insert",
    "signature_evidence_insert",
    "signed_event_insert",
    "idempotency_insert",
)

_DIRECTLY_MUTATED_TABLES = frozenset(
    {
        "sab_operator_countersigns_v1",
        "sab_rehearsal_artifacts_v1",
        "sab_rehearsal_dispositions_v1",
        "sab_seed_lineage_edges_v1",
        "sab_first_verdict_signature_evidence_v1",
        "sab_first_verdict_signed_events_v1",
        "sab_first_verdict_idempotency_v1",
    }
)
_TABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class LifecycleError(RuntimeError):
    """Stable domain error suitable for the dedicated maintenance API."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


class LifecycleValidationError(LifecycleError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=422)


class LifecycleAuthorityDenied(LifecycleError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=403)


class LifecycleConflict(LifecycleError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, status_code=409)


@dataclass(frozen=True)
class FixtureExecutionContext:
    """Out-of-band trust anchor provisioned by the copied-fixture runner.

    The dedicated application must construct this value from its local,
    authorized fixture configuration.  It is intentionally not accepted as a
    member of request JSON.
    """

    proof_class: str
    target_artifact_id: str
    target_artifact_sha256: str
    source_fixture_id: str
    copied_database_id: str
    source_backup_sha256: str
    code_sha: str
    copied_lifecycle_fingerprint: str
    synthetic_state_hash: str
    expected_case_head: str
    policy_issuer_identity: str
    policy_issuer_public_key: str
    operator_identity: str
    operator_public_key: str
    clerk_identity: str
    clerk_public_key: str
    claimant_identity: str
    claimant_public_key: str
    event_signer_identity: str
    event_signer_public_key: str
    seat_execution_identities: tuple[tuple[str, str, str], ...]

    def __post_init__(self) -> None:
        if self.proof_class != "authorized_synthetic_copy_fixture":
            raise ValueError(
                "fixture context proof_class is not authorized synthetic copy"
            )
        for field in (
            "target_artifact_sha256",
            "source_backup_sha256",
            "copied_lifecycle_fingerprint",
            "synthetic_state_hash",
            "expected_case_head",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(getattr(self, field))):
                raise ValueError(f"fixture context {field} must be lowercase SHA-256")
        if not re.fullmatch(r"[0-9a-f]{40}", self.code_sha):
            raise ValueError("fixture context code_sha must be lowercase Git SHA")
        for field in (
            "policy_issuer_public_key",
            "operator_public_key",
            "clerk_public_key",
            "claimant_public_key",
            "event_signer_public_key",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(getattr(self, field))):
                raise ValueError(f"fixture context {field} must be an Ed25519 key")
        if len(self.seat_execution_identities) != 9:
            raise ValueError("fixture context must bind exactly nine execution seats")
        seat_ids = {item[0] for item in self.seat_execution_identities}
        if len(seat_ids) != 9 or any(
            not re.fullmatch(r"[0-9a-f]{64}", item[2])
            for item in self.seat_execution_identities
        ):
            raise ValueError("fixture context seat identities/keys are invalid")

    @property
    def digest(self) -> str:
        return canonical_json_sha256(asdict(self))


class LifecycleEventPayloadV1(BaseModel):
    """Closed payload signed by the ephemeral lifecycle-event fixture key."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["sab.first_verdict_lifecycle_event.v1"] = (
        "sab.first_verdict_lifecycle_event.v1"
    )
    event_id: str = Field(min_length=1, max_length=240)
    event_type: Literal["rehearsal_supersession_committed"] = (
        "rehearsal_supersession_committed"
    )
    case_id: str = Field(min_length=1, max_length=240)
    verdict_id: str = Field(min_length=1, max_length=240)
    disposition_id: str = Field(min_length=1, max_length=240)
    lineage_edge_id: str = Field(min_length=1, max_length=240)
    target_artifact_id: str = Field(min_length=1, max_length=240)
    successor_artifact_id: str = Field(min_length=1, max_length=240)
    authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    countersign_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    lineage_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    prev_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    scope: Literal["Copy"] = "Copy"
    proof_class: Literal["copied_live_db_rehearsal"] = "copied_live_db_rehearsal"
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False


class SignedLifecycleEventV1(BaseModel):
    """Exact signed-event envelope; undeclared unsigned fields are forbidden."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_type: Literal["lifecycle_event"] = "lifecycle_event"
    artifact_id: str = Field(min_length=1, max_length=240)
    signer_kind: Literal["fixture_ephemeral"] = "fixture_ephemeral"
    signed_payload: LifecycleEventPayloadV1
    signature: ContractSignatureV1

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)


class LifecycleEventPayloadWireV1(BaseModel):
    """Closed wire shape checked before authority without effect semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Any
    event_id: Any
    event_type: Any
    case_id: Any
    verdict_id: Any
    disposition_id: Any
    lineage_edge_id: Any
    target_artifact_id: Any
    successor_artifact_id: Any
    authority_digest: Any
    countersign_sha256: Any
    disposition_sha256: Any
    lineage_sha256: Any
    before_state_hash: Any
    after_state_hash: Any
    prev_hash: Any
    scope: Any
    proof_class: Any
    standing_effect: Any
    live_eligible: Any


class ContractSignatureWireV1(BaseModel):
    """Closed signature wire shape; cryptographic semantics run after authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    alg: Any
    signer: Any
    public_key: Any
    signature: Any
    signed_payload_sha256: Any
    canonicalization: Any


class SignedLifecycleEventWireV1(BaseModel):
    """Closed event wire shape which cannot carry undeclared unsigned data."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_type: Any
    artifact_id: Any
    signer_kind: Any
    signed_payload: LifecycleEventPayloadWireV1
    signature: ContractSignatureWireV1


class RehearsalLifecycleRequestV1(BaseModel):
    """Strict wire envelope; effect semantics are parsed only after authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["sab.rehearsal_lifecycle_request.v1"] = (
        "sab.rehearsal_lifecycle_request.v1"
    )
    idempotency_key: str = Field(min_length=1, max_length=240)
    code_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    artifact_id: str = Field(min_length=1, max_length=200)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluated_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_effects: tuple[str, ...]
    signed_policy: dict[str, Any]
    countersign: dict[str, Any]
    disposition: dict[str, Any]
    successor_artifact: dict[str, Any]
    lineage_edge_id: str = Field(min_length=1, max_length=240)
    supersession: dict[str, Any]
    signed_event: SignedLifecycleEventWireV1

    @field_validator("requested_effects", mode="before")
    @classmethod
    def exact_frozen_effects(cls, value: Sequence[str]) -> tuple[str, ...]:
        if isinstance(value, (str, bytes, bytearray)) or not isinstance(
            value, Sequence
        ):
            raise ValueError("request effects must be a sequence of strings")
        if any(not isinstance(item, str) for item in value):
            raise ValueError("request effects must contain strings only")
        normalized = tuple(sorted({item.strip() for item in value}))
        if normalized != FROZEN_EFFECTS:
            raise ValueError("request effects must equal the frozen Build A effect set")
        return normalized

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)


class SyntheticSeedPacketV1(BaseModel):
    """Strict synthetic successor packet parsed only after authority succeeds."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, populate_by_name=True, serialize_by_alias=True
    )

    schema_: Literal["sab.synthetic_seed_packet.v1"] = Field(
        "sab.synthetic_seed_packet.v1", alias="schema"
    )
    seed_id: str = Field(min_length=1, max_length=200)
    claim: str = Field(min_length=1, max_length=6000)
    claimant_identity: str = Field(min_length=1, max_length=200)


class SyntheticSuccessorArtifactV1(BaseModel):
    """Closed effect envelope; arbitrary request keys can never be persisted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(min_length=1, max_length=200)
    state: Literal["pending"] = "pending"
    packet: SyntheticSeedPacketV1
    packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    packet_signature: ContractSignatureV1
    claimant_identity: str = Field(min_length=1, max_length=200)
    challenges: tuple[Any, ...] = Field(default=(), max_length=0)
    source_fixture_id: str = Field(min_length=1, max_length=240)
    copied_database_id: str = Field(min_length=1, max_length=240)
    standing_effect: Literal["none"] = "none"
    live_eligible: Literal[False] = False

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=False)


def _fail(code: str, message: str) -> None:
    raise LifecycleValidationError(code, message)


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        _fail(code, message)


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise LifecycleValidationError("naive_now", "now must be timezone-aware")
    return current.astimezone(timezone.utc)


def _json_ready(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=False)
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return value


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise LifecycleValidationError(
            "request_shape_invalid", f"{field} must be an object"
        )
    return {str(key): _json_ready(item) for key, item in value.items()}


def _parse(model: Any, value: Any, field: str) -> Any:
    try:
        return model.model_validate(value)
    except ValidationError as exc:
        raise LifecycleValidationError(
            f"{field}_contract_invalid", f"invalid {field} contract"
        ) from exc


def _fetchone_dict(
    conn: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any] = (),
) -> dict[str, Any] | None:
    cursor = conn.execute(sql, tuple(parameters))
    row = cursor.fetchone()
    if row is None:
        return None
    columns = tuple(item[0] for item in cursor.description or ())
    return dict(zip(columns, tuple(row)))


def _fetchall_dicts(
    conn: sqlite3.Connection,
    sql: str,
    parameters: Sequence[Any] = (),
) -> list[dict[str, Any]]:
    cursor = conn.execute(sql, tuple(parameters))
    columns = tuple(item[0] for item in cursor.description or ())
    return [dict(zip(columns, tuple(row))) for row in cursor.fetchall()]


def _stable_sql_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"$bytes_hex": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def table_content_digest(
    conn: sqlite3.Connection,
    table: str,
    *,
    exclude_column: str | None = None,
    exclude_values: Sequence[str] = (),
) -> str:
    """Hash table rows without relying on rowid or connection row factories."""

    if not _TABLE_NAME.fullmatch(table):
        raise ValueError("unsafe table name")
    if exclude_column is not None and not _TABLE_NAME.fullmatch(exclude_column):
        raise ValueError("unsafe column name")
    cursor = conn.execute(f'SELECT * FROM "{table}"')
    columns = [item[0] for item in cursor.description or ()]
    if exclude_column is not None and exclude_column not in columns:
        raise ValueError(f"unknown exclusion column {exclude_column} for {table}")
    excluded = set(exclude_values)
    encoded_rows: list[str] = []
    for raw_row in cursor.fetchall():
        row = dict(zip(columns, tuple(raw_row)))
        if exclude_column is not None and str(row[exclude_column]) in excluded:
            continue
        normalized = {key: _stable_sql_value(row[key]) for key in columns}
        encoded_rows.append(canonical_json_text(normalized))
    encoded_rows.sort()
    return canonical_json_sha256({"columns": columns, "rows": encoded_rows})


def _user_tables(conn: sqlite3.Connection) -> tuple[str, ...]:
    rows = conn.execute(
        """
        SELECT name FROM sqlite_master
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name
        """
    ).fetchall()
    return tuple(str(row[0]) for row in rows)


def _invariant_snapshot(
    conn: sqlite3.Connection,
    *,
    target_id: str,
    successor_id: str,
    countersign_id: str,
    disposition_id: str,
    lineage_edge_id: str,
    event_id: str,
    idempotency_key: str,
) -> dict[str, str]:
    """Digest every untouched table and every unrelated row in touched tables."""

    exclusions = {
        "sab_operator_countersigns_v1": ("countersign_id", (countersign_id,)),
        "sab_rehearsal_artifacts_v1": ("artifact_id", (target_id, successor_id)),
        "sab_rehearsal_dispositions_v1": ("disposition_id", (disposition_id,)),
        "sab_seed_lineage_edges_v1": ("edge_id", (lineage_edge_id,)),
        "sab_first_verdict_signature_evidence_v1": (
            "lifecycle_event_id",
            (event_id,),
        ),
        "sab_first_verdict_signed_events_v1": ("event_id", (event_id,)),
        # The primary key is compound; excluding this key is sufficient because
        # Build A uses one frozen operation name.
        "sab_first_verdict_idempotency_v1": ("idempotency_key", (idempotency_key,)),
    }
    snapshot: dict[str, str] = {}
    for table in _user_tables(conn):
        if table in exclusions:
            column, values = exclusions[table]
            snapshot[f"{table}:unrelated"] = table_content_digest(
                conn, table, exclude_column=column, exclude_values=values
            )
        else:
            snapshot[table] = table_content_digest(conn, table)
    return snapshot


def _artifact_state_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _fetchall_dicts(
        conn,
        """
        SELECT artifact_id, state, artifact_json, artifact_sha256, live_eligible
        FROM sab_rehearsal_artifacts_v1
        ORDER BY artifact_id
        """,
    )


def _state_fingerprint_rows(rows: Sequence[Mapping[str, Any]]) -> str:
    normalized = [
        {
            "artifact_id": str(row["artifact_id"]),
            "state": str(row["state"]),
            "artifact_json": str(row["artifact_json"]),
            "artifact_sha256": str(row["artifact_sha256"]),
            "live_eligible": int(row["live_eligible"]),
        }
        for row in rows
    ]
    normalized.sort(key=lambda row: row["artifact_id"])
    return canonical_json_sha256(normalized)


def rehearsal_state_fingerprint(conn: sqlite3.Connection) -> str:
    """Fingerprint the synthetic artifact state domain, and no live tables."""

    return _state_fingerprint_rows(_artifact_state_rows(conn))


def _event_hash_material(
    *,
    event_id: str,
    event_type: str,
    signer: str,
    public_key: str,
    prev_hash: str | None,
    payload_sha256: str,
    signature: str,
    created_at: str,
) -> str:
    return canonical_json_sha256(
        {
            "event_id": event_id,
            "event_type": event_type,
            "signer": signer,
            "public_key": public_key,
            "prev_hash": prev_hash,
            "payload_sha256": payload_sha256,
            "signature": signature,
            "created_at": created_at,
        }
    )


def new_signed_event_chain_head(conn: sqlite3.Connection) -> str | None:
    """Validate the entire new signed suffix and return its unique head."""

    rows = _fetchall_dicts(
        conn,
        """
        SELECT event_id, event_type, signer, public_key, prev_hash,
               payload_json, payload_sha256, signature, event_hash, created_at
        FROM sab_first_verdict_signed_events_v1 ORDER BY rowid
        """,
    )
    head: str | None = None
    seen_hashes: set[str] = set()
    for row in rows:
        event_id = str(row["event_id"])
        if row["prev_hash"] != head:
            raise LifecycleConflict(
                "signed_event_chain_fork",
                f"new signed event {event_id} does not extend the unique head",
            )
        payload_json = str(row["payload_json"])
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError as exc:
            raise LifecycleConflict(
                "signed_event_payload_invalid",
                f"new signed event {event_id} JSON is invalid",
            ) from exc
        if canonical_json_text(payload) != payload_json:
            raise LifecycleConflict(
                "signed_event_payload_noncanonical",
                f"new signed event {event_id} payload is not canonical",
            )
        payload_sha = hashlib.sha256(payload_json.encode()).hexdigest()
        if payload_sha != str(row["payload_sha256"]):
            raise LifecycleConflict(
                "signed_event_payload_hash_mismatch",
                f"new signed event {event_id} payload hash mismatches",
            )
        computed = _event_hash_material(
            event_id=event_id,
            event_type=str(row["event_type"]),
            signer=str(row["signer"]),
            public_key=str(row["public_key"]),
            prev_hash=None if row["prev_hash"] is None else str(row["prev_hash"]),
            payload_sha256=payload_sha,
            signature=str(row["signature"]),
            created_at=str(row["created_at"]),
        )
        if computed != str(row["event_hash"]) or computed in seen_hashes:
            raise LifecycleConflict(
                "signed_event_hash_mismatch",
                f"new signed event {event_id} hash mismatches or repeats",
            )
        try:
            verify_new_signature_suffix(
                [
                    {
                        "artifact_type": "lifecycle_event",
                        "artifact_id": event_id,
                        "signed_payload": payload,
                        "signature": {
                            "alg": "ed25519",
                            "signer": str(row["signer"]),
                            "public_key": str(row["public_key"]),
                            "signature": str(row["signature"]),
                            "signed_payload_sha256": payload_sha,
                            "canonicalization": "json-sort-keys-compact-v1",
                        },
                    }
                ],
                required_artifact_types=("lifecycle_event",),
            )
        except ReplayValidationError as exc:
            raise LifecycleConflict(exc.code, str(exc)) from exc
        seen_hashes.add(computed)
        head = computed
    return head


def case_scope_head(conn: sqlite3.Connection, target_artifact_id: str) -> str:
    """Derive the countersigned case head from legacy and new evidence state."""

    legacy = {
        scope: digest
        for scope, digest in witness_forest_heads(conn).items()
        if target_artifact_id in scope
    }
    return canonical_json_sha256(
        {
            "target_artifact_id": target_artifact_id,
            "legacy_witness_heads": legacy,
            "new_signed_suffix_head": new_signed_event_chain_head(conn),
        }
    )


def compute_ballot_set_sha256(ballot_rows: Sequence[Mapping[str, Any]]) -> str:
    """Bind a verdict to an exact ordered set of immutable ballot digests."""

    members = sorted(
        (
            {
                "ballot_id": str(row["ballot_id"]),
                "ballot_sha256": str(row["ballot_sha256"]),
            }
            for row in ballot_rows
        ),
        key=lambda item: item["ballot_id"],
    )
    return canonical_json_sha256(members)


def build_effect_payload(
    *,
    effects: Sequence[str],
    disposition_id: str,
    target_artifact_id: str,
    successor_artifact: Mapping[str, Any],
    supersession_sha256: str,
) -> dict[str, Any]:
    """Return the exact effect object that an operator countersign must bind."""

    successor = _json_ready(successor_artifact)
    return {
        "effects": sorted({str(effect) for effect in effects}),
        "disposition_id": disposition_id,
        "target_artifact_id": target_artifact_id,
        "successor_artifact_id": str(successor["artifact_id"]),
        "successor_artifact_sha256": canonical_json_sha256(successor),
        "supersession_sha256": supersession_sha256,
    }


def build_lifecycle_event_payload(
    *,
    event_id: str,
    case_id: str,
    verdict_id: str,
    disposition_id: str,
    lineage_edge_id: str,
    target_artifact_id: str,
    successor_artifact_id: str,
    authority_digest: str,
    countersign_sha256: str,
    disposition_sha256: str,
    lineage_sha256: str,
    before_state_hash: str,
    after_state_hash: str,
    prev_hash: str | None,
) -> dict[str, Any]:
    """Return the exact payload an ephemeral fixture event key must sign."""

    return {
        "schema_version": "sab.first_verdict_lifecycle_event.v1",
        "event_id": event_id,
        "event_type": "rehearsal_supersession_committed",
        "case_id": case_id,
        "verdict_id": verdict_id,
        "disposition_id": disposition_id,
        "lineage_edge_id": lineage_edge_id,
        "target_artifact_id": target_artifact_id,
        "successor_artifact_id": successor_artifact_id,
        "authority_digest": authority_digest,
        "countersign_sha256": countersign_sha256,
        "disposition_sha256": disposition_sha256,
        "lineage_sha256": lineage_sha256,
        "before_state_hash": before_state_hash,
        "after_state_hash": after_state_hash,
        "prev_hash": prev_hash,
        "scope": "Copy",
        "proof_class": "copied_live_db_rehearsal",
        "standing_effect": "none",
        "live_eligible": False,
    }


def _transitioned_target(
    target: Mapping[str, Any],
    *,
    case: ArtifactCaseV1,
    successor_id: str,
    disposition_id: str,
) -> dict[str, Any]:
    transitioned = copy.deepcopy(dict(target))
    challenges = transitioned.get("challenges")
    _require(
        isinstance(challenges, list),
        "target_challenges_missing",
        "target challenges missing",
    )
    expected = {
        item.challenge_id: (item.challenge_packet_sha256, item.status)
        for item in case.challenges
    }
    observed: dict[str, tuple[str, str]] = {}
    for challenge in challenges:
        _require(
            isinstance(challenge, dict),
            "target_challenge_invalid",
            "challenge must be an object",
        )
        challenge_id = str(challenge.get("challenge_id") or "")
        observed[challenge_id] = (
            str(challenge.get("challenge_packet_sha256") or ""),
            str(challenge.get("status") or ""),
        )
    _require(
        observed == expected,
        "challenge_snapshot_drift",
        "challenge snapshot does not match case",
    )
    _require(
        bool(expected) and all(status == "pending" for _, status in expected.values()),
        "challenge_not_pending",
        "synthetic supersession requires pending challenge state",
    )
    for challenge in challenges:
        challenge["status"] = "resolved"
    transitioned["state"] = "superseded"
    transitioned["superseded_by"] = successor_id
    transitioned["disposition_id"] = disposition_id
    transitioned["standing_effect"] = "none"
    transitioned["live_eligible"] = False
    return transitioned


def _simulated_after_fingerprint(
    conn: sqlite3.Connection,
    *,
    target_id: str,
    transitioned_target: Mapping[str, Any],
    successor: Mapping[str, Any],
) -> str:
    target_json = canonical_json_text(_json_ready(transitioned_target))
    successor_json = canonical_json_text(_json_ready(successor))
    rows = [
        row
        for row in _artifact_state_rows(conn)
        if str(row["artifact_id"]) != target_id
    ]
    rows.extend(
        (
            {
                "artifact_id": target_id,
                "state": str(transitioned_target["state"]),
                "artifact_json": target_json,
                "artifact_sha256": hashlib.sha256(target_json.encode()).hexdigest(),
                "live_eligible": 0,
            },
            {
                "artifact_id": str(successor["artifact_id"]),
                "state": str(successor["state"]),
                "artifact_json": successor_json,
                "artifact_sha256": hashlib.sha256(successor_json.encode()).hexdigest(),
                "live_eligible": 0,
            },
        )
    )
    return _state_fingerprint_rows(rows)


def preview_rehearsal_transition(
    conn: sqlite3.Connection,
    *,
    case: ArtifactCaseV1 | Mapping[str, Any],
    successor_artifact: Mapping[str, Any],
    disposition_id: str,
) -> dict[str, Any]:
    """Deterministically preview the copy-state hashes without writing.

    This is the construction helper used before a caller signs the countersign
    and lifecycle event.  It reads only the synthetic rehearsal-artifact table.
    The activation path re-derives the same values under ``BEGIN IMMEDIATE``.
    """

    parsed_case = (
        case
        if isinstance(case, ArtifactCaseV1)
        else _parse(ArtifactCaseV1, case, "case")
    )
    successor = _mapping(successor_artifact, "successor_artifact")
    target_row = _fetchone_dict(
        conn,
        """
        SELECT artifact_json FROM sab_rehearsal_artifacts_v1
        WHERE artifact_id = ?
        """,
        (parsed_case.target_seed_id,),
    )
    if target_row is None:
        raise LifecycleValidationError(
            "target_artifact_missing", "synthetic target artifact is missing"
        )
    target = json.loads(str(target_row["artifact_json"]))
    transitioned = _transitioned_target(
        target,
        case=parsed_case,
        successor_id=str(successor.get("artifact_id") or ""),
        disposition_id=disposition_id,
    )
    before = rehearsal_state_fingerprint(conn)
    after = _simulated_after_fingerprint(
        conn,
        target_id=parsed_case.target_seed_id,
        transitioned_target=transitioned,
        successor=successor,
    )
    return {
        "before_state_hash": before,
        "after_state_hash": after,
        "transitioned_target": transitioned,
        "transitioned_target_sha256": canonical_json_sha256(transitioned),
        "successor_artifact_sha256": canonical_json_sha256(successor),
        "mutation_count": 0,
    }


def _verify_contract_message(
    artifact: Any,
    signature_field: str,
    *,
    code: str,
) -> None:
    signature = getattr(artifact, signature_field)
    message = artifact.canonical_bytes(exclude={signature_field})
    if not verify_contract_signature(message, signature):
        raise LifecycleValidationError(code, f"invalid signature on {signature_field}")


def _verify_lease(
    row: Mapping[str, Any],
    *,
    code_sha: str,
    expected_copy_fingerprint: str,
    context: FixtureExecutionContext,
    now: datetime,
) -> SessionWriteLeaseV1:
    lease = _parse(SessionWriteLeaseV1, json.loads(str(row["lease_json"])), "lease")
    _require(
        str(row["status"]) == "active", "lease_not_active", "write lease is not active"
    )
    _require(
        lease.scope == DispositionScope.COPY,
        "lease_scope_invalid",
        "lease is not Copy scoped",
    )
    _require(
        lease.accepted_code_sha == code_sha,
        "lease_code_sha_mismatch",
        "lease does not bind the running code SHA",
    )
    _require(
        lease.expected_lifecycle_fingerprint == expected_copy_fingerprint,
        "lease_state_hash_mismatch",
        "lease lifecycle fingerprint is stale",
    )
    _require(
        lease.activated_at <= now < lease.expires_at,
        "lease_expired_or_inactive",
        "lease is outside its active time window",
    )
    _require(
        str(row["lease_sha256"]) == lease.lease_sha256,
        "stored_lease_hash_mismatch",
        "stored lease hash does not match contract",
    )
    _require(
        str(row["lease_json_sha256"])
        == canonical_json_sha256(lease.canonical_payload()),
        "stored_lease_json_mismatch",
        "stored lease JSON digest does not match contract",
    )
    operations_json = canonical_json_text(
        [operation.canonical_payload() for operation in lease.allowed_operations]
    )
    _require(
        str(row["operations_json"]) == operations_json
        and str(row["operations_sha256"])
        == hashlib.sha256(operations_json.encode()).hexdigest(),
        "stored_lease_operations_mismatch",
        "stored lease method/path digest differs from the contract",
    )
    activated_at = lease.activated_at.isoformat().replace("+00:00", "Z")
    _require(
        str(row["activated_at"]) == activated_at,
        "stored_lease_activation_mismatch",
        "stored lease activation time differs from the signed contract",
    )
    _require(
        lease.signature.public_key == lease.issuer_public_key
        and lease.signature.signer == lease.issuer_identity,
        "lease_signer_binding_mismatch",
        "lease signature does not bind its issuer",
    )
    _require(
        lease.issuer_identity == context.operator_identity
        and lease.issuer_public_key == context.operator_public_key
        and lease.clerk_identity == context.clerk_identity
        and lease.source_backup_sha256 == context.source_backup_sha256,
        "lease_fixture_context_mismatch",
        "lease identity/key/source backup is outside the provisioned fixture context",
    )
    _verify_contract_message(lease, "signature", code="lease_signature_invalid")
    operations = {
        (operation.method, operation.path) for operation in lease.allowed_operations
    }
    _require(
        ACTIVATION_METHOD_PATH in operations,
        "lease_operation_denied",
        "lease does not authorize the exact rehearsal-disposition method/path",
    )
    return lease


def _verify_case(
    row: Mapping[str, Any],
    *,
    authority_artifact_id: str,
    lease: SessionWriteLeaseV1,
    context: FixtureExecutionContext,
    actual_case_head: str,
) -> tuple[ArtifactCaseV1, str]:
    case = _parse(ArtifactCaseV1, json.loads(str(row["case_json"])), "case")
    digest = canonical_json_sha256(case.canonical_payload())
    _require(
        str(row["case_sha256"]) == digest,
        "stored_case_hash_mismatch",
        "case digest mismatch",
    )
    _require(
        str(row["target_seed_id"]) == case.target_seed_id and int(row["round_no"]) == 1,
        "stored_case_columns_mismatch",
        "stored case relational columns differ from signed JSON",
    )
    _require(
        case.target_seed_id == authority_artifact_id,
        "case_target_mismatch",
        "case target drifted",
    )
    _require(
        case.lease_id == lease.lease_id,
        "case_lease_mismatch",
        "case binds another lease",
    )
    _require(
        case.expected_case_head == actual_case_head,
        "case_head_drift",
        "case head differs from independently derived evidence state",
    )
    _require(
        case.clerk_identity == lease.clerk_identity == context.clerk_identity
        and case.clerk_signature.signer == context.clerk_identity
        and case.clerk_signature.public_key == context.clerk_public_key,
        "case_clerk_context_mismatch",
        "case clerk identity/key is outside the provisioned fixture context",
    )
    try:
        signed_artifact = base64.b64decode(case.signed_artifact_b64, validate=True)
    except ValueError as exc:
        raise LifecycleValidationError(
            "case_signed_artifact_invalid", "case signed artifact is not base64"
        ) from exc
    _require(
        hashlib.sha256(signed_artifact).hexdigest()
        == case.signed_artifact_sha256
        == case.target_seed_packet_sha256
        == context.target_artifact_sha256,
        "case_signed_artifact_binding_mismatch",
        "case signed bytes do not bind the authorized target packet",
    )
    _verify_contract_message(case, "clerk_signature", code="case_signature_invalid")
    return case, digest


def _verify_ballots_and_verdict(
    conn: sqlite3.Connection,
    *,
    case: ArtifactCaseV1,
    case_sha256: str,
    authority_digest: str,
    authorized_evaluation_id: str,
    requested_effects: tuple[str, ...],
    verdict_id: str,
    context: FixtureExecutionContext,
) -> tuple[CouncilVerdictV1, str, list[dict[str, Any]]]:
    # This function is deliberately called only after Authorized<Copy> exists.
    ballot_rows = _fetchall_dicts(
        conn,
        """
        SELECT ballot_id, case_id, round_no, seat_id, ballot_source,
               credited_cluster, ballot_json, ballot_sha256
        FROM sab_artifact_ballots_v1
        WHERE case_id = ? AND round_no = 1
        ORDER BY ballot_id
        """,
        (case.case_id,),
    )
    _require(
        len(ballot_rows) == 9,
        "ballot_set_incomplete",
        "terminal fixture verdict requires nine ballots",
    )
    roster = {seat.seat_id: seat for seat in case.frozen_roster}
    trusted_seats = {
        seat_id: (signer, public_key)
        for seat_id, signer, public_key in context.seat_execution_identities
    }
    ballots: list[ArtifactBallotV1] = []
    for row in ballot_rows:
        ballot = _parse(ArtifactBallotV1, json.loads(str(row["ballot_json"])), "ballot")
        digest = canonical_json_sha256(ballot.canonical_payload())
        _require(
            digest == str(row["ballot_sha256"]),
            "stored_ballot_hash_mismatch",
            "ballot digest mismatch",
        )
        _require(
            str(row["ballot_id"]) == ballot.ballot_id
            and str(row["case_id"]) == ballot.case_id
            and int(row["round_no"]) == ballot.round_no
            and str(row["seat_id"]) == ballot.seat_id
            and str(row["ballot_source"]) == str(ballot.ballot_source)
            and str(row["credited_cluster"]) == ballot.credited_cluster,
            "stored_ballot_columns_mismatch",
            "stored ballot relational columns differ from signed JSON",
        )
        _require(
            ballot.case_id == case.case_id and ballot.case_sha256 == case_sha256,
            "ballot_case_mismatch",
            "ballot case binding mismatch",
        )
        _require(
            ballot.stage == "final",
            "ballot_not_final",
            "only final ballots may form a terminal verdict",
        )
        _require(
            ballot.ballot_source == "fixture_model",
            "ballot_source_not_fixture",
            "Build A activation requires fixture ballots",
        )
        seat = roster.get(ballot.seat_id)
        _require(
            seat is not None,
            "ballot_seat_unknown",
            "ballot seat is outside frozen roster",
        )
        _require(
            ballot.execution_signature.public_key == seat.execution_public_key,
            "ballot_execution_key_mismatch",
            "ballot signature key differs from frozen seat",
        )
        trusted_signer, trusted_key = trusted_seats.get(ballot.seat_id, (None, None))
        _require(
            ballot.execution_signature.signer == trusted_signer
            and ballot.execution_signature.public_key == trusted_key,
            "ballot_fixture_context_mismatch",
            "ballot signer/key is outside the provisioned fixture context",
        )
        _verify_contract_message(
            ballot, "execution_signature", code="ballot_signature_invalid"
        )
        _require(
            ballot.credited_cluster == seat.credited_cluster
            and ballot.requested_model == seat.requested_model
            and ballot.requested_route == seat.requested_route
            and ballot.served_provider == seat.served_provider
            and ballot.served_model == seat.served_model,
            "ballot_roster_drift",
            "ballot execution facts drifted from frozen roster",
        )
        ballots.append(ballot)
    _require(
        {ballot.seat_id for ballot in ballots} == set(roster),
        "ballot_roster_incomplete",
        "ballots do not cover the frozen roster",
    )

    verdict_row = _fetchone_dict(
        conn,
        """
        SELECT verdict_json, verdict_sha256, evaluation_id, ballot_set_sha256
        FROM sab_council_verdicts_v1 WHERE verdict_id = ?
        """,
        (verdict_id,),
    )
    _require(verdict_row is not None, "verdict_missing", "council verdict is missing")
    verdict = _parse(
        CouncilVerdictV1, json.loads(str(verdict_row["verdict_json"])), "verdict"
    )
    verdict_sha = canonical_json_sha256(verdict.canonical_payload())
    _require(
        str(verdict_row["verdict_sha256"]) == verdict_sha,
        "stored_verdict_hash_mismatch",
        "verdict digest mismatch",
    )
    _require(
        str(verdict_row["evaluation_id"]) == authorized_evaluation_id,
        "verdict_evaluation_mismatch",
        "verdict relational authority differs from the freshly evaluated value",
    )
    _require(
        verdict.case_id == case.case_id and verdict.case_sha256 == case_sha256,
        "verdict_case_mismatch",
        "verdict case binding mismatch",
    )
    _require(
        verdict.authority_digest == authority_digest,
        "verdict_authority_mismatch",
        "verdict binds another authority value",
    )
    _require(
        verdict.scope == DispositionScope.COPY,
        "verdict_scope_invalid",
        "verdict is not Copy scoped",
    )
    _require(
        verdict.evidence_provenance == "fixture_models",
        "verdict_provenance_invalid",
        "verdict is not fixture evidence",
    )
    _require(
        verdict.decision == "correct_and_supersede"
        and verdict.terminality == "terminal",
        "verdict_not_terminal_supersession",
        "verdict cannot create the synthetic supersession",
    )
    _require(
        tuple(verdict.requested_effects) == requested_effects,
        "verdict_effects_mismatch",
        "verdict effects differ from authority request",
    )

    raw = dict(Counter(ballot.decision for ballot in ballots))
    _require(
        verdict.raw_tally == raw,
        "verdict_raw_tally_mismatch",
        "raw tally is not re-derived from ballots",
    )
    _require(
        raw == {"correct_and_supersede": 9},
        "verdict_winner_mismatch",
        "correct_and_supersede must be the unique nine-ballot fixture winner",
    )
    sources = {str(ballot.ballot_source) for ballot in ballots}
    _require(
        set(verdict.ballot_sources) == sources,
        "verdict_sources_mismatch",
        "verdict ballot sources mismatch",
    )
    clusters: defaultdict[str, set[str]] = defaultdict(set)
    clean_clusters: defaultdict[str, set[str]] = defaultdict(set)
    smeared = set(verdict.smeared_seats)
    derived_smeared = {
        ballot.seat_id for ballot in ballots if ballot.correlation_smeared
    }
    _require(
        smeared == derived_smeared,
        "verdict_smear_set_mismatch",
        "verdict smeared seats are not derived from ballot transport evidence",
    )
    for ballot in ballots:
        clusters[ballot.decision].add(ballot.credited_cluster)
        if ballot.seat_id not in smeared:
            clean_clusters[ballot.decision].add(ballot.credited_cluster)
    expected_clusters = {
        key: tuple(sorted(value)) for key, value in sorted(clusters.items())
    }
    expected_clean = {key: len(value) for key, value in sorted(clean_clusters.items())}
    _require(
        verdict.credited_clusters_by_result == expected_clusters,
        "verdict_cluster_tally_mismatch",
        "credited clusters are not re-derived",
    )
    _require(
        verdict.clean_routing_tally == expected_clean,
        "verdict_clean_tally_mismatch",
        "clean tally is not re-derived",
    )
    _require(
        str(verdict_row["ballot_set_sha256"]) == compute_ballot_set_sha256(ballot_rows),
        "ballot_set_hash_mismatch",
        "verdict does not bind the exact immutable ballot set",
    )
    return verdict, verdict_sha, ballot_rows


def _verify_countersign(
    countersign: OperatorCountersignV1,
    *,
    lease: SessionWriteLeaseV1,
    case: ArtifactCaseV1,
    case_sha256: str,
    verdict: CouncilVerdictV1,
    verdict_sha256: str,
    authority_digest: str,
    expected_copy_fingerprint: str,
    actual_case_head: str,
    code_sha: str,
    exact_effect_payload: Mapping[str, Any],
    successor_envelope_sha256: str,
    context: FixtureExecutionContext,
    now: datetime,
) -> str:
    _require(
        countersign.signature.public_key == lease.issuer_public_key
        and countersign.signature.signer == lease.issuer_identity,
        "countersign_fixture_key_mismatch",
        "countersign is not made by the active fixture lease key",
    )
    _require(
        countersign.signature.signer == context.operator_identity
        and countersign.signature.public_key == context.operator_public_key,
        "countersign_fixture_context_mismatch",
        "countersign signer/key is outside the provisioned fixture context",
    )
    _verify_contract_message(
        countersign, "signature", code="countersign_signature_invalid"
    )
    _require(
        countersign.created_at <= now < countersign.expires_at,
        "countersign_expired_or_future",
        "countersign is outside its validity window",
    )
    _require(
        lease.activated_at <= countersign.created_at
        and countersign.expires_at <= lease.expires_at,
        "countersign_lease_window_mismatch",
        "countersign validity exceeds the lease",
    )
    _require(
        countersign.verdict_id == verdict.verdict_id
        and countersign.verdict_sha256 == verdict_sha256,
        "countersign_verdict_mismatch",
        "countersign verdict binding mismatch",
    )
    _require(
        countersign.case_id == case.case_id and countersign.case_sha256 == case_sha256,
        "countersign_case_mismatch",
        "countersign case binding mismatch",
    )
    _require(
        countersign.target_seed_id == case.target_seed_id,
        "countersign_target_mismatch",
        "countersign target mismatch",
    )
    _require(
        countersign.decision == verdict.decision,
        "countersign_decision_mismatch",
        "countersign decision mismatch",
    )
    _require(
        countersign.expected_seed_state == case.expected_seed_state,
        "countersign_state_mismatch",
        "countersign expected state mismatch",
    )
    _require(
        countersign.expected_case_head == case.expected_case_head == actual_case_head,
        "countersign_head_mismatch",
        "countersign case head mismatch",
    )
    _require(
        countersign.expected_lifecycle_fingerprint == expected_copy_fingerprint,
        "countersign_fingerprint_mismatch",
        "countersign copied-DB lifecycle fingerprint mismatch",
    )
    _require(
        countersign.write_lease_id == lease.lease_id
        and countersign.lease_sha256 == lease.lease_sha256,
        "countersign_lease_mismatch",
        "countersign lease binding mismatch",
    )
    _require(
        countersign.authority_digest == authority_digest,
        "countersign_authority_mismatch",
        "countersign authority binding mismatch",
    )
    _require(
        countersign.code_sha == code_sha,
        "countersign_code_sha_mismatch",
        "countersign code SHA mismatch",
    )
    _require(
        countersign.allowed_operations == lease.allowed_operations
        and countersign.allowed_operations_sha256 == lease.allowed_operations_sha256,
        "countersign_operations_mismatch",
        "countersign method/path inventory differs from lease",
    )
    _require(
        countersign.effect_payload == dict(exact_effect_payload),
        "countersign_effect_payload_mismatch",
        "countersign effect payload is not exact",
    )
    _require(
        countersign.successor_envelope_sha256 == successor_envelope_sha256,
        "countersign_successor_mismatch",
        "countersign successor envelope mismatch",
    )
    return canonical_json_sha256(countersign.canonical_payload())


def _signed_event_hash(
    record: Mapping[str, Any],
    *,
    prev_hash: str | None,
    payload_sha256: str,
    created_at: str,
) -> str:
    """Hash exactly the frozen C0 signed-event row material."""

    signature = _mapping(record["signature"], "signed_event.signature")
    return _event_hash_material(
        event_id=str(record["artifact_id"]),
        event_type="rehearsal_supersession_committed",
        signer=str(signature["signer"]),
        public_key=str(signature["public_key"]),
        prev_hash=prev_hash,
        payload_sha256=payload_sha256,
        signature=str(signature["signature"]),
        created_at=created_at,
    )


def _persist_signature_evidence(
    conn: sqlite3.Connection,
    records: Sequence[Mapping[str, Any]],
    *,
    lifecycle_event_id: str,
    created_at: str,
) -> tuple[int, str | None]:
    """Persist the exact independently replayable signature bundle."""

    head_row = conn.execute(
        """
        SELECT sequence_no, record_hash
        FROM sab_first_verdict_signature_evidence_v1
        ORDER BY sequence_no DESC LIMIT 1
        """
    ).fetchone()
    sequence_no = 0 if head_row is None else int(head_row[0])
    previous_hash = None if head_row is None else str(head_row[1])
    inserted = 0

    for record in records:
        artifact_type = str(record["artifact_type"])
        artifact_id = str(record["artifact_id"])
        payload = _mapping(record["signed_payload"], "signed_payload")
        signature = _mapping(record["signature"], "signature")
        canonicalization = str(signature["canonicalization"])
        if canonicalization == "json-sort-keys-compact-v1":
            payload_json = json.dumps(
                dict(payload),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        elif canonicalization == "canonical_json_v1":
            payload_json = canonical_json_bytes(dict(payload)).decode("utf-8")
        else:
            raise LifecycleValidationError(
                "canonicalization_unsupported",
                "signature evidence canonicalization is unsupported",
            )
        payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
        expected_values = (
            str(signature["signer"]),
            str(signature["public_key"]),
            payload_json,
            payload_sha256,
            canonicalization,
            str(signature["signature"]),
        )
        existing = conn.execute(
            """
            SELECT signer, public_key, payload_json, payload_sha256,
                   canonicalization, signature, record_hash
            FROM sab_first_verdict_signature_evidence_v1
            WHERE artifact_type = ? AND artifact_id = ?
            """,
            (artifact_type, artifact_id),
        ).fetchone()
        if existing is not None:
            if tuple(str(value) for value in existing[:6]) != expected_values:
                raise LifecycleConflict(
                    "signature_evidence_identity_conflict",
                    "persisted signature identity has conflicting content",
                )
            previous_hash = str(existing[6])
            continue

        sequence_no += 1
        identity_material = {
            "artifact_type": artifact_type,
            "artifact_id": artifact_id,
            "payload_sha256": payload_sha256,
            "signature": str(signature["signature"]),
        }
        record_id = "sab_signature_" + canonical_json_sha256(identity_material)[:40]
        row = {
            "sequence_no": sequence_no,
            "record_id": record_id,
            "artifact_type": artifact_type,
            "artifact_id": artifact_id,
            "lifecycle_event_id": lifecycle_event_id,
            "signer": str(signature["signer"]),
            "public_key": str(signature["public_key"]),
            "prev_hash": previous_hash,
            "payload_sha256": payload_sha256,
            "canonicalization": canonicalization,
            "signature": str(signature["signature"]),
            "created_at": created_at,
        }
        record_hash = signature_evidence_record_hash(row)
        conn.execute(
            """
            INSERT INTO sab_first_verdict_signature_evidence_v1
                (sequence_no, record_id, artifact_type, artifact_id,
                 lifecycle_event_id, signer, public_key, prev_hash, payload_json,
                 payload_sha256, canonicalization, signature, record_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sequence_no,
                record_id,
                artifact_type,
                artifact_id,
                lifecycle_event_id,
                row["signer"],
                row["public_key"],
                previous_hash,
                payload_json,
                payload_sha256,
                canonicalization,
                row["signature"],
                record_hash,
                created_at,
            ),
        )
        previous_hash = record_hash
        inserted += 1
    return inserted, previous_hash


def _invoke_failure(hook: Callable[[str], None] | None, boundary: str) -> None:
    if hook is not None:
        hook(boundary)


def apply_rehearsal_lifecycle(
    conn: sqlite3.Connection,
    request: Mapping[str, Any],
    *,
    fixture_context: FixtureExecutionContext,
    now: datetime | None = None,
    failure_hook: Callable[[str], None] | None = None,
    expected_verdict_id: str | None = None,
    expected_write_lease_id: str | None = None,
) -> dict[str, Any]:
    """Atomically apply one authorized synthetic supersession on a copied DB.

    Required request members are ``idempotency_key``, ``code_sha``,
    ``artifact_id``, ``artifact_sha256``, ``evaluated_state_hash``,
    ``requested_effects``, ``signed_policy``, ``countersign``, ``disposition``,
    ``successor_artifact``, ``lineage_edge_id``, ``supersession``, and
    ``signed_event``.  Exact retry returns byte-equivalent response content.
    """

    # This must precede every lifecycle read or write gate. Lower-level storage
    # tests may use disposable/in-memory fixtures, but an effective Copy-scoped
    # disposition can only be constructed on a receipt-backed copied database.
    require_copy_or_fixture_connection(conn)
    if not isinstance(fixture_context, FixtureExecutionContext):
        raise LifecycleValidationError(
            "fixture_context_required",
            "activation requires an out-of-band FixtureExecutionContext object",
        )
    copy_attestation = getattr(conn, "sab_copy_attestation", None)
    _require(
        isinstance(copy_attestation, CopyDatabaseAttestation)
        and copy_attestation.proof_class == "copied_live_db_rehearsal",
        "copied_live_attestation_required",
        "effective rehearsal requires a receipt-backed copied-live attestation",
    )
    copy_attestation.validate(require_pristine_backup=False)
    if not (
        copy_attestation.source_backup_sha256 == fixture_context.source_backup_sha256
        and copy_attestation.expected_lifecycle_fingerprint
        == fixture_context.copied_lifecycle_fingerprint
    ):
        raise LifecycleAuthorityDenied(
            "fixture_copy_attestation_mismatch",
            "fixture context does not bind the active copied-database attestation",
        )
    if conn.in_transaction:
        raise LifecycleConflict(
            "caller_transaction_active",
            "lifecycle requires ownership of its single BEGIN IMMEDIATE transaction",
        )
    try:
        envelope = RehearsalLifecycleRequestV1.model_validate(request)
    except ValidationError as exc:
        raise LifecycleValidationError(
            "request_contract_invalid", "invalid lifecycle request contract"
        ) from exc
    req = envelope.canonical_payload()
    idempotency_key = str(req["idempotency_key"]).strip()
    code_sha = str(req["code_sha"]).strip().lower()
    artifact_id = str(req["artifact_id"]).strip()
    artifact_sha256 = str(req["artifact_sha256"]).strip().lower()
    evaluated_state_hash = str(req["evaluated_state_hash"]).strip().lower()
    requested_effects = tuple(req["requested_effects"])
    _require(
        bool(idempotency_key), "idempotency_key_missing", "idempotency key is blank"
    )
    _require(
        bool(re.fullmatch(r"[0-9a-f]{40}", code_sha)),
        "code_sha_invalid",
        "code SHA must be 40 lowercase hex characters",
    )
    _require(
        bool(re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)),
        "artifact_sha_invalid",
        "artifact hash must be lowercase SHA-256",
    )
    _require(
        bool(re.fullmatch(r"[0-9a-f]{64}", evaluated_state_hash)),
        "state_hash_invalid",
        "state hash must be lowercase SHA-256",
    )
    _require(
        artifact_id == fixture_context.target_artifact_id
        and artifact_sha256 == fixture_context.target_artifact_sha256
        and evaluated_state_hash == fixture_context.synthetic_state_hash
        and code_sha == fixture_context.code_sha,
        "request_fixture_context_mismatch",
        "request target/state/code is outside the provisioned fixture context",
    )
    request_sha256 = canonical_json_sha256(req)
    current = _utc(now)

    try:
        conn.execute("PRAGMA foreign_keys = ON")
        if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise LifecycleConflict(
                "foreign_keys_disabled",
                "SQLite foreign-key enforcement is required before activation",
            )
        conn.execute("BEGIN IMMEDIATE")

        try:
            replay = idempotency_lookup(
                conn,
                operation=ACTIVATION_OPERATION,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
            )
        except ImmutableConflict as exc:
            raise LifecycleConflict("idempotency_content_conflict", str(exc)) from exc
        if replay is not None:
            if replay.get("fixture_context_sha256") != fixture_context.digest:
                raise LifecycleAuthorityDenied(
                    "idempotency_context_mismatch",
                    "stored idempotent receipt belongs to another fixture context",
                )
            replay_artifacts = replay.get("artifacts")
            if not isinstance(replay_artifacts, Mapping):
                raise LifecycleConflict(
                    "idempotency_receipt_corrupt",
                    "stored idempotent receipt has no artifact bindings",
                )
            replay_verdict = replay_artifacts.get("verdict")
            replay_lease = replay_artifacts.get("lease")
            if (
                expected_verdict_id is not None
                and (
                    not isinstance(replay_verdict, Mapping)
                    or replay_verdict.get("id") != expected_verdict_id
                )
            ) or (
                expected_write_lease_id is not None
                and (
                    not isinstance(replay_lease, Mapping)
                    or replay_lease.get("id") != expected_write_lease_id
                )
            ):
                raise LifecycleConflict(
                    "idempotency_route_binding_mismatch",
                    "stored idempotent receipt belongs to another route or lease",
                )
            replay_row = _fetchone_dict(
                conn,
                """
                SELECT response_json, response_sha256
                FROM sab_first_verdict_idempotency_v1
                WHERE operation = ? AND idempotency_key = ?
                """,
                (ACTIVATION_OPERATION, idempotency_key),
            )
            replay_json = canonical_json_text(replay)
            if (
                replay_row is None
                or str(replay_row["response_json"]) != replay_json
                or str(replay_row["response_sha256"])
                != hashlib.sha256(replay_json.encode()).hexdigest()
            ):
                raise LifecycleConflict(
                    "idempotency_receipt_corrupt",
                    "stored idempotency response digest does not verify",
                )
            conn.commit()
            return replay

        actual_synthetic_state = rehearsal_state_fingerprint(conn)
        actual_copy_fingerprint = copied_database_lifecycle_fingerprint(conn)["sha256"]
        actual_case_head = case_scope_head(conn, artifact_id)
        master_vision_observation = None
        if artifact_id == MASTER_VISION_SEED_ID:
            try:
                master_vision_observation = observe_master_vision_state(conn)
            except EvidenceValidationError:
                master_vision_observation = None
        expected_authority_state = (
            master_vision_observation.observed_state_hash
            if master_vision_observation is not None
            else actual_synthetic_state
        )
        _require(
            expected_authority_state == fixture_context.synthetic_state_hash
            and actual_copy_fingerprint == fixture_context.copied_lifecycle_fingerprint
            and actual_case_head == fixture_context.expected_case_head,
            "fixture_state_witness_drift",
            "independently derived fixture state differs from provisioned context",
        )

        # Gate 1.  This deliberately precedes case, ballot, verdict, and effect
        # parsing.  A Master Vision request therefore exits AdvisoryOnly before
        # any lifecycle object can be constructed or mutated.
        authority = evaluate_disposition_authority(
            artifact_id=artifact_id,
            artifact_sha256=artifact_sha256,
            requested_scope=DispositionScope.COPY,
            requested_effects=requested_effects,
            evaluated_state_hash=evaluated_state_hash,
            signed_policy=req["signed_policy"],
            trusted_policy_issuer=TrustedPolicyIssuerV1(
                issuer_identity=fixture_context.policy_issuer_identity,
                issuer_public_key=fixture_context.policy_issuer_public_key,
                source_fixture_id=fixture_context.source_fixture_id,
                copied_database_id=fixture_context.copied_database_id,
                authority_basis="founder_bootstrap_self_declared",
            ),
            master_vision_observation=master_vision_observation,
            now=current,
        )
        try:
            authorized = require_rehearsal_authority(
                authority, effects=requested_effects
            )
        except Exception as exc:
            raise LifecycleAuthorityDenied(
                f"authority_{str(authority.result).lower()}",
                f"{authority.result} cannot produce a rehearsal lifecycle effect",
            ) from exc
        policy = _parse(
            SignedDispositionPolicyV1, req["signed_policy"], "signed_policy"
        )
        _require(
            policy.test_issuer and not policy.live_eligible,
            "fixture_policy_required",
            "Build A requires a test-issued non-live policy",
        )
        _require(
            bool(policy.source_fixture_id and policy.copied_database_id),
            "fixture_evidence_missing",
            "policy must bind source fixture and copied database",
        )
        _require(
            tuple(authorized.allowed_effects) == FROZEN_EFFECTS
            and tuple(policy.permitted_effects) == FROZEN_EFFECTS,
            "authority_effect_grant_not_exact",
            "fixture authority may grant only the two frozen effects",
        )
        _require(
            tuple(policy.preconditions)
            == ("challenge_state=pending", "seed_state=challenged"),
            "policy_preconditions_not_exact",
            "fixture policy preconditions are not the frozen state predicates",
        )
        _require(
            policy.issued_at <= current < policy.expires_at,
            "policy_time_window_invalid",
            "fixture policy is outside its signed time window",
        )
        _require(
            policy.source_fixture_id == fixture_context.source_fixture_id
            and policy.copied_database_id == fixture_context.copied_database_id
            and policy.issuer == fixture_context.policy_issuer_identity
            and policy.signature.signer == fixture_context.policy_issuer_identity
            and policy.signature.public_key == fixture_context.policy_issuer_public_key,
            "policy_fixture_context_mismatch",
            "policy issuer/key/provenance is outside the provisioned fixture context",
        )

        # The evaluated authority must already be stored as an immutable input;
        # activation never modifies the authority table.
        authority_row = _fetchone_dict(
            conn,
            """
            SELECT case_id, result, scope, evaluated_state_hash,
                   authority_json, authority_sha256
            FROM sab_disposition_authority_v1 WHERE evaluation_id = ?
            """,
            (authorized.evaluation_id,),
        )
        _require(
            authority_row is not None,
            "authority_record_missing",
            "evaluated authority is not stored",
        )
        authority_payload = authorized.canonical_payload()
        authority_digest = canonical_json_sha256(authority_payload)
        _require(
            json.loads(str(authority_row["authority_json"])) == authority_payload
            and str(authority_row["authority_sha256"]) == authority_digest
            and str(authority_row["result"]) == "Authorized"
            and str(authority_row["scope"]) == "Copy"
            and str(authority_row["evaluated_state_hash"]) == evaluated_state_hash,
            "authority_record_mismatch",
            "stored authority differs from the freshly evaluated typed value",
        )

        case_row = _fetchone_dict(
            conn,
            """
            SELECT case_id, target_seed_id, round_no, case_json, case_sha256
            FROM sab_artifact_cases_v1 WHERE case_id = ?
            """,
            (str(authority_row["case_id"]),),
        )
        _require(case_row is not None, "case_missing", "authority case is missing")
        raw_case = _parse(
            ArtifactCaseV1, json.loads(str(case_row["case_json"])), "case"
        )

        lease_row = _fetchone_dict(
            conn,
            """
            SELECT lease_json, lease_json_sha256, lease_sha256, status, activated_at,
                   operations_json, operations_sha256
            FROM sab_session_write_leases_v1 WHERE lease_id = ?
            """,
            (raw_case.lease_id,),
        )
        _require(lease_row is not None, "lease_missing", "case write lease is missing")
        lease = _verify_lease(
            lease_row,
            code_sha=code_sha,
            expected_copy_fingerprint=actual_copy_fingerprint,
            context=fixture_context,
            now=current,
        )
        _require(
            expected_write_lease_id is None
            or lease.lease_id == expected_write_lease_id,
            "route_write_lease_mismatch",
            "active fixture lease differs from the HTTP write-lease binding",
        )
        case, case_sha256 = _verify_case(
            case_row,
            authority_artifact_id=artifact_id,
            lease=lease,
            context=fixture_context,
            actual_case_head=actual_case_head,
        )

        target_row = _fetchone_dict(
            conn,
            """
            SELECT artifact_id, state, artifact_json, artifact_sha256, live_eligible
            FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?
            """,
            (artifact_id,),
        )
        _require(
            target_row is not None,
            "target_artifact_missing",
            "synthetic target artifact is missing",
        )
        target = json.loads(str(target_row["artifact_json"]))
        _require(
            canonical_json_text(target) == str(target_row["artifact_json"]),
            "target_json_noncanonical",
            "target artifact JSON is noncanonical",
        )
        _require(
            str(target_row["artifact_sha256"])
            == hashlib.sha256(str(target_row["artifact_json"]).encode()).hexdigest(),
            "target_artifact_hash_mismatch",
            "target row hash does not bind its canonical JSON",
        )
        _require(
            str(target.get("artifact_id")) == artifact_id,
            "target_artifact_id_mismatch",
            "target JSON identity differs from its row identity",
        )
        _require(
            str(target_row["state"])
            == case.expected_seed_state
            == str(target.get("state")),
            "target_state_drift",
            "target state differs from frozen case",
        )
        _require(
            int(target_row["live_eligible"]) == 0
            and target.get("live_eligible") is False,
            "target_live_eligible",
            "synthetic target must be non-live",
        )
        _require(
            str(target.get("packet_sha256"))
            == artifact_sha256
            == case.target_seed_packet_sha256,
            "target_packet_hash_mismatch",
            "target packet hash differs from authority/case",
        )
        _require(
            canonical_json_sha256(target.get("packet")) == artifact_sha256
            and canonical_json_bytes(target.get("packet"))
            == base64.b64decode(case.signed_artifact_b64, validate=True),
            "target_signed_bytes_mismatch",
            "target packet differs from the exact signed case bytes",
        )
        _require(
            target.get("source_fixture_id") == fixture_context.source_fixture_id
            and target.get("copied_database_id") == fixture_context.copied_database_id
            and target.get("standing_effect") == "none",
            "target_fixture_context_mismatch",
            "target provenance/standing is outside the provisioned fixture context",
        )
        actual_before = actual_synthetic_state
        _require(
            actual_before == evaluated_state_hash,
            "synthetic_state_hash_drift",
            "current synthetic state hash drifted",
        )

        countersign_raw = _mapping(req["countersign"], "countersign")
        verdict_id = str(countersign_raw.get("verdict_id") or "")
        verdict, verdict_sha256, ballot_rows = _verify_ballots_and_verdict(
            conn,
            case=case,
            case_sha256=case_sha256,
            authority_digest=authority_digest,
            authorized_evaluation_id=authorized.evaluation_id,
            requested_effects=requested_effects,
            verdict_id=verdict_id,
            context=fixture_context,
        )
        _require(
            expected_verdict_id is None or verdict.verdict_id == expected_verdict_id,
            "route_verdict_mismatch",
            "verified verdict differs from the route binding",
        )

        supersession = _parse(SeedSupersessionV1, req["supersession"], "supersession")
        _verify_contract_message(
            supersession, "claimant_signature", code="supersession_signature_invalid"
        )
        _require(
            supersession.claimant_signature.signer
            == supersession.claimant_identity
            == fixture_context.claimant_identity
            and supersession.claimant_signature.public_key
            == fixture_context.claimant_public_key,
            "supersession_claimant_mismatch",
            "supersession signature does not bind the provisioned fixture claimant",
        )
        _require(
            supersession.predecessor_seed_id == artifact_id
            and supersession.predecessor_packet_sha256 == artifact_sha256,
            "supersession_predecessor_mismatch",
            "supersession predecessor binding mismatch",
        )
        _require(
            supersession.authority_lease_id == lease.lease_id,
            "supersession_lease_mismatch",
            "supersession authority lease mismatch",
        )
        _require(
            lease.activated_at <= supersession.created_at <= current < lease.expires_at,
            "supersession_time_window_invalid",
            "supersession was not signed within the active fixture lease",
        )
        supersession_sha256 = canonical_json_sha256(supersession.canonical_payload())

        successor_model = _parse(
            SyntheticSuccessorArtifactV1,
            req["successor_artifact"],
            "successor_artifact",
        )
        successor = successor_model.canonical_payload()
        successor_id = successor_model.artifact_id
        _require(
            successor_id == supersession.successor_seed_id,
            "successor_id_mismatch",
            "successor artifact ID mismatch",
        )
        _require(
            successor.get("state") == "pending",
            "successor_state_invalid",
            "successor must start pending",
        )
        _require(
            successor.get("live_eligible") is False
            and successor.get("standing_effect") == "none",
            "successor_effect_invalid",
            "successor must be non-live and standing-neutral",
        )
        _require(
            str(successor.get("packet_sha256")) == supersession.successor_packet_sha256,
            "successor_packet_hash_mismatch",
            "successor packet hash mismatch",
        )
        _require(
            str(successor.get("claimant_identity")) == supersession.claimant_identity,
            "successor_claimant_mismatch",
            "successor claimant mismatch",
        )
        _require(
            str(successor.get("source_fixture_id")) == policy.source_fixture_id
            and str(successor.get("copied_database_id")) == policy.copied_database_id,
            "successor_fixture_provenance_mismatch",
            "successor fixture provenance mismatch",
        )
        _require(
            _fetchone_dict(
                conn,
                "SELECT artifact_id FROM sab_rehearsal_artifacts_v1 WHERE artifact_id = ?",
                (successor_id,),
            )
            is None,
            "successor_identity_conflict",
            "successor artifact already exists",
        )
        _require(
            isinstance(successor.get("packet"), Mapping)
            and canonical_json_sha256(successor["packet"])
            == supersession.successor_packet_sha256,
            "successor_packet_content_mismatch",
            "successor packet hash does not bind canonical packet bytes",
        )
        successor_packet_signature = _parse(
            ContractSignatureV1,
            successor.get("packet_signature"),
            "successor_packet_signature",
        )
        _require(
            successor_packet_signature.signer == fixture_context.claimant_identity
            and successor_packet_signature.public_key
            == fixture_context.claimant_public_key
            and verify_contract_signature(
                canonical_json_bytes(successor["packet"]), successor_packet_signature
            ),
            "successor_packet_signature_invalid",
            "successor packet is not signed by the provisioned fixture claimant",
        )
        successor_envelope_sha256 = canonical_json_sha256(successor)

        disposition_raw = _mapping(req["disposition"], "disposition")
        disposition_id = str(disposition_raw.get("disposition_id") or "")
        transitioned_target = _transitioned_target(
            target,
            case=case,
            successor_id=successor_id,
            disposition_id=disposition_id,
        )
        after_state_hash = _simulated_after_fingerprint(
            conn,
            target_id=artifact_id,
            transitioned_target=transitioned_target,
            successor=successor,
        )

        exact_effect_payload = build_effect_payload(
            effects=requested_effects,
            disposition_id=disposition_id,
            target_artifact_id=artifact_id,
            successor_artifact=successor,
            supersession_sha256=supersession_sha256,
        )
        countersign = _parse(OperatorCountersignV1, countersign_raw, "countersign")
        countersign_sha256 = _verify_countersign(
            countersign,
            lease=lease,
            case=case,
            case_sha256=case_sha256,
            verdict=verdict,
            verdict_sha256=verdict_sha256,
            authority_digest=authority_digest,
            code_sha=code_sha,
            exact_effect_payload=exact_effect_payload,
            successor_envelope_sha256=successor_envelope_sha256,
            actual_case_head=actual_case_head,
            expected_copy_fingerprint=actual_copy_fingerprint,
            context=fixture_context,
            now=current,
        )

        disposition = _parse(RehearsalDispositionV1, disposition_raw, "disposition")
        _require(
            disposition.verdict_id == verdict.verdict_id
            and disposition.verdict_sha256 == verdict_sha256,
            "disposition_verdict_mismatch",
            "disposition verdict binding mismatch",
        )
        _require(
            disposition.case_id == case.case_id
            and disposition.case_sha256 == case_sha256,
            "disposition_case_mismatch",
            "disposition case binding mismatch",
        )
        _require(
            disposition.authority.canonical_payload() == authority_payload,
            "disposition_authority_mismatch",
            "disposition contains another authority value",
        )
        _require(
            disposition.countersign_id == countersign.countersign_id
            and disposition.countersign_sha256 == countersign_sha256,
            "disposition_countersign_mismatch",
            "disposition countersign binding mismatch",
        )
        _require(
            tuple(disposition.effects) == requested_effects,
            "disposition_effects_mismatch",
            "disposition effects mismatch",
        )
        _require(
            disposition.source_fixture_id == policy.source_fixture_id
            and disposition.copied_database_id == policy.copied_database_id,
            "disposition_fixture_provenance_mismatch",
            "disposition fixture provenance mismatch",
        )
        _require(
            disposition.before_state_hash == actual_before
            and disposition.after_state_hash == after_state_hash,
            "disposition_state_hash_mismatch",
            "disposition before/after state hash mismatch",
        )
        _require(
            abs(disposition.applied_at - current) <= MAX_ACTIVATION_CLOCK_SKEW,
            "disposition_time_mismatch",
            "disposition applied_at is outside the server-observed activation window",
        )
        disposition_sha256 = canonical_json_sha256(disposition.canonical_payload())

        lineage_edge_id = str(req["lineage_edge_id"]).strip()
        _require(
            bool(lineage_edge_id), "lineage_edge_id_missing", "lineage edge ID is blank"
        )
        lineage_payload = {
            "edge_id": lineage_edge_id,
            **supersession.canonical_payload(),
            "disposition_id": disposition.disposition_id,
            "disposition_sha256": disposition_sha256,
        }
        lineage_sha256 = canonical_json_sha256(lineage_payload)

        signed_event = _parse(
            SignedLifecycleEventV1,
            req["signed_event"],
            "signed_event",
        ).canonical_payload()
        event_id = str(signed_event.get("artifact_id") or "")
        _require(
            signed_event.get("artifact_type") == "lifecycle_event",
            "event_type_invalid",
            "signed event artifact_type must be lifecycle_event",
        )
        _require(
            signed_event.get("signer_kind") == "fixture_ephemeral",
            "event_signer_kind_invalid",
            "event must use fixture_ephemeral signer kind",
        )
        prev_hash = new_signed_event_chain_head(conn)
        expected_event_payload = build_lifecycle_event_payload(
            event_id=event_id,
            case_id=case.case_id,
            verdict_id=verdict.verdict_id,
            disposition_id=disposition.disposition_id,
            lineage_edge_id=lineage_edge_id,
            target_artifact_id=artifact_id,
            successor_artifact_id=successor_id,
            authority_digest=authority_digest,
            countersign_sha256=countersign_sha256,
            disposition_sha256=disposition_sha256,
            lineage_sha256=lineage_sha256,
            before_state_hash=actual_before,
            after_state_hash=after_state_hash,
            prev_hash=prev_hash,
        )
        _require(
            signed_event.get("signed_payload") == expected_event_payload,
            "event_payload_mismatch",
            "signed lifecycle event payload is not exact",
        )

        event_signature = _mapping(
            signed_event.get("signature"), "signed_event.signature"
        )
        _require(
            event_signature.get("signer") == fixture_context.event_signer_identity
            and event_signature.get("public_key")
            == fixture_context.event_signer_public_key,
            "event_fixture_context_mismatch",
            "event signer/key is outside the provisioned fixture context",
        )

        replay_records: list[dict[str, Any]] = [
            {
                "artifact_type": "policy",
                "artifact_id": policy.policy_id,
                "signed_payload": policy.canonical_payload(exclude={"signature"}),
                "signature": policy.signature.canonical_payload(),
            },
            {
                "artifact_type": "lease",
                "artifact_id": lease.lease_id,
                "signed_payload": lease.canonical_payload(exclude={"signature"}),
                "signature": lease.signature.canonical_payload(),
            },
            {
                "artifact_type": "case",
                "artifact_id": case.case_id,
                "signed_payload": case.canonical_payload(exclude={"clerk_signature"}),
                "signature": case.clerk_signature.canonical_payload(),
            },
        ]
        for ballot_row in ballot_rows:
            ballot = ArtifactBallotV1.model_validate(
                json.loads(str(ballot_row["ballot_json"]))
            )
            replay_records.append(
                {
                    "artifact_type": "ballot",
                    "artifact_id": ballot.ballot_id,
                    "signed_payload": ballot.canonical_payload(
                        exclude={"execution_signature"}
                    ),
                    "signature": ballot.execution_signature.canonical_payload(),
                }
            )
        replay_records.extend(
            [
                {
                    "artifact_type": "countersign",
                    "artifact_id": countersign.countersign_id,
                    "signed_payload": countersign.canonical_payload(
                        exclude={"signature"}
                    ),
                    "signature": countersign.signature.canonical_payload(),
                },
                {
                    "artifact_type": "lineage",
                    "artifact_id": lineage_edge_id,
                    "signed_payload": supersession.canonical_payload(
                        exclude={"claimant_signature"}
                    ),
                    "signature": supersession.claimant_signature.canonical_payload(),
                },
                {
                    "artifact_type": "successor",
                    "artifact_id": successor_id,
                    "signed_payload": successor["packet"],
                    "signature": successor_packet_signature.canonical_payload(),
                },
                signed_event,
            ]
        )
        try:
            replay_proof = verify_new_signature_suffix(
                replay_records,
                required_artifact_types=(
                    "policy",
                    "lease",
                    "case",
                    "ballot",
                    "countersign",
                    "lineage",
                    "successor",
                    "lifecycle_event",
                ),
            )
        except ReplayValidationError as exc:
            raise LifecycleValidationError(exc.code, str(exc)) from exc

        invariants_before = _invariant_snapshot(
            conn,
            target_id=artifact_id,
            successor_id=successor_id,
            countersign_id=countersign.countersign_id,
            disposition_id=disposition.disposition_id,
            lineage_edge_id=lineage_edge_id,
            event_id=event_id,
            idempotency_key=idempotency_key,
        )

        created_at = current.isoformat().replace("+00:00", "Z")
        countersign_json = canonical_json_text(countersign.canonical_payload())
        conn.execute(
            """
            INSERT INTO sab_operator_countersigns_v1
                (countersign_id, verdict_id, write_lease_id, countersign_json,
                 countersign_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                countersign.countersign_id,
                verdict.verdict_id,
                lease.lease_id,
                countersign_json,
                countersign_sha256,
                created_at,
            ),
        )
        _invoke_failure(failure_hook, "countersign_insert")

        transitioned_json = canonical_json_text(transitioned_target)
        transitioned_sha = hashlib.sha256(transitioned_json.encode()).hexdigest()
        cursor = conn.execute(
            """
            UPDATE sab_rehearsal_artifacts_v1
            SET state = 'superseded', artifact_json = ?, artifact_sha256 = ?,
                live_eligible = 0, updated_at = ?
            WHERE artifact_id = ? AND state = ? AND artifact_sha256 = ?
            """,
            (
                transitioned_json,
                transitioned_sha,
                created_at,
                artifact_id,
                case.expected_seed_state,
                str(target_row["artifact_sha256"]),
            ),
        )
        _require(
            cursor.rowcount == 1,
            "target_compare_and_swap_failed",
            "target changed during activation",
        )
        _invoke_failure(failure_hook, "target_transition")

        successor_json = canonical_json_text(successor)
        successor_sha = hashlib.sha256(successor_json.encode()).hexdigest()
        conn.execute(
            """
            INSERT INTO sab_rehearsal_artifacts_v1
                (artifact_id, state, artifact_json, artifact_sha256,
                 live_eligible, created_at, updated_at)
            VALUES (?, 'pending', ?, ?, 0, ?, ?)
            """,
            (successor_id, successor_json, successor_sha, created_at, created_at),
        )
        _invoke_failure(failure_hook, "successor_insert")

        disposition_json = canonical_json_text(disposition.canonical_payload())
        conn.execute(
            """
            INSERT INTO sab_rehearsal_dispositions_v1
                (disposition_id, verdict_id, countersign_id, evaluation_id,
                 target_artifact_id, successor_artifact_id, scope,
                 disposition_json, disposition_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'Copy', ?, ?, ?)
            """,
            (
                disposition.disposition_id,
                verdict.verdict_id,
                countersign.countersign_id,
                authorized.evaluation_id,
                artifact_id,
                successor_id,
                disposition_json,
                disposition_sha256,
                created_at,
            ),
        )
        _invoke_failure(failure_hook, "disposition_insert")

        lineage_json = canonical_json_text(lineage_payload)
        conn.execute(
            """
            INSERT INTO sab_seed_lineage_edges_v1
                (edge_id, predecessor_seed_id, successor_seed_id, disposition_id,
                 edge_json, edge_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                lineage_edge_id,
                artifact_id,
                successor_id,
                disposition.disposition_id,
                lineage_json,
                lineage_sha256,
                created_at,
            ),
        )
        _invoke_failure(failure_hook, "lineage_insert")

        persisted_signature_count, persisted_signature_head = (
            _persist_signature_evidence(
                conn,
                replay_records,
                lifecycle_event_id=event_id,
                created_at=created_at,
            )
        )
        _invoke_failure(failure_hook, "signature_evidence_insert")

        event_signature = _mapping(signed_event["signature"], "signed_event.signature")
        event_payload_json = canonical_json_text(expected_event_payload)
        event_payload_sha = hashlib.sha256(event_payload_json.encode()).hexdigest()
        event_hash = _signed_event_hash(
            signed_event,
            prev_hash=prev_hash,
            payload_sha256=event_payload_sha,
            created_at=created_at,
        )
        conn.execute(
            """
            INSERT INTO sab_first_verdict_signed_events_v1
                (event_id, event_type, signer, public_key, prev_hash, payload_json,
                 payload_sha256, signature, event_hash, created_at)
            VALUES (?, 'rehearsal_supersession_committed', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                str(event_signature["signer"]),
                str(event_signature["public_key"]),
                prev_hash,
                event_payload_json,
                event_payload_sha,
                str(event_signature["signature"]),
                event_hash,
                created_at,
            ),
        )
        _invoke_failure(failure_hook, "signed_event_insert")

        _require(
            rehearsal_state_fingerprint(conn) == after_state_hash,
            "post_state_hash_mismatch",
            "written lifecycle state differs from simulated hash",
        )
        try:
            signed_event_table_replay = verify_new_signature_table(
                conn,
                required_event_types=("rehearsal_supersession_committed",),
            )
            persisted_signature_replay = verify_signature_evidence_table(
                conn,
                required_artifact_types=(
                    "policy",
                    "lease",
                    "case",
                    "ballot",
                    "countersign",
                    "lineage",
                    "successor",
                    "lifecycle_event",
                ),
            )
        except ReplayValidationError as exc:
            raise LifecycleValidationError(exc.code, str(exc)) from exc
        _require(
            signed_event_table_replay["head_event_hash"] == event_hash,
            "post_event_chain_mismatch",
            "written signed event does not form the unique verified suffix head",
        )
        _require(
            persisted_signature_replay["head_record_hash"] == persisted_signature_head
            and persisted_signature_replay["signature_count"] == len(replay_records),
            "persisted_signature_replay_mismatch",
            "persisted signature bundle does not replay exactly",
        )
        _require(
            copied_database_lifecycle_fingerprint(conn)["sha256"]
            == actual_copy_fingerprint,
            "copied_lifecycle_changed",
            "copy-only rehearsal changed the legacy/source lifecycle fingerprint",
        )
        invariants_after = _invariant_snapshot(
            conn,
            target_id=artifact_id,
            successor_id=successor_id,
            countersign_id=countersign.countersign_id,
            disposition_id=disposition.disposition_id,
            lineage_edge_id=lineage_edge_id,
            event_id=event_id,
            idempotency_key=idempotency_key,
        )
        _require(
            invariants_after == invariants_before,
            "unrelated_state_changed",
            "standing, identity, authority, or unrelated rows changed",
        )

        receipt_without_hash: dict[str, Any] = {
            "schema_version": "sab.rehearsal_lifecycle_receipt.v1",
            "proof_class": "copied_live_db_rehearsal",
            "operation": ACTIVATION_OPERATION,
            "idempotency_key": idempotency_key,
            "request_sha256": request_sha256,
            "validation_order": [
                "DispositionAuthority<Copy>",
                "fixture_policy",
                "active_lease",
                "case_and_target",
                "ballot_merit",
                "terminal_verdict",
                "operator_countersign",
                "rehearsal_effect",
            ],
            "scope": "Copy",
            "fixture_context_sha256": fixture_context.digest,
            "authority": {
                "evaluation_id": authorized.evaluation_id,
                "result": "Authorized",
                "authority_digest": authority_digest,
                "evaluated_state_hash": evaluated_state_hash,
            },
            "artifacts": {
                "case": {"id": case.case_id, "sha256": case_sha256},
                "lease": {"id": lease.lease_id, "sha256": lease.lease_sha256},
                "verdict": {"id": verdict.verdict_id, "sha256": verdict_sha256},
                "countersign": {
                    "id": countersign.countersign_id,
                    "sha256": countersign_sha256,
                },
                "disposition": {
                    "id": disposition.disposition_id,
                    "sha256": disposition_sha256,
                },
                "lineage": {"id": lineage_edge_id, "sha256": lineage_sha256},
                "target": {"id": artifact_id, "sha256": transitioned_sha},
                "successor": {"id": successor_id, "sha256": successor_sha},
            },
            "state": {
                "synthetic_before_sha256": actual_before,
                "synthetic_after_sha256": after_state_hash,
                "copied_lifecycle_fingerprint": actual_copy_fingerprint,
                "case_head_before": actual_case_head,
            },
            "transaction": {
                "mode": "BEGIN IMMEDIATE",
                "boundaries": list(MUTATION_BOUNDARIES),
                "commits": 1,
            },
            "invariant_table_digests": {
                name: {
                    "before_sha256": digest,
                    "after_sha256": invariants_after[name],
                    "unchanged": True,
                }
                for name, digest in sorted(invariants_before.items())
            },
            "signature_replay": persisted_signature_replay,
            "request_signature_validation": replay_proof,
            "persisted_signature_count": persisted_signature_count,
            "signed_event_table_replay": signed_event_table_replay,
            "signed_event": {
                "event_id": event_id,
                "event_hash": event_hash,
                "signature_verified": True,
                "replay_result": "SignaturesVerified",
            },
            "source_fixture_id": policy.source_fixture_id,
            "copied_database_id": policy.copied_database_id,
            "standing_effect": "none",
            "identity_effect": "none",
            "live_eligible": False,
            "live_mutations": 0,
            "provider_calls": 0,
            "external_actions": 0,
        }
        receipt = {
            **receipt_without_hash,
            "receipt_sha256": canonical_json_sha256(receipt_without_hash),
        }
        receipt = json.loads(canonical_json_text(receipt))
        record_idempotency(
            conn,
            operation=ACTIVATION_OPERATION,
            idempotency_key=idempotency_key,
            request_sha256=request_sha256,
            response=receipt,
            created_at=created_at,
        )
        _invoke_failure(failure_hook, "idempotency_insert")
        conn.commit()
        return receipt
    except LifecycleError:
        if conn.in_transaction:
            conn.rollback()
        raise
    except sqlite3.IntegrityError as exc:
        if conn.in_transaction:
            conn.rollback()
        raise LifecycleConflict("immutable_lifecycle_conflict", str(exc)) from exc
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


__all__ = [
    "ACTIVATION_METHOD_PATH",
    "ACTIVATION_OPERATION",
    "FROZEN_EFFECTS",
    "MAX_ACTIVATION_CLOCK_SKEW",
    "MUTATION_BOUNDARIES",
    "FixtureExecutionContext",
    "LifecycleAuthorityDenied",
    "LifecycleConflict",
    "LifecycleError",
    "LifecycleValidationError",
    "RehearsalLifecycleRequestV1",
    "apply_rehearsal_lifecycle",
    "build_effect_payload",
    "build_lifecycle_event_payload",
    "case_scope_head",
    "compute_ballot_set_sha256",
    "new_signed_event_chain_head",
    "preview_rehearsal_transition",
    "rehearsal_state_fingerprint",
    "table_content_digest",
]
