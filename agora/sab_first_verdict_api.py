"""Dedicated, fail-closed maintenance API for SAB First Verdict Build A.

This module intentionally creates a separate FastAPI application.  It never
mounts the public Agora application or the legacy SAB seeding router, never
discovers a database path, and has no live verdict/application endpoint.  The
only writable database is supplied through an out-of-band copy attestation;
the fixture trust context is likewise a Python object supplied to the factory,
never request data.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from fastapi import Body, FastAPI, Header, Request, status
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .sab_artifact_verdict import (
    ArtifactBallotV1,
    ArtifactCaseV1,
    AuthorizedDispositionAuthorityV1,
    CompostBatchPreviewV1,
    CouncilVerdictV1,
    DispositionAuthorityV1,
    DispositionScope,
    FROZEN_MAINTENANCE_OPERATIONS,
    MASTER_VISION_SEED_ID,
    RehearsalDispositionV1,
    SeedSupersessionV1,
    SessionWriteLeaseV1,
    SignedDispositionPolicyV1,
    TrustedPolicyIssuerV1,
    canonical_json,
    canonical_json_sha256,
    evaluate_disposition_authority,
    verify_contract_signature,
)
from .sab_first_verdict_evidence import (
    DEFAULT_ACTOR_SLOTS,
    EvidenceValidationError,
    observe_master_vision_state,
    preview_contract_payload,
    preview_database_readonly,
)
from .sab_first_verdict_lifecycle import (
    ACTIVATION_OPERATION,
    FROZEN_EFFECTS,
    FixtureExecutionContext,
    LifecycleError,
    RehearsalLifecycleRequestV1,
    apply_rehearsal_lifecycle,
)
from .sab_first_verdict_storage import (
    MIGRATION_DIGEST,
    MIGRATION_ID,
    SIGNATURE_EVIDENCE_MIGRATION_DIGEST,
    SIGNATURE_EVIDENCE_MIGRATION_ID,
    CopyDatabaseAttestation,
    DatabaseSafetyError,
    FirstVerdictStorageError,
    ImmutableConflict,
    LeaseStateConflict,
    activate_session_lease,
    ballot_set_sha256_for_case,
    get_json_record,
    immutable_digest_for,
    idempotency_lookup,
    open_attested_copy_connection,
    release_session_lease,
    store_artifact_ballot,
    store_artifact_case,
    store_authority_evaluation,
    store_council_verdict,
)


FROZEN_FIRST_VERDICT_API_OPERATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/health"),
        ("POST", "/api/v1/session-write-leases/activate"),
        ("POST", "/api/v1/session-write-leases/{lease_id}/release"),
        ("GET", "/api/v1/session-write-leases/{lease_id}"),
        ("POST", "/api/v1/artifact-cases"),
        ("GET", "/api/v1/artifact-cases/{case_id}"),
        ("POST", "/api/v1/artifact-cases/{case_id}/ballots"),
        (
            "POST",
            "/api/v1/artifact-cases/{case_id}/authority-evaluations",
        ),
        ("POST", "/api/v1/artifact-cases/{case_id}/verdicts"),
        ("GET", "/api/v1/artifact-verdicts/{verdict_id}"),
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        ),
        ("GET", "/api/v1/rehearsal-dispositions/{disposition_id}"),
        ("GET", "/api/v1/seeds/{seed_id}/lineage"),
        ("POST", "/api/v1/compost-batches/preview"),
    }
)
if FROZEN_FIRST_VERDICT_API_OPERATIONS != FROZEN_MAINTENANCE_OPERATIONS:
    raise RuntimeError("A2 and A4 frozen maintenance inventories disagree")
WRITE_LEASE_HEADER = "X-SAB-Write-Lease"


class StrictRequestModel(BaseModel):
    """Immutable request base which rejects undeclared HTTP input."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        serialize_by_alias=True,
        use_enum_values=True,
    )


def _walk_sensitive_request_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).casefold()
            if any(
                part in key
                for part in (
                    "credential",
                    "password",
                    "private",
                    "secret",
                    "token",
                )
            ):
                raise ValueError("signed policy contains a forbidden sensitive field")
            _walk_sensitive_request_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk_sensitive_request_keys(item)


def _reject_sensitive_request_keys(value: Any) -> Any:
    if not isinstance(value, Mapping):
        raise ValueError("signed policy must be an object")
    _walk_sensitive_request_keys(value)
    return value


class ClosedPolicyWireV1(StrictRequestModel):
    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=False)

    @model_validator(mode="before")
    @classmethod
    def no_sensitive_input(cls, value: Any) -> Any:
        return _reject_sensitive_request_keys(value)


class SignedDispositionPolicyWireV1(ClosedPolicyWireV1):
    schema_: Literal["sab.signed_disposition_policy.v1"] = Field(alias="schema")
    policy_id: Any
    artifact_id: Any
    artifact_sha256: Any
    disposition_mode: Any
    scope: Any
    permitted_effects: Any
    forbidden_effects: Any
    preconditions: Any
    evaluated_state_hash: Any
    source_fixture_id: Any
    copied_database_id: Any
    test_issuer: Any
    live_eligible: Any
    standing_effect: Any
    authority_refs: Any
    issued_at: Any
    expires_at: Any
    issuer: Any
    policy_sha256: Any
    signature: Any


class MasterVisionPolicyEvidenceWireV1(ClosedPolicyWireV1):
    schema_: Literal["sab.master_vision_policy_evidence.v1"] = Field(alias="schema")
    proof_class: Any
    source_commit: Any
    document_path: Any
    document_base64: Any
    document_sha256: Any
    seed_packet_path: Any
    seed_packet_base64: Any
    seed_packet_raw_sha256: Any
    seed_packet_sha256: Any
    seed_state: Any
    challenge_packet_path: Any
    challenge_packet_base64: Any
    challenge_packet_raw_sha256: Any
    challenge_packet_sha256: Any
    challenge_state: Any
    signer: Any
    signer_public_key: Any


DispositionPolicyWireV1 = Annotated[
    SignedDispositionPolicyWireV1 | MasterVisionPolicyEvidenceWireV1,
    Field(discriminator="schema_"),
]


def _closed_domain_request(
    model: type[Any], value: Any, *, field: str
) -> dict[str, Any]:
    """Translate raw-validator type failures into ordinary request rejection."""

    try:
        parsed = model.model_validate(value)
    except (AttributeError, TypeError) as exc:
        raise ValueError(f"{field} request shape is invalid") from exc
    return parsed.canonical_payload()


class LeaseActivationRequestV1(SessionWriteLeaseV1):
    @model_validator(mode="before")
    @classmethod
    def safe_domain_validation(cls, value: Any) -> Any:
        return _closed_domain_request(
            SessionWriteLeaseV1, value, field="session write lease"
        )


class ArtifactCaseRequestV1(ArtifactCaseV1):
    @model_validator(mode="before")
    @classmethod
    def safe_domain_validation(cls, value: Any) -> Any:
        return _closed_domain_request(ArtifactCaseV1, value, field="artifact case")


class ArtifactBallotRequestV1(ArtifactBallotV1):
    @model_validator(mode="before")
    @classmethod
    def safe_domain_validation(cls, value: Any) -> Any:
        return _closed_domain_request(ArtifactBallotV1, value, field="artifact ballot")


class RehearsalLifecycleWireRequestV1(RehearsalLifecycleRequestV1):
    @model_validator(mode="before")
    @classmethod
    def safe_domain_validation(cls, value: Any) -> Any:
        return _closed_domain_request(
            RehearsalLifecycleRequestV1, value, field="rehearsal lifecycle"
        )


class AuthorityEvaluationRequestV1(StrictRequestModel):
    schema_version: Literal["sab.authority_evaluation_request.v1"] = (
        "sab.authority_evaluation_request.v1"
    )
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_scope: Literal[DispositionScope.COPY] = DispositionScope.COPY
    requested_effects: tuple[str, ...] = ()
    evaluated_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_policy: DispositionPolicyWireV1 | None = None

    @field_validator("requested_effects", mode="before")
    @classmethod
    def exact_effects(cls, value: Sequence[str]) -> tuple[str, ...]:
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise ValueError("requested effects must be a sequence of strings")
        if any(not isinstance(item, str) for item in value):
            raise ValueError("requested effects must contain only strings")
        effects = tuple(sorted({item.strip() for item in value}))
        if any(not effect or "*" in effect for effect in effects):
            raise ValueError("requested effects must be exact non-wildcard names")
        return effects


class LeaseReleaseRequestV1(StrictRequestModel):
    schema_version: Literal["sab.session_write_lease_release_request.v1"] = (
        "sab.session_write_lease_release_request.v1"
    )


class VerdictCreateRequestV1(StrictRequestModel):
    schema_version: Literal["sab.council_verdict_create_request.v1"] = (
        "sab.council_verdict_create_request.v1"
    )
    evaluation_id: str = Field(min_length=1, max_length=200)
    verdict: CouncilVerdictV1

    @field_validator("verdict", mode="before")
    @classmethod
    def safe_verdict_validation(cls, value: Any) -> Any:
        return _closed_domain_request(CouncilVerdictV1, value, field="council verdict")


class PreviewActorSlotsV1(StrictRequestModel):
    hermes_m5: str = Field(default=DEFAULT_ACTOR_SLOTS["hermes_m5"], min_length=1)
    dharma_cron: str = Field(default=DEFAULT_ACTOR_SLOTS["dharma_cron"], min_length=1)


class CompostBatchPreviewRequestV1(StrictRequestModel):
    schema_version: Literal["sab.compost_batch_preview_request.v1"] = (
        "sab.compost_batch_preview_request.v1"
    )
    actor_slots: PreviewActorSlotsV1 = Field(default_factory=PreviewActorSlotsV1)


class StrictResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=True)


_SENSITIVE_RESPONSE_KEY_PARTS = (
    "credential",
    "password",
    "private",
    "secret",
    "token",
)


def _reject_sensitive_response_keys(value: Any) -> Any:
    """Reject secret-shaped keys before response serialization can drop them."""

    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).casefold()
            if any(part in key for part in _SENSITIVE_RESPONSE_KEY_PARTS):
                raise ValueError("response contains a forbidden sensitive field")
            _reject_sensitive_response_keys(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_sensitive_response_keys(item)
    return value


class ErrorIssueV1(StrictResponseModel):
    location: tuple[str, ...]
    type: str
    message: str


class ErrorBodyV1(StrictResponseModel):
    code: str
    message: str
    issues: tuple[ErrorIssueV1, ...] = ()


class ErrorEnvelopeV1(StrictResponseModel):
    error: ErrorBodyV1


class HealthResponseV1(StrictResponseModel):
    status: Literal["ok"] = "ok"
    proof_class: Literal["copied_fixture_maintenance"]
    lifecycle_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    live_eligible: Literal[False] = False


class LeaseActivatedResponseV1(StrictResponseModel):
    lease: SessionWriteLeaseV1
    status: Literal["active"] = "active"


class LeaseReleasedResponseV1(StrictResponseModel):
    lease: SessionWriteLeaseV1
    status: Literal["released"] = "released"
    replayed: bool


class LeaseReadResponseV1(StrictResponseModel):
    lease: SessionWriteLeaseV1
    status: Literal["active", "released", "expired", "revoked"]
    released_at: datetime | None


class CaseWriteResponseV1(StrictResponseModel):
    case: ArtifactCaseV1
    case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class CaseReadResponseV1(StrictResponseModel):
    case: ArtifactCaseV1
    case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class BallotWriteResponseV1(StrictResponseModel):
    ballot: ArtifactBallotV1
    ballot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class AuthorityWriteResponseV1(StrictResponseModel):
    authority: DispositionAuthorityV1
    authority_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class VerdictWriteResponseV1(StrictResponseModel):
    verdict: CouncilVerdictV1
    verdict_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ballot_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replayed: bool


class VerdictReadResponseV1(StrictResponseModel):
    verdict: CouncilVerdictV1
    verdict_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReceiptAuthorityResponseV1(StrictResponseModel):
    evaluation_id: str = Field(min_length=1, max_length=240)
    result: Literal["Authorized"] = "Authorized"
    authority_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluated_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReceiptArtifactRefResponseV1(StrictResponseModel):
    id: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReceiptArtifactsResponseV1(StrictResponseModel):
    case: ReceiptArtifactRefResponseV1
    lease: ReceiptArtifactRefResponseV1
    verdict: ReceiptArtifactRefResponseV1
    countersign: ReceiptArtifactRefResponseV1
    disposition: ReceiptArtifactRefResponseV1
    lineage: ReceiptArtifactRefResponseV1
    target: ReceiptArtifactRefResponseV1
    successor: ReceiptArtifactRefResponseV1


class ReceiptStateResponseV1(StrictResponseModel):
    synthetic_before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    synthetic_after_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    copied_lifecycle_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    case_head_before: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReceiptTransactionResponseV1(StrictResponseModel):
    mode: Literal["BEGIN IMMEDIATE"] = "BEGIN IMMEDIATE"
    boundaries: tuple[str, ...]
    commits: Literal[1] = 1


class ReceiptInvariantDigestResponseV1(StrictResponseModel):
    before_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    unchanged: Literal[True] = True


class ReceiptSignatureRecordResponseV1(StrictResponseModel):
    artifact_type: str = Field(min_length=1, max_length=240)
    artifact_id: str = Field(min_length=1, max_length=240)
    signer: str = Field(min_length=1, max_length=240)
    public_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReceiptSignatureValidationResponseV1(StrictResponseModel):
    proof_class: Literal["SignaturesVerified"] = "SignaturesVerified"
    verified: Literal[True] = True
    signature_count: int = Field(ge=1)
    artifact_types: tuple[str, ...]
    records: tuple[ReceiptSignatureRecordResponseV1, ...]


class ReceiptPersistedSignatureReplayResponseV1(ReceiptSignatureValidationResponseV1):
    table: Literal["sab_first_verdict_signature_evidence_v1"]
    ordered_record_ids: tuple[str, ...]
    head_record_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    persisted_after_reopen: Literal[True] = True


class ReceiptSignedEventReplayItemResponseV1(StrictResponseModel):
    event_id: str = Field(min_length=1, max_length=240)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    public_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_verified: Literal[True] = True
    replay_result: Literal["SignaturesVerified"] = "SignaturesVerified"


class ReceiptSignedEventTableReplayResponseV1(ReceiptSignatureValidationResponseV1):
    table: Literal["sab_first_verdict_signed_events_v1"]
    ordered_event_ids: tuple[str, ...]
    head_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signed_events: tuple[ReceiptSignedEventReplayItemResponseV1, ...]


class ReceiptSignedEventResponseV1(StrictResponseModel):
    event_id: str = Field(min_length=1, max_length=240)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_verified: Literal[True] = True
    replay_result: Literal["SignaturesVerified"] = "SignaturesVerified"


class LifecycleReceiptResponseV1(StrictResponseModel):
    schema_version: Literal["sab.rehearsal_lifecycle_receipt.v1"]
    proof_class: Literal["copied_live_db_rehearsal"]
    operation: str
    idempotency_key: str
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    validation_order: tuple[str, ...]
    scope: Literal["Copy"]
    fixture_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authority: ReceiptAuthorityResponseV1
    artifacts: ReceiptArtifactsResponseV1
    state: ReceiptStateResponseV1
    transaction: ReceiptTransactionResponseV1
    invariant_table_digests: dict[str, ReceiptInvariantDigestResponseV1]
    signature_replay: ReceiptPersistedSignatureReplayResponseV1
    request_signature_validation: ReceiptSignatureValidationResponseV1
    persisted_signature_count: int = Field(ge=1)
    signed_event_table_replay: ReceiptSignedEventTableReplayResponseV1
    signed_event: ReceiptSignedEventResponseV1
    source_fixture_id: str
    copied_database_id: str
    standing_effect: Literal["none"]
    identity_effect: Literal["none"]
    live_eligible: Literal[False]
    live_mutations: Literal[0]
    provider_calls: Literal[0]
    external_actions: Literal[0]
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="before")
    @classmethod
    def no_sensitive_output(cls, value: Any) -> Any:
        return _reject_sensitive_response_keys(value)


class DispositionReadResponseV1(StrictResponseModel):
    disposition: RehearsalDispositionV1
    disposition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LineageEdgeResponseV1(SeedSupersessionV1):
    edge_id: str = Field(min_length=1, max_length=240)
    disposition_id: str = Field(min_length=1, max_length=240)
    disposition_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="before")
    @classmethod
    def no_sensitive_output(cls, value: Any) -> Any:
        return _reject_sensitive_response_keys(value)


class LineageReadResponseV1(StrictResponseModel):
    seed_id: str
    edges: tuple[LineageEdgeResponseV1, ...]
    count: int = Field(ge=0)


class FirstVerdictAPIError(RuntimeError):
    """Stable API-domain failure without storage or secret disclosure."""

    def __init__(self, code: str, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _api_error(code: str, message: str, *, status_code: int) -> None:
    raise FirstVerdictAPIError(code, message, status_code=status_code)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_runtime_binding(
    attestation: CopyDatabaseAttestation,
    fixture_context: FixtureExecutionContext,
) -> None:
    """Bind the two out-of-band trust objects to the same copied database."""

    if not isinstance(attestation, CopyDatabaseAttestation):
        raise TypeError("attestation must be CopyDatabaseAttestation")
    if not isinstance(fixture_context, FixtureExecutionContext):
        raise TypeError("fixture_context must be FixtureExecutionContext")
    attestation.validate(require_pristine_backup=False)
    if attestation.source_backup_sha256 != fixture_context.source_backup_sha256:
        raise DatabaseSafetyError(
            "copy attestation and fixture context disagree on source backup SHA-256"
        )
    if (
        attestation.expected_lifecycle_fingerprint
        != fixture_context.copied_lifecycle_fingerprint
    ):
        raise DatabaseSafetyError(
            "copy attestation and fixture context disagree on lifecycle fingerprint"
        )
    with closing(open_attested_copy_connection(attestation)) as conn:
        try:
            rows = conn.execute(
                """
                SELECT migration_id, migration_digest
                FROM sab_first_verdict_schema_migrations_v1
                WHERE migration_id IN (?, ?)
                """,
                (MIGRATION_ID, SIGNATURE_EVIDENCE_MIGRATION_ID),
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise DatabaseSafetyError(
                "first-verdict storage migration is not installed"
            ) from exc
        observed = {str(row[0]): str(row[1]) for row in rows}
        expected = {
            MIGRATION_ID: MIGRATION_DIGEST,
            SIGNATURE_EVIDENCE_MIGRATION_ID: SIGNATURE_EVIDENCE_MIGRATION_DIGEST,
        }
        if observed != expected:
            raise DatabaseSafetyError(
                "first-verdict storage migration is absent or has the wrong digest"
            )


def _bind_copy_file_identity(
    attestation: CopyDatabaseAttestation,
) -> tuple[int, int]:
    path = attestation.validate(require_pristine_backup=False)
    file_stat = path.stat()
    return file_stat.st_dev, file_stat.st_ino


@contextmanager
def _connection(
    attestation: CopyDatabaseAttestation,
    *,
    expected_file_identity: tuple[int, int] | None = None,
) -> Iterator[sqlite3.Connection]:
    conn = open_attested_copy_connection(
        attestation,
        expected_file_identity=expected_file_identity,
    )
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def _non_lifecycle_write(conn: sqlite3.Connection) -> Iterator[None]:
    """Give ordinary immutable writes one explicit transaction boundary."""

    if conn.in_transaction:
        _api_error(
            "caller_transaction_active",
            "maintenance write requires ownership of its transaction",
            status_code=status.HTTP_409_CONFLICT,
        )
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    else:
        conn.commit()


def _verify_fixture_signature(
    model: Any,
    signature_field: str,
    *,
    expected_signer: str,
    expected_public_key: str,
    code: str,
) -> None:
    signature = getattr(model, signature_field)
    valid = (
        signature.signer == expected_signer
        and signature.public_key == expected_public_key
        and verify_contract_signature(
            model.canonical_bytes(exclude={signature_field}), signature
        )
    )
    if not valid:
        _api_error(
            code,
            "signature is invalid or outside the provisioned fixture context",
            status_code=status.HTTP_403_FORBIDDEN,
        )


def _load_lease(
    conn: sqlite3.Connection,
    lease_id: str,
    *,
    fixture_context: FixtureExecutionContext,
) -> tuple[SessionWriteLeaseV1, str, str | None]:
    row = conn.execute(
        """
        SELECT lease_json, lease_json_sha256, lease_sha256, status, released_at
        FROM sab_session_write_leases_v1 WHERE lease_id = ?
        """,
        (lease_id,),
    ).fetchone()
    if row is None:
        _api_error(
            "lease_not_found",
            "session write lease was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    try:
        raw = json.loads(str(row[0]))
        lease = SessionWriteLeaseV1.model_validate(raw)
    except Exception as exc:
        raise FirstVerdictAPIError(
            "stored_lease_invalid",
            "stored session write lease does not satisfy its contract",
            status_code=status.HTTP_409_CONFLICT,
        ) from exc
    if (
        canonical_json(lease.canonical_payload()) != str(row[0])
        or canonical_json_sha256(lease.canonical_payload()) != str(row[1])
        or lease.lease_sha256 != str(row[2])
    ):
        _api_error(
            "stored_lease_digest_mismatch",
            "stored session write lease digest does not verify",
            status_code=status.HTTP_409_CONFLICT,
        )
    if (
        lease.issuer_identity != fixture_context.operator_identity
        or lease.issuer_public_key != fixture_context.operator_public_key
        or lease.clerk_identity != fixture_context.clerk_identity
        or lease.source_backup_sha256 != fixture_context.source_backup_sha256
        or lease.expected_lifecycle_fingerprint
        != fixture_context.copied_lifecycle_fingerprint
        or lease.accepted_code_sha != fixture_context.code_sha
    ):
        _api_error(
            "lease_fixture_context_mismatch",
            "session write lease is outside the provisioned fixture context",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    _verify_fixture_signature(
        lease,
        "signature",
        expected_signer=fixture_context.operator_identity,
        expected_public_key=fixture_context.operator_public_key,
        code="lease_signature_invalid",
    )
    return lease, str(row[3]), None if row[4] is None else str(row[4])


def _require_write_lease(
    conn: sqlite3.Connection,
    lease_id: str | None,
    *,
    operation: tuple[str, str],
    fixture_context: FixtureExecutionContext,
    at: datetime | None = None,
) -> SessionWriteLeaseV1:
    if not lease_id:
        _api_error(
            "write_lease_required",
            f"{WRITE_LEASE_HEADER} is required",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    lease, lease_status, _ = _load_lease(
        conn, lease_id, fixture_context=fixture_context
    )
    if lease_status != "active":
        _api_error(
            "write_lease_not_active",
            "session write lease is not active",
            status_code=status.HTTP_409_CONFLICT,
        )
    checked_at = at or _utc_now()
    if checked_at.tzinfo is None:
        _api_error(
            "write_time_naive",
            "maintenance write time must be timezone-aware",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    checked_at = checked_at.astimezone(timezone.utc)
    if not (lease.activated_at <= checked_at < lease.expires_at):
        _api_error(
            "write_lease_outside_window",
            "session write lease is outside its signed active window",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    allowed = {(item.method, item.path) for item in lease.allowed_operations}
    if operation not in allowed:
        _api_error(
            "write_lease_operation_denied",
            "session write lease does not authorize this exact method/path",
            status_code=status.HTTP_403_FORBIDDEN,
        )
    return lease


def _stored_contract(
    conn: sqlite3.Connection,
    *,
    kind: str,
    table: str,
    id_column: str,
    json_column: str,
    object_id: str,
    model: type[Any],
) -> tuple[dict[str, Any], str]:
    try:
        record = get_json_record(
            conn,
            table=table,
            id_column=id_column,
            json_column=json_column,
            object_id=object_id,
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise FirstVerdictAPIError(
            f"stored_{kind}_invalid",
            f"stored {kind} does not satisfy its contract",
            status_code=status.HTTP_409_CONFLICT,
        ) from exc
    if record is None:
        _api_error(
            f"{kind}_not_found",
            f"{kind} was not found",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    if not isinstance(record, Mapping):
        _api_error(
            f"stored_{kind}_invalid",
            f"stored {kind} does not satisfy its contract",
            status_code=status.HTTP_409_CONFLICT,
        )
    try:
        parsed = model.model_validate(record)
        payload = parsed.canonical_payload()
        digest = canonical_json_sha256(payload)
    except Exception as exc:
        raise FirstVerdictAPIError(
            f"stored_{kind}_invalid",
            f"stored {kind} does not satisfy its contract",
            status_code=status.HTTP_409_CONFLICT,
        ) from exc
    if immutable_digest_for(conn, kind, object_id) != digest:
        _api_error(
            f"stored_{kind}_digest_mismatch",
            f"stored {kind} digest does not verify",
            status_code=status.HTTP_409_CONFLICT,
        )
    return payload, digest


def create_sab_first_verdict_app(
    attestation: CopyDatabaseAttestation,
    fixture_context: FixtureExecutionContext,
) -> FastAPI:
    """Construct the isolated 14-operation copied-fixture maintenance app."""

    _validate_runtime_binding(attestation, fixture_context)
    bound_copy_identity = _bind_copy_file_identity(attestation)
    app = FastAPI(
        title="SAB First Verdict Build A Maintenance",
        version="1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
        responses={
            status.HTTP_403_FORBIDDEN: {
                "model": ErrorEnvelopeV1,
                "description": "Forbidden",
            },
            status.HTTP_404_NOT_FOUND: {
                "model": ErrorEnvelopeV1,
                "description": "Not found",
            },
            status.HTTP_409_CONFLICT: {
                "model": ErrorEnvelopeV1,
                "description": "Conflict",
            },
            status.HTTP_422_UNPROCESSABLE_ENTITY: {
                "model": ErrorEnvelopeV1,
                "description": "Request rejected",
            },
        },
    )

    @contextmanager
    def bound_connection() -> Iterator[sqlite3.Connection]:
        with _connection(
            attestation,
            expected_file_identity=bound_copy_identity,
        ) as conn:
            yield conn

    @app.exception_handler(FirstVerdictAPIError)
    async def handle_api_error(_: Request, exc: FirstVerdictAPIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": str(exc)}},
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(
        _: Request, exc: RequestValidationError
    ) -> JSONResponse:
        issues = [
            {
                "location": [str(item) for item in error.get("loc", ())],
                "type": str(error.get("type", "validation_error")),
                "message": str(error.get("msg", "request validation failed")),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": {
                    "code": "request_validation_error",
                    "message": "request validation failed",
                    "issues": issues,
                }
            },
        )

    @app.exception_handler(ResponseValidationError)
    async def handle_response_validation_error(
        _: Request, __: ResponseValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": {
                    "code": "response_contract_invalid",
                    "message": "maintenance response failed its closed contract",
                }
            },
        )

    @app.exception_handler(LifecycleError)
    async def handle_lifecycle_error(_: Request, exc: LifecycleError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": "lifecycle request failed closed",
                }
            },
        )

    @app.exception_handler(DatabaseSafetyError)
    async def handle_database_safety_error(
        _: Request, __: DatabaseSafetyError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": {
                    "code": "database_attestation_failed",
                    "message": "copied database attestation failed closed",
                }
            },
        )

    @app.exception_handler(FirstVerdictStorageError)
    async def handle_storage_error(
        _: Request, exc: FirstVerdictStorageError
    ) -> JSONResponse:
        code = (
            "immutable_content_conflict"
            if isinstance(exc, ImmutableConflict)
            else "lease_state_conflict"
            if isinstance(exc, LeaseStateConflict)
            else "first_verdict_storage_error"
        )
        message = (
            "immutable content conflicts with an existing record"
            if isinstance(exc, ImmutableConflict)
            else "session write lease state conflicts with the requested transition"
            if isinstance(exc, LeaseStateConflict)
            else "first-verdict storage operation failed closed"
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"error": {"code": code, "message": message}},
        )

    @app.exception_handler(EvidenceValidationError)
    async def handle_evidence_error(
        _: Request, exc: EvidenceValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"error": {"code": exc.code, "message": str(exc)}},
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def handle_sqlite_integrity_error(
        _: Request, __: sqlite3.IntegrityError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": {
                    "code": "immutable_database_conflict",
                    "message": "database rejected the immutable write",
                }
            },
        )

    @app.exception_handler(sqlite3.DatabaseError)
    async def handle_sqlite_database_error(
        _: Request, __: sqlite3.DatabaseError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                "error": {
                    "code": "copied_database_error",
                    "message": "copied database operation failed closed",
                }
            },
        )

    @app.get("/health", response_model=HealthResponseV1)
    async def health() -> dict[str, Any]:
        with bound_connection() as conn:
            rows = conn.execute(
                """
                SELECT migration_id, migration_digest
                FROM sab_first_verdict_schema_migrations_v1
                WHERE migration_id IN (?, ?)
                """,
                (MIGRATION_ID, SIGNATURE_EVIDENCE_MIGRATION_ID),
            ).fetchall()
            observed = {str(row[0]): str(row[1]) for row in rows}
            expected = {
                MIGRATION_ID: MIGRATION_DIGEST,
                SIGNATURE_EVIDENCE_MIGRATION_ID: SIGNATURE_EVIDENCE_MIGRATION_DIGEST,
            }
            if observed != expected:
                _api_error(
                    "migration_attestation_failed",
                    "first-verdict migration digest does not verify",
                    status_code=status.HTTP_409_CONFLICT,
                )
        return {
            "status": "ok",
            "proof_class": "copied_fixture_maintenance",
            "lifecycle_fingerprint": fixture_context.copied_lifecycle_fingerprint,
            "live_eligible": False,
        }

    @app.post(
        "/api/v1/session-write-leases/activate",
        status_code=status.HTTP_201_CREATED,
        response_model=LeaseActivatedResponseV1,
    )
    async def activate_lease(payload: LeaseActivationRequestV1) -> dict[str, Any]:
        if (
            payload.issuer_identity != fixture_context.operator_identity
            or payload.issuer_public_key != fixture_context.operator_public_key
            or payload.clerk_identity != fixture_context.clerk_identity
            or payload.source_backup_sha256 != fixture_context.source_backup_sha256
            or payload.expected_lifecycle_fingerprint
            != fixture_context.copied_lifecycle_fingerprint
            or payload.accepted_code_sha != fixture_context.code_sha
        ):
            _api_error(
                "lease_fixture_context_mismatch",
                "lease is outside the provisioned fixture context",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        _verify_fixture_signature(
            payload,
            "signature",
            expected_signer=fixture_context.operator_identity,
            expected_public_key=fixture_context.operator_public_key,
            code="lease_signature_invalid",
        )
        observed_at = _utc_now()
        if not (payload.activated_at <= observed_at < payload.expires_at):
            _api_error(
                "lease_outside_activation_window",
                "lease cannot be activated outside its signed time window",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        with bound_connection() as conn, _non_lifecycle_write(conn):
            stored = activate_session_lease(conn, payload.canonical_payload())
        return {"lease": stored, "status": "active"}

    @app.post(
        "/api/v1/session-write-leases/{lease_id}/release",
        response_model=LeaseReleasedResponseV1,
    )
    async def release_lease(
        lease_id: str,
        _: LeaseReleaseRequestV1 = Body(default=LeaseReleaseRequestV1()),
        x_sab_write_lease: str = Header(alias=WRITE_LEASE_HEADER),
    ) -> dict[str, Any]:
        if x_sab_write_lease != lease_id:
            _api_error(
                "release_lease_header_mismatch",
                "release must be authorized by the same lease named in the path",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        operation = ("POST", "/api/v1/session-write-leases/{lease_id}/release")
        with bound_connection() as conn, _non_lifecycle_write(conn):
            lease, lease_status, _ = _load_lease(
                conn, lease_id, fixture_context=fixture_context
            )
            allowed = {(item.method, item.path) for item in lease.allowed_operations}
            if operation not in allowed:
                _api_error(
                    "write_lease_operation_denied",
                    "session write lease does not authorize this exact method/path",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            replayed = lease_status == "released"
            if not replayed:
                _require_write_lease(
                    conn,
                    x_sab_write_lease,
                    operation=operation,
                    fixture_context=fixture_context,
                )
            stored = release_session_lease(conn, lease_id)
        return {"lease": stored, "status": "released", "replayed": replayed}

    @app.get(
        "/api/v1/session-write-leases/{lease_id}",
        response_model=LeaseReadResponseV1,
    )
    async def get_lease(lease_id: str) -> dict[str, Any]:
        with bound_connection() as conn:
            lease, lease_status, released_at = _load_lease(
                conn, lease_id, fixture_context=fixture_context
            )
        derived_status = lease_status
        if lease_status == "active" and _utc_now() >= lease.expires_at:
            derived_status = "expired"
        return {
            "lease": lease.canonical_payload(),
            "status": derived_status,
            "released_at": released_at,
        }

    @app.post(
        "/api/v1/artifact-cases",
        status_code=status.HTTP_201_CREATED,
        response_model=CaseWriteResponseV1,
    )
    async def create_artifact_case(
        payload: ArtifactCaseRequestV1,
        x_sab_write_lease: str = Header(alias=WRITE_LEASE_HEADER),
    ) -> dict[str, Any]:
        if payload.clerk_identity != fixture_context.clerk_identity:
            _api_error(
                "case_clerk_identity_mismatch",
                "case clerk identity is outside the provisioned fixture context",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        if payload.lease_id != x_sab_write_lease:
            _api_error(
                "case_lease_header_mismatch",
                "case lease does not match the write-lease header",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        _verify_fixture_signature(
            payload,
            "clerk_signature",
            expected_signer=fixture_context.clerk_identity,
            expected_public_key=fixture_context.clerk_public_key,
            code="case_signature_invalid",
        )
        with bound_connection() as conn, _non_lifecycle_write(conn):
            _require_write_lease(
                conn,
                x_sab_write_lease,
                operation=("POST", "/api/v1/artifact-cases"),
                fixture_context=fixture_context,
            )
            stored, digest, replayed = store_artifact_case(
                conn, payload.canonical_payload()
            )
        return {"case": stored, "case_sha256": digest, "replayed": replayed}

    @app.get(
        "/api/v1/artifact-cases/{case_id}",
        response_model=CaseReadResponseV1,
    )
    async def get_artifact_case(case_id: str) -> dict[str, Any]:
        with bound_connection() as conn:
            stored, digest = _stored_contract(
                conn,
                kind="case",
                table="sab_artifact_cases_v1",
                id_column="case_id",
                json_column="case_json",
                object_id=case_id,
                model=ArtifactCaseV1,
            )
        return {"case": stored, "case_sha256": digest}

    @app.post(
        "/api/v1/artifact-cases/{case_id}/ballots",
        status_code=status.HTTP_201_CREATED,
        response_model=BallotWriteResponseV1,
    )
    async def create_artifact_ballot(
        case_id: str,
        payload: ArtifactBallotRequestV1,
        x_sab_write_lease: str = Header(alias=WRITE_LEASE_HEADER),
    ) -> dict[str, Any]:
        if payload.case_id != case_id:
            _api_error(
                "ballot_case_path_mismatch",
                "ballot case does not match the path",
                status_code=status.HTTP_409_CONFLICT,
            )
        if payload.ballot_source != "fixture_model":
            _api_error(
                "ballot_source_not_fixture",
                "Build A maintenance accepts fixture ballots only",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        trusted_seats = {
            seat_id: (signer, public_key)
            for seat_id, signer, public_key in fixture_context.seat_execution_identities
        }
        expected = trusted_seats.get(payload.seat_id)
        if expected is None:
            _api_error(
                "ballot_seat_outside_fixture",
                "ballot seat is outside the provisioned fixture context",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        _verify_fixture_signature(
            payload,
            "execution_signature",
            expected_signer=expected[0],
            expected_public_key=expected[1],
            code="ballot_signature_invalid",
        )
        with bound_connection() as conn, _non_lifecycle_write(conn):
            _require_write_lease(
                conn,
                x_sab_write_lease,
                operation=("POST", "/api/v1/artifact-cases/{case_id}/ballots"),
                fixture_context=fixture_context,
            )
            stored, digest, replayed = store_artifact_ballot(
                conn, payload.canonical_payload()
            )
        return {"ballot": stored, "ballot_sha256": digest, "replayed": replayed}

    @app.post(
        "/api/v1/artifact-cases/{case_id}/authority-evaluations",
        status_code=status.HTTP_201_CREATED,
        response_model=AuthorityWriteResponseV1,
    )
    async def create_authority_evaluation(
        case_id: str,
        payload: AuthorityEvaluationRequestV1,
        x_sab_write_lease: str = Header(alias=WRITE_LEASE_HEADER),
    ) -> dict[str, Any]:
        observed_at = _utc_now()
        with bound_connection() as conn, _non_lifecycle_write(conn):
            _require_write_lease(
                conn,
                x_sab_write_lease,
                operation=(
                    "POST",
                    "/api/v1/artifact-cases/{case_id}/authority-evaluations",
                ),
                fixture_context=fixture_context,
                at=observed_at,
            )
            case_record, _ = _stored_contract(
                conn,
                kind="case",
                table="sab_artifact_cases_v1",
                id_column="case_id",
                json_column="case_json",
                object_id=case_id,
                model=ArtifactCaseV1,
            )
            case = ArtifactCaseV1.model_validate(case_record)
            if payload.artifact_sha256 != case.target_seed_packet_sha256:
                _api_error(
                    "authority_case_artifact_mismatch",
                    "authority request does not bind the case artifact bytes",
                    status_code=status.HTTP_409_CONFLICT,
                )
            policy_payload = (
                None
                if payload.signed_policy is None
                else payload.signed_policy.canonical_payload()
            )
            master_vision_observation = None
            if case.target_seed_id == MASTER_VISION_SEED_ID:
                try:
                    master_vision_observation = observe_master_vision_state(conn)
                except EvidenceValidationError:
                    master_vision_observation = None
            authority = evaluate_disposition_authority(
                artifact_id=case.target_seed_id,
                artifact_sha256=payload.artifact_sha256,
                requested_scope=DispositionScope.COPY,
                requested_effects=payload.requested_effects,
                evaluated_state_hash=payload.evaluated_state_hash,
                signed_policy=policy_payload,
                trusted_policy_issuer=TrustedPolicyIssuerV1(
                    issuer_identity=fixture_context.policy_issuer_identity,
                    issuer_public_key=fixture_context.policy_issuer_public_key,
                    source_fixture_id=fixture_context.source_fixture_id,
                    copied_database_id=fixture_context.copied_database_id,
                    authority_basis="founder_bootstrap_self_declared",
                ),
                master_vision_observation=master_vision_observation,
                now=observed_at,
            )
            if isinstance(authority, AuthorizedDispositionAuthorityV1):
                try:
                    policy = SignedDispositionPolicyV1.model_validate(policy_payload)
                except Exception as exc:
                    raise FirstVerdictAPIError(
                        "authorized_policy_contract_invalid",
                        "authorized policy did not re-derive from its wire contract",
                        status_code=status.HTTP_409_CONFLICT,
                    ) from exc
                if (
                    tuple(payload.requested_effects) != FROZEN_EFFECTS
                    or tuple(authority.allowed_effects) != FROZEN_EFFECTS
                    or tuple(policy.permitted_effects) != FROZEN_EFFECTS
                    or case.target_seed_id != fixture_context.target_artifact_id
                    or payload.artifact_sha256 != fixture_context.target_artifact_sha256
                    or payload.evaluated_state_hash
                    != fixture_context.synthetic_state_hash
                    or policy.source_fixture_id != fixture_context.source_fixture_id
                    or policy.copied_database_id != fixture_context.copied_database_id
                    or policy.issuer != fixture_context.policy_issuer_identity
                    or policy.signature.signer != fixture_context.policy_issuer_identity
                    or policy.signature.public_key
                    != fixture_context.policy_issuer_public_key
                    or not policy.test_issuer
                    or policy.live_eligible
                ):
                    _api_error(
                        "authorized_policy_outside_fixture_context",
                        "authorized policy is outside the provisioned fixture context",
                        status_code=status.HTTP_403_FORBIDDEN,
                    )
            stored, digest, replayed = store_authority_evaluation(
                conn,
                case_id=case_id,
                authority=authority.canonical_payload(),
            )
        return {
            "authority": stored,
            "authority_sha256": digest,
            "replayed": replayed,
        }

    @app.post(
        "/api/v1/artifact-cases/{case_id}/verdicts",
        status_code=status.HTTP_201_CREATED,
        response_model=VerdictWriteResponseV1,
    )
    async def create_council_verdict(
        case_id: str,
        payload: VerdictCreateRequestV1,
        x_sab_write_lease: str = Header(alias=WRITE_LEASE_HEADER),
    ) -> dict[str, Any]:
        verdict = payload.verdict
        if verdict.case_id != case_id:
            _api_error(
                "verdict_case_path_mismatch",
                "verdict case does not match the path",
                status_code=status.HTTP_409_CONFLICT,
            )
        if verdict.scope != "Copy" or verdict.evidence_provenance != "fixture_models":
            _api_error(
                "verdict_not_copy_fixture",
                "Build A maintenance accepts Copy-scoped fixture verdicts only",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        with bound_connection() as conn, _non_lifecycle_write(conn):
            _require_write_lease(
                conn,
                x_sab_write_lease,
                operation=("POST", "/api/v1/artifact-cases/{case_id}/verdicts"),
                fixture_context=fixture_context,
            )
            authority_row = conn.execute(
                """
                SELECT result FROM sab_disposition_authority_v1
                WHERE evaluation_id = ? AND case_id = ?
                """,
                (payload.evaluation_id, case_id),
            ).fetchone()
            if authority_row is None:
                _api_error(
                    "authority_evaluation_not_found",
                    "verdict requires a prior immutable authority evaluation",
                    status_code=status.HTTP_409_CONFLICT,
                )
            if str(authority_row[0]) != "Authorized" and verdict.requested_effects:
                _api_error(
                    "advisory_verdict_requested_effect",
                    "a non-authorized opinion cannot request an artifact effect",
                    status_code=status.HTTP_403_FORBIDDEN,
                )
            ballot_set_sha256 = ballot_set_sha256_for_case(conn, case_id)
            stored, digest, replayed = store_council_verdict(
                conn,
                evaluation_id=payload.evaluation_id,
                verdict=verdict.canonical_payload(),
                ballot_set_sha256=ballot_set_sha256,
            )
        return {
            "verdict": stored,
            "verdict_sha256": digest,
            "ballot_set_sha256": ballot_set_sha256,
            "replayed": replayed,
        }

    @app.get(
        "/api/v1/artifact-verdicts/{verdict_id}",
        response_model=VerdictReadResponseV1,
    )
    async def get_council_verdict(verdict_id: str) -> dict[str, Any]:
        with bound_connection() as conn:
            stored, digest = _stored_contract(
                conn,
                kind="verdict",
                table="sab_council_verdicts_v1",
                id_column="verdict_id",
                json_column="verdict_json",
                object_id=verdict_id,
                model=CouncilVerdictV1,
            )
        return {"verdict": stored, "verdict_sha256": digest}

    @app.post(
        "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        status_code=status.HTTP_201_CREATED,
        response_model=LifecycleReceiptResponseV1,
    )
    async def create_rehearsal_disposition(
        verdict_id: str,
        payload: RehearsalLifecycleWireRequestV1,
        x_sab_write_lease: str = Header(alias=WRITE_LEASE_HEADER),
    ) -> dict[str, Any]:
        if not x_sab_write_lease:
            _api_error(
                "write_lease_required",
                f"{WRITE_LEASE_HEADER} is required",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        observed_at = _utc_now()
        with bound_connection() as conn:
            request_payload = payload.canonical_payload()
            request_sha256 = canonical_json_sha256(request_payload)
            try:
                replay = idempotency_lookup(
                    conn,
                    operation=ACTIVATION_OPERATION,
                    idempotency_key=payload.idempotency_key,
                    request_sha256=request_sha256,
                )
            except ImmutableConflict as exc:
                raise FirstVerdictAPIError(
                    "idempotency_content_conflict",
                    "idempotency identity has conflicting content",
                    status_code=status.HTTP_409_CONFLICT,
                ) from exc
            if replay is None:
                _require_write_lease(
                    conn,
                    x_sab_write_lease,
                    operation=(
                        "POST",
                        "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
                    ),
                    fixture_context=fixture_context,
                    at=observed_at,
                )
            # apply_rehearsal_lifecycle owns the one BEGIN IMMEDIATE transaction.
            if conn.in_transaction:
                _api_error(
                    "api_transaction_leak",
                    "API must not pre-open the lifecycle transaction",
                    status_code=status.HTTP_409_CONFLICT,
                )
            receipt = apply_rehearsal_lifecycle(
                conn,
                request_payload,
                fixture_context=fixture_context,
                now=observed_at,
                expected_verdict_id=verdict_id,
                expected_write_lease_id=x_sab_write_lease,
            )
        return receipt

    @app.get(
        "/api/v1/rehearsal-dispositions/{disposition_id}",
        response_model=DispositionReadResponseV1,
    )
    async def get_rehearsal_disposition(disposition_id: str) -> dict[str, Any]:
        with bound_connection() as conn:
            stored, digest = _stored_contract(
                conn,
                kind="disposition",
                table="sab_rehearsal_dispositions_v1",
                id_column="disposition_id",
                json_column="disposition_json",
                object_id=disposition_id,
                model=RehearsalDispositionV1,
            )
        return {"disposition": stored, "disposition_sha256": digest}

    @app.get(
        "/api/v1/seeds/{seed_id}/lineage",
        response_model=LineageReadResponseV1,
    )
    async def get_seed_lineage(seed_id: str) -> dict[str, Any]:
        with bound_connection() as conn:
            rows = conn.execute(
                """
                SELECT edge_id, edge_json, edge_sha256
                FROM sab_seed_lineage_edges_v1
                WHERE predecessor_seed_id = ? OR successor_seed_id = ?
                ORDER BY edge_id
                """,
                (seed_id, seed_id),
            ).fetchall()
            edges: list[dict[str, Any]] = []
            for edge_id, edge_json, edge_sha256 in rows:
                try:
                    edge = json.loads(str(edge_json))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise FirstVerdictAPIError(
                        "stored_lineage_invalid",
                        "stored lineage edge is not valid JSON",
                        status_code=status.HTTP_409_CONFLICT,
                    ) from exc
                if not isinstance(edge, Mapping):
                    _api_error(
                        "stored_lineage_invalid",
                        "stored lineage edge does not satisfy its contract",
                        status_code=status.HTTP_409_CONFLICT,
                    )
                try:
                    parsed_edge = LineageEdgeResponseV1.model_validate(edge)
                    normalized_edge = parsed_edge.canonical_payload()
                except Exception as exc:
                    raise FirstVerdictAPIError(
                        "stored_lineage_invalid",
                        "stored lineage edge does not satisfy its contract",
                        status_code=status.HTTP_409_CONFLICT,
                    ) from exc
                if canonical_json_sha256(normalized_edge) != str(edge_sha256):
                    _api_error(
                        "stored_lineage_digest_mismatch",
                        "stored lineage edge digest does not verify",
                        status_code=status.HTTP_409_CONFLICT,
                    )
                if parsed_edge.edge_id != str(edge_id):
                    _api_error(
                        "stored_lineage_identity_mismatch",
                        "stored lineage edge identity does not verify",
                        status_code=status.HTTP_409_CONFLICT,
                    )
                edges.append(normalized_edge)
        return {"seed_id": seed_id, "edges": edges, "count": len(edges)}

    @app.post(
        "/api/v1/compost-batches/preview",
        response_model=CompostBatchPreviewV1,
    )
    async def preview_compost_batch(
        payload: CompostBatchPreviewRequestV1,
    ) -> dict[str, Any]:
        actor_slots = payload.actor_slots.model_dump(mode="json")
        attestation.validate(require_pristine_backup=False)
        preview = preview_database_readonly(
            attestation.database_path,
            actor_slots=actor_slots,
            expected_file_identity=bound_copy_identity,
            expected_lifecycle_fingerprint=(attestation.expected_lifecycle_fingerprint),
        )
        try:
            return preview_contract_payload(preview)
        except EvidenceValidationError:
            raise
        except Exception as exc:
            raise EvidenceValidationError(
                "preview_contract_invalid",
                "preview did not satisfy the frozen no-write contract",
            ) from exc

    mounted = {
        (method, route.path)
        for route in app.routes
        for method in getattr(route, "methods", set())
        if method not in {"HEAD", "OPTIONS"}
    }
    if mounted != FROZEN_FIRST_VERDICT_API_OPERATIONS:
        raise RuntimeError("dedicated maintenance route inventory drifted")
    return app


# Stable shorter spelling for callers which already name the subsystem.
create_first_verdict_app = create_sab_first_verdict_app


__all__ = [
    "AuthorityEvaluationRequestV1",
    "CompostBatchPreviewRequestV1",
    "FROZEN_FIRST_VERDICT_API_OPERATIONS",
    "FirstVerdictAPIError",
    "LeaseReleaseRequestV1",
    "PreviewActorSlotsV1",
    "StrictRequestModel",
    "VerdictCreateRequestV1",
    "WRITE_LEASE_HEADER",
    "create_first_verdict_app",
    "create_sab_first_verdict_app",
]
