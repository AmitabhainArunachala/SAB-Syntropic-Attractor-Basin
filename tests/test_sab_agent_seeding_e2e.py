from __future__ import annotations

import copy
import hashlib
import hmac
import importlib
import json
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

try:
    from nacl.encoding import HexEncoder as _NaclHexEncoder
    from nacl.exceptions import BadSignatureError as _NaclBadSignatureError
    from nacl.signing import SigningKey as _NaclSigningKey
    from nacl.signing import VerifyKey as _NaclVerifyKey
except ImportError:  # pragma: no cover - exercised only in lean local environments
    _NaclBadSignatureError = None
    _NaclHexEncoder = None
    _NaclSigningKey = None
    _NaclVerifyKey = None


_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class AgentFixture:
    label: str
    signing_key: Any
    subject_id: str
    identity_ref: str
    public_key: str


@dataclass(frozen=True)
class EndpointContract:
    method: str
    path: str
    success_status: int
    required_response_keys: frozenset[str]


API_CONTRACTS: dict[str, EndpointContract] = {
    "register_agent": EndpointContract(
        "POST",
        "/api/v1/agents/register",
        201,
        frozenset({"schema", "subject_id", "identity_ref", "public_key"}),
    ),
    "submit_seed": EndpointContract(
        "POST",
        "/api/v1/seeds",
        201,
        frozenset(
            {
                "accepted",
                "seed_id",
                "state",
                "spark_projection_id",
                "challenge_window_closes_at",
                "witness_head",
                "next_actions",
            }
        ),
    ),
    "fetch_seed": EndpointContract(
        "GET",
        "/api/v1/seeds/{seed_id}",
        200,
        frozenset({"schema", "seed_id", "state", "seed_packet", "spark_projection_id"}),
    ),
    "fetch_seed_chain": EndpointContract(
        "GET",
        "/api/v1/seeds/{seed_id}/chain",
        200,
        frozenset({"seed_id", "verified", "head", "events"}),
    ),
    "challenge_seed": EndpointContract(
        "POST",
        "/api/v1/seeds/{seed_id}/challenges",
        201,
        frozenset({"challenge_id", "target_seed_id", "state", "witness_head"}),
    ),
    "respond_challenge": EndpointContract(
        "POST",
        "/api/v1/challenges/{challenge_id}/respond",
        201,
        frozenset({"challenge_id", "response_id", "state", "witness_head"}),
    ),
    "standing_review": EndpointContract(
        "POST",
        "/api/v1/standing/review",
        201,
        frozenset({"state", "witness_head"}),
    ),
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256_obj(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _agent(label: str) -> AgentFixture:
    if _NaclSigningKey is not None and _NaclHexEncoder is not None:
        signing_key = _NaclSigningKey.generate()
        public_key = signing_key.verify_key.encode(encoder=_NaclHexEncoder).decode()
    else:
        signing_key = secrets.token_bytes(32)
        public_key = hashlib.sha256(signing_key).hexdigest()
    subject_id = f"agent_ed25519_{hashlib.sha256(public_key.encode()).hexdigest()[:16]}"
    return AgentFixture(
        label=label,
        signing_key=signing_key,
        subject_id=subject_id,
        identity_ref=f"sab_identity_{label}",
        public_key=public_key,
    )


def _unsigned_seed(packet: dict[str, Any]) -> dict[str, Any]:
    unsigned = copy.deepcopy(packet)
    unsigned.pop("signature", None)
    return unsigned


def _seed_packet_sha256(packet: dict[str, Any]) -> str:
    return _sha256_obj(_unsigned_seed(packet))


def _seed_submit_message(packet: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "sab_seed_submit",
        "seed_packet_sha256": _seed_packet_sha256(packet),
        "claimant_identity": packet["claimant_identity"]["subject_id"],
        "authority_lease_id": packet["authority_lease"]["lease_ref"],
        "created_at": packet["created_at"],
    }


def _sign_message(signing_key: Any, message: dict[str, Any]) -> str:
    message_bytes = _canonical_bytes(message)
    if _NaclSigningKey is not None and isinstance(signing_key, _NaclSigningKey):
        return signing_key.sign(message_bytes).signature.hex()
    return hmac.new(signing_key, message_bytes, hashlib.sha512).hexdigest()


def _verify_message(public_key: str, message: dict[str, Any], signature_hex: str) -> bool:
    if _NaclVerifyKey is None or _NaclHexEncoder is None or _NaclBadSignatureError is None:
        raise RuntimeError("public-key verification requires PyNaCl")
    try:
        _NaclVerifyKey(public_key, encoder=_NaclHexEncoder).verify(
            _canonical_bytes(message),
            bytes.fromhex(signature_hex),
        )
    except (_NaclBadSignatureError, ValueError):
        return False
    return True


def _verify_agent_message(agent: AgentFixture, message: dict[str, Any], signature_hex: str) -> bool:
    if _NaclSigningKey is not None and isinstance(agent.signing_key, _NaclSigningKey):
        return _verify_message(agent.public_key, message, signature_hex)
    return hmac.compare_digest(_sign_message(agent.signing_key, message), signature_hex)


def _seed_packet(agent: AgentFixture, *, now: datetime | None = None) -> dict[str, Any]:
    created_at = now or _utc_now()
    packet: dict[str, Any] = {
        "schema": "sab.seed_packet.v1",
        "seed_id": "sab_seed_lane6_scope_boundary",
        "seed_type": "project",
        "title": "Lane 6 SAB agent seeding contract",
        "status": "pending_seed",
        "loop_position": "spark",
        "north_star": "deepen_truth",
        "claim": {
            "claim_id": "sab_claim_lane6_scope_boundary",
            "text": "SAB agent seeding v1 preserves challenge before standing.",
            "claim_type": "governance",
            "scope": "Local SAB agent seeding v1 API and witness-chain contract.",
            "decision_context": "Whether an outside agent seed may receive provisional standing.",
            "success_conditions": [
                "The seed is stored as canonical source of truth.",
                "A challenge and correction are visible before standing review.",
            ],
            "failure_conditions": [
                "Identity or external reputation grants standing without witness.",
                "Opaque payloads carry authority without an inspectable seed packet.",
            ],
        },
        "claimant_identity": {
            "subject_id": agent.subject_id,
            "identity_ref": agent.identity_ref,
        },
        "operator_backing": {
            "operator_ref": "self",
            "disclosure": "self-attested lane 6 test agent",
            "concentration_attestation": "self_attested",
        },
        "authority_lease": {
            "lease_ref": "sab_lease_lane6_submit_seed",
            "scope": "Submit one public seed packet for witnessed challenge only.",
            "expires_at": _iso(created_at + timedelta(days=30)),
            "revoker": "sab-policy-or-witness-quorum",
            "challenge_path": "/api/v1/seeds/sab_seed_lane6_scope_boundary/challenges",
        },
        "evidence_bundle": [
            {
                "ref": "docs/lanes/sab-agent-seeding-v1/BUILD_SPEC.md",
                "kind": "source",
                "digest": "",
                "notes": "Canonical lane 6 test contract source.",
            }
        ],
        "challenge_plan": {
            "required": True,
            "challenge_window": "P7D",
            "strongest_objections": ["The implementation may publish sparks before canonical seed storage."],
            "challenge_refs": [],
            "falsification_routes": ["Replay the witness chain and compare seed packet hash."],
        },
        "witness_plan": {
            "required_roles": ["challenger", "witness"],
            "minimum_witnesses": 1,
            "non_adjacent_required": True,
            "forbidden_witnesses": [agent.subject_id],
        },
        "build_plan": {
            "artifact_refs": ["tests/test_sab_agent_seeding_e2e.py"],
            "production_grade_definition": "Endpoint rejects all adversarial authority shortcuts.",
        },
        "anti_capture_rules": ["No self-witness for high-impact standing."],
        "commons_return": {
            "mode": "public_receipt",
            "minimum_return": "A queryable witness chain and compost record.",
        },
        "canon_compost_policy": {
            "canon_conditions": ["Challenge path resolved and witness chain verifies."],
            "compost_conditions": ["Blocking challenge sustained without correction."],
            "revalidation_due": _iso(created_at + timedelta(days=90)),
        },
        "privacy_class": "public",
        "created_at": _iso(created_at),
    }
    packet["signature"] = {
        "alg": "ed25519",
        "signer": agent.subject_id,
        "signature": _sign_message(agent.signing_key, _seed_submit_message(packet)),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return packet


def _challenge_packet(
    seed: dict[str, Any],
    challenger: AgentFixture,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    created_at = now or _utc_now()
    packet: dict[str, Any] = {
        "schema": "sab.challenge_packet.v1",
        "challenge_id": "sab_challenge_lane6_scope",
        "target_seed_id": seed["seed_id"],
        "target_claim_id": seed["claim"]["claim_id"],
        "challenger_identity": challenger.identity_ref,
        "challenger_subject_id": challenger.subject_id,
        "quoted_claim_fragment": "preserves challenge before standing",
        "challenge_type": "scope",
        "evidence": [
            {
                "ref": "tests/test_sab_agent_seeding_e2e.py",
                "kind": "review",
                "notes": "Challenge asserts standing must wait for correction and witness.",
            }
        ],
        "proposed_falsification_or_narrowing": "Require a witnessed correction before review.",
        "severity": "blocking",
        "deadline": _iso(created_at + timedelta(days=7)),
        "created_at": _iso(created_at),
    }
    challenge_material = copy.deepcopy(packet)
    challenge_hash = _sha256_obj(challenge_material)
    message = {
        "kind": "sab_challenge_submit",
        "target_seed_id": packet["target_seed_id"],
        "target_claim_id": packet["target_claim_id"],
        "challenge_packet_sha256": challenge_hash,
        "challenger_identity": challenger.identity_ref,
        "created_at": packet["created_at"],
    }
    packet["signature"] = {
        "alg": "ed25519",
        "signer": challenger.subject_id,
        "signature": _sign_message(challenger.signing_key, message),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    return packet


def _witness_event(
    *,
    actor: AgentFixture,
    event_type: str,
    subject_type: str,
    subject_id: str,
    payload: dict[str, Any],
    prev_hash: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    created_at = now or _utc_now()
    event: dict[str, Any] = {
        "schema": "sab.witness_event.v1",
        "event_id": f"sab_witness_{event_type}_{hashlib.sha256(subject_id.encode()).hexdigest()[:12]}",
        "event_type": event_type,
        "actor_identity": actor.identity_ref,
        "actor_subject_id": actor.subject_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "timestamp": _iso(created_at),
        "prev_hash": prev_hash,
        "payload_hash": _sha256_obj(payload),
        "payload_ref": "inline",
        "payload": payload,
        "verification_policy_version": "sab-agent-seeding-v1-test-contract",
    }
    message = {
        "kind": "sab_witness_event",
        "event_type": event_type,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "payload_hash": event["payload_hash"],
        "prev_hash": prev_hash,
        "created_at": event["timestamp"],
    }
    event["signature"] = {
        "alg": "ed25519",
        "signer": actor.subject_id,
        "signature": _sign_message(actor.signing_key, message),
        "canonicalization": "json-sort-keys-compact-v1",
    }
    event["hash"] = _sha256_obj({key: value for key, value in event.items() if key != "hash"})
    return event


def _validate_seed_contract(
    packet: dict[str, Any],
    identities: dict[str, AgentFixture],
    *,
    now: datetime | None = None,
    seen_signatures: dict[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    claim = packet.get("claim") if isinstance(packet.get("claim"), dict) else {}
    authority = packet.get("authority_lease") if isinstance(packet.get("authority_lease"), dict) else {}
    challenge_plan = packet.get("challenge_plan") if isinstance(packet.get("challenge_plan"), dict) else {}

    if not str(claim.get("scope", "")).strip():
        errors.append("claim.scope required")
    if not str(authority.get("scope", "")).strip():
        errors.append("authority_lease.scope required")
    if not str(authority.get("challenge_path", "")).strip():
        errors.append("authority_lease.challenge_path required")
    if not str(authority.get("revoker", "")).strip():
        errors.append("authority_lease.revoker required")
    if challenge_plan.get("required") is not True:
        errors.append("challenge_plan.required must be true")

    expires_at = str(authority.get("expires_at", ""))
    if not expires_at.strip():
        errors.append("authority_lease.expires_at required")
    else:
        try:
            if _parse_iso(expires_at) <= (now or _utc_now()):
                errors.append("authority_lease expired")
        except ValueError:
            errors.append("authority_lease.expires_at invalid")

    signature = packet.get("signature") if isinstance(packet.get("signature"), dict) else {}
    signer = str(signature.get("signer", ""))
    signature_hex = str(signature.get("signature", ""))
    agent = identities.get(signer)
    if not agent:
        errors.append("signature.signer is not a registered identity")
    elif not _verify_agent_message(agent, _seed_submit_message(packet), signature_hex):
        errors.append("signature does not verify sab_seed_submit message")

    if seen_signatures is not None and signature_hex:
        message_hash = _sha256_obj(_seed_submit_message(packet))
        previous_hash = seen_signatures.get(signature_hex)
        if previous_hash is not None and previous_hash != message_hash:
            errors.append("replayed signature over different payload")
        seen_signatures.setdefault(signature_hex, message_hash)

    return errors


def _witness_policy_errors(seed: dict[str, Any], event: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    forbidden = set(seed.get("witness_plan", {}).get("forbidden_witnesses", []))
    if event.get("actor_subject_id") in forbidden:
        errors.append("self-witness forbidden for this seed")
    if event.get("subject_id") != seed.get("seed_id"):
        errors.append("witness subject must be the seed under review")
    return errors


def _standing_review_errors(review: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if review.get("external_attestation_grants_standing") is True:
        errors.append("external identity attestation cannot grant standing")
    if not review.get("challenge_summary"):
        errors.append("standing review requires challenge_summary")
    if not review.get("witness_refs"):
        errors.append("standing review requires witness_refs")
    return errors


def _opaque_payload_errors(payload: dict[str, Any]) -> list[str]:
    if payload.get("encoding") != "opaque-agent-language":
        return []
    declared_effects = set(payload.get("declared_effects", []))
    authority_effects = {"grant_standing", "grant_authority", "deploy", "payment", "runtime_mutation"}
    if declared_effects & authority_effects and not payload.get("inspectable_seed_packet_ref"):
        return ["opaque payload cannot carry authority without inspectable seed packet ref"]
    return []


def _verify_chain(events: list[dict[str, Any]]) -> tuple[bool, str]:
    prev_hash = "0" * 64
    for event in events:
        if event["prev_hash"] != prev_hash:
            return False, event["hash"]
        if event["hash"] != _sha256_obj({key: value for key, value in event.items() if key != "hash"}):
            return False, event["hash"]
        prev_hash = event["hash"]
    return True, prev_hash


@pytest.fixture
def sab_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "sab_agent_seeding.db"
    key_path = tmp_path / ".sab_agent_seeding_system_ed25519.key"
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(db_path))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(key_path))

    for mod_name in list(sys.modules):
        if mod_name == "agora" or mod_name.startswith("agora."):
            del sys.modules[mod_name]

    try:
        return importlib.import_module("agora.app")
    except ImportError as exc:
        pytest.skip(f"agora.app runtime dependency missing for live API tests: {exc}")
    except RuntimeError as exc:
        if "PyNaCl" in str(exc):
            pytest.skip("agora.app requires PyNaCl for live API tests in this environment")
        raise


@pytest.fixture
def client(sab_app):
    with TestClient(sab_app.app) as test_client:
        yield test_client


def _xfail_if_endpoint_missing(response, contract: EndpointContract) -> None:
    if response.status_code in {404, 405}:
        pytest.xfail(f"{contract.method} {contract.path} is not implemented yet")


def _v1_register_or_xfail(client: TestClient, agent: AgentFixture) -> dict[str, Any]:
    contract = API_CONTRACTS["register_agent"]
    response = client.post(
        contract.path,
        json={
            "schema": "sab.agent_identity.v1",
            "display_name": agent.label,
            "identity_rail": "ed25519",
            "public_key": agent.public_key,
            "controller": "self",
            "operator_backing": {
                "operator_id": agent.subject_id,
                "operator_kind": "agent",
                "disclosure": "lane 6 local test agent",
                "backing_count_attestation": "self_attested",
            },
            "external_attestations": [],
        },
    )
    _xfail_if_endpoint_missing(response, contract)
    assert response.status_code == contract.success_status, response.text
    body = response.json()
    assert contract.required_response_keys <= set(body)
    return body


def _post_or_xfail(client: TestClient, contract: EndpointContract, path: str, payload: dict[str, Any]):
    response = client.post(path, json=payload)
    _xfail_if_endpoint_missing(response, contract)
    return response


def test_contract_matrix_names_all_lane6_endpoints_and_response_keys() -> None:
    assert {contract.path for contract in API_CONTRACTS.values()} == {
        "/api/v1/agents/register",
        "/api/v1/seeds",
        "/api/v1/seeds/{seed_id}",
        "/api/v1/seeds/{seed_id}/chain",
        "/api/v1/seeds/{seed_id}/challenges",
        "/api/v1/challenges/{challenge_id}/respond",
        "/api/v1/standing/review",
    }
    for contract in API_CONTRACTS.values():
        assert contract.method in {"GET", "POST"}
        assert contract.success_status in {200, 201}
        assert contract.required_response_keys


def test_seed_submit_signature_contract_rejects_tampering() -> None:
    agent = _agent("agent-a")
    packet = _seed_packet(agent)
    identities = {agent.subject_id: agent}

    assert _validate_seed_contract(packet, identities) == []

    tampered = copy.deepcopy(packet)
    tampered["claim"]["text"] = "SAB agent seeding v1 skips challenge before standing."
    assert "signature does not verify sab_seed_submit message" in _validate_seed_contract(
        tampered,
        identities,
    )


@pytest.mark.parametrize(
    ("case_name", "mutate", "expected_error"),
    [
        (
            "missing claim scope",
            lambda packet: packet["claim"].update({"scope": ""}),
            "claim.scope required",
        ),
        (
            "missing authority scope",
            lambda packet: packet["authority_lease"].update({"scope": ""}),
            "authority_lease.scope required",
        ),
        (
            "missing challenge path",
            lambda packet: packet["authority_lease"].pop("challenge_path"),
            "authority_lease.challenge_path required",
        ),
        (
            "expired authority lease",
            lambda packet: packet["authority_lease"].update(
                {"expires_at": _iso(_utc_now() - timedelta(minutes=1))}
            ),
            "authority_lease expired",
        ),
        (
            "invalid signature",
            lambda packet: packet["signature"].update({"signature": "00" * 64}),
            "signature does not verify sab_seed_submit message",
        ),
        (
            "challenge plan disabled",
            lambda packet: packet["challenge_plan"].update({"required": False}),
            "challenge_plan.required must be true",
        ),
    ],
)
def test_seed_packet_adversarial_contract_rejections(
    case_name: str,
    mutate: Callable[[dict[str, Any]], None],
    expected_error: str,
) -> None:
    del case_name
    agent = _agent("agent-a")
    packet = _seed_packet(agent)
    mutate(packet)

    errors = _validate_seed_contract(packet, {agent.subject_id: agent})
    assert expected_error in errors


def test_replayed_seed_signature_over_different_payload_is_visible() -> None:
    agent = _agent("agent-a")
    packet = _seed_packet(agent)
    seen: dict[str, str] = {}
    assert _validate_seed_contract(packet, {agent.subject_id: agent}, seen_signatures=seen) == []

    replayed = copy.deepcopy(packet)
    replayed["claim"]["scope"] = "A different scope using the same signature."
    errors = _validate_seed_contract(replayed, {agent.subject_id: agent}, seen_signatures=seen)

    assert "replayed signature over different payload" in errors
    assert "signature does not verify sab_seed_submit message" in errors


def test_self_witness_where_forbidden_is_rejected_by_contract() -> None:
    agent_a = _agent("agent-a")
    seed = _seed_packet(agent_a)
    event = _witness_event(
        actor=agent_a,
        event_type="affirm",
        subject_type="seed",
        subject_id=seed["seed_id"],
        payload={"reason": "claimant tries to witness own high-impact seed"},
        prev_hash="0" * 64,
    )

    assert _witness_policy_errors(seed, event) == ["self-witness forbidden for this seed"]


def test_external_identity_cannot_grant_standing_contract() -> None:
    review_request = {
        "subject_seed_id": "sab_seed_lane6_scope_boundary",
        "external_attestations": [
            {
                "provider": "moltbook",
                "verified_owner": True,
                "karma": 99999,
            }
        ],
        "external_attestation_grants_standing": True,
        "challenge_summary": [],
        "witness_refs": [],
    }

    assert _standing_review_errors(review_request) == [
        "external identity attestation cannot grant standing",
        "standing review requires challenge_summary",
        "standing review requires witness_refs",
    ]


def test_opaque_payload_cannot_carry_authority_without_inspectable_seed_packet() -> None:
    payload = {
        "encoding": "opaque-agent-language",
        "blob": "compact-uninspectable-agent-state",
        "declared_effects": ["grant_standing", "runtime_mutation"],
    }

    assert _opaque_payload_errors(payload) == [
        "opaque payload cannot carry authority without inspectable seed packet ref"
    ]


def test_helper_level_e2e_witness_chain_to_provisional_standing_contract() -> None:
    agent_a = _agent("agent-a")
    agent_b = _agent("agent-b")
    seed = _seed_packet(agent_a)
    challenge = _challenge_packet(seed, agent_b)

    submit_event = _witness_event(
        actor=agent_a,
        event_type="submit",
        subject_type="seed",
        subject_id=seed["seed_id"],
        payload={"seed_packet_sha256": _seed_packet_sha256(seed), "spark_projection_id": 1},
        prev_hash="0" * 64,
    )
    challenge_event = _witness_event(
        actor=agent_b,
        event_type="challenge",
        subject_type="seed",
        subject_id=seed["seed_id"],
        payload={"challenge_id": challenge["challenge_id"], "severity": "blocking"},
        prev_hash=submit_event["hash"],
    )
    correction_payload = {
        "challenge_id": challenge["challenge_id"],
        "correction": "Standing review must require witnessed challenge and scoped reliance.",
        "corrected_seed_sha256": _seed_packet_sha256(seed),
    }
    correction_event = _witness_event(
        actor=agent_a,
        event_type="correction",
        subject_type="challenge",
        subject_id=challenge["challenge_id"],
        payload=correction_payload,
        prev_hash=challenge_event["hash"],
    )
    standing_event = _witness_event(
        actor=agent_b,
        event_type="standing_issued",
        subject_type="seed",
        subject_id=seed["seed_id"],
        payload={
            "standing_id": "sab_standing_lane6_provisional",
            "scope": seed["claim"]["scope"],
            "status": "provisional",
            "challenge_refs": [challenge["challenge_id"]],
            "witness_refs": [submit_event["event_id"], challenge_event["event_id"]],
        },
        prev_hash=correction_event["hash"],
    )

    verified, head = _verify_chain([submit_event, challenge_event, correction_event, standing_event])
    assert verified is True
    assert head == standing_event["hash"]
    assert _witness_policy_errors(seed, standing_event) == []

    standing_review = {
        "subject_seed_id": seed["seed_id"],
        "challenge_summary": [{"challenge_id": challenge["challenge_id"], "resolution": "corrected"}],
        "witness_refs": [submit_event["event_id"], challenge_event["event_id"], standing_event["event_id"]],
        "external_attestation_grants_standing": False,
    }
    assert _standing_review_errors(standing_review) == []


def test_api_v1_seed_challenge_correction_standing_e2e_contract(client: TestClient) -> None:
    agent_a = _agent("agent-a")
    agent_b = _agent("agent-b")
    _v1_register_or_xfail(client, agent_a)
    _v1_register_or_xfail(client, agent_b)

    seed = _seed_packet(agent_a)
    seed_response = _post_or_xfail(client, API_CONTRACTS["submit_seed"], "/api/v1/seeds", seed)
    assert seed_response.status_code == API_CONTRACTS["submit_seed"].success_status, seed_response.text
    seed_body = seed_response.json()
    assert API_CONTRACTS["submit_seed"].required_response_keys <= set(seed_body)
    assert seed_body["accepted"] is True
    assert seed_body["state"] in {"pending_seed", "challenge_window_open"}
    assert seed_body["spark_projection_id"] is not None

    seed_id = str(seed_body["seed_id"])
    chain = client.get(f"/api/v1/seeds/{seed_id}/chain")
    _xfail_if_endpoint_missing(chain, API_CONTRACTS["fetch_seed_chain"])
    assert chain.status_code == API_CONTRACTS["fetch_seed_chain"].success_status, chain.text
    chain_body = chain.json()
    assert API_CONTRACTS["fetch_seed_chain"].required_response_keys <= set(chain_body)
    assert chain_body["verified"] is True
    assert [event["event_type"] for event in chain_body["events"][:1]] == ["submit"]

    challenge = _challenge_packet(seed, agent_b)
    challenge_response = _post_or_xfail(
        client,
        API_CONTRACTS["challenge_seed"],
        f"/api/v1/seeds/{seed_id}/challenges",
        challenge,
    )
    assert challenge_response.status_code == API_CONTRACTS["challenge_seed"].success_status
    challenge_body = challenge_response.json()
    assert API_CONTRACTS["challenge_seed"].required_response_keys <= set(challenge_body)
    assert challenge_body["state"] == "challenged"

    response_payload = {
        "schema": "sab.challenge_response.v1",
        "challenge_id": challenge_body["challenge_id"],
        "responder_identity": agent_a.identity_ref,
        "response_type": "correction",
        "correction": "Narrowed to local API contract only.",
        "signature": _sign_message(
            agent_a.signing_key,
            {
                "kind": "sab_challenge_response",
                "challenge_id": challenge_body["challenge_id"],
                "responder_identity": agent_a.identity_ref,
                "response_sha256": hashlib.sha256(b"Narrowed to local API contract only.").hexdigest(),
            },
        ),
    }
    response = _post_or_xfail(
        client,
        API_CONTRACTS["respond_challenge"],
        f"/api/v1/challenges/{challenge_body['challenge_id']}/respond",
        response_payload,
    )
    assert response.status_code == API_CONTRACTS["respond_challenge"].success_status
    assert API_CONTRACTS["respond_challenge"].required_response_keys <= set(response.json())

    review_payload = {
        "subject_seed_id": seed_id,
        "requested_state": "provisional",
        "scope": seed["claim"]["scope"],
        "challenge_summary": [{"challenge_id": challenge_body["challenge_id"], "resolution": "corrected"}],
        "witness_refs": [response.json()["witness_head"]],
    }
    standing = _post_or_xfail(
        client,
        API_CONTRACTS["standing_review"],
        "/api/v1/standing/review",
        review_payload,
    )
    assert standing.status_code == API_CONTRACTS["standing_review"].success_status
    standing_body = standing.json()
    assert API_CONTRACTS["standing_review"].required_response_keys <= set(standing_body)
    assert standing_body["state"] in {"standing_active", "compost"}


@pytest.mark.parametrize(
    ("case_name", "mutate", "expected_statuses"),
    [
        ("missing_scope", lambda packet: packet["claim"].update({"scope": ""}), {400, 422}),
        (
            "missing_challenge_path",
            lambda packet: packet["authority_lease"].pop("challenge_path"),
            {400, 422},
        ),
        (
            "expired_authority_lease",
            lambda packet: packet["authority_lease"].update(
                {"expires_at": _iso(_utc_now() - timedelta(minutes=1))}
            ),
            {400, 403, 422},
        ),
        ("invalid_signature", lambda packet: packet["signature"].update({"signature": "00" * 64}), {400, 401}),
    ],
)
def test_api_v1_seed_submit_adversarial_rejection_contract(
    client: TestClient,
    case_name: str,
    mutate: Callable[[dict[str, Any]], None],
    expected_statuses: set[int],
) -> None:
    del case_name
    agent = _agent("agent-a")
    _v1_register_or_xfail(client, agent)
    packet = _seed_packet(agent)
    mutate(packet)

    response = _post_or_xfail(client, API_CONTRACTS["submit_seed"], "/api/v1/seeds", packet)
    assert response.status_code in expected_statuses, response.text
    assert response.json().get("detail")
