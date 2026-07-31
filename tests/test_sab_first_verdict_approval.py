from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from agora.sab_artifact_verdict import canonical_sha256
from agora.sab_first_verdict_approval import (
    BUILD_A_CLOSEOUT_CANONICAL_SHA256,
    BUILD_A_CLOSEOUT_SHA256,
    BUILD_A_MERGE_COMMIT,
    BUILD_A_MERGE_TREE,
    SIGNING_INSTRUCTION,
    SIGNING_INSTRUCTION_SHA256,
    ApprovalPacketError,
    CeremonyApprovalEvidence,
    bind_operator_approval_evidence,
    build_operator_approval_packet,
    canonical_packet_json,
    render_operator_approval_markdown,
    short_display_checksum,
    verify_operator_approval_packet,
)
from agora.sab_first_verdict_ceremony import (
    StructurallyCompleteAwaitingAuthority,
)
from tests.test_sab_attended_ceremony_e2e import (
    ARTIFACT_ID,
    CASE_ID,
    build_attended_ceremony_fixture,
)


@pytest.fixture(scope="module")
def complete_fixture() -> dict[str, Any]:
    return build_attended_ceremony_fixture()


def _closeout_bytes(
    complete_fixture: dict[str, Any],
    *path_and_value: Any,
) -> bytes:
    payload = json.loads(complete_fixture["build_a_closeout_bytes"])
    *path, value = path_and_value
    target = payload
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def test_packet_is_deterministic_unsigned_and_non_authorizing(
    complete_fixture: dict[str, Any],
) -> None:
    first = complete_fixture["packet"]
    second = build_operator_approval_packet(complete_fixture["evidence"])

    assert canonical_packet_json(first) == canonical_packet_json(second)
    assert first["status"] == "awaiting_operator_countersign"
    assert first["operator_signature"] is None
    assert first["effect_executable"] is False
    assert first["live_authority_created"] is False
    assert first["signing_instruction"] == SIGNING_INSTRUCTION
    assert first["signing_instruction_sha256"] == SIGNING_INSTRUCTION_SHA256
    assert first["short_display_checksum"] == short_display_checksum(
        first["approval_payload_sha256"]
    )

    verified = verify_operator_approval_packet(first)
    assert verified["packet_integrity_valid"] is True
    assert verified["evidence_reverified"] is False
    assert verified["evidence_freshness_reverified"] is False
    assert verified["operator_signing_eligible"] is False
    assert verified["live_authority_created"] is False
    assert verified["effect_executable"] is False


def test_payload_exposes_distinct_code_roots_closed_proposals_and_trust_sets(
    complete_fixture: dict[str, Any],
) -> None:
    payload = complete_fixture["packet"]["approval_payload"]
    code = payload["code"]
    assert code["runtime_commit_sha"] == "a" * 40
    assert code["build_a_merge_commit"] == BUILD_A_MERGE_COMMIT
    assert code["runtime_commit_sha"] != code["build_a_merge_commit"]
    assert code["build_a_merge_tree"] == BUILD_A_MERGE_TREE
    assert code["build_a_closeout_sha256"] == BUILD_A_CLOSEOUT_SHA256
    assert (
        code["build_a_closeout_canonical_sha256"] == BUILD_A_CLOSEOUT_CANONICAL_SHA256
    )
    assert (
        hashlib.sha256(complete_fixture["build_a_closeout_bytes"]).hexdigest()
        == BUILD_A_CLOSEOUT_SHA256
    )
    assert (
        canonical_sha256(json.loads(complete_fixture["build_a_closeout_bytes"]))
        == BUILD_A_CLOSEOUT_CANONICAL_SHA256
    )

    authority = payload["authority_evidence"]
    assert tuple(authority["requested_effects"]) == (
        "challenge:resolve",
        "seed:supersede",
    )
    assert "reported_result" not in authority
    assert "reported_live_eligible" not in authority
    assert ("Authorized" + "<Live>") not in json.dumps(payload, sort_keys=True)

    proposals = {
        item["proposal"]["effect_type"]: item for item in payload["proposed_effects"]
    }
    assert set(proposals) == {"challenge:resolve", "seed:supersede"}
    assert proposals["challenge:resolve"]["proposal"]["target_id"] == CASE_ID
    assert proposals["seed:supersede"]["proposal"]["target_id"] == ARTIFACT_ID
    for item in proposals.values():
        proposal = item["proposal"]
        assert proposal["schema_version"] == "sab.ceremony_effect_proposal.v1"
        assert proposal["effect_executable"] is False
        assert proposal["standing_effect"] == "none"
        assert item["proposal_sha256"] == canonical_sha256(proposal)

    anchors = payload["trust_anchors"]
    ceremony = complete_fixture["ceremony"]
    assert (
        tuple(anchors["frozen_trust_anchor_set_sha256s"])
        == ceremony["frozen_readiness"].trust_anchor_set_sha256s
    )
    assert (
        tuple(anchors["live_trust_anchor_set_sha256s"])
        == ceremony["live_readiness"].trust_anchor_set_sha256s
    )


def test_markdown_requires_full_digest_and_shows_exact_evidence_roots(
    complete_fixture: dict[str, Any],
) -> None:
    packet = complete_fixture["packet"]
    rendered = render_operator_approval_markdown(packet)

    assert packet["approval_payload_sha256"] in rendered
    assert packet["short_display_checksum"] in rendered
    assert SIGNING_INSTRUCTION in rendered
    assert "Build A merge commit" in rendered
    assert "Build B runtime commit" in rendered
    assert "Out-of-band trust-anchor set digests" in rendered
    for digest in packet["approval_payload"]["trust_anchors"][
        "live_trust_anchor_set_sha256s"
    ]:
        assert digest in rendered
    for item in packet["approval_payload"]["proposed_effects"]:
        assert item["proposal_sha256"] in rendered
        assert item["proposal"]["target_id"] in rendered

    def sha256_leaves(value: Any) -> set[str]:
        if isinstance(value, dict):
            return set().union(*(sha256_leaves(child) for child in value.values()))
        if isinstance(value, list):
            return set().union(*(sha256_leaves(child) for child in value))
        if (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        ):
            return {value}
        return set()

    for digest in sha256_leaves(packet["approval_payload"]):
        assert digest in rendered
    assert "integrity_only_not_signable" in rendered
    assert "Operator signing eligible from this view:** `false`" in rendered
    assert "do not sign from this persisted view" in rendered
    assert "Full canonical digest to sign" not in rendered
    assert ("Authorized" + "<Live>") not in rendered


def test_persisted_freshness_is_explicitly_non_authorizing(
    complete_fixture: dict[str, Any],
) -> None:
    packet = complete_fixture["packet"]
    before = verify_operator_approval_packet(
        packet,
        checked_at=datetime(2026, 7, 31, 23, 59, 59, tzinfo=timezone.utc),
    )
    during = verify_operator_approval_packet(
        packet,
        checked_at=datetime(2026, 8, 1, 0, 1, tzinfo=timezone.utc),
    )
    expired = verify_operator_approval_packet(
        packet,
        checked_at=datetime(2026, 8, 1, 0, 10, tzinfo=timezone.utc),
    )

    assert before["evidence_time_state"] == "not_yet_prepared"
    assert during["evidence_time_state"] == "within_recorded_window_unreverified"
    assert expired["evidence_time_state"] == "expired"
    assert all(
        result["operator_signing_eligible"] is False
        and result["evidence_freshness_reverified"] is False
        for result in (before, during, expired)
    )


def test_raw_mapping_and_forged_evidence_cannot_construct_packet(
    complete_fixture: dict[str, Any],
) -> None:
    with pytest.raises(TypeError, match="evaluator-constructed"):
        CeremonyApprovalEvidence()

    with pytest.raises(ApprovalPacketError) as raised:
        build_operator_approval_packet({})  # type: ignore[arg-type]
    assert raised.value.code == "approval_evidence_not_locally_bound"

    evidence = complete_fixture["evidence"]
    forged = object.__new__(CeremonyApprovalEvidence)
    object.__setattr__(forged, "_payload", evidence._payload)
    object.__setattr__(forged, "_payload_sha256", evidence._payload_sha256)
    with pytest.raises(ApprovalPacketError) as raised:
        build_operator_approval_packet(forged)
    assert raised.value.code == "approval_evidence_not_locally_bound"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signing_instruction", "Sign the short checksum."),
        ("signing_instruction_sha256", "0" * 64),
    ],
)
def test_signing_instruction_is_immutable(
    complete_fixture: dict[str, Any], field: str, value: str
) -> None:
    packet = copy.deepcopy(complete_fixture["packet"])
    packet[field] = value
    if field == "signing_instruction":
        packet["signing_instruction_sha256"] = hashlib.sha256(
            value.encode()
        ).hexdigest()
    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(packet)
    assert raised.value.code == "signing_instruction_mismatch"


def test_payload_tampering_and_extra_fields_fail_closed(
    complete_fixture: dict[str, Any],
) -> None:
    changed = copy.deepcopy(complete_fixture["packet"])
    changed["approval_payload"]["bench"]["attended_manifest_sha256"] = "0" * 64
    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(changed)
    assert raised.value.code == "packet_digest_mismatch"

    proposal = copy.deepcopy(complete_fixture["packet"])
    proposal["approval_payload"]["proposed_effects"][0]["proposal"]["target_id"] = (
        "caller-selected-target"
    )
    proposal_body = proposal["approval_payload"]["proposed_effects"][0]["proposal"]
    proposal["approval_payload"]["proposed_effects"][0]["proposal_sha256"] = (
        canonical_sha256(proposal_body)
    )
    proposal["approval_payload_sha256"] = canonical_sha256(proposal["approval_payload"])
    proposal["short_display_checksum"] = short_display_checksum(
        proposal["approval_payload_sha256"]
    )
    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(proposal)
    assert raised.value.code == "approval_payload_invalid"

    extra = copy.deepcopy(complete_fixture["packet"])
    extra["approval_hint"] = "approve"
    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(extra)
    assert raised.value.code == "packet_shape_invalid"


def test_rehashed_zero_runtime_commit_fails_closed(
    complete_fixture: dict[str, Any],
) -> None:
    packet = copy.deepcopy(complete_fixture["packet"])
    packet["approval_payload"]["code"]["runtime_commit_sha"] = "0" * 40
    packet["approval_payload_sha256"] = canonical_sha256(packet["approval_payload"])
    packet["short_display_checksum"] = short_display_checksum(
        packet["approval_payload_sha256"]
    )

    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(packet)
    assert raised.value.code == "approval_payload_invalid"


def test_rehashed_cross_field_contradiction_fails_closed(
    complete_fixture: dict[str, Any],
) -> None:
    packet = copy.deepcopy(complete_fixture["packet"])
    effect = packet["approval_payload"]["proposed_effects"][0]
    effect["proposal"]["compiled_outcome_sha256"] = "f" * 64
    effect["proposal_sha256"] = canonical_sha256(effect["proposal"])
    idempotency_sha256 = canonical_sha256(
        {
            "ceremony_id": packet["approval_payload"]["ceremony_id"],
            "effect_type": effect["proposal"]["effect_type"],
            "proposal_sha256": effect["proposal_sha256"],
            "write_lease_sha256": packet["approval_payload"]["maintenance"][
                "write_lease_sha256"
            ],
        }
    )
    effect["idempotency_key"] = f"sab-{idempotency_sha256[:32]}"
    packet["approval_payload_sha256"] = canonical_sha256(packet["approval_payload"])
    packet["short_display_checksum"] = short_display_checksum(
        packet["approval_payload_sha256"]
    )

    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(packet)
    assert raised.value.code == "approval_payload_invalid"


def test_rehashed_requested_effect_contradiction_fails_closed(
    complete_fixture: dict[str, Any],
) -> None:
    packet = copy.deepcopy(complete_fixture["packet"])
    packet["approval_payload"]["authority_evidence"]["requested_effects"] = [
        "challenge:resolve"
    ]
    packet["approval_payload_sha256"] = canonical_sha256(packet["approval_payload"])
    packet["short_display_checksum"] = short_display_checksum(
        packet["approval_payload_sha256"]
    )

    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(packet)
    assert raised.value.code == "approval_payload_invalid"


def test_rehashed_decision_effect_contradiction_fails_closed(
    complete_fixture: dict[str, Any],
) -> None:
    packet = copy.deepcopy(complete_fixture["packet"])
    packet["approval_payload"]["bench"]["compiled_decision"] = "canon"
    packet["approval_payload_sha256"] = canonical_sha256(packet["approval_payload"])
    packet["short_display_checksum"] = short_display_checksum(
        packet["approval_payload_sha256"]
    )

    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(packet)
    assert raised.value.code == "approval_payload_invalid"


def test_serialized_readiness_and_nonterminal_outcome_are_rejected(
    complete_fixture: dict[str, Any],
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    readiness = arguments["frozen_readiness"]
    arguments["frozen_readiness"] = (
        StructurallyCompleteAwaitingAuthority.model_validate(
            readiness.canonical_payload()
        )
    )
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == "frozen_execution_facts_not_locally_verified"

    arguments = dict(complete_fixture["binding_arguments"])
    arguments["compiled_outcome"] = arguments["compiled_outcome"].model_copy(
        update={
            "terminality": "no_terminal_verdict",
            "decision": "no_terminal_verdict",
            "requested_effects": (),
        }
    )
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == "compiled_outcome_binding_mismatch"


@pytest.mark.parametrize(
    ("argument", "update", "expected_code"),
    [
        (
            "bench_manifest",
            {"terminality_rule_sha256": "f" * 64},
            "frozen_execution_facts_receipt_set_mismatch",
        ),
        (
            "cost_envelope",
            {"spend_cap_microusd": 99_999},
            "cost_approval_signature_invalid",
        ),
        (
            "live_write_lease",
            {"allowed_effects": ("challenge:resolve",)},
            "live_write_lease_signature_invalid",
        ),
    ],
)
def test_binder_rejects_roster_cost_and_lease_mismatches(
    complete_fixture: dict[str, Any],
    argument: str,
    update: dict[str, Any],
    expected_code: str,
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    arguments[argument] = arguments[argument].model_copy(update=update)
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == expected_code


def test_compiler_authority_must_be_local_and_rederived(
    complete_fixture: dict[str, Any],
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    authority = arguments["compiler_authority"]
    arguments["compiler_authority"] = type(authority).model_validate(
        authority.canonical_payload()
    )
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == "compiled_outcome_reverification_failed"


@pytest.mark.parametrize("offset", [timedelta(seconds=-1), timedelta(seconds=1)])
def test_compiled_outcome_must_be_inside_the_preparation_interval(
    complete_fixture: dict[str, Any],
    offset: timedelta,
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    boundary = (
        arguments["frozen_readiness"].checked_at
        if offset < timedelta(0)
        else arguments["prepared_at"]
    )
    arguments["compiled_outcome"] = arguments["compiled_outcome"].model_copy(
        update={"compiled_at": boundary + offset}
    )
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == "compiled_outcome_time_invalid"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("github_ci", "security"), "FAIL"),
        (("pull_request", "state"), "OPEN"),
        (("terminal_claim", "live_mutations"), 1),
        (("pull_request", "merge_commit"), "a" * 40),
    ],
)
def test_mutated_build_a_closeout_fails_pinned_provenance(
    complete_fixture: dict[str, Any],
    path: tuple[str, ...],
    value: Any,
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    arguments["build_a_closeout_bytes"] = _closeout_bytes(
        complete_fixture, *path, value
    )
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == "build_a_closeout_provenance_mismatch"


def test_arbitrary_green_build_a_closeout_fails_pinned_provenance(
    complete_fixture: dict[str, Any],
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    arguments["build_a_closeout_bytes"] = _closeout_bytes(
        complete_fixture, "github_ci", "run_id", 30_643_074_766
    )
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == "build_a_closeout_provenance_mismatch"


def test_build_a_closeout_duplicate_json_key_fails_closed(
    complete_fixture: dict[str, Any],
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    arguments["build_a_closeout_bytes"] = b'{"schema":"first","schema":"second"}'
    with pytest.raises(ApprovalPacketError) as raised:
        bind_operator_approval_evidence(**arguments)
    assert raised.value.code == "build_a_closeout_duplicate_key"


def test_arbitrary_effect_payload_is_not_an_approval_input(
    complete_fixture: dict[str, Any],
) -> None:
    arguments = dict(complete_fixture["binding_arguments"])
    arguments["effect_payloads"] = {
        "seed:supersede": {"target_id": "caller-selected-target"}
    }
    with pytest.raises(TypeError, match="effect_payloads"):
        bind_operator_approval_evidence(**arguments)


@pytest.mark.parametrize("field", ["private_key", "api_key", "access_token"])
def test_secret_bearing_packet_fields_are_rejected_without_echoing_values(
    complete_fixture: dict[str, Any], field: str
) -> None:
    marker = "DO-NOT-ECHO-SECRET-MARKER"
    packet = copy.deepcopy(complete_fixture["packet"])
    packet["approval_payload"][field] = marker
    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(packet)
    assert raised.value.code == "secret_field_forbidden"
    assert marker not in str(raised.value)


def test_cli_only_verifies_and_renders_existing_packet(
    complete_fixture: dict[str, Any], tmp_path: Path
) -> None:
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(complete_fixture["packet"]), encoding="utf-8")
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "sab_attended_ceremony.py"
    )

    verified = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify-unsigned-packet",
            "--packet",
            str(packet_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert verified.returncode == 0, verified.stderr
    verification = json.loads(verified.stdout)
    assert verification["packet_integrity_valid"] is True
    assert verification["evidence_reverified"] is False
    assert verification["operator_signing_eligible"] is False
    assert verification["live_authority_created"] is False

    rendered = subprocess.run(
        [
            sys.executable,
            str(script),
            "render-unsigned-packet",
            "--packet",
            str(packet_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rendered.returncode == 0, rendered.stderr
    assert "integrity_only_not_signable" in rendered.stdout
    assert "Full canonical digest to sign" not in rendered.stdout
    assert SIGNING_INSTRUCTION in rendered.stdout

    duplicate_path = tmp_path / "duplicate-packet.json"
    duplicate_path.write_text('{"status":"first","status":"second"}', encoding="utf-8")
    duplicate = subprocess.run(
        [
            sys.executable,
            str(script),
            "verify-unsigned-packet",
            "--packet",
            str(duplicate_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert duplicate.returncode == 2
    assert json.loads(duplicate.stdout)["error"] == "approval_input_duplicate_key"

    prepare = subprocess.run(
        [
            sys.executable,
            str(script),
            "prepare-unsigned-packet",
            "--input",
            str(packet_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert prepare.returncode == 2
    assert "invalid choice" in prepare.stderr
