from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from agora.sab_first_verdict_approval import (
    ApprovalPacketError,
    build_operator_approval_packet,
    canonical_packet_json,
    render_operator_approval_markdown,
    short_display_checksum,
    verify_operator_approval_packet,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
GIT_A = "a" * 40
GIT_B = "b" * 40


def _envelope() -> dict:
    return {
        "schema_version": "sab.ceremony_approval_envelope.v1",
        "ceremony_id": "ceremony-fixture-1",
        "prepared_at": "2026-07-31T15:00:00Z",
        "requested_scope": "Live",
        "code": {
            "commit_sha": GIT_A,
            "tree_sha": GIT_B,
            "build_a_closeout_sha256": SHA_A,
        },
        "authority": {
            "case_id": "case-fixture-1",
            "case_sha256": SHA_A,
            "policy_sha256": SHA_B,
            "authority_evaluation_sha256": SHA_C,
            "authority_result": "Authorized<Live>",
        },
        "bench": {
            "frozen_manifest_sha256": SHA_A,
            "provider_probe_bundle_sha256": SHA_B,
            "cost_envelope_sha256": SHA_C,
            "transcript_head_sha256": SHA_A,
            "final_ballot_set_sha256": SHA_B,
            "compiled_outcome_kind": "verdict",
            "compiled_outcome_sha256": SHA_C,
        },
        "maintenance": {
            "runtime_attestation_sha256": SHA_A,
            "service_state_snapshot_sha256": SHA_B,
            "tick_exclusion_receipt_sha256": SHA_C,
            "restoration_plan_sha256": SHA_A,
            "write_lease_sha256": SHA_B,
        },
        "proposed_effect": {
            "effect_type": "seed:supersede",
            "effect_payload_sha256": SHA_C,
            "idempotency_key": "first-verdict-fixture-1",
        },
        "operator_limits": {
            "public_key_fingerprint": SHA_A,
            "spend_cap_usd": "12.50",
            "automatic_top_up": False,
        },
    }


def test_packet_is_deterministic_unsigned_and_non_authorizing() -> None:
    first = build_operator_approval_packet(_envelope())
    second = build_operator_approval_packet(copy.deepcopy(_envelope()))

    assert canonical_packet_json(first) == canonical_packet_json(second)
    assert first["status"] == "awaiting_operator_countersign"
    assert first["operator_signature"] is None
    assert first["effect_executable"] is False
    assert first["short_display_checksum"] == short_display_checksum(
        first["approval_payload_sha256"]
    )

    verified = verify_operator_approval_packet(first)
    assert verified["valid"] is True
    assert verified["live_authority_created"] is False
    assert verified["effect_executable"] is False


def test_markdown_requires_full_digest_and_demotes_short_checksum() -> None:
    packet = build_operator_approval_packet(_envelope())
    rendered = render_operator_approval_markdown(packet)

    assert packet["approval_payload_sha256"] in rendered
    assert packet["short_display_checksum"] in rendered
    assert "Do not sign the short checksum" in rendered
    assert "non-authorizing" in rendered
    assert "awaiting_operator_countersign" in rendered


def test_payload_tampering_and_extra_packet_fields_fail_closed() -> None:
    packet = build_operator_approval_packet(_envelope())
    changed = copy.deepcopy(packet)
    changed["approval_payload"]["operator_limits"]["spend_cap_usd"] = "99.00"
    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(changed)
    assert raised.value.code == "packet_digest_mismatch"

    extra = copy.deepcopy(packet)
    extra["approval_hint"] = "approve"
    with pytest.raises(ApprovalPacketError) as raised:
        verify_operator_approval_packet(extra)
    assert raised.value.code == "packet_shape_invalid"


def test_non_live_authority_cannot_enter_approval_contract() -> None:
    envelope = _envelope()
    envelope["authority"]["authority_result"] = "AdvisoryOnly"
    with pytest.raises(ValidationError):
        build_operator_approval_packet(envelope)


@pytest.mark.parametrize("field", ["private_key", "api_key", "access_token"])
def test_secret_bearing_fields_are_rejected_without_echoing_values(field: str) -> None:
    marker = "DO-NOT-ECHO-SECRET-MARKER"
    envelope = _envelope()
    envelope["operator_limits"][field] = marker
    with pytest.raises(ApprovalPacketError) as raised:
        build_operator_approval_packet(envelope)
    assert raised.value.code == "secret_field_forbidden"
    assert marker not in str(raised.value)


def test_cli_prepares_markdown_and_verifies_canonical_packet(tmp_path: Path) -> None:
    input_path = tmp_path / "envelope.json"
    packet_path = tmp_path / "packet.json"
    input_path.write_text(json.dumps(_envelope()), encoding="utf-8")
    script = (
        Path(__file__).resolve().parents[1] / "scripts" / "sab_attended_ceremony.py"
    )

    prepared = subprocess.run(
        [
            sys.executable,
            str(script),
            "prepare-unsigned-packet",
            "--input",
            str(input_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert prepared.returncode == 0, prepared.stderr
    packet_path.write_text(prepared.stdout, encoding="utf-8")

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
    assert json.loads(verified.stdout)["live_authority_created"] is False

    markdown = subprocess.run(
        [
            sys.executable,
            str(script),
            "prepare-unsigned-packet",
            "--input",
            str(input_path),
            "--format",
            "markdown",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert markdown.returncode == 0, markdown.stderr
    assert "Full canonical digest to sign" in markdown.stdout
