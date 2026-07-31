from __future__ import annotations

import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.sab_language_womb_tick import build_seed_packet, run_tick, utc_now  # noqa: E402
from tests.test_sab_agent_seeding_schemas import _load_json, _validate  # noqa: E402


def test_build_seed_packet_matches_sab_seed_schema(tmp_path: Path) -> None:
    contribution = {
        "problem_ref": "language_womb.epistemic_authority.v1",
        "delta_kind": "type_rule",
        "claim": "Attested claims must not satisfy proven claim slots without an explicit promotion proof.",
        "evidence_or_reasoning": ["docs/lanes/sab-agent-seeding-v1/LANGUAGE_WOMB_GRAND_CHALLENGE_SEED.md"],
        "falsification_route": "Find a well-typed coercion that promotes attestation without proof or review.",
        "language_impact": "The evaluator rejects invalid epistemic substitution before execution.",
        "authority_boundary": "No standing or deployment authority is granted.",
    }
    packet = build_seed_packet(
        contribution,
        agent_id="agent_test_language_womb",
        agent_name="test-language-womb",
        created_at=utc_now(),
        key_dir=tmp_path / "keys",
    )

    schema = _load_json(REPO_ROOT / "nodes" / "schemas" / "sab.seed_packet.v1.schema.json")
    assert _validate(schema, packet) == []
    assert packet["signature"]["signed_payload"]["kind"] == "sab_seed_submit"
    assert len(packet["signature"]["signature"]) == 128
    assert packet["anti_capture_rules"]


def test_run_tick_packages_inbox_contribution_and_moves_it(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    packets = tmp_path / "packets"
    receipts = tmp_path / "receipts"
    processed = tmp_path / "processed"
    inbox.mkdir()
    (inbox / "delta.json").write_text(
        json.dumps(
            {
                "problem_ref": "language_womb.epistemic_authority.v1",
                "delta_kind": "counterexample",
                "claim": "A receipt emitted after Python execution cannot by itself enforce epistemic authority.",
                "evidence_or_reasoning": ["local:test"],
                "falsification_route": "Show a runtime receipt that prevents bad composition before execution.",
                "language_impact": "Receipt-only designs should be folded back into governance.",
                "authority_boundary": "Local packaging only.",
            }
        ),
        encoding="utf-8",
    )

    summary = run_tick(
        agent_id="agent_test_packager",
        agent_name="test-packager",
        inbox_dir=inbox,
        packet_dir=packets,
        receipt_dir=receipts,
        processed_dir=processed,
        key_dir=tmp_path / "keys",
    )

    assert summary.status == "packaged"
    assert len(summary.packets_written) == 1
    assert len(summary.receipts_written) == 1
    assert not (inbox / "delta.json").exists()
    packet = json.loads(Path(summary.packets_written[0]).read_text(encoding="utf-8"))
    receipt = json.loads(Path(summary.receipts_written[0]).read_text(encoding="utf-8"))
    assert packet["seed_id"] == receipt["seed_id"]
    assert receipt["standing_effect"] == "none"


def test_run_tick_is_silent_when_no_delta(tmp_path: Path) -> None:
    summary = run_tick(
        agent_id="agent_test_quiet",
        agent_name="test-quiet",
        inbox_dir=tmp_path / "missing-inbox",
        packet_dir=tmp_path / "packets",
        receipt_dir=tmp_path / "receipts",
        processed_dir=tmp_path / "processed",
        key_dir=tmp_path / "keys",
    )

    assert summary.status == "no_delta"
    assert summary.packets_written == []

