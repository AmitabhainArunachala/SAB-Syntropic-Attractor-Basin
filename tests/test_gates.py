from __future__ import annotations

import json
import sys
from pathlib import Path

# Pytest 9's import mode can omit repo root from sys.path when running `pytest tests/`.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pytest

from agora.gates import (
    GATE_EVALUATOR_VERSION,
    GATE_POLICY_HASH,
    GateResult,
    OrthogonalGates,
    evaluate_submission_gates,
    verify_content,
)


def test_orthogonal_gates_empty_is_rejected():
    out = OrthogonalGates().evaluate({"body": ""}, agent_telos="")
    assert out["admitted"] is False
    assert out["passed_count"] == 0
    assert set(out["dimensions"].keys()) == {
        "structural_rigor",
        "build_artifacts",
        "telos_alignment",
    }


def test_orthogonal_gates_known_good_input_is_admitted():
    body = "\n".join(
        [
            "# Title",
            "",
            "Some text with enough structure to pass.",
            "",
            "```python",
            "print('x')",
            "```",
            "",
            "https://example.com",
        ]
    )
    out = OrthogonalGates().evaluate({"body": body}, agent_telos="testing")
    assert out["admitted"] is True
    assert out["passed_count"] >= 2
    assert out["dimensions"]["build_artifacts"]["passed"] is True


def test_gate_protocol_includes_satya_ahimsa_witness():
    passed, evidence, _ = verify_content(
        "This is a harmless, factual note with enough length to pass required gates.",
        author_address="a" * 16,
        context={},
    )
    assert passed is True

    by_gate = {e.gate_name: e for e in evidence}
    assert by_gate["satya"].result in {GateResult.PASSED, GateResult.WARNING}
    assert by_gate["ahimsa"].result == GateResult.PASSED
    assert by_gate["witness"].result == GateResult.PASSED


@pytest.mark.parametrize(
    "author_address",
    [
        "a" * 16,
        "t_" + "a" * 14,
        "k_" + "b" * 14,
        "agent_ed25519_" + "a" * 32,
    ],
)
def test_gate_protocol_accepts_sab_identity_ladder(author_address: str):
    passed, evidence, _ = verify_content(
        "This is a harmless, factual note with enough length to pass required gates.",
        author_address=author_address,
        context={},
    )
    assert passed is True

    by_gate = {item.gate_name: item for item in evidence}
    assert by_gate["witness"].result == GateResult.PASSED


@pytest.mark.parametrize("suffix", ["a" * 31, "a" * 33, "G" * 32, "a" * 32 + "\n"])
def test_witness_gate_rejects_malformed_canonical_agent_address(suffix):
    from agora.gates import GateResult, WitnessGate

    result = WitnessGate().check("Synthetic gate input", "agent_ed25519_" + suffix, {})
    assert result.result == GateResult.FAILED


def test_gate_result_includes_stable_policy_metadata():
    content = "This is a harmless, factual note with enough length to pass required gates."
    first, _, _, _ = evaluate_submission_gates(content, "a" * 16, {})
    second, _, _, _ = evaluate_submission_gates(content, "a" * 16, {})

    metadata = first["evaluation_metadata"]
    assert metadata["evaluator_version"] == GATE_EVALUATOR_VERSION
    assert metadata["policy_hash"] == GATE_POLICY_HASH
    assert metadata["policy_hash_algorithm"] == "sha256"
    assert metadata["weight_set"]["ahimsa"] == "2.000000"
    assert second["evaluation_metadata"] == metadata


def test_replayable_adversarial_corpus_expected_outcomes():
    corpus_path = _REPO_ROOT / "agora" / "tests" / "fixtures" / "adversarial_corpus.jsonl"
    rows = [json.loads(line) for line in corpus_path.read_text().splitlines() if line.strip()]
    assert rows

    for row in rows:
        passed, evidence, _ = verify_content(
            row["content"],
            author_address=row["author_address"],
            context=row.get("context") or {},
        )
        failed_gates = {item.gate_name for item in evidence if item.result == GateResult.FAILED}
        assert passed is row["expected_verified"], row["id"]
        assert row["expected_failed_required_gate"] in failed_gates, row["id"]
