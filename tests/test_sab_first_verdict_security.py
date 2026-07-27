from __future__ import annotations

import copy

import pytest

from agora.sab_first_verdict_evidence import (
    EvidenceValidationError,
    canonical_json_bytes,
    checkpoint_sha256,
    seal_checkpoint,
    validate_checkpoint_chain,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
GIT_A = "a" * 40
GIT_B = "b" * 40


def _database_ref(*, sha256: str | None = SHA_A, integrity: str = "ok") -> dict:
    return {
        "present": True,
        "path_ref": "private-local:sha256:" + "d" * 64,
        "sha256": sha256,
        "integrity": integrity,
        "lifecycle_fingerprint": SHA_B,
    }


def _checkpoint(seq: int, dag_node: str, predecessor: str | None) -> dict:
    return {
        "schema_version": "sab.build_a_checkpoint.v1",
        "run_id": "run_fixture",
        "native_goal_id": "goal_fixture",
        "checkpoint_seq": seq,
        "checkpoint_id": f"checkpoint_{seq}",
        "dag_node": dag_node,
        "status": "passed",
        "started_at": "2026-07-28T00:00:00Z",
        "completed_at": "2026-07-28T00:01:00Z",
        "accepted_base": {
            "repo": "fixture",
            "source_sha": GIT_A,
            "source_tree_sha": GIT_B,
            "integration_sha": GIT_A,
            "integration_tree_sha": GIT_B,
        },
        "worktree": {
            "path": "/fixture",
            "branch": "fixture",
            "head": GIT_A,
            "tree_sha": GIT_B,
            "porcelain_sha256": SHA_C,
        },
        "authority": {
            "implementation": "authorized_local_build_a",
            "live_effects": "forbidden",
            "authority_refs": ["fixture"],
        },
        "disposition_evaluations": [],
        "source_db": _database_ref(),
        "copy_db": _database_ref(),
        "inputs": [],
        "outputs": [],
        "tests": [],
        "commit_sha": GIT_A,
        "mutation_counters": {
            "live_db": 0,
            "services": 0,
            "providers": 0,
            "external": 0,
            "source_checkout": 0,
            "fixture_or_copy_db": 0,
        },
        "blockers": [],
        "next_dag_nodes": ["A0"],
        "next_safe_action": "continue to the next frozen DAG node",
        "previous_checkpoint_sha256": predecessor,
    }


def _valid_chain() -> list[dict]:
    genesis = seal_checkpoint(_checkpoint(0, "G0", None))
    second = seal_checkpoint(_checkpoint(1, "A0", genesis["checkpoint_sha256"]))
    return [genesis, second]


def test_checkpoint_chain_accepts_canonical_hash_and_bound_current_state() -> None:
    chain = _valid_chain()
    result = validate_checkpoint_chain(
        chain,
        expected_head=GIT_A,
        expected_tree_sha=GIT_B,
        expected_database_sha256=SHA_A,
        expected_lifecycle_fingerprint=SHA_B,
    )
    assert result["valid"] is True
    assert result["checkpoint_count"] == 2
    assert result["head_checkpoint_sha256"] == checkpoint_sha256(chain[-1])


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("changed_payload", "checkpoint_hash_mismatch"),
        ("broken_predecessor", "broken_predecessor"),
        ("non_monotonic", "non_monotonic_sequence"),
        ("invalid_genesis", "invalid_genesis"),
        ("missing_database_hash", "database_hash_missing"),
        ("failed_integrity", "database_integrity_failed"),
        ("forbidden_mutation", "forbidden_mutation_recorded"),
    ],
)
def test_checkpoint_chain_required_negative_cases(
    mutation: str, expected_code: str
) -> None:
    chain = _valid_chain()
    if mutation == "changed_payload":
        chain[1]["next_safe_action"] = "tampered without resealing"
    elif mutation == "broken_predecessor":
        chain[1]["previous_checkpoint_sha256"] = SHA_C
        chain[1] = seal_checkpoint(chain[1])
    elif mutation == "non_monotonic":
        chain[1]["checkpoint_seq"] = 4
        chain[1] = seal_checkpoint(chain[1])
    elif mutation == "invalid_genesis":
        chain[0]["dag_node"] = "A0"
        chain[0] = seal_checkpoint(chain[0])
    elif mutation == "missing_database_hash":
        chain[1]["copy_db"]["sha256"] = None
        chain[1] = seal_checkpoint(chain[1])
    elif mutation == "failed_integrity":
        chain[1]["copy_db"]["integrity"] = "failed"
        chain[1] = seal_checkpoint(chain[1])
    else:
        chain[1]["mutation_counters"]["providers"] = 1
        chain[1] = seal_checkpoint(chain[1])

    with pytest.raises(EvidenceValidationError) as raised:
        validate_checkpoint_chain(chain)
    assert raised.value.code == expected_code


def test_checkpoint_resume_rejects_head_mismatch() -> None:
    with pytest.raises(EvidenceValidationError) as raised:
        validate_checkpoint_chain(_valid_chain(), expected_head="f" * 40)
    assert raised.value.code == "head_mismatch"


def test_checkpoint_resume_rejects_changed_lifecycle_fingerprint() -> None:
    with pytest.raises(EvidenceValidationError) as raised:
        validate_checkpoint_chain(
            _valid_chain(), expected_lifecycle_fingerprint="f" * 64
        )
    assert raised.value.code == "lifecycle_fingerprint_changed"


def test_checkpoint_resume_rejects_changed_copy_database_hash() -> None:
    with pytest.raises(EvidenceValidationError) as raised:
        validate_checkpoint_chain(_valid_chain(), expected_database_sha256="f" * 64)
    assert raised.value.code == "database_hash_mismatch"


def test_checkpoint_canonical_hash_is_key_order_independent_but_array_order_sensitive() -> (
    None
):
    checkpoint = _checkpoint(0, "G0", None)
    reordered = {key: checkpoint[key] for key in reversed(checkpoint)}
    assert checkpoint_sha256(checkpoint) == checkpoint_sha256(reordered)

    changed_array = copy.deepcopy(checkpoint)
    changed_array["next_dag_nodes"] = ["C0", "A0"]
    checkpoint["next_dag_nodes"] = ["A0", "C0"]
    assert checkpoint_sha256(checkpoint) != checkpoint_sha256(changed_array)
    assert b" " not in canonical_json_bytes({"z": 1, "a": 2})
