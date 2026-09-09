"""Scoped graph admission using real synthetic key, review and grant proofs."""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from datetime import timedelta
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from pathlib import Path

import pytest

from agora import operator_control as oc
from agora.authority import lease_reference
from agora.sab_identity import canonical_json_bytes
from operator_control_fixtures import SyntheticOperatorControl, sign_reviews
from test_authority_service import Rig as AuthorityRig, connect, ORIGIN, SEED

CLAIM = "a" * 64


class Rig:
    def __init__(self, conn):
        self.conn = conn
        self.authority = AuthorityRig(conn)
        self.clock = self.authority.clock
        self.control = self.authority.control
        self.fixture = SyntheticOperatorControl(now=self.clock.wall, audience=ORIGIN)
        for subject, key in {**self.fixture.reviewer_keys,
                             self.fixture.revoker_subject_id: self.fixture.revoker_key}.items():
            challenge = self.control.issue(conn, {"action": "register", "registration": {
                "public_key": key.verify_key.encode().hex(), "display_name": "Synthetic review bootstrap",
            }})
            self.control.verify(conn, {"challenge_id": challenge["message"]["challenge_id"],
                                       "signature": key.sign(canonical_json_bytes(challenge["message"])).signature.hex()})
        self.participants = {self.authority.subject(name): self.authority.keys[name]
                             for name in ("subject", "other", "revoker")}
        self.service = self.new_service()
        self.grant = None

    def new_service(self, policy=True, authority=True):
        return oc.OperatorControlRegistry(self.fixture.policy if policy is True else policy, self.control,
                                           self.authority.service if authority else None)

    def envelope(self, **kwargs):
        defaults = {"seed_id": SEED, "claim_sha256": CLAIM, "purpose": "standing_quorum", "now": self.clock.wall}
        defaults.update(kwargs)
        return self.fixture.envelope(self.participants, **defaults)

    def sign(self, assessment):
        return sign_reviews(assessment, self.fixture.reviewer_keys, observed_at=self.clock.wall)

    def evaluate(self, envelope, **kwargs):
        assessment = envelope["assessment"]
        defaults = {"assessment_id": assessment["assessment_id"], "assessment_sha256": oc.hash_json(assessment),
                    "seed_id": SEED, "claim_sha256": CLAIM, "purpose": "standing_quorum",
                    "participant_subject_ids": list(self.participants)}
        defaults.update(kwargs)
        return self.service.evaluate(self.conn, **defaults)

    def issue(self, envelope=None):
        envelope = envelope or self.envelope()
        self.service.issue(self.conn, envelope)
        return envelope

    def command(self, envelope, kind="revoke", **changes):
        assessment = envelope["assessment"]
        now = self.clock.wall
        field, actor = ("challenge", "challenger") if kind == "challenge" else ("revocation", "revoker")
        key = self.authority.keys["subject"] if kind == "challenge" else self.fixture.revoker_key
        subject = self.authority.subject("subject") if kind == "challenge" else self.fixture.revoker_subject_id
        message = {"schema": "sab.operator_control_" + field + ".v1",
                   "challenge_id" if kind == "challenge" else "revocation_id":
                       ("sab_operator_challenge_" if kind == "challenge" else "sab_operator_revoke_") + "1" * 24,
                   "assessment_id": assessment["assessment_id"], "assessment_sha256": oc.hash_json(assessment),
                   "audience": ORIGIN, actor + "_subject_id": subject,
                   actor + "_public_key": key.verify_key.encode().hex(), "reason": "Synthetic source requires correction",
                   "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=90)).isoformat()}
        if kind == "challenge":
            if self.grant is None:
                grant = self.authority.envelope(lease_changes={"allowed_actions": ["challenge_operator_control"]})
                self.grant = self.authority.service.issue(self.conn, grant)
            message.update(evidence_ref="synthetic:contradicting-custody-inventory",
                           authority_lease=lease_reference({"lease": self.grant["lease"]}),
                           authority_lease_sha256=self.grant["lease_sha256"])
        message.update(changes)
        return {field: message, "signature": key.sign(canonical_json_bytes(message)).signature.hex()}

    def retire(self, subject, key):
        challenge = self.control.issue(self.conn, {"action": "revoke", "subject_id": subject})
        self.control.verify(self.conn, {"challenge_id": challenge["message"]["challenge_id"],
                                       "signature": key.sign(canonical_json_bytes(challenge["message"])).signature.hex()})


@pytest.fixture
def rig():
    conn = connect()
    yield Rig(conn)
    conn.close()


def state(conn):
    return tuple(conn.iterdump())


def denied(rig, operation, code=None):
    before, transaction = state(rig.conn), rig.conn.in_transaction
    with pytest.raises(oc.OperatorControlError) as error:
        operation()
    if code:
        assert error.value.code == "operator_control_" + code
    assert state(rig.conn) == before
    assert rig.conn.in_transaction == transaction
    return error.value


def observed_denial(rig, envelope, **kwargs):
    before = state(rig.conn)
    result = rig.evaluate(envelope, **kwargs)
    assert not result.eligible
    assert result.independent_controller_count == 0
    assert result.to_observation()["authority_effect"] == result.to_observation()["standing_effect"] == "none"
    assert state(rig.conn) == before
    return result


def sort_graph(assessment):
    assessment["graph"]["nodes"].sort(key=lambda n: n["node_id"])
    assessment["graph"]["edges"].sort(key=lambda e: (e["source"], e["target"], e["relation"]))


def test_actual_enrollment_review_evidence_and_immutable_evaluation(rig):
    envelope = rig.envelope()
    receipt = rig.service.issue(rig.conn, envelope)
    assert receipt["created"] and receipt["status"] == "eligible"
    assert receipt["assessment"] == envelope["assessment"]
    assert receipt["reviews"] == envelope["reviews"]
    before = state(rig.conn)
    result = rig.evaluate(envelope)
    assert result.eligible and result.grade == "verified"
    assert result.participant_count == result.independent_controller_count == 3
    assert len(result.pairs) == 3 and all(pair.eligible for pair in result.pairs)
    assert all(len(pair.evidence_ids) == 7 for pair in result.pairs)
    with pytest.raises(FrozenInstanceError):
        result.eligible = False
    mutable = result.to_observation()
    mutable["grade"] = "unknown"
    mutable["participant_subject_ids"].clear()
    assert result.grade == "verified" and result.participant_count == 3
    assert not rig.service.issue(rig.conn, envelope)["created"]
    assert state(rig.conn) == before


@pytest.mark.parametrize("purpose", sorted(oc.PURPOSES))
def test_each_purpose_is_exact_and_supported(rig, purpose):
    envelope = rig.issue(rig.envelope(purpose=purpose))
    assert rig.evaluate(envelope, purpose=purpose).eligible
    other = next(p for p in oc.PURPOSES if p != purpose)
    observed_denial(rig, envelope, purpose=other)


def test_larger_cohort_counts_only_actual_requested_pairs_and_never_unrelated_keys(rig):
    envelope = rig.issue()
    selected = sorted(rig.participants)[:2]
    result = rig.evaluate(envelope, participant_subject_ids=selected)
    assert result.eligible and result.participant_count == result.independent_controller_count == 2
    assert len(result.pairs) == 1
    observed_denial(rig, envelope, participant_subject_ids=selected + [rig.authority.subject("issuer")])
    observed_denial(rig, envelope, participant_subject_ids=selected + selected)


@pytest.mark.parametrize("field,value", [("seed_id", "sab_seed_different"), ("claim_sha256", "b" * 64),
                                         ("assessment_sha256", "b" * 64), ("purpose", "*"), ("purpose", []),
                                         ("participant_subject_ids", [{"verified": True}])])
def test_exact_binding_and_caller_proof_denial_is_read_only(rig, field, value):
    envelope = rig.issue()
    observed_denial(rig, envelope, **{field: value})


@pytest.mark.parametrize("category", sorted(oc.CATEGORIES))
def test_every_evidence_category_required_before_any_schema_change(rig, category):
    assessment = rig.envelope()["assessment"]
    assessment["evidence"] = [e for e in assessment["evidence"] if e["category"] != category]
    denied(rig, lambda: rig.service.issue(rig.conn, rig.sign(assessment)))


@pytest.mark.parametrize("source", ["self_report", "unknown_forged_grade"])
def test_source_labels_never_manufacture_verification(rig, source):
    assessment = rig.envelope()["assessment"]
    for artifact in assessment["evidence"]:
        artifact["source_class"] = source
    envelope = rig.sign(assessment)
    if source == "self_report":
        receipt = rig.service.issue(rig.conn, envelope)
        assert receipt["observation"]["grade"] == "self_declared"
        observed_denial(rig, envelope)
    else:
        denied(rig, lambda: rig.service.issue(rig.conn, envelope))


@pytest.mark.parametrize("outcome", ["unknown", "contradicted"])
@pytest.mark.parametrize("reviewer_index", [0, 1])
def test_each_reviewer_needs_complete_supported_findings(rig, outcome, reviewer_index):
    envelope = rig.envelope()
    review = envelope["reviews"][reviewer_index]
    review["findings"][0]["outcome"] = outcome
    key = rig.fixture.reviewer_keys[review["reviewer_subject_id"]]
    review["signature"] = key.sign(canonical_json_bytes({k: v for k, v in review.items() if k != "signature"})).signature.hex()
    rig.issue(envelope)
    result = observed_denial(rig, envelope)
    assert result.grade == ("unknown" if outcome == "contradicted" else "corroborated")


def test_pooled_reviewer_coverage_cannot_count_as_complete(rig):
    assessment = rig.envelope()["assessment"]
    category = sorted(oc.CATEGORIES)[0]
    original = next(e for e in assessment["evidence"] if e["category"] == category)
    extra = copy.deepcopy(original)
    extra["evidence_id"] += "_second"
    original["subject_ids"] = sorted(rig.participants)[:1]
    extra["subject_ids"] = sorted(rig.participants)[1:]
    assessment["evidence"].append(extra)
    assessment["evidence"].sort(key=lambda e: e["evidence_id"])
    envelope = rig.sign(assessment)
    for index, review in enumerate(envelope["reviews"]):
        review["findings"][0]["evidence_ids"] = [(original if index == 0 else extra)["evidence_id"]]
        key = rig.fixture.reviewer_keys[review["reviewer_subject_id"]]
        review["signature"] = key.sign(canonical_json_bytes({k: v for k, v in review.items() if k != "signature"})).signature.hex()
    rig.issue(envelope)
    observed_denial(rig, envelope)


@pytest.mark.parametrize("mutation", ["signature", "evidence_hash", "policy_hash", "unknown_field", "secret",
                                      "reviewer_duplicate", "participant_duplicate", "key_duplicate", "enum_list"])
def test_tampered_closed_envelopes_fail_without_rows_or_ddl(rig, mutation):
    envelope = rig.envelope()
    assessment = envelope["assessment"]
    if mutation == "signature":
        envelope["reviews"][0]["signature"] = "0" * 128
    elif mutation == "evidence_hash":
        assessment["evidence"][0]["document_sha256"] = "0" * 64
    elif mutation == "policy_hash":
        assessment["policy_sha256"] = "0" * 64
    elif mutation == "unknown_field":
        assessment["verified"] = True
    elif mutation == "secret":
        assessment["evidence"][0]["document"]["private_key"] = "DO_NOT_REFLECT_THIS_SECRET"
    elif mutation == "reviewer_duplicate":
        envelope["reviews"][1] = copy.deepcopy(envelope["reviews"][0])
    elif mutation == "participant_duplicate":
        assessment["participants"].append(copy.deepcopy(assessment["participants"][0]))
    elif mutation == "key_duplicate":
        assessment["participants"][1]["public_key"] = assessment["participants"][0]["public_key"]
    else:
        assessment["graph"]["nodes"][0]["kind"] = []
    error = denied(rig, lambda: rig.service.issue(rig.conn, envelope))
    assert "DO_NOT_REFLECT" not in str(error)


@pytest.mark.parametrize("kind,relation", [("controller", "controlled_by"), ("signing_root", "signs_with"),
                                           ("administrator", "administered_by"), ("runtime", "operated_by"),
                                           ("delegate", "delegates_to"), ("decision_authority", "decided_by")])
def test_shared_control_kind_cannot_count_as_independent(rig, kind, relation):
    assessment = rig.envelope()["assessment"]
    left, right = assessment["participants"][:2]
    if kind == "delegate":
        shared = "control_shared_delegate"
        assessment["graph"]["nodes"].append({"node_id": shared, "kind": kind})
        for p in (left, right):
            assessment["graph"]["edges"].append({"source": p["subject_id"], "target": shared,
                                                 "relation": relation, "funding_ppm": None})
    else:
        edge = next(e for e in assessment["graph"]["edges"] if e["source"] == left["subject_id"] and e["relation"] == relation)
        shared = edge["target"]
        other = next(e for e in assessment["graph"]["edges"] if e["source"] == right["subject_id"] and e["relation"] == relation)
        other["target"] = shared
        if kind == "controller":
            right["controller_class_id"] = shared
    sort_graph(assessment)
    envelope = rig.sign(assessment)
    rig.issue(envelope)
    result = observed_denial(rig, envelope)
    assert any("shared_" + kind in pair.reason_codes for pair in result.pairs)


def test_witness_pair_is_checked_even_when_both_are_separate_from_claimant(rig):
    assessment = rig.envelope()["assessment"]
    subjects = [p["subject_id"] for p in assessment["participants"]]
    assessment["graph"]["edges"].append({"source": subjects[1], "target": subjects[2],
                                         "relation": "conflicts_with", "funding_ppm": None})
    sort_graph(assessment)
    envelope = rig.sign(assessment)
    rig.issue(envelope)
    result = observed_denial(rig, envelope)
    assert [p.eligible for p in result.pairs] == [True, True, False]


@pytest.mark.parametrize("ppm,eligible", [(999, True), (1000, True), (1001, False)])
def test_funding_threshold_is_inclusive_max_of_each_subject_total(rig, ppm, eligible):
    rig.fixture.policy["max_common_funding_ppm"] = 1000
    rig.service = rig.new_service()
    assessment = rig.envelope()["assessment"]
    assessment["graph"]["nodes"].append({"node_id": "control_common_funder", "kind": "funder"})
    for index, p in enumerate(assessment["participants"][:2]):
        assessment["graph"]["edges"].append({"source": p["subject_id"], "target": "control_common_funder",
                                             "relation": "funded_by", "funding_ppm": ppm if index == 0 else 1})
    sort_graph(assessment)
    envelope = rig.sign(assessment)
    rig.issue(envelope)
    assert rig.evaluate(envelope).eligible is eligible


@pytest.mark.parametrize("retired", ["participant", "reviewer"])
def test_current_key_retirement_denies_read_evaluation_and_restart(rig, retired):
    envelope = rig.issue()
    subject, key = next(iter(rig.participants.items() if retired == "participant" else rig.fixture.reviewer_keys.items()))
    rig.retire(subject, key)
    observed_denial(rig, envelope)
    rig.service = rig.new_service()
    observed_denial(rig, envelope)
    assert rig.service.get(rig.conn, envelope["assessment"]["assessment_id"])["status"] == "ineligible"


@pytest.mark.parametrize("seconds", [3600, 86400, 8 * 86400])
def test_expiry_observation_never_changes_original_history(rig, seconds):
    envelope = rig.issue()
    rig.clock.advance(seconds)
    observed_denial(rig, envelope)
    assert oc.validate_envelope(envelope, policy=rig.fixture.policy, check_freshness=False) == envelope


def test_clock_rollback_is_latched_and_read_does_not_repair(rig):
    envelope = rig.issue()
    rig.clock.wall -= timedelta(seconds=10)
    assert "operator_control_clock_uncertain" in observed_denial(rig, envelope).reason_codes
    rig.clock.wall += timedelta(seconds=10)
    observed_denial(rig, envelope)


def test_policy_removed_changed_or_expired_does_not_revoke_old_history(rig):
    envelope = rig.issue()
    rig.service = rig.new_service(policy=None)
    observed_denial(rig, envelope)
    command = rig.command(envelope)
    assert rig.service.revoke(rig.conn, command)["created"]
    assert rig.service.get(rig.conn, envelope["assessment"]["assessment_id"])["status"] == "revoked"


def test_signed_grant_authorized_challenge_suspends_and_cannot_resurrect(rig):
    envelope = rig.issue()
    command = rig.command(envelope, "challenge")
    receipt = rig.service.challenge(rig.conn, command)
    assert receipt["challenge"] == command["challenge"] and receipt["signature"] == command["signature"]
    before = state(rig.conn)
    assert not rig.service.challenge(rig.conn, command)["created"]
    assert not rig.service.issue(rig.conn, envelope)["created"]
    assert state(rig.conn) == before
    rig.service = rig.new_service()
    observed_denial(rig, envelope)
    assert rig.service.get(rig.conn, envelope["assessment"]["assessment_id"])["status"] == "challenged"


def test_identity_or_forged_lease_digest_cannot_suspend_registry(rig):
    envelope = rig.issue()
    command = rig.command(envelope, "challenge")
    unconfigured = rig.new_service(authority=False)
    denied(rig, lambda: unconfigured.challenge(rig.conn, command), "authority_required")
    wrong = rig.command(envelope, "challenge", authority_lease_sha256="0" * 64)
    denied(rig, lambda: rig.service.challenge(rig.conn, wrong), "authority_mismatch")
    assert rig.evaluate(envelope).eligible


def test_revocation_is_absorbing_idempotent_and_preserves_envelope(rig):
    envelope = rig.issue()
    command = rig.command(envelope)
    rig.service.revoke(rig.conn, command)
    before = state(rig.conn)
    rig.clock.advance(1000)
    assert not rig.service.revoke(rig.conn, command)["created"]
    assert not rig.service.issue(rig.conn, envelope)["created"]
    rig.service = rig.new_service()
    observed_denial(rig, envelope)
    assert rig.service.get(rig.conn, envelope["assessment"]["assessment_id"])["assessment"] == envelope["assessment"]
    assert state(rig.conn) == before


def test_head_replacement_requires_all_challenges_and_prevents_alternate_cohort(rig):
    first = rig.issue()
    alternative = rig.envelope()
    challenge = rig.command(first, "challenge")
    rig.service.challenge(rig.conn, challenge)
    denied(rig, lambda: rig.service.issue(rig.conn, alternative), "predecessor_mismatch")
    replaced = {"assessment_id": first["assessment"]["assessment_id"],
                "assessment_sha256": oc.hash_json(first["assessment"]), "challenge_ids": []}
    incomplete = rig.envelope(replaces=replaced)
    denied(rig, lambda: rig.service.issue(rig.conn, incomplete), "predecessor_mismatch")
    replaced["challenge_ids"] = [challenge["challenge"]["challenge_id"]]
    second = rig.issue(rig.envelope(replaces=replaced))
    assert rig.evaluate(second).eligible
    observed_denial(rig, first)
    denied(rig, lambda: rig.service.issue(rig.conn, rig.envelope(replaces=replaced)), "predecessor_mismatch")
    old_challenge = rig.command(first, "challenge", challenge_id="sab_operator_challenge_" + "2" * 24)
    denied(rig, lambda: rig.service.challenge(rig.conn, old_challenge), "assessment_terminal")


def test_replacement_review_cannot_predate_the_challenge_it_claims_to_address(rig):
    first = rig.issue()
    before_challenge = rig.clock.wall
    rig.clock.advance(1)
    challenge = rig.command(first, "challenge")
    rig.service.challenge(rig.conn, challenge)
    replaced = {"assessment_id": first["assessment"]["assessment_id"],
                "assessment_sha256": oc.hash_json(first["assessment"]),
                "challenge_ids": [challenge["challenge"]["challenge_id"]]}
    stale = rig.envelope(replaces=replaced, now=before_challenge)
    denied(rig, lambda: rig.service.issue(rig.conn, stale), "predecessor_mismatch")
    fresh = rig.issue(rig.envelope(replaces=replaced))
    assert rig.evaluate(fresh).eligible


def test_caller_transaction_is_not_committed_and_failure_rolls_back_only_service(rig):
    envelope = rig.envelope()
    before = state(rig.conn)
    rig.conn.execute("BEGIN IMMEDIATE")
    rig.service.issue(rig.conn, envelope)
    assert rig.conn.in_transaction
    assert rig.evaluate(envelope).eligible
    rig.conn.rollback()
    assert state(rig.conn) == before
    denied(rig, lambda: rig.service.issue(rig.conn, {"verified": True}))


@pytest.mark.parametrize("table,field", [("sab_operator_assessments_v1", "assessment_sha256"),
                                       ("sab_operator_assessments_v1", "policy_sha256"),
                                       ("sab_operator_events_v1", "envelope_sha256")])
def test_corrupt_projection_or_history_is_never_an_eligibility_proof(rig, table, field):
    envelope = rig.issue()
    if table == "sab_operator_events_v1":
        rig.service.revoke(rig.conn, rig.command(envelope))
    rig.conn.execute(f"UPDATE {table} SET {field}=?", ("0" * 64,))
    rig.conn.commit()
    assert "operator_control_inconsistent" in observed_denial(rig, envelope).reason_codes


def test_missing_tables_and_invalid_reads_never_initialize_private_schema(rig):
    envelope = rig.envelope()
    observed_denial(rig, envelope)
    assert not any("CREATE TABLE sab_operator" in row for row in state(rig.conn))
    empty = sqlite3.connect(":memory:")
    try:
        before = state(empty)
        assert not rig.service.evaluate(empty, assessment_id=envelope["assessment"]["assessment_id"],
                                        assessment_sha256=oc.hash_json(envelope["assessment"]), seed_id=SEED,
                                        claim_sha256=CLAIM, purpose="standing_quorum",
                                        participant_subject_ids=list(rig.participants)).eligible
        assert state(empty) == before
    finally:
        empty.close()


def test_policy_loader_checks_content_pin_owned_file_and_symlink(tmp_path, rig):
    path = tmp_path / "operator.json"
    path.write_bytes(canonical_json_bytes(rig.fixture.policy))
    path.chmod(0o600)
    digest = oc.hash_json(rig.fixture.policy)
    assert oc.load_operator_policy(path, digest) == rig.fixture.policy
    alias = tmp_path / "alias.json"
    alias.symlink_to(path)
    for candidate, pin in ((alias, digest), (path, "0" * 64)):
        with pytest.raises(oc.OperatorControlError):
            oc.load_operator_policy(candidate, pin)
    path.write_text('{"schema":"one","schema":"two"}')
    with pytest.raises(oc.OperatorControlError):
        oc.load_operator_policy(path, digest)
    assert oc.load_operator_policy(None, None) is None


def test_real_concurrent_issue_has_one_creation_and_idempotent_retry(tmp_path):
    path = tmp_path / "cohort.db"
    conn = connect(path)
    rig = Rig(conn)
    envelope = rig.envelope()
    conn.close()
    barrier = Barrier(2)

    def issue():
        with sqlite3.connect(path, timeout=10) as db:
            barrier.wait(timeout=5)
            return rig.service.issue(db, envelope)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(issue) for _ in range(2)]
        observations = [f.result(timeout=10) for f in futures]
    assert sorted(r["created"] for r in observations) == [False, True]


def test_challenge_does_not_bypass_retired_or_expired_authority(rig):
    envelope = rig.issue()
    challenge = rig.command(envelope, "challenge")
    grant_envelope = {k: rig.grant[k] for k in ("lease", "issuer_signature", "issuance_witness")}
    rig.authority.service.revoke(rig.conn, rig.authority.retirement(grant_envelope))
    denied(rig, lambda: rig.service.challenge(rig.conn, challenge), "authority_required")
    assert rig.evaluate(envelope).eligible


@pytest.mark.parametrize("kind", ["challenge", "revoke"])
@pytest.mark.parametrize("mutation", ["signature", "digest", "audience", "extra", "expired"])
def test_terminal_commands_validate_exact_signed_scope_before_mutation(rig, kind, mutation):
    envelope = rig.issue()
    kwargs = {"assessment_sha256": "0" * 64} if mutation == "digest" else {"audience": "https://wrong.example.test"} if mutation == "audience" else {}
    command = rig.command(envelope, kind, **kwargs)
    if mutation == "signature":
        command["signature"] = "0" * 128
    elif mutation == "extra":
        command["verified"] = True
    elif mutation == "expired":
        rig.clock.advance(90)
    operation = rig.service.challenge if kind == "challenge" else rig.service.revoke
    denied(rig, lambda: operation(rig.conn, command))


def test_event_capacity_preserves_a_real_revocation_slot(rig, monkeypatch):
    envelope = rig.issue()
    first = rig.command(envelope, "challenge")
    monkeypatch.setattr(oc, "MAX_EVENTS", 2)
    rig.service.challenge(rig.conn, first)
    second = rig.command(envelope, "challenge", challenge_id="sab_operator_challenge_" + "2" * 24)
    denied(rig, lambda: rig.service.challenge(rig.conn, second), "capacity")
    assert rig.service.revoke(rig.conn, rig.command(envelope))["created"]
    assert rig.service.get(rig.conn, envelope["assessment"]["assessment_id"])["status"] == "revoked"


def test_creation_capacity_and_oversize_material_do_not_initialize_tables(rig, monkeypatch):
    envelope = rig.envelope()
    monkeypatch.setattr(oc, "MAX_ASSESSMENTS", 0)
    denied(rig, lambda: rig.service.issue(rig.conn, envelope), "capacity")
    monkeypatch.setattr(oc, "MAX_ASSESSMENTS", 10000)
    artifact = envelope["assessment"]["evidence"][0]
    artifact["document"]["oversized"] = "A" * 9000
    artifact["document_sha256"] = oc.hash_json(artifact["document"])
    denied(rig, lambda: rig.service.issue(rig.conn, rig.sign(envelope["assessment"])))


def test_read_only_connection_observes_existing_proof_without_schema_or_history_effects(tmp_path):
    path = tmp_path / "readonly.db"
    conn = connect(path)
    rig = Rig(conn)
    envelope = rig.issue()
    before = state(conn)
    conn.close()
    rig.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        assert rig.evaluate(envelope).eligible
        assert state(rig.conn) == before
    finally:
        rig.conn.close()


def test_failed_insert_rolls_back_only_service_savepoint(rig):
    first = rig.issue()
    replaced = {"assessment_id": first["assessment"]["assessment_id"],
                "assessment_sha256": oc.hash_json(first["assessment"]), "challenge_ids": []}
    second = rig.envelope(replaces=replaced)
    rig.conn.execute("CREATE TEMP TRIGGER refuse_operator_insert BEFORE INSERT ON sab_operator_assessments_v1 BEGIN SELECT RAISE(ABORT,'refuse'); END")
    rig.conn.execute("BEGIN IMMEDIATE")
    before = state(rig.conn)
    denied(rig, lambda: rig.service.issue(rig.conn, second), "storage_unavailable")
    assert rig.conn.in_transaction and state(rig.conn) == before
    rig.conn.rollback()
    assert rig.evaluate(first).eligible


def test_funding_edge_splitting_and_intermediaries_are_not_a_bypass(rig):
    rig.fixture.policy["max_common_funding_ppm"] = 1000
    rig.service = rig.new_service()
    assessment = rig.envelope()["assessment"]
    graph = assessment["graph"]
    graph["nodes"].append({"node_id": "control_common_funder", "kind": "funder"})
    first, second = assessment["participants"][:2]
    for source, ppm in ((first["subject_id"], 600), (first["controller_class_id"], 600), (second["subject_id"], 1)):
        graph["edges"].append({"source": source, "target": "control_common_funder", "relation": "funded_by", "funding_ppm": ppm})
    sort_graph(assessment)
    envelope = rig.issue(rig.sign(assessment))
    assert any("common_funding_above_policy" in p.reason_codes for p in observed_denial(rig, envelope).pairs)
    graph["nodes"].append({"node_id": "control_intermediary", "kind": "funder"})
    graph["edges"].append({"source": "control_intermediary", "target": "control_common_funder", "relation": "funded_by", "funding_ppm": 1})
    sort_graph(assessment)
    with pytest.raises(oc.OperatorControlError):
        oc.validate_assessment(assessment, policy=rig.fixture.policy, observed_at=rig.clock.wall)


def test_two_concurrent_scope_successors_cannot_fork_history(tmp_path):
    path = tmp_path / "lineage.db"
    conn = connect(path)
    rig = Rig(conn)
    first = rig.issue()
    parent = {"assessment_id": first["assessment"]["assessment_id"],
              "assessment_sha256": oc.hash_json(first["assessment"]), "challenge_ids": []}
    successors = [rig.envelope(replaces=parent) for _ in range(2)]
    conn.close()
    barrier = Barrier(2)

    def issue(payload):
        with sqlite3.connect(path, timeout=10) as db:
            barrier.wait(timeout=5)
            try:
                return rig.service.issue(db, payload)["created"]
            except oc.OperatorControlError as exc:
                return exc.code
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(issue, payload) for payload in successors]
        results = [f.result(timeout=10) for f in futures]
    assert results.count(True) == 1
    assert results.count("operator_control_predecessor_mismatch") == 1


def test_retirement_holds_writer_lock_before_registry_checks_key(tmp_path, monkeypatch):
    path = tmp_path / "retire-race.db"
    conn = connect(path)
    rig = Rig(conn)
    envelope = rig.envelope()
    subject, key = next(iter(rig.participants.items()))
    challenge = rig.control.issue(conn, {"action": "revoke", "subject_id": subject})
    proof = {"challenge_id": challenge["message"]["challenge_id"],
             "signature": key.sign(canonical_json_bytes(challenge["message"])).signature.hex()}
    locked, release, attempted = Event(), Event(), Event()
    original = rig.control._now

    def hold_clock():
        result = original()
        locked.set()
        assert release.wait(5)
        return result
    monkeypatch.setattr(rig.control, "_now", hold_clock)
    conn.close()

    def retire():
        with sqlite3.connect(path, timeout=10) as db:
            return rig.control.verify(db, proof)

    def issue():
        with sqlite3.connect(path, timeout=10) as db:
            attempted.set()
            try:
                rig.service.issue(db, envelope)
            except oc.OperatorControlError as exc:
                return exc.code
            return "unexpected_acceptance"
    with ThreadPoolExecutor(max_workers=2) as executor:
        retired = executor.submit(retire)
        try:
            assert locked.wait(5)
            issued = executor.submit(issue)
            assert attempted.wait(5)
        finally:
            release.set()
        retired.result(timeout=10)
        assert issued.result(timeout=10) == "operator_control_key_inactive"
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='sab_operator_assessments_v1'").fetchone()[0] == 0


def test_closed_published_schemas_cover_real_signed_material_and_refuse_grade_override(rig):
    import jsonschema
    folder = Path(__file__).resolve().parents[1] / "nodes" / "schemas"
    envelope = rig.issue()
    values = {"sab.operator_control_policy.v1": rig.fixture.policy,
              "sab.operator_cohort_assessment.v1": envelope["assessment"],
              "sab.operator_control_review.v1": envelope["reviews"][0],
              "sab.operator_cohort_issuance.v1": envelope,
              "sab.operator_control_challenge.v1": rig.command(envelope, "challenge")["challenge"],
              "sab.operator_control_revocation.v1": rig.command(envelope)["revocation"]}
    for name, value in values.items():
        schema = json.loads((folder / (name + ".schema.json")).read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(value, schema)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate({**value, "verified": True}, schema)
