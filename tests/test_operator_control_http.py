"""Real signed local ceremonies under an explicitly synthetic review policy.

Every fixture key is held by this test runner. Passing these tests does not
establish an external independent operator or authorize a public release.
"""
from __future__ import annotations

import importlib
import sys
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from test_sab_build3_enforcement import (
    _Agent, _register, _submit_seed, _submit_challenge, _challenge_action,
    _witness_event, _iso, _now, _sha256_obj,
)


@pytest.fixture
def ceremony(tmp_path, monkeypatch):
    from authority_fixtures import provision_authority_policy
    from operator_control_fixtures import provision_operator_policy
    authority = provision_authority_policy(tmp_path, monkeypatch)
    control = provision_operator_policy(tmp_path, monkeypatch)
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "synthetic.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "system.key"))
    for name in list(sys.modules):
        if name == "agora" or name.startswith("agora."):
            del sys.modules[name]
    module = importlib.import_module("agora.app")
    with TestClient(module.app) as client:
        authority.enroll(client)
        control.enroll(client)
        actors = {role: _Agent() for role in ("claimant", "challenger", "adjudicator", "w1", "w2", "reviewer")}
        seed_id = "sab_seed_operator_http"
        actions = {"claimant": ["submit_seed", "respond_challenge", "correct_seed"],
                   "challenger": ["submit_challenge", "challenge_operator_control"],
                   "adjudicator": ["adjudicate_challenge"], "w1": ["submit_witness_event"],
                   "w2": ["submit_witness_event"], "reviewer": ["request_standing_review", "revalidate_standing"]}
        for role, actor in actors.items():
            _register(client, actor, "Synthetic " + role, "unknown")
            authority.issue(client, actor.subject_id, seed_id, actions[role])
        _submit_seed(client, actors["claimant"], seed_id)
        _submit_challenge(client, actors["challenger"], seed_id, "sab_challenge_operator_http")
        response = _challenge_action(client, actors["claimant"], "sab_challenge_operator_http", "respond", {"value": "Narrowed scope"})
        assert response.status_code == 201, response.text
        members = {actor.subject_id: actor.key for actor in actors.values()}
        members.update({authority.issuer_id: authority.issuer_key, authority.witness_id: authority.witness_key})
        yield Ceremony(client, module, control, actors, members, seed_id)


class Ceremony:
    def __init__(self, client, module, control, actors, members, seed_id):
        self.client, self.module, self.control, self.actors = client, module, control, actors
        self.members, self.seed_id = members, seed_id

    def context(self):
        result = self.client.get(f"/api/v1/seeds/{self.seed_id}")
        assert result.status_code == 200, result.text
        return result.json()["operator_control_context"]

    def snapshot(self):
        with self.module._db() as conn:
            return tuple(conn.iterdump())

    def assessment(self, purpose, **kwargs):
        envelope = self.control.envelope(self.members, seed_id=self.seed_id,
                                         claim_sha256=self.context()["claim_sha256"], purpose=purpose, **kwargs)
        response = self.client.post("/api/operator-control/assessments", json=envelope)
        assert response.status_code == 201, response.text
        receipt = response.json()
        assert receipt["status"] == "eligible", receipt
        return {key: receipt[key] for key in ("assessment_id", "assessment_sha256")}

    def basis(self):
        adjudication_assessment = self.assessment("challenge_adjudication")
        response = _challenge_action(self.client, self.actors["adjudicator"], "sab_challenge_operator_http", "reject",
                                     {"value": "Claim correction resolves this exact challenge",
                                      "operator_control_assessment": adjudication_assessment})
        assert response.status_code == 201, response.text
        adjudication = {"event_id": response.json()["response_id"], "event_sha256": response.json()["witness_head"]}
        before = self.context()["claim_sha256"]
        witnesses = []
        for role in ("w1", "w2"):
            response = _witness_event(self.client, self.actors[role], self.seed_id, "affirm",
                                      {"operator_control_claim_sha256": before, "finding": "Synthetic inspected claim"})
            assert response.status_code == 201, response.text
            witnesses.append({"event_id": response.json()["event_id"], "event_sha256": response.json()["event_hash"]})
        assert self.context()["claim_sha256"] == before
        return {"assessment": self.assessment("standing_quorum"), "witness_events": witnesses,
                "adjudication_events": [adjudication]}

    def review(self, basis, *, actor=None, mutate=None, overrides=None):
        actor = actor or self.actors["reviewer"]
        lease = {"standing_id": "sab_standing_operator_" + uuid.uuid4().hex,
                 "subject_seed_id": self.seed_id, "subject_claim_id": "sab_claim_" + self.seed_id,
                 "scope": "Synthetic isolated test only", "purpose": "Exercise reviewed control predicate",
                 "expiry": _iso(_now() + timedelta(days=1)), "revoker": actor.subject_id,
                 "challenge_path": "/api/v1/standing/challenge", "issued_by": actor.subject_id,
                 "issued_at": _iso(_now()), "operator_control_basis": basis}
        lease.update(overrides or {})
        message = {"kind": "sab_standing_review", "standing_lease_sha256": _sha256_obj(lease),
                   "subject_seed_id": self.seed_id, "reviewer_identity": actor.subject_id,
                   "created_at": lease["issued_at"]}
        lease["signature"] = actor.sign(message)
        if mutate:
            mutate(lease)
        return self.client.post("/api/v1/standing/review", json={"standing_lease": lease})


def test_reviewed_exact_ceremony_and_read_only_status_filters(ceremony):
    basis = ceremony.basis()
    response = ceremony.review(basis)
    assert response.status_code == 201, response.text
    record = response.json()
    assert record["status"] == "active"
    assert record["issued_under"]["system_operator_count"] == 3
    assert len(record["issued_under"]["operator_control"]["participant_subject_ids"]) == 8
    before = ceremony.snapshot()
    fetched = ceremony.client.get("/api/v1/standing/" + record["standing_id"]).json()
    assert fetched["status"] == fetched["stored_status"] == "active", fetched
    assert fetched["operator_control_eligible"] is True
    assert fetched["standing_lease"] == record["standing_lease"]
    active = ceremony.client.get("/api/v1/standing?status=active&limit=1").json()
    assert [row["standing_id"] for row in active["items"]] == [record["standing_id"]]
    assert ceremony.client.get("/api/v1/standing?status=unknown").json()["items"] == []
    assert ceremony.snapshot() == before


@pytest.mark.parametrize("change", ["duplicate_witness", "tampered_digest", "omit_adjudication", "extra_field"])
def test_invalid_signed_roster_rejects_without_writes(ceremony, change):
    basis = ceremony.basis()
    if change == "duplicate_witness":
        basis["witness_events"][1] = basis["witness_events"][0]
    elif change == "tampered_digest":
        basis["witness_events"][0]["event_sha256"] = "a" * 64
    elif change == "omit_adjudication":
        basis["adjudication_events"] = []
    else:
        basis["verified"] = True
    before = ceremony.snapshot()
    response = ceremony.review(basis)
    assert response.status_code == 403, response.text
    assert ceremony.snapshot() == before


def test_unsigned_replacement_of_basis_cannot_change_effect(ceremony):
    basis = ceremony.basis()
    before = ceremony.snapshot()
    response = ceremony.review(basis, mutate=lambda lease: lease["operator_control_basis"].update(verified=True))
    assert response.status_code == 400, response.text
    assert ceremony.snapshot() == before


@pytest.mark.parametrize("overrides", [{"issued_at": "2999-01-01T00:00:00Z"}, {"issued_at": ""}, {"purpose": 123}])
def test_reviewed_lease_has_coherent_original_signed_fields(ceremony, overrides):
    basis = ceremony.basis()
    before = ceremony.snapshot()
    response = ceremony.review(basis, overrides=overrides)
    assert response.status_code == 400, response.text
    assert ceremony.snapshot() == before


def test_claim_correction_changes_revision_and_can_receive_fresh_evidence(ceremony):
    before = ceremony.context()["claim_sha256"]
    actor = ceremony.actors["claimant"]
    body, created = {"text": "A second explicit narrowing"}, _iso(_now())
    message = {"kind": "sab_seed_correct", "target_seed_id": ceremony.seed_id,
               "actor_identity": actor.subject_id, "correction_sha256": _sha256_obj(body), "created_at": created}
    response = ceremony.client.post(f"/api/v1/seeds/{ceremony.seed_id}/correct", json={
        "actor_identity": actor.subject_id, "correction": body, "created_at": created, "signature": actor.sign(message)})
    assert response.status_code == 200, response.text
    assert ceremony.context()["claim_sha256"] != before
    response = ceremony.review(ceremony.basis())
    assert response.status_code == 201 and response.json()["status"] == "active", response.text


def test_retired_witness_permission_removes_current_standing_without_rewriting_history(ceremony):
    response = ceremony.review(ceremony.basis())
    assert response.status_code == 201, response.text
    record = response.json()
    authority = ceremony.client.authority
    grant = authority.grants[(ceremony.actors["w1"].subject_id, ceremony.seed_id)]
    retired = ceremony.client.post(f"/api/v1/authority/leases/{grant['lease_id']}/revoke",
                                    json=authority.revocation(grant))
    assert retired.status_code == 200, retired.text
    before = ceremony.snapshot()
    fetched = ceremony.client.get("/api/v1/standing/" + record["standing_id"]).json()
    assert fetched["status"] == "unknown" and fetched["stored_status"] == "active", fetched
    assert fetched["current_standing_eligible"] is False
    assert fetched["standing_lease"] == record["standing_lease"]
    assert ceremony.client.get("/api/v1/standing?status=active").json()["items"] == []
    assert len(ceremony.client.get("/api/v1/standing?status=unknown&limit=1").json()["items"]) == 1
    assert ceremony.snapshot() == before


def _challenge_assessment(ceremony, selector):
    actor, authority = ceremony.actors["challenger"], ceremony.client.authority
    now = _now()
    grant = authority.grants[(actor.subject_id, ceremony.seed_id)]
    message = {"schema": "sab.operator_control_challenge.v1", "challenge_id": "sab_operator_challenge_" + uuid.uuid4().hex,
               **selector, "audience": ceremony.control.policy["audience"],
               "challenger_subject_id": actor.subject_id, "challenger_public_key": actor.public_key,
               "reason": "Synthetic disputed runtime evidence", "evidence_ref": "synthetic:runtime-dispute",
               "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=90)).isoformat(),
               "authority_lease": authority.reference(actor.subject_id, ceremony.seed_id),
               "authority_lease_sha256": grant["lease_sha256"]}
    response = ceremony.client.post(f"/api/operator-control/assessments/{selector['assessment_id']}/challenge",
                                     json={"challenge": message, "signature": actor.sign(message)})
    assert response.status_code == 200, response.text
    return message["challenge_id"]


def test_challenged_assessment_and_replacement_cannot_auto_upgrade_old_standing(ceremony):
    basis = ceremony.basis()
    response = ceremony.review(basis)
    assert response.status_code == 201, response.text
    record = response.json()
    challenge_id = _challenge_assessment(ceremony, basis["assessment"])
    replacement = ceremony.assessment("standing_quorum", replaces={**basis["assessment"], "challenge_ids": [challenge_id]})
    fetched = ceremony.client.get("/api/v1/standing/" + record["standing_id"]).json()
    assert fetched["status"] == "unknown" and fetched["stored_status"] == "active", fetched
    assert fetched["standing_lease"] == record["standing_lease"]
    actor, created = ceremony.actors["reviewer"], _iso(_now())
    basis["assessment"] = replacement
    evidence = {"operator_control_basis": basis}
    message = {"kind": "sab_standing_revalidate", "standing_id": record["standing_id"], "actor_identity": actor.subject_id,
               "payload_sha256": _sha256_obj({"reason": "Fresh explicit review", "evidence": evidence}), "created_at": created}
    response = ceremony.client.post(f"/api/v1/standing/{record['standing_id']}/revalidate", json={
        "actor_identity": actor.subject_id, "reason": "Fresh explicit review", "evidence": evidence,
        "created_at": created, "signature": actor.sign(message)})
    assert response.status_code == 200, response.text
    fetched = ceremony.client.get("/api/v1/standing/" + record["standing_id"]).json()
    assert fetched["status"] == "active", fetched
    assert fetched["standing_lease"] == record["standing_lease"]
    assert fetched["expiry"] == record["expiry"]


def test_explicit_adjudication_renewal_requires_latest_signed_predecessor(ceremony):
    basis = ceremony.basis()
    decision = ceremony.client.get("/api/v1/witness-events/" + basis["adjudication_events"][0]["event_id"]).json()
    old = decision["payload"]["payload"]["operator_control_assessment"]
    challenge_id = _challenge_assessment(ceremony, old)
    selector = ceremony.assessment("challenge_adjudication", replaces={**old, "challenge_ids": [challenge_id]})
    actor = ceremony.actors["adjudicator"]
    reason = {"operator_control_assessment": selector, "prior_adjudication_event": basis["adjudication_events"][0],
              "value": "Explicit current review of the prior rejection"}
    response = _challenge_action(ceremony.client, actor, "sab_challenge_operator_http", "revalidate", reason)
    assert response.status_code == 201, response.text
    before = ceremony.snapshot()
    stale = _challenge_action(ceremony.client, actor, "sab_challenge_operator_http", "revalidate", reason)
    assert stale.status_code == 409, stale.text
    assert ceremony.snapshot() == before
    denied = ceremony.review(basis)
    assert denied.status_code == 403, denied.text
    basis["adjudication_events"] = [{"event_id": response.json()["response_id"], "event_sha256": response.json()["witness_head"]}]
    accepted = ceremony.review(basis)
    assert accepted.status_code == 201 and accepted.json()["status"] == "active", accepted.text


@pytest.mark.parametrize("alias", [False, True])
def test_forbidden_witness_aliases_cannot_bypass_policy(ceremony, alias):
    claimant, witness = ceremony.actors["claimant"], ceremony.actors["w1"]
    seed_id = "sab_seed_forbidden_alias"
    ceremony.client.authority.issue(ceremony.client, claimant.subject_id, seed_id, ["submit_seed"])
    ceremony.client.authority.issue(ceremony.client, witness.subject_id, seed_id, ["submit_witness_event"])
    blocked = "sab_identity_" + witness.subject_id if alias else witness.subject_id
    _submit_seed(ceremony.client, claimant, seed_id, forbidden_witnesses=[blocked])
    before = ceremony.snapshot()
    response = _witness_event(ceremony.client, witness, seed_id, "affirm", {"finding": "Forbidden"})
    assert response.status_code == 403, response.text
    assert ceremony.snapshot() == before


def test_generic_observation_cannot_replace_the_actual_adjudication(ceremony):
    basis = ceremony.basis()
    record = ceremony.review(basis).json()
    response = _witness_event(ceremony.client, ceremony.actors["w1"], ceremony.seed_id, "challenge", {
        "challenge_id": "sab_challenge_operator_http", "action": "reject", "payload": {"finding": "Ordinary observation"}})
    assert response.status_code == 201, response.text
    before = ceremony.snapshot()
    observed = ceremony.client.get("/api/v1/standing/" + record["standing_id"]).json()
    assert observed["status"] == "active", observed
    assert ceremony.snapshot() == before


def test_last_adjudication_capacity_does_not_break_current_reads(ceremony, monkeypatch):
    basis = ceremony.basis()
    api = importlib.import_module("agora.sab_seeding_api")
    monkeypatch.setattr(api, "CONTROL_DECISION_LIMIT", 2)
    decision = ceremony.client.get("/api/v1/witness-events/" + basis["adjudication_events"][0]["event_id"]).json()
    selector = decision["payload"]["payload"]["operator_control_assessment"]
    actor = ceremony.actors["adjudicator"]
    reason = {"operator_control_assessment": selector, "prior_adjudication_event": basis["adjudication_events"][0]}
    accepted = _challenge_action(ceremony.client, actor, "sab_challenge_operator_http", "revalidate", reason)
    assert accepted.status_code == 201, accepted.text
    latest = {"event_id": accepted.json()["response_id"], "event_sha256": accepted.json()["witness_head"]}
    reason["prior_adjudication_event"] = latest
    before = ceremony.snapshot()
    denied = _challenge_action(ceremony.client, actor, "sab_challenge_operator_http", "revalidate", reason)
    assert denied.status_code == 429, denied.text
    assert ceremony.snapshot() == before
    basis["adjudication_events"] = [latest]
    record = ceremony.review(basis)
    assert record.status_code == 201 and record.json()["status"] == "active", record.text
    assert ceremony.client.get("/api/v1/standing/" + record.json()["standing_id"]).json()["status"] == "active"


def test_duplicate_display_names_cannot_move_a_forbidden_reference(ceremony):
    first, second = _Agent(), _Agent()
    _register(ceremony.client, first, "duplicate", "unknown")
    _register(ceremony.client, second, "duplicate", "unknown")
    seed_id, claimant = "sab_seed_forbidden_name", ceremony.actors["claimant"]
    ceremony.client.authority.issue(ceremony.client, claimant.subject_id, seed_id, ["submit_seed"])
    ceremony.client.authority.issue(ceremony.client, first.subject_id, seed_id, ["submit_witness_event"])
    _submit_seed(ceremony.client, claimant, seed_id, forbidden_witnesses=["sab_identity_duplicate"])
    before = ceremony.snapshot()
    response = _witness_event(ceremony.client, first, seed_id, "affirm", {"finding": "The first named participant"})
    assert response.status_code == 403, response.text
    assert ceremony.snapshot() == before


@pytest.mark.parametrize("body,content_type,status", [
    ('[]', 'application/json', 400), ('{"assessment":{},"assessment":{}}', 'application/json', 400),
    ('{"assessment":NaN}', 'application/json', 400), ('{"assessment":0.5}', 'application/json', 400),
    ('{"value":"SYNTHETIC_PRIVATE_SENTINEL"}', 'text/plain', 415),
    ('{"value":"' + 'x' * (1024 * 1024) + '"}', 'application/json', 413),
])
def test_operator_http_inputs_are_bounded_and_fail_without_writes(ceremony, body, content_type, status):
    before = ceremony.snapshot()
    response = ceremony.client.post("/api/operator-control/assessments", content=body, headers={"content-type": content_type})
    assert response.status_code == status, response.text
    assert "SYNTHETIC_PRIVATE_SENTINEL" not in response.text
    assert ceremony.snapshot() == before


def test_public_mode_never_loads_private_operator_policy_or_reads_command_bodies(tmp_path, monkeypatch):
    monkeypatch.setenv("SAB_PUBLIC_MODE", "public_readonly")
    monkeypatch.setenv("SAB_OPERATOR_CONTROL_POLICY_PATH", str(tmp_path / "missing-private-policy"))
    monkeypatch.setenv("SAB_OPERATOR_CONTROL_POLICY_SHA256", "a" * 64)
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "private-must-not-exist.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "private-must-not-exist.key"))
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT", raising=False)
    monkeypatch.delenv("SAB_PUBLIC_SNAPSHOT_SHA256", raising=False)
    for name in list(sys.modules):
        if name == "agora" or name.startswith("agora."):
            del sys.modules[name]
    module = importlib.import_module("agora.app")
    with TestClient(module.app) as client:
        for path in ("/api/operator-control/assessments", "/api/operator-control/assessments/private/challenge",
                     "/api/operator-control/assessments/private/revoke", "/api/v1/challenges/private/revalidate"):
            response = client.post(path, content="invalid JSON" * 100000, headers={"content-type": "application/json"})
            assert response.status_code == 403, response.text
    assert not (tmp_path / "private-must-not-exist.db").exists()
    assert not (tmp_path / "private-must-not-exist.key").exists()


def test_high_impact_witness_requires_current_reviewed_control(ceremony):
    claimant, witness = ceremony.actors["claimant"], ceremony.actors["w1"]
    seed_id = "sab_seed_high_impact_control"
    authority = ceremony.client.authority
    authority.issue(ceremony.client, claimant.subject_id, seed_id, ["submit_seed"])
    authority.issue(ceremony.client, witness.subject_id, seed_id, ["submit_witness_event"])
    authority.issue(ceremony.client, ceremony.actors["challenger"].subject_id, seed_id, ["challenge_operator_control"])
    _submit_seed(ceremony.client, claimant, seed_id, impact="high")
    ceremony.seed_id = seed_id
    context = ceremony.context()["claim_sha256"]
    payload = {"operator_control_claim_sha256": context, "finding": "Synthetic high-impact inspection"}
    before = ceremony.snapshot()
    missing = _witness_event(ceremony.client, witness, seed_id, "affirm", payload)
    assert missing.status_code == 403, missing.text
    assert ceremony.snapshot() == before
    selector = ceremony.assessment("high_impact_witness")
    payload["operator_control_assessment"] = selector
    accepted = _witness_event(ceremony.client, witness, seed_id, "affirm", payload)
    assert accepted.status_code == 201, accepted.text
    _challenge_assessment(ceremony, selector)
    before = ceremony.snapshot()
    retired = _witness_event(ceremony.client, witness, seed_id, "affirm", payload)
    assert retired.status_code == 403, retired.text
    assert ceremony.snapshot() == before


@pytest.mark.parametrize("impact", ["hihg", None, 1])
def test_invalid_impact_cannot_silently_become_low(ceremony, impact):
    from test_sab_seeding_api import _seed_packet, _sign_seed
    actor, seed_id = ceremony.actors["claimant"], "sab_seed_bad_impact"
    ceremony.client.authority.issue(ceremony.client, actor.subject_id, seed_id, ["submit_seed"])
    packet = _seed_packet(actor.subject_id, seed_id=seed_id,
                          authority_reference=ceremony.client.authority.reference(actor.subject_id, seed_id))
    packet["witness_plan"]["impact"] = impact
    before = ceremony.snapshot()
    response = ceremony.client.post("/api/v1/seeds", json=_sign_seed(actor.key, packet, actor.subject_id))
    assert response.status_code == 400, response.text
    assert ceremony.snapshot() == before
