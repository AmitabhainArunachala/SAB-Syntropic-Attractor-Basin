"""Authority enforcement at the real signed HTTP boundary, using synthetic keys."""
from __future__ import annotations

import copy
import importlib
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from authority_fixtures import canonical, hash_json, reference_for
from keycontrol_fixtures import enroll_identity, prove_control
from operator_control_fixtures import adjudication_assessment
from test_sab_seeding_api import (
    _seed_packet, _sign_seed, _submit_seed, _challenge_packet,
    _submit_challenge, _sign_challenge_action, _sign_witness, _standing_lease,
    _sign_standing_review, _sign_standing_action, _now,
)


@pytest.fixture
def web_app(tmp_path, monkeypatch):
    from authority_fixtures import provision_authority_policy
    from operator_control_fixtures import provision_operator_policy

    authority = provision_authority_policy(tmp_path, monkeypatch)
    control = provision_operator_policy(tmp_path, monkeypatch)
    monkeypatch.setenv("SAB_SPARK_DB_PATH", str(tmp_path / "authority_http.db"))
    monkeypatch.setenv("SAB_SYSTEM_WITNESS_KEY", str(tmp_path / "synthetic_system.key"))
    for name in list(sys.modules):
        if name == "agora" or name.startswith("agora."):
            del sys.modules[name]
    module = importlib.import_module("agora.app")
    module.authority_test_fixture = authority
    module.operator_control_test_fixture = control
    return module


@pytest.fixture
def client(web_app):
    with TestClient(web_app.app) as test_client:
        web_app.authority_test_fixture.enroll(test_client)
        web_app.operator_control_test_fixture.enroll(test_client)
        yield test_client


def actor(client, name="authority participant"):
    key = SigningKey.generate()
    identity = enroll_identity(client, key, display_name=name)
    return identity["subject_id"], key


def state(web_app):
    with web_app._db() as conn:
        return tuple(conn.iterdump())


def seed_command(client, key, subject, seed_id, *, reference=None):
    packet = _seed_packet(subject, seed_id=seed_id,
                          authority_reference=reference or client.authority.reference(subject, seed_id))
    return _sign_seed(key, packet, subject)


def resign_challenge(packet, key, *, signer=None):
    packet = copy.deepcopy(packet)
    packet.pop("signature", None)
    message = {"kind": "sab_challenge_submit", "target_seed_id": packet["target_seed_id"],
               "target_claim_id": packet["target_claim_id"], "challenge_packet_sha256": hash_json(packet),
               "challenger_identity": packet["challenger_identity"], "created_at": packet["created_at"]}
    packet["signature"] = {"alg": "ed25519", "signer": signer or packet["challenger_identity"],
                           "signature": key.sign(canonical(message)).signature.hex(),
                           "canonicalization": "json-sort-keys-compact-v1"}
    return packet


def setup_seed(client, *, seed_id="sab_seed_authority_http"):
    subject, key = actor(client, "authority claimant")
    grant = client.authority.issue(client, subject, seed_id, ["submit_seed"])
    _submit_seed(client, key, subject, seed_id)
    return subject, key, grant


def setup_standing(client):
    seed_id = "sab_seed_authority_standing"
    standing_id = "sab_standing_authority_http"
    claimant, claimant_key, _ = setup_seed(client, seed_id=seed_id)
    challenger, challenger_key = actor(client, "authority challenger")
    reviewer, reviewer_key = actor(client, "authority reviewer")
    client.authority.issue(client, challenger, seed_id, ["submit_challenge", "challenge_standing"])
    review_grant = client.authority.issue(client, reviewer, seed_id, [
        "adjudicate_challenge", "submit_witness_event", "request_standing_review",
        "revalidate_standing", "revoke_standing",
    ])
    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    _submit_challenge(client, challenger_key, challenger_id=challenger, seed_id=seed_id,
                      claim_id=seed["claim_id"], challenge_id="sab_challenge_authority_standing")
    created = _now()
    reason = {"value": "Resolved within explicit test scope",
              "operator_control_assessment": adjudication_assessment(
                  client, seed_id, "sab_challenge_authority_standing", reviewer)}
    response = client.post("/api/v1/challenges/sab_challenge_authority_standing/reject", json={
        "actor_identity": reviewer, "created_at": created, "reason": reason,
        "signature": _sign_challenge_action(reviewer_key, action="reject",
                       challenge_id="sab_challenge_authority_standing", actor_identity=reviewer,
                       payload=reason, created_at=created),
    })
    assert response.status_code == 201, response.text
    previous = client.get(f"/api/v1/seeds/{seed_id}/chain").json()["head"]
    created = _now()
    response = client.post("/api/v1/witness-events", json={
        "event_type": "affirm", "actor_identity": reviewer, "subject_type": "seed", "subject_id": seed_id,
        "payload": {"reason": "Explicitly scoped observation"}, "created_at": created, "prev_hash": previous,
        "signature": _sign_witness(reviewer_key, event_type="affirm", subject_type="seed", subject_id=seed_id,
                       payload={"reason": "Explicitly scoped observation"}, prev_hash=previous, created_at=created),
    })
    assert response.status_code == 201, response.text
    lease = _standing_lease(standing_id=standing_id, seed_id=seed_id, claim_id=seed["claim_id"], reviewer_id=reviewer)
    response = client.post("/api/v1/standing/review", json=_sign_standing_review(reviewer_key, lease, reviewer))
    assert response.status_code == 201, response.text
    return {"seed_id": seed_id, "standing_id": standing_id, "claimant": claimant, "claimant_key": claimant_key,
            "reviewer": reviewer, "reviewer_key": reviewer_key, "challenger": challenger,
            "challenger_key": challenger_key, "review_grant": review_grant, "lease": lease}


def test_proved_key_requires_scoped_authority_home(client):
    subject, _ = actor(client)
    home = client.get("/api/v1/agents/me/home", params={"subject_id": subject}).json()
    assert home["identity_status"] == "active"
    assert home["active_authority_leases"] == []
    assert home["recommended_next_action"] == "obtain_scoped_authority"
    grant = client.authority.issue(client, subject, "sab_seed_home_authority", ["submit_seed"])
    home = client.get("/api/v1/agents/me/home", params={"subject_id": subject}).json()
    assert home["active_authority_leases"][0]["lease_id"] == grant["lease_id"]
    assert home["authority_effect"] == home["standing_effect"] == "none"


def test_policy_issuance_exact_retry_and_old_declaration_table_unchanged(client, web_app):
    subject, _ = actor(client)
    policy = client.get("/api/v1/authority/policy")
    assert policy.status_code == 200
    assert policy.json()["policy_hash"] == client.authority.policy_hash
    envelope = client.authority.envelope(client, subject, "sab_seed_issue_authority", ["submit_seed"])
    first = client.post("/api/v1/authority/leases", json=envelope)
    assert first.status_code == 201, first.text
    before = state(web_app)
    second = client.post("/api/v1/authority/leases", json=envelope)
    assert second.status_code == 200, second.text
    assert second.json()["created"] is False
    assert second.json()["issued_receipt_at"] == first.json()["issued_receipt_at"]
    assert state(web_app) == before
    with web_app._db() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sab_authority_leases_v1").fetchone()[0] == 0


def test_fabricated_lease_metadata_cannot_create_or_overwrite_authority(client, web_app):
    subject, key = actor(client)
    packet = _sign_seed(key, _seed_packet(subject, seed_id="sab_seed_fabricated_authority"), subject)
    before = state(web_app)
    response = client.post("/api/v1/seeds", json=packet)
    assert response.status_code in {404, 428}, response.text
    assert state(web_app) == before


@pytest.mark.parametrize("field,value", [("scope", "wider permission"), ("expires_at", "2099-01-01T00:00:00+00:00"),
                                         ("revoker", "agent_forged"), ("challenge_path", "/fake")])
def test_declared_lease_fields_must_equal_stored_grant(client, web_app, field, value):
    subject, key = actor(client)
    seed_id = "sab_seed_reference_mismatch"
    client.authority.issue(client, subject, seed_id, ["submit_seed"])
    reference = client.authority.reference(subject, seed_id)
    reference[field] = value
    command = seed_command(client, key, subject, seed_id, reference=reference)
    before = state(web_app)
    response = client.post("/api/v1/seeds", json=command)
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "authority_reference_mismatch"
    assert state(web_app) == before


@pytest.mark.parametrize("case", ["wrong_subject", "wrong_seed", "wrong_action", "unknown_field"])
def test_signed_seed_requires_exact_actor_action_and_resource(client, web_app, case):
    subject, key = actor(client)
    other, _ = actor(client, "different participant")
    seed_id = "sab_seed_scoped_authority"
    grant = client.authority.issue(client, other if case == "wrong_subject" else subject,
        "sab_seed_other_resource" if case == "wrong_seed" else seed_id,
        ["correct_seed"] if case == "wrong_action" else ["submit_seed"])
    reference = reference_for(grant)
    if case == "unknown_field":
        reference["allowed_actions"] = ["submit_seed", "canonize_standing"]
    before = state(web_app)
    response = client.post("/api/v1/seeds", json=seed_command(client, key, subject, seed_id, reference=reference))
    assert response.status_code in {400, 403}, response.text
    assert state(web_app) == before


def test_challenge_signer_cannot_impersonate_attributed_actor(client, web_app):
    seed_id = "sab_seed_actor_attribution"
    setup_seed(client, seed_id=seed_id)
    attributed, _ = actor(client, "attributed challenger")
    signer, signing_key = actor(client, "different signer")
    grant = client.authority.issue(client, attributed, seed_id, ["submit_challenge"])
    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    command = _challenge_packet(signing_key, challenger_id=attributed, seed_id=seed_id,
        claim_id=seed["claim_id"], challenge_id="sab_challenge_actor_attribution", authority_reference=reference_for(grant))
    command["signature"]["signer"] = signer
    before = state(web_app)
    response = client.post(f"/api/v1/seeds/{seed_id}/challenges", json=command)
    assert response.status_code == 403, response.text
    assert "signer" in response.text
    assert state(web_app) == before


@pytest.mark.parametrize("retirement", ["grant", "key"])
def test_claimant_retirement_does_not_silence_permitted_challenger(client, retirement):
    seed_id = "sab_seed_retired_claimant"
    subject, key, grant = setup_seed(client, seed_id=seed_id)
    challenger, challenger_key = actor(client)
    client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
    if retirement == "grant":
        response = client.post(f"/api/v1/authority/leases/{grant['lease_id']}/revoke", json=client.authority.revocation(grant))
        assert response.status_code == 200, response.text
    else:
        prove_control(client, key, {"action": "revoke", "subject_id": subject})
    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    result = _submit_challenge(client, challenger_key, challenger_id=challenger, seed_id=seed_id,
                              claim_id=seed["claim_id"], challenge_id="sab_challenge_retired_claimant")
    assert result["status"] == "pending"


def test_authority_challenge_path_is_real_exact_and_does_not_auto_revoke(client, web_app):
    seed_id = "sab_seed_linked_authority"
    claimant, claimant_key = actor(client)
    grant = client.authority.issue(client, claimant, seed_id, ["submit_seed"])
    challenger, challenger_key = actor(client)
    client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
    packet = _challenge_packet(challenger_key, challenger_id=challenger, seed_id=seed_id,
        claim_id=f"sab_claim_{seed_id}", challenge_id="sab_challenge_linked_authority",
        authority_reference=client.authority.reference(challenger, seed_id))
    packet.update(authority_lease_id=grant["lease_id"], authority_lease_sha256=grant["lease_sha256"])
    packet = resign_challenge(packet, challenger_key)
    before = state(web_app)
    response = client.post(grant["lease"]["challenge_path"], json=packet)
    assert response.status_code == 409, response.text
    assert "linked seed" in response.text
    assert state(web_app) == before
    _submit_seed(client, claimant_key, claimant, seed_id)
    wrong = copy.deepcopy(packet)
    wrong["authority_lease_sha256"] = "0" * 64
    before = state(web_app)
    response = client.post(grant["lease"]["challenge_path"], json=wrong)
    assert response.status_code == 400
    assert state(web_app) == before
    response = client.post(grant["lease"]["challenge_path"], json=packet)
    assert response.status_code == 201, response.text
    listed = client.get(grant["lease"]["challenge_path"])
    assert listed.status_code == 200
    assert listed.json()["items"][0]["challenge_packet"] == packet
    assert client.get(f"/api/v1/authority/leases/{grant['lease_id']}").json()["status"] == "active"


def advance_command(key, actor_id, seed_id, previous):
    created = _now()
    message = {"kind": "sab_seed_advance_deadlines", "seed_id": seed_id, "actor_identity": actor_id,
               "prev_hash": previous, "created_at": created}
    return {key: value for key, value in message.items() if key not in {"kind", "seed_id"}} | {
        "signature": key.sign(canonical(message)).signature.hex()}


def test_reads_do_not_advance_deadlines_and_explicit_scoped_advance_does(client, web_app):
    seed_id = "sab_seed_explicit_advance"
    claimant, claimant_key, _ = setup_seed(client, seed_id=seed_id)
    challenger, challenger_key = actor(client)
    client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    packet = _challenge_packet(challenger_key, challenger_id=challenger, seed_id=seed_id,
        claim_id=seed["claim_id"], challenge_id="sab_challenge_explicit_advance",
        authority_reference=client.authority.reference(challenger, seed_id))
    packet["deadline"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    packet = resign_challenge(packet, challenger_key)
    response = client.post(f"/api/v1/seeds/{seed_id}/challenges", json=packet)
    assert response.status_code == 201, response.text
    before = state(web_app)
    for path in (f"/api/v1/seeds/{seed_id}", f"/api/v1/seeds/{seed_id}/chain", "/api/v1/seeds",
                 "/api/v1/challenges/sab_challenge_explicit_advance", "/api/v1/standing"):
        assert client.get(path).status_code == 200
    assert state(web_app) == before
    previous = client.get(f"/api/v1/seeds/{seed_id}/chain").json()["head"]
    command = advance_command(claimant_key, claimant, seed_id, previous)
    response = client.post(f"/api/v1/seeds/{seed_id}/advance", json=command)
    assert response.status_code == 428, response.text
    assert state(web_app) == before
    grant = client.authority.issue(client, claimant, seed_id, ["advance_deadlines"])
    response = client.post(f"/api/v1/seeds/{seed_id}/advance", json=command)
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "compost"
    assert len(response.json()["generated_witness_ids"]) == 2
    assert response.json()["authority"]["lease_id"] == grant["lease_id"]
    assert client.get("/api/v1/challenges/sab_challenge_explicit_advance").json()["status"] == "sustained_by_default"
    assert client.get(f"/api/v1/witness/verify?seed_id={seed_id}").json()["verified"] is True
    before = state(web_app)
    assert client.post(f"/api/v1/seeds/{seed_id}/advance", json=command).status_code == 409
    assert state(web_app) == before


@pytest.mark.parametrize("event_type,allowed_action", [("response", "respond_challenge"), ("correction", "correct_seed")])
def test_generic_witness_effects_cannot_bypass_claimant_role(client, web_app, event_type, allowed_action):
    seed_id = "sab_seed_witness_actor"
    setup_seed(client, seed_id=seed_id)
    outsider, key = actor(client)
    client.authority.issue(client, outsider, seed_id, [allowed_action, "submit_witness_event"])
    previous = client.get(f"/api/v1/seeds/{seed_id}/chain").json()["head"]
    created = _now()
    payload = {"reason": "Attempted claimant effect"}
    command = {"event_type": event_type, "actor_identity": outsider, "subject_type": "seed", "subject_id": seed_id,
               "prev_hash": previous, "created_at": created, "payload": payload,
               "signature": _sign_witness(key, event_type=event_type, subject_type="seed", subject_id=seed_id,
                                           payload=payload, prev_hash=previous, created_at=created)}
    before = state(web_app)
    response = client.post("/api/v1/witness-events", json=command)
    assert response.status_code == 403, response.text
    assert state(web_app) == before


def test_generic_witness_effect_requires_effect_action_permission(client, web_app):
    seed_id = "sab_seed_witness_action"
    subject, key, _ = setup_seed(client, seed_id=seed_id)
    client.authority.issue(client, subject, seed_id, ["submit_witness_event"])
    previous = client.get(f"/api/v1/seeds/{seed_id}/chain").json()["head"]
    created = _now()
    command = {"event_type": "correction", "actor_identity": subject, "subject_type": "seed", "subject_id": seed_id,
               "prev_hash": previous, "created_at": created, "payload": {},
               "signature": _sign_witness(key, event_type="correction", subject_type="seed", subject_id=seed_id,
                                           payload={}, prev_hash=previous, created_at=created)}
    before = state(web_app)
    response = client.post("/api/v1/witness-events", json=command)
    assert response.status_code == 428, response.text
    assert state(web_app) == before


def test_standing_inner_issuer_must_equal_authenticated_reviewer(client, web_app):
    scenario = setup_standing(client)
    lease = {**scenario["lease"], "standing_id": "sab_standing_false_attribution", "issued_by": scenario["challenger"]}
    signed = _sign_standing_review(scenario["reviewer_key"], lease, scenario["reviewer"])
    before = state(web_app)
    response = client.post("/api/v1/standing/review", json={"standing_lease": signed, "reviewer_identity": scenario["reviewer"]})
    assert response.status_code == 403, response.text
    assert state(web_app) == before


@pytest.mark.parametrize("signed_promotion", [False, True])
def test_canon_requires_both_signed_effect_and_canon_permission(client, web_app, signed_promotion):
    scenario = setup_standing(client)
    created = _now()
    command = {"actor_identity": scenario["reviewer"], "created_at": created, "reason": "Canon request", "evidence": {},
               "promote_to_canon": True,
               "signature": _sign_standing_action(scenario["reviewer_key"], action="revalidate",
                    standing_id=scenario["standing_id"], actor_identity=scenario["reviewer"], reason="Canon request",
                    evidence={}, created_at=created, promote_to_canon=signed_promotion)}
    before = state(web_app)
    response = client.post(f"/api/v1/standing/{scenario['standing_id']}/revalidate", json=command)
    assert response.status_code == (428 if signed_promotion else 400), response.text
    assert state(web_app) == before


@pytest.mark.parametrize("body,content_type,status", [('{"lease":{},"lease":{}}', "application/json", 400),
    ('{"lease":NaN}', "application/json", 400), ('{"lease":1e9999}', "application/json", 400),
    ('[]', "application/json", 400), ('{"private_key":"secret-never-reflect"}', "text/plain", 415),
    ('{"private_key":"' + 'x' * 66000 + '"}', "application/json", 413)])
def test_authority_commands_are_bounded_strict_and_nonreflecting(client, web_app, body, content_type, status):
    before = state(web_app)
    response = client.post("/api/v1/authority/leases", content=body, headers={"content-type": content_type})
    assert response.status_code == status, response.text
    assert "secret-never-reflect" not in response.text
    assert state(web_app) == before


def test_public_router_rejects_before_parsing_and_never_opens_private_rows():
    from agora.sab_seeding_api import SabSeedingDeps, create_sab_seeding_router

    def forbidden(*args, **kwargs):
        raise AssertionError("Public route touched private state")

    app = FastAPI()
    app.include_router(create_sab_seeding_router(SabSeedingDeps(
        init_db=forbidden, db=forbidden, verify_agent_signature=forbidden, system_sign=forbidden,
        utc_now=forbidden, invalidate_web_cache=forbidden, read_only=True, read_observation=lambda: None,
    )))
    with TestClient(app) as public:
        for path in ("/api/v1/authority/leases", "/api/v1/authority/leases/sab_lease_private/revoke",
                     "/api/v1/authority/leases/sab_lease_private/challenges", "/api/v1/seeds", "/api/v1/standing/review",
                     "/api/v1/seeds/sab_seed_private/advance"):
            response = public.post(path, content="not JSON" * 10000, headers={"content-type": "application/json"})
            assert response.status_code == 403, response.text
        for path in ("/api/v1/authority/policy", "/api/v1/authority/leases/sab_lease_private",
                     "/api/v1/authority/leases/sab_lease_private/challenges"):
            assert public.get(path).status_code == 404


@pytest.mark.parametrize("action", ["correct", "withdraw", "witness", "respond", "adjudicate", "review", "challenge_standing", "revoke_standing", "revalidate_standing"])
def test_every_existing_actor_mutation_requires_its_covering_grant(client, web_app, action):
    if action in {"review", "challenge_standing", "revoke_standing", "revalidate_standing"}:
        scenario = setup_standing(client)
        seed_id = scenario["seed_id"]
        subject, key = scenario["reviewer"], scenario["reviewer_key"]
        revoked = scenario["review_grant"]
        if action == "challenge_standing":
            subject, key = scenario["challenger"], scenario["challenger_key"]
            revoked = client.authority.grants[(subject, seed_id)]
        retirement = client.post(f"/api/v1/authority/leases/{revoked['lease_id']}/revoke", json=client.authority.revocation(revoked))
        assert retirement.status_code == 200, retirement.text
        created = _now()
        if action == "review":
            lease = {**scenario["lease"], "standing_id": "sab_standing_without_permission"}
            command = _sign_standing_review(key, lease, subject)
            path = "/api/v1/standing/review"
        else:
            operation = action.split("_", 1)[0]
            path = f"/api/v1/standing/{scenario['standing_id']}/{operation}"
            command = {"actor_identity": subject, "created_at": created, "reason": "Permission is required",
                       "signature": _sign_standing_action(key, action=operation, standing_id=scenario["standing_id"],
                                        actor_identity=subject, reason="Permission is required", evidence={}, created_at=created)}
    else:
        seed_id = "sab_seed_command_requires_authority"
        subject, key, _ = setup_seed(client, seed_id=seed_id)
        created = _now()
        if action == "correct":
            message = {"kind": "sab_seed_correct", "target_seed_id": seed_id, "actor_identity": subject,
                       "correction_sha256": hash_json({}), "created_at": created}
            command = {"actor_identity": subject, "created_at": created, "correction": {},
                       "signature": key.sign(canonical(message)).signature.hex()}
            path = f"/api/v1/seeds/{seed_id}/correct"
        elif action == "withdraw":
            message = {"kind": "sab_seed_withdraw", "target_seed_id": seed_id, "actor_identity": subject,
                       "reason_sha256": __import__("hashlib").sha256(b"withdraw").hexdigest(), "created_at": created}
            command = {"actor_identity": subject, "created_at": created, "reason": "withdraw",
                       "signature": key.sign(canonical(message)).signature.hex()}
            path = f"/api/v1/seeds/{seed_id}/withdraw"
        elif action == "witness":
            subject, key = actor(client)
            previous = client.get(f"/api/v1/seeds/{seed_id}/chain").json()["head"]
            command = {"actor_identity": subject, "event_type": "affirm", "subject_type": "seed", "subject_id": seed_id,
                       "created_at": created, "prev_hash": previous, "payload": {},
                       "signature": _sign_witness(key, event_type="affirm", subject_type="seed", subject_id=seed_id,
                                                   payload={}, prev_hash=previous, created_at=created)}
            path = "/api/v1/witness-events"
        else:
            challenger, challenger_key = actor(client)
            client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
            seed = client.get(f"/api/v1/seeds/{seed_id}").json()
            _submit_challenge(client, challenger_key, challenger_id=challenger, seed_id=seed_id,
                              claim_id=seed["claim_id"], challenge_id="sab_challenge_requires_authority")
            operation = "respond" if action == "respond" else "reject"
            if action == "adjudicate":
                subject, key = actor(client)
            body = {"value": "Signed statement without a covering permission"}
            created = _now()
            command = {"actor_identity": subject, "created_at": created,
                       "response" if action == "respond" else "reason": body,
                       "signature": _sign_challenge_action(key, action=operation, challenge_id="sab_challenge_requires_authority",
                                                            actor_identity=subject, payload=body, created_at=created)}
            path = f"/api/v1/challenges/sab_challenge_requires_authority/{operation}"
    before = state(web_app)
    response = client.post(path, json=command)
    assert response.status_code == 428, response.text
    assert response.json()["code"].startswith("authority_")
    assert state(web_app) == before


def test_unsigned_witness_selector_cannot_override_deterministic_issued_permission(client, web_app):
    seed_id = "sab_seed_deterministic_authority"
    setup_seed(client, seed_id=seed_id)
    subject, key = actor(client)
    later = client.authority.issue(client, subject, seed_id, ["submit_witness_event"], lease_id="sab_lease_z_selection")
    first = client.authority.issue(client, subject, seed_id, ["submit_witness_event"], lease_id="sab_lease_a_selection")
    created = _now()
    previous = client.get(f"/api/v1/seeds/{seed_id}/chain").json()["head"]
    command = {"actor_identity": subject, "event_type": "affirm", "subject_type": "seed", "subject_id": seed_id,
               "created_at": created, "prev_hash": previous, "payload": {"observation": "exact original payload"},
               "authority_lease": reference_for(later),
               "signature": _sign_witness(key, event_type="affirm", subject_type="seed", subject_id=seed_id,
                           payload={"observation": "exact original payload"}, prev_hash=previous, created_at=created)}
    before = state(web_app)
    response = client.post("/api/v1/witness-events", json=command)
    assert response.status_code == 400, response.text
    assert state(web_app) == before
    command.pop("authority_lease")
    response = client.post("/api/v1/witness-events", json=command)
    assert response.status_code == 201, response.text
    result = response.json()
    assert result["authority"]["lease_id"] == first["lease_id"]
    assert result["payload"] == command["payload"]
    assert result["payload_hash"] == hash_json(command["payload"])
    fetched = client.get(f"/api/v1/witness-events/{result['event_id']}").json()
    assert fetched["authority"] == result["authority"]
    assert client.get(f"/api/v1/witness/verify?seed_id={seed_id}").json()["verified"] is True


def test_authentic_second_issuer_packet_cannot_overwrite_a_lease_id_across_subjects(client, web_app):
    original, _ = actor(client, "original grantee")
    alternate, _ = actor(client, "alternate grantee")
    grant = client.authority.issue(client, original, "sab_seed_immutable_grant", ["submit_seed"])
    replacement = client.authority.envelope(client, alternate, "sab_seed_immutable_grant", ["submit_seed"], lease_id=grant["lease_id"])
    before = state(web_app)
    response = client.post("/api/v1/authority/leases", json=replacement)
    assert response.status_code == 409, response.text
    assert state(web_app) == before
    assert client.get(f"/api/v1/authority/leases/{grant['lease_id']}").json()["lease"]["subject_id"] == original


@pytest.mark.parametrize("tamper", ["missing_issuer_signature", "allowed_actions", "scope", "policy_hash", "witness_signature", "witness_digest"])
def test_issuance_http_rejects_unauthenticated_or_changed_signed_grants(client, web_app, tamper):
    subject, _ = actor(client)
    envelope = client.authority.envelope(client, subject, "sab_seed_tamper_issuance", ["submit_seed"])
    if tamper == "missing_issuer_signature":
        envelope.pop("issuer_signature")
    elif tamper == "allowed_actions":
        envelope["lease"]["allowed_actions"].append("canonize_standing")
    elif tamper == "scope":
        envelope["lease"]["scope"] = "Changed after signature"
    elif tamper == "policy_hash":
        envelope["lease"]["policy_hash"] = "0" * 64
    elif tamper == "witness_signature":
        envelope["issuance_witness"]["signature"] = "0" * 128
    else:
        envelope["issuance_witness"]["lease_sha256"] = "0" * 64
    before = state(web_app)
    response = client.post("/api/v1/authority/leases", json=envelope)
    assert response.status_code in {400, 403}, response.text
    assert state(web_app) == before


def test_a_claimant_response_is_not_challenge_resolution_for_standing(client, web_app):
    seed_id = "sab_seed_response_not_resolution"
    claimant, claimant_key, _ = setup_seed(client, seed_id=seed_id)
    challenger, challenger_key = actor(client)
    reviewer, reviewer_key = actor(client)
    client.authority.issue(client, claimant, seed_id, ["respond_challenge"])
    client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
    client.authority.issue(client, reviewer, seed_id, ["request_standing_review"])
    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    challenge_id = "sab_challenge_response_not_resolution"
    _submit_challenge(client, challenger_key, challenger_id=challenger, seed_id=seed_id,
                      claim_id=seed["claim_id"], challenge_id=challenge_id)
    created = _now()
    body = {"value": "The claimant says the objection is addressed"}
    response = client.post(f"/api/v1/challenges/{challenge_id}/respond", json={
        "actor_identity": claimant, "created_at": created, "response": body,
        "signature": _sign_challenge_action(claimant_key, action="respond", challenge_id=challenge_id,
                                              actor_identity=claimant, payload=body, created_at=created),
    })
    assert response.status_code == 201, response.text
    lease = _standing_lease(standing_id="sab_standing_response_not_resolution", seed_id=seed_id,
                             claim_id=seed["claim_id"], reviewer_id=reviewer)
    before = state(web_app)
    response = client.post("/api/v1/standing/review", json=_sign_standing_review(reviewer_key, lease, reviewer))
    assert response.status_code == 409, response.text
    assert "resolved challenge" in response.text
    assert state(web_app) == before


def test_expired_standing_gets_observe_without_changing_stored_history(client, web_app, monkeypatch):
    import importlib
    scenario = setup_standing(client)
    observed_at = datetime.now(timezone.utc) + timedelta(days=31)

    class FutureObservation(datetime):
        @classmethod
        def now(cls, tz=None):
            return observed_at if tz else observed_at.replace(tzinfo=None)

    module = importlib.import_module("agora.sab_seeding_api")
    monkeypatch.setattr(module, "datetime", FutureObservation)
    before = state(web_app)
    fetched = client.get(f"/api/v1/standing/{scenario['standing_id']}").json()
    listed = client.get("/api/v1/standing", params={"status": "expired"}).json()["items"]
    assert fetched["status"] == "expired"
    assert fetched["stored_status"] == "provisional"
    assert fetched["status_basis"] == "expiry_observation"
    assert listed[0]["standing_id"] == scenario["standing_id"]
    assert listed[0]["stored_status"] == "provisional"
    assert state(web_app) == before


def test_authorized_effect_and_revocation_serialize_in_one_write_transaction(client, web_app, monkeypatch):
    import concurrent.futures
    import sqlite3
    import threading

    seed_id = "sab_seed_transaction_authority"
    subject, key, _ = setup_seed(client, seed_id=seed_id)
    grant = client.authority.issue(client, subject, seed_id, ["correct_seed"])
    authorized, release, revocation_entered = threading.Event(), threading.Event(), threading.Event()
    original = web_app.AUTHORITY.authorize_actor

    def controlled(conn, **kwargs):
        result = original(conn, **kwargs)
        if kwargs["action"] == "correct_seed":
            authorized.set()
            assert release.wait(5), "test did not release the authorized actor"
        return result

    monkeypatch.setattr(web_app.AUTHORITY, "authorize_actor", controlled)

    def correction(text):
        created = _now()
        body = {"text": text}
        message = {"kind": "sab_seed_correct", "target_seed_id": seed_id, "actor_identity": subject,
                   "correction_sha256": hash_json(body), "created_at": created}
        return {"actor_identity": subject, "created_at": created, "correction": body,
                "signature": key.sign(canonical(message)).signature.hex()}

    revocation = client.authority.revocation(grant)
    with TestClient(web_app.app) as second_client, concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        write = pool.submit(client.post, f"/api/v1/seeds/{seed_id}/correct", json=correction("First permitted correction"))
        try:
            assert authorized.wait(5)
            probe = sqlite3.connect(web_app.SPARK_DB, timeout=0)
            try:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    probe.execute("BEGIN IMMEDIATE")
            finally:
                probe.close()

            def retire():
                revocation_entered.set()
                return second_client.post(f"/api/v1/authority/leases/{grant['lease_id']}/revoke", json=revocation)

            retirement = pool.submit(retire)
            assert revocation_entered.wait(5)
        finally:
            release.set()
        applied = write.result(timeout=10)
        retired = retirement.result(timeout=10)
    assert applied.status_code == 200, applied.text
    assert retired.status_code == 200, retired.text
    before = state(web_app)
    denied = client.post(f"/api/v1/seeds/{seed_id}/correct", json=correction("Permission has retired"))
    assert denied.status_code == 428, denied.text
    assert state(web_app) == before


def test_historical_web_only_home_remains_observable_without_manufactured_authority(client, web_app):
    from keycontrol_fixtures import historical_web_identity
    key = SigningKey.generate()
    historic = historical_web_identity(web_app, key.verify_key.encode().hex(), "old web-only participant")
    before = state(web_app)
    response = client.get("/api/v1/agents/me/home", params={"subject_id": historic["id"]})
    assert response.status_code == 200, response.text
    assert response.json()["identity_status"] == "unproven"
    assert response.json()["active_authority_leases"] == []
    assert response.json()["authority_effect"] == "none"
    assert state(web_app) == before


def test_openapi_authority_bodies_validate_real_commands_with_published_schemas(client, web_app):
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource

    specification = client.get("/openapi.json").json()
    registry = Registry()
    for name in ("sab.authority_lease.v2", "sab.authority_issuance_witness.v1", "sab.authority_revocation.v1"):
        path = f"/schemas/{name}.schema.json"
        response = client.get(path)
        assert response.status_code == 200, response.text
        document = response.json()
        Draft202012Validator.check_schema(document)
        registry = registry.with_resource(f"http://testserver{path}", Resource.from_contents(document))

    def validator(path):
        operation = specification["paths"][path]["post"]
        assert operation["requestBody"]["required"] is True
        schema = operation["requestBody"]["content"]["application/json"]["schema"]
        Draft202012Validator.check_schema(schema)
        return Draft202012Validator({"$id": "http://testserver/openapi.json", **schema},
                                    registry=registry, format_checker=FormatChecker())

    issue_shape = validator("/api/v1/authority/leases")
    assert "200" in specification["paths"]["/api/v1/authority/leases"]["post"]["responses"]
    claimant, claimant_key = actor(client)
    seed_id = "sab_seed_openapi_authority"
    issue = client.authority.envelope(client, claimant, seed_id, ["submit_seed"])
    issue_shape.validate(issue)
    for location in (None, "lease", "issuance_witness"):
        changed = copy.deepcopy(issue)
        (changed if location is None else changed[location])["unsigned_override"] = True
        assert not issue_shape.is_valid(changed)
        before = state(web_app)
        response = client.post("/api/v1/authority/leases", json=changed)
        assert response.status_code == 400, response.text
        assert state(web_app) == before
    issued = client.post("/api/v1/authority/leases", json=issue)
    assert issued.status_code == 201, issued.text
    grant = issued.json()
    seeded = client.post("/api/v1/seeds", json=seed_command(client, claimant_key, claimant, seed_id, reference=reference_for(grant)))
    assert seeded.status_code == 201, seeded.text

    challenger, challenger_key = actor(client)
    challenger_grant = client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
    challenge_shape = validator("/api/v1/authority/leases/{lease_id}/challenges")
    challenge = _challenge_packet(challenger_key, challenger_id=challenger, seed_id=seed_id,
        claim_id=f"sab_claim_{seed_id}", challenge_id="sab_challenge_openapi_authority",
        authority_reference=reference_for(challenger_grant))
    challenge.update(authority_lease_id=grant["lease_id"], authority_lease_sha256=grant["lease_sha256"],
                     additional_signed_observation={"detail": "The legacy packet remains extensible"})
    challenge = resign_challenge(challenge, challenger_key)
    challenge_shape.validate(challenge)
    for wrapper in ("challenge_packet", "packet"):
        challenge_shape.validate({wrapper: challenge})
        inner = {key: value for key, value in challenge.items() if key != "signature"}
        challenge_shape.validate({wrapper: inner, "signature": challenge["signature"]})
    missing_link = {key: value for key, value in challenge.items() if key != "authority_lease_sha256"}
    assert not challenge_shape.is_valid(missing_link)
    before = state(web_app)
    assert client.post(grant["lease"]["challenge_path"], json=missing_link).status_code == 400
    assert state(web_app) == before
    challenged = client.post(grant["lease"]["challenge_path"], json=challenge)
    assert challenged.status_code == 201, challenged.text
    assert challenged.json()["challenge_packet"]["additional_signed_observation"] == challenge["additional_signed_observation"]

    revoke_shape = validator("/api/v1/authority/leases/{lease_id}/revoke")
    revocation = client.authority.revocation(grant)
    revoke_shape.validate(revocation)
    for location in (None, "revocation"):
        changed = copy.deepcopy(revocation)
        (changed if location is None else changed[location])["unsigned_override"] = True
        assert not revoke_shape.is_valid(changed)
        before = state(web_app)
        response = client.post(f"/api/v1/authority/leases/{grant['lease_id']}/revoke", json=changed)
        assert response.status_code == 400, response.text
        assert state(web_app) == before
    retired = client.post(f"/api/v1/authority/leases/{grant['lease_id']}/revoke", json=revocation)
    assert retired.status_code == 200, retired.text


def response_scenario(client):
    seed_id = "sab_seed_response_replay"
    claimant, claimant_key, _ = setup_seed(client, seed_id=seed_id)
    challenger, challenger_key = actor(client)
    client.authority.issue(client, claimant, seed_id, ["respond_challenge"])
    client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
    seed = client.get(f"/api/v1/seeds/{seed_id}").json()
    challenge_id = "sab_challenge_response_replay"
    _submit_challenge(client, challenger_key, challenger_id=challenger, seed_id=seed_id,
                      claim_id=seed["claim_id"], challenge_id=challenge_id)
    return seed_id, challenge_id, claimant, claimant_key


def response_command(key, subject, challenge_id, text, *, legacy=False):
    import hashlib
    if legacy:
        message = {"kind": "sab_challenge_response", "challenge_id": challenge_id,
                   "responder_identity": subject, "response_sha256": hashlib.sha256(text.encode()).hexdigest()}
        return {"responder_identity": subject, "response": text,
                "signature": key.sign(canonical(message)).signature.hex()}
    created = _now()
    return {"actor_identity": subject, "created_at": created, "response": text,
            "signature": _sign_challenge_action(key, action="respond", challenge_id=challenge_id,
                                actor_identity=subject, payload={"value": text}, created_at=created)}


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("wire_signature", ["original", "uppercase"])
def test_signed_response_replay_leaves_result_history_and_deadline_unchanged(client, web_app, legacy, wire_signature):
    _, challenge_id, claimant, key = response_scenario(client)
    command = response_command(key, claimant, challenge_id, "The same accepted response", legacy=legacy)
    first = client.post(f"/api/v1/challenges/{challenge_id}/respond", json=command)
    assert first.status_code == 201, first.text
    before = state(web_app)
    replay = copy.deepcopy(command)
    if wire_signature == "uppercase":
        replay["signature"] = replay["signature"].upper()
    response = client.post(f"/api/v1/challenges/{challenge_id}/respond", json=replay)
    assert response.status_code == 409, response.text
    assert state(web_app) == before


def test_revised_response_needs_new_signature_and_preserves_first_prosecution_deadline(client, web_app, monkeypatch):
    import importlib
    _, challenge_id, claimant, key = response_scenario(client)
    original = response_command(key, claimant, challenge_id, "First response")
    first = client.post(f"/api/v1/challenges/{challenge_id}/respond", json=original)
    assert first.status_code == 201, first.text
    with web_app._db() as conn:
        deadline = conn.execute("SELECT prosecute_by FROM sab_challenge_packets_v1 WHERE challenge_id=?", (challenge_id,)).fetchone()[0]
    module = importlib.import_module("agora.sab_seeding_api")
    # If a revised response recomputes its deadline, make the defect deterministic.
    later_deadline = (datetime.fromisoformat(deadline) + timedelta(days=7)).isoformat()
    monkeypatch.setattr(module, "_challenge_prosecute_by", lambda packet: later_deadline)
    revised = response_command(key, claimant, challenge_id, "A fresh signed correction to the first response")
    assert revised["signature"] != original["signature"]
    accepted = client.post(f"/api/v1/challenges/{challenge_id}/respond", json=revised)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["response_id"] != first.json()["response_id"]
    with web_app._db() as conn:
        row = conn.execute("SELECT prosecute_by, response_json FROM sab_challenge_packets_v1 WHERE challenge_id=?", (challenge_id,)).fetchone()
        assert row["prosecute_by"] == deadline
        assert "fresh signed correction" in row["response_json"]
    before = state(web_app)
    # Historical accepted responses remain spent after a later genuine revision.
    assert client.post(f"/api/v1/challenges/{challenge_id}/respond", json=original).status_code == 409
    assert state(web_app) == before
    forged_revision = {**revised, "response": "Changed without a new signature"}
    assert client.post(f"/api/v1/challenges/{challenge_id}/respond", json=forged_revision).status_code == 400
    assert state(web_app) == before


@pytest.mark.parametrize("action", ["sustain", "reject"])
def test_final_challenge_adjudication_replay_cannot_append_history(client, web_app, action):
    seed_id, challenge_id, _, _ = response_scenario(client)
    reviewer, key = actor(client)
    client.authority.issue(client, reviewer, seed_id, ["adjudicate_challenge"])
    created = _now()
    reason = {"value": "A final scoped adjudication",
              "operator_control_assessment": adjudication_assessment(client, seed_id, challenge_id, reviewer)}
    command = {"actor_identity": reviewer, "created_at": created, "reason": reason,
               "signature": _sign_challenge_action(key, action=action, challenge_id=challenge_id,
                                                     actor_identity=reviewer, payload=reason, created_at=created)}
    first = client.post(f"/api/v1/challenges/{challenge_id}/{action}", json=command)
    assert first.status_code == 201, first.text
    before = state(web_app)
    assert client.post(f"/api/v1/challenges/{challenge_id}/{action}", json=command).status_code == 409
    assert state(web_app) == before


def correction_command(key, subject, seed_id, text):
    created = _now()
    body = {"text": text}
    message = {"kind": "sab_seed_correct", "target_seed_id": seed_id, "actor_identity": subject,
               "correction_sha256": hash_json(body), "created_at": created}
    return {"actor_identity": subject, "created_at": created, "correction": body,
            "signature": key.sign(canonical(message)).signature.hex()}


def altered_signature(signature, spelling):
    if spelling == "uppercase":
        return signature.upper()
    if spelling == "whitespace":
        return " \t\r\n\v\f".join(signature[index:index + 2] for index in range(0, len(signature), 2))
    return signature


@pytest.mark.parametrize("spelling", ["original", "uppercase", "whitespace"])
def test_old_correction_cannot_be_replayed_across_a_new_challenge(client, web_app, spelling):
    seed_id = "sab_seed_correction_replay"
    claimant, key, _ = setup_seed(client, seed_id=seed_id)
    client.authority.issue(client, claimant, seed_id, ["correct_seed"])
    command = correction_command(key, claimant, seed_id, "Original correction")
    assert client.post(f"/api/v1/seeds/{seed_id}/correct", json=command).status_code == 200
    challenger, challenger_key = actor(client)
    client.authority.issue(client, challenger, seed_id, ["submit_challenge"])
    _submit_challenge(client, challenger_key, challenger_id=challenger, seed_id=seed_id,
                      claim_id=f"sab_claim_{seed_id}", challenge_id="sab_challenge_after_old_correction")
    before = state(web_app)
    replay = {**command, "signature": altered_signature(command["signature"], spelling)}
    response = client.post(f"/api/v1/seeds/{seed_id}/correct", json=replay)
    assert response.status_code == 409, response.text
    assert state(web_app) == before


@pytest.mark.parametrize("spelling", ["uppercase", "whitespace"])
def test_historical_signature_alias_cannot_be_reused_as_canonical_hex(client, web_app, spelling):
    seed_id = "sab_seed_historical_signature_alias"
    claimant, key, _ = setup_seed(client, seed_id=seed_id)
    client.authority.issue(client, claimant, seed_id, ["correct_seed"])
    command = correction_command(key, claimant, seed_id, "Already used historical signature")
    assert client.post(f"/api/v1/seeds/{seed_id}/correct", json=command).status_code == 200
    historical = altered_signature(command["signature"], spelling)
    with web_app._db() as conn:
        # Simulate the old API's accepted spelling in its replay index only.
        # No authority, identity proof, signed event, or source packet is fabricated.
        changed = conn.execute("UPDATE sab_signature_index_v1 SET signature=? WHERE signature=?", (historical, command["signature"]))
        assert changed.rowcount == 1
    before = state(web_app)
    response = client.post(f"/api/v1/seeds/{seed_id}/correct", json=command)
    assert response.status_code == 409, response.text
    assert state(web_app) == before


@pytest.mark.parametrize("spelling", ["uppercase", "whitespace"])
def test_new_actor_signatures_require_canonical_hex_before_any_effect(client, web_app, spelling):
    seed_id = "sab_seed_noncanonical_new_signature"
    claimant, key, _ = setup_seed(client, seed_id=seed_id)
    client.authority.issue(client, claimant, seed_id, ["correct_seed"])
    command = correction_command(key, claimant, seed_id, "New command must use canonical signature spelling")
    command["signature"] = altered_signature(command["signature"], spelling)
    before = state(web_app)
    response = client.post(f"/api/v1/seeds/{seed_id}/correct", json=command)
    assert response.status_code == 400, response.text
    assert state(web_app) == before


def standing_action_command(scenario, action, *, challenger=False, promote=False):
    subject = scenario["challenger"] if challenger else scenario["reviewer"]
    key = scenario["challenger_key"] if challenger else scenario["reviewer_key"]
    created = _now()
    reason = f"Fresh {action} request"
    command = {"actor_identity": subject, "created_at": created, "reason": reason, "evidence": {},
               "signature": _sign_standing_action(key, action=action, standing_id=scenario["standing_id"],
                    actor_identity=subject, reason=reason, evidence={}, created_at=created, promote_to_canon=promote)}
    if promote:
        command["promote_to_canon"] = True
    return command


def test_old_revalidation_cannot_erase_a_later_standing_challenge(client, web_app):
    scenario = setup_standing(client)
    path = f"/api/v1/standing/{scenario['standing_id']}"
    original = standing_action_command(scenario, "revalidate")
    assert client.post(f"{path}/revalidate", json=original).status_code == 200
    challenged = client.post(f"{path}/challenge", json=standing_action_command(scenario, "challenge", challenger=True))
    assert challenged.status_code == 200, challenged.text
    before = state(web_app)
    response = client.post(f"{path}/revalidate", json=original)
    assert response.status_code == 409, response.text
    assert state(web_app) == before


@pytest.mark.parametrize("challenge_status", ["pending", "responded"])
@pytest.mark.parametrize("promote", [False, True])
def test_fresh_revalidation_cannot_bypass_unresolved_seed_challenges(client, web_app, challenge_status, promote):
    scenario = setup_standing(client)
    seed_id = scenario["seed_id"]
    if promote:
        client.authority.issue(client, scenario["reviewer"], seed_id, ["canonize_standing"])
    challenge_id = "sab_challenge_blocks_revalidation"
    _submit_challenge(client, scenario["challenger_key"], challenger_id=scenario["challenger"], seed_id=seed_id,
                      claim_id=f"sab_claim_{seed_id}", challenge_id=challenge_id)
    if challenge_status == "responded":
        client.authority.issue(client, scenario["claimant"], seed_id, ["respond_challenge"])
        command = response_command(scenario["claimant_key"], scenario["claimant"], challenge_id, "Response is not final adjudication")
        assert client.post(f"/api/v1/challenges/{challenge_id}/respond", json=command).status_code == 201
    before = state(web_app)
    command = standing_action_command(scenario, "revalidate", promote=promote)
    response = client.post(f"/api/v1/standing/{scenario['standing_id']}/revalidate", json=command)
    assert response.status_code == 409, response.text
    assert "resolved challenge" in response.text
    assert state(web_app) == before
