"""Participant intent and custody across offline signatures and authority HTTP."""

from __future__ import annotations

import importlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from nacl.signing import SigningKey


@pytest.fixture
def case():
    # Other integration fixtures reload agora; always use the live module.
    api = importlib.import_module("agora.authority_client")
    authority = importlib.import_module("agora.authority")
    identity = importlib.import_module("agora.sab_identity")
    issuer, witness, subject = (SigningKey.generate() for _ in range(3))
    keys = {name: key.verify_key.encode().hex() for name, key in
            (("issuer", issuer), ("witness", witness), ("subject", subject))}
    ids = {name: identity.subject_id_from_public_key(value) for name, value in keys.items()}
    now = datetime(2026, 9, 9, tzinfo=timezone.utc)
    actions = ["submit_seed", "correct_seed"]
    policy = {
        "schema": "sab.authority_policy.v1", "audience": "http://127.0.0.1:8000",
        "policy_id": "sab_policy_client_fixture",
        "not_before": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "issuers": [{"subject_id": ids["issuer"], "public_key": keys["issuer"],
                     "allowed_actions": actions, "allowed_seed_ids": ["sab_seed_client_fixture"],
                     "all_seeds": False, "max_ttl_seconds": 3600, "revoker_ids": [ids["issuer"]]}],
        "witnesses": [{"subject_id": ids["witness"], "public_key": keys["witness"]}],
        "revokers": [{"subject_id": ids["issuer"], "public_key": keys["issuer"]}],
    }
    lease = {
        "schema": "sab.authority_lease.v2", "lease_id": "sab_lease_client_fixture",
        "audience": policy["audience"], "policy_hash": authority.hash_json(policy),
        "subject_id": ids["subject"], "subject_public_key": keys["subject"],
        "issuer_id": ids["issuer"], "issuer_public_key": keys["issuer"],
        "target_seed_id": "sab_seed_client_fixture", "purpose": "Submit one local fixture claim",
        "scope": "One synthetic seed and its correction", "allowed_actions": actions,
        "forbidden_actions": [], "allowed_reliance": [], "forbidden_reliance": ["standing", "truth"],
        "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=10)).isoformat(),
        "revoker_id": ids["issuer"], "revoker_public_key": keys["issuer"],
        "challenge_path": "/api/v1/authority/leases/sab_lease_client_fixture/challenges",
        "evidence_refs": ["test://explicit-synthetic-policy"],
    }
    return {"api": api, "authority": authority, "issuer": issuer, "witness": witness,
            "subject": subject, "keys": keys, "ids": ids, "now": now, "policy": policy,
            "lease": lease, "intent": {"subject_id": ids["subject"],
            "seed_id": lease["target_seed_id"], "actions": actions}}


class CountingSigner:
    def __init__(self, key):
        self.verify_key = key.verify_key
        self.key = key
        self.calls = 0

    def sign(self, message):
        self.calls += 1
        return self.key.sign(message)


def assembled(case):
    api = case["api"]
    signed = api.sign_lease(case["lease"], case["policy"], case["issuer"],
                            **case["intent"], utc_now=lambda: case["now"])
    return api.witness_lease(signed, case["policy"], case["witness"],
                             witness_id=case["ids"]["witness"], **case["intent"],
                             utc_now=lambda: case["now"])


def observation(case, envelope, status="active"):
    h = case["authority"].hash_json
    return {**envelope, "lease_id": envelope["lease"]["lease_id"],
            "lease_sha256": h({name: envelope[name] for name in ("lease", "issuer_signature")}),
            "envelope_sha256": h(envelope), "status": status,
            "authority_effect": "none", "standing_effect": "none"}


def test_separate_signers_bind_full_lease_and_distinct_witness(case):
    result = assembled(case)
    canonical = case["authority"].canonical_bytes
    case["issuer"].verify_key.verify(canonical(result["lease"]), bytes.fromhex(result["issuer_signature"]))
    witness = dict(result["issuance_witness"])
    signature = witness.pop("signature")
    case["witness"].verify_key.verify(canonical(witness), bytes.fromhex(signature))
    assert result["lease"] == case["lease"]
    assert "authority_effect" not in result  # a signed proposal is not an effect receipt
    for key in (case["issuer"], case["witness"], case["subject"]):
        assert key.encode().hex() not in canonical(result).decode()


@pytest.mark.parametrize("field,value", [
    ("subject_id", "agent_someone_else"), ("seed_id", "sab_seed_other"),
    ("actions", ["submit_seed"]), ("actions", ["submit_seed", "correct_seed", "correct_seed"]),
])
def test_mismatched_explicit_intent_never_reaches_signer(case, field, value):
    intent = {**case["intent"], field: value}
    key = CountingSigner(case["issuer"])
    with pytest.raises(case["api"].AuthorityClientError):
        case["api"].sign_lease(case["lease"], case["policy"], key, **intent, utc_now=lambda: case["now"])
    assert key.calls == 0


@pytest.mark.parametrize("patch", [
    {"allowed_reliance": ["deploy"]}, {"allowed_actions": ["revoke_standing"]},
    {"private_key": "NEVER_SIGN_THIS"}, {"audience": "http://example.com"},
    {"policy_hash": "0" * 64}, {"target_seed_id": "sab_seed_outside_policy"},
    {"revoker_public_key": "0" * 64}, {"expires_at": "2026-09-11T00:00:00Z"},
    {"issued_at": "2026-09-09T00:01:00Z"},
])
def test_invalid_grant_never_reaches_issuer_signer(case, patch):
    key = CountingSigner(case["issuer"])
    with pytest.raises((case["authority"].AuthorityError, ValueError)):
        case["api"].sign_lease({**case["lease"], **patch}, case["policy"], key,
                               **case["intent"], utc_now=lambda: case["now"])
    assert key.calls == 0


def test_wrong_witness_key_never_signs(case):
    signed = case["api"].sign_lease(case["lease"], case["policy"], case["issuer"],
                                    **case["intent"], utc_now=lambda: case["now"])
    key = CountingSigner(case["issuer"])
    with pytest.raises(case["api"].AuthorityClientError):
        case["api"].witness_lease(signed, case["policy"], key,
                                  witness_id=case["ids"]["witness"], **case["intent"],
                                  utc_now=lambda: case["now"])
    assert key.calls == 0


def test_altered_issuer_document_is_not_witnessed_or_uploaded(case):
    signed = assembled(case)
    signed["lease"]["scope"] = "Changed after the issuer signed"
    calls = []
    transport = httpx.MockTransport(lambda request: calls.append(request))
    with pytest.raises(case["authority"].AuthorityError):
        case["api"].issue(case["policy"]["audience"], signed, case["policy"],
                          transport=transport, utc_now=lambda: case["now"])
    assert calls == []


def test_issue_transports_public_envelope_and_reports_no_permission(case):
    signed = assembled(case)
    seen = []

    def serve(request):
        seen.append(request)
        assert request.url.path == "/api/v1/authority/leases"
        assert json.loads(request.content) == signed
        assert "authorization" not in request.headers
        return httpx.Response(201, json=observation(case, signed))

    result = case["api"].issue(case["policy"]["audience"], signed, case["policy"],
                               transport=httpx.MockTransport(serve), utc_now=lambda: case["now"])
    assert len(seen) == 1
    assert result["current_permission"] == "evaluate_at_mutation"
    assert result["signature_integrity"] == "valid_under_pinned_policy"
    assert result["authority_effect"] == result["standing_effect"] == "none"


@pytest.mark.parametrize("tamper", [
    {"status": "PRIVATE_UNVALIDATED_PEER_TEXT"}, {"lease_sha256": "0" * 64},
    {"envelope_sha256": "0" * 64}, {"authority_effect": "grant"},
    {"standing_effect": "active"}, {"lease_id": "sab_lease_other"},
])
def test_inspection_rejects_unbound_or_unclassified_server_fields(case, tamper):
    result = {**observation(case, assembled(case)), **tamper}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=result))
    with pytest.raises(case["api"].AuthorityClientError):
        case["api"].inspect_lease(case["policy"]["audience"], case["lease"]["lease_id"],
                                  case["policy"], transport=transport)


@pytest.mark.parametrize("reason", ["", " ", "x" * 2049, " " * 2049 + "x", "x\x00y"])
def test_invalid_revocation_reason_is_refused_before_signing_or_transport(case, reason):
    key = CountingSigner(case["issuer"])
    calls = []
    with pytest.raises((case["api"].AuthorityClientError, case["authority"].AuthorityError)):
        case["api"].revoke(case["policy"]["audience"], assembled(case), case["policy"], key,
                           reason=reason, utc_now=lambda: case["now"],
                           transport=httpx.MockTransport(lambda request: calls.append(request)))
    assert key.calls == 0
    assert calls == []


def test_retirement_remains_available_after_original_policy_and_lease_expire(case):
    signed = assembled(case)
    later = case["now"] + timedelta(days=2)

    def serve(request):
        payload = json.loads(request.content)
        case["authority"].validate_revocation(payload, lease_envelope=signed, observed_at=later)
        return httpx.Response(200, json={**payload, "authority_effect": "none", "standing_effect": "none"})

    result = case["api"].revoke(case["policy"]["audience"], signed, case["policy"], case["issuer"],
                                reason="Retire the synthetic grant", utc_now=lambda: later,
                                transport=httpx.MockTransport(serve))
    assert result["receipt_matched"] is True


@pytest.mark.parametrize("path", ["../other", "sab_lease_ok/path", "sab_lease_ok?secret=value"])
def test_inspection_cannot_escape_fixed_lease_route(case, path):
    calls = []
    with pytest.raises(case["api"].AuthorityClientError):
        case["api"].inspect_lease(case["policy"]["audience"], path, case["policy"],
                                  transport=httpx.MockTransport(lambda request: calls.append(request)))
    assert calls == []


def test_cli_signing_uses_safe_key_and_exclusive_output(case, tmp_path, monkeypatch, capsys):
    api = case["api"]
    monkeypatch.setattr(api, "_now", lambda clock: case["now"])
    policy, draft, key, output = (tmp_path / name for name in ("policy.json", "draft.json", "issuer.key", "signed.json"))
    policy.write_text(json.dumps(case["policy"]))
    draft.write_text(json.dumps(case["lease"]))
    key.write_text(case["issuer"].encode().hex() + "\n")
    key.chmod(0o600)
    argv = ["sign-lease", "--policy-file", str(policy), "--policy-sha256", case["authority"].hash_json(case["policy"]),
            "--document", str(draft), "--key-file", str(key), "--output", str(output),
            "--subject-id", case["ids"]["subject"], "--seed-id", case["lease"]["target_seed_id"],
            "--action", "submit_seed", "--action", "correct_seed"]
    assert api.main(argv) == 0
    original = output.read_bytes()
    assert api.main(argv) == 1
    assert output.read_bytes() == original
    captured = capsys.readouterr()
    assert case["issuer"].encode().hex() not in captured.out + captured.err + original.decode()
    assert json.loads(captured.out)["authority_effect"] == "none"
    output.unlink()
    key.chmod(0o644)
    assert api.main(argv) == 1
    assert not output.exists()


def test_policy_digest_is_canonical_and_grants_nothing(case, tmp_path, capsys):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(case["policy"], indent=2))
    path.chmod(0o600)
    assert case["api"].main(["policy-digest", "--policy-file", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["policy_sha256"] == case["authority"].hash_json(case["policy"])
    assert result["authority_effect"] == result["standing_effect"] == "none"


def _tick_module():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("authority_tick_fixture", Path(__file__).resolve().parents[1] / "scripts/sab_agent_tick.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tick_requires_a_policy_before_loading_any_participant_key(tmp_path, monkeypatch):
    tick = _tick_module()
    monkeypatch.delenv("SAB_AUTHORITY_POLICY_PATH", raising=False)
    monkeypatch.delenv("SAB_AUTHORITY_POLICY_SHA256", raising=False)
    monkeypatch.setattr(tick, "api", lambda *args: (404, {}))
    monkeypatch.setattr(tick, "find_key", lambda *args: pytest.fail("Unissued packet reached key custody"))
    packet = tmp_path / "packet.json"
    packet.write_text(json.dumps({"schema": "sab.seed_packet.v1", "seed_id": "sab_seed_unissued", "claimant_identity": {"subject_id": "agent_test"}, "authority_lease": {"lease_ref": "self_declared"}}))
    result = tick.reconcile_packet(packet)
    assert result["action"] == "skip"
    assert result["reason"] == "existing scoped authority grant required"


@pytest.mark.parametrize("change", [None, "subject", "seed", "reference", "revoked", "expired", "wrong_action"])
def test_tick_checks_exact_signed_reference_action_subject_and_time(case, monkeypatch, change):
    tick = _tick_module()
    real_now = datetime.now(timezone.utc)
    shift = real_now - case["now"]
    for field in ("not_before", "expires_at"):
        case["policy"][field] = (datetime.fromisoformat(case["policy"][field]) + shift).isoformat()
    for field in ("issued_at", "expires_at"):
        case["lease"][field] = (datetime.fromisoformat(case["lease"][field]) + shift).isoformat()
    case["lease"]["policy_hash"] = case["authority"].hash_json(case["policy"])
    case["now"] = real_now
    if change == "wrong_action":
        case["lease"]["allowed_actions"] = ["correct_seed"]
        case["intent"]["actions"] = ["correct_seed"]
    envelope = assembled(case)
    observed = case["api"]._verified_observation(observation(case, envelope), case["policy"], origin=case["policy"]["audience"], lease_id=case["lease"]["lease_id"])
    packet = {"seed_id": case["lease"]["target_seed_id"], "claimant_identity": {"subject_id": case["lease"]["subject_id"]}, "authority_lease": case["authority"].lease_reference(envelope)}
    if change == "subject":
        packet["claimant_identity"]["subject_id"] = "other_subject"
    elif change == "seed":
        packet["seed_id"] = "other_seed"
    elif change == "reference":
        packet["authority_lease"]["scope"] = "Broaden the permission"
    elif change == "revoked":
        observed["reported_status"] = "revoked"
    elif change == "expired":
        observed["lease"]["expires_at"] = (real_now - timedelta(seconds=1)).isoformat()
        packet["authority_lease"] = case["authority"].lease_reference(observed)
    monkeypatch.setattr(case["authority"], "load_authority_policy", lambda *args: case["policy"])
    monkeypatch.setattr(case["api"], "inspect_lease", lambda *args: observed)
    assert tick.inspect_submission_grant(packet) is (change is None)
