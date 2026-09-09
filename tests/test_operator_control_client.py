"""Real signatures and bounded protocols under explicit synthetic test policies."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from nacl.signing import SigningKey

from test_operator_control_http import ceremony  # noqa: F401 -- real HTTP enrollment fixture


@pytest.fixture
def case():
    api = importlib.import_module("agora.operator_control_client")
    core = importlib.import_module("agora.operator_control")
    identity = importlib.import_module("agora.sab_identity")
    keys = [SigningKey.generate() for _ in range(4)]
    pins = [{"subject_id": identity.subject_id_from_public_key(k.verify_key.encode().hex()),
             "public_key": k.verify_key.encode().hex()} for k in keys]
    by_subject = {p["subject_id"]: k for p, k in zip(pins, keys)}
    now = datetime(2026, 9, 9, tzinfo=timezone.utc)
    policy = {
        "schema": "sab.operator_control_policy.v1", "policy_id": "sab_operator_policy_client_synthetic",
        "audience": "http://127.0.0.1:8000", "not_before": (now - timedelta(hours=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(), "max_assessment_ttl_seconds": 3600,
        "max_evidence_age_seconds": 3600, "max_common_funding_ppm": 0,
        "reviewers": sorted(pins[2:], key=lambda p: p["subject_id"]), "revokers": [pins[2]],
    }
    participants, nodes, edges = [], [], []
    for index, pin in enumerate(pins[:2]):
        controller = f"control_claimed_{index}"
        participants.append({**pin, "controller_class_id": controller})
        nodes.append({"node_id": pin["subject_id"], "kind": "participant"})
        for kind, relation in (("controller", "controlled_by"), ("signing_root", "signs_with"),
                               ("administrator", "administered_by"), ("runtime", "operated_by")):
            target = controller if kind == "controller" else f"control_{kind}_{index}"
            nodes.append({"node_id": target, "kind": kind})
            edges.append({"source": pin["subject_id"], "target": target, "relation": relation, "funding_ppm": None})
        edges.append({"source": pin["subject_id"], "target": controller, "relation": "decided_by", "funding_ppm": None})
    participants.sort(key=lambda p: p["subject_id"])
    evidence = []
    for category in sorted(core.CATEGORIES):
        document = {"fixture": "Synthetic self-report; no independent control established. 東京 \U0001f9ed"}
        evidence.append({
            "evidence_id": "evidence_" + category, "category": category, "source_class": "self_report",
            "source_ref": "test://unverified-client-material", "observed_at": now.isoformat(),
            "valid_until": (now + timedelta(minutes=30)).isoformat(),
            "subject_ids": [p["subject_id"] for p in participants], "document": document,
            "document_sha256": core.hash_json(document),
        })
    assessment = {
        "schema": "sab.operator_cohort_assessment.v1", "assessment_id": "sab_operator_assessment_" + "a" * 32,
        "policy_id": policy["policy_id"], "policy_sha256": core.hash_json(policy), "audience": policy["audience"],
        "seed_id": "sab_seed_client_fixture", "claim_sha256": "c" * 64, "purpose": "standing_quorum",
        "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=20)).isoformat(),
        "participants": participants, "graph": {"nodes": sorted(nodes, key=lambda n: n["node_id"]),
            "edges": sorted(edges, key=lambda e: (e["source"], e["target"], e["relation"]))},
        "evidence": evidence, "replaces": None,
    }
    reviews = [{
        "reviewer_subject_id": p["subject_id"], "reviewer_public_key": p["public_key"],
        "assessment_sha256": core.hash_json(assessment), "observed_at": now.isoformat(),
        "findings": [{"category": category, "evidence_ids": ["evidence_" + category], "outcome": "unknown"}
                     for category in sorted(core.CATEGORIES)],
    } for p in policy["reviewers"]]
    return {"api": api, "core": core, "keys": keys, "pins": pins, "by_subject": by_subject,
            "now": now, "policy": policy, "assessment": assessment, "reviews": reviews}


class CountingSigner:
    def __init__(self, key):
        self.key, self.verify_key, self.calls = key, key.verify_key, 0

    def sign(self, message):
        self.calls += 1
        return self.key.sign(message)


def _sign(case, review=None, key=None, assessment=None, digest=None, reviewer=None):
    review = review if review is not None else case["reviews"][0]
    return case["api"].sign_review(
        assessment if assessment is not None else case["assessment"], review, case["policy"],
        key if key is not None else case["by_subject"][review["reviewer_subject_id"]],
        assessment_sha256=digest if digest is not None else case["core"].hash_json(case["assessment"]),
        reviewer_id=reviewer if reviewer is not None else review["reviewer_subject_id"], utc_now=lambda: case["now"],
    )


def _envelope(case):
    return case["api"].assemble(case["assessment"], [_sign(case, r) for r in case["reviews"]], case["policy"])


def _home(case, subject):
    key = case["by_subject"][subject]
    public_key = key.verify_key.encode().hex()
    control = importlib.import_module("agora.key_control")
    proved_at = (case["now"] - timedelta(minutes=1)).isoformat()
    identity = control.prepare_identity({"public_key": public_key, "display_name": "Synthetic client actor"}, created_at=proved_at)
    return {"schema": "sab.agent_home.v1", "identity_status": "active", "identity": identity,
            "witness_accuracy": 0.0,
            "key_control": {"schema": "sab.key_control_binding.v1", "subject_id": subject,
                            "public_key": public_key, "status": "active", "proof_id": "sab_kc_proof_" + "1" * 32,
                            "proved_at": proved_at, "successor_subject_id": None, "scope": "key_control_only",
                            "authority_effect": "none", "standing_effect": "none"}}


def _observation(case, envelope):
    return {**envelope, "assessment_id": envelope["assessment"]["assessment_id"],
            "assessment_sha256": case["core"].hash_json(envelope["assessment"]),
            "envelope_sha256": case["core"].hash_json(envelope), "status": "ineligible", "created": True,
            "observation": {"eligible": False, "grade": "unknown"}, "challenge_ids": [],
            "authority_effect": "none", "standing_effect": "none"}


def _no_reliance(result):
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert result["effective_reliance"] == "unestablished"
    assert result["current_use_eligible"] is False
    assert result["evidence_truth"] == "not_verified_by_client"


def test_real_unicode_review_signatures_and_historical_inspection(case):
    envelope = _envelope(case)
    for signed in envelope["reviews"]:
        message = {k: v for k, v in signed.items() if k != "signature"}
        expected = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        case["by_subject"][signed["reviewer_subject_id"]].verify_key.verify(expected, bytes.fromhex(signed["signature"]))
        assert signed["assessment_sha256"] == hashlib.sha256(json.dumps(
            case["assessment"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    result = case["api"].inspect_document(envelope, case["policy"])
    assert result["signature_integrity"] == "valid_under_pinned_policy"
    assert len(result["materials"]) == 7
    assert {finding["outcome"] for review in result["reviews"] for finding in review["findings"]} == {"unknown"}
    _no_reliance(result)
    output = json.dumps(envelope) + json.dumps(result)
    assert all(key.encode().hex() not in output for key in case["keys"])


@pytest.mark.parametrize("tamper", ["evidence", "unknown_field", "wrong_digest", "wrong_reviewer", "wrong_key", "findings"])
def test_tamper_and_wrong_intent_are_rejected_before_signing(case, tamper):
    assessment, review = copy.deepcopy(case["assessment"]), copy.deepcopy(case["reviews"][0])
    key = CountingSigner(case["by_subject"][review["reviewer_subject_id"]])
    kwargs = {}
    if tamper == "evidence":
        assessment["evidence"][0]["document"]["fixture"] = "Changed material"
    elif tamper == "unknown_field":
        review["verified"] = True
    elif tamper == "wrong_digest":
        kwargs["digest"] = "0" * 64
    elif tamper == "wrong_reviewer":
        kwargs["reviewer"] = case["pins"][0]["subject_id"]
    elif tamper == "wrong_key":
        key = CountingSigner(case["keys"][0])
    else:
        review["findings"][0]["outcome"] = "verified"
    with pytest.raises((case["core"].OperatorControlError, case["api"].OperatorControlClientError)):
        _sign(case, review=review, assessment=assessment, key=key, **kwargs)
    assert key.calls == 0


@pytest.mark.parametrize("value", [0.0, float("inf"), 9007199254740992, "\ud800"])
def test_unsupported_canonical_input_never_reaches_signer(case, value):
    assessment = copy.deepcopy(case["assessment"])
    assessment["evidence"][0]["document"]["value"] = value
    key = CountingSigner(case["by_subject"][case["reviews"][0]["reviewer_subject_id"]])
    with pytest.raises(case["api"].OperatorControlClientError):
        _sign(case, key=key, assessment=assessment)
    assert key.calls == 0


def test_issue_preflights_exact_keys_and_preserves_unknown_evidence(case):
    envelope, seen = _envelope(case), []

    def serve(request):
        seen.append(request)
        assert "authorization" not in request.headers and "cookie" not in request.headers
        if request.method == "GET":
            assert request.url.path == "/api/v1/agents/me/home"
            return httpx.Response(200, json=_home(case, request.url.params["subject_id"]))
        assert request.url.path == "/api/operator-control/assessments"
        assert json.loads(request.content) == envelope
        return httpx.Response(201, json=_observation(case, envelope))

    result = case["api"].issue(case["policy"]["audience"], envelope, case["policy"],
                               transport=httpx.MockTransport(serve), utc_now=lambda: case["now"])
    assert [r.method for r in seen] == ["GET"] * 4 + ["POST"]
    assert result["receipt_matched"] is True
    _no_reliance(result)


@pytest.mark.parametrize("status", ["revoked", "superseded", "unproven", "unavailable"])
def test_inactive_key_preflight_prevents_issuance_post(case, status):
    seen = []

    def serve(request):
        seen.append(request.method)
        home = _home(case, request.url.params["subject_id"])
        home["identity_status"] = home["key_control"]["status"] = status
        return httpx.Response(200, json=home)

    with pytest.raises(case["api"].OperatorControlClientError):
        case["api"].issue(case["policy"]["audience"], _envelope(case), case["policy"],
                           transport=httpx.MockTransport(serve), utc_now=lambda: case["now"])
    assert seen == ["GET"]


@pytest.mark.parametrize("tamper", [{"assessment_sha256": "0" * 64}, {"envelope_sha256": "0" * 64},
                                    {"standing_effect": "active"}, {"authority_effect": "grant"}])
def test_remote_observation_is_bound_to_expected_signed_bytes(case, tamper):
    envelope = _envelope(case)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={**_observation(case, envelope), **tamper}))
    with pytest.raises(case["api"].OperatorControlClientError):
        case["api"].get_assessment(case["policy"]["audience"], case["assessment"]["assessment_id"],
                                    case["core"].hash_json(case["assessment"]), case["policy"], transport=transport)


@pytest.mark.parametrize("suffix", ["/other", "?secret=sentinel", "#fragment"])
def test_get_cannot_escape_fixed_assessment_route(case, suffix):
    seen = []
    with pytest.raises(case["api"].OperatorControlClientError):
        case["api"].get_assessment(case["policy"]["audience"], case["assessment"]["assessment_id"] + suffix,
                                    case["core"].hash_json(case["assessment"]), case["policy"],
                                    transport=httpx.MockTransport(lambda r: seen.append(r)))
    assert seen == []


def _action(case, kind):
    pin = case["policy"]["revokers"][0] if kind == "revoke" else case["pins"][0]
    actor = "revoker" if kind == "revoke" else "challenger"
    message = {"schema": "sab.operator_control_" + ("revocation" if kind == "revoke" else "challenge") + ".v1",
               ("revocation_id" if kind == "revoke" else "challenge_id"):
                   ("sab_operator_revoke_" if kind == "revoke" else "sab_operator_challenge_") + "d" * 32,
               "assessment_id": case["assessment"]["assessment_id"],
               "assessment_sha256": case["core"].hash_json(case["assessment"]),
               "audience": case["policy"]["audience"], actor + "_subject_id": pin["subject_id"],
               actor + "_public_key": pin["public_key"], "reason": "Synthetic unknown evidence needs review",
               "issued_at": case["now"].isoformat(), "expires_at": (case["now"] + timedelta(seconds=120)).isoformat()}
    if kind == "challenge":
        # This public reference is a protocol test input, never a forged accepted grant.
        message.update(evidence_ref="test://synthetic-question", authority_lease_sha256="b" * 64,
                       authority_lease={"lease_ref": "sab_lease_client_challenge", "scope": "One synthetic challenge",
                                        "expires_at": (case["now"] + timedelta(minutes=10)).isoformat(),
                                        "revoker": pin["subject_id"],
                                        "challenge_path": "/api/v1/authority/leases/sab_lease_client_challenge/challenges"})
    return pin, message


@pytest.mark.parametrize("kind", ["challenge", "revoke"])
def test_explicit_actions_sign_exact_message_and_match_receipt(case, kind):
    pin, message = _action(case, kind)
    seen = []

    def serve(request):
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(200, json=_home(case, pin["subject_id"]))
        payload = json.loads(request.content)
        field = "revocation" if kind == "revoke" else "challenge"
        assert payload[field] == message
        case["by_subject"][pin["subject_id"]].verify_key.verify(
            case["core"].canonical_json_bytes(message), bytes.fromhex(payload["signature"]))
        assert request.url.path == "/api/operator-control/assessments/" + case["assessment"]["assessment_id"] + "/" + kind
        return httpx.Response(200, json={**payload, "event_id": message.get("revocation_id", message.get("challenge_id")),
            "event_sha256": case["core"].hash_json(payload), "assessment_id": message["assessment_id"],
            "assessment_sha256": message["assessment_sha256"], "created": True,
            "authority_effect": "none", "standing_effect": "none"})

    result = case["api"].submit_action(kind, case["policy"]["audience"], case["assessment"], message,
        case["policy"], case["by_subject"][pin["subject_id"]], assessment_sha256=case["core"].hash_json(case["assessment"]),
        actor_id=pin["subject_id"], transport=httpx.MockTransport(serve), utc_now=lambda: case["now"])
    assert [r.method for r in seen] == ["GET", "POST"]
    _no_reliance(result)


def test_retired_actor_never_signs_a_challenge(case):
    pin, message = _action(case, "challenge")
    key = CountingSigner(case["by_subject"][pin["subject_id"]])
    seen = []

    def serve(request):
        seen.append(request.method)
        home = _home(case, pin["subject_id"])
        home["key_control"]["status"] = "revoked"
        return httpx.Response(200, json=home)

    with pytest.raises((case["api"].OperatorControlClientError, importlib.import_module("agora.key_control_client").KeyControlClientError)):
        case["api"].submit_action("challenge", case["policy"]["audience"], case["assessment"], message,
            case["policy"], key, assessment_sha256=case["core"].hash_json(case["assessment"]),
            actor_id=pin["subject_id"], transport=httpx.MockTransport(serve), utc_now=lambda: case["now"])
    assert key.calls == 0 and seen == ["GET"]


def test_expiry_during_preflight_never_reaches_command_signer(case):
    pin, message = _action(case, "challenge")
    key = CountingSigner(case["by_subject"][pin["subject_id"]])
    times = iter([case["now"], case["now"] + timedelta(seconds=120)])
    seen = []

    def serve(request):
        seen.append(request.method)
        return httpx.Response(200, json=_home(case, pin["subject_id"]))

    with pytest.raises(case["core"].OperatorControlError):
        case["api"].submit_action("challenge", case["policy"]["audience"], case["assessment"], message,
            case["policy"], key, assessment_sha256=case["core"].hash_json(case["assessment"]),
            actor_id=pin["subject_id"], transport=httpx.MockTransport(serve), utc_now=lambda: next(times))
    assert key.calls == 0 and seen == ["GET"]


@pytest.mark.parametrize("field,value", [("event_sha256", "0" * 64), ("assessment_sha256", "0" * 64),
                                       ("event_id", "sab_operator_revoke_" + "f" * 32)])
def test_action_receipt_must_match_event_and_target(case, field, value):
    pin, message = _action(case, "revoke")

    def serve(request):
        if request.method == "GET":
            return httpx.Response(200, json=_home(case, pin["subject_id"]))
        payload = json.loads(request.content)
        result = {**payload, "event_id": message["revocation_id"],
                  "event_sha256": case["core"].hash_json(payload), "assessment_id": message["assessment_id"],
                  "assessment_sha256": message["assessment_sha256"],
                  "authority_effect": "none", "standing_effect": "none", field: value}
        return httpx.Response(200, json=result)

    with pytest.raises(case["api"].OperatorControlClientError):
        case["api"].submit_action("revoke", case["policy"]["audience"], case["assessment"], message,
            case["policy"], case["by_subject"][pin["subject_id"]],
            assessment_sha256=case["core"].hash_json(case["assessment"]), actor_id=pin["subject_id"],
            transport=httpx.MockTransport(serve), utc_now=lambda: case["now"])


@pytest.mark.parametrize("response", [
    lambda: httpx.Response(307, headers={"location": "https://example.invalid/secret"}),
    lambda: httpx.Response(500, text="PRIVATE_PEER_SENTINEL"),
    lambda: httpx.Response(200, content=b'{"a":1,"a":2}', headers={"content-type": "application/json"}),
    lambda: httpx.Response(200, content=b'{"a":1.0}', headers={"content-type": "application/json"}),
    lambda: httpx.Response(200, content=b'x' * (2 * 1024 * 1024 + 1), headers={"content-type": "application/json"}),
])
def test_transport_refuses_redirect_malformed_or_oversized_reply(case, response):
    with pytest.raises(case["api"].OperatorControlClientError) as caught:
        case["api"].get_assessment(case["policy"]["audience"], case["assessment"]["assessment_id"],
            case["core"].hash_json(case["assessment"]), case["policy"],
            transport=httpx.MockTransport(lambda request: response()))
    assert "PRIVATE_PEER_SENTINEL" not in str(caught.value)


def _cli_files(case, tmp_path):
    paths = {name: tmp_path / (name + ".json") for name in ("policy", "assessment", "review")}
    for name, path in paths.items():
        path.write_text(json.dumps(case["reviews"][0] if name == "review" else case[name]))
        path.chmod(0o600)
    key = tmp_path / "reviewer.key"
    key.write_text(case["by_subject"][case["reviews"][0]["reviewer_subject_id"]].encode().hex() + "\n")
    key.chmod(0o600)
    paths["key"] = key
    return paths


def test_cli_offline_ceremony_has_exclusive_output_and_no_key_leaks(case, tmp_path, monkeypatch, capsys):
    paths = _cli_files(case, tmp_path)
    monkeypatch.setattr(case["api"], "_now", lambda clock=None: case["now"])
    original = {p: p.read_bytes() for p in paths.values()}
    output = tmp_path / "signed-review.json"
    args = ["sign-review", "--policy-file", str(paths["policy"]), "--policy-sha256", case["core"].hash_json(case["policy"]),
            "--assessment-file", str(paths["assessment"]), "--assessment-sha256", case["core"].hash_json(case["assessment"]),
            "--document", str(paths["review"]), "--key-file", str(paths["key"]),
            "--actor-id", case["reviews"][0]["reviewer_subject_id"], "--output", str(output)]
    assert case["api"].main(args) == 0
    first = capsys.readouterr()
    _no_reliance(json.loads(first.out))
    signed = output.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o600
    assert case["api"].main(args) == 1
    refused = capsys.readouterr()
    assert output.read_bytes() == signed
    assert all(p.read_bytes() == raw for p, raw in original.items())
    assert all(key.encode().hex() not in first.out + first.err + refused.out + refused.err + signed.decode() for key in case["keys"])


@pytest.mark.parametrize("mode", ["wrong_pin", "unsafe_key", "duplicate", "unknown_field", "oversized", "symlink"])
def test_cli_invalid_inputs_fail_without_output_or_reflected_material(case, tmp_path, monkeypatch, capsys, mode):
    paths = _cli_files(case, tmp_path)
    monkeypatch.setattr(case["api"], "_now", lambda clock=None: case["now"])
    output = tmp_path / "refused.json"
    pin = case["core"].hash_json(case["policy"])
    if mode == "wrong_pin":
        pin = "0" * 64
    elif mode == "unsafe_key":
        paths["key"].chmod(0o644)
    elif mode == "duplicate":
        paths["review"].write_text('{"findings":"PRIVATE_SENTINEL","findings":[]}')
    elif mode == "unknown_field":
        paths["review"].write_text(json.dumps({**case["reviews"][0], "private_key": "PRIVATE_SENTINEL"}))
    elif mode == "oversized":
        paths["review"].write_bytes(b"PRIVATE_SENTINEL" + b" " * case["api"].MAX_BYTES)
    else:
        link = tmp_path / "link.json"
        link.symlink_to(paths["review"])
        paths["review"] = link
    args = ["sign-review", "--policy-file", str(paths["policy"]), "--policy-sha256", pin,
            "--assessment-file", str(paths["assessment"]), "--assessment-sha256", case["core"].hash_json(case["assessment"]),
            "--document", str(paths["review"]), "--key-file", str(paths["key"]),
            "--actor-id", case["reviews"][0]["reviewer_subject_id"], "--output", str(output)]
    assert case["api"].main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "PRIVATE_SENTINEL" not in captured.err
    assert not output.exists()


def test_module_cli_policy_and_material_hashes_are_read_only(case, tmp_path):
    paths = _cli_files(case, tmp_path)
    material = tmp_path / "material.json"
    document = {"source": "Synthetic unpublished material \U0001f9ed", "count": 2}
    material.write_text(json.dumps(document, ensure_ascii=False, indent=2))
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    root = Path(__file__).resolve().parents[1]
    for args, expected, field in (
        (["policy-digest", "--policy-file", str(paths["policy"])], case["core"].hash_json(case["policy"]), "policy_sha256"),
        (["material-digest", "--document", str(material)], case["core"].hash_json(document), "document_sha256"),
    ):
        completed = subprocess.run([sys.executable, "-B", "-m", "agora.operator_control_client", *args],
                                   cwd=root, text=True, capture_output=True, check=True, timeout=15)
        result = json.loads(completed.stdout)
        assert result[field] == expected and completed.stderr == ""
        _no_reliance(result)
    assert {p: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_document_fifo_is_refused_without_waiting(case, tmp_path):
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run([sys.executable, "-B", "-m", "agora.operator_control_client",
                               "material-digest", "--document", str(fifo)],
                              cwd=root, text=True, capture_output=True, timeout=5)
    assert completed.returncode == 1 and completed.stdout == ""
    assert json.loads(completed.stderr)["error"] == "operator_control_operation_refused"


def test_policy_fifo_is_refused_without_waiting(case, tmp_path):
    paths = _cli_files(case, tmp_path)
    fifo = tmp_path / "policy.fifo"
    os.mkfifo(fifo)
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run([sys.executable, "-B", "-m", "agora.operator_control_client", "inspect",
                               "--document", str(paths["assessment"]), "--policy-file", str(fifo),
                               "--policy-sha256", case["core"].hash_json(case["policy"])],
                              cwd=root, text=True, capture_output=True, timeout=5)
    assert completed.returncode == 1 and completed.stdout == ""
    assert json.loads(completed.stderr)["error"] == "operator_control_operation_refused"


def test_client_roundtrip_through_real_http_preserves_unestablished_evidence(ceremony):
    api = importlib.import_module("agora.operator_control_client")
    core = importlib.import_module("agora.operator_control")
    policy = ceremony.control.policy
    # Use real enrolled keys and actual HTTP, with explicitly unknown findings.
    assessment = ceremony.control.envelope(ceremony.members, seed_id=ceremony.seed_id,
        claim_sha256=ceremony.context()["claim_sha256"], purpose="standing_quorum")["assessment"]
    for material in assessment["evidence"]:
        material["source_class"] = "self_report"
    digest = core.hash_json(assessment)
    reviews = []
    for subject, key in sorted(ceremony.control.reviewer_keys.items()):
        message = {"reviewer_subject_id": subject, "reviewer_public_key": key.verify_key.encode().hex(),
                   "assessment_sha256": digest, "observed_at": datetime.now(timezone.utc).isoformat(),
                   "findings": [{"category": category, "evidence_ids": [], "outcome": "unknown"}
                                for category in sorted(core.CATEGORIES)]}
        reviews.append(api.sign_review(assessment, message, policy, key,
                                        assessment_sha256=digest, reviewer_id=subject))
    envelope = api.assemble(assessment, reviews, policy)

    def forward(request):
        result = ceremony.client.request(request.method, request.url.raw_path.decode(),
                                         content=request.content, headers=dict(request.headers))
        return httpx.Response(result.status_code, content=result.content, headers=dict(result.headers))

    transport = httpx.MockTransport(forward)
    issued = api.issue(policy["audience"], envelope, policy, transport=transport)
    _no_reliance(issued)
    server = ceremony.client.get("/api/operator-control/assessments/" + assessment["assessment_id"]).json()
    assert server["status"] == "ineligible"
    assert server["observation"]["eligible"] is False
    before = ceremony.snapshot()
    fetched = api.get_assessment(policy["audience"], assessment["assessment_id"], digest, policy, transport=transport)
    assert fetched["assessment_sha256"] == digest
    _no_reliance(fetched)
    assert ceremony.snapshot() == before

    now = datetime.now(timezone.utc)
    message = {"schema": "sab.operator_control_revocation.v1", "revocation_id": "sab_operator_revoke_" + "9" * 32,
               "assessment_id": assessment["assessment_id"], "assessment_sha256": digest,
               "audience": policy["audience"], "revoker_subject_id": ceremony.control.revoker_subject_id,
               "revoker_public_key": ceremony.control.revoker_key.verify_key.encode().hex(),
               "reason": "Retire the explicitly unestablished client fixture", "issued_at": now.isoformat(),
               "expires_at": (now + timedelta(seconds=120)).isoformat()}
    retired = api.submit_action("revoke", policy["audience"], assessment, message, policy,
        ceremony.control.revoker_key, assessment_sha256=digest, actor_id=ceremony.control.revoker_subject_id,
        transport=transport)
    assert retired["receipt_matched"] is True
    _no_reliance(retired)
    before_retry = ceremony.snapshot()
    assert api.submit_action("revoke", policy["audience"], assessment, message, policy,
        ceremony.control.revoker_key, assessment_sha256=digest, actor_id=ceremony.control.revoker_subject_id,
        transport=transport)["command_sha256"] == retired["command_sha256"]
    assert ceremony.snapshot() == before_retry


def test_standing_basis_schema_accepts_real_signed_citations_and_preserves_history(ceremony):
    from jsonschema import Draft202012Validator, FormatChecker

    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "nodes/schemas/sab.standing_lease.v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    historical = json.loads((root / "docs/lanes/sab-agent-seeding-v1/fixtures/valid/sab.standing_lease.v1.json").read_text())
    assert "operator_control_basis" not in historical
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(historical)

    # Real HTTP enrollment, grants, two reviews, adjudication and affirmations
    # under the fixture's explicitly synthetic policy. No positive SQL inserts.
    basis = ceremony.basis()
    reviewed = ceremony.review(basis)
    assert reviewed.status_code == 201, reviewed.text
    record = reviewed.json()
    assert record["standing_lease"]["operator_control_basis"] == basis
    validator = Draft202012Validator(schema["properties"]["operator_control_basis"])
    validator.validate(record["standing_lease"]["operator_control_basis"])

    invalid = []
    for path in ((), ("assessment",), ("witness_events", 0), ("adjudication_events", 0)):
        changed = copy.deepcopy(basis)
        target = changed
        for part in path:
            target = target[part]
        target["verified"] = True
        invalid.append(("unknown field at " + repr(path), changed))
    for role in ("witness_events", "adjudication_events"):
        for label, values in (("empty", []), ("duplicate", [basis[role][0]] * 2),
                              ("over limit", [{"event_id": "event_" + str(i), "event_sha256": "a" * 64}
                                               for i in range(17)])):
            changed = copy.deepcopy(basis)
            changed[role] = values
            invalid.append((role + " " + label, changed))
        for digest in ("A" * 64, "sha256:" + "a" * 64, "a" * 63):
            changed = copy.deepcopy(basis)
            changed[role][0]["event_sha256"] = digest
            invalid.append((role + " malformed digest", changed))
    changed = copy.deepcopy(basis)
    changed["assessment"]["assessment_id"] = "unresolved_display_name"
    invalid.append(("ambiguous assessment", changed))
    changed = copy.deepcopy(basis)
    changed["assessment"]["assessment_sha256"] = "sha256:" + "a" * 64
    invalid.append(("prefixed assessment digest", changed))
    changed = copy.deepcopy(basis)
    del changed["adjudication_events"]
    invalid.append(("missing adjudications", changed))
    for label, changed in invalid:
        assert not validator.is_valid(changed), label

    # Schema acceptance is structural: a well-shaped invented digest still
    # needs exact stored-record verification by the current service.
    changed = copy.deepcopy(basis)
    changed["witness_events"][0]["event_sha256"] = "0" * 64
    validator.validate(changed)
    before = ceremony.snapshot()
    denied = ceremony.review(changed)
    assert denied.status_code == 403, denied.text
    assert ceremony.snapshot() == before
