"""Synthetic reviewed materials and actual signatures, never real independence.

All keys belong to this test runner. Separate fixture keys are not evidence of
independent operators; the policy is an explicit synthetic review trust root.
Imports remain lazy because HTTP fixtures reload Agora modules.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import uuid


def _utc(value=None):
    return value or datetime.now(timezone.utc)


def _public(key):
    return key if isinstance(key, str) else key.verify_key.encode().hex()


def sign_reviews(assessment, reviewer_keys, *, observed_at=None):
    from agora.operator_control import CATEGORIES, hash_json
    from agora.sab_identity import canonical_json_bytes

    reviews = []
    observed = observed_at.isoformat() if isinstance(observed_at, datetime) else observed_at or assessment["issued_at"]
    for subject, key in sorted(reviewer_keys.items()):
        message = {"reviewer_subject_id": subject, "reviewer_public_key": _public(key),
                   "assessment_sha256": hash_json(assessment), "observed_at": observed,
                   "findings": [{"category": category, "outcome": "supported",
                                 "evidence_ids": sorted(e["evidence_id"] for e in assessment["evidence"]
                                                        if e["category"] == category)}
                                for category in sorted(CATEGORIES)]}
        reviews.append({**message, "signature": key.sign(canonical_json_bytes(message)).signature.hex()})
    return {"assessment": assessment, "reviews": reviews}


class SyntheticOperatorControl:
    def __init__(self, *, now=None, audience="http://127.0.0.1:8000"):
        from nacl.signing import SigningKey
        from agora.sab_identity import subject_id_from_public_key

        self.now = _utc(now)
        keys = [SigningKey.generate() for _ in range(3)]
        self.reviewer_keys = {subject_id_from_public_key(_public(key)): key for key in keys[:2]}
        self.revoker_key = keys[2]
        self.revoker_subject_id = subject_id_from_public_key(_public(self.revoker_key))
        self.policy = {
            "schema": "sab.operator_control_policy.v1", "policy_id": "sab_operator_policy_synthetic",
            "audience": audience, "not_before": (self.now - timedelta(hours=1)).isoformat(),
            "expires_at": (self.now + timedelta(days=7)).isoformat(),
            "max_assessment_ttl_seconds": 86400, "max_evidence_age_seconds": 86400,
            "max_common_funding_ppm": 0,
            "reviewers": [{"subject_id": subject, "public_key": _public(key)}
                          for subject, key in sorted(self.reviewer_keys.items())],
            "revokers": [{"subject_id": self.revoker_subject_id, "public_key": _public(self.revoker_key)}],
        }

    def enroll(self, client):
        from keycontrol_fixtures import enroll_identity

        for subject, key in sorted(self.reviewer_keys.items()):
            identity = enroll_identity(client, key, display_name="Synthetic evidence reviewer")
            assert identity["subject_id"] == subject
        identity = enroll_identity(client, self.revoker_key, display_name="Synthetic evidence revoker")
        assert identity["subject_id"] == self.revoker_subject_id
        client.operator_control = self

    def envelope(self, participants, *, seed_id, claim_sha256, purpose, now=None,
                 assessment_id=None, replaces=None, ttl_seconds=3600):
        from agora.operator_control import CATEGORIES, hash_json

        observed = _utc(now)
        issued, expiry = observed.isoformat(), (observed + timedelta(seconds=ttl_seconds)).isoformat()
        members, nodes, edges = [], [], []
        for index, (subject, key) in enumerate(sorted(participants.items())):
            controller = f"control_synthetic_controller_{index}"
            members.append({"subject_id": subject, "public_key": _public(key), "controller_class_id": controller})
            nodes.append({"node_id": subject, "kind": "participant"})
            for kind, relation in (("controller", "controlled_by"), ("signing_root", "signs_with"),
                                   ("administrator", "administered_by"), ("runtime", "operated_by"),
                                   ("decision_authority", "decided_by")):
                node = f"control_synthetic_{kind}_{index}"
                nodes.append({"node_id": node, "kind": kind})
                edges.append({"source": subject, "target": node, "relation": relation, "funding_ppm": None})
        graph = {"nodes": sorted(nodes, key=lambda n: n["node_id"]),
                 "edges": sorted(edges, key=lambda e: (e["source"], e["target"], e["relation"]))}
        scope = {"seed_id": seed_id, "claim_sha256": claim_sha256, "purpose": purpose}
        sources = {"controller_resolution": "organizational_record", "signing_custody": "custody_inspection",
                   "administrator_access": "custody_inspection", "runtime_control": "custody_inspection",
                   "delegation_decision_rights": "delegation_record", "funding": "financial_record",
                   "conflicts": "conflict_record"}
        artifacts = []
        for category in sorted(CATEGORIES):
            document = {"schema": "sab.synthetic_operator_material.v1", "synthetic": True,
                        "category": category, "scope": scope, "subject_ids": sorted(participants),
                        "examined_graph_sha256": hash_json(graph),
                        "limitations": "Synthetic local test material; no real independent operator is evidenced."}
            artifacts.append({"evidence_id": "evidence_synthetic_" + category, "category": category,
                              "source_class": sources[category], "source_ref": "synthetic:" + category,
                              "observed_at": issued, "valid_until": expiry, "subject_ids": sorted(participants),
                              "document": document, "document_sha256": hash_json(document)})
        assessment = {"schema": "sab.operator_cohort_assessment.v1",
                      "assessment_id": assessment_id or "sab_operator_assessment_" + uuid.uuid4().hex,
                      "policy_id": self.policy["policy_id"], "policy_sha256": hash_json(self.policy),
                      "audience": self.policy["audience"], **scope, "issued_at": issued, "expires_at": expiry,
                      "participants": members, "graph": graph, "evidence": artifacts, "replaces": replaces}
        return sign_reviews(assessment, self.reviewer_keys, observed_at=observed)


def provision_operator_policy(tmp_path, monkeypatch, *, now=None, audience=None):
    import os
    from agora.operator_control import hash_json
    from agora.sab_identity import canonical_json_bytes

    fixture = SyntheticOperatorControl(now=now, audience=audience or os.environ.get("SAB_IDENTITY_ORIGIN", "http://127.0.0.1:8000"))
    path = Path(tmp_path) / "synthetic-operator-control-policy.json"
    path.write_bytes(canonical_json_bytes(fixture.policy))
    path.chmod(0o600)
    monkeypatch.setenv("SAB_OPERATOR_CONTROL_POLICY_PATH", str(path))
    monkeypatch.setenv("SAB_OPERATOR_CONTROL_POLICY_SHA256", hash_json(fixture.policy))
    return fixture


def adjudication_assessment(client, seed_id, challenge_id, adjudicator):
    """Issue reviewed synthetic evidence for the actual signed adjudication roles."""
    seed_response = client.get(f"/api/v1/seeds/{seed_id}")
    challenge_response = client.get(f"/api/v1/challenges/{challenge_id}")
    assert seed_response.status_code == 200, seed_response.text
    assert challenge_response.status_code == 200, challenge_response.text
    seed, challenge = seed_response.json(), challenge_response.json()
    challenger = challenge["challenge_packet"].get("challenger_subject_id", challenge["challenger_identity"])
    subjects = {seed["claimant_identity"], challenger, adjudicator,
                client.authority.issuer_id, client.authority.witness_id}
    members = {}
    for subject in subjects:
        response = client.get("/api/v1/agents/me/home", params={"subject_id": subject})
        assert response.status_code == 200, response.text
        assert response.json()["identity_status"] == "active"
        members[subject] = response.json()["agent"]["public_key"]
    envelope = client.operator_control.envelope(
        members, seed_id=seed_id, claim_sha256=seed["operator_control_context"]["claim_sha256"],
        purpose="challenge_adjudication")
    response = client.post("/api/operator-control/assessments", json=envelope)
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "eligible"
    return {field: response.json()[field] for field in ("assessment_id", "assessment_sha256")}
