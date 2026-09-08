"""Explicit synthetic policy and grants, issued through the real HTTP boundary.

No fixture manufactures bindings or authority records in SQL. Tests must name
subjects, seeds, and actions in each grant; enrollment never implies permission.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

ACTIONS = (
    "submit_seed", "correct_seed", "withdraw_seed", "submit_challenge",
    "respond_challenge", "adjudicate_challenge", "submit_witness_event",
    "request_standing_review", "challenge_standing", "revoke_standing",
    "revalidate_standing", "canonize_standing", "advance_deadlines", "challenge_authority",
)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def hash_json(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def subject_for(key: SigningKey) -> str:
    return "agent_ed25519_" + hashlib.sha256(key.verify_key.encode().hex().encode()).hexdigest()[:32]


def reference_for(grant: dict) -> dict:
    lease = grant["lease"]
    return {"lease_ref": lease["lease_id"], "scope": lease["scope"], "expires_at": lease["expires_at"],
            "revoker": lease["revoker_id"], "challenge_path": lease["challenge_path"]}


@dataclass
class AuthorityFixture:
    policy: dict
    issuer_key: SigningKey
    witness_key: SigningKey
    grants: dict = field(default_factory=dict)

    @property
    def policy_hash(self) -> str:
        return hash_json(self.policy)

    @property
    def issuer_id(self) -> str:
        return subject_for(self.issuer_key)

    @property
    def witness_id(self) -> str:
        return subject_for(self.witness_key)

    def enroll(self, client) -> None:
        from keycontrol_fixtures import enroll_identity
        enroll_identity(client, self.issuer_key, display_name="Synthetic configured issuer")
        enroll_identity(client, self.witness_key, display_name="Synthetic issuance witness")
        client.authority = self

    def envelope(self, client, subject_id: str, seed_id: str, actions, *, lease_id=None,
                 expires_at=None, issued_at=None, scope="Synthetic exact seed permission") -> dict:
        home = client.get("/api/v1/agents/me/home", params={"subject_id": subject_id})
        assert home.status_code == 200, home.text
        now = datetime.now(timezone.utc)
        timestamp = issued_at or (now - timedelta(seconds=1)).isoformat()
        lease_id = lease_id or "sab_lease_" + secrets.token_hex(12)
        lease = {
            "schema": "sab.authority_lease.v2", "lease_id": lease_id,
            "audience": self.policy["audience"], "policy_hash": self.policy_hash,
            "subject_id": subject_id, "subject_public_key": home.json()["agent"]["public_key"],
            "issuer_id": self.issuer_id, "issuer_public_key": self.issuer_key.verify_key.encode().hex(),
            "target_seed_id": seed_id, "purpose": "Explicit synthetic test permission", "scope": scope,
            "allowed_actions": list(actions), "forbidden_actions": [], "allowed_reliance": [],
            "forbidden_reliance": ["independent_operator", "standing", "truth"],
            "issued_at": timestamp, "expires_at": expires_at or (now + timedelta(days=1)).isoformat(),
            "revoker_id": self.issuer_id, "revoker_public_key": self.issuer_key.verify_key.encode().hex(),
            "challenge_path": f"/api/v1/authority/leases/{lease_id}/challenges", "evidence_refs": ["test://explicit-policy"],
        }
        issuer_signature = self.issuer_key.sign(canonical(lease)).signature.hex()
        witness = {
            "schema": "sab.authority_issuance_witness.v1", "event_id": "sab_authority_witness_" + secrets.token_hex(12),
            "audience": self.policy["audience"], "policy_hash": self.policy_hash,
            "lease_sha256": hash_json({"lease": lease, "issuer_signature": issuer_signature}),
            "witness_id": self.witness_id, "witness_public_key": self.witness_key.verify_key.encode().hex(),
            "observed_at": now.isoformat(),
        }
        witness["signature"] = self.witness_key.sign(canonical(witness)).signature.hex()
        return {"lease": lease, "issuer_signature": issuer_signature, "issuance_witness": witness}

    def issue(self, client, subject_id: str, seed_id: str, actions, **kwargs) -> dict:
        envelope = self.envelope(client, subject_id, seed_id, actions, **kwargs)
        response = client.post("/api/v1/authority/leases", json=envelope)
        assert response.status_code == 201, response.text
        result = response.json()
        assert result["status"] == "active", result
        self.grants[(subject_id, seed_id)] = result
        return result

    def reference(self, subject_id: str, seed_id: str) -> dict:
        """Read an explicitly issued test grant; never mint a per-command grant."""
        return reference_for(self.grants[(subject_id, seed_id)])

    def revocation(self, grant: dict, *, command_id=None, reason="Retire synthetic permission") -> dict:
        now = datetime.now(timezone.utc)
        command = {
            "schema": "sab.authority_revocation.v1", "command_id": command_id or "sab_authority_revoke_" + secrets.token_hex(12),
            "audience": self.policy["audience"], "lease_id": grant["lease_id"], "lease_sha256": grant["lease_sha256"],
            "revoker_id": self.issuer_id, "revoker_public_key": self.issuer_key.verify_key.encode().hex(),
            "reason": reason, "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=90)).isoformat(),
        }
        return {"revocation": command, "signature": self.issuer_key.sign(canonical(command)).signature.hex()}


def provision_authority_policy(tmp_path: Path, monkeypatch, *, audience="http://127.0.0.1:8000",
                               actions=ACTIONS, allowed_seed_ids=None) -> AuthorityFixture:
    issuer = SigningKey.generate()
    witness = SigningKey.generate()
    now = datetime.now(timezone.utc)
    issuer_public = issuer.verify_key.encode().hex()
    policy = {
        "schema": "sab.authority_policy.v1", "audience": audience, "policy_id": "sab_policy_synthetic_test",
        "not_before": (now - timedelta(minutes=1)).isoformat(), "expires_at": (now + timedelta(days=31)).isoformat(),
        "issuers": [{"subject_id": subject_for(issuer), "public_key": issuer_public,
                     "allowed_actions": list(actions), "allowed_seed_ids": list(allowed_seed_ids or []),
                     "all_seeds": allowed_seed_ids is None, "max_ttl_seconds": 31 * 86400,
                     "revoker_ids": [subject_for(issuer)]}],
        "witnesses": [{"subject_id": subject_for(witness), "public_key": witness.verify_key.encode().hex()}],
        "revokers": [{"subject_id": subject_for(issuer), "public_key": issuer_public}],
    }
    path = tmp_path / "synthetic-authority-policy.json"
    path.write_bytes(canonical(policy))
    path.chmod(0o600)
    monkeypatch.setenv("SAB_AUTHORITY_POLICY_PATH", str(path))
    monkeypatch.setenv("SAB_AUTHORITY_POLICY_SHA256", hash_json(policy))
    monkeypatch.setenv("SAB_IDENTITY_ORIGIN", audience)
    return AuthorityFixture(policy, issuer, witness)


def issue_grant(client, authority: AuthorityFixture, subject_id: str, target_seed_id: str, actions, **kwargs) -> dict:
    return authority.issue(client, subject_id, target_seed_id, actions, **kwargs)
