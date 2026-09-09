"""Caller-signed historical discussion fixtures, without server-held user keys.

These clients enroll through a real Ed25519 proof and explicitly sign the legacy
discussion protocol. The resulting records exercise historical rendering only;
they do not issue a SAB authority grant or establish scoped standing.
"""

from __future__ import annotations

import hashlib
import json


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class HistoricalWebActor:
    def __init__(self, client, display_name="historical-test-author"):
        from nacl.signing import SigningKey
        from keycontrol_fixtures import enroll_identity

        self.client = client
        self._key = SigningKey.generate()
        self.identity = enroll_identity(client, self._key, display_name=display_name)
        self.subject_id = self.identity["subject_id"]

    def _signature(self, message):
        return self._key.sign(_canonical(message)).signature.hex()

    def submit(self, content):
        response = self.client.post("/api/spark/submit", json={
            "content": content, "content_type": "text", "author_id": self.subject_id,
            "signature": self._signature({
                "kind": "spark_submit", "author_id": self.subject_id,
                "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            }),
        })
        assert response.status_code == 201, response.text
        record = response.json()
        assert record["author_id"] == self.subject_id
        assert record["authority"]["standing_effect"] == "none"
        return record

    def challenge(self, spark_id, content):
        response = self.client.post(f"/api/spark/{spark_id}/challenge", json={
            "challenger_id": self.subject_id, "content": content,
            "signature": self._signature({
                "kind": "spark_challenge", "spark_id": spark_id,
                "challenger_id": self.subject_id,
                "content_sha256": hashlib.sha256(content.encode()).hexdigest(),
            }),
        })
        assert response.status_code == 201, response.text
        record = response.json()
        assert record["challenger_id"] == self.subject_id
        assert record["content"] == content
        return record

    def witness(self, spark_id, action, note):
        payload = {"note": note}
        response = self.client.post("/api/witness/sign", json={
            "spark_id": spark_id, "witness_id": self.subject_id,
            "action": action, "payload": payload,
            "signature": self._signature({
                "kind": "witness_attestation", "spark_id": spark_id,
                "witness_id": self.subject_id, "action": action,
                "payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
            }),
        })
        assert response.status_code == 200, response.text
        record = response.json()
        assert record["entry"]["witness_id"] == self.subject_id
        assert record["entry"]["action"] == action
        assert record["authority"]["standing_effect"] == "none"
        return record

    def open_session(self, audience):
        """Perform the independent signed login proof using this caller's key."""
        headers = {"Origin": audience}
        challenge = self.client.post("/api/v1/browser/session/challenge",
                                     json={"subject_id": self.subject_id}, headers=headers)
        assert challenge.status_code == 200, challenge.text
        message = challenge.json()["message"]
        assert message["audience"] == audience
        assert message["action"] == "open_session"
        assert message["path"] == "/api/v1/browser/session/verify"
        assert message["subject_id"] == self.subject_id
        assert message["public_key"] == self.identity["public_key"]
        response = self.client.post("/api/v1/browser/session/verify", json={
            "challenge_id": message["challenge_id"], "signature": self._signature(message),
        }, headers=headers)
        assert response.status_code == 200, response.text
        observation = response.json()
        assert "_session_token" not in observation
        assert observation["subject_id"] == self.subject_id
        assert observation["authority_effect"] == observation["standing_effect"] == "none"
        return observation


def historical_actor(client):
    """Retain the synthetic key on the test client, never on the application."""
    actor = getattr(client, "_historical_test_actor", None)
    if actor is None:
        actor = HistoricalWebActor(client)
        client._historical_test_actor = actor
    return actor


def historical_spark(client, content):
    record = historical_actor(client).submit(content)
    return f"/spark/{record['id']}"


def database_state(module):
    with module._db() as conn:
        return tuple(conn.iterdump())
