"""Participant client tests use real Ed25519 and the actual SQLite verifier."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from nacl.signing import SigningKey

from agora import key_control_client as client
from agora.key_control import KeyControlError, KeyControlService, canonical_json_bytes
from agora.sab_seeding_api import _init_v1_tables

NOW = datetime(2026, 9, 9, tzinfo=timezone.utc)
ORIGIN = "https://sab.example"
REGISTRATION = {
    "display_name": "Public participant",
    "controller": "self",
    "operator_backing": {
        "operator_id": "operator:self-declared:test",
        "operator_kind": "human",
        "disclosure": "Test participant; independence remains unestablished.",
        "backing_count_attestation": "self_attested",
    },
}


class CountingKey(SigningKey):
    def __init__(self, seed):
        super().__init__(seed)
        self.signatures = []

    def sign(self, message, *args, **kwargs):
        self.signatures.append(message)
        return super().sign(message, *args, **kwargs)


@pytest.fixture
def key():
    return CountingKey(SigningKey.generate().encode())


class ServiceTransport:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""CREATE TABLE web_agents (
                id TEXT PRIMARY KEY, name TEXT, public_key TEXT, created_at TEXT,
                witness_count INTEGER, witness_accuracy REAL
            )""")
        _init_v1_tables(self.conn)
        self.conn.commit()
        self.service = KeyControlService(ORIGIN, utc_now=lambda: NOW, monotonic=lambda: 20.0)
        self.requests = []
        self.challenge_mutation = None
        self.result_mutation = None
        self.last_message = None

    def handler(self, request):
        payload = json.loads(request.content) if request.content else None
        self.requests.append((str(request.url), payload, request))
        assert request.headers.get("accept-encoding") == "identity"
        assert str(request.url).startswith(ORIGIN + "/")
        try:
            if request.url.path == client.CHALLENGE_PATH:
                document = self.service.issue(self.conn, payload)
                self.last_message = copy.deepcopy(document["message"])
                if self.challenge_mutation:
                    self.challenge_mutation(document)
            elif request.url.path == client.VERIFY_PATH:
                document = self.service.verify(self.conn, payload)
                if self.result_mutation:
                    self.result_mutation(document)
            else:
                raise AssertionError("unexpected endpoint")
            return httpx.Response(200, json=document)
        except KeyControlError as exc:
            return httpx.Response(exc.status, json={"code": exc.code})

    def options(self):
        return {"transport": httpx.MockTransport(self.handler), "utc_now": lambda: NOW}


@pytest.fixture
def service():
    bridge = ServiceTransport()
    yield bridge
    bridge.conn.close()


def test_enroll_real_key_control_without_transmitting_private_seed(service, key):
    result = client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    assert result["binding"]["status"] == "active"
    assert result["binding"]["scope"] == "key_control_only"
    assert result["authority_effect"] == result["standing_effect"] == "none"
    assert len(service.requests) == 2
    assert service.requests[0][1] == {
        "action": "register",
        "registration": {**REGISTRATION, "public_key": key.verify_key.encode().hex()},
    }
    assert set(service.requests[1][1]) == {"challenge_id", "signature"}
    assert len(key.signatures) == 1
    key.verify_key.verify(key.signatures[0], bytes.fromhex(service.requests[1][1]["signature"]))
    raw = json.dumps([payload for _, payload, _ in service.requests]) + json.dumps(result)
    assert key.encode().hex() not in raw
    assert service.conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 1


def test_revoke_proves_control_and_rejects_further_enrollment(service, key):
    enrollment = client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    subject = enrollment["identity"]["subject_id"]
    result = client.revoke(ORIGIN, subject, key, **service.options())
    assert result["identity"]["revocation_status"] == "revoked"
    assert result["binding"]["status"] == "revoked"
    assert service.requests[-2][1] == {"action": "revoke", "subject_id": subject}
    assert service.last_message["proposed_identity"] is None
    assert result["previous_binding"] is None
    with pytest.raises(client.KeyControlClientError) as failure:
        client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    assert failure.value.status_code == 403


def test_rotation_requires_both_signatures_on_identical_intended_message(service, key):
    enrollment = client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    successor = CountingKey(SigningKey.generate().encode())
    result = client.rotate(
        ORIGIN,
        enrollment["identity"]["subject_id"],
        {**REGISTRATION, "display_name": "Successor"},
        key,
        successor,
        **service.options(),
    )
    assert result["binding"]["public_key"] == successor.verify_key.encode().hex()
    assert result["binding"]["status"] == "active"
    assert result["previous_binding"]["status"] == "superseded"
    assert result["previous_binding"]["successor_subject_id"] == result["identity"]["subject_id"]
    assert key.signatures[-1] == successor.signatures[-1]
    verification = service.requests[-1][1]
    assert set(verification) == {"challenge_id", "signature", "successor_signature"}
    successor.verify_key.verify(
        key.signatures[-1], bytes.fromhex(verification["successor_signature"])
    )


def alter_message(field, value):
    return lambda envelope: envelope["message"].__setitem__(field, value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda envelope: envelope.__setitem__("untrusted_extra", True),
        lambda envelope: envelope.__setitem__("canonicalization", "server-selected"),
        lambda envelope: envelope.__setitem__("signature_algorithm", "rsa"),
        lambda envelope: envelope.__setitem__("standing_effect", "active"),
        lambda envelope: envelope.__setitem__("authority_effect", "granted"),
        lambda envelope: envelope.__setitem__("schema", "sab.seed_packet.v1"),
        alter_message("schema", "sab.authority_lease.v1"),
        alter_message("action", "revoke"),
        alter_message("audience", "https://different.example"),
        alter_message("audience", ORIGIN + "/"),
        alter_message("method", "GET"),
        alter_message("path", "/api/v1/standing"),
        alter_message("subject_id", "agent_attacker"),
        alter_message("public_key", "a" * 64),
        alter_message("nonce", "weak"),
        alter_message("challenge_id", "other_challenge"),
        alter_message("proposed_identity_sha256", "f" * 64),
        alter_message("unknown_signed_extension", "do not sign"),
        alter_message("issued_at", "2026-09-09T00:00:00"),
        alter_message("expires_at", "2026-09-09T00:01:00"),
        alter_message("issued_at", (NOW + timedelta(seconds=6)).isoformat()),
        alter_message("expires_at", NOW.isoformat()),
        alter_message("expires_at", (NOW + timedelta(seconds=121)).isoformat()),
        alter_message("expires_at", (NOW - timedelta(seconds=1)).isoformat()),
        alter_message("proposed_identity", None),
    ],
    ids=lambda value: str(getattr(value, "__name__", "mutation")),
)
def test_malformed_or_wrong_purpose_challenge_is_rejected_before_signing(service, key, mutate):
    service.challenge_mutation = mutate
    with pytest.raises(client.KeyControlClientError):
        client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    assert key.signatures == []
    assert len(service.requests) == 1
    assert service.conn.execute("SELECT count(*) FROM web_agents").fetchone()[0] == 0


@pytest.mark.parametrize(
    "change",
    [
        {"display_name": "Changed by server"},
        {"controller": "org"},
        {"identity_ref": "sab_identity_server_replacement"},
        {"revocation_status": "revoked"},
        {"operator_backing": {**REGISTRATION["operator_backing"], "disclosure": "Changed"}},
        {"unknown_field": "hidden instruction"},
        {"created_at": (NOW + timedelta(seconds=1)).isoformat()},
        {"evidence_refs": ["r"] * 33},
        {"evidence_refs": ["r" * 513]},
    ],
)
def test_rehashed_registration_tampering_cannot_pass_client(service, key, change):
    def mutate(envelope):
        identity = envelope["message"]["proposed_identity"]
        identity.update(change)
        envelope["message"]["proposed_identity_sha256"] = hashlib.sha256(
            canonical_json_bytes(identity)
        ).hexdigest()

    service.challenge_mutation = mutate
    with pytest.raises(client.KeyControlClientError):
        client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    assert key.signatures == []


def test_challenge_expiry_is_inclusive_in_participant_clock(service, key):
    options = {**service.options(), "utc_now": lambda: NOW + timedelta(seconds=120)}
    with pytest.raises(client.KeyControlClientError, match="challenge_expired"):
        client.enroll(ORIGIN, REGISTRATION, key, **options)
    assert key.signatures == []


@pytest.mark.parametrize("observed", [NOW.replace(tzinfo=None), None, "2026-09-09"])
def test_invalid_local_clock_prevents_signing(service, key, observed):
    with pytest.raises(client.KeyControlClientError, match="local_clock_unavailable"):
        client.enroll(
            ORIGIN, REGISTRATION, key, **{**service.options(), "utc_now": lambda: observed}
        )
    assert key.signatures == []


@pytest.mark.parametrize(
    "origin",
    [
        "http://sab.example",
        "ftp://sab.example",
        "https://name:private@host.example",
        "https://sab.example/path",
        "https://sab.example?x=1",
        "https://sab.example#x",
        "https://sab.example\\@evil.example",
        "https://sab.example\n",
        "http://127.0.0.1.evil.example",
        "https://sab.example:0",
        "https://sab.example:65536",
    ],
)
def test_invalid_origin_rejected_before_network(service, key, origin):
    with pytest.raises(client.KeyControlClientError, match="https_or_loopback_origin_required"):
        client.enroll(origin, REGISTRATION, key, **service.options())
    assert service.requests == []
    assert key.signatures == []


@pytest.mark.parametrize(
    "origin, canonical",
    [
        ("https://SAB.EXAMPLE:443/", ORIGIN),
        ("http://127.0.0.1:8765/", "http://127.0.0.1:8765"),
        ("http://[::1]:8765", "http://[::1]:8765"),
        ("http://localhost/", "http://localhost"),
    ],
)
def test_canonical_origin_selects_actual_transport_destination(origin, canonical, key):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(403, json={"error": "readonly"})

    with pytest.raises(client.KeyControlClientError) as failure:
        client.enroll(origin, REGISTRATION, key, transport=httpx.MockTransport(handler))
    assert failure.value.status_code == 403
    assert calls == [canonical + client.CHALLENGE_PATH]
    assert key.signatures == []


@pytest.mark.parametrize(
    "response, reason",
    [
        (httpx.Response(307, headers={"location": ORIGIN + "/forward"}), "redirect_refused"),
        (
            httpx.Response(302, headers={"location": "https://elsewhere.example"}),
            "redirect_refused",
        ),
        (
            httpx.Response(
                200,
                content=b"x" * (client.MAX_DOCUMENT_BYTES + 1),
                headers={"content-type": "application/json"},
            ),
            "response_too_large",
        ),
        (
            httpx.Response(
                200, content=b'{"same":1,"same":2}', headers={"content-type": "application/json"}
            ),
            "invalid_json_document",
        ),
        (
            httpx.Response(
                200, content=b'{"value":NaN}', headers={"content-type": "application/json"}
            ),
            "invalid_json_document",
        ),
        (
            httpx.Response(
                200, content=b'{"value":1e999}', headers={"content-type": "application/json"}
            ),
            "invalid_json_document",
        ),
        (
            httpx.Response(200, content=b"[]", headers={"content-type": "application/json"}),
            "unexpected_document_shape",
        ),
        (httpx.Response(200, text="text only"), "json_response_required"),
    ],
)
def test_untrusted_transport_responses_do_not_prompt_signatures(key, response, reason):
    calls = []

    def handler(request):
        calls.append(request)
        return response

    with pytest.raises(client.KeyControlClientError, match=reason):
        client.enroll(ORIGIN, REGISTRATION, key, transport=httpx.MockTransport(handler))
    assert len(calls) == 1
    assert key.signatures == []


def test_network_error_and_remote_errors_do_not_echo_body_or_secret(key):
    seed = key.encode().hex()

    def failed_transport(request):
        raise httpx.ConnectError(seed, request=request)

    with pytest.raises(client.KeyControlClientError) as failure:
        client.enroll(ORIGIN, REGISTRATION, key, transport=httpx.MockTransport(failed_transport))
    assert str(failure.value) == "transport_failed"
    with pytest.raises(client.KeyControlClientError) as failure:
        client.enroll(
            ORIGIN,
            REGISTRATION,
            key,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(403, json={"detail": seed})
            ),
        )
    assert str(failure.value) == "service_rejected_operation"
    assert failure.value.status_code == 403


def test_response_budget_stops_slow_trickle_and_closes_stream(monkeypatch, key):
    observed = [0.0]

    class Trickle(httpx.SyncByteStream):
        def __init__(self):
            self.delivered = 0
            self.closed = False

        def __iter__(self):
            while True:
                observed[0] += 6.0
                self.delivered += 1
                yield b" "

        def close(self):
            self.closed = True

    stream = Trickle()
    monkeypatch.setattr(client.time, "monotonic", lambda: observed[0])
    with pytest.raises(client.KeyControlClientError, match="response_time_budget_exceeded"):
        client.enroll(
            ORIGIN,
            REGISTRATION,
            key,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, stream=stream, headers={"content-type": "application/json"}
                )
            ),
        )
    assert stream.delivered == 4
    assert stream.closed
    assert key.signatures == []


def test_encoded_response_is_rejected_before_reading_or_decompressing(key):
    class Unreadable(httpx.SyncByteStream):
        def __iter__(self):
            pytest.fail("compressed body must not be read")
            yield b""

    with pytest.raises(client.KeyControlClientError, match="encoded_response_refused"):
        client.enroll(
            ORIGIN,
            REGISTRATION,
            key,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    stream=Unreadable(),
                    headers={
                        "content-type": "application/json",
                        "content-encoding": "gzip",
                    },
                )
            ),
        )
    assert key.signatures == []


def test_oversized_outbound_document_never_reaches_transport(key, monkeypatch):
    # Isolate the outbound cap from the normalizer's tighter field limits.
    monkeypatch.setattr(client, "MAX_REQUEST_BYTES", 32)
    with pytest.raises(client.KeyControlClientError, match="request_too_large"):
        client.enroll(
            ORIGIN,
            REGISTRATION,
            key,
            transport=httpx.MockTransport(
                lambda request: pytest.fail("oversized document must not leave client")
            ),
        )
    assert key.signatures == []


def test_environment_proxy_and_credentials_are_not_inherited(monkeypatch, service, key):
    monkeypatch.setenv("HTTPS_PROXY", "https://private:credential@proxy.invalid")
    monkeypatch.setenv("HTTP_PROXY", "https://private:credential@proxy.invalid")
    monkeypatch.setenv("ALL_PROXY", "https://private:credential@proxy.invalid")
    actual = httpx.Client
    options = []

    def observe_client(**kwargs):
        options.append(kwargs)
        return actual(**kwargs)

    monkeypatch.setattr(client.httpx, "Client", observe_client)
    client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    assert options[0]["trust_env"] is False
    assert options[0]["follow_redirects"] is False
    assert all("authorization" not in request.headers for _, _, request in service.requests)


@pytest.mark.parametrize(
    "registration",
    [
        {**REGISTRATION, "private_key": "must never be sent"},
        {**REGISTRATION, "public_key": "a" * 64},
        {**REGISTRATION, "operator_backing": {"private_key": "must never be sent"}},
        {**REGISTRATION, "display_name": float("nan")},
        {**REGISTRATION, "display_name": "x" * (client.MAX_DOCUMENT_BYTES + 1)},
    ],
)
def test_invalid_or_secret_registration_never_leaves_client(service, key, registration):
    with pytest.raises(client.KeyControlClientError):
        client.enroll(ORIGIN, registration, key, **service.options())
    assert service.requests == []
    assert key.signatures == []


def test_rotation_cannot_reuse_key_or_mismatch_successor_metadata(service, key):
    with pytest.raises(client.KeyControlClientError, match="distinct_successor_key"):
        client.rotate(ORIGIN, "agent_old", REGISTRATION, key, key, **service.options())
    successor = SigningKey.generate()
    with pytest.raises(
        client.KeyControlClientError, match="registration_key_does_not_match_local_key"
    ):
        client.rotate(
            ORIGIN,
            "agent_old",
            {**REGISTRATION, "public_key": key.verify_key.encode().hex()},
            key,
            successor,
            **service.options(),
        )
    assert service.requests == []
    assert key.signatures == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.__setitem__("standing_effect", "active"),
        lambda result: result.__setitem__("unknown_extension", "extra"),
        lambda result: result.__setitem__("challenge_id", "sab_kc_challenge_" + "a" * 32),
        lambda result: result.__setitem__(
            "verified_at", (NOW + timedelta(seconds=120)).isoformat()
        ),
        lambda result: result["identity"].__setitem__("display_name", "Changed after signing"),
        lambda result: result["binding"].__setitem__("scope", "authority"),
        lambda result: result["binding"].__setitem__("status", "superseded"),
        lambda result: result.__setitem__("previous_binding", {}),
    ],
)
def test_unexpected_result_is_not_returned_as_a_successful_receipt(service, key, mutate):
    service.result_mutation = mutate
    with pytest.raises(client.KeyControlClientError):
        client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    # Verification may already have committed remotely; the client reports no
    # accepted receipt and makes no automatic retry or rollback claim.
    assert len(service.requests) == 2


def test_keygen_writes_private_seed_exclusively_and_returns_only_public_metadata(tmp_path, capsys):
    path = tmp_path / "participant.ed25519"
    assert client.main(["keygen", "--key-file", str(path)]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    key = client.load_signing_key(path)
    assert result["public_key"] == key.verify_key.encode().hex()
    assert key.encode().hex() not in captured.out + captured.err
    original = path.read_bytes()
    assert client.main(["keygen", "--key-file", str(path)]) == 1
    assert path.read_bytes() == original
    assert "key_file_already_exists" in capsys.readouterr().err


def test_keygen_and_load_refuse_symlinks_and_preserve_target(tmp_path):
    target = tmp_path / "target.ed25519"
    client.generate_key_file(target)
    original = target.read_bytes()
    alias = tmp_path / "alias.ed25519"
    alias.symlink_to(target)
    with pytest.raises(client.KeyControlClientError):
        client.generate_key_file(alias)
    with pytest.raises(client.KeyControlClientError):
        client.load_signing_key(alias)
    assert target.read_bytes() == original
    dangling = tmp_path / "dangling.ed25519"
    dangling.symlink_to(tmp_path / "missing")
    with pytest.raises(client.KeyControlClientError):
        client.generate_key_file(dangling)
    assert not (tmp_path / "missing").exists()


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o666, 0o400, 0o700])
def test_key_reader_requires_exact_private_mode(tmp_path, mode):
    path = tmp_path / "key"
    client.generate_key_file(path)
    path.chmod(mode)
    with pytest.raises(client.KeyControlClientError, match="0600"):
        client.load_signing_key(path)
    assert stat.S_IMODE(path.stat().st_mode) == mode


def test_key_reader_refuses_fifo_directory_and_hardlinks(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    for path in (fifo, tmp_path):
        with pytest.raises(client.KeyControlClientError):
            client.load_signing_key(path)
    path = tmp_path / "key"
    client.generate_key_file(path)
    os.link(path, tmp_path / "hardlink")
    with pytest.raises(client.KeyControlClientError, match="single_link"):
        client.load_signing_key(path)


@pytest.mark.parametrize("content", [b"", b"a" * 63, b"g" * 64, b"a" * 64 + b" ", b"a" * 128])
def test_invalid_seed_encoding_fails_without_echoing_contents(tmp_path, content):
    path = tmp_path / "key"
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(client.KeyControlClientError) as failure:
        client.load_signing_key(path)
    assert repr(content) not in str(failure.value)


@pytest.mark.parametrize("line_ending", [b"", b"\n", b"\r\n"])
def test_existing_hex_seed_files_are_supported(tmp_path, key, line_ending):
    path = tmp_path / "key"
    path.write_bytes(key.encode().hex().upper().encode() + line_ending)
    path.chmod(0o600)
    assert client.load_signing_key(path).verify_key == key.verify_key


@pytest.mark.parametrize("command", ["enroll", "revoke", "rotate"])
def test_cli_uses_existing_local_keys_and_outputs_public_receipt(
    tmp_path, capsys, monkeypatch, command
):
    path = tmp_path / "key"
    new_path = tmp_path / "new-key"
    client.generate_key_file(path)
    client.generate_key_file(new_path)
    registration = tmp_path / "public-registration.json"
    registration.write_text(json.dumps(REGISTRATION))
    seen = []

    def operation(*args):
        seen.append(args)
        return {
            "schema": "sab.key_control_result.v1",
            "authority_effect": "none",
            "standing_effect": "none",
        }

    monkeypatch.setattr(client, command, operation)
    args = [command, "--origin", ORIGIN, "--key-file", str(path)]
    if command in {"enroll", "rotate"}:
        args += ["--registration", str(registration)]
    if command in {"revoke", "rotate"}:
        args += ["--subject-id", "agent_existing"]
    if command == "rotate":
        args += ["--new-key-file", str(new_path)]
    assert client.main(args) == 0
    assert len(seen) == 1
    assert seen[0][0] == ORIGIN
    if command in {"revoke", "rotate"}:
        assert seen[0][1] == "agent_existing"
    if command in {"enroll", "rotate"}:
        assert seen[0][1 if command == "enroll" else 2] == REGISTRATION
    local_keys = [argument for argument in seen[0] if isinstance(argument, SigningKey)]
    assert local_keys[0].verify_key == client.load_signing_key(path).verify_key
    if command == "rotate":
        assert len(local_keys) == 2
        assert local_keys[1].verify_key == client.load_signing_key(new_path).verify_key
    captured = capsys.readouterr()
    assert json.loads(captured.out)["standing_effect"] == "none"
    for key_path in (path, new_path):
        assert key_path.read_text().strip() not in captured.out + captured.err


def test_cli_reports_readonly_rejection_without_retry_or_secret(tmp_path, capsys, monkeypatch):
    path = tmp_path / "key"
    client.generate_key_file(path)

    def rejected(*args):
        raise client.KeyControlClientError("service_rejected_operation", status_code=403)

    monkeypatch.setattr(client, "revoke", rejected)
    assert (
        client.main(
            [
                "revoke",
                "--origin",
                ORIGIN,
                "--key-file",
                str(path),
                "--subject-id",
                "agent_existing",
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {"error": "service_rejected_operation", "http_status": 403}
    assert path.read_text().strip() not in captured.err


def test_enrollment_never_implicitly_creates_a_key(tmp_path, monkeypatch, capsys):
    key_path = tmp_path / "missing-key"
    registration = tmp_path / "public.json"
    registration.write_text(json.dumps(REGISTRATION))
    monkeypatch.setattr(client, "enroll", lambda *args: pytest.fail("a key must already exist"))
    assert (
        client.main(
            [
                "enroll",
                "--origin",
                ORIGIN,
                "--key-file",
                str(key_path),
                "--registration",
                str(registration),
            ]
        )
        == 1
    )
    assert not key_path.exists()
    assert capsys.readouterr().out == ""


def test_cli_rejects_fifo_or_symlink_registration_without_opening_transport(
    tmp_path, monkeypatch, capsys
):
    key_path = tmp_path / "key"
    client.generate_key_file(key_path)
    fifo = tmp_path / "public-fifo"
    os.mkfifo(fifo)
    symlink = tmp_path / "public-symlink"
    symlink.symlink_to(key_path)
    monkeypatch.setattr(
        client, "enroll", lambda *args: pytest.fail("unsafe file must not be submitted")
    )
    for registration in (fifo, symlink):
        assert (
            client.main(
                [
                    "enroll",
                    "--origin",
                    ORIGIN,
                    "--key-file",
                    str(key_path),
                    "--registration",
                    str(registration),
                ]
            )
            == 1
        )
        captured = capsys.readouterr()
        assert captured.out == ""
        assert key_path.read_text().strip() not in captured.err


def test_active_binding_match_requires_exact_declared_metadata(service, key):
    receipt = client.enroll(ORIGIN, REGISTRATION, key, **service.options())
    home = {"identity": receipt["identity"], "key_control": receipt["binding"]}
    assert client.active_binding_matches(home, REGISTRATION, key)
    assert not client.active_binding_matches({}, REGISTRATION, key)
    assert not client.active_binding_matches(
        home, {**REGISTRATION, "display_name": "Different"}, key
    )
    changed = copy.deepcopy(home)
    changed["key_control"]["status"] = "unproven"
    assert not client.active_binding_matches(changed, REGISTRATION, key)
    changed["key_control"]["status"] = "revoked"
    assert not client.active_binding_matches(changed, REGISTRATION, key)


def test_read_home_is_bounded_and_does_not_follow_redirects():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.content == b""
        assert request.url.params["subject_id"] == "agent_existing"
        return httpx.Response(307, headers={"location": "https://elsewhere.example"})

    with pytest.raises(client.KeyControlClientError, match="redirect_refused"):
        client.read_home(ORIGIN, "agent_existing", transport=httpx.MockTransport(handler))
    assert len(calls) == 1


def load_tick():
    path = Path(__file__).resolve().parents[1] / "scripts" / "sab_agent_tick.py"
    spec = importlib.util.spec_from_file_location("sab_agent_tick_client_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_tick_does_not_treat_an_unsigned_home_as_registered(monkeypatch, key):
    tick = load_tick()
    # The full suite reloads Agora modules; patch the client used by this tick.
    live_client = importlib.import_module("agora.key_control_client")
    monkeypatch.setattr(
        httpx, "Client", lambda *args, **kwargs: pytest.fail("unexpected live HTTP")
    )
    events = []
    enrollments = []
    monkeypatch.setattr(tick, "log_event", events.append)
    monkeypatch.setattr(live_client, "read_home", lambda *args: {"subject_id": "agent_existing"})

    def enroll(origin, registration, sk):
        enrollments.append((origin, registration, sk))
        return {"proof_id": "sab_kc_proof_" + "a" * 32}

    monkeypatch.setattr(live_client, "enroll", enroll)
    assert tick.ensure_registered("agent_existing", key)
    assert len(enrollments) == 1
    assert enrollments[0][1]["controller"] == "operator"
    assert enrollments[0][1]["operator_backing"]["operator_id"] == tick.OPERATOR
    assert "operator_ref" not in enrollments[0][1]["operator_backing"]
    assert key.encode().hex() not in json.dumps(events)


def test_tick_does_not_reenroll_an_exact_active_binding(monkeypatch, key):
    tick = load_tick()
    # The full suite reloads Agora modules; patch the client used by this tick.
    live_client = importlib.import_module("agora.key_control_client")
    monkeypatch.setattr(
        httpx, "Client", lambda *args, **kwargs: pytest.fail("unexpected live HTTP")
    )
    monkeypatch.setattr(live_client, "read_home", lambda *args: {"identity": "checked by helper"})
    monkeypatch.setattr(live_client, "active_binding_matches", lambda *args: True)
    monkeypatch.setattr(
        live_client, "enroll", lambda *args: pytest.fail("must not create another proof")
    )
    assert tick.ensure_registered("agent_existing", key)


@pytest.mark.parametrize("status", ["revoked", "superseded", "inconsistent"])
def test_tick_never_reactivates_a_retired_binding(monkeypatch, key, status):
    tick = load_tick()
    # The full suite reloads Agora modules; patch the client used by this tick.
    live_client = importlib.import_module("agora.key_control_client")
    monkeypatch.setattr(
        httpx, "Client", lambda *args, **kwargs: pytest.fail("unexpected live HTTP")
    )
    monkeypatch.setattr(tick, "log_event", lambda value: None)
    monkeypatch.setattr(live_client, "read_home", lambda *args: {"key_control": {"status": status}})
    monkeypatch.setattr(
        live_client, "enroll", lambda *args: pytest.fail("retired identity must not enroll")
    )
    assert not tick.ensure_registered("agent_existing", key)
