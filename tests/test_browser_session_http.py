"""Cookie custody, explicit signed login, and denied-before-body HTTP boundaries."""
from __future__ import annotations

import asyncio
import hashlib

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from keycontrol_fixtures import enroll_identity, proof_for, prove_control
from test_key_control_http import local_app, client, _state  # noqa: F401

ORIGIN = 'http://127.0.0.1:8000'
PREFIX = '/api/v1/browser/session'


def open_session(client, key, subject, origin=ORIGIN):
    issued = client.post(PREFIX + '/challenge', json={'subject_id': subject}, headers={'Origin': origin})
    assert issued.status_code == 200, issued.text
    proof = proof_for(key, issued.json())
    response = client.post(PREFIX + '/verify', json=proof, headers={'Origin': origin})
    assert response.status_code == 200, response.text
    return issued.json(), proof, response


def test_cookie_contains_only_random_bearer_and_durable_store_only_hash(client, local_app):
    key = SigningKey.generate()
    identity = enroll_identity(client, key, display_name='Browser public name')
    challenge, proof, response = open_session(client, key, identity['subject_id'])
    token = response.cookies['sab_web_session']
    cookie = response.headers['set-cookie'].lower()
    assert len(token) == 43
    assert 'httponly' in cookie and 'samesite=strict' in cookie and 'max-age=21600' in cookie
    assert 'secure' not in cookie
    assert token not in response.text
    assert key.encode().hex() not in response.text
    assert '_session_token' not in response.json()
    state = '\n'.join(_state(local_app))
    assert token not in state and key.encode().hex() not in state
    assert hashlib.sha256(token.encode()).hexdigest() in state
    before = _state(local_app)
    observed = client.get(PREFIX)
    assert observed.status_code == 200
    assert observed.json()['session']['subject_id'] == identity['subject_id']
    assert observed.json()['session']['csrf_token'] != token
    assert observed.headers['cache-control'] == 'no-store'
    assert _state(local_app) == before
    replay = client.post(PREFIX + '/verify', json=proof, headers={'Origin': ORIGIN})
    assert replay.status_code == 409
    assert _state(local_app) == before
    with TestClient(local_app.app) as stranger:
        assert stranger.get(PREFIX).json()['session'] is None


def test_cookie_session_is_not_a_grant_and_unsigned_forms_have_no_effect(client, local_app):
    key = SigningKey.generate()
    identity = enroll_identity(client, key)
    open_session(client, key, identity['subject_id'])
    before = _state(local_app)
    for path in ['/register', '/submit', '/spark/1/challenge', '/spark/1/witness']:
        rejected = client.post(path, content=b'not valid form or JSON', headers={'Origin': ORIGIN})
        assert rejected.status_code == 428
    home = client.get('/api/v1/agents/me/home', params={'subject_id': identity['subject_id']}).json()
    assert home['active_authority_leases'] == []
    assert _state(local_app) == before


@pytest.mark.parametrize('path', ['/register', '/submit', '/spark/9/challenge', '/spark/9/witness', PREFIX+'/challenge', PREFIX+'/verify', PREFIX+'/logout'])
@pytest.mark.parametrize('origin', [None, 'null', 'https://attacker.invalid', ORIGIN])
def test_retired_forms_and_origin_denials_do_not_read_body(local_app, path, origin):
    headers = [(b'host', b'127.0.0.1:8000'), (b'content-type', b'application/json')]
    if origin is not None:
        headers.append((b'origin', origin.encode()))
    # Proper-origin active session requests legitimately read JSON; this test
    # instead exercises the adapter's origin-required branch for those routes.
    if path.startswith(PREFIX) and origin == ORIGIN:
        headers.append((b'sec-fetch-site', b'cross-site'))
    scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'POST','scheme':'http',
             'path':path,'raw_path':path.encode(),'query_string':b'', 'headers':headers,
             'client':('127.0.0.1',12345),'server':('127.0.0.1',8000),'root_path':''}
    messages = []

    async def receive():
        pytest.fail('A denied browser request read its body')

    async def send(message):
        messages.append(message)

    before = _state(local_app)
    asyncio.run(local_app.app(scope, receive, send))
    status = next(item['status'] for item in messages if item['type'] == 'http.response.start')
    assert status in {403, 428}
    assert _state(local_app) == before


@pytest.mark.parametrize('content,status', [(b'{"subject_id":"a","subject_id":"b"}',400), (b'NaN',400),
                                           (b'[]',400), (b'{"subject_id":1e999}',400), (b'x'*4097,413)])
def test_session_body_is_closed_bounded_and_no_effect(client, local_app, content, status):
    before = _state(local_app)
    response = client.post(PREFIX+'/challenge', content=content, headers={'Origin':ORIGIN,'Content-Type':'application/json'})
    assert response.status_code == status
    assert _state(local_app) == before


def test_logout_requires_origin_and_csrf_and_ends_only_its_session(client, local_app):
    key = SigningKey.generate(); identity = enroll_identity(client, key)
    _, _, first = open_session(client,key,identity['subject_id'])
    first_token = first.cookies['sab_web_session']
    _, _, second = open_session(client,key,identity['subject_id'])
    csrf = second.json()['csrf_token']
    before = _state(local_app)
    for headers, token in [({},csrf), ({'Origin':'https://attacker.invalid'},csrf), ({'Origin':ORIGIN},'wrong')]:
        result = client.post(PREFIX+'/logout',json={'csrf_token':token},headers=headers)
        assert result.status_code == 403
        assert _state(local_app) == before
    response = client.post(PREFIX+'/logout', json={'csrf_token':csrf}, headers={'Origin':ORIGIN})
    assert response.status_code == 200 and response.json()['signed_out'] is True
    assert 'Max-Age=0' in response.headers['set-cookie']
    assert client.get(PREFIX).json()['session'] is None
    with local_app._db() as conn:
        assert local_app.BROWSER_SESSIONS.read(conn,first_token)['subject_id'] == identity['subject_id']


def test_retirement_invalidates_cookie_and_page_does_not_reflect_private_state(client, local_app):
    key = SigningKey.generate(); identity = enroll_identity(client,key,display_name='<script>alert(1)</script>')
    _, _, response = open_session(client,key,identity['subject_id'])
    page = client.get('/register')
    assert page.status_code == 200
    assert '<script>alert(1)</script>' not in page.text
    assert response.cookies['sab_web_session'] not in page.text
    assert key.encode().hex() not in page.text
    assert "script-src 'self'" in page.headers['content-security-policy']
    assert 'unsafe-eval' not in page.headers['content-security-policy']
    assert page.headers['x-content-type-options'] == 'nosniff'
    prove_control(client,key,{'action':'revoke','subject_id':identity['subject_id']})
    assert client.get(PREFIX).json()['session'] is None


def test_https_cookie_security_uses_configured_origin_not_forwarded_headers(local_app, monkeypatch):
    from test_key_control_http import _reload_app

    monkeypatch.setenv("SAB_IDENTITY_ORIGIN", "https://sab.example")
    monkeypatch.delenv("SAB_AUTHORITY_POLICY_PATH", raising=False)
    monkeypatch.delenv("SAB_AUTHORITY_POLICY_SHA256", raising=False)
    module = _reload_app()
    with TestClient(module.app, base_url="https://sab.example") as secure_client:
        key = SigningKey.generate()
        identity = enroll_identity(secure_client, key)
        secure_client.headers["X-Forwarded-Proto"] = "http"
        _, _, response = open_session(secure_client, key, identity["subject_id"], origin="https://sab.example")
        cookie = response.headers["set-cookie"].lower()
        assert "secure" in cookie and "httponly" in cookie and "samesite=strict" in cookie
        assert secure_client.get(PREFIX).json()["session"]["subject_id"] == identity["subject_id"]
