from __future__ import annotations

import hashlib
import json
from html.parser import HTMLParser

import pytest
from fastapi.testclient import TestClient
from jsonschema import validate


class Links(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.hrefs = []
        self.texts = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs.extend(value for key, value in attrs if key == "href")

    def handle_data(self, data):
        self.texts.append(data)


@pytest.fixture
def public_site(tmp_path, monkeypatch):
    from contextlib import ExitStack
    from publication_fixtures import source_database, configure_publication, import_public_app

    with source_database() as source, ExitStack() as stack:
        def open_site():
            configure_publication(source, tmp_path / "bundle", monkeypatch)
            app = import_public_app(tmp_path, monkeypatch)
            return app, stack.enter_context(TestClient(app.app))

        yield source, open_site



def seed(conn, seed_id="seed_dossier_web", title="Inspect a bounded claim", *, created="2026-07-01T00:00:00Z"):
    packet = {
        "schema": "sab.seed_packet.v1", "seed_id": seed_id, "title": title,
        "claim": {"claim_id": "claim_" + seed_id, "text": 'Exact <script>alert("claim")</script> text & scope.',
                  "scope": "Only the declared test fixture", "decision_context": "Whether to reproduce the fixture"},
        "claimant_identity": {"subject_id": "agent_web_fixture"},
        "evidence_bundle": [
            {"ref": "javascript:alert(1)", "kind": "untrusted_reference", "notes": "Must remain text"},
            {"ref": "https://example.org/record", "kind": "test", "digest": "sha256:" + "a" * 64},
        ],
        "challenge_plan": {"falsification_routes": ["Reproduce the bounded fixture and report the failure."],
                           "strongest_objections": ["The fixture may not cover an external runtime."]},
        "signature": {"signer": "agent_web_fixture", "signature": "not-a-signature"},
        "created_at": created,
    }
    unsigned = {key: value for key, value in packet.items() if key != "signature"}
    digest = "sha256:" + hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    conn.execute(
        """INSERT INTO sab_seed_packets_v1
        (seed_id,seed_type,title,claim_id,claimant_identity,authority_lease_id,state,packet_json,
         packet_hash,spark_projection_id,challenge_window_closes_at,created_at,updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (seed_id, "claim", title, "claim_" + seed_id, "agent_web_fixture", "lease_fixture", "pending_seed",
         json.dumps(packet), digest, None, "2026-07-08T00:00:00Z", created, created),
    )
    return packet


def database_digest(app):
    from publication_fixtures import database_observation

    return hashlib.sha256(json.dumps(database_observation(app)).encode()).hexdigest()


def test_origin_discovery_to_shared_dossier_and_download(public_site):
    source, open_site = public_site
    packet = seed(source)
    app, client = open_site()
    before = database_digest(app)
    discovery = client.get("/.well-known/sab-standing.json")
    assert discovery.status_code == 200
    assert discovery.headers["cache-control"] == "no-store"
    descriptor = discovery.json()
    assert descriptor["runtime_mode"] == "public_readonly"
    assert descriptor["public_mutation_enabled"] is False
    assert descriptor["inspection_authentication"] == "none"
    publication = client.get(descriptor["links"]["publication"]).json()
    manifest_response = client.get(descriptor["links"]["publication_manifest"])
    assert hashlib.sha256(manifest_response.content).hexdigest() == publication["manifest_sha256"]
    ledger = client.get(descriptor["links"]["claim_ledger"]).json()
    item = ledger["items"][0]
    dossier_response = client.get(item["links"]["dossier"])
    assert dossier_response.status_code == 200
    dossier = dossier_response.json()
    assert dossier["claim"]["text"] == packet["claim"]["text"]
    assert dossier["reliance"]["status"] == "unestablished"
    assert dossier["authority_effect"] == dossier["standing_effect"] == "none"
    schema_index = client.get(descriptor["links"]["schemas"]).json()
    for entry in schema_index["schemas"]:
        response = client.get(entry["url"])
        assert response.status_code == 200
        if entry["schema"] == dossier["schema"]:
            validate(dossier, response.json())
        if entry["schema"] == "sab.public_snapshot.v1":
            validate(manifest_response.json(), response.json())
    page = client.get(dossier["links"]["html"])
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert packet["claim"]["text"] in "".join(Links(page.text).texts)
    assert dossier["identity"]["packet_hash"] in page.text
    assert "Reliance not established" in page.text
    assert "Not established" in page.text
    assert 'href="javascript:' not in page.text
    assert '<script>alert("claim")</script>' not in page.text
    assert 'href="https://example.org/record"' in page.text
    download = client.get(dossier["links"]["download"])
    assert download.status_code == 200
    assert "attachment" in download.headers["content-disposition"]
    exported = download.json()
    assert exported["identity"] == dossier["identity"]
    assert exported["claim"] == dossier["claim"]
    assert not client.cookies
    assert app.BROWSER_SESSIONS is None
    assert database_digest(app) == before


def test_home_opens_actual_latest_claim_and_feed_bookmarks_survive(public_site):
    source, open_site = public_site
    seed(source, "seed_old", "Older claim")
    seed(source, "seed_new", "Latest actual submission", created="2026-07-02T00:00:00Z")
    app, client = open_site()
    page = client.get("/")
    assert page.status_code == 200
    assert 'data-seed-id="seed_new"' in page.text
    assert "Latest actual submission" in page.text
    assert "Latest submitted claim" in page.text
    old_bookmark = client.get("/?mode=most-challenged&limit=10", follow_redirects=False)
    assert old_bookmark.status_code == 307
    assert old_bookmark.headers["location"] == "/claims"
    assert client.get(old_bookmark.headers["location"]).status_code == 200


def test_ledger_search_pagination_and_clear_state(public_site):
    source, open_site = public_site
    seed(source, "seed_alpha", "Alpha reproduction")
    seed(source, "seed_beta", "Beta reproduction", created="2026-07-02T00:00:00Z")
    app, client = open_site()
    page = client.get("/claims?q=reproduction&limit=1")
    assert page.status_code == 200
    assert "2 matching claims" in page.text
    assert "Beta reproduction" in page.text
    assert "Alpha reproduction" not in page.text
    next_page = next(link for link in Links(page.text).hrefs if link.startswith("/claims?") and "offset=1" in link)
    assert "Alpha reproduction" in client.get(next_page).text
    filtered = client.get("/claims?q=ALPHA")
    assert "1 matching claim" in filtered.text
    assert "Alpha reproduction" in filtered.text
    missing = client.get("/claims?q=not-in-any-record")
    assert "No claims match these filters" in missing.text
    assert "Clear filters" in missing.text
    assert client.get("/claims?q=" + "x" * 201).status_code == 422


def test_empty_and_missing_claims_are_honest_recoverable_states(public_site):
    _, open_site = public_site
    _, client = open_site()
    assert "No claim dossier is available yet" in client.get("/").text
    assert "No submitted claims in this instance" in client.get("/claims").text
    missing = client.get("/claims/unknown")
    assert missing.status_code == 404
    assert "Claim dossier not found" in missing.text
    assert "/claims" in Links(missing.text).hrefs


@pytest.mark.parametrize("seed_id", ["seed/with/slash", ".", "..", "seed?query#fragment", "seed\\backslash", "seed\nnewline", "seed_言語"])
def test_stored_identifiers_round_trip_through_advertised_links(public_site, seed_id):
    source, open_site = public_site
    packet = seed(source, seed_id)
    app, client = open_site()
    item = client.get("/api/v1/claims").json()["items"][0]
    page = client.get(item["links"]["html"])
    assert page.status_code == 200
    assert packet["claim"]["text"] in "".join(Links(page.text).texts)
    for name in ("dossier", "download", "seed", "chain"):
        response = client.get(item["links"][name])
        assert response.status_code == 200, (name, item["links"][name], response.text)


def test_unavailable_challenge_table_is_unknown_in_local_ledger(tmp_path, monkeypatch):
    from publication_fixtures import import_public_app

    app = import_public_app(tmp_path, monkeypatch, mode="local")
    with TestClient(app.app) as client:
        with app._db() as conn:
            seed(conn)
            conn.execute("DROP TABLE sab_challenge_packets_v1")
        page = client.get("/claims")
        assert page.status_code == 200
        assert "Unresolved challenges: unknown" in page.text
        assert "None unresolved" not in page.text


@pytest.mark.parametrize("reference", ["javascript:alert(1)", "data:text/html,test", "//example.com", "/etc/passwd", "https://user:secret@example.com/x", "https://example.com/\nscript", "https://[invalid"])
def test_external_evidence_references_cannot_create_unsafe_links(public_site, reference):
    _, open_site = public_site
    app, _ = open_site()
    assert app._evidence_url(reference) is None
