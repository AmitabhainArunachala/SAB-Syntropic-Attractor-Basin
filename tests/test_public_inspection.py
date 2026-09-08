"""A server's self-advertised digest cannot satisfy an independent input pin."""

from __future__ import annotations

import io
from urllib.request import Request

import pytest
from fastapi.testclient import TestClient

from agora import public_inspection
from tests.publication_fixtures import configure_publication, import_public_app, source_database


@pytest.fixture
def transport(tmp_path, monkeypatch):
    with source_database() as source:
        bundle = configure_publication(source, tmp_path / "empty", monkeypatch)
    app = import_public_app(tmp_path, monkeypatch)
    seen = []

    class Response(io.BytesIO):
        def __init__(self, response):
            super().__init__(response.content)
            self.status = response.status_code
            self.headers = response.headers

    with TestClient(app.app) as client:

        class Opener:
            def open(self, request, timeout):
                seen.append((request.method, request.selector))
                return Response(
                    client.request(
                        request.method,
                        request.selector,
                        content=request.data,
                        follow_redirects=False,
                    )
                )

        monkeypatch.setattr(public_inspection, "build_opener", lambda *args: Opener())
        yield bundle, seen


def test_expected_pin_is_independent_and_precedes_mutation_probe(transport):
    import hashlib

    bundle, seen = transport
    with pytest.raises(RuntimeError, match="independently expected"):
        public_inspection.inspect("https://example.org", expected_manifest_sha256="0" * 64)
    assert all(method == "GET" for method, _ in seen)
    expected = hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest()
    result = public_inspection.inspect("https://example.org", expected_manifest_sha256=expected)
    assert result["independent_pin_checked"] is True
    assert result["publication"]["manifest_sha256"] == expected
    assert result["claim_count"] == 0
    assert ("GET", "/heartbeat.md") in seen
    assert ("GET", "/static/dossier.css") in seen
    assert ("POST", "/api/v1/seeds") in seen


def test_smoke_without_expected_pin_does_not_claim_independent_check(transport):
    result = public_inspection.inspect("https://example.org")
    assert result["independent_pin_checked"] is False
    assert result["expected_manifest_sha256"] is None


@pytest.mark.parametrize("pin", ["", "A" * 64, "../private", "0" * 63])
def test_malformed_expected_pin_rejected_before_network(monkeypatch, pin):
    def unexpected(*args):
        pytest.fail("malformed pin reached transport")

    monkeypatch.setattr(public_inspection, "build_opener", unexpected)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        public_inspection.inspect("https://example.org", expected_manifest_sha256=pin)


def test_redirects_cannot_forward_inspection_to_another_service():
    handler = public_inspection._NoRedirect()
    assert (
        handler.redirect_request(
            Request("https://example.org/", data=b"not-json"),
            None,
            302,
            "Found",
            {},
            "https://other.example/",
        )
        is None
    )
