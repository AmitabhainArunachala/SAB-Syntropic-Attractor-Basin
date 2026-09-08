"""A server's self-advertised digest cannot satisfy an independent input pin."""

from __future__ import annotations

import io
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from urllib.request import Request

import pytest
from fastapi.testclient import TestClient

from agora import public_inspection
from tests.publication_fixtures import configure_publication, import_public_app, source_database


SOURCE_TIME = datetime(2026, 9, 9, tzinfo=timezone.utc)


@pytest.fixture
def response_changes():
    return {}


@pytest.fixture
def transport(tmp_path, monkeypatch, request, response_changes):
    configuration = getattr(request, "param", {})
    with source_database() as source:
        if configuration.get("populated"):
            from tests.test_public_snapshot import _seed

            _seed(source)
        bundle = configure_publication(source, tmp_path / "empty", monkeypatch)
    app = import_public_app(tmp_path, monkeypatch)
    from agora.public_freshness import FreshnessPolicy, PublicationFreshnessObserver

    clock = {"elapsed": 0}
    now = SOURCE_TIME + timedelta(seconds=configuration.get("source_age", 90000))
    app.PUBLIC_FRESHNESS = PublicationFreshnessObserver(
        app.PUBLIC_SNAPSHOT.status, FreshnessPolicy(),
        utc_now=lambda: now + timedelta(seconds=clock["elapsed"]),
        monotonic=lambda: 100.0 + clock["elapsed"],
    )
    seen = []

    class Response(io.BytesIO):
        def __init__(self, response, path):
            data = {"body": response.content, "headers": dict(response.headers)}
            if path in response_changes:
                response_changes[path](data)
            super().__init__(data["body"])
            self.status = response.status_code
            from httpx import Headers

            self.headers = Headers(data["headers"])

    with TestClient(app.app) as client:

        class Opener:
            def open(self, request, timeout):
                seen.append((request.method, request.selector))
                clock["elapsed"] += 1
                return Response(
                    client.request(
                        request.method,
                        request.selector,
                        content=request.data,
                        follow_redirects=False,
                    ), request.selector,
                )

        monkeypatch.setattr(public_inspection, "build_opener", lambda *args: Opener())
        yield bundle, seen


def test_expected_pin_is_independent_and_precedes_mutation_probe(transport):
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
    assert ("GET", "/status") in seen
    assert ("GET", "/schemas/sab.public_read_observation.v1.schema.json") in seen
    assert ("POST", "/api/v1/seeds") in seen


def test_smoke_without_expected_pin_does_not_claim_independent_check(transport):
    result = public_inspection.inspect("https://example.org")
    assert result["independent_pin_checked"] is False
    assert result["expected_manifest_sha256"] is None
    assert result["client_age_admission"] == {"requested": False, "status": "not_requested"}
    assert result["currentness"] == "unestablished"
    assert result["authorizes_use"] is False
    assert result["authority_effect"] == result["standing_effect"] == "none"


@pytest.mark.parametrize("transport", [{"populated": True}, {"source_age": -3600}], indirect=True)
def test_historical_smoke_accepts_stale_or_future_history_and_different_request_times(transport):
    result = public_inspection.inspect("https://example.org")
    observations = result["publication_observations"]
    assert {"publication", "ledger", "readiness"} <= observations.keys()
    if result["populated_dossier_exercised"]:
        assert "dossier" in observations
        expected_age_status = "stale"
    else:
        expected_age_status = "future_observation"
    assert {value["local_age_policy"]["status"] for value in observations.values()} == {expected_age_status}
    assert len({value["observed_at"] for value in observations.values()}) == len(observations)


def _change_json(callback):
    def change(response):
        body = json.loads(response["body"])
        callback(body)
        response["body"] = json.dumps(body).encode()

    return change


def _response_observation(body):
    return body.get("publication", body)["publication_observation"]


@pytest.mark.parametrize("transport", [{"populated": True}], indirect=True)
@pytest.mark.parametrize("path", [
    "/publication", "/api/v1/claims", "/readyz",
    "/api/v1/seeds/sab_seed_public_snapshot/dossier",
])
@pytest.mark.parametrize("fault", ["schema", "currentness", "authority", "clock_authority", "pin"])
def test_observation_contract_rejects_invalid_claims_before_mutation(
    transport, response_changes, path, fault
):
    def alter(body):
        observation = _response_observation(body)
        if fault == "schema":
            observation["schema"] = "unexpected.v2"
        elif fault == "currentness":
            observation["currentness"]["status"] = "established"
        elif fault == "authority":
            observation["authority_effect"] = "authorized"
        elif fault == "clock_authority":
            observation["clock"]["externally_verified"] = True
        else:
            observation["manifest_sha256"] = "0" * 64

    response_changes[path] = _change_json(alter)
    with pytest.raises(RuntimeError):
        public_inspection.inspect("https://example.org")
    assert all(method == "GET" for method, _ in transport[1])


@pytest.mark.parametrize("name,value", [
    ("sab-publication-age-status", "within_limit"),
    ("sab-clock-state", "uncertain"),
    ("sab-currentness", "established"),
])
def test_observation_headers_must_match_the_same_response_body(
    transport, response_changes, name, value
):
    response_changes["/publication"] = lambda response: response["headers"].update({name: value})
    with pytest.raises(RuntimeError, match="headers disagree"):
        public_inspection.inspect("https://example.org")
    assert all(method == "GET" for method, _ in transport[1])


def test_readiness_never_claims_current_use_eligibility(transport, response_changes):
    response_changes["/readyz"] = _change_json(lambda body: body.update(current_use_eligible=True))
    with pytest.raises(RuntimeError, match="eligibility"):
        public_inspection.inspect("https://example.org")
    assert all(method == "GET" for method, _ in transport[1])


@pytest.mark.parametrize("transport", [{"populated": True}], indirect=True)
@pytest.mark.parametrize("path,field", [
    ("/publication", "observed_at"),
    ("/readyz", "timestamp"),
    ("/api/v1/seeds/sab_seed_public_snapshot/dossier", "observed_at"),
])
def test_source_and_read_timestamps_are_consistent_within_a_response(
    transport, response_changes, path, field
):
    response_changes[path] = _change_json(lambda body: body.update({field: "2000-01-01T00:00:00Z"}))
    with pytest.raises(RuntimeError, match="disagrees with its observation"):
        public_inspection.inspect("https://example.org")
    assert all(method == "GET" for method, _ in transport[1])


@pytest.mark.parametrize("value", [float("inf"), float("nan"), 10 ** 400, True, -1])
def test_invalid_observation_age_is_rejected_before_post(transport, response_changes, value):
    response_changes["/publication"] = _change_json(
        lambda body: _response_observation(body)["local_age_policy"].update(age_seconds=value)
    )
    with pytest.raises(RuntimeError):
        public_inspection.inspect("https://example.org")
    assert all(method == "GET" for method, _ in transport[1])


def test_discovered_observation_schema_identity_is_required(transport, response_changes):
    path = "/schemas/sab.public_read_observation.v1.schema.json"
    response_changes[path] = _change_json(
        lambda body: body["properties"]["schema"].update(const="unknown.v1")
    )
    with pytest.raises(RuntimeError, match="schema has the wrong identity"):
        public_inspection.inspect("https://example.org")
    assert all(method == "GET" for method, _ in transport[1])


@pytest.mark.parametrize("age", [3599.999999, 0, -5])
def test_client_age_admission_uses_one_unverified_sample_and_original_manifest(
    transport, monkeypatch, age
):
    samples = []

    def sample():
        samples.append(True)
        return SOURCE_TIME + timedelta(seconds=age)

    monkeypatch.setattr(public_inspection, "_utc_now", sample)
    pin = hashlib.sha256((transport[0] / "manifest.json").read_bytes()).hexdigest()
    result = public_inspection.inspect(
        "https://example.org", expected_manifest_sha256=pin, max_snapshot_age_seconds=3600
    )
    admission = result["client_age_admission"]
    assert len(samples) == 1
    assert admission["status"] == "within_limit"
    assert admission["age_seconds"] == max(0, age)
    assert admission["source_observed_at"] == SOURCE_TIME.isoformat()
    assert admission["clock"] == {"source": "client_local_system_utc", "externally_verified": False}
    assert admission["currentness"] == "unestablished"
    assert admission["authority_effect"] == "none"
    # The server's independent sample is stale; it is not the client's age authority.
    assert result["publication_observations"]["publication"]["local_age_policy"]["status"] == "stale"


@pytest.mark.parametrize("age,message", [
    (3600, "maximum snapshot age"),
    (3600.000001, "maximum snapshot age"),
    (-5.000001, "ahead of the client clock"),
])
def test_client_age_boundary_rejects_before_post(transport, monkeypatch, age, message):
    monkeypatch.setattr(public_inspection, "_utc_now", lambda: SOURCE_TIME + timedelta(seconds=age))
    pin = hashlib.sha256((transport[0] / "manifest.json").read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match=message):
        public_inspection.inspect(
            "https://example.org", expected_manifest_sha256=pin, max_snapshot_age_seconds=3600
        )
    assert all(method == "GET" for method, _ in transport[1])


@pytest.mark.parametrize("maximum", [0, -1, 86401, True, 1.0, "60", float("inf"), float("nan")])
def test_invalid_client_age_limit_fails_before_network(monkeypatch, maximum):
    monkeypatch.setattr(public_inspection, "build_opener", lambda *args: pytest.fail("network setup"))
    with pytest.raises(ValueError, match="integer from 1 through 86400"):
        public_inspection.inspect(
            "https://example.org", expected_manifest_sha256="a" * 64,
            max_snapshot_age_seconds=maximum,
        )


def test_client_age_limit_requires_independent_pin_before_network(monkeypatch):
    monkeypatch.setattr(public_inspection, "build_opener", lambda *args: pytest.fail("network setup"))
    with pytest.raises(ValueError, match="independently expected manifest pin"):
        public_inspection.inspect("https://example.org", max_snapshot_age_seconds=60)


def test_client_clock_must_be_aware_before_network(monkeypatch):
    monkeypatch.setattr(public_inspection, "_utc_now", lambda: datetime(2026, 9, 9))
    monkeypatch.setattr(public_inspection, "build_opener", lambda *args: pytest.fail("network setup"))
    with pytest.raises(ValueError, match="aware local UTC"):
        public_inspection.inspect(
            "https://example.org", expected_manifest_sha256="a" * 64, max_snapshot_age_seconds=60
        )


def test_cli_passes_optional_independent_age_policy(monkeypatch, capsys):
    calls = []

    def inspect(origin, **kwargs):
        calls.append((origin, kwargs))
        return {"authorizes_use": False}

    monkeypatch.setattr(public_inspection, "inspect", inspect)
    monkeypatch.setattr(sys, "argv", [
        "agora-public-inspect", "https://example.org",
        "--expected-manifest-sha256", "a" * 64, "--max-snapshot-age-seconds", "60",
    ])
    public_inspection.main()
    assert calls == [("https://example.org", {
        "expected_manifest_sha256": "a" * 64, "max_snapshot_age_seconds": 60,
    })]
    assert json.loads(capsys.readouterr().out) == {"authorizes_use": False}


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
