from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_deployment_parity import assess_deployment


EXPECTED_TITLE = "SAB DHARMIC_AGORA API"
REQUIRED_OPERATIONS = {
    "/auth/register": {"post"},
    "/posts": {"get", "post"},
    "/admin/queue": {"get"},
    "/witness": {"get"},
    "/posts/{post_id}/comment": {"post"},
    "/comments/{comment_id}/accept-correction": {"post"},
    "/admin/appeal/{queue_id}": {"post"},
}


def _canonical_openapi() -> dict:
    return {
        "info": {"title": EXPECTED_TITLE, "version": "0.3.1"},
        "paths": {
            path: {method: {} for method in methods}
            for path, methods in REQUIRED_OPERATIONS.items()
        },
    }


def test_assessment_accepts_canonical_openapi_and_exact_build() -> None:
    result = assess_deployment(
        status_payload={
            "status": "healthy",
            "version": "0.3.1",
            "build_sha": "a" * 40,
        },
        openapi_payload=_canonical_openapi(),
        expected_build_sha="a" * 40,
    )

    assert result["healthy"] is True
    assert result["problems"] == []


def test_assessment_rejects_foreign_openapi_and_missing_build_binding() -> None:
    result = assess_deployment(
        status_payload={"status": "healthy", "version": "0.3.1"},
        openapi_payload={
            "info": {"title": "Ginko Signal API", "version": "1.0.0"},
            "paths": {"/api/v1/health": {"get": {}}},
        },
        expected_build_sha="b" * 40,
    )

    assert result["healthy"] is False
    assert any("OpenAPI title" in problem for problem in result["problems"])
    assert any("build SHA" in problem for problem in result["problems"])
    assert any("/auth/register" in problem for problem in result["problems"])
    assert any("accept-correction" in problem for problem in result["problems"])


def test_every_production_launch_surface_uses_canonical_server() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text()
    compose = (ROOT / "docker-compose.yml").read_text()
    systemd = (ROOT / "deploy" / "sab-agora.service").read_text()
    deploy_helper = (ROOT / "scripts" / "deploy_agni_docker.sh").read_text()
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()

    assert 'CMD ["uvicorn", "agora.api_server:app"' in dockerfile
    assert "127.0.0.1:8000/health" in dockerfile
    assert "localhost:8000/health" in compose
    assert "agora.api_server:app" in systemd
    assert 'AGNI_HEALTH_PATH="${AGNI_HEALTH_PATH:-/health}"' in deploy_helper
    assert "check_deployment_parity.py" in deploy_helper
    assert "check_deployment_parity.py" in ci
