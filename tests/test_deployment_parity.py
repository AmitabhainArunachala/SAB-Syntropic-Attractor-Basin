from __future__ import annotations

import os
import subprocess
import sys
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.check_deployment_parity import MAX_JSON_BYTES, _fetch_json, assess_deployment


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


@pytest.mark.parametrize("invalid_operation", [None, "not-an-operation", [], True])
def test_assessment_rejects_non_mapping_required_operation(invalid_operation: object) -> None:
    openapi = _canonical_openapi()
    openapi["paths"]["/auth/register"]["post"] = invalid_operation

    result = assess_deployment(
        status_payload={
            "status": "healthy",
            "version": "0.3.1",
            "build_sha": "a" * 40,
        },
        openapi_payload=openapi,
        expected_build_sha="a" * 40,
    )

    assert result["healthy"] is False
    assert "POST /auth/register" in result["missing_operations"]


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


def test_assessment_rejects_nonidentical_openapi_digest() -> None:
    canonical = _canonical_openapi()
    baseline = assess_deployment(
        status_payload={
            "status": "healthy",
            "version": "0.3.1",
            "build_sha": "a" * 40,
        },
        openapi_payload=canonical,
        expected_build_sha="a" * 40,
    )

    modified = _canonical_openapi()
    modified["paths"]["/unexpected"] = {"get": {}}
    result = assess_deployment(
        status_payload={
            "status": "healthy",
            "version": "0.3.1",
            "build_sha": "a" * 40,
        },
        openapi_payload=modified,
        expected_build_sha="a" * 40,
        expected_openapi_sha256=baseline["openapi_sha256"],
    )

    assert result["healthy"] is False
    assert any("OpenAPI SHA-256" in problem for problem in result["problems"])


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


def test_deploy_requires_clean_exact_remote_commit_before_build() -> None:
    deploy_helper = (ROOT / "scripts" / "deploy_agni_docker.sh").read_text()

    clean_check = deploy_helper.index("git status --porcelain")
    exact_remote_check = deploy_helper.index('origin/${TARGET_BRANCH}')
    archive_build_context = deploy_helper.index("git archive")
    build = deploy_helper.index("docker build")
    assert clean_check < build
    assert exact_remote_check < build
    assert archive_build_context < build


def test_deployment_probe_rejects_redirect_without_contacting_target() -> None:
    target_hits = 0

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            nonlocal target_hits
            target_hits += 1
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{target.server_port}/foreign",
            )
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    source_thread = threading.Thread(target=source.serve_forever, daemon=True)
    source_thread.start()
    try:
        with pytest.raises(urllib.error.HTTPError):
            _fetch_json(f"http://127.0.0.1:{source.server_port}", "/status", 2.0)
        assert target_hits == 0
    finally:
        source.shutdown()
        target.shutdown()
        source.server_close()
        target.server_close()
        source_thread.join(timeout=2)
        target_thread.join(timeout=2)


def test_deployment_probe_rejects_non_json_content_type() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            body = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(RuntimeError, match="JSON Content-Type"):
            _fetch_json(f"http://127.0.0.1:{server.server_port}", "/status", 2.0)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_deployment_probe_rejects_announced_oversized_body_before_reading() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(MAX_JSON_BYTES + 1))
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(RuntimeError, match="JSON size limit"):
            _fetch_json(f"http://127.0.0.1:{server.server_port}", "/openapi.json", 2.0)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_agni_deploy_requires_public_origin_before_ssh(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ssh_marker = tmp_path / "ssh-called"
    fake_ssh = fake_bin / "ssh"
    fake_ssh.write_text(
        "#!/bin/sh\n"
        f"touch {ssh_marker}\n"
        "exit 0\n"
    )
    fake_ssh.chmod(0o755)

    env = os.environ.copy()
    env.pop("AGNI_PUBLIC_BASE_URL", None)
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "deploy_agni_docker.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert "AGNI_PUBLIC_BASE_URL is required" in result.stderr
    assert not ssh_marker.exists(), "deployment must fail before any remote mutation"


def test_agni_deploy_rejects_no_build_mode_before_ssh(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ssh_marker = tmp_path / "ssh-called"
    fake_ssh = fake_bin / "ssh"
    fake_ssh.write_text(
        "#!/bin/sh\n"
        f"touch {ssh_marker}\n"
        "exit 0\n"
    )
    fake_ssh.chmod(0o755)
    fake_git = fake_bin / "git"
    fake_git.write_text("#!/bin/sh\nexit 0\n")
    fake_git.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "AGNI_PUBLIC_BASE_URL": "https://agora.example",
            "PATH": f"{fake_bin}:{env['PATH']}",
        }
    )
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "deploy_agni_docker.sh"), "--no-build"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert "--no-build is disabled" in result.stderr
    assert not ssh_marker.exists(), "unverified images must fail before ssh"


@pytest.mark.parametrize(
    "public_url",
    [
        "--help",
        "http://agora.example",
        "https://agora.example/path",
        "https://agora.example?probe=false",
        "https://user:password@agora.example",
        "https://agora.example; true",
        "https://agora.example:99999",
        "https://.",
        "https://-",
        "https://999.245.1.1",
    ],
)
def test_agni_deploy_rejects_unsafe_public_origin_before_ssh(
    tmp_path: Path,
    public_url: str,
) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ssh_marker = tmp_path / "ssh-called"
    fake_ssh = fake_bin / "ssh"
    fake_ssh.write_text(
        "#!/bin/sh\n"
        f"touch {ssh_marker}\n"
        "exit 0\n"
    )
    fake_ssh.chmod(0o755)

    env = os.environ.copy()
    env["AGNI_PUBLIC_BASE_URL"] = public_url
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "deploy_agni_docker.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert "AGNI_PUBLIC_BASE_URL must be a root HTTPS origin" in result.stderr
    assert not ssh_marker.exists(), "invalid public origins must fail before SSH"


def test_agni_deploy_rejects_option_like_ssh_target(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    ssh_marker = tmp_path / "ssh-called"
    fake_ssh = fake_bin / "ssh"
    fake_ssh.write_text(
        "#!/bin/sh\n"
        f"touch {ssh_marker}\n"
        "exit 0\n"
    )
    fake_ssh.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "AGNI_PUBLIC_BASE_URL": "https://agora.example",
            "AGNI_SSH_TARGET": "-V",
            "PATH": f"{fake_bin}:{env['PATH']}",
        }
    )
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "deploy_agni_docker.sh")],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 2
    assert "AGNI_SSH_TARGET must not be empty or option-like" in result.stderr
    assert not ssh_marker.exists(), "option-like SSH targets must fail before ssh"


def test_agni_deploy_propagates_external_public_parity_failure(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    parity_calls = tmp_path / "parity-calls"
    git_calls = tmp_path / "git-calls"
    docker_calls = tmp_path / "docker-calls"
    docker_ps_marker = tmp_path / "docker-ps-called"
    build_sha = "a" * 40
    openapi_sha = "b" * 64
    image_id = "sha256:" + "c" * 64
    container_name = f"sab-parity-{os.getpid()}"
    cid_path = Path("/tmp") / f"{container_name}.cid"

    def write_executable(name: str, body: str) -> None:
        path = fake_bin / name
        path.write_text(f"#!/bin/sh\n{body}")
        path.chmod(0o755)

    # OpenSSH reconstructs a remote command string from argv; emulate that
    # extra shell parse so metacharacter injection is exercised here.
    write_executable(
        "ssh",
        'if [ "$1" = "--" ]; then shift; fi\n'
        'shift\n'
        'exec /bin/bash -c "$*"\n',
    )
    write_executable(
        "git",
        f'printf "%s\\n" "$*" >> {git_calls}\n'
        'case "$*" in\n'
        f'  ls-remote*) printf "{build_sha}\\trefs/heads/test\\n" ;;\n'
        '  "rev-parse --abbrev-ref HEAD") printf "main\\n" ;;\n'
        f'  "rev-parse HEAD") printf "{build_sha}\\n" ;;\n'
        f'  rev-parse\\ origin/*) printf "{build_sha}\\n" ;;\n'
        "esac\n"
        "exit 0\n",
    )
    write_executable(
        "docker",
        f'printf "%s\\n" "$*" >> {docker_calls}\n'
        'if [ "$1" = "image" ] && [ "$2" = "inspect" ]; then\n'
        '  case "$*" in\n'
        f'    *.Id*) printf "{image_id}\\n" ;;\n'
        f'    *) printf "{build_sha}\\n" ;;\n'
        "  esac\n"
        'elif [ "$1" = "ps" ]; then\n'
        f"  touch {docker_ps_marker}\n"
        "fi\n"
        "exit 0\n",
    )
    write_executable("curl", 'printf "200"\n')
    write_executable("chown", "exit 0\n")
    write_executable("tar", "cat >/dev/null\nexit 0\n")
    write_executable(
        "python3",
        f'printf "%s|%s\\n" "${{SAB_PARITY_VANTAGE:-unset}}" "$*" >> {parity_calls}\n'
        'case "$*" in\n'
        f'  *--openapi-sha256-only*) printf "{openapi_sha}\\n" ;;\n'
        "esac\n"
        'if [ "${SAB_PARITY_VANTAGE:-}" = "external" ] && '
        '[ "$2" = "https://agora.example" ]; then\n'
        "  exit 17\n"
        "fi\n"
        "exit 0\n",
    )

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:{env['PATH']}",
            "AGNI_PUBLIC_BASE_URL": "https://agora.example/",
            "AGNI_BRANCH": "main; exit 0 #",
            "AGNI_REPO_PATH": str(ROOT),
            "AGNI_DATA_DIR": str(tmp_path / "data"),
            "AGNI_LOG_DIR": str(tmp_path / "logs"),
            "AGNI_CONTAINER_NAME": container_name,
            "AGNI_TIMEOUT_SECONDS": "1",
            "AGNI_RESTORE_BRANCH": "0",
        }
    )
    try:
        result = subprocess.run(
            ["bash", str(ROOT / "scripts" / "deploy_agni_docker.sh")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    finally:
        cid_path.unlink(missing_ok=True)

    assert result.returncode == 17
    calls = parity_calls.read_text().splitlines()
    assert len(calls) == 3
    assert "http://127.0.0.1:8800" in calls[0]
    assert "--openapi-sha256-only" in calls[0]
    assert calls[1].startswith("agni|")
    assert "https://agora.example" in calls[1]
    assert f"--expected-openapi-sha256 {openapi_sha}" in calls[1]
    assert calls[2].startswith("external|")
    assert "https://agora.example" in calls[2]
    assert f"--expected-openapi-sha256 {openapi_sha}" in calls[2]
    assert "status --porcelain" in git_calls.read_text()
    docker_log = docker_calls.read_text()
    assert ".Id" in docker_log
    assert f"run -d --name {container_name}" in docker_log
    assert image_id in docker_log
    assert docker_ps_marker.exists(), "external probe must run after remote completion"
