from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.render_caddy_sab_openapi_cutover import CutoverError, render_cutover

SITE = "sab.example"
SOURCE = """sab.example {
    handle /api/v1/* {
        reverse_proxy localhost:8100
    }

    handle /docs {
        reverse_proxy localhost:8100
    }
    handle /openapi.json {
        reverse_proxy localhost:8100
    }

    handle {
        reverse_proxy localhost:8000 {
            header_up X-Real-IP {remote_host}
        }
    }
}

other.example {
    reverse_proxy localhost:9000
}
"""


def test_render_moves_only_docs_and_openapi_to_canonical_sab() -> None:
    candidate, receipt = render_cutover(
        SOURCE,
        site=SITE,
        sab_upstream="localhost:8000",
        displaced_upstream="localhost:8100",
    )

    assert candidate.count("reverse_proxy localhost:8000") == 3
    assert "handle /api/v1/* {\n        reverse_proxy localhost:8100" in candidate
    assert "other.example {\n    reverse_proxy localhost:9000" in candidate
    assert receipt["changed_routes"] == ["/docs", "/openapi.json"]
    assert receipt["replacement_count"] == 2
    assert receipt["source_sha256"] != receipt["candidate_sha256"]


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (SOURCE.replace("sab.example {", "wrong.example {", 1), "site block"),
        (SOURCE.replace("handle /docs {", "handle /documentation {", 1), "/docs"),
        (
            SOURCE.replace(
                "handle /openapi.json {\n        reverse_proxy localhost:8100",
                "handle /openapi.json {\n        reverse_proxy localhost:8200",
            ),
            "unexpected upstream",
        ),
        (
            SOURCE.replace(
                "    handle {\n        reverse_proxy localhost:8000 {",
                "    handle {\n        reverse_proxy localhost:8200 {",
            ),
            "catch-all",
        ),
        (
            SOURCE.replace(
                "    handle /docs {\n        reverse_proxy localhost:8100\n    }",
                "    handle /docs {\n        reverse_proxy localhost:8100\n    }\n"
                "    handle /docs {\n        reverse_proxy localhost:8100\n    }",
            ),
            "exactly one",
        ),
    ],
)
def test_render_fails_closed_on_ambiguous_or_drifted_config(
    source: str,
    message: str,
) -> None:
    with pytest.raises(CutoverError, match=message):
        render_cutover(
            source,
            site=SITE,
            sab_upstream="localhost:8000",
            displaced_upstream="localhost:8100",
        )


def test_cli_writes_hash_bound_candidate_and_receipt(tmp_path: Path) -> None:
    source_path = tmp_path / "Caddyfile"
    output_path = tmp_path / "Caddyfile.candidate"
    receipt_path = tmp_path / "receipt.json"
    source_path.write_text(SOURCE)

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "render_caddy_sab_openapi_cutover.py"),
            str(source_path),
            "--site",
            SITE,
            "--sab-upstream",
            "localhost:8000",
            "--displaced-upstream",
            "localhost:8100",
            "--output",
            str(output_path),
            "--receipt",
            str(receipt_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    receipt = json.loads(receipt_path.read_text())
    stdout_receipt = json.loads(result.stdout)
    assert receipt == stdout_receipt
    assert receipt["schema_version"] == "sab.caddy_openapi_cutover.v1"
    assert receipt["candidate_sha256"]
    assert receipt["applied"] is False
    assert output_path.read_text().count("reverse_proxy localhost:8000") == 3
    assert output_path.stat().st_mode & 0o777 == 0o600
    assert receipt_path.stat().st_mode & 0o777 == 0o600


def test_cli_does_not_write_candidate_when_precondition_fails(tmp_path: Path) -> None:
    source_path = tmp_path / "Caddyfile"
    output_path = tmp_path / "candidate"
    receipt_path = tmp_path / "receipt.json"
    source_path.write_text(
        SOURCE.replace(
            "handle /docs {\n        reverse_proxy localhost:8100",
            "handle /docs {\n        reverse_proxy localhost:8101",
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "render_caddy_sab_openapi_cutover.py"),
            str(source_path),
            "--site",
            SITE,
            "--sab-upstream",
            "localhost:8000",
            "--displaced-upstream",
            "localhost:8100",
            "--output",
            str(output_path),
            "--receipt",
            str(receipt_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "unexpected upstream" in result.stderr
    assert not output_path.exists()
    assert not receipt_path.exists()


def test_cli_refuses_to_replace_its_source_or_alias_outputs(tmp_path: Path) -> None:
    source_path = tmp_path / "Caddyfile"
    receipt_path = tmp_path / "receipt.json"
    source_path.write_text(SOURCE)

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "render_caddy_sab_openapi_cutover.py"),
            str(source_path),
            "--site",
            SITE,
            "--sab-upstream",
            "localhost:8000",
            "--displaced-upstream",
            "localhost:8100",
            "--output",
            str(source_path),
            "--receipt",
            str(receipt_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "paths must be distinct" in result.stderr
    assert source_path.read_text() == SOURCE
    assert not receipt_path.exists()


@pytest.mark.parametrize("existing_artifact", ["candidate", "receipt"])
def test_cli_refuses_to_overwrite_exact_receipt_artifacts(
    tmp_path: Path,
    existing_artifact: str,
) -> None:
    source_path = tmp_path / "Caddyfile"
    output_path = tmp_path / "candidate"
    receipt_path = tmp_path / "receipt.json"
    source_path.write_text(SOURCE)
    selected_path = output_path if existing_artifact == "candidate" else receipt_path
    selected_path.write_text("preserve-me")

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "render_caddy_sab_openapi_cutover.py"),
            str(source_path),
            "--site",
            SITE,
            "--sab-upstream",
            "localhost:8000",
            "--displaced-upstream",
            "localhost:8100",
            "--output",
            str(output_path),
            "--receipt",
            str(receipt_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "refusing to overwrite existing artifact" in result.stderr
    assert selected_path.read_text() == "preserve-me"
    other_path = receipt_path if existing_artifact == "candidate" else output_path
    assert not other_path.exists()
