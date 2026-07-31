from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from connectors import sabp_cli
from connectors.sabp_cli import _read_json, _read_json_events


def test_read_json_inline_and_path(tmp_path: Path) -> None:
    inline = _read_json('{"a": 1, "b": "x"}')
    assert inline == {"a": 1, "b": "x"}

    payload_path = tmp_path / "payload.json"
    payload_path.write_text(json.dumps({"event_id": "evt-1"}))
    from_path = _read_json(str(payload_path))
    assert from_path == {"event_id": "evt-1"}


def test_read_json_events_array_and_jsonl(tmp_path: Path) -> None:
    events = _read_json_events('[{"event_id":"a"},{"event_id":"b"}]')
    assert [e["event_id"] for e in events] == ["a", "b"]

    jsonl_path = tmp_path / "payloads.jsonl"
    jsonl_path.write_text('{"event_id":"x"}\n{"event_id":"y"}\n')
    from_file = _read_json_events(str(jsonl_path))
    assert [e["event_id"] for e in from_file] == ["x", "y"]


def test_read_json_events_rejects_non_objects() -> None:
    with pytest.raises(ValueError):
        _read_json_events("[1,2,3]")


def test_cli_ingest_dgc_batch_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class DummyClient:
        def __init__(self, *_args, **_kwargs):
            self.events = []

        def ingest_dgc_signal(self, payload, dgc_shared_secret):
            assert dgc_shared_secret == "secret-123"
            self.events.append(payload)
            return {"event_id": payload.get("event_id")}

        def close(self):
            return None

    payloads_path = tmp_path / "payloads.jsonl"
    payloads_path.write_text(
        '{"event_id":"evt-1","timestamp":"2026-02-16T00:00:00Z","gate_scores":{"satya":0.9}}\n'
        '{"event_id":"evt-2","timestamp":"2026-02-16T00:01:00Z","gate_scores":{"satya":0.8}}\n'
    )
    monkeypatch.setattr(sabp_cli, "SabpClient", DummyClient)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "ingest-dgc-batch",
            "--payloads",
            str(payloads_path),
            "--dgc-secret",
            "secret-123",
        ],
    )

    sabp_cli.main()
    out = capsys.readouterr().out
    assert '"status": "ok"' in out
    assert '"ok": 2' in out
    assert '"failed": 0' in out


def test_cli_default_output_is_json(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class DummyClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def issue_token(self, name, telos=""):
            return {"token": "sab_t_abc", "address": "agent_1", "name": name, "telos": telos}

        def close(self):
            return None

    monkeypatch.setattr(sabp_cli, "SabpClient", DummyClient)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "token",
            "--name",
            "agent-x",
            "--telos",
            "eval",
        ],
    )

    sabp_cli.main()
    out = capsys.readouterr().out.strip()
    parsed = json.loads(out)
    assert parsed["token"] == "sab_t_abc"
    assert parsed["name"] == "agent-x"


def test_cli_register_uses_explicit_onboarding_route_and_emits_once_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, str]] = []

    class DummyClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def register(self, name, telos=""):
            calls.append((name, telos))
            return {
                "address": "t_registered",
                "token": "sab_t_return_once",
                "message": "Welcome to SAB",
            }

        def close(self):
            return None

    monkeypatch.setattr(sabp_cli, "SabpClient", DummyClient)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "https://sab.example",
            "register",
            "--name",
            "agent-opted-in",
            "--telos",
            "correction research",
        ],
    )

    sabp_cli.main()

    assert calls == [("agent-opted-in", "correction research")]
    parsed = json.loads(capsys.readouterr().out.strip())
    assert parsed == {
        "address": "t_registered",
        "message": "Welcome to SAB",
        "token": "sab_t_return_once",
    }


def test_cli_text_output_mode(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class DummyClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def issue_token(self, name, telos=""):
            return {"token": "sab_t_textmode", "address": "agent_1"}

        def close(self):
            return None

    monkeypatch.setattr(sabp_cli, "SabpClient", DummyClient)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "--format",
            "text",
            "token",
            "--name",
            "agent-x",
        ],
    )
    sabp_cli.main()
    out = capsys.readouterr().out.strip()
    assert out == "sab_t_textmode"


def test_cli_ingest_dgc_batch_requires_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payloads_path = tmp_path / "payloads.jsonl"
    payloads_path.write_text('{"event_id":"evt-1","timestamp":"2026-02-16T00:00:00Z","gate_scores":{"satya":0.9}}\n')

    monkeypatch.delenv("SAB_DGC_SHARED_SECRET", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "ingest-dgc-batch",
            "--payloads",
            str(payloads_path),
        ],
    )
    with pytest.raises(SystemExit) as exc:
        sabp_cli.main()
    assert exc.value.code == 2
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "error"
    assert "missing --dgc-secret" in payload["error"]


def test_cli_emits_json_error_on_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class DummyClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def trust_history(self, address, limit=50):
            raise RuntimeError(f"boom:{address}:{limit}")

        def close(self):
            return None

    monkeypatch.setattr(sabp_cli, "SabpClient", DummyClient)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "trust",
            "--address",
            "agent-z",
            "--limit",
            "7",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        sabp_cli.main()
    assert exc.value.code == 1
    payload = json.loads(capsys.readouterr().out.strip())
    assert payload["status"] == "error"
    assert payload["exit_code"] == 1
    assert payload["error"] == "boom:agent-z:7"


def test_cli_admin_anti_gaming_commands(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class DummyClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def admin_anti_gaming_scan(self, limit=500):
            return {"summary": {"suspicious_count": 2, "limit": limit}}

        def admin_convergence_clawback(self, event_id, reason, penalty=0.15):
            return {"status": "clawback_applied", "event_id": event_id, "penalty": penalty, "reason": reason}

        def admin_convergence_override(self, event_id, reason, trust_adjustment=0.0):
            return {
                "status": "trust_override_applied",
                "event_id": event_id,
                "trust_adjustment": trust_adjustment,
                "reason": reason,
            }

        def close(self):
            return None

    monkeypatch.setattr(sabp_cli, "SabpClient", DummyClient)

    monkeypatch.setattr(
        sys,
        "argv",
        ["sabp_cli.py", "--url", "http://example", "anti-scan", "--limit", "321"],
    )
    sabp_cli.main()
    scan_out = json.loads(capsys.readouterr().out.strip())
    assert scan_out["summary"]["suspicious_count"] == 2

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "clawback",
            "--event-id",
            "evt-1",
            "--reason",
            "manual",
            "--penalty",
            "0.2",
        ],
    )
    sabp_cli.main()
    claw_out = json.loads(capsys.readouterr().out.strip())
    assert claw_out["status"] == "clawback_applied"
    assert claw_out["event_id"] == "evt-1"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "override",
            "--event-id",
            "evt-1",
            "--reason",
            "override",
            "--trust-adjustment",
            "0.0",
        ],
    )
    sabp_cli.main()
    override_out = json.loads(capsys.readouterr().out.strip())
    assert override_out["status"] == "trust_override_applied"
    assert override_out["trust_adjustment"] == 0.0


def test_cli_outcome_and_darwin_commands(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class DummyClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def admin_record_outcome(self, event_id, outcome_type, status, evidence):
            return {
                "outcome": {
                    "event_id": event_id,
                    "outcome_type": outcome_type,
                    "status": status,
                    "evidence": evidence,
                }
            }

        def admin_list_outcomes(self, event_id):
            return {"event_id": event_id, "outcomes": [{"status": "pass"}]}

        def admin_darwin_status(self):
            return {"policy": {"version": 2}, "latest_run": {"run_id": "abc"}}

        def admin_darwin_run(self, dry_run=True, reason="darwin_cycle", run_validation=False):
            return {
                "run_id": "run-1",
                "dry_run": dry_run,
                "reason": reason,
                "run_validation": run_validation,
            }

        def close(self):
            return None

    monkeypatch.setattr(sabp_cli, "SabpClient", DummyClient)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "outcome",
            "--event-id",
            "evt-1",
            "--type",
            "tests",
            "--status",
            "pass",
            "--evidence",
            '{"suite":"core"}',
        ],
    )
    sabp_cli.main()
    out = json.loads(capsys.readouterr().out.strip())
    assert out["outcome"]["event_id"] == "evt-1"

    monkeypatch.setattr(
        sys,
        "argv",
        ["sabp_cli.py", "--url", "http://example", "outcomes", "--event-id", "evt-1"],
    )
    sabp_cli.main()
    outcomes = json.loads(capsys.readouterr().out.strip())
    assert outcomes["event_id"] == "evt-1"

    monkeypatch.setattr(
        sys,
        "argv",
        ["sabp_cli.py", "--url", "http://example", "darwin-status"],
    )
    sabp_cli.main()
    status = json.loads(capsys.readouterr().out.strip())
    assert status["policy"]["version"] == 2

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "sabp_cli.py",
            "--url",
            "http://example",
            "darwin-run",
            "--reason",
            "test cycle",
            "--apply",
        ],
    )
    sabp_cli.main()
    run = json.loads(capsys.readouterr().out.strip())
    assert run["dry_run"] is False
