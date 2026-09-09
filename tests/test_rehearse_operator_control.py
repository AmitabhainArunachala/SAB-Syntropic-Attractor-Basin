"""Delivery-boundary regressions using real disposable child processes.

These tests exercise orchestration output and cleanup only. Runtime markers
are synthetic test input, not evidence that a test child imported the app.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import secrets
import sys
import time

import pytest


SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "rehearse_operator_control.py"
SPEC = importlib.util.spec_from_file_location("operator_rehearsal_under_test", SOURCE)
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)
MARKERS = ("SIGNED_BODY_SENTINEL", "Authorization: Bearer HEADER_SENTINEL",
           "https://synthetic.invalid/URL_SENTINEL", "REMOTE_ERROR_SENTINEL")
CHILD = '''
import json, os, signal, sys, time
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_bytes())
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(config["ready"]).touch()
runtime = config["runtime"]
runtime["pid"] = os.getpid() + (1 if config["marker"] == "wrong_pid" else 0)
if config["marker"] != "missing":
    body = b"{invalid" if config["marker"] == "malformed" else json.dumps(runtime).encode()
    os.write(1, b"SAB_KEY_CONTROL_RUNTIME " + body + b"\\n")
    if config["marker"] == "duplicate":
        os.write(1, b"SAB_KEY_CONTROL_RUNTIME " + body + b"\\n")
noise = config["noise"].encode()
os.write(1, noise + b"\\n")
os.write(2, noise + b"\\n")
if config["wait"]:
    time.sleep(60)
sys.exit(config["exit_code"])
'''


@pytest.fixture
def run(tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    internal = {"status": "running", "processes": [], "observations": [], "denials": []}
    run = HARNESS.Rehearsal(output, Path(sys.executable), Path(sys.executable), Path(sys.executable), internal)
    run.synthetic_seed = secrets.token_bytes(32)
    HARNESS.write_private(run.participant / "synthetic.key", run.synthetic_seed.hex().encode())
    run.remember_participant_files()
    monkeypatch.setattr(HARNESS, "STOP_TIMEOUT", 0.1)
    monkeypatch.setattr(HARNESS, "KILL_TIMEOUT", 1)
    yield run
    # A broken implementation under test must not leave the tests' own children.
    for process, _ in run.children:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def child_configuration(run, label, *, marker="valid", exit_code=0, wait=False, leak_seed=False):
    runtime = {"pid": 0, "module": str(run.application_path), "mode": "local", "key_control_available": True,
               "system_key_loaded": True, "authority_service_available": True, "authority_policy_loaded": True}
    if marker == "wrong_module":
        runtime["module"] = MARKERS[2]
    elif marker == "extra":
        runtime["request_body"] = MARKERS[0]
    elif marker == "wrong_boolean":
        runtime["key_control_available"] = "true"
    ready = run.output.parent / (label + "-ready")
    noise = "\n".join(MARKERS) + ("\n" + run.synthetic_seed.hex() if leak_seed else "")
    config = run.participant / (label + ".json")
    HARNESS.write_private(config, HARNESS.encoded({"runtime": runtime, "marker": marker, "exit_code": exit_code,
                                                 "wait": wait, "noise": noise, "ready": str(ready)}))
    run.remember_participant_files()
    return config, ready


def spawn_server(run, label, **kwargs):
    config, ready = child_configuration(run, label, **kwargs)
    child = run.spawn(label, [sys.executable, "-I", "-B", "-c", CHILD, str(config)],
                      run.server, HARNESS.HARNESS["ENV"])
    child[1]["mode"] = "local"
    deadline = time.monotonic() + 3
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready.exists(), "test child failed to signal readiness"
    return child


def execute(run):
    return HARNESS.run_rehearsal(run, {"wheel_sha256": "1" * 64, "record_sha256": "2" * 64})


def assert_retained_boundary(run, receipt):
    assert receipt["wheel_sha256_basis"] == "caller_supplied_artifact_digest"
    assert receipt["authority_effect"] == receipt["standing_effect"] == "none"
    files = [*run.output.glob("*.log"), run.output / "receipt.json"]
    forbidden = [value.encode() for value in MARKERS] + [run.synthetic_seed, run.synthetic_seed.hex().encode()]
    if any(value in path.read_bytes() for path in files for value in forbidden):
        pytest.fail("retained output contained synthetic probe material", pytrace=False)
    logs = list(run.output.glob("*.log"))
    assert len(logs) == 2 * len(run.children)
    for path in logs:
        record = json.loads(path.read_bytes())
        assert set(record) == {"bytes", "sha256", "exit_code"}
        assert type(record["bytes"]) is int and record["bytes"] >= 0
        assert len(record["sha256"]) == 64
        assert record["exit_code"] is None or type(record["exit_code"]) is int
    assert all(process.poll() is not None for process, _ in run.children)


@pytest.mark.parametrize("exit_code,expected,status", [(0, 0, "passed"), (7, 7, "passed"), (7, 0, "failed")])
def test_success_and_failure_server_outputs_are_always_digest_only(run, exit_code, expected, status):
    def exercise():
        child = spawn_server(run, "server", exit_code=exit_code)
        run.finish(child, expected=expected)
    run.exercise = exercise
    receipt = execute(run)
    assert receipt["status"] == status
    assert run.children[0][1].get("runtime_identity_sha256")
    assert_retained_boundary(run, receipt)


@pytest.mark.parametrize("marker", ["missing", "malformed", "duplicate", "wrong_pid", "wrong_module", "extra", "wrong_boolean"])
def test_missing_or_malformed_runtime_identity_fails_without_raw_persistence(run, marker):
    run.exercise = lambda: run.finish(spawn_server(run, "bad-marker", marker=marker))
    receipt = execute(run)
    assert receipt["status"] == "failed"
    assert receipt["failed_check"] == "runtime_identity_invalid"
    assert "runtime_identity_sha256" not in run.children[0][1]
    assert_retained_boundary(run, receipt)


def test_printed_synthetic_key_is_not_retained_even_when_scan_refuses_child(run):
    run.exercise = lambda: run.finish(spawn_server(run, "key-output", leak_seed=True))
    receipt = execute(run)
    assert receipt["status"] == "failed"
    assert receipt["failed_check"] == "participant_secret_detected"
    assert_retained_boundary(run, receipt)


def test_real_server_stop_timeout_kills_reaps_and_keeps_only_metadata(run):
    run.exercise = lambda: run.finish(spawn_server(run, "stop-timeout", wait=True))
    receipt = execute(run)
    assert receipt["status"] == "failed"
    assert receipt["failed_check"] == "child_stop_timeout"
    assert receipt["counts"]["forced_kills"] == 1
    assert receipt["counts"]["stopped_processes"] == 1
    assert_retained_boundary(run, receipt)


def test_real_cli_timeout_is_sanitized_and_reaped(run, monkeypatch):
    config, _ = child_configuration(run, "cli-timeout", marker="missing", wait=True)
    entry = run.participant / "cli.py"
    HARNESS.write_private(entry, CHILD.encode())
    run.remember_participant_files()
    run.entry = entry
    monkeypatch.setattr(HARNESS, "CLI_TIMEOUT", 0.5)
    run.exercise = lambda: run.cli("cli-timeout", config)
    receipt = execute(run)
    assert receipt["status"] == "failed"
    assert receipt["failed_check"] == "cli_time_budget_exceeded"
    assert receipt["counts"]["forced_kills"] == 1
    assert_retained_boundary(run, receipt)


def test_failed_pipe_collection_cannot_skip_remaining_children_or_leak_error(run, monkeypatch):
    arbitrary_error = type("REMOTE_ERROR_SENTINEL", (Exception,), {})

    def exercise():
        spawn_server(run, "remaining-child", wait=True)
        broken = spawn_server(run, "broken-collection", wait=True)

        def broken_communicate(*args, **kwargs):
            raise arbitrary_error("\n".join(MARKERS))
        monkeypatch.setattr(broken[0], "communicate", broken_communicate)
        raise arbitrary_error("\n".join(MARKERS))

    run.exercise = exercise
    receipt = execute(run)
    assert receipt["status"] == "failed"
    assert receipt["error_type"] == "unexpected_error"
    assert receipt["counts"]["cleanup_failures"] == 2
    assert receipt["counts"]["stopped_processes"] == 2
    assert receipt["counts"]["incomplete_process_outputs"] == 1
    assert receipt["counts"]["unreaped_children"] == 0
    assert_retained_boundary(run, receipt)


@pytest.mark.parametrize("value", ["remote_error_sentinel", {"url": MARKERS[2]}])
def test_arbitrary_runtime_error_arguments_are_not_receipt_codes(run, value):
    def exercise():
        raise RuntimeError(value)
    run.exercise = exercise
    receipt = execute(run)
    assert receipt["status"] == "failed"
    assert receipt["error_type"] == "rehearsal_error"
    assert "failed_check" not in receipt
    assert_retained_boundary(run, receipt)
