#!/usr/bin/env python3
"""Rehearse installed key-control CLI and HTTP processes with synthetic keys.

Invoke the non-editable wheel environment's python -I -B from an unrelated
working directory. Output is create-only and private; participant seeds are
never included in the retained receipt or logs. This is one local service with
separate participant/server directories, not a filesystem sandbox, TLS proof,
multiworker deployment, authenticated UTC, or authority certification.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

CHILD = """
import json, os, sys
import agora.app as application
import uvicorn
print('SAB_KEY_CONTROL_RUNTIME ' + json.dumps({
    'pid': os.getpid(), 'module': application.__file__,
    'mode': application.PUBLIC_MODE.value,
    'key_control_available': application.KEY_CONTROL is not None,
    'system_key_loaded': application.SYSTEM_SIGNING_KEY is not None,
}), flush=True)
uvicorn.run(application.app, fd=int(sys.argv[1]), access_log=False,
            log_level='warning', timeout_keep_alive=1, timeout_graceful_shutdown=3)
"""
CLAIM = "sab_claim_synthetic_key_control_rehearsal"
ENV = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def write_private(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def provenance(digest):
    require(sys.flags.isolated and sys.dont_write_bytecode, "invoke_installed_python_with_I_B")
    import agora

    distribution = importlib.metadata.distribution("dharmic-agora")
    module = Path(agora.__file__).resolve()
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    require(not direct.get("dir_info", {}).get("editable"), "editable_install_refused")
    require(module.is_relative_to(Path(sys.prefix).resolve()), "module_outside_environment")
    require(
        module == Path(distribution.locate_file("agora/__init__.py")).resolve(),
        "metadata_module_mismatch",
    )
    entry = Path(sys.executable).parent / "agora-key-control"
    require(entry.is_file(), "installed_key_control_entrypoint_missing")
    require(
        any(
            item.name == "agora-key-control" and item.value == "agora.key_control_client:main"
            for item in distribution.entry_points
        ),
        "entrypoint_metadata_mismatch",
    )
    return entry, {
        "wheel_sha256": digest,
        "wheel_sha256_basis": "caller_supplied_artifact_digest",
        "distribution": distribution.metadata["Name"],
        "version": distribution.version,
        "record_sha256": sha((distribution.read_text("RECORD") or "").encode()),
        "entrypoint_sha256": sha(entry.read_bytes()),
        "module": str(module),
        "python": sys.executable,
        "isolated": True,
        "editable": False,
    }


class Rehearsal:
    def __init__(self, output, entry, receipt):
        self.output, self.entry, self.receipt = output, entry, receipt
        self.participant = output / "participant"
        self.server = output / "server"
        self.public_cwd = output / "public-cwd"
        self.canary = output / "public-private-must-not-exist"
        self.children = []
        self.participant_hashes = {}
        for directory in (self.participant, self.server, self.public_cwd):
            directory.mkdir(mode=0o700)

    def safe(self, content):
        for path in self.participant.glob("*.key"):
            seed_hex = path.read_bytes().strip()
            seed = bytes.fromhex(seed_hex.decode("ascii"))
            representations = (
                seed,
                seed_hex.lower(),
                seed_hex.upper(),
                base64.b64encode(seed),
                base64.urlsafe_b64encode(seed),
            )
            require(
                not any(value.rstrip(b"=") in content for value in representations),
                "participant_secret_detected",
            )

    def spawn(self, label, command, cwd, environment, **options):
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **options,
        )
        record = {"label": label, "pid": process.pid, "exit_code": None, "stopped": False}
        self.children.append((process, record))
        self.receipt["processes"].append(record)
        return process, record

    def finish(self, child, *, expected=0):
        process, record = child
        if record["stopped"]:
            return
        if process.poll() is None:
            record["sigterm_requested"] = True
            process.terminate()
        stdout, stderr = process.communicate(timeout=12)
        record.update(
            exit_code=process.returncode,
            stopped=True,
            expected_exit=(
                process.returncode in (expected, -signal.SIGTERM)
                if expected == 0
                else process.returncode == expected
            ),
        )
        for suffix, content in (("stdout", stdout), ("stderr", stderr)):
            self.safe(content)
            write_private(self.output / f"{record['label']}-{suffix}.log", content)
        require(record["expected_exit"], "unexpected_child_exit")
        return stdout, stderr

    def cli(self, label, *arguments, expected=0):
        child = self.spawn(
            label,
            [sys.executable, "-I", "-B", str(self.entry), *map(str, arguments)],
            self.participant,
            ENV,
        )
        process, record = child
        try:
            stdout, stderr = process.communicate(timeout=25)
        except subprocess.TimeoutExpired:
            self.finish(child)
            raise RuntimeError("cli_time_budget_exceeded") from None
        # Complete keygen before reading its synthetic seed for the leak check.
        self.safe(stdout + stderr)
        record.update(
            exit_code=process.returncode, stopped=True, expected_exit=process.returncode == expected
        )
        write_private(self.output / f"{label}-stdout.log", stdout)
        write_private(self.output / f"{label}-stderr.log", stderr)
        require(record["expected_exit"], "unexpected_cli_exit")
        result = json.loads(stdout if expected == 0 else stderr)
        self.receipt["observations"].append(
            {
                "kind": "cli",
                "label": label,
                "exit_code": process.returncode,
                "response_sha256": sha(encoded(result)),
            }
        )
        return result

    def start(self, label, mode, listener):
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        root = self.server if mode == "local" else self.canary
        environment = {
            **ENV,
            "SAB_PUBLIC_MODE": mode,
            "SAB_IDENTITY_ORIGIN": origin,
            "SAB_SPARK_DB_PATH": str(root / "spark.db"),
            "SAB_DB_PATH": str(root / "protocol.db"),
            "SAB_AUTHORITY_DB_PATH": str(root / "authority.db"),
            "SAB_SYSTEM_WITNESS_KEY": str(root / "system.key"),
            "SAB_JWT_SECRET": str(root / "jwt.key"),
            "SAB_SEED_CLAIMS_PATH": str(root / "claims.json"),
            "SAB_LANGUAGE_WOMB_LANE_DIR": str(root / "lane"),
        }
        child = self.spawn(
            label,
            [sys.executable, "-I", "-B", "-c", CHILD, str(listener.fileno())],
            self.server if mode == "local" else self.public_cwd,
            environment,
            pass_fds=(listener.fileno(),),
        )
        child[1].update(origin=origin, mode=mode)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(child[0].poll() is None, "server_exited_before_readiness")
            try:
                result = self.http(origin, "/readyz")
                require(result["status"] == "ready", "server_not_ready")
                return child, origin
            except (URLError, TimeoutError, ConnectionError):
                time.sleep(0.05)
        raise RuntimeError("server_readiness_time_budget_exceeded")

    def http(self, origin, path, payload=None, *, expected=200, raw=None):
        data = encoded(payload) if payload is not None else raw
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json" if raw is None else "text/plain",
        }
        request = Request(origin + path, data=data, headers=headers)
        try:
            response = build_opener(ProxyHandler({}), NoRedirect()).open(
                request, timeout=2
            )  # nosec B310
        except HTTPError as error:
            response = error
        with response:
            body = response.read(262145)
            require(len(body) <= 262144, "http_response_too_large")
            self.safe(body)
            decoded = json.loads(body)
            self.receipt["observations"].append(
                {
                    "kind": "http",
                    "method": request.get_method(),
                    "path": path,
                    "status": response.status,
                    "body_sha256": sha(body),
                    "code": decoded.get("code") if isinstance(decoded, dict) else None,
                }
            )
            require(response.status == expected, "unexpected_http_status")
            require(not response.headers.get("Set-Cookie"), "unexpected_session_cookie")
            if path.startswith("/api/v1/agents/") and data is not None:
                require(
                    response.headers.get("Cache-Control") == "no-store",
                    "identity_response_cacheable",
                )
            return decoded

    def home(self, origin, subject):
        return self.http(origin, "/api/v1/agents/me/home?" + urlencode({"subject_id": subject}))

    def sign_challenge(self, challenge, key_file):
        from agora.key_control_client import load_signing_key

        message = challenge["message"]
        return {
            "challenge_id": message["challenge_id"],
            "signature": load_signing_key(key_file).sign(encoded(message)).signature.hex(),
        }

    def witness(self, origin, subject, key_file, *, previous="genesis", expected=201):
        from agora.key_control_client import load_signing_key

        payload = {
            "text": "Synthetic local key-control rehearsal; no standing or authority.",
            "standing_effect": "none",
        }
        stamp = datetime.now(timezone.utc).isoformat()
        message = {
            "kind": "sab_witness_event",
            "event_type": "response",
            "subject_type": "claim",
            "subject_id": CLAIM,
            "payload_hash": sha(encoded(payload)),
            "prev_hash": previous,
            "created_at": stamp,
        }
        return self.http(
            origin,
            "/api/v1/witness-events",
            {
                "event_type": "response",
                "subject_type": "claim",
                "subject_id": CLAIM,
                "payload": payload,
                "actor_identity": subject,
                "prev_hash": previous,
                "created_at": stamp,
                "signature": load_signing_key(key_file).sign(encoded(message)).signature.hex(),
            },
            expected=expected,
        )

    def exercise(self):
        keys, registrations, identities = {}, {}, {}
        for label in ("old", "successor", "revoked"):
            keys[label] = self.participant / f"{label}.key"
            public = self.cli("keygen-" + label, "keygen", "--key-file", keys[label])
            require(stat.S_IMODE(keys[label].stat().st_mode) == 0o600, "participant_key_not_0600")
            identities[label] = public["subject_id"]
            registration = {
                "display_name": "Synthetic " + label,
                "public_key": public["public_key"],
            }
            registrations[label] = self.participant / f"{label}.json"
            write_private(registrations[label], encoded(registration))
        self.participant_hashes = {
            path.name: sha(path.read_bytes()) for path in self.participant.iterdir()
        }
        with socket.socket() as local, socket.socket() as public:
            for listener in (local, public):
                listener.bind(("127.0.0.1", 0))
                listener.listen(16)
            first, origin = self.start("local-cold", "local", local)
            for label in ("old", "revoked"):
                result = self.cli(
                    "enroll-" + label,
                    "enroll",
                    "--origin",
                    origin,
                    "--key-file",
                    keys[label],
                    "--registration",
                    registrations[label],
                )
                require(result["binding"]["status"] == "active", "enrollment_not_active")
            event = self.witness(origin, identities["old"], keys["old"])
            history_path = "/api/v1/witness/chain?" + urlencode(
                {"subject_type": "claim", "subject_id": CLAIM}
            )
            history = self.http(origin, history_path)
            require(len(history["entries"]) == 1, "synthetic_history_missing")
            rotated = self.cli(
                "rotate-old",
                "rotate",
                "--origin",
                origin,
                "--subject-id",
                identities["old"],
                "--key-file",
                keys["old"],
                "--new-key-file",
                keys["successor"],
                "--registration",
                registrations["successor"],
            )
            require(
                rotated["previous_binding"]["status"] == "superseded",
                "rotation_did_not_retire_old_key",
            )
            revoked = self.cli(
                "revoke-other",
                "revoke",
                "--origin",
                origin,
                "--subject-id",
                identities["revoked"],
                "--key-file",
                keys["revoked"],
            )
            require(revoked["binding"]["status"] == "revoked", "revocation_not_recorded")
            issue = {
                "action": "register",
                "registration": json.loads(registrations["successor"].read_bytes()),
            }
            consumed = self.sign_challenge(
                self.http(origin, "/api/v1/agents/challenge", issue, expected=201),
                keys["successor"],
            )
            self.http(origin, "/api/v1/agents/verify", consumed)
            pending = self.sign_challenge(
                self.http(origin, "/api/v1/agents/challenge", issue, expected=201),
                keys["successor"],
            )
            homes = {label: self.home(origin, subject) for label, subject in identities.items()}
            self.finish(first)
            second, restarted_origin = self.start("local-restart", "local", local)
            require(restarted_origin == origin, "restart_changed_audience")
            for name, signed in (("consumed_replay", consumed), ("pending_restart", pending)):
                rejection = self.http(origin, "/api/v1/agents/verify", signed, expected=409)
                require(rejection["code"] == "challenge_unavailable", name + "_not_rejected")
            for label, status in (
                ("old", "superseded"),
                ("successor", "active"),
                ("revoked", "revoked"),
            ):
                home = self.home(origin, identities[label])
                require(
                    home == homes[label] and home["key_control"]["status"] == status,
                    "restart_changed_binding",
                )
                require(
                    home["authority_effect"] == home["standing_effect"] == "none",
                    "binding_granted_authority",
                )
            for label in ("old", "revoked"):
                result = self.cli(
                    "reactivation-refused-" + label,
                    "enroll",
                    "--origin",
                    origin,
                    "--key-file",
                    keys[label],
                    "--registration",
                    registrations[label],
                    expected=1,
                )
                require(result.get("http_status") == 403, "retired_key_reactivation_not_refused")
            self.witness(
                origin, identities["old"], keys["old"], previous=event["event_hash"], expected=403
            )
            require(
                self.http(origin, history_path) == history, "retirement_changed_original_history"
            )
            self.finish(second)
            reader, public_origin = self.start("public-reader", "public_readonly", public)
            for route in ("register", "challenge", "verify"):
                self.http(
                    public_origin, "/api/v1/agents/" + route, expected=403, raw=b"not valid JSON"
                )
                require(not self.canary.exists(), "public_identity_command_created_private_state")
            self.finish(reader)
        with sqlite3.connect((self.server / "spark.db").as_uri() + "?mode=ro", uri=True) as conn:
            require(
                conn.execute("SELECT count(*) FROM sab_key_control_proofs_v1").fetchone()[0] == 5,
                "durable_proof_history_changed",
            )
            require(
                conn.execute("SELECT count(*) FROM sab_authority_leases_v1").fetchone()[0] == 0,
                "key_control_created_authority",
            )
            require(
                conn.execute("SELECT count(*) FROM sab_standing_leases_v1").fetchone()[0] == 0,
                "key_control_created_standing",
            )
        self.receipt.update(
            durable_states={label: homes[label]["key_control"]["status"] for label in homes},
            pending_restart_rejected=True,
            consumed_replay_rejected=True,
            retired_key_reactivation_rejected=True,
            original_witness_history_unchanged=True,
            original_history_sha256=sha(encoded(history)),
            real_v1_command_before_retirement=True,
            retired_key_v1_command_rejected=True,
            authority_effect="none",
            standing_effect="none",
        )

    def audit(self):
        allowed_server = {
            "spark.db",
            "spark.db-journal",
            "spark.db-wal",
            "spark.db-shm",
            "system.key",
        }
        server_files = []
        for path in self.server.rglob("*"):
            require(
                path.is_file()
                and not path.is_symlink()
                and path.name in allowed_server
                and path.parent == self.server,
                "unexpected_server_write",
            )
            self.safe(path.read_bytes())
            server_files.append(path.name)
        require(
            not self.canary.exists() and not any(self.public_cwd.iterdir()),
            "public_runtime_wrote_private_files",
        )
        require(
            all(path.is_file() and not path.is_symlink() for path in self.participant.iterdir()),
            "unexpected_participant_entry",
        )
        require(
            {path.name: sha(path.read_bytes()) for path in self.participant.iterdir()}
            == self.participant_hashes,
            "participant_files_changed",
        )
        for path in self.output.glob("*.log"):
            self.safe(path.read_bytes())
        for process, record in self.children:
            require(
                process.poll() is not None and record["stopped"] and record["expected_exit"],
                "owned_process_not_cleanly_stopped",
            )
            if "mode" in record:
                content = (self.output / f"{record['label']}-stdout.log").read_text()
                runtime = [
                    json.loads(line.removeprefix("SAB_KEY_CONTROL_RUNTIME "))
                    for line in content.splitlines()
                    if line.startswith("SAB_KEY_CONTROL_RUNTIME ")
                ]
                require(
                    len(runtime) == 1
                    and runtime[0]["pid"] == process.pid
                    and runtime[0]["mode"] == record["mode"],
                    "owned_runtime_identity_unverified",
                )
                require(
                    runtime[0]["key_control_available"] == (record["mode"] == "local"),
                    "unexpected_public_key_control_service",
                )
                require(
                    record["mode"] == "local" or not runtime[0]["system_key_loaded"],
                    "public_reader_loaded_system_key",
                )
                record["runtime"] = runtime[0]
        self.receipt.update(
            participant_seed_scan="no_seed_bytes_found_in_server_files_logs_or_receipt",
            expected_server_files=sorted(server_files),
            public_private_paths_absent=True,
            participant_files_unchanged=True,
            all_owned_processes_stopped=True,
            forced_kills=0,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.artifact_sha256):
        parser.error("artifact-sha256 must be 64 lowercase hexadecimal characters")
    entry, artifact = provenance(args.artifact_sha256)
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    receipt = {
        "schema": "sab.key_control_rehearsal.v1",
        "status": "running",
        "artifact": artifact,
        "synthetic_only": True,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "processes": [],
        "observations": [],
        "limitations": [
            "One local service, same-user separate directories, no filesystem sandbox.",
            "No TLS, multiworker support, authenticated UTC, operator independence, or authority demonstrated.",
            "Artifact digest is caller provenance; this rehearsal does not reconstruct the installed wheel.",
        ],
    }
    run = Rehearsal(output, entry, receipt)
    try:
        run.exercise()
        receipt["status"] = "passed"
    except BaseException as error:
        receipt.update(status="failed", error_type=type(error).__name__)
        # Our RuntimeError messages are fixed probe codes; other exception text
        # may contain external content and is deliberately omitted.
        if (
            type(error) is RuntimeError
            and error.args
            and re.fullmatch(r"[a-z_]{1,100}", str(error.args[0]))
        ):
            receipt["error_code"] = str(error.args[0])
    finally:
        for child in reversed(run.children):
            try:
                run.finish(child)
            except BaseException as error:
                receipt.update(status="failed")
                receipt.setdefault("cleanup_errors", []).append(
                    {"pid": child[0].pid, "type": type(error).__name__}
                )
        try:
            run.audit()
        except BaseException as error:
            receipt.update(status="failed", audit_error_type=type(error).__name__)
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            run.safe(encoded(receipt))
        except BaseException:
            # Never retain a receipt whose content failed the leak check.
            receipt = {
                "schema": "sab.key_control_rehearsal.v1",
                "status": "failed",
                "error_code": "receipt_secret_scan_failed",
            }
        write_private(output / "receipt.json", encoded(receipt) + b"\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(output / "receipt.json")}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
