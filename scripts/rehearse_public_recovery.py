#!/usr/bin/env python3
"""Rehearse an installed public reader with disposable synthetic publications.

Run with the wheel environment's ``python -I -B`` from an unrelated directory.
All output is create-only and private. No production source, signing material,
daemon, container, proxy, or external deployment is involved. The supplied wheel
digest is caller provenance; this script does not reconstruct a wheel from its
installed files. This is a process/bundle rehearsal, not image rollback or TLS.
"""

from __future__ import annotations

import argparse
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
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


SEED = "sab_seed_synthetic_recovery"
CLAIM = "sab_claim_synthetic_recovery"
STAMP = "2026-09-09T00:00:00+00:00"
CORRECTED_AT = "2026-09-09T00:01:00+00:00"
WITHDRAWN_AT = "2026-09-09T00:02:00+00:00"
MEMBERS = ("manifest.json", "snapshot.sqlite3")
SIGNATURE = "SYNTHETIC-NOT-A-VALID-SIGNATURE"
CHILD = """
import json, os, sys
from agora.public_snapshot import PublicSnapshotError
try:
    import agora.app as application
except PublicSnapshotError as error:
    print('SAB_RECOVERY_STARTUP_REJECTED ' + json.dumps({'code': error.code}), flush=True)
    raise SystemExit(2)
import uvicorn
assert application.SYSTEM_SIGNING_KEY is None
assert application.SYSTEM_VERIFY_KEY_HEX is None
print('SAB_RECOVERY_RUNTIME ' + json.dumps({
    'pid': os.getpid(), 'module': application.__file__, 'signing_key_loaded': False,
}), flush=True)
uvicorn.run(application.app, fd=int(sys.argv[1]), access_log=False, log_level='warning')
"""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def _private_write(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)


def _artifact_identity(digest: str) -> dict:
    import agora

    _require(bool(sys.flags.isolated), "Invoke the installed interpreter with -I.")
    module = Path(agora.__file__).resolve()
    _require(
        module.is_relative_to(Path(sys.prefix).resolve()),
        "agora is outside the interpreter environment.",
    )
    distribution = importlib.metadata.distribution("dharmic-agora")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    _require(
        not direct.get("dir_info", {}).get("editable"),
        "Editable installs are not an artifact rehearsal.",
    )
    _require(
        module == Path(distribution.locate_file("agora/__init__.py")).resolve(),
        "Imported agora does not match installed distribution metadata.",
    )
    return {
        "wheel_sha256": digest,
        "wheel_sha256_basis": "caller_supplied_approved_artifact_digest",
        "distribution": distribution.metadata["Name"],
        "version": distribution.version,
        "installed_record_sha256": _sha((distribution.read_text("RECORD") or "").encode()),
        "python": sys.executable,
        "module": str(module),
        "isolated_interpreter": True,
        "editable": False,
    }


def _insert(conn: sqlite3.Connection, table: str, **values) -> None:
    # Table and column names below are fixed synthetic-fixture constants.
    conn.execute(
        f"INSERT INTO {table} ({','.join(values)}) VALUES ({','.join('?' for _ in values)})",  # nosec B608
        tuple(values.values()),
    )


def _synthetic_bundles(output: Path) -> tuple[dict, str]:
    from agora.public_snapshot import (
        export_empty_public_snapshot,
        export_public_snapshot,
        plan_public_snapshot,
    )
    from agora.sab_seeding_api import (
        _append_witness_event,
        _hash_json,
        _init_v1_tables,
        _without_signature,
    )

    packet = {
        "schema": "sab.seed_packet.v1",
        "seed_id": SEED,
        "privacy_class": "public",
        "claim": {
            "claim_id": CLAIM,
            "text": "SYNTHETIC REHEARSAL ONLY: preserve this original.\n条件を確認する。",
            "scope": "Disposable local recovery exercise",
            "decision_context": "No real-world reliance",
        },
        "claimant_identity": {"subject_id": "synthetic_claimant"},
        "evidence_bundle": [
            {
                "ref": "https://example.invalid/synthetic-recovery-evidence",
                "digest": _sha(b"Synthetic evidence placeholder, never fetched"),
                "notes": "Synthetic reference; evidence bytes are not verified.",
            }
        ],
        "signature": {"signature": SIGNATURE},
        "created_at": STAMP,
    }
    original_json = json.dumps(packet, indent=2)
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    bundles = {}
    try:
        _init_v1_tables(conn)
        for actor in ("synthetic_claimant", "synthetic_challenger", "synthetic_witness"):
            identity = {
                "subject_id": actor,
                "public_key": "SYNTHETIC-NOT-A-VALID-PUBLIC-KEY",
                "operator_backing": {"operator_id": "one_synthetic_operator"},
            }
            _insert(
                conn,
                "sab_agent_identities_v1",
                subject_id=actor,
                display_name=actor,
                public_key=identity["public_key"],
                controller="synthetic_fixture",
                operator_id="one_synthetic_operator",
                operator_backing_json=json.dumps(identity["operator_backing"]),
                identity_json=json.dumps(identity),
                created_at=STAMP,
                updated_at=STAMP,
            )
        _insert(
            conn,
            "sab_seed_packets_v1",
            seed_id=SEED,
            seed_type="claim",
            title="Synthetic recovery fixture",
            claim_id=CLAIM,
            claimant_identity="synthetic_claimant",
            authority_lease_id="synthetic_unissued_lease",
            state="challenged",
            packet_json=original_json,
            packet_hash=_hash_json(_without_signature(packet)),
            spark_projection_id=None,
            challenge_window_closes_at=None,
            created_at=STAMP,
            updated_at=STAMP,
        )

        def event(kind, actor, payload, *, stamp=STAMP, subject_type="seed", subject_id=SEED):
            return _append_witness_event(
                conn,
                event_type=kind,
                actor_identity=actor,
                subject_type=subject_type,
                subject_id=subject_id,
                subject_seed_id=SEED,
                payload=payload,
                signature_hex=SIGNATURE,
                timestamp=stamp,
            )

        def state_event(kind, payload, witnessed, from_state, to_state, stamp):
            _insert(
                conn,
                "sab_seed_events_v1",
                event_id="synthetic_event_" + kind,
                seed_id=SEED,
                actor_identity="synthetic_claimant",
                event_type=kind,
                from_state=from_state,
                to_state=to_state,
                payload_json=json.dumps(payload),
                witness_event_id=witnessed["event_id"],
                created_at=stamp,
            )

        submit_payload = {"seed_packet_hash": _hash_json(_without_signature(packet))}
        state_event(
            "submit",
            submit_payload,
            event("submit", "synthetic_claimant", submit_payload),
            "pending_seed",
            "pending_seed",
            STAMP,
        )
        challenge = {
            "challenge_id": "synthetic_challenge",
            "target_seed_id": SEED,
            "target_claim_id": CLAIM,
            "quoted_claim_fragment": "preserve this original",
            "evidence": [
                {
                    "ref": "https://example.invalid/synthetic-counterexample",
                    "digest": _sha(b"Synthetic counterexample placeholder"),
                }
            ],
            "text": "SYNTHETIC: can a correction preserve the submitted original?",
        }
        _insert(
            conn,
            "sab_challenge_packets_v1",
            challenge_id="synthetic_challenge",
            target_seed_id=SEED,
            target_claim_id=CLAIM,
            challenger_identity="synthetic_challenger",
            status="pending",
            packet_json=json.dumps(challenge),
            packet_hash=_hash_json(challenge),
            response_json=None,
            respond_by=None,
            prosecute_by=None,
            created_at=STAMP,
            updated_at=STAMP,
        )
        event(
            "challenge",
            "synthetic_challenger",
            {"challenge_id": "synthetic_challenge"},
            subject_type="challenge",
            subject_id="synthetic_challenge",
        )
        event(
            "affirm",
            "synthetic_witness",
            {"note": "Synthetic stored event, no authenticated witness or independence."},
        )

        def publish(label, stamp):
            conn.commit()
            review = plan_public_snapshot(conn, [SEED], observed_at=stamp)
            for record in review["records"]:
                record.update(
                    decision="approve",
                    publication_basis="own_work",
                    license="CC0-1.0",
                    privacy_review={
                        "status": "approved",
                        "reviewer": "Synthetic rehearsal fixture author",
                    },
                    consent={
                        "required": False,
                        "satisfied": True,
                        "basis": "Synthetic records only; no real people or signatures.",
                    },
                    takedown={
                        "owner": "Synthetic rehearsal runner",
                        "route": "https://example.invalid/synthetic-takedown",
                    },
                )
                for document in record["raw_json_review"].values():
                    document.update(classification="public_original", extensions_reviewed=True)
            export_public_snapshot(conn, output / label, review)

        publish("A", STAMP)
        correction = {
            "text": "SYNTHETIC correction: original inspection does not establish reliance."
        }
        payload = {"correction": correction, "correction_hash": _hash_json(correction)}
        state_event(
            "correction",
            payload,
            event("correction", "synthetic_claimant", payload, stamp=CORRECTED_AT),
            "challenged",
            "corrected",
            CORRECTED_AT,
        )
        conn.execute(
            "UPDATE sab_seed_packets_v1 SET state='corrected', updated_at=? WHERE seed_id=?",
            (CORRECTED_AT, SEED),
        )
        publish("B", CORRECTED_AT)
        export_empty_public_snapshot(output / "W", observed_at=WITHDRAWN_AT)
    finally:
        conn.close()
    for label in ("A", "B", "W"):
        bundle = output / label
        pin = _sha((bundle / "manifest.json").read_bytes())
        pin_path = output / "pins" / (label + ".sha256")
        _private_write(pin_path, (pin + "\n").encode())
        pin_path.chmod(0o400)
        for member in MEMBERS:
            (bundle / member).chmod(0o400)
        bundle.chmod(0o500)
        bundles[label] = {
            "path": str(bundle),
            "manifest_sha256": pin,
            "files": {name: _sha((bundle / name).read_bytes()) for name in MEMBERS},
        }
    return bundles, original_json


def _copy_bundle(source: Path, destination: Path, retained_pin: str) -> dict:
    from agora.public_snapshot import load_public_snapshot

    load_public_snapshot(source, retained_pin)
    destination.mkdir(mode=0o700)
    hashes = {}
    for member in MEMBERS:
        content = (source / member).read_bytes()
        _private_write(destination / member, content)
        _require(
            (destination / member).read_bytes() == content, "Backup/restore byte comparison failed."
        )
        hashes[member] = _sha(content)
        (destination / member).chmod(0o400)
    load_public_snapshot(destination, retained_pin)
    destination.chmod(0o500)
    return {
        "source": str(source),
        "destination": str(destination),
        "retained_manifest_sha256": retained_pin,
        "files": hashes,
        "byte_equal": True,
        "loader_integrity_and_inventory_accepted": True,
    }


class _Server:
    def __init__(self, output: Path, label: str, bundle: Path, pin: str, processes: list):
        self.cwd = output / (label + "-cwd")
        self.cwd.mkdir(mode=0o500)
        self.log_path = output / (label + ".log")
        self.canary = output / (label + "-private-must-not-exist")
        self.log = os.fdopen(
            os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        )
        environment = {
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "SAB_PUBLIC_MODE": "public_readonly",
            "SAB_PUBLIC_SNAPSHOT": str(bundle),
            "SAB_PUBLIC_SNAPSHOT_SHA256": pin,
            "SAB_SPARK_DB_PATH": str(self.canary / "spark.db"),
            "SAB_DB_PATH": str(self.canary / "protocol.db"),
            "SAB_AUTHORITY_DB_PATH": str(self.canary / "authority.db"),
            "SAB_SYSTEM_WITNESS_KEY": str(self.canary / "system.key"),
            "SAB_JWT_SECRET": str(self.canary / "jwt.key"),
            "SAB_SEED_CLAIMS_PATH": str(self.canary / "seed_claims.json"),
            "SAB_LANGUAGE_WOMB_LANE_DIR": str(self.canary / "lane"),
        }
        try:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(16)
                self.origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
                self.process = subprocess.Popen(
                    [sys.executable, "-I", "-B", "-c", CHILD, str(listener.fileno())],
                    cwd=self.cwd,
                    env=environment,
                    stdout=self.log,
                    stderr=subprocess.STDOUT,
                    pass_fds=(listener.fileno(),),
                )
        except BaseException:
            self.log.close()
            raise
        self.record = {
            "label": label,
            "pid": self.process.pid,
            "origin": self.origin,
            "expected_manifest_sha256": pin,
            "log": str(self.log_path),
            "exit_code": None,
        }
        processes.append(self.record)

    def stop(self):
        if self.process.poll() is None:
            self.record["termination_requested"] = True
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.record["forced_kill"] = True
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()
        self.record.update(
            exit_code=self.process.returncode,
            stopped=self.process.poll() is not None,
            private_paths_absent=not self.canary.exists(),
            cwd_unchanged=not any(self.cwd.iterdir()),
        )
        self.record["expected_exit_status"] = (
            self.record.get("startup_rejected", False)
            and self.process.returncode == 2
            or self.record.get("termination_requested", False)
            and self.process.returncode in (0, -signal.SIGTERM)
        )

    def ready(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            _require(
                self.process.poll() is None,
                f"{self.record['label']} exited before readiness; see {self.log_path}",
            )
            try:
                ready = self.read("/readyz")
                _require(ready.get("status") == "ready", "Readiness did not report ready.")
                _require(
                    ready["publication"]["manifest_sha256"]
                    == self.record["expected_manifest_sha256"],
                    "Readiness did not match the independently supplied pin.",
                )
                _require("db_path" not in ready, "Readiness disclosed a database path.")
                self.record["readiness"] = True
                return
            except (URLError, TimeoutError, ConnectionError):
                time.sleep(0.05)
        raise RuntimeError(f"{self.record['label']} did not become ready within 20 seconds.")

    def rejected(self):
        deadline = time.monotonic() + 20
        while self.process.poll() is None and time.monotonic() < deadline:
            try:
                self.read("/readyz")
            except (URLError, TimeoutError, ConnectionError):
                pass
            else:
                raise RuntimeError("Wrong-pin candidate answered readiness.")
            time.sleep(0.05)
        _require(self.process.poll() not in (None, 0), "Wrong-pin candidate did not fail startup.")
        errors = [
            json.loads(line.removeprefix("SAB_RECOVERY_STARTUP_REJECTED "))
            for line in self.log_path.read_text().splitlines()
            if line.startswith("SAB_RECOVERY_STARTUP_REJECTED ")
        ]
        _require(
            errors == [{"code": "manifest_pin_mismatch"}],
            "Candidate failed for a reason other than the wrong pin.",
        )
        self.record.update(
            readiness=False, startup_rejected=True, startup_error_code=errors[0]["code"]
        )
        self.stop()
        _require(
            self.record["private_paths_absent"], "Rejected candidate created a private fallback."
        )

    def read(self, path, *, expected=200, raw=False):
        _require(
            path.startswith("/") and not path.startswith("//"),
            "Only local-origin paths are supported.",
        )
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            response = opener.open(Request(self.origin + path), timeout=1)  # nosec B310
        except HTTPError as error:
            response = error
        with response:
            body = response.read()
            _require(
                response.status == expected,
                f"{path}: expected HTTP {expected}, got {response.status}.",
            )
            _require(
                response.headers.get("Cache-Control") == "no-store", f"{path}: missing no-store."
            )
            _require(not response.headers.get("Set-Cookie"), f"{path}: unexpected cookie.")
            return body if raw else json.loads(body)


def _commitment(dossier: dict) -> dict:
    """Only stable stored content; exclude request-time deadline observations."""
    return {
        "identity": dossier["identity"],
        "original_packet_json": dossier["original_packet_json"],
        "seed": dossier["seed"],
        "witness_events": dossier["witness"]["events"],
        "state_events": dossier["witness"]["state_events"],
        "witness_head": dossier["witness"]["head"],
        "corrections": dossier["corrections"]["items"],
        "challenges": [
            {
                key: item[key]
                for key in ("challenge_id", "packet_json", "packet_hash", "response_json", "status")
            }
            for item in dossier["challenges"]["items"]
        ],
    }


def _inspect(
    server: _Server, bundle: Path, pin: str, original: str, corrections: int | None
) -> tuple[dict, dict | None]:
    from agora.public_inspection import inspect

    server.ready()
    result = inspect(server.origin, expected_manifest_sha256=pin)
    served_manifest = server.read("/publication/manifest", raw=True)
    _require(
        served_manifest == (bundle / "manifest.json").read_bytes(),
        "Served manifest changed exact bytes.",
    )
    _require(
        _sha(served_manifest) == pin, "Served manifest differs from the retained approved pin."
    )
    lines = server.log_path.read_text().splitlines()
    runtime = [
        json.loads(line.removeprefix("SAB_RECOVERY_RUNTIME "))
        for line in lines
        if line.startswith("SAB_RECOVERY_RUNTIME ")
    ]
    _require(
        len(runtime) == 1
        and runtime[0]["pid"] == server.process.pid
        and runtime[0]["signing_key_loaded"] is False,
        "Owned reader did not establish its no-signing-key import check.",
    )
    server.record["runtime"] = runtime[0]
    dossier_path = f"/api/v1/seeds/{SEED}/dossier"
    result.update(expected_manifest_sha256=pin, exact_manifest_bytes=True, signing_key_loaded=False)
    if corrections is None:
        _require(result["claim_count"] == 0, "Withdrawal still lists a claim.")
        server.read(dossier_path, expected=404)
        witness = server.read("/api/v1/witness/verify")
        _require(
            witness["entry_count"] == 0 and witness["verified"] is None,
            "Empty publication reported verified witness history.",
        )
        return result, None
    _require(result["claim_count"] == 1, "Synthetic claim count differs.")
    dossier = server.read(dossier_path)
    _require(
        dossier["identity"]["seed_id"] == SEED and dossier["identity"]["claim_id"] == CLAIM,
        "Dossier identity changed.",
    )
    _require(
        dossier["original_packet_json"] == original
        and dossier["original_packet"] == json.loads(original),
        "Original submission changed.",
    )
    _require(len(dossier["corrections"]["items"]) == corrections, "Unexpected correction history.")
    _require(
        len(dossier["challenges"]["items"]) == 1
        and dossier["witness"]["total_count"] == 3 + corrections,
        "Synthetic challenge/witness context was lost.",
    )
    _require(
        dossier["authority_effect"] == dossier["standing_effect"] == "none"
        and dossier["reliance"]["status"] == "unestablished",
        "Inspection acquired authority or reliance.",
    )
    commitment = _commitment(dossier)
    result.update(
        commitment_sha256=_sha(_json_bytes(commitment)),
        original_json_sha256=_sha(original.encode()),
        correction_count=corrections,
        witness_count=dossier["witness"]["total_count"],
    )
    return result, commitment


def rehearse(output: Path, artifact: dict) -> dict:
    started = time.monotonic()
    receipt = {
        "schema": "sab.public_recovery_rehearsal.v1",
        "status": "running",
        "artifact": artifact,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "synthetic_only": True,
        "phases": [],
        "processes": [],
        "copies": [],
        "scope": "Installed wheel process and immutable public bundle recovery on loopback",
        "limitations": [
            "No container/image rollback, TLS, production deployment, or C7 completion.",
            "No real signatures, evidence truth, operator independence, or authority verified.",
            "Pins and fixtures are generated for this disposable rehearsal only.",
        ],
    }
    servers = []
    try:
        for name in ("pins", "backup", "restored"):
            (output / name).mkdir(mode=0o700)
        bundles, original = _synthetic_bundles(output)
        receipt["bundles"] = bundles

        def pin(label):
            # Read the independently retained commitment, never derive it from a backup.
            return (output / "pins" / (label + ".sha256")).read_text().strip()

        def start(label, bundle, approved):
            server = _Server(output, label, bundle, approved, receipt["processes"])
            servers.append(server)
            return server

        def inspect_phase(server, label, bundle, approved, corrections):
            phase_started = time.monotonic()
            check, commitment = _inspect(server, bundle, approved, original, corrections)
            receipt["phases"].append(
                {
                    "name": label,
                    "elapsed_seconds": round(time.monotonic() - phase_started, 3),
                    **check,
                }
            )
            return commitment

        a = start("A-cold", output / "A", pin("A"))
        baseline = inspect_phase(a, "A_cold_start", output / "A", pin("A"), 0)
        a.stop()
        a = start("A-restart", output / "A", pin("A"))
        _require(
            inspect_phase(a, "A_fresh_restart", output / "A", pin("A"), 0) == baseline,
            "A restart changed stored commitments.",
        )
        for label in ("A", "B", "W"):
            receipt["copies"].append(
                _copy_bundle(output / label, output / "backup" / label, pin(label))
            )
        receipt["copies"].append(
            _copy_bundle(output / "backup" / "A", output / "restored" / "A", pin("A"))
        )
        restored_a = start("A-restored", output / "restored" / "A", pin("A"))
        _require(
            inspect_phase(restored_a, "A_backup_restore", output / "restored" / "A", pin("A"), 0)
            == baseline,
            "Restored A changed stored commitments.",
        )
        restored_a.stop()
        candidate_b = start("B-candidate", output / "B", pin("B"))
        corrected = inspect_phase(
            candidate_b, "B_candidate_while_A_live", output / "B", pin("B"), 1
        )
        _require(
            inspect_phase(a, "A_unchanged_during_B_candidate", output / "A", pin("A"), 0)
            == baseline,
            "Candidate changed live A.",
        )
        _require(
            corrected["identity"] == baseline["identity"]
            and corrected["witness_events"][:3] == baseline["witness_events"]
            and corrected["challenges"] == baseline["challenges"],
            "Correction replaced original identity or history.",
        )
        candidate_b.stop()
        a.stop()
        b = start("B-active", output / "B", pin("B"))
        _require(
            inspect_phase(b, "B_fresh_replacement", output / "B", pin("B"), 1) == corrected,
            "Fresh B differs from candidate B.",
        )
        bad = start("B-wrong-pin", output / "B", "0" * 64)
        bad.rejected()
        receipt["phases"].append(
            {"name": "B_wrong_pin_rejected", "startup_nonzero": True, "readiness": False}
        )
        _require(
            inspect_phase(b, "B_survives_rejected_candidate", output / "B", pin("B"), 1)
            == corrected,
            "Rejected candidate changed live B.",
        )
        b.stop()
        receipt["copies"].append(
            _copy_bundle(output / "backup" / "B", output / "restored" / "B", pin("B"))
        )
        b = start("B-restored", output / "restored" / "B", pin("B"))
        _require(
            inspect_phase(
                b, "B_recovery_from_eligible_backup", output / "restored" / "B", pin("B"), 1
            )
            == corrected,
            "Recovered B differs from approved B.",
        )
        b.stop()
        w = start("W-withdrawn", output / "W", pin("W"))
        inspect_phase(w, "W_withdrawal", output / "W", pin("W"), None)
        bad = start("W-wrong-pin", output / "W", pin("B"))
        bad.rejected()
        receipt["phases"].append(
            {"name": "W_wrong_pin_rejected", "startup_nonzero": True, "readiness": False}
        )
        inspect_phase(w, "W_survives_rejected_candidate", output / "W", pin("W"), None)
        w.stop()
        receipt["copies"].append(
            _copy_bundle(output / "backup" / "W", output / "restored" / "W", pin("W"))
        )
        w = start("W-restored", output / "restored" / "W", pin("W"))
        inspect_phase(
            w, "W_recovery_preserves_withdrawal", output / "restored" / "W", pin("W"), None
        )
        receipt["withdrawal_policy"] = {
            "eligible_recovery_pin": pin("W"),
            "retired_pins": [pin("A"), pin("B")],
            "retired_publications_restarted_after_withdrawal": False,
            "enforcement_scope": "This rehearsal's explicit recovery selection only",
        }
        for label, bundle in bundles.items():
            _require(
                {name: _sha((output / label / name).read_bytes()) for name in MEMBERS}
                == bundle["files"],
                "An original publication bundle changed during the rehearsal.",
            )
        receipt["original_bundle_bytes_unchanged"] = True
        receipt["status"] = "passed"
    except BaseException as error:
        receipt.update(status="failed", error={"type": type(error).__name__, "detail": str(error)})
    finally:
        for server in reversed(servers):
            try:
                server.stop()
            except BaseException as error:
                receipt.setdefault("cleanup_errors", []).append(
                    {"pid": server.process.pid, "type": type(error).__name__}
                )
        receipt["cleanup"] = {
            "all_owned_processes_stopped": all(
                item.get("stopped") for item in receipt["processes"]
            ),
            "private_paths_absent": all(
                item.get("private_paths_absent") for item in receipt["processes"]
            ),
            "working_directories_unchanged": all(
                item.get("cwd_unchanged") for item in receipt["processes"]
            ),
            "expected_exit_statuses": all(
                item.get("expected_exit_status") for item in receipt["processes"]
            ),
            "forced_kills": sum(bool(item.get("forced_kill")) for item in receipt["processes"]),
        }
        if (
            receipt.get("cleanup_errors")
            or not all(
                receipt["cleanup"][key]
                for key in (
                    "all_owned_processes_stopped",
                    "private_paths_absent",
                    "working_directories_unchanged",
                )
            )
            or receipt["cleanup"]["forced_kills"]
        ):
            receipt["status"] = "failed"
        if not receipt["cleanup"]["expected_exit_statuses"]:
            receipt["status"] = "failed"
        receipt.update(
            finished_at=datetime.now(timezone.utc).isoformat(),
            elapsed_seconds=round(time.monotonic() - started, 3),
        )
        _private_write(output / "receipt.json", _json_bytes(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="new private directory under an existing real parent",
    )
    parser.add_argument(
        "--artifact-sha256", required=True, help="independently approved installed wheel SHA-256"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.artifact_sha256):
        parser.error("--artifact-sha256 must be a lowercase SHA-256 hex digest")
    try:
        artifact = _artifact_identity(args.artifact_sha256)
        from agora.public_snapshot import _no_symlinks

        output = args.output.absolute()
        _no_symlinks(output)
        output.mkdir(mode=0o700)
        result = rehearse(output, artifact)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Rehearsal rejected: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": result["status"],
                "receipt": str(output / "receipt.json"),
                "phase_count": len(result["phases"]),
                "cleanup": result["cleanup"],
            },
            sort_keys=True,
        )
    )
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
