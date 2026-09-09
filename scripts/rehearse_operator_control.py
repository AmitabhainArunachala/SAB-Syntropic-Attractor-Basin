#!/usr/bin/env python3
"""Rehearse installed operator-control CLI and HTTP with synthetic local material.

Run the wheel environment's python -I -B from outside the source checkout.
Output must be a new directory. Retain only receipt.json and root *.log files;
participant/, configuration/, and server/ contain private rehearsal state and
must never be uploaded. Four keys belong to this one runner. A two-member
registry assessment demonstrates neither standing quorum nor real independence.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import signal
import socket
import sqlite3
import stat
import subprocess
import sys


# These trusted adjacent scripts provide orchestration only. Every application
# import in this interpreter and all children resolves from the installed wheel.
AUTHORITY = runpy.run_path(str(Path(__file__).with_name("rehearse_authority.py")),
                          run_name="sab_installed_operator_orchestration")
HARNESS = AUTHORITY["HARNESS"]
require, encoded, sha, write_private = (HARNESS[name] for name in ("require", "encoded", "sha", "write_private"))
SEED = "sab_seed_installed_operator_control"
CATEGORIES = {
    "controller_resolution": "organizational_record", "signing_custody": "custody_inspection",
    "administrator_access": "custody_inspection", "runtime_control": "custody_inspection",
    "delegation_decision_rights": "delegation_record", "funding": "financial_record", "conflicts": "conflict_record",
}
ACTION = "challenge_operator_control"
CLI_TIMEOUT = 25
STOP_TIMEOUT = 12
KILL_TIMEOUT = 5
RUNTIME_PREFIX = b"SAB_KEY_CONTROL_RUNTIME "
ERROR_CODES = frozenset({
    "unexpected_cli_exit", "unexpected_http_status", "cli_time_budget_exceeded",
    "child_stop_timeout", "child_cleanup_failed", "unexpected_child_exit",
    "runtime_identity_invalid", "owned_process_not_cleanly_stopped", "participant_secret_detected",
    "server_exited_before_readiness", "server_readiness_time_budget_exceeded",
})


def error_type(error):
    """Finite categories; exception class names and messages may contain data."""
    for cls, label in ((subprocess.TimeoutExpired, "timeout"), (TimeoutError, "timeout"),
                       (KeyboardInterrupt, "interrupted"), (SystemExit, "interrupted"),
                       (OSError, "io_error"), (ValueError, "invalid_data"), (RuntimeError, "rehearsal_error")):
        if isinstance(error, cls):
            return label
    return "unexpected_error"


class Rehearsal(AUTHORITY["Rehearsal"]):
    def __init__(self, output, entry, authority_entry, operator_entry, receipt):
        super().__init__(output, entry, authority_entry, receipt)
        self.operator_entry = operator_entry
        self.operator_policy = None
        self.operator_policy_path = None
        self.operator_policy_sha256 = None
        self.assessments = []
        self.checks = {}
        self.counts = {}
        self.application_path = Path(importlib.metadata.distribution("dharmic-agora").locate_file("agora/app.py")).resolve()

    def check(self, code, condition=True):
        require(condition, code)
        self.checks[code] = True

    def spawn(self, label, command, cwd, environment, **options):
        if environment.get("SAB_PUBLIC_MODE") == "local":
            environment = {**environment, "SAB_OPERATOR_CONTROL_POLICY_PATH": str(self.operator_policy_path),
                           "SAB_OPERATOR_CONTROL_POLICY_SHA256": self.operator_policy_sha256}
        return super().spawn(label, command, cwd, environment, **options)

    def cli(self, label, *arguments, expected=0):
        """Retain digests only: some installed CLIs emit full signed documents."""
        child = self.spawn(label, [sys.executable, "-I", "-B", str(self.entry), *map(str, arguments)],
                           self.participant, HARNESS["ENV"])
        process, record = child
        try:
            stdout, stderr = process.communicate(timeout=CLI_TIMEOUT)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            try:
                self.finish(child)
            except BaseException:
                pass  # Final cleanup independently attempts every owned child.
            raise RuntimeError("cli_time_budget_exceeded") from None
        record.update(exit_code=process.returncode, stopped=True, expected_exit=process.returncode == expected)
        self.record_output(record, stdout, stderr)
        self.safe(stdout + stderr)
        require(record["expected_exit"], "unexpected_cli_exit")
        result = json.loads(stdout if expected == 0 else stderr)
        self.receipt["observations"].append({"kind": "cli", "label": label, "exit_code": process.returncode,
                                              "response_sha256": sha(encoded(result))})
        return result

    def record_output(self, record, stdout, stderr):
        """The only child-output writer: closed metadata, including on failure."""
        for suffix, content in (("stdout", stdout), ("stderr", stderr)):
            path = self.output / f"{record['label']}-{suffix}.log"
            data = encoded({"bytes": len(content), "sha256": sha(content), "exit_code": record.get("exit_code")}) + b"\n"
            if not path.exists():
                write_private(path, data)
            else:
                require(path.read_bytes() == data, "retained_log_changed")
        record["logs_recorded"] = True

    def expected_runtime(self, process, record):
        require(record.get("mode") in {"local", "public_readonly"}, "runtime_identity_invalid")
        local = record["mode"] == "local"
        return {"pid": process.pid, "module": str(self.application_path), "mode": record["mode"],
                "key_control_available": local, "system_key_loaded": local,
                "authority_service_available": local, "authority_policy_loaded": local}

    def capture_runtime(self, process, record, stdout):
        """Validate raw identity only in memory; preserve a digest, never its text."""
        def unique_pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate")
                result[key] = value
            return result

        try:
            markers = [line[len(RUNTIME_PREFIX):] for line in stdout.splitlines() if line.startswith(RUNTIME_PREFIX)]
            if len(markers) != 1 or len(markers[0]) > 8192:
                raise ValueError("marker")
            runtime = json.loads(markers[0], object_pairs_hook=unique_pairs)
            expected = self.expected_runtime(process, record)
            if (not isinstance(runtime, dict) or set(runtime) != set(expected)
                    or any(type(runtime[key]) is not type(value) or runtime[key] != value for key, value in expected.items())):
                raise ValueError("identity")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise RuntimeError("runtime_identity_invalid") from None
        record["runtime_identity_sha256"] = sha(encoded(expected))

    def finish(self, child, *, expected=0):
        process, record = child
        if record["stopped"]:
            return
        if process.poll() is None:
            record["sigterm_requested"] = True
            process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            process.kill()
            self.receipt["forced_kills"] = self.receipt.get("forced_kills", 0) + 1
            stdout, stderr = process.communicate(timeout=KILL_TIMEOUT)
        expected_exit = process.returncode in ((expected, -signal.SIGTERM) if expected == 0 else (expected,))
        record.update(exit_code=process.returncode, stopped=True, expected_exit=expected_exit and not record.get("timed_out", False))
        self.record_output(record, stdout, stderr)
        self.safe(stdout + stderr)
        if "mode" in record:
            self.capture_runtime(process, record, stdout)
        require(not record.get("timed_out"), "child_stop_timeout")
        require(record["expected_exit"], "unexpected_child_exit")

    def cleanup(self):
        """One failed drain or kill must never prevent another child's cleanup."""
        for child in reversed(self.children):
            process, record = child
            try:
                self.finish(child)
            except BaseException:
                self.receipt["status"] = "failed"
                self.receipt["cleanup_failures"] = self.receipt.get("cleanup_failures", 0) + 1
                stdout, stderr = b"", b""
                try:
                    if process.poll() is None:
                        process.kill()
                        self.receipt["forced_kills"] = self.receipt.get("forced_kills", 0) + 1
                    if not record["stopped"]:
                        stdout, stderr = process.communicate(timeout=KILL_TIMEOUT)
                except BaseException:
                    record["output_incomplete"] = True
                    # Reap a killed child even if pipe collection itself failed.
                    try:
                        if process.poll() is None:
                            process.kill()
                        process.wait(timeout=KILL_TIMEOUT)
                    except BaseException:
                        self.receipt["unreaped_children"] = self.receipt.get("unreaped_children", 0) + 1
                    for stream in (process.stdout, process.stderr):
                        try:
                            if stream is not None:
                                stream.close()
                        except BaseException:
                            pass
                finally:
                    record.update(exit_code=process.poll(), stopped=process.poll() is not None, expected_exit=False)
                    if not record.get("logs_recorded"):
                        try:
                            self.record_output(record, stdout, stderr)
                        except BaseException:
                            self.receipt["log_failures"] = self.receipt.get("log_failures", 0) + 1

    def operator_cli(self, label, *arguments, expected=0):
        original = self.entry
        self.entry = self.operator_entry
        try:
            result = self.cli(label, *arguments, expected=expected)
            require(result.get("authority_effect") == result.get("standing_effect") == "none",
                    "operator_cli_observation_claimed_effect")
            require(result.get("current_use_eligible", False) is False,
                    "operator_cli_observation_claimed_current_authority")
            return result
        finally:
            self.entry = original

    def operator_args(self):
        return ("--policy-file", self.operator_policy_path, "--policy-sha256", self.operator_policy_sha256)

    def provision(self, origin):
        now = datetime.now(timezone.utc)
        pins = {name: {"subject_id": self.identities[name], "public_key": self.public_keys[name]}
                for name in ("issuer", "witness")}
        interval = {"not_before": (now - timedelta(minutes=1)).isoformat(),
                    "expires_at": (now + timedelta(hours=1)).isoformat()}
        authority = {"schema": "sab.authority_policy.v1", "audience": origin,
                     "policy_id": "sab_policy_installed_operator", **interval,
                     "issuers": [{**pins["issuer"], "allowed_actions": [ACTION], "allowed_seed_ids": [SEED],
                                  "all_seeds": False, "max_ttl_seconds": 1800,
                                  "revoker_ids": [self.identities["issuer"]]}],
                     "witnesses": [pins["witness"]], "revokers": [pins["issuer"]]}
        self.original_policy = authority
        self.original_policy_path = self.configuration / "authority-policy.json"
        self.original_policy_hash = sha(encoded(authority))
        self.authority_policy_path, self.authority_policy_sha256 = self.original_policy_path, self.original_policy_hash
        write_private(self.original_policy_path, encoded(authority))
        self.operator_policy = {"schema": "sab.operator_control_policy.v1",
                                "policy_id": "sab_operator_policy_installed_synthetic", "audience": origin, **interval,
                                "max_assessment_ttl_seconds": 1800, "max_evidence_age_seconds": 1800,
                                "max_common_funding_ppm": 0,
                                "reviewers": sorted(pins.values(), key=lambda p: p["subject_id"]),
                                "revokers": [pins["issuer"]]}
        self.operator_policy_path = self.configuration / "operator-policy.json"
        self.operator_policy_sha256 = sha(encoded(self.operator_policy))
        write_private(self.operator_policy_path, encoded(self.operator_policy))
        self.configuration_hashes = {path.name: sha(path.read_bytes()) for path in self.configuration.iterdir()}
        result = self.operator_cli("operator-policy-digest", "policy-digest", "--policy-file", self.operator_policy_path)
        self.check("installed_policy_digest_matches_pin", result["policy_sha256"] == self.operator_policy_sha256)

    def draft_assessment(self, origin, *, replaces=None):
        now = datetime.now(timezone.utc)
        issued, expiry = now.isoformat(), (now + timedelta(minutes=10)).isoformat()
        scope = {"seed_id": SEED, "claim_sha256": sha(encoded({"synthetic": True, "claim": "Registry pair only"})),
                 "purpose": "high_impact_witness"}
        participants, nodes, edges = [], [], []
        for index, name in enumerate(("participant", "peer")):
            subject = self.identities[name]
            participants.append({"subject_id": subject, "public_key": self.public_keys[name],
                                 "controller_class_id": f"control_synthetic_controller_{index}"})
            nodes.append({"node_id": subject, "kind": "participant"})
            for kind, relation in (("controller", "controlled_by"), ("signing_root", "signs_with"),
                                   ("administrator", "administered_by"), ("runtime", "operated_by"),
                                   ("decision_authority", "decided_by")):
                node = f"control_synthetic_{kind}_{index}"
                nodes.append({"node_id": node, "kind": kind})
                edges.append({"source": subject, "target": node, "relation": relation, "funding_ppm": None})
        graph = {"nodes": sorted(nodes, key=lambda n: n["node_id"]),
                 "edges": sorted(edges, key=lambda e: (e["source"], e["target"], e["relation"]))}
        subjects = sorted(p["subject_id"] for p in participants)
        evidence = []
        for category, source in sorted(CATEGORIES.items()):
            material = {"synthetic": True, "category": category, "scope": scope, "subject_ids": subjects,
                        "examined_graph_sha256": sha(encoded(graph)),
                        "limitation": "Invented rehearsal material; this runner controls every key."}
            evidence.append({"evidence_id": "evidence_synthetic_" + category, "category": category,
                             "source_class": source, "source_ref": "synthetic:" + category,
                             "observed_at": issued, "valid_until": expiry, "subject_ids": subjects,
                             "document": material, "document_sha256": sha(encoded(material))})
        return {"schema": "sab.operator_cohort_assessment.v1",
                "assessment_id": "sab_operator_assessment_" + secrets.token_hex(12),
                "policy_id": self.operator_policy["policy_id"], "policy_sha256": self.operator_policy_sha256,
                "audience": origin, **scope, "issued_at": issued, "expires_at": expiry,
                "participants": sorted(participants, key=lambda p: p["subject_id"]),
                "graph": graph, "evidence": evidence, "replaces": replaces}

    def make_assessment(self, origin, label, *, replaces=None, unknown=False):
        assessment = self.draft_assessment(origin, replaces=replaces)
        digest = sha(encoded(assessment))
        draft = self.participant / f"{label}-assessment.json"
        write_private(draft, encoded(assessment))
        inspection = self.operator_cli(label + "-inspect-draft", "inspect", *self.operator_args(), "--document", draft)
        require(inspection["assessment_sha256"] == digest, "assessment_inspection_digest_mismatch")
        review_paths = []
        for name in sorted(("issuer", "witness"), key=lambda n: self.identities[n]):
            message = {"reviewer_subject_id": self.identities[name], "reviewer_public_key": self.public_keys[name],
                       "assessment_sha256": digest, "observed_at": datetime.now(timezone.utc).isoformat(),
                       "findings": [{"category": category, "evidence_ids": ["evidence_synthetic_" + category],
                                     "outcome": "unknown" if unknown and category == "funding" else "supported"}
                                    for category in sorted(CATEGORIES)]}
            unsigned = self.participant / f"{label}-{name}-review-draft.json"
            signed = self.participant / f"{label}-{name}-review.json"
            write_private(unsigned, encoded(message))
            self.operator_cli(label + "-sign-" + name, "sign-review", *self.operator_args(), "--document", unsigned,
                              "--assessment-file", draft, "--assessment-sha256", digest,
                              "--key-file", self.keys[name], "--actor-id", self.identities[name], "--output", signed)
            review_paths.append(signed)
        envelope_path = self.participant / f"{label}-envelope.json"
        self.operator_cli(label + "-assemble", "assemble", *self.operator_args(), "--assessment-file", draft,
                          "--review-file", review_paths[0], "--review-file", review_paths[1], "--output", envelope_path)
        self.remember_participant_files()
        envelope = json.loads(envelope_path.read_bytes())
        inspected = self.operator_cli(label + "-inspect", "inspect", *self.operator_args(), "--document", envelope_path)
        require(inspected["signature_integrity"] == "valid_under_pinned_policy", "signed_reviews_failed_inspection")
        issued = self.operator_cli(label + "-issue", "issue", *self.operator_args(), "--origin", origin,
                                  "--document", envelope_path)
        require(issued["receipt_matched"] and issued["assessment_sha256"] == digest, "issuance_receipt_mismatch")
        item = {"assessment": assessment, "envelope": envelope, "digest": digest, "draft": draft,
                "document": envelope_path, "label": label}
        self.assessments.append(item)
        return item

    def observe(self, origin, item, expected, *, label):
        before = self.snapshot()
        result = self.operator_cli(label, "get", *self.operator_args(), "--origin", origin,
                                   "--assessment-id", item["assessment"]["assessment_id"],
                                   "--assessment-sha256", item["digest"])
        observed = self.http(origin, "/api/operator-control/assessments/" + item["assessment"]["assessment_id"])
        require(result["receipt_matched"] and observed["status"] == expected, "registry_observation_mismatch")
        require(all(observed[field] == item["envelope"][field] for field in ("assessment", "reviews")),
                "observation_rewrote_signed_history")
        require(observed["authority_effect"] == observed["standing_effect"] == "none", "registry_observation_claimed_effect")
        self.check("registry_reads_leave_database_unchanged", before == self.snapshot())
        return observed

    @staticmethod
    def replacement(item, challenge_ids=()):
        return {"assessment_id": item["assessment"]["assessment_id"], "assessment_sha256": item["digest"],
                "challenge_ids": sorted(challenge_ids)}

    def grant_proposal(self, origin):
        now = datetime.now(timezone.utc)
        lease_id = "sab_lease_installed_operator_" + secrets.token_hex(12)
        lease = {"schema": "sab.authority_lease.v2", "lease_id": lease_id, "audience": origin,
                 "policy_hash": self.original_policy_hash, "subject_id": self.identities["participant"],
                 "subject_public_key": self.public_keys["participant"], "issuer_id": self.identities["issuer"],
                 "issuer_public_key": self.public_keys["issuer"], "target_seed_id": SEED,
                 "purpose": "Synthetic assessment challenge", "scope": "Challenge this exact synthetic seed's operator evidence",
                 "allowed_actions": [ACTION], "forbidden_actions": [], "allowed_reliance": [],
                 "forbidden_reliance": ["standing", "independent_operator", "truth"],
                 "issued_at": now.isoformat(), "expires_at": (now + timedelta(minutes=15)).isoformat(),
                 "revoker_id": self.identities["issuer"], "revoker_public_key": self.public_keys["issuer"],
                 "challenge_path": f"/api/v1/authority/leases/{lease_id}/challenges",
                 "evidence_refs": ["synthetic:installed-operator-control"]}
        draft, signed, witnessed = (self.participant / name for name in (
            "challenge-grant-draft.json", "challenge-grant-issuer.json", "challenge-grant-envelope.json"))
        write_private(draft, encoded(lease))
        intent = ("--subject-id", self.identities["participant"], "--seed-id", SEED, "--action", ACTION)
        self.authority_cli("grant-sign", "sign-lease", *self.policy_args(), "--document", draft,
                           "--key-file", self.keys["issuer"], *intent, "--output", signed)
        self.authority_cli("grant-witness", "witness", *self.policy_args(), "--document", signed,
                           "--key-file", self.keys["witness"], "--witness-id", self.identities["witness"],
                           *intent, "--output", witnessed)
        self.remember_participant_files()
        envelope = json.loads(witnessed.read_bytes())
        return {**envelope, "document": witnessed, "lease_sha256": sha(encoded({
            field: envelope[field] for field in ("lease", "issuer_signature")}))}

    def command(self, origin, item, action, *, grant=None):
        field, role, actor = ("challenge", "participant", "challenger") if action == "challenge" else ("revocation", "issuer", "revoker")
        id_field = "challenge_id" if action == "challenge" else "revocation_id"
        prefix = "sab_operator_challenge_" if action == "challenge" else "sab_operator_revoke_"
        now = datetime.now(timezone.utc)
        message = {"schema": "sab.operator_control_" + field + ".v1", id_field: prefix + secrets.token_hex(12),
                   "assessment_id": item["assessment"]["assessment_id"], "assessment_sha256": item["digest"],
                   "audience": origin, actor + "_subject_id": self.identities[role],
                   actor + "_public_key": self.public_keys[role], "reason": "Synthetic custody material requires retirement",
                   "issued_at": now.isoformat(), "expires_at": (now + timedelta(seconds=120)).isoformat()}
        if action == "challenge":
            message.update(evidence_ref="synthetic:contradicting-custody", authority_lease=self.grant_reference(grant),
                           authority_lease_sha256=grant["lease_sha256"])
        path = self.participant / f"{item['label']}-{action}-draft.json"
        write_private(path, encoded(message))
        self.remember_participant_files()
        return {"message": message, "document": path, "role": role, "field": field, "action": action}

    def send_command(self, origin, item, command, label, *, expected=0):
        return self.operator_cli(label, command["action"], *self.operator_args(), "--origin", origin,
                                 "--document", command["document"], "--assessment-file", item["draft"],
                                 "--assessment-sha256", item["digest"], "--key-file", self.keys[command["role"]],
                                 "--actor-id", self.identities[command["role"]], expected=expected)

    def signed_command(self, command):
        from agora.key_control_client import load_signing_key

        # Ed25519 is deterministic: reconstruct the exact bytes that the real
        # installed CLI just signed, solely for an unchanged HTTP retry.
        signature = load_signing_key(self.keys[command["role"]]).sign(encoded(command["message"])).signature.hex()
        return {command["field"]: command["message"], "signature": signature}

    def exercise(self):
        registrations = {}
        for name in ("issuer", "witness", "participant", "peer"):
            path = self.participant / f"{name}.key"
            public = self.cli("keygen-" + name, "keygen", "--key-file", path)
            require(stat.S_IMODE(path.stat().st_mode) == 0o600, "participant_key_not_private")
            self.keys[name], self.identities[name], self.public_keys[name] = path, public["subject_id"], public["public_key"]
            registrations[name] = self.participant / f"{name}-registration.json"
            write_private(registrations[name], encoded({"display_name": "Synthetic registry " + name,
                                                        "public_key": public["public_key"]}))
        self.remember_participant_files()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
            self.provision(origin)
            first, _ = self.start("local-registry", "local", listener)
            for name in registrations:
                self.cli("enroll-" + name, "enroll", "--origin", origin, "--key-file", self.keys[name],
                         "--registration", registrations[name])
            policy = self.http(origin, "/api/operator-control/policy")
            self.check("http_policy_matches_explicit_pin", policy["policy"] == self.operator_policy
                       and policy["policy_sha256"] == self.operator_policy_sha256)
            unknown = self.make_assessment(origin, "unknown", unknown=True)
            observation = self.observe(origin, unknown, "ineligible", label="unknown-get")
            self.check("signatures_do_not_force_verified", observation["observation"]["grade"] != "verified"
                       and not observation["observation"]["eligible"])
            primary = self.make_assessment(origin, "primary", replaces=self.replacement(unknown))
            observed = self.observe(origin, primary, "eligible", label="primary-get")
            self.check("exact_two_member_pair_reviewed", observed["observation"]["participant_count"] == 2
                       and len(observed["observation"]["pairs"]) == 1)
            grant = self.grant_proposal(origin)
            challenge = self.command(origin, primary, "challenge", grant=grant)
            before = self.snapshot()
            self.send_command(origin, primary, challenge, "ungranted-challenge", expected=1)
            self.check("ungranted_cli_challenge_has_no_effect", before == self.snapshot())
            path = "/api/operator-control/assessments/" + primary["assessment"]["assessment_id"] + "/challenge"
            self.denied_http("ungranted_http_challenge", origin, path, self.signed_command(challenge), 428)
            issued = self.authority_cli("grant-issue", "issue", *self.policy_args(), "--origin", origin,
                                        "--document", grant["document"])
            self.check("genuine_exact_challenge_grant_issued", issued["reported_status"] == "active"
                       and issued["lease_sha256"] == grant["lease_sha256"])
            result = self.send_command(origin, primary, challenge, "granted-challenge")
            command = self.signed_command(challenge)
            require(result["receipt_matched"] and result["command_sha256"] == sha(encoded(command)),
                    "challenge_receipt_digest_mismatch")
            self.observe(origin, primary, "challenged", label="challenged-get")
            self.check("granted_challenge_suspends_eligibility")
            before = self.snapshot()
            retry = self.http(origin, path, command)
            self.check("exact_challenge_retry_has_no_effect", not retry["created"] and before == self.snapshot())
            replacement = self.make_assessment(origin, "replacement", replaces=self.replacement(
                primary, [challenge["message"]["challenge_id"]]))
            self.observe(origin, replacement, "eligible", label="replacement-get")
            self.check("fresh_signed_replacement_acknowledges_challenge")
            revoke = self.command(origin, replacement, "revoke")
            result = self.send_command(origin, replacement, revoke, "configured-revocation")
            command = self.signed_command(revoke)
            require(result["receipt_matched"] and result["command_sha256"] == sha(encoded(command)),
                    "revocation_receipt_digest_mismatch")
            path = "/api/operator-control/assessments/" + replacement["assessment"]["assessment_id"] + "/revoke"
            before = self.snapshot()
            retry = self.http(origin, path, command)
            self.check("exact_revocation_retry_has_no_effect", not retry["created"] and before == self.snapshot())
            self.observe(origin, replacement, "revoked", label="revoked-get")
            self.finish(first)
            second, _ = self.start("local-registry-restarted", "local", listener)
            for item, status in ((unknown, "superseded"), (primary, "challenged"), (replacement, "revoked")):
                self.observe(origin, item, status, label="restart-" + item["label"])
                before = self.snapshot()
                retried = self.http(origin, "/api/operator-control/assessments", item["envelope"], expected=201)
                require(retried["status"] == status and not retried["created"] and before == self.snapshot(),
                        "issuance_retry_resurrected_assessment")
            self.check("restart_and_issuance_retries_never_resurrect")
            self.finish(second)
        conn = sqlite3.connect((self.server / "spark.db").as_uri() + "?mode=ro", uri=True)
        try:
            actual = {"assessments": conn.execute("SELECT count(*) FROM sab_operator_assessments_v1").fetchone()[0],
                      "challenges": conn.execute("SELECT count(*) FROM sab_operator_events_v1 WHERE kind='challenge'").fetchone()[0],
                      "revocations": conn.execute("SELECT count(*) FROM sab_operator_events_v1 WHERE kind='revoke'").fetchone()[0],
                      "authority_grants": conn.execute("SELECT count(*) FROM sab_authority_grants_v2").fetchone()[0],
                      "standing_records": conn.execute("SELECT count(*) FROM sab_standing_leases_v1").fetchone()[0]}
        finally:
            conn.close()
        self.check("bounded_expected_history_only", actual == {"assessments": 3, "challenges": 1, "revocations": 1,
                                                              "authority_grants": 1, "standing_records": 0})
        self.counts.update(actual, cohort_members=2, review_pins=2, synthetic_keys=4)
        self.receipt["final_database_sha256"] = self.snapshot()

    def audit(self):
        # The inherited auditor requires raw runtime logs. Keep its filesystem
        # and process checks, but validate our closed logs and in-memory marker.
        allowed_server = {"spark.db", "spark.db-journal", "spark.db-wal", "spark.db-shm", "system.key"}
        for path in self.server.rglob("*"):
            require(path.is_file() and not path.is_symlink() and path.parent == self.server
                    and path.name in allowed_server, "unexpected_server_write")
            self.safe(path.read_bytes())
        require(not self.canary.exists() and not any(self.public_cwd.iterdir()), "public_runtime_wrote_private_files")
        require(all(path.is_file() and not path.is_symlink() for path in self.participant.iterdir()),
                "unexpected_participant_entry")
        require({path.name: sha(path.read_bytes()) for path in self.participant.iterdir()} == self.participant_hashes,
                "participant_files_changed")
        require({path.name: sha(path.read_bytes()) for path in self.configuration.iterdir()} == self.configuration_hashes,
                "explicit_policy_files_changed")
        for path in self.output.glob("*.log"):
            raw = path.read_bytes()
            self.safe(raw)
            value = json.loads(raw)
            require(isinstance(value, dict) and set(value) == {"bytes", "sha256", "exit_code"}
                    and type(value["bytes"]) is int and value["bytes"] >= 0
                    and isinstance(value["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
                    and (value["exit_code"] is None or type(value["exit_code"]) is int), "retained_log_not_closed")
        for process, record in self.children:
            require(process.poll() is not None and record["stopped"] and record.get("expected_exit")
                    and record.get("logs_recorded"), "owned_process_not_cleanly_stopped")
            if "mode" in record:
                require(record.get("runtime_identity_sha256") == sha(encoded(self.expected_runtime(process, record))),
                        "runtime_identity_invalid")
        self.check("all_retained_logs_are_closed_metadata")
        self.check("application_processes_use_installed_wheel")
        self.check("participant_and_policy_files_unchanged")
        self.check("participant_seeds_absent_from_server_logs_and_receipt")
        self.check("all_owned_processes_cleanly_stopped")


def run_rehearsal(run, artifact):
    """Exercise, clean up every owned child, then write a sanitized observation."""
    internal = run.receipt
    try:
        run.exercise()
        internal["status"] = "passed"
    except BaseException as error:
        internal.update(status="failed", error_type=error_type(error))
        if (type(error) is RuntimeError and error.args and isinstance(error.args[0], str)
                and error.args[0] in ERROR_CODES):
            internal["failed_check"] = error.args[0]
    finally:
        run.cleanup()
        try:
            run.audit()
        except BaseException as error:
            internal.update(status="failed", audit_error_type=error_type(error))
        receipt = {"schema": "sab.operator_control_rehearsal.v1", "status": internal["status"], "synthetic_only": True,
                   "authority_effect": "none", "standing_effect": "none", "checks": run.checks,
                   "wheel_sha256_basis": "caller_supplied_artifact_digest",
                   "counts": {**run.counts, "checks_passed": len(run.checks), "processes": len(run.children),
                              "stopped_processes": sum(p.poll() is not None for p, _ in run.children),
                              "observations": len(internal["observations"]), "denied_http_commands": len(internal["denials"]),
                              "forced_kills": internal.get("forced_kills", 0),
                              "cleanup_failures": internal.get("cleanup_failures", 0),
                              "unreaped_children": internal.get("unreaped_children", 0),
                              "incomplete_process_outputs": sum(bool(r.get("output_incomplete")) for _, r in run.children)},
                   "digests": {key: value for key, value in artifact.items() if key.endswith("sha256")}}
        for key in ("error_type", "failed_check", "audit_error_type"):
            if key in internal:
                receipt[key] = internal[key]
        receipt["digests"].update(operator_policy_sha256=run.operator_policy_sha256,
                                  final_database_sha256=internal.get("final_database_sha256"),
                                  runtime_identity_sha256=sha(encoded(sorted(r["runtime_identity_sha256"] for _, r in run.children
                                                                           if "runtime_identity_sha256" in r))),
                                  log_inventory_sha256=sha(encoded({p.name: sha(p.read_bytes()) for p in run.output.glob("*.log")})))
        try:
            run.safe(encoded(receipt))
        except BaseException:
            receipt = {"schema": "sab.operator_control_rehearsal.v1", "status": "failed",
                       "wheel_sha256_basis": "caller_supplied_artifact_digest",
                       "failed_check": "receipt_secret_scan_failed", "authority_effect": "none", "standing_effect": "none"}
        write_private(run.output / "receipt.json", encoded(receipt) + b"\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.artifact_sha256):
        parser.error("artifact-sha256 must be 64 lowercase hexadecimal characters")
    require(not Path.cwd().resolve().is_relative_to(Path(__file__).resolve().parents[1]), "use_unrelated_working_directory")
    entry, artifact = HARNESS["provenance"](args.artifact_sha256)
    distribution = importlib.metadata.distribution("dharmic-agora")
    entries = {}
    for name, module in (("authority", "agora.authority_client:main"), ("operator-control", "agora.operator_control_client:main")):
        path = Path(sys.executable).parent / ("agora-" + name)
        require(path.is_file() and any(e.name == "agora-" + name and e.value == module for e in distribution.entry_points),
                "installed_entrypoint_missing")
        entries[name] = path
        artifact[name.replace("-", "_") + "_entrypoint_sha256"] = sha(path.read_bytes())
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    internal = {"status": "running", "processes": [], "observations": [], "denials": []}
    run = Rehearsal(output, entry, entries["authority"], entries["operator-control"], internal)
    receipt = run_rehearsal(run, artifact)
    print(json.dumps({"status": receipt["status"], "receipt": str(output / "receipt.json")}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
