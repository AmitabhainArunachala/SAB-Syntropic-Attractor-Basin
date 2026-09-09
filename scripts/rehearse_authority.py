#!/usr/bin/env python3
"""Exercise installed SAB authority CLI and HTTP with three synthetic local keys.

Run a noneditable wheel's python -I -B from an unrelated working directory.
The adjacent key-control harness owns all child process cleanup and seed scans.
Only receipt.json and root logs are suitable for retained CI artifacts; never
upload the participant, configuration or server directories.
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
import socket
import sqlite3
import stat
import sys
import time

# Load only the trusted adjacent orchestration script. It imports Agora inside
# methods, so -I still resolves every application module from the installed wheel.
HARNESS = runpy.run_path(str(Path(__file__).with_name("rehearse_key_control.py")), run_name="sab_installed_rehearsal")
require = HARNESS["require"]
encoded = HARNESS["encoded"]
sha = HARNESS["sha"]
write_private = HARNESS["write_private"]
signed_seed = HARNESS["signed_seed"]
SEED = "sab_seed_installed_authority_rehearsal"
ACTIONS = ["submit_seed", "correct_seed"]


class Rehearsal(HARNESS["Rehearsal"]):
    def __init__(self, output, entry, authority_entry, receipt):
        super().__init__(output, entry, receipt)
        self.authority_entry = authority_entry
        self.configuration = output / "configuration"
        self.configuration.mkdir(mode=0o700)
        self.configuration_hashes = {}
        self.keys = {}
        self.identities = {}
        self.public_keys = {}
        self.original_policy = None
        self.original_policy_path = None
        self.original_policy_hash = None
        self.grants = []

    def remember_participant_files(self):
        current = {path.name: sha(path.read_bytes()) for path in self.participant.iterdir()}
        require(all(current.get(name) == digest for name, digest in self.participant_hashes.items()),
                "previous_participant_file_changed")
        self.participant_hashes = current

    def authority_cli(self, label, *arguments, expected=0):
        key_control_entry = self.entry
        self.entry = self.authority_entry
        try:
            return self.cli(label, *arguments, expected=expected)
        finally:
            self.entry = key_control_entry

    def policy_args(self):
        return ("--policy-file", self.original_policy_path, "--policy-sha256", self.original_policy_hash)

    def snapshot(self):
        conn = sqlite3.connect((self.server / "spark.db").as_uri() + "?mode=ro", uri=True)
        try:
            result = encoded(list(conn.iterdump()))
            self.safe(result)
            return sha(result)
        finally:
            conn.close()

    def denied_http(self, label, origin, path, payload, expected):
        before = self.snapshot()
        result = self.http(origin, path, payload, expected=expected)
        require(self.snapshot() == before, "denied_command_changed_durable_state")
        self.receipt["denials"].append({"label": label, "status": expected,
                                       "state_sha256_before_and_after": before})
        return result

    def grant_reference(self, grant):
        lease = grant["lease"]
        return {"lease_ref": lease["lease_id"], "scope": lease["scope"], "expires_at": lease["expires_at"],
                "revoker": lease["revoker_id"], "challenge_path": lease["challenge_path"]}

    def correction(self):
        from agora.key_control_client import load_signing_key

        created = datetime.now(timezone.utc).isoformat()
        correction = {"text": "Synthetic local clarification; no standing or reliance is inferred."}
        message = {"kind": "sab_seed_correct", "target_seed_id": SEED,
                   "actor_identity": self.identities["participant"], "correction_sha256": sha(encoded(correction)),
                   "created_at": created}
        return {"actor_identity": self.identities["participant"], "created_at": created, "correction": correction,
                "signature": load_signing_key(self.keys["participant"]).sign(encoded(message)).signature.hex()}

    def make_grant(self, origin, name, *, ttl_seconds=300):
        now = datetime.now(timezone.utc)
        lease_id = "sab_lease_installed_authority_" + name
        lease = {
            "schema": "sab.authority_lease.v2", "lease_id": lease_id, "audience": origin,
            "policy_hash": self.original_policy_hash, "subject_id": self.identities["participant"],
            "subject_public_key": self.public_keys["participant"], "issuer_id": self.identities["issuer"],
            "issuer_public_key": self.public_keys["issuer"], "target_seed_id": SEED,
            "purpose": "Synthetic installed permission check", "scope": "One exact synthetic seed",
            "allowed_actions": ACTIONS, "forbidden_actions": [], "allowed_reliance": [],
            "forbidden_reliance": ["standing", "independent_operator", "truth"],
            "issued_at": (now - timedelta(seconds=1)).isoformat(),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
            "revoker_id": self.identities["issuer"], "revoker_public_key": self.public_keys["issuer"],
            "challenge_path": f"/api/v1/authority/leases/{lease_id}/challenges",
            "evidence_refs": ["test:synthetic-installed-issuance"],
        }
        draft = self.participant / f"{name}-draft.json"
        issuer_signed = self.participant / f"{name}-issuer.json"
        witnessed = self.participant / f"{name}-witnessed.json"
        write_private(draft, encoded(lease))
        intent = ("--subject-id", self.identities["participant"], "--seed-id", SEED,
                  "--action", "submit_seed", "--action", "correct_seed")
        self.authority_cli("sign-" + name, "sign-lease", *self.policy_args(), "--document", draft,
                           "--key-file", self.keys["issuer"], *intent, "--output", issuer_signed)
        self.authority_cli("witness-" + name, "witness", *self.policy_args(), "--document", issuer_signed,
                           "--key-file", self.keys["witness"], "--witness-id", self.identities["witness"],
                           *intent, "--output", witnessed)
        self.remember_participant_files()
        result = self.authority_cli("issue-" + name, "issue", *self.policy_args(), "--origin", origin,
                                   "--document", witnessed)
        require(result["reported_status"] == "active", "issued_grant_not_reported_active")
        observed = self.authority_cli("inspect-" + name, "inspect", *self.policy_args(), "--origin", origin,
                                     "--lease-id", lease_id)
        require(observed == result, "inspect_changed_signed_issuance")
        signed = json.loads(witnessed.read_bytes())
        require(all(result[key] == signed[key] for key in signed), "installed_cli_changed_signed_grant")
        grant = {**signed, "lease_id": lease_id, "lease_sha256": result["lease_sha256"],
                 "envelope_sha256": result["envelope_sha256"], "document": witnessed}
        self.grants.append(grant)
        return grant

    def retire(self, origin, grant, name):
        result = self.authority_cli("revoke-" + name, "revoke", *self.policy_args(), "--origin", origin,
                                   "--document", grant["document"], "--key-file", self.keys["issuer"],
                                   "--reason", "Retire synthetic installed permission")
        require(result["receipt_matched"], "revocation_signed_receipt_did_not_match")
        observation = self.http(origin, "/api/v1/authority/leases/" + grant["lease_id"])
        require(observation["status"] == "revoked", "revocation_not_durable")
        require(all(observation[key] == grant[key] for key in ("lease", "issuer_signature", "issuance_witness")),
                "retirement_rewrote_issuance")
        before = self.snapshot()
        self.http(origin, "/api/v1/authority/leases/" + grant["lease_id"] + "/revoke",
                  {"revocation": result["revocation"], "signature": result["signature"]})
        require(before == self.snapshot(), "exact_revocation_retry_changed_history")

    def denied_use(self, origin, grant, name, *, seed_status):
        self.denied_http(name + "-correction", origin, f"/api/v1/seeds/{SEED}/correct", self.correction(), 428)
        self.denied_http(name + "-seed", origin, "/api/v1/seeds", signed_seed(
            self.identities["participant"], self.keys["participant"], SEED, self.grant_reference(grant)), seed_status)

    def provision(self, origin):
        now = datetime.now(timezone.utc)
        policy = {
            "schema": "sab.authority_policy.v1", "audience": origin,
            "policy_id": "sab_policy_installed_authority_original",
            "not_before": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "issuers": [{"subject_id": self.identities["issuer"], "public_key": self.public_keys["issuer"],
                         "allowed_actions": ACTIONS, "allowed_seed_ids": [SEED], "all_seeds": False,
                         "max_ttl_seconds": 3600, "revoker_ids": [self.identities["issuer"]]}],
            "witnesses": [{"subject_id": self.identities["witness"], "public_key": self.public_keys["witness"]}],
            "revokers": [{"subject_id": self.identities["issuer"], "public_key": self.public_keys["issuer"]}],
        }
        path = self.configuration / "original-policy.json"
        write_private(path, encoded(policy))
        self.original_policy, self.original_policy_path, self.original_policy_hash = policy, path, sha(encoded(policy))
        self.authority_policy_path, self.authority_policy_sha256 = path, self.original_policy_hash
        changed = {**policy, "policy_id": "sab_policy_installed_authority_changed"}
        changed_path = self.configuration / "changed-policy.json"
        write_private(changed_path, encoded(changed))
        self.configuration_hashes = {item.name: sha(item.read_bytes()) for item in self.configuration.iterdir()}
        digest = self.authority_cli("policy-digest", "policy-digest", "--policy-file", path)
        require(digest["policy_sha256"] == self.original_policy_hash, "installed_policy_digest_disagrees")
        return changed_path, sha(encoded(changed))

    def exercise(self):
        registrations = {}
        for name in ("issuer", "witness", "participant"):
            path = self.participant / f"{name}.key"
            public = self.cli("keygen-" + name, "keygen", "--key-file", path)
            require(stat.S_IMODE(path.stat().st_mode) == 0o600, "participant_key_not_0600")
            self.keys[name], self.identities[name], self.public_keys[name] = path, public["subject_id"], public["public_key"]
            registration = self.participant / f"{name}-registration.json"
            write_private(registration, encoded({"display_name": "Synthetic authority " + name, "public_key": public["public_key"]}))
            registrations[name] = registration
        self.remember_participant_files()
        with socket.socket() as local, socket.socket() as public:
            for listener in (local, public):
                listener.bind(("127.0.0.1", 0))
                listener.listen(16)
            origin = f"http://127.0.0.1:{local.getsockname()[1]}"
            changed_path, changed_digest = self.provision(origin)
            first, _ = self.start("local-original", "local", local)
            for name in ("issuer", "witness", "participant"):
                self.cli("enroll-" + name, "enroll", "--origin", origin, "--key-file", self.keys[name],
                         "--registration", registrations[name])
            observed_policy = self.http(origin, "/api/v1/authority/policy")
            require(observed_policy["policy"] == self.original_policy and observed_policy["policy_hash"] == self.original_policy_hash,
                    "server_changed_configured_policy")
            self.denied_http("enrollment_without_issuance", origin, "/api/v1/seeds", signed_seed(
                self.identities["participant"], self.keys["participant"], SEED,
                {"lease_ref": "sab_lease_installed_missing"}), 404)
            primary = self.make_grant(origin, "primary")
            before = self.snapshot()
            duplicate = self.http(origin, "/api/v1/authority/leases", json.loads(primary["document"].read_bytes()))
            require(not duplicate["created"] and before == self.snapshot(), "duplicate_issuance_changed_history")
            self.denied_http("wrong_exact_seed", origin, "/api/v1/seeds", signed_seed(
                self.identities["participant"], self.keys["participant"], "sab_seed_outside_installed_scope",
                self.grant_reference(primary)), 403)
            seed = self.http(origin, "/api/v1/seeds", signed_seed(self.identities["participant"], self.keys["participant"],
                                                                SEED, self.grant_reference(primary)), expected=201)
            require(seed["accepted"], "granted_seed_not_accepted")
            correction = self.http(origin, f"/api/v1/seeds/{SEED}/correct", self.correction())
            require(correction["state"] == "corrected", "granted_correction_not_applied")
            history_path = f"/api/v1/seeds/{SEED}/chain"
            original_history = self.http(origin, history_path)
            require(len(original_history["entries"]) == 2, "authorized_witness_history_missing")
            for event in original_history["entries"]:
                authority = event.get("authority") or event["payload"].get("authority")
                require(authority and authority["lease_id"] == primary["lease_id"]
                        and authority["lease_sha256"] == primary["lease_sha256"], "selected_authority_missing_from_history")
            self.retire(origin, primary, "primary")
            self.denied_use(origin, primary, "revoked", seed_status=403)

            expiring = self.make_grant(origin, "expiry", ttl_seconds=15)
            expires = datetime.fromisoformat(expiring["lease"]["expires_at"].replace("Z", "+00:00"))
            expiry_deadline = time.monotonic() + 20
            while datetime.now(timezone.utc) < expires:
                require(first[0].poll() is None, "server_stopped_before_expiry_observation")
                require(time.monotonic() < expiry_deadline, "expiry_observation_time_budget_exceeded")
                time.sleep(min(0.25, max(0, (expires - datetime.now(timezone.utc)).total_seconds())))
            before = self.snapshot()
            observed = self.http(origin, "/api/v1/authority/leases/" + expiring["lease_id"])
            require(observed["status"] == "expired", "inclusive_grant_expiry_not_observed")
            require(before == self.snapshot(), "expiry_read_changed_durable_state")
            self.denied_use(origin, expiring, "expired", seed_status=410)
            self.retire(origin, expiring, "expired")

            changed_grant = self.make_grant(origin, "policy")
            self.finish(first)
            self.authority_policy_path, self.authority_policy_sha256 = changed_path, changed_digest
            second, _ = self.start("local-policy-changed", "local", local)
            observed = self.http(origin, "/api/v1/authority/leases/" + changed_grant["lease_id"])
            require(observed["status"] == "inactive" and observed["reason_code"] == "authority_policy_changed",
                    "changed_policy_did_not_disable_old_grant")
            self.denied_use(origin, changed_grant, "policy_changed", seed_status=403)
            self.retire(origin, changed_grant, "original_policy_after_change")
            self.finish(second)
            self.authority_policy_path, self.authority_policy_sha256 = self.original_policy_path, self.original_policy_hash
            third, _ = self.start("local-policy-restored", "local", local)
            for grant in self.grants:
                observed = self.http(origin, "/api/v1/authority/leases/" + grant["lease_id"])
                require(observed["status"] == "revoked", "restart_or_policy_restore_resurrected_grant")
            before = self.snapshot()
            replay = self.http(origin, "/api/v1/authority/leases", json.loads(primary["document"].read_bytes()))
            require(replay["status"] == "revoked" and not replay["created"] and before == self.snapshot(),
                    "duplicate_issuance_resurrected_retired_grant")

            key_grant = self.make_grant(origin, "key_retirement")
            self.cli("retire-witness-key", "revoke", "--origin", origin, "--key-file", self.keys["witness"],
                     "--subject-id", self.identities["witness"])
            observed = self.http(origin, "/api/v1/authority/leases/" + key_grant["lease_id"])
            require(observed["status"] == "inactive" and observed["reason_code"] == "authority_key_inactive",
                    "retired_witness_key_left_grant_active")
            self.denied_use(origin, key_grant, "witness_key_retired", seed_status=403)
            self.retire(origin, key_grant, "retired_issuance_witness")
            self.cli("retire-participant-key", "revoke", "--origin", origin, "--key-file", self.keys["participant"],
                     "--subject-id", self.identities["participant"])
            self.denied_http("participant_key_retired", origin, f"/api/v1/seeds/{SEED}/correct", self.correction(), 403)
            require(self.http(origin, history_path) == original_history, "retirement_changed_original_witness_history")
            self.finish(third)
            reader, public_origin = self.start("public-reader", "public_readonly", public)
            for route in ("/api/v1/authority/policy", "/api/v1/authority/leases/" + primary["lease_id"],
                          primary["lease"]["challenge_path"]):
                self.http(public_origin, route, expected=404)
            for route in ("/api/v1/authority/leases", "/api/v1/authority/leases/" + primary["lease_id"] + "/revoke",
                          primary["lease"]["challenge_path"]):
                self.http(public_origin, route, expected=403, raw=b"not valid JSON")
                require(not self.canary.exists(), "public_authority_command_created_private_state")
            self.finish(reader)
        conn = sqlite3.connect((self.server / "spark.db").as_uri() + "?mode=ro", uri=True)
        try:
            require(conn.execute("SELECT count(*) FROM sab_authority_grants_v2 WHERE status='revoked'").fetchone()[0] == 4,
                    "unexpected_durable_grant_states")
            require(conn.execute("SELECT count(*) FROM sab_authority_events_v2").fetchone()[0] == 8,
                    "signed_authority_history_missing")
            require(conn.execute("SELECT count(*) FROM sab_authority_leases_v1").fetchone()[0] == 0,
                    "issued_grants_rewrote_legacy_declarations")
            require(conn.execute("SELECT count(*) FROM sab_standing_leases_v1").fetchone()[0] == 0,
                    "authority_granted_standing")
        finally:
            conn.close()
        self.receipt.update(real_cli_signed_issuance=True, real_granted_seed_and_correction=True,
                            expiry_and_policy_change_disable_use=True, retired_keys_disable_use=True,
                            revocation_after_expiry_policy_change_and_witness_retirement=True,
                            exact_retries_do_not_rewrite_history=True, restart_does_not_resurrect_revoked_grants=True,
                            original_witness_history_unchanged=True, original_history_sha256=sha(encoded(original_history)),
                            authority_effect="none", standing_effect="none")

    def audit(self):
        super().audit()
        require({path.name: sha(path.read_bytes()) for path in self.configuration.iterdir()} == self.configuration_hashes,
                "explicit_policy_files_changed")
        for process, record in self.children:
            if "mode" in record:
                runtime = record["runtime"]
                require(runtime["authority_service_available"] == (record["mode"] == "local")
                        and runtime["authority_policy_loaded"] == (record["mode"] == "local"),
                        "unexpected_authority_policy_loading")
        self.receipt["configuration_files_unchanged"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact-sha256", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.artifact_sha256):
        parser.error("artifact-sha256 must be 64 lowercase hexadecimal characters")
    entry, artifact = HARNESS["provenance"](args.artifact_sha256)
    authority_entry = Path(sys.executable).parent / "agora-authority"
    distribution = importlib.metadata.distribution("dharmic-agora")
    require(authority_entry.is_file() and any(item.name == "agora-authority" and item.value == "agora.authority_client:main"
                                            for item in distribution.entry_points), "installed_authority_entrypoint_missing")
    artifact["authority_entrypoint_sha256"] = sha(authority_entry.read_bytes())
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    receipt = {"schema": "sab.authority_rehearsal.v1", "status": "running", "artifact": artifact,
               "synthetic_only": True, "started_at": datetime.now(timezone.utc).isoformat(),
               "processes": [], "observations": [], "denials": [], "limitations": [
                   "One local service, same-user separate directories, no filesystem sandbox or TLS.",
                   "Configured issuer and witness keys do not establish separate operators, standing or truth.",
                   "Local UTC and monotonic guards are not authenticated civil time; no multiworker claim.",
                   "Artifact digest is caller provenance; this rehearsal does not reconstruct the installed wheel.",
               ]}
    run = Rehearsal(output, entry, authority_entry, receipt)
    try:
        run.exercise()
        receipt["status"] = "passed"
    except BaseException as error:
        receipt.update(status="failed", error_type=type(error).__name__)
        if type(error) is RuntimeError and error.args and re.fullmatch(r"[a-z_]{1,100}", str(error.args[0])):
            receipt["error_code"] = str(error.args[0])
    finally:
        for child in reversed(run.children):
            try:
                run.finish(child)
            except BaseException as error:
                receipt.update(status="failed")
                receipt.setdefault("cleanup_errors", []).append({"pid": child[0].pid, "type": type(error).__name__})
        try:
            run.audit()
        except BaseException as error:
            receipt.update(status="failed", audit_error_type=type(error).__name__)
        receipt["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            run.safe(encoded(receipt))
        except BaseException:
            receipt = {"schema": "sab.authority_rehearsal.v1", "status": "failed", "error_code": "receipt_secret_scan_failed"}
        write_private(output / "receipt.json", encoded(receipt) + b"\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(output / "receipt.json")}))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
