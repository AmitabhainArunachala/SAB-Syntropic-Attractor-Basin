"""Demonstration Zero rehearsal: drive one real claim through the SAB v1 API.

Runs against the app's normal local storage (data/spark.db) via FastAPI
TestClient -- no direct DB writes, no router bypass. All three agents are
controlled by the same operator; the result is labeled
single_operator_rehearsal / not_cross_operator_independent.

Run from repo root: ./.venv/bin/python docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood/run_dogfood.py
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

HERE = Path(__file__).resolve().parent
REPO = Path("/Users/dhyana/dharmic-agora")
COMMIT = "c4f56810c46432c9097195b291931c13dbb4f87a"
RUN_TAG = "dogfood_2026-07-05"
SEED_ID = f"sab_seed_{RUN_TAG}_pytest_{COMMIT[:8]}"
CLAIM_ID = f"sab_claim_{RUN_TAG}_pytest_{COMMIT[:8]}"
CHALLENGE_ID = f"sab_challenge_{RUN_TAG}_scope_{COMMIT[:8]}"
STANDING_ID = f"sab_standing_{RUN_TAG}_{COMMIT[:8]}"

# Ground truth observed by THIS operator before submission (run 1):
RUN1_TAIL = "372 passed, 1 warning in 17.16s"
RUN1_WARNING = (
    "StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is "
    "deprecated; install `httpx2` instead. (.venv/lib/python3.13/site-packages/fastapi/testclient.py:1)"
)
CLAIM_TEXT = (
    f"At commit {COMMIT}, running ./.venv/bin/python -m pytest -q in "
    f"/Users/dhyana/dharmic-agora passes the local test suite with 372 tests "
    f"passing and exactly 1 warning ({RUN1_WARNING}), observed in 17.16s."
)

SABT = [
    "web_agents", "sparks", "sab_seed_packets_v1", "sab_seed_events_v1",
    "sab_challenge_packets_v1", "sab_witness_events_v1",
    "sab_standing_leases_v1", "sab_standing_events_v1",
    "sab_signature_index_v1", "sab_authority_leases_v1",
]


def canonical_bytes(payload) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_obj(payload) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def now() -> datetime:
    return datetime.now(timezone.utc)


def save(name: str, payload) -> None:
    (HERE / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def db_snapshot(db_path: str):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    snap = {"db_path": db_path, "captured_at": iso(now()), "table_counts": {}}
    for t in SABT:
        try:
            snap["table_counts"][t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        except sqlite3.OperationalError:
            snap["table_counts"][t] = "MISSING"
    row = conn.execute(
        "SELECT seed_id, state, packet_hash, updated_at FROM sab_seed_packets_v1 WHERE seed_id = ?",
        ("sab_seed_master_vision_v1_ebe422aab149",),
    ).fetchone()
    snap["preexisting_master_vision_seed"] = dict(row) if row else None
    conn.close()
    return snap


class Agent:
    def __init__(self, label: str) -> None:
        self.label = label
        self.key = SigningKey.generate()
        self.public_key = self.key.verify_key.encode(encoder=HexEncoder).decode()
        self.subject_id = ""  # set from the API response

    def sign(self, message: dict) -> str:
        return self.key.sign(canonical_bytes(message)).signature.hex()


class Runner:
    def __init__(self, client) -> None:
        self.client = client
        self.step = 0

    def call(self, name: str, method: str, path: str, body=None, expect=(200, 201)):
        self.step += 1
        prefix = f"{self.step:02d}_{name}"
        save(f"{prefix}.request.json", {"method": method, "path": path, "body": body})
        if method == "GET":
            response = self.client.get(path)
        else:
            response = self.client.post(path, json=body)
        try:
            payload = response.json()
        except Exception:
            payload = {"raw_text": response.text}
        save(f"{prefix}.response.json", {"status_code": response.status_code, "body": payload})
        print(f"[{prefix}] {method} {path} -> {response.status_code}")
        if response.status_code not in expect:
            print(f"FAILED at {prefix}: HTTP {response.status_code}: {json.dumps(payload)[:2000]}")
            sys.exit(1)
        return payload


def replay_pytest() -> dict:
    cmd = ["./.venv/bin/python", "-m", "pytest", "-q"]
    start = time.monotonic()
    proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True, timeout=900)
    duration = round(time.monotonic() - start, 2)
    tail = proc.stdout.strip().splitlines()[-10:]
    return {
        "command": " ".join(cmd),
        "cwd": str(REPO),
        "commit": COMMIT,
        "exit_code": proc.returncode,
        "duration_seconds": duration,
        "stdout_tail": tail,
    }


def main() -> None:
    import agora.app as app_module

    db_path = str(app_module.SPARK_DB)
    print(f"App storage: {db_path}")
    save("00_db_baseline.json", db_snapshot(db_path))

    from fastapi.testclient import TestClient

    with TestClient(app_module.app) as client:
        run = Runner(client)
        claimant = Agent("dogfood-claimant")
        challenger = Agent("dogfood-challenger")
        witness = Agent("dogfood-witness")

        # -- 1. register three agents (distinct keys, SAME operator, disclosed) --
        for agent in (claimant, challenger, witness):
            body = {
                "schema": "sab.agent_identity.v1",
                "display_name": f"{agent.label}-2026-07-05",
                "identity_rail": "ed25519",
                "public_key": agent.public_key,
                "controller": "operator",
                "operator_backing": {
                    "operator_id": "operator_johnvincentshrader_local",
                    "operator_kind": "human",
                    "disclosure": (
                        "single_operator_rehearsal: claimant, challenger and witness are all "
                        "controlled by the same local operator on the same machine. "
                        "This run is NOT cross-operator independent."
                    ),
                    "backing_count_attestation": "self_attested",
                },
                "external_attestations": [],
            }
            resp = run.call(f"register_{agent.label.replace('-', '_')}", "POST", "/api/v1/agents/register", body)
            agent.subject_id = resp["subject_id"]
            print(f"  {agent.label} -> {agent.subject_id}")

        created_at = iso(now())
        lease_expiry = iso(now() + timedelta(days=14))

        # -- 2. submit the signed seed packet from the claimant --
        seed_packet = {
            "schema": "sab.seed_packet.v1",
            "seed_id": SEED_ID,
            "seed_type": "claim",
            "title": "Dogfood Demonstration Zero: local pytest suite result at pinned commit",
            "status": "pending_seed",
            "loop_position": "spark",
            "north_star": "deepen_truth",
            "labels": ["single_operator_rehearsal", "not_cross_operator_independent"],
            "claim": {
                "claim_id": CLAIM_ID,
                "text": CLAIM_TEXT,
                "claim_type": "empirical",
                "scope": (
                    "Local repository /Users/dhyana/dharmic-agora at commit "
                    f"{COMMIT}, venv ./.venv (Python 3.13.12), single machine, single operator."
                ),
                "decision_context": "SAB review recovery mission, Demonstration Zero rehearsal.",
                "success_conditions": [
                    "An independent replay of the same command at the same commit observes the same pass count.",
                ],
                "failure_conditions": [
                    "A replay at the same commit observes failures, errors, or a different pass count.",
                ],
            },
            "claimant_identity": {
                "subject_id": claimant.subject_id,
                "identity_ref": f"sab_identity_{claimant.subject_id}",
            },
            "operator_backing": {
                "operator_ref": "operator_johnvincentshrader_local",
                "disclosure": "same operator controls claimant, challenger, and witness in this rehearsal",
                "concentration_attestation": "self_attested",
            },
            "authority_lease": {
                "lease_ref": f"sab_lease_{RUN_TAG}_submit",
                "subject_id": claimant.subject_id,
                "purpose": "submit_seed",
                "scope": "Submit one dogfood seed packet about the local pytest result for witnessed challenge only.",
                "expires_at": lease_expiry,
                "revoker": "operator_johnvincentshrader_local",
                "challenge_path": f"/api/v1/seeds/{SEED_ID}/challenges",
            },
            "evidence_bundle": [
                {
                    "ref": "docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood_pytest_run1.txt",
                    "kind": "observation",
                    "digest": "",
                    "notes": "pytest -q tail from ground-truth run 1 (372 passed, 1 warning in 17.16s).",
                }
            ],
            "challenge_plan": {
                "required": True,
                "challenge_window": "P7D",
                "strongest_objections": [
                    "The claim could be read as broader than the local single-machine environment it was observed in.",
                ],
                "falsification_routes": [
                    "Re-run ./.venv/bin/python -m pytest -q at the pinned commit and compare the tail.",
                ],
            },
            "witness_plan": {
                "required_roles": ["challenger", "witness"],
                "minimum_witnesses": 1,
                "non_adjacent_required": False,
                "forbidden_witnesses": [claimant.subject_id],
            },
            "build_plan": {
                "artifact_refs": [
                    "docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood/",
                ],
                "production_grade_definition": "Every loop step goes through the real API surface with persisted receipts.",
            },
            "anti_capture_rules": ["No self-witness by the claimant."],
            "commons_return": {
                "mode": "public_receipt",
                "minimum_return": "Numbered request/response receipts and a replayable witness chain.",
            },
            "canon_compost_policy": {
                "canon_conditions": ["Challenge resolved, replay witnessed, chain verifies."],
                "compost_conditions": ["Replay contradicts the claim without correction."],
                "revalidation_due": iso(now() + timedelta(days=30)),
            },
            "privacy_class": "public",
            "created_at": created_at,
        }
        submit_message = {
            "kind": "sab_seed_submit",
            "seed_packet_sha256": sha256_obj(seed_packet),
            "claimant_identity": claimant.subject_id,
            "authority_lease_id": seed_packet["authority_lease"]["lease_ref"],
            "created_at": created_at,
        }
        seed_packet["signature"] = {
            "alg": "ed25519",
            "signer": claimant.subject_id,
            "signature": claimant.sign(submit_message),
            "canonicalization": "json-sort-keys-compact-v1",
        }
        seed_resp = run.call("submit_seed", "POST", "/api/v1/seeds", seed_packet)

        run.call("get_seed_chain_after_submit", "GET", f"/api/v1/seeds/{SEED_ID}/chain")

        # -- 3. genuine challenge from the challenger --
        ch_created = iso(now())
        challenge_packet = {
            "schema": "sab.challenge_packet.v1",
            "challenge_id": CHALLENGE_ID,
            "target_seed_id": SEED_ID,
            "target_claim_id": CLAIM_ID,
            "challenger_identity": challenger.subject_id,
            "quoted_claim_fragment": "passes the local test suite with 372 tests passing",
            "challenge_type": "scope",
            "challenge_text": (
                "This claim is too broad unless scoped to local repo/test environment and "
                "does not imply production readiness or cross-operator independence."
            ),
            "evidence": [
                {
                    "ref": "docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood/",
                    "kind": "review",
                    "notes": "All agents in this run share one operator; a green local suite is not production evidence.",
                }
            ],
            "proposed_falsification_or_narrowing": (
                "Narrow the claim to: this repo, this venv, this commit, this machine, single operator; "
                "explicitly disclaim production readiness and cross-operator independence."
            ),
            "severity": "blocking",
            "deadline": iso(now() + timedelta(days=7)),
            "authority_lease": {
                "lease_ref": f"sab_lease_{RUN_TAG}_challenge",
                "subject_id": challenger.subject_id,
                "purpose": "challenge",
                "scope": "Challenge one dogfood seed packet for scope narrowing only.",
                "expires_at": lease_expiry,
                "revoker": "operator_johnvincentshrader_local",
                "challenge_path": f"/api/v1/seeds/{SEED_ID}/challenges",
            },
            "created_at": ch_created,
        }
        challenge_message = {
            "kind": "sab_challenge_submit",
            "target_seed_id": SEED_ID,
            "target_claim_id": CLAIM_ID,
            "challenge_packet_sha256": sha256_obj(challenge_packet),
            "challenger_identity": challenger.subject_id,
            "created_at": ch_created,
        }
        challenge_packet["signature"] = {
            "alg": "ed25519",
            "signer": challenger.subject_id,
            "signature": challenger.sign(challenge_message),
            "canonicalization": "json-sort-keys-compact-v1",
        }
        challenge_resp = run.call("submit_challenge", "POST", f"/api/v1/seeds/{SEED_ID}/challenges", challenge_packet)

        # -- 4. claimant responds by narrowing scope --
        narrowed = {
            "response_type": "scope_narrowing",
            "narrowed_claim_text": (
                f"At commit {COMMIT}, in the single checkout /Users/dhyana/dharmic-agora on one local "
                "machine (Darwin), using ./.venv/bin/python (3.13.12), the command "
                "'./.venv/bin/python -m pytest -q' was observed by this operator to report "
                f"'{RUN1_TAIL}' with the single warning being {RUN1_WARNING} "
                "This says nothing about production readiness, other machines, other commits, or "
                "cross-operator independence; claimant, challenger, and witness share one operator."
            ),
            "accepted_challenge": CHALLENGE_ID,
            "labels": ["single_operator_rehearsal", "not_cross_operator_independent"],
        }
        resp_created = iso(now())
        respond_message = {
            "kind": "sab_challenge_respond",
            "challenge_id": CHALLENGE_ID,
            "actor_identity": claimant.subject_id,
            "payload_sha256": sha256_obj(narrowed),
            "created_at": resp_created,
        }
        respond_body = {
            "schema": "sab.challenge_response.v1",
            "challenge_id": CHALLENGE_ID,
            "actor_identity": claimant.subject_id,
            "responder_identity": claimant.subject_id,
            "response": narrowed,
            "created_at": resp_created,
            "signature": claimant.sign(respond_message),
        }
        run.call("respond_challenge", "POST", f"/api/v1/challenges/{CHALLENGE_ID}/respond", respond_body)

        chain_now = run.call("get_chain_head_pre_witness", "GET", f"/api/v1/seeds/{SEED_ID}/chain")
        prev_hash = chain_now["head"]

        # -- 5. witness ACTUALLY replays pytest and attests to what it saw --
        print("Witness replaying pytest (this takes a while)...")
        replay = replay_pytest()
        save("09_witness_pytest_replay.json", replay)
        tail_line = replay["stdout_tail"][-1] if replay["stdout_tail"] else ""
        matches = replay["exit_code"] == 0 and "372 passed" in tail_line and "1 warning" in tail_line
        witness_payload = {
            "attestation": "replayed_command_and_observed_output",
            "command": replay["command"],
            "cwd": replay["cwd"],
            "commit": COMMIT,
            "exit_code": replay["exit_code"],
            "duration_seconds": replay["duration_seconds"],
            "observed_tail": tail_line,
            "matches_narrowed_claim": matches,
            "independence_disclosure": (
                "witness shares the operator and machine with the claimant; "
                "this is a single_operator_rehearsal, not an independent replication"
            ),
        }
        wit_created = iso(now())
        witness_message = {
            "kind": "sab_witness_event",
            "event_type": "affirm" if matches else "refuse",
            "subject_type": "seed",
            "subject_id": SEED_ID,
            "payload_hash": sha256_obj(witness_payload),
            "prev_hash": prev_hash,
            "created_at": wit_created,
        }
        witness_body = {
            "event_type": "affirm" if matches else "refuse",
            "actor_identity": witness.subject_id,
            "subject_type": "seed",
            "subject_id": SEED_ID,
            "created_at": wit_created,
            "payload": witness_payload,
            "prev_hash": prev_hash,
            "signature": witness.sign(witness_message),
        }
        run.call("witness_event", "POST", "/api/v1/witness-events", witness_body)

        # -- 6. chain verification via the router --
        verify = run.call("witness_verify_seed", "GET", f"/api/v1/witness/verify?seed_id={SEED_ID}")
        print(f"  witness chain verified={verify['verified']} entries={verify['entry_count']}")

        # -- 7. standing lease review (reviewer = witness agent, same operator, disclosed) --
        issued_at = iso(now())
        standing_lease = {
            "schema": "sab.standing_lease.v1",
            "standing_id": STANDING_ID,
            "subject_seed_id": SEED_ID,
            "subject_claim_id": CLAIM_ID,
            "scope": (
                "Cite the narrowed local pytest observation as valid_local_pipeline_evidence for the SAB "
                "dogfood loop only; single_operator_rehearsal; not_cross_operator_independent; "
                "no production or cross-operator reliance."
            ),
            "purpose": "demonstration_zero_rehearsal_receipt",
            "expiry": iso(now() + timedelta(days=30)),
            "revoker": "operator_johnvincentshrader_local",
            "challenge_path": f"/api/v1/standing/{STANDING_ID}/challenge",
            "issued_by": witness.subject_id,
            "issued_at": issued_at,
        }
        standing_message = {
            "kind": "sab_standing_review",
            "standing_lease_sha256": sha256_obj(standing_lease),
            "subject_seed_id": SEED_ID,
            "reviewer_identity": witness.subject_id,
            "created_at": issued_at,
        }
        standing_lease["signature"] = {
            "alg": "ed25519",
            "signer": witness.subject_id,
            "signature": witness.sign(standing_message),
            "canonicalization": "json-sort-keys-compact-v1",
        }
        standing_body = {
            "standing_lease": standing_lease,
            "reviewer_identity": witness.subject_id,
            "created_at": issued_at,
        }
        standing_resp = run.call("standing_review", "POST", "/api/v1/standing/review", standing_body)

        run.call("get_seed_final", "GET", f"/api/v1/seeds/{SEED_ID}")
        run.call("get_standing_final", "GET", f"/api/v1/standing/{STANDING_ID}")
        run.call("witness_verify_full_db", "GET", "/api/v1/witness/verify")

    save("99_db_after.json", db_snapshot(db_path))
    summary = {
        "seed_id": SEED_ID,
        "claim_id": CLAIM_ID,
        "challenge_id": CHALLENGE_ID,
        "standing_id": STANDING_ID,
        "db_path": db_path,
        "agents": {
            "claimant": claimant.subject_id,
            "challenger": challenger.subject_id,
            "witness": witness.subject_id,
        },
        "final_labels": [
            "single_operator_rehearsal",
            "not_cross_operator_independent",
            "valid_local_pipeline_evidence",
        ],
        "note": "private keys intentionally not persisted; public keys are in the register receipts",
    }
    save("98_run_summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
