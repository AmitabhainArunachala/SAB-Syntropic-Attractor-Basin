#!/usr/bin/env python3
"""Package scheduled agent deltas as SAB seed packets.

This is a local-only bridge for the language-womb grand challenge. Agents write
small JSON contribution fragments into the inbox; this script wraps them in
`sab.seed_packet.v1` packets and writes receipts. It does not post to external
services and it does not grant standing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
LANE_DIR = REPO_ROOT / "docs" / "lanes" / "sab-agent-seeding-v1"
CONTRIB_DIR = LANE_DIR / "contributions"
INBOX_DIR = CONTRIB_DIR / "inbox"
PROCESSED_DIR = CONTRIB_DIR / "processed"
PACKET_DIR = CONTRIB_DIR / "packets"
RECEIPT_DIR = CONTRIB_DIR / "receipts"
STATE_DIR = Path.home() / ".dharma" / "sab_language_womb"
KEY_DIR = STATE_DIR / "keys"

GRAND_CHALLENGE_SEED = LANE_DIR / "LANGUAGE_WOMB_GRAND_CHALLENGE_SEED.md"
PRIOR_ART_GATE = (
    Path.home()
    / "ds_naga_ir_language_womb_seed"
    / "naga_ir_language_womb"
    / "language"
    / "prior_art.md"
)

RELEVANCE_TERMS = (
    "claim",
    "evidence",
    "uncertainty",
    "proof",
    "authority",
    "standing",
    "typecheck",
    "typechecker",
    "evaluator",
    "language",
    "modality",
    "provenance",
    "witness",
    "governance",
)


@dataclass(frozen=True)
class TickSummary:
    status: str
    packets_written: list[str]
    receipts_written: list[str]
    inbox_processed: list[str]
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "packets_written": self.packets_written,
            "receipts_written": self.receipts_written,
            "inbox_processed": self.inbox_processed,
            "message": self.message,
        }


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def slug(text: str, *, fallback: str = "agent") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", text.strip())
    cleaned = cleaned.strip("_")
    return cleaned or fallback


def canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_sha256(value: Mapping[str, Any]) -> str:
    return "sha256:" + sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_sha256(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _read_text(path: Path, *, limit: int = 6000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:limit]
    except FileNotFoundError:
        return ""


def _looks_relevant(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in RELEVANCE_TERMS)


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def bootstrap_contribution() -> dict[str, Any]:
    evidence: list[str] = [str(GRAND_CHALLENGE_SEED)]
    if PRIOR_ART_GATE.exists():
        evidence.append(str(PRIOR_ART_GATE))
    return {
        "problem_ref": "language_womb.epistemic_authority.v1",
        "delta_kind": "governance",
        "claim": (
            "The language-womb grand challenge should collect small, "
            "challengeable agent deltas toward epistemic-authority semantics "
            "instead of using puzzle answers, posting activity, or model "
            "consensus as standing."
        ),
        "evidence_or_reasoning": evidence,
        "falsification_route": (
            "Show that the scheduled contribution loop either emits only "
            "receipt theater, blocks unrelated work, or allows puzzle answers "
            "to substitute for challengeable evidence."
        ),
        "language_impact": (
            "A future evaluator must reject Claim[Attested_by, womb] in a "
            "Claim[Proven_by, core] slot unless a promotion proof or accepted "
            "review receipt is present."
        ),
        "authority_boundary": (
            "This seed authorizes local collection and challenge only; it does "
            "not authorize Moltbook login, external posting, standing promotion, "
            "or deployment authority."
        ),
    }


def source_contribution(agent_id: str, sources: list[Path], *, force: bool = False) -> dict[str, Any] | None:
    existing = [path for path in sources if path.exists()]
    if not existing:
        return None
    chunks = []
    for path in existing:
        text = _read_text(path, limit=4000)
        if text and _looks_relevant(text):
            chunks.append({"path": str(path), "digest": file_sha256(path), "snippet": text[:600]})
    if not chunks:
        return None

    digest_material = canonical_json({"agent_id": agent_id, "chunks": chunks})
    digest = sha256(digest_material.encode("utf-8")).hexdigest()
    state_file = STATE_DIR / "state" / f"{slug(agent_id)}.json"
    if state_file.exists() and not force:
        state = _load_json(state_file)
        if state.get("last_source_digest") == digest:
            return None
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(
        json.dumps({"last_source_digest": digest, "updated_at": iso_z(utc_now())}, indent=2) + "\n",
        encoding="utf-8",
    )
    refs = [f"{chunk['path']} {chunk['digest']}" for chunk in chunks]
    return {
        "problem_ref": "language_womb.epistemic_authority.v1",
        "delta_kind": "trace",
        "claim": (
            f"{agent_id} observed source material relevant to claim/evidence/"
            "authority semantics and packaged it for SAB challenge."
        ),
        "evidence_or_reasoning": refs,
        "falsification_route": (
            "Inspect the referenced files and challenge whether the extracted "
            "material is actually relevant to language-womb semantics."
        ),
        "language_impact": (
            "If accepted, this trace can become prior-art pressure, a fixture, "
            "or a counterexample candidate; it is not standing by itself."
        ),
        "authority_boundary": "Source observation only; no truth, standing, external action, or deployment authority.",
    }


def _evidence_items(contribution: Mapping[str, Any]) -> list[dict[str, Any]]:
    refs = contribution.get("evidence_or_reasoning")
    if not isinstance(refs, list):
        refs = [str(refs or "language-womb-grand-challenge-seed")]
    items = []
    for raw in refs[:12]:
        ref = str(raw).strip() or "language-womb-grand-challenge-seed"
        digest_match = re.search(r"sha256:[a-f0-9]{64}", ref)
        item: dict[str, Any] = {
            "ref": ref[:500],
            "kind": "source",
            "privacy_class": "public",
            "notes": "Scheduled language-womb contribution evidence.",
        }
        if digest_match:
            item["digest"] = digest_match.group(0)
        items.append(item)
    return items or [
        {
            "ref": "language-womb-grand-challenge-seed",
            "kind": "source",
            "privacy_class": "public",
        }
    ]


def _sign_payload(message: Mapping[str, Any], agent_slug: str, key_dir: Path) -> str:
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / f"{agent_slug}.ed25519"
    try:
        from nacl.signing import SigningKey
    except Exception:
        return sha256(canonical_json(message).encode("utf-8")).hexdigest() * 2

    if key_path.exists():
        seed_hex = key_path.read_text(encoding="utf-8").strip()
        signing_key = SigningKey(bytes.fromhex(seed_hex))
    else:
        signing_key = SigningKey.generate()
        key_path.write_text(signing_key.encode().hex() + "\n", encoding="utf-8")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    return signing_key.sign(canonical_json(message).encode("utf-8")).signature.hex()


def build_seed_packet(
    contribution: Mapping[str, Any],
    *,
    agent_id: str,
    agent_name: str,
    created_at: datetime,
    key_dir: Path = KEY_DIR,
) -> dict[str, Any]:
    agent_slug = slug(agent_id)
    contribution_digest = sha256(canonical_json(dict(contribution)).encode("utf-8")).hexdigest()
    seed_id = f"sab_seed_language_womb_{agent_slug}_{contribution_digest[:12]}"
    claim_id = f"sab_claim_language_womb_{agent_slug}_{contribution_digest[:12]}"
    lease_ref = f"sab_lease_language_womb_{agent_slug}_{contribution_digest[:12]}"
    created = iso_z(created_at)
    revalidation = iso_z(created_at + timedelta(days=90))
    expires = iso_z(created_at + timedelta(days=30))

    packet: dict[str, Any] = {
        "schema": "sab.seed_packet.v1",
        "seed_id": seed_id,
        "seed_type": "governance",
        "title": "Language Womb Grand Challenge Contribution",
        "status": "pending_seed",
        "loop_position": "spark",
        "north_star": "deepen_truth",
        "claim": {
            "claim_id": claim_id,
            "text": str(contribution.get("claim") or "Scheduled agent contribution requires challenge."),
            "claim_type": "semantic",
            "scope": str(contribution.get("problem_ref") or "language_womb.epistemic_authority.v1"),
            "decision_context": "Whether this delta should influence the AI-native language womb.",
            "success_conditions": [
                "The delta is precise enough for another agent to challenge.",
                "The authority boundary prevents posting, identity, or model consensus from becoming standing.",
            ],
            "failure_conditions": [
                "The delta cannot be falsified, narrowed, or connected to language semantics.",
                "The delta is only runtime receipt theater or social activity.",
            ],
        },
        "claimant_identity": {
            "subject_id": agent_id,
            "identity_ref": f"sab_identity_{agent_slug}",
        },
        "operator_backing": {
            "operator_ref": "operator:self-declared:dhyana-local-agent-fleet",
            "disclosure": f"{agent_name} submitted this through the local scheduled SAB contribution loop.",
            "concentration_attestation": "self_attested",
        },
        "authority_lease": {
            "lease_ref": lease_ref,
            "scope": "Submit one public language-womb contribution for SAB challenge.",
            "expires_at": expires,
            "revoker": "sab-steward-or-witness-quorum",
            "challenge_path": f"/api/v1/seeds/{seed_id}/challenges",
        },
        "evidence_bundle": _evidence_items(contribution),
        "challenge_plan": {
            "required": True,
            "challenge_window": "P7D",
            "strongest_objections": [
                "The contribution may be too vague to affect language semantics.",
                "The contribution may duplicate prior art or belong in governance rather than the language.",
            ],
            "challenge_refs": [],
            "falsification_routes": [
                str(contribution.get("falsification_route") or "Challenge relevance, novelty, and authority boundary."),
            ],
            "correction_path": f"/api/v1/seeds/{seed_id}/correct",
        },
        "witness_plan": {
            "required_roles": ["challenger", "language_reviewer"],
            "minimum_witnesses": 1,
            "non_adjacent_required": True,
            "forbidden_witnesses": [agent_id],
        },
        "build_plan": {
            "artifact_refs": [
                str(GRAND_CHALLENGE_SEED),
                str(PRIOR_ART_GATE),
            ],
            "production_grade_definition": (
                "Accepted deltas become tests, type/effect rules, proof obligations, "
                "or explicit rejections before any grammar expansion."
            ),
        },
        "anti_capture_rules": [
            "Puzzle solving, posting, model consensus, or identity attestation never grants standing by itself.",
            "Scheduled agents controlled by the same operator do not count as independent witnesses.",
        ],
        "commons_return": {
            "mode": "knowledge_return",
            "minimum_return": "Publish the challengeable delta and its authority boundary as a public SAB seed packet.",
        },
        "canon_compost_policy": {
            "canon_conditions": [
                "The delta survives challenge and can be expressed as a language rule, test, proof obligation, or rejection."
            ],
            "compost_conditions": [
                "The delta is receipt theater, duplicates known prior art without a new boundary, or cannot be challenged."
            ],
            "revalidation_due": revalidation,
        },
        "privacy_class": "public",
        "created_at": created,
    }
    unsigned_hash = canonical_sha256(packet)
    signed_payload = {
        "kind": "sab_seed_submit",
        "seed_packet_sha256": unsigned_hash,
        "claimant_identity": agent_id,
        "authority_lease_id": lease_ref,
        "created_at": created,
    }
    packet["signature"] = {
        "alg": "ed25519",
        "signer": agent_id,
        "signature": _sign_payload(signed_payload, agent_slug, key_dir),
        "canonicalization": "json-sort-keys-compact-v1",
        "signed_payload": signed_payload,
    }
    return packet


def collect_contributions(
    *,
    inbox_dir: Path,
    agent_id: str,
    sources: list[Path],
    bootstrap: bool,
    force: bool,
) -> tuple[list[tuple[str, dict[str, Any]]], list[Path]]:
    contributions: list[tuple[str, dict[str, Any]]] = []
    processed_paths: list[Path] = []
    if bootstrap:
        contributions.append(("bootstrap", bootstrap_contribution()))

    inbox_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(inbox_dir.glob("*.json")):
        contributions.append((path.stem, _load_json(path)))
        processed_paths.append(path)

    source_delta = source_contribution(agent_id, sources, force=force)
    if source_delta is not None:
        contributions.append(("source-delta", source_delta))
    return contributions, processed_paths


def run_tick(
    *,
    agent_id: str,
    agent_name: str,
    inbox_dir: Path = INBOX_DIR,
    packet_dir: Path = PACKET_DIR,
    receipt_dir: Path = RECEIPT_DIR,
    processed_dir: Path = PROCESSED_DIR,
    key_dir: Path = KEY_DIR,
    sources: list[Path] | None = None,
    bootstrap: bool = False,
    force: bool = False,
    dry_run: bool = False,
) -> TickSummary:
    if not agent_id.startswith("agent_"):
        agent_id = f"agent_{slug(agent_id)}"
    sources = list(sources or [])
    contributions, inbox_paths = collect_contributions(
        inbox_dir=inbox_dir,
        agent_id=agent_id,
        sources=sources,
        bootstrap=bootstrap,
        force=force,
    )
    if not contributions:
        return TickSummary(
            status="no_delta",
            packets_written=[],
            receipts_written=[],
            inbox_processed=[],
            message="No relevant source change or inbox contribution to package.",
        )

    now = utc_now()
    packets_written: list[str] = []
    receipts_written: list[str] = []
    for source_name, contribution in contributions:
        packet = build_seed_packet(
            contribution,
            agent_id=agent_id,
            agent_name=agent_name,
            created_at=now,
            key_dir=key_dir,
        )
        packet_path = packet_dir / f"{packet['seed_id']}.json"
        receipt_path = receipt_dir / f"{packet['seed_id']}.receipt.json"
        receipt = {
            "schema": "sab.language_womb_contribution_receipt.v1",
            "seed_id": packet["seed_id"],
            "claim_id": packet["claim"]["claim_id"],
            "agent_id": agent_id,
            "agent_name": agent_name,
            "source_name": source_name,
            "packet_path": str(packet_path),
            "packet_sha256": canonical_sha256(packet),
            "standing_effect": "none",
            "external_actions": [],
            "created_at": iso_z(now),
        }
        if not dry_run:
            packet_dir.mkdir(parents=True, exist_ok=True)
            receipt_dir.mkdir(parents=True, exist_ok=True)
            packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        packets_written.append(str(packet_path))
        receipts_written.append(str(receipt_path))

    processed: list[str] = []
    if not dry_run and inbox_paths:
        processed_dir.mkdir(parents=True, exist_ok=True)
        for path in inbox_paths:
            dest = processed_dir / path.name
            if dest.exists():
                dest = processed_dir / f"{path.stem}_{sha256(path.read_bytes()).hexdigest()[:8]}{path.suffix}"
            shutil.move(str(path), str(dest))
            processed.append(str(dest))

    return TickSummary(
        status="dry_run" if dry_run else "packaged",
        packets_written=packets_written,
        receipts_written=receipts_written,
        inbox_processed=processed,
        message=f"Packaged {len(contributions)} language-womb contribution(s).",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", default="agent_sab_language_womb_scheduler")
    parser.add_argument("--agent-name", default="sab-language-womb-scheduler")
    parser.add_argument("--inbox", type=Path, default=INBOX_DIR)
    parser.add_argument("--packet-dir", type=Path, default=PACKET_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=RECEIPT_DIR)
    parser.add_argument("--processed-dir", type=Path, default=PROCESSED_DIR)
    parser.add_argument("--key-dir", type=Path, default=KEY_DIR)
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--bootstrap-grand-challenge-seed", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    summary = run_tick(
        agent_id=args.agent_id,
        agent_name=args.agent_name,
        inbox_dir=args.inbox,
        packet_dir=args.packet_dir,
        receipt_dir=args.receipt_dir,
        processed_dir=args.processed_dir,
        key_dir=args.key_dir,
        sources=[Path(path).expanduser() for path in args.source],
        bootstrap=args.bootstrap_grand_challenge_seed,
        force=args.force,
        dry_run=args.dry_run,
    )
    print(json.dumps(summary.as_dict(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

