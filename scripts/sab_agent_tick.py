#!/usr/bin/env python3
"""SAB agent tick — the standing loop's heartbeat.

Runs on a launchd schedule (com.dharma.sab-agent-tick). Each tick:
  1. health-checks the SAB server,
  2. reconciles lane packet files into the API store (re-signing with local
     keys where the legacy file signature does not match the API contract),
  3. reports every seed's lifecycle state and challenge window,
  4. writes a digest to ~/.dharma/sab_agent/LATEST.md and appends log.jsonl.

Hard policy (AGENT_CONSTITUTION.md + SAB_MASTER_VISION_V1.md §6):
  - never resolves challenges, never reviews standing, never promotes canon;
  - same-operator activity is disclosed, counted as pressure, never witness;
  - the blocking challenge on the master vision seed stays open until an
    independent operator resolves it.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

BASE = "http://127.0.0.1:8765"
REPO = Path(__file__).resolve().parents[1]
LANE = REPO / "docs" / "lanes" / "sab-agent-seeding-v1" / "contributions"
STATE_DIR = Path.home() / ".dharma" / "sab_agent"
KEY_DIRS = [
    Path.home() / ".dharma" / "sab_keys",
    Path.home() / ".dharma" / "sab_language_womb" / "keys",
]
OPERATOR = "operator:self-declared:dhyana-local-agent-fleet"


def canonical(payload) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def now_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def api(path, payload=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"} if payload is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode())
        except Exception:
            return exc.code, {}
    except Exception as exc:
        return 0, {"error": str(exc)}


def log_event(event):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    event = {"t": now_z(), **event}
    with (STATE_DIR / "log.jsonl").open("a") as fh:
        fh.write(json.dumps(event, sort_keys=True) + "\n")


def find_key(agent_id: str):
    for key_dir in KEY_DIRS:
        path = key_dir / f"{agent_id}.ed25519"
        if path.exists():
            return path
    return None


def signing_key(path: Path):
    from nacl.signing import SigningKey

    return SigningKey(bytes.fromhex(path.read_text().strip()))


def ensure_registered(agent_id: str, sk) -> bool:
    status, _ = api(f"/api/v1/agents/me/home?subject_id={agent_id}")
    if status == 200:
        return True
    status, resp = api("/api/v1/agents/register", {
        "public_key": sk.verify_key.encode().hex(),
        "display_name": agent_id.removeprefix("agent_").replace("_", "-"),
        "subject_id": agent_id,
        "controller": "sab_agent_tick",
        "operator_backing": {
            "operator_ref": OPERATOR,
            "disclosure": "Founding operator's fleet; not independent of other fleet identities.",
            "concentration_attestation": "self_attested",
        },
    })
    log_event({"kind": "register", "agent_id": agent_id, "status": status})
    return status == 201


def reconcile_packet(path: Path):
    """Submit a lane seed packet through the API if it is not there yet."""
    packet = json.loads(path.read_text())
    if packet.get("schema") != "sab.seed_packet.v1":
        return {"packet": path.name, "action": "skip", "reason": "not a seed packet"}
    seed_id = packet.get("seed_id")
    status, _ = api(f"/api/v1/seeds/{seed_id}")
    if status == 200:
        return {"packet": path.name, "action": "none", "reason": "already in store"}

    claimant = (packet.get("claimant_identity") or {}).get("subject_id", "")
    key_path = find_key(claimant)
    if key_path is None:
        return {"packet": path.name, "action": "skip", "reason": f"no local key for {claimant}"}
    sk = signing_key(key_path)
    if not ensure_registered(claimant, sk):
        return {"packet": path.name, "action": "fail", "reason": "registration failed"}

    body = {k: v for k, v in packet.items() if k != "signature"}
    packet_hash = sha256(canonical(body).encode()).hexdigest()
    lease = body.get("authority_lease") or {}
    message = {
        "kind": "sab_seed_submit",
        "seed_packet_sha256": packet_hash,
        "claimant_identity": claimant,
        "authority_lease_id": lease.get("lease_ref") or lease.get("lease_id") or "",
        "created_at": body.get("created_at", ""),
    }
    body["signature"] = {
        "alg": "ed25519",
        "signer": claimant,
        "signature": sk.sign(canonical(message).encode()).signature.hex(),
        "canonicalization": "json-sort-keys-compact-v1",
        "signed_payload": message,
        "note": "re-signed by sab_agent_tick to match API contract; original file signature preserved in lane",
    }
    status, resp = api("/api/v1/seeds", {"seed_packet": body})
    result = {
        "packet": path.name,
        "action": "submitted" if status == 201 else "fail",
        "status": status,
        "detail": resp.get("detail") or resp.get("state"),
        "submitted_hash": packet_hash,
    }
    log_event({"kind": "reconcile", **result})
    return result


def main() -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    started = now_z()

    status, seeds_resp = api("/api/v1/seeds")
    if status != 200:
        (STATE_DIR / "LATEST.md").write_text(
            f"# SAB agent tick — {started}\n\nCRIT: server unreachable at {BASE} "
            f"(status {status}). launchd com.dharma.sab-server should be inspected:\n"
            f"`launchctl list | grep sab` / log at ~/.dharma/sab_agent/server.log\n"
        )
        log_event({"kind": "tick", "ok": False, "reason": "server unreachable"})
        return 1

    reconciled = [reconcile_packet(p) for p in sorted((LANE / "packets").glob("*.json"))]

    status, seeds_resp = api("/api/v1/seeds")
    seeds = seeds_resp.get("items", [])
    _, verify = api("/api/v1/witness/verify")

    lines = [
        f"# SAB agent tick — {started}",
        "",
        f"Server: {BASE} OK | seeds in store: {len(seeds)} | witness chain: "
        f"{'VERIFIED' if verify.get('verified') else 'FAILED'} ({verify.get('entry_count', '?')} events)",
        "",
        "## Seeds",
        "",
        "| seed | state | window closes | note |",
        "| --- | --- | --- | --- |",
    ]
    now = now_z()
    for seed in seeds:
        window = str(seed.get("challenge_window_closes_at") or "")
        note = ""
        if seed.get("state") == "challenged":
            note = "challenge open — same-operator challenges stay open for an independent resolver"
        elif window and window < now:
            note = "window closed — awaiting standing review (NOT automated by this tick)"
        lines.append(
            f"| {seed.get('seed_id')} | {seed.get('state')} | {window[:19]} | {note} |"
        )
    lines += [
        "",
        "## Reconciliation",
        "",
    ]
    for r in reconciled:
        lines.append(f"- {r['packet']}: {r['action']} ({r.get('reason') or r.get('detail') or ''})")
    lines += [
        "",
        "## Policy reminders",
        "",
        "- This tick never resolves challenges, never grants standing, never promotes canon.",
        "- Everything is provisional until >=3 independent operators exist (SAB_MASTER_VISION_V1.md section 6).",
        "- Next builds: docs and order in NEXT_10_BUILDS.md; blockers in the 2026-07-05 recovery final_receipt.md.",
        "",
    ]
    (STATE_DIR / "LATEST.md").write_text("\n".join(lines))
    log_event({
        "kind": "tick",
        "ok": True,
        "seeds": len(seeds),
        "chain_verified": bool(verify.get("verified")),
        "reconciled": [r for r in reconciled if r["action"] not in {"none"}],
    })
    print(json.dumps({"ok": True, "seeds": len(seeds), "reconciled": reconciled}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
