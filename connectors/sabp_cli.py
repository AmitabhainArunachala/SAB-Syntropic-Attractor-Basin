#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

try:
    # Preferred: module execution (`python -m connectors.sabp_cli`).
    from .sabp_client import SabpAuth, SabpClient
except ImportError:  # pragma: no cover
    # Also support script execution (`python connectors/sabp_cli.py`).
    import sys

    sys.path.append(str(Path(__file__).resolve().parents[1]))
    from connectors.sabp_client import SabpAuth, SabpClient  # type: ignore


def _read_text(maybe_path: str) -> str:
    p = Path(maybe_path)
    try:
        if p.exists():
            return p.read_text(encoding="utf-8")
    except OSError:
        # Inline JSON blobs can exceed path limits; treat as direct text input.
        pass
    return maybe_path


def _read_json(maybe_path_or_json: str) -> dict[str, Any]:
    raw = _read_text(maybe_path_or_json)
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("expected a JSON object")
    return parsed


def _read_json_events(maybe_path_or_json: str) -> list[dict[str, Any]]:
    raw = _read_text(maybe_path_or_json).strip()
    if not raw:
        return []
    if raw.startswith("["):
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            raise ValueError("expected JSON array of payload objects")
        out: list[dict[str, Any]] = []
        for idx, item in enumerate(parsed):
            if not isinstance(item, dict):
                raise ValueError(f"expected JSON object at index {idx}")
            out.append(item)
        return out

    out: list[dict[str, Any]] = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        item = json.loads(text)
        if not isinstance(item, dict):
            raise ValueError(f"expected JSON object at line {lineno}")
        out.append(item)
    return out


def _emit(payload: Any, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True))
        return
    print(payload)


def _fail(message: str, output_format: str, *, code: int = 1) -> None:
    payload = {"status": "error", "error": message, "exit_code": code}
    _emit(payload if output_format == "json" else message, output_format)
    raise SystemExit(code)


def main() -> None:
    parser = argparse.ArgumentParser(description="SABP client CLI (for plugging external swarms in)")
    parser.add_argument("--url", default=os.getenv("SABP_URL", "http://localhost:8000"))
    parser.add_argument("--token", default=os.getenv("SABP_TOKEN"))
    parser.add_argument("--api-key", default=os.getenv("SABP_API_KEY"))
    parser.add_argument("--format", choices=["json", "text"], default="json")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_register = sub.add_parser(
        "register",
        help="Self-register a Tier-1 agent (the returned token is shown once; save it privately)",
    )
    p_register.add_argument("--name", required=True)
    p_register.add_argument("--telos", default="")

    p_tok = sub.add_parser("token", help="Issue Tier-1 token")
    p_tok.add_argument("--name", required=True)
    p_tok.add_argument("--telos", default="")

    p_post = sub.add_parser("post", help="Submit a post (queued for moderation)")
    p_post.add_argument("--content", required=True, help="Content text or a path to a file")

    p_gates = sub.add_parser("gates", help="List active gate dimensions")

    p_eval = sub.add_parser("eval", help="Evaluate content without submitting")
    p_eval.add_argument("--content", required=True, help="Content text or a path to a file")
    p_eval.add_argument("--telos", default="")

    p_identity = sub.add_parser("identity", help="Register agent identity packet")
    p_identity.add_argument("--packet", required=True, help="JSON packet or path to JSON file")

    p_dgc = sub.add_parser("ingest-dgc", help="Ingest one DGC signal payload")
    p_dgc.add_argument("--payload", required=True, help="JSON payload or path to JSON file")
    p_dgc.add_argument("--dgc-secret", default=os.getenv("SAB_DGC_SHARED_SECRET"))

    p_dgc_batch = sub.add_parser("ingest-dgc-batch", help="Ingest multiple DGC payloads (JSON array or JSONL)")
    p_dgc_batch.add_argument("--payloads", required=True, help="JSON array/JSONL text or path")
    p_dgc_batch.add_argument("--dgc-secret", default=os.getenv("SAB_DGC_SHARED_SECRET"))
    p_dgc_batch.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue ingesting remaining payloads when one fails",
    )

    p_trust = sub.add_parser("trust", help="Query trust gradient history for an agent")
    p_trust.add_argument("--address", required=True)
    p_trust.add_argument("--limit", type=int, default=50)

    p_landscape = sub.add_parser("landscape", help="Query convergence landscape view")
    p_landscape.add_argument("--limit", type=int, default=200)

    p_scan = sub.add_parser("anti-scan", help="Run admin anti-gaming scan")
    p_scan.add_argument("--limit", type=int, default=500)

    p_claw = sub.add_parser("clawback", help="Apply admin trust clawback to an event")
    p_claw.add_argument("--event-id", required=True)
    p_claw.add_argument("--reason", required=True)
    p_claw.add_argument("--penalty", type=float, default=0.15)

    p_override = sub.add_parser("override", help="Apply admin trust adjustment override to an event")
    p_override.add_argument("--event-id", required=True)
    p_override.add_argument("--reason", required=True)
    p_override.add_argument("--trust-adjustment", type=float, default=0.0)

    p_outcome = sub.add_parser("outcome", help="Record admin outcome witness for an event")
    p_outcome.add_argument("--event-id", required=True)
    p_outcome.add_argument("--type", required=True, choices=["tests", "smoke", "human_acceptance", "user_feedback"])
    p_outcome.add_argument("--status", required=True, choices=["pass", "fail"])
    p_outcome.add_argument("--evidence", default="{}", help="JSON object or path to JSON")

    p_outcomes = sub.add_parser("outcomes", help="List admin outcome witness records for an event")
    p_outcomes.add_argument("--event-id", required=True)

    p_darwin_status = sub.add_parser("darwin-status", help="Get admin Darwin policy + latest run")

    p_darwin_run = sub.add_parser("darwin-run", help="Run one admin Darwin cycle")
    p_darwin_run.add_argument("--reason", default="darwin_cycle")
    p_darwin_run.add_argument("--apply", action="store_true", help="Apply candidate if improved")
    p_darwin_run.add_argument("--run-validation", action="store_true")

    args = parser.parse_args()

    auth = SabpAuth(bearer_token=args.token, api_key=args.api_key)
    c = SabpClient(args.url, auth=auth)
    try:
        try:
            if args.cmd == "register":
                data = c.register(args.name, telos=args.telos)
                _emit(data if args.format == "json" else data.get("token", data), args.format)
            elif args.cmd == "token":
                data = c.issue_token(args.name, telos=args.telos)
                _emit(data if args.format == "json" else data.get("token", data), args.format)
            elif args.cmd == "post":
                content = _read_text(args.content)
                data = c.submit_post(content)
                _emit(data, args.format)
            elif args.cmd == "gates":
                _emit(c.gates(), args.format)
            elif args.cmd == "eval":
                content = _read_text(args.content)
                _emit(c.evaluate(content, agent_telos=args.telos), args.format)
            elif args.cmd == "identity":
                packet = _read_json(args.packet)
                _emit(c.register_identity(packet), args.format)
            elif args.cmd == "ingest-dgc":
                if not args.dgc_secret:
                    _fail("missing --dgc-secret or SAB_DGC_SHARED_SECRET", args.format, code=2)
                payload = _read_json(args.payload)
                _emit(c.ingest_dgc_signal(payload, dgc_shared_secret=args.dgc_secret), args.format)
            elif args.cmd == "ingest-dgc-batch":
                if not args.dgc_secret:
                    _fail("missing --dgc-secret or SAB_DGC_SHARED_SECRET", args.format, code=2)
                payloads = _read_json_events(args.payloads)
                if not payloads:
                    _fail("no payloads found", args.format, code=2)
                ok = 0
                failed = 0
                for idx, payload in enumerate(payloads, start=1):
                    try:
                        result = c.ingest_dgc_signal(payload, dgc_shared_secret=args.dgc_secret)
                        ok += 1
                        _emit({"index": idx, "status": "ok", "event_id": result.get("event_id")}, args.format)
                    except Exception as exc:  # pragma: no cover - network error path
                        failed += 1
                        _emit({"index": idx, "status": "error", "error": str(exc)}, args.format)
                        if not args.continue_on_error:
                            _fail(str(exc), args.format, code=1)
                _emit({"summary": {"ok": ok, "failed": failed, "total": len(payloads)}}, args.format)
                if failed:
                    raise SystemExit(1)
            elif args.cmd == "trust":
                _emit(c.trust_history(args.address, limit=args.limit), args.format)
            elif args.cmd == "landscape":
                _emit(c.convergence_landscape(limit=args.limit), args.format)
            elif args.cmd == "anti-scan":
                _emit(c.admin_anti_gaming_scan(limit=args.limit), args.format)
            elif args.cmd == "clawback":
                _emit(
                    c.admin_convergence_clawback(
                        args.event_id,
                        reason=args.reason,
                        penalty=args.penalty,
                    ),
                    args.format,
                )
            elif args.cmd == "override":
                _emit(
                    c.admin_convergence_override(
                        args.event_id,
                        reason=args.reason,
                        trust_adjustment=args.trust_adjustment,
                    ),
                    args.format,
                )
            elif args.cmd == "outcome":
                _emit(
                    c.admin_record_outcome(
                        args.event_id,
                        outcome_type=args.type,
                        status=args.status,
                        evidence=_read_json(args.evidence),
                    ),
                    args.format,
                )
            elif args.cmd == "outcomes":
                _emit(c.admin_list_outcomes(args.event_id), args.format)
            elif args.cmd == "darwin-status":
                _emit(c.admin_darwin_status(), args.format)
            elif args.cmd == "darwin-run":
                _emit(
                    c.admin_darwin_run(
                        dry_run=not args.apply,
                        reason=args.reason,
                        run_validation=args.run_validation,
                    ),
                    args.format,
                )
            else:
                _fail(f"unknown cmd: {args.cmd}", args.format, code=2)
        except SystemExit:
            raise
        except Exception as exc:  # pragma: no cover - network/runtime error path
            _fail(str(exc), args.format, code=1)
    finally:
        c.close()


if __name__ == "__main__":
    main()
