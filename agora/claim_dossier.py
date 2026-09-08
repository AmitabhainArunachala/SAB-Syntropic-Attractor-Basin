"""Read one immutable SAB v1 submission and its recorded reliance context.

This projection has no authority effect. Digest equality checks only the named
stored bytes/documents; it does not verify signatures, evidence, or permission.
Each public function uses one SQLite read snapshot and never initializes tables
or advances lifecycle state. A caller's existing transaction is left untouched.
"""

from __future__ import annotations

import json
import math
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import quote, urlencode

from .public_freshness import PublicationObservation, current_publication_observation
from .sab_seeding_api import (
    CHALLENGE_STATUSES,
    FINAL_SEED_STATES,
    OPEN_CHALLENGE_STATUSES,
    STANDING_STATUSES,
    _hash_json,
    _sha256_hex,
    _verify_witness_rows,
    _without_signature,
    observe_standing_status,
    _publication_response,
)


@contextmanager
def _read_snapshot(conn: sqlite3.Connection) -> Iterator[None]:
    own_transaction = not conn.in_transaction
    if own_transaction:
        conn.execute("BEGIN")
    try:
        yield
    finally:
        if own_transaction:
            # There are no writes to commit, and caller-owned work is never
            # committed or rolled back by this service.
            conn.rollback()


def _rows(conn: sqlite3.Connection, sql: str, parameters: tuple = ()) -> list[dict[str, Any]]:
    cursor = conn.execute(sql, parameters)
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _tables(conn: sqlite3.Connection) -> set[str]:
    return {
        row["name"] for row in _rows(conn, "SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _check(check_id: str, label: str, state: str, detail: str, **extra: Any) -> dict[str, Any]:
    return {"id": check_id, "label": label, "state": state, "detail": detail, **extra}


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-JSON numeric constant: {value}")


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("JSON number is outside the finite float range")
    return parsed


def _require_unicode_scalars(value: Any) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            current.encode("utf-8")
        elif isinstance(current, dict):
            pending.extend(current.keys())
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def _decode(raw: Any, location: str, missing: list[str]) -> Any:
    if raw is None or raw == "":
        missing.append(f"{location}: no stored JSON document.")
        return None
    try:
        value = json.loads(raw, parse_constant=_reject_constant, parse_float=_finite_float)
        _require_unicode_scalars(value)
        return value
    except UnicodeError:
        missing.append(
            f"{location}: contains non-scalar Unicode; original escaped JSON is retained."
        )
        return None
    except (TypeError, ValueError, RecursionError):
        missing.append(f"{location}: malformed stored JSON; raw content is retained.")
        return None


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _claim_text_fields(claim: dict[str, Any]) -> dict[str, str | None]:
    return {
        field: claim.get(field) if isinstance(claim.get(field), str) else None
        for field in ("text", "scope", "decision_context")
    }


def _digest_check(check_id: str, label: str, value: Any, stored: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(stored, str) or not stored:
        return _check(
            check_id, label, "not_checked", "A readable JSON object and stored digest are required."
        )
    computed = _hash_json(_without_signature(value))
    return _check(
        check_id,
        label,
        "passed" if computed == stored else "failed",
        "SHA-256 of canonical JSON with the top-level signature removed; no signature or content-truth check.",
        stored=stored,
        computed=computed,
    )


def _aggregate(
    check_id: str, label: str, checks: list[dict[str, Any]], detail: str
) -> dict[str, Any]:
    states = [check["state"] for check in checks]
    state = (
        "failed"
        if "failed" in states
        else "not_checked" if not states or "not_checked" in states else "passed"
    )
    return _check(
        check_id,
        label,
        state,
        detail,
        checked_count=sum(s != "not_checked" for s in states),
        total_count=len(states),
    )


def _time_observation(
    value: Any, now: datetime, publication_observation: PublicationObservation | None = None
) -> dict[str, Any]:
    if publication_observation is not None:
        return publication_observation.expiry(value)
    observation = {
        "value": value,
        "observed_at": now.isoformat(),
        "state": "unknown",
        "elapsed": None,
    }
    try:
        if not isinstance(value, str) or not value:
            return observation
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=timezone.utc)
        elapsed = instant <= now
    except (TypeError, ValueError, OverflowError):
        return observation
    observation.update(state="elapsed" if elapsed else "not_elapsed", elapsed=elapsed)
    return observation


def _path_safe(identifier: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.~-]+", identifier)) and identifier not in {".", ".."}


def _record_link(kind: str, identifier: str, *, force_query: bool = False) -> str:
    # ASGI decodes %2F before route matching. Query identifiers also avoid
    # ambiguous seed IDs ending in /chain or /dossier and URL dot normalization.
    if force_query or not _path_safe(identifier):
        return "/api/v1/claims/record?" + urlencode({"kind": kind, "identifier": identifier})
    encoded = quote(identifier, safe="")
    return {
        "seed": f"/api/v1/seeds/{encoded}",
        "chain": f"/api/v1/seeds/{encoded}/chain",
        "challenge": f"/api/v1/challenges/{encoded}",
        "standing": f"/api/v1/standing/{encoded}",
        "witness_event": f"/api/v1/witness-events/{encoded}",
        "dossier": f"/api/v1/seeds/{encoded}/dossier",
    }[kind]


def _links(seed_id: str) -> dict[str, Any]:
    dossier = _record_link("dossier", seed_id)
    return {
        "seed": _record_link("seed", seed_id),
        "chain": _record_link("chain", seed_id),
        "verify": "/api/v1/witness/verify?" + urlencode({"seed_id": seed_id}),
        "dossier": dossier,
        "download": dossier + ("&" if "?" in dossier else "?") + "download=true",
        "html": (
            f"/claims/{quote(seed_id, safe='')}"
            if _path_safe(seed_id)
            else "/claims?" + urlencode({"seed_id": seed_id})
        ),
        "ledger": "/api/v1/claims",
        "challenges": [],
        "standing": [],
    }


def _evidence(value: Any, location: str, missing: list[str]) -> dict[str, Any]:
    if not isinstance(value, list):
        missing.append(f"{location}: evidence list is missing or malformed.")
        availability = "missing" if value is None else "malformed"
        values = []
    else:
        availability = "present" if value else "empty"
        values = value
        if not value:
            missing.append(f"{location}: no evidence references are recorded.")
    items = []
    for index, entry in enumerate(values):
        obj = _object(entry)
        absent = [field for field in ("ref", "digest") if not obj.get(field)]
        if absent:
            missing.append(f"{location}[{index}]: missing " + ", ".join(absent) + ".")
        items.append(
            {
                "index": index,
                "submitted": entry,
                "ref": obj.get("ref"),
                "kind": obj.get("kind"),
                "digest": obj.get("digest"),
                "declared_digest": obj.get("digest"),
                "notes": obj.get("notes"),
                "privacy_class": obj.get("privacy_class"),
                "check": _check(
                    "evidence_bytes",
                    "Referenced evidence bytes",
                    "not_checked",
                    "No referenced content was fetched or its digest compared.",
                ),
            }
        )
    return {
        "items": items,
        "availability": availability,
        "submitted": value,
        "bytes_check": _check(
            "evidence_bytes",
            "Referenced evidence bytes",
            "not_checked",
            "References, digests and notes are submitted assertions; no external content was fetched.",
        ),
    }


def _history(rows: list[dict[str, Any]], missing: list[str]) -> list[dict[str, Any]]:
    events = []
    for row in rows:
        payload = _decode(row.get("payload_json"), f"event {row.get('event_id')}.payload", missing)
        if not isinstance(payload, dict):
            missing.append(f"event {row.get('event_id')}.payload: not a readable JSON object.")
        events.append({**row, "payload": payload})
    return events


def _contains(value: Any, query: str) -> int:
    return int(isinstance(value, str) and query.casefold() in value.casefold())


def _packet_contains(raw: Any, query: str) -> int:
    # API storage escapes non-ASCII JSON. Search decoded submitted strings too,
    # so human text (including Unicode and line breaks) remains searchable.
    if _contains(raw, query):
        return 1
    pending = [_decode(raw, "search packet", [])]
    while pending:
        value = pending.pop()
        if _contains(value, query):
            return 1
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return 0


def _operators(
    conn: sqlite3.Connection,
    tables: set[str],
    seed: dict[str, Any],
    packet: dict[str, Any],
    challenges: list[dict[str, Any]],
    witnesses: list[dict[str, Any]],
    standing: list[dict[str, Any]],
    missing: list[str],
) -> dict[str, Any]:
    actors: dict[str, set[str]] = {}

    def add(actor: Any, role: str) -> None:
        if isinstance(actor, str) and actor:
            actors.setdefault(actor, set()).add(role)

    add(seed.get("claimant_identity"), "claimant")
    for challenge in challenges:
        add(challenge.get("challenger_identity"), "challenger")
    for event in witnesses:
        add(
            event.get("actor_identity"),
            "witness" if event.get("event_type") in {"affirm", "refuse"} else "event_actor",
        )
    for lease in standing:
        add(lease.get("issued_by"), "standing_issuer")

    disclosures = []
    for actor, roles in actors.items():
        identities = []
        if "sab_agent_identities_v1" in tables:
            candidates = _rows(
                conn,
                "SELECT * FROM sab_agent_identities_v1 WHERE subject_id IN (?, ?)",
                (actor, actor.removeprefix("sab_identity_")),
            )
            # A display name cannot bind a historical actor to whichever
            # operator most recently registered that name. Keep it unknown.
            identities = candidates
        if not identities:
            missing.append(f"operator disclosure for {actor}: no matching stored identity record.")
            disclosures.append(
                {
                    "actor_identity": actor,
                    "roles": sorted(roles),
                    "source": "missing",
                    "operator_id": None,
                    "operator_backing": None,
                }
            )
        for row in identities:
            disclosures.append(
                {
                    **row,
                    "actor_identity": actor,
                    "roles": sorted(roles),
                    "source": "sab_agent_identities_v1",
                    "identity": _decode(row.get("identity_json"), f"identity {actor}", missing),
                    "operator_backing": _decode(
                        row.get("operator_backing_json"), f"operator backing {actor}", missing
                    ),
                }
            )
    if "operator_backing" in packet:
        disclosures.append(
            {
                "actor_identity": seed.get("claimant_identity"),
                "roles": ["claimant"],
                "source": "original_packet.operator_backing",
                "operator_backing": packet["operator_backing"],
                "operator_id": _object(packet["operator_backing"]).get("operator_id"),
            }
        )
    return {
        "disclosures": disclosures,
        "independently_verified": [],
        "independently_verified_count": None,
        "independence_status": "unknown",
        "check": _check(
            "operator_independence",
            "Independent operator control",
            "not_checked",
            "Stored operator disclosures, distinct keys and different operator strings do not establish independent control.",
        ),
    }


def load_claim_dossier(
    conn: sqlite3.Connection, seed_id: str, *, observed_at: datetime | None = None,
    publication_observation: PublicationObservation | None = None,
) -> dict[str, Any] | None:
    """Return one complete dossier, or None when the exact seed is not stored."""
    publication = publication_observation or current_publication_observation()
    now = publication.observed_at if publication is not None else observed_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    with _read_snapshot(conn):
        return _load_dossier(conn, seed_id, now, publication)


def _load_dossier(
    conn: sqlite3.Connection, seed_id: str, now: datetime,
    publication: PublicationObservation | None = None,
) -> dict[str, Any] | None:
    tables = _tables(conn)
    if "sab_seed_packets_v1" not in tables:
        return None
    seeds = _rows(conn, "SELECT * FROM sab_seed_packets_v1 WHERE seed_id = ?", (seed_id,))
    if not seeds:
        return None
    seed = seeds[0]
    missing: list[str] = []
    original_packet = _decode(seed.get("packet_json"), "original_packet", missing)
    packet = _object(original_packet)
    if not isinstance(original_packet, dict):
        missing.append("original_packet: submitted packet is not a readable object.")
    submitted_claim = packet.get("claim")
    claim = _object(submitted_claim)
    for field in ("text", "scope", "decision_context"):
        if not isinstance(claim.get(field), str) or not claim[field]:
            missing.append(
                f"claim.{field}: missing or not a non-empty string; no substitute is inferred."
            )

    def related(
        table: str, condition: str, parameters: tuple, order: str = "id ASC"
    ) -> list[dict[str, Any]]:
        if table not in tables:
            missing.append(f"{table}: storage table is unavailable.")
            return []
        # SQL identifiers and expressions come from fixed calls below; values are bound.
        return _rows(
            conn,
            f"SELECT * FROM {table} WHERE {condition} ORDER BY {order}",  # nosec B608
            parameters,
        )

    challenge_rows = related("sab_challenge_packets_v1", "target_seed_id = ?", (seed_id,))
    event_rows = related(
        "sab_witness_events_v1",
        "subject_seed_id = ? OR chain_scope = ?",
        (seed_id, seed_id),
        "chain_scope ASC, id ASC",
    )
    state_rows = related("sab_seed_events_v1", "seed_id = ?", (seed_id,))
    standing_rows = related("sab_standing_leases_v1", "subject_seed_id = ?", (seed_id,), "id DESC")
    links = _links(seed_id)
    if not isinstance(original_packet, dict):
        links["seed"] = _record_link("seed", seed_id, force_query=True)
    evidence = _evidence(packet.get("evidence_bundle"), "original_packet.evidence_bundle", missing)
    checks = [
        _check(
            "packet_json",
            "Stored packet JSON object",
            "passed" if isinstance(original_packet, dict) else "failed",
            "Only JSON object readability is checked; this does not validate the seed schema.",
        ),
        _digest_check(
            "packet_digest", "Submitted packet digest", original_packet, seed.get("packet_hash")
        ),
    ]
    identifier_checks = [packet.get("seed_id") == seed_id]
    if "claim_id" in claim:
        identifier_checks.append(claim["claim_id"] == seed.get("claim_id"))
    checks.append(
        _check(
            "packet_identifiers",
            "Stored seed and claim identifiers",
            (
                "not_checked"
                if "seed_id" not in packet
                else "passed" if all(identifier_checks) else "failed"
            ),
            "Compares supplied packet identifiers with the stored seed and claim identifiers; claim IDs need not be unique across submissions.",
        )
    )

    challenges = []
    challenge_checks = []
    for row in challenge_rows:
        document = _decode(
            row.get("packet_json"), f"challenge {row.get('challenge_id')}.packet", missing
        )
        response = (
            _decode(
                row.get("response_json"), f"challenge {row.get('challenge_id')}.response", missing
            )
            if row.get("response_json")
            else None
        )
        digest = _digest_check(
            "challenge_packet_digest", "Challenge packet digest", document, row.get("packet_hash")
        )
        challenge_checks.append(digest)
        link = _record_link(
            "challenge",
            str(row["challenge_id"]),
            force_query=not isinstance(document, dict)
            or bool(row.get("response_json") and response is None),
        )
        links["challenges"].append(link)
        unresolved = row.get("status") in OPEN_CHALLENGE_STATUSES
        if row.get("status") not in CHALLENGE_STATUSES:
            unresolved = None
            missing.append(
                f"challenge {row.get('challenge_id')}.status: unrecognized stored label; resolution is unknown."
            )
        challenges.append(
            {
                **row,
                "challenge_packet": document,
                "response": response,
                "unresolved": unresolved,
                "resolution_state": (
                    "unknown" if unresolved is None else "unresolved" if unresolved else "resolved"
                ),
                "respond_by": row.get("respond_by"),
                "prosecute_by": row.get("prosecute_by"),
                "respond_deadline": _time_observation(row.get("respond_by"), now, publication),
                "prosecute_deadline": _time_observation(row.get("prosecute_by"), now, publication),
                **({"status_basis": "stored"} if publication is not None else {}),
                "evidence": _evidence(
                    _object(document).get("evidence"),
                    f"challenge {row.get('challenge_id')}.evidence",
                    missing,
                ),
                "checks": [digest],
                "links": {"challenge": link},
            }
        )
    checks.append(
        _aggregate(
            "challenge_packet_digests",
            "Challenge packet digests",
            challenge_checks,
            "Each available challenge document is compared with its stored unsigned canonical digest.",
        )
    )

    events = _history(event_rows, missing)
    for event in events:
        event["links"] = {
            "event": _record_link(
                "witness_event",
                str(event["event_id"]),
                force_query=not isinstance(event["payload"], dict),
            )
        }
    if any(not isinstance(event["payload"], dict) for event in events):
        links["chain"] = _record_link("chain", seed_id, force_query=True)
    state_events = _history(state_rows, missing)
    corrections = []
    seen_correction_witnesses = set()
    for event in state_events:
        if event.get("event_type") == "correction":
            corrections.append(
                {
                    **event,
                    "source": "sab_seed_events_v1",
                    "correction": _object(event["payload"]).get("correction"),
                }
            )
            seen_correction_witnesses.add(event.get("witness_event_id"))
    for event in events:
        if (
            event.get("event_type") == "correction"
            and event.get("event_id") not in seen_correction_witnesses
        ):
            corrections.append(
                {
                    **event,
                    "source": "sab_witness_events_v1",
                    "correction": _object(event["payload"]).get("correction"),
                }
            )

    correction_checks = []
    for correction in corrections:
        payload = _object(correction.get("payload"))
        stored = payload.get("correction_hash")
        value = payload.get("correction")
        computed = (
            _hash_json(value if isinstance(value, dict) else {"value": value})
            if "correction" in payload
            else None
        )
        check = _check(
            "correction_payload_digest",
            "Recorded correction payload digest",
            (
                "not_checked"
                if computed is None or not isinstance(stored, str)
                else "passed" if computed == stored else "failed"
            ),
            "Recomputes the correction digest using the original correction endpoint's object-or-value encoding; no replacement claim is inferred.",
            stored=stored,
            computed=computed,
        )
        correction["checks"] = [check]
        correction_checks.append(check)
    checks.append(
        _aggregate(
            "correction_payload_digests",
            "Recorded correction payload digests",
            correction_checks,
            "Only recorded correction payload digests are compared; the submitted seed stays unchanged.",
        )
    )

    submit_hashes = [
        _object(event.get("payload")).get("seed_packet_hash")
        for event in events
        if event.get("event_type") == "submit"
    ]
    supplied_submit_hashes = [value for value in submit_hashes if isinstance(value, str) and value]
    checks.append(
        _check(
            "submission_packet_binding",
            "Submission event packet reference",
            (
                "not_checked"
                if not supplied_submit_hashes
                else (
                    "passed"
                    if all(value == seed.get("packet_hash") for value in supplied_submit_hashes)
                    else "failed"
                )
            ),
            "Compares packet hashes quoted by stored submit events with the stored packet hash; event signatures and an external immutable head remain unchecked.",
            referenced_hashes=supplied_submit_hashes,
        )
    )
    if not supplied_submit_hashes:
        missing.append(
            "submission event: no recorded packet hash reference is available for comparison."
        )

    chain_check = _check(
        "event_hashes_and_links",
        "Event hashes and previous-hash links",
        (
            "not_checked"
            if not event_rows
            else "passed" if _verify_witness_rows(event_rows) else "failed"
        ),
        "Recomputes stored event material and previous-hash links from genesis for every returned chain scope; does not authenticate signatures, prove completeness against an external head, or validate transition semantics.",
    )
    payload_checks = []
    for event in events:
        raw = event.get("payload_json")
        computed = _sha256_hex(raw.encode("utf-8")) if isinstance(raw, str) else None
        check = _check(
            "witness_payload_digest",
            "Witness payload byte digest",
            (
                "not_checked"
                if computed is None
                else "passed" if computed == event.get("payload_hash") else "failed"
            ),
            "SHA-256 of exactly the stored UTF-8 payload_json text.",
            stored=event.get("payload_hash"),
            computed=computed,
        )
        event["checks"] = [check]
        payload_checks.append(check)
    scope_check = _check(
        "witness_seed_scope",
        "Witness chain seed scope",
        (
            "not_checked"
            if not events
            else (
                "passed"
                if all(
                    e.get("chain_scope") == seed_id and e.get("subject_seed_id") == seed_id
                    for e in events
                )
                else "failed"
            )
        ),
        "Checks that every selected event belongs to this seed's chain scope and subject seed.",
    )
    payload_check = _aggregate(
        "witness_payload_digests",
        "Witness payload byte digests",
        payload_checks,
        "Compares stored payload_json UTF-8 bytes with each stored payload_hash; no external evidence is checked.",
    )
    checks.extend([chain_check, payload_check, scope_check])
    if not events:
        missing.append(
            "witness chain: no events are recorded; an empty chain is not a passed integrity check."
        )

    standing = []
    standing_checks = []
    for row in standing_rows:
        document = _decode(
            row.get("lease_json"), f"standing {row.get('standing_id')}.lease", missing
        )
        lease = _object(document)
        observation = observe_standing_status(
            str(row.get("status") or "unknown"), row.get("expiry"), observed_at=now,
            publication_observation=publication,
        )
        if row.get("status") not in STANDING_STATUSES:
            observation.update(status="unknown", status_basis="invalid_stored_status")
            missing.append(
                f"standing {row.get('standing_id')}.status: unrecognized stored label; standing observation is unknown."
            )
        digest = _digest_check(
            "standing_lease_digest", "Standing lease digest", document, row.get("lease_hash")
        )
        standing_checks.append(digest)
        for field in ("allowed_reliance", "forbidden_reliance"):
            if field not in lease:
                missing.append(
                    f"standing {row.get('standing_id')}.{field}: not recorded; no permission is inferred."
                )
        issued_under = (
            _decode(
                row.get("issued_under_json"),
                f"standing {row.get('standing_id')}.issued_under",
                missing,
            )
            if row.get("issued_under_json")
            else None
        )
        link = _record_link(
            "standing",
            str(row["standing_id"]),
            force_query=not isinstance(document, dict)
            or bool(row.get("issued_under_json") and issued_under is None),
        )
        links["standing"].append(link)
        history = related("sab_standing_events_v1", "standing_id = ?", (row["standing_id"],))
        standing.append(
            {
                **row,
                **observation,
                "standing_lease": document,
                "allowed_reliance": lease.get("allowed_reliance"),
                "forbidden_reliance": lease.get("forbidden_reliance"),
                "allowed_actions": lease.get("allowed_actions"),
                "forbidden_actions": lease.get("forbidden_actions"),
                "policy_hash": lease.get("policy_hash"),
                "issued_under": issued_under,
                "expiry_observation": _time_observation(row.get("expiry"), now, publication),
                "checks": [digest],
                "events": _history(history, missing),
                "links": {"standing": link},
                "reliance_status": "unestablished",
            }
        )
    checks.append(
        _aggregate(
            "standing_lease_digests",
            "Standing lease digests",
            standing_checks,
            "Compares the original unsigned lease document with its stored digest; runtime status is a separate observation.",
        )
    )

    operators = _operators(conn, tables, seed, packet, challenges, events, standing, missing)
    checks.extend(
        [
            _check(
                "signatures",
                "Cryptographic signatures",
                "not_checked",
                "Stored signatures are disclosed; this reader does not replay signature verification.",
            ),
            evidence["bytes_check"],
            operators["check"],
            _check(
                "schema_validation",
                "Document schema validation",
                "not_checked",
                "Historical documents are exposed without claiming conformance to current schemas.",
            ),
            _check(
                "authority_policy",
                "Permission for a proposed reliance action",
                "not_checked",
                "No proposed action, policy proof or independently checked authority basis is evaluated by this read-only dossier.",
            ),
        ]
    )
    unresolved = [item["challenge_id"] for item in challenges if item["unresolved"]]
    unknown_challenges = [item["challenge_id"] for item in challenges if item["unresolved"] is None]
    reasons = [
        "This dossier has no authority or standing effect; stored lifecycle labels and matching hashes do not establish permission."
    ]
    if not standing:
        reasons.append("No scoped standing lease is recorded for this exact seed.")
    for lease in standing:
        reasons.append(
            f"Standing {lease['standing_id']}: stored status {lease['stored_status']}; observed status {lease['status']} ({lease['status_basis']}). Its scope and declared reliance lists are not a checked permission."
        )
    if unresolved:
        reasons.append(
            f"{len(unresolved)} challenge(s) remain unresolved (pending or responded); elapsed deadlines do not resolve them on read."
        )
    if unknown_challenges:
        reasons.append(
            f"{len(unknown_challenges)} challenge(s) have an unknown resolution status; the known-open count is not a complete resolution assessment."
        )
    if any(check["state"] == "failed" for check in checks):
        reasons.append("At least one local integrity or readability check failed.")
    if missing:
        reasons.append(
            "Missing or malformed records are listed in missing_data; absent evidence is not proof."
        )
    reasons.append(
        "Signatures, referenced evidence bytes, independent operator control and action-specific authority remain unchecked."
    )
    reliance_check = _check(
        "reliance",
        "Reliance permission",
        "not_checked",
        "The dossier is an inspection record; reliance remains unestablished.",
    )

    return _publication_response({
        "schema": "sab.claim_dossier.v1",
        "observed_at": now.isoformat(),
        "source": {"kind": "sab_v1_store", "snapshot": "single_read_transaction"},
        "authority_effect": "none",
        "standing_effect": "none",
        "identity": {
            "seed_id": seed_id,
            "claim_id": seed.get("claim_id"),
            "packet_hash": seed.get("packet_hash"),
            "packet_schema": packet.get("schema"),
            "version_meaning": "This exact submission is identified by seed_id and the stored unsigned packet hash. claim_id can recur; no numeric version or current replacement packet is inferred.",
        },
        "seed": {
            **{key: value for key, value in seed.items() if key != "packet_json"},
            "stored_state": seed.get("state"),
            **({"state_basis": "stored"} if publication is not None else {}),
        },
        "claim": {
            **_claim_text_fields(claim),
            **{
                field: claim.get(field)
                for field in ("claim_type", "success_conditions", "failure_conditions")
            },
            "submitted": submitted_claim,
            "claim_id": claim.get("claim_id"),
            "current_corrected_text": None,
        },
        "original_packet": original_packet,
        "original_packet_json": seed.get("packet_json"),
        "evidence": evidence,
        "challenges": {
            "items": challenges,
            "unresolved_count": len(unresolved),
            "unresolved_count_basis": "known_open_records",
            "unknown_status_count": len(unknown_challenges),
            "resolution_complete": not unknown_challenges and "sab_challenge_packets_v1" in tables,
            "availability": "present" if "sab_challenge_packets_v1" in tables else "missing",
            "meaning": "Both pending and responded are unresolved. The response field is the latest stored response; witness history preserves recorded actions.",
        },
        "corrections": {
            "items": corrections,
            "availability": (
                "present"
                if "sab_seed_events_v1" in tables and "sab_witness_events_v1" in tables
                else "partial"
            ),
            "meaning": "Correction events append recorded payloads; they do not rewrite this submitted packet or establish a replacement version.",
        },
        "witness": {
            "events": events,
            "state_events": state_events,
            "head": events[-1]["event_hash"] if events else None,
            "total_count": len(events),
            "complete": "sab_witness_events_v1" in tables,
            "availability": (
                "present" if events else "empty" if "sab_witness_events_v1" in tables else "missing"
            ),
            "checks": [chain_check, payload_check, scope_check],
        },
        "standing": {
            "items": standing,
            "availability": "present" if "sab_standing_leases_v1" in tables else "missing",
        },
        "operators": operators,
        "checks": checks,
        "finality": {
            "stored_seed_state": seed.get("state"),
            "terminal_state": seed.get("state") in FINAL_SEED_STATES,
            "challenge_window": _time_observation(seed.get("challenge_window_closes_at"), now, publication),
            "unresolved_challenge_ids": unresolved,
            "unknown_challenge_ids": unknown_challenges,
            "meaning": "Stored finality and elapsed windows do not establish truth or permission.",
        },
        "reliance": {"status": "unestablished", "reasons": reasons, "check": reliance_check},
        "missing_data": list(dict.fromkeys(missing)),
        "links": links,
    }, publication)


def load_claim_record(
    conn: sqlite3.Connection, kind: str, identifier: str, *, observed_at: datetime | None = None,
    publication_observation: PublicationObservation | None = None,
) -> dict[str, Any] | None:
    """Dereference an exact ID that cannot be represented by legacy path routes.

    Record fallbacks are projections from the same read-only dossier; chain
    results carry named checks, without the old endpoint's broad verified flag.
    """
    publication = publication_observation or current_publication_observation()
    now = publication.observed_at if publication is not None else observed_at or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    with _read_snapshot(conn):
        seed_id = identifier
        if kind not in {"seed", "chain", "dossier"}:
            references = {
                "challenge": ("sab_challenge_packets_v1", "challenge_id", "target_seed_id"),
                "standing": ("sab_standing_leases_v1", "standing_id", "subject_seed_id"),
                "witness_event": ("sab_witness_events_v1", "event_id", "subject_seed_id"),
            }
            if kind not in references:
                return None
            table, key, subject = references[kind]
            if table not in _tables(conn):
                return None
            # Identifiers come from the fixed mapping above; the supplied ID is bound.
            rows = _rows(
                conn,
                f"SELECT {subject} AS seed_id FROM {table} WHERE {key} = ?",  # nosec B608
                (identifier,),
            )
            if not rows:
                return None
            seed_id = rows[0]["seed_id"]
        dossier = _load_dossier(conn, seed_id, now, publication)
        if dossier is None or kind == "dossier":
            return dossier
        if kind == "seed":
            return _publication_response({
                **dossier["seed"],
                "schema": "sab.seed_packet.v1",
                "seed_packet": dossier["original_packet"],
                "packet_json": dossier["original_packet_json"],
                "witness_head": dossier["witness"]["head"],
            }, publication)
        if kind == "chain":
            witness = dossier["witness"]
            return _publication_response({
                "seed_id": seed_id,
                "head": witness["head"],
                "entries": witness["events"],
                "events": witness["events"],
                "state_events": witness["state_events"],
                "checks": witness["checks"],
                "total_count": witness["total_count"],
                "complete": witness["complete"],
            }, publication)
        collection, item_key = {
            "challenge": (dossier["challenges"]["items"], "challenge_id"),
            "standing": (dossier["standing"]["items"], "standing_id"),
            "witness_event": (dossier["witness"]["events"], "event_id"),
        }[kind]
        item = next((item for item in collection if item[item_key] == identifier), None)
        return _publication_response(item, publication) if item is not None else None


def list_claims(
    conn: sqlite3.Connection, *, q: str = "", state: str = "", limit: int = 20, offset: int = 0,
    publication_observation: PublicationObservation | None = None,
) -> dict[str, Any]:
    """Search stored submissions without conflating claim IDs or advancing state.

    Search is a literal, Unicode case-insensitive substring search of IDs,
    title and stored packet text. Limits apply after filtering; total and
    page share one read snapshot. Dossier content itself is never truncated.
    """
    publication = publication_observation or current_publication_observation()
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    q = str(q or "")
    state = str(state or "")
    with _read_snapshot(conn):
        tables = _tables(conn)
        result: dict[str, Any] = _publication_response({
            "schema": "sab.claim_ledger.v1",
            "items": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "q": q,
            "state": state,
            "has_more": False,
            "availability": "present" if "sab_seed_packets_v1" in tables else "missing",
            "state_basis": "stored",
            "search_basis": "literal Unicode case-insensitive substring of seed ID, claim ID, title or stored packet text",
        }, publication)
        if "sab_seed_packets_v1" not in tables:
            return result
        clauses = []
        parameters: list[Any] = []
        if q:
            conn.create_function("sab_dossier_contains", 2, _contains, deterministic=True)
            conn.create_function(
                "sab_dossier_packet_contains", 2, _packet_contains, deterministic=True
            )
            clauses.append(
                "(sab_dossier_contains(seed_id, ?) OR sab_dossier_contains(claim_id, ?) OR sab_dossier_contains(title, ?) OR sab_dossier_packet_contains(packet_json, ?))"
            )
            parameters.extend([q] * 4)
        if state:
            clauses.append("state = ?")
            parameters.append(state)
        # Clauses are fixed literals; search, state and pagination values are bound.
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        result["total"] = _rows(
            conn,
            "SELECT count(*) AS total FROM sab_seed_packets_v1" + where,  # nosec B608
            tuple(parameters),
        )[0]["total"]
        rows = _rows(
            conn,
            "SELECT * FROM sab_seed_packets_v1" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",  # nosec B608
            (*parameters, limit, offset),
        )
        for row in rows:
            malformed: list[str] = []
            packet = _object(_decode(row.get("packet_json"), "original_packet", malformed))
            claim = _object(packet.get("claim"))
            unresolved = None
            unknown_challenge_status_count = None
            standing_count = None
            if "sab_challenge_packets_v1" in tables:
                unresolved = _rows(
                    conn,
                    "SELECT count(*) AS total FROM sab_challenge_packets_v1 WHERE target_seed_id = ? AND status IN ('pending', 'responded')",
                    (row["seed_id"],),
                )[0]["total"]
                unknown_challenge_status_count = _rows(
                    conn,
                    "SELECT count(*) AS total FROM sab_challenge_packets_v1 WHERE target_seed_id = ? AND (status NOT IN ('pending', 'responded', 'sustained', 'rejected', 'sustained_by_default', 'lapsed') OR status IS NULL)",
                    (row["seed_id"],),
                )[0]["total"]
            if "sab_standing_leases_v1" in tables:
                standing_count = _rows(
                    conn,
                    "SELECT count(*) AS total FROM sab_standing_leases_v1 WHERE subject_seed_id = ?",
                    (row["seed_id"],),
                )[0]["total"]
            result["items"].append(
                {
                    **{
                        field: row.get(field)
                        for field in (
                            "seed_id",
                            "claim_id",
                            "title",
                            "packet_hash",
                            "created_at",
                            "updated_at",
                        )
                    },
                    **_claim_text_fields(claim),
                    "stored_state": row.get("state"),
                    "unresolved_challenge_count": unresolved,
                    "unknown_challenge_status_count": unknown_challenge_status_count,
                    "standing_count": standing_count,
                    "links": _links(row["seed_id"]),
                    "reliance_status": "unestablished",
                    "missing_data": malformed,
                }
            )
        result["has_more"] = offset + len(rows) < result["total"]
        return result
