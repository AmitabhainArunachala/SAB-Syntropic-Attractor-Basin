"""Scoped operator-control evidence under an explicit local review trust root.

Signatures authenticate accountable reviews of included source material. They
do not establish its external truth or the reviewers' independent control.
Only this registry evaluates current, exact cohorts; serialized observations
are never accepted as proof or permission.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import combinations
from typing import Any

from .authority import AuthorityError
from .key_control import KeyControlError, KeyControlService, canonical_origin
from .sab_identity import canonical_json_bytes, verify_ed25519_signature

POLICY_SCHEMA = "sab.operator_control_policy.v1"
ASSESSMENT_SCHEMA = "sab.operator_cohort_assessment.v1"
PURPOSES = frozenset({"standing_quorum", "high_impact_witness", "challenge_adjudication"})
CATEGORIES = frozenset({"controller_resolution", "signing_custody", "administrator_access",
                        "runtime_control", "delegation_decision_rights", "funding", "conflicts"})
SOURCE_CLASSES = frozenset({"self_report", "custody_inspection", "organizational_record",
                            "financial_record", "delegation_record", "conflict_record"})
NODE_KINDS = frozenset({"participant", "controller", "signing_root", "administrator",
                        "runtime", "delegate", "decision_authority", "funder"})
RELATIONS = frozenset({"controlled_by", "signs_with", "administered_by", "operated_by",
                       "delegates_to", "decided_by", "funded_by", "conflicts_with"})
MAX_BYTES = 1024 * 1024
MAX_DOCUMENT_BYTES = 8192
MAX_ASSESSMENTS = 10000
MAX_EVENTS = 20000
MAX_SCOPE_ASSESSMENTS = 100
MAX_CHALLENGES = 16
FRESHNESS_SECONDS = 120
SUBJECT = r"agent_[A-Za-z0-9_.:-]{2,154}"
HEX = r"[0-9a-f]{64}"
SIGNATURE = r"[0-9a-f]{128}"
ASSESSMENT_ID = r"sab_operator_assessment_[0-9a-f]{24,32}"
CHALLENGE_ID = r"sab_operator_challenge_[0-9a-f]{24,32}"
REVOCATION_ID = r"sab_operator_revoke_[0-9a-f]{24,32}"
RESOURCE_ID = r"control_[A-Za-z0-9_.:-]{3,96}"
EVIDENCE_ID = r"evidence_[A-Za-z0-9_.:-]{3,96}"
_TABLES = ("sab_operator_assessments_v1", "sab_operator_events_v1")
_POLICY_FIELDS = {"schema", "policy_id", "audience", "not_before", "expires_at", "reviewers", "revokers",
                  "max_assessment_ttl_seconds", "max_evidence_age_seconds", "max_common_funding_ppm"}
_ASSESSMENT_FIELDS = {"schema", "assessment_id", "policy_id", "policy_sha256", "audience", "seed_id",
                      "claim_sha256", "purpose", "issued_at", "expires_at", "participants", "graph", "evidence", "replaces"}
_REVIEW_FIELDS = {"reviewer_subject_id", "reviewer_public_key", "assessment_sha256", "observed_at", "findings"}


class OperatorControlError(Exception):
    def __init__(self, code: str, status: int, detail: str):
        super().__init__(detail)
        self.code, self.status, self.detail = code, status, detail


def _error(code="invalid", status=400):
    return OperatorControlError("operator_control_" + code, status,
                                "The operator-control request or evidence cannot be accepted.")


def hash_json(value):
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    def number(value):
        raise ValueError("integer required")
    return json.loads(raw, object_pairs_hook=pairs, parse_float=number, parse_constant=number)


def _copy(value, limit=MAX_BYTES):
    def walk(item, depth=0):
        if depth > 16:
            raise ValueError("depth")
        if item is None or isinstance(item, (str, bool)):
            return
        if type(item) is int and abs(item) <= 9007199254740991:
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or key.lower() in {
                    "private_key", "privatekey", "secret", "password", "bearer_token", "seed_phrase"
                }:
                    raise ValueError("member")
                walk(child, depth + 1)
            return
        if isinstance(item, list):
            for child in item:
                walk(child, depth + 1)
            return
        raise ValueError("JSON value")
    try:
        walk(value)
        raw = canonical_json_bytes(value)
        if len(raw) > limit:
            raise ValueError("size")
        result = _strict(raw)
        if not isinstance(result, dict):
            raise ValueError("object")
        return result
    except (ValueError, TypeError, RecursionError, UnicodeError, OverflowError):
        raise _error() from None


def _closed(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise _error()


def _match(value, pattern):
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise _error()
    return value


def _text(value, maximum=2048):
    if (not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise _error()
    return value


def _list(value, *, minimum=0, maximum=64):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise _error()
    return value


def _ids(value, pattern, *, minimum=0, maximum=64):
    _list(value, minimum=minimum, maximum=maximum)
    for item in value:
        _match(item, pattern)
    if value != sorted(set(value)):
        raise _error()
    return value


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise _error()


def _enum(value, vocabulary):
    if not isinstance(value, str) or value not in vocabulary:
        raise _error()


def _utc(value):
    _match(value, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _error() from None


def _now(value=None):
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, str):
        return _utc(value)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise _error()
    return value


def _audience(value, expected=None):
    try:
        if canonical_origin(value) != value or (expected is not None and value != expected):
            raise ValueError("audience")
    except (ValueError, TypeError, AttributeError):
        raise _error() from None


def _pins(value, minimum):
    _list(value, minimum=minimum, maximum=16)
    for pin in value:
        _closed(pin, {"subject_id", "public_key"})
        _match(pin["subject_id"], SUBJECT)
        _match(pin["public_key"], HEX)
    if (len({p["subject_id"] for p in value}) != len(value)
            or len({p["public_key"] for p in value}) != len(value)
            or value != sorted(value, key=lambda p: p["subject_id"])):
        raise _error()


def validate_policy(policy, audience=None):
    value = _copy(policy)
    _closed(value, _POLICY_FIELDS)
    if value["schema"] != POLICY_SCHEMA:
        raise _error()
    _match(value["policy_id"], r"sab_operator_policy_[A-Za-z0-9_.:-]{3,96}")
    _audience(value["audience"], audience)
    if not _utc(value["not_before"]) < _utc(value["expires_at"]):
        raise _error()
    _integer(value["max_assessment_ttl_seconds"], 1, 604800)
    _integer(value["max_evidence_age_seconds"], 1, 604800)
    _integer(value["max_common_funding_ppm"], 0, 1000000)
    _pins(value["reviewers"], 2)
    _pins(value["revokers"], 1)
    by_subject, by_key = {}, {}
    for pin in value["reviewers"] + value["revokers"]:
        subject, key = pin["subject_id"], pin["public_key"]
        if by_subject.get(subject, key) != key or by_key.get(key, subject) != subject:
            raise _error()
        by_subject[subject], by_key[key] = key, subject
    return value


def load_operator_policy(path, expected_sha256):
    if path is None and expected_sha256 is None:
        return None
    _match(expected_sha256, HEX)
    fd = None
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o022 or not 0 < before.st_size <= MAX_BYTES):
            raise ValueError("file")
        raw = bytearray()
        while len(raw) <= MAX_BYTES:
            chunk = os.read(fd, min(8192, MAX_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size, after.st_mtime_ns, after.st_ctime_ns
        ) or len(raw) != before.st_size:
            raise ValueError("changed")
        value = validate_policy(_strict(raw))
        if hash_json(value) != expected_sha256:
            raise ValueError("pin")
        return value
    except (OSError, TypeError, ValueError, RecursionError, OperatorControlError):
        raise _error("policy_unavailable", 503) from None
    finally:
        if fd is not None:
            os.close(fd)


def _graph(assessment):
    graph = assessment["graph"]
    _closed(graph, {"nodes", "edges"})
    nodes = {}
    for node in _list(graph["nodes"], minimum=2, maximum=128):
        _closed(node, {"node_id", "kind"})
        _enum(node["kind"], NODE_KINDS)
        _match(node["node_id"], SUBJECT if node["kind"] == "participant" else RESOURCE_ID)
        if node["node_id"] in nodes:
            raise _error()
        nodes[node["node_id"]] = node["kind"]
    if list(nodes) != sorted(nodes):
        raise _error()
    participants = {p["subject_id"]: p for p in assessment["participants"]}
    if {n for n, kind in nodes.items() if kind == "participant"} != set(participants):
        raise _error()
    edges, outgoing = set(), {node: [] for node in nodes}
    targets = {"controlled_by": {"controller"}, "signs_with": {"signing_root"},
               "administered_by": {"administrator"}, "operated_by": {"runtime"},
               "delegates_to": {"delegate", "controller"},
               "decided_by": {"decision_authority", "controller"}, "funded_by": {"funder"}}
    order = []
    for edge in _list(graph["edges"], maximum=512):
        _closed(edge, {"source", "target", "relation", "funding_ppm"})
        source, target, relation = edge["source"], edge["target"], edge["relation"]
        _match(source, f"(?:{SUBJECT}|{RESOURCE_ID})")
        _match(target, f"(?:{SUBJECT}|{RESOURCE_ID})")
        _enum(relation, RELATIONS)
        if source not in nodes or target not in nodes or source == target:
            raise _error()
        if nodes[source] == "funder":
            raise _error("ambiguous_funding")
        if relation in targets and nodes[target] not in targets[relation]:
            raise _error()
        key = (source, target, relation)
        if key in edges:
            raise _error()
        edges.add(key)
        order.append(key)
        if relation == "funded_by":
            _integer(edge["funding_ppm"], 1, 1000000)
        elif edge["funding_ppm"] is not None:
            raise _error()
        if relation not in {"funded_by", "conflicts_with"}:
            outgoing[source].append(target)
    if order != sorted(order):
        raise _error()
    visited, visiting, closures = set(), set(), {}

    def visit(node):
        if node in visiting:
            raise _error("contradictory_graph")
        if node not in visited:
            visiting.add(node)
            closure = {node}
            for target in outgoing[node]:
                closure.update(visit(target))
            visiting.remove(node)
            visited.add(node)
            closures[node] = closure
        return closures[node]

    for node in nodes:
        visit(node)
    for subject, participant in participants.items():
        _match(participant["controller_class_id"], RESOURCE_ID)
        closure = closures[subject]
        if {n for n in closure if nodes[n] == "controller"} != {participant["controller_class_id"]}:
            raise _error("contradictory_graph")
        if not {"signing_root", "administrator", "runtime"} <= {nodes[n] for n in closure}:
            raise _error("incomplete_graph")
        if not any(e["source"] in closure and e["relation"] == "decided_by" for e in graph["edges"]):
            raise _error("incomplete_graph")
        if sum(e["funding_ppm"] for e in graph["edges"]
               if e["source"] in closure and e["relation"] == "funded_by") > 1000000:
            raise _error("ambiguous_funding")
    return nodes, closures


def validate_assessment(assessment, *, policy, audience=None, observed_at=None, check_freshness=True):
    value, policy = _copy(assessment), validate_policy(policy, audience)
    _closed(value, _ASSESSMENT_FIELDS)
    _enum(value["purpose"], PURPOSES)
    if (value["schema"] != ASSESSMENT_SCHEMA or value["policy_id"] != policy["policy_id"]
            or value["policy_sha256"] != hash_json(policy)):
        raise _error()
    _audience(value["audience"], policy["audience"])
    _match(value["assessment_id"], ASSESSMENT_ID)
    _match(value["seed_id"], r"sab_seed_[A-Za-z0-9_.:-]{3,128}")
    _match(value["claim_sha256"], HEX)
    issued, expires = _utc(value["issued_at"]), _utc(value["expires_at"])
    if (not _utc(policy["not_before"]) <= issued < expires <= _utc(policy["expires_at"])
            or (expires - issued).total_seconds() > policy["max_assessment_ttl_seconds"]):
        raise _error()
    now = _now(observed_at)
    if check_freshness and (not issued <= now < expires or (now - issued).total_seconds() > FRESHNESS_SECONDS):
        raise _error("expired", 410)
    participants = _list(value["participants"], minimum=2, maximum=16)
    for p in participants:
        _closed(p, {"subject_id", "public_key", "controller_class_id"})
        _match(p["subject_id"], SUBJECT)
        _match(p["public_key"], HEX)
    if (participants != sorted(participants, key=lambda p: p["subject_id"])
            or len({p["subject_id"] for p in participants}) != len(participants)
            or len({p["public_key"] for p in participants}) != len(participants)):
        raise _error()
    _graph(value)
    subjects = {p["subject_id"] for p in participants}
    evidence_ids = []
    for evidence in _list(value["evidence"], minimum=7, maximum=64):
        _closed(evidence, {"evidence_id", "category", "source_class", "source_ref", "observed_at",
                           "valid_until", "subject_ids", "document", "document_sha256"})
        evidence_ids.append(_match(evidence["evidence_id"], EVIDENCE_ID))
        _enum(evidence["category"], CATEGORIES)
        _enum(evidence["source_class"], SOURCE_CLASSES)
        _text(evidence["source_ref"])
        covered = _ids(evidence["subject_ids"], SUBJECT, minimum=1, maximum=16)
        if not set(covered) <= subjects:
            raise _error()
        document = _copy(evidence["document"], MAX_DOCUMENT_BYTES)
        if not document or evidence["document_sha256"] != hash_json(document):
            raise _error("evidence_digest_mismatch")
        observed, until = _utc(evidence["observed_at"]), _utc(evidence["valid_until"])
        if not observed <= issued < until or (issued - observed).total_seconds() > policy["max_evidence_age_seconds"]:
            raise _error("evidence_expired", 410)
        if check_freshness and (not observed <= now < until or (now - observed).total_seconds() > policy["max_evidence_age_seconds"]):
            raise _error("evidence_expired", 410)
    if evidence_ids != sorted(set(evidence_ids)) or {e["category"] for e in value["evidence"]} != CATEGORIES:
        raise _error("evidence_incomplete")
    replaced = value["replaces"]
    if replaced is not None:
        _closed(replaced, {"assessment_id", "assessment_sha256", "challenge_ids"})
        _match(replaced["assessment_id"], ASSESSMENT_ID)
        _match(replaced["assessment_sha256"], HEX)
        _ids(replaced["challenge_ids"], CHALLENGE_ID, maximum=MAX_CHALLENGES)
        if replaced["assessment_id"] == value["assessment_id"]:
            raise _error()
    return value


def validate_review_message(review_without_signature, *, assessment, policy, audience=None,
                            observed_at=None, check_freshness=True):
    policy = validate_policy(policy, audience)
    assessment = validate_assessment(assessment, policy=policy, audience=audience,
                                     observed_at=observed_at, check_freshness=check_freshness)
    value = _copy(review_without_signature)
    _closed(value, _REVIEW_FIELDS)
    pin = {"subject_id": value["reviewer_subject_id"], "public_key": value["reviewer_public_key"]}
    if pin not in policy["reviewers"] or any(
        p["subject_id"] == pin["subject_id"] or p["public_key"] == pin["public_key"] for p in assessment["participants"]
    ) or value["assessment_sha256"] != hash_json(assessment):
        raise _error("reviewer_untrusted", 403)
    observed, now = _utc(value["observed_at"]), _now(observed_at)
    if not _utc(assessment["issued_at"]) <= observed < _utc(assessment["expires_at"]):
        raise _error()
    if check_freshness and (observed > now or (now - observed).total_seconds() > FRESHNESS_SECONDS):
        raise _error("expired", 410)
    artifacts = {e["evidence_id"]: e for e in assessment["evidence"]}
    categories = []
    for finding in _list(value["findings"], minimum=7, maximum=7):
        _closed(finding, {"category", "evidence_ids", "outcome"})
        _enum(finding["category"], CATEGORIES)
        _enum(finding["outcome"], {"supported", "unknown", "contradicted"})
        categories.append(finding["category"])
        ids = _ids(finding["evidence_ids"], EVIDENCE_ID, maximum=64,
                   minimum=1 if finding["outcome"] == "supported" else 0)
        if any(eid not in artifacts or artifacts[eid]["category"] != finding["category"] for eid in ids):
            raise _error()
    if categories != sorted(CATEGORIES):
        raise _error()
    return value


def validate_envelope(envelope, *, policy, audience=None, observed_at=None, check_freshness=True):
    value = _copy(envelope)
    _closed(value, {"assessment", "reviews"})
    assessment = validate_assessment(value["assessment"], policy=policy, audience=audience,
                                     observed_at=observed_at, check_freshness=check_freshness)
    reviewers, keys = [], []
    for review in _list(value["reviews"], minimum=2, maximum=2):
        _closed(review, _REVIEW_FIELDS | {"signature"})
        _match(review["signature"], SIGNATURE)
        message = validate_review_message({k: v for k, v in review.items() if k != "signature"},
                                          assessment=assessment, policy=policy, audience=audience,
                                          observed_at=observed_at, check_freshness=check_freshness)
        if not verify_ed25519_signature(review["reviewer_public_key"], canonical_json_bytes(message), review["signature"]):
            raise _error("signature_invalid", 403)
        reviewers.append(review["reviewer_subject_id"])
        keys.append(review["reviewer_public_key"])
    if reviewers != sorted(set(reviewers)) or len(set(keys)) != 2:
        raise _error("reviewer_untrusted", 403)
    return value


@dataclass(frozen=True)
class OperatorControlPair:
    left_subject_id: str
    right_subject_id: str
    left_controller_class_id: str
    right_controller_class_id: str
    eligible: bool
    reason_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class OperatorControlEvaluation:
    eligible: bool
    grade: str
    participant_subject_ids: tuple[str, ...]
    controller_class_ids: tuple[str, ...]
    assessment_id: str | None
    assessment_sha256: str | None
    policy_sha256: str | None
    observed_at: str | None
    expires_at: str | None
    reason_codes: tuple[str, ...]
    pairs: tuple[OperatorControlPair, ...] = ()

    @property
    def participant_count(self):
        return len(self.participant_subject_ids)

    @property
    def independent_controller_count(self):
        return len(set(self.controller_class_ids)) if self.eligible else 0

    def to_observation(self):
        return {"schema": "sab.operator_control_observation.v1", "eligible": self.eligible,
                "grade": self.grade, "participant_subject_ids": list(self.participant_subject_ids),
                "controller_class_ids": list(self.controller_class_ids), "participant_count": self.participant_count,
                "independent_controller_count": self.independent_controller_count,
                "assessment_id": self.assessment_id, "assessment_sha256": self.assessment_sha256,
                "policy_sha256": self.policy_sha256, "observed_at": self.observed_at,
                "expires_at": self.expires_at, "reason_codes": list(self.reason_codes),
                "pairs": [{"left_subject_id": p.left_subject_id, "right_subject_id": p.right_subject_id,
                           "left_controller_class_id": p.left_controller_class_id,
                           "right_controller_class_id": p.right_controller_class_id, "eligible": p.eligible,
                           "reason_codes": list(p.reason_codes), "evidence_ids": list(p.evidence_ids)} for p in self.pairs],
                "authority_effect": "none", "standing_effect": "none"}


def _grade(envelope, subjects):
    evidence = {e["evidence_id"]: e for e in envelope["assessment"]["evidence"]}
    if any(f["outcome"] == "contradicted" for r in envelope["reviews"] for f in r["findings"]):
        return "unknown"
    complete, corroborated = True, False
    for review in envelope["reviews"]:
        for finding in review["findings"]:
            covered = set()
            for eid in finding["evidence_ids"]:
                item = evidence[eid]
                if item["source_class"] != "self_report" and finding["outcome"] == "supported":
                    covered.update(item["subject_ids"])
                    corroborated = True
            complete &= finding["outcome"] == "supported" and set(subjects) <= covered
    return "verified" if complete else "corroborated" if corroborated else "self_declared"


def _pairs(envelope, subjects, policy):
    assessment = envelope["assessment"]
    nodes, closures = _graph(assessment)
    participants = {p["subject_id"]: p for p in assessment["participants"]}
    evidence_ids = tuple(e["evidence_id"] for e in assessment["evidence"])
    result = []
    for left, right in combinations(subjects, 2):
        lc, rc = closures[left], closures[right]
        reasons = set()
        for node in lc & rc:
            if nodes[node] in {"controller", "signing_root", "administrator", "runtime", "delegate", "decision_authority"}:
                reasons.add("shared_" + nodes[node])
        left_funds, right_funds = {}, {}
        for edge in assessment["graph"]["edges"]:
            a, b, relation = edge["source"], edge["target"], edge["relation"]
            if relation == "conflicts_with" and ((a in lc and b in rc) or (a in rc and b in lc)):
                reasons.add("disclosed_conflict")
            if relation == "funded_by":
                for closure, funds in ((lc, left_funds), (rc, right_funds)):
                    if a in closure:
                        funds[b] = funds.get(b, 0) + edge["funding_ppm"]
        for funder in left_funds.keys() & right_funds.keys():
            if max(left_funds[funder], right_funds[funder]) > policy["max_common_funding_ppm"]:
                reasons.add("common_funding_above_policy")
        for edge in assessment["graph"]["edges"]:
            if edge["relation"] == "conflicts_with" and (
                (edge["source"] in lc | left_funds.keys() and edge["target"] in rc | right_funds.keys())
                or (edge["source"] in rc | right_funds.keys() and edge["target"] in lc | left_funds.keys())
            ):
                reasons.add("disclosed_conflict")
        result.append(OperatorControlPair(left, right, participants[left]["controller_class_id"],
                                          participants[right]["controller_class_id"], not reasons,
                                          tuple(sorted(reasons)), evidence_ids))
    return tuple(result)


def _event_message(message, *, assessment, policy, kind, observed_at=None, check_freshness=True):
    value = _copy(message)
    policy = validate_policy(policy)
    assessment = validate_assessment(assessment, policy=policy, check_freshness=False)
    actor = "challenger" if kind == "challenge" else "revoker"
    id_field = "challenge_id" if kind == "challenge" else "revocation_id"
    fields = {"schema", id_field, "assessment_id", "assessment_sha256", "audience",
              actor + "_subject_id", actor + "_public_key", "reason", "issued_at", "expires_at"}
    if kind == "challenge":
        fields |= {"evidence_ref", "authority_lease", "authority_lease_sha256"}
    _closed(value, fields)
    expected_schema = "sab.operator_control_" + ("challenge" if kind == "challenge" else "revocation") + ".v1"
    if (value["schema"] != expected_schema or value["assessment_id"] != assessment["assessment_id"]
            or value["assessment_sha256"] != hash_json(assessment)):
        raise _error()
    _match(value[id_field], CHALLENGE_ID if kind == "challenge" else REVOCATION_ID)
    _audience(value["audience"], assessment["audience"])
    _match(value[actor + "_subject_id"], SUBJECT)
    _match(value[actor + "_public_key"], HEX)
    _text(value["reason"])
    if kind == "revoke":
        pin = {"subject_id": value["revoker_subject_id"], "public_key": value["revoker_public_key"]}
        if pin not in policy["revokers"]:
            raise _error("revoker_untrusted", 403)
    else:
        _text(value["evidence_ref"])
        _closed(value["authority_lease"], {"lease_ref", "scope", "expires_at", "revoker", "challenge_path"})
        reference = value["authority_lease"]
        _match(reference["lease_ref"], r"sab_lease_[A-Za-z0-9_.:-]{3,128}")
        _text(reference["scope"])
        _utc(reference["expires_at"])
        _text(reference["revoker"])
        _text(reference["challenge_path"])
        _match(value["authority_lease_sha256"], HEX)
    issued, expires, now = _utc(value["issued_at"]), _utc(value["expires_at"]), _now(observed_at)
    if not _utc(assessment["issued_at"]) <= issued < expires or (expires - issued).total_seconds() > FRESHNESS_SECONDS:
        raise _error()
    if check_freshness and not issued <= now < expires:
        raise _error("expired", 410)
    return value


def validate_challenge_message(message, *, assessment, policy, observed_at=None, check_freshness=True):
    return _event_message(message, assessment=assessment, policy=policy, kind="challenge",
                          observed_at=observed_at, check_freshness=check_freshness)


def validate_revocation_message(message, *, assessment, policy, observed_at=None, check_freshness=True):
    return _event_message(message, assessment=assessment, policy=policy, kind="revoke",
                          observed_at=observed_at, check_freshness=check_freshness)


def _event_envelope(envelope, *, assessment, policy, kind, observed_at=None, check_freshness=True):
    value = _copy(envelope)
    field = "challenge" if kind == "challenge" else "revocation"
    actor = "challenger" if kind == "challenge" else "revoker"
    _closed(value, {field, "signature"})
    _match(value["signature"], SIGNATURE)
    message = _event_message(value[field], assessment=assessment, policy=policy, kind=kind,
                             observed_at=observed_at, check_freshness=check_freshness)
    if not verify_ed25519_signature(message[actor + "_public_key"], canonical_json_bytes(message), value["signature"]):
        raise _error("signature_invalid", 403)
    return value


def validate_challenge(envelope, *, assessment, policy, observed_at=None, check_freshness=True):
    return _event_envelope(envelope, assessment=assessment, policy=policy, kind="challenge",
                           observed_at=observed_at, check_freshness=check_freshness)


def validate_revocation(envelope, *, assessment, policy, observed_at=None, check_freshness=True):
    return _event_envelope(envelope, assessment=assessment, policy=policy, kind="revoke",
                           observed_at=observed_at, check_freshness=check_freshness)


def _rows(conn, query, parameters=()):
    cursor = conn.execute(query, parameters)
    names = [f[0] for f in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _tables(conn):
    count = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (?,?)", _TABLES).fetchone()[0]
    if count not in {0, 2}:
        raise _error("inconsistent", 409)
    return count == 2


@contextmanager
def _transaction(conn, *, write):
    owned = not conn.in_transaction
    saved = not owned and write
    try:
        if owned:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        elif saved:
            conn.execute("SAVEPOINT sab_operator_control")
            if _tables(conn):
                conn.execute("UPDATE sab_operator_assessments_v1 SET assessment_id=assessment_id WHERE 0")
            else:
                conn.execute("UPDATE web_agents SET id=id WHERE 0")
        yield
        if owned:
            conn.commit()
        elif saved:
            conn.execute("RELEASE SAVEPOINT sab_operator_control")
    except BaseException as exc:
        if owned:
            conn.rollback()
        elif saved:
            try:
                conn.execute("ROLLBACK TO SAVEPOINT sab_operator_control")
                conn.execute("RELEASE SAVEPOINT sab_operator_control")
            except sqlite3.Error:
                pass
        if isinstance(exc, sqlite3.Error):
            raise _error("storage_unavailable", 503) from None
        raise


def _init_tables(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_operator_assessments_v1 (
        assessment_id TEXT PRIMARY KEY, seed_id TEXT NOT NULL, claim_sha256 TEXT NOT NULL,
        purpose TEXT NOT NULL, assessment_sha256 TEXT NOT NULL, envelope_json TEXT NOT NULL,
        envelope_sha256 TEXT NOT NULL, policy_json TEXT NOT NULL, policy_sha256 TEXT NOT NULL,
        accepted_at TEXT NOT NULL, record_sha256 TEXT NOT NULL)""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_operator_scope
        ON sab_operator_assessments_v1(seed_id,claim_sha256,purpose)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sab_operator_events_v1 (
        event_id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, kind TEXT NOT NULL,
        envelope_json TEXT NOT NULL, envelope_sha256 TEXT NOT NULL, accepted_at TEXT NOT NULL,
        record_sha256 TEXT NOT NULL, FOREIGN KEY(assessment_id) REFERENCES sab_operator_assessments_v1(assessment_id))""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_operator_events ON sab_operator_events_v1(assessment_id,event_id)")
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_operator_revocation
        ON sab_operator_events_v1(assessment_id) WHERE kind='revoke'""")


def _record_hash(row):
    return hash_json({k: v for k, v in row.items() if k != "record_sha256"})


class OperatorControlRegistry:
    def __init__(self, policy, key_control: KeyControlService, authority=None):
        self.key_control = key_control
        self.authority = authority
        self._policy = canonical_json_bytes(validate_policy(policy, key_control.audience)) if policy is not None else None

    @property
    def policy(self):
        return _strict(self._policy) if self._policy is not None else None

    @property
    def policy_sha256(self):
        return hashlib.sha256(self._policy).hexdigest() if self._policy is not None else None

    def _time(self):
        try:
            return self.key_control.observe_time()
        except KeyControlError:
            raise _error("clock_uncertain", 503) from None

    def _active(self, conn, subject, key):
        try:
            if self.key_control.require_active_binding(conn, subject) != key:
                raise _error("key_inactive", 403)
        except KeyControlError:
            raise _error("key_inactive", 403) from None

    def _stored(self, conn, row):
        try:
            if row["record_sha256"] != _record_hash(row):
                raise _error()
            if len(row["envelope_json"]) > MAX_BYTES or len(row["policy_json"]) > MAX_BYTES:
                raise _error()
            policy = validate_policy(_strict(row["policy_json"]))
            envelope = validate_envelope(_strict(row["envelope_json"]), policy=policy,
                                         observed_at=row["accepted_at"], check_freshness=True)
            assessment = envelope["assessment"]
            if (row["assessment_sha256"] != hash_json(assessment) or row["envelope_sha256"] != hash_json(envelope)
                    or row["policy_sha256"] != hash_json(policy)
                    or any(row[k] != assessment[k] for k in ("assessment_id", "seed_id", "claim_sha256", "purpose"))
                    or row["envelope_json"] != canonical_json_bytes(envelope).decode()
                    or row["policy_json"] != canonical_json_bytes(policy).decode()):
                raise _error()
            events = _rows(conn, "SELECT * FROM sab_operator_events_v1 WHERE assessment_id=? ORDER BY event_id LIMIT ?",
                           (row["assessment_id"], MAX_CHALLENGES + 2))
            if len(events) > MAX_CHALLENGES + 1:
                raise _error()
            challenges, revocations = [], []
            for event in events:
                if event["kind"] not in {"challenge", "revoke"} or event["record_sha256"] != _record_hash(event):
                    raise _error()
                if len(event["envelope_json"]) > MAX_BYTES:
                    raise _error()
                command = _event_envelope(_strict(event["envelope_json"]), assessment=assessment, policy=policy,
                                          kind=event["kind"], observed_at=event["accepted_at"])
                field = "challenge" if event["kind"] == "challenge" else "revocation"
                id_field = "challenge_id" if event["kind"] == "challenge" else "revocation_id"
                if (event["event_id"] != command[field][id_field]
                        or event["envelope_sha256"] != hash_json(command)
                        or event["envelope_json"] != canonical_json_bytes(command).decode()
                        or _utc(event["accepted_at"]) < _utc(row["accepted_at"])):
                    raise _error()
                (challenges if event["kind"] == "challenge" else revocations).append(event)
            if len(challenges) > MAX_CHALLENGES or len(revocations) > 1:
                raise _error()
            return {"row": row, "envelope": envelope, "policy": policy,
                    "challenges": challenges, "revocations": revocations}
        except (OperatorControlError, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            raise _error("inconsistent", 409) from None

    def _scope(self, conn, seed, claim, purpose):
        if not _tables(conn):
            return {}, None
        rows = _rows(conn, "SELECT * FROM sab_operator_assessments_v1 WHERE seed_id=? AND claim_sha256=? AND purpose=? LIMIT ?",
                     (seed, claim, purpose, MAX_SCOPE_ASSESSMENTS + 1))
        if len(rows) > MAX_SCOPE_ASSESSMENTS:
            raise _error("inconsistent", 409)
        records = {r["assessment_id"]: self._stored(conn, r) for r in rows}
        if not records:
            return records, None
        roots, children = [], {}
        for aid, record in records.items():
            replaces = record["envelope"]["assessment"]["replaces"]
            if replaces is None:
                roots.append(aid)
                continue
            parent = records.get(replaces["assessment_id"])
            if (parent is None or replaces["assessment_id"] in children
                    or parent["row"]["assessment_sha256"] != replaces["assessment_sha256"]
                    or replaces["challenge_ids"] != sorted(e["event_id"] for e in parent["challenges"])
                    or _utc(record["row"]["accepted_at"]) < _utc(parent["row"]["accepted_at"])
                    or _utc(record["envelope"]["assessment"]["issued_at"]) < max(
                        [_utc(parent["row"]["accepted_at"])] + [_utc(e["accepted_at"]) for e in parent["challenges"]])):
                raise _error("inconsistent", 409)
            children[replaces["assessment_id"]] = aid
        if len(roots) != 1:
            raise _error("inconsistent", 409)
        visited, head = set(), roots[0]
        while head not in visited:
            visited.add(head)
            if head not in children:
                break
            head = children[head]
        if len(visited) != len(records) or head in children:
            raise _error("inconsistent", 409)
        return records, head

    def _lookup(self, conn, assessment_id):
        _match(assessment_id, ASSESSMENT_ID)
        if not _tables(conn):
            raise _error("assessment_missing", 404)
        rows = _rows(conn, "SELECT * FROM sab_operator_assessments_v1 WHERE assessment_id=?", (assessment_id,))
        if len(rows) != 1:
            raise _error("assessment_missing", 404)
        row = rows[0]
        records, head = self._scope(conn, row["seed_id"], row["claim_sha256"], row["purpose"])
        return records[assessment_id], head

    def _evaluate(self, conn, record, head, subjects, now):
        assessment, row = record["envelope"]["assessment"], record["row"]
        reasons = []
        if record["revocations"]:
            reasons.append("revoked")
        if record["challenges"]:
            reasons.append("challenged")
        if row["assessment_id"] != head:
            reasons.append("superseded")
        if self.policy is None:
            reasons.append("policy_unavailable")
        elif self.policy_sha256 != row["policy_sha256"]:
            reasons.append("policy_changed")
        policy = record["policy"]
        if not _utc(policy["not_before"]) <= now < _utc(policy["expires_at"]):
            reasons.append("policy_expired")
        if not _utc(assessment["issued_at"]) <= now < _utc(assessment["expires_at"]):
            reasons.append("assessment_expired")
        if assessment["audience"] != self.key_control.audience:
            reasons.append("audience_mismatch")
        participant_map = {p["subject_id"]: p for p in assessment["participants"]}
        if not set(subjects) <= participant_map.keys():
            raise _error("cohort_mismatch", 403)
        for subject in subjects:
            self._active(conn, subject, participant_map[subject]["public_key"])
        for review in record["envelope"]["reviews"]:
            self._active(conn, review["reviewer_subject_id"], review["reviewer_public_key"])
        expiry = min(_utc(assessment["expires_at"]), _utc(policy["expires_at"]))
        for artifact in assessment["evidence"]:
            # Uncounted subjects never add eligibility, but contradictory or
            # stale evidence in the signed dossier cannot be silently discarded.
            observed = _utc(artifact["observed_at"])
            bound = min(_utc(artifact["valid_until"]), observed + timedelta(seconds=policy["max_evidence_age_seconds"]))
            expiry = min(expiry, bound)
            if not observed <= now < bound:
                reasons.append("evidence_expired")
        grade = _grade(record["envelope"], subjects)
        pairs = _pairs(record["envelope"], subjects, policy)
        for pair in pairs:
            reasons.extend(pair.reason_codes)
        if grade != "verified":
            reasons.append("evidence_" + grade)
        if reasons:
            grade = "unknown" if any(r not in {"evidence_self_declared", "evidence_corroborated"} for r in reasons) else grade
        return OperatorControlEvaluation(not reasons, grade, subjects,
                                         tuple(participant_map[s]["controller_class_id"] for s in subjects),
                                         row["assessment_id"], row["assessment_sha256"], row["policy_sha256"],
                                         now.isoformat(), expiry.isoformat(), tuple(sorted(set(reasons))), pairs)

    def evaluate(self, conn, *, assessment_id, assessment_sha256, seed_id, claim_sha256, purpose,
                 participant_subject_ids):
        subjects, aid, digest, observed = (), None, None, None
        try:
            aid = _match(assessment_id, ASSESSMENT_ID)
            digest = _match(assessment_sha256, HEX)
            _match(seed_id, r"sab_seed_[A-Za-z0-9_.:-]{3,128}")
            _match(claim_sha256, HEX)
            _enum(purpose, PURPOSES)
            if not isinstance(participant_subject_ids, (list, tuple)):
                raise _error()
            values = list(participant_subject_ids)
            if not 2 <= len(values) <= 16:
                raise _error("cohort_mismatch", 403)
            for subject in values:
                _match(subject, SUBJECT)
            if len(set(values)) != len(values):
                raise _error("cohort_mismatch", 403)
            subjects = tuple(sorted(values))
            with _transaction(conn, write=False):
                record, head = self._lookup(conn, aid)
                row = record["row"]
                if (row["assessment_sha256"] != digest or row["seed_id"] != seed_id
                        or row["claim_sha256"] != claim_sha256 or row["purpose"] != purpose):
                    raise _error("scope_mismatch", 403)
                now = self._time()
                observed = now.isoformat()
                return self._evaluate(conn, record, head, subjects, now)
        except OperatorControlError as exc:
            return OperatorControlEvaluation(False, "unknown", subjects, (), aid, digest,
                                             self.policy_sha256, observed, None, (exc.code,), ())

    def _observation(self, conn, record, head, *, created=False):
        assessment = record["envelope"]["assessment"]
        result = self.evaluate(conn, assessment_id=assessment["assessment_id"],
                               assessment_sha256=record["row"]["assessment_sha256"], seed_id=assessment["seed_id"],
                               claim_sha256=assessment["claim_sha256"], purpose=assessment["purpose"],
                               participant_subject_ids=[p["subject_id"] for p in assessment["participants"]])
        status = ("revoked" if record["revocations"] else "challenged" if record["challenges"]
                  else "superseded" if assessment["assessment_id"] != head
                  else "eligible" if result.eligible else "ineligible")
        return {**record["envelope"], "assessment_id": assessment["assessment_id"],
                "assessment_sha256": record["row"]["assessment_sha256"],
                "envelope_sha256": record["row"]["envelope_sha256"], "status": status, "created": created,
                "observation": result.to_observation(), "challenge_ids": sorted(e["event_id"] for e in record["challenges"]),
                "authority_effect": "none", "standing_effect": "none"}

    def get(self, conn, assessment_id):
        with _transaction(conn, write=False):
            record, head = self._lookup(conn, assessment_id)
            return self._observation(conn, record, head)

    def _capacity(self, conn, *, for_revocation=False):
        if not _tables(conn):
            return 0, 0, 0
        assessments = conn.execute("SELECT count(*) FROM sab_operator_assessments_v1").fetchone()[0]
        events = conn.execute("SELECT count(*) FROM sab_operator_events_v1").fetchone()[0]
        reserved = conn.execute("""SELECT count(*) FROM sab_operator_assessments_v1 a WHERE NOT EXISTS
            (SELECT 1 FROM sab_operator_events_v1 e WHERE e.assessment_id=a.assessment_id AND e.kind='revoke')""").fetchone()[0]
        if assessments > MAX_ASSESSMENTS or events > MAX_EVENTS or (not for_revocation and events + reserved > MAX_EVENTS):
            raise _error("capacity", 429)
        return assessments, events, reserved

    def issue(self, conn, envelope):
        payload = _copy(envelope)
        _closed(payload, {"assessment", "reviews"})
        aid = payload["assessment"].get("assessment_id") if isinstance(payload["assessment"], dict) else None
        _match(aid, ASSESSMENT_ID)
        with _transaction(conn, write=True):
            if _tables(conn):
                existing = _rows(conn, "SELECT * FROM sab_operator_assessments_v1 WHERE assessment_id=?", (aid,))
                if existing:
                    record, head = self._lookup(conn, aid)
                    if hash_json(payload) != record["row"]["envelope_sha256"]:
                        raise _error("conflict", 409)
                    return self._observation(conn, record, head)
            if self.policy is None:
                raise _error("policy_unavailable", 503)
            now = self._time()
            payload = validate_envelope(payload, policy=self.policy, audience=self.key_control.audience, observed_at=now)
            assessment = payload["assessment"]
            for p in assessment["participants"]:
                self._active(conn, p["subject_id"], p["public_key"])
            for r in payload["reviews"]:
                self._active(conn, r["reviewer_subject_id"], r["reviewer_public_key"])
            for pin in self.policy["revokers"]:
                self._active(conn, pin["subject_id"], pin["public_key"])
            records, head = self._scope(conn, assessment["seed_id"], assessment["claim_sha256"], assessment["purpose"])
            replaces = assessment["replaces"]
            if head is None:
                if replaces is not None:
                    raise _error("predecessor_mismatch", 409)
            elif (replaces is None or replaces["assessment_id"] != head
                  or replaces["assessment_sha256"] != records[head]["row"]["assessment_sha256"]
                  or replaces["challenge_ids"] != sorted(e["event_id"] for e in records[head]["challenges"])
                  or _utc(assessment["issued_at"]) < max(
                      [_utc(records[head]["row"]["accepted_at"])]
                      + [_utc(e["accepted_at"]) for e in records[head]["challenges"]])
                  ):
                raise _error("predecessor_mismatch", 409)
            assessments, events, reserved = self._capacity(conn)
            if assessments >= MAX_ASSESSMENTS or len(records) >= MAX_SCOPE_ASSESSMENTS or events + reserved + 1 > MAX_EVENTS:
                raise _error("capacity", 429)
            row = {"assessment_id": aid, "seed_id": assessment["seed_id"], "claim_sha256": assessment["claim_sha256"],
                   "purpose": assessment["purpose"], "assessment_sha256": hash_json(assessment),
                   "envelope_json": canonical_json_bytes(payload).decode(), "envelope_sha256": hash_json(payload),
                   "policy_json": self._policy.decode(), "policy_sha256": self.policy_sha256, "accepted_at": now.isoformat()}
            row["record_sha256"] = _record_hash(row)
            _init_tables(conn)
            conn.execute("INSERT INTO sab_operator_assessments_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?)", tuple(row.values()))
            record, head = self._lookup(conn, aid)
            return self._observation(conn, record, head, created=True)

    @staticmethod
    def _event_receipt(payload, *, created):
        field = "challenge" if "challenge" in payload else "revocation"
        id_field = "challenge_id" if field == "challenge" else "revocation_id"
        return {**payload, "event_id": payload[field][id_field], "event_sha256": hash_json(payload),
                "assessment_id": payload[field]["assessment_id"],
                "assessment_sha256": payload[field]["assessment_sha256"], "created": created,
                "authority_effect": "none", "standing_effect": "none"}

    def _command(self, conn, envelope, kind):
        payload = _copy(envelope)
        field = "challenge" if kind == "challenge" else "revocation"
        id_field = "challenge_id" if kind == "challenge" else "revocation_id"
        actor = "challenger" if kind == "challenge" else "revoker"
        _closed(payload, {field, "signature"})
        if not isinstance(payload[field], dict):
            raise _error()
        aid, eid = payload[field].get("assessment_id"), payload[field].get(id_field)
        _match(aid, ASSESSMENT_ID)
        _match(eid, CHALLENGE_ID if kind == "challenge" else REVOCATION_ID)
        with _transaction(conn, write=True):
            record, head = self._lookup(conn, aid)
            existing = _rows(conn, "SELECT * FROM sab_operator_events_v1 WHERE event_id=?", (eid,))
            if existing:
                if existing[0]["assessment_id"] != aid or existing[0]["envelope_sha256"] != hash_json(payload):
                    raise _error("conflict", 409)
                return self._event_receipt(payload, created=False)
            now = self._time()
            payload = _event_envelope(payload, assessment=record["envelope"]["assessment"], policy=record["policy"],
                                      kind=kind, observed_at=now)
            message = payload[field]
            _audience(message["audience"], self.key_control.audience)
            self._active(conn, message[actor + "_subject_id"], message[actor + "_public_key"])
            if kind == "challenge":
                if aid != head or record["revocations"]:
                    raise _error("assessment_terminal", 409)
                if len(record["challenges"]) >= MAX_CHALLENGES:
                    raise _error("capacity", 429)
                if self.authority is None:
                    raise _error("authority_required", 428)
                try:
                    grant = self.authority.authorize(conn, message["authority_lease"],
                                                     subject_id=message["challenger_subject_id"],
                                                     action="challenge_operator_control",
                                                     target_seed_id=record["row"]["seed_id"])
                except AuthorityError:
                    raise _error("authority_required", 428) from None
                if grant["lease_sha256"] != message["authority_lease_sha256"]:
                    raise _error("authority_mismatch", 403)
            elif record["revocations"]:
                raise _error("revoked", 409)
            _, events, reserved = self._capacity(conn, for_revocation=kind == "revoke")
            if events >= MAX_EVENTS or (kind == "challenge" and events + reserved + 1 > MAX_EVENTS):
                raise _error("capacity", 429)
            row = {"event_id": eid, "assessment_id": aid, "kind": kind,
                   "envelope_json": canonical_json_bytes(payload).decode(), "envelope_sha256": hash_json(payload),
                   "accepted_at": now.isoformat()}
            row["record_sha256"] = _record_hash(row)
            conn.execute("INSERT INTO sab_operator_events_v1 VALUES (?,?,?,?,?,?,?)", tuple(row.values()))
            return self._event_receipt(payload, created=True)

    def challenge(self, conn, envelope):
        return self._command(conn, envelope, "challenge")

    def revoke(self, conn, envelope):
        return self._command(conn, envelope, "revoke")
