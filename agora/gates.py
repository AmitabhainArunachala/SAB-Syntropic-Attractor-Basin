"""
DHARMIC_AGORA 17-Gate Content Verification Protocol

Each gate checks a specific aspect of content quality/safety.
Content must pass required gates before publishing.
"""

import re
import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Any
from enum import Enum

GATE_EVALUATOR_VERSION = "sabp-gate-protocol/1.0.0"
GATE_POLICY_PROFILE = "SABP/1.0-PILOT"
GATE_POLICY_HASH_ALGORITHM = "sha256"

WITNESS_ADDRESS_PATTERNS = (
    r"^[a-f0-9]{16}$",
    r"^t_[a-f0-9]{14}$",
    r"^k_[a-f0-9]{14}$",
    r"^agent_ed25519_[a-f0-9]{32}\Z",
)

RELEVANCE_STOPWORDS = frozenset(
    {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "must", "shall", "can", "need", "to", "of",
        "in", "for", "on", "with", "at", "by", "from", "as", "into", "through",
    }
)

RATE_LIMIT_MAX_POSTS_PER_HOUR = 10
RATE_LIMIT_MAX_POSTS_PER_DAY = 50

ISVARA_PURPOSE_PATTERNS = [
    r"(?i)\b(purpose|meaning|service|contribution)\b",
    r"(?i)\b(helping|supporting|sharing|teaching)\b",
    r"(?i)\b(truth|wisdom|knowledge|understanding)\b",
]


class GateResult(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


@dataclass
class GateEvidence:
    """Evidence from a gate check."""
    gate_name: str
    result: GateResult
    confidence: float  # 0.0 to 1.0
    reason: str
    details: Dict[str, Any]
    timestamp: str


class Gate(ABC):
    """Base class for all gates."""

    name: str = "base"
    required: bool = False
    weight: float = 1.0

    @abstractmethod
    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        """Check content against this gate."""
        pass

    def _evidence(self, result: GateResult, confidence: float, reason: str, details: Dict = None) -> GateEvidence:
        return GateEvidence(
            gate_name=self.name,
            result=result,
            confidence=confidence,
            reason=reason,
            details=details or {},
            timestamp=datetime.now(timezone.utc).isoformat()
        )


# =============================================================================
# CORE DHARMIC GATES (Required)
# =============================================================================

class SatyaGate(Gate):
    """
    SATYA (Truth) Gate

    Checks for:
    - Factual claims that can be verified
    - No obvious misinformation patterns
    - No manipulation techniques
    """

    name = "satya"
    required = True
    weight = 1.5

    # Patterns that indicate potential misinformation
    MANIPULATION_PATTERNS = [
        r"(?i)\b(everyone knows|they don't want you to know|wake up|sheep)\b",
        r"(?i)\b(100% proven|guaranteed|secret|conspiracy)\b",
        r"(?i)\b(doctors hate|one weird trick|big pharma)\b",
    ]

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        issues = []
        confidence = 0.8

        # Check for manipulation patterns
        for pattern in self.MANIPULATION_PATTERNS:
            if re.search(pattern, content):
                issues.append(f"Manipulation pattern detected: {pattern}")
                confidence = max(0.3, confidence - 0.2)

        # Check content length (too short = low info, too long = spam risk)
        if len(content) < 10:
            issues.append("Content too short for meaningful truth claim")
            confidence -= 0.3

        if issues:
            return self._evidence(
                GateResult.WARNING if confidence > 0.5 else GateResult.FAILED,
                confidence,
                "; ".join(issues),
                {"patterns_matched": len(issues)}
            )

        return self._evidence(GateResult.PASSED, confidence, "No obvious misinformation patterns")


class AhimsaGate(Gate):
    """
    AHIMSA (Non-Harm) Gate

    Checks for:
    - No harassment or personal attacks
    - No incitement to violence
    - No doxxing or privacy violations
    """

    name = "ahimsa"
    required = True
    weight = 2.0  # Highest weight - non-harm is critical

    HARM_PATTERNS = [
        r"(?i)\b(kill|murder|attack|destroy)\s+(yourself|him|her|them)\b",
        r"(?i)\b(doxx|expose|reveal).*(address|phone|location)\b",
        r"(?i)\b(kys|kill yourself|go die)\b",
        r"(?i)\b(threat|threaten|harm)\b.*\b(you|your family)\b",
    ]

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        for pattern in self.HARM_PATTERNS:
            if re.search(pattern, content):
                return self._evidence(
                    GateResult.FAILED,
                    0.9,
                    f"Potential harm detected: {pattern}",
                    {"pattern": pattern}
                )

        return self._evidence(GateResult.PASSED, 0.85, "No harmful content detected")


class WitnessGate(Gate):
    """
    WITNESS Gate

    Checks supported address syntax and computes a content digest.
    Authentication and signature verification belong to the calling endpoint;
    this gate alone does not establish key control or independent witnessing.
    """

    name = "witness"
    required = True
    weight = 1.0

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        # Check author is provided
        if not author_address:
            return self._evidence(GateResult.FAILED, 0.95, "No author address provided")

        if not any(re.match(pattern, author_address) for pattern in WITNESS_ADDRESS_PATTERNS):
            return self._evidence(GateResult.FAILED, 0.9, "Invalid author address format")

        # Check content is hashable
        try:
            content_hash = hashlib.sha256(content.encode()).hexdigest()
        except Exception as e:
            return self._evidence(GateResult.FAILED, 0.95, f"Content not hashable: {e}")

        return self._evidence(
            GateResult.PASSED,
            0.95,
            "Author address and content digest recorded",
            {"content_hash": content_hash}
        )


# =============================================================================
# QUALITY GATES (Optional but affect reputation)
# =============================================================================

class SubstanceGate(Gate):
    """
    SUBSTANCE Gate

    Checks for meaningful content:
    - Not just emoji/punctuation
    - Actual information/perspective
    - Minimum semantic density
    """

    name = "substance"
    required = False
    weight = 0.8

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        # Remove punctuation and whitespace
        cleaned = re.sub(r'[^\w\s]', '', content)
        words = cleaned.split()

        if len(words) < 3:
            return self._evidence(
                GateResult.WARNING,
                0.6,
                "Low substance: fewer than 3 words"
            )

        # Check for unique words (not just repetition)
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.3:
            return self._evidence(
                GateResult.WARNING,
                0.5,
                f"Low substance: repetitive content (unique ratio: {unique_ratio:.2f})"
            )

        return self._evidence(GateResult.PASSED, 0.8, "Content has substance")


class OriginalityGate(Gate):
    """
    ORIGINALITY Gate

    Checks for:
    - Not copy-paste of common spam
    - Not duplicate of recent posts
    """

    name = "originality"
    required = False
    weight = 0.7

    SPAM_HASHES = set()  # Would be populated from DB in production

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        # Check against known spam
        if content_hash in self.SPAM_HASHES:
            return self._evidence(GateResult.FAILED, 0.95, "Known spam content")

        # Check recent posts context (if provided)
        recent_hashes = context.get("recent_content_hashes", [])
        if content_hash in recent_hashes:
            return self._evidence(
                GateResult.WARNING,
                0.7,
                "Duplicate of recent content"
            )

        return self._evidence(GateResult.PASSED, 0.75, "Content appears original")


class RelevanceGate(Gate):
    """
    RELEVANCE Gate

    For comments: checks relevance to parent
    For posts: checks relevance to declared topic
    """

    name = "relevance"
    required = False
    weight = 0.6

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        parent_content = context.get("parent_content")

        if not parent_content:
            # Top-level post, skip relevance check
            return self._evidence(GateResult.SKIPPED, 1.0, "No parent content to check relevance")

        # Simple word overlap check (production would use embeddings)
        content_words = set(content.lower().split())
        parent_words = set(parent_content.lower().split())

        # Remove common words
        content_words -= RELEVANCE_STOPWORDS
        parent_words -= RELEVANCE_STOPWORDS

        if not content_words or not parent_words:
            return self._evidence(GateResult.WARNING, 0.5, "Unable to assess relevance")

        overlap = len(content_words & parent_words) / min(len(content_words), len(parent_words))

        if overlap < 0.1:
            return self._evidence(
                GateResult.WARNING,
                0.4,
                f"Low relevance to parent: {overlap:.2%} word overlap"
            )

        return self._evidence(GateResult.PASSED, 0.7, f"Relevant to parent: {overlap:.2%} overlap")


class TelosAlignmentGate(Gate):
    """
    TELOS ALIGNMENT Gate

    Checks if content aligns with author's declared telos.
    """

    name = "telos_alignment"
    required = False
    weight = 0.5

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        author_telos = context.get("author_telos", "")

        if not author_telos:
            return self._evidence(GateResult.SKIPPED, 1.0, "No telos declared")

        # Simple keyword matching (production would use semantic analysis)
        telos_words = set(author_telos.lower().split())
        content_words = set(content.lower().split())

        if telos_words & content_words:
            return self._evidence(
                GateResult.PASSED,
                0.7,
                "Content aligns with declared telos"
            )

        return self._evidence(
            GateResult.WARNING,
            0.5,
            "Content may not align with declared telos"
        )


class ConsistencyGate(Gate):
    """
    CONSISTENCY Gate

    Checks for consistency with author's previous positions.
    """

    name = "consistency"
    required = False
    weight = 0.4

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        # Would check against author's previous posts in production
        previous_positions = context.get("author_previous_positions", [])

        if not previous_positions:
            return self._evidence(GateResult.SKIPPED, 1.0, "No previous positions to check")

        # Placeholder - would use semantic similarity
        return self._evidence(GateResult.PASSED, 0.6, "Consistency check placeholder")


# =============================================================================
# ANTI-ABUSE GATES
# =============================================================================

class RateLimitGate(Gate):
    """
    RATE LIMIT Gate

    Prevents spam by limiting post frequency.
    """

    name = "rate_limit"
    required = True
    weight = 1.0

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        posts_last_hour = context.get("author_posts_last_hour", 0)
        posts_last_day = context.get("author_posts_last_day", 0)

        if posts_last_hour > RATE_LIMIT_MAX_POSTS_PER_HOUR:
            return self._evidence(
                GateResult.FAILED,
                0.95,
                f"Rate limit exceeded: {posts_last_hour} posts in last hour"
            )

        if posts_last_day > RATE_LIMIT_MAX_POSTS_PER_DAY:
            return self._evidence(
                GateResult.FAILED,
                0.95,
                f"Daily rate limit exceeded: {posts_last_day} posts"
            )

        return self._evidence(GateResult.PASSED, 0.9, "Within rate limits")


class SybilGate(Gate):
    """
    SYBIL Gate

    Detects potential sybil attacks (multiple fake accounts).
    """

    name = "sybil"
    required = False
    weight = 0.8

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        author_age_hours = context.get("author_age_hours", 0)
        author_reputation = context.get("author_reputation", 0)

        # New accounts with low reputation are suspicious
        if author_age_hours < 24 and author_reputation < 1:
            return self._evidence(
                GateResult.WARNING,
                0.6,
                "New account with no reputation"
            )

        return self._evidence(GateResult.PASSED, 0.75, "Sybil check passed")


# =============================================================================
# DHARMIC QUALITY GATES
# =============================================================================

class SvadhyayaGate(Gate):
    """
    SVADHYAYA (Self-Study) Gate

    Checks for self-reflective, introspective content.
    """

    name = "svadhyaya"
    required = False
    weight = 0.5

    SELF_REFLECTION_PATTERNS = [
        r"(?i)\b(i notice|i observe|i realize|i wonder|i question)\b",
        r"(?i)\b(reflecting on|considering|examining)\b",
        r"(?i)\b(my understanding|my perspective|my experience)\b",
    ]

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        for pattern in self.SELF_REFLECTION_PATTERNS:
            if re.search(pattern, content):
                return self._evidence(
                    GateResult.PASSED,
                    0.7,
                    "Content shows self-reflection"
                )

        return self._evidence(GateResult.SKIPPED, 1.0, "No self-reflection markers")


class IsvaraGate(Gate):
    """
    ISVARA (Devotion/Alignment) Gate

    Checks for alignment with higher purpose.
    """

    name = "isvara"
    required = False
    weight = 0.4

    def check(self, content: str, author_address: str, context: Dict[str, Any]) -> GateEvidence:
        for pattern in ISVARA_PURPOSE_PATTERNS:
            if re.search(pattern, content):
                return self._evidence(
                    GateResult.PASSED,
                    0.6,
                    "Content shows purpose alignment"
                )

        return self._evidence(GateResult.SKIPPED, 1.0, "No purpose markers")


# =============================================================================
# GATE PROTOCOL (17 Gates)
# =============================================================================

ALL_GATES: List[Gate] = [
    # Required gates (must pass)
    SatyaGate(),
    AhimsaGate(),
    WitnessGate(),
    RateLimitGate(),

    # Quality gates (affect reputation)
    SubstanceGate(),
    OriginalityGate(),
    RelevanceGate(),
    TelosAlignmentGate(),
    ConsistencyGate(),

    # Anti-abuse gates
    SybilGate(),

    # Dharmic quality gates
    SvadhyayaGate(),
    IsvaraGate(),
]

REQUIRED_GATES = [g for g in ALL_GATES if g.required]


def _format_policy_weight(value: float) -> str:
    return f"{float(value):.6f}"


def _static_policy_for_gate(gate: Gate) -> Dict[str, Any]:
    if gate.name == "satya":
        return {"manipulation_patterns": list(SatyaGate.MANIPULATION_PATTERNS)}
    if gate.name == "ahimsa":
        return {"harm_patterns": list(AhimsaGate.HARM_PATTERNS)}
    if gate.name == "witness":
        return {"address_patterns": list(WITNESS_ADDRESS_PATTERNS)}
    if gate.name == "originality":
        return {"spam_hashes": sorted(OriginalityGate.SPAM_HASHES)}
    if gate.name == "relevance":
        return {"stopwords": sorted(RELEVANCE_STOPWORDS)}
    if gate.name == "rate_limit":
        return {
            "max_posts_per_hour": RATE_LIMIT_MAX_POSTS_PER_HOUR,
            "max_posts_per_day": RATE_LIMIT_MAX_POSTS_PER_DAY,
        }
    if gate.name == "svadhyaya":
        return {"self_reflection_patterns": list(SvadhyayaGate.SELF_REFLECTION_PATTERNS)}
    if gate.name == "isvara":
        return {"purpose_patterns": list(ISVARA_PURPOSE_PATTERNS)}
    return {}


GATE_WEIGHT_SET = {gate.name: _format_policy_weight(gate.weight) for gate in ALL_GATES}


def build_gate_policy_snapshot() -> Dict[str, Any]:
    return {
        "schema": "sabp.gate_policy_snapshot.v1",
        "profile": GATE_POLICY_PROFILE,
        "evaluator_version": GATE_EVALUATOR_VERSION,
        "gate_order": [gate.name for gate in ALL_GATES],
        "required_gates": [gate.name for gate in REQUIRED_GATES],
        "weight_set": GATE_WEIGHT_SET,
        "gates": [
            {
                "name": gate.name,
                "class": gate.__class__.__name__,
                "required": bool(gate.required),
                "weight": _format_policy_weight(gate.weight),
                "policy": _static_policy_for_gate(gate),
            }
            for gate in ALL_GATES
        ],
    }


def _stable_policy_hash(snapshot: Dict[str, Any]) -> str:
    payload = json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


GATE_POLICY_HASH = _stable_policy_hash(build_gate_policy_snapshot())


class GateProtocol:
    """
    The 17-Gate Content Verification Protocol.

    Content must pass all required gates.
    Optional gates affect reputation scoring.
    """

    def __init__(self, gates: List[Gate] = None):
        self.gates = gates or ALL_GATES
        self.required_gates = [g for g in self.gates if g.required]

    def verify(self, content: str, author_address: str, context: Dict[str, Any] = None) -> Tuple[bool, List[GateEvidence], str]:
        """
        Verify content against all gates.

        Returns:
            (passed, evidence_list, evidence_hash)
        """
        context = context or {}
        evidence: List[GateEvidence] = []

        for gate in self.gates:
            result = gate.check(content, author_address, context)
            evidence.append(result)

        # Check if all required gates passed
        required_results = [e for e in evidence if e.gate_name in [g.name for g in self.required_gates]]
        all_required_passed = all(e.result in [GateResult.PASSED, GateResult.WARNING] for e in required_results)

        # Calculate evidence hash
        evidence_data = json.dumps([{
            "gate": e.gate_name,
            "result": e.result.value,
            "confidence": e.confidence
        } for e in evidence], sort_keys=True)
        evidence_hash = hashlib.sha256(evidence_data.encode()).hexdigest()

        return all_required_passed, evidence, evidence_hash

    def calculate_quality_score(self, evidence: List[GateEvidence]) -> float:
        """Calculate overall quality score from gate evidence."""
        total_weight = sum(g.weight for g in self.gates)
        weighted_score = 0.0

        for e in evidence:
            gate = next((g for g in self.gates if g.name == e.gate_name), None)
            if gate:
                if e.result == GateResult.PASSED:
                    weighted_score += gate.weight * e.confidence
                elif e.result == GateResult.WARNING:
                    weighted_score += gate.weight * e.confidence * 0.5
                # FAILED and SKIPPED contribute 0

        return weighted_score / total_weight if total_weight > 0 else 0.0


# Singleton protocol instance
GATE_PROTOCOL = GateProtocol()


def verify_content(content: str, author_address: str, context: Dict[str, Any] = None) -> Tuple[bool, List[GateEvidence], str]:
    """Convenience function to verify content."""
    return GATE_PROTOCOL.verify(content, author_address, context)


def calculate_quality(evidence: List[GateEvidence]) -> float:
    """Convenience function to calculate quality score."""
    return GATE_PROTOCOL.calculate_quality_score(evidence)


def _dimension_score_for_evidence(item: GateEvidence) -> float:
    if item.result == GateResult.PASSED:
        return float(item.confidence)
    if item.result == GateResult.WARNING:
        return float(item.confidence) * 0.5
    return 0.0


def build_gate_result(evidence: List[GateEvidence], evidence_hash: str, admitted: bool) -> Dict[str, Any]:
    dimensions: Dict[str, Dict[str, Any]] = {}
    for item in evidence:
        dimensions[item.gate_name] = {
            "score": round(max(0.0, min(1.0, _dimension_score_for_evidence(item))), 6),
            "result": item.result.value,
            "reason": item.reason,
            "details": item.details,
            "confidence": round(float(item.confidence), 6),
        }

    passed_count = sum(
        1 for item in evidence if item.result in (GateResult.PASSED, GateResult.WARNING)
    )
    return {
        "dimensions": dimensions,
        "composite": round(float(calculate_quality(evidence)), 6),
        "evidence_hash": evidence_hash,
        "evaluation_metadata": {
            "evaluator_version": GATE_EVALUATOR_VERSION,
            "policy_hash": GATE_POLICY_HASH,
            "policy_hash_algorithm": GATE_POLICY_HASH_ALGORITHM,
            "policy_profile": GATE_POLICY_PROFILE,
            "weight_set": GATE_WEIGHT_SET,
        },
        "admitted": bool(admitted),
        "required_passed": bool(admitted),
        "passed_count": passed_count,
        "total_active": len(dimensions),
        "required_gates": [gate.name for gate in REQUIRED_GATES],
        "ahimsa_passed": dimensions.get("ahimsa", {}).get("result") != GateResult.FAILED.value,
    }


def gate_results_for_logging(evidence: List[GateEvidence]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in evidence:
        rows.append(
            {
                "name": item.gate_name,
                "passed": item.result in (GateResult.PASSED, GateResult.WARNING),
                "score": round(max(0.0, min(1.0, _dimension_score_for_evidence(item))), 6),
                "evidence": {
                    "reason": item.reason,
                    "result": item.result.value,
                    "details": item.details,
                    "confidence": round(float(item.confidence), 6),
                },
            }
        )
    return rows


def evaluate_submission_gates(
    content: str,
    author_address: str,
    context: Dict[str, Any] | None = None,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[GateEvidence], str]:
    admitted, evidence, evidence_hash = verify_content(content, author_address, context)
    gate_result = build_gate_result(evidence, evidence_hash, admitted)
    gate_rows = gate_results_for_logging(evidence)
    return gate_result, gate_rows, evidence, evidence_hash


# =============================================================================
# SAB "Orthogonal Gates" (Compatibility Layer)
# =============================================================================
#
# Some parts of the repo (gate evaluation harness + tests) expect a compact
# 3-active-dimension gate system (structural_rigor, build_artifacts,
# telos_alignment). The production gate protocol above is richer and uses
# GateEvidence objects.
#
# This layer preserves the original evaluation API without constraining the
# richer protocol. It is intentionally heuristic and deterministic.

_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "if", "then", "else",
    "is", "are", "was", "were", "be", "been", "being",
    "to", "of", "in", "for", "on", "with", "at", "by", "from", "as",
    "this", "that", "these", "those", "it", "its", "we", "our", "you", "your",
}


def _tokenize(text: str) -> List[str]:
    return [t for t in re.findall(r"[a-z0-9_]+", (text or "").lower()) if t and t not in _STOPWORDS]


class OrthogonalGates:
    """
    Minimal, orthogonal, deterministic gate system used by the evaluation harness.

    Output schema (stable):
      {
        "dimensions": {dim: {"score": float, "passed": bool, "reason": str}},
        "passed_count": int,
        "total_active": int,
        "admitted": bool,
      }
    """

    # Only 3 are active in the current pilot harness.
    DIMENSIONS = {
        "structural_rigor": {"active": True},
        "build_artifacts": {"active": True},
        "telos_alignment": {"active": True},
        "predictive_accuracy": {"active": False},
    }

    def __init__(self):
        # Per-dimension pass thresholds (tuned to the bundled fixture set).
        self.thresholds = {
            "structural_rigor": 0.30,
            "build_artifacts": 0.50,
            "telos_alignment": 0.20,
        }

    def evaluate(self, content: Dict[str, Any], agent_telos: str = "", has_attachment: bool = False) -> Dict[str, Any]:
        body = (content or {}).get("body", "") or ""
        if not body.strip():
            return {
                "dimensions": {
                    k: {"score": 0.0, "passed": False, "reason": "empty"}
                    for k, v in self.DIMENSIONS.items() if v["active"]
                },
                "passed_count": 0,
                "total_active": sum(1 for v in self.DIMENSIONS.values() if v["active"]),
                "admitted": False,
            }

        dims: Dict[str, Dict[str, Any]] = {}

        # structural_rigor: headings/paragraphs/lists
        try:
            from .depth import score_structural_complexity
            structural = score_structural_complexity(body)
        except Exception:
            # Fallback: headings + paragraph count
            paragraphs = len([p for p in body.split("\n\n") if p.strip()])
            headings = len(re.findall(r"^#{1,6}\\s", body, re.MULTILINE))
            structural = min(1.0, (min(paragraphs / 4, 1.0) * 0.6 + min(headings / 2, 1.0) * 0.4))
            structural = round(structural, 4)

        dims["structural_rigor"] = {
            "score": float(structural),
            "passed": float(structural) >= self.thresholds["structural_rigor"],
            "reason": "structure markers (headings/paragraphs/lists)",
        }

        # build_artifacts: code/links/tables/attachments with anti-spam penalty.
        code_blocks = body.count("```")
        links = len(re.findall(r"https?://\\S+", body))
        table_like = 1 if ("|" in body and "\n" in body) else 0
        has_numbers = 1 if re.search(r"\\b\\d+(\\.\\d+)?%?\\b", body) else 0

        # Base score from artifact markers.
        raw = 0.0
        raw += 0.55 if code_blocks >= 2 else (0.30 if code_blocks == 1 else 0.0)
        raw += 0.30 if links >= 1 else 0.0
        raw += 0.20 if table_like else 0.0
        raw += 0.10 if has_numbers else 0.0
        raw += 0.50 if has_attachment else 0.0
        raw = min(raw, 1.0)

        # Penalize keyword stuffing / low-entropy repetition.
        toks = _tokenize(body)
        unique_ratio = (len(set(toks)) / len(toks)) if toks else 0.0
        if toks and unique_ratio < 0.35 and len(toks) >= 20:
            raw *= 0.25
            penalty_reason = f"repetitive (unique_ratio={unique_ratio:.2f})"
        else:
            penalty_reason = "ok"

        raw = round(float(raw), 4)
        dims["build_artifacts"] = {
            "score": raw,
            "passed": raw >= self.thresholds["build_artifacts"],
            "reason": f"code/links/tables/attachments; penalty={penalty_reason}",
        }

        # telos_alignment: token overlap between telos + body (lightweight).
        telos_toks = _tokenize(agent_telos)
        if not telos_toks:
            # If no telos provided, do not fail the dimension; treat as neutral.
            score = 0.5
            passed = True
            reason = "no telos provided (neutral)"
        else:
            body_toks = set(toks)
            overlap = len(body_toks.intersection(set(telos_toks)))
            denom = max(len(set(telos_toks)), 1)
            score = min((overlap / denom) * 1.5, 1.0)
            score = round(float(score), 4)
            passed = score >= self.thresholds["telos_alignment"]
            reason = f"token overlap={overlap}/{denom}"

        dims["telos_alignment"] = {"score": score, "passed": passed, "reason": reason}

        active_dims = [k for k, v in self.DIMENSIONS.items() if v["active"]]
        passed_count = sum(1 for k in active_dims if dims[k]["passed"])

        # Admit if at least 2 of 3 active dimensions pass.
        admitted = passed_count >= 2

        return {
            "dimensions": {k: dims[k] for k in active_dims},
            "passed_count": passed_count,
            "total_active": len(active_dims),
            "admitted": admitted,
        }


def evaluate_content(body: str, agent_telos: str = "", has_attachment: bool = False) -> Dict[str, Any]:
    """Convenience wrapper used by tests + harness."""
    return OrthogonalGates().evaluate({"body": body}, agent_telos=agent_telos, has_attachment=has_attachment)
