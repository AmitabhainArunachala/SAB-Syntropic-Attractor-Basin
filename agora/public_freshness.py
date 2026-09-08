"""Local age observations for frozen publication, never proof of current standing.

The source timestamp is operator supplied. This module has no trusted UTC or
current revocation input, so passing a local age policy never establishes
currentness. One observer lives for the process lifetime; request contexts only
carry its immutable observations.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any

POLICY_ID = "sab.public_read_freshness.v1"
OBSERVATION_SCHEMA = "sab.public_read_observation.v1"
DEFAULT_MAXIMUM_AGE_SECONDS = 86400
DEFAULT_MAXIMUM_CLOCK_SKEW_SECONDS = 5
_UTC = timezone.utc
_TIME_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_TERMINAL_STANDING = frozenset({"revoked", "expired", "compost", "superseded"})
_KNOWN_STANDING = _TERMINAL_STANDING | {"provisional", "active", "challenged", "canon"}
_CURRENTNESS_REASONS = ("trusted_utc_unverified", "revocation_currentness_unverified")


def _bounded_integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}.")
    return value


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    maximum_age_seconds: int = DEFAULT_MAXIMUM_AGE_SECONDS
    maximum_clock_skew_seconds: int = DEFAULT_MAXIMUM_CLOCK_SKEW_SECONDS

    def __post_init__(self) -> None:
        _bounded_integer(self.maximum_age_seconds, "maximum_age_seconds", 1, 86400)
        _bounded_integer(self.maximum_clock_skew_seconds, "maximum_clock_skew_seconds", 0, 60)

    def to_dict(self) -> dict[str, Any]:
        values = {
            "id": POLICY_ID,
            "maximum_age_seconds": self.maximum_age_seconds,
            "maximum_clock_skew_seconds": self.maximum_clock_skew_seconds,
        }
        encoded = json.dumps(values, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return {**values, "sha256": hashlib.sha256(encoded.encode("ascii")).hexdigest()}


def read_freshness_policy(environ: Mapping[str, str] | None = None) -> FreshnessPolicy:
    source = os.environ if environ is None else environ

    def read(name: str, default: int, minimum: int, maximum: int) -> int:
        if name not in source:
            return default
        value = source[name]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
            raise ValueError(f"{name} must contain only ASCII decimal digits.")
        # Bound conversion itself, including on runtimes with no int digit cap.
        significant = value.lstrip("0") or "0"
        if len(significant) > len(str(maximum)):
            raise ValueError(f"{name} exceeds its operational cap of {maximum}.")
        return _bounded_integer(int(significant), name, minimum, maximum)

    return FreshnessPolicy(
        maximum_age_seconds=read(
            "SAB_PUBLIC_MAX_SNAPSHOT_AGE_SECONDS", DEFAULT_MAXIMUM_AGE_SECONDS, 1, 86400
        ),
        maximum_clock_skew_seconds=read(
            "SAB_PUBLIC_MAX_CLOCK_SKEW_SECONDS", DEFAULT_MAXIMUM_CLOCK_SKEW_SECONDS, 0, 60
        ),
    )


def _aware_utc(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("A timezone-aware datetime is required.")
    return value.astimezone(_UTC)


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _TIME_PATTERN.fullmatch(value):
        return None
    try:
        return _aware_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except (ValueError, OverflowError):
        return None


def _monotonic_number(value: Any) -> float:
    if type(value) not in {int, float}:
        raise ValueError("A finite monotonic reading is required.")
    try:
        number = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError("A finite monotonic reading is required.") from exc
    if not math.isfinite(number):
        raise ValueError("A finite monotonic reading is required.")
    return number


@dataclass(frozen=True, slots=True)
class PublicationObservation:
    observed_at: datetime
    local_age_status: str
    clock_state: str
    source_observed_at: str | None
    manifest_sha256: str | None
    policy: FreshnessPolicy
    age_seconds: float | None
    historical_integrity: str
    clock_reasons: tuple[str, ...] = ()
    effective_time_basis: str = "boot_utc_monotonic_and_wall_maximum"
    warnings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at))
        if not isinstance(self.policy, FreshnessPolicy):
            raise ValueError("An observation requires a validated freshness policy.")
        if self.clock_state not in {"stable", "uncertain"}:
            raise ValueError("An observation requires a stable or uncertain clock state.")
        if self.local_age_status not in {
            "not_configured",
            "within_limit",
            "stale",
            "future_observation",
            "clock_uncertain",
        }:
            raise ValueError("Unsupported local age status.")
        if self.age_seconds is not None and (
            type(self.age_seconds) not in {int, float}
            or not math.isfinite(self.age_seconds)
            or self.age_seconds < 0
        ):
            raise ValueError("Observed age must be finite and nonnegative, or null.")
        for name in ("clock_reasons", "warnings"):
            values = tuple(getattr(self, name))
            if any(not isinstance(value, str) for value in values):
                raise ValueError("Observation explanations must be text.")
            object.__setattr__(self, name, values)

    def to_dict(self) -> dict[str, Any]:
        """Return fresh JSON data, with no mutable references into the observer."""
        remaining = (
            None
            if self.age_seconds is None
            else max(0.0, self.policy.maximum_age_seconds - self.age_seconds)
        )
        return {
            "schema": OBSERVATION_SCHEMA,
            "observed_at": self.observed_at.isoformat(),
            "source_observed_at": self.source_observed_at,
            "manifest_sha256": self.manifest_sha256,
            "policy": self.policy.to_dict(),
            "clock": {
                "source": "local_system_utc",
                "externally_verified": False,
                "status": self.clock_state,
                "reasons": list(self.clock_reasons),
                "effective_time_basis": self.effective_time_basis,
            },
            "local_age_policy": {
                "status": self.local_age_status,
                "age_seconds": self.age_seconds,
                "remaining_seconds": remaining,
            },
            "currentness": {"status": "unestablished", "reasons": list(_CURRENTNESS_REASONS)},
            "historical_integrity": self.historical_integrity,
            "warnings": list(self.warnings),
            "authority_effect": "none",
            "standing_effect": "none",
        }

    def expiry(self, value: Any) -> dict[str, Any]:
        result = {
            "value": copy.deepcopy(value),
            "observed_at": self.observed_at.isoformat(),
            "state": "unknown",
            "elapsed": None,
            "reason": "clock_uncertain",
            "time_basis": "local_system_utc",
        }
        if self.clock_state != "stable":
            return result
        expires_at = _parse_timestamp(value)
        if expires_at is None:
            result["reason"] = "invalid_expiry"
            return result
        elapsed = expires_at <= self.observed_at
        result.update(
            state="elapsed" if elapsed else "not_elapsed",
            elapsed=elapsed,
            reason="local_expiry_elapsed" if elapsed else "local_expiry_not_elapsed",
        )
        return result

    def standing(self, stored_status: Any, expiry: Any) -> dict[str, Any]:
        expiry_observation = self.expiry(expiry)
        result = {
            "status": "unknown",
            "stored_status": copy.deepcopy(stored_status),
            "status_basis": "currentness_unestablished",
            "observed_at": self.observed_at.isoformat(),
            "reason": "snapshot_and_local_time_do_not_establish_current_standing",
            "expiry_observation": expiry_observation,
            "local_age_status": self.local_age_status,
            "currentness": "unestablished",
        }
        if isinstance(stored_status, str) and stored_status in _TERMINAL_STANDING:
            result.update(
                status=stored_status, status_basis="stored", reason="recorded_terminal_status"
            )
        elif not isinstance(stored_status, str) or stored_status not in _KNOWN_STANDING:
            result.update(
                status_basis="invalid_stored_status", reason="unrecognized_recorded_status"
            )
        elif self.clock_state != "stable":
            result.update(status_basis="clock_uncertain", reason="local_clock_is_uncertain")
        elif self.local_age_status != "within_limit":
            basis = {
                "not_configured": "publication_not_configured",
                "stale": "publication_stale",
                "future_observation": "publication_future_observation",
                "clock_uncertain": "clock_uncertain",
            }.get(self.local_age_status, "currentness_unestablished")
            result.update(status_basis=basis, reason=basis)
        elif expiry_observation["state"] == "unknown":
            result.update(
                status_basis="invalid_expiry", reason="expiry_requires_an_aware_timestamp"
            )
        elif expiry_observation["elapsed"]:
            result.update(
                status="expired",
                status_basis="local_expiry_observation",
                reason="expiry_elapsed_on_unverified_local_clock",
            )
        return result


class PublicationFreshnessObserver:
    """Sample one process clock anchor, latching uncertainty and nondecreasing age."""

    def __init__(
        self,
        snapshot_status: Mapping[str, Any],
        policy: FreshnessPolicy,
        *,
        utc_now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ):
        if not isinstance(policy, FreshnessPolicy):
            raise ValueError("A validated FreshnessPolicy is required.")
        status = copy.deepcopy(dict(snapshot_status))
        if type(status.get("configured")) is not bool:
            raise ValueError("Snapshot status must explicitly state whether it is configured.")
        self._configured = status["configured"]
        self._source_time = (
            _parse_timestamp(status.get("observed_at")) if self._configured else None
        )
        if self._configured and self._source_time is None:
            raise ValueError(
                "A configured snapshot requires an aware source observation timestamp."
            )
        manifest_sha256 = status.get("manifest_sha256") if self._configured else None
        if manifest_sha256 is not None and not isinstance(manifest_sha256, str):
            raise ValueError("The manifest digest must be text or null.")
        self._manifest_sha256 = manifest_sha256
        self._policy = policy
        self._utc_now = utc_now if utc_now is not None else lambda: datetime.now(_UTC)
        self._monotonic = monotonic if monotonic is not None else time.monotonic
        self._lock = RLock()
        try:
            self._boot_utc = _aware_utc(self._utc_now())
            self._boot_monotonic = _monotonic_number(self._monotonic())
        except Exception as exc:
            raise ValueError("The initial UTC and monotonic clock readings must be valid.") from exc
        self._last_monotonic = self._boot_monotonic
        self._elapsed_seconds = 0.0
        self._effective = self._boot_utc
        self._initial_age = (
            max(0.0, (self._boot_utc - self._source_time).total_seconds())
            if self._source_time is not None
            else None
        )
        self._age = self._initial_age
        self._future_source = (
            self._source_time is not None
            and (self._source_time - self._boot_utc).total_seconds()
            > policy.maximum_clock_skew_seconds
        )
        self._clock_reasons: list[str] = []

    def _uncertain(self, reason: str) -> None:
        if reason not in self._clock_reasons:
            self._clock_reasons.append(reason)

    def observe(self) -> PublicationObservation:
        with self._lock:
            valid_sample = True
            wall = None
            try:
                wall = _aware_utc(self._utc_now())
            except Exception:
                self._uncertain("utc_reading_invalid_or_failed")
                valid_sample = False
            try:
                monotonic_value = _monotonic_number(self._monotonic())
                if monotonic_value < self._last_monotonic:
                    self._uncertain("monotonic_regressed")
                    valid_sample = False
                else:
                    elapsed = monotonic_value - self._boot_monotonic
                    if not math.isfinite(elapsed):
                        raise ValueError("Monotonic elapsed time is not finite.")
                    # Validate projection before advancing either stored clock anchor.
                    self._boot_utc + timedelta(seconds=elapsed)
                    self._last_monotonic = monotonic_value
                    self._elapsed_seconds = elapsed
            except Exception:
                self._uncertain("monotonic_reading_invalid_or_failed")
                valid_sample = False
            projected = self._boot_utc + timedelta(seconds=self._elapsed_seconds)
            if (
                wall is not None
                and abs((wall - projected).total_seconds())
                > self._policy.maximum_clock_skew_seconds
            ):
                self._uncertain("wall_monotonic_divergence")
            if valid_sample:
                self._effective = max(self._effective, projected, wall)
                time_basis = "boot_utc_monotonic_and_wall_maximum"
            else:
                # Invalid samples carry the previous effective time, explicitly
                # uncertain. A later valid pair may advance it but cannot clear the latch.
                time_basis = "last_valid_effective_utc"
            if self._source_time is not None:
                candidates = [self._age, self._initial_age + self._elapsed_seconds, 0.0]
                if wall is not None:
                    candidates.append((wall - self._source_time).total_seconds())
                self._age = max(candidates)
            if not self._configured:
                local_age_status = "not_configured"
            elif self._clock_reasons:
                local_age_status = "clock_uncertain"
            elif self._future_source:
                local_age_status = "future_observation"
            elif self._age >= self._policy.maximum_age_seconds:
                local_age_status = "stale"
            else:
                local_age_status = "within_limit"
            warnings = [
                "The source observation time is operator supplied; local UTC is not externally verified.",
                "Current revocation status is not established by this frozen snapshot.",
                "Passing a local age policy does not establish currentness or permission to rely.",
            ]
            if not self._configured:
                warnings.append("No public snapshot is configured.")
            if self._future_source:
                warnings.append(
                    "The source observation was ahead of the boot clock beyond the allowed skew."
                )
            if self._age is not None and self._age >= self._policy.maximum_age_seconds:
                warnings.append("The snapshot has reached the configured local age limit.")
            if self._clock_reasons:
                warnings.append(
                    "Clock uncertainty is latched for this process; current expiry is unknown."
                )
            return PublicationObservation(
                observed_at=self._effective,
                local_age_status=local_age_status,
                clock_state="uncertain" if self._clock_reasons else "stable",
                source_observed_at=(
                    self._source_time.isoformat() if self._source_time is not None else None
                ),
                manifest_sha256=self._manifest_sha256,
                policy=self._policy,
                age_seconds=self._age,
                historical_integrity="validated" if self._configured else "not_configured",
                clock_reasons=tuple(self._clock_reasons),
                effective_time_basis=time_basis,
                warnings=tuple(warnings),
            )


_PUBLICATION_OBSERVATION: ContextVar[PublicationObservation | None] = ContextVar(
    "sab_publication_observation", default=None
)


def current_publication_observation() -> PublicationObservation | None:
    return _PUBLICATION_OBSERVATION.get()


@contextmanager
def publication_context(observation: PublicationObservation) -> Iterator[PublicationObservation]:
    if not isinstance(observation, PublicationObservation):
        raise TypeError("A PublicationObservation is required.")
    token = _PUBLICATION_OBSERVATION.set(observation)
    try:
        yield observation
    finally:
        _PUBLICATION_OBSERVATION.reset(token)
