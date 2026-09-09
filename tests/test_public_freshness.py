from __future__ import annotations

import asyncio
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from agora.public_freshness import (
    FreshnessPolicy,
    PublicationFreshnessObserver,
    current_publication_observation,
    publication_context,
    read_freshness_policy,
)

UTC = timezone.utc
BOOT = datetime(2026, 9, 9, tzinfo=UTC)


class Clock:
    def __init__(self, wall=BOOT, ticks=100.0):
        self.wall = wall
        self.ticks = ticks

    def utc_now(self):
        if isinstance(self.wall, Exception):
            raise self.wall
        return self.wall

    def monotonic(self):
        if isinstance(self.ticks, Exception):
            raise self.ticks
        return self.ticks

    def advance(self, seconds, *, wall_seconds=None):
        self.ticks += seconds
        self.wall += timedelta(seconds=seconds if wall_seconds is None else wall_seconds)


def snapshot(source=BOOT, *, configured=True):
    return {
        "configured": configured,
        "manifest_sha256": "a" * 64 if configured else None,
        "database_sha256": "b" * 64 if configured else None,
        "observed_at": source.isoformat() if isinstance(source, datetime) else source,
        "seed_count": 2 if configured else 0,
        "status": "ready" if configured else "not_configured",
    }


def observer(clock=None, *, source=BOOT, maximum_age=86400, skew=5, configured=True):
    clock = clock or Clock()
    return PublicationFreshnessObserver(
        snapshot(source, configured=configured),
        FreshnessPolicy(maximum_age, skew),
        utc_now=clock.utc_now,
        monotonic=clock.monotonic,
    )


def test_policy_defaults_caps_and_digest_are_explicit_and_immutable():
    policy = read_freshness_policy({})
    assert policy == FreshnessPolicy(86400, 5)
    value = policy.to_dict()
    digest = value.pop("sha256")
    assert value == {
        "id": "sab.public_read_freshness.v1",
        "maximum_age_seconds": 86400,
        "maximum_clock_skew_seconds": 5,
    }
    assert (
        digest
        == hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
    )
    assert FreshnessPolicy(1, 0).to_dict()["sha256"] != digest
    assert FreshnessPolicy(86400, 60)
    with pytest.raises(FrozenInstanceError):
        policy.maximum_age_seconds = 1


@pytest.mark.parametrize(
    "name,maximum",
    [
        ("SAB_PUBLIC_MAX_SNAPSHOT_AGE_SECONDS", 86400),
        ("SAB_PUBLIC_MAX_CLOCK_SKEW_SECONDS", 60),
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "",
        "1.0",
        "+1",
        "-1",
        " 1",
        "1 ",
        "1\n",
        "nan",
        "inf",
        "unlimited",
        "1e2",
        "1_0",
        "١",
        True,
        False,
        1,
        None,
    ],
)
def test_policy_rejects_non_decimal_environment_inputs(name, maximum, value):
    with pytest.raises(ValueError):
        read_freshness_policy({name: value})


@pytest.mark.parametrize(
    "values",
    [
        {"SAB_PUBLIC_MAX_SNAPSHOT_AGE_SECONDS": "0"},
        {"SAB_PUBLIC_MAX_SNAPSHOT_AGE_SECONDS": "86401"},
        {"SAB_PUBLIC_MAX_CLOCK_SKEW_SECONDS": "61"},
        {"SAB_PUBLIC_MAX_CLOCK_SKEW_SECONDS": "9" * 10000},
    ],
)
def test_policy_rejects_out_of_bounds_values_before_unbounded_conversion(values):
    with pytest.raises(ValueError):
        read_freshness_policy(values)


@pytest.mark.parametrize(
    "maximum_age,skew",
    [
        (True, 5),
        (1.0, 5),
        (0, 5),
        (86401, 5),
        (1, False),
        (1, 0.0),
        (1, -1),
        (1, 61),
    ],
)
def test_direct_policy_construction_cannot_bypass_integer_bounds(maximum_age, skew):
    with pytest.raises(ValueError):
        FreshnessPolicy(maximum_age, skew)


def test_environment_policy_only_reads_named_limits(monkeypatch):
    monkeypatch.setenv("SAB_PUBLIC_MAX_SNAPSHOT_AGE_SECONDS", "20")
    monkeypatch.setenv("SAB_PUBLIC_MAX_CLOCK_SKEW_SECONDS", "0")
    monkeypatch.setenv("SAB_TRUST_LOCAL_CLOCK", "true")
    assert read_freshness_policy() == FreshnessPolicy(20, 0)
    assert read_freshness_policy({}) == FreshnessPolicy()


def test_age_limit_is_inclusive_and_never_resets_per_request():
    clock = Clock()
    engine = observer(clock, maximum_age=10)
    first = engine.observe()
    assert first.local_age_status == "within_limit"
    clock.advance(9.999999)
    before = engine.observe()
    assert before.local_age_status == "within_limit"
    assert before.to_dict()["local_age_policy"]["remaining_seconds"] == pytest.approx(0.000001)
    clock.advance(0.000001)
    assert engine.observe().local_age_status == "stale"
    for _ in range(3):
        clock.advance(1)
        observed = engine.observe()
        assert observed.local_age_status == "stale"
        assert observed.to_dict()["local_age_policy"]["remaining_seconds"] == 0
    assert first.to_dict()["local_age_policy"]["age_seconds"] == 0


def test_restart_recomputes_age_from_original_source_date():
    clock = Clock()
    first = observer(clock, source=BOOT - timedelta(seconds=7), maximum_age=10)
    assert first.observe().age_seconds == 7
    clock.advance(4)
    assert first.observe().local_age_status == "stale"
    restarted = observer(clock, source=BOOT - timedelta(seconds=7), maximum_age=10)
    assert restarted.observe().age_seconds == 11
    assert restarted.observe().local_age_status == "stale"


@pytest.mark.parametrize("ahead,status", [(5, "within_limit"), (5.000001, "future_observation")])
def test_future_source_boundary_is_latched_without_negative_age_credit(ahead, status):
    clock = Clock()
    engine = observer(clock, source=BOOT + timedelta(seconds=ahead))
    first = engine.observe()
    assert first.local_age_status == status
    assert first.age_seconds == 0
    clock.advance(10)
    later = engine.observe()
    assert later.local_age_status == status
    assert later.age_seconds == 10


def test_rollback_within_skew_and_later_recovery_cannot_rejuvenate_age_or_effective_time():
    clock = Clock()
    engine = observer(clock, maximum_age=10, skew=5)
    clock.wall += timedelta(seconds=4)
    ahead = engine.observe()
    assert ahead.clock_state == "stable"
    assert ahead.age_seconds == 4
    clock.ticks += 1
    clock.wall = BOOT + timedelta(seconds=1)
    rollback = engine.observe()
    assert rollback.clock_state == "stable"
    assert rollback.age_seconds == 4
    assert rollback.observed_at == ahead.observed_at
    clock.advance(5)
    recovered = engine.observe()
    assert recovered.observed_at == BOOT + timedelta(seconds=6)
    assert recovered.age_seconds == 6


def test_wall_clock_rollback_uses_original_monotonic_projection():
    clock = Clock()
    engine = observer(clock, skew=5)
    clock.advance(1, wall_seconds=-4)
    observed = engine.observe()
    assert observed.clock_state == "stable"
    assert observed.observed_at == BOOT + timedelta(seconds=1)
    assert observed.age_seconds == 1
    clock.advance(1, wall_seconds=0)
    assert engine.observe().clock_state == "uncertain"


def test_cumulative_small_drift_is_compared_to_original_boot_anchor():
    clock = Clock()
    engine = observer(clock, skew=5)
    for _ in range(10):
        clock.advance(1, wall_seconds=1.5)
        assert engine.observe().clock_state == "stable"
    clock.advance(1, wall_seconds=1.5)
    drifted = engine.observe()
    assert drifted.clock_state == "uncertain"
    assert drifted.local_age_status == "clock_uncertain"
    assert "wall_monotonic_divergence" in drifted.to_dict()["clock"]["reasons"]
    clock.wall = BOOT + timedelta(seconds=11)
    recovered = engine.observe()
    assert recovered.clock_state == "uncertain"
    assert recovered.age_seconds >= drifted.age_seconds
    assert recovered.observed_at >= drifted.observed_at


@pytest.mark.parametrize(
    "wall,ticks",
    [
        (None, 100.0),
        ("2026-09-09T00:00:00Z", 100.0),
        (datetime(2026, 9, 9), 100.0),
        (RuntimeError("UTC failed"), 100.0),
        (BOOT, None),
        (BOOT, True),
        (BOOT, "100"),
        (BOOT, float("nan")),
        (BOOT, float("inf")),
        (BOOT, float("-inf")),
        (BOOT, 10**1000),
        (BOOT, RuntimeError("monotonic failed")),
    ],
)
def test_invalid_boot_readings_raise_before_an_observer_can_run(wall, ticks):
    with pytest.raises(ValueError, match="initial UTC and monotonic"):
        observer(Clock(wall, ticks))


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("wall", None, "utc_reading_invalid_or_failed"),
        ("wall", "malformed", "utc_reading_invalid_or_failed"),
        ("wall", datetime(2026, 9, 9), "utc_reading_invalid_or_failed"),
        ("wall", RuntimeError("UTC read failed"), "utc_reading_invalid_or_failed"),
        ("ticks", float("nan"), "monotonic_reading_invalid_or_failed"),
        ("ticks", float("inf"), "monotonic_reading_invalid_or_failed"),
        ("ticks", False, "monotonic_reading_invalid_or_failed"),
        ("ticks", RuntimeError("monotonic read failed"), "monotonic_reading_invalid_or_failed"),
        ("ticks", 99.0, "monotonic_regressed"),
        ("ticks", 1e308, "monotonic_reading_invalid_or_failed"),
    ],
)
def test_bad_later_readings_latch_uncertainty_and_carry_last_effective_time(field, value, reason):
    clock = Clock()
    engine = observer(clock)
    first = engine.observe()
    setattr(clock, field, value)
    invalid = engine.observe()
    assert invalid.observed_at == first.observed_at
    assert invalid.clock_state == "uncertain"
    assert invalid.local_age_status == "clock_uncertain"
    assert reason in invalid.clock_reasons
    assert invalid.to_dict()["clock"]["effective_time_basis"] == "last_valid_effective_utc"
    assert invalid.expiry("2027-01-01T00:00:00Z")["elapsed"] is None
    clock.wall = BOOT + timedelta(seconds=5)
    clock.ticks = 105.0
    recovered = engine.observe()
    assert recovered.clock_state == "uncertain"
    assert recovered.observed_at == BOOT + timedelta(seconds=5)
    assert recovered.age_seconds >= invalid.age_seconds
    assert recovered.expiry("2020-01-01T00:00:00Z")["state"] == "unknown"
    json.dumps(recovered.to_dict(), allow_nan=False)


def test_invalid_wall_still_cannot_stop_monotonic_age_from_increasing():
    clock = Clock()
    engine = observer(clock, maximum_age=10)
    clock.wall = None
    clock.ticks = 112.0
    observation = engine.observe()
    assert observation.observed_at == BOOT
    assert observation.age_seconds == 12
    assert observation.local_age_status == "clock_uncertain"
    assert observation.to_dict()["local_age_policy"]["remaining_seconds"] == 0


@pytest.mark.parametrize(
    "value", [None, "", "malformed", "2026-09-09T00:00:00", datetime(2026, 9, 9)]
)
def test_configured_source_requires_valid_aware_timestamp(value):
    with pytest.raises(ValueError, match="source observation timestamp"):
        observer(source=value)


def test_source_status_is_copied_and_not_re_read_or_mutated():
    status = snapshot()
    original = dict(status)
    clock = Clock()
    engine = PublicationFreshnessObserver(
        status, FreshnessPolicy(), utc_now=clock.utc_now, monotonic=clock.monotonic
    )
    assert status == original
    status["observed_at"] = "2099-01-01T00:00:00Z"
    status["manifest_sha256"] = "c" * 64
    status["configured"] = False
    result = engine.observe().to_dict()
    assert result["source_observed_at"] == BOOT.isoformat()
    assert result["manifest_sha256"] == "a" * 64
    assert result["historical_integrity"] == "validated"


def test_unconfigured_observation_has_no_inventory_or_age_claims():
    observed = observer(configured=False, source=None).observe()
    result = observed.to_dict()
    assert observed.local_age_status == "not_configured"
    assert result["historical_integrity"] == "not_configured"
    assert result["source_observed_at"] is None
    assert result["manifest_sha256"] is None
    assert result["local_age_policy"] == {
        "status": "not_configured",
        "age_seconds": None,
        "remaining_seconds": None,
    }
    assert observed.standing("active", "2027-01-01T00:00:00Z")["status"] == "unknown"


@pytest.mark.parametrize(
    "value,elapsed",
    [
        ("2026-09-08T23:59:59.999999Z", True),
        ("2026-09-09T00:00:00Z", True),
        ("2026-09-09T09:00:00+09:00", True),
        ("2026-09-08T20:00:00-04:00", True),
        ("2026-09-09T00:00:00.000001+00:00", False),
    ],
)
def test_expiry_boundary_and_timezone_offsets_are_inclusive(value, elapsed):
    observed = observer().observe()
    expiry = observed.expiry(value)
    assert expiry == {
        "value": value,
        "observed_at": BOOT.isoformat(),
        "state": "elapsed" if elapsed else "not_elapsed",
        "elapsed": elapsed,
        "reason": "local_expiry_elapsed" if elapsed else "local_expiry_not_elapsed",
        "time_basis": "local_system_utc",
    }


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "garbled",
        "2026-09-09",
        "2026-09-09T00:00:00",
        "2026-09-09 00:00:00Z",
        "2026-09-09T00:00:00+09:60",
        "2026-09-09T00:00:00+24:00",
        "2026-02-30T00:00:00Z",
        "2026-09-09T00:00:00.0000001Z",
        1234,
        True,
        [],
        {"expiry": "2027-01-01T00:00:00Z"},
    ],
)
def test_malformed_or_naive_expiry_remains_unknown_and_preserves_value(value):
    expiry = observer().observe().expiry(value)
    assert expiry["value"] == value
    assert expiry["state"] == "unknown"
    assert expiry["elapsed"] is None
    assert expiry["reason"] == "invalid_expiry"
    if isinstance(value, (list, dict)):
        assert expiry["value"] is not value


@pytest.mark.parametrize("stored", ["active", "canon", "provisional", "challenged"])
def test_valid_age_and_future_expiry_never_promote_standing(stored):
    result = observer().observe().standing(stored, "2027-01-01T00:00:00Z")
    assert result["status"] == "unknown"
    assert result["stored_status"] == stored
    assert result["status_basis"] == "currentness_unestablished"
    assert result["currentness"] == "unestablished"
    assert result["expiry_observation"]["state"] == "not_elapsed"
    if stored in {"active", "canon"}:
        assert result["reason"] == "snapshot_does_not_establish_current_operator_control"


def test_elapsed_standing_is_only_a_local_expiry_observation():
    result = observer().observe().standing("active", BOOT.isoformat())
    assert result["status"] == "expired"
    assert result["stored_status"] == "active"
    assert result["status_basis"] == "local_expiry_observation"
    assert result["reason"] == "expiry_elapsed_on_unverified_local_clock"


@pytest.mark.parametrize("stored", ["revoked", "expired", "compost", "superseded"])
def test_terminal_records_survive_stale_uncertain_clock_and_bad_expiry(stored):
    clock = Clock()
    engine = observer(clock, maximum_age=1)
    clock.advance(2)
    clock.wall = None
    result = engine.observe().standing(stored, "invalid")
    assert result["status"] == stored
    assert result["stored_status"] == stored
    assert result["status_basis"] == "stored"
    assert result["expiry_observation"]["state"] == "unknown"


@pytest.mark.parametrize("stored", [None, [], "unknown_new_status", "ACTIVE", ""])
def test_invalid_recorded_standing_is_unknown(stored):
    result = observer().observe().standing(stored, "2020-01-01T00:00:00Z")
    assert result["status"] == "unknown"
    assert result["stored_status"] == stored
    assert result["status_basis"] == "invalid_stored_status"


def test_stale_and_future_publication_do_not_supply_current_standing():
    stale = observer(source=BOOT - timedelta(seconds=10), maximum_age=10).observe()
    future = observer(source=BOOT + timedelta(seconds=6)).observe()
    for observed, basis in (
        (stale, "publication_stale"),
        (future, "publication_future_observation"),
    ):
        result = observed.standing("active", "2020-01-01T00:00:00Z")
        assert result["status"] == "unknown"
        assert result["status_basis"] == basis
        assert result["expiry_observation"]["elapsed"] is True


def test_observations_are_immutable_and_json_outputs_are_defensive():
    observed = observer().observe()
    with pytest.raises(FrozenInstanceError):
        observed.clock_state = "stable"
    warnings = ["original"]
    derived = replace(observed, warnings=warnings)
    warnings.append("mutated")
    assert derived.warnings == ("original",)
    first = observed.to_dict()
    first["clock"]["reasons"].append("fake")
    first["policy"]["maximum_age_seconds"] = 999999
    first["currentness"]["reasons"].clear()
    first["warnings"].clear()
    second = observed.to_dict()
    assert second["clock"]["reasons"] == []
    assert second["clock"]["externally_verified"] is False
    assert second["clock"]["source"] == "local_system_utc"
    assert second["policy"]["maximum_age_seconds"] == 86400
    assert second["currentness"] == {
        "status": "unestablished",
        "reasons": ["trusted_utc_unverified", "revocation_currentness_unverified",
                    "operator_control_currentness_unverified"],
    }
    assert second["authority_effect"] == second["standing_effect"] == "none"
    json.dumps(second, allow_nan=False)


def test_clock_and_source_offsets_are_normalized_to_aware_utc():
    jst = timezone(timedelta(hours=9))
    clock = Clock(datetime(2026, 9, 9, 9, tzinfo=jst))
    observed = observer(clock, source="2026-09-09T09:00:00+09:00").observe()
    assert observed.observed_at == BOOT
    assert observed.observed_at.tzinfo is UTC
    assert observed.to_dict()["source_observed_at"] == BOOT.isoformat()


def test_context_nested_reset_and_exception_cleanup():
    first = observer().observe()
    second = observer(source=BOOT - timedelta(seconds=1)).observe()
    assert current_publication_observation() is None
    with publication_context(first) as returned:
        assert returned is first
        assert current_publication_observation() is first
        with pytest.raises(RuntimeError):
            with publication_context(second):
                assert current_publication_observation() is second
                raise RuntimeError("request failed")
        assert current_publication_observation() is first
    assert current_publication_observation() is None
    with pytest.raises(TypeError):
        with publication_context(None):
            pytest.fail("invalid context accepted")


def test_contexts_do_not_leak_between_concurrent_requests():
    first = observer().observe()
    second = observer(source=BOOT - timedelta(seconds=1)).observe()

    async def exercise():
        entered = 0
        ready = asyncio.Event()

        async def request(observation):
            nonlocal entered
            assert current_publication_observation() is None
            with publication_context(observation):
                entered += 1
                if entered == 2:
                    ready.set()
                await ready.wait()
                assert current_publication_observation() is observation
            assert current_publication_observation() is None

        await asyncio.gather(request(first), request(second))

    asyncio.run(exercise())
    assert current_publication_observation() is None


def test_concurrent_samples_share_one_lifetime_and_contexts_remain_thread_local():
    class AdvancingClock:
        tick = -1

        def utc_now(self):
            self.tick += 1
            return BOOT + timedelta(seconds=self.tick)

        def monotonic(self):
            return float(self.tick)

    clock = AdvancingClock()
    engine = PublicationFreshnessObserver(
        snapshot(), FreshnessPolicy(20, 0), utc_now=clock.utc_now, monotonic=clock.monotonic
    )

    def request(_):
        observation = engine.observe()
        with publication_context(observation):
            assert current_publication_observation() is observation
            assert observation.clock_state == "stable"
        assert current_publication_observation() is None
        return observation.age_seconds

    with ThreadPoolExecutor(max_workers=4) as pool:
        ages = list(pool.map(request, range(30)))
    assert sorted(ages) == list(range(1, 31))
    assert engine.observe().local_age_status == "stale"
