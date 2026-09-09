# Publication age and currentness

The public reader serves historical records with an explicit time observation.
`GET /status` explains it for people. `/publication`, discovery, readiness,
the frontier, claim dossiers, and public record envelopes expose the same
`sab.public_read_observation.v1` contract. Its schema is served at
`/schemas/sab.public_read_observation.v1.schema.json`.

Three assessments remain separate:

| Field | Meaning |
| --- | --- |
| `historical_integrity` | The configured publication passed the loader's pin, schema, inventory, and closure checks. |
| `local_age_policy` | The publisher's source timestamp was assessed against this process's guarded local clock and declared age limit. |
| `currentness` | Always `unestablished`: neither UTC accuracy nor receipt of all later corrections/revocations is independently established. |

The semantic boundary is:

```text
HashValid ∧ WithinLocalAgePolicy does not imply Current, Authorized, or SafeToRely.
```

An old approved pin can be obsolete immediately after a revocation. A publisher
supplies its observation timestamp; a recent timestamp does not prove a recent
review. No environment flag promotes the public reader into a current verifier.

## Local policy and clock behavior

| Startup variable | Default | Allowed values |
| --- | --- | --- |
| `SAB_PUBLIC_MAX_SNAPSHOT_AGE_SECONDS` | 86400 (24 hours) | ASCII decimal integer, 1–86400 |
| `SAB_PUBLIC_MAX_CLOCK_SKEW_SECONDS` | 5 | ASCII decimal integer, 0–60 |

Invalid values stop public startup before the publication is loaded. Local
rehearsal behavior is unchanged. Policy ID `sab.public_read_freshness.v1` and its
SHA-256 bind both configured limits. These are bounded operational choices,
not certificates of time accuracy.

At startup the observer anchors local UTC to a monotonic sample. Every allowed
public HTTP request captures one immutable observation, reused by its handlers,
SQL standing filters, dossier deadlines, templates, and response headers:
`SAB-Publication-Age-Status`, `SAB-Clock-State`, and `SAB-Currentness`.
Request dates, query parameters, and proxy headers cannot select this policy or
clock. Denied writes do not need a time observation.

Age advances using both elapsed monotonic time and wall time, and never decreases
within a process. Wall-clock divergence is measured against the original startup
anchor, so repeated small adjustments cannot reset its allowance. Excessive
divergence, invalid time, failed clock reads, or monotonic regression latch
uncertainty until the process ends. A later apparently good sample does not clear
it. Uncertainty is visible even though historical reads remain available.

Age becomes `stale` at **age ≥ maximum age**. A source timestamp beyond the
startup UTC plus the skew allowance produces `future_observation`. A slightly
future source within that allowance gets zero initial age, never extra lifetime.
Restarting calculates age again from the original source timestamp; it is not a
publication refresh. Stable local clocks may be wrong from startup, and a
coordinated rollback across restarts is not detected here. Suspension behavior
depends on the platform monotonic clock; resumed wall/monotonic divergence can
make the process uncertain. `clock.externally_verified` is always false.

## Standing, expiry, and availability

Public standing projections preserve the stored status and original lease.
Recorded terminal states remain visible. A positive recorded state such as
`active` or `canon` becomes `unknown` when currentness is unestablished. With
stable time and a publication within its age limit, an elapsed expiry can be
reported as `expired` with basis `local_expiry_observation`. Stale, future, or
uncertain publications cannot support positive standing. Missing, malformed,
or timezone-naive expiries are unknown; the public observer does not assume UTC.

The local expiry boundary is inclusive: **assessment time ≥ expiry**. Deadline
observations never resolve a challenge or alter stored state. Public frontier
records are historical candidates, with no current build permission or asserted
active-standing count.

Historical responses remain HTTP 200 with visible and machine-readable warnings.
`/health` describes the reader process. `/readyz` means ready for historical
inspection and reports `current_use_eligible: false`. Neither is a current-use
acceptance check. Original packet, manifest, and signature bytes remain unchanged;
observations are separate response metadata.

The installed inspector can additionally enforce an independently chosen local
age limit, using an independently retained manifest pin:

```sh
agora-public-inspect http://127.0.0.1:8000 \
  --expected-manifest-sha256 APPROVED_MANIFEST_SHA256 \
  --max-snapshot-age-seconds 3600
```

This admission check uses one client UTC sample at inspection start against the exact original
manifest, with inclusive expiry and a five-second future tolerance. Its clock
is also unverified. It refuses stale or excessively future publications before
the invalid-body write probe. Passing means only that the historical inspection
and requested local age checks passed; it grants no currentness or authority.
Without this option the inspector accepts correctly labeled historical data.

## Corrections and remaining proof

Every public response says `Cache-Control: no-store`. This prevents the service
from authorizing cache reuse; it does not purge downloaded copies or prove that
revocations arrived. A frozen process needs a restart with a newly approved
publication and independently retained pin for replacement or withdrawal.
Operators must retain which pins are retired; the loader cannot discover an
unseen revocation. Use the [recovery procedure](PUBLIC_DISTRIBUTION.md) and avoid
restoring retired publications.

The Update Framework provides relevant prior art: it fixes time once per update
and distinguishes expiry from rollback protection. SAB borrows that separation
of obligations; it does not implement TUF metadata or authenticated time.
See the [TUF specification](https://theupdateframework.github.io/specification/latest/).

Deterministic tests exercise exact age and expiry boundaries, skew and rollback,
sticky uncertainty, original-byte preservation, request isolation, SQL filters,
headers, rendered warnings, and inspector refusal. Independent UTC, a live
revocation source, a current reliance verifier, image-version rollback, public
TLS, and independent operator acceptance remain separate work.
