# Public runtime policy

`agora.app:app` starts in `public_readonly` mode when `SAB_PUBLIC_MODE` is
unset. Only the exact values `public_readonly` and `local` are valid. An empty,
misspelled, or differently cased value fails application import before database
or signing-key initialization. The policy is fixed when the application starts;
request headers, cookies, and later environment changes cannot enable writes.

```sh
# Public observation surface (also the default).
PYTHONDONTWRITEBYTECODE=1 SAB_PUBLIC_MODE=public_readonly uvicorn agora.app:app --host 127.0.0.1 --port 8000

# Explicitly writable local development.
SAB_PUBLIC_MODE=local uvicorn agora.app:app --host 127.0.0.1 --port 8000
```

The pure ASGI middleware allows `GET`, `HEAD`, and `OPTIONS` only on the
explicit public inspection route allowlist. Unpublished routes return 404
before their handlers run; new public path patterns require explicit admission.
Every other HTTP method receives HTTP 403 before routing, request
body parsing, dependencies, or handlers run. This covers legacy APIs, `/api/v1`,
browser forms, mounted applications, unknown paths, redirects, and future
routes. Public WebSocket connections are rejected before the handshake.

The rejection body is stable and has `Cache-Control: no-store`:

```json
{
  "code": "public_readonly",
  "mode": "public_readonly",
  "detail": "This SAB instance is read-only. Write operations are disabled."
}
```

Public browser reads ignore local session cookies and neither mint browser
signing keys or cookies nor change existing session or CSRF state. The public
process has **no signing key** and performs **no database or authority-schema
initialization**, during import, startup, requests, or direct helper calls.

Data comes only from a separately reviewed, pinned [public snapshot](PUBLIC_SNAPSHOT.md).
The app never falls back to `SAB_SPARK_DB_PATH`, `SAB_AUTHORITY_DB_PATH`, or
`SAB_DB_PATH`. An absent snapshot produces a schema-free empty reader; a
configured invalid or unpinned snapshot fails startup. The approved data is
frozen in memory, with SQLite query-only mode and an authorizer that denies
mutation, attachments, and unsafe pragmas. Public reads do not scan repository
packet/receipt directories or `SAB_SEED_CLAIMS_PATH`.

Reading seeds and witness chains does not adjudicate overdue challenges.
Reading standing does not append expiry events, sign anything, or change stored
status. A snapshot reflects its recorded observation time, including only the
revocations and corrections present then. A later HTTP fetch does not refresh
that source; replacing a publication requires a reviewed bundle and restart.

Standing responses distinguish stored history from current observation:

```json
{
  "status": "expired",
  "stored_status": "canon",
  "status_basis": "expiry_observation",
  "observed_at": "2026-09-09T00:00:00+00:00"
}
```

An elapsed lease cannot support current reliance merely because its stored
status is `canon`. Missing or invalid expiry produces `status: "unknown"` and
`status_basis: "invalid_expiry"`. Revoked, expired, composted, and superseded
records retain their terminal status. List status filters apply the same
observer before their result limit. These observations confer no authority and
do not change the canonical record.

## Application integration

`read_public_mode()` validates the environment without side effects.
`install_public_runtime(app, mode)` installs the middleware, returns `PublicMode`,
and sets `app.state.public_mode` to the wire string and
`app.state.public_readonly` to a boolean. Install it after any other user
middleware so the policy is the outermost user layer.

`public_read_request()` exposes the request-scoped boundary to database and
schema helpers. It is true while an allowed public HTTP read executes, including
mounted apps and threadpool handlers. The context resets after completion,
failure, or cancellation and does not leak into concurrent local requests.
The application's source remains frozen outside that request context too.

`SabSeedingDeps(read_only=True)` enables observational v1 reads from the frozen
source. With `publication_configured=False`, list endpoints return empty data
with `availability: "not_configured"`; raw record and witness verification
endpoints return 503 instead of inventing history. Dossier lookup returns a
recoverable 404. No convenience schema is created to make empty reads succeed.
`observe_standing_status(stored_status, expiry, observed_at=...)` is the shared
side-effect-free projection for APIs and browser summaries.

The public container runs with `PYTHONDONTWRITEBYTECODE=1` and is smoke-tested
with Docker's `--read-only` filesystem. Separate server entry points such as
`agora.api_server:app` need their own deployment boundary; the public app's
policy does not protect an independently exposed process. Local mode enables
existing writes and must be selected only for the intended writable environment.

## Verification

The public home and `/claims` now expose a shared claim dossier and agent
discovery path. See [public claim inspection](PUBLIC_CLAIM_DOSSIER.md) for routes,
export semantics, verification limits, and the public container target.

```sh
python -m pytest tests/test_public_readonly.py -q
```

The suite checks startup rejection, every registered route and method variants,
mounted and unknown routes, body-reader isolation, database and session
snapshots, private-file exclusion, invalid publication pins, frozen data after
external replacement, unpublished async and threadpool handlers, direct-helper
write rejection, context isolation, expired challenge and standing records, invalid
expiry, effective status filtering, and a successful explicitly local browser
submission.

## Endorsements and reliance

Legacy spark records are discourse. A quorum of `affirm` or `canon_affirm`
observations never creates a standing lease or a `canon_promoted` event.
Historical `sparks.status='canon'` rows and their signed history stay intact;
local spark responses project them as `status: "spark"`, disclose
`legacy_status: "canon"`, and include this boundary:

```json
{
  "authority": {
    "kind": "discourse",
    "standing_effect": "none",
    "standing_assessment": "not_assessed",
    "standing_api": "/api/v1/standing"
  }
}
```

In explicit local mode, `/canon` remains an endorsement archive. Legacy
discussion, spark, and profile routes are excluded from public publication. `/api/feed/canon` returns
`status: "legacy_endorsements"`; its records carry the same discourse boundary.
Historical endorsements also remain visible in the ordinary spark feed. Node
status reports zero spark-derived canon grants and a separate
`legacy_endorsements` count. Profiles report activity without presenting a
quorum-derived reliability score. No migration rewrites historical evidence.

The promotion rule is explicit: `LegacyEndorsement` cannot be converted into a
`StandingLease`. A stored standing record remains separate evidence; a valid
hash chain does not establish truth, independence, or permission to rely.

## Identity control and rehearsal compatibility

Public identity commands remain blocked before body parsing. In local mode,
v1 enrollment now requires a signed, expiring challenge; unsigned
`/api/v1/agents/register` returns 428. Exact existing complete records can prove
control without metadata replacement. Conflicting bindings and partial legacy
migrations remain closed. Key rotation and self-revocation preserve history.
See [the key-control contract](KEY_CONTROL.md).

Unsigned legacy registration cannot reserve new public keys; it returns 428.
Existing discussion/browser accounts stay explicitly rehearsal metadata and
cannot satisfy the mandatory v1 binding check. Known revoked or superseded keys
are also rejected on legacy signed writes. Public participation still requires
complete authority/issuer and witness validation, browser participant custody,
independent operator evidence, and the remaining acceptance work.
