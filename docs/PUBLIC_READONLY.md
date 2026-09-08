# Public runtime policy

`agora.app:app` starts in `public_readonly` mode when `SAB_PUBLIC_MODE` is
unset. Only the exact values `public_readonly` and `local` are valid. An empty,
misspelled, or differently cased value fails application import before database
or signing-key initialization. The policy is fixed when the application starts;
request headers, cookies, and later environment changes cannot enable writes.

```sh
# Public observation surface (also the default).
SAB_PUBLIC_MODE=public_readonly uvicorn agora.app:app --host 127.0.0.1 --port 8000

# Explicitly writable local development.
SAB_PUBLIC_MODE=local uvicorn agora.app:app --host 127.0.0.1 --port 8000
```

The pure ASGI middleware allows `GET`, `HEAD`, and `OPTIONS` through to the
application. Every other HTTP method receives HTTP 403 before routing, request
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
signing keys or cookies nor change existing session or CSRF state. During public
HTTP reads, the application's database helper opens an existing database with
SQLite `mode=ro` and `query_only` enabled. Schema initialization runs at startup;
a public GET cannot repair a missing table or insert rows through that helper.
The read-only file connection still rejects writes if code clears `query_only`.
Reading seeds and witness chains does not adjudicate overdue challenges. Reading
standing does not append expiry events, sign anything, or change stored status.

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
Startup and maintenance operations outside a request remain writable.

`SabSeedingDeps(read_only=True)` enables observational v1 reads. Initialize both
the public schema and `_init_v1_tables` during lifespan startup before accepting
reads. `observe_standing_status(stored_status, expiry, observed_at=...)` is the
shared side-effect-free projection for APIs and browser summaries.

This is an application transport policy, not an operating-system read-only
filesystem. Startup still performs schema initialization and manages the system
witness key. Separate server entry points such as `agora.api_server:app` need
their own deployment boundary; installing middleware on the public app does
not protect an independently exposed process. Local mode enables existing
writes and must be selected only for the intended writable environment.

## Verification

```sh
python -m pytest tests/test_public_readonly.py -q
```

The suite checks startup rejection, every registered route and method variants,
mounted and unknown routes, body-reader isolation, database and session
snapshots, external table removal, attempted GET inserts in async and threadpool
handlers, context isolation, expired challenge and standing records, invalid
expiry, effective status filtering, and a successful explicitly local browser
submission.

## Endorsements and reliance

Legacy spark records are discourse. A quorum of `affirm` or `canon_affirm`
observations never creates a standing lease or a `canon_promoted` event.
Historical `sparks.status='canon'` rows and their signed history stay intact;
public spark responses project them as `status: "spark"`, disclose
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

`/canon` remains an endorsement archive. `/api/feed/canon` returns
`status: "legacy_endorsements"`; its records carry the same discourse boundary.
Historical endorsements also remain visible in the ordinary spark feed. Node
status reports zero spark-derived canon grants and a separate
`legacy_endorsements` count. Profiles report activity without presenting a
quorum-derived reliability score. No migration rewrites historical evidence.

The promotion rule is explicit: `LegacyEndorsement` cannot be converted into a
`StandingLease`. A stored standing record remains separate evidence; a valid
hash chain does not establish truth, independence, or permission to rely.

## Registration compatibility

Both registration routes compare public-key bytes independently of hex casing
under a serialized transaction. Repeating the same enrollment preserves its
identity and history. A request to change a key, subject, display name, or
operator metadata returns 409 instead of overwriting the record. The legacy
route can return an existing v1 identity; upgrading a legacy-only identity
through the v1 route remains an explicit migration boundary (409).

This prevents record takeover and alias eviction; initial enrollment still
does not prove control of a signing key or independence of the stated operator.
Public mutation remains paused. Witness-reference validation, complete reliance
verification, browser key custody, and an independently operated continuation
workflow remain separate work before public participation is enabled.
