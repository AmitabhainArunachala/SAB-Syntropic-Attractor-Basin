# Browser participation in local SAB

The local participant pages retain a signing key in the browser and use it for
explicitly reviewed SAB v1 commands. A key, session, grant, or recorded
contribution establishes neither truth nor permission to rely on a claim.
Invitation beta remains unreleased. Public read-only mode provides inspection,
not participation.

## Retain, prove, sign in, contribute

1. Open `/register` on the instance's configured origin. Enter the public
   display name and optional operator disclosure, acknowledge the custody
   limits, and choose **Retain key in this browser**. Nothing is enrolled yet.
2. Choose **Prove control**. The browser validates and signs a fresh
   [key-control challenge](KEY_CONTROL.md), publishing the public identity and
   proof. A disclosure is an assertion, not proof of independent control.
3. Choose **Sign in with this key**. This signs a separate session challenge;
   the enrollment receipt cannot open a session. Reading a page never signs a
   command automatically.
4. Obtain a current [authority grant](AUTHORITY.md) from the instance's
   configured issuer and issuance witness for this subject, exact seed and
   action. The browser cannot mint that permission. Without a covering grant,
   the page explains the missing issuer step and leaves contribution unavailable.
5. On `/submit`, choose a covering `submit_seed` grant and complete the claim,
   scope, evidence, falsification and review fields. Review the displayed
   summary and exact packet, then explicitly sign and record it. The result
   links to `/claims/{seed_id}`. The local claim dossier similarly supports a
   reviewed challenge or witness observation under covering permission.

Seed and challenge packets contain the issued five-field `authority_lease`
reference. New browser challenges include `created_at`; their actor signature
binds that timestamp and the complete packet digest. Historical packets remain
readable without rewriting their signed bytes to add newer fields.

The witness page displays current covering `submit_witness_event` grants. It
does not send an unsigned lease selector as permission. The signed witness
command binds the event, actor, exact seed, payload, previous chain hash and
creation time. The server resolves and rechecks a covering stored grant in the
effect's transaction and records its authorization reference. Existing operator
and independence rules still apply; an affirmation does not promote standing.

## Custody and browser trust

The client calls Web Crypto Ed25519 key generation with the private
`CryptoKey.extractable` flag false. It stores the object in IndexedDB and proves
that the retrieved object can sign before enrollment. Public identity download
exports public metadata only. SAB offers no private-key export, escrow or
lost-key recovery. Clearing the origin's site data or losing the browser profile
loses this key; another device does not acquire it by knowing the subject ID.

Non-extractability restricts script access to raw key material. Code with access
to the retained key can still sign with it. The origin's code and operator,
browser, device and extensions remain trusted. This is not a claim of hardware
isolation or resistance to a compromised device. The W3C Web Cryptography
specification describes storing serializable `CryptoKey` objects in IndexedDB,
the shared trust of code at one origin, and the limits of key-storage guarantees.
See its [key storage and security discussion](https://www.w3.org/TR/webcrypto/).

The custody pages require a secure context with Ed25519 and working IndexedDB.
Chromium has been exercised in synthetic local rehearsals; support in other
browsers is not established here. Unsupported features fail with a route to
the [installed key-control CLI](KEY_CONTROL.md), rather than creating a
participant key on the server.

Executable scripts are served from the instance. Remote CDN scripts and inline
script execution were removed; the CSP includes `script-src 'self'` and
`script-src-attr 'none'`. Native controls preserve the reading interface.
`/docs` and `/redoc` serve a read-only API reference linked to `/openapi.json`,
without an executable third-party API console. These measures reduce script
exposure; they do not remove the trust placed in same-origin code.

## Separate session protocol

These routes exist only in the local process:

| Method and path | Exact request | Observation |
| --- | --- | --- |
| `POST /api/v1/browser/session/challenge` | `{"subject_id":"…"}` | Fresh signed-message envelope |
| `POST /api/v1/browser/session/verify` | `{"challenge_id":"…","signature":"…"}` | Public session fields and an HttpOnly cookie |
| `GET /api/v1/browser/session` | Cookie, if present | `session` object or `null` |
| `POST /api/v1/browser/session/logout` | Cookie and `{"csrf_token":"…"}` | Session retirement and cookie expiry |

The challenge envelope is closed: `schema: sab.browser_session_challenge.v1`,
`message`, `signature_algorithm: ed25519`,
`canonicalization: json-sort-keys-compact-v1`, and both `authority_effect` and
`standing_effect` equal to `none`. The message contains exactly:

```json
{
  "schema": "sab.browser_session_message.v1",
  "action": "open_session",
  "audience": "http://127.0.0.1:8000",
  "method": "POST",
  "path": "/api/v1/browser/session/verify",
  "challenge_id": "sab_browser_challenge_<32 lowercase hex characters>",
  "nonce": "<64 lowercase hex characters>",
  "subject_id": "<current subject>",
  "public_key": "<64 lowercase hex characters>",
  "issued_at": "<aware UTC timestamp>",
  "expires_at": "<aware UTC timestamp>"
}
```

This illustrates field names, not a usable challenge. The client checks the
complete intended audience, subject, key, action, method, path, nonce, schema
and freshness before signing sorted, compact, ASCII-escaped JSON as UTF-8.
Its strict parser rejects duplicate members and unsupported numbers; the
canonical numeric subset is safe integers. The verify request carries the
128-character lowercase hexadecimal Ed25519 signature.

Challenges expire within 120 seconds and are usable once, in the issuing
process. Verification checks the active, consistent key binding, signature and
nonce while holding the same SQLite write transaction that consumes the
challenge and creates the session. Restart invalidates pending challenges;
accepted sessions survive within their original lifetime. The guard compares
local UTC with monotonic elapsed time and latches clock uncertainty. It does not
authenticate civil time or protect against restoring an older database backup.

The `sab_web_session` cookie contains a random 32-byte URL-safe token. It has a
six-hour absolute lifetime, `HttpOnly`, `SameSite=Strict`, path `/`, and `Secure`
when the configured audience is HTTPS. Only its SHA-256 digest is stored on the
server, alongside the public proof and binding history. The bearer is absent
from response JSON. A `sab.browser_session.v1` observation contains only
`subject_id`, `public_key`, `display_name`, `created_at`, `expires_at`,
`csrf_token`, schema and the two `none` effects. Reads recheck the active key
and expiry without renewing cookies or changing database history.

Session POSTs require exactly one matching configured `Origin`, refuse
cross-site requests before reading bodies, and accept closed JSON objects of
at most 4096 bytes. Host and forwarding headers cannot select the audience.
The CSRF value is HMAC-SHA256 keyed by the cookie token's ASCII bytes over
`sab.browser_session.csrf.v1`; logout compares it in constant time. Pending
capacity is 512 challenges, at most four per subject; accepted history is
bounded at 10,000 records with at most 16 active sessions per subject. History
is not silently evicted to admit another session.

## Logout, retirement and historical identities

Signing out retires only the current cookie session. The key remains in
IndexedDB and can open another session while its binding is active. Retiring
the key uses the separate signed key-control revoke operation, making that key
unavailable for future sessions and actor commands. Rotation requires old and
successor keys to sign the same transition. The successor needs its own session
and grants; historical profiles, signed records and grants do not transfer.

Historical server-held browser aliases remain historical observations. The new
browser flow cannot recover their keys or silently claim those profiles.
Discussion pages remain readable. The unsigned forms at `/register`, `/submit`,
`/spark/{spark_id}/challenge` and `/spark/{spark_id}/witness` return 428 before
body parsing and perform no identity or contribution effect. Public read-only
mode has no browser-session service or private routes, ignores old cookies,
and denies mutations before parsing bodies.

The evaluator obligation is deliberately small:

```text
Session<subject> cannot convert to Permission<action, seed>.

apply(command, signature) requires, in the effect's transaction:
  active KeyControl<subject, key>
  valid Signature<key, exact_command>
  current IssuedGrant<subject, exact_action, exact_seed>
```

This is a reviewable obligation enforced by separate server checks, not a claim
that a language typechecker proves the implementation. Neither its successful
evaluation nor the resulting receipt establishes finality, independent operator
control, invitation eligibility or justified reliance.

## Reproduce a local rehearsal

The service and HTTP tests support Python 3.10. The browser protocol tests and
portable [rehearsal launcher](../scripts/rehearse_participant_browser.py) use
Node 22 and Playwright Chromium. Install the Python runtime requirements plus
the development dependency `jsonschema`, and provision Playwright and Chromium
explicitly. The launcher does not install them. For a source rehearsal:

```sh
python3.10 -B scripts/rehearse_participant_browser.py \
  --node /absolute/node22/bin/node \
  --playwright-module /absolute/tooling/node_modules/playwright \
  --runtime-root "$HOME/.dharma/sab/browser-rehearsals/source-example"
```

Choose a new runtime directory outside the checkout and installed package.
The default is a unique directory under `~/.dharma/sab/browser-rehearsals/`.
Use `--browser-cache` or `PLAYWRIGHT_BROWSERS_PATH` for an explicit Chromium
cache; `SAB_PLAYWRIGHT_MODULE` can supply the Playwright package directory.

For an installed artifact, run its interpreter from an unrelated directory:

```sh
cd /absolute/runtime
/absolute/installed/bin/python -I -B \
  /absolute/source-checkout/scripts/rehearse_participant_browser.py \
  --installed --source-root /absolute/source-checkout \
  --node /absolute/node22/bin/node \
  --playwright-module /absolute/tooling/node_modules/playwright \
  --runtime-root "$HOME/.dharma/sab/browser-rehearsals/installed-example"
```

Installed mode verifies that Agora imports and served assets come from the
selected installed environment. Source fixture files remain explicit rehearsal
inputs; the source package is not placed on `sys.path` or `PYTHONPATH`.
`--fixtures-root` and `--node-script` can override those inputs. The launcher
uses synthetic local identities, issuer policy and grants, validates accepted
packets, and records observations in `bridge-receipt.json`, browser receipts
and screenshots. Inspect completion and process-cleanup fields for that run;
this command example is not evidence that a particular artifact passed.
Keep browser profiles, synthetic databases and runtime keys private. Rehearsal
receipts do not authorize deployment or establish independent beta acceptance.
