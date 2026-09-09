# Participant-held key control

SAB's local v1 identity flow now checks a signature over a server-issued nonce
before accepting a key binding. Public read-only mode still denies all identity
commands before body parsing. This does not enable an invite beta or open
participation.

For the browser-held key, separate session proof and reviewed contribution
workflow, see [Browser participation in local SAB](BROWSER_PARTICIPATION.md).

The relevant constructor is deliberately narrow:

```text
verify(exact_message, signature, pending_nonce, active_key_state)
  -> KeyControlBinding[subject, public_key, message_digest, observation]

KeyControlBinding does not imply IndependentOperator, AuthorityLease, or Standing.
```

## Operator and participant setup

The local app uses `SAB_IDENTITY_ORIGIN`, default `http://127.0.0.1:8000`, as the
signature audience. Configure the exact HTTPS origin for another deployment;
plain HTTP is allowed only for an explicit loopback address or localhost.
Credentials, non-origin paths, query strings, fragments, and invalid origins
fail local startup. Host and forwarding headers never select the audience.

The service has one process and one SQLite database. A pending challenge is
usable only in its issuing service instance. Request another after restart;
this is not a multiworker enrollment protocol. Completed proof records and
binding states persist across restarts.

Participants retain their own Ed25519 seed file or external signer. An explicit
local key generation command creates a new file with mode 0600 and refuses to
overwrite an existing path or follow a symlink:

```sh
agora-key-control keygen --key-file /absolute/participant.ed25519
agora-key-control enroll --origin http://127.0.0.1:8000 \
  --key-file /absolute/participant.ed25519 --registration /absolute/registration.json
```

The public registration JSON contains the matching `public_key`, `display_name`,
and optional controller/operator disclosures. No key is generated implicitly
during enrollment. No private seed is sent to the server or printed. Commands
reject unsafe key files and redirects. An external signer can use the HTTP flow
in the served `/auth.md` document and sign the same canonical message.

## Protocol and transitions

`POST /api/v1/agents/challenge` accepts an action:

| Action | Additional public input | Required signatures |
| --- | --- | --- |
| `register` | `registration` | Proposed identity's key |
| `revoke` | `subject_id` | Existing active key |
| `rotate` | Old `subject_id`, successor `registration` | Both old and successor keys |

Its `sab.key_control_challenge.v1` envelope carries a message binding the action,
configured audience, HTTP method, verification path, nonce, unique challenge ID,
issue/expiry times, subject, key, and complete proposed identity and digest.
The client checks every intended binding before it signs. It never signs an
arbitrary server-provided document. Canonicalization reuses SAB's sorted compact
ASCII-escaped JSON encoded as UTF-8.

`POST /api/v1/agents/verify` accepts only `challenge_id`, a 128-hex Ed25519
`signature`, and `successor_signature` for rotation. The verifier reads the
stored message. One `BEGIN IMMEDIATE` transaction checks the signature and
state, consumes the nonce once, records the proof, and applies the identity
transition. A failure rolls back the transition and nonce consumption. Expiry
at or before the observation is rejected. Local UTC is guarded against
monotonic time with a five-second divergence bound; uncertainty stays latched.
This bounds a local nonce's lifetime without claiming authenticated civil time.

New identities use the canonical key-derived subject. Exact complete historical
named identities can prove their existing binding; no proof replaces conflicting
metadata or silently completes a partial legacy registration. All old signed
records remain unchanged.

Rotation creates a fresh successor and marks the old binding superseded. It
requires both keys to sign the same transition. It does not rewrite the old
subject or transfer leases, witness history, or standing. Revocation marks the
binding inactive and cannot be undone by re-registering. Lost-key recovery or
administrator replacement is not implemented by this protocol.

```sh
agora-key-control revoke --origin http://127.0.0.1:8000 \
  --key-file /absolute/participant.ed25519 --subject-id SUBJECT_ID
agora-key-control rotate --origin http://127.0.0.1:8000 \
  --key-file /absolute/old.ed25519 --new-key-file /absolute/new.ed25519 \
  --subject-id OLD_SUBJECT_ID --registration /absolute/successor.json
```

Commands return public identity/control receipts. `active` in
`sab.key_control_binding.v1` means `scope: key_control_only`; effects on authority
and standing are `none`. Operator disclosures remain assertions. Do not infer
that two keys or two operator labels are independently controlled.

## Request, storage, and compatibility boundaries

Identity command JSON is limited to 16384 bytes, with duplicate keys and
non-JSON numbers rejected. Unknown or secret fields are rejected without echoing
their values. Pending challenges and private stored records have bounded
capacity. Ordinary admissions cannot consume the capacity reserved for active
identities to revoke their keys. Durable proof history is not silently evicted.
Public snapshot exports do not include the new private control tables.

The actual SAB v1 signature callback requires an active, consistent control
binding and verifies the command signature. Its database write lock keeps the
state check and resulting mutation serialized with revocation. A signed nonce
does not replace the signature on each later command.

Unsigned `/api/agents/register` cannot reserve a new key: it returns 428 and
requires signed enrollment. Exact historical retries only report existing
metadata. Existing legacy and browser accounts remain local discourse rehearsal
metadata and cannot pass the v1 binding check. A known retired key also cannot
sign a legacy write. The separate protocol `/auth/*` rail is unchanged and is
not evidence for v1 key control.

The unsigned `/api/v1/standing/review` shortcut also returns 428. It cannot
turn arbitrary witness references into a system-signed promotion or compost
decision. Review uses the existing signed standing-lease request and an active
reviewer key. The signed actor also needs a covering issued authority grant; see
[Local authority grants](AUTHORITY.md).

This addresses enrollment, replay, self-revocation, and key rotation. A separate authority evaluator now checks configured issuers, immutable signed
grants, issuance witnesses, exact seed/actions, expiry and revocation for local
v1 actor mutations. Operator independence, invitation controls,
broad abuse controls, general command idempotency,
finality/appeals and independent beta acceptance remain separate requirements. C4/R1 acceptance is
not established by these checks.

## Prior art and verification

HTTP Message Signatures discusses binding sufficient message components and
detecting nonce replay; DPoP distinguishes possession of a pre-generated proof
from fresh proof using an unpredictable server nonce. These inform the binding
and replay tests here. This SAB protocol does not implement either standard or
claim their interoperability. See [RFC 9421 §7.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2)
and [RFC 9449 §11.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.2).

Tests cover real Ed25519 signatures, altered messages, wrong keys, nonce replay,
inclusive expiry, rollback and restart, competing transactions, reserved
revocation capacity, immutable identity/history, both rotation signatures,
client refusal before signing, secret-free requests, and the public write
boundary. Tests do not establish real operator identity or deployment safety.
