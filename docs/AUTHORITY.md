# Local authority grants

An enrolled key proves control. A local SAB action additionally requires an
authentic stored grant for that actor, exact seed and action, evaluated under
explicitly configured issuer policy in the action's database transaction.
Authority grants confer no standing, truth or operator independence. This does
not enable invite beta or public mutation.

```text
KeyControl + SignedProposal != Permission

evaluate(configured_policy, authentic_issuance, active_keys,
         exact_actor_action_seed, current_time, revocation)
  -> permission for this transaction
```

JSON returned by a read or earlier evaluation cannot be submitted as a
permission capability. The server always reads and reevaluates the immutable
stored grant before applying an actor command.

## Configure the local issuer policy

An operator reviews a `sab.authority_policy.v1` JSON document out of band. It
names the exact origin and policy interval, issuer identities and public keys,
allowed actions, seed scope, lifetime limits, designated revokers, and separate
issuance witnesses. Grants always cover one exact seed ID. The optional
`all_seeds: true` root setting is explicit operator configuration; a grant
cannot use a wildcard or infer scope from prose.

Validate and calculate the canonical JSON digest with:

```sh
agora-authority policy-digest --policy-file /absolute/reviewed-policy.json
```

For a local process, configure both `SAB_AUTHORITY_POLICY_PATH` and
`SAB_AUTHORITY_POLICY_SHA256`, plus the matching `SAB_IDENTITY_ORIGIN`. The
policy file must be an owned, bounded regular file, without a final symlink or
group/world write permission. The digest is of canonical JSON, not raw file
formatting. Missing policy disables grants and actor authority; malformed or
mismatched configuration fails startup. No system witness key, operator label,
administrator string or enrollment automatically becomes an issuer.

The policy is loaded once per service instance. Changing the pinned policy
invalidates older grants for new use without changing their history. Public
read-only mode does not load this policy, initialize grant tables, create keys
or expose private grant records.

## Issue a grant with separate local signers

The subject, issuer and distinct issuance witness first prove their key control
through `agora-key-control`. The issuer prepares a complete
`sab.authority_lease.v2` draft under the reviewed policy. Use fresh aware UTC
timestamps, an exact seed ID, the subject's actual public key, named actions,
the designated revoker, and the exact lease challenge URI. Scope and purpose
are explanatory text; permission comes from the exact seed/action fields.
`allowed_reliance` must be empty.

The issuer signs the draft locally. The explicit subject, seed and action flags
must agree with the complete draft before the key signs:

```sh
agora-authority sign-lease --policy-file /absolute/reviewed-policy.json \
  --policy-sha256 POLICY_DIGEST --document /absolute/lease-draft.json \
  --key-file /absolute/issuer.ed25519 --subject-id SUBJECT_ID \
  --seed-id SEED_ID --action submit_seed --action correct_seed \
  --output /absolute/issuer-signed.json
```

A separately configured witness checks the issuer signature and full intent,
then signs an observation over the complete issuer-signed digest:

```sh
agora-authority witness --policy-file /absolute/reviewed-policy.json \
  --policy-sha256 POLICY_DIGEST --document /absolute/issuer-signed.json \
  --key-file /absolute/witness.ed25519 --witness-id WITNESS_ID \
  --subject-id SUBJECT_ID --seed-id SEED_ID \
  --action submit_seed --action correct_seed --output /absolute/witnessed.json
```

Submit the public envelope; no private key crosses the HTTP boundary:

```sh
agora-authority issue --origin http://127.0.0.1:8000 \
  --policy-file /absolute/reviewed-policy.json --policy-sha256 POLICY_DIGEST \
  --document /absolute/witnessed.json
```

New issuance requires both observations to be within 120 seconds of the
server's guarded local time. A delayed proposal must be prepared and signed
again; the client does not alter signed timestamps. This clock guard uses local
UTC and monotonic elapsed time, with a five-second divergence bound and latched
uncertainty. It does not authenticate civil time. Expiry is inclusive.

Keep the original witnessed envelope. Offline outputs are signed proposals.
Issuance and inspection outputs add observations and are not the strict
three-field issuance input. Output files are created exclusively; keys use the
same owned regular single-link 0600 custody checks as `agora-key-control`.

## Use, inspect and retire

The seed packet keeps its five-field `authority_lease` reference:
`lease_ref`, `scope`, `expires_at`, `revoker`, and `challenge_path`. Copy those
fields exactly from the issued grant. Supplying metadata cannot create a grant,
extend it or replace an existing ID. Historical v1 declarations stay readable
and have no inferred issuance.

Other actor commands resolve a current covering grant from the authenticated
actor, signed action and exact target seed. The selected lease ID, digest and
action are recorded in witness history. An unsigned selector does not choose
permission. Correction, withdrawal, challenges, responses, adjudication,
witness acts and standing transitions all need covering grants. Existing role
and independence limits still apply; canon promotion requires its separately
signed effect and permission.

```sh
agora-authority inspect --origin http://127.0.0.1:8000 \
  --policy-file /absolute/reviewed-policy.json --policy-sha256 POLICY_DIGEST \
  --lease-id LEASE_ID
agora-authority revoke --origin http://127.0.0.1:8000 \
  --policy-file /absolute/original-policy.json --policy-sha256 ORIGINAL_DIGEST \
  --document /absolute/witnessed.json --key-file /absolute/revoker.ed25519 \
  --reason 'Retire this bounded permission'
```

Revocation binds the exact lease digest and requires its designated revoker's
active key. It remains available after the subject, issuer or policy retires.
Revocation is absorbing. Exact signed issuance and revocation retries are
idempotent; conflicting bytes under an existing ID fail. Previously used actor
command signatures return 409 without another effect. New actor signatures
must use canonical lowercase hexadecimal; historical equivalent encodings
still identify the same consumed signature. A fresh response keeps the first
prosecution deadline. Revalidation and canon require every seed challenge to
be resolved. A new key receives no transferred leases.
Lease, issuance, revocation and prior claim/witness/standing bytes remain
queryable. A reported status is an observation, never a permission to rely.

The lease's challenge URI accepts a signed seed challenge with the exact lease
ID and digest included in the packet. A covering challenger grant is required.
Before the linked seed exists, the route refuses the operation. Challenges
remain visible in that seed's history; volume alone does not revoke authority.
An expired or revoked claimant grant cannot silence another permitted actor's
challenge. Authority adjudication, finality and appeals remain separate work.

Local GETs do not advance deadlines or write expiry transitions. A signed
`POST /api/v1/seeds/{seed_id}/advance` command, under an `advance_deadlines`
grant, applies only that seed's existing time rules and records the resulting
events. This is local rule execution, not a finality certificate.

New private grant tables are outside the public snapshot allowlist. Reviewed
witness records can include their hash-covered authorization reference; it
does not establish authentic issuance or current permission in a frozen public
snapshot. Previously pinned records without the extension retain their hashes.

Invitation controls, authenticated operator independence, participant browser
custody, general command versioning and cached retry results, finality/appeals, abuse controls and
independent beta acceptance remain open. A configured issuer plus a second
key is not evidence of two independent operators.

The local SQLite store and operator policy pin are trusted inputs. Signatures
and digest checks detect many inconsistent edits; they cannot detect a complete
rollback to an earlier authentic database. A database writer can remove a
revocation event and restore its matching issuance status. Absorbing revocation
here describes the API and ordinary process restarts, not resistance to a
malicious storage owner or restored pre-revocation backup. That stronger
currentness guarantee needs an independently anchored monotonic history.
