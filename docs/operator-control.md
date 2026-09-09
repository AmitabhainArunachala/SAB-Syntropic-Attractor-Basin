# Scoped operator-control review

Operator strings, distinct keys, authority grants and reviewer signatures do not
establish independent control. This local workflow records a review of source
material for one exact cohort, seed, claim revision and purpose. The server can
then evaluate that record against its explicitly pinned review policy, current
keys, evidence validity, challenges and revocations. It cannot discover hidden
collusion or authenticate external facts merely by hashing a document.

The command is `agora-operator-control` after installation, or
`python -m agora.operator_control_client` from a source checkout. It does not
enroll keys, create evidence, choose trusted reviewers, fetch evidence locators,
or configure the server. Keep working files outside the repository, for example
under `~/.dharma/sab/operator-reviews/`. Signed output files are created with mode
0600 and never overwrite an existing path. Private keys use the existing
[participant key-control workflow](KEY_CONTROL.md).

## Establish the review policy explicitly

The policy owner must decide who may examine source material and report what it
supports. That decision is the trust bootstrap. Two reviewer signatures supply
separate accountability; they do not prove that those reviewers are independently
controlled. Reviewers must be outside the assessed cohort. A malicious policy
owner or trusted reviewer can misrepresent external facts.

Prepare a closed `sab.operator_control_policy.v1` document containing:

| Fields | Meaning |
| --- | --- |
| `policy_id`, `audience` | Stable policy ID and the exact configured origin |
| `not_before`, `expires_at` | Explicit UTC validity interval |
| `reviewers`, `revokers` | Sorted lists of exact `{subject_id, public_key}` pins; at least two distinct reviewers |
| `max_assessment_ttl_seconds`, `max_evidence_age_seconds` | Integer bounds from 1 to 604800 seconds |
| `max_common_funding_ppm` | Integer bound from 0 to 1000000; shared control remains disqualifying |

`schema` is also required. Policy IDs use `sab_operator_policy_` followed by a
bounded safe identifier. All policy, assessment and material hashes are bare
64-character lowercase SHA256 values over sorted, compact, ASCII-escaped JSON.
They are not file-byte hashes or `sha256:`-prefixed values.

```sh
agora-operator-control policy-digest --policy-file /absolute/operator-policy.json
```

Inspect the policy's complete content and the returned hash through your chosen
review process. Protocol inspection, signing, assembly and transport require
both `--policy-file` and `--policy-sha256`; the client never adopts a fetched
policy as its trust root.
The local server must separately be configured with that exact policy and hash
through `SAB_OPERATOR_CONTROL_POLICY_PATH` and
`SAB_OPERATOR_CONTROL_POLICY_SHA256`. The registry is enabled only in local
mode; public mode keeps private operator-control reads and writes closed.
Policy files must be owned, regular files without group/world write permission.
No role is obtained from an operator display name or an enrollment receipt.

## Bind the claim revision and actual cohort

Read `GET /api/v1/seeds/{seed_id}` at the selected origin. Its
`operator_control_context` includes `seed_id`, `claim_sha256`,
`original_packet_sha256` and `claim_change_event_sha256`. The digest commits to:

```json
{
  "schema": "sab.operator_claim_revision.v1",
  "seed_id": "THE_EXACT_SEED_ID",
  "original_packet_sha256": "THE_RECORDED_PACKET_DIGEST",
  "claim_change_event_sha256": ["ORDERED_CLAIM_CHANGE_EVENT_DIGESTS"]
}
```

These strings are placeholders, not an admissible assessment. Corrections and
challenge responses change this context. Affirmations and adjudication decisions
do not. The original packet digest covers its canonical unsigned content;
claim-change digests cover the ordered stored events. Re-read the
context before finalizing a review; a stale claim digest cannot cover a newer
claim. A GET observes history and does not grant standing.

Choose exactly one purpose: `standing_quorum`, `high_impact_witness`, or
`challenge_adjudication`. Include the actual subjects participating in that
action, with their current public keys. An assessment can contain 2–16 subjects;
an unused subject never pads the quorum. Adjudication coverage includes its
actual role members, including the relevant grant issuer and issuance witness.
Do not substitute convenient unrelated identities for signed participants.

Prepare a closed `sab.operator_cohort_assessment.v1` document with
`assessment_id`, `policy_id`, `policy_sha256`, `audience`, `seed_id`,
`claim_sha256`, `purpose`, `issued_at`, `expires_at`, `participants`, `graph`,
`evidence` and `replaces`. Assessment IDs have the prefix
`sab_operator_assessment_` and 24–32 lowercase hexadecimal characters. Each
participant is exactly `{subject_id, public_key, controller_class_id}`.

The reviewed graph must inventory ultimate controllers, signing custody,
privileged administrators, runtime operators, delegations and decision rights.
Every participant must reach its sole declared ultimate controller, with a
complete inventory. Unknown inventory is not an empty graph. Shared controllers,
signing roots, privileged administrators, runtime operators, delegates or
decision authority defeat separation. Conflicts defeat separation; funding is
subject to the policy bound and may not conceal common control. Entity names
must refer to reviewed entities; renaming a shared entity proves nothing.

## Examine material and record findings

Supply material for all seven categories:

| Category | Review obligation |
| --- | --- |
| `controller_resolution` | Resolve the actual ultimate controllers and the scope of their control |
| `signing_custody` | Inspect custody and signing access, including shared roots |
| `administrator_access` | Identify privileged administrators and their access |
| `runtime_control` | Identify who operates or can direct the runtime |
| `delegation_decision_rights` | Account for delegations and decision rights; justify any empty inventory |
| `funding` | Examine funding coverage, common funding and associated control |
| `conflicts` | Examine relevant conflicts and omissions |

Each artifact has exactly `evidence_id`, `category`, `source_class`, `source_ref`,
`observed_at`, `valid_until`, `subject_ids`, `document` and `document_sha256`.
`document` is the bounded JSON material examined by the reviewers. Record its
canonical digest before inclusion:

```sh
agora-operator-control material-digest --document /absolute/material.json
```

This command only hashes the supplied JSON. It does not certify its origin or
truth. Include only material suitable for the local reviewed record; do not
include private keys, bearer credentials or unneeded personal information.
The client never dereferences `source_ref`. Reviewers must inspect the source,
meaning, coverage, freshness and possible omissions themselves.

`source_class` is one of `self_report`, `custody_inspection`,
`organizational_record`, `financial_record`, `delegation_record`, or
`conflict_record`. A source-class label is not an authenticity proof. Self-report
alone cannot establish verified independence. Every category needs current
non-self-report supporting material covering every subject being counted, and
each reviewer must cite sufficient coverage independently. Full-roster `get`
and issuance observations evaluate the complete roster; a later action can
evaluate its exact requested subset. A full roster can therefore be ineligible
while a sufficiently supported subset qualifies. Uncounted members never pad
that subset's quorum. All signed material must still be current, and any
contradicted finding blocks even subset evaluation. A signature count cannot
repair missing or contradictory material.

```sh
agora-operator-control inspect --document /absolute/assessment.json \
  --policy-file /absolute/operator-policy.json --policy-sha256 REVIEWED_POLICY_SHA256
```

Inspection checks the actual protocol validator and reports the assessment,
artifact and material hashes, exact scope, public participant pins and validity
bounds. It permits historical inspection without claiming freshness. It does
not print embedded material. Inspect the original local documents themselves
before signing. There are no automatically generated `supported` findings.

## Sign two explicit reviews and submit

Each reviewer authors an exact unsigned review with `reviewer_subject_id`,
`reviewer_public_key`, `assessment_sha256`, `observed_at` and `findings`.
`findings` contains one entry per category, sorted by category, with exactly
`category`, `evidence_ids` and `outcome`. Outcomes are `supported`, `unknown`, or
`contradicted`; use the latter two whenever the available material warrants it.
Evidence IDs and participant IDs are sorted and unique. Do not turn uncertainty
into support to make a submission pass.

```sh
agora-operator-control sign-review \
  --policy-file /absolute/operator-policy.json --policy-sha256 REVIEWED_POLICY_SHA256 \
  --assessment-file /absolute/assessment.json --assessment-sha256 REVIEWED_ASSESSMENT_SHA256 \
  --document /absolute/reviewer-one-unsigned.json \
  --actor-id REVIEWER_ONE_SUBJECT_ID --key-file /absolute/reviewer-one.ed25519 \
  --output /absolute/reviewer-one-signed.json
```

The second pinned reviewer repeats this with their own reviewed findings and
local key. The client validates the full assessment, every material hash,
reviewer pin, explicit assessment digest and findings before signing. No remote
document is silently signed. Offline signing cannot establish that the key is
still active at the service.

Prepare and inspect the evidence before the final signing window. Assessment
issuance and review timestamps must be current within 120 seconds when accepted;
the policy also bounds their lifetimes. Changing an assessment timestamp or any
other assessment byte changes its digest and requires both new reviews. The CLI
never refreshes signed dates automatically. All times must be explicit UTC.

```sh
agora-operator-control assemble \
  --policy-file /absolute/operator-policy.json --policy-sha256 REVIEWED_POLICY_SHA256 \
  --assessment-file /absolute/assessment.json \
  --review-file /absolute/reviewer-one-signed.json \
  --review-file /absolute/reviewer-two-signed.json --output /absolute/envelope.json

agora-operator-control issue --origin http://127.0.0.1:8000 \
  --policy-file /absolute/operator-policy.json --policy-sha256 REVIEWED_POLICY_SHA256 \
  --document /absolute/envelope.json
```

Pass the review files in ascending reviewer subject-ID order. Assembly verifies
both signatures without rewriting any input. Issue validates freshness, checks
the exact participant/reviewer key bindings at the selected origin and submits
the unchanged envelope. The server repeats currentness checks in its transaction.
Preflight reads are observations and cannot remove that requirement.

`GET /api/operator-control/assessments/{assessment_id}` returns stored reviewed
bytes with a current service observation. The client requires the expected
assessment digest and verifies the historical envelope under the pinned policy:

```sh
agora-operator-control get --origin http://127.0.0.1:8000 \
  --policy-file /absolute/operator-policy.json --policy-sha256 REVIEWED_POLICY_SHA256 \
  --assessment-id ASSESSMENT_ID --assessment-sha256 REVIEWED_ASSESSMENT_SHA256
```

Every client summary keeps `authority_effect` and `standing_effect` at `none`,
`effective_reliance` at `unestablished` and `current_use_eligible` false. Valid
review signatures mean signature integrity under the selected policy; a copied
result is not a reusable eligibility token.

## Challenge, retire and replace an assessment

The `challenge` and `revoke` commands accept a caller-authored unsigned inner
command as `--document`, the exact original `--assessment-file`, its explicit
`--assessment-sha256`, the original pinned policy, `--actor-id`, `--key-file`
and `--origin`. They validate before signing, require the actor's currently
active binding in preflight, and match the returned signed event and digests.
The original draft stays local, so a retry signs identical bytes; the CLI does
not generate a new command or extend its expiry after an ambiguous response.

A challenge inner command contains `schema: sab.operator_control_challenge.v1`,
`challenge_id`, `assessment_id`, `assessment_sha256`, `audience`,
`challenger_subject_id`, `challenger_public_key`, `reason`, `evidence_ref`,
`issued_at`, `expires_at`, `authority_lease` and `authority_lease_sha256`.
The lease reference contains exactly `lease_ref`, `scope`, `expires_at`,
`revoker` and `challenge_path`; its digest is the authority service's
`lease_sha256` over `{lease, issuer_signature}`, not its envelope digest.
The service requires an authentic current `challenge_operator_control` grant
for that challenger and seed. Local structural validation does not certify a
caller-supplied grant reference. See [Local authority grants](AUTHORITY.md).

A revocation uses `schema: sab.operator_control_revocation.v1`, `revocation_id`,
`assessment_id`, `assessment_sha256`, `audience`, `revoker_subject_id`,
`revoker_public_key`, `reason`, `issued_at` and `expires_at`. Only an original
pinned revoker with an active key can retire the record, including after the
original policy or assessment expires. Preserve the original policy file and
pin for that operation.

Challenge IDs use `sab_operator_challenge_`; revocation IDs use
`sab_operator_revoke_`, each followed by 24–32 lowercase hexadecimal characters.
Command validity is at most 120 seconds and expiry is inclusive.

```sh
agora-operator-control challenge --origin http://127.0.0.1:8000 \
  --policy-file /absolute/operator-policy.json --policy-sha256 REVIEWED_POLICY_SHA256 \
  --assessment-file /absolute/assessment.json --assessment-sha256 REVIEWED_ASSESSMENT_SHA256 \
  --document /absolute/challenge-draft.json \
  --actor-id CHALLENGER_SUBJECT_ID --key-file /absolute/challenger.ed25519
```

For retirement, use `revoke` with a revocation draft and the pinned revoker's
subject/key. These map to
`POST /api/operator-control/assessments/{assessment_id}/challenge` and `/revoke`.
Issuance uses `POST /api/operator-control/assessments`.

Accepted challenges permanently prevent reuse of the old assessment. A
replacement needs a new assessment ID, fresh full reviews and `replaces` with
the exact current predecessor ID/digest and every predecessor challenge ID.
The service serializes one head per exact seed, claim digest and purpose.
The successor's issue time cannot precede its predecessor or the acceptance
time of any acknowledged challenge.
Replacement never edits predecessor signatures or removes challenges.
Revocation remains absorbing, including across restart and exact retries.

## Standing remains a separate signed act

A registry record does not itself promote a claim. Current standing commands
must cite the exact assessment and actual signed event records through
`operator_control_basis`, with `assessment: {assessment_id, assessment_sha256}`,
`witness_events: [{event_id, event_sha256}]` and
`adjudication_events: [{event_id, event_sha256}]`.
Initial review signs this basis inside `standing_lease`; revalidation signs it
inside `evidence`. An event citation uses the stored event's `event_hash`, not
its payload hash or the chain's later head. A generic witness observation with
an adjudication-shaped payload cannot replace an actual signed decision.
Each event list contains 1–16 references with distinct event IDs; all digests
are bare lowercase SHA256 values of the exact stored records. The optional
closed field is described in the
[standing lease schema](../nodes/schemas/sab.standing_lease.v1.schema.json).
Its absence remains valid for historical documents, but cannot establish
current independent control. Schema validation does not resolve a record or
verify its current eligibility.
A countable signed affirmation binds `payload.operator_control_claim_sha256` to
the current claim context. High-impact witnessing also binds
`payload.operator_control_assessment`; adjudication binds
`reason.operator_control_assessment`. These are independently signed actions
with their own authority requirements, not packets constructed by this CLI.

Missing basis cannot establish active/canon standing. The basis must cover every
challenge through a currently verified rejection event. Old self-declared
resolved or lapsed records remain history, including when a different newer
challenge has a verified rejection. Original embedded seed/challenge signatures
are also required for current promotion; modern response/correction signatures
remain bound to their exact records. Fresh standing evidence does not silently
repair an old unbacked adjudication or extend a recorded lease's expiry.

Current evaluation rechecks the original signatures and exact recorded grants
for the seed, its claim changes, each challenge, and every cited witness,
adjudicator and standing reviewer. Each grant must still cover that actor,
action and seed under the current authority policy. Its subject, issuer,
issuance witness and revoker must retain the required active key bindings.
Revocation, expiry, key rotation or a policy change can therefore remove current
standing without altering any historical bytes. A replacement grant does not
substitute for an old event's recorded grant. Missing original signatures,
unavailable records or unbacked history cannot be repaired by attaching a new
assessment alone.

Historical signed grades and statuses stay recorded. Local standing GETs can
report `stored_status: active` with `status: unknown` when these current checks
fail. Public snapshots and the [offline standing observer](../scripts/sab_verify.py)
cannot perform the private current-control evaluation. They cannot establish
current active/canon reliance from a copied receipt or publication hash;
`unknown` preserves that limit, alongside any more specific expiry, terminal or
rehearsal observation. They do not rewrite the recorded status or signed lease.

The seed's `witness_plan.forbidden_witnesses` must use stable `agent_*` subject
IDs or their direct `sab_identity_agent_*` aliases. Display names and other
ambiguous references fail closed. Changing an alias cannot make a forbidden
subject or the same registered public key count as a permitted witness.

## Renew an adjudication before revalidating standing

When an adjudication's control assessment expires, is challenged, or is replaced,
issuing a fresh assessment does not update the old decision's signed basis.
Restoring active standing requires explicit authorized actions while the
original standing lease is still unexpired:

1. Inspect the current claim context and issue the required fresh
   `challenge_adjudication` assessment through the review ceremony above.
   Supply the exact predecessor and its challenges when replacing a record.
2. Read `GET /api/v1/seeds/{seed_id}/chain` and the cited
   `GET /api/v1/witness-events/{event_id}` records. Identify the latest signed
   rejection or revalidation for the challenge. Construct a `reason` object
   containing `operator_control_assessment: {assessment_id, assessment_sha256}`
   for the fresh assessment and
   `prior_adjudication_event: {event_id, event_sha256}` for that exact decision.
   Include the substantive review explanation in the signed reason.
3. Have the current authorized adjudicator sign the command below and submit
   `POST /api/v1/challenges/{challenge_id}/revalidate` with
   `{actor_identity, created_at, reason, signature}`. The server requires a
   current `adjudicate_challenge` grant and verified coverage of the actual
   role members. Only an already rejected challenge on a nonfinal seed can
   use this route. A stale predecessor or replay fails without appending a
   decision.
4. Replace that challenge's citation in the next `operator_control_basis` with
   `{event_id: response_id, event_sha256: witness_head}` from the accepted
   response. Every challenge must cite its newest decision. The old event
   remains in history and cannot substitute for the new one.
5. Obtain a current `standing_quorum` assessment as needed and submit a fresh
   authorized `POST /api/v1/standing/{standing_id}/revalidate`. Its signed
   `evidence.operator_control_basis` must include that exact assessment and
   all current witness/adjudication citations. Active revalidation requires
   a `revalidate_standing` grant and a sufficient current quorum. Pending or
   responded challenges prevent this transition.

The adjudication signature covers this exact message; the values below are
placeholders, not a usable command:

```json
{
  "kind": "sab_challenge_revalidate",
  "challenge_id": "THE_EXACT_CHALLENGE_ID",
  "actor_identity": "THE_ADJUDICATOR_SUBJECT_ID",
  "payload_sha256": "BARE_SHA256_OF_CANONICAL_REASON_OBJECT",
  "created_at": "EXPLICIT_UTC_TIMESTAMP"
}
```

Both the reason digest and signed message use sorted, compact, ASCII-escaped
JSON. For standing revalidation, sign `kind: sab_standing_revalidate`,
`standing_id`, `actor_identity`, `created_at`, and `payload_sha256` over
`{reason, evidence}`. The standing reason is a string; its evidence is an
object containing the basis. These domain commands are not constructed or sent
by `agora-operator-control`.

Adjudication revalidation appends a decision without changing the seed's state
or reviving a final seed. Standing revalidation appends its own signed event
and preserves the original lease bytes and finite expiry. Neither assessment
renewal nor either revalidation extends that expiry; an expired or revoked
lease cannot be restored this way. GET requests never choose replacement
assessments, rebase citations, or perform either signed action. A recorded
`active` or `canon` value can therefore remain historical while its current
observation is `unknown`.

Operator-control CLI inputs are strict JSON: duplicate/unknown protocol fields,
floats, nonfinite numbers, unsafe integers, unpaired surrogates and excessive
depth/size are rejected. Documents are bounded to 1 MiB, embedded material to 8192 canonical
bytes, and transport responses to 2 MiB with time limits. Requests use the exact
HTTPS or loopback origin, no environment proxy, no credentials and no redirects.
Errors report fixed codes without echoing documents, signatures or key seeds.

The tests exercise synthetic signatures, protocol validation and local transport
behavior. Their reviewer pins and all participant keys are controlled by the
test runner; they are not actual independent operators. This slice provides no
invitations or beta enablement and does not establish real operator independence,
public readiness or deployment safety. Local storage rollback and dishonest
trusted-source reports still need external controls beyond this ceremony.
