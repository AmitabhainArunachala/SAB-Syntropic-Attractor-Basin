# ADR-0006: Build the Attended-Ceremony Prerequisites Offline

**Status:** Accepted for the offline prerequisite slice

**Date:** 2026-08-01

**Decision Type:** Authority boundary / Build B preparation

---

## Context

Build A proved the first-verdict mechanics on an attested copied database and
was merged after Linux and GitHub CI verification. It did not run a real
council, call a provider, use a human signing key, pause a service, or mutate a
live database.

An attended Build B ceremony still needs substantial machinery before those
external authorities are exercised. Most of that machinery is safe to build
and falsify offline. Leaving it until the maintenance window would combine
contract design, provider facts, governance judgment, and live operations in
one irreversible event.

## Decision

Implement the deterministic, non-live prerequisites now while preserving the
following type boundary:

```text
StructurallyCompleteAwaitingAuthority != Authorized<Live>
PersistedAuthorityReceipt !-> EvaluatorCapability
SignedObservationReceipt !-> LiveObservation
UnsignedOperatorPacket !-> OperatorCountersign
CompiledVerdict<Copy> !-> EffectiveVerdict<Live>
```

The slice has four deliberately separate components:

| Component | Public role | Strongest positive result | Forbidden result |
| --- | --- | --- | --- |
| `sab_first_verdict_ceremony.py` | Verify signed founder, provider, cost, runtime, state, control, tick, restoration, and prepared-Live-lease evidence against exact out-of-band trust-anchor sets | locally sealed `StructurallyCompleteAwaitingAuthority` | live authority or permission to execute |
| `sab_first_verdict_transcript.py` | Verify and append an exact nine-seat, three-stage commitment/reveal transcript to an in-memory fixture or attested copy | structural readiness plus an immutable transcript digest | provider calls, live persistence, standing effects |
| `sab_first_verdict_compiler.py` | Re-derive raw and clean-cluster tallies under an explicit self-hashed terminality rule | verified Copy-scoped verdict, refusal, or appeal | a Live capability or implicit terminality policy |
| `sab_first_verdict_approval.py` | Re-derive all cross-module evidence bindings in memory, then produce a full canonical digest and phone-readable unsigned packet | `awaiting_operator_countersign` | caller-authored hash envelopes, signature acceptance, or effect execution |

The compiler checks evaluator-sealed Copy authority before it receives or
parses the rule, case, roster, ballots, or other merits. Serialized authority
objects cannot recreate that capability. A refusal therefore proves that
merit-bearing input was not inspected.

The transcript schema is additive. It does not alter Build A's one-terminal-
ballot uniqueness constraint. Three append-only tables store commitments,
reveals, and stage envelopes by stage; immutable triggers reject update and
delete, exact replay is idempotent, and an injected failure rolls the whole
three-stage write back. Storage accepts only an in-memory fixture or a
connection already attested by Build A as a copy.

Every commitment is signed by the exact frozen seat over the full canonical
context: case, roster, authority, rule, stage input, predecessor reveal set,
final deliberation subject, seat position, execution facts, and committed
preimage. Rewrapping a valid preimage under a different context therefore
fails. The schema rejects recursive zero-digest placeholders and scalar
coercion at stage and seat indices. The offline transcript proves structural
commit-before-reveal ordering; it does not claim an externally witnessed
wall-clock publication time, which remains an attended-controller concern.

The frozen bench contains exactly nine ordered `FrozenSeatV1` records. The
same roster root and terminality-rule digest are required by provider
preflight, all three transcript stages, the compiler, and the approval
derivation. Every ballot signature is verified over the canonical ballot
bytes against that seat's exact signer and execution key. A reordered seat,
substituted route, changed cluster, changed key, or invalid signature is a
typed non-positive result.

Each frozen seat has exactly one probed served route; a broader list containing
the observed route is insufficient. Probe observations must predate the bench
freeze, and the signed cost approval must not predate the exact bench digest it
approves. Money, port, threshold, count, stage, and seat-position integers are
strictly typed rather than repaired from strings, floats, or booleans.

Founder, provider, maintenance, control, and prepared-lease records carry
Ed25519 attestations and are checked against role-specific out-of-band trust
sets. Their signatures authenticate persisted bytes; they do not prove that a
live observation occurred or recreate a control/evaluator capability. A
readiness result therefore also carries the digests of the trust-anchor sets
used and an evaluator-local seal. Serialization, direct construction, or a
tampered model copy cannot be promoted into readiness.

The approval packet is always unsigned and non-executable. Its constructor
accepts only a locally sealed evidence derivation produced from the typed
manifest, both readiness values, transcript, terminal compiler outcome,
signed maintenance evidence, exact effect proposals, and Build A closeout.
It does not accept a caller-authored JSON envelope. Its short checksum is a
display aid only. An operator must inspect and sign the full 64-character
canonical digest during the attended window; this offline slice deliberately
contains no signature-ingest or live-effect path.

The persisted packet view is integrity-only and never a signing surface. It
records the shortest source-evidence validity boundary, renders every full
SHA-256 evidence root, and always reports that freshness was not reverified and
operator signing is ineligible. Only a future attended controller may rederive
fresh evidence in memory and present a full digest under a separately approved
human custody rail. The offline manifest records that rail as
`approval_required`, and service/tick authority must equal—not merely enclose—
the narrow ceremony windows.

The Build A closeout parser accepts the exact merged/green/non-live receipt
schema and records its merge commit and tree separately from the later Build B
runtime commit. A copied SHA string in an arbitrary JSON object is not a
closeout receipt.

## Offline CLI

The checked-in CLI can integrity-check or render an already derived unsigned
packet. It cannot synthesize a trusted packet from JSON:

```bash
python scripts/sab_attended_ceremony.py verify-unsigned-packet \
  --packet unsigned-operator-packet.json

python scripts/sab_attended_ceremony.py render-unsigned-packet \
  --packet unsigned-operator-packet.json
```

This is intentionally a source-checkout operator tool, not a service endpoint
or container entrypoint. Adding it to a deployed image would be a separate
reviewed packaging decision.

Successful persisted verification reports canonical packet integrity only,
with `evidence_reverified=false`, `evidence_freshness_reverified=false`,
`operator_signing_eligible=false`, `live_authority_created=false`, and
`effect_executable=false`.

## Authorities Still Required

No additional ordinary coding work may truthfully manufacture these inputs:

1. **Founder jurisdiction choice.** Record either a jurisdictional-refusal
   ceremony for the challenged Master Vision or choose another signed artifact
   whose terms authorize terminal disposition. A sovereign override, if ever
   chosen, is a separately typed governance action and cannot masquerade as a
   council countersign.
2. **Fresh evaluator capability.** A trusted evaluator must examine the exact
   signed case, policy, requested Live scope/effects, and current state. Its
   signed receipt is evidence; the evaluator capability is not serializable.
3. **Human signing authority.** Approve the operator identity, public-key
   fingerprint, custody rail, physical presence, and full-digest signing
   procedure. No production or persistent private key belongs in this repo.
4. **Provider and spend authority.** Supply credentials outside artifacts,
   run fresh catalog/balance/requested-versus-served/model-lineage/transport
   probes, sign them with an approved probe-attestor key, approve the exact
   cost ceiling, and prohibit automatic top-up.
5. **Maintenance authority.** Approve the service and tick pause/restore
   controls, deployment topology, maintenance window, dedicated accepted SHA,
   and sole-writer runtime. A passing validator does not grant those controls.
6. **Fresh live state.** During the window, produce and attest the backup,
   integrity result, database hash, lifecycle fingerprint, state snapshot,
   exclusion receipt, prepared Live lease, narrow service/tick control
   receipts, and restoration plan from the actual deployment. Test signatures
   prove the verifier; they are not substitutes for these operator-controlled
   receipts.
7. **Exact Live effect semantics.** Only after the founder choice and a fresh
   `Authorized<Live>` value exist may an attended controller expose one
   idempotent effect. This slice intentionally does not guess that policy or
   add a dormant Live activation surface.

If any input is missing, stale, malformed, substituted, correlation-smeared,
over budget, or outside the frozen window, the result remains `Blocked`,
`refused`, `appeal_required`, or `awaiting_operator_countersign` with no effect.

Great Composting is a later, separate case. It needs its own rule, manifest,
authority, council outcome, operator countersign, rehearsal, maintenance
window, and live transaction. It is not bundled into this ceremony.

## Consequences

The attended window can begin with reviewed contracts and replayable negative
cases instead of designing them under pressure. The cost is intentional: this
branch does not make the historic ceremony happen by itself. It makes the
remaining blockers explicit human/live authorities rather than hidden
engineering work.
