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
UnsignedOperatorPacket !-> OperatorCountersign
CompiledVerdict<Copy> !-> EffectiveVerdict<Live>
```

The slice has four deliberately separate components:

| Component | Public role | Strongest positive result | Forbidden result |
| --- | --- | --- | --- |
| `sab_first_verdict_ceremony.py` | Verify frozen authority receipts, provider facts, cost, runtime, state, tick exclusion, and restoration bindings | `StructurallyCompleteAwaitingAuthority` | live authority or permission to execute |
| `sab_first_verdict_transcript.py` | Verify and append an exact nine-seat, three-stage commitment/reveal transcript to an in-memory fixture or attested copy | structural readiness plus an immutable transcript digest | provider calls, live persistence, standing effects |
| `sab_first_verdict_compiler.py` | Re-derive raw and clean-cluster tallies under an explicit self-hashed terminality rule | verified Copy-scoped verdict, refusal, or appeal | a Live capability or implicit terminality policy |
| `sab_first_verdict_approval.py` | Bind the evidence to a full canonical digest and phone-readable unsigned packet | `awaiting_operator_countersign` | signature acceptance or effect execution |

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

The approval packet is always unsigned and non-executable. Its short checksum
is a display aid only. An operator must inspect and sign the full 64-character
canonical digest during the attended window; this offline slice deliberately
contains no signature-ingest or live-effect path.

## Offline CLI

The checked-in CLI prepares or verifies only the unsigned packet:

```bash
python scripts/sab_attended_ceremony.py prepare-unsigned-packet \
  --input ceremony-approval-envelope.json

python scripts/sab_attended_ceremony.py prepare-unsigned-packet \
  --input ceremony-approval-envelope.json --format markdown

python scripts/sab_attended_ceremony.py verify-unsigned-packet \
  --packet unsigned-operator-packet.json
```

Successful verification still returns `live_authority_created=false` and
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
   probes, approve the exact cost ceiling, and prohibit automatic top-up.
5. **Maintenance authority.** Approve the service and tick pause/restore
   controls, deployment topology, maintenance window, dedicated accepted SHA,
   and sole-writer runtime. A passing validator does not grant those controls.
6. **Fresh live state.** During the window, produce the backup, integrity
   result, database hash, lifecycle fingerprint, state snapshot, exclusion
   receipt, write lease, and restoration plan from the actual deployment.
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
