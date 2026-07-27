# ADR-0005: Defer Dormant Lineage Preview and All Activation

**Status:** Accepted for Build A

**Date:** 2026-07-28

**Decision Type:** Authority boundary / deferred lineage scope

---

## Context

Build A is authorized to implement and verify engineering mechanics on
fixtures and a copied database. It is not an attended governance ceremony and
has no authority for provider calls, a real council, human signing, live
effects, standing changes, or lineage activation.

The earlier v1 plan combined that engineering work with attended operations and
a dormant lineage substrate. The controlling Build V2 audit removes those
items from Build A. D0 therefore records the unresolved questions and the
prohibition; it does not answer them or design Build B.

## Decision

Build A produces this ADR as its only lineage deliverable. It must not create
lineage models, policy, storage, migrations, schemas, fixtures, APIs, CLIs,
routes, activation logic, or a Build B implementation plan.

The following questions remain deferred:

1. **Providers:** Which requested routes are presently available, which models
   are actually served, what spend is authorized, and what model-lineage or
   transport correlations prevent an independence claim? Provider state
   remains `provider_blocked` pending later, fresh, persisted probes.
2. **Real council:** Which artifact is jurisdictionally eligible, who
   authorizes the case, what real nine-seat roster is feasible, how are
   credited model/training clusters evidenced, and what conflicts or route
   substitutions invalidate the bench?
3. **Clerk:** What authority, if any, may a zero-vote clerk hold; how are
   clerk/author/challenger conflicts resolved; and who may synthesize or sign a
   corrected successor without laundering authorship or disposition authority?
4. **Operator signing:** Which genuinely human signing rail, public-key
   fingerprint, custody policy, canonical envelope, and explicit approval
   ceremony are authorized? Build A creates or uses no human, operator, live,
   or persistent private key.
5. **Live activation:** Which later case, if any, receives
   `Authorized<Live>`; what exact effects are authorized; and who has authority
   over the live database, maintenance runtime, and service pause/restore? The
   unresolved founder choice between a jurisdictional refusal and a terminal
   artifact lifecycle remains outside Build A.
6. **Batch activation:** Whether Great Composting should ever be activated, and
   under what separately authorized case, lease, manifest, verdict,
   countersign, rehearsal, and transaction, remains unresolved. Build A has no
   batch-apply route.
7. **Successor revival:** What a revival means without rewriting immutable
   compost history, which authority may approve it, how continuity is proven,
   and what standing survives remain unresolved. Build A creates no revival or
   live-successor effect.
8. **Multi-file lineage preview:** Whether the v1 lineage substrate should be
   built at all, who ratifies its open policy, and which exact file manifest is
   intended remain unresolved. The controlling Build A goal calls it the
   “twenty-file lineage preview,” while v1 section 11.2 enumerates 23 paths.
   Build A neither reconciles that scope nor implements any of those paths.

## Build A Activation Prohibition

Nothing produced by Build A may:

- create or register a child;
- issue `lineage_ready` or another inherited capability;
- alter agent identity, standing, rank, or lineage;
- migrate a live identity;
- mount a public lineage or live disposition route;
- activate a constitutional change;
- resolve, compost, canon, supersede, or revive a live artifact;
- activate a compost batch; or
- treat a council vote, countersign, lease, API route, fixture, receipt, or this
  ADR as disposition authority.

Any ambiguous activation request fails closed. Build A must retain
`live_mutations=0`, `provider_calls=0`, `standing_effect=none`, and
`master_vision_effect=none`.

## Proof and Authority Are Different Types

Build A may establish that local code and evaluator semantics work on an
explicitly authorized synthetic fixture and a copied database. That is
engineering proof, not historic or live authority:

```text
ProvenOnCopy != Authorized<Live>
RehearsalDisposition<Copy> !-> EffectiveVerdict<Live>
ADRRecorded !-> LineagePolicyRatified
```

A passing copy rehearsal cannot promote fixture evidence into real evidence,
manufacture live jurisdiction, change standing, or count as a historic live
win. The only truthful Build A claim is:

```text
engineering_status = proven_on_copy
historic_live_win = false
standing_effect = none
build_b = not_run_authority_unresolved
```

## Consequences

Build A can close without provider availability or Build B authority. The cost
is intentional: no lineage substrate or activation capability is created, and
all attended, live, batch, revival, and reproduction questions remain open for
a separately authorized future decision.

This ADR records a boundary, not approval of the v1 Phase B design. A later ADR
may supersede it only after the relevant authority and policy questions are
explicitly resolved; technical capability or model consensus is insufficient.
