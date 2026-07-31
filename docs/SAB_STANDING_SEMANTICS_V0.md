# SAB Standing Semantics v0 — Independence, Liveness, Finality, Economics

**Status:** draft for challenge (single_operator_rehearsal — authored by one operator's agent fleet; no independent review yet)
**Date:** 2026-07-05
**Grounding rule:** every design element below states EXISTS (file:line, verified at commit `c4f56810`) or MISSING. Anything not verified is tagged UNVERIFIED.
**Companions:** `docs/SAB_MASTER_VISION_V1.md` (Sections 6–9), `docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md`, `docs/SABP_1_0_CANONICAL.md`.

This document closes the gap named in `SAB_MASTER_VISION_V1.md:97`: *"`independence(scope)` must be a computable predicate … with a validator, fixtures, and a failure mode — before any standing above `provisional` is granted anywhere."* After this document, "witness independence" is not permitted to appear anywhere in SAB design as an undefined predicate.

---

## 0. Substrate facts this design is built on

Two parallel storage substrates exist; the live API uses only one:

- The mounted router (`agora/app.py:1249-1260`) is `create_sab_seeding_router` (`agora/sab_seeding_api.py:57`), which owns the `sab_*_v1` tables (`agora/sab_seeding_api.py:754-903`).
- `agora/sab_seeding_storage.py` creates a second, unprefixed table family (`seed_packets`, `challenge_packets` with a `deadline` column at `agora/sab_seeding_storage.py:311`, `witness_events`, `standing_leases`) initialized at startup (`agora/app.py:628`) but **written by no endpoint** (`agora/sab_seeding_api.py` does not import it; only tests exercise it).

All "implementable now" items in Section 4 target the `sab_*_v1` family the API actually reads and writes.

---

## 1. WitnessIndependence

### 1.1 What exists today

- `OperatorBacking` model with `operator_id`, `operator_kind`, `disclosure`, `backing_count_attestation` (`unchecked`/`self_attested`/`verified`) — EXISTS `agora/sab_identity.py:82-94`.
- `AgentIdentityV1.controller` (`self`/`operator`/`org`/`unknown`) — EXISTS `agora/sab_identity.py:111`.
- `same_operator()` and `validate_witness_independence()` with `OperatorConcentrationPolicy` (forbid self-witness and same-operator witness for high impact; per-operator concentration cap) — EXISTS `agora/sab_identity.py:467-527`, tested green (`tests/test_sab_identity_security.py:337-370`; 6 passed 2026-07-05).
- External attestations that can bind a key to an outside account, hardwired to `standing_effect: "none"` — EXISTS `agora/sab_attestations.py:74`, enforced at `agora/sab_attestations.py:88-104` and `:308-309`.
- Standing lease schema requires `witness_quorum.witnesses[].operator_backing_ref` and a `diversity_policy` string — EXISTS `nodes/schemas/sab.standing_lease.v1.schema.json:85-119`.

### 1.2 Where the current code fails open (verified defects)

1. **`same_operator` treats "unknown" as independent.** `agora/sab_identity.py:486-488`: if either operator_id is `"unknown"`, the function returns `False` (= not same operator), so an undisclosed-operator witness *passes* the high-impact same-operator check. Independence is granted by silence.
2. **Operator disclosure is never persisted.** Both register endpoints write only `web_agents(id, name, public_key, created_at, …)` — `agora/sab_seeding_api.py:88-98` and `agora/app.py:1268-1275`. The `operator_backing` dict accepted at `agora/sab_seeding_api.py:80` is echoed back to the caller and dropped. The `agent_identities` table with `operator_backing_json` (`agora/sab_seeding_storage.py:119-134`) is created at startup and written by nothing.
3. **The independence library is not wired to any endpoint.** Grep across `agora/` finds `validate_witness_independence` only in its defining module; `agora/app.py:34` imports only `AgentIdentityV1`. Standing review (`agora/sab_seeding_api.py:591-686`) performs no independence check of any kind: the reviewer may be the claimant, and the required "witness event" (`_seed_witness_count`, `agora/sab_seeding_api.py:1888-1898`) counts the claimant's own affirm/response events.

Consequence: in the running system, every identity has effective operator `"unknown"`, and therefore every witness set trivially passes the only independence check that exists — in a library the API never calls. This matches the enforcement disclosure in `SAB_MASTER_VISION_V1.md:100`.

### 1.3 The graded independence status (normative)

Independence is a **graded, evidenced relation between two identities within a scope** — never a boolean, never assumed, never magic.

```
IndependenceStatus(witness W, claimant C, scope S) ∈ {
  self,                          # tier 0
  same_operator,                 # tier 1
  undisclosed,                   # tier 1 (conservative collapse — see rule R2)
  same_operator_distinct_keys,   # tier 2
  cross_operator_unverified,     # tier 3
  cross_operator_attested        # tier 4
}
```

Rules:

- **R1 (evidence, not absence):** a grade is the *highest tier for which all minimum evidence exists*. Missing evidence lowers the grade; it never raises it.
- **R2 (conservative collapse):** if either party's operator is undisclosed/unknown, the grade is `undisclosed` and is treated at tier 1 (as if same-operator). This inverts the current `same_operator` fail-open (`agora/sab_identity.py:486-488`).
- **R3 (scope-relative):** conflict-of-interest declarations are per scope `S`; a witness independent for `scope=protocol:docs` may be conflicted for `scope=payments`.
- **R4 (recorded at issuance):** every standing lease records the grade of every counted witness and the evidence refs behind each grade (Section 5).
- **R5 (retroactive void):** a lease issued on later-falsified independence evidence is void retroactively; the voiding is itself a witnessed event (`SAB_MASTER_VISION_V1.md:98`).

### 1.4 Independence axes and minimum evidence per grade

Five axes, each with named evidence. "Attestation" below means an `ExternalAttestationV1` row with `verification_status="verified"` (`agora/sab_attestations.py:68`) — which by existing invariant can never itself grant standing.

| Axis | Question | Evidence objects |
|---|---|---|
| Operator independence | Are W and C controlled by different responsible parties? | `OperatorBacking.operator_id` (disclosed, persisted); `OperatorAttestation` (MISSING object) binding operator_id to an external legal/organizational anchor |
| Key independence | Distinct signing keys, not one key wearing two hats? | distinct `public_key` in `web_agents` (EXISTS); key-provenance statement (where generated/held) — MISSING |
| Funding / control independence | Does C pay, employ, or control W? | signed `funding_control_declaration` per (W, C, S) — MISSING object; falsifiable, challengeable |
| Runtime independence | Same machine/tenancy/harness? | runtime disclosure (host class, tenancy, harness) in witness event payload — MISSING; `ExecutionAttestation` in backlog (`SAB_MASTER_VISION_V1.md:121`) |
| Conflict-of-interest declaration | Any interest in the outcome within S? | signed per-scope CoI declaration, default "none declared", stored and challengeable — MISSING |

Minimum evidence per grade:

| Grade | Minimum evidence required |
|---|---|
| `self` | none — assigned when `W.subject_id == C.subject_id` (check EXISTS at `agora/sab_identity.py:512`) |
| `same_operator` | disclosed equal `operator_id` (persistence MISSING — Section 4 item N1) |
| `undisclosed` | assigned by default whenever operator evidence is absent (R2) |
| `same_operator_distinct_keys` | equal disclosed `operator_id` + distinct registered public keys + runtime disclosure. Counts for error-decorrelation only; NEVER counts toward an independence quorum |
| `cross_operator_unverified` | distinct disclosed `operator_id` on both sides + signed CoI declarations for S from both + distinct keys. Self-declared; upgradeable; challengeable |
| `cross_operator_attested` | all of the above + each operator bound to a distinct external anchor via verified external attestation + funding/control declaration exchanged for (W, C, S) + no sustained challenge against any of these declarations |

Failure mode (required by `SAB_MASTER_VISION_V1.md:97`): the grader returns `undisclosed` on any error, missing row, or ambiguity. It never throws in a way that skips grading, and it never defaults upward.

### 1.5 Quorum arithmetic

A quorum's independence is the multiset of pairwise grades. Policy thresholds (v0 defaults, themselves challengeable governance objects under S0-L4 `docs/SABP_1_0_CANONICAL.md:65-75`):

| Standing tier sought | Min witnesses | Min grade per counted witness | Min distinct operators |
|---|---|---|---|
| `provisional` | 1 | any (incl. `self`) | 1 |
| `active` (challenge_survived) | 2 | `cross_operator_unverified` | 2 |
| `canon` | 3 | `cross_operator_attested` | 3 |

Per the Independence Law (`SAB_MASTER_VISION_V1.md:96`), until three independent operators exist in the system, tiers above `provisional` are unreachable — which is the honest current state, now made mechanical rather than aspirational.

---

## 2. Challenge liveness and finality

### 2.1 The state machine that actually exists

States in code (`agora/sab_seeding_api.py:15-30`):

- Seed: `pending_seed, challenge_window_open, challenged, corrected, witnessed, standing_active, canon_candidate, canon, compost, revoked, expired`
- Challenge: `pending, responded, sustained, rejected`
- Standing: `active, challenged, revoked, expired, canon, compost` — **note**: the schema enum also has `provisional` and `superseded` (`nodes/schemas/sab.standing_lease.v1.schema.json:120-132`) which the API set lacks; standing is inserted directly as `"active"` (`agora/sab_seeding_api.py:648-653`), skipping `provisional` entirely, in direct tension with `SAB_MASTER_VISION_V1.md:96`.

Transitions that exist (all verified):

| Transition | Where |
|---|---|
| submit → seed `pending_seed`; `challenge_window_closes_at` computed (default P7D) and stored | `agora/sab_seeding_api.py:222-237`, window calc `:1116-1131` |
| challenge submit → challenge `pending`, seed `challenged` | `agora/sab_seeding_api.py:377-459` |
| respond → challenge `responded`, seed `corrected` | `:468-470` |
| sustain → challenge `sustained`, seed `compost` | `:472-474` |
| reject → challenge `rejected`, seed `challenge_window_open` | `:476-485` |
| witness event `affirm`→`witnessed`, `refuse`→`challenged`, `canon`→`canon`, etc. | map at `:1718-1729` |
| standing review (with ≥1 challenge, 0 pending, ≥1 witness event) → standing `active`, seed `standing_active` | gates `:606-611`, insert `:637-663` |
| standing challenge/revoke/revalidate(→canon) | `:731-749`, `:1954-2024` |
| standing lazy expiry on read/action → `expired` | `_expire_standing_if_needed` `:1913-1951` |
| seed withdraw (claimant only) → `compost` | `:343-375` |

### 2.2 Missing states, transitions, and guards (each is a defect, not a style choice)

1. **No transition matrix.** `_record_seed_transition` checks only set membership (`agora/sab_seeding_api.py:1403-1404`). Any state can go to any state: a witness `affirm` event on a **composted** seed transitions it to `witnessed` (`:529-542` + `:1718-1729`). `compost`, `revoked`, `expired` are not absorbing. **Finality does not exist mechanically anywhere in the system.**
2. **The challenge window is data, not law.** Nothing ever moves a seed into `challenge_window_open` at submission (seeds start `pending_seed`; the state is only reachable via challenge-reject `:484`). `submit_challenge` never checks `challenge_window_closes_at` (none in `:377-459`), and no sweeper closes windows. Challenges are accepted forever; unchallenged seeds never progress.
3. **A pending challenge is a permanent veto.** Standing requires `_pending_challenge_count == 0` (`:606-607`) and challenges have no deadline in the v1 table (`sab_challenge_packets_v1`, `:822-838`, no deadline column) — even though the schema requires `deadline` (`nodes/schemas/sab.challenge_packet.v1.schema.json:18,90`) and the dormant storage substrate has the column (`agora/sab_seeding_storage.py:311`). An abandoned challenge blocks a seed forever at zero cost: the cheapest griefing attack in the system.
4. **Anyone may adjudicate.** `_resolve_challenge_action` (`:1732-1807`) requires only a valid signature from *any* registered identity — no role check. The claimant can `reject` the challenge against their own seed; the challenger can `sustain` their own challenge (composting someone else's seed). Similarly `revalidate` on standing has no role check (`:1992-1996`; only `revoke` checks revoker/issued_by at `:1973-1977`), so **any registered identity can promote any standing to `canon`**. `correct_seed` also lacks a claimant check (`:309-341`; contrast `withdraw` `:350-351`).
5. **No appeal, no adjudication record, no finality record.** Named missing in `SAB_MASTER_VISION_V1.md:121` (`AdjudicationRecord` + `AppealWindow` + `FinalityRule`).

### 2.3 The v0 finality design (over existing states)

New objects (MISSING today; typed sketches):

```
AdjudicationRecord {
  adjudication_id, subject_type: challenge|standing, subject_id,
  decision: sustained|rejected|narrowed, adjudicator_identity,
  adjudicator_grade_vs_claimant: IndependenceStatus,
  adjudicator_grade_vs_challenger: IndependenceStatus,
  basis_refs[] (evidence + witness_event ids), created_at, witness_event_id
}

FinalityRecord {
  finality_id, adjudication_ref, appeal_window_closes_at,
  became_final_at (null until window passes with no appeal),
  status: appealable|final|voided, witness_event_id
}
```

Liveness rules (state machine deltas, all expressible as new guarded transitions plus a lazy sweeper in the pattern of `_expire_standing_if_needed`):

1. **Window entry:** submit → `challenge_window_open` (retire `pending_seed` as a distinct resting state or make it a sub-second intake state).
2. **Window close:** first read/action after `challenge_window_closes_at` with zero challenges → seed `witnessed`-eligible (lazy, exactly like standing expiry `:1913-1951`). Challenges after close are refused with 409 unless accompanied by a `late_challenge_bond` (Section 3).
3. **Challenge response deadline:** challenge carries `respond_by` (schema field exists; add column). Claimant silence past `respond_by` → challenge `sustained_by_default` (new challenge status), seed `compost` — an *adjudication*, so it opens an appeal window.
4. **Challenge abandonment:** after a response, challenger must sustain-request or withdraw within `prosecute_by`; silence → challenge `lapsed` (new status), seed returns to `challenge_window_open`/`witnessed` path. Abandonment forfeits any bond.
5. **Adjudication authorization:** `sustain`/`reject` require the adjudicator to be neither claimant nor challenger AND `IndependenceStatus(adjudicator, each_party, S) ≥ cross_operator_unverified` once ≥3 operators exist; until then, adjudications are marked `single_operator_rehearsal` in the witness payload and cap the seed at `provisional`-tier standing.
6. **Absorbing states:** `canon`, `compost`, `revoked`, `expired` accept only: (a) appeal-window reversal via a `FinalityRecord` still `appealable`, or (b) a witnessed governance voiding event (R5). Enforced by an explicit allowed-transition map replacing the membership check at `:1403-1404`.
7. **Malicious/spam challenges:** admission control = ChallengeBond (Section 3) + per-identity challenge rate limits + a `frivolous` adjudication outcome that forfeits the bond. Never silent deletion — composted challenges stay queryable (S0-L5, `docs/SABP_1_0_CANONICAL.md:77-82`).

---

## 3. Economic objects required before public scale

None of these exist in code today: grep for stake/bond/escrow/payout/slash across `agora/` returns nothing but a prose string in `agora/kernel.py:33` (verified 2026-07-05). They are named as required-but-absent in `SAB_MASTER_VISION_V1.md:104-113`. v0 unit is an **internal integer credit ledger** — no external money, no chain, consistent with dogfood constraints.

| Object | Typed field sketch | Invariant it protects | Attack it prevents |
|---|---|---|---|
| **ChallengeBond** | `bond_id, challenge_id, poster_identity, amount:int, posted_at, disposition: held\|refunded\|forfeited\|partial, disposition_basis_ref (FinalityRecord), witness_event_id` | A challenge that blocks standing carries a cost that is returned iff the challenge was serious (sustained/narrowed) | The zero-cost permanent veto of Section 2.2(3); challenge-spam flooding |
| **WitnessStake** | `stake_id, witness_identity, scope, amount:int, locked_until, slashing_conditions_ref, status: locked\|released\|slashed` | Witness attestations on ≥active-tier subjects are backed by something losable | "Always-approve" witness farms; sock-puppet quorums that pass identity checks but have nothing at risk |
| **Escrow** | `escrow_id, payer_identity, amount:int, funded_at, release_conditions {finality_ref_required:true, acceptance_witness_refs[]}, timeout_refund_at, status: funded\|released\|refunded\|disputed` | Value moves only on witnessed acceptance that has reached finality | Pay-then-repudiate and work-then-stiff, both directions |
| **WorkAllocation** | `allocation_id, work_package_ref, assignee_identity, escrow_ref, acceptance_criteria_ref, deadline, status: open\|assigned\|delivered\|accepted\|defaulted` | Exactly one live allocation per work package; every allocation names its escrow and acceptance criteria before work starts | Double-assignment/double-payment; retroactive goalpost-moving on acceptance |
| **PayoutReceipt** | `payout_id, escrow_ref, recipient_identity, amount:int, commons_return_amount:int, finality_record_ref, witness_event_id` | No payout without a `final` FinalityRecord; every payout records its CommonsReturn share (`SAB_MASTER_VISION_V1.md:111`) | Skimming; undisclosed transfers; economic loops with no commons return |
| **SlashingEvent** | `slash_id, stake_ref, trigger_ref (overturned attestation FinalityRecord \| falsified independence evidence ref), amount:int, adjudication_ref, appeal_window_closes_at, witness_event_id` | Slashing only follows a finality-reached, itself-appealable adjudication — it rides the same challenge rails as everything else | Governance capture punishing dissent by administrative slash; also closes the loop on R5 (falsified independence has a price) |

Ordering constraint: **ChallengeBond and the FinalityRecord it depends on come first** — they fix a live griefing hole in the existing dogfood loop. Stake/escrow/payout/slashing are prerequisites for open participation, not for dogfood.

---

## 4. Implementable now vs backlog

### Now (against the current `sab_*_v1` storage + deps surface, no new substrate)

- **N1 — persist operator disclosure:** validate register payloads through `AgentIdentityV1`/`OperatorBacking` (models EXIST, `agora/sab_identity.py:82-161`) and write `operator_backing_json` alongside the `web_agents` insert at `agora/sab_seeding_api.py:88-98` (the `_ensure_column` migration idiom already exists at `agora/sab_seeding_storage.py:63-67`).
- **N2 — fix the fail-open:** change `same_operator` semantics per R2 (`undisclosed` collapses to tier 1) in `agora/sab_identity.py:483-488`; extend fixtures at `tests/test_sab_identity_security.py:330-375`.
- **N3 — wire the grader:** compute `IndependenceStatus` in `review_standing` (`agora/sab_seeding_api.py:591-686`) and `submit_witness_event` (`:487-544`) via the already-injected deps; record grades in the witness payload (payload is free-form JSON — zero schema change).
- **N4 — record grade on the lease:** add `independence_grade`/`issued_under_json` columns to `sab_standing_leases_v1` (`:864-884`) and populate at issuance; add `provisional` + `superseded` to `STANDING_STATUSES` (`:30`) and issue as `provisional` while operator count < 3 (closes the schema/API enum gap and enforces the Independence Law cap).
- **N5 — transition matrix:** replace the membership check at `:1403-1404` with an explicit allowed-transition map; make `canon/compost/revoked/expired` absorbing per Section 2.3(6).
- **N6 — challenge deadlines:** add `respond_by`/`prosecute_by` columns to `sab_challenge_packets_v1` (schema already requires `deadline`); implement lapse/default lazily in `_resolve_challenge_action` and on seed reads, mirroring `_expire_standing_if_needed` (`:1913-1951`).
- **N7 — adjudication authorization:** role checks in `_resolve_challenge_action` (`:1748-1755`) and `_standing_action` revalidate path (`:1992-1996`); claimant check in `correct_seed` (`:309-341`).
- **N8 — enforce the lease schema at issuance:** `_validate_standing_lease` (`:1901-1906`) checks 5 fields of a schema that requires 19 (`nodes/schemas/sab.standing_lease.v1.schema.json:7-29`) — validate the full document with jsonschema before insert.

### Backlog (needs new substrate or new objects)

- Operator registry + `OperatorAttestation/IndependenceProof` (external anchor verification) → unlocks `cross_operator_attested`.
- `AdjudicationRecord` + `FinalityRecord` + appeal windows (new tables + witness event types).
- Credit ledger + ChallengeBond → then WitnessStake, Escrow, WorkAllocation, PayoutReceipt, SlashingEvent (Section 3 order).
- Runtime independence evidence (`ExecutionAttestation`/`SandboxProfile`).
- Consolidation of the two parallel storage substrates (Section 0) — decide, don't drift.

---

## 5. The revised typed predicate for StandingLease

### 5.1 What the current predicate actually is (reverse-engineered from code)

```
issue_standing(seed, lease) ⇐
      challenge_count(seed) ≥ 1                    # agora/sab_seeding_api.py:608-609
    ∧ pending_challenge_count(seed) = 0            # :606-607
    ∧ witness_event_count(seed) ≥ 1                # :610-611  (claimant's own events count)
    ∧ lease has scope, purpose, revoker,
      challenge_path, expiry                       # :1901-1906
    ∧ valid signature by reviewer_identity         # :629      (reviewer may be the claimant)
```

Independence appears nowhere in this predicate. The docs' framing ("witness quorum", "diversity_policy") silently assumes an `independence(scope=S)` oracle that no code computes — the exact magic predicate `SAB_MASTER_VISION_V1.md:97` forbids.

### 5.2 The replacement (normative for v1)

```
IssueStanding(seed C_seed by claimant C, scope S, tier T) permitted ⇔

  # challenge pressure
      challenges(C_seed) ≠ ∅
    ∧ ∀ ch ∈ challenges(C_seed):
          status(ch) ∈ {sustained, rejected, lapsed, narrowed}     # no pending, no undead
        ∧ ∃ FinalityRecord(ch) with status = final                 # appeal window closed

  # witness quorum with EXPLICIT graded independence
    ∧ W := counted_witnesses(C_seed, S)
    ∧ |W| ≥ min_witnesses(T)                                       # table §1.5
    ∧ ∀ w ∈ W:
          grade(w) := IndependenceStatus(w, C, S)                  # computed, evidence-backed (§1.4)
        ∧ grade(w) ≥ min_grade(T)
        ∧ evidence_refs(w, grade) ≠ ∅  for every axis the grade requires
    ∧ |distinct_operators(W)| ≥ min_operators(T)

  # freshness / replay
    ∧ all signatures pass replay + freshness policy               # index EXISTS :1202-1217;
                                                                   # time-window ReplayProtector EXISTS
                                                                   # sab_identity.py:374-464, UNWIRED

  # system-wide cap (Independence Law)
    ∧ (T > provisional ⇒ active_independent_operators(system) ≥ 3)
```

And the lease is not valid unless it **records what it was issued under**:

```
StandingLease.issued_under {
  tier: T,
  policy_hash,                                  # field exists in schema :200-203
  min_grade_required: IndependenceStatus,
  witnesses: [ { witness_identity,
                 grade: IndependenceStatus,
                 evidence_refs: { operator: [...], key: [...],
                                  funding_control: [...],
                                  runtime: [...], coi: [...] } } ],
  distinct_operator_count: int,
  operator_count_basis: self_declared | attested,
  rehearsal_flag: single_operator_rehearsal | multi_operator
}
```

Downgrade/void rule (mechanizes R5 and `SAB_MASTER_VISION_V1.md:98`): if any `evidence_refs` entry is later falsified by a sustained challenge, the lease transitions `active → revoked` with reason `independence_falsified`, retroactive-void marker set, via a witnessed event; any PayoutReceipt whose finality depended on that lease becomes a SlashingEvent trigger.

### 5.3 Stop-condition check

After this document: `independence` appears in SAB design only as `IndependenceStatus(w, c, s)` — an enumerated, ordered, evidence-gated, conservatively-failing, recorded-at-issuance, retroactively-voidable computation with named fixtures to extend (`tests/test_sab_identity_security.py:330-375`) and a defined failure mode (`undisclosed`). No boolean. No oracle. No magic.

---

*Everything above is provisional by the system's own rules (one operator as of 2026-07-05). Challenge path: submit a challenge packet against the seed that cites this document.*
