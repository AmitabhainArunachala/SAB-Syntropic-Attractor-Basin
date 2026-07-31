# Agent 3 Receipt — Standing Semantics, Independence, Finality, Economics

**Run:** SAB Review Recovery + Demonstration Zero, 2026-07-05
**Branch/HEAD verified at start:** `build/sab-agent-seeding-v1` @ `c4f56810c46432c9097195b291931c13dbb4f87a`
**Deliverable written:** `docs/SAB_STANDING_SEMANTICS_V0.md` (new file, sole write besides this receipt)
**Labeling:** single_operator_rehearsal — all analysis by one operator's agent; no independent review.

## Commands run (evidence)

- `git -C /Users/dhyana/dharmic-agora branch --show-current && git rev-parse HEAD` → `build/sab-agent-seeding-v1` / `c4f56810…` (match).
- `./.venv/bin/python -m pytest tests/test_sab_identity_security.py -q` → **6 passed, 1 warning in 0.56s** (grounds "independence library exists and is tested").
- `grep -rn validate_witness_independence agora/ tests/` → defined `agora/sab_identity.py:491`, used only in `tests/test_sab_identity_security.py` — **no endpoint calls it**.
- `grep -rni "stake|bond|escrow|payout|slash" agora/*.py` → only a prose string at `agora/kernel.py:33` — **zero economic primitives in code**.

## EXISTS vs MISSING (verified, file:line)

**EXISTS**
- Seed/challenge/standing state sets: `agora/sab_seeding_api.py:15-30`. Full endpoint lifecycle: submit `:163`, challenge `:377`, respond/sustain/reject `:468-485`, standing review `:591`, revoke/revalidate `:735-749`.
- Challenge window computed (default P7D) and stored: `:1116-1131`, `:226`.
- Standing issuance gate (≥1 challenge, 0 pending, ≥1 witness event): `:606-611`.
- Lazy standing expiry: `_expire_standing_if_needed` `:1913-1951`.
- Per-subject witness hash chain + verify endpoints: `:502-505`, `:559-589`, `:1672-1696`. Signature replay index: `:1202-1217`.
- Independence library (unwired): `OperatorBacking` `agora/sab_identity.py:82-94`; `same_operator` `:483-488`; `validate_witness_independence` + `OperatorConcentrationPolicy` `:467-527`; time-window `ReplayProtector` `:374-464` (also unwired).
- External attestations hardwired `standing_effect:"none"`: `agora/sab_attestations.py:74, 88-104, 308-309`.
- Standing lease schema with witness_quorum/diversity/standing_basis: `nodes/schemas/sab.standing_lease.v1.schema.json:85-197`.

**MISSING / DEFECTIVE (the load-bearing findings)**
1. **Fail-open independence:** `same_operator` returns False (= independent) when either operator is `"unknown"` (`agora/sab_identity.py:486-488`), AND both register endpoints drop `operator_backing` — only `web_agents(id,name,public_key,…)` is persisted (`agora/sab_seeding_api.py:88-98`, `agora/app.py:1268-1275`); the `agent_identities.operator_backing_json` table (`agora/sab_seeding_storage.py:119-134`) is created at startup (`agora/app.py:628`) and written by nothing. Net: every live identity is "unknown" ⇒ passes the only independence check that exists ⇒ in a library the API never calls.
2. **No transition matrix / no finality:** `_record_seed_transition` checks only set membership (`:1403-1404`); a witness `affirm` on a composted seed resurrects it to `witnessed` (`:529-542` + `:1718-1729`). compost/revoked/expired are not absorbing.
3. **Window is data, not law:** nothing enters `challenge_window_open` at submit; `submit_challenge` never checks `challenge_window_closes_at`; no sweeper. A `pending` challenge blocks standing forever at zero cost (`:606-607`; v1 challenge table has no deadline column `:822-838`, though the schema requires one — `nodes/schemas/sab.challenge_packet.v1.schema.json:18,90`).
4. **Anyone adjudicates:** `_resolve_challenge_action` has no role check (`:1732-1807`) — claimant can reject their own challenge; challenger can sustain-compost another's seed; `revalidate` can promote any standing to **canon** with any valid signature (`:1992-1996`; only revoke is gated `:1973-1977`). `correct_seed` also unchecked (`:309-341`).
5. **API skips `provisional`:** standing inserted directly as `active` (`:648-653`); `STANDING_STATUSES` (`:30`) lacks schema's `provisional`/`superseded` — violating the Independence Law cap (`docs/SAB_MASTER_VISION_V1.md:96`) mechanically, exactly as its own enforcement disclosure (`:100`) admits.
6. **Zero economics:** no bond/stake/escrow/payout/slashing objects anywhere in `agora/`.
7. **Two parallel substrates:** live API owns `sab_*_v1` tables; `agora/sab_seeding_storage.py`'s unprefixed family is initialized but endpoint-orphaned (verified: `sab_seeding_api.py` never imports it).

## Build-order correction

Economics + finality must precede any public commons claim. Concretely, relative to `SAB_MASTER_VISION_V1.md` Section 9: keep item 0 (dogfood) and item 3 (independence quorum), but **FinalityRecord/AdjudicationRecord + ChallengeBond must land before items 4-5 (adapters, public challenge UX)** — the pending-challenge permanent veto and anyone-can-canon holes are live griefing/capture vectors the moment a second operator touches the API. Until then, every issued state above `provisional` is unearned by the system's own law. The doc's Section 4 splits this into 8 implementable-now items (N1-N8, all against the existing `sab_*_v1` surface) vs genuinely-new substrate (ledger, adjudication tables, operator registry).

## Dossier patch note for Agent 6 (do not edit FIELD_DOSSIER.md yourself — integrate this)

The dossier should stop describing witness independence as a property SAB "has" and describe it as a property SAB has now **specified but not yet enforced**. New canonical reference: `docs/SAB_STANDING_SEMANTICS_V0.md` defines a six-grade `IndependenceStatus` enum (`self / same_operator / undisclosed / same_operator_distinct_keys / cross_operator_unverified / cross_operator_attested`) with per-axis minimum evidence (operator, key, funding/control, runtime, conflict-of-interest), a conservative failure mode (anything ambiguous grades `undisclosed`, which counts as same-operator), and quorum thresholds per standing tier. Any dossier sentence that currently implies independent witnessing is operational should be revised to cite the grade actually achievable today: `undisclosed`, single operator, rehearsal-flagged.

Two code-grounded facts belong in the dossier's risk register verbatim: (a) the only independence check in the codebase fails open on undisclosed operators (`agora/sab_identity.py:486-488`) and is called by no endpoint, while the register endpoints discard the operator disclosure that check would need (`agora/sab_seeding_api.py:88-98`, `agora/app.py:1268-1275`); (b) the challenge/standing lifecycle has no finality mechanics — no transition guards (composted seeds are resurrectable, `agora/sab_seeding_api.py:1403-1404`), no adjudicator role checks (any signature can sustain, reject, or canon-promote, `:1732-1807`, `:1992-1996`), and no challenge deadlines (a pending challenge is a free permanent veto, `:606-607`). These are the two facts an external reviewer will find in under an hour; the dossier gains credibility by finding them first.

Finally, the dossier's economics posture should be: six typed objects (ChallengeBond, WitnessStake, Escrow, WorkAllocation, PayoutReceipt, SlashingEvent) are now **designed with invariants and attack rationales** in `SAB_STANDING_SEMANTICS_V0.md` Section 3, none built, and the declared ordering is bonds+finality before open participation — dogfood may proceed without them, public scale may not. Cite the master vision's own enforcement disclosure (`docs/SAB_MASTER_VISION_V1.md:100-102`) as the precedent for this style of honest gap declaration.

## Blockers

None. Git untouched (read-only). No other agents' files modified.
