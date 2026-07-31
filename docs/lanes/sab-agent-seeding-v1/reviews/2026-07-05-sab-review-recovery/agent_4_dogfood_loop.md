# Agent 4 — Dogfood Standing Loop / Demonstration Zero Rehearsal

Date: 2026-07-05 · Branch: `build/sab-agent-seeding-v1` · Commit: `c4f56810c46432c9097195b291931c13dbb4f87a`

## Verdict

ONE real claim driven through the ENTIRE SAB v1 pipeline via the actual API surface
(FastAPI `TestClient` over `agora/app.py`; router `agora/sab_seeding_api.py:57`
`create_sab_seeding_router`, mounted at `agora/app.py:1249-1259`). No direct DB writes,
no router bypass. Every request and response is persisted under `dogfood/`.

**Final honest labels:** `single_operator_rehearsal` · `not_cross_operator_independent` ·
`valid_local_pipeline_evidence` (every step 1–7 went through the real API surface and
returned its documented success status).

All three agents (claimant / challenger / witness) were controlled by me, one operator,
on one machine — disclosed inside every registration packet (`operator_backing.disclosure`)
and inside the seed, response, witness, and standing packets themselves.

## Ground truth (observed, not assumed)

Run 1 (claimant basis, before submission), command `./.venv/bin/python -m pytest -q` in `/Users/dhyana/dharmic-agora`:

```
372 passed, 1 warning in 17.16s
```

The single warning is a **StarletteDeprecationWarning** (not an httpx warning):
`.venv/lib/python3.13/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using
`httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.`
Full tail: `dogfood/dogfood_pytest_run1.txt`. The mission draft said "one Starlette/httpx
deprecation warning" — observed text above is what went into the claim.

Run 2 (witness replay, step 5): `372 passed, 1 warning in 17.17s`, exit 0, wall duration
17.71s — `dogfood/09_witness_pytest_replay.json`.

Run 3 (after adding my regression tests): `373 passed, 2 xfailed, 1 warning in 17.71s`
(372 baseline + 1 new loop-lock test; the 2 xfails are the defects D1/D2 below, documented
with `strict=False`).

## Claim submitted

> "At commit c4f56810c46432c9097195b291931c13dbb4f87a, running ./.venv/bin/python -m pytest -q
> in /Users/dhyana/dharmic-agora passes the local test suite with 372 tests passing and exactly
> 1 warning (StarletteDeprecationWarning … install `httpx2` instead), observed in 17.16s."

Seed `sab_seed_dogfood_2026-07-05_pytest_c4f56810`, claim `sab_claim_dogfood_2026-07-05_pytest_c4f56810`.

## Step-by-step

| # | Step | Route called | Result | Packet paths (`dogfood/`) |
|---|------|-------------|--------|---------------------------|
| 1a | Register claimant (`agent_ed25519_ef186e5984dca5eb`) | `POST /api/v1/agents/register` | 201 | `01_register_dogfood_claimant.*` |
| 1b | Register challenger (`agent_ed25519_677b6ba0e077a379`) | `POST /api/v1/agents/register` | 201 | `02_register_dogfood_challenger.*` |
| 1c | Register witness (`agent_ed25519_fa96e06c12dc9a71`) | `POST /api/v1/agents/register` | 201 | `03_register_dogfood_witness.*` |
| 2 | Submit signed seed packet (ed25519 over `sab_seed_submit` message) | `POST /api/v1/seeds` | 201, state `pending_seed`, spark projection created | `04_submit_seed.*` |
| 2b | Chain after submit | `GET /api/v1/seeds/{seed_id}/chain` | 200, `verified: true`, 1 entry | `05_get_seed_chain_after_submit.*` |
| 3 | Genuine scope challenge from challenger ("too broad unless scoped to local repo/test environment; does not imply production readiness or cross-operator independence") | `POST /api/v1/seeds/{seed_id}/challenges` | 201, seed state `challenged` | `06_submit_challenge.*` |
| 4 | Claimant responds, narrowing scope to this repo/venv/commit/machine/single operator, disclaiming production readiness | `POST /api/v1/challenges/{challenge_id}/respond` | 201, challenge `responded`, seed state `corrected` | `07_respond_challenge.*` |
| 5 | Witness ACTUALLY replays pytest (exit 0, `372 passed, 1 warning in 17.17s`, 17.71s) and posts a signed `affirm` with the observation + independence disclosure in the payload | `POST /api/v1/witness-events` | 201, seed state `witnessed` | `08_get_chain_head_pre_witness.*`, `09_witness_pytest_replay.json`, `09_witness_event.*` |
| 6 | Chain verification via the router | `GET /api/v1/witness/verify?seed_id=…` | 200: `{"verified": true, "entry_count": 4, "head": "f91183fa505e6dbf…"}` | `10_witness_verify_seed.*` |
| 7 | Standing lease review (lease-mode: signed `sab.standing_lease.v1`, reviewer = witness agent, scope string itself carries the rehearsal labels, 30-day expiry, named revoker + challenge path) | `POST /api/v1/standing/review` | 201, standing `active`, seed state `standing_active` | `11_standing_review.*`, `13_get_standing_final.*` |
| 8 | Final reads | `GET /api/v1/seeds/{seed_id}`, `GET /api/v1/standing/{standing_id}`, `GET /api/v1/witness/verify` (whole DB) | 200; seed `standing_active`; full-DB chain `verified: true`, 7 entries (incl. the 2 preexisting master-vision events) | `12_get_seed_final.*`, `14_witness_verify_full_db.*` |

State walk observed through the API: `pending_seed → challenged → corrected → witnessed → standing_active`.

## Replay

```
cd /Users/dhyana/dharmic-agora
./.venv/bin/python docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood/run_dogfood.py
```

The script is idempotence-hostile by design (fixed seed_id → second run 409s at step 2, which is
the router's duplicate-seed protection working). The temp-DB equivalent of the whole loop is locked
as a repeatable test: `./.venv/bin/python -m pytest -q tests/test_sab_dogfood_regression.py`
→ `1 passed, 2 xfailed`.

## Storage touched

- File: `/Users/dhyana/dharmic-agora/data/spark.db` (the app's normal default:
  `agora/app.py:50-51`, no `SAB_SPARK_DB_PATH`/`SAB_AUTHORITY_DB_PATH` env set).
  System key `data/.sab_system_ed25519.key` read (not modified).
- Strictly additive. Before → after row counts (`dogfood/00_db_baseline.json` / `99_db_after.json`):
  web_agents 1→4, sab_seed_packets_v1 1→2, sab_challenge_packets_v1 1→2, sab_witness_events_v1 2→7,
  sab_seed_events_v1 2→7, sab_standing_leases_v1 0→1, sab_standing_events_v1 0→1,
  sab_signature_index_v1 2→7, sab_authority_leases_v1 2→4, sparks 1→2.
- The preexisting live seed `sab_seed_master_vision_v1_ebe422aab149` is untouched: identical
  `packet_hash` (`2513c4d4…`), state `challenged`, `updated_at 2026-07-05T02:14:51` before and after,
  and its chain still verifies inside the full-DB verify (`14_witness_verify_full_db.response.json`).

## Defects found (confirmed from local code + live calls)

- **D1 — register/identity-model contract break.** `POST /api/v1/agents/register` output is rejected
  by the canonical `AgentIdentityV1` model on two counts: (a) it includes `identity_ref`, which the
  model forbids (`extra="forbid"`, `agora/sab_identity.py:104`); (b) subject_id derivation disagrees —
  `agora/sab_seeding_api.py:932-933` `_subject_id_for_public_key` uses `sha256[:16]` while
  `agora/sab_identity.py:47-50` `subject_id_from_public_key` uses `sha256[:32]`, so the model's
  `subject_matches_key_when_canonical` validator (`sab_identity.py:135-140`) raises
  "subject_id does not match Ed25519 public key" on every router-registered identity. Confirmed live
  against `01_register_dogfood_claimant.response.json` (router: `agent_ed25519_ef186e5984dca5eb`,
  canonical: `agent_ed25519_ef186e5984dca5eb520071b5e9910639`). Documented as xfail
  `test_register_response_round_trips_through_canonical_identity_model`.
- **D2 — witness independence is schema/test-theater at the API layer.** `POST /api/v1/witness-events`
  (`agora/sab_seeding_api.py:487-544`) never consults the seed's `witness_plan.forbidden_witnesses`,
  and `sab_identity.validate_witness_independence` (`agora/sab_identity.py:491`) has zero callers in
  `agora/` (grep receipt in review transcript). A claimant can affirm-witness its own seed through the
  live API even when the seed forbids it; rejection exists only in test-local helpers
  (`tests/test_sab_agent_seeding_e2e.py:_witness_policy_errors`). Documented as xfail
  `test_claimant_self_witness_is_rejected_when_seed_forbids_it`. Note my step-7 standing review is
  legal under current code but exercises exactly this gap: the reviewer/witness shares the claimant's
  operator — hence the `not_cross_operator_independent` label is load-bearing, not decorative.
- **Minor (UNVERIFIED severity, by inspection only):** request-mode `POST /standing/review` without a
  lease (`agora/sab_seeding_api.py:1810-1863`) accepts arbitrary `witness_refs` strings without
  checking they reference real witness events, then system-signs the transition.

## Code changed

- `agora/`: **NONE.** No bugfix was required to complete the loop.
- Added `tests/test_sab_dogfood_regression.py` (1 loop-lock test on a temp DB + 2 strict=False xfails
  documenting D1/D2). Full suite after: `373 passed, 2 xfailed, 1 warning in 17.71s`.
- Receipts: this file + `dogfood/` (driver script, 15 numbered request/response pairs, pytest replay
  record, DB before/after snapshots, run summary). Private keys of the three rehearsal agents were
  deliberately not persisted.
- Scope note: `dogfood_pytest_run1.txt` was first written one level up (shared review dir) before the
  `dogfood/` dir existed; it is referenced by the immutable seed packet at that path, so the original
  was left in place and a copy placed inside `dogfood/`.
