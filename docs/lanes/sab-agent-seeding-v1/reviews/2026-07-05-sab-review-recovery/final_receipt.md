# SAB Review Recovery + Demonstration Zero — FINAL RECEIPT

Completed: 2026-07-06T00:05+0900 (started 2026-07-05T23:25+0900, ~40 min wall vs 4h budget)
Repo: /Users/dhyana/dharmic-agora — branch `build/sab-agent-seeding-v1`, HEAD `c4f56810c46432c9097195b291931c13dbb4f87a` (UNCHANGED start→finish; git used read-only by all agents)
Run: workflow `wf_70761c85-80b`, 6 agents + coordinator, 796,782 subagent tokens, 252 tool calls, 0 agent errors.

## PROOF CLASS (Definition of Done item 10 — stated first)

**Single-operator local rehearsal via the real API. NOT a mock. NOT cross-operator evidence.**

One real claim (pytest ground truth at this HEAD) walked
`pending_seed → challenged → corrected → witnessed → standing_active` entirely through the
mounted FastAPI router (TestClient over `agora/app.py`, statuses 201/200), with all 15
request/response pairs persisted under `dogfood/`. Three distinct Ed25519 keys, one operator.
Labels carried in the packets themselves and honored by the verifier:
`single_operator_rehearsal`, `not_cross_operator_independent`, `valid_local_pipeline_evidence`.
The verifier deliberately grades the resulting lease `rehearsal_only`, not `active`.

## Coordinator verification (all commands re-run by coordinator, not trusted from agents)

| Check | Result |
|---|---|
| CSV parse (14 cols, source_refs) | `35 rows, 14 columns, all source_refs present` ✅ |
| `./.venv/bin/python -m pytest -q` | `383 passed, 2 xfailed, 1 warning in 16.43s` ✅ (372 baseline + 1 loop-lock + 10 verifier tests; 2 xfail document defects D1/D2) |
| `./.venv/bin/python -m bandit -r agora connectors -x agora/tests -q` | 1 Medium (B608 `sab_seeding_storage.py:943` — SAFE, identifiers from PRAGMA∩hardcoded dict, values parameterized), 1 Low (B105 false positive) — unchanged from baseline, no new issues ✅ |
| Route/doc consistency | Coordinator grep confirms the 6 phantom endpoints are now annotated "target design, returns 404 today" in `site/auth.md:59-66,170-183` and `site/skill.md:50-51` ✅ |
| Verifier demo (independent re-run) | `scripts/sab_verify.py sab_standing_dogfood_2026-07-05_c4f56810` → `rehearsal_only`, `independence_status: same_operator_distinct_keys`; nonexistent id → `unknown` ✅ |
| DB integrity | `data/spark.db` strictly additive; pre-existing seed `sab_seed_master_vision_v1_ebe422aab149` untouched (state=challenged, same hash) ✅ |
| New-script bandit (extra, beyond mission command) | `scripts/sab_verify.py`: 1 Low B101 (assert at :450 in CLI path) — cosmetic, noted |

## Definition of Done — 10/10

1. **White-space monopoly claim removed** ✅ — dossier grep: every "commons" is FUTURE, quotation, or negation; "accountability gradient" replaces vacuum framing (FIELD_DOSSIER.md §0, §3).
2. **ERC-8004 + GitHub-as-trust-substrate represented** ✅ — CSV rows added with mechanism-level sources (EIP-8004; Sigstore/SLSA v1.0/branch protection); ERC-8004 ranked closest threat with explicit bridge posture. Coral Protocol SKIPPED with reason (docs redirect to marketing landing; fails primary-mechanism bar).
3. **Present/future positioning corrected** ✅ — Two-Tense Thesis governs the dossier; CSV SAB row relabeled "standing overlay / claim verifier (build commons = future by demonstration)".
4. **Phantom endpoints + citations fixed** ✅ — 6 phantoms confirmed by runtime 404 probes, all now truthfully annotated in site docs; dossier citations ALL verified against sources (one attribution nuance fixed: v1 replay index lives in `sab_seeding_api.py:757`, not storage).
5. **Dogfood standing loop with receipts** ✅ — see PROOF CLASS; `agent_4_dogfood_loop.md` + `dogfood/` (15 numbered request/response pairs, pytest replay record, DB before/after snapshots).
6. **Independence/finality/economics no longer omitted** ✅ — `docs/SAB_STANDING_SEMANTICS_V0.md` (graded independence enum, finality state machine, 6 economic objects, now-vs-backlog); the code-level gaps it exposes are listed as blockers below.
7. **Build order starts dogfood → deploy/onboarding → verifier** ✅ — `NEXT_10_BUILDS.md` in exact reviewed order 0–10 with receipt-based statuses (0 DONE-as-rehearsal, 1 PARTIAL, 2 v0-EXISTS, 3–10 NOT BUILT); economics/finality written as HARD GATE inside build 3; convening demoted to build 10, demand-gated.
8. **CSV parses** ✅ (coordinator-run, above).
9. **Tests run** ✅ (coordinator-run, above).
10. **Proof class stated** ✅ (top of this receipt).

## Changed files

Mission-modified (tracked): `connectors/sab_mcp_tools.py` (wording: manifest-only, stub disclosed; dead `sab.lease.validate` route corrected), `site/auth.md`, `site/heartbeat.md`, `site/seed.md`, `site/skill.md` (endpoint truth). `docs/INDEX.md` was already modified pre-mission — untouched by this run.

Mission-created: `docs/SAB_STANDING_SEMANTICS_V0.md`, `site/standing.md`, `site/.well-known/sab-standing.json` (served=false, production_url=null — honest), `scripts/sab_verify.py`, `tests/test_sab_standing_verifier.py`, `tests/test_sab_dogfood_regression.py`, this review dir (STATUS, 6 agent receipts, dogfood/, final_receipt.md).

Mission-revised in place (pre-existing untracked user work, per hard rule never reverted): `FIELD_DOSSIER.md`, `SAB_POSITIONING_SCORECARD.md` (now explicitly qualitative; 54/86 self-scores removed — no reproducible formula existed), `NEXT_10_BUILDS.md`, `COMPARISON_MATRIX.csv` (23→35 rows), `METHODS.md`.

Untouched pre-existing user work: `docs/SAB_MASTER_VISION_V1.md`, all `contributions/` packets/receipts, `data/spark.db` prior rows.

`agora/` production code: **zero changes** — no bugfix was needed to complete the loop.

## Remaining blockers (exact, sourced)

- **B1 (D1)** Register/identity contract break: router `identity_ref` + `sha256[:16]` subject_id vs canonical `extra=forbid` + `[:32]` (`sab_seeding_api.py:932-933` vs `sab_identity.py:47-50,104,135-140`). Every router-registered identity fails canonical validation. xfail: `test_register_response_round_trips_through_canonical_identity_model`.
- **B2 (D2)** Witness independence is theater at the API layer: `POST /api/v1/witness-events` never consults `witness_plan.forbidden_witnesses`; `validate_witness_independence` (`sab_identity.py:491`) has ZERO callers; claimant self-witness accepted live. xfail: `test_claimant_self_witness_is_rejected_when_seed_forbids_it`.
- **B3** Independence fails OPEN (`same_operator()` returns independent when operator unknown, `sab_identity.py:486-488`); register endpoints discard `operator_backing`.
- **B4** No finality: composted seeds resurrectable via affirm; no role checks in `_resolve_challenge_action` (claimant can reject own challenge, `sab_seeding_api.py:1732-1807`); any signature can revalidate standing to canon (`:1992-1996`).
- **B5** Challenge window is data, not law: no deadline enforcement; a pending challenge is a free permanent veto (`:606-607`).
- **B6** API inserts standing as `active`, skipping schema's `provisional` — mechanically violates the master-vision Independence Law cap (`:648-653`).
- **B7** Zero economics primitives in `agora/` (grep-verified).
- **B8** 6 auth/lease endpoints are target design (404 today) — now documented, not built.
- **B9** `/.well-known/` is unservable as deployed-designed: FastAPI serves a `site/` whitelist only (`agora/app.py:1204-1246`) and `deploy/sab-agora.nginx.conf` denies all dot-paths.
- **B10** UNVERIFIED (inspection only): request-mode `POST /standing/review` accepts arbitrary `witness_refs` without existence checks, then system-signs (`sab_seeding_api.py:1810-1863`).
- **B11** Everything above is UNCOMMITTED on this branch. Nothing is protected by git yet.

## Exact next step

Operator reviews and commits this branch (all mission work + the pre-existing deliverables it revised — one review, one commit). Then build item 3 of `NEXT_10_BUILDS.md`: wire `validate_witness_independence` + `forbidden_witnesses` into the witness-event route and add the finality/`provisional` gate (closes B2/B3/B4/B5/B6 at their cheapest point, per `docs/SAB_STANDING_SEMANTICS_V0.md` §3/§5).
