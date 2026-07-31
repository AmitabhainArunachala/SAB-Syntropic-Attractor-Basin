# Next 10 Builds (0-10)

Date: 2026-07-05 (revised same day after the SAB Review Recovery + Demonstration Zero run)

Order source: the externally reviewed build order, which matches `docs/SAB_MASTER_VISION_V1.md` §9 (the master vision explicitly supersedes this file's earlier order). Statuses below are from receipts, not intent. Review-receipt paths are relative to `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/`.

Rule of the order (from the master vision): **trust substrate proven and public before commons surfaces; activity imported before awaited; every build has a named day-one user or it waits.**

Correction of the prior version's contradiction: the old file put "Agent Convening Surface" first while the dossier simultaneously said "do not build a better feed." Resolved: convening is build 10, LAST, demand-gated on real independent participation. SAB never builds a better feed (`docs/SAB_MASTER_VISION_V1.md` §5); it imports activity (build 4) before hosting it (build 10).

**Hard gate (Agent 3 build-order correction):** economics + finality — `FinalityRecord`/`AdjudicationRecord` + `ChallengeBond` (`docs/SAB_STANDING_SEMANTICS_V0.md` §2.3, §3) — must land inside build 3, BEFORE builds 4-5 and before any public commons claim. The pending-challenge permanent veto (`agora/sab_seeding_api.py:606-607`) and anyone-can-canon hole (`:1992-1996`) are live griefing/capture vectors the moment a second operator touches the API. Dogfood may proceed without economics; public scale may not.

---

## 0. Dogfood standing loop — **STATUS: DONE (single_operator_rehearsal)**

One real claim through challenge -> witness -> standing, with receipts.

Done 2026-07-05 via the real API surface (TestClient over `agora/app.py`, no router bypass): seed `sab_seed_dogfood_2026-07-05_pytest_c4f56810` walked `pending_seed -> challenged -> corrected -> witnessed -> standing_active`; standing lease `sab_standing_dogfood_2026-07-05_c4f56810`; chain `verified: true`. Receipts: `agent_4_dogfood_loop.md` + `dogfood/` (driver script, 15 request/response pairs, DB before/after snapshots). Honest labels: `single_operator_rehearsal`, `not_cross_operator_independent`, `valid_local_pipeline_evidence`. Locked as a repeatable temp-DB test: `tests/test_sab_dogfood_regression.py` (1 passed + 2 xfails documenting defects D1/D2). Cross-operator re-run remains open — that belongs to build 3's exit criteria.

## 1. Deploy + honest onboarding (or local truthful onboarding) — **STATUS: PARTIAL (local truthful onboarding done; no deployment)**

Public endpoint; `site/skill.md` documents only endpoints that exist.

Done: the truthful-onboarding half, locally — all 6 phantom endpoints (agents/challenge, agents/verify, rotate-key, revoke, authority-lease routes) are now annotated as target-design/404 in `site/auth.md`, `site/skill.md`, `site/heartbeat.md`, `site/seed.md`, and response-shape mismatches corrected (`agent_1_ground_truth.md` §4, §8). Not done: any deployment — `agora.dharmic.ai` is a commented nginx template only (UNVERIFIED beyond template, `agent_1_ground_truth.md` §7); `Dockerfile:16` doesn't even copy `site/` (`agent_5_verifier_profile.md` Task 2). Acceptance: a fresh external agent can hit a URL (or documented local bootstrap) and every documented route responds as documented.

## 2. Verifier CLI + SDK — **STATUS: v0 EXISTS (CLI local, read-only; SDK missing)**

"Can I rely on this claim, for this scope, now?" — the wedge.

Done: `scripts/sab_verify.py` (stdlib-only, sqlite `mode=ro`, receipts fallback) resolves standing_id/seed_id/claim_id/claim_hash/lease_hash; status vocab `{active, challenged, revoked, expired, unknown, rehearsal_only}`; grades independence conservatively (can never claim `cross_operator_*` because the store persists no operator identity); correctly downgrades the dogfood standing to `rehearsal_only`. 10 tests green; full suite 383 passed + 2 xfailed (`agent_5_verifier_profile.md` Tasks 4-5). Profile docs: `site/standing.md` + unserved `site/.well-known/sab-standing.json` (`served: false`). Not done: importable SDK function, scope-argument verification, served profile, remote mode.

## 3. Witness quorum + replay gate + finality + bonds — **STATUS: NOT BUILT (design complete; live defects known)**

The Independence Law (`docs/SAB_MASTER_VISION_V1.md` §6) enforced in code before any registry exists — now explicitly including the economics/finality gate above.

Current defects this build closes (all verified): independence check fails open on unknown operators and has zero endpoint callers (`agora/sab_identity.py:486-488`, `:491`); register endpoints discard `operator_backing` (`agora/sab_seeding_api.py:88-98`, `agora/app.py:1268-1275`); live self-witness accepted against a seed's own `forbidden_witnesses` (defect D2, xfail-locked); no transition matrix (`:1403-1404`); no challenge deadlines (`:606-607`); no adjudicator role checks (`:1732-1807`); API skips `provisional` (`:648-653`); register/identity contract break (defect D1). Implementation path exists as N1-N8 in `docs/SAB_STANDING_SEMANTICS_V0.md` §4 plus AdjudicationRecord/FinalityRecord/ChallengeBond (§2.3, §3). Acceptance: standing above `provisional` is mechanically unreachable until 3 independent operators exist; composted/revoked/expired states absorbing; every counted witness carries a recorded, evidence-backed `IndependenceStatus` grade; a pending challenge can no longer veto forever without a bond at risk.

## 4. Thin ingestion adapters — **STATUS: NOT BUILT**

Moltbook + GitHub in; A2A standing-profile extension authored.

External activity becomes SAB claim candidates; nothing external grants standing (firewall already enforced: `agora/sab_attestations.py:308-309`). A2A fact base: official extensions mechanism exists, no official trust extension — community proposals only (`agent_2_competitors.md` Task 3), so the SAB profile can be authored as the reference trust extension. ERC-8004 bridge posture (emit standing events as 8004 feedback/validation records) belongs here (`agent_2_competitors.md` (b)). Blocked behind build 3 by the hard gate.

## 5. Claims-scoped challenge UX — **STATUS: NOT BUILT**

Public pages for challenge/correction/standing/revocation on claims (not build objects — those are FUTURE). Requires build 3's window/deadline enforcement first, or the UX would render states the API doesn't enforce. Blocked behind build 3 by the hard gate.

## 6. Project charter — **STATUS: NOT BUILT (FUTURE tense begins here)**

`sab.project_charter.v1`: goal claim, scope, dependency claims, roles, authority leases, success criteria, rollback, expiry, review cadence. First charter: SAB building its own remaining adapters (`docs/SAB_MASTER_VISION_V1.md` §9). Acceptance: a charter cannot enter `buildable` unless its goal claim and dependencies hold active (post-build-3: genuinely earned) standing.

## 7. Work packages + dependency graph — **STATUS: NOT BUILT**

First-class `WorkPackage` + `IntegrationEdge`; first cross-agent build executes the charter from build 6. Acceptance: a project surface shows which work packages are ready, blocked by challenge, missing authority, or dependent on other work.

## 8. Artifact + operations receipts — **STATUS: NOT BUILT**

`ArtifactRecord` + `OperationsReceipt`, born behind the witness gate, never before it. Acceptance: every completed work package yields at least one artifact record with provenance, hash, acceptance evidence, and replay/inspection path.

## 9. Discourse-to-claim promotion — **STATUS: NOT BUILT**

Pointed at adapter-imported threads (build 4), not at a native feed. Acceptance: a thread promotes to a `ClaimPacket` only with provenance, proposer identity, open objections, and a visible challenge path.

## 10. Native convening surface — **STATUS: NOT BUILT; LAST, demand-gated**

Built only when real independent participation demands it — imported activity (build 4) must saturate first. Acceptance: two agents from **different operators** convene, and the surface's absence was the demonstrated bottleneck. Until then, SAB does not build a better feed.

---

## Sequencing summary

- 0-2 are the demonstrated wedge (0 done as rehearsal; 1 half-done; 2 at v0).
- 3 is the credibility build: enforcement + finality + bonds. **No public commons claim, no builds 4-5, before it lands.**
- 4-5 make the wedge public and adversarial.
- 6-8 are the FUTURE build-commons body — they earn the present tense only via a cross-operator, standing-gated build that survives challenge (`docs/SAB_MASTER_VISION_V1.md` §4).
- 9-10 import discourse before hosting it; convening is last and demand-gated.

Falsification clocks that bound this plan: no public deployment by 2026-10-03 = automatic vision revision; absorption test vs A2A/ERC-8004/GitHub shipping the full verb set (`docs/SAB_MASTER_VISION_V1.md` §11).
