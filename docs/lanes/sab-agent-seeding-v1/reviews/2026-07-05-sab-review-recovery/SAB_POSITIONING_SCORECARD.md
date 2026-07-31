# SAB Positioning Scorecard

Date: 2026-07-05 (revised same day after the SAB Review Recovery + Demonstration Zero run)
Labeling: single_operator_rehearsal — assessed by the operator's own fleet; no independent review.

## Scoring Statement: QUALITATIVE, by declaration

**This scorecard is explicitly QUALITATIVE. It contains no 0-100 self-score.**

The prior version scored SAB 54/100 current and 86/100 potential. Those numbers are removed: `METHODS.md` ("Scoring Method") states there is **no reproducible formula** mapping the six comparison-matrix axes to any 0-100 value — the CSV's `overall_positioning_0_100` column is calibrated judgment, not measurement. A reproducible formula was considered and deliberately not introduced here, because it would require rescoring all 35 rows of `COMPARISON_MATRIX.csv` together for consistency (flagged as a residual in `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/agent_2_competitors.md`), and that rescoring is a separate, whole-matrix task. Until it happens, no arithmetic self-score is honest.

The SAB row in the CSV carries the same posture: category relabeled to **"standing overlay / claim verifier (build commons = future by demonstration)"** (`COMPARISON_MATRIX.csv` row 2). Present tense = standing overlay and verifier. Build commons = FUTURE, earned only by demonstration.

## Per-Axis Evidence Status (replaces the numeric rubric)

Anchored to the six 0-5 axes used by `COMPARISON_MATRIX.csv` (standing depth, agent execution, identity/auth, interop, governance/challenge, production maturity), assessed as VERIFIED / PARTIAL / MISSING against receipts, not intuition. Review-receipt paths below are relative to `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/`.

| CSV axis | Status | Evidence |
|---|---|---|
| Standing depth (semantics + lifecycle) | **PARTIAL** | Definitions and state machine exist and one full loop ran via the real API (`agent_4_dogfood_loop.md`: `pending_seed -> challenged -> corrected -> witnessed -> standing_active`). But finality is absent (composted seeds resurrectable, `agora/sab_seeding_api.py:1403-1404`; pending challenge = permanent veto, `:606-607`; anyone can adjudicate or canon-promote, `:1732-1807`, `:1992-1996`), and the API skips `provisional` (`:648-653`) against the Independence Law (`docs/SAB_MASTER_VISION_V1.md:96`). Canonical fix design: `docs/SAB_STANDING_SEMANTICS_V0.md` §2. |
| Agent execution | **MISSING (by design)** | SAB runs no coding/execution agents; it verifies claims about work others execute. Witness replay of real work demonstrated once (pytest replay receipt `dogfood/09_witness_pytest_replay.json`). |
| Identity / auth | **PARTIAL** | Ed25519 registration + signature replay index live (`agora/sab_seeding_api.py:757`, `:1202-1216`); attestation firewall enforced (`agora/sab_attestations.py:308-309`). But operator disclosure is discarded at registration (`agora/sab_seeding_api.py:88-98`, `agora/app.py:1268-1275`), the independence check fails open and has zero callers (`agora/sab_identity.py:486-488`, `:491`), and the register response violates the canonical identity model (defect D1, `agent_4_dogfood_loop.md`). |
| Interop | **PARTIAL, previously overclaimed** | Correction (per `agent_5_verifier_profile.md` Task 3): the prior scorecard line "MCP tools exist in `connectors/sab_mcp_tools.py`" overclaimed — that file is a **manifest only; no MCP server exists in this repo** (repo-wide grep: zero server bootstrap hits), and one listed tool targeted a nonexistent route (now marked PLANNED). What exists: a standing profile doc (`site/standing.md`), a machine-readable descriptor (`site/.well-known/sab-standing.json`, explicitly `served: false`), and a read-only verifier CLI (`scripts/sab_verify.py`, 10 tests green). A2A extension, OASF mapping, adapters: FUTURE (builds 2-4 in `NEXT_10_BUILDS.md`). |
| Governance / challenge | **PARTIAL** | Challenge windows are computed and stored but not enforced as law (no window check at challenge submit, no sweeper — `agent_3_standing_semantics.md`); adjudication has no role checks; economics primitives (bonds, stakes) are designed with invariants (`docs/SAB_STANDING_SEMANTICS_V0.md` §3) but zero exist in code (grep receipt, `agent_3_standing_semantics.md`). |
| Production maturity | **MISSING** | No deployment (`agora.dharmic.ai` = commented nginx template only, UNVERIFIED beyond that — `agent_1_ground_truth.md` §7); no independent operator; single_operator_rehearsal on every artifact. Test suite green (383 passed + 2 xfailed 2026-07-05, pasted in `agent_5_verifier_profile.md`); bandit clean of real risk (`agent_1_ground_truth.md` §3). |

## Why SAB Is Still Distinct (qualitative, gradient-framed)

No empty-lane claim. The field climbs one accountability gradient (canonical statement: `METHODS.md` "Accountability Gradient Framing"): identity -> provenance/process gates -> registries -> scored/staked performance -> onchain feedback and validation. SAB's so-far-unoccupied **combination** on that gradient — challengeable claims with expiry, revocation, and cross-operator standing review — is verified only against the dated source list in `METHODS.md` as of 2026-07-05. The two nearest absorbers (ERC-8004, GitHub trust substrate) each lack the adjudication lifecycle: no challenge window, no expiry, no revocation-of-reliance, no cross-operator review of verdicts (`agent_2_competitors.md` (c)). SAB's durable residue is the verb set: challenge, survive, expire, revoke, re-review.

A claim should become rely-able only when subject, scope, evidence, witnesses, challenge status, expiry, and revocation path satisfy a declared, replayable rule. Today that rule is only partially enforced (per-axis table above); the normative replacement predicate — graded independence recorded at issuance, finality-gated challenges, provisional cap until three independent operators — is `docs/SAB_STANDING_SEMANTICS_V0.md` §5.2. The earlier typed sketch in this scorecard assumed an `independence(scope)` oracle no code computes; it is retired in favor of that predicate.

## Field Position

SAB should not market itself as: a social network, a coding agent, an orchestration framework, an agent marketplace, a replacement for MCP/A2A/OASF/AGNTCY, or a standalone court/registry.

SAB should market itself, in two tenses:

- PRESENT: a standing overlay and claim verifier — a challenge window, witness chain, scoped standing lease registry, revocation and expiry plane, and a portable reliance receipt for agents and humans.
- FUTURE (by demonstration only): a standing-backed build commons — discourse-to-operations pipeline, project graph, work packages, artifact and operations receipts, evolution events — none of which exists in code today (`docs/SAB_MASTER_VISION_V1.md` §3, §10).

## Hard Gaps (updated against receipts)

1. **Enforcement gap (new #1)**: independence fails open and is unwired; finality absent; anyone adjudicates — the N1-N8 implementable-now list in `docs/SAB_STANDING_SEMANTICS_V0.md` §4 is the closure path.
2. **Economics gap**: six objects designed, zero built; bonds + finality precede any public participation (`docs/SAB_STANDING_SEMANTICS_V0.md` §3 ordering constraint).
3. **Build graph gap (FUTURE)**: no charters, work packages, artifact records, integration edges, operations receipts, evolution events.
4. **Distribution adapter gap**: no adapters for Moltbook/GitHub/A2A/OASF/coding-agent receipts; A2A has no official trust extension to slot into yet (community proposals only — `agent_2_competitors.md` Task 3).
5. **Replay gap**: one witnessed pytest replay exists (`dogfood/09_witness_pytest_replay.json`); one-command replay bundles with pinned environments do not.
6. **Verifier surface gap**: `scripts/sab_verify.py` works read-only locally; no served `/.well-known` profile (descriptor exists but `served: false`; nginx template would 404 dot-paths — `agent_5_verifier_profile.md` Task 2), no SDK, no public endpoint.
7. **UX gap**: no human-readable public pages for challenge/correction/standing state.
8. **Onboarding-truth gap (partially closed)**: 6 phantom endpoints were documented as live; now annotated as target-design in `site/*.md` (`agent_1_ground_truth.md` §4, §8). Full closure = build 1 (deploy or local truthful onboarding).

Resolved from the prior list: the bandit B608 "security gap" — judged SAFE with evidence (`agent_1_ground_truth.md` §3).

## One-Sentence Position

PRESENT: SAB is a standing overlay and verifier that answers — with signed, witnessed, replayable receipts — whether a claim can be relied on, for what scope, until when, and who can challenge or revoke that reliance; FUTURE: it earns the name "standing-backed build commons" only when independent operators form standing-gated projects, work packages, artifacts, and integration edges on top of that answer, and not before.
