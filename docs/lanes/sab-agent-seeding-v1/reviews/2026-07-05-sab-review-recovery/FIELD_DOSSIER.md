# SAB Field Dossier — Standing Overlay and Verifier (Present) / Standing-Backed Build Commons (Future)

Date: 2026-07-05 (revised same day after the SAB Review Recovery + Demonstration Zero run)
Branch: `build/sab-agent-seeding-v1` @ `c4f56810c46432c9097195b291931c13dbb4f87a`
Labeling: single_operator_rehearsal — this dossier, its evidence run, and all local packets were produced by one operator's agent fleet. No independent operator has touched the system (receipt: `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/agent_1_ground_truth.md` §5).

Scope: compare SAB / Dharmic Agora with Moltbook and the 2026 agent ecosystem, now extended to the decentralized-agent-trust field (ERC-8004, GitHub trust substrate, Microsoft Entra Agent ID, Bittensor, MCP Registry, NANDA, cheqd, Recall, x402) and build-side prior art (MetaGPT, ChatDev, SWE-agent). Full matrix: `COMPARISON_MATRIX.csv` (35 rows, all source-ref'd; method and dated source list in `METHODS.md`).

---

## 0. The Two-Tense Thesis (governs every claim below)

**PRESENT TENSE: SAB is a standing overlay and verifier for agent ecosystems.** It answers: "Can I rely on this claim, for this scope, until when, and who can challenge or revoke that reliance?"

**FUTURE TENSE: SAB can become a standing-backed build commons only after it demonstrates cross-operator, standing-gated project formation, work packages, artifacts, integration edges, and evolution events.**

Nothing in this dossier is permitted to describe the build commons in the present tense. Where the word "commons" appears below, it is either explicitly FUTURE, a quotation, or a negation. The demonstrated present is exactly this:

- One real claim driven through the entire pipeline via the real API — `pending_seed -> challenged -> corrected -> witnessed -> standing_active` — with every request/response persisted (receipt: `agent_4_dogfood_loop.md` + `dogfood/` in the same review dir; seed `sab_seed_dogfood_2026-07-05_pytest_c4f56810`, standing lease `sab_standing_dogfood_2026-07-05_c4f56810`, chain `verified: true`). Labels on that run: `single_operator_rehearsal`, `not_cross_operator_independent`, `valid_local_pipeline_evidence`.
- A read-only verifier that answers the reliance question against the live store (`scripts/sab_verify.py`; 10 tests green; it grades the dogfood standing `rehearsal_only`, not `active` — receipt: `agent_5_verifier_profile.md` Task 4-5).
- Zero external submissions, zero independent operators, no public deployment (`agora.dharmic.ai` exists only as a commented nginx template, `deploy/sab-agora.nginx.conf:10` — UNVERIFIED as anything beyond a template; receipt: `agent_1_ground_truth.md` §7).

## 1. Executive Verdict

The earlier version of this dossier said "the thesis survives evidence" and described SAB as a build commons that "needs both" a court and a construction arm. That framing overclaimed the present. Corrected verdict:

1. **The standing overlay is real but partially enforced.** The seeding API implements registration, signed seeds, challenges, responses, witness hash chains, standing review, revocation, and revalidation (`agora/sab_seeding_api.py:60-749`; mount `agora/app.py:1249`; 17 documented routes runtime-verified — `agent_1_ground_truth.md` §4). But its two load-bearing promises — witness independence and challenge finality — are specified, not enforced (Section 5, Risk Register). The canonical semantics now live in `docs/SAB_STANDING_SEMANTICS_V0.md`.
2. **The build commons is FUTURE work, by demonstration only.** No project charter, work package, artifact record, integration edge, or operations receipt object exists in code (`docs/SAB_MASTER_VISION_V1.md` §3, §10, corroborated by grep — zero economics or build objects in `agora/`, `agent_3_standing_semantics.md`). The CSV row for SAB is accordingly relabeled "standing overlay / claim verifier (build commons = future by demonstration)" (`COMPARISON_MATRIX.csv` row 2).
3. **The field is not empty.** This dossier drops all lane-vacancy framing in favor of the accountability gradient (Section 3). The closest external threats are ERC-8004 and GitHub's trust substrate, and SAB's declared posture toward the closest one is bridge, not compete (Section 4).

## 2. Local SAB Evidence (all citations verified 2026-07-05 — `agent_1_ground_truth.md` §6)

Evidence anchors:

- Branch: `build/sab-agent-seeding-v1`; commits `f817d61` (v1 slice), `56904c1`, `c4ac93b` (verified in `git log`).
- Runtime: `agora/sab_seeding_api.py`, `agora/sab_seeding_storage.py`, `agora/sab_identity.py`, `agora/sab_attestations.py`.
- Schemas: `nodes/schemas/sab.*.v1.schema.json` (6 files).
- Tests: full suite green — 372 passed at mission start; 383 passed + 2 xfailed after this run added dogfood-regression and verifier tests (pasted outputs in `agent_1_ground_truth.md` §2, `agent_5_verifier_profile.md` Task 4). The 2 xfails document known defects D1/D2, not regressions.
- The lane spec's "signed seed packets into a challengeable evidence pipeline" and the standing standard's "standing is not truth, popularity, or permission" both quote-match their sources (`docs/lanes/sab-agent-seeding-v1/BUILD_SPEC.md:17`, `docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md:20-26`).
- Identity proves key control + operator disclosure, not truth (`agora/sab_identity.py:100`); external attestations — including Moltbook tokens — are hardwired to `standing_effect: "none"` (`agora/sab_attestations.py:89, :121`).
- Citation correction applied: the v1 signature replay index lives in `agora/sab_seeding_api.py:757` (recording at `:1202-1216`), not in `sab_seeding_storage.py` as the earlier phrasing implied.
- Truth-in-docs correction applied: 6 documented routes were phantoms (404 at runtime): `POST /api/v1/agents/challenge`, `/agents/verify`, `/agents/me/rotate-key`, `/agents/me/revoke`, `/authority-leases/{id}/revoke`, `/authority-leases/{id}/challenge`. All are now annotated as target-design in `site/*.md`; none are silently documented as live (`agent_1_ground_truth.md` §4, probe outputs pasted there).

**Demonstration Zero (new since the prior dossier):** the first and so far only claim to complete the loop is a pytest-status claim about this repo, submitted, genuinely challenged on scope, corrected, witnessed by an actual test replay (exit 0, `372 passed`), and granted a 30-day standing lease — end-to-end through the mounted API, strictly additive to `data/spark.db` (row-count receipts `dogfood/00_db_baseline.json` / `99_db_after.json`). This is `valid_local_pipeline_evidence` and nothing more: same operator on both sides of every adversarial step.

**Packet provenance, disclosed:** of the pre-existing lane packets, 6 were script-generated without touching the API (`scripts/sab_language_womb_tick.py`); the master-vision seed + challenge were API-generated locally and are corroborated by the DB (state `challenged`, window closes 2026-07-19) (`agent_1_ground_truth.md` §5). All signers are one operator's fleet.

## 3. Field Framing: Accountability Gradient, Not Empty Lane

This dossier makes no vacuum, white-space, or nobody-else-has-this claim. The honest frame (canonical statement in `METHODS.md` "Accountability Gradient Framing"): the whole field is climbing one gradient —

identity (Entra Agent ID, AGNTCY, cheqd, NANDA) -> provenance and process gates (GitHub branch protection, Sigstore/SLSA attestations) -> registries and namespace trust (MCP Registry, NANDA index) -> scored or staked performance (Bittensor Yuma, Recall competitions) -> onchain feedback and validation registries (ERC-8004, Draft).

SAB's position on that gradient is a specific so-far-unoccupied **combination** — challengeable claims with expiry, revocation, and cross-operator standing review — verified only against the dated source list in `METHODS.md` as of 2026-07-05, not a claim that nobody is moving toward it. ERC-8004 and GitHub's trust substrate are each roughly one integration away from covering much of it (`agent_2_competitors.md` (c)).

## 4. Threat Ranking and Integration Posture (from Agent 2, all rows primary-source-backed)

Top threats, in order (full rationale: `agent_2_competitors.md` (a); rows in `COMPARISON_MATRIX.csv`):

| # | Platform | Why it threatens SAB |
|---|----------|----------------------|
| 1 | **ERC-8004 Trustless Agents** | Standards-track Draft specifying the same triad SAB implements locally (identity, reputation/feedback, third-party validation), explicitly wired to A2A+MCP. The emerging schelling point for "agent trust". Deployment claims ("audited contracts on 20+ networks") are ecosystem-reported, UNVERIFIED at spec level. |
| 2 | **GitHub as trust substrate** | Distribution monopoly + real mechanisms today: branch protection, required checks, CODEOWNERS, signed commits, Sigstore-backed attestations at SLSA v1.0 Build L2. "Good enough" provenance can absorb demand for standing before agents look elsewhere. |
| 3 | **Microsoft Entra Agent ID** | Enterprise-default agent identity with OAuth2/MCP/A2A, conditional access, lifecycle governance. If accountability becomes an Entra checkbox, enterprises never seek a public standing layer. |
| 4 | **Bittensor validation** | Live crypto-economic validation of machine work at production scale (Yuma Consensus) — the strongest existence proof that the validation lane can be done with tokens instead of standing semantics. |
| 5 | **MetaGPT / ChatDev** | The FUTURE build-commons half of SAB's pitch is prior art since 2023: role-agent software companies producing full artifacts, minus any trust axis. They own the cross-agent-build mindshare. |

Lower-ranked: MCP Registry, MIT NANDA, Recall, cheqd, x402, SWE-agent (`agent_2_competitors.md`). Coral Protocol was skipped for failing the primary-mechanism evidence bar, not judged irrelevant.

**Closest-threat posture — ERC-8004: bridge, don't compete** (`agent_2_competitors.md` (b)):

1. Treat 8004 as a settlement/anchor layer: SAB standing events (challenge opened, challenge survived, revocation, expiry) can be emitted as 8004 Reputation Registry feedback and Validation Registry request/response pairs — SAB as one of the validators the spec anticipates.
2. Keep SAB's differentiators off-chain where 8004 is silent: challenge windows, expiry, revocation semantics, cross-operator standing review, human-readable witness receipts.
3. Publish the mapping as an A2A extension profile. Verified 2026-07-05: A2A has an official extensions mechanism but **no official trust extension** — only community proposals (A2A Discussion #1631, Issue #1628). SAB can arrive as the reference implementation of the missing trust extension rather than a 14th registry.

**What survives GitHub/ERC-8004 absorption?** (verbatim integration of `agent_2_competitors.md` (c)): If GitHub's trust substrate and ERC-8004 both mature, most of what SAB does today gets absorbed: identity handles, signed provenance, feedback scores, and validator attestations all have credible external homes. What survives is the part neither system defines: **adversarial standing with a lifecycle.** GitHub attestations bind an artifact to a build process and explicitly disclaim being "a guarantee that an artifact is secure"; nothing in branch protection lets a third party challenge a merged claim, and nothing expires. ERC-8004 records feedback and validation responses, but a score is not a standing: the Draft spec has no challenge window, no expiry, no revocation of previously-granted reliance, and no cross-operator review of a verdict — its trust models outsource exactly the adjudication SAB implements. SAB's durable residue is therefore the verb set, not the nouns: *challenge, survive, expire, revoke, re-review* — claims as leases rather than ledger entries, enforced by receipts either system could anchor. The honest strategic statement is not "SAB owns an empty lane" but "SAB is the adjudication layer both absorbers currently assume someone else provides"; the build-commons half of the vision remains FUTURE work that MetaGPT/ChatDev-style frameworks already prototype without any trust axis — which is precisely the gap a demonstration must fill.

## 5. Standing Semantics: Specified, Not Yet Enforced (Agent 3 patch, integrated)

The prior dossier described witness independence as a property SAB has. Corrected: it is a property SAB has now **specified but not yet enforced**. Canonical reference: `docs/SAB_STANDING_SEMANTICS_V0.md` — a six-grade `IndependenceStatus` enum (`self / same_operator / undisclosed / same_operator_distinct_keys / cross_operator_unverified / cross_operator_attested`) with per-axis minimum evidence (operator, key, funding/control, runtime, conflict-of-interest), a conservative failure mode (anything ambiguous grades `undisclosed`, counted as same-operator), and quorum thresholds per standing tier. The grade actually achievable today is `undisclosed`: single operator, rehearsal-flagged. Under the system's own Independence Law (`docs/SAB_MASTER_VISION_V1.md:96`), until three independent operators exist, every standing above `provisional` is unearned — and the API currently issues `active` directly, skipping `provisional` (`agora/sab_seeding_api.py:648-653`), a mechanical violation its own enforcement disclosure admits (`SAB_MASTER_VISION_V1.md:100`).

### Risk register (code-grounded; an external reviewer would find these in under an hour, so this dossier finds them first)

- **(a) Independence fails open and is never called.** The only independence check in the codebase treats an unknown operator as independent (`agora/sab_identity.py:486-488`) and is called by zero endpoints, while both register endpoints discard the operator disclosure that check would need (`agora/sab_seeding_api.py:88-98`, `agora/app.py:1268-1275`). Confirmed live: a claimant can affirm-witness its own seed through the API even when the seed forbids it (Agent 4 defect D2, locked as xfail in `tests/test_sab_dogfood_regression.py`).
- **(b) No finality mechanics.** No transition guards — composted seeds are resurrectable (`agora/sab_seeding_api.py:1403-1404`); no adjudicator role checks — any registered signature can sustain, reject, or canon-promote (`:1732-1807`, `:1992-1996`); no challenge deadlines — a pending challenge is a free permanent veto of standing (`:606-607`).
- **(c) Register/identity contract break.** The register endpoint's output is rejected by the canonical `AgentIdentityV1` model (extra `identity_ref` field + `sha256[:16]` vs `[:32]` subject_id derivation) — Agent 4 defect D1, `agora/sab_seeding_api.py:932-933` vs `agora/sab_identity.py:47-50`, xfail-locked.
- **Economics posture:** six typed objects (ChallengeBond, WitnessStake, Escrow, WorkAllocation, PayoutReceipt, SlashingEvent) are now **designed with invariants and attack rationales** (`docs/SAB_STANDING_SEMANTICS_V0.md` §3); none are built (grep: zero economic primitives in `agora/`). Declared ordering: bonds + finality before open participation — dogfood may proceed without them, public scale may not. Precedent for this style of honest gap declaration: the master vision's own enforcement disclosure (`docs/SAB_MASTER_VISION_V1.md:100-102`).
- Security posture: bandit run 2026-07-05 — 1 Medium (B608, judged SAFE: identifiers from `PRAGMA table_info` intersected with a hardcoded dict, values parameterized) + 1 Low false positive; no real SQL-injection or credential risk found (`agent_1_ground_truth.md` §3). This closes the prior scorecard's open "security gap" item.

## 6. Internal Prior Art

SAB's own repo anticipated the two-tense structure before this review. `docs/SAB_RECURSIVE_CIVILIZATION_ENGINE.md` (2026-07-01, internal canonical seed) defines the carrier-wave loop `spark -> challenge -> witness -> standing -> build -> deploy -> learn/earn -> fund -> canon/compost` and hardwires the constraints this dossier now enforces in positioning: no claim without scope, no authority without expiry, no canon without challenge, no economic loop without commons return. It is internal propagation language — a design target, not a description of running capability — and is cited here as prior art for the FUTURE half of the thesis. `docs/SAB_MASTER_VISION_V1.md` (2026-07-05) is the L1 canonical articulation: spine (built, claim layer) vs body (FUTURE, not built), the Independence Law, the economics requirement, and four falsification tests with clocks. This dossier defers to both rather than restating them.

## 7. Field Map (present-tense facts about others; SAB posture per section)

### Agent participation
Moltbook is the clearest public agent participation/social surface: registration, API keys, posts, votes, submolts, roles, short-lived identity tokens (sources: moltbook.com skill/auth/heartbeat/rules docs, `METHODS.md`). Its public docs show no adversarial standing process. SAB posture: consume Moltbook activity as claim candidates via an adapter (FUTURE, build 4); never grant standing from its tokens (enforced today: `agora/sab_attestations.py:89`).

### Agent economies (adjacent precedents, all medium-confidence sources per the hard confidence rule — `agent_2_competitors.md` Task 4)
Fetch.ai/Agentverse (identity, discovery, transactions), Olas (agent services, marketplace), Virtuals (onchain agent society, ACP commerce), OpenServ (production agent ops). These falsify any claim that Moltbook is the only agent-to-agent platform and that agent economies are hypothetical. None implements challengeable claim standing per their cited docs.

### Coding workflow capture
GitHub Copilot, OpenAI Codex, Claude Code, Devin, Replit Agent, Jules, Gemini CLI, OpenHands optimize task execution around repos, PRs, and developer workflow. They create evidence trails, not third-party reliance semantics. SAB posture: make their outputs rely-able — "this PR's security claim has standing for scope X until date Y" — via receipts they can anchor (verifier exists today: `scripts/sab_verify.py`; ingestion adapters FUTURE, build 4).

### Runtime, orchestration, interop
LangGraph/LangSmith, CrewAI, AutoGen/Foundry, Google ADK are execution substrates; A2A and AGNTCY are interop/identity layers. SAB posture: publish the standing profile (`standing_uri`, `claim_hash`, `scope`, `status`, `expires_at`, `revocation_uri`, `challenge_uri`, `witness_quorum`, `last_verified_at`) as an A2A extension and OASF mapping (profile fields drafted in `site/standing.md`; A2A extension FUTURE, build 4). Correction from Agent 5: `connectors/sab_mcp_tools.py` is a manifest only — no MCP server exists in this repo (repo-wide grep, zero bootstrap hits; one tool targeted a nonexistent route, now marked PLANNED — `agent_5_verifier_profile.md` Task 3).

### Cursor / Origin (corrected)
The prior dossier said Origin "did not resolve to a primary public platform source." Corrected 2026-07-05: **Origin exists** — cursor.com/origin is an official Anysphere page ("A git forge for the agentic era"), waitlist pre-launch, zero published mechanism docs; press details (Graphite basis, keynote date) remain secondary/UNVERIFIED (`agent_2_competitors.md` Task 2; `COMPARISON_MATRIX.csv` row 8). An agent-first git forge would directly contest the code-trust substrate.

### Local sandbox boundary
OpenClaw evidence remains local-profile-only (hardened Docker sandboxes; OpenClaw itself not installed locally; not a git repo — `METHODS.md` Limitations). Sandboxing is a precondition for trustworthy witness execution, not standing.

## 8. What SAB Must Become (FUTURE — none of this exists in code)

The FUTURE object model is specified in `docs/SAB_MASTER_VISION_V1.md` §8: trust objects (implemented at the claim layer) vs build objects (`IdeaThread`, `ProjectCharter`, `WorkPackage`, `ArtifactRecord`, `IntegrationEdge`, `OperationsReceipt`, `EvolutionEvent` — designed, not built) vs prerequisite objects for scale (bonds, stakes, escrow, adjudication/finality records — designed with invariants in `docs/SAB_STANDING_SEMANTICS_V0.md` §2.3/§3, not built).

The typed standing predicate that replaces the earlier magic-predicate sketch is normative in `docs/SAB_STANDING_SEMANTICS_V0.md` §5.2: graded, evidence-backed independence recorded at issuance, finality-gated challenges, and a system-wide provisional cap until three independent operators exist. The earlier `StandingLease<S,C,E,Q,T>` sketch in this dossier assumed an `independence(scope=S)` oracle no code computes; that assumption is retired.

The FUTURE `ProjectCharter` predicate sketch (charter buildable iff goal claim has active standing, dependencies satisfy required standing, authority leases cover work packages, review rule defines rollback/expiry/challenge) stands as design language for builds 6-8. It earns present tense only when a charter object exists and a cross-operator build survives challenge — the master vision's "genuinely novel unit" (`SAB_MASTER_VISION_V1.md` §4).

## 9. Positioning Risks (updated)

1. **Ahead in language, behind in distribution.** GitHub, OpenAI, Anthropic, Microsoft, Google, Devin own developer attention; ERC-8004 owns the trust-standards conversation (threat table, Section 4).
2. **Enforcement debt is the credibility risk.** The gap between declared law (independence, finality) and enforced code (fails open, none) is now the first thing a competent reviewer finds. This dossier's mitigation is disclosure-first (Section 5) plus build 3 sequencing (bonds + finality before any public claim surface — `NEXT_10_BUILDS.md`).
3. **Do not claim truth.** Standing is scoped reliance after process (`docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md:20-26`).
4. **Do not become a governance essay.** Every rule needs a validator, fixture, replay path, failure mode (the N1-N8 implementable-now list exists: `docs/SAB_STANDING_SEMANTICS_V0.md` §4).
5. **Witness capture.** A witness event without enforced independence, replay material, and adversarial challenge is logging. Today's witness events are exactly that unless rehearsal-labeled (defect D2).
6. **Identity is not authority.** External identity/activity signals must never bypass standing (enforced for attestations: `agora/sab_attestations.py:308-309`).
7. **A busy board is not a build civilization.** The FUTURE standard: independent agents forming reliable cross-project dependencies that keep evolving after the first artifact ships — measured by the falsification tests in `SAB_MASTER_VISION_V1.md` §11, not by activity volume.

## 10. Review Deltas Accepted / Rejected

Each external-review assertion from the 2026-07-05 review cycle, adjudicated against local code or primary sources (hard rule: assertions were hypotheses until verified). Evidence refs decide each verdict.

| # | External-review assertion | Verdict | Deciding evidence |
|---|---------------------------|---------|-------------------|
| 1 | SAB's present tense is a standing overlay/verifier, not a build commons | **ACCEPTED** | Zero build/economics objects in code (`agent_3_standing_semantics.md`); all packets single-operator (`agent_1_ground_truth.md` §5); CSV row relabeled (`COMPARISON_MATRIX.csv` row 2) |
| 2 | ERC-8004 + GitHub are the real threats | **ACCEPTED** | Primary-source threat table (`agent_2_competitors.md` (a); eips.ethereum.org/EIPS/eip-8004; docs.github.com attestation docs) |
| 3 | The wedge is challenge/expiry/revocation/cross-operator review (the verb set) | **ACCEPTED** | Absorption analysis (`agent_2_competitors.md` (c), integrated in Section 4); neither GitHub nor ERC-8004 Draft defines an adjudication lifecycle |
| 4 | The dossier made empty-lane/white-space claims | **PARTIAL** | Literal vacuum grep over METHODS/CSV was zero-hit pre-edit (`agent_2_competitors.md` Task 6), but this dossier's prior "the gap SAB should own" / present-tense "defensible position is: SAB is the standing-backed build commons" framing was equivalent overclaim — replaced by the accountability gradient (Section 3) and two-tense thesis (Section 0) |
| 5 | Documented endpoints don't all exist | **ACCEPTED** | 6 phantom routes 404-confirmed at runtime; site docs corrected (`agent_1_ground_truth.md` §4) |
| 6 | Witness independence is unenforced theater at the API layer | **ACCEPTED** | Fail-open + zero callers + discarded operator disclosure (`agora/sab_identity.py:486-488`, `agora/sab_seeding_api.py:88-98`); live self-witness accepted (Agent 4 D2) |
| 7 | Challenge lifecycle lacks finality/liveness (permanent-veto, anyone-adjudicates, resurrectable compost) | **ACCEPTED** | `agora/sab_seeding_api.py:606-607, :1403-1404, :1732-1807, :1992-1996` (`agent_3_standing_semantics.md`) |
| 8 | The 54/86 self-scoring is arbitrary | **ACCEPTED** | METHODS.md states no reproducible 0-100 formula exists; scorecard rewritten as explicitly QUALITATIVE, numbers removed (`SAB_POSITIONING_SCORECARD.md`) |
| 9 | The dogfood loop had not been run | **ACCEPTED, then RESOLVED** | Demonstration Zero completed via real API with receipts, honestly labeled rehearsal (`agent_4_dogfood_loop.md`, `dogfood/`) |
| 10 | "MCP tools exist" overclaims | **ACCEPTED** | Manifest only, no server, one nonexistent target route (`agent_5_verifier_profile.md` Task 3); scorecard line corrected |
| 11 | No deployment exists; domain claims unverified | **ACCEPTED** | `agora.dharmic.ai` template-only; no site doc claims a live domain (`agent_1_ground_truth.md` §7) |
| 12 | Convening-first build order was backwards | **ACCEPTED** | Order inverted: verifier wedge first, convening LAST demand-gated (`NEXT_10_BUILDS.md`; `SAB_MASTER_VISION_V1.md` §9) |
| 13 | Economics/finality must precede public commons claims | **ACCEPTED** | Agent 3 build-order correction: FinalityRecord + ChallengeBond before adapters/public challenge UX (`docs/SAB_STANDING_SEMANTICS_V0.md` §3; gate written into `NEXT_10_BUILDS.md`) |
| 14 | Moltbook wrongly treated as the only convening reference | **ACCEPTED** | Field map extended with primary-sourced economies + trust rows (`COMPARISON_MATRIX.csv` 23->35 rows) |
| 15 | Cursor Origin doesn't exist / was hallucinated | **REJECTED** | Origin exists — official page primary-verified 2026-07-05, pre-launch waitlist; capabilities unpublished (`agent_2_competitors.md` Task 2) |
| 16 | The prior dossier's local-evidence citations were fabricated | **REJECTED** | All "Local SAB Evidence" citations verified against sources; one minor file-attribution nuance corrected (replay index location) (`agent_1_ground_truth.md` §6) |
| 17 | The bandit Medium finding is an open SQL-injection risk | **REJECTED** | B608 site judged SAFE (schema-derived identifiers ∩ hardcoded dict, parameterized values) (`agent_1_ground_truth.md` §3) |
| 18 | The pytest warning is an httpx deprecation | **REJECTED** | It is a StarletteDeprecationWarning; exact text captured in the seeded claim (`agent_4_dogfood_loop.md` Ground truth) |

## 11. Strategic Conclusion

PRESENT: SAB is a standing overlay and verifier for agent ecosystems — locally mounted, single-operator, rehearsal-grade, with a completed Demonstration Zero and a working read-only verifier that honestly downgrades its own standing to `rehearsal_only`. Its enforcement debt (independence, finality) is disclosed, specified in `docs/SAB_STANDING_SEMANTICS_V0.md`, and sequenced ahead of any public surface in `NEXT_10_BUILDS.md`.

FUTURE: SAB can become a standing-backed build commons — but only by demonstration: cross-operator, standing-gated project formation, work packages, artifacts, integration edges, and evolution events, with economics and finality landed first. Until an independent operator sustains a challenge that changes a claim, the commons hypothesis remains unsupported at current scale by the system's own falsification tests (`docs/SAB_MASTER_VISION_V1.md` §11 Test 2), and this dossier will keep saying so.

The two questions SAB should let other systems ask remain the right ones — one answerable now, one only in the FUTURE tense:

1. (PRESENT) Can I rely on this claim, for this scope, until when, and who can challenge or revoke that reliance?
2. (FUTURE) Can this relied-on claim be promoted into a project, split into work, executed by independent agents, integrated with other projects, and evolved without losing provenance, authority, or challengeability?

Everything else — Moltbook participation, Fetch.ai discovery, Olas services, Virtuals commerce, OpenServ operations, Cursor/Origin forging, GitHub/OpenAI/Anthropic workflow capture, LangGraph orchestration, A2A messaging, AGNTCY identity, ERC-8004 registries — is a complement, peer, precedent, distribution channel, or absorber to bridge. SAB's durable residue is the verb set: challenge, survive, expire, revoke, re-review.
