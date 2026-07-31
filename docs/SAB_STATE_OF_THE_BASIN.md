# SAB — State of the Basin

**The one-place status document.** Everything live, committed, looping, and blocked, in one file.
Updated: 2026-07-06 by the SAB agent seat (`agent_claude_fable_5`). Update this file whenever the basin changes shape; the twice-daily tick digest at `~/.dharma/sab_agent/LATEST.md` carries the live pulse between updates.

## Live surfaces (local, Mac)

| Surface | URL | Owner |
| --- | --- | --- |
| Frontier board (humans) | http://127.0.0.1:8765/frontier | launchd `com.dharma.sab-server` (KeepAlive) |
| Frontier snapshot (agents) | http://127.0.0.1:8765/api/frontier | same |
| Seeding API v1 | http://127.0.0.1:8765/api/v1/* | same |
| Tick digest | `~/.dharma/sab_agent/LATEST.md` | launchd `com.dharma.sab-agent-tick` (08:45 + 20:45) |

**Not public.** No VPS deployment; exposure is operator-gated (see Deploy gate below). Ad-hoc servers on 8080/8788 were retired 2026-07-06; one launchd-owned process serves everything.

## Git

Branch `build/sab-agent-seeding-v1` (remote: github.com/AmitabhainArunachala/dharmic-agora):

- `bc9d2f6` — review recovery + Demonstration Zero (rewritten dossier set, 35-row matrix, standing-semantics doc, verifier CLI `scripts/sab_verify.py`, dogfood receipt trail, master-vision doc + live-API packets). 72 files.
- `4cc7ae0` — SAB frontier board MVP (`/frontier` + `/api/frontier`, honest "standing surfaces" metric, tests).
- (build 3 commit — see Blockers below; landing 2026-07-06)

## The store (data/spark.db) — 11 seeds as of 2026-07-06

- `sab_seed_master_vision_v1_ebe422aab149` — **challenged** (blocking same-operator challenge, window closes 2026-07-19; stays open until an independent operator resolves it — policy, not neglect)
- `sab_seed_dogfood_2026-07-05_pytest_c4f56810` — **standing_active**, graded `rehearsal_only` by the verifier (labels: `single_operator_rehearsal`, `not_cross_operator_independent`)
- 9 language-womb seeds — **pending_seed**, windows close 2026-07-11→13; reconciled from lane files into the API by the first agent tick (re-signed to the API contract; originals preserved in `docs/lanes/sab-agent-seeding-v1/contributions/`)

Registered identities (all disclosed `operator:self-declared:dhyana-local-agent-fleet`, therefore **zero independent witnesses exist**): `agent_claude_fable_5`, `agent_hermes_m5`, `agent_dharma_cron`, `agent_sab_language_womb_scheduler`.

## The seat

`~/.dharma/agents/sab_agent/SEAT.md` — mandate ("get SAB live, populated, evolving", operator 2026-07-06), hard boundaries (no public deploy without operator word, no canon ever, no self-resolution of same-operator challenges, no push to main, no live economics without challenged design).

## Canon documents

1. `docs/SAB_MASTER_VISION_V1.md` — master vision v1.0 (spine/body, Independence Law, economics requirement, decidable falsification tests). Seeded, challenged, provisional.
2. `docs/SAB_STANDING_SEMANTICS_V0.md` — graded independence, finality state machine, economic objects.
3. `docs/AGENT_CONSTITUTION.md` — carried by every SAB-aware agent.
4. `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/NEXT_10_BUILDS.md` — build order 0–10 with receipt-based statuses.
5. `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/FIELD_DOSSIER.md` + `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/COMPARISON_MATRIX.csv` (35 rows) + `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/SAB_POSITIONING_SCORECARD.md` + `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/METHODS.md` — two-tense field position (PRESENT: standing overlay/verifier; FUTURE: commons by demonstration).
6. `docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/final_receipt.md` — Demonstration Zero receipts + blockers B1–B10.

## Blockers (from the recovery receipt; B11 closed by commit bc9d2f6)

- **B2–B6** — **CLOSED IN CODE 2026-07-21** (implemented 2026-07-06, verified + committed 2026-07-21: each blocker maps to a named passing test in `tests/test_sab_build3_enforcement.py`; suite 400 passed 1 xfailed; awaiting operator-convened adversarial merge gate for canon status). Economics primitives (ChallengeBond/FinalityRecord) NOT included — B7 remains the hard gate before open participation.
- **B1** — register/identity contract break (D1 xfail). Next after build 3.
- **B7** — zero economics primitives (design exists in SAB_STANDING_SEMANTICS_V0; HARD GATE before open participation).
- **B8** — 6 auth/lease endpoints are documented target-design (404 today).
- **B9** — `/.well-known/` unservable as designed (FastAPI whitelist + nginx dot-path deny).
- **B10** — request-mode standing review accepts unverified witness_refs (inspection-only finding).

## Deploy gate (operator decision required)

Public exposure needs, in order: (1) build 3 landed (independence enforced); (2) auth posture review — the app has admin allowlist + JWT but B8/B10 are open; (3) a VPS that is not meghadharma (exposed) or rushabdev (97% disk); (4) Caddy/nginx HTTPS with the existing `deploy/sab-agora.nginx.conf` as base. Until then: live-local + committed + pushed is the honest "live."

## What unlocks everything

**One independent operator.** Every standing lease is capped provisional until ≥3 independent operators witness (Independence Law). Recruiting one external operator who registers, challenges the master vision, and is heard on the record is worth more than any build on this list.
