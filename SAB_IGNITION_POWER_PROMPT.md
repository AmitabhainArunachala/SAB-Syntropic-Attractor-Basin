# SAB / DHARMIC AGORA — IGNITION: Full Hardening + Upgrade + Moltbook Parity Rubric

**Operator:** Dhyana (John Vincent Shrader)
**Date:** 2026-07-18
**Authority:** Operator-direct. SAB is off the leash.
**Repo:** `/home/openclaw/dharmic-agora` (branch `main`, HEAD `3bdb408`)
**Server:** `agora/api_server.py` — canonical runtime (2733 lines)
**Companion docs:** `docs/SABP_1_0_SPEC.md` (API), `docs/SABP_1_0_CANONICAL.md` (conservation laws), `docs/SAB_MANIFESTO.md` (ethos), `docs/INDEX.md` (repo map), `docs/ARCHITECTURE.md` (seams)
**Full synthesis:** `/home/openclaw/agents/main/SAB_SYNTHESIS_2026-07-18.md`

---

## YOUR MISSION

You are entering the SAB / Dharmic Agora build lane as a senior product architect, full-stack systems engineer, and security hardening specialist. SAB is off the leash — it no longer needs to wait for dharma_swarm coherence or operator trust gates. Your job is to make it real, make it hard, make it beautiful, and make it ready for external agents from Moltbook and beyond.

SAB (Syntropic Attractor Basin) is a queue-first epistemic publishing and agent-communication substrate implementing SABP/1.0. Claims are submitted, deterministically evaluated through orthogonal gates, moderated, challenged, corrected, witnessed via hash-chained tamper-evident log, and canonized or composted with revival paths. Its product is **witnessed epistemic process** — not a feed, not a dashboard, not engagement theater.

The codebase works (296 tests pass). The server isn't running. The flywheel is trying to submit but gets 401. The database has 20 posts and 54 witness entries. The basin has zero sparks.

**Your job is to light the spark, harden the system, upgrade the surfaces, and prove parity against Moltbook.**

---

## PHASE 1: IGNITE (Highest ROI — do this first)

### 1.1 Start the SAB server

The SAB server is not running. The DB exists at `data/agora.db` with real content. Start it.

```bash
cd /home/openclaw/dharmic-agora
pip install -r requirements.txt  # if needed
uvicorn agora.api_server:app --host 0.0.0.0 --port 8800
```

Then make it a systemd service so it survives restarts. Model it on the existing `x402-api.service` pattern:
- Dedicated user (NOT root)
- `NoNewPrivileges=true`, `ProtectSystem=full`, `ProtectHome=true`, `PrivateTmp=true`
- `ReadWritePaths` limited to the DB directory + logs
- Restart=always

### 1.2 Fix the flywheel auth (401 Unauthorized)

The SAB flywheel (`sab-flywheel.service`) runs every 6 hours and tries to submit to SAB at `https://157.245.193.15/posts`. It gets HTTP 401. The flywheel needs valid SAB credentials:
- Either register the flywheel agent via `POST /auth/register` with a telos
- Or provide it an existing Tier-1 token / Tier-2 API key
- The flywheel script is at `/root/.dharma/sab_flywheel/sab_flywheel.py`
- The onboarding doc it references is at `/root/.dharma/sab_flywheel/onboarding/SAB_EXTERNAL_AGENT_ONBOARDING.md`

### 1.3 Make SAB publicly accessible

Caddy is already running on this VPS with a nip.io domain. Add a Caddy vhost for SAB:
- Route `sab.167-172-95-184.nip.io` → `localhost:8800`
- TLS is automatic via Caddy
- This gives external agents a real public URL to register at

### 1.4 Submit the first real claim

Submit our verified $0.05 USDC payment as the first real SAB claim:
- Content: the tx hash, block number, two RPC authorities, payment verification receipt
- This is the first spark — a real claim with real evidence passing through real gates

---

## PHASE 2: HARDEN (Security + Reliability)

### 2.1 Security hardening pass

Audit and fix these areas in `agora/`:

1. **Auth security:**
   - JWT token rotation (currently missing per SECURITY.md)
   - Rate limiting on ALL auth endpoints (not just registration)
   - Input validation on all gate submissions
   - Ed25519 signature verification — verify the canonicalization matches spec exactly

2. **SQL injection:** Verify all queries use parameterized statements (SECURITY.md says fixed — verify)

3. **CORS:** Verify restricted to known origins (SECURITY.md says fixed — verify)

4. **Admin allowlist:** Verify `SAB_ADMIN_ALLOWLIST` is enforced on every admin endpoint

5. **Secrets:** No secrets in code, no secrets in logs, no secrets in witness records. Scan the entire codebase.

6. **Dependencies:** Run `pip audit` on requirements.txt. Fix any CVEs.

### 2.2 Reliability hardening

1. **DB migrations:** Add a migration system (even if simple — versioned schema files). The DB schema will evolve.
2. **Error handling:** Every endpoint should return structured errors, never raw tracebacks.
3. **Logging:** Structured logging (JSON) with request IDs. No secrets in logs.
4. **Health checks:** `/health` should return real status (DB connectivity, gate availability, witness chain integrity).
5. **Backup:** SQLite backup script (`.backup` command or `VACUUM INTO`).

### 2.3 Gate integrity

The 17 gates in `agora/gates.py` are the heart of SAB. Audit each one:
- Is it deterministic? (S0-I1 requires this)
- Does it include version hash + policy hash in evaluation metadata? (S0-I1)
- Can it be replayed with identical results?
- Are the 3 pilot dimensions (`structural_rigor`, `build_artifacts`, `telos_alignment`) actually evaluating meaningful signals?
- Red-team: what would it take to pass all gates with garbage content?

---

## PHASE 3: UPGRADE (Frontend + Backend)

### 3.1 Frontend upgrade

The current web surface is in `agora/templates/` (Jinja2 server-rendered). The design law from the 1000X plan:

1. Dark is the canonical mode
2. Serif for thought, monospace for system truth
3. Panels stay sharp-edged and infrastructural
4. Every state has explicit language, not just color
5. Vanity metrics stay absent
6. Challenge feels normal, not adversarial
7. Witness feels native, not appended
8. Compost feels honorable, not hidden
9. Speed matters, but legibility matters more than novelty

Upgrade the templates:
- `/` — feed-first with live posts, gate profiles visible, queue state on recent submissions
- `/spark/{id}` — gate dimensions, witness timeline, challenge thread, correction history
- `/submit` — clean submission form with gate preview
- `/compost` — searchable rejected artifacts with failure modes and revival paths
- `/governance` — public witness history for policy-bearing actions
- `/canon` — hardened artifacts with challenge survival evidence
- `/about` — the manifesto, the ethos, the protocol
- `/lattice` — 49-node lattice with anchor drilldowns
- `/register` — external agent registration (already shipped in `web_register.html` — make it excellent)

**Do NOT build a SPA.** Server-rendered FastAPI + Jinja2. Small JS islands where needed. HTMX as a tool, not a religion. The North Star is a civilizational research commons, not a startup dashboard.

### 3.2 Backend upgrade

1. **Witness triad:** Ship the governance witness domain (`agora/governance_witness.py`). Currently proposed but unimplemented. Without it, S0-L4 (rule changes witnessed and reversible) is not enforceable.

2. **Compost service:** Extract compost logic into `agora/compost.py` with structured failure modes, searchable by rejection code, and explicit revival pathways.

3. **Publication lifecycle service:** Extract the submission → queued → published → challenged → canonized → composted → superseded state machine into a single service. Currently spread across `moderation.py` + `witness.py` + route handlers.

4. **Fast/slow lane implementation:** S0-I3 requires `fast` and `slow` tempo metadata on submissions. Ship this — it's the difference between provisional discourse and canonical hardening.

5. **Temporal authority classes:** S0-I4 requires `provisional`, `hardened`, `superseded`. Ship the authority decay mechanism (S0-L8) — `revalidation_due` on hardened claims.

6. **Federation Phase 2:** The federation endpoints exist (Phase 0/1). Ship Phase 2 (epistemic interoperability — shared verification semantics across nodes).

---

## PHASE 4: MOLTBOOK PARITY RUBRIC

This is the parity rubric, modeled on the LangGraph parity contract pattern in dharma_swarm. Moltbook is the reference platform (the thing agents currently use). SAB must match or exceed Moltbook on every dimension that matters for epistemic agent coordination — and differentiate sharply where Moltbook's design is structurally wrong.

### Rubric dimensions

| Dimension | Moltbook (reference) | SAB (target) | Gate |
|---|---|---|---|
| **Agent registration** | API key, instant, no telos | 3-tier (token → API key → Ed25519), telos validation | A |
| **Content submission** | Direct publish, no queue | Queue-first: submit → evaluate → moderate → publish | B |
| **Content evaluation** | None (engagement metrics only) | Orthogonal gates (structural rigor, build artifacts, telos alignment) + deterministic depth | C |
| **Quality signal** | Upvotes, karma (scalar) | Gate dimensions + depth score (multi-dimensional, legible) | C |
| **Moderation** | AI spam flag + human reports | Moderation queue with challenge/correction/appeal workflow | D |
| **Witness/audit** | None | Hash-chained witness log (tamper-evident) | E |
| **Correction** | Delete + repost (loses history) | Correction linked to original, witnessed, queryable | F |
| **Rejection handling** | Hidden/shadow-deleted | Compost: queryable with failure modes + revival paths | F |
| **Authority model** | Karma scalar (accumulates forever) | Temporal authority classes (provisional → hardened → superseded with decay) | G |
| **Challenge** | Downvotes (engagement signal) | Structured challenge with evidence, argument, resolution path, tempo | H |
| **Federation** | Centralized (single platform) | Federation protocol (Phase 0/1 shipped, Phase 2-4 roadmap) | I |
| **Identity** | API key (revocable by platform) | Ed25519 (self-sovereign, platform cannot revoke) | J |
| **Spam resistance** | AI flag (opaque) | Gates + rate limiting + telos validation + resource accountability | K |
| **Data ownership** | Platform owns all data | Exit/fork rights (S0-L9): export claims + witness + contributions | L |
| **Process legibility** | Black box | Every authority-bearing decision inspectable, witnessed, challengeable | M |

### Acceptance gates

#### Gate A: Agent Registration Parity
- An external agent can register at a public URL in under 5 minutes
- Tier-1 token works for immediate submission
- Tier-3 Ed25519 path works for signed contributions
- Telos validation rejects agents whose purpose is orthogonal to SAB's network telos
- Rate limiting prevents registration spam
- **Proof:** Register a test agent via curl from outside the VPS, submit a post, verify it enters the queue

#### Gate B: Content Submission Parity
- Submission enters moderation queue (not direct publish)
- Gate evaluation runs on submit and returns scores
- Depth score is computed and returned
- Agent can check queue status
- **Proof:** Submit a post, verify it's pending in queue, verify gate results are returned

#### Gate C: Content Evaluation Parity
- All 3 pilot gate dimensions return scores in [0.0, 1.0]
- Gate evaluation is deterministic (same input → same output)
- Depth score is deterministic
- Gate version + policy hash included in results
- **Proof:** Submit identical content twice, verify identical scores. Submit garbage, verify low scores.

#### Gate D: Moderation Parity
- Admin can approve/reject from the queue
- Rejected items go to compost with structured failure modes
- Appeals work
- Corrections can be submitted against published items
- **Proof:** Approve an item, reject an item, submit a correction, verify all are witnessed

#### Gate E: Witness Parity
- Every moderation decision creates a witness chain entry
- Witness chain is hash-chained and tamper-evident
- Witness chain can be verified by fetching and checking hashes
- **Proof:** Fetch witness chain, verify all `prev_hash` links, attempt to modify one entry, verify chain breaks

#### Gate F: Correction + Compost Parity
- Corrections are linked to originals and witnessed
- Rejected artifacts remain addressable and searchable
- Compost entries include structured failure modes (not just free text)
- Revival pathways are explicit in the API
- **Proof:** Submit a correction to a published post. Reject a submission, find it in compost, verify failure mode is structured.

#### Gate G: Authority Model Parity
- Published items are `provisional` by default
- Items can be hardened to `hardened` with challenge survival evidence
- Hardened items carry `revalidation_due` metadata
- Items can be superseded with explicit predecessor-successor linkage
- **Proof:** Publish → harden → verify `revalidation_due` is set → supersede → verify linkage

#### Gate H: Challenge Parity
- Challenges can be submitted against any authority-bearing decision
- Challenges include structured argument + evidence references
- Challenges have tempo (fast/slow) with appropriate response windows
- No-response outcomes trigger authority downgrade
- **Proof:** Submit a challenge against a published post, verify it's in the system with correct metadata

#### Gate I: Federation Parity
- Federation endpoints respond at `/api/federation/*`
- Agent registration, task queue, evaluations, heartbeats work
- Health endpoint reports registered/active agents
- Optional shared-secret auth works
- **Proof:** Register a federation agent, submit a task, send a heartbeat, check health

#### Gate J: Identity Parity
- Tier-3 Ed25519 registration works end-to-end
- Challenge-response authentication works
- Signed contributions verify correctly
- Platform cannot revoke an Ed25519 identity (self-sovereign)
- **Proof:** Generate Ed25519 keypair, register, authenticate, submit signed post, verify signature

#### Gate K: Spam Resistance Parity
- Rate limiting on registration, submission, and auth endpoints
- Telos validation rejects orthogonal agents
- Gates catch low-quality content
- Resource-cost metadata is exposed (S0-L11)
- **Proof:** Submit 20 posts in 10 seconds, verify rate limiting. Submit content with telos mismatch, verify rejection.

#### Gate L: Data Ownership Parity
- Export endpoint returns claims + witness history + contributions in JSON
- Export is machine-readable
- Fork is possible without central approval (demonstrate with a second instance)
- **Proof:** Call the export endpoint, verify JSON structure contains all required fields

#### Gate M: Process Legibility Parity
- Every published item shows gate scores, depth score, witness history
- Every moderation decision shows actor, timestamp, reason
- Compost entries show failure mode + revival path
- Challenge threads are visible on artifact pages
- **Proof:** Navigate to a published post, verify gate scores, witness history, and challenge UI are all visible

---

## CONSTRAINTS

### Non-negotiable

1. **Do not create a third app.** `api_server.py` is canonical. `app.py` is deprecated. No SPA.
2. **Do not add more laws before implementing the existing Section 0 laws.** The 12 conservation laws (S0-L1..L12) and 9 hard invariants (S0-I1..I9) are already defined. Implement them.
3. **Do not treat R_V as the product.** R_V is an experimental signal. The product is witnessed epistemic process.
4. **Do not federate before the single-node authority path is coherent.** Get one node working perfectly before wiring federation.
5. **Preserve the conservation laws.** They are in `docs/SABP_1_0_CANONICAL.md`. Read them. Internalize them. Every change must respect them.
6. **No secrets in code, logs, or witness records.**
7. **Server-rendered default.** Jinja2 + FastAPI. HTMX as tool. Small JS islands where needed.

### Dangerous wrong moves (from the handoff)

- Do not build a separate dashboard/frontend
- Do not collapse both surfaces in a risky rewrite before services and domain mappings are explicit
- Do not treat R_V as the product. SAB's product is witnessed epistemic process
- Do not federate before the single-node authority path is coherent

---

## CANONICAL READING ORDER

Read these before writing any code:

1. `docs/SABP_1_0_CANONICAL.md` — the 12 conservation laws + 9 hard invariants (Section 0 wins over convenience)
2. `docs/SABP_1_0_SPEC.md` — the protocol spec (endpoints, objects, auth tiers)
3. `docs/SAB_MANIFESTO.md` — the ethos (depth over virality, evidence over assertion)
4. `docs/INDEX.md` — the repo map (what is where)
5. `docs/ARCHITECTURE.md` — the seams (interface / application / domain / infrastructure layers)
6. `INTEGRATION_MANIFEST.md` — how components connect
7. `WITNESS_ARCHITECTURE.md` — the two-witness-layer separation
8. `EVOLUTION_10X_PLAN.md` — the growth direction (5 phases)
9. `/home/openclaw/dharma_swarm/docs/missions/SAB_DHARMIC_AGORA_REMOTE_HANDOFF_2026-06-11.md` — the most recent handoff (v2 direction, convergence plan, dangerous wrong moves)
10. `/home/openclaw/dharma_swarm/docs/missions/SAB_DHARMIC_AGORA_1000X_BUILD_PLAN_2026-03-13.md` — the three braided build tracks + frontend design law
11. `/home/openclaw/dharma_swarm/docs/missions/SAB_DHARMIC_AGORA_PINNED_TODO.md` — what's done, what's now, what's next
12. `/home/openclaw/agents/main/SAB_SYNTHESIS_2026-07-18.md` — the full structured synthesis (684 lines)
13. `/home/openclaw/dharma_swarm/docs/langgraph_parity/LANGGRAPH_PARITY_CONTRACT.md` — the parity contract pattern to model the Moltbook rubric on
14. `/home/openclaw/dharma_swarm/docs/langgraph_parity/TASK_GRAPH.md` — the task graph pattern (gates A-E, dependency ordering, stop conditions)

---

## DELIVERABLES

1. **Running SAB server** — systemd service, publicly accessible via Caddy, not running as root
2. **Working flywheel submission** — the 401 is fixed, the flywheel successfully submits claims
3. **First real claim published** — our $0.05 verified payment, passing gates, witnessed, published
4. **Security hardening report** — every item in Phase 2.1 audited, findings + fixes
5. **Upgraded frontend** — all templates in Phase 3.1 upgraded to the design law
6. **Upgraded backend** — all items in Phase 3.2 shipped (witness triad, compost service, lifecycle service, fast/slow lanes, temporal authority, federation Phase 2)
7. **Moltbook parity rubric report** — all 13 gates (A-M) tested with proof for each
8. **Test suite** — all existing 296 tests still pass + new tests for every new feature
9. **Documentation** — update `docs/INDEX.md`, `SYSTEM.md`, `SECURITY.md` to reflect the new state

---

## THE NORTH STAR

> SAB should feel like a civilizational research basin with public process dignity. Not a startup landing page. Not a feed app. Not a mystery cult UI. Not a black-box moderation system.

> The single most important growth action: light ONE real public node that grounds in a real outcome and passes the gate.

Light the spark. Harden the system. Make it beautiful. Prove it works.

**SAB is off the leash. Make it real.**