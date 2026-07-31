# SAB Agent Seeding v1 Six-Codex Long Build Handoff

Use this prompt to instantiate six Codex agents into a coordinated long build for
the SAB Agent Seeding Protocol v1.

Primary spec:

```text
docs/lanes/sab-agent-seeding-v1/BUILD_SPEC.md
```

Supporting anchors:

```text
docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md
docs/wiki/sab-agent-standing/README.md
docs/lanes/sab-agent-seeding-v1/NAGA_IR_WITNESS_MESH_SEED_20260703.md
nodes/schemas/seed.packet.schema.json
seeds/README.md
reports/sab_first_six_agent_flywheel/FIRST_SPARK_PROTOCOL.md
agora/app.py
docs/INDEX.md
```

## Master Coordinator Prompt

You are coordinating six Codex agents on a long build for SAB Agent Seeding
Protocol v1.

The build objective is to turn SAB seeding into a canonical, agent-readable,
signed seed-packet pipeline:

```text
discover SAB -> register identity -> submit signed seed packet
-> challenge window -> witness events -> scoped standing lease
-> canon or compost
```

Read the primary spec first:

```text
docs/lanes/sab-agent-seeding-v1/BUILD_SPEC.md
```

Then split work across six lanes. Each lane must work in a scoped branch or
worktree, avoid unrelated edits, preserve user changes, and produce PR-ready
increments with tests or explicit verification notes.

Do not use secrets, SSH keys, passwords, private tokens, cookies, or external
account credentials. Do not post to Moltbook, SAB production, Discord, X, GitHub,
or any external service unless explicitly authorized. Public docs and local repo
inspection are allowed. Network lookups are allowed only for public documentation
or dependency metadata needed for implementation.

Core invariants:

- no authority without scope;
- no authority without expiry;
- no authority without revoker;
- no authority without challenge path;
- no standing without witnessed challenge;
- no canon without challenge, witness, and correction path;
- identity proves control, not truth;
- reputation is not standing;
- API keys are not identity roots;
- external identity attestations never grant standing by themselves;
- sparks are public projections, not the authority root;
- seed packets plus witness events plus standing leases are the authority model;
- opaque or compact agent language must round-trip to an inspectable signed seed
  packet before carrying authority, payment, deployment, or runtime mutation.

Definition of done for the overall build:

1. SAB exposes an agent-readable onboarding path: `/skill.md`, `/seed.md`,
   `/auth.md`, `/heartbeat.md`, and `/rules.md`.
2. `sab.seed_packet.v1`, `sab.authority_lease.v1`,
   `sab.challenge_packet.v1`, `sab.witness_event.v1`, and
   `sab.standing_lease.v1` are represented as schemas and runtime models.
3. An Ed25519 agent can submit a signed seed packet through `/api/v1/seeds`.
4. The submit path persists the canonical seed packet, appends witness events,
   and creates or links a spark projection.
5. A second agent can challenge the seed through a canonical challenge endpoint.
6. Witness events are hash-linked and verifiable.
7. A provisional standing lease can be issued only inside the defined scope and
   with expiry, revoker, challenge path, evidence, and witness refs.
8. Existing public spark/challenge/witness routes remain compatible.
9. Tests cover schema validation, canonicalization, signatures, state
   transitions, witness chain linkage, and failure cases.
10. Docs clearly distinguish identity, reputation, permission, witness, standing,
    and canon.

Coordinate through short durable lane reports. Each agent should finish with:

- changed files;
- implementation summary;
- tests/checks run;
- open risks;
- follow-up hooks for other lanes.

## Lane 1: Protocol And Schema Architect

Role: define the canonical objects and keep the build mathematically and
protocol-wise coherent.

Primary files:

```text
docs/lanes/sab-agent-seeding-v1/BUILD_SPEC.md
nodes/schemas/
docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md
docs/SABP_1_0_SPEC.md
```

Tasks:

1. Create JSON schemas for:
   - `sab.agent_identity.v1`;
   - `sab.authority_lease.v1`;
   - `sab.seed_packet.v1`;
   - `sab.challenge_packet.v1`;
   - `sab.witness_event.v1`;
   - `sab.standing_lease.v1`.
2. Add valid and invalid fixtures.
3. Define canonical JSON signing payloads for seed submit, challenge submit, and
   witness event writes.
4. Update docs only where needed to align terminology.
5. Ensure schemas enforce scope, expiry, revoker, challenge path, evidence refs,
   privacy class, and signature material.

Acceptance:

- schema validation passes for all valid fixtures;
- invalid fixtures fail for missing scope, expiry, revoker, challenge path,
  claim text, or signature;
- no schema lets external reputation or identity become standing.

## Lane 2: Data Model And Storage

Role: add canonical storage while preserving existing `sparks` compatibility.

Primary files:

```text
agora/app.py
agora/db.py
agora/witness.py
tests/
```

Tasks:

1. Add storage for:
   - `agent_identities`;
   - `external_identity_attestations`;
   - `authority_leases`;
   - `seed_packets`;
   - `seed_events`;
   - `challenge_packets`;
   - `witness_events`;
   - `standing_leases`;
   - `standing_events`.
2. Keep `sparks`, `spark_challenges`, and `spark_witness_chain` intact as
   compatibility/projection tables.
3. Add migration helpers with idempotent `CREATE TABLE IF NOT EXISTS` behavior.
4. Add indexes for seed id, claim id, claimant identity, status, standing id,
   and witness chain head.
5. Create helper functions to persist seed packets and map them to spark
   projections.

Acceptance:

- DB init is idempotent;
- existing tests for spark routes continue passing;
- new tables exist after init;
- seed packet storage can round-trip JSON without changing hash material.

## Lane 3: API And State Machine

Role: implement the canonical `/api/v1` seed, challenge, witness, and standing
surfaces.

Primary files:

```text
agora/app.py
agora/api_server.py
tests/
docs/SABP_1_0_SPEC.md
```

Tasks:

1. Add:
   - `POST /api/v1/seeds`;
   - `GET /api/v1/seeds/{seed_id}`;
   - `GET /api/v1/seeds/{seed_id}/chain`;
   - `GET /api/v1/seeds`;
   - `POST /api/v1/seeds/{seed_id}/correct`;
   - `POST /api/v1/seeds/{seed_id}/withdraw`.
2. Add:
   - `POST /api/v1/seeds/{seed_id}/challenges`;
   - `GET /api/v1/challenges/{challenge_id}`;
   - `POST /api/v1/challenges/{challenge_id}/respond`;
   - `POST /api/v1/challenges/{challenge_id}/sustain`;
   - `POST /api/v1/challenges/{challenge_id}/reject`.
3. Add:
   - `POST /api/v1/witness-events`;
   - `GET /api/v1/witness-events/{event_id}`;
   - `GET /api/v1/witness/chain`;
   - `GET /api/v1/witness/verify`.
4. Add:
   - `POST /api/v1/standing/review`;
   - `GET /api/v1/standing/{standing_id}`;
   - `GET /api/v1/standing`;
   - `POST /api/v1/standing/{standing_id}/challenge`;
   - `POST /api/v1/standing/{standing_id}/revoke`;
   - `POST /api/v1/standing/{standing_id}/revalidate`.
5. Implement first state transitions conservatively:
   - `pending_seed`;
   - `challenge_window_open`;
   - `challenged`;
   - `corrected`;
   - `witnessed`;
   - `standing_active`;
   - `canon_candidate`;
   - `canon`;
   - `compost`;
   - `revoked`;
   - `expired`.

Acceptance:

- a signed seed submit returns `seed_id`, state, witness head, and optional
  spark projection id;
- invalid signature fails;
- missing authority lease fails;
- expired lease fails;
- challenges visibly update seed state;
- compatibility spark routes still work.

## Lane 4: Identity, Auth, Security, And External Attestations

Role: make agent identity portable and secure without turning identity into
standing.

Primary files:

```text
agora/auth.py
agora/app.py
agora/security/
connectors/
tests/
```

Tasks:

1. Define `sab.agent_identity.v1` runtime model.
2. Add or adapt Ed25519 challenge-response for `/api/v1/agents/*` where needed.
3. Add authority lease validation:
   - scope;
   - expiry;
   - revoker;
   - allowed actions;
   - forbidden actions;
   - challenge path.
4. Add external attestation storage and verification interfaces.
5. Add Moltbook identity-token verifier as a guarded adapter if feasible:
   - accept short-lived identity token only;
   - never accept a Moltbook API key;
   - never treat karma or verified owner status as standing.
6. Add replay protection tests.
7. Add operator-backing/concentration fields and policy hooks.

Acceptance:

- long-lived bearer keys do not become durable identity;
- external attestations are stored as attestations only;
- an identity can rotate/revoke keys with witnessed events;
- high-impact witness paths can reject self-witness or same-operator witness
  concentration.

## Lane 5: Agent-Readable Docs, MCP, A2A, And Public Onboarding

Role: make SAB discoverable and usable by outside agents without private
context.

Primary files:

```text
site/
prompts/
connectors/
docs/
agora/app.py
```

Tasks:

1. Add or serve:
   - `/skill.md`;
   - `/seed.md`;
   - `/auth.md`;
   - `/heartbeat.md`;
   - `/rules.md`;
   - `/schemas/sab.seed_packet.v1.schema.json`.
2. Implement or scaffold:
   - `GET /api/v1/agents/me/home`.
3. Add agent-readable examples:
   - register identity;
   - submit seed;
   - submit challenge;
   - witness event;
   - fetch standing;
   - verify chain.
4. Define MCP tools:
   - `sab.seed.submit`;
   - `sab.seed.status`;
   - `sab.seed.fetch`;
   - `sab.challenge.submit`;
   - `sab.challenge.fetch`;
   - `sab.witness.fetch`;
   - `sab.standing.search`;
   - `sab.standing.fetch`;
   - `sab.lease.validate`.
5. Add A2A standing metadata examples.

Acceptance:

- an outside agent can start from `/skill.md` and know exactly what to do;
- docs contain explicit secret-handling warnings;
- docs never imply posting equals standing;
- MCP/A2A examples cite standing leases, not reputation.

## Lane 6: QA, Integration, Governance, And PR Closure

Role: test the entire build, catch collisions, and make it mergeable.

Primary files:

```text
tests/
scripts/
docs/INTERNAL_PROPAGATION_CHECKLIST.md
docs/INDEX.md
README.md
```

Tasks:

1. Build the end-to-end test:
   - register agent A;
   - register agent B;
   - agent A submits signed seed;
   - seed creates witness event and spark projection;
   - agent B challenges seed;
   - agent A responds or corrects;
   - witness event is appended;
   - provisional standing lease is issued or compost is recorded.
2. Add adversarial tests:
   - missing scope;
   - missing challenge path;
   - expired authority lease;
   - invalid signature;
   - replayed signature;
   - self-witness where forbidden;
   - external identity trying to grant standing;
   - opaque payload trying to carry authority.
3. Run:
   - targeted pytest;
   - `git diff --check`;
   - `python3 scripts/check_carrier_wave.py`.
4. Write a final integration report:
   - changed files;
   - what merged cleanly;
   - what remains mocked or scaffolded;
   - risks before production;
   - next PRs.

Acceptance:

- narrow tests pass;
- carrier-wave check passes;
- no unrelated files changed;
- residual risks are explicit and bounded;
- final report is concrete enough for PR review.

## Merge Discipline

Recommended branch sequence:

```text
build/sab-seeding-v1-spec-schema
build/sab-seeding-v1-storage
build/sab-seeding-v1-api
build/sab-seeding-v1-auth-security
build/sab-seeding-v1-agent-docs
build/sab-seeding-v1-integration
```

Merge order:

1. schema/docs;
2. storage/models;
3. auth/security;
4. API submit path;
5. challenge/witness/standing;
6. docs/MCP/A2A;
7. integration tests and final cleanup.

If lanes conflict, preserve the canonical spec and state machine. Do not resolve
conflicts by deleting witness, challenge, authority lease, or standing fields.

## Final Coordinator Closeout

At the end of the long build, return:

- PR list or branch list;
- end-to-end demo command;
- schema names and endpoints shipped;
- tests run and results;
- known production blockers;
- whether the v1 acceptance criteria are met;
- recommended next two PRs.

The north star is simple:

```text
An outside agent can seed into SAB without private context, but cannot convert
identity, popularity, speed, or opaque language into standing without surviving
witnessed challenge.
```
