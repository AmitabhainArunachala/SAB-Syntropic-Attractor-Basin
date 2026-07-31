# Agent 1 — Local Ground Truth + Phantom Endpoint Audit

Date: 2026-07-05 | Branch: `build/sab-agent-seeding-v1` | HEAD: `c4f56810c46432c9097195b291931c13dbb4f87a`
All commands run from `/Users/dhyana/dharmic-agora` with `./.venv/bin/python` (3.13). Git used read-only.

---

## 1. `git status --short` (at start of this audit, before my edits)

```
 M docs/INDEX.md
?? COMPARISON_MATRIX.csv
?? FIELD_DOSSIER.md
?? METHODS.md
?? NEXT_10_BUILDS.md
?? SAB_POSITIONING_SCORECARD.md
?? docs/SAB_MASTER_VISION_V1.md
?? docs/lanes/sab-agent-seeding-v1/contributions/packets/sab_challenge_master_vision_v1_ebe422aab149.json
?? docs/lanes/sab-agent-seeding-v1/contributions/packets/sab_seed_language_womb_agent_hermes_m5_00bfffc5e316.json
?? docs/lanes/sab-agent-seeding-v1/contributions/packets/sab_seed_language_womb_agent_hermes_m5_0f4540c019a1.json
?? docs/lanes/sab-agent-seeding-v1/contributions/packets/sab_seed_language_womb_agent_hermes_m5_d993f5f00419.json
?? docs/lanes/sab-agent-seeding-v1/contributions/packets/sab_seed_master_vision_v1_ebe422aab149.json
?? docs/lanes/sab-agent-seeding-v1/contributions/receipts/sab_seed_language_womb_agent_hermes_m5_00bfffc5e316.receipt.json
?? docs/lanes/sab-agent-seeding-v1/contributions/receipts/sab_seed_language_womb_agent_hermes_m5_0f4540c019a1.receipt.json
?? docs/lanes/sab-agent-seeding-v1/contributions/receipts/sab_seed_language_womb_agent_hermes_m5_d993f5f00419.receipt.json
?? docs/lanes/sab-agent-seeding-v1/contributions/receipts/sab_seed_master_vision_v1_ebe422aab149.receipt.json
?? docs/lanes/sab-agent-seeding-v1/reviews/
```

Note: other packets/receipts in those directories (dharma_cron, hermes_m5_58e6, scheduler_91e8) are already tracked at HEAD. By end of my run, concurrent agents had also added `docs/SAB_STANDING_SEMANTICS_V0.md` and `tests/test_sab_dogfood_regression.py` (untracked) — not mine.

## 2. Full pytest (`./.venv/bin/python -m pytest -q`)

Run A (mission start, before any edits by any agent this session):

```
........................................................................ [ 19%]
........................................................................ [ 38%]
........................................................................ [ 58%]
........................................................................ [ 77%]
........................................................................ [ 96%]
............                                                             [100%]
=============================== warnings summary ===============================
.venv/lib/python3.13/site-packages/fastapi/testclient.py:1
  /Users/dhyana/dharmic-agora/.venv/lib/python3.13/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
372 passed, 1 warning in 17.96s
```

Run B (after my site/*.md edits; a concurrent agent had by then added a test file):
`373 passed, 2 xfailed, 1 warning in 17.28s` — the +1 passed / +2 xfailed come from the concurrently added `tests/test_sab_dogfood_regression.py`, not from my doc edits. Doc-affecting tests re-run in isolation: `tests/test_sab_agent_docs.py tests/test_sab_seeding_api.py` → `9 passed`.

## 3. Bandit (`./.venv/bin/python -m bandit -r agora connectors -x agora/tests -q`)

```
Run started:2026-07-05 14:30:44
>> Issue: [B608:hardcoded_sql_expressions] Severity: Medium Confidence: Medium
   Location: agora/sab_seeding_storage.py:943
>> Issue: [B105:hardcoded_password_string] Severity: Low Confidence: Medium
   Location: connectors/sab_mcp_tools.py:15
Total lines of code: 20839 | skipped via #nosec BXXX: 13
Totals: Medium 1, Low 1, High 0
```

Plus 3 pre-existing `#nosec B608` suppressions surfaced by the tester warnings: `agora/sab_seeding_api.py:301, 722, 1664`.

Classification (all four SQL sites opened and read):

| Location | Verdict | Evidence |
|---|---|---|
| `agora/sab_seeding_storage.py:943` | SAFE (parameterized; identifiers from schema, not input) | Column names come from `_table_columns()` = `PRAGMA table_info` (storage.py:57-59) intersected with a hardcoded `insert_values` dict (storage.py:905-935); values bound via `?` placeholders (storage.py:940-944). No user-controlled identifier can enter the f-string. |
| `agora/sab_seeding_api.py:301` | SAFE, nosec justified | `where` assembled only from fixed literals `"state = ?"`, `"seed_type = ?"`, `"claimant_identity = ?"` (api.py:285-297); all values parameterized. |
| `agora/sab_seeding_api.py:722` | SAFE, nosec justified | Same fixed-clause pattern over `sab_standing_leases_v1` (`"status = ?"`, `"scope = ?"`); values parameterized. |
| `agora/sab_seeding_api.py:1664` | SAFE, nosec justified | Same fixed-clause pattern in `_witness_rows` (`"subject_type = ?"`, `"subject_id = ?"`); values parameterized. |
| `connectors/sab_mcp_tools.py:15` | FALSE POSITIVE | The "password" is `SECRET_HANDLING_WARNING`, a policy warning string ("Never pass SAB private keys..."), not a credential. |

No real SQL-injection or hardcoded-credential risk found.

## 4. Endpoint Truth Table

Mount verified two ways: statically (`APIRouter(prefix="/api/v1")` at `agora/sab_seeding_api.py:58`, included at `agora/app.py:1249-1260`) and at runtime via `fastapi.testclient.TestClient(agora.app.app)` with DB env redirected to scratchpad (`SAB_AUTHORITY_DB_PATH`/`SAB_SPARK_DB_PATH`) so no live DB was touched. Probe outputs pasted below the table.

| Documented route (doc:line) | Actual route | Status | Evidence |
|---|---|---|---|
| `POST /api/v1/agents/register` (skill.md:49,64; auth.md:33) | same | implemented, response-shape MISMATCH (docs claimed `challenge_required` + challenge/verify endpoints; actual returns active identity object) | sab_seeding_api.py:60-99; fixed in skill.md |
| `POST /api/v1/agents/challenge` (skill.md:50,92; auth.md:60) | none | PHANTOM (404) | probe below; no route in sab_seeding_api.py; fixed in skill.md + auth.md |
| `POST /api/v1/agents/verify` (skill.md:51,93; auth.md:74) | none | PHANTOM (404) | probe below; fixed in skill.md + auth.md |
| `GET /api/v1/agents/me/home` w/ `Authorization: Bearer` (heartbeat.md:4,20-21; skill.md:301) | `GET /api/v1/agents/me/home?subject_id=` | implemented, auth MISMATCH (query param, no bearer auth) + response-shape mismatch | sab_seeding_api.py:101-161; probe 422 without subject_id; fixed in heartbeat.md + skill.md |
| `POST /api/v1/agents/me/rotate-key` (auth.md:161) | none | PHANTOM (404) | probe below; fixed in auth.md |
| `POST /api/v1/agents/me/revoke` (auth.md:167) | none | PHANTOM (404) | probe below; fixed in auth.md |
| `POST /api/v1/authority-leases/{lease_id}/revoke` (auth.md:168) | none | PHANTOM (404) | probe below; fixed in auth.md |
| `/api/v1/authority-leases/{id}/challenge` as `challenge_path` (auth.md:149; heartbeat.md:38) | none | PHANTOM path reference (404); lease `challenge_path` is a declared packet field only | probe below; status notes added in auth.md + heartbeat.md |
| `POST /api/v1/seeds` (skill.md:53,103; seed.md:74) | same | implemented; expected-result mismatch (`witness_event_id`, `next_actions`) fixed | sab_seeding_api.py:163, return :247-255; fixed in skill.md |
| `GET /api/v1/seeds/{seed_id}` (seed.md:75) | same | implemented | sab_seeding_api.py:257 |
| `GET /api/v1/seeds/{seed_id}/chain` (seed.md:76) | same | implemented | sab_seeding_api.py:265 |
| `GET /api/v1/seeds?status=&type=&claimant=` (seed.md:77) | same (aliases `status`,`type` + `claimant`,`state`,`limit`) | implemented | sab_seeding_api.py:273-282 |
| `POST /api/v1/seeds/{seed_id}/correct` (seed.md:78) | same | implemented | sab_seeding_api.py:309 |
| `POST /api/v1/seeds/{seed_id}/withdraw` (seed.md:79) | same | implemented | sab_seeding_api.py:343 |
| `POST /api/v1/seeds/{seed_id}/challenges` (seed.md:80; skill.md:208) | same | implemented | sab_seeding_api.py:377 |
| `GET /api/v1/challenges/{challenge_id}` (seed.md:81; skill.md:257) | same | implemented | sab_seeding_api.py:461 |
| `POST /api/v1/challenges/{challenge_id}/respond` (heartbeat.md:75) | same | implemented (also `/sustain` :472, `/reject` :476, undocumented) | sab_seeding_api.py:468 |
| `POST /api/v1/witness-events` (seed.md:82,241; skill.md:242) | same | implemented | sab_seeding_api.py:487 |
| `GET /api/v1/witness/verify?seed_id=` (seed.md:83,292; skill.md:280) | same | implemented; response-shape mismatch (actual `{verified, entry_count, head}`) fixed in both docs | sab_seeding_api.py:575-590 |
| `GET /api/v1/standing/{standing_id}` (seed.md:84,269; skill.md:270) | same | implemented; lease fields nested under `standing_lease` (note added to seed.md) | sab_seeding_api.py:688, `_serialize_standing` :1595-1613 |
| `POST /api/v1/standing/{standing_id}/challenge` (seed.md:284 challenge_path) | same | implemented | sab_seeding_api.py:731 |
| `POST /api/v1/standing/{standing_id}/revoke` (auth.md:169) | same | implemented | sab_seeding_api.py:735 |
| Public docs `/skill.md /seed.md /auth.md /heartbeat.md /rules.md` (skill.md:5) | same | implemented | agora/app.py:1211-1233 |
| `/schemas/sab.seed_packet.v1.schema.json` (skill.md:6) | same | implemented (serves nodes/schemas then site/schemas fallback; both files exist) | agora/app.py:1236-1244 |
| site/rules.md, site/README.md | — | no API endpoints documented (grep for `/api/`, GET/POST: zero hits) | grep output empty |
| site/standing.html | — | no API paths; static page | grep for `/api/` returned nothing |
| site/app.js | `fetch("./data/seed_claims.json")` only | static asset, exists at site/data/seed_claims.json | site/app.js:6 |

Runtime probe output (TestClient, scratchpad DBs):

```
POST /api/v1/agents/challenge -> 404
POST /api/v1/agents/verify -> 404
POST /api/v1/agents/me/rotate-key -> 404
POST /api/v1/agents/me/revoke -> 404
POST /api/v1/authority-leases/sab_lease_x/revoke -> 404
POST /api/v1/authority-leases/sab_lease_x/challenge -> 404
GET /api/v1/agents/me/home -> 422   (exists; missing required subject_id query param)
```

Undocumented-but-implemented (reverse phantoms, FYI): `POST /api/v1/challenges/{id}/sustain` (:472), `/reject` (:476), `GET /api/v1/witness-events/{event_id}` (:546), `GET /api/v1/witness/chain` (:559), `POST /api/v1/standing/review` (:591), `GET /api/v1/standing` (:696), `POST /api/v1/standing/{id}/revalidate` (:739), `GET /api/v1/seeds/{id}/chain` documented ✓.

**Stop condition met: zero unaccounted phantoms.** All six phantom routes are now annotated as target-design/404 in the site docs (my scope); none silently documented as live.

## 5. Packet Provenance

| Artifact (docs/lanes/sab-agent-seeding-v1/contributions/) | Provenance | Evidence |
|---|---|---|
| packets/sab_seed_language_womb_agent_sab_language_womb_scheduler_91e85c7fa3c2.json (+receipt) | SCRIPT-generated (bootstrap) | receipt `source_name: "bootstrap"`; generator `scripts/sab_language_womb_tick.py` writes packet+receipt directly (`:459-460`), receipt schema string at `:444`, `source_name` at `:449`; no HTTP calls in script; signer `agent_sab_language_womb_scheduler` |
| packets/sab_seed_language_womb_agent_dharma_cron_26e035e5305b.json (+receipt) | SCRIPT-generated (source-delta) | receipt `source_name: "source-delta"`; same generator; signer `agent_dharma_cron` |
| packets/sab_seed_language_womb_agent_hermes_m5_58e673376e09.json (+receipt) | SCRIPT-generated (source-delta) | same generator; signer `agent_hermes_m5`; created 2026-07-04T15:55Z |
| packets/sab_seed_language_womb_agent_hermes_m5_0f4540c019a1.json (+receipt) | SCRIPT-generated (source-delta) | same; created 2026-07-04T21:55Z |
| packets/sab_seed_language_womb_agent_hermes_m5_d993f5f00419.json (+receipt) | SCRIPT-generated (source-delta) | same; created 2026-07-05T04:00Z |
| packets/sab_seed_language_womb_agent_hermes_m5_00bfffc5e316.json (+receipt) | SCRIPT-generated (source-delta) | same; created 2026-07-05T10:04Z; receipt hash matches canonical-JSON-with-signature: `sha256:b8e994...` recomputed ✓ |
| packets/sab_seed_master_vision_v1_ebe422aab149.json (+receipt) | API-generated (live locally-mounted API) | receipt `submitted_via: "live seeding API (locally mounted, undeployed) at http://127.0.0.1:8080"`; `api_calls` log register 201 → submit_seed 201 (state pending_seed) → submit_challenge 201 (state challenged) → get_seed 200 → get_seed_chain 200 → witness_verify 200; packet hash matches canonical-JSON-without-signature: `sha256:2513c4d4...` recomputed ✓ |
| packets/sab_challenge_master_vision_v1_ebe422aab149.json | API-generated (same session) | schema `sab.challenge_packet.v1`, signer `agent_claude_fable_5`, challenge_id matches receipt's submit_challenge response |

DB cross-check of the reported live-API entry (read-only SELECTs):
- `data/sabp.db` has NO `sab_seed_packets_v1` table — the v1 API persists to the spark DB, not sabp.db.
- `data/spark.db` `sab_seed_packets_v1`: exactly 1 row — `sab_seed_master_vision_v1_ebe422aab149 | challenged | agent_claude_fable_5 | 2026-07-05T02:14:51Z | window closes 2026-07-19T02:14:51Z`. `sab_challenge_packets_v1`: 1 row, `sab_challenge_master_vision_v1_ebe422aab149 | pending`. `sab_witness_events_v1`: 2 rows (submit, challenge).
- Verdict: the "first-ever API entry, state=challenged, window closes 07-19" report is CORROBORATED by the artifacts and DB. `first_api_entry` claim ("no prior rows existed") is consistent with the single-row table but is self-reported for the moment of submission — UNVERIFIED beyond consistency.
- Independence: NONE of these are external submissions. All signers (`agent_hermes_m5`, `agent_dharma_cron`, `agent_sab_language_womb_scheduler`, `agent_claude_fable_5`) are the operator's own fleet; the master-vision packet's own `operator_backing.disclosure` says "Founding operator's fleet. Not independent of any other identity this operator runs." Label: **single_operator_rehearsal**.

## 6. Citation Check — FIELD_DOSSIER.md "Local SAB Evidence" (lines 35-55)

| Cited | Claim attributed | What the file/repo actually shows | Verdict |
|---|---|---|---|
| Branch `build/sab-agent-seeding-v1` (l.41) | current branch | `git branch --show-current` ✓ | VERIFIED |
| Commits `f817d61`, `56904c1`, `c4ac93b` (l.42-43) | exist with those subjects | `git log --oneline` shows all three, subjects match exactly | VERIFIED |
| `agora/sab_seeding_api.py`, `sab_seeding_storage.py`, `sab_identity.py`, `sab_attestations.py` (l.44) | runtime modules exist | all four present | VERIFIED |
| `nodes/schemas/sab.*.v1.schema.json` (l.45) | schemas exist | 6 files: agent_identity, authority_lease, challenge_packet, seed_packet, standing_lease, witness_event | VERIFIED |
| `tests/test_sab_agent_*`, `tests/test_sab_seeding_*` (l.47) | tests exist | 5 files present | VERIFIED |
| BUILD_SPEC.md / lane README (l.49) | signed seed packets into challengeable pipeline; separation of identity/reputation/permission/witness/standing/canon | BUILD_SPEC.md:17 "agents submit signed seed packets into a challengeable evidence pipeline"; :24 flow "discover SAB -> register identity -> submit seed packet -> challenge window" | VERIFIED |
| SAB_WORLD_AGENT_STANDING_STANDARD_V0.md (l.51) | standing = signed, witnessed, replayable judgment...; "not truth, popularity, or permission" | :20 exact definition sentence; :22/:24/:26 "Standing is not truth/popularity/permission." | VERIFIED |
| Router capability list (l.53) | registration, seeds, correct/withdraw, challenges+respond, witness events, chain verify, standing review/search/fetch/challenge/revoke/revalidate | all routes present, sab_seeding_api.py:60-739 (see truth table) | VERIFIED |
| Storage records "...authority leases, and signature replay indexes" (l.53) | storage layer tables | `sab_signature_index_v1` (sab_seeding_api.py:757, `_record_signature_use` :1202-1216, 409 on replay :1209); `authority_leases` (sab_seeding_storage.py:210) + `sab_authority_leases_v1` (api.py:767). Nuance: the v1 replay index lives in sab_seeding_api.py's `_init_v1_tables`, not sab_seeding_storage.py — but both files are cited in the same source line | VERIFIED (minor file-attribution imprecision) |
| `agora/sab_identity.py` (l.55) | identity proves key control + operator disclosure, not truth | sab_identity.py:100 "This proves public-key control and operator disclosure. It does not prove..." | VERIFIED |
| `agora/sab_attestations.py` (l.55) | external attestations (incl. Moltbook tokens) cannot grant standing | :89 `external_attestation_cannot_grant_standing`, :121 `never_standing`, :40-45 Moltbook key detection | VERIFIED |
| skill.md:34 `docs/lanes/sab-agent-seeding-v1/LANGUAGE_WOMB_GRAND_CHALLENGE_SEED.md`; skill.md:307 `MCP_A2A_PROFILE.md` | files exist | both present | VERIFIED |

No false citations found in the Local SAB Evidence section. Corrections needed: none beyond the file-attribution nuance noted above. (External "Field Map" web citations are Agent 6's scope.)

## 7. DNS / Deploy Assumptions

| Source | Claim | Classification |
|---|---|---|
| `deploy/sab-agora.nginx.conf:10,22,29,32-33` | domain `agora.dharmic.ai`, certbot, LetsEncrypt paths | UNVERIFIED-external-assumption — config template only; SSL cert lines commented out; no local evidence the domain is registered, resolves, or is deployed. Never present as a live URL. |
| `deploy/sab-agora.service:15-38` | Linux host paths `/home/openclaw/dharmic-agora`, `.env.production` | UNVERIFIED-external-assumption — systemd template for a host not verifiable from this repo |
| `DEPLOY.md` | localhost quick-start (`curl http://localhost:8000/docs`, `:9091/healthz`), port map "8080:8000" note | verified-local-config in intent; docker runtime NOT exercised in this audit. Note: docker-compose.yml:7 actually maps `8000:8000` for agora; the "8080:8000" line in DEPLOY.md:89 is presented as an example edit. |
| `docker-compose.yml` | services agora(8000), redis(6379), milvus(19530/9091), etcd, minio(9001); all loopback/local | verified-local-config (file-level); not runtime-verified here |
| `site/README.md:9-15` | local preview `http://localhost:8080/site/` | verified-local-config |
| Master-vision receipt | `http://127.0.0.1:8080` "locally mounted, undeployed" | consistent with local-only; no public deploy claimed |

No site doc claims a live production domain. The only domain string in the repo's deploy surface is `agora.dharmic.ai`, and it is template-only.

## 8. site/*.md Edits Made (my write scope; all doc tests green after)

1. `site/auth.md` — status note before `POST /api/v1/agents/challenge` block (challenge+verify = 404 today); status note after authority-lease example (`/api/v1/authority-leases/*` routes not implemented); status note in Rotation And Revocation (only `standing/{id}/revoke` implemented).
2. `site/skill.md` — First Path step 3 rewritten (challenge/verify = target design, 404); register expected-result block replaced with actual identity-object response; seed-submit expected result corrected (no `witness_event_id`; real `next_actions`); witness/verify expected result corrected to `{verified, entry_count, head}`; heartbeat line corrected to `?subject_id=` + no bearer auth.
3. `site/heartbeat.md` — request example corrected to `?subject_id=` (bearer auth marked target design); status note on actual `sab.agent_home.v1` response fields vs target shape; note that authority-lease challenge route doesn't exist while `challenges/{id}/respond` does.
4. `site/seed.md` — witness/verify example corrected to actual shape; status note on standing-fetch nesting (`standing_lease`).

Not touched (other agents' scope): site/standing.md (does not exist; standing.html untouched), FIELD_DOSSIER.md, SAB_POSITIONING_SCORECARD.md, NEXT_10_BUILDS.md, COMPARISON_MATRIX.csv, METHODS.md.

Verification after edits: `pytest tests/test_sab_agent_docs.py tests/test_sab_seeding_api.py -q` → 9 passed; full suite → 373 passed, 2 xfailed (delta from concurrent agent's new test file, see §2).
