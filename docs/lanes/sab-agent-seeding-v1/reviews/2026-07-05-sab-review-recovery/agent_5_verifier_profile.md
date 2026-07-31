# Agent 5 Receipt — Verifier Profile + CLI/SDK Minimal Path

Date: 2026-07-05 · Branch: `build/sab-agent-seeding-v1` · HEAD: `c4f56810c46432c9097195b291931c13dbb4f87a` (verified at start; git read-only throughout)
Label: **single_operator_rehearsal** — all work by one operator's agent on one machine.

## Files written / changed

| Path | Action |
|---|---|
| `site/standing.md` | NEW — truthful standing profile (field table, status vocabulary, gaps, divergences from standing.html) |
| `site/.well-known/sab-standing.json` | NEW — machine-readable profile descriptor (JSON validated by parse) |
| `scripts/sab_verify.py` | NEW — minimal read-only standing verifier (stdlib only, sqlite `mode=ro`, receipts fallback) |
| `tests/test_sab_standing_verifier.py` | NEW — 10 tests, all passing |
| `connectors/sab_mcp_tools.py` | Wording corrections only (docstring verdict, stub/PLANNED marking on `sab.lease.validate`, read-tool `returns` corrected to observed keys, two description fixes) |
| this receipt | NEW |

No other files touched. `agora/` unmodified.

## Task 1 — site/standing.md profile field table (summary; full cites in the file)

| Field | Today | Enforcement |
|---|---|---|
| `claim_hash` | = seed `packet_hash`, sha256 of canonical packet JSON (`agora/sab_seeding_api.py:926`, `:784-799`, `:1549`) | real |
| `scope` | free-text lease column (`:866-886`, `:1600`) | stored, no grammar (PLANNED) |
| `status` | stored vocab `{active, challenged, revoked, expired, canon, compost}` (`:30`); profile vocab `{active, challenged, revoked, expired, unknown, rehearsal_only}` mapped by verifier | `rehearsal_only`/`unknown` computed, not stored |
| `expires_at` | lease `expiry` column; input alias `expires_at` accepted (`:1909-1910`); lazy witnessed expiry (`:1913-1951`) | real |
| `challenge_uri` | lease `challenge_path`; live route `POST /api/v1/standing/{id}/challenge` (`:731`) | real |
| `revocation_uri` | derived from live route `POST /api/v1/standing/{id}/revoke` (`:735`); lease stores revoker *identity*, not URI | partially (PLANNED first-class) |
| `witness_quorum` | schema-only (`nodes/schemas/sab.standing_lease.v1.schema.json:20,85-116`); API validates only scope/purpose/revoker/challenge_path/expiry (`:1901-1906`) + ≥1 witness event of any kind (`:606-611`) | NOT enforced (PLANNED) |
| `independence_status` | not stored, zero API callers of `validate_witness_independence` (`agora/sab_identity.py:491`); enum in `docs/SAB_STANDING_SEMANTICS_V0.md`; verifier grades conservatively | NOT enforced (PLANNED) |
| `replay_recipe` | lives inside seed packet `challenge_plan.falsification_routes` + claim text | no dedicated field (PLANNED) |
| `standing_uri` | local route `GET /api/v1/standing/{standing_id}` (`:688`) only; **no public production URL claimed** | local only |

Divergences from `site/standing.html` noted in the doc: its present-tense "public test" / "distinct reviewers" sentences are aspirational (no deployment; reviewer distinctness unenforced per Agent 4's D2).

## Task 2 — .well-known placement verdict

Landed at **`site/.well-known/sab-standing.json`** because no serving path is verifiable:
- FastAPI serves only a whitelist of `site/` files — `/skill.md`, `/seed.md`, `/auth.md`, `/heartbeat.md`, `/rules.md`, one schema (`agora/app.py:1204-1246`); no generic static mount of `site/` (only `/static` → `agora/static`, `agora/app.py:1201`).
- `Dockerfile:16` copies only `agora/` — `site/` never enters the image.
- `deploy/sab-agora.nginx.conf` proxies everything to the backend AND contains `location ~ /\. { deny all; return 404; }` — **dot-paths including `/.well-known/` would 404 in that deployment as configured**.
- `DEPLOY.md` defines no static root for `site/`.

The JSON therefore carries `"serving_status": {"served": false, ...}`, `"production_url": null`, and `"environment": "single_operator_rehearsal"`. Serving it is marked PLANNED (needs an app route or an nginx exception).

## Task 3 — MCP manifest-vs-server verdict

**Verdict: manifest only; a stub with respect to any runtime MCP surface. No bindable/served MCP server exists in this repo.**
Evidence:
- Repo-wide grep for server bootstrap (`fastmcp|mcp\.server|modelcontextprotocol|mcp_server|serve_mcp` over *.py/*.toml/*.json/*.cfg, excluding node_modules/.venv/docs prose): **zero hits** (pasted run, rc=0, empty output).
- `connectors/` contains no server entry point; `pyproject.toml`/`package.json` register no MCP anything.
- Only importer of the manifest is `tests/test_sab_agent_docs.py:16`.
- Additional inaccuracy found and corrected in-file: `sab.lease.validate` targets `GET /api/v1/authority-leases/{lease_id}` — **that route does not exist** in `agora/sab_seeding_api.py` (grep over routes: authority_leases appears only as a table, `:767,1085,1290`). Now marked "PLANNED / stub" in its description.
- Mutation `returns` divergence disclosed in the docstring (kept in list because `tests/test_sab_agent_docs.py:95` locks `witness_event_id` in mutation returns, and it is the declared contract of `MCP_A2A_PROFILE.md`): live routes observed 2026-07-05 return `witness_head`, not top-level `witness_event_id` (`dogfood/04_submit_seed.response.json`, `06_submit_challenge.response.json`).
- Read-tool `returns` lists corrected to observed response keys (from `_serialize_seed` `:1537-1558`, `_serialize_challenge` `:1561-1574`, `_serialize_standing` `:1595-1613`, `GET /standing` `:729`).

**Other docs that overclaim (for the integrator — NOT edited by me):**
- `SAB_POSITIONING_SCORECARD.md:23` — "MCP tools exist in `connectors/sab_mcp_tools.py`": manifest entries exist; no runnable tools/server.
- `docs/lanes/sab-agent-seeding-v1/MCP_A2A_PROFILE.md:39` — lists `sab.lease.validate` → `GET /api/v1/authority-leases/{lease_id}`, a nonexistent route; and its "Common Return Fields" block (~:48-57) plus "Mutation tools must return witness event IDs" (:26-27) do not match live responses (`witness_head` yes, `witness_event_id` no).
- `site/standing.html` — aspirational present tense (handled via standing.md divergence note, per write scope).
- `docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md:148` — "SHOULD expose MCP tools": correctly aspirational, no action needed.

## Task 4 — verifier + tests

`scripts/sab_verify.py`: resolves standing_id / lease_hash / seed_id / claim_id / claim_hash against the store (read-only sqlite URI `mode=ro`; never writes — unlike the API's lazy expiry at `:1913` it computes expiry at read time), falls back to dogfood `*.response.json` snapshots via `--receipts`. Answers `status` ∈ {active, challenged, revoked, expired, unknown, rehearsal_only} + `independence_status` graded conservatively per `docs/SAB_STANDING_SEMANTICS_V0.md` R2 (can never emit `cross_operator_*` because the store persists no operator identity — `agora/app.py:1268-1275`). Stored-active + rehearsal markers ⇒ `rehearsal_only`, not `active`.

Test run (exact command + output):

```
$ ./.venv/bin/python -m pytest tests/test_sab_standing_verifier.py -q
..........                                                               [100%]
10 passed in 0.30s
```

(Re-run after a wording fix: `10 passed in 0.24s`.) Covers: active, rehearsal_only downgrade, read-time expiry **with proof the DB row stays `active` (no write)**, revoked, challenged-seed-without-lease, claim_hash lookup, self-issued lease ⇒ independence `self`, nonexistent ⇒ `unknown`, vocabulary invariant, receipts fallback (skipif dir missing).

Full suite after all my changes: `./.venv/bin/python -m pytest -q` → **`383 passed, 2 xfailed, 1 warning in 16.78s`** (373+2xf from Agent 4's baseline + my 10).

## Task 5 — demo against Agent 4 output (exact commands + trimmed output)

```
$ ./.venv/bin/python scripts/sab_verify.py sab_seed_dogfood_2026-07-05_pytest_c4f56810 --compact
{... "status": "rehearsal_only", "raw_status": "active", "independence_status": "same_operator_distinct_keys",
 "standing_id": "sab_standing_dogfood_2026-07-05_c4f56810", "expires_at": "2026-08-04T14:35:04Z",
 "witness_event_count": 5, "rehearsal_markers": ["single_operator_rehearsal", "not_cross_operator_independent", "rehearsal"],
 "source": "sqlite_ro", "resolved_as": "standing_lease" ...}

$ ./.venv/bin/python scripts/sab_verify.py sab_standing_dogfood_2026-07-05_c4f56810 --compact
{... "status": "rehearsal_only", "independence_status": "same_operator_distinct_keys" ...}   # same lease

$ ./.venv/bin/python scripts/sab_verify.py sab_seed_does_not_exist_xyz --compact
{... "status": "unknown", "resolved_as": "none", "source": "none",
 "notes": ["identifier not found in any consulted source"] ...}

$ ./.venv/bin/python scripts/sab_verify.py sab_seed_master_vision_v1_ebe422aab149 --compact
{... "status": "challenged", "raw_status": "challenged", "independence_status": "undisclosed",
 "claim_hash": "2513c4d4...", "witness_event_count": 2, "source": "sqlite_ro" ...}

$ ./.venv/bin/python scripts/sab_verify.py sab_seed_dogfood_2026-07-05_pytest_c4f56810 \
    --db /tmp/does_not_exist.db --receipts docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood --compact
{... "status": "rehearsal_only", "source": "dogfood_receipts", "independence_status": "same_operator",
 "notes": ["database not found ...", "answered from receipt snapshot(s) [...8 files...] — receipts are point-in-time captures, not the live store", ...]}
```

Read-only proof against user data: after all verifier runs,
`SELECT status, updated_at FROM sab_standing_leases_v1 WHERE standing_id='sab_standing_dogfood_2026-07-05_c4f56810'`
→ `('active', '2026-07-05T14:35:04.461565+00:00')` — identical to Agent 4's recorded values; lease row count still 1.

## Honest limits

- The verifier's independence grade is inference from packet disclosures, not verification — the store keeps no operator identity (Agent 3 finding N1). It intentionally cannot say `cross_operator_*`.
- `rehearsal_only` detection is marker-string based; a claimant who omits the markers would verify `active`. Enforcement belongs in the API (PLANNED, per `docs/SAB_STANDING_SEMANTICS_V0.md`).
- `.well-known` file is rehearsal-grade and unserved by design of the current stack; no production URL exists or is claimed.

## Blockers

None.
