# SAB Standing Profile (v0, rehearsal-grade)

Status of this document: **truthful profile of the local implementation** at
branch `build/sab-agent-seeding-v1`, commit `c4f56810c46432c9097195b291931c13dbb4f87a`
(2026-07-05). Everything stated in the present tense is implemented in this
repository and cited to a file and line. Everything else is marked **PLANNED**.
The only standing produced so far is **single-operator rehearsal** standing:
one operator controlled claimant, challenger, and witness
(`docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/agent_4_dogfood_loop.md`).
No production deployment of this API is claimed here. Never treat any private
keys or secret material as part of a standing exchange; identity proves control
of a key, and posting, feed visibility, engagement, karma, or reputation never
equals standing.

This page is the markdown twin of `site/standing.html`. Divergences are listed
at the bottom.

## What a standing record is, concretely

A standing lease is a row in `sab_standing_leases_v1`
(DDL: `agora/sab_seeding_api.py:866-886`), issued through
`POST /api/v1/standing/review` (`agora/sab_seeding_api.py:591`) only after the
subject seed has at least one challenge, zero pending challenges, and at least
one witness event (`agora/sab_seeding_api.py:606-611`). It is served by
`GET /api/v1/standing/{standing_id}` (`agora/sab_seeding_api.py:688`) and
searchable via `GET /api/v1/standing` (`agora/sab_seeding_api.py:696`).

## Profile fields

| Field | Local implementation today | Cite |
|---|---|---|
| `claim_hash` | Implemented as the seed `packet_hash`: sha256 over the canonical (sorted-keys, compact) seed packet JSON without its signature. Returned by `GET /api/v1/seeds/{seed_id}`. | `agora/sab_seeding_api.py:926` (`_hash_json`), `:784-799` (column), `:1549` (serialized) |
| `scope` | Free-text reliance scope stored on the lease and returned verbatim. No machine-readable scope grammar exists yet (**PLANNED**). | `agora/sab_seeding_api.py:866-886`, `:1600` |
| `status` | Stored lease status. Live code vocabulary is `{active, challenged, revoked, expired, canon, compost}` (`STANDING_STATUSES`). This profile's vocabulary is `{active, challenged, revoked, expired, unknown, rehearsal_only}`; the mapping is performed by the read-only verifier (`canon`→`active` family, `compost`→`revoked` with note, `unknown` = unresolved identifier, `rehearsal_only` = stored-active but carrying single-operator rehearsal markers). `rehearsal_only` and `unknown` are verifier-computed, not stored. | `agora/sab_seeding_api.py:30`, `scripts/sab_verify.py` |
| `expires_at` | Stored as the lease `expiry` column and required at issuance; the API accepts `expiry` or `expires_at` as input. Expiry is enforced lazily: reads through the API mark an overdue lease `expired` and witness the transition. The standalone verifier computes expiry at read time without writing. | `agora/sab_seeding_api.py:1905-1910`, `:1913-1951`, `scripts/sab_verify.py` |
| `challenge_uri` | Stored per lease as `challenge_path`; the live challenge route is `POST /api/v1/standing/{standing_id}/challenge`. | `agora/sab_seeding_api.py:866-886`, `:731` |
| `revocation_uri` | The live revoke route is `POST /api/v1/standing/{standing_id}/revoke`. The lease itself stores a `revoker` **identity**, not a URI; a first-class stored revocation URI is **PLANNED**. | `agora/sab_seeding_api.py:735`, `:1605` |
| `witness_quorum` | Defined in the lease JSON schema (`minimum_witnesses`, `witnesses`, `diversity_policy`) but **not enforced by the live API**: issuance validates only `scope`, `purpose`, `revoker`, `challenge_path`, `expiry`, and requires ≥1 witness event of any kind. Quorum/diversity enforcement is **PLANNED**. | `nodes/schemas/sab.standing_lease.v1.schema.json:20,85-116`; `agora/sab_seeding_api.py:1901-1906`, `:606-611` |
| `independence_status` | **Not stored or enforced anywhere in the live API.** The six-grade enum (`self` / `same_operator` / `undisclosed` / `same_operator_distinct_keys` / `cross_operator_unverified` / `cross_operator_attested`) is specified in `docs/SAB_STANDING_SEMANTICS_V0.md`. The independence library exists but has zero callers in `agora/` (`validate_witness_independence`, `agora/sab_identity.py:491`), and both register endpoints discard `operator_backing` (`agora/sab_seeding_api.py:88-98`, `agora/app.py:1268-1275`). The read-only verifier grades conservatively from packet disclosures and can never emit `cross_operator_*`. Enforcement is **PLANNED**. | `agora/sab_identity.py:491`, `docs/SAB_STANDING_SEMANTICS_V0.md`, `scripts/sab_verify.py` |
| `replay_recipe` | Carried inside the seed packet as `challenge_plan.falsification_routes` plus the claim text (the dogfood seed's recipe is "re-run `./.venv/bin/python -m pytest -q` at the pinned commit and compare the tail"). Not a dedicated top-level field (**PLANNED**). | `site/schemas/sab.seed_packet.v1.schema.json`; example: `docs/.../dogfood/12_get_seed_final.response.json` |
| `standing_uri` | Local route only: `GET /api/v1/standing/{standing_id}`. **No public production URL exists for this API**; `deploy/sab-agora.nginx.conf` describes an intended deployment, and this repo makes no claim that it is live. | `agora/sab_seeding_api.py:688` |

## Status vocabulary

- `active` — lease stored `active` (or `canon`), unexpired, no rehearsal markers.
- `challenged` — lease or subject seed is under an open challenge
  (`agora/sab_seeding_api.py:731`, seed states `:15-27`).
- `revoked` — lease revoked via `POST /api/v1/standing/{standing_id}/revoke`
  (`agora/sab_seeding_api.py:735`); `compost` maps here with a note.
- `expired` — lease `expiry` has passed (lazily witnessed by the API at
  `agora/sab_seeding_api.py:1913-1951`, or computed read-only by the verifier).
- `unknown` — the identifier resolves to nothing, or to a seed with no lease.
- `rehearsal_only` — stored-active lease whose packet/lease carries
  single-operator rehearsal markers (`single_operator_rehearsal`,
  `not_cross_operator_independent`). Every standing lease issued in this
  repository to date (exactly one, `sab_standing_dogfood_2026-07-05_c4f56810`)
  verifies as `rehearsal_only`.

## Verify a standing record locally

```
./.venv/bin/python scripts/sab_verify.py <standing_id|seed_id|claim_id|claim_hash>
./.venv/bin/python scripts/sab_verify.py <id> --receipts docs/lanes/sab-agent-seeding-v1/reviews/2026-07-05-sab-review-recovery/dogfood
```

Read-only (SQLite `mode=ro`); answers `status` + `independence_status` in the
vocabularies above. Tests: `tests/test_sab_standing_verifier.py`.

A machine-readable descriptor of this profile sits at
`site/.well-known/sab-standing.json`. That path is **not currently served by
anything**: the FastAPI app serves only an explicit whitelist of `site/` files
(`agora/app.py:1204-1246`), the Dockerfile copies only `agora/`
(`Dockerfile:16`), and the sample nginx config denies all dot-paths
(`deploy/sab-agora.nginx.conf`, `location ~ /\.`). Serving it is **PLANNED**.

## Known enforcement gaps (disclosed, current as of 2026-07-05)

1. Witness independence is not enforced at the API: `witness_plan.forbidden_witnesses`
   is never consulted by `POST /api/v1/witness-events` (`agora/sab_seeding_api.py:487-544`);
   a claimant can self-affirm live (defect D2, `agent_4_dogfood_loop.md`).
2. Router-registered identities fail the canonical `AgentIdentityV1` validator
   (subject-id derivation mismatch, `agora/sab_seeding_api.py:932-933` vs
   `agora/sab_identity.py:47-50`; defect D1).
3. No challenge deadline enforcement, no transition-matrix finality, no role
   checks on adjudication, no economics (bonds/stakes) — detailed with cites in
   `docs/SAB_STANDING_SEMANTICS_V0.md`.

## Divergences from `site/standing.html`

`standing.html` is a vision/marketing surface. Its present-tense sentences
"SAB gives those claims a public test" and "Distinct reviewers record signed
events" describe the intended protocol, not the current implementation: there
is no public deployment, and reviewer distinctness is not enforced (gap 1
above). Its interop bullets ("MCP should query standing…") are correctly
phrased as "should" — the MCP surface today is a tool **manifest** only, with
no bound server (`connectors/sab_mcp_tools.py`). This page is the normative,
implementation-true profile; where the two disagree, trust this one.
