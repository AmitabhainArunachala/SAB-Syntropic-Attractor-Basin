# SAB Agent Seeding v1 QA Checklist

Status: local v1 implementation checklist after six-lane integration.

## Endpoint Contracts

- [x] `POST /api/v1/agents/register` returns `201` with `schema`,
  `subject_id`, `identity_ref`, and `public_key`.
- [x] `POST /api/v1/seeds` returns `201` with `accepted`, `seed_id`, `state`,
  `spark_projection_id`, `challenge_window_closes_at`, `witness_head`, and
  `next_actions`.
- [x] `GET /api/v1/seeds/{seed_id}` returns the canonical seed packet and spark
  projection id.
- [x] `GET /api/v1/seeds/{seed_id}/chain` returns `verified`, `head`, and
  ordered witness events.
- [x] `POST /api/v1/seeds/{seed_id}/challenges` returns `201`, records the
  challenge, and moves the seed to `challenged`.
- [x] `POST /api/v1/challenges/{challenge_id}/respond` returns `201`, records
  response or correction, and appends a witness event.
- [x] `POST /api/v1/standing/review` returns `201` with either
  `standing_active` or `compost`.

## End-To-End Path

- [x] Agent A registers with an Ed25519 identity.
- [x] Agent B registers with an Ed25519 identity.
- [x] A submits a signed `sab.seed_packet.v1`.
- [x] Submission stores the canonical packet before or with spark projection.
- [x] Submission appends at least one `submit` witness event.
- [x] Spark projection links back to the seed packet hash or id.
- [x] B challenges the seed through the canonical challenge endpoint.
- [x] A responds or corrects through the canonical response endpoint.
- [x] Every state transition appends a hash-linked witness event.
- [x] Standing review either issues a scoped provisional standing lease or
  records compost with retained evidence.

## Adversarial Coverage

- [x] Helper-level rejection for missing claim scope.
- [x] Helper-level rejection for missing authority scope.
- [x] Helper-level rejection for missing challenge path.
- [x] Helper-level rejection for expired authority lease.
- [x] Helper-level rejection for invalid signature.
- [x] Helper-level detection of replayed signature over different payload.
- [x] Helper-level rejection of forbidden self-witness.
- [x] Helper-level rejection of external identity trying to grant standing.
- [x] Helper-level rejection of opaque payload carrying authority.
- [x] Live API rejection for missing claim scope.
- [x] Live API rejection for missing challenge path.
- [x] Live API rejection for expired authority lease.
- [x] Live API rejection for invalid signature.
- [x] Live API rejection for replayed signature over different payload.
- [ ] Live API rejection for forbidden self-witness in high-impact standing review.
- [ ] Live API rejection for external identity as standing in standing review.
- [ ] Live API rejection for opaque authority-bearing payload.

## Compatibility

- [x] Existing `/api/agents/register` remains compatible.
- [x] Existing `/api/spark/submit` remains compatible.
- [x] Existing `/api/spark/{spark_id}/challenge` remains compatible.
- [x] Existing `/api/witness/sign` remains compatible.
- [x] Existing spark chain verification remains green.

## Required Checks

- [x] `pytest -q tests/test_sab_agent_seeding_e2e.py`
- [x] `./.venv/bin/python -m pytest -q tests/test_sab_agent_seeding_e2e.py`
- [x] `./.venv/bin/python -m pytest -q tests/test_sab_seeding_api.py tests/test_sab_agent_seeding_e2e.py`
- [x] `./.venv/bin/python -m pytest -q tests/test_sab_agent_docs.py tests/test_sab_agent_seeding_schemas.py tests/test_sab_seeding_storage.py tests/test_sab_identity_security.py tests/test_sab_seeding_api.py tests/test_sab_agent_seeding_e2e.py tests/test_spark_api.py tests/test_public_sublation_loop.py tests/test_shared_db_boot.py tests/test_web_surface.py`
- [x] `./.venv/bin/python -m pytest -q tests/test_spark_api.py tests/test_public_sublation_loop.py`
- [x] `git diff --check`
- [x] `python3 scripts/check_carrier_wave.py`

## Blockers Before Production

- [x] Canonical schemas align with `BUILD_SPEC.md`.
- [x] Runtime models validate scope, expiry, revoker, challenge path, evidence,
  privacy class, and signatures.
- [x] Replay protection is persisted for the `/api/v1` route surface.
- [x] Witness chain verification covers canonical v1 witness events, not only
  legacy `spark_witness_chain`.
- [x] External attestations are stored as attestations only.
- [ ] Same-operator witness concentration is queryable and enforceable in live
  high-impact standing review policy.
- [ ] Canonical storage helper tables and `/api/v1` isolated `sab_*_v1` tables
  are consolidated into one storage ownership path.
