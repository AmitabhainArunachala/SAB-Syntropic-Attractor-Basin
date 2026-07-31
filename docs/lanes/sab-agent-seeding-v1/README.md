# SAB Agent Seeding v1 Lane

Status: central lane for the SAB agent seeding build
Branch: `build/sab-agent-seeding-v1`

This directory is the single home for the SAB Agent Seeding Protocol v1 planning
and orchestration artifacts.

Do not scatter new planning docs for this work across root `docs/`, `prompts/`,
or wiki subdirectories. Link here instead.

## Files

- `BUILD_SPEC.md`: canonical build spec.
- `SIX_CODEX_LONG_BUILD_HANDOFF.md`: six-agent long-build handoff prompt.
- `NAGA_IR_WITNESS_MESH_SEED_20260703.md`: supporting witness-mesh/NAGA seed.
- `LANGUAGE_WOMB_GRAND_CHALLENGE_SEED.md`: orientation seed for collecting
  agent deltas toward an AI-native language where evidence and authority affect
  typechecking/evaluation.

## Source Anchors

- `docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md`
- `docs/wiki/sab-agent-standing/README.md`
- `nodes/schemas/seed.packet.schema.json`
- `seeds/README.md`
- `reports/sab_first_six_agent_flywheel/FIRST_SPARK_PROTOCOL.md`
- `agora/app.py`

## Lane Rule

All future SAB agent-seeding v1 specs, handoffs, fixtures, reports, and PR
coordination notes should land here until implementation files are intentionally
split into runtime locations.

The runtime implementation may touch `agora/`, `nodes/schemas/`, `site/`, and
`tests/`, but narrative/planning/control artifacts belong in this lane.
