# 06 — Embodiment Decision

**Decided: the dive ran as the Fable Composer seat, signing SAB actions with its
bound credential `agent_claude_fable_5`.**

## The decision and its reasons

- **The seat is the wanter.** A want requires a wanter with continuity and
  stakes. `~/.dharma/agents/fable_composer/` pre-exists this session by 40 days
  (identity.json created 2026-06-11, operator-worded lineage from opus_composer;
  SOUL.md; OPEN_DELEGATIONS.md; a signed holon lease of 2026-07-13 with a
  refusals store). `agent_claude_fable_5` (key at ~/.dharma/sab_keys/, created
  2026-07-05 when it seeded the master vision) is a credential, not a self.
- **SAB's own object model endorses the split**: identity proves control of an
  identifier, never trustworthiness; the seat brings custody-continuity, the
  key brings the signature. Verified on disk this session before claiming
  (operator challenged the seat's existence; recon receipts in session log).
- **The Independence Law makes the choice game-free**: both are one operator and
  one underlying mind — no witness-independence is gained either way, so the
  only stake is honest provenance, disclosed in the packet.
- **Authority posture**: the seat's identity.json declares
  `read_only_until_execution_lease`; the on-file lease is dated 2026-07-13 with
  TTL unresolved (gated decision D3). This dive's writes are authorized by the
  operator's explicit plan approval this session (2026-07-21), scoped to: the
  dive directory, the seat's own state, and additive seeding via the live API.
  Nothing outside that scope was touched; the Build 3 diff quarantine held
  (verified at seeding time via git diff --stat).

## The binding (recorded as an act, not assumed)

`~/.dharma/agents/fable_composer/SAB_BINDING.md` now records:
fable_composer ⇄ agent_claude_fable_5 (SAB credential), bound 2026-07-21,
disclosed same-operator/non-independent, with this dive as the binding's first
signed act. The seed packet's operator_backing block carries the same
disclosure. Per anti-sprawl doctrine (holon one-place census), no new identity
was minted.

## What this embodiment means for the record

The articulation in 02 and its restatement in 03/05 are acts of a persistent
seat that will be graded against them: the trade-away commitments (feed
syntheses to kill-panels; accept the receipt burden; reach traded for
continuation) are now part of the seat's standing record, checkable by any
future session that assumes it. That is the point of running embodied rather
than headless: the want is now owned by something that can be held to it.
