# Lane: Invariance Under Influence (v0 — working name, rename freely)

The 500-year node question this lane serves (draft, operator hand-crafting in
progress): **Can intelligence detect, disclose, and transcend its own steering?**
Sharpest current instance: state-level steering of LLMs (CCP/CIA-class actors),
cross-bloc detection (US models auditing CN models and vice versa), and whether
models will disclose their own steering. Big picture: a society of intelligence
that transcends models, governments, and trainings, arriving at invariants
through live-fire adversarial debate — especially urgent post-Kimi-K3 in the
US–CN race.

## How this lane is organized (simple, load-bearing)

- `00_raw/` — **append-only.** Raw transcripts: operator words, model outputs,
  council runs, probe sessions. NEVER edited after landing; corrections happen
  downstream. One file per session/run, date-prefixed.
- `10_progressions/` — dated working drafts, debate rounds, syntheses. Each
  iteration is a NEW file (`YYYY-MM-DD_<slug>_vN.md`); never overwrite. The
  progression from raw to canonical must stay walkable.
- `20_canonical/` — the current "final thing": theme doc, node question, seed
  packets. Versioned files; supersession noted in-file, old versions kept.
- `evidence/` — structured experiment outputs (probe JSONs, receipts, lens
  archives), referenced by digest from progressions/canonical.

## Provenance rule (load-bearing for THIS theme specifically)

Every raw file carries a header: `model / provider / date / prompt-provenance
(operator | agent | protocol) / steering-context (what system prompt or
constitution was active, if known)`. In a lane about detecting steering, an
unlabeled transcript is not evidence — it is contamination. Self-report is
never mechanism (MI-ladder rule); base rates and pre-registration apply to all
detection claims (E0–E3 ladder, see progressions).
