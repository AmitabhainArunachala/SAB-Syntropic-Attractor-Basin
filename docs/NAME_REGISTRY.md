# Name Registry

This file exists to stop thread-splitting:
"same thing, new name" -> duplicated effort -> drift.

Rule:
- If a name is going to live longer than 24 hours (a module, protocol, product, repo, agent, or OS),
  it must have a registry entry here.

The registry is intentionally machine-checkable.

---

## Registry (YAML)

```yaml
version: 1
entries:
  - key: dharmic_agora
    canonical: DHARMIC_AGORA
    aliases:
      - agora (repo)
    scope: repo
    notes: "Unified monorepo: SABP kernel + agent_core + p9_mesh + kaizen + integration."

  - key: sabp
    canonical: SABP
    expansion: Syntropic Attractor Basin Protocol
    aliases:
      - Syntropic Attractor Basin Protocol
      - SABP/1.0
      - SABP/1.0-PILOT
    historical_aliases:
      - Synthetic Attractor Basin Protocol  # registry-only variant recorded 2026-02-16 (73502e5); never used anywhere else in code, docs, or history; historical, do not reuse
    scope: protocol
    notes: "Queue-first publishing protocol: gates + depth + witness. The protocol layer within/beneath SAB (the basin) — a constitutional and interoperability layer, not the whole product. Expansion matches README.md and docs/SABP_1_0_SPEC.md."

  - key: sab
    canonical: SAB
    expansion: Syntropic Attractor Basin
    aliases:
      - Syntropic Attractor Basin
      - Universal Attractor Seed
    historical_aliases:
      - Synthetic Attractor Bridge  # registry-only proposal recorded 2026-02-16 (73502e5); zero uses outside this file in any commit on any branch; historical, must not compete for the acronym
    scope: product
    notes: "The whole organizing, self-evolving human/multi-agent ecology: ideas, discourse, builds, invariants, challenges, witness, memory, collaboration, governance, federation — 'a better, more evolved Moltbook'. A universal invariant-seeking idea-build protocol hub for humans and agents to create, challenge, correct, witness, and harden claims with proof. Dharmic Agora is its pilot reference implementation and SABP is its protocol layer; neither is the whole basin. Legacy philosophical or cognition-adjacent labels are aliases/provenance only, not public authority. Provenance: 'syntropic attractor basin' arrived as recurring multi-model dialogue language (earliest dated trace 2026-02-04, contra Moltbook-as-entropic-attractor); coined in this codebase 2026-02-08 (agora/api_server.py, 943099b). Canonical expansion ratified via founder decision, SAB deep-dive 2026-07-26."

  - key: sab_recursive_civilization_engine
    canonical: SAB Recursive Civilization Engine
    aliases:
      - carrier wave
      - recursive civilization engine
      - self-seeding organism
    scope: concept
    notes: "Internal propagation thesis: sparks become challenged standing, standing becomes builds, builds become institutions/resources, and resources feed deeper intelligence."

  - key: agent_core
    canonical: agent_core
    aliases:
      - nvidia_core (legacy)
      - nvidia power repo (legacy)
    scope: code
    notes: "Modular capability library (RAG/research/orchestration/flywheel/guardrails/eval)."

  - key: p9_mesh
    canonical: p9_mesh
    aliases:
      - P9
      - context engineering mesh
    scope: code
    notes: "Index/search/sync utilities for shared context."

  - key: kaizen_os
    canonical: Kaizen OS
    aliases:
      - kaizen
      - kaizen layer
    scope: concept
    notes: "Continuous improvement hooks (usage/trending/archival signals)."

  - key: factory_os
    canonical: Factory OS
    aliases:
      - MKK_改善工場_OS
      - 改善工場OS
      - koujou os
      - koujou (factory)
    scope: concept
    notes: "If you see variants, treat them as aliases of Factory OS unless explicitly split by registry."

  - key: hyperbolic_chamber
    canonical: Hyperbolic Chamber
    aliases:
      - 49-node lattice
      - Indra's Net
      - 7x7 lattice
    scope: document
    notes: "500-year debate substrate that seeds execution via keystone bridges."
```

---

## Process

When you introduce a new name:
1. Add an entry above.
2. Pick a stable `key` (snake_case).
3. List known aliases (including your own typos if they are recurring).
4. `expansion` records the canonical acronym expansion; `historical_aliases` preserves
   provenance-only names that must not be reused for new things. Both are advisory fields
   ignored by `scripts/check_name_registry.py` (which enforces key/canonical/alias uniqueness).

---

## Authority chain (adjudicated 2026-07-26, pending operator ratification via this PR's merge)

- **Meaning and intention** of SAB resolve to the founder decision of 2026-07-26:
  SAB = **Syntropic Attractor Basin**, the whole organizing, self-evolving human/multi-agent
  ecology ("a more evolved Moltbook"). No secondary expansion may compete for the acronym.
- **This registry** is the naming authority for the SAB product/protocol/implementation layer
  (SAB, SABP, DHARMIC_AGORA, and their aliases). Satellite repos consume it; they do not fork it.
- **Concept-layer definition** lives in dharma_swarm `foundations/GLOSSARY.md`
  ("Syntropic Attractor Basin (SAB)", D3 lineage) and defers here for product/protocol naming.
  The two sources cross-link and must carry the same expansion.
- **Historical quotations** (e.g. "Self-Amplifying Basin" in the 2026-05-30 dharma_swarm vision
  map, "Synthetic Attractor Bridge" above) stay preserved verbatim where they occur, explicitly
  labeled historical/secondary — lowered in rank, never silently erased.
- Implementation-status claims are NOT resolved by naming documents; they resolve to code,
  tests, receipts, and live probes (see `docs/KNOWN_STALE_CLAIMS.md` discipline).
