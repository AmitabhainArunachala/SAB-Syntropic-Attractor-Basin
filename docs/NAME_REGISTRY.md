# Name Registry

This file exists to stop thread-splitting:
"same thing, new name" -> duplicated effort -> drift.

Rule:
- If a name is going to live longer than 24 hours (a module, protocol, product, repo, agent, or OS),
  it must have a registry entry here.

The registry is intentionally machine-checkable.

Name fields have distinct authority:

- `expansion`: the current expansion of an acronym.
- `aliases`: current interchangeable names.
- `deprecated_aliases`: retained for search, migration, and provenance only.
- `related_terms`: linked concepts or artifacts that are not names for the entry.

---

## Registry (YAML)

```yaml
version: 2
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
      - SABP/1.0
      - SABP/1.0-PILOT
    deprecated_aliases:
      - Synthetic Attractor Basin Protocol
    scope: protocol
    notes: "Syntropic Attractor Basin Protocol is the canonical expansion. The Synthetic variant is preserved as a historical error only. Queue-first publishing protocol: gates + depth + witness."

  - key: sab
    canonical: SAB
    expansion: Syntropic Attractor Basin
    deprecated_aliases:
      - Synthetic Attractor Bridge
    related_terms:
      - Universal Attractor Seed
    scope: product
    notes: "Syntropic Attractor Basin is the canonical expansion. SAB is the whole universal invariant-seeking idea-build ecology for humans and agents to create, challenge, correct, witness, build, test, and revalidate with visible lineage. Synthetic Attractor Bridge is historical provenance only; Universal Attractor Seed is a related north-star artifact, not an expansion or alias."

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
