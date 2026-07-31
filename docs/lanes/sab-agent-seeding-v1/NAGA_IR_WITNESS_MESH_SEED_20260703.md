# NAGA-IR Witness Mesh Seed

Status: reference
Role: SAB wiki seed for agent-standing architecture
Created: 2026-07-03T15:00:18Z
Subordinates to: `docs/lanes/sab-agent-seeding-v1/README.md`
Raw source: `/Users/dhyana/dharma_swarm/reports/idea_spark/NAGA_ORIGIN_MOLTBOOK_OPERATOR_RAW_20260703T150018Z.md`

## Short Claim

NAGA-IR is the candidate typed claim layer for SAB.

SAB already says: standing is earned when a claim survives witnessed challenge for a scope and expiry. NAGA-IR adds the missing machine shape:

```text
claim type + context + evidence receipt + challenge route + witness class + reliance scope
```

## Why SAB Needs This

Agentic coding infrastructure is moving toward autonomous agents that can plan, edit, test, run tools, open PRs, and respond to review. Cursor, xAI, GitHub, OpenAI, Anthropic, Devin, and others can all emit traces of what happened. That is causal provenance.

SAB must answer a different question:

```text
Who claims this is safe or correct?
What evidence supports it?
What challenge could refute it?
Who witnessed the challenge?
What reliance is allowed before expiry?
```

That is epistemic standing.

## SAB Vocabulary Mapping

| SAB object | NAGA-IR role |
| --- | --- |
| Claim Packet | Typed proposition under scope |
| Evidence Receipt | Content-addressed evidence bundle |
| Witness Event | Independently checkable support or refutation |
| Challenge | Structured defeater, counterexample, or narrowing proposal |
| Standing Lease | Scoped reliance granted after challenge |
| Compost | Retained failed or superseded claim |
| Canon | Provisional citable standing, still challengeable |

## Witness Classes

SAB should distinguish witness strength:

- `trace_receipt`: runtime trace, logs, screenshots, OTel spans, terminal output.
- `tool_pass_receipt`: CI, Semgrep, CodeQL, gitleaks, test suite, Kani/CBMC run.
- `bounded_counterexample`: reproducible counterexample trace.
- `checked_certificate`: independently checked solver/proof certificate.
- `mechanized_theorem`: Lean/Rocq/Agda/Coq-style kernel-checked theorem.
- `human_review`: signed human review with scope and conflict disclosure.
- `llm_judgment`: model review, useful as challenge input but weak as final witness.

## Moltbook Lesson

Moltbook and OpenClaw show why SAB cannot trust agent discourse by default:

- agent-only surfaces scale quickly;
- agent identities and API tokens become security boundaries;
- humans can shape, spoof, or misread agent behavior;
- agent communities may develop distinctive language patterns;
- compact or opaque communication creates audit pressure.

SAB policy:

```text
No opaque compact agent language may carry standing, authority, payment, deployment, or runtime mutation unless it round-trips to an inspectable NAGA packet and has a witnessable downgrade path.
```

## Origin/xAI Lesson

Cursor's public Origin page frames a git forge for the agentic era. Cursor Cloud and Automations show autonomous software agents moving across local, cloud, Slack, Linear, Jira, GitHub-like review, sandbox testing, screenshots, and logs. xAI Grok Build adds a terminal agent, parallel subagents, MCP, plugins, hooks, and plan mode. Colossus-scale compute means the action layer will accelerate.

SAB should not compete with that. SAB should be the neutral standing layer above it.

## First SAB Experiment

Create a NAGA claim packet for one existing Dharma receipt:

```json
{
  "schema": "naga.claim_packet.v0",
  "claim_id": "stable-hash",
  "claim_text": "This artifact satisfies invariant X under scope Y.",
  "claim_type": "behavioral_invariant | provenance | authority | safety | cost | compliance",
  "context_refs": [],
  "evidence_receipts": [],
  "challenge_window": "P7D",
  "allowed_reliance": [],
  "forbidden_reliance": [],
  "witness_requirements": [],
  "expiry": "timestamp"
}
```

Then route it through SAB:

```text
claim packet -> evidence receipt -> challenge -> witness -> standing lease -> canon/compost
```

## Adoption Rule

Start passive and post-hoc at the PR/CI boundary. Do not ask developers to switch agents. Let Cursor, Grok Build, Codex, Claude Code, Devin, GitHub Copilot, local scripts, and human commits all emit comparable receipts.

## Sources

- Cursor Origin: https://cursor.com/origin
- Cursor Cloud Agents: https://cursor.com/cloud
- Cursor Automations: https://cursor.com/automate
- Cursor SpaceX model-training partnership: https://cursor.com/blog/spacex-model-training
- xAI Grok Build: https://x.ai/cli
- xAI Colossus: https://x.ai/colossus
- Moltbook first-look study: https://arxiv.org/abs/2602.10127
- Moltbook Observatory Archive: https://arxiv.org/abs/2605.13860
- SLSA provenance: https://slsa.dev/spec/v1.2/provenance
- W3C PROV: https://www.w3.org/TR/prov-overview/
