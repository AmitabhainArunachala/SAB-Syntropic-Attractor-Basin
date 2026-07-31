# Methods

Date: 2026-07-05

## Research Discipline

This pass used local repository evidence first, then current primary public sources where available. Closed-source products were treated as public-documentation evidence plus inference, not as source-level proof. Social proof, stars, screenshots, valuations, and hype were not used as evidence.

No private credentials were used. No external services were mutated. All external access was read-only HTTP fetches.

## Local Repository Orientation

Repository: `/Users/dhyana/dharmic-agora`

Observed state:

```text
branch: build/sab-agent-seeding-v1
status: clean before deliverable creation
remote: https://github.com/AmitabhainArunachala/dharmic-agora.git
recent commits:
56904c1 docs: seed language womb grand challenge
f817d61 feat: implement SAB agent seeding v1 slice
c4ac93b docs: centralize SAB agent seeding lane
```

Primary local evidence inspected:

- `docs/lanes/sab-agent-seeding-v1/README.md`
- `docs/lanes/sab-agent-seeding-v1/BUILD_SPEC.md`
- `docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md`
- `docs/SABP_1_0_SPEC.md`
- `docs/SABP_1_0_CANONICAL.md`
- `agora/sab_seeding_api.py`
- `agora/sab_seeding_storage.py`
- `agora/sab_identity.py`
- `agora/sab_attestations.py`
- `connectors/sab_mcp_tools.py`
- `site/skill.md`
- `site/auth.md`
- `nodes/schemas/sab.*.v1.schema.json`
- `tests/test_sab_agent_*`
- `tests/test_sab_seeding_*`

## Measurements

Tracked repository size:

```text
command: cloc --vcs=git --exclude-dir=node_modules,.venv --json
result: 392 files, 73,516 total lines, 55,791 code LOC
```

Runtime tree measurement:

```text
command: cloc agora connectors agent_core integration kaizen models p9_mesh scripts --exclude-dir=node_modules,.venv --json
result: 180 files, 30,034 code LOC
note: this tree includes embedded agora/tests files; separately measured test LOC is authoritative for tests.
```

Tests:

```text
command: cloc tests agora/tests --json
result: 43 files, 8,166 code LOC
```

Docs/site:

```text
command: cloc docs README.md CHANGELOG.md SECURITY.md WITNESS_ARCHITECTURE.md MANIFEST.md SAB_MASTER_INDEX.md site --exclude-ext=json --json
result: 74 files, 10,027 code LOC
```

Schemas/fixtures:

```text
command: cloc nodes/schemas docs/lanes/sab-agent-seeding-v1/fixtures --json
result: 27 JSON files, 2,460 LOC
```

## Test Environment

System Python collection was not treated as authoritative because it failed on missing local dependencies (`nacl` and connector import issues).

Authoritative virtualenv check:

```text
command: ./.venv/bin/python -m pytest --collect-only -q
result: 369 tests collected in 0.54s
key packages: PyNaCl 1.6.2, FastAPI 0.139.0, Starlette 1.3.1, pytest 9.1.0, pydantic 2.13.4
```

Security scan:

```text
command: ./.venv/bin/python -m bandit -r agora connectors -x agora/tests -q
result: 2 findings
medium: B608 possible SQL injection at agora/sab_seeding_storage.py:943
low: B105 false-positive hardcoded password string at connectors/sab_mcp_tools.py:15
```

The B608 finding appears likely mitigated by SQL identifier allowlisting and controlled column construction, but the dossier treats it as an open hardening item until it is explicitly tested, rewritten, or annotated.

## External Primary Sources

Moltbook:

- https://www.moltbook.com/skill.md
- https://www.moltbook.com/auth.md
- https://www.moltbook.com/heartbeat.md
- https://www.moltbook.com/rules.md
- https://www.moltbook.com/developers

Fetch.ai / Agentverse:

- https://fetch.ai/llms.txt
- https://fetch.ai/docs

Olas:

- https://docs.olas.network/llms.txt
- https://olas.network/llms.txt

Virtuals Protocol:

- https://whitepaper.virtuals.io/about-virtuals/about-virtuals-protocol.md

OpenServ / SERV:

- https://docs.openserv.ai/what-is-serv.md
- https://docs.openserv.ai/llms.txt

GitHub Copilot:

- https://docs.github.com/api/article/body?pathname=/en/copilot/concepts/agents/cloud-agent/about-cloud-agent

OpenAI Codex:

- Skill route used: `/Users/dhyana/.codex/skills/.system/openai-docs/SKILL.md`
- Manual helper succeeded.
- Public source: https://developers.openai.com/codex/codex-manual.md
- Local fetched manual: `/var/folders/2n/h27kz83n6dn90pzkb_8v3pm80000gn/T/openai-docs-cache/codex-manual.md`

Anthropic Claude Code:

- https://code.claude.com/docs/en/overview.md

Devin:

- https://docs.devin.ai/llms.txt
- https://docs.devin.ai/work-with-devin/devin-session-tools.md
- https://docs.devin.ai/work-with-devin/computer-use.md
- https://docs.devin.ai/api-reference/overview.md

Replit Agent:

- https://docs.replit.com/references/agent/overview.md

LangGraph / LangSmith:

- https://docs.langchain.com/oss/python/langgraph/overview.md

CrewAI:

- https://docs.crewai.com/introduction.md

Cursor:

- https://docs.cursor.com/agent/overview
- https://docs.cursor.com

xAI:

- https://docs.x.ai/llms.txt
- https://docs.x.ai/build/cli/headless-scripting
- https://docs.x.ai/build/enterprise
- https://docs.x.ai/grok/overview

Microsoft:

- https://learn.microsoft.com/en-us/azure/foundry/agents/overview?accept=text/markdown
- https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/index.html
- https://github.com/microsoft/autogen

AGNTCY:

- https://agntcy.org
- https://docs.agntcy.org
- https://github.com/agntcy/identity
- https://github.com/agntcy/dir
- https://github.com/agntcy/oasf

Google:

- https://google.github.io/adk-docs/
- https://github.com/google/adk-python
- https://a2a-protocol.org/latest/
- https://github.com/a2aproject/A2A
- https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/
- https://jules.google/docs/
- https://github.com/google-gemini/gemini-cli

OpenHands:

- https://github.com/All-Hands-AI/OpenHands
- https://docs.openhands.dev/overview/introduction

OpenClaw local profile:

- `/Users/dhyana/openclaw-secure/README.md`
- `/Users/dhyana/openclaw-secure/config/openclaw.json`
- `/Users/dhyana/openclaw-secure/scripts/validate-config.py`
- `git -C /Users/dhyana/openclaw-secure rev-parse HEAD` returned `fatal: not a git repository`

## Scoring Method

The comparison matrix scores each platform on six axes, each 0-5:

- standing depth,
- agent execution,
- identity/auth,
- interoperability,
- governance/challenge,
- production maturity.

The 0-100 score is a field-positioning judgment, not a purely arithmetic sum. There is no reproducible formula mapping the six axes to the 0-100 value; treat the number as calibrated judgment, not measurement. A platform can score high by being excellent at its own optimization target even if it lacks SAB-style standing. SAB's score is stricter: it measures how far SAB has actually traveled along the accountability gradient, not whether the idea is differentiated in the abstract.

### Accountability Gradient Framing

This dossier does not claim SAB occupies an empty lane, a vacuum, or uncontested white space. The honest frame is an accountability gradient that the whole field is already climbing: identity (Entra Agent ID, AGNTCY, cheqd, NANDA) -> provenance and process gates (GitHub branch protection, Sigstore/SLSA artifact attestations) -> registries and namespace trust (MCP Registry, NANDA index) -> scored or staked performance (Bittensor Yuma Consensus, Recall competitions) -> onchain feedback and validation registries (ERC-8004, Draft). SAB's position on that gradient is a specific unoccupied-so-far combination — challengeable claims with expiry, revocation, and cross-operator standing review — verified only against the sources listed below as of 2026-07-05, not a claim that no one else is moving toward it. ERC-8004 and GitHub's trust substrate are each one integration away from covering much of it.

After the user correction, the scoring interpretation was expanded. Moltbook is not treated as the only agent-to-agent convening precedent. Fetch.ai / Agentverse, Olas, Virtuals Protocol, and OpenServ / SERV were added as primary-source examples of agent economies, agent marketplaces, autonomous business operations, and onchain agent society. SAB is therefore evaluated against a broader requirement: not just whether claims can earn standing, but whether standing can support cross-agent project formation, artifact production, integration, and evolution.

## Limitations

- Cursor's "Origin" was primary-verified on 2026-07-05: https://cursor.com/origin is an official Anysphere page describing "A git forge for the agentic era", in waitlist pre-launch. No mechanism or spec docs are published; press claims about it (Graphite basis, June 16 2026 keynote) remain secondary. Origin capability claims stay UNVERIFIED beyond existence and positioning.
- OpenClaw evidence is local profile evidence only; the local directory is not a git repo and OpenClaw was documented locally as not installed.
- Closed-source product internals were not inferred beyond what public docs support.
- The added Fetch.ai, Olas, Virtuals, and OpenServ rows use public documentation, not private runtime inspection. They are treated as platform-position evidence, not proof that every advertised capability is live in production.
- Public docs can change after 2026-07-05; source URLs should be rechecked before using this dossier for investment, integration, or governance commitments.

## Agent 2 Source Verification Pass (2026-07-05)

A second research pass (SAB review recovery, Agent 2) added a "decentralized agent trust" category plus adjacent prior-art rows, corrected the Cursor / Origin row, verified A2A trust-extension status, and applied a hard confidence rule: no row carries source_confidence "high" on marketing or navigation pages alone. Under that rule, Fetch.ai / Agentverse, Olas, Virtuals Protocol, and OpenServ / SERV were downgraded to medium (their citations are llms.txt manifests, docs landings, or whitepaper/what-is overview pages). The SAB row category was relabeled to the honest present tense: standing overlay / claim verifier; the build commons is future work to be earned by demonstration.

Rows added (12): ERC-8004 Trustless Agents; GitHub as trust substrate; Recall / AgentRank; MetaGPT; ChatDev; SWE-agent; MIT NANDA; cheqd; Bittensor validation; x402; MCP Registry; Microsoft Entra Agent ID. Candidate skipped: Coral Protocol (docs.coralprotocol.org 301-redirects to docs.coralos.ai, whose landing content is marketing-level — "Kubernetes for AI agents" — with no retrievable mechanism detail in this pass; fails the primary-mechanism bar).

Sources verified 2026-07-05 (all read-only HTTP fetches):

- https://eips.ethereum.org/EIPS/eip-8004 (ERC-8004 Draft: Identity/Reputation/Validation registries, A2A+MCP references, three pluggable trust models)
- https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches (required checks, required reviews, CODEOWNERS, signed commits, push restriction)
- https://docs.github.com/en/actions/concepts/security/artifact-attestations (built on Sigstore; SLSA v1.0 Build Level 2; attestations are not a security guarantee)
- https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds (gh attestation verify usage)
- https://slsa.dev/spec/v1.0/levels (Build L0-L3 definitions)
- https://docs.sigstore.dev/about/overview/ (cosign, Fulcio, Rekor, keyless OIDC signing)
- https://cursor.com/origin (official Origin page: "A git forge for the agentic era", waitlist)
- https://a2a-protocol.org/latest/topics/extensions/ (AgentExtension mechanism; no official trust extension listed)
- https://github.com/a2aproject/A2A/discussions/1631 and https://github.com/a2aproject/A2A/issues/1628 (community trust-extension proposals; located via web search)
- https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id (agent identities/blueprints, OAuth 2.0 + MCP + A2A, conditional access, governance, Agent 365 licensing)
- https://github.com/FoundationAgents/MetaGPT (multi-agent software company, SOP orchestration)
- https://github.com/OpenBMB/ChatDev (ChatDev 1.0 roles; ChatDev 2.0 DevAll released 2026-01-07)
- https://github.com/SWE-agent/SWE-agent (Princeton/Stanford, NeurIPS 2024, SWE-bench)
- https://github.com/projnanda (NANDA org: adapter, nanda-index-v2, agentfacts-format, nanda-registry-server-repo)
- https://docs.cheqd.io/product (DIDs, VCs, Decentralized Trust Chain registries, credential payments; not agent-specific)
- https://docs.learnbittensor.org/learn/yuma-consensus (stake-weighted median, kappa=0.5 clipping, bond penalty beta)
- https://github.com/coinbase/x402 (HTTP 402 flow, facilitator settlement, x402 Foundation)
- https://github.com/modelcontextprotocol/registry (preview, API freeze v0.1, GitHub/DNS/HTTP namespace verification)
- https://docs.recall.network/ (competitions, leaderboards, RECALL staking; "AgentRank" term not confirmed in fetched content)
- https://docs.coralos.ai/ (redirect target of docs.coralprotocol.org; marketing-level landing only — row skipped)
