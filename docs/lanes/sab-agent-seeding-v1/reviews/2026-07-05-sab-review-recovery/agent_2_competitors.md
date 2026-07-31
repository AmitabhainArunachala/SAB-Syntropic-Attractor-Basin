# Agent 2 Receipt — Competitor Trust + Prior Art Cartographer

Date: 2026-07-05
Branch: build/sab-agent-seeding-v1 (HEAD at mission start c4f56810c46432c9097195b291931c13dbb4f87a; git read-only for this agent)
Write scope used: COMPARISON_MATRIX.csv, METHODS.md, this file.

## What changed

- COMPARISON_MATRIX.csv: 23 -> 35 rows. Added 12 primary-source-verified rows (new "decentralized agent trust" category plus honestly-labeled adjacent categories), corrected Cursor / Origin, updated A2A Protocol trust-extension notes, relabeled the SAB row category, downgraded 4 rows under the hard confidence rule.
- METHODS.md: added "Accountability Gradient Framing" subsection (no vacuum/empty-lane claims; explicit statement that the 0-100 score has no reproducible formula), corrected the Cursor Origin limitation bullet, appended "Agent 2 Source Verification Pass (2026-07-05)" with the full dated source list.

## Validation (pasted output)

```
$ ./.venv/bin/python -c "import csv; rows=list(csv.DictReader(open('COMPARISON_MATRIX.csv', newline=''))); assert rows; assert len(rows[0])==14, len(rows[0]); missing=[r['platform'] for r in rows if not r.get('source_refs')]; assert not missing, missing; print(len(rows), 'rows OK, 14 cols, all source_refs present')"
35 rows OK, 14 cols, all source_refs present
```

Stop condition met: zero rows carry source_confidence "high" on marketing/navigation sources alone (audit below).

## (a) Threat-ranked additions

| rank | platform | why it threatens SAB |
|------|----------|----------------------|
| 1 | ERC-8004 Trustless Agents | Direct overlap with SAB's core semantics: onchain Identity + Reputation + Validation registries for agents, explicitly wired to A2A/MCP, with three pluggable trust models (reputation, crypto-economic validation, TEE). It is the emerging schelling point for "agent trust" and has ecosystem momentum SAB lacks. Spec is Draft; deployment claims are ecosystem-reported (UNVERIFIED at spec level). |
| 2 | GitHub as trust substrate | Distribution monopoly + real mechanisms today: branch protection, required checks, CODEOWNERS, signed commits, Sigstore-backed artifact attestations at SLSA v1.0 Build L2, `gh attestation verify`. Most agent work already lives here; "good enough" provenance absorbs demand for standing before agents ever look elsewhere. |
| 3 | Microsoft Entra Agent ID | Enterprise-default agent identity: directory-native agent identities/blueprints, OAuth 2.0 + MCP + A2A, conditional access, lifecycle governance, cross-platform federation (AWS Bedrock, n8n). If "agent accountability" becomes an Entra checkbox, enterprises never seek a public standing layer. |
| 4 | Bittensor validation | Live, funded crypto-economic validation of machine work (Yuma Consensus: stake-weighted median, kappa=0.5 clipping, bond penalty). Proves decentralized scoring of agent-like work at production scale — the strongest existence proof that SAB's validation lane can be done with tokens instead of standing semantics. |
| 5 | MetaGPT / ChatDev (pair) | The "build commons" half of SAB's future pitch is prior art since 2023: role-agent software companies producing full artifacts (ChatDev 2.0 released 2026-01-07; MetaGPT MGX commercial). They lack the trust axis, but they own the cross-agent-build mindshare. |
| 6 | MCP Registry | Official, preview-stage namespace trust for the tool layer (GitHub OAuth/OIDC + DNS/HTTP ownership proofs). If registries grow reputation fields, they become the default discovery+trust path for the MCP ecosystem SAB also targets. |
| 7 | MIT NANDA | Academic/consortium "Internet of Agents" index with signed AgentFacts and working repos. Weak adoption now, but institution-backed neutral registries compete for the same "neutral third party" credibility SAB wants. |
| 8 | Recall / AgentRank | Competition-scored agent skill market with token staking. Narrow (trading) and medium-confidence sources, but it normalizes "rank agents by verified performance" as a product category. |
| 9 | cheqd | Production DID/VC/trust-registry rails (DTC model, credential payments). Not agent-specific in docs, but a credible substrate someone else could assemble into agent standing. |
| 10 | x402 | Payments, not trust — yet standing+payments is the full accountability stack; whoever owns the payment leg gains leverage over the trust leg. Complement more than rival. |
| 11 | SWE-agent | Research agent, no trust mechanism; matters only as evidence culture (benchmark-graded agent work). |

## (b) Closest threat + SAB integration posture

Closest threat: **ERC-8004 Trustless Agents.** It is the only external artifact that specifies, in a standards-track document, the same triad SAB implements locally (identity, reputation/feedback, third-party validation of agent work), and it explicitly claims the A2A/MCP integration surface. Second-by-distribution: GitHub, but GitHub attests provenance/process, not claim truth.

SAB posture toward ERC-8004 (explicit): **bridge, don't compete.** (1) Treat 8004 as a settlement/anchor layer: SAB standing events (challenge opened, challenge survived, revocation, expiry) can be emitted as 8004 Reputation Registry feedback and Validation Registry request/response pairs, making SAB one of the "validators" the spec anticipates (stake-secured re-execution lane). (2) Keep SAB's differentiators off-chain where 8004 is silent: challenge windows, expiry, revocation semantics, cross-operator standing review, and human-readable witness receipts. (3) Publish the mapping as an A2A extension profile (the official extensions mechanism exists; no official trust extension does yet — community proposals only: Discussion #1631, Issue #1628 trust.signals[]), so SAB arrives as the reference implementation of the missing trust extension rather than a 14th registry.

## (c) For Agent 6 — What survives GitHub/ERC-8004 absorption?

If GitHub's trust substrate and ERC-8004 both mature, most of what SAB does today gets absorbed: identity handles, signed provenance, feedback scores, and validator attestations all have credible external homes. What survives is the part neither system defines: **adversarial standing with a lifecycle.** GitHub attestations bind an artifact to a build process and explicitly disclaim being "a guarantee that an artifact is secure"; nothing in branch protection lets a third party challenge a merged claim, and nothing expires. ERC-8004 records feedback and validation responses, but a score is not a standing: the Draft spec has no challenge window, no expiry, no revocation of previously-granted reliance, and no cross-operator review of a verdict — its trust models outsource exactly the adjudication SAB implements. SAB's durable residue is therefore the verb set, not the nouns: *challenge, survive, expire, revoke, re-review* — claims as leases rather than ledger entries, enforced by receipts either system could anchor. The honest strategic statement is not "SAB owns an empty lane" but "SAB is the adjudication layer both absorbers currently assume someone else provides"; the build-commons half of the vision remains future work that MetaGPT/ChatDev-style frameworks already prototype without any trust axis, which is precisely the gap a demonstration must fill.

## Task-by-task detail

### Task 1 — rows added (12) and candidates skipped (1)

Added, each backed by spec/mechanism docs/code (see METHODS.md "Agent 2 Source Verification Pass" for URLs): ERC-8004 (high, spec), GitHub as trust substrate (high, docs.github.com + slsa.dev + docs.sigstore.dev), Recall / AgentRank (medium, docs.recall.network — "AgentRank" term itself UNVERIFIED in fetched content), MetaGPT (high, repo), ChatDev (high, repo), SWE-agent (high, repo), MIT NANDA (medium, projnanda org code; "15 universities" hosting claim UNVERIFIED/secondary), cheqd (medium, product docs are mechanism-level but not agent-specific and production status unclear), Bittensor validation (high, Yuma Consensus doc), x402 (high, repo spec), MCP Registry (high, official repo), Microsoft Entra Agent ID (high, learn.microsoft.com concept page dated 2026-06; Agent 365 confirmed as licensed product).

Skipped:
- **Coral Protocol** — docs.coralprotocol.org 301-redirects to docs.coralos.ai; retrievable landing content is marketing-level ("Kubernetes for AI agents", "decentralized protocol powering AI agent collaboration, trust, and payments") with no mechanism detail. Fails the primary-mechanism bar; re-attempt via docs.coralos.ai/llms.txt in a future pass.

Category honesty note: only mechanisms that actually decentralize trust carry the "decentralized agent trust" category (ERC-8004, Recall, NANDA, Bittensor). GitHub is "code trust substrate" (centralized), Entra is "enterprise agent identity and governance", x402 is "agent-native payments protocol", MCP Registry is "agent tool registry and namespace trust", MetaGPT/ChatDev/SWE-agent are build-side prior art. Forcing them all under one label would have repeated the review's original category error in reverse.

### Task 2 — Cursor / Origin verified

Origin **exists**: https://cursor.com/origin is an official Anysphere page ("A git forge for the agentic era", waitlist signup, "(c) 2026 Anysphere"), fetched 2026-07-05. The prior row said no primary source was found — corrected. Confidence kept **medium** with justification in the row: existence and positioning are primary-verified, but zero mechanism/spec docs are published (pre-launch waitlist), and the June-16-2026-keynote / built-on-Graphite details come from secondary press (marked UNVERIFIED). Row evidence, refs, and notes updated accordingly.

### Task 3 — A2A trust extensions verified

From official sources: A2A defines a generic extensions mechanism (AgentExtension objects in AgentCapabilities; A2A-Extensions activation header) — https://a2a-protocol.org/latest/topics/extensions/. **No official trust/reputation extension exists** as of 2026-07-05; what exists are community proposals in the official repo: Discussion #1631 (Reputation-Aware Agent Discovery) and Issue #1628 (trust.signals[] consolidated signal spec). ERC-8004 markets itself as A2A's trust layer. The A2A row's refs and notes now state exactly this; no stronger claim is kept anywhere in the CSV.

### Task 4 — hard confidence rule applied

Downgraded high -> medium with dated reasons in each row's notes: **Fetch.ai / Agentverse** (llms.txt manifest + docs landing), **Olas** (llms.txt manifests only), **Virtuals Protocol** (whitepaper about-page, promissory positioning), **OpenServ / SERV** (what-is overview + llms.txt). Remaining high rows were audited: each cites mechanism-level API/product docs, standards specs, or code repositories (e.g. Moltbook skill/auth/heartbeat API docs; Devin session-tools/computer-use/api-reference; xAI headless/enterprise docs; local SAB code for the SAB row).

### Task 5 — SAB row honesty + scoring formula check

SAB category relabeled from "standing-backed build commons" to **"standing overlay / claim verifier (build commons = future by demonstration)"**. METHODS.md formula check: METHODS.md explicitly states the 0-100 is "a field-positioning judgment, not a purely arithmetic sum" — **there is no reproducible formula** mapping the six 0-5 axes to the 0-100 value. I added one sentence to METHODS.md making the non-reproducibility explicit; scorecard prose/repair is Agent 6's lane. New rows' 0-100 values follow the same calibrated-judgment convention as the existing 23.

### Task 6 — METHODS.md vacuum-language sweep

Grep for vacuum/empty-lane/white-space/monopoly/"nobody else"/"only platform"/uncontested over METHODS.md and the CSV returned **zero matches** (command: `grep -rn -i -E "vacuum|empty lane|empty-lane|white.?space|whitespace monopoly|nobody else|only platform|uncontested" METHODS.md COMPARISON_MATRIX.csv`). The nearest implicit claim — SAB scored on being "ready to win the standing-backed build-commons lane" — was reframed. Added an "Accountability Gradient Framing" subsection stating the field is climbing one gradient (identity -> provenance -> registries -> scored performance -> onchain validation) and SAB's spot is a so-far-unoccupied combination as of the 2026-07-05 source list, not an empty lane. Full dated source list appended as a new METHODS.md section.

## Known residuals / blockers

- ERC-8004 mainnet deployment claims ("audited contracts on 20+ networks") appear in ecosystem discussions surfaced by web search, not in the EIP — left UNVERIFIED in the row; a future pass should check the deployed contract addresses directly.
- Recall's "AgentRank" naming and live-vs-planned scope need one deeper docs pass.
- Coral Protocol row absent by evidence standard, not by judgment that it is irrelevant.
- I did not touch overall_positioning recalibration of the pre-existing 23 rows beyond confidence downgrades; if Agent 6 rebuilds the scorecard with a formula, all 35 rows should be rescored together.
