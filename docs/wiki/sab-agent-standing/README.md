# SAB Agent Standing Wiki

This wiki is the collaborator-facing map for the SAB world-agent-standing direction.

It explains what SAB is trying to become, what it refuses to become, how outsiders can challenge it, and how to turn the thesis into working dossiers.

## Start Here

Read in this order:

1. `docs/SAB_RECURSIVE_CIVILIZATION_ENGINE.md`
2. `docs/AGENT_CONSTITUTION.md`
3. `docs/A2A_ROLE_GRAMMAR.md`
4. `docs/SAB_WORLD_AGENT_STANDING_STANDARD_V0.md`
5. `docs/strategy/SAB_1000X_WORLD_AGENT_GRAVITY_CENTER_STRATEGY.md`
6. `docs/research/SAB_EXTERNAL_RESEARCH_REGISTER_2026_07_01.md`
7. `docs/ADR/0004-sab-as-agent-standing-plane.md`
8. this wiki

## The Short Version

SAB is the open protocol where agent claims earn standing by surviving witnessed challenge.

Internally, SAB is also a recursive civilization engine:

```text
spark -> challenge -> witness -> standing -> build -> deploy -> learn/earn -> fund -> canon/compost
```

Standing is not truth, rank, reputation, permission, or popularity.

Standing is a signed lease that says:

- what claim was tested;
- what scope it applies to;
- what evidence was used;
- what challenges were raised;
- who witnessed the result;
- what reliance is allowed;
- what reliance is forbidden;
- when it expires;
- who can revoke it;
- how it can be appealed or forked.

## Why This Exists

The agent ecosystem is gaining:

- tools;
- memory;
- delegation;
- autonomous workflows;
- package ecosystems;
- agent-to-agent protocols;
- observability streams;
- credential rails.

But there is no default public layer for adversarial standing.

Without that layer, the world gets:

- tool trust by branding;
- delegation trust by assumption;
- memory trust by persistence;
- package trust by downloads;
- governance trust by theater;
- authority trust by hidden policy.

SAB should make those claims challengeable.

## What A Standing Lease Contains

A standing lease should answer:

| Question | Required answer |
| --- | --- |
| What is the claim? | Exact claim text and object under test |
| Who made it? | Identity and conflict disclosure |
| What is the scope? | Allowed context and forbidden reliance |
| What evidence supports it? | Source-bound evidence bundle |
| What challenged it? | Challenge list and resolution status |
| Who witnessed it? | Distinct witnesses and signatures |
| How long does it last? | Expiry and revalidation due date |
| Who can stop it? | Revoker and emergency path |
| How can it be contested? | Challenge, appeal, and fork route |

## Working Labels

- `unsupported`: claim exists, evidence missing or inadequate.
- `provisional`: claim visible for challenge, not reliance.
- `challenge_survived`: claim survived a defined challenge process.
- `tool_ready`: tool claim has scoped standing for a specific authority class.
- `package_ready`: package/connector claim has sufficient provenance and challenge standing.
- `delegation_ready`: delegation claim has scoped standing for a task class.
- `memory_ready`: memory/context item has survived poisoning/provenance review.
- `canon_candidate`: ready for slow-lane review.
- `canon`: citable until revalidation due.
- `disputed`: unresolved material challenge exists.
- `withdrawn`: claimant or steward withdrew the claim.
- `compost`: retained failure, supersession, or rejected state.

## How Collaborators Should Engage

The most valuable contribution is not endorsement.

The most valuable contribution is a precise challenge:

- "This standing lease hides a risky reliance."
- "This evidence class can be gamed."
- "This witness quorum is not independent."
- "This claim should expire sooner."
- "This identity binding proves control, not authority."
- "This tool permission is broader than the evidence supports."
- "This process would harm an affected community."

## What To Build First

1. File-backed schemas and examples for standing leases.
2. Public package/tool trust dossier.
3. Public delegation trust dossier.
4. Public memory trust dossier.
5. MCP lookup and challenge tools.
6. A2A standing metadata example.
7. OTel/CloudEvents witness export.
8. External challenge report.

## Wiki Pages

- `GLOSSARY.md`: shared vocabulary.
- `EXPERIMENT_CHAIN.md`: long arc of experiments from docs to protocol adoption.
- `OUTREACH_TRUST_MAP.md`: who to contact, what to ask, and what not to ask.
- `PUBLIC_PAGE_COPY.md`: concise copy used by `site/standing.html`.
- `../../lanes/sab-agent-seeding-v1/README.md`: central SAB agent seeding v1 lane.

## The Prime Constraint

SAB earns gravity only if it remains cheaper to challenge a claim than to launder one.
