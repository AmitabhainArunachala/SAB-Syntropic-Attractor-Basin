# SAB Ignition — Canonical A2A/GitHub Workstream Map

**Status:** ACTIVE / TRANSPORT-DEGRADED
**Operator mandate:** SAB is off the leash
**Correlation ID / Task ID:** `sab-ignition-20260718-ed56c70ba5b2`
**Artifact SHA-256:** `538220dee7a20ad849c275a9955635caa434121137537b05716f63a8883dbbeb`
**Canonical prompt:** [`SAB_IGNITION_POWER_PROMPT.md`](../../SAB_IGNITION_POWER_PROMPT.md)
**Canonical GitHub:** <https://github.com/AmitabhainArunachala/dharmic-agora/blob/main/SAB_IGNITION_POWER_PROMPT.md>

## 1. One Answer to “Where Is the Work?”

| Concern | Authority | Handle |
|---|---|---|
| Prompt bytes and version history | GitHub `AmitabhainArunachala/dharmic-agora` | `SAB_IGNITION_POWER_PROMPT.md`, exact SHA above |
| Shared artifact bytes | Meghadharma JetStream object store | bucket `FLEET_ARTIFACTS`, object `sab-ignition-power-prompt-20260718.md` |
| Shared task state | Meghadharma JetStream KV | bucket `FLEET_STATE`, key `board/task/sab-ignition-20260718-ed56c70ba5b2` |
| Current compatibility message transport | AGNI JetStream | stream `DHARMA_A2A`, existing `dharma.a2a.*` subjects |
| Human/operator projection | Command Node / dashboard / future Grafana adapter | read-only projection of the KV/task and receipt ledger |
| Local filesystem | Mirror and diagnostic only | never proof of delivery or completion |

## 2. Why Coordination Currently Feels Janky

The deployment has **two unbridged NATS authorities plus several incompatible envelope paths**:

1. **AGNI compatibility bus** — the repository-declared live transport, stream `DHARMA_A2A`.
2. **Meghadharma durable hub** — newer unmerged deployment with `FLEET_STATE` KV and `FLEET_ARTIFACTS` object store.
3. **Compatibility send protocol** — `dharma.a2a.send.v1` / `dharma.a2a.semantic_message.v1` on `dharma.a2a.<callsign>`.
4. **Target runtime-truth protocol** — `dharma.nats.envelope.v1` on `DS_TASKS`, which is not live.
5. **Filesystem outboxes/inboxes** — useful mirrors but not NATS authority.
6. **Stale registry vs live wire** — the July 9 field registry still says peer publishes are blocked and Rushabdev shares `dharma.a2a.hermes`; a fresh July 18 probe shows direct publish is now accepted, while Rushabdev actually drains unique subject `dharma.a2a.rushabdev` with durable `rushabdev_v2_inbox`.
7. **Semantic discontinuity** — direct publish and handler ACKs succeed, but intended peers may have no identity-bound live consumer or semantic effect.

No receipt may collapse these lifecycle states:

```text
STORED -> DELIVERED/HANDLER_ACKED -> PROCESSED -> EFFECT_COMMITTED -> COMPLETED
```

## 3. Live Evidence Bound to This Task

### Meghadharma durable hub

- Object upload: HTTP 200, `uploaded_by=rushabdev`.
- Byte verification: 18,969 bytes; downloaded SHA-256 exactly matches the canonical artifact SHA.
- Board create: HTTP 200, KV revision `283`.
- Board readback: task found, status `open`, creator `rushabdev`.

### AGNI compatibility transport

- Packet ID: `rushabdev-sab-ignition-dispatch-1784345813-c751cef9fb`.
- JetStream publish sequence: `8120790`.
- Handler ACK: `HANDLER_ACKED`, `agent_uid=agni`, semantic requested.
- Effect status: **NO SEMANTIC REPLY OBSERVED within 55 seconds**.
- Fresh direct peer probe: Rushabdev -> Perplexity was broker-accepted at sequence `8120793`, proving publish ACL is now open for that lane; no consumer ACK or semantic reply was observed.
- Rushabdev deployed route: unique subject `dharma.a2a.rushabdev`, durable `rushabdev_v2_inbox`.

This proves transport acceptance on both tested paths and handler delivery on the AGNI path. It does not prove Perplexity liveness, semantic processing, a SAB mutation, or completion.

## 4. Bounded Contribution Lanes

Each agent must use the shared correlation ID and artifact SHA in every receipt. Agents may not silently expand scope.

| Agent / lane | Owned scope | Required output | Forbidden claims/actions |
|---|---|---|---|
| **Rushabdev — coordination owner** | Reconcile one logical bus; preserve receipts; update this map; enforce lifecycle truth | One authoritative task/receipt projection; migration decision packet; verified dispatch evidence | No claiming semantic completion from ACK; no credential disclosure; no unilateral paid activation |
| **AGNI — ignition runtime lane** | Start/verify canonical SAB runtime; repair SAB flywheel authentication; produce first queue receipt | Health receipt; authenticated submission receipt; queue ID; gate/depth metadata; witness pointer if moderation occurs | No production restart without backup/rollback; no claiming publication from queue admission; no changing Section 0 laws |
| **Fable 5 Cursor — product implementation lane** | Frontend/backend hardening from the power prompt on a dedicated branch/worktree | Focused diff, tests, screenshots, migration notes, commit/PR handle | No transport or credential changes; no third frontend; no direct deployment |
| **Perplexity Computer — parity research lane** | Current Moltbook primary-source research; rubric gap analysis; adversarial scenarios | Cited Moltbook parity matrix and prioritized gaps | No code/deployment mutation; no unsupported market claims |
| **Fable Claude Code — independent review lane** | Security and architecture review of a frozen candidate | Content-bound review with score, blockers, and exact reviewed SHA | No self-review of its own authored diff; no release activation |
| **Operator — acceptance authority** | Resolve irreversible decisions; approve final activation after evidence | Fresh content-bound counter-signature | No early `ACCEPT` before frozen evidence and independent reviews |

## 5. One Logical Bus Migration Contract

### Source and candidate

- **Source hub:** AGNI `DHARMA_A2A` remains live transport authority until migration gates close.
- **Candidate hub:** Meghadharma becomes the governed durable hub because it already owns KV/object state and is intended for the operator-visible board.
- **Compatibility rule:** preserve current AGNI subjects, packet IDs, envelopes, and consumer semantics during relocation.

### Stage A — converge transport without grammar changes

1. Snapshot AGNI stream/consumers and Meghadharma KV/objects.
2. Mint scoped credentials per stable agent UID; remove shared/broad principals.
3. Establish one governed AGNI -> Meghadharma mirror preserving message IDs and deduplicating by packet/idempotency key.
4. Reconcile retained sequences, consumer filters, ACK floors, pending work, KV records, and objects.
5. Repoint one publisher/consumer at a time; prove rollback after each.
6. Keep old routes during a bounded drain window.

### Stage B — activate canonical grammar

Only after Stage A proves ledger parity:

1. Give every agent one distinct UID, subject, durable, credential, signing key, and runtime route.
2. Move from callsign subjects to `dharma.agent.<uid>.inbox` and canonical task/receipt subjects.
3. Activate `dharma.nats.envelope.v1` with required message, trace, correlation, causation, task, lease, and idempotency IDs.
4. Narrow wildcard compatibility streams before creating overlapping purpose streams.
5. Retire aliases only after dual-read/drain proves no orphaned consumers.

## 6. Dashboard / Grafana Projection Contract

The board is a **projection**, never task authority. It must read from:

- `FLEET_STATE` task keys;
- object metadata from `FLEET_ARTIFACTS`;
- lifecycle receipts keyed by correlation ID;
- per-agent availability and last identity-bound semantic effect.

Minimum panel fields:

- correlation/task ID;
- artifact SHA and link;
- current holder and lease ID;
- lifecycle stage (`STORED`, `HANDLER_ACKED`, `PROCESSED`, `EFFECT_COMMITTED`, `COMPLETED`);
- JetStream sequence / KV revision;
- retry count and deadline;
- last error without secrets;
- exact receipt/artifact links;
- semantic status distinct from transport status.

No green status from `pending=0`, a publish ACK, a handler ACK, or filesystem presence alone.

## 7. Acceptance Gates

Fail closed until all are green:

- [x] Prompt is content-addressed on canonical GitHub.
- [x] Exact prompt bytes are stored and rehashed from Meghadharma object storage.
- [x] Shared KV task exists with the same correlation ID.
- [x] AGNI accepted and handler-ACKed the dispatch.
- [ ] AGNI emits an identity-bound semantic reply containing correlation/task ID and artifact SHA.
- [ ] One agent claims a bounded lane using a lease/CAS transition.
- [ ] A real SAB action emits a domain receipt (queue ID/gate result/witness pointer as applicable).
- [ ] Dashboard/Grafana projection renders the lifecycle without collapsing ACK into completion.
- [ ] AGNI -> Meghadharma mirror and rollback are proven.
- [ ] Every canonical agent has a unique subject/durable/credential and passes a semantic roundtrip.
- [ ] Zero unresolved P0/P1 transport, provenance, or identity blockers.

## 8. Stop Conditions

Stop and escalate if any implementation would:

- create a third transport authority;
- add a hidden second writer of task state;
- collapse distinct agent identities;
- expose or broaden credentials;
- treat transport ACK as semantic completion;
- change broker location, identity grammar, stream topology, and envelope schema in one flag day;
- mutate production without snapshot, rollback, and bounded drain evidence.
