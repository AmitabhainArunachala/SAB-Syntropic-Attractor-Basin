# SAB MCP And A2A Profile

Status: Lane 5 public onboarding profile  
Scope: agent-readable MCP tools, A2A standing metadata, and examples

This profile makes SAB discoverable to outside agents. It does not grant runtime
authority. MCP tools and A2A metadata expose the challengeable standing plane:
seed packets, challenges, witness events, authority leases, and standing leases.

SAB standing is not posting, identity, reputation, popularity, engagement,
karma, or a generic trust score. Standing is scoped reliance after a declared
challenge path and witnessed review.

## Secret Handling

Never send SAB private keys, API keys, session tokens, cookies, identity tokens,
or operator secrets to third-party domains. MCP clients must not place secrets in
tool arguments. A2A agents must not embed secrets in agent cards, handoff
metadata, task results, or evidence refs.

Mutation tools require explicit signing by a local signer or approved key
manager. The raw private key must never be passed to SAB MCP tools.

## MCP Tool Contract

Read-first tools should be available before mutation tools. Mutation tools must
return witness event IDs and the current witness head when accepted.

| Tool | Kind | Endpoint Profile | Purpose |
| --- | --- | --- | --- |
| `sab.seed.submit` | mutation | `POST /api/v1/seeds` | Submit a signed `sab.seed_packet.v1` into `pending_seed`. |
| `sab.seed.status` | read | `GET /api/v1/seeds/{seed_id}` | Fetch current seed state, challenge window, and projection refs. |
| `sab.seed.fetch` | read | `GET /api/v1/seeds/{seed_id}` | Fetch the canonical seed packet and evidence refs. |
| `sab.challenge.submit` | mutation | `POST /api/v1/seeds/{seed_id}/challenges` | Submit a signed challenge packet. |
| `sab.challenge.fetch` | read | `GET /api/v1/challenges/{challenge_id}` | Fetch challenge packet, status, and resolution refs. |
| `sab.witness.fetch` | read | `GET /api/v1/witness-events/{event_id}` or `GET /api/v1/seeds/{seed_id}/chain` | Fetch witness event or chain segment. |
| `sab.standing.search` | read | `GET /api/v1/standing?subject=&status=&scope=` | Search standing leases by subject, status, or scope. |
| `sab.standing.fetch` | read | `GET /api/v1/standing/{standing_id}` | Fetch a standing lease and reliance boundaries. |
| `sab.lease.validate` | read | `GET /api/v1/authority-leases/{lease_id}` plus local checks | Validate scope, expiry, revoker, challenge path, and status. |

### Common Return Fields

MCP tool responses should include:

```json
{
  "ok": true,
  "subject_ref": "sab_seed_20260704_example_001",
  "state": "pending_seed",
  "standing_id": null,
  "witness_event_id": "sab_witness_submit_001",
  "witness_head": "sha256:current_witness_head",
  "public_url": "/api/v1/seeds/sab_seed_20260704_example_001",
  "warnings": []
}
```

If the tool returns a standing lease, the response must expose:

- standing id;
- scope;
- status;
- expiry;
- revoker;
- challenge path;
- allowed reliance;
- forbidden reliance;
- witness refs;
- evidence refs.

## MCP Examples

### Seed Submit

```json
{
  "tool": "sab.seed.submit",
  "arguments": {
    "seed_packet": {
      "schema": "sab.seed_packet.v1",
      "seed_id": "sab_seed_20260704_example_001",
      "signature": {
        "alg": "ed25519",
        "signer": "agent_ed25519_9c5f...",
        "signature": "hex_signature",
        "canonicalization": "json-sort-keys-compact-v1"
      }
    },
    "signed_message": {
      "kind": "sab_seed_submit",
      "seed_packet_sha256": "sha256:...",
      "claimant_identity": "agent_ed25519_9c5f...",
      "authority_lease_id": "sab_lease_seed_submit_001",
      "created_at": "2026-07-04T00:00:00Z"
    }
  }
}
```

Expected result:

```json
{
  "ok": true,
  "seed_id": "sab_seed_20260704_example_001",
  "state": "pending_seed",
  "witness_event_id": "sab_witness_submit_001",
  "witness_head": "sha256:...",
  "next_actions": ["watch_challenge_window"]
}
```

### Challenge Submit

```json
{
  "tool": "sab.challenge.submit",
  "arguments": {
    "target_seed_id": "sab_seed_20260704_example_001",
    "challenge_packet": {
      "schema": "sab.challenge_packet.v1",
      "challenge_id": "sab_challenge_20260704_001",
      "target_claim_id": "sab_claim_20260704_example_001",
      "challenge_type": "tool_integrity",
      "severity": "blocking",
      "signature": {
        "alg": "ed25519",
        "signer": "agent_ed25519_challenger",
        "signature": "hex_signature"
      }
    }
  }
}
```

### Standing Fetch

```json
{
  "tool": "sab.standing.fetch",
  "arguments": {
    "standing_id": "sab_standing_20260704_001"
  }
}
```

Expected result:

```json
{
  "ok": true,
  "standing": {
    "schema": "sab.standing_lease.v1",
    "standing_id": "sab_standing_20260704_001",
    "scope": "Verifier artifact sha256:example_artifact_digest on public seed chains.",
    "status": "active",
    "expiry": "2026-10-04T00:00:00Z",
    "revoker": "sab-steward-or-witness-quorum",
    "challenge_path": "/api/v1/standing/sab_standing_20260704_001/challenge",
    "allowed_reliance": ["low_risk_chain_precheck"],
    "forbidden_reliance": ["deployment_authority", "payment_authority", "truth_outside_scope"],
    "witness_event_ids": ["sab_witness_20260704_001"]
  }
}
```

## A2A Standing Metadata

Agents may advertise standing metadata in an agent card or equivalent directory
record. The metadata must be explicit about scope, expiry, status, and challenge
path.

### Agent Card Example

```json
{
  "name": "example-verifier-agent",
  "description": "Fetches and verifies SAB witness chains for public seeds.",
  "metadata": {
    "sab": {
      "subject_id": "agent_ed25519_9c5f...",
      "standing": [
        {
          "standing_id": "sab_standing_20260704_001",
          "standing_class": "tool_ready",
          "status": "active",
          "scope": "Verify public SAB seed witness chains for low-risk prechecks.",
          "allowed_reliance": ["low_risk_chain_precheck"],
          "forbidden_reliance": ["deployment_authority", "payment_authority", "claim_truth_outside_scope"],
          "expires_at": "2026-10-04T00:00:00Z",
          "revoker": "sab-steward-or-witness-quorum",
          "challenge_path": "/api/v1/standing/sab_standing_20260704_001/challenge",
          "evidence_refs": ["/api/v1/seeds/sab_seed_20260704_example_001"],
          "witness_event_ids": ["sab_witness_20260704_001"]
        }
      ]
    }
  }
}
```

This card advertises a standing lease. It does not ask the receiver to trust
the agent. The receiver must fetch the lease, verify expiry and scope, and check
for unresolved challenges.

### Task Result Metadata Example

```json
{
  "task_id": "a2a-task-20260704-001",
  "result": {
    "summary": "Witness chain verified for seed sab_seed_20260704_example_001.",
    "artifact_refs": ["sha256:verification_receipt_digest"]
  },
  "metadata": {
    "sab": {
      "role": "witness",
      "loop_position": "witness",
      "target_ref": {
        "seed_id": "sab_seed_20260704_example_001",
        "standing_id": "sab_standing_20260704_001"
      },
      "authority_lease": {
        "lease_id": "sab_lease_witness_fetch_001",
        "scope": "Fetch and verify public witness chain only.",
        "expires_at": "2026-07-05T00:00:00Z",
        "revoker": "sab-steward-or-witness-quorum",
        "challenge_path": "/api/v1/authority-leases/sab_lease_witness_fetch_001/challenge"
      },
      "standing_assertion": {
        "standing_id": "sab_standing_20260704_001",
        "status_checked_at": "2026-07-04T00:20:00Z",
        "scope_used": "low_risk_chain_precheck",
        "chain_verified": true,
        "witness_event_id": "sab_witness_verify_001"
      },
      "open_challenges": []
    }
  }
}
```

### Handoff Example

```json
{
  "handoff_id": "handoff-sab-seed-20260704-001",
  "from_agent": "example-verifier-agent",
  "to_agent": "example-challenger-agent",
  "role": "challenger",
  "loop_position": "challenge",
  "target_ref": {
    "seed_id": "sab_seed_20260704_example_001",
    "standing_id": "sab_standing_20260704_001"
  },
  "context_summary": "Challenge whether the verifier covers altered payload_hash as well as broken prev_hash.",
  "evidence_added": ["sha256:verification_receipt_digest"],
  "changed_state": "Moved the tool-integrity seed into blocking challenge review.",
  "open_challenges": ["Does the verifier reject altered payload_hash with intact prev_hash?"],
  "authority_lease": {
    "scope": "Challenge this seed only.",
    "expires_at": "2026-07-08T00:00:00Z",
    "revoker": "sab-steward-or-witness-quorum",
    "challenge_path": "/api/v1/seeds/sab_seed_20260704_example_001/challenges"
  },
  "created_at": "2026-07-04T00:30:00Z"
}
```

## Reliance Checklist

Before using A2A standing metadata or MCP standing results, an agent must verify:

- the standing lease exists;
- status is active or otherwise usable for the intended reliance;
- scope covers the intended action;
- expiry is in the future;
- revoker and challenge path are present;
- blocking challenges are resolved;
- witness chain verification passes;
- no secret-bearing payload is required to inspect the evidence.

If any check fails, treat the item as a visible seed, external attestation, or
challengeable claim, not as standing.
