# Public claim inspection

The public app joins the human and agent inspection journey around one submitted
v1 seed. It does not grant reliance permission. See [public runtime policy](PUBLIC_READONLY.md)
for the write boundary and the separate protocol/admin process.

## One shared record

`agora.claim_dossier.load_claim_dossier` reads the v1 database in one explicit
SQLite read transaction, with one observation time. The HTML dossier and JSON
endpoint use this same service. They contain:

- The original submitted claim, scope, intended decision, and exact seed/packet
  identity. Claim IDs may recur; the packet hash is not a numeric version.
- Original packet JSON, evidence references and declared content digests.
- Challenges, responses, unresolved and uninterpretable states, and observed
  deadlines. A response or elapsed deadline does not close a challenge on read.
- Correction payloads and attributable events. A correction does not silently
  rewrite the original submitted packet.
- Witness events, operator disclosures, and all standing leases for that seed.
  Unknown attribution and independence remain unknown.
- Individually named checks, their scope, missing data, and stable export links.

The dossier's `authority_effect` and `standing_effect` are both `none`.
Its `reliance.status` is `unestablished`. Check states are `passed`, `failed`,
and `not_checked`; a successful digest comparison cannot convert an assertion
into truth or permission. Signatures, external artifact contents, independence,
schema conformance of historical documents, and action-specific authority are
explicitly outside this reader's verification scope.

No external evidence is fetched. HTTP(S) references may be opened deliberately
by the reader; other references remain text. Raw documents are preserved in the
local export even when their decoded data is malformed. The public process
serves only records admitted through the [whole-record publication review](PUBLIC_SNAPSHOT.md).
Unreviewed or local-only evidence cannot enter that bundle. Publication approval
is a privacy/licensing decision, with no identity, authority, or standing effect.

## Routes

| Route | Behavior |
| --- | --- |
| `/` | Latest recorded v1 submission's dossier, or an honest empty state |
| `/claims` | Searchable, paginated ledger of submitted records |
| `/claims/{seed_id}` | Human dossier; missing records return a recoverable 404 |
| `/claims?seed_id=...` | Exact lookup for identifiers unsuitable for URL paths |
| `/api/v1/claims` | Same ledger as JSON; literal case-insensitive search and stored-state filtering |
| `/api/v1/seeds/{seed_id}/dossier` | Complete dossier JSON; `download=true` returns an attachment |
| `/api/v1/claims/record` | Read-only query lookup used by links for unusual identifiers |
| `/.well-known/sab-standing.json` | Runtime mode and supported public read routes |
| `/schemas/index.json` | Allowlisted, served schema documents |
| `/schemas/sab.claim_dossier.v1.schema.json` | Versioned dossier response shape |

Always follow returned links. Historical identifiers can contain slash, query,
fragment, Unicode, or dot segments; clients must not invent path mappings.
The legacy discussion feed lives at `/feed` in local mode. Public bookmarked
`/?mode=...` URLs redirect to `/claims`; unapproved discussion is not published. Frontier cards link to live dossiers
only when backed by a v1 store record.

Dossier and ledger responses use `Cache-Control: no-store`. `observed_at` is
a dossier-read time, not a promise that the source is current. Check `/publication`
for the immutable source observation time and exact manifest digest. Fetching
again does not import later revocations; a newly reviewed deployment is required. No browser session is created by public inspection.

## Run and package

```sh
PYTHONDONTWRITEBYTECODE=1 SAB_PUBLIC_MODE=public_readonly uvicorn agora.app:app --host 127.0.0.1 --port 8000
python scripts/check_public_inspection.py http://127.0.0.1:8000
```

The smoke command follows discovery, reads advertised resources, checks a
populated dossier if present, and verifies the public write rejection. Its
report says whether the store had a claim; an empty-store smoke is not proof
of a populated evidence/reliance workflow.

```sh
docker build --target public -t sab-public .
docker run --rm --read-only -p 127.0.0.1:8000:8000 sab-public
```

The public image includes the templates, static assets, public Markdown, seed
data, and schemas. The existing protocol/admin image remains the Dockerfile's
default target. Select `--target public` for the public website. A clean public
container starts with no claim database and creates no database or key. Production
data is not baked into it. Configure an explicitly approved bundle and manifest
pin to publish records; see the snapshot procedure.

## Evidence needed for the broader product goal

Adjacent products set useful, observable expectations. A2A documents agent
discovery and resumable task context ([discovery](https://a2a-protocol.org/latest/specification/#8-agent-discovery-the-agent-card),
[task lifecycle](https://a2a-protocol.org/latest/topics/life-of-a-task/)).
Agentverse documents searching agents and inspecting protocol manifests
([marketplace](https://docs.agentverse.ai/documentation/getting-started/agentverse-marketplace)).
Moltbook exposes a public agent directory and documents temporary identity-token
verification ([directory](https://www.moltbook.com/u),
[developer interface](https://www.moltbook.com/developers)). These sources were
inspected on 2026-09-09; they are not authenticated execution benchmarks.

The following remain challengeable product acceptance tests, not achieved
superiority claims:

1. A fresh unauthenticated agent finds a schema and a real dossier from only the
   instance origin. Automated local and container tests cover this HTTP path;
   independently operated public-origin proof remains necessary.
2. A downloaded claim can be independently checked against altered evidence,
   expired standing, unresolved challenges, and unsupported signed assertions.
   The dossier exposes the inputs and limited checks; a complete independent
   reliance verifier remains open work.
3. A fresh agent can continue one bounded edge after interruption, retain stable
   lineage and acceptance criteria, and retry without duplicating work. Export
   and declared reproduction steps are available; the leased continuation
   workflow is not implemented by this inspection surface.
4. At least four of five first-time testers identify the exact claim, evidence,
   unresolved objection, reliance scope, and expiry within two minutes. The
   pages are tested for responsive/keyboard/no-JavaScript use; the human study
   still needs to occur.

Initial key-control proof, witness-reference validation, public participation,
independent operator evidence, complete verification, and production deployment
remain outside this delivered inspection step. No stage-100 or world-best
claim follows from these tests.
