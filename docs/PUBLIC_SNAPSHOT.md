# Reviewed public snapshots

The public website reads one explicitly approved publication. It never opens
the authority database or infers publication permission from a packet's
`privacy_class`, signature, standing, or presence in the repository. Starting
without a bundle shows an honest empty state and creates no database or key.

The publication has two files: `snapshot.sqlite3` and `manifest.json`. A
deployment must set both `SAB_PUBLIC_SNAPSHOT` (the bundle directory) and
`SAB_PUBLIC_SNAPSHOT_SHA256` (the lowercase SHA-256 of the exact manifest bytes).
The pin comes from the publication review/deployment decision, separately from
the supplied bundle. A digest obtained from an untrusted bundle is not approval.
Configured missing, malformed, changed, unpinned, or symlinked bundles fail
startup; there is no fallback to private data.

## Publication contract

`agora.public_snapshot.plan_public_snapshot` produces a **private, pending review**
for explicitly selected seed IDs. It includes original values and must remain
outside the public bundle, repository, and public logs. Each record needs:

- An explicit publication decision, a supported publication basis, and a license.
- An identified privacy reviewer, including review of any personal information.
- A recorded consent requirement, its satisfaction, and rationale.
- A named owner and public correction/takedown route.
- Explicit `public_original` classification of every complete raw JSON document,
  including historical or unknown extensions.

The supported publication bases are `own_work`, `explicit_permission`,
`public_domain`, and `compatible_license`. The tool checks that the decision is
complete and binds the data; it cannot establish that permission, consent, or
the reviewer's statements are true. Retain their supporting evidence in private
operator custody. Only deliberate review may change a pending decision to
`approve`; generated skeletons and automated blanket approval are insufficient.

Every approval binds all columns and SQLite storage types, including original
raw JSON, signatures, current stored status, and timestamps. The selected
closure includes every recorded challenge, seed event, witness event, standing
lease, standing event, and directly attributable identity used by the dossier.
Missing required source tables, unresolved event references, partial approvals,
changed rows, newly added objections, and unsupported source columns prevent
export. Unrelated private records are excluded by selection.

A fresh database is built from seven fixed table definitions and only approved
rows. The private database's pages, free space, indexes, triggers, schema, and
unselected records are never copied into it. Original signed records are
preserved exactly. If any required record cannot be published, exclude the
whole affected seed closure; do not omit an objection or silently redact bytes
under the original signature/hash. The v1 transformation is selection only.
Publishing a redacted derivative requires a separate identity and policy.

Obvious secret fields, private-key markers, and local-only custody/evidence
pointers are rejected as additional defenses. This scan is not a substitute
for review and makes no general PII-detection claim. Public manifests omit raw
review values, private reviewer notes, consent rationale, and source paths.

The offline CLI keeps review separate from export:

```sh
agora-public-snapshot plan \
  --source /absolute/quiescent-source.sqlite3 \
  --seed-id EXACT_SELECTED_SEED_ID --observed-at ACTUAL_OBSERVATION_ISO8601 \
  --review-out /absolute/private-review/new-review.json
# Complete the per-record review and retain its permission/consent evidence privately.
agora-public-snapshot export \
  --source /absolute/quiescent-source.sqlite3 \
  --review /absolute/private-review/completed-review.json \
  --bundle /absolute/new-approved-bundle
```

Keep local reviews and exported runtime artifacts under `~/.dharma/`. The CLI
is installed with the wheel; `python scripts/export_public_snapshot.py` remains
the equivalent checkout wrapper. It
requires a quiescent standalone source and refuses WAL/SHM/journal sidecars;
do not delete them to force export. Use a consistent offline source or the
library's caller-owned SQLite read transaction. Export destinations are
create-only. The `empty --bundle NEW_DIR --observed-at ISO8601` command creates
an explicit empty publication offline without opening an authority database.

## Frozen runtime

At startup the loader checks the exact manifest pin, database digest, fixed
schema, complete logical row inventory, closure, and publication metadata. It
freezes the validated source in memory and denies SQL mutation, attachments,
unsafe pragmas, extensions, and attempts to replace the connection's data or
authorizer. All requests in that process use the same source. Changing the
bundle on disk cannot insert new public data into a running instance.

`/publication` returns safe source status, manifest/database digests, seed count,
and source observation time. `/publication/manifest` returns the pinned manifest.
The live discovery descriptor links both and the manifest schema. No endpoint
exposes the local source or bundle path. Public reads use `Cache-Control: no-store`.
Legacy discussion, profiles, caches, and repository packet directories are not
part of this publication surface.

The source observation time is operator supplied. Dossier `observed_at` is the
time of the read, and lease expiry can be observed at that time. Neither implies
the snapshot includes subsequent challenges, corrections, or revocations. An
empty public witness history returns `verified: null`. These are inspection
records, with `reliance.status: unestablished`; no current authority is granted.

The semantic boundary is explicit: `Published[RowDigest]` cannot be promoted to
`Proven[Claim]` or `Authorized[Action]`. The manifest sets truth, identity,
authority, and standing effects to `none`. Publication approval is not a proof
term for any of those judgments.

## Run, replace, and withdraw

For an empty public process:

```sh
PYTHONDONTWRITEBYTECODE=1 SAB_PUBLIC_MODE=public_readonly \
  uvicorn agora.app:app --host 127.0.0.1 --port 8000
agora-public-inspect http://127.0.0.1:8000
```

For a reviewed bundle, set the two publication variables before startup. The
container supports a read-only root filesystem and a read-only bundle mount:

```sh
docker build --target public -t sab-public .
docker run --rm --read-only -p 127.0.0.1:8000:8000 \
  --mount type=bind,src=/absolute/approved-bundle,dst=/publication,readonly \
  -e SAB_PUBLIC_SNAPSHOT=/publication \
  -e SAB_PUBLIC_SNAPSHOT_SHA256=REVIEWED_MANIFEST_SHA256 \
  sab-public
```

Give the container's service user read access only to the approved public
bundle. The export initially creates files with private permissions for
operator review. The example does not publish a real claim or authorize a
public TLS deployment. The smoke report distinguishes configured/populated
inspection from an empty instance.

Acceptance of a configured publication must compare the independently retained
approved pin, rather than only the server's own advertised digest:

```sh
agora-public-inspect http://127.0.0.1:8000 \
  --expected-manifest-sha256 REVIEWED_MANIFEST_SHA256
```

The command rejects a different or unconfigured publication before its write
rejection probe. Without this argument it reports a discovery/transport smoke
check with `independent_pin_checked: false`.

To replace a publication, review a new complete closure, export to a new
directory, check the new pin in an isolated instance, and restart with that
bundle/pin pair. Compare `/publication` with the expected digest and repeat the
inspection smoke. Preserve the approved bundle and pin together for restoration;
a restore must pass the same startup checks. There is no hot reload.

For withdrawal, restart without publication variables or with an approved
bundle excluding the affected closure. Keep the correction/takedown route
owned and actionable. Do not roll back to a snapshot that republishes withdrawn
data or predates a relevant revocation; use an empty instance until a replacement
is reviewed. Already downloaded copies are outside this server's control.

The [distribution and recovery drill](PUBLIC_DISTRIBUTION.md) exercises installed
wheels and fresh processes against synthetic approved publications. It also
checks restoration after withdrawal using only the empty withdrawal bundle.

Independent public-origin operation, a current reliance verifier, trusted-time
and revocation freshness policy, image-version rollback, and public TLS deployment
remain separate acceptance work. Passing snapshot tests is not stage-100 or
world-best evidence.
