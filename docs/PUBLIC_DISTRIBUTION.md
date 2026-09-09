# Installed public artifacts and recovery

The `dharmic-agora` wheel supplies the public app, templates, seven static
assets, five agent documents, four served schemas, and its runtime dependencies.
It also installs `agora-public-snapshot` for offline publication review/export and
`agora-public-inspect` for the public HTTP contract. Existing repository scripts
remain wrappers around those same implementations.

For a reviewed wheel, create an isolated environment outside the checkout:

```sh
python3 -m venv ~/.dharma/sab/public-env
~/.dharma/sab/public-env/bin/python -m pip install /absolute/reviewed/dharmic_agora-0.3.1-py3-none-any.whl
PYTHONDONTWRITEBYTECODE=1 SAB_PUBLIC_MODE=public_readonly \
  ~/.dharma/sab/public-env/bin/agora-web
```

This starts an empty publication. A configured publication additionally requires
the reviewed bundle and its separately retained manifest pin, as described in
[PUBLIC_SNAPSHOT.md](PUBLIC_SNAPSHOT.md). The protocol/admin commands remain a
separate surface. Public inspection never initializes their authority database.

## Resource ownership

Canonical Markdown remains in `site/`; canonical served schemas remain in
`nodes/schemas/`. The build stages only the nine named files into
`agora/_public_resources/`. These generated copies live in build output, with
no second source tree to edit. `MANIFEST.in` carries the canonical inputs and
build helper into source distributions, so rebuilding a wheel preserves them.
Templates and the seven named assets are explicit package data.

The runtime reads installed resource bytes without extracting temporary files.
A source checkout or the Docker source layout may use canonical inputs anchored
to its own module root, marked by `pyproject.toml` and the build helper. It never
searches the working directory. An incomplete packaged resource tree fails;
the old `site/schemas` seed-schema fallback is removed. Repository seed lists,
databases, keys, reviews, and runtime receipts are not public package resources.

## Clean installation checks

The CI distribution job builds a direct wheel and a wheel from the source
distribution on Python 3.10 and 3.12. Each gets a fresh environment with only
runtime dependencies. From outside the checkout it runs:

```sh
/absolute/installed-env/bin/python -I -B /absolute/source/scripts/check_installed_public.py \
  --source /absolute/source --wheel /absolute/reviewed.whl \
  --output /absolute/new-inspection-output
```

The check verifies that imports come from the installed environment, installed
application files match the exact wheel, and all served resource bytes match
canonical sources. It exercises empty HTML, discovery, schemas, readiness,
unapproved-route rejection, write rejection, and the installed offline CLI.
Publication status and freshness metadata are checked as historical observations,
with currentness unestablished. Package files must remain unchanged; private database/key sentinel paths must
remain absent. `-I -B` excludes checkout/PYTHONPATH imports and bytecode writes.

## Synthetic process recovery drill

From that installed environment and an unrelated working directory, run:

```sh
/absolute/installed-env/bin/python -I -B /absolute/source/scripts/rehearse_public_recovery.py \
  --artifact-sha256 INDEPENDENTLY_RECORDED_WHEEL_SHA256 \
  --output /absolute/new-recovery-output
```

Use a new output directory under `~/.dharma/` locally. The drill owns only its
loopback child processes. It creates synthetic original/history publications A
and B and an explicit empty withdrawal publication W, with separate approved
pins. Its fixture approvals concern invented records only. They are not an
approval procedure for real data, and fixture signatures establish no identity.

The drill cold-starts A, restarts it, serves a restored backup, validates B as a
candidate, and replaces A with B while preserving the original submission. It
requires invalid-pin startup failure, then starts a fresh process from an
eligible backup. It withdraws all fixture claims using W and repeats recovery
with W. It never restores A or B after withdrawal. Each phase checks the expected
publication pin, exact manifest bytes, stable record commitments, the HTTP
inspection contract, and absence of private runtime files. The private receipt
records phases, process outcomes, artifact identity, and cleanup.

This proves a bounded process and bundle recovery path for the tested artifact.
It does not prove rollback between image versions, operation behind public TLS,
independent operators, trusted time, revocation freshness, or broader C7/stage
acceptance. A valid old manifest cannot by itself reveal a later withdrawal;
operators must retain recovery eligibility and must not republish withdrawn
data. Public TLS deployment still requires explicit approval.

See [the freshness contract](PUBLIC_FRESHNESS.md) for the local age limit, clock
uncertainty, historical standing projections, and optional inspector age admission.
The recovery drill keeps its synthetic dates fixed and does not refresh them to
make a local age assessment pass.
