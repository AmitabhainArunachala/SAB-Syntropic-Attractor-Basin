#!/usr/bin/env python3
"""Install local cron entries for scheduled SAB language-womb contributions.

The installer is idempotent. By default it prints the changes it would make.
Use `--apply` to update the live Dharma and Hermes cron JSON files and install
the Hermes wrapper script.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HOME = Path.home()
AGORA_REPO = HOME / "dharmic-agora"
DHARMA_JOBS = HOME / ".dharma" / "cron" / "jobs.json"
HERMES_JOBS = HOME / ".hermes" / "cron" / "jobs.json"
HERMES_SCRIPT = HOME / ".hermes" / "scripts" / "sab_language_womb_tick.py"


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def dharma_job(enabled: bool) -> dict[str, Any]:
    return {
        "id": "sab_language_womb_tick",
        "name": "SAB Language Womb Contribution Tick",
        "handler": "shell",
        "schedule": {
            "kind": "interval",
            "minutes": 360,
            "display": "every 360m",
        },
        "enabled": enabled,
        "shell_command": (
            "/Users/dhyana/dharmic-agora/.venv/bin/python "
            "/Users/dhyana/dharmic-agora/scripts/sab_language_womb_tick.py "
            "--agent-id agent_dharma_cron --agent-name dharma-cron "
            "--source /Users/dhyana/AGENTS.md "
            "--source /Users/dhyana/dharmic-agora/docs/lanes/sab-agent-seeding-v1/LANGUAGE_WOMB_GRAND_CHALLENGE_SEED.md "
            "--source /Users/dhyana/ds_naga_ir_language_womb_seed/naga_ir_language_womb/language/prior_art.md"
        ),
        "prompt": (
            "Package new local language-womb deltas into SAB seed packets. "
            "Local-only; no external posting or standing promotion."
        ),
    }


def hermes_job(enabled: bool) -> dict[str, Any]:
    return {
        "id": "sab_language_womb_tick",
        "name": "sab-language-womb-tick",
        "schedule": {
            "kind": "interval",
            "minutes": 360,
            "display": "every 360m",
        },
        "enabled": enabled,
        "prompt": "",
        "script": "sab_language_womb_tick.py",
    }


def hermes_wrapper_text() -> str:
    return '''#!/Users/dhyana/dharmic-agora/.venv/bin/python
"""Hermes cron wrapper for SAB language-womb contribution packaging."""
from __future__ import annotations

import runpy
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

home = Path.home()
script = home / "dharmic-agora" / "scripts" / "sab_language_womb_tick.py"
sources = [
    home / "AGENTS.md",
    home / ".hermes" / "heartbeat" / "state.json",
    home / "dharmic-agora" / "docs" / "lanes" / "sab-agent-seeding-v1" / "LANGUAGE_WOMB_GRAND_CHALLENGE_SEED.md",
    home / "ds_naga_ir_language_womb_seed" / "naga_ir_language_womb" / "language" / "prior_art.md",
]
today = datetime.now(timezone.utc).date()
for offset in range(0, 3):
    sources.append(home / ".hermes" / "nikki" / f"{today - timedelta(days=offset)}.md")
args = [
    str(script),
    "--agent-id",
    "agent_hermes_m5",
    "--agent-name",
    "hermes-m5",
]
for source in sources:
    args.extend(["--source", str(source)])
sys.argv = args
runpy.run_path(str(script), run_name="__main__")
'''


def load_jobs(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"jobs": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return {"jobs": data}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object or list")
    jobs = data.get("jobs")
    if not isinstance(jobs, list):
        raise ValueError(f"{path} has no jobs list")
    return data


def upsert_job(blob: dict[str, Any], job: dict[str, Any]) -> tuple[dict[str, Any], str]:
    jobs = list(blob.get("jobs", []))
    for idx, existing in enumerate(jobs):
        if isinstance(existing, dict) and existing.get("id") == job["id"]:
            jobs[idx] = {**existing, **job}
            updated = {**blob, "jobs": jobs}
            return updated, "updated"
    jobs.append(job)
    updated = {**blob, "jobs": jobs}
    return updated, "added"


def write_json_with_backup(path: Path, blob: dict[str, Any]) -> Path | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = None
    if path.exists():
        backup = path.with_name(f"{path.name}.bak-sab-language-womb-{utc_stamp()}")
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(blob, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    tmp.replace(path)
    return backup


def install(apply: bool, enabled: bool) -> dict[str, Any]:
    changes: dict[str, Any] = {"apply": apply, "enabled": enabled}
    for label, path, job in (
        ("dharma", DHARMA_JOBS, dharma_job(enabled)),
        ("hermes", HERMES_JOBS, hermes_job(enabled)),
    ):
        blob = load_jobs(path)
        updated, action = upsert_job(blob, job)
        changes[label] = {"path": str(path), "action": action, "job": job}
        if apply:
            backup = write_json_with_backup(path, updated)
            changes[label]["backup"] = str(backup) if backup else None

    changes["hermes_script"] = {"path": str(HERMES_SCRIPT), "action": "install_wrapper"}
    if apply:
        HERMES_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        HERMES_SCRIPT.write_text(hermes_wrapper_text(), encoding="utf-8")
        os.chmod(HERMES_SCRIPT, 0o755)
    return changes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="write live cron files")
    parser.add_argument("--disabled", action="store_true", help="install jobs disabled")
    args = parser.parse_args()
    result = install(apply=args.apply, enabled=not args.disabled)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
