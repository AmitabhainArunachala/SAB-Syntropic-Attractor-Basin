#!/usr/bin/env python3
"""
Fail-fast check for docs/NAME_REGISTRY.md.

Goal: prevent "same thing, new name" drift by enforcing a single canonical
registry with unique keys and non-overlapping aliases.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


def _extract_yaml_block(md: str) -> str:
    # Grab the first ```yaml ... ``` block.
    m = re.search(r"```yaml\s*\n(.*?)\n```", md, flags=re.DOTALL)
    if not m:
        raise ValueError("No ```yaml ...``` block found in docs/NAME_REGISTRY.md")
    return m.group(1).strip() + "\n"


def _norm(s: str) -> str:
    # Normalize aggressively: casefold + strip separators/punct.
    # Keeps unicode letters/digits (so non-latin aliases still work).
    return re.sub(r"[\W_]+", "", s.strip().casefold())


def main() -> int:
    path = Path("docs/NAME_REGISTRY.md")
    if not path.exists():
        print("FAIL: docs/NAME_REGISTRY.md missing", file=sys.stderr)
        return 2

    raw = path.read_text(encoding="utf-8")
    try:
        y = yaml.safe_load(_extract_yaml_block(raw)) or {}
    except Exception as e:
        print(f"FAIL: could not parse YAML block: {e}", file=sys.stderr)
        return 2

    entries = y.get("entries")
    if not isinstance(entries, list) or not entries:
        print("FAIL: YAML must contain non-empty `entries:` list", file=sys.stderr)
        return 2

    key_seen: set[str] = set()
    name_seen: dict[str, str] = {}  # norm_name -> "key: field"

    errors: list[str] = []

    for idx, ent in enumerate(entries, start=1):
        if not isinstance(ent, dict):
            errors.append(f"Entry #{idx} is not a mapping")
            continue

        key = ent.get("key")
        canonical = ent.get("canonical")
        expansion = ent.get("expansion")
        aliases = ent.get("aliases") or []
        deprecated_aliases = ent.get("deprecated_aliases") or []
        related_terms = ent.get("related_terms") or []

        if not isinstance(key, str) or not key.strip():
            errors.append(f"Entry #{idx} missing string `key`")
            continue
        if not isinstance(canonical, str) or not canonical.strip():
            errors.append(f"Entry #{idx} ({key}) missing string `canonical`")
            continue
        if expansion is not None and (not isinstance(expansion, str) or not expansion.strip()):
            errors.append(f"Entry #{idx} ({key}) `expansion` must be a non-empty string")
            continue
        if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
            errors.append(f"Entry #{idx} ({key}) `aliases` must be a list[str]")
            continue
        if not isinstance(deprecated_aliases, list) or any(
            not isinstance(a, str) for a in deprecated_aliases
        ):
            errors.append(f"Entry #{idx} ({key}) `deprecated_aliases` must be a list[str]")
            continue
        if not isinstance(related_terms, list) or any(not isinstance(a, str) for a in related_terms):
            errors.append(f"Entry #{idx} ({key}) `related_terms` must be a list[str]")
            continue

        key_norm = _norm(key)
        if key_norm in key_seen:
            errors.append(f"Duplicate key: {key!r}")
        key_seen.add(key_norm)

        # Canonical names, acronym expansions, and aliases (including deprecated
        # search aliases) must not collide globally. Related terms are links, not
        # names for this entry, so they are intentionally outside this namespace.
        names = [("canonical", canonical)]
        if expansion is not None:
            names.append(("expansion", expansion))
        names.extend(("alias", alias) for alias in aliases)
        names.extend(("deprecated_alias", alias) for alias in deprecated_aliases)
        for field, name in names:
            n = _norm(name)
            if not n:
                errors.append(f"Empty/invalid {field} after normalization: {name!r} (key={key})")
                continue
            prev = name_seen.get(n)
            where = f"{key}:{field}"
            if prev and prev != where:
                errors.append(f"Name collision: {name!r} ({where}) collides with ({prev})")
            else:
                name_seen[n] = where

    if errors:
        print("FAIL: NAME_REGISTRY violations:", file=sys.stderr)
        for e in errors:
            print(f"- {e}", file=sys.stderr)
        return 1

    print("PASS: docs/NAME_REGISTRY.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
