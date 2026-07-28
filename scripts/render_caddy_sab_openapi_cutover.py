#!/usr/bin/env python3
"""Render, but never apply, a fail-closed Caddy cutover for SAB OpenAPI routes.

The canonical AGNI origin can co-host auxiliary services.  This tool changes only
explicit ``/docs`` and ``/openapi.json`` handlers in one selected site block,
and only when both still point at the expected displaced upstream.  It requires
an existing catch-all handler for the canonical SAB upstream, emits a hash-bound
candidate and receipt, and never reloads Caddy or mutates the input file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_CADDYFILE_BYTES = 1_000_000
ROUTES = ("/docs", "/openapi.json")
_SAFE_SITE = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$")
_SAFE_UPSTREAM = re.compile(r"^[A-Za-z0-9_.:-]+$")
_HANDLE = re.compile(r"^handle\s+(\S+)\s*\{$")
_PROXY = re.compile(r"^(?P<indent>\s*)reverse_proxy\s+(?P<upstream>\S+)(?P<suffix>\s*\{?\s*)$")


class CutoverError(ValueError):
    """The input is ambiguous or does not match the bounded cutover preconditions."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_symbol(value: str, *, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CutoverError(f"{label} has an unsafe or unsupported shape")
    return value


def _line_opens_block(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped and not stripped.startswith("#") and stripped.endswith("{"))


def _line_closes_block(line: str) -> bool:
    return line.strip() == "}"


def _block_end(lines: list[str], start: int) -> int:
    if not _line_opens_block(lines[start]):
        raise CutoverError("internal parser error: block does not open")
    depth = 1
    for index in range(start + 1, len(lines)):
        if _line_opens_block(lines[index]):
            depth += 1
        elif _line_closes_block(lines[index]):
            depth -= 1
            if depth == 0:
                return index
    raise CutoverError("unterminated Caddy block")


def _selected_site(lines: list[str], site: str) -> tuple[int, int]:
    expected = f"{site} {{"
    starts = [index for index, line in enumerate(lines) if line.strip() == expected]
    if len(starts) != 1:
        raise CutoverError(f"expected exactly one site block for {site!r}; found {len(starts)}")
    start = starts[0]
    return start, _block_end(lines, start)


def _direct_handlers(
    lines: list[str],
    *,
    site_start: int,
    site_end: int,
) -> list[tuple[str | None, int, int]]:
    """Return direct child ``handle`` blocks in the selected site."""
    handlers: list[tuple[str | None, int, int]] = []
    index = site_start + 1
    while index < site_end:
        stripped = lines[index].strip()
        if stripped == "handle {":
            end = _block_end(lines, index)
            handlers.append((None, index, end))
            index = end + 1
            continue
        match = _HANDLE.fullmatch(stripped)
        if match:
            end = _block_end(lines, index)
            handlers.append((match.group(1), index, end))
            index = end + 1
            continue
        if _line_opens_block(lines[index]):
            index = _block_end(lines, index) + 1
            continue
        index += 1
    return handlers


def _single_proxy(
    lines: list[str],
    *,
    start: int,
    end: int,
    context: str,
) -> tuple[int, str, re.Match[str]]:
    proxies: list[tuple[int, str, re.Match[str]]] = []
    for index in range(start + 1, end):
        raw = lines[index].rstrip("\r\n")
        match = _PROXY.fullmatch(raw)
        if match:
            proxies.append((index, match.group("upstream"), match))
    if len(proxies) != 1:
        raise CutoverError(f"{context} must contain exactly one reverse_proxy directive")
    return proxies[0]


def render_cutover(
    source: str,
    *,
    site: str,
    sab_upstream: str,
    displaced_upstream: str,
) -> tuple[str, dict[str, Any]]:
    """Return a bounded candidate and deterministic hash receipt.

    No files, processes, services, or network endpoints are changed.
    """
    site = _validate_symbol(site, label="site", pattern=_SAFE_SITE)
    sab_upstream = _validate_symbol(sab_upstream, label="SAB upstream", pattern=_SAFE_UPSTREAM)
    displaced_upstream = _validate_symbol(
        displaced_upstream, label="displaced upstream", pattern=_SAFE_UPSTREAM
    )
    if sab_upstream == displaced_upstream:
        raise CutoverError("SAB and displaced upstreams must differ")
    if not isinstance(source, str):
        raise CutoverError("Caddy source must be text")
    encoded = source.encode("utf-8")
    if len(encoded) > MAX_CADDYFILE_BYTES:
        raise CutoverError("Caddy source exceeds the size limit")
    if "\x00" in source:
        raise CutoverError("Caddy source contains a NUL byte")

    lines = source.splitlines(keepends=True)
    site_start, site_end = _selected_site(lines, site)
    handlers = _direct_handlers(lines, site_start=site_start, site_end=site_end)

    replacement_indices: list[int] = []
    for route in ROUTES:
        matching = [(start, end) for path, start, end in handlers if path == route]
        if len(matching) != 1:
            raise CutoverError(
                f"expected exactly one {route} handler in the selected site; found {len(matching)}"
            )
        start, end = matching[0]
        proxy_index, upstream, _ = _single_proxy(
            lines, start=start, end=end, context=f"{route} handler"
        )
        if upstream != displaced_upstream:
            raise CutoverError(
                f"{route} handler has unexpected upstream {upstream!r}; "
                f"expected {displaced_upstream!r}"
            )
        replacement_indices.append(proxy_index)

    catchalls = [(start, end) for path, start, end in handlers if path is None]
    matching_catchalls = 0
    for start, end in catchalls:
        _, upstream, _ = _single_proxy(lines, start=start, end=end, context="catch-all handler")
        if upstream == sab_upstream:
            matching_catchalls += 1
    if matching_catchalls != 1:
        raise CutoverError(
            "selected site must contain exactly one catch-all handler for the canonical "
            f"SAB upstream {sab_upstream!r}; found {matching_catchalls}"
        )

    candidate_lines = list(lines)
    for index in replacement_indices:
        raw = lines[index].rstrip("\r\n")
        newline = lines[index][len(raw) :]
        match = _PROXY.fullmatch(raw)
        if match is None:  # pragma: no cover - guarded by _single_proxy
            raise CutoverError("internal parser error: replacement directive disappeared")
        candidate_lines[index] = (
            f"{match.group('indent')}reverse_proxy {sab_upstream}{match.group('suffix')}"
            f"{newline}"
        )

    candidate = "".join(candidate_lines)
    changed_line_count = sum(
        1 for before, after in zip(lines, candidate_lines, strict=True) if before != after
    )
    if changed_line_count != len(ROUTES) or candidate == source:
        raise CutoverError("candidate did not change exactly the two bounded route directives")

    receipt: dict[str, Any] = {
        "schema_version": "sab.caddy_openapi_cutover.v1",
        "site": site,
        "sab_upstream": sab_upstream,
        "displaced_upstream": displaced_upstream,
        "changed_routes": list(ROUTES),
        "replacement_count": changed_line_count,
        "source_sha256": _sha256(source),
        "candidate_sha256": _sha256(candidate),
        "applied": False,
    }
    return candidate, receipt


def _atomic_private_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise CutoverError(f"refusing to replace symlink: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="read-only source Caddyfile")
    parser.add_argument("--site", required=True, help="exact Caddy site label")
    parser.add_argument("--sab-upstream", required=True)
    parser.add_argument("--displaced-upstream", required=True)
    parser.add_argument("--output", type=Path, required=True, help="candidate output path")
    parser.add_argument("--receipt", type=Path, required=True, help="JSON receipt output path")
    args = parser.parse_args(argv)

    try:
        source_identity = args.source.resolve(strict=True)
        output_identity = args.output.resolve(strict=False)
        receipt_identity = args.receipt.resolve(strict=False)
        if len({source_identity, output_identity, receipt_identity}) != 3:
            raise CutoverError("source, candidate, and receipt paths must be distinct")
        if args.source.stat().st_size > MAX_CADDYFILE_BYTES:
            raise CutoverError("Caddy source exceeds the size limit")
        source = args.source.read_text(encoding="utf-8")
        candidate, receipt = render_cutover(
            source,
            site=args.site,
            sab_upstream=args.sab_upstream,
            displaced_upstream=args.displaced_upstream,
        )
        receipt.update(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source_path": str(args.source),
                "candidate_path": str(args.output),
            }
        )
        serialized_receipt = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        _atomic_private_write(args.output, candidate)
        _atomic_private_write(args.receipt, serialized_receipt)
    except (CutoverError, OSError, UnicodeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(serialized_receipt, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
