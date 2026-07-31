"""Additive, copy-only storage for the SAB first-verdict Build A slice.

This module deliberately does not discover a database path, import the public
application, or commit caller-owned lifecycle transactions.  A caller must
provide an explicit SQLite connection to a disposable fixture or copied
database.
"""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional
from urllib.parse import quote

from .sab_artifact_verdict import (
    ArtifactBallotV1,
    ArtifactCaseV1,
    CouncilVerdictV1,
    DISPOSITION_AUTHORITY_ADAPTER,
    SessionWriteLeaseV1,
    canonical_json,
    canonical_json_sha256 as contract_json_sha256,
    verify_contract_signature,
)


MIGRATION_ID = "20260728_first_verdict_build_a_v1"
SIGNATURE_EVIDENCE_MIGRATION_ID = "20260728_first_verdict_signature_evidence_v1"

_SIGNATURE_EVIDENCE_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS sab_first_verdict_signature_evidence_v1 (
        sequence_no INTEGER PRIMARY KEY CHECK (sequence_no >= 1),
        record_id TEXT NOT NULL UNIQUE,
        artifact_type TEXT NOT NULL CHECK (artifact_type IN
            ('policy', 'lease', 'case', 'ballot', 'countersign',
             'lineage', 'successor', 'lifecycle_event')),
        artifact_id TEXT NOT NULL,
        lifecycle_event_id TEXT NOT NULL,
        signer TEXT NOT NULL,
        public_key TEXT NOT NULL CHECK (length(public_key) = 64),
        prev_hash TEXT CHECK (prev_hash IS NULL OR length(prev_hash) = 64),
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
        canonicalization TEXT NOT NULL CHECK (canonicalization IN
            ('canonical_json_v1', 'json-sort-keys-compact-v1')),
        signature TEXT NOT NULL CHECK (length(signature) = 128),
        record_hash TEXT NOT NULL UNIQUE CHECK (length(record_hash) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (artifact_type, artifact_id)
    )
    """,
    """
    CREATE TRIGGER IF NOT EXISTS sab_first_verdict_signature_evidence_v1_no_update
    BEFORE UPDATE ON sab_first_verdict_signature_evidence_v1
    BEGIN
        SELECT RAISE(ABORT, 'signature evidence is immutable');
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS sab_first_verdict_signature_evidence_v1_no_delete
    BEFORE DELETE ON sab_first_verdict_signature_evidence_v1
    BEGIN
        SELECT RAISE(ABORT, 'signature evidence is immutable');
    END
    """,
)
SIGNATURE_EVIDENCE_MIGRATION_DIGEST = hashlib.sha256(
    "\n".join(
        statement.strip() for statement in _SIGNATURE_EVIDENCE_STATEMENTS
    ).encode()
).hexdigest()

FROZEN_METHOD_PATHS = frozenset(
    {
        ("GET", "/health"),
        ("POST", "/api/v1/session-write-leases/activate"),
        ("POST", "/api/v1/session-write-leases/{lease_id}/release"),
        ("GET", "/api/v1/session-write-leases/{lease_id}"),
        ("POST", "/api/v1/artifact-cases"),
        ("GET", "/api/v1/artifact-cases/{case_id}"),
        ("POST", "/api/v1/artifact-cases/{case_id}/ballots"),
        ("POST", "/api/v1/artifact-cases/{case_id}/authority-evaluations"),
        ("POST", "/api/v1/artifact-cases/{case_id}/verdicts"),
        ("GET", "/api/v1/artifact-verdicts/{verdict_id}"),
        (
            "POST",
            "/api/v1/artifact-verdicts/{verdict_id}/rehearsal-dispositions",
        ),
        ("GET", "/api/v1/rehearsal-dispositions/{disposition_id}"),
        ("GET", "/api/v1/seeds/{seed_id}/lineage"),
        ("POST", "/api/v1/compost-batches/preview"),
    }
)


class FirstVerdictStorageError(RuntimeError):
    """Base class for deterministic storage failures."""


class MigrationDigestMismatch(FirstVerdictStorageError):
    """The recorded migration ID exists with different bytes."""


class MigrationSchemaMismatch(FirstVerdictStorageError):
    """A pre-existing object conflicts with the additive migration schema."""


class ForeignKeysRequired(FirstVerdictStorageError):
    """The caller did not enable SQLite foreign-key enforcement."""


class DatabaseSafetyError(FirstVerdictStorageError):
    """A database is not proven to be a disposable or copied Build A target."""


class ImmutableConflict(FirstVerdictStorageError):
    """An immutable identity was reused with different content."""


class LeaseStateConflict(FirstVerdictStorageError):
    """A lease transition was invalid or conflicted with prior state."""


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json_text(value: Any) -> str:
    return canonical_json(value)


def canonical_json_sha256(value: Any) -> str:
    return contract_json_sha256(value)


@dataclass(frozen=True)
class CopyDatabaseAttestation:
    """Out-of-band binding for the only file-backed writable storage surface."""

    proof_class: str
    database_path: Path
    source_database_path: Path | None
    source_backup_sha256: str
    expected_lifecycle_fingerprint: str
    copy_receipt_sha256: str
    copy_receipt_path: Path | None = None

    def validate(self, *, require_pristine_backup: bool) -> Path:
        if self.proof_class not in {
            "copied_live_db_rehearsal",
            "disposable_fixture",
        }:
            raise DatabaseSafetyError("database proof class is not copy/fixture scoped")
        for field_name in (
            "source_backup_sha256",
            "expected_lifecycle_fingerprint",
            "copy_receipt_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(getattr(self, field_name))):
                raise DatabaseSafetyError(f"{field_name} is not lowercase SHA-256")
        candidate = Path(self.database_path)
        if (
            not candidate.is_absolute()
            or candidate.is_symlink()
            or not candidate.is_file()
        ):
            raise DatabaseSafetyError(
                "copy database must be an explicit absolute non-symlink file"
            )
        resolved = candidate.resolve(strict=True)
        if any(
            (parent / ".git").exists()
            for parent in (resolved.parent, *resolved.parents)
        ):
            raise DatabaseSafetyError("copy database must be outside a Git checkout")
        if self.source_database_path is None:
            raise DatabaseSafetyError(
                "every file-backed target requires an explicit forbidden source path"
            )
        source = Path(self.source_database_path)
        if not source.is_absolute() or source.is_symlink() or not source.is_file():
            raise DatabaseSafetyError(
                "source database must be an explicit absolute non-symlink file"
            )
        if source.resolve(strict=True) == resolved or os.path.samefile(
            source, resolved
        ):
            raise DatabaseSafetyError("copy database is the forbidden source file")
        if self.proof_class == "copied_live_db_rehearsal":
            if self.copy_receipt_path is None:
                raise DatabaseSafetyError(
                    "copied-live proof requires the frozen A0 copy receipt"
                )
            receipt_path = Path(self.copy_receipt_path)
            if (
                not receipt_path.is_absolute()
                or receipt_path.is_symlink()
                or not receipt_path.is_file()
            ):
                raise DatabaseSafetyError(
                    "copy receipt must be an explicit absolute non-symlink file"
                )
            receipt_bytes = receipt_path.read_bytes()
            if hashlib.sha256(receipt_bytes).hexdigest() != self.copy_receipt_sha256:
                raise DatabaseSafetyError("copy receipt digest does not verify")
            try:
                receipt = json.loads(receipt_bytes)
                receipt_source = receipt["source"]
                receipt_schema = receipt.get("schema_version")
                if receipt_schema == "sab.sqlite_online_backup_receipt.v1":
                    receipt_copy = receipt["destination"]
                    logical_equivalence = receipt.get("logical_equivalence")
                    content_equal = bool(
                        receipt.get("source_unchanged") is True
                        and isinstance(logical_equivalence, dict)
                        and set(logical_equivalence)
                        == {
                            "schema_manifest",
                            "preexisting_table_digests",
                            "lifecycle_fingerprint",
                        }
                        and all(value is True for value in logical_equivalence.values())
                    )
                    backup_method = receipt.get("backup_method")
                    source_opened = "sqlite_uri_mode_ro"
                    expected_source_ref = (
                        "private-local:sha256:"
                        + hashlib.sha256(
                            str(source.resolve(strict=True)).encode()
                        ).hexdigest()
                    )
                    expected_copy_refs = {
                        "private-local:sha256:"
                        + hashlib.sha256(str(resolved).encode()).hexdigest()
                    }
                elif receipt_schema == "sab.build_a.a0_database_snapshot.v1":
                    receipt_copy = receipt["copy"]
                    content_equal = receipt.get("content_equal") is True
                    backup_method = receipt_copy.get("backup_method")
                    source_opened = receipt_source.get("opened")
                    expected_source_ref = str(source.resolve(strict=True))
                    expected_copy_refs = {str(resolved), f"private:{resolved}"}
                else:
                    raise DatabaseSafetyError(
                        "copy receipt schema is not an accepted A0 receipt"
                    )
                if not isinstance(receipt_source, dict) or not isinstance(
                    receipt_copy, dict
                ):
                    raise TypeError("receipt source/copy fields must be objects")
            except (
                AttributeError,
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                raise DatabaseSafetyError(
                    "copy receipt does not satisfy the A0 evidence contract"
                ) from exc
            copy_path_ref = str(receipt_copy.get("path_ref", ""))
            source_path_ref = str(receipt_source.get("path_ref", ""))
            source_sha256 = hashlib.sha256(
                source.resolve(strict=True).read_bytes()
            ).hexdigest()
            if (
                not content_equal
                or backup_method != "sqlite_online_backup_from_mode_ro_source"
                or source_opened != "sqlite_uri_mode_ro"
                or str(receipt_source.get("sha256", "")) != source_sha256
                or str(receipt_copy.get("sha256", "")) != self.source_backup_sha256
                or copy_path_ref not in expected_copy_refs
                or source_path_ref != expected_source_ref
            ):
                raise DatabaseSafetyError(
                    "copy receipt does not bind the explicit source and destination"
                )
        if require_pristine_backup:
            digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
            if digest != self.source_backup_sha256:
                raise DatabaseSafetyError(
                    "copy database does not match source-backup digest"
                )
        return resolved


def _anchored_source_binding(
    attestation: CopyDatabaseAttestation,
) -> tuple[str, int, int, int] | None:
    """Return source SHA/device/inode/size from the anchored receipt."""

    if attestation.proof_class != "copied_live_db_rehearsal":
        return None
    receipt_path = attestation.copy_receipt_path
    if receipt_path is None:
        raise DatabaseSafetyError("copied-live receipt is missing")
    try:
        receipt = json.loads(Path(receipt_path).read_bytes())
        source = receipt["source"]
        sha256 = str(source["sha256"])
        device = int(source["device"])
        inode = int(source["inode"])
        size = int(source["size"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DatabaseSafetyError(
            "copy receipt lacks the exact source file identity"
        ) from exc
    if not re.fullmatch(r"[0-9a-f]{64}", sha256) or size < 0:
        raise DatabaseSafetyError("copy receipt source identity is invalid")
    return sha256, device, inode, size


def _fd_sha256(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            break
        digest.update(block)
        offset += len(block)
    return digest.hexdigest()


class AttestedSQLiteConnection(sqlite3.Connection):
    """SQLite connection carrying an out-of-band copy attestation."""

    sab_copy_attestation: CopyDatabaseAttestation
    sab_open_file_identity: tuple[int, int]
    sab_open_fd: int | None
    sab_source_fd: int | None
    sab_lock_fd: int | None
    sab_lock_identity: tuple[int, int]
    sab_parent_identity: tuple[int, int]

    def close(self) -> None:
        """Close SQLite before releasing the inode-binding file descriptor."""

        open_fd = getattr(self, "sab_open_fd", None)
        source_fd = getattr(self, "sab_source_fd", None)
        lock_fd = getattr(self, "sab_lock_fd", None)
        errors: list[BaseException] = []
        try:
            super().close()
        except BaseException as exc:
            errors.append(exc)
        finally:
            for attribute, descriptor in (
                ("sab_open_fd", open_fd),
                ("sab_source_fd", source_fd),
            ):
                if descriptor is not None:
                    setattr(self, attribute, None)
                    try:
                        os.close(descriptor)
                    except BaseException as exc:
                        errors.append(exc)
            if lock_fd is not None:
                self.sab_lock_fd = None
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except BaseException as exc:
                    errors.append(exc)
                try:
                    os.close(lock_fd)
                except BaseException as exc:
                    errors.append(exc)
        if errors:
            raise errors[0]


def _regular_file_identity(path: Path) -> tuple[int, int]:
    """Return a no-follow identity for an existing regular database file."""

    try:
        file_stat = os.lstat(path)
    except OSError as exc:
        raise DatabaseSafetyError("copy database identity cannot be read") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise DatabaseSafetyError("copy database must remain a regular file")
    return (int(file_stat.st_dev), int(file_stat.st_ino))


def _regular_fd_identity(fd: int) -> tuple[int, int]:
    try:
        file_stat = os.fstat(fd)
    except OSError as exc:
        raise DatabaseSafetyError("copy database file descriptor is invalid") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise DatabaseSafetyError("copy database descriptor must name a regular file")
    return (int(file_stat.st_dev), int(file_stat.st_ino))


def _require_private_parent(path: Path) -> None:
    """Require a same-user private directory for SQLite and its sidecars."""

    parent = path.parent
    try:
        parent_stat = os.lstat(parent)
    except OSError as exc:
        raise DatabaseSafetyError("copy database parent cannot be read") from exc
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent.is_symlink()
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) & 0o077
    ):
        raise DatabaseSafetyError(
            "copy database parent must be a same-user private directory"
        )


def _private_parent_identity(path: Path) -> tuple[int, int]:
    _require_private_parent(path)
    parent_stat = os.lstat(path.parent)
    return int(parent_stat.st_dev), int(parent_stat.st_ino)


def _acquire_runner_lock(path: Path) -> int:
    lock_path = path.parent / ".sab-first-verdict.lock"
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        lock_fd = os.open(lock_path, flags, 0o600)
        lock_stat = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_stat.st_mode)
            or lock_stat.st_uid != os.geteuid()
            or lock_stat.st_nlink != 1
        ):
            raise DatabaseSafetyError("runner lock is not a private regular file")
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, DatabaseSafetyError) as exc:
        if "lock_fd" in locals():
            os.close(lock_fd)
        raise DatabaseSafetyError(
            "another runner holds or replaced the private database lock"
        ) from exc
    return lock_fd


_RAW_SQLITE_CONNECT = sqlite3.connect


def _prove_connection_matches_descriptor(
    conn: sqlite3.Connection,
    open_fd: int,
) -> None:
    """Check the main/fd lock domain under the cooperative-runner boundary.

    The primary connection takes a RESERVED lock.  A second connection opened
    through the already-bound descriptor must then be unable to take the same
    lock.  A successful second lock means the pathname was redirected during
    connect and fails closed before any schema or data write.  A conflicting
    third-party lock can cause a false positive, so the owner-only directory is
    the security boundary; this check is defense in depth, not protection from
    arbitrary same-process or same-UID code.
    """

    conn.execute("PRAGMA busy_timeout=0")
    verifier: sqlite3.Connection | None = None
    conn.execute("BEGIN IMMEDIATE")
    try:
        descriptor_path = f"/dev/fd/{open_fd}"
        uri = f"file:{quote(descriptor_path, safe='/')}?mode=rw"
        try:
            verifier = _RAW_SQLITE_CONNECT(uri, uri=True, timeout=0)
        except sqlite3.Error as exc:
            raise DatabaseSafetyError(
                "could not verify the attested database lock identity"
            ) from exc
        verifier.execute("PRAGMA busy_timeout=0")
        try:
            verifier.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower():
                raise DatabaseSafetyError(
                    "could not verify the attested database lock identity"
                ) from exc
        else:
            verifier.rollback()
            raise DatabaseSafetyError(
                "SQLite connection differs from the attested copy descriptor"
            )
    finally:
        conn.rollback()
        if verifier is not None:
            verifier.close()


def require_copy_or_fixture_connection(conn: sqlite3.Connection) -> None:
    """Permit in-memory fixtures or a connection opened by the attested opener."""

    database_rows = conn.execute("PRAGMA database_list").fetchall()
    file_backed = [
        (str(row[1]), str(row[2]))
        for row in database_rows
        if str(row[2]) and str(row[1]) != "temp"
    ]
    main_path = next(
        (str(row[2]) for row in database_rows if str(row[1]) == "main"), ""
    )
    if not main_path:
        if file_backed:
            raise DatabaseSafetyError(
                "in-memory fixtures must not attach a file-backed database"
            )
        return
    if any(name != "main" for name, _ in file_backed):
        raise DatabaseSafetyError(
            "attested copy connections must not attach another file-backed database"
        )
    if not isinstance(conn, AttestedSQLiteConnection) or not hasattr(
        conn, "sab_copy_attestation"
    ):
        raise DatabaseSafetyError(
            "file-backed storage mutation requires an attested copy connection"
        )
    attestation = conn.sab_copy_attestation
    expected = attestation.validate(require_pristine_backup=False)
    opened_identity = getattr(conn, "sab_open_file_identity", None)
    open_fd = getattr(conn, "sab_open_fd", None)
    source_fd = getattr(conn, "sab_source_fd", None)
    lock_fd = getattr(conn, "sab_lock_fd", None)
    if opened_identity is None or _regular_file_identity(expected) != opened_identity:
        raise DatabaseSafetyError(
            "attested copy file identity changed after connection open"
        )
    if open_fd is None or _regular_fd_identity(open_fd) != opened_identity:
        raise DatabaseSafetyError("active connection differs from attested copy path")
    if source_fd is None or _regular_fd_identity(source_fd) == opened_identity:
        raise DatabaseSafetyError("attested copy aliases the forbidden source")
    lock_path = expected.parent / ".sab-first-verdict.lock"
    if (
        lock_fd is None
        or _regular_fd_identity(lock_fd) != getattr(conn, "sab_lock_identity", None)
        or _regular_file_identity(lock_path) != getattr(conn, "sab_lock_identity", None)
    ):
        raise DatabaseSafetyError("private database runner lock changed")
    if _private_parent_identity(expected) != getattr(conn, "sab_parent_identity", None):
        raise DatabaseSafetyError("private copy directory identity changed")
    if Path(main_path).resolve(strict=False) != expected:
        raise DatabaseSafetyError("active connection path differs from attested copy")
    if str(conn.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "delete":
        raise DatabaseSafetyError("attested copy requires DELETE journal mode")
    if int(conn.execute("PRAGMA synchronous").fetchone()[0]) != 2:
        raise DatabaseSafetyError("attested copy requires FULL synchronization")


def open_attested_copy_connection(
    attestation: CopyDatabaseAttestation,
    *,
    require_pristine_backup: bool = False,
    expected_file_identity: tuple[int, int] | None = None,
) -> sqlite3.Connection:
    """Open one inode-bound attested copy with ``mode=rw``; never create a DB.

    The copy and its SQLite sidecars live in a same-user mode-private directory.
    Retained ``O_NOFOLLOW`` descriptors bind the intended source and copy
    identities.  A cooperative pre-write lock-domain check detects ordinary
    redirection; the owner-only directory prevents outside path mutation.  The
    original path must retain the same identity at every mutation boundary.
    Ordinary durable SQLite journal semantics remain enabled.  Arbitrary
    same-process, root, or hostile same-UID code is outside this boundary.
    """

    resolved = attestation.validate(require_pristine_backup=require_pristine_backup)
    parent_identity = _private_parent_identity(resolved)
    before_identity = _regular_file_identity(resolved)
    if expected_file_identity is not None and before_identity != tuple(
        expected_file_identity
    ):
        raise DatabaseSafetyError(
            "copy database identity differs from the bound application file"
        )
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    source_flags = (
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        lock_fd = _acquire_runner_lock(resolved)
        lock_identity = _regular_fd_identity(lock_fd)
        open_fd = os.open(resolved, flags)
        source_fd = os.open(attestation.source_database_path, source_flags)
        descriptor_identity = _regular_fd_identity(open_fd)
        source_identity = _regular_fd_identity(source_fd)
        source_stat = os.fstat(source_fd)
        source_binding = _anchored_source_binding(attestation)
        if (
            source_binding is not None
            and (
                _fd_sha256(source_fd),
                int(source_stat.st_dev),
                int(source_stat.st_ino),
                int(source_stat.st_size),
            )
            != source_binding
        ):
            raise DatabaseSafetyError(
                "forbidden source descriptor differs from the anchored A0 receipt"
            )
        source_path = Path(attestation.source_database_path)
        if Path(f"{source_path}-wal").exists() or Path(f"{source_path}-shm").exists():
            raise DatabaseSafetyError(
                "forbidden source must have no live WAL sidecars during replay"
            )
        copy_stat = os.fstat(open_fd)
        if copy_stat.st_uid != os.geteuid() or copy_stat.st_nlink != 1:
            raise DatabaseSafetyError(
                "copy database must be an owner-held single-link file"
            )
        if source_identity == descriptor_identity:
            raise DatabaseSafetyError("copy database is the forbidden source file")
        if descriptor_identity != before_identity:
            raise DatabaseSafetyError(
                "copy database identity changed while binding the descriptor"
            )
        uri = f"file:{quote(str(resolved), safe='/')}?mode=rw"
        conn = sqlite3.connect(uri, uri=True, factory=AttestedSQLiteConnection)
    except Exception:
        for descriptor_name in ("source_fd", "open_fd"):
            if descriptor_name in locals():
                os.close(locals()[descriptor_name])
        if "lock_fd" in locals():
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        raise
    conn.sab_copy_attestation = attestation
    conn.sab_open_file_identity = descriptor_identity
    conn.sab_open_fd = open_fd
    conn.sab_source_fd = source_fd
    conn.sab_lock_fd = lock_fd
    conn.sab_lock_identity = lock_identity
    conn.sab_parent_identity = parent_identity
    try:
        if _regular_fd_identity(open_fd) != descriptor_identity:
            raise DatabaseSafetyError(
                "copy descriptor identity changed while opening the connection"
            )
        # SQLite's Linux pathname VFS may be unable to open /dev/fd/N once the
        # bound inode is unlinked.  Detect the ordinary one-way path swap
        # directly before the lock-domain challenge; the challenge remains
        # necessary for an ABA swap that restores the original pathname.
        if _regular_file_identity(resolved) != descriptor_identity:
            raise DatabaseSafetyError(
                "SQLite connection differs from the attested copy descriptor"
            )
        _prove_connection_matches_descriptor(conn, open_fd)
        database_rows = conn.execute("PRAGMA database_list").fetchall()
        main_paths = [str(row[2]) for row in database_rows if str(row[1]) == "main"]
        if (
            len(main_paths) != 1
            or Path(main_paths[0]).resolve(strict=False) != resolved
        ):
            raise DatabaseSafetyError(
                "SQLite main database path differs from the attested copy"
            )
        conn.execute("PRAGMA foreign_keys = ON")
        if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
            raise DatabaseSafetyError("could not enable SQLite foreign keys")
        journal_mode = str(conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0])
        if journal_mode.lower() != "delete":
            raise DatabaseSafetyError("could not enable SQLite DELETE journal mode")
        conn.execute("PRAGMA synchronous=FULL")
        if int(conn.execute("PRAGMA synchronous").fetchone()[0]) != 2:
            raise DatabaseSafetyError("could not enable SQLite FULL synchronization")
        from .sab_first_verdict_evidence import (
            capture_preexisting_table_digests,
            lifecycle_fingerprint,
            verify_preexisting_table_digests,
        )

        actual = lifecycle_fingerprint(conn)["sha256"]
        if actual != attestation.expected_lifecycle_fingerprint:
            raise DatabaseSafetyError(
                "copy lifecycle fingerprint differs from attestation"
            )
        source_uri = f"file:{quote(f'/dev/fd/{source_fd}', safe='/')}?mode=ro"
        with _RAW_SQLITE_CONNECT(source_uri, uri=True) as source_conn:
            if (
                str(source_conn.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                != "delete"
            ):
                raise DatabaseSafetyError(
                    "forbidden source must use DELETE journal mode for fd replay"
                )
            baseline = capture_preexisting_table_digests(source_conn)
            source_schema = _schema_object_manifest(source_conn)
        provenance = verify_preexisting_table_digests(conn, baseline)
        if not provenance["verified"]:
            raise DatabaseSafetyError(
                "copy preexisting tables differ from the forbidden source"
            )
        _verify_copy_schema_provenance(conn, source_schema)
        if (
            _regular_fd_identity(open_fd) != descriptor_identity
            or _regular_file_identity(resolved) != descriptor_identity
            or _regular_fd_identity(source_fd) != source_identity
            or _private_parent_identity(resolved) != parent_identity
        ):
            raise DatabaseSafetyError(
                "copy database identity changed during connection validation"
            )
    except Exception:
        conn.close()
        raise
    return conn


_LEDGER_STATEMENT = """
    CREATE TABLE IF NOT EXISTS sab_first_verdict_schema_migrations_v1 (
        migration_id TEXT PRIMARY KEY,
        migration_digest TEXT NOT NULL CHECK (length(migration_digest) = 64),
        applied_at TEXT NOT NULL
    )
    """


_TABLE_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS sab_session_write_leases_v1 (
        lease_id TEXT PRIMARY KEY,
        scope TEXT NOT NULL CHECK (scope = 'Copy'),
        operations_json TEXT NOT NULL,
        operations_sha256 TEXT NOT NULL CHECK (length(operations_sha256) = 64),
        lease_json TEXT NOT NULL,
        lease_json_sha256 TEXT NOT NULL UNIQUE CHECK (length(lease_json_sha256) = 64),
        lease_sha256 TEXT NOT NULL UNIQUE CHECK (length(lease_sha256) = 64),
        status TEXT NOT NULL CHECK (status IN ('active', 'released', 'expired', 'revoked')),
        activated_at TEXT NOT NULL,
        released_at TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_artifact_cases_v1 (
        case_id TEXT PRIMARY KEY,
        target_seed_id TEXT NOT NULL,
        round_no INTEGER NOT NULL CHECK (round_no = 1),
        case_json TEXT NOT NULL,
        case_sha256 TEXT NOT NULL UNIQUE CHECK (length(case_sha256) = 64),
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_artifact_ballots_v1 (
        ballot_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES sab_artifact_cases_v1(case_id),
        round_no INTEGER NOT NULL CHECK (round_no = 1),
        seat_id TEXT NOT NULL,
        ballot_source TEXT NOT NULL CHECK (ballot_source IN ('real_external_model', 'fixture_model')),
        credited_cluster TEXT NOT NULL,
        ballot_json TEXT NOT NULL,
        ballot_sha256 TEXT NOT NULL UNIQUE CHECK (length(ballot_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (case_id, round_no, seat_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_disposition_authority_v1 (
        evaluation_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES sab_artifact_cases_v1(case_id),
        result TEXT NOT NULL CHECK (result IN ('Authorized', 'AdvisoryOnly', 'NoJurisdiction')),
        scope TEXT NOT NULL CHECK (scope IN ('Copy', 'Live', 'All')),
        evaluated_state_hash TEXT NOT NULL CHECK (length(evaluated_state_hash) = 64),
        authority_json TEXT NOT NULL,
        authority_sha256 TEXT NOT NULL UNIQUE CHECK (length(authority_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (evaluation_id, case_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_council_verdicts_v1 (
        verdict_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL REFERENCES sab_artifact_cases_v1(case_id),
        evaluation_id TEXT NOT NULL REFERENCES sab_disposition_authority_v1(evaluation_id),
        round_no INTEGER NOT NULL CHECK (round_no = 1),
        decision TEXT NOT NULL,
        ballot_set_sha256 TEXT NOT NULL CHECK (length(ballot_set_sha256) = 64),
        verdict_json TEXT NOT NULL,
        verdict_sha256 TEXT NOT NULL UNIQUE CHECK (length(verdict_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (case_id, round_no),
        UNIQUE (verdict_id, evaluation_id),
        UNIQUE (verdict_id, evaluation_id, case_id),
        FOREIGN KEY (evaluation_id, case_id)
            REFERENCES sab_disposition_authority_v1(evaluation_id, case_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_operator_countersigns_v1 (
        countersign_id TEXT PRIMARY KEY,
        verdict_id TEXT NOT NULL UNIQUE REFERENCES sab_council_verdicts_v1(verdict_id),
        write_lease_id TEXT NOT NULL REFERENCES sab_session_write_leases_v1(lease_id),
        countersign_json TEXT NOT NULL,
        countersign_sha256 TEXT NOT NULL UNIQUE CHECK (length(countersign_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (countersign_id, verdict_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_rehearsal_artifacts_v1 (
        artifact_id TEXT PRIMARY KEY,
        state TEXT NOT NULL,
        artifact_json TEXT NOT NULL,
        artifact_sha256 TEXT NOT NULL UNIQUE CHECK (length(artifact_sha256) = 64),
        live_eligible INTEGER NOT NULL CHECK (live_eligible = 0),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_rehearsal_dispositions_v1 (
        disposition_id TEXT PRIMARY KEY,
        verdict_id TEXT NOT NULL UNIQUE REFERENCES sab_council_verdicts_v1(verdict_id),
        countersign_id TEXT NOT NULL UNIQUE REFERENCES sab_operator_countersigns_v1(countersign_id),
        evaluation_id TEXT NOT NULL REFERENCES sab_disposition_authority_v1(evaluation_id),
        target_artifact_id TEXT NOT NULL REFERENCES sab_rehearsal_artifacts_v1(artifact_id),
        successor_artifact_id TEXT REFERENCES sab_rehearsal_artifacts_v1(artifact_id),
        scope TEXT NOT NULL CHECK (scope = 'Copy'),
        disposition_json TEXT NOT NULL,
        disposition_sha256 TEXT NOT NULL UNIQUE CHECK (length(disposition_sha256) = 64),
        created_at TEXT NOT NULL,
        FOREIGN KEY (verdict_id, evaluation_id)
            REFERENCES sab_council_verdicts_v1(verdict_id, evaluation_id),
        FOREIGN KEY (countersign_id, verdict_id)
            REFERENCES sab_operator_countersigns_v1(countersign_id, verdict_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_seed_lineage_edges_v1 (
        edge_id TEXT PRIMARY KEY,
        predecessor_seed_id TEXT NOT NULL,
        successor_seed_id TEXT NOT NULL,
        disposition_id TEXT NOT NULL REFERENCES sab_rehearsal_dispositions_v1(disposition_id),
        edge_json TEXT NOT NULL,
        edge_sha256 TEXT NOT NULL UNIQUE CHECK (length(edge_sha256) = 64),
        created_at TEXT NOT NULL,
        UNIQUE (predecessor_seed_id, successor_seed_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_first_verdict_signed_events_v1 (
        event_id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        signer TEXT NOT NULL,
        public_key TEXT NOT NULL,
        prev_hash TEXT,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
        signature TEXT NOT NULL,
        event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sab_first_verdict_idempotency_v1 (
        operation TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
        response_json TEXT NOT NULL,
        response_sha256 TEXT NOT NULL CHECK (length(response_sha256) = 64),
        created_at TEXT NOT NULL,
        PRIMARY KEY (operation, idempotency_key)
    )
    """,
)


_IMMUTABLE_TABLES = (
    "sab_first_verdict_schema_migrations_v1",
    "sab_artifact_cases_v1",
    "sab_artifact_ballots_v1",
    "sab_disposition_authority_v1",
    "sab_council_verdicts_v1",
    "sab_operator_countersigns_v1",
    "sab_rehearsal_dispositions_v1",
    "sab_seed_lineage_edges_v1",
    "sab_first_verdict_signed_events_v1",
    "sab_first_verdict_idempotency_v1",
)


def _trigger_statements() -> tuple[str, ...]:
    statements = []
    for table in _IMMUTABLE_TABLES:
        statements.extend(
            (
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_reject_update
                BEFORE UPDATE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, '{table} is immutable');
                END
                """,
                f"""
                CREATE TRIGGER IF NOT EXISTS {table}_reject_delete
                BEFORE DELETE ON {table}
                BEGIN
                    SELECT RAISE(ABORT, '{table} is immutable');
                END
                """,
            )
        )
    statements.extend(
        (
            """
            CREATE TRIGGER IF NOT EXISTS sab_session_write_leases_v1_reject_delete
            BEFORE DELETE ON sab_session_write_leases_v1
            BEGIN
                SELECT RAISE(ABORT, 'session write leases cannot be deleted');
            END
            """,
            """
            CREATE TRIGGER IF NOT EXISTS sab_session_write_leases_v1_restrict_update
            BEFORE UPDATE ON sab_session_write_leases_v1
            WHEN NOT (
                OLD.status = 'active'
                AND NEW.status IN ('released', 'expired', 'revoked')
                AND NEW.lease_id = OLD.lease_id
                AND NEW.scope = OLD.scope
                AND NEW.operations_json = OLD.operations_json
                AND NEW.operations_sha256 = OLD.operations_sha256
                AND NEW.lease_json = OLD.lease_json
                AND NEW.lease_json_sha256 = OLD.lease_json_sha256
                AND NEW.lease_sha256 = OLD.lease_sha256
                AND NEW.activated_at = OLD.activated_at
                AND NEW.released_at IS NOT NULL
            )
            BEGIN
                SELECT RAISE(ABORT, 'invalid session write lease transition');
            END
            """,
        )
    )
    return tuple(statements)


MIGRATION_STATEMENTS = (_LEDGER_STATEMENT,) + _TABLE_STATEMENTS + _trigger_statements()
MIGRATION_DIGEST = hashlib.sha256(
    "\n".join(statement.strip() for statement in MIGRATION_STATEMENTS).encode()
).hexdigest()


_SCHEMA_OBJECT = re.compile(
    r"^CREATE\s+(?:TABLE|TRIGGER)\s+IF\s+NOT\s+EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


def _normalized_schema_sql(sql: str) -> str:
    return re.sub(r"\s+", " ", sql.strip()).replace(" IF NOT EXISTS ", " ")


def _schema_object_manifest(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    rows = conn.execute(
        "SELECT type, name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'trigger', 'view') "
        "AND sql IS NOT NULL ORDER BY type, name"
    ).fetchall()
    return {
        (str(row[0]), str(row[1])): _normalized_schema_sql(str(row[2])) for row in rows
    }


def _schema_from_statements(
    statements: tuple[str, ...],
) -> dict[tuple[str, str], str]:
    expected: dict[tuple[str, str], str] = {}
    for statement in statements:
        stripped = statement.strip()
        match = _SCHEMA_OBJECT.match(stripped)
        if match is None:
            raise MigrationSchemaMismatch("unrecognized frozen migration statement")
        kind = "table" if stripped.upper().startswith("CREATE TABLE") else "trigger"
        expected[(kind, match.group(1))] = _normalized_schema_sql(statement)
    return expected


def _frozen_additive_schema() -> dict[tuple[str, str], str]:
    return {
        **_schema_from_statements(MIGRATION_STATEMENTS),
        **_schema_from_statements(_SIGNATURE_EVIDENCE_STATEMENTS),
    }


def _verify_copy_schema_provenance(
    conn: sqlite3.Connection,
    source_schema: Mapping[tuple[str, str], str],
) -> None:
    """Require exact source schema plus only the two frozen additive migrations."""

    current = _schema_object_manifest(conn)
    for identity, expected_sql in source_schema.items():
        if current.get(identity) != expected_sql:
            raise DatabaseSafetyError(
                f"preexisting schema object {identity[1]} differs from the source"
            )
    extras = {
        identity: sql
        for identity, sql in current.items()
        if identity not in source_schema
    }
    base_frozen = _schema_from_statements(MIGRATION_STATEMENTS)
    signature_frozen = _schema_from_statements(_SIGNATURE_EVIDENCE_STATEMENTS)
    frozen = {**base_frozen, **signature_frozen}
    if any(frozen.get(identity) != sql for identity, sql in extras.items()):
        raise DatabaseSafetyError(
            "copy contains schema outside the frozen additive migrations"
        )
    if not extras:
        return
    ledger = conn.execute(
        "SELECT migration_id, migration_digest "
        "FROM sab_first_verdict_schema_migrations_v1 ORDER BY migration_id"
    ).fetchall()
    observed_ledger = {str(row[0]): str(row[1]) for row in ledger}
    allowed_ledger = {
        MIGRATION_ID: MIGRATION_DIGEST,
        SIGNATURE_EVIDENCE_MIGRATION_ID: SIGNATURE_EVIDENCE_MIGRATION_DIGEST,
    }
    if (
        not observed_ledger
        or any(
            allowed_ledger.get(key) != value for key, value in observed_ledger.items()
        )
        or observed_ledger.get(MIGRATION_ID) != MIGRATION_DIGEST
    ):
        raise DatabaseSafetyError(
            "copy additive schema is not bound to the frozen migration ledger"
        )
    signature_installed = (
        observed_ledger.get(SIGNATURE_EVIDENCE_MIGRATION_ID)
        == SIGNATURE_EVIDENCE_MIGRATION_DIGEST
    )
    expected_extras = {
        **base_frozen,
        **(signature_frozen if signature_installed else {}),
    }
    expected_extras = {
        identity: sql
        for identity, sql in expected_extras.items()
        if identity not in source_schema
    }
    if extras != expected_extras:
        raise DatabaseSafetyError(
            "copy migration schema and ledger are not an exact pair"
        )


def _verify_migration_schema(conn: sqlite3.Connection) -> None:
    """Reject a same-named table/trigger whose realized DDL differs.

    ``CREATE ... IF NOT EXISTS`` alone is not an attestation: without this
    check, a partial or hostile pre-existing object could be silently accepted
    and the migration digest recorded anyway.
    """

    for statement in MIGRATION_STATEMENTS:
        match = _SCHEMA_OBJECT.match(statement.strip())
        if match is None:
            raise MigrationSchemaMismatch("unrecognized migration statement")
        name = match.group(1)
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = ?", (name,)
        ).fetchone()
        expected = _normalized_schema_sql(statement)
        actual = (
            "" if row is None or row[0] is None else _normalized_schema_sql(str(row[0]))
        )
        if actual != expected:
            raise MigrationSchemaMismatch(
                f"migration object {name} differs from the frozen schema"
            )


def _invoke_failure(hook: Optional[Callable[[str], None]], boundary: str) -> None:
    if hook is not None:
        hook(boundary)


def init_first_verdict_storage(
    conn: sqlite3.Connection,
    *,
    applied_at: Optional[str] = None,
    failure_hook: Optional[Callable[[str], None]] = None,
) -> str:
    """Install the additive migration atomically and return its digest.

    The function uses ``BEGIN IMMEDIATE`` when it owns the connection
    transaction and a savepoint otherwise.  Reusing the migration ID with
    different bytes fails closed.
    """

    require_copy_or_fixture_connection(conn)
    if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        raise ForeignKeysRequired(
            "PRAGMA foreign_keys=ON is required before the migration transaction"
        )

    owns_transaction = not conn.in_transaction
    savepoint = "sab_first_verdict_migration"
    if owns_transaction:
        conn.execute("BEGIN IMMEDIATE")
    else:
        conn.execute(f"SAVEPOINT {savepoint}")
    try:
        conn.execute(_LEDGER_STATEMENT)
        ledger_name = "sab_first_verdict_schema_migrations_v1"
        ledger_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (ledger_name,),
        ).fetchone()
        if (
            ledger_row is None
            or ledger_row[0] is None
            or _normalized_schema_sql(str(ledger_row[0]))
            != _normalized_schema_sql(_LEDGER_STATEMENT)
        ):
            raise MigrationSchemaMismatch(
                "migration ledger differs from the frozen schema"
            )
        existing = conn.execute(
            """
            SELECT migration_digest
            FROM sab_first_verdict_schema_migrations_v1
            WHERE migration_id = ?
            """,
            (MIGRATION_ID,),
        ).fetchone()
        if existing is not None and str(existing[0]) != MIGRATION_DIGEST:
            raise MigrationDigestMismatch(
                f"{MIGRATION_ID} digest mismatch: {existing[0]} != {MIGRATION_DIGEST}"
            )
        _invoke_failure(failure_hook, "migration:0")
        for index, statement in enumerate(MIGRATION_STATEMENTS[1:], start=1):
            conn.execute(statement)
            _invoke_failure(failure_hook, f"migration:{index}")
        _verify_migration_schema(conn)
        _invoke_failure(failure_hook, "migration:schema-verified")
        conn.execute(
            """
            INSERT OR IGNORE INTO sab_first_verdict_schema_migrations_v1
                (migration_id, migration_digest, applied_at)
            VALUES (?, ?, ?)
            """,
            (MIGRATION_ID, MIGRATION_DIGEST, applied_at or utc_now_text()),
        )
        _invoke_failure(failure_hook, "migration:record")
        if owns_transaction:
            conn.commit()
        else:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        if owns_transaction:
            conn.rollback()
        else:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    return MIGRATION_DIGEST


def init_signature_evidence_storage(
    conn: sqlite3.Connection,
    *,
    applied_at: Optional[str] = None,
) -> str:
    """Install the append-only persisted-signature extension atomically."""

    require_copy_or_fixture_connection(conn)
    if int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
        raise ForeignKeysRequired(
            "PRAGMA foreign_keys=ON is required before the signature migration"
        )
    base = conn.execute(
        """
        SELECT migration_digest
        FROM sab_first_verdict_schema_migrations_v1
        WHERE migration_id = ?
        """,
        (MIGRATION_ID,),
    ).fetchone()
    if base is None or str(base[0]) != MIGRATION_DIGEST:
        raise MigrationDigestMismatch(
            "signature evidence requires the exact first-verdict base migration"
        )

    owns_transaction = not conn.in_transaction
    savepoint = "sab_signature_evidence_migration"
    if owns_transaction:
        conn.execute("BEGIN IMMEDIATE")
    else:
        conn.execute(f"SAVEPOINT {savepoint}")
    try:
        existing = conn.execute(
            """
            SELECT migration_digest
            FROM sab_first_verdict_schema_migrations_v1
            WHERE migration_id = ?
            """,
            (SIGNATURE_EVIDENCE_MIGRATION_ID,),
        ).fetchone()
        if (
            existing is not None
            and str(existing[0]) != SIGNATURE_EVIDENCE_MIGRATION_DIGEST
        ):
            raise MigrationDigestMismatch(
                "signature evidence migration digest mismatch"
            )
        for statement in _SIGNATURE_EVIDENCE_STATEMENTS:
            conn.execute(statement)
            match = _SCHEMA_OBJECT.match(statement.strip())
            if match is None:
                raise MigrationSchemaMismatch(
                    "unrecognized signature evidence migration statement"
                )
            name = match.group(1)
            row = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = ?", (name,)
            ).fetchone()
            actual = "" if row is None or row[0] is None else str(row[0])
            if _normalized_schema_sql(actual) != _normalized_schema_sql(statement):
                raise MigrationSchemaMismatch(
                    f"signature evidence object {name} differs from frozen schema"
                )
        conn.execute(
            """
            INSERT OR IGNORE INTO sab_first_verdict_schema_migrations_v1
                (migration_id, migration_digest, applied_at)
            VALUES (?, ?, ?)
            """,
            (
                SIGNATURE_EVIDENCE_MIGRATION_ID,
                SIGNATURE_EVIDENCE_MIGRATION_DIGEST,
                applied_at or utc_now_text(),
            ),
        )
    except Exception:
        if owns_transaction:
            conn.rollback()
        else:
            conn.execute(f"ROLLBACK TO {savepoint}")
            conn.execute(f"RELEASE {savepoint}")
        raise
    else:
        if owns_transaction:
            conn.commit()
        else:
            conn.execute(f"RELEASE {savepoint}")
    return SIGNATURE_EVIDENCE_MIGRATION_DIGEST


_IMMUTABLE_DIGEST_QUERIES: Dict[str, str] = {
    "case": "SELECT case_sha256 FROM sab_artifact_cases_v1 WHERE case_id = ?",
    "ballot": "SELECT ballot_sha256 FROM sab_artifact_ballots_v1 WHERE ballot_id = ?",
    "authority": (
        "SELECT authority_sha256 FROM sab_disposition_authority_v1 "
        "WHERE evaluation_id = ?"
    ),
    "verdict": (
        "SELECT verdict_sha256 FROM sab_council_verdicts_v1 WHERE verdict_id = ?"
    ),
    "countersign": (
        "SELECT countersign_sha256 FROM sab_operator_countersigns_v1 "
        "WHERE countersign_id = ?"
    ),
    "disposition": (
        "SELECT disposition_sha256 FROM sab_rehearsal_dispositions_v1 "
        "WHERE disposition_id = ?"
    ),
    "lineage": (
        "SELECT edge_sha256 FROM sab_seed_lineage_edges_v1 WHERE edge_id = ?"
    ),
}

_JSON_RECORD_QUERIES: Dict[tuple[str, str, str], str] = {
    (
        "sab_session_write_leases_v1",
        "lease_id",
        "lease_json",
    ): "SELECT lease_json FROM sab_session_write_leases_v1 WHERE lease_id = ?",
    (
        "sab_artifact_cases_v1",
        "case_id",
        "case_json",
    ): "SELECT case_json FROM sab_artifact_cases_v1 WHERE case_id = ?",
    (
        "sab_council_verdicts_v1",
        "verdict_id",
        "verdict_json",
    ): "SELECT verdict_json FROM sab_council_verdicts_v1 WHERE verdict_id = ?",
    (
        "sab_rehearsal_dispositions_v1",
        "disposition_id",
        "disposition_json",
    ): (
        "SELECT disposition_json FROM sab_rehearsal_dispositions_v1 "
        "WHERE disposition_id = ?"
    ),
}


def immutable_digest_for(
    conn: sqlite3.Connection,
    kind: str,
    object_id: str,
) -> Optional[str]:
    row = conn.execute(_IMMUTABLE_DIGEST_QUERIES[kind], (object_id,)).fetchone()
    return None if row is None else str(row[0])


def require_immutable_identity(
    conn: sqlite3.Connection,
    kind: str,
    object_id: str,
    digest: str,
) -> bool:
    """Return True for an exact replay, False for a new identity."""

    existing = immutable_digest_for(conn, kind, object_id)
    if existing is None:
        return False
    if existing != digest:
        raise ImmutableConflict(
            f"{kind} {object_id} already exists with different content"
        )
    return True


def store_artifact_case(
    conn: sqlite3.Connection,
    case: Dict[str, Any],
    *,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        normalized = ArtifactCaseV1.model_validate(case).canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(f"invalid artifact case contract: {exc}") from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    case_id = str(normalized["case_id"])
    replay = require_immutable_identity(conn, "case", case_id, digest)
    if not replay:
        conn.execute(
            """
            INSERT INTO sab_artifact_cases_v1
                (case_id, target_seed_id, round_no, case_json,
                 case_sha256, created_at)
            VALUES (?, ?, 1, ?, ?, ?)
            """,
            (
                case_id,
                str(normalized["target_seed_id"]),
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def store_artifact_ballot(
    conn: sqlite3.Connection,
    ballot: Dict[str, Any],
    *,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        normalized = ArtifactBallotV1.model_validate(ballot).canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(f"invalid artifact ballot contract: {exc}") from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    ballot_id = str(normalized["ballot_id"])
    case_row = conn.execute(
        "SELECT case_sha256 FROM sab_artifact_cases_v1 WHERE case_id = ?",
        (str(normalized["case_id"]),),
    ).fetchone()
    if case_row is None or str(case_row[0]) != str(normalized["case_sha256"]):
        raise ImmutableConflict("ballot case digest does not match stored case")
    replay = require_immutable_identity(conn, "ballot", ballot_id, digest)
    if not replay:
        conn.execute(
            """
            INSERT INTO sab_artifact_ballots_v1
                (ballot_id, case_id, round_no, seat_id, ballot_source,
                 credited_cluster, ballot_json, ballot_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ballot_id,
                str(normalized["case_id"]),
                int(normalized["round_no"]),
                str(normalized["seat_id"]),
                str(normalized["ballot_source"]),
                str(normalized["credited_cluster"]),
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def store_authority_evaluation(
    conn: sqlite3.Connection,
    *,
    case_id: str,
    authority: Dict[str, Any],
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        model = DISPOSITION_AUTHORITY_ADAPTER.validate_python(authority)
        normalized = model.canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(
            f"invalid disposition authority contract: {exc}"
        ) from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    evaluation_id = str(normalized["evaluation_id"])
    case_row = conn.execute(
        "SELECT target_seed_id FROM sab_artifact_cases_v1 WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    if case_row is None:
        raise ImmutableConflict(f"unknown artifact case {case_id}")
    if str(case_row[0]) != str(normalized["artifact_id"]):
        raise ImmutableConflict(
            "authority artifact does not match the case target seed"
        )
    replay = require_immutable_identity(conn, "authority", evaluation_id, digest)
    if replay:
        row = conn.execute(
            "SELECT case_id FROM sab_disposition_authority_v1 WHERE evaluation_id = ?",
            (evaluation_id,),
        ).fetchone()
        if row is None or str(row[0]) != case_id:
            raise ImmutableConflict(
                f"authority {evaluation_id} has conflicting case binding"
            )
    else:
        conn.execute(
            """
            INSERT INTO sab_disposition_authority_v1
                (evaluation_id, case_id, result, scope, evaluated_state_hash,
                 authority_json, authority_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evaluation_id,
                case_id,
                str(normalized["result"]),
                str(normalized["scope"]),
                str(normalized["evaluated_state_hash"]),
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def ballot_set_sha256_for_case(conn: sqlite3.Connection, case_id: str) -> str:
    rows = conn.execute(
        """
        SELECT ballot_id, ballot_sha256
        FROM sab_artifact_ballots_v1
        WHERE case_id = ? AND round_no = 1
        ORDER BY ballot_id
        """,
        (case_id,),
    ).fetchall()
    members = [{"ballot_id": str(row[0]), "ballot_sha256": str(row[1])} for row in rows]
    return canonical_json_sha256(members)


def store_council_verdict(
    conn: sqlite3.Connection,
    *,
    evaluation_id: str,
    verdict: Dict[str, Any],
    ballot_set_sha256: str,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    try:
        normalized = CouncilVerdictV1.model_validate(verdict).canonical_payload()
    except Exception as exc:
        raise ImmutableConflict(f"invalid council verdict contract: {exc}") from exc
    payload_json = canonical_json_text(normalized)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    verdict_id = str(normalized["verdict_id"])
    case_id = str(normalized["case_id"])
    authority_row = conn.execute(
        """
        SELECT case_id, authority_sha256
        FROM sab_disposition_authority_v1
        WHERE evaluation_id = ?
        """,
        (evaluation_id,),
    ).fetchone()
    if authority_row is None:
        raise ImmutableConflict(f"unknown authority evaluation {evaluation_id}")
    if str(authority_row[0]) != case_id:
        raise ImmutableConflict("verdict case does not match authority evaluation case")
    if str(authority_row[1]) != str(normalized["authority_digest"]):
        raise ImmutableConflict("verdict authority digest does not match evaluation")
    case_row = conn.execute(
        "SELECT case_sha256 FROM sab_artifact_cases_v1 WHERE case_id = ?", (case_id,)
    ).fetchone()
    if case_row is None or str(case_row[0]) != str(normalized["case_sha256"]):
        raise ImmutableConflict("verdict case digest does not match stored case")
    ballot_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM sab_artifact_ballots_v1 WHERE case_id = ? AND round_no = 1",
            (case_id,),
        ).fetchone()[0]
    )
    if ballot_count != 9:
        raise ImmutableConflict("Build A verdict requires exactly nine stored ballots")
    expected_ballot_set = ballot_set_sha256_for_case(conn, case_id)
    if ballot_set_sha256 != expected_ballot_set:
        raise ImmutableConflict(
            "verdict ballot-set digest does not match stored ballots"
        )
    replay = require_immutable_identity(conn, "verdict", verdict_id, digest)
    if replay:
        row = conn.execute(
            """
            SELECT evaluation_id, ballot_set_sha256, case_id
            FROM sab_council_verdicts_v1 WHERE verdict_id = ?
            """,
            (verdict_id,),
        ).fetchone()
        if row is None or tuple(str(value) for value in row) != (
            evaluation_id,
            ballot_set_sha256,
            case_id,
        ):
            raise ImmutableConflict(
                f"verdict {verdict_id} has conflicting relational bindings"
            )
    else:
        conn.execute(
            """
            INSERT INTO sab_council_verdicts_v1
                (verdict_id, case_id, evaluation_id, round_no, decision,
                 ballot_set_sha256, verdict_json, verdict_sha256, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verdict_id,
                case_id,
                evaluation_id,
                int(normalized["round_no"]),
                str(normalized["decision"]),
                ballot_set_sha256,
                payload_json,
                digest,
                created_at or utc_now_text(),
            ),
        )
    return normalized, digest, replay


def create_rehearsal_artifact(
    conn: sqlite3.Connection,
    artifact: Dict[str, Any],
    *,
    created_at: Optional[str] = None,
) -> tuple[Dict[str, Any], str, bool]:
    require_copy_or_fixture_connection(conn)
    payload_json = canonical_json_text(artifact)
    digest = hashlib.sha256(payload_json.encode()).hexdigest()
    artifact_id = str(artifact["artifact_id"])
    row = conn.execute(
        """
        SELECT artifact_sha256, artifact_json
        FROM sab_rehearsal_artifacts_v1
        WHERE artifact_id = ?
        """,
        (artifact_id,),
    ).fetchone()
    if row is not None:
        if str(row[0]) != digest or str(row[1]) != payload_json:
            raise ImmutableConflict(
                f"rehearsal artifact {artifact_id} exists with different content"
            )
        return artifact, digest, True
    timestamp = created_at or utc_now_text()
    conn.execute(
        """
        INSERT INTO sab_rehearsal_artifacts_v1
            (artifact_id, state, artifact_json, artifact_sha256,
             live_eligible, created_at, updated_at)
        VALUES (?, ?, ?, ?, 0, ?, ?)
        """,
        (
            artifact_id,
            str(artifact["state"]),
            payload_json,
            digest,
            timestamp,
            timestamp,
        ),
    )
    return artifact, digest, False


def idempotency_lookup(
    conn: sqlite3.Connection,
    *,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
        raise ImmutableConflict("idempotency request digest is not lowercase SHA-256")
    row = conn.execute(
        """
        SELECT request_sha256, response_json, response_sha256
        FROM sab_first_verdict_idempotency_v1
        WHERE operation = ? AND idempotency_key = ?
        """,
        (operation, idempotency_key),
    ).fetchone()
    if row is None:
        return None
    if str(row[0]) != request_sha256:
        raise ImmutableConflict(
            f"idempotency identity {operation}/{idempotency_key} has conflicting content"
        )
    response_json = str(row[1])
    response_sha256 = str(row[2])
    try:
        response = json.loads(response_json)
    except json.JSONDecodeError as exc:
        raise ImmutableConflict(
            "stored idempotency response is not valid JSON"
        ) from exc
    if canonical_json_text(response) != response_json:
        raise ImmutableConflict("stored idempotency response is not canonical JSON")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", response_sha256)
        or hashlib.sha256(response_json.encode()).hexdigest() != response_sha256
    ):
        raise ImmutableConflict("stored idempotency response digest mismatch")
    return response


def record_idempotency(
    conn: sqlite3.Connection,
    *,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
    response: Dict[str, Any],
    created_at: Optional[str] = None,
) -> None:
    require_copy_or_fixture_connection(conn)
    if not operation or not idempotency_key:
        raise ImmutableConflict("idempotency operation and key must be non-empty")
    if not re.fullmatch(r"[0-9a-f]{64}", request_sha256):
        raise ImmutableConflict("idempotency request digest is not lowercase SHA-256")
    response_json = canonical_json_text(response)
    existing = idempotency_lookup(
        conn,
        operation=operation,
        idempotency_key=idempotency_key,
        request_sha256=request_sha256,
    )
    if existing is not None:
        if canonical_json_text(existing) != response_json:
            raise ImmutableConflict(
                f"idempotency identity {operation}/{idempotency_key} has conflicting response"
            )
        return
    conn.execute(
        """
        INSERT INTO sab_first_verdict_idempotency_v1
            (operation, idempotency_key, request_sha256,
             response_json, response_sha256, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            operation,
            idempotency_key,
            request_sha256,
            response_json,
            hashlib.sha256(response_json.encode()).hexdigest(),
            created_at or utc_now_text(),
        ),
    )


def activate_session_lease(
    conn: sqlite3.Connection,
    lease: Dict[str, Any],
    *,
    activated_at: Optional[str] = None,
) -> Dict[str, Any]:
    require_copy_or_fixture_connection(conn)
    try:
        model = SessionWriteLeaseV1.model_validate(lease)
    except Exception as exc:
        raise LeaseStateConflict(
            f"invalid session write lease contract: {exc}"
        ) from exc
    if model.signature.signer != model.issuer_identity:
        raise LeaseStateConflict(
            "lease signature signer does not match issuer identity"
        )
    if model.signature.public_key != model.issuer_public_key:
        raise LeaseStateConflict("lease signature key does not match issuer key")
    if not verify_contract_signature(
        model.canonical_bytes(exclude={"signature"}), model.signature
    ):
        raise LeaseStateConflict("lease signature verification failed")
    signed_activated_at = model.activated_at.isoformat().replace("+00:00", "Z")
    if activated_at is not None and activated_at != signed_activated_at:
        raise LeaseStateConflict(
            "database activation timestamp differs from signed lease activation"
        )
    normalized_lease = model.canonical_payload()
    operations = normalized_lease["allowed_operations"]
    payload_json = canonical_json_text(normalized_lease)
    payload_sha = hashlib.sha256(payload_json.encode()).hexdigest()
    semantic_lease_sha = model.lease_sha256
    lease_id = model.lease_id
    row = conn.execute(
        """
        SELECT lease_json_sha256, lease_sha256, lease_json, status
        FROM sab_session_write_leases_v1
        WHERE lease_id = ?
        """,
        (lease_id,),
    ).fetchone()
    if row is not None:
        if (
            str(row[0]) != payload_sha
            or str(row[1]) != semantic_lease_sha
            or str(row[2]) != payload_json
        ):
            raise ImmutableConflict(
                f"lease {lease_id} already exists with different content"
            )
        if str(row[3]) != "active":
            raise LeaseStateConflict(f"lease {lease_id} is already {row[3]}")
        return json.loads(str(row[2]))
    operations_json = canonical_json_text(operations)
    conn.execute(
        """
        INSERT INTO sab_session_write_leases_v1
            (lease_id, scope, operations_json, operations_sha256,
             lease_json, lease_json_sha256, lease_sha256,
             status, activated_at, released_at)
        VALUES (?, 'Copy', ?, ?, ?, ?, ?, 'active', ?, NULL)
        """,
        (
            lease_id,
            operations_json,
            hashlib.sha256(operations_json.encode()).hexdigest(),
            payload_json,
            payload_sha,
            semantic_lease_sha,
            signed_activated_at,
        ),
    )
    return normalized_lease


def release_session_lease(
    conn: sqlite3.Connection,
    lease_id: str,
    *,
    terminal_status: str = "released",
    released_at: Optional[str] = None,
) -> Dict[str, Any]:
    require_copy_or_fixture_connection(conn)
    if terminal_status not in {"released", "expired", "revoked"}:
        raise LeaseStateConflict(f"invalid terminal lease status: {terminal_status}")
    row = conn.execute(
        "SELECT status, lease_json FROM sab_session_write_leases_v1 WHERE lease_id = ?",
        (lease_id,),
    ).fetchone()
    if row is None:
        raise LeaseStateConflict(f"unknown lease: {lease_id}")
    current = str(row[0])
    if current == terminal_status:
        return json.loads(str(row[1]))
    if current != "active":
        raise LeaseStateConflict(f"lease {lease_id} is already {current}")
    conn.execute(
        """
        UPDATE sab_session_write_leases_v1
        SET status = ?, released_at = ?
        WHERE lease_id = ? AND status = 'active'
        """,
        (terminal_status, released_at or utc_now_text(), lease_id),
    )
    return json.loads(str(row[1]))


def get_json_record(
    conn: sqlite3.Connection,
    *,
    table: str,
    id_column: str,
    json_column: str,
    object_id: str,
) -> Optional[Dict[str, Any]]:
    try:
        query = _JSON_RECORD_QUERIES[(table, id_column, json_column)]
    except KeyError:
        raise ValueError("unsupported first-verdict record lookup") from None
    row = conn.execute(query, (object_id,)).fetchone()
    return None if row is None else json.loads(str(row[0]))
