from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


MANIFEST_SCHEMA = "r3/verified-sqlite-backup/v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_KEYS = frozenset(
    {
        "manifest_schema",
        "created_at",
        "source_path",
        "backup_path",
        "manifest_path",
        "schema_version",
        "database_sha256",
        "integrity_check",
        "foreign_key_check",
        "verification_mode",
    }
)


class RecoveryError(RuntimeError):
    """Raised when a backup cannot be created or verified safely."""


def _resolved_file(path: str | os.PathLike[str], *, field: str) -> Path:
    try:
        resolved = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RecoveryError(f"{field} does not identify an existing file") from exc
    if not resolved.is_file():
        raise RecoveryError(f"{field} does not identify an existing file")
    return resolved


def _resolved_directory(path: str | os.PathLike[str]) -> Path:
    try:
        directory = Path(path).expanduser().resolve(strict=False)
        directory.mkdir(parents=True, exist_ok=True)
        directory = directory.resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RecoveryError("destination_dir cannot be created") from exc
    if not directory.is_dir():
        raise RecoveryError("destination_dir must identify a directory")
    return directory


def _readonly_uri(path: Path) -> str:
    return path.as_uri() + "?mode=ro"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise RecoveryError(f"cannot read backup file: {path}") from exc
    return digest.hexdigest()


def _schema_version(connection: sqlite3.Connection) -> str:
    try:
        row = connection.execute(
            """
            SELECT value
            FROM schema_meta
            WHERE key = 'schema_version'
            """
        ).fetchone()
    except sqlite3.Error as exc:
        raise RecoveryError("backup has no readable schema_meta table") from exc
    if row is None or row[0] is None or not str(row[0]).strip():
        raise RecoveryError("backup has no recorded schema version")
    return str(row[0])


def _inspect_backup(backup_path: Path) -> dict[str, Any]:
    before_sha256 = _file_sha256(backup_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            _readonly_uri(backup_path),
            uri=True,
            isolation_level=None,
        )
        connection.execute("PRAGMA query_only = ON")
        query_only = connection.execute("PRAGMA query_only").fetchone()
        if query_only is None or int(query_only[0]) != 1:
            raise RecoveryError("backup verification connection is not read-only")

        integrity_rows = [
            str(row[0])
            for row in connection.execute("PRAGMA integrity_check").fetchall()
        ]
        foreign_key_rows = [
            list(row)
            for row in connection.execute("PRAGMA foreign_key_check").fetchall()
        ]
        schema_version = _schema_version(connection)
    except RecoveryError:
        raise
    except sqlite3.Error as exc:
        raise RecoveryError("backup cannot be opened as a SQLite database") from exc
    finally:
        if connection is not None:
            connection.close()

    after_sha256 = _file_sha256(backup_path)
    if after_sha256 != before_sha256:
        raise RecoveryError("read-only backup verification changed the database")
    if integrity_rows != ["ok"]:
        raise RecoveryError(
            "backup failed PRAGMA integrity_check: " + "; ".join(integrity_rows)
        )
    if foreign_key_rows:
        raise RecoveryError(
            "backup failed PRAGMA foreign_key_check "
            f"with {len(foreign_key_rows)} violation(s)"
        )
    return {
        "backup_path": str(backup_path),
        "schema_version": schema_version,
        "database_sha256": after_sha256,
        "integrity_check": "ok",
        "foreign_key_check": [],
        "verification_mode": "sqlite-mode-ro-query-only",
    }


def _sidecar_path(backup_path: Path) -> Path:
    return Path(str(backup_path) + ".manifest.json")


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise RecoveryError("backup manifest is unexpectedly large")
        value = json.loads(path.read_text(encoding="utf-8"))
    except RecoveryError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("backup manifest is not readable JSON") from exc
    if not isinstance(value, dict):
        raise RecoveryError("backup manifest must be a JSON object")
    actual_keys = set(value)
    if actual_keys != _MANIFEST_KEYS:
        missing = sorted(_MANIFEST_KEYS - actual_keys)
        unexpected = sorted(actual_keys - _MANIFEST_KEYS)
        raise RecoveryError(
            "backup manifest keys do not match the schema "
            f"(missing={missing}, unexpected={unexpected})"
        )
    return value


def _validate_manifest(
    manifest: Mapping[str, Any],
    *,
    manifest_path: Path,
    verification: Mapping[str, Any],
) -> None:
    if manifest.get("manifest_schema") != MANIFEST_SCHEMA:
        raise RecoveryError("backup manifest schema is unsupported")
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str):
        raise RecoveryError("backup manifest created_at is invalid")
    try:
        parsed_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RecoveryError("backup manifest created_at is invalid") from exc
    if parsed_time.tzinfo is None:
        raise RecoveryError("backup manifest created_at must include a timezone")

    manifest_path_value = manifest.get("manifest_path")
    backup_path_value = manifest.get("backup_path")
    source_path_value = manifest.get("source_path")
    if not all(
        isinstance(value, str) and value
        for value in (manifest_path_value, backup_path_value, source_path_value)
    ):
        raise RecoveryError("backup manifest paths are invalid")
    try:
        recorded_manifest = Path(manifest_path_value).resolve(strict=True)
        recorded_backup = Path(backup_path_value).resolve(strict=True)
        recorded_source = Path(source_path_value)
    except (OSError, RuntimeError, ValueError) as exc:
        raise RecoveryError("backup manifest paths are invalid") from exc
    if recorded_manifest != manifest_path:
        raise RecoveryError("backup manifest_path does not match the manifest")
    if recorded_backup != Path(str(verification["backup_path"])):
        raise RecoveryError("backup manifest_path does not bind the requested backup")
    if not recorded_source.is_absolute():
        raise RecoveryError("backup source_path must be absolute")

    for field in (
        "schema_version",
        "database_sha256",
        "integrity_check",
        "foreign_key_check",
        "verification_mode",
    ):
        if manifest.get(field) != verification.get(field):
            raise RecoveryError(f"backup manifest {field} does not match the backup")
    if (
        not isinstance(manifest.get("database_sha256"), str)
        or _SHA256.fullmatch(manifest["database_sha256"]) is None
    ):
        raise RecoveryError("backup manifest database_sha256 is invalid")


def verify_backup(
    backup_path: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Open a backup read-only and fail unless its SQLite checks are clean.

    When an explicit manifest is supplied, or the adjacent sidecar exists, its
    recorded hash and verification fields must also match the backup.
    """

    backup = _resolved_file(backup_path, field="backup_path")
    verification = _inspect_backup(backup)

    if manifest_path is None:
        candidate = _sidecar_path(backup)
        manifest = candidate if candidate.is_file() else None
    else:
        manifest = _resolved_file(manifest_path, field="manifest_path")
    if manifest is not None:
        manifest = manifest.resolve(strict=True)
        manifest_value = _load_manifest(manifest)
        _validate_manifest(
            manifest_value,
            manifest_path=manifest,
            verification=verification,
        )
        verification["manifest_path"] = str(manifest)
    else:
        verification["manifest_path"] = None
    return verification


def _backup_name(value: str | None) -> str:
    if value is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        return f"r3-backup-{timestamp}-{uuid.uuid4().hex[:12]}.sqlite3"
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or Path(value).name != value
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RecoveryError("backup_name must be a safe single filename")
    return value


def _reserve_new_file(path: Path) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise RecoveryError(f"refusing to overwrite existing backup: {path}") from exc
    except OSError as exc:
        raise RecoveryError(f"cannot create backup file: {path}") from exc
    else:
        os.close(descriptor)


def _write_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(
            manifest,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
            indent=2,
        )
        + "\n"
    )
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise RecoveryError(f"refusing to overwrite existing manifest: {path}") from exc
    except OSError as exc:
        raise RecoveryError(f"cannot write backup manifest: {path}") from exc


def create_verified_backup(
    source_db: str | os.PathLike[str],
    destination_dir: str | os.PathLike[str],
    *,
    backup_name: str | None = None,
) -> dict[str, Any]:
    """Create one online SQLite backup and its verified JSON manifest."""

    source = _resolved_file(source_db, field="source_db")
    destination = _resolved_directory(destination_dir)
    backup = destination / _backup_name(backup_name)
    manifest_path = _sidecar_path(backup)
    if backup == source:
        raise RecoveryError("backup path must differ from source_db")
    if manifest_path.exists():
        raise RecoveryError(
            f"refusing to overwrite existing manifest: {manifest_path}"
        )

    _reserve_new_file(backup)
    completed = False
    try:
        source_connection: sqlite3.Connection | None = None
        destination_connection: sqlite3.Connection | None = None
        try:
            source_connection = sqlite3.connect(
                _readonly_uri(source),
                uri=True,
            )
            source_connection.execute("PRAGMA query_only = ON")
            destination_connection = sqlite3.connect(backup)
            source_connection.backup(destination_connection)
            destination_connection.commit()
        except sqlite3.Error as exc:
            raise RecoveryError("SQLite online backup failed") from exc
        finally:
            if destination_connection is not None:
                destination_connection.close()
            if source_connection is not None:
                source_connection.close()

        verification = _inspect_backup(backup)
        manifest = {
            "manifest_schema": MANIFEST_SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
            "source_path": str(source),
            "backup_path": str(backup.resolve(strict=True)),
            "manifest_path": str(manifest_path.resolve(strict=False)),
            "schema_version": verification["schema_version"],
            "database_sha256": verification["database_sha256"],
            "integrity_check": verification["integrity_check"],
            "foreign_key_check": verification["foreign_key_check"],
            "verification_mode": verification["verification_mode"],
        }
        _write_manifest(manifest_path, manifest)
        completed = True
        return manifest
    finally:
        if not completed:
            try:
                backup.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


__all__ = [
    "MANIFEST_SCHEMA",
    "RecoveryError",
    "create_verified_backup",
    "verify_backup",
]
