from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from r3radar.__main__ import build_parser
from r3radar.recovery import (
    MANIFEST_SCHEMA,
    RecoveryError,
    create_verified_backup,
    verify_backup,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _make_database(path: Path, *, violate_foreign_key: bool = False) -> None:
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT INTO schema_meta(key, value)
            VALUES ('schema_version', '7');

            CREATE TABLE parent (
                id INTEGER PRIMARY KEY,
                label TEXT NOT NULL
            );
            CREATE TABLE child (
                id INTEGER PRIMARY KEY,
                parent_id INTEGER NOT NULL REFERENCES parent(id)
            );
            INSERT INTO parent(id, label) VALUES (1, 'frozen row');
            INSERT INTO child(id, parent_id) VALUES (1, 1);
            """
        )
        if violate_foreign_key:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.commit()
            connection.execute(
                "INSERT INTO child(id, parent_id) VALUES (2, 999)"
            )
        connection.commit()


class RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "live.sqlite3"
        self.backups = self.root / "explicit-backups"
        _make_database(self.source)

    def test_create_verified_backup_uses_online_copy_and_manifest(self) -> None:
        manifest = create_verified_backup(
            self.source,
            self.backups,
            backup_name="checkpoint.sqlite3",
        )

        backup = Path(manifest["backup_path"])
        manifest_path = Path(manifest["manifest_path"])
        self.assertTrue(backup.is_file())
        self.assertTrue(manifest_path.is_file())
        self.assertEqual(manifest["manifest_schema"], MANIFEST_SCHEMA)
        self.assertEqual(manifest["source_path"], str(self.source.resolve()))
        self.assertEqual(manifest["schema_version"], "7")
        self.assertEqual(manifest["database_sha256"], _sha256(backup))
        self.assertEqual(manifest["integrity_check"], "ok")
        self.assertEqual(manifest["foreign_key_check"], [])
        self.assertEqual(
            manifest["verification_mode"],
            "sqlite-mode-ro-query-only",
        )
        self.assertTrue(manifest["created_at"].endswith("Z"))
        self.assertEqual(
            json.loads(manifest_path.read_text(encoding="utf-8")),
            manifest,
        )

        with closing(
            sqlite3.connect(
                backup.as_uri() + "?mode=ro",
                uri=True,
            )
        ) as restored:
            self.assertEqual(
                restored.execute("SELECT label FROM parent").fetchone()[0],
                "frozen row",
            )

    def test_verify_backup_is_read_only_and_checks_adjacent_manifest(self) -> None:
        manifest = create_verified_backup(self.source, self.backups)
        backup = Path(manifest["backup_path"])
        before = _sha256(backup)

        verification = verify_backup(backup)

        self.assertEqual(verification["database_sha256"], before)
        self.assertEqual(_sha256(backup), before)
        self.assertEqual(
            verification["manifest_path"],
            manifest["manifest_path"],
        )
        self.assertEqual(verification["schema_version"], "7")

    def test_existing_backup_or_manifest_is_never_overwritten(self) -> None:
        first = create_verified_backup(
            self.source,
            self.backups,
            backup_name="fixed.sqlite3",
        )
        backup = Path(first["backup_path"])
        manifest_path = Path(first["manifest_path"])
        backup_bytes = backup.read_bytes()
        manifest_bytes = manifest_path.read_bytes()

        with self.assertRaises(RecoveryError):
            create_verified_backup(
                self.source,
                self.backups,
                backup_name="fixed.sqlite3",
            )

        self.assertEqual(backup.read_bytes(), backup_bytes)
        self.assertEqual(manifest_path.read_bytes(), manifest_bytes)

    def test_manifest_hash_mismatch_fails_closed(self) -> None:
        manifest = create_verified_backup(self.source, self.backups)
        backup = Path(manifest["backup_path"])
        with closing(sqlite3.connect(backup)) as connection:
            connection.execute(
                "INSERT INTO parent(id, label) VALUES (2, 'tampered')"
            )
            connection.commit()

        with self.assertRaisesRegex(
            RecoveryError,
            "database_sha256 does not match",
        ):
            verify_backup(backup, manifest["manifest_path"])

    def test_corrupt_backup_and_foreign_key_violation_fail_closed(self) -> None:
        corrupt = self.root / "corrupt.sqlite3"
        corrupt.write_bytes(b"not a sqlite database")
        with self.assertRaises(RecoveryError):
            verify_backup(corrupt)

        invalid_source = self.root / "invalid.sqlite3"
        _make_database(invalid_source, violate_foreign_key=True)
        with self.assertRaisesRegex(RecoveryError, "foreign_key_check"):
            create_verified_backup(
                invalid_source,
                self.backups,
                backup_name="invalid-copy.sqlite3",
            )
        self.assertFalse((self.backups / "invalid-copy.sqlite3").exists())
        self.assertFalse(
            (self.backups / "invalid-copy.sqlite3.manifest.json").exists()
        )

    def test_unsafe_name_and_missing_paths_are_rejected(self) -> None:
        with self.assertRaises(RecoveryError):
            create_verified_backup(
                self.source,
                self.backups,
                backup_name="../escape.sqlite3",
            )
        with self.assertRaises(RecoveryError):
            create_verified_backup(
                self.root / "missing.sqlite3",
                self.backups,
            )
        with self.assertRaises(RecoveryError):
            verify_backup(self.root / "missing-backup.sqlite3")

    def test_cli_exposes_explicit_backup_and_read_only_verification(self) -> None:
        parser = build_parser()
        backup = parser.parse_args(
            ["backup", "--output-dir", str(self.backups), "--name", "safe.sqlite3"]
        )
        verify = parser.parse_args(
            [
                "verify-backup",
                str(self.backups / "safe.sqlite3"),
                "--manifest",
                str(self.backups / "safe.sqlite3.manifest.json"),
            ]
        )
        self.assertEqual(backup.command, "backup")
        self.assertEqual(backup.name, "safe.sqlite3")
        self.assertEqual(verify.command, "verify-backup")
        self.assertEqual(
            verify.manifest,
            self.backups / "safe.sqlite3.manifest.json",
        )


if __name__ == "__main__":
    unittest.main()
