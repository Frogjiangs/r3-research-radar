from __future__ import annotations

import hashlib
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path

from r3radar.storage import SCHEMA_VERSION, RadarStore


def _file_fingerprint(path: Path) -> tuple[int, int, str] | None:
    if not path.exists():
        return None
    contents = path.read_bytes()
    stat = path.stat()
    return (
        len(contents),
        stat.st_mtime_ns,
        hashlib.sha256(contents).hexdigest(),
    )


def _wal_frame_count(path: Path) -> int:
    if not path.exists():
        return 0
    contents = path.read_bytes()
    if len(contents) < 32:
        return 0
    page_size = struct.unpack(">I", contents[8:12])[0]
    if page_size == 1:
        page_size = 65536
    return (len(contents) - 32) // (page_size + 24)


class RadarStoreInitializationIdempotenceTests(unittest.TestCase):
    def test_new_database_initializes_current_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "new.sqlite3"

            with RadarStore(database_path) as store:
                schema_version = store._connection.execute(
                    """
                    SELECT value FROM schema_meta
                    WHERE key='schema_version'
                    """
                ).fetchone()["value"]
                foreign_keys = store._connection.execute(
                    "PRAGMA foreign_keys"
                ).fetchone()[0]

            self.assertEqual(schema_version, str(SCHEMA_VERSION))
            self.assertEqual(foreign_keys, 1)
            self.assertTrue(database_path.exists())

    def test_older_schema_migrates_to_current_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "legacy.sqlite3"
            connection = sqlite3.connect(database_path)
            try:
                connection.executescript(
                    f"""
                    CREATE TABLE schema_meta (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    INSERT INTO schema_meta(key, value)
                    VALUES ('schema_version', '{SCHEMA_VERSION - 1}');
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with RadarStore(database_path) as store:
                schema_version = store._connection.execute(
                    """
                    SELECT value FROM schema_meta
                    WHERE key='schema_version'
                    """
                ).fetchone()["value"]
                tables = {
                    row["name"]
                    for row in store._connection.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type='table'
                        """
                    ).fetchall()
                }

            self.assertEqual(schema_version, str(SCHEMA_VERSION))
            self.assertIn("run_publication_snapshots", tables)
            self.assertIn("research_decisions", tables)

    def test_current_schema_reopen_has_no_database_or_wal_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "current.sqlite3"
            wal_path = Path(f"{database_path}-wal")
            with RadarStore(database_path):
                pass

            database_before = _file_fingerprint(database_path)
            wal_frames_before = _wal_frame_count(wal_path)

            with RadarStore(database_path) as reopened:
                database_during = _file_fingerprint(database_path)
                wal_frames_during = _wal_frame_count(wal_path)
                total_changes = reopened._connection.total_changes
                foreign_keys = reopened._connection.execute(
                    "PRAGMA foreign_keys"
                ).fetchone()[0]

            database_after = _file_fingerprint(database_path)
            wal_frames_after = _wal_frame_count(wal_path)

            self.assertEqual(total_changes, 0)
            self.assertEqual(foreign_keys, 1)
            self.assertEqual(database_before, database_during)
            self.assertEqual(database_before, database_after)
            self.assertEqual(wal_frames_before, 0)
            self.assertEqual(wal_frames_during, 0)
            self.assertEqual(wal_frames_after, 0)

    def test_current_schema_does_not_refresh_converged_backfills(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "converged.sqlite3"
            with RadarStore(database_path) as store:
                with store.transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO profiles(
                            profile_id, profile_version, config_hash,
                            config_json, created_at
                        ) VALUES ('profile', 1, 'config', '{}', '2026-01-01')
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO runs(
                            id, profile_id, profile_version, config_hash,
                            retrieval_hash, analysis_policy_hash, mode, status,
                            started_at, updated_at, deadline_at
                        ) VALUES (
                            'run', 'profile', 1, 'config', 'retrieval',
                            'analysis', 'test', 'completed', '2026-01-01',
                            '2026-01-01', '2026-01-02'
                        )
                        """
                    )
                    query_job_id = int(
                        connection.execute(
                            """
                            INSERT INTO query_jobs(
                                run_id, query_id, source, lane, query_text,
                                status, not_before, updated_at
                            ) VALUES (
                                'run', 'query', 'source', 'core', 'query',
                                'retry', '2099-01-01', '2026-01-01'
                            )
                            """
                        ).lastrowid
                    )
                    connection.execute(
                        """
                        INSERT INTO source_cooldowns(
                            source, not_before, reason, updated_at
                        ) VALUES (
                            'source', '2099-01-01', 'existing', '2026-01-01'
                        )
                        """
                    )
                    work_id = int(
                        connection.execute(
                            """
                            INSERT INTO works(
                                canonical_key, kind, title, normalized_title,
                                lane, state, admission_code, metadata_json,
                                first_seen_at, updated_at
                            ) VALUES (
                                'work', 'paper', 'Work', 'work', 'core',
                                'analyzed', 'admitted', '{}', '2026-01-01',
                                '2026-01-01'
                            )
                            """
                        ).lastrowid
                    )
                    source_record_id = int(
                        connection.execute(
                            """
                            INSERT INTO source_records(
                                source, source_id, kind, title, metadata_json,
                                first_seen_at, last_seen_at
                            ) VALUES (
                                'source', 'record', 'paper', 'Work', '{}',
                                '2026-01-01', '2026-01-01'
                            )
                            """
                        ).lastrowid
                    )
                    connection.execute(
                        """
                        INSERT INTO run_hits(
                            run_id, work_id, query_job_id, source_record_id,
                            admitted, admission_code, admission_reason, seen_at
                        ) VALUES (
                            'run', ?, ?, ?, 1, 'admitted', 'existing',
                            '2026-01-01'
                        )
                        """,
                        (work_id, query_job_id, source_record_id),
                    )
                    connection.execute(
                        """
                        INSERT INTO work_scopes(
                            work_id, config_hash, profile_id, profile_version,
                            lane, state, admission_code, first_seen_at,
                            last_seen_at
                        ) VALUES (
                            ?, 'retrieval', 'profile', 1, 'core', 'analyzed',
                            'admitted', '2026-01-01', '2026-01-01'
                        )
                        """,
                        (work_id,),
                    )
                    connection.execute(
                        """
                        CREATE TABLE init_update_audit (
                            table_name TEXT NOT NULL
                        )
                        """
                    )
                    connection.execute(
                        """
                        CREATE TRIGGER audit_source_cooldown_update
                        AFTER UPDATE ON source_cooldowns
                        BEGIN
                            INSERT INTO init_update_audit(table_name)
                            VALUES ('source_cooldowns');
                        END
                        """
                    )
                    connection.execute(
                        """
                        CREATE TRIGGER audit_work_scope_update
                        AFTER UPDATE ON work_scopes
                        BEGIN
                            INSERT INTO init_update_audit(table_name)
                            VALUES ('work_scopes');
                        END
                        """
                    )

            with RadarStore(database_path) as reopened:
                total_changes = reopened._connection.total_changes
                cooldown = tuple(
                    reopened._connection.execute(
                        """
                        SELECT not_before, reason, updated_at
                        FROM source_cooldowns WHERE source='source'
                        """
                    ).fetchone()
                )
                scope = tuple(
                    reopened._connection.execute(
                        """
                        SELECT first_seen_at, last_seen_at
                        FROM work_scopes
                        WHERE work_id=? AND config_hash='retrieval'
                        """,
                        (work_id,),
                    ).fetchone()
                )
                audit_rows = reopened._connection.execute(
                    "SELECT table_name FROM init_update_audit"
                ).fetchall()

            self.assertEqual(total_changes, 0)
            self.assertEqual(
                cooldown,
                ("2099-01-01", "existing", "2026-01-01"),
            )
            self.assertEqual(scope, ("2026-01-01", "2026-01-01"))
            self.assertEqual(audit_rows, [])


if __name__ == "__main__":
    unittest.main()
