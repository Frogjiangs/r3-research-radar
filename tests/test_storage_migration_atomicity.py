from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from r3radar.storage import SCHEMA_VERSION, RadarStore


class InjectedMigrationFailure(RuntimeError):
    pass


def _inject_failure_at(expected_step: str):
    def inject(step: str) -> None:
        if step == expected_step:
            raise InjectedMigrationFailure(f"injected at {step}")

    return inject


def _create_minimal_legacy_database(path: Path) -> None:
    connection = sqlite3.connect(path)
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
    finally:
        connection.close()


def _schema_version(connection: sqlite3.Connection) -> str:
    return str(
        connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0]
    )


def _assert_sqlite_health(test_case: unittest.TestCase, path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        test_case.assertEqual(
            connection.execute("PRAGMA integrity_check").fetchone()[0],
            "ok",
        )
        test_case.assertEqual(
            connection.execute("PRAGMA foreign_key_check").fetchall(),
            [],
        )
    finally:
        connection.close()


class RadarStoreMigrationAtomicityTests(unittest.TestCase):
    def test_process_exit_before_commit_recovers_old_version(self) -> None:
        """A worker disappearance must not publish a partially upgraded schema."""
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "crashed.sqlite3"
            _create_minimal_legacy_database(database_path)
            child_code = "\n".join(
                (
                    "import os, sys",
                    "from pathlib import Path",
                    "from r3radar.storage import RadarStore",
                    "def crash(step):",
                    "    if step == 'after_schema_version':",
                    "        os._exit(93)",
                    "RadarStore(Path(sys.argv[1]), _migration_fault_injector=crash)",
                )
            )
            completed = subprocess.run(
                [sys.executable, "-c", child_code, str(database_path)],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 93, completed.stderr)

            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(
                    _schema_version(connection),
                    str(SCHEMA_VERSION - 1),
                )
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                self.assertEqual(tables, {"schema_meta"})
            finally:
                connection.close()
            _assert_sqlite_health(self, database_path)

            with RadarStore(database_path) as recovered:
                self.assertEqual(
                    _schema_version(recovered._connection),
                    str(SCHEMA_VERSION),
                )
            _assert_sqlite_health(self, database_path)

    def test_failure_matrix_keeps_legacy_version_and_reopens_cleanly(self) -> None:
        failure_steps = (
            "before_schema",
            "after_schema",
            "after_data_backfills",
            "after_document_policy",
            "before_schema_version",
            "after_schema_version",
        )
        for failure_step in failure_steps:
            with self.subTest(failure_step=failure_step):
                with tempfile.TemporaryDirectory() as temporary:
                    database_path = Path(temporary) / "legacy.sqlite3"
                    _create_minimal_legacy_database(database_path)

                    with self.assertRaisesRegex(
                        RuntimeError,
                        rf"old_version={SCHEMA_VERSION - 1}.*"
                        rf"target_version={SCHEMA_VERSION}.*"
                        rf"step={failure_step}.*Reopen",
                    ):
                        RadarStore(
                            database_path,
                            _migration_fault_injector=_inject_failure_at(
                                failure_step
                            ),
                        )

                    connection = sqlite3.connect(database_path)
                    try:
                        self.assertEqual(
                            _schema_version(connection),
                            str(SCHEMA_VERSION - 1),
                        )
                        tables = {
                            str(row[0])
                            for row in connection.execute(
                                "SELECT name FROM sqlite_master "
                                "WHERE type='table'"
                            ).fetchall()
                        }
                        self.assertEqual(tables, {"schema_meta"})
                    finally:
                        connection.close()
                    _assert_sqlite_health(self, database_path)

                    with RadarStore(database_path) as recovered:
                        self.assertEqual(
                            _schema_version(recovered._connection),
                            str(SCHEMA_VERSION),
                        )
                    _assert_sqlite_health(self, database_path)

    def test_keyboard_interrupt_rolls_back_without_changing_exception_type(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "interrupted.sqlite3"
            _create_minimal_legacy_database(database_path)

            def interrupt(step: str) -> None:
                if step == "after_schema_version":
                    raise KeyboardInterrupt()

            with self.assertRaises(KeyboardInterrupt):
                RadarStore(
                    database_path,
                    _migration_fault_injector=interrupt,
                )

            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(
                    _schema_version(connection),
                    str(SCHEMA_VERSION - 1),
                )
                self.assertIsNone(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master "
                        "WHERE type='table' AND name='publication_outbox'"
                    ).fetchone()
                )
            finally:
                connection.close()
            _assert_sqlite_health(self, database_path)

    def test_added_columns_are_rolled_back_with_the_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "legacy-columns.sqlite3"
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
                    CREATE TABLE query_jobs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        run_id TEXT NOT NULL,
                        query_id TEXT NOT NULL,
                        source TEXT NOT NULL,
                        lane TEXT NOT NULL,
                        query_text TEXT NOT NULL,
                        job_kind TEXT NOT NULL DEFAULT 'official',
                        status TEXT NOT NULL DEFAULT 'pending',
                        cursor TEXT,
                        page_no INTEGER NOT NULL DEFAULT 0,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        result_count INTEGER NOT NULL DEFAULT 0,
                        error TEXT,
                        started_at TEXT,
                        updated_at TEXT NOT NULL,
                        completed_at TEXT,
                        UNIQUE(run_id, query_id, source, job_kind)
                    );
                    CREATE INDEX idx_query_jobs_claim
                    ON query_jobs(run_id, status, id);
                    """
                )
            finally:
                connection.close()

            with self.assertRaisesRegex(
                RuntimeError,
                "step=after_query_job_columns",
            ):
                RadarStore(
                    database_path,
                    _migration_fault_injector=_inject_failure_at(
                        "after_query_job_columns"
                    ),
                )

            connection = sqlite3.connect(database_path)
            try:
                columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(query_jobs)"
                    ).fetchall()
                }
                self.assertNotIn("not_before", columns)
                self.assertNotIn("claim_lease_token", columns)
                self.assertEqual(
                    _schema_version(connection),
                    str(SCHEMA_VERSION - 1),
                )
            finally:
                connection.close()
            _assert_sqlite_health(self, database_path)

            with RadarStore(database_path) as recovered:
                columns = {
                    str(row["name"])
                    for row in recovered._connection.execute(
                        "PRAGMA table_info(query_jobs)"
                    ).fetchall()
                }
                self.assertIn("not_before", columns)
                self.assertIn("claim_lease_token", columns)
                self.assertEqual(
                    _schema_version(recovered._connection),
                    str(SCHEMA_VERSION),
                )

    def test_document_policy_backfill_rolls_back_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "legacy-document.sqlite3"
            with RadarStore(database_path) as store:
                with store.transaction() as connection:
                    work_id = int(
                        connection.execute(
                            """
                            INSERT INTO works(
                                canonical_key, kind, title, normalized_title,
                                lane, state, admission_code, metadata_json,
                                first_seen_at, updated_at
                            ) VALUES (
                                'legacy-work', 'repository', 'Legacy Work',
                                'legacy work', 'code', 'content_ready',
                                'admitted', '{}', '2026-08-01', '2026-08-01'
                            )
                            """
                        ).lastrowid
                    )
                    connection.execute(
                        """
                        INSERT INTO documents(
                            work_id, content_kind, status, coverage_json,
                            created_at, updated_at
                        ) VALUES (?, 'repository', 'ready', '{}',
                                  '2026-08-01', '2026-08-01')
                        """,
                        (work_id,),
                    )
                    connection.execute(
                        "UPDATE schema_meta SET value=? "
                        "WHERE key='schema_version'",
                        (str(SCHEMA_VERSION - 1),),
                    )

            with self.assertRaisesRegex(
                RuntimeError,
                "step=after_document_policy",
            ):
                RadarStore(
                    database_path,
                    _migration_fault_injector=_inject_failure_at(
                        "after_document_policy"
                    ),
                )

            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM document_processing_observations"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    _schema_version(connection),
                    str(SCHEMA_VERSION - 1),
                )
            finally:
                connection.close()

            with RadarStore(database_path) as recovered:
                self.assertEqual(
                    recovered._connection.execute(
                        "SELECT COUNT(*) FROM document_processing_observations"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    _schema_version(recovered._connection),
                    str(SCHEMA_VERSION),
                )
            _assert_sqlite_health(self, database_path)

    def test_data_backfill_rolls_back_then_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "legacy-backfill.sqlite3"
            with RadarStore(database_path) as store:
                with store.transaction() as connection:
                    connection.execute(
                        """
                        INSERT INTO profiles(
                            profile_id, profile_version, config_hash,
                            config_json, created_at
                        ) VALUES ('profile', 1, 'config', '{}', '2026-08-01')
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO runs(
                            id, profile_id, profile_version, config_hash,
                            mode, status, started_at, updated_at, deadline_at
                        ) VALUES (
                            'run', 'profile', 1, 'config', 'test', 'completed',
                            '2026-08-01', '2026-08-01', '2026-08-02'
                        )
                        """
                    )
                    connection.execute(
                        """
                        INSERT INTO query_jobs(
                            run_id, query_id, source, lane, query_text,
                            status, not_before, updated_at
                        ) VALUES (
                            'run', 'query', 'source', 'core', 'query',
                            'retry', '2099-01-01', '2026-08-01'
                        )
                        """
                    )
                    connection.execute(
                        "UPDATE schema_meta SET value=? "
                        "WHERE key='schema_version'",
                        (str(SCHEMA_VERSION - 1),),
                    )

            with self.assertRaisesRegex(
                RuntimeError,
                "step=after_data_backfills",
            ):
                RadarStore(
                    database_path,
                    _migration_fault_injector=_inject_failure_at(
                        "after_data_backfills"
                    ),
                )

            connection = sqlite3.connect(database_path)
            try:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM source_cooldowns"
                    ).fetchone()[0],
                    0,
                )
                self.assertEqual(
                    _schema_version(connection),
                    str(SCHEMA_VERSION - 1),
                )
            finally:
                connection.close()

            with RadarStore(database_path) as recovered:
                self.assertEqual(
                    recovered._connection.execute(
                        "SELECT COUNT(*) FROM source_cooldowns"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    _schema_version(recovered._connection),
                    str(SCHEMA_VERSION),
                )
            _assert_sqlite_health(self, database_path)


if __name__ == "__main__":
    unittest.main()
