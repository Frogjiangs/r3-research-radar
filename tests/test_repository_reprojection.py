from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from r3radar.config import DEFAULT_CONFIG, PROJECT_DIR, Settings
from r3radar.reprojection import reproject_repository_corpus
from r3radar.storage import RadarStore
from r3radar.utils import sha256_bytes, sha256_text, utc_now


def _settings(root: Path) -> Settings:
    raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    raw["documents"]["repository_corpus"] = {
        "mode": "core_plus_sampled_aux_v1",
        "max_selected_text_bytes": 2400,
        "max_auxiliary_text_bytes": 600,
    }
    raw["documents"]["chunk_characters"] = 180
    raw["documents"]["chunk_overlap_characters"] = 20
    raw["analysis"]["batch_chunk_count"] = 2
    raw["analysis"]["synthesis_group_max_items"] = 24
    raw["analysis"]["max_parallel_batches"] = 2
    raw["analysis"]["output_detail"] = "concise_evidence"
    raw["analysis"]["budget_planning"] = {
        "retry_reserve_invocations": 0
    }
    data = root / "data"
    literature = root / "literature"
    outputs = root / "outputs"
    settings = Settings(
        raw=raw,
        config_path=DEFAULT_CONFIG,
        project_dir=PROJECT_DIR,
        workspace_dir=root,
        data_dir=data,
        literature_dir=literature,
        outputs_dir=outputs,
        database_path=data / "radar.sqlite3",
    )
    settings.ensure_directories()
    return settings


def _repository_files() -> dict[str, bytes]:
    repeated_script = (
        "def benchmark_cache():\n"
        "    values = [index * 3 for index in range(80)]\n"
        "    return sum(values)\n"
    ).encode("utf-8")
    return {
        "demo/README.md": (
            b"# Cache research demo\n"
            b"Workflow semantics guide short-lived cache retention.\n"
        ),
        "demo/pyproject.toml": b"[project]\nname = \"cache-demo\"\n",
        "demo/src/cache_policy.py": (
            b"def retention_value(workflow_step, semantic_context):\n"
            b"    return workflow_step + semantic_context\n"
        ),
        "demo/src/eviction.py": (
            b"def evict(scores):\n"
            b"    return min(scores, key=scores.get)\n"
        ),
        "demo/tests/test_cache_policy.py": (
            b"def test_retention_value():\n"
            b"    assert True\n"
        ),
        "demo/docs/design.md": (
            b"# Design\nCompare semantic value against recency and frequency.\n"
        ),
        **{
            f"demo/scripts/benchmark_{index}.py": repeated_script * 5
            for index in range(12)
        },
    }


def _archive_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    return output.getvalue()


def _legacy_text(files: dict[str, bytes]) -> str:
    return "\n\n".join(
        f"=== FILE: {name.removeprefix('demo/')} ===\n"
        + value.decode("utf-8")
        for name, value in files.items()
    )


def _insert_work(
    store: RadarStore,
    settings: Settings,
    *,
    canonical_key: str,
    kind: str,
    title: str,
) -> int:
    timestamp = utc_now()
    with store.transaction() as connection:
        cursor = connection.execute(
            """
            INSERT INTO works(
                canonical_key, kind, title, normalized_title, lane,
                state, admission_code, metadata_json, first_seen_at, updated_at
            ) VALUES (?, ?, ?, ?, 'github', 'admitted', 'test', '{}', ?, ?)
            """,
            (
                canonical_key,
                kind,
                title,
                title.casefold(),
                timestamp,
                timestamp,
            ),
        )
        work_id = int(cursor.lastrowid)
        connection.execute(
            """
            INSERT INTO work_scopes(
                work_id, config_hash, profile_id, profile_version, lane,
                state, admission_code, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, 'github', 'admitted', 'test', ?, ?)
            """,
            (
                work_id,
                settings.retrieval_hash,
                settings.profile_id,
                settings.profile_version,
                timestamp,
                timestamp,
            ),
        )
    return work_id


def _seed_repository(root: Path) -> dict[str, object]:
    settings = _settings(root)
    files = _repository_files()
    archive_bytes = _archive_bytes(files)
    archive_path = settings.data_dir / "repositories" / "demo.zip"
    archive_path.write_bytes(archive_bytes)
    legacy_text = _legacy_text(files)
    legacy_text_path = settings.literature_dir / "text" / "demo-legacy.txt"
    legacy_text_path.write_bytes(legacy_text.encode("utf-8"))
    legacy_text_sha256 = sha256_text(legacy_text)
    with RadarStore(settings.database_path) as store:
        work_id = _insert_work(
            store,
            settings,
            canonical_key="github:example/demo",
            kind="repository",
            title="Example Cache Demo",
        )
        document_id = store.save_document(
            work_id=work_id,
            content_kind="repository_zip",
            status="ready",
            source_url="https://github.com/example/demo",
            local_path=str(archive_path.resolve()),
            text_path=str(legacy_text_path.resolve()),
            content_sha256=sha256_bytes(archive_bytes),
            text_sha256=legacy_text_sha256,
            byte_count=len(archive_bytes),
            text_char_count=len(legacy_text),
            page_count=None,
            coverage={
                "complete": True,
                "reason": None,
                "coverage_scope": "legacy_all_eligible",
                "included_file_count": len(files),
            },
        )
        timestamp = utc_now()
        with store.transaction() as connection:
            cursor = connection.execute(
                """
                INSERT INTO analysis_tasks(
                    work_id, document_id, provider, prompt_version,
                    config_hash, retrieval_hash, profile_id, profile_version,
                    input_sha256, status, updated_at, completed_at
                ) VALUES (?, ?, 'codex_cli', 'legacy-prompt',
                          'legacy-analysis-policy', ?, ?, ?, ?,
                          'completed', ?, ?)
                """,
                (
                    work_id,
                    document_id,
                    settings.retrieval_hash,
                    settings.profile_id,
                    settings.profile_version,
                    legacy_text_sha256,
                    timestamp,
                    timestamp,
                ),
            )
            legacy_task_id = int(cursor.lastrowid)
            cursor = connection.execute(
                """
                INSERT INTO analyses(
                    task_id, work_id, provider, model, prompt_version,
                    config_hash, retrieval_hash, profile_id, profile_version,
                    deep_read_status, tier, score, analysis_json,
                    coverage_json, provider_receipt_json, provenance_status,
                    created_at
                ) VALUES (?, ?, 'codex_cli', 'gpt-5.6-sol', 'legacy-prompt',
                          'legacy-analysis-policy', ?, ?, ?, 'complete',
                          'watch', 0.5, '{}', '{}', '{}', 'verified', ?)
                """,
                (
                    legacy_task_id,
                    work_id,
                    settings.retrieval_hash,
                    settings.profile_id,
                    settings.profile_version,
                    timestamp,
                ),
            )
            legacy_analysis_id = int(cursor.lastrowid)

        other_work_id = _insert_work(
            store,
            settings,
            canonical_key="web:unrelated",
            kind="paper",
            title="Unrelated Ready Work",
        )
        store.save_document(
            work_id=other_work_id,
            content_kind="web_text",
            status="ready",
            source_url="https://example.invalid/unrelated",
            local_path=None,
            text_path=None,
            content_sha256=sha256_text("unrelated"),
            text_sha256=sha256_text("unrelated"),
            byte_count=9,
            text_char_count=9,
            page_count=None,
            coverage={},
        )
    return {
        "settings": settings,
        "work_id": work_id,
        "document_id": document_id,
        "legacy_task_id": legacy_task_id,
        "legacy_analysis_id": legacy_analysis_id,
        "other_work_id": other_work_id,
        "archive_path": archive_path,
        "legacy_text_path": legacy_text_path,
    }


def _logical_snapshot(database_path: Path) -> dict[str, list[tuple]]:
    connection = sqlite3.connect(database_path)
    try:
        return {
            table: connection.execute(
                f"SELECT * FROM {table} ORDER BY 1"
            ).fetchall()
            for table in (
                "documents",
                "content_revisions",
                "analysis_tasks",
                "analyses",
                "work_scopes",
            )
        }
    finally:
        connection.close()


def _tree_snapshot(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class RepositoryReprojectionTests(unittest.TestCase):
    def test_dry_run_is_read_only_and_reports_smaller_call_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)
            database_hash = hashlib.sha256(
                settings.database_path.read_bytes()
            ).hexdigest()
            tree_before = _tree_snapshot(root)
            logical_before = _logical_snapshot(settings.database_path)

            result = reproject_repository_corpus(settings)

            self.assertEqual(result["status"], "ready")
            self.assertFalse(result["network_access"])
            self.assertEqual(result["candidate_count"], 1)
            self.assertEqual(result["would_change_count"], 1)
            candidate = result["candidates"][0]
            self.assertGreater(
                candidate["old_chunks"],
                candidate["selected_chunks"],
            )
            self.assertGreater(candidate["estimated_call_savings"], 0)
            self.assertEqual(
                database_hash,
                hashlib.sha256(settings.database_path.read_bytes()).hexdigest(),
            )
            self.assertEqual(tree_before, _tree_snapshot(root))
            self.assertEqual(
                logical_before,
                _logical_snapshot(settings.database_path),
            )

    def test_apply_is_atomic_scoped_auditable_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)

            first = reproject_repository_corpus(settings, apply=True)

            self.assertEqual(first["status"], "completed")
            self.assertEqual(first["applied_count"], 1)
            candidate = first["candidates"][0]
            text_path = Path(candidate["text_path"])
            inventory_path = Path(candidate["inventory_path"])
            self.assertTrue(text_path.is_file())
            self.assertTrue(inventory_path.is_file())
            self.assertTrue(Path(fixture["archive_path"]).is_file())
            self.assertTrue(Path(fixture["legacy_text_path"]).is_file())
            self.assertNotEqual(
                text_path.resolve(),
                Path(fixture["legacy_text_path"]).resolve(),
            )

            connection = sqlite3.connect(settings.database_path)
            connection.row_factory = sqlite3.Row
            try:
                document = connection.execute(
                    "SELECT * FROM documents WHERE id=?",
                    (fixture["document_id"],),
                ).fetchone()
                coverage = json.loads(document["coverage_json"])
                self.assertEqual(
                    coverage["coverage_scope"],
                    "selected_repository_corpus",
                )
                self.assertEqual(
                    coverage["reprojection_receipt"]["network_access"],
                    False,
                )
                self.assertEqual(document["text_path"], str(text_path))
                self.assertEqual(
                    document["text_sha256"],
                    sha256_text(text_path.read_text(encoding="utf-8")),
                )
                self.assertEqual(
                    coverage["inventory_sha256"],
                    sha256_text(inventory_path.read_text(encoding="utf-8")),
                )
                self.assertEqual(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM content_revisions
                        WHERE work_id=?
                        """,
                        (fixture["work_id"],),
                    ).fetchone()[0],
                    2,
                )
                legacy_task = connection.execute(
                    "SELECT status FROM analysis_tasks WHERE id=?",
                    (fixture["legacy_task_id"],),
                ).fetchone()
                self.assertEqual(legacy_task["status"], "completed")
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT id FROM analyses WHERE id=?",
                        (fixture["legacy_analysis_id"],),
                    ).fetchone()
                )
                current_tasks = connection.execute(
                    """
                    SELECT work_id, status, input_sha256
                    FROM analysis_tasks WHERE config_hash=?
                    """,
                    (settings.analysis_policy_hash,),
                ).fetchall()
                self.assertEqual(len(current_tasks), 1)
                self.assertEqual(
                    current_tasks[0]["work_id"],
                    fixture["work_id"],
                )
                self.assertEqual(current_tasks[0]["status"], "pending")
                self.assertEqual(
                    current_tasks[0]["input_sha256"],
                    document["text_sha256"],
                )
                other_task_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM analysis_tasks
                    WHERE work_id=? AND config_hash=?
                    """,
                    (
                        fixture["other_work_id"],
                        settings.analysis_policy_hash,
                    ),
                ).fetchone()[0]
                self.assertEqual(other_task_count, 0)
            finally:
                connection.close()

            logical_after_first = _logical_snapshot(settings.database_path)
            tree_after_first = _tree_snapshot(root)
            second = reproject_repository_corpus(settings, apply=True)
            self.assertEqual(second["status"], "completed")
            self.assertEqual(second["applied_count"], 0)
            self.assertEqual(second["unchanged_count"], 1)
            self.assertEqual(
                logical_after_first,
                _logical_snapshot(settings.database_path),
            )
            self.assertEqual(tree_after_first, _tree_snapshot(root))

    def test_database_failure_removes_only_new_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)
            logical_before = _logical_snapshot(settings.database_path)
            tree_before = _tree_snapshot(root)

            with patch.object(
                RadarStore,
                "save_selected_repository_revision_and_queue",
                side_effect=RuntimeError("injected database failure"),
            ):
                result = reproject_repository_corpus(settings, apply=True)

            self.assertEqual(result["status"], "completed_with_gaps")
            self.assertEqual(result["applied_count"], 0)
            self.assertEqual(result["failed_count"], 1)
            self.assertIn(
                "injected database failure",
                result["candidates"][0]["error"],
            )
            self.assertEqual(
                logical_before,
                _logical_snapshot(settings.database_path),
            )
            self.assertEqual(tree_before, _tree_snapshot(root))
            self.assertTrue(Path(fixture["archive_path"]).is_file())
            self.assertTrue(Path(fixture["legacy_text_path"]).is_file())

    def test_active_task_from_any_policy_blocks_reprojection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)
            connection = sqlite3.connect(settings.database_path)
            try:
                connection.execute(
                    """
                    UPDATE analysis_tasks
                    SET status='running', claimed_run_id='older-policy-run',
                        claim_lease_token='lease'
                    WHERE id=?
                    """,
                    (fixture["legacy_task_id"],),
                )
                connection.commit()
            finally:
                connection.close()
            logical_before = _logical_snapshot(settings.database_path)
            tree_before = _tree_snapshot(root)

            result = reproject_repository_corpus(settings, apply=True)

            self.assertEqual(result["status"], "completed_with_gaps")
            self.assertEqual(result["failed_count"], 1)
            self.assertIn(
                "active analysis task",
                result["candidates"][0]["error"],
            )
            self.assertEqual(
                logical_before,
                _logical_snapshot(settings.database_path),
            )
            self.assertEqual(tree_before, _tree_snapshot(root))

    def test_uncheckpointed_wal_is_read_without_touching_source_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)
            writer = sqlite3.connect(settings.database_path)
            try:
                writer.execute("PRAGMA wal_autocheckpoint=0")
                writer.execute(
                    "UPDATE works SET title='WAL-visible title' WHERE id=?",
                    (fixture["work_id"],),
                )
                writer.commit()
                self.assertTrue(
                    Path(f"{settings.database_path}-wal").is_file()
                )
                source_before = _tree_snapshot(root)

                result = reproject_repository_corpus(settings)

                self.assertEqual(
                    result["candidates"][0]["title"],
                    "WAL-visible title",
                )
                self.assertEqual(source_before, _tree_snapshot(root))
            finally:
                writer.close()

    def test_active_scope_in_another_retrieval_blocks_apply(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)
            timestamp = utc_now()
            connection = sqlite3.connect(settings.database_path)
            try:
                connection.execute(
                    """
                    INSERT INTO work_scopes(
                        work_id, config_hash, profile_id, profile_version,
                        lane, state, admission_code, active_run_id,
                        active_lease_token, first_seen_at, last_seen_at
                    ) VALUES (?, 'other-retrieval', ?, ?, 'github',
                              'content_running', 'test', 'other-run',
                              'other-lease', ?, ?)
                    """,
                    (
                        fixture["work_id"],
                        settings.profile_id,
                        settings.profile_version,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            logical_before = _logical_snapshot(settings.database_path)
            tree_before = _tree_snapshot(root)

            result = reproject_repository_corpus(settings, apply=True)

            self.assertEqual(result["status"], "completed_with_gaps")
            self.assertEqual(result["failed_count"], 1)
            self.assertIn(
                "active retrieval scope",
                result["candidates"][0]["error"],
            )
            self.assertEqual(
                logical_before,
                _logical_snapshot(settings.database_path),
            )
            self.assertEqual(tree_before, _tree_snapshot(root))

    def test_any_running_run_blocks_apply_even_when_latest_is_terminal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)
            with RadarStore(settings.database_path) as store:
                store.register_profile(settings)
                with store.transaction() as connection:
                    for (
                        run_id,
                        status,
                        started_at,
                        ended_at,
                    ) in (
                        (
                            "older-running",
                            "running",
                            "2026-01-01T00:00:00+00:00",
                            None,
                        ),
                        (
                            "newer-terminal",
                            "completed",
                            "2026-01-02T00:00:00+00:00",
                            "2026-01-02T00:05:00+00:00",
                        ),
                    ):
                        connection.execute(
                            """
                            INSERT INTO runs(
                                id, profile_id, profile_version, config_hash,
                                retrieval_hash, analysis_policy_hash, mode,
                                status, started_at, updated_at, ended_at,
                                deadline_at
                            ) VALUES (?, ?, ?, ?, ?, ?, 'test', ?, ?, ?, ?,
                                      '2027-01-01T00:00:00+00:00')
                            """,
                            (
                                run_id,
                                settings.profile_id,
                                settings.profile_version,
                                settings.config_hash,
                                settings.retrieval_hash,
                                settings.analysis_policy_hash,
                                status,
                                started_at,
                                started_at,
                                ended_at,
                            ),
                        )
            logical_before = _logical_snapshot(settings.database_path)
            tree_before = _tree_snapshot(root)

            with self.assertRaisesRegex(
                RuntimeError,
                "older-running is active",
            ):
                reproject_repository_corpus(settings, apply=True)

            self.assertEqual(
                logical_before,
                _logical_snapshot(settings.database_path),
            )
            self.assertEqual(tree_before, _tree_snapshot(root))

    def test_infeasible_task_budget_is_visible_and_apply_fails_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _seed_repository(root)
            settings = fixture["settings"]
            assert isinstance(settings, Settings)
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_task"
            ] = 1
            logical_before = _logical_snapshot(settings.database_path)
            tree_before = _tree_snapshot(root)

            dry_run = reproject_repository_corpus(settings)
            applied = reproject_repository_corpus(settings, apply=True)

            candidate = dry_run["candidates"][0]
            self.assertEqual(candidate["status"], "budget_blocked")
            self.assertFalse(candidate["budget_feasible"])
            self.assertGreater(
                candidate["selected_estimated_calls"],
                candidate["task_call_budget"],
            )
            self.assertEqual(dry_run["status"], "ready_with_gaps")
            self.assertEqual(applied["status"], "completed_with_gaps")
            self.assertEqual(applied["applied_count"], 0)
            self.assertEqual(applied["failed_count"], 1)
            self.assertIn(
                "exceed max_invocations_per_task",
                applied["candidates"][0]["error"],
            )
            self.assertEqual(
                logical_before,
                _logical_snapshot(settings.database_path),
            )
            self.assertEqual(tree_before, _tree_snapshot(root))


if __name__ == "__main__":
    unittest.main()
