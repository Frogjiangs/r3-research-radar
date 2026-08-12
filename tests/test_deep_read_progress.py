from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from r3radar.document_policy import CURRENT_PDF_DOCUMENT_POLICY_HASH
from r3radar.storage import RadarStore
from tests.test_core import current_pdf_ready_coverage, make_settings


class DeepReadProgressTests(unittest.TestCase):
    def test_reports_live_progress_and_detects_stale_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            now = datetime.now(timezone.utc)
            now_text = now.isoformat(timespec="seconds")
            text_sha256 = "a" * 64
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "deep-read-progress",
                )
                with store.transaction() as connection:
                    work_id = int(
                        connection.execute(
                            """
                            INSERT INTO works(
                                canonical_key, kind, title, normalized_title,
                                year, lane, state, admission_code,
                                metadata_json, first_seen_at, updated_at
                            ) VALUES (
                                'fixture:deep-read-progress', 'paper',
                                'Live deep-read fixture',
                                'live deep-read fixture', 2026, 'core',
                                'analysis_running', 'fixture', '{}', ?, ?
                            )
                            """,
                            (now_text, now_text),
                        ).lastrowid
                    )
                    connection.execute(
                        """
                        INSERT INTO work_scopes(
                            work_id, config_hash, profile_id, profile_version,
                            lane, state, admission_code, active_run_id,
                            active_lease_token, first_seen_at, last_seen_at
                        ) VALUES (
                            ?, ?, ?, ?, 'core', 'analysis_running', 'fixture',
                            ?, ?, ?, ?
                        )
                        """,
                        (
                            work_id,
                            settings.retrieval_hash,
                            settings.profile_id,
                            settings.profile_version,
                            run_id,
                            lease_token,
                            now_text,
                            now_text,
                        ),
                    )
                    document_id = int(
                        connection.execute(
                            """
                            INSERT INTO documents(
                                work_id, content_kind, status, source_url,
                                content_sha256, text_sha256, byte_count,
                                text_char_count, page_count,
                                document_policy_hash, coverage_json,
                                created_at, updated_at
                            ) VALUES (
                                ?, 'paper_pdf', 'ready',
                                'https://example.test/live.pdf',
                                'pdf-fixture', ?, 100, 100, 1, ?, ?, ?, ?
                            )
                            """,
                            (
                                work_id,
                                text_sha256,
                                CURRENT_PDF_DOCUMENT_POLICY_HASH,
                                json.dumps(current_pdf_ready_coverage()),
                                now_text,
                                now_text,
                            ),
                        ).lastrowid
                    )
                    task_id = int(
                        connection.execute(
                            """
                            INSERT INTO analysis_tasks(
                                work_id, document_id, provider, prompt_version,
                                config_hash, retrieval_hash, profile_id,
                                profile_version, input_sha256, claimed_run_id,
                                claim_lease_token, status, chunk_total,
                                chunk_done, started_at, updated_at
                            ) VALUES (
                                ?, ?, 'codex_cli', 'fixture', ?, ?, ?, ?, ?,
                                ?, ?, 'running', 12, 6, ?, ?
                            )
                            """,
                            (
                                work_id,
                                document_id,
                                settings.analysis_policy_hash,
                                settings.retrieval_hash,
                                settings.profile_id,
                                settings.profile_version,
                                text_sha256,
                                run_id,
                                lease_token,
                                now_text,
                                now_text,
                            ),
                        ).lastrowid
                    )
                    connection.execute(
                        """
                        INSERT INTO model_invocations(
                            invocation_id, run_id, task_id, work_id, provider,
                            purpose, model, duration_seconds, receipt_sha256,
                            receipt_json, created_at
                        ) VALUES (
                            'fixture-live-receipt', ?, ?, ?, 'codex_cli',
                            'analysis_batch', 'fixture', 91.5,
                            'receipt-fixture', '{}', ?
                        )
                        """,
                        (run_id, task_id, work_id, now_text),
                    )

                store.update_analysis_progress(
                    task_id=task_id,
                    phase="hierarchical_synthesis",
                    phase_done=2,
                    phase_total=5,
                    lease_token=lease_token,
                )
                progress = store.deep_read_progress(
                    settings.analysis_policy_hash,
                    retrieval_hash=settings.retrieval_hash,
                    run_id=run_id,
                )
                self.assertEqual(progress["state"], "running")
                self.assertEqual(progress["total"], 1)
                self.assertEqual(progress["running"], 1)
                self.assertEqual(progress["queued"], 0)
                self.assertEqual(progress["current_task"]["chunk_done"], 6)
                self.assertEqual(progress["current_task"]["chunk_total"], 12)
                self.assertEqual(
                    progress["current_task"]["phase"],
                    "hierarchical_synthesis",
                )
                self.assertEqual(progress["current_task"]["phase_done"], 2)
                self.assertEqual(progress["current_task"]["phase_total"], 5)
                self.assertEqual(
                    progress["current_task"]["model_invocation_count"],
                    1,
                )
                self.assertEqual(
                    progress["current_task"]["title"],
                    "Live deep-read fixture",
                )
                self.assertEqual(
                    progress["current_task"]["last_model_duration_seconds"],
                    91.5,
                )

                stale_text = (now - timedelta(minutes=15)).isoformat(
                    timespec="seconds"
                )
                expired_text = (now - timedelta(minutes=1)).isoformat(
                    timespec="seconds"
                )
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE analysis_tasks SET updated_at=? WHERE id=?
                        """,
                        (stale_text, task_id),
                    )
                    connection.execute(
                        """
                        UPDATE model_invocations
                        SET created_at=? WHERE invocation_id='fixture-live-receipt'
                        """,
                        (stale_text,),
                    )
                    connection.execute(
                        """
                        UPDATE runs SET lease_expires_at=? WHERE id=?
                        """,
                        (expired_text, run_id),
                    )
                stalled = store.deep_read_progress(
                    settings.analysis_policy_hash,
                    retrieval_hash=settings.retrieval_hash,
                    run_id=run_id,
                )
                self.assertEqual(stalled["state"], "stalled")
                self.assertGreaterEqual(stalled["last_activity_age_seconds"], 600)


if __name__ == "__main__":
    unittest.main()
