from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from r3radar.calibration import (
    CalibrationError,
    GOLD_SET_SCHEMA,
    _LABELS,
    evaluate_gold_set,
    evaluate_gold_set_file,
)
from r3radar.config import canonical_json


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _gold_set(
    *,
    source_run_id: str = "source-run",
    retrieval_hash: str = "a" * 64,
    verified: bool,
) -> dict:
    items = []
    for work_id in range(1, 51):
        input_sha256 = _sha256_text(f"input-{work_id}")
        snapshot = {
            "schema": "r3/publication-item-snapshot/v1",
            "analysis_id": work_id,
            "work_id": work_id,
            "input_sha256": input_sha256,
        }
        items.append(
            {
                "item_id": f"analysis:{work_id}",
                "record_class": "complete_analysis",
                "work_id": work_id,
                "analysis_id": work_id,
                "input_sha256": input_sha256,
                "snapshot_sha256": _sha256_text(canonical_json(snapshot)),
                "captured_as": "publication_selected",
                "selection_bucket": "must_read",
                "review_context": {"title": f"work {work_id}"},
                "frozen_snapshot": snapshot,
                "human_label": "known_important" if verified else None,
                "human_notes": None,
            }
        )
    return {
        "schema": GOLD_SET_SCHEMA,
        "scope": {
            "run_id": source_run_id,
            "issue_id": "issue-1",
            "profile_id": "r3-cache-value",
            "profile_version": 1,
            "config_hash": "e" * 64,
            "retrieval_hash": retrieval_hash,
            "analysis_policy_hash": "b" * 64,
            "database_sha256_at_draft": "c" * 64,
        },
        "review": {
            "status": "human_verified" if verified else "pending_human_verification",
            "reviewer": "human-reviewer" if verified else None,
            "reviewed_at": "2026-07-30T10:00:00+08:00" if verified else None,
            "allowed_labels": list(_LABELS),
            "instructions": "Review each frozen item independently.",
        },
        "sampling": {
            "actual_count": len(items),
            "selection_bias_warning": "Run-derived sample.",
        },
        "items": items,
    }


class GoldSetDocumentIntegrityTests(unittest.TestCase):
    def test_unlabeled_draft_never_reports_recall(self) -> None:
        result = evaluate_gold_set(
            _gold_set(verified=False),
            candidate_work_ids=set(range(1, 51)),
            same_source=False,
        )

        self.assertEqual(result["status"], "pending_human_verification")
        self.assertIsNone(result["recall_at_candidate"])
        self.assertIsNone(result["coverage_at_candidate"])
        self.assertFalse(result["passed"])

    def test_schema_and_scope_are_strict(self) -> None:
        wrong_schema = _gold_set(verified=False)
        wrong_schema["schema"] = "r3/gold-set-review/v0"
        with self.assertRaisesRegex(CalibrationError, "schema"):
            evaluate_gold_set(wrong_schema, candidate_work_ids=set())

        missing_scope_field = _gold_set(verified=False)
        del missing_scope_field["scope"]["issue_id"]
        with self.assertRaisesRegex(CalibrationError, "scope"):
            evaluate_gold_set(missing_scope_field, candidate_work_ids=set())

        extra_scope_field = _gold_set(verified=False)
        extra_scope_field["scope"]["untracked"] = True
        with self.assertRaisesRegex(CalibrationError, "scope"):
            evaluate_gold_set(extra_scope_field, candidate_work_ids=set())

    def test_item_work_and_input_identities_are_unique(self) -> None:
        duplicate_item = _gold_set(verified=False)
        duplicate_item["items"][1]["item_id"] = duplicate_item["items"][0]["item_id"]
        with self.assertRaisesRegex(CalibrationError, "duplicate Gold Set item_id"):
            evaluate_gold_set(duplicate_item, candidate_work_ids=set())

        duplicate_work = _gold_set(verified=False)
        duplicate_work["items"][1]["work_id"] = duplicate_work["items"][0]["work_id"]
        with self.assertRaisesRegex(CalibrationError, "duplicate Gold Set work_id"):
            evaluate_gold_set(duplicate_work, candidate_work_ids=set())

        duplicate_input = _gold_set(verified=False)
        duplicate_input["items"][1]["input_sha256"] = duplicate_input["items"][0][
            "input_sha256"
        ]
        duplicate_input["items"][1]["frozen_snapshot"]["input_sha256"] = (
            duplicate_input["items"][0]["input_sha256"]
        )
        duplicate_input["items"][1]["snapshot_sha256"] = _sha256_text(
            canonical_json(duplicate_input["items"][1]["frozen_snapshot"])
        )
        with self.assertRaisesRegex(CalibrationError, "duplicate Gold Set input_sha256"):
            evaluate_gold_set(duplicate_input, candidate_work_ids=set())

    def test_snapshot_checksum_and_human_review_metadata_are_enforced(self) -> None:
        tampered = _gold_set(verified=False)
        tampered["items"][0]["frozen_snapshot"]["work_id"] = 999
        with self.assertRaisesRegex(CalibrationError, "frozen_snapshot work_id mismatch"):
            evaluate_gold_set(tampered, candidate_work_ids=set())

        missing_reviewer = _gold_set(verified=True)
        missing_reviewer["review"]["reviewer"] = None
        with self.assertRaisesRegex(CalibrationError, "review.reviewer"):
            evaluate_gold_set(missing_reviewer, candidate_work_ids=set())

        naive_review_time = _gold_set(verified=True)
        naive_review_time["review"]["reviewed_at"] = "2026-07-30T10:00:00"
        with self.assertRaisesRegex(CalibrationError, "timezone"):
            evaluate_gold_set(naive_review_time, candidate_work_ids=set())

    def test_same_source_is_coverage_not_recall(self) -> None:
        result = evaluate_gold_set(
            _gold_set(verified=True),
            candidate_work_ids=set(range(1, 46)),
            same_source=True,
        )

        self.assertEqual(result["status"], "same_source_coverage_only")
        self.assertEqual(result["coverage_at_candidate"], 0.9)
        self.assertIsNone(result["recall_at_candidate"])
        self.assertFalse(result["passed"])


class GoldSetFileEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "radar.sqlite3"
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(
                """
                CREATE TABLE runs (
                    id TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL,
                    profile_version INTEGER NOT NULL,
                    config_hash TEXT NOT NULL,
                    retrieval_hash TEXT NOT NULL,
                    analysis_policy_hash TEXT NOT NULL
                );
                CREATE TABLE run_hits (
                    run_id TEXT NOT NULL,
                    work_id INTEGER NOT NULL
                );
                """
            )
            connection.executemany(
                """
                INSERT INTO runs(
                    id, profile_id, profile_version, config_hash,
                    retrieval_hash, analysis_policy_hash
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        "source-run",
                        "r3-cache-value",
                        1,
                        "e" * 64,
                        "a" * 64,
                        "b" * 64,
                    ),
                    (
                        "same-source-run",
                        "r3-cache-value",
                        2,
                        "f" * 64,
                        "a" * 64,
                        "b" * 64,
                    ),
                    (
                        "independent-run",
                        "r3-cache-value",
                        2,
                        "f" * 64,
                        "d" * 64,
                        "b" * 64,
                    ),
                ],
            )
            connection.executemany(
                "INSERT INTO run_hits(run_id, work_id) VALUES (?, ?)",
                [
                    *((("same-source-run", work_id) for work_id in range(1, 51))),
                    *((("independent-run", work_id) for work_id in range(1, 46))),
                ],
            )
            connection.commit()
        self.gold_path = self.root / "gold.json"
        self.gold_path.write_text(
            json.dumps(_gold_set(verified=True), ensure_ascii=False),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _settings(self, *, retrieval_hash: str) -> SimpleNamespace:
        return SimpleNamespace(
            database_path=self.database,
            profile_id="r3-cache-value",
            profile_version=2,
            config_hash="f" * 64,
            retrieval_hash=retrieval_hash,
            analysis_policy_hash="b" * 64,
        )

    def test_candidate_run_cannot_be_the_gold_source_run(self) -> None:
        with self.assertRaisesRegex(CalibrationError, "must differ"):
            evaluate_gold_set_file(
                self._settings(retrieval_hash="a" * 64),
                run_id="source-run",
                gold_set_path=self.gold_path,
                output_path=self.root / "result.json",
            )

    def test_matching_retrieval_scope_reports_only_coverage(self) -> None:
        result = evaluate_gold_set_file(
            self._settings(retrieval_hash="a" * 64),
            run_id="same-source-run",
            gold_set_path=self.gold_path,
            output_path=self.root / "same-source-result.json",
        )

        self.assertEqual(result["status"], "same_source_coverage_only")
        self.assertEqual(result["coverage_at_candidate"], 1.0)
        self.assertIsNone(result["recall_at_candidate"])
        self.assertEqual(result["gold_source_run_id"], "source-run")
        self.assertEqual(
            result["candidate_run_identity"]["retrieval_hash"],
            "a" * 64,
        )
        self.assertEqual(
            result["candidate_settings_hashes"],
            {
                "config_hash": "f" * 64,
                "retrieval_hash": "a" * 64,
                "analysis_policy_hash": "b" * 64,
            },
        )

    def test_independent_retrieval_scope_can_report_recall(self) -> None:
        result = evaluate_gold_set_file(
            self._settings(retrieval_hash="d" * 64),
            run_id="independent-run",
            gold_set_path=self.gold_path,
            output_path=self.root / "independent-result.json",
        )

        self.assertEqual(result["status"], "evaluated")
        self.assertEqual(result["recall_at_candidate"], 0.9)
        self.assertTrue(result["passed"])

    def test_candidate_run_must_match_current_settings_identity(self) -> None:
        with self.assertRaisesRegex(CalibrationError, "candidate run.*config_hash"):
            evaluate_gold_set_file(
                SimpleNamespace(
                    **{
                        **vars(self._settings(retrieval_hash="d" * 64)),
                        "config_hash": "9" * 64,
                    }
                ),
                run_id="independent-run",
                gold_set_path=self.gold_path,
                output_path=self.root / "identity-mismatch.json",
            )


if __name__ == "__main__":
    unittest.main()
