from __future__ import annotations

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from r3radar.config import canonical_json
from r3radar.storage import (
    GoldReviewConflictError,
    RadarStore,
)
from r3radar.web import RadarHttpServer
from tests.test_core import make_settings
from tests.test_gold_v2_contract import _realistic_v1_gold


def _write_source(path: Path) -> dict:
    source = _realistic_v1_gold()
    path.write_text(
        json.dumps(source, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return source


def _y0_payload(
    *, item_id: str, document_sequence: int, request_id: str | None = None
) -> dict:
    return {
        "request_id": request_id or str(uuid.uuid4()),
        "item_id": item_id,
        "reviewer_identity": "researcher-local",
        "semantic_label": "known_important",
        "operational_status": "normal",
        "confidence": 4,
        "evidence_opened": True,
        "elapsed_ms": 52_000,
        "notes": (
            "核对了工作流状态、未来复用窗口、缓存对象身份和淘汰动作，"
            "并将语义信号与 recency/frequency 基线逐项比较。"
        ),
        "submitted_at": "2026-08-10T12:00:00+08:00",
        "expected_item_revision_sequence": 0,
        "expected_document_revision_sequence": document_sequence,
    }


class GoldReviewPersistenceTests(unittest.TestCase):
    def test_import_is_local_persistent_and_resets_all_v1_labels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "含长摘要的-gold-v1.json"
            _write_source(source_path)
            database_path = root / "radar.sqlite3"

            with RadarStore(database_path) as store:
                created = store.create_gold_review_from_v1_file(
                    source_path=source_path,
                    reviewer_identity="researcher-local",
                    creation_request_id="create-real-workflow-001",
                )
                review_id = created["review_id"]
                document = store.gold_review_document(review_id)
                self.assertEqual(created["item_count"], 70)
                self.assertEqual(created["document_revision_sequence"], 0)
                self.assertTrue(all(item["y0"] is None for item in document["document"]["items"]))
                self.assertNotIn("source_path", created)
                self.assertNotIn(str(source_path), canonical_json(created))

            with RadarStore(database_path) as reopened:
                restored = reopened.gold_review_document(review_id)
                self.assertEqual(restored["document_sha256"], created["document_sha256"])
                self.assertEqual(restored["source_sha256"], created["source_v1_sha256"])
                repeated = reopened.create_gold_review_from_v1_file(
                    source_path=source_path,
                    reviewer_identity="researcher-local",
                    creation_request_id="create-real-workflow-001",
                )
                self.assertTrue(repeated["idempotent"])
                self.assertEqual(repeated["review_id"], review_id)

    def test_import_rechecks_actual_bytes_after_the_pre_read_size_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "changed-during-read.json"
            _write_source(source_path)
            with RadarStore(root / "radar.sqlite3") as store:
                with patch.object(
                    Path,
                    "read_bytes",
                    return_value=b"x" * (16 * 1024 * 1024 + 1),
                ):
                    with self.assertRaisesRegex(ValueError, "file size"):
                        store.create_gold_review_from_v1_file(
                            source_path=source_path,
                            reviewer_identity="researcher-local",
                            creation_request_id="post-read-size-check",
                        )

    def test_y0_revision_is_atomic_idempotent_and_optimistically_concurrent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "gold-v1.json"
            _write_source(source_path)
            with RadarStore(root / "radar.sqlite3") as store:
                created = store.create_gold_review_from_v1_file(
                    source_path=source_path,
                    reviewer_identity="researcher-local",
                    creation_request_id="create-concurrency",
                )
                review_id = created["review_id"]
                item_ids = [
                    item["item_id"]
                    for item in store.gold_review_document(review_id)["document"]["items"]
                ]
                request = _y0_payload(
                    item_id=item_ids[0],
                    document_sequence=0,
                    request_id="tab-a-submit-001",
                )
                first = store.save_gold_y0(review_id=review_id, **request)
                repeated = store.save_gold_y0(review_id=review_id, **request)
                self.assertFalse(first["idempotent"])
                self.assertTrue(repeated["idempotent"])
                self.assertEqual(first["document_sha256"], repeated["document_sha256"])

                stale = _y0_payload(
                    item_id=item_ids[1],
                    document_sequence=0,
                    request_id="tab-b-stale-001",
                )
                with self.assertRaisesRegex(
                    GoldReviewConflictError,
                    "stale Gold review",
                ):
                    store.save_gold_y0(review_id=review_id, **stale)

                with store._lock:
                    revision_count = store._connection.execute(
                        "SELECT COUNT(*) FROM gold_review_revisions WHERE review_id=?",
                        (review_id,),
                    ).fetchone()[0]
                self.assertEqual(revision_count, 1)

    def test_seventy_realistic_items_must_all_be_saved_before_irreversible_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "gold-v1.json"
            _write_source(source_path)
            with RadarStore(root / "radar.sqlite3") as store:
                created = store.create_gold_review_from_v1_file(
                    source_path=source_path,
                    reviewer_identity="researcher-local",
                    creation_request_id="create-lock",
                )
                review_id = created["review_id"]
                items = store.gold_review_document(review_id)["document"]["items"]
                sequence = 0
                for index, item in enumerate(items):
                    if index == 35:
                        with self.assertRaisesRegex(Exception, "all 70"):
                            store.lock_gold_y0_review(
                                review_id=review_id,
                                request_id="premature-lock",
                                reviewer_identity="researcher-local",
                                locked_at="2026-08-10T13:00:00+08:00",
                                expected_document_revision_sequence=sequence,
                            )
                    payload = _y0_payload(
                        item_id=item["item_id"],
                        document_sequence=sequence,
                        request_id=f"real-label-{index:02d}",
                    )
                    if item["record_class"] == "operational_sentinel":
                        payload["semantic_label"] = "unjudged"
                        payload["operational_status"] = "inaccessible"
                        payload["confidence"] = None
                    saved = store.save_gold_y0(review_id=review_id, **payload)
                    sequence = saved["document_revision_sequence"]

                locked = store.lock_gold_y0_review(
                    review_id=review_id,
                    request_id="complete-lock",
                    reviewer_identity="researcher-local",
                    locked_at="2026-08-10T14:30:00+08:00",
                    expected_document_revision_sequence=sequence,
                )
                self.assertEqual(locked["status"], "y0_locked")
                self.assertEqual(locked["document_revision_sequence"], 71)
                with self.assertRaises(Exception):
                    store.save_gold_y0(
                        review_id=review_id,
                        **_y0_payload(
                            item_id=items[0]["item_id"],
                            document_sequence=71,
                            request_id="forbidden-after-lock",
                        ),
                    )
                with store._lock:
                    counts = store._connection.execute(
                        """
                        SELECT COUNT(*), COUNT(DISTINCT sequence),
                               COUNT(DISTINCT request_id)
                        FROM gold_review_revisions WHERE review_id=?
                        """,
                        (review_id,),
                    ).fetchone()
                self.assertEqual(tuple(counts), (71, 71, 71))
                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    with store.transaction() as connection:
                        connection.execute(
                            """
                            UPDATE gold_review_revisions SET event='tampered'
                            WHERE review_id=? AND sequence=1
                            """,
                            (review_id,),
                        )
                with store._lock:
                    page_count = int(
                        store._connection.execute("PRAGMA page_count").fetchone()[0]
                    )
                    page_size = int(
                        store._connection.execute("PRAGMA page_size").fetchone()[0]
                    )
                self.assertLess(page_count * page_size, 10 * 1024 * 1024)

    def test_schema_23_migration_failure_rolls_back_gold_tables_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "legacy.sqlite3"
            with closing(sqlite3.connect(database_path)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO schema_meta VALUES('schema_version', '22');
                    """
                )
                connection.commit()

            def fail_after_schema(step: str) -> None:
                if step == "after_schema":
                    raise RuntimeError("intentional migration fault")

            with self.assertRaisesRegex(RuntimeError, "rolled back"):
                RadarStore(
                    database_path,
                    _migration_fault_injector=fail_after_schema,
                )
            with closing(sqlite3.connect(database_path)) as connection:
                version = connection.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
                gold_tables = connection.execute(
                    """
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name LIKE 'gold_review%'
                    """
                ).fetchall()
            self.assertEqual(version, "22")
            self.assertEqual(gold_tables, [])

    def test_partial_database_claiming_schema_23_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "partial-current.sqlite3"
            with closing(sqlite3.connect(database_path)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO schema_meta VALUES('schema_version', '23');
                    """
                )
                connection.commit()
            with self.assertRaisesRegex(
                RuntimeError,
                "required contract is incomplete",
            ):
                RadarStore(database_path)

    def test_v22_with_obsolete_gold_tables_rolls_back_before_version_23(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database_path = Path(directory) / "obsolete-gold-v22.sqlite3"
            with closing(sqlite3.connect(database_path)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO schema_meta VALUES('schema_version', '22');
                    CREATE TABLE gold_reviews(
                        review_id TEXT PRIMARY KEY,
                        creation_request_id TEXT NOT NULL UNIQUE,
                        source_schema TEXT NOT NULL,
                        source_sha256 TEXT NOT NULL,
                        source_file_sha256 TEXT NOT NULL,
                        source_path TEXT NOT NULL,
                        status TEXT NOT NULL,
                        reviewer_identity TEXT NOT NULL,
                        item_count INTEGER NOT NULL,
                        document_sha256 TEXT NOT NULL,
                        document_json TEXT NOT NULL,
                        current_revision_sequence INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        locked_at TEXT
                    );
                    CREATE TABLE gold_review_revisions(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        review_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        event TEXT NOT NULL,
                        item_id TEXT,
                        request_id TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        previous_document_sha256 TEXT NOT NULL,
                        document_sha256 TEXT NOT NULL,
                        document_json TEXT NOT NULL,
                        submitted_at TEXT NOT NULL,
                        UNIQUE(review_id, sequence),
                        UNIQUE(review_id, request_id)
                    );
                    """
                )
                connection.commit()

            with self.assertRaisesRegex(RuntimeError, "rolled back"):
                RadarStore(database_path)
            with closing(sqlite3.connect(database_path)) as connection:
                version = connection.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
                review_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(gold_reviews)"
                    ).fetchall()
                }
            self.assertEqual(version, "22")
            self.assertNotIn("initial_document_sha256", review_columns)


class GoldReviewApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.settings = make_settings(self.root)
        self.source_path = self.root / "gold-v1-secret-location.json"
        _write_source(self.source_path)
        self.server = RadarHttpServer(("127.0.0.1", 0), self.settings)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary_directory.cleanup()

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        *,
        origin: str | None = None,
    ) -> tuple[int, dict]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Host": f"127.0.0.1:{self.port}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Origin"] = origin or f"http://127.0.0.1:{self.port}"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        decoded = json.loads(response.read().decode("utf-8"))
        status = response.status
        connection.close()
        return status, decoded

    def test_api_is_blind_path_private_and_conflict_safe(self) -> None:
        create_payload = {
            "source_path": str(self.source_path.resolve()),
            "reviewer_identity": "researcher-local",
            "creation_request_id": "api-create-001",
        }
        status, created = self._request("POST", "/api/gold/reviews", create_payload)
        self.assertEqual(status, 201)
        review_id = created["review"]["review_id"]
        self.assertNotIn(str(self.source_path), canonical_json(created))
        self.assertNotIn("source_path", canonical_json(created))

        status, blind = self._request(
            "GET",
            f"/api/gold/reviews/{review_id}/y0",
        )
        self.assertEqual(status, 200)
        self.assertEqual(blind["item_count"], 70)
        self.assertEqual(len(blind["items"]), 10)
        self.assertTrue(blind["has_more"])
        self.assertEqual(blind["next_offset"], 10)
        serialized = canonical_json(blind)
        for marker in (
            "AI_LEAK",
            "codex_cli",
            "must_read",
            "publication_selected",
            "candidate_unselected",
            str(self.source_path),
        ):
            self.assertNotIn(marker, serialized)

        forbidden_keys = {
            "tier",
            "score",
            "selected",
            "selection_bucket",
            "captured_as",
            "provider",
            "model",
            "analysis",
            "ai_assistance",
            "frozen_snapshot",
            "review_context",
            "source_path",
        }

        def walk(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for nested in value.values():
                    walk(nested)
            elif isinstance(value, list):
                for nested in value:
                    walk(nested)

        walk(blind)

        status, page_two = self._request(
            "GET",
            f"/api/gold/reviews/{review_id}/y0?limit=7&offset=10",
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(page_two["items"]), 7)
        self.assertEqual(page_two["offset"], 10)
        self.assertTrue(
            {item["item_id"] for item in blind["items"]}.isdisjoint(
                {item["item_id"] for item in page_two["items"]}
            )
        )
        walk(page_two)

        status, bad_page = self._request(
            "GET",
            f"/api/gold/reviews/{review_id}/y0?cursor=not-supported",
        )
        self.assertEqual(status, 400)
        self.assertEqual(bad_page, {"error": "invalid_gold_pagination"})

        item_id = blind["items"][0]["item_id"]
        submission = _y0_payload(item_id=item_id, document_sequence=0)
        submission.pop("submitted_at")
        status, saved = self._request(
            "POST",
            f"/api/gold/reviews/{review_id}/y0",
            submission,
        )
        self.assertEqual(status, 200)
        self.assertEqual(saved["review"]["document_revision_sequence"], 1)
        status, repeated_saved = self._request(
            "POST",
            f"/api/gold/reviews/{review_id}/y0",
            submission,
        )
        self.assertEqual(status, 200)
        self.assertTrue(repeated_saved["review"]["idempotent"])
        self.assertEqual(
            repeated_saved["review"]["document_sha256"],
            saved["review"]["document_sha256"],
        )
        stale = _y0_payload(
            item_id=blind["items"][1]["item_id"],
            document_sequence=0,
        )
        status, conflict = self._request(
            "POST",
            f"/api/gold/reviews/{review_id}/y0",
            stale,
        )
        self.assertEqual(status, 409)
        self.assertEqual(conflict, {"error": "gold_review_conflict"})

        status, invalid_origin = self._request(
            "POST",
            f"/api/gold/reviews/{review_id}/y0",
            stale,
            origin="https://attacker.invalid",
        )
        self.assertEqual(status, 403)
        self.assertEqual(invalid_origin, {"error": "invalid_origin"})

        sequence = 1
        persisted = self.server.store.gold_review_document(review_id)
        for index, item in enumerate(persisted["document"]["items"]):
            if item["y0"] is not None:
                continue
            next_payload = _y0_payload(
                item_id=item["item_id"],
                document_sequence=sequence,
                request_id=f"api-complete-{index:02d}",
            )
            if item["record_class"] == "operational_sentinel":
                next_payload["semantic_label"] = "unjudged"
                next_payload["operational_status"] = "recoverable_failure"
                next_payload["confidence"] = None
            result = self.server.store.save_gold_y0(
                review_id=review_id,
                **next_payload,
            )
            sequence = result["document_revision_sequence"]
        self.assertEqual(sequence, 70)

        lock_payload = {
            "request_id": "api-final-lock",
            "reviewer_identity": "researcher-local",
            "expected_document_revision_sequence": 70,
        }
        status, locked = self._request(
            "POST",
            f"/api/gold/reviews/{review_id}/lock",
            lock_payload,
        )
        self.assertEqual(status, 200)
        self.assertEqual(locked["review"]["status"], "y0_locked")
        walk(locked)
        status, repeated_lock = self._request(
            "POST",
            f"/api/gold/reviews/{review_id}/lock",
            lock_payload,
        )
        self.assertEqual(status, 200)
        self.assertTrue(repeated_lock["review"]["idempotent"])
        status, unavailable = self._request(
            "GET",
            f"/api/gold/reviews/{review_id}/y0",
        )
        self.assertEqual(status, 409)
        self.assertEqual(unavailable, {"error": "gold_y0_unavailable"})
        after_lock = _y0_payload(
            item_id=item_id,
            document_sequence=71,
            request_id="api-forbidden-after-lock",
        )
        after_lock["expected_item_revision_sequence"] = 1
        status, rejected = self._request(
            "POST",
            f"/api/gold/reviews/{review_id}/y0",
            after_lock,
        )
        self.assertEqual(status, 409)
        self.assertEqual(rejected, {"error": "gold_review_conflict"})

    def test_api_invalid_file_error_does_not_echo_path_or_contents(self) -> None:
        secret_path = self.root / "super-secret-invalid-input.json"
        secret_path.write_text("TOP_SECRET_NOT_JSON", encoding="utf-8")
        status, response = self._request(
            "POST",
            "/api/gold/reviews",
            {
                "source_path": str(secret_path.resolve()),
                "reviewer_identity": "researcher-local",
                "creation_request_id": "invalid-source-001",
            },
        )
        self.assertEqual(status, 400)
        serialized = canonical_json(response)
        self.assertNotIn(str(secret_path), serialized)
        self.assertNotIn("TOP_SECRET", serialized)

    def test_gold_writes_enforce_host_origin_json_and_bounded_body(self) -> None:
        path = "/api/gold/reviews"
        valid_payload = json.dumps(
            {
                "source_path": str(self.source_path.resolve()),
                "reviewer_identity": "researcher-local",
                "creation_request_id": "security-create-001",
            }
        ).encode("utf-8")

        cases = [
            (
                {"Host": "attacker.invalid", "Origin": f"http://127.0.0.1:{self.port}", "Content-Type": "application/json"},
                valid_payload,
                421,
                "invalid_host",
            ),
            (
                {"Host": f"127.0.0.1:{self.port}", "Origin": "https://attacker.invalid", "Content-Type": "application/json"},
                valid_payload,
                403,
                "invalid_origin",
            ),
            (
                {"Host": f"127.0.0.1:{self.port}", "Origin": f"http://127.0.0.1:{self.port}", "Content-Type": "text/plain"},
                valid_payload,
                415,
                "json_required",
            ),
            (
                {"Host": f"127.0.0.1:{self.port}", "Origin": f"http://127.0.0.1:{self.port}", "Content-Type": "application/json"},
                b"{" + b" " * 65536 + b"}",
                400,
                "invalid_body_size",
            ),
        ]
        for headers, body, expected_status, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                connection = http.client.HTTPConnection(
                    "127.0.0.1", self.port, timeout=10
                )
                connection.request("POST", path, body=body, headers=headers)
                response = connection.getresponse()
                decoded = json.loads(response.read().decode("utf-8"))
                connection.close()
                self.assertEqual(response.status, expected_status)
                self.assertEqual(decoded, {"error": expected_error})

    def test_decision_slice_defaults_to_three_cards_and_all_remains_unbounded(self) -> None:
        observed_limits: list[int | None] = []

        def decision_slice(**kwargs: object) -> dict:
            observed_limits.append(kwargs["pending_limit"])
            return {"items": [], "remaining_count": 0}

        self.server.store.decision_slice = decision_slice
        status, _ = self._request("GET", "/api/decision-slice")
        self.assertEqual(status, 200)
        status, _ = self._request("GET", "/api/decision-slice?all=1")
        self.assertEqual(status, 200)
        self.assertEqual(observed_limits, [3, None])


if __name__ == "__main__":
    unittest.main()
