from __future__ import annotations

import hashlib
import http.client
import json
import math
import statistics
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.parse import quote

from r3radar.storage import RadarStore
from r3radar.web import RadarHttpServer
from tests.fixtures.synthetic_research_workflows import (
    DOMAINS,
    FIXTURE_SCHEMA,
    SYNTHETIC_NOTICE,
    seed_synthetic_research_workflows,
)
from tests.test_core import make_settings


def _request_json(port: int, path: str) -> tuple[bytes, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request(
        "GET",
        path,
        headers={"Host": f"127.0.0.1:{port}"},
    )
    response = connection.getresponse()
    body = response.read()
    status = int(response.status)
    connection.close()
    if status != 200:
        raise AssertionError(f"GET {path} returned HTTP {status}: {body[:300]!r}")
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise AssertionError("expected a JSON object")
    return body, payload


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * percentile) - 1)
    return ordered[index]


class SyntheticRealisticWorkflowFixtureTests(unittest.TestCase):
    """The 16-item tier covers every lifecycle, not just a happy-path demo."""

    def test_16_item_fixture_is_long_multidomain_deterministic_and_auditable(self) -> None:
        manifests = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as temporary:
                settings = make_settings(Path(temporary))
                manifest = seed_synthetic_research_workflows(settings, count=16)
                manifests.append(manifest)

                self.assertEqual(manifest.schema, FIXTURE_SCHEMA)
                self.assertEqual(manifest.inserted_count, 16)
                self.assertEqual(set(manifest.domain_counts), {item.key for item in DOMAINS})
                self.assertEqual(manifest.domain_counts, {
                    "clinical_bioinformatics": 4,
                    "developer_agent_systems": 4,
                    "elder_companion_hri": 4,
                    "workflow_cache_kv": 4,
                })
                self.assertEqual(manifest.kind_counts, {"paper": 8, "repository": 8})
                self.assertGreaterEqual(manifest.total_abstract_characters, 30_000)
                self.assertGreaterEqual(manifest.total_analysis_characters, 70_000)
                self.assertEqual(manifest.missing_full_text_count, 1)
                self.assertEqual(manifest.version_drift_count, 1)
                self.assertEqual(manifest.retry_count, 2)
                self.assertEqual(manifest.near_duplicate_count, 1)
                self.assertGreaterEqual(manifest.feedback_count, 1)
                self.assertGreaterEqual(manifest.decision_count, 1)

                with RadarStore(settings.database_path) as store:
                    integrity = store._connection.execute(
                        "PRAGMA integrity_check"
                    ).fetchone()[0]
                    foreign_keys = store._connection.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchall()
                    rows = store._connection.execute(
                        """
                        SELECT canonical_key, doi, arxiv_id, best_url, metadata_json
                        FROM works ORDER BY id
                        """
                    ).fetchall()
                    self.assertEqual(integrity, "ok")
                    self.assertEqual(foreign_keys, [])
                    self.assertEqual(len(rows), 16)
                    for row in rows:
                        metadata = json.loads(row["metadata_json"])
                        self.assertTrue(metadata["synthetic_realistic"])
                        self.assertEqual(metadata["notice"], SYNTHETIC_NOTICE)
                        self.assertTrue(row["canonical_key"].startswith("synthetic-realistic:"))
                        self.assertIsNone(row["doi"])
                        self.assertIsNone(row["arxiv_id"])
                        self.assertTrue(row["best_url"].startswith("https://example.invalid/"))

                    feedback_rows = int(
                        store._connection.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
                    )
                    decision_rows = int(
                        store._connection.execute(
                            "SELECT COUNT(*) FROM research_decisions"
                        ).fetchone()[0]
                    )
                    relation_rows = int(
                        store._connection.execute(
                            "SELECT COUNT(*) FROM paper_repository_relations"
                        ).fetchone()[0]
                    )
                    duplicate_title_groups = int(
                        store._connection.execute(
                            """
                            SELECT COUNT(*) FROM (
                                SELECT normalized_title FROM works
                                GROUP BY normalized_title HAVING COUNT(*) > 1
                            )
                            """
                        ).fetchone()[0]
                    )
                    self.assertEqual(feedback_rows, manifest.feedback_count)
                    self.assertEqual(decision_rows, manifest.decision_count)
                    self.assertEqual(relation_rows, 8)
                    self.assertGreaterEqual(duplicate_title_groups, 1)

                    projected = store.list_dashboard_works(
                        config_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                        limit=16,
                    )
                    by_id = {int(row["id"]): row for row in projected}
                    # Index 13 has no full text; index 14 has a stale task input.
                    self.assertEqual(by_id[14]["content_status"], "failed")
                    self.assertIsNone(by_id[14]["deep_read_status"])
                    self.assertEqual(by_id[15]["content_status"], "ready")
                    self.assertIsNone(by_id[15]["deep_read_status"])

        self.assertEqual(manifests[0].fixture_sha256, manifests[1].fixture_sha256)
        self.assertEqual(manifests[0].as_dict(), manifests[1].as_dict())


class DashboardScaleContractTests(unittest.TestCase):
    """500/1,500 tiers exercise stable API behaviour at real note lengths."""

    def _start_server(self, count: int):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        settings = make_settings(Path(temporary.name))
        manifest = seed_synthetic_research_workflows(settings, count=count)
        server = RadarHttpServer(("127.0.0.1", 0), settings)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def close_server() -> None:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        self.addCleanup(close_server)
        return settings, manifest, int(server.server_address[1])

    def test_500_item_summary_page_is_bounded_and_repeatably_fast(self) -> None:
        _settings, manifest, port = self._start_server(500)
        self.assertGreater(manifest.total_abstract_characters, 900_000)
        self.assertGreater(manifest.total_analysis_characters, 2_000_000)

        # Warm the SQLite page cache before measuring the fixed-reference process.
        for _ in range(3):
            _request_json(port, "/api/works?limit=25")

        durations_ms: list[float] = []
        bodies: list[bytes] = []
        payloads: list[dict] = []
        for _ in range(15):
            started = time.perf_counter()
            body, payload = _request_json(port, "/api/works?limit=25")
            durations_ms.append((time.perf_counter() - started) * 1000.0)
            bodies.append(body)
            payloads.append(payload)

        response_hashes = {hashlib.sha256(body).hexdigest() for body in bodies}
        p50_ms = statistics.median(durations_ms)
        p95_ms = _percentile(durations_ms, 0.95)
        largest_body = max(map(len, bodies))
        diagnostic = (
            f"p50_ms={p50_ms:.2f}, p95_ms={p95_ms:.2f}, "
            f"largest_body={largest_body}, hashes={len(response_hashes)}"
        )
        self.assertEqual(len(response_hashes), 1, diagnostic)
        self.assertLessEqual(p95_ms, 750.0, diagnostic)
        self.assertLessEqual(largest_body, 200 * 1024, diagnostic)
        self.assertEqual(len(payloads[0]["works"]), 25)
        self.assertTrue(payloads[0]["has_more"])
        self.assertEqual(payloads[0]["total"], 500)
        for work in payloads[0]["works"]:
            self.assertNotIn(
                "analysis",
                work,
                "list summary contract must not inline full deep-read JSON",
            )

    def test_full_analysis_is_explicit_and_corrupt_cursor_fails_closed(self) -> None:
        _settings, _manifest, port = self._start_server(16)
        _body, first = _request_json(port, "/api/works?limit=5")
        summarized = next(
            work for work in first["works"] if work.get("analysis_id")
        )
        self.assertNotIn("analysis", summarized)

        _detail_body, detail = _request_json(
            port,
            f"/api/work-analysis?work_id={int(summarized['id'])}",
        )
        self.assertEqual(detail["work_id"], int(summarized["id"]))
        self.assertEqual(detail["analysis_id"], int(summarized["analysis_id"]))
        self.assertIsInstance(detail["analysis"], dict)
        self.assertGreater(len(detail["analysis"].get("summary_zh", "")), 100)

        cursor = str(first["next_cursor"])
        corrupted = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request(
            "GET",
            f"/api/works?cursor={quote(corrupted, safe='')}",
            headers={"Host": f"127.0.0.1:{port}"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        self.assertEqual(response.status, 400)
        self.assertEqual(payload, {"error": "invalid_pagination"})

    def test_1500_item_default_page_and_cursor_are_bounded_and_nonoverlapping(self) -> None:
        _settings, manifest, port = self._start_server(1500)
        self.assertEqual(manifest.inserted_count, 1500)
        self.assertGreater(manifest.total_abstract_characters, 2_500_000)
        self.assertGreater(manifest.total_analysis_characters, 6_000_000)

        first_started = time.perf_counter()
        first_body, first = _request_json(port, "/api/works")
        first_elapsed_ms = (time.perf_counter() - first_started) * 1000.0
        self.assertLessEqual(
            first_elapsed_ms,
            750.0,
            f"1500-item default list took {first_elapsed_ms:.2f}ms",
        )
        self.assertEqual(first["total"], 1500)
        self.assertEqual(first["limit"], 25)
        self.assertEqual(len(first["works"]), 25)
        self.assertLessEqual(len(first_body), 200 * 1024)
        self.assertTrue(first["has_more"])
        for work in first["works"]:
            self.assertNotIn("analysis", work)
        next_cursor = first.get("next_cursor")
        self.assertIsInstance(next_cursor, str)
        self.assertTrue(next_cursor)

        second_body, second = _request_json(
            port,
            f"/api/works?limit=25&cursor={quote(next_cursor, safe='')}",
        )
        first_ids = [int(work["id"]) for work in first["works"]]
        second_ids = [int(work["id"]) for work in second["works"]]
        self.assertEqual(len(second_ids), 25)
        self.assertTrue(set(first_ids).isdisjoint(second_ids))
        self.assertLessEqual(len(second_body), 200 * 1024)

        # Re-reading the same cursor must be deterministic; this catches accidental
        # dependence on mutable client offset or unordered SQLite results.
        repeated_body, repeated = _request_json(
            port,
            f"/api/works?limit=25&cursor={quote(next_cursor, safe='')}",
        )
        self.assertEqual(second_ids, [int(work["id"]) for work in repeated["works"]])
        self.assertEqual(
            hashlib.sha256(second_body).hexdigest(),
            hashlib.sha256(repeated_body).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
