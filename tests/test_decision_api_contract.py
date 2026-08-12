from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from r3radar.config import canonical_json
from r3radar.storage import RadarStore
from r3radar.utils import sha256_text
from r3radar.web import RadarHttpServer
from tests.test_core import make_settings
from tests.test_decision_exports import frozen_snapshot


def _seed_phase_c_fixture(settings) -> dict[str, object]:
    source_text = (
        "=== PAGE 1 ===\n"
        "The measured cache reuse signal predicts future workflow demand.\n"
        "This exact sentence is the decision evidence.\n"
    )
    excerpt = "This exact sentence is the decision evidence."
    text_sha256 = sha256_text(source_text)
    text_path = settings.literature_dir / "text" / "phase-c-fixture.txt"
    text_path.write_text(source_text, encoding="utf-8")
    now = datetime.now(timezone.utc).isoformat()

    with RadarStore(settings.database_path) as store:
        run_id, _, lease_token = store.create_or_resume_run(
            settings,
            "phase-c-contract",
        )
        with store.transaction() as connection:
            work_ids: list[int] = []
            analysis_ids: list[int] = []
            document_ids: list[int] = []
            for index, published in enumerate((True, False), start=1):
                work = connection.execute(
                    """
                    INSERT INTO works(
                        canonical_key, kind, title, normalized_title, year,
                        doi, best_url, lane, state, admission_code,
                        metadata_json, first_seen_at, updated_at
                    ) VALUES (?, 'paper', ?, ?, 2026, ?, ?, 'core',
                              'analyzed', 'admitted', '{}', ?, ?)
                    """,
                    (
                        f"doi:10.1234/phase-c-{index}",
                        f"Phase C {'Published' if published else 'Unpublished'}",
                        f"phase c {'published' if published else 'unpublished'}",
                        f"10.1234/phase-c-{index}",
                        f"https://doi.org/10.1234/phase-c-{index}",
                        now,
                        now,
                    ),
                )
                work_id = int(work.lastrowid)
                document = connection.execute(
                    """
                    INSERT INTO documents(
                        work_id, content_kind, status, source_url, text_path,
                        content_sha256, text_sha256, byte_count,
                        text_char_count, page_count, coverage_json,
                        created_at, updated_at
                    ) VALUES (?, 'paper_pdf', 'ready', ?, ?, ?, ?, ?, ?, 1,
                              '{"complete":true}', ?, ?)
                    """,
                    (
                        work_id,
                        f"https://example.test/phase-c-{index}.pdf",
                        str(text_path),
                        f"pdf-sha-{index}",
                        text_sha256,
                        len(source_text.encode("utf-8")),
                        len(source_text),
                        now,
                        now,
                    ),
                )
                document_id = int(document.lastrowid)
                task = connection.execute(
                    """
                    INSERT INTO analysis_tasks(
                        work_id, document_id, provider, prompt_version,
                        config_hash, retrieval_hash, profile_id,
                        profile_version, input_sha256, status, chunk_total,
                        chunk_done, updated_at, completed_at
                    ) VALUES (?, ?, 'codex_cli', ?, ?, ?, ?, ?, ?,
                              'completed', 1, 1, ?, ?)
                    """,
                    (
                        work_id,
                        document_id,
                        settings.raw["analysis"]["prompt_version"],
                        settings.analysis_policy_hash,
                        settings.retrieval_hash,
                        settings.profile_id,
                        settings.profile_version,
                        text_sha256,
                        now,
                        now,
                    ),
                )
                task_id = int(task.lastrowid)
                chunk_output = {
                    "chunk_index": 0,
                    "coverage_confirmed": True,
                    "summary_zh": "证据块",
                    "evidence": [
                        {
                            "anchor": "=== PAGE 1 ===",
                            "claim_zh": "可核验的决策证据",
                            "excerpt": excerpt,
                            "excerpt_match_method": "literal_substring",
                        }
                    ],
                }
                connection.execute(
                    """
                    INSERT INTO analysis_chunks(
                        task_id, chunk_index, span_json, input_sha256,
                        status, output_json, provider_receipt_json, updated_at
                    ) VALUES (?, 0, ?, ?, 'complete', ?, '{}', ?)
                    """,
                    (
                        task_id,
                        canonical_json(
                            {
                                "character_start": 0,
                                "character_end": len(source_text),
                                "anchors": ["=== PAGE 1 ==="],
                            }
                        ),
                        text_sha256,
                        canonical_json(chunk_output),
                        now,
                    ),
                )
                analysis_payload = {
                    "summary_zh": "面向科研决策的冻结分析",
                    "problem": "缓存复用价值判断",
                    "method": "工作流证据",
                    "limitations": [],
                    "r3_relationship": ["直接相关"],
                    "evidence_anchors": ["=== PAGE 1 ==="],
                    "uncertainties": [],
                }
                analysis = connection.execute(
                    """
                    INSERT INTO analyses(
                        task_id, work_id, provider, model, prompt_version,
                        config_hash, retrieval_hash, profile_id,
                        profile_version, deep_read_status, tier, score,
                        analysis_json, coverage_json, provider_receipt_json,
                        provenance_status, created_at
                    ) VALUES (?, ?, 'codex_cli', 'fixture', ?, ?, ?, ?, ?,
                              'complete', 'must_read', 95, ?, ?, '{}',
                              'append_only', ?)
                    """,
                    (
                        task_id,
                        work_id,
                        settings.raw["analysis"]["prompt_version"],
                        settings.analysis_policy_hash,
                        settings.retrieval_hash,
                        settings.profile_id,
                        settings.profile_version,
                        canonical_json(analysis_payload),
                        canonical_json(
                            {
                                "complete": True,
                                "chunk_total": 1,
                                "chunk_done": 1,
                                "text_sha256": text_sha256,
                            }
                        ),
                        now,
                    ),
                )
                work_ids.append(work_id)
                document_ids.append(document_id)
                analysis_ids.append(int(analysis.lastrowid))

            connection.execute(
                """
                UPDATE runs
                SET status='completed', ended_at=?, updated_at=?,
                    owner_pid=NULL, lease_token=NULL, lease_expires_at=NULL
                WHERE id=? AND lease_token=?
                """,
                (now, now, run_id, lease_token),
            )
            issue_id = "issue-phase-c-contract"
            counts = {"new_or_updated": 1, "selected": 1}
            payload = {
                "issue_id": issue_id,
                "publication": {
                    "run_id": run_id,
                    "terminal_status": "completed",
                },
                "counts": counts,
            }
            snapshot = {
                "analysis_id": analysis_ids[0],
                "work_id": work_ids[0],
                "document_id": document_ids[0],
                "input_sha256": text_sha256,
                "title": "Phase C Published",
                "kind": "paper",
                "lane": "core",
                "tier": "must_read",
                "score": 95,
                "provider": "codex_cli",
                "citation": {
                    "type": "article",
                    "title": "Phase C Published",
                    "author": [
                        {"family": "Zhang", "given": "Yan"},
                        {"family": "Li", "given": "Ming"},
                    ],
                    "issued": {"date-parts": [[2026]]},
                    "DOI": "10.1234/phase-c-1",
                    "URL": "https://doi.org/10.1234/phase-c-1",
                },
                "analysis": {
                    "summary_zh": "面向科研决策的冻结分析",
                    "evidence_anchors": ["=== PAGE 1 ==="],
                },
                "coverage": {
                    "complete": True,
                    "text_sha256": text_sha256,
                },
            }
            snapshot = frozen_snapshot(
                source_text,
                title="Phase C Published",
                authors=["Zhang Yan", "Li Ming"],
                doi="10.1234/phase-c-1",
                evidence_anchors=["=== PAGE 1 ==="],
            )
            snapshot.update(
                {
                    "analysis_id": analysis_ids[0],
                    "work_id": work_ids[0],
                    "document_id": document_ids[0],
                    "input_sha256": text_sha256,
                    "lane": "core",
                    "score": 95.0,
                }
            )
            snapshot["analysis"]["candidate_id"] = work_ids[0]
            snapshot["analysis"]["scores"]["overall"] = 95.0
            snapshot["coverage"]["text_sha256"] = text_sha256
            snapshot["coverage"]["text_char_count"] = len(source_text)
            snapshot["citation"].update(
                {
                    "year": 2026,
                    "doi": "10.1234/phase-c-1",
                    "arxiv_id": None,
                    "best_url": "https://doi.org/10.1234/phase-c-1",
                }
            )
            connection.execute(
                """
                INSERT INTO report_issues(
                    issue_id, run_id, publication_key, retrieval_hash,
                    analysis_policy_hash, terminal_status, generated_at,
                    output_dir, report_path, selection_path, counts_json,
                    payload_sha256, payload_json, report_sha256,
                    selection_sha256, run_summary_path
                ) VALUES (?, ?, 'publication-phase-c', ?, ?, 'completed', ?,
                          ?, ?, ?, ?, ?, ?, 'report-sha', 'selection-sha', ?)
                """,
                (
                    issue_id,
                    run_id,
                    settings.retrieval_hash,
                    settings.analysis_policy_hash,
                    now,
                    str(settings.outputs_dir),
                    str(settings.outputs_dir / "report.md"),
                    str(settings.outputs_dir / "selection.json"),
                    canonical_json(counts),
                    sha256_text(canonical_json(payload)),
                    canonical_json(payload),
                    str(settings.outputs_dir / "run-summary.json"),
                ),
            )
            connection.execute(
                """
                INSERT INTO report_issue_items(
                    issue_id, analysis_id, work_id, selection_bucket,
                    selected, input_sha256, snapshot_sha256, snapshot_json
                ) VALUES (?, ?, ?, 'must_read', 1, ?, ?, ?)
                """,
                (
                    issue_id,
                    analysis_ids[0],
                    work_ids[0],
                    text_sha256,
                    sha256_text(canonical_json(snapshot)),
                    canonical_json(snapshot),
                ),
            )

    return {
        "issue_id": issue_id,
        "published_analysis_id": analysis_ids[0],
        "unpublished_analysis_id": analysis_ids[1],
        "published_work_id": work_ids[0],
        "document_id": document_ids[0],
        "source_text": source_text,
        "excerpt": excerpt,
        "input_sha256": text_sha256,
    }


class DecisionApiContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.settings = make_settings(Path(self.temporary.name))
        self.fixture = _seed_phase_c_fixture(self.settings)
        self.server = RadarHttpServer(("127.0.0.1", 0), self.settings)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.port,
            timeout=5,
        )
        headers = {"Host": f"127.0.0.1:{self.port}"}
        body = None
        if payload is not None:
            body = canonical_json(payload).encode("utf-8")
            headers.update(
                {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Origin": f"http://127.0.0.1:{self.port}",
                }
            )
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        response_headers = {
            key.casefold(): value for key, value in response.getheaders()
        }
        status = int(response.status)
        connection.close()
        return status, response_headers, response_body

    @staticmethod
    def _json(body: bytes) -> dict:
        value = json.loads(body)
        if not isinstance(value, dict):
            raise AssertionError("expected a JSON object")
        return value

    def _post_decision(
        self,
        analysis_id: int,
        action: str,
        *,
        reason: str | None = None,
    ) -> tuple[int, dict]:
        payload = {
            "issue_id": self.fixture["issue_id"],
            "analysis_id": analysis_id,
            "action": action,
        }
        if reason is not None:
            payload["reason"] = reason
        status, _, body = self._request("POST", "/api/decision", payload)
        return status, self._json(body)

    def test_only_frozen_issue_item_can_receive_decision(self):
        published_status, published = self._post_decision(
            int(self.fixture["published_analysis_id"]),
            "save",
        )
        unpublished_status, unpublished = self._post_decision(
            int(self.fixture["unpublished_analysis_id"]),
            "save",
        )

        self.assertEqual(published_status, 201, published)
        self.assertIn(unpublished_status, {404, 409}, unpublished)
        self.assertEqual(
            unpublished.get("error"),
            "decision_requires_published_item",
        )

    def test_decision_persists_in_refreshed_slice(self):
        status, created = self._post_decision(
            int(self.fixture["published_analysis_id"]),
            "save",
        )
        self.assertEqual(status, 201, created)

        query = urlencode({"issue_id": self.fixture["issue_id"], "all": 1})
        slice_status, _, body = self._request(
            "GET",
            f"/api/decision-slice?{query}",
        )
        refreshed = self._json(body)

        self.assertEqual(slice_status, 200, refreshed)
        self.assertIsInstance(refreshed.get("issue"), dict)
        self.assertIsInstance(refreshed.get("items"), list)
        self.assertIsInstance(refreshed.get("remaining_count"), int)
        item = next(
            value
            for value in refreshed["items"]
            if int(value["analysis_id"])
            == int(self.fixture["published_analysis_id"])
        )
        self.assertEqual(item["decision"]["action"], "save")

    def test_latest_zero_delta_carries_forward_previous_actionable_issue(self):
        latest_issue_id = "issue-phase-c-zero-delta"
        counts = {"new_or_updated": 0, "selected": 0}
        with RadarStore(self.settings.database_path) as store:
            run_id, _, lease_token = store.create_or_resume_run(
                self.settings,
                "phase-c-zero-delta",
            )
            store.pause_or_complete_run(
                run_id,
                paused=False,
                lease_token=lease_token,
                status_override="completed_with_gaps",
            )
            with store.transaction() as connection:
                payload = {
                    "issue_id": latest_issue_id,
                    "publication": {
                        "run_id": run_id,
                        "terminal_status": "completed_with_gaps",
                    },
                    "counts": counts,
                }
                connection.execute(
                    """
                    INSERT INTO report_issues(
                        issue_id, run_id, publication_key, retrieval_hash,
                        analysis_policy_hash, previous_issue_id,
                        terminal_status, generated_at, output_dir,
                        report_path, selection_path, counts_json,
                        payload_sha256, payload_json, report_sha256,
                        selection_sha256, run_summary_path
                    ) VALUES (?, ?, 'publication-phase-c-zero', ?, ?, ?,
                              'completed_with_gaps',
                              '9999-12-31T23:59:59+00:00', ?, ?, ?, ?, ?,
                              ?, 'report-zero-sha', 'selection-zero-sha', ?)
                    """,
                    (
                        latest_issue_id,
                        run_id,
                        self.settings.retrieval_hash,
                        self.settings.analysis_policy_hash,
                        self.fixture["issue_id"],
                        str(self.settings.outputs_dir),
                        str(self.settings.outputs_dir / "report-zero.md"),
                        str(self.settings.outputs_dir / "selection-zero.json"),
                        canonical_json(counts),
                        sha256_text(canonical_json(payload)),
                        canonical_json(payload),
                        str(self.settings.outputs_dir / "run-zero-summary.json"),
                    ),
                )

        slice_status, _, body = self._request("GET", "/api/decision-slice")
        response = self._json(body)

        self.assertEqual(slice_status, 200, response)
        self.assertTrue(response["carried_forward"])
        self.assertEqual(response["latest_issue"]["issue_id"], latest_issue_id)
        self.assertEqual(response["issue"]["issue_id"], self.fixture["issue_id"])
        self.assertEqual(len(response["items"]), 1)
        self.assertEqual(
            int(response["items"][0]["analysis_id"]),
            int(self.fixture["published_analysis_id"]),
        )

    def test_action_enum_and_reason_contract(self):
        for action in ("save", "defer", "reject", "request_deep_read"):
            with self.subTest(action=action):
                reason = None if action == "save" else f"human reason for {action}"
                status, response = self._post_decision(
                    int(self.fixture["published_analysis_id"]),
                    action,
                    reason=reason,
                )
                self.assertEqual(status, 201, response)

        invalid_status, invalid = self._post_decision(
            int(self.fixture["published_analysis_id"]),
            "silently_promote",
            reason="must not be accepted",
        )
        self.assertEqual(invalid_status, 400, invalid)
        self.assertEqual(invalid.get("error"), "invalid_decision")

        missing_reason_status, missing_reason = self._post_decision(
            int(self.fixture["published_analysis_id"]),
            "reject",
        )
        self.assertEqual(missing_reason_status, 400, missing_reason)
        self.assertEqual(missing_reason.get("error"), "invalid_decision")

    def test_evidence_is_bound_to_frozen_input_and_literal_source(self):
        query = urlencode(
            {
                "issue_id": self.fixture["issue_id"],
                "analysis_id": self.fixture["published_analysis_id"],
            }
        )
        status, _, body = self._request("GET", f"/api/evidence?{query}")
        evidence = self._json(body)

        self.assertEqual(status, 200, evidence)
        source = evidence["source"]
        self.assertEqual(source["input_sha256"], self.fixture["input_sha256"])
        self.assertEqual(source["document_id"], self.fixture["document_id"])
        self.assertGreater(len(evidence["anchors"]), 0)
        original = str(self.fixture["source_text"])
        for anchor in evidence["anchors"]:
            excerpt = str(anchor["excerpt"])
            context = str(anchor["context"])
            start = int(anchor["start"])
            self.assertIn(excerpt, original)
            self.assertIn(excerpt, context)
            self.assertEqual(original[start : start + len(excerpt)], excerpt)

    def test_single_item_exports_are_byte_deterministic(self):
        for format_name in ("csl-json", "bibtex", "ris", "markdown"):
            with self.subTest(format=format_name):
                query = urlencode(
                    {
                        "issue_id": self.fixture["issue_id"],
                        "analysis_id": self.fixture["published_analysis_id"],
                        "format": format_name,
                    }
                )
                first_status, first_headers, first = self._request(
                    "GET",
                    f"/api/export?{query}",
                )
                second_status, second_headers, second = self._request(
                    "GET",
                    f"/api/export?{query}",
                )
                self.assertEqual(first_status, 200, first)
                self.assertEqual(second_status, 200, second)
                self.assertGreater(len(first), 0)
                self.assertEqual(first, second)
                self.assertEqual(
                    first_headers.get("content-type"),
                    second_headers.get("content-type"),
                )

    def test_reproduction_handoff_is_frozen_deterministic_and_non_executable(self):
        query = urlencode(
            {
                "issue_id": self.fixture["issue_id"],
                "analysis_id": self.fixture["published_analysis_id"],
            }
        )
        first_status, first_headers, first = self._request(
            "GET",
            f"/api/reproduction-handoff?{query}",
        )
        second_status, second_headers, second = self._request(
            "GET",
            f"/api/reproduction-handoff?{query}",
        )
        handoff = self._json(first)

        self.assertEqual(first_status, 200, first)
        self.assertEqual(second_status, 200, second)
        self.assertEqual(first, second)
        self.assertEqual(
            first_headers.get("content-type"),
            "application/json; charset=utf-8",
        )
        self.assertEqual(
            first_headers.get("content-disposition"),
            second_headers.get("content-disposition"),
        )
        self.assertEqual(handoff["schema"], "r3/reproduction-handoff/v2")
        self.assertEqual(
            handoff["analysis_id"],
            self.fixture["published_analysis_id"],
        )
        self.assertEqual(
            handoff["input_sha256"],
            self.fixture["input_sha256"],
        )
        self.assertEqual(handoff["manual_confirmation"]["status"], "pending")
        self.assertFalse(handoff["executable"])


if __name__ == "__main__":
    unittest.main()
