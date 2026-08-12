from __future__ import annotations

import hashlib
import http.client
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from urllib.parse import urlencode

from r3radar.__main__ import main
from r3radar.config import canonical_json
from r3radar.known_answers import validate_known_answer_evaluation_receipt
from r3radar.storage import RadarStore
from r3radar.web import RadarHttpServer
from tests.fixtures.synthetic_research_workflows import (
    DOMAINS,
    FIXTURE_SEED,
    SYNTHETIC_NOTICE,
    seed_synthetic_research_workflows,
)
from tests.test_core import make_settings
from tests.test_decision_api_contract import _seed_phase_c_fixture
from tests.test_gold_persistence_api import _y0_payload
from tests.test_gold_v2_contract import _realistic_v1_gold
from tests.test_known_answer_evaluation import _candidate, _draft_set


SIMULATION_BOUNDARY = "simulated_not_calendar_evidence"
REPLAY_COUNT = 3


class _LocalDashboard:
    def __init__(self, settings) -> None:
        self.settings = settings
        self.server: RadarHttpServer | None = None
        self.thread: threading.Thread | None = None
        self.port: int | None = None

    def start(self) -> "_LocalDashboard":
        if self.server is not None:
            raise AssertionError("dashboard is already running")
        self.server = RadarHttpServer(("127.0.0.1", 0), self.settings)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            daemon=True,
        )
        self.thread.start()
        return self

    def stop(self) -> None:
        if self.server is None:
            return
        self.server.shutdown()
        self.server.server_close()
        assert self.thread is not None
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise AssertionError("dashboard thread did not stop")
        self.server = None
        self.thread = None
        self.port = None

    def request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        if self.port is None:
            raise AssertionError("dashboard is not running")
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.port,
            timeout=10,
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

    def json_request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
    ) -> tuple[int, dict[str, str], dict]:
        status, headers, body = self.request(method, path, payload)
        decoded = json.loads(body)
        if not isinstance(decoded, dict):
            raise AssertionError(f"{method} {path} did not return an object")
        return status, headers, decoded


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _four_domain_gold_source() -> dict:
    """Return 70 long blind-review records without claiming human labels."""

    source = _realistic_v1_gold()
    for index, item in enumerate(source["items"]):
        domain = DOMAINS[index % len(DOMAINS)]
        evidence_paragraph = (
            f"Synthetic-realistic blind review record {index + 1} in "
            f"{domain.display_name}. Research question: {domain.research_question} "
            f"Decision: {domain.decision} Boundary: {domain.boundary} "
            "The reviewer must distinguish discovery metadata from source evidence, "
            "keep unknowns unjudged, and avoid treating the pre-existing model fields "
            "as human truth. "
        )
        citation = {
            "kind": "repository" if (index + 1) % 5 == 0 else "paper",
            "authors": [
                {
                    "display_name": f"Synthetic Researcher {index + 1}",
                    "score": "AI_LEAK_AUTHOR_SCORE",
                }
            ],
            "title": (
                f"[SYNTHETIC] {domain.display_name}: blind-review decision "
                f"record {index + 1:02d}"
            ),
            "year": 2024 + (index + 1) % 3,
            "canonical_url": (
                "https://example.invalid/r3-four-domain-gold/"
                f"{domain.key}/{index + 1}"
            ),
            "abstract": evidence_paragraph * 8 + SYNTHETIC_NOTICE,
        }
        item["review_context"]["citation"] = citation
        item["frozen_snapshot"]["citation"] = citation
        item["snapshot_sha256"] = hashlib.sha256(
            canonical_json(item["frozen_snapshot"]).encode("utf-8")
        ).hexdigest()
    return source


def _mechanical_y0_payload(
    item: dict,
    *,
    sequence: int,
    request_id: str,
) -> dict:
    payload = _y0_payload(
        item_id=str(item["item_id"]),
        document_sequence=sequence,
        request_id=request_id,
    )
    payload["reviewer_identity"] = "synthetic-journey-runner-not-human-gold"
    payload["notes"] = (
        "MECHANICAL TEST LABEL ONLY; NOT HUMAN GOLD. "
        "The local journey verifies persistence, blindness, concurrency, and lock state."
    )
    if item["record_class"] == "operational_sentinel":
        payload["semantic_label"] = "unjudged"
        payload["operational_status"] = "recoverable_failure"
        payload["confidence"] = None
    return payload


def _evaluation_args(
    known_set: Path,
    candidates: Path,
    output: Path,
) -> list[str]:
    return [
        "known-answer-evaluate",
        "--known-answer-set",
        str(known_set),
        "--candidates",
        str(candidates),
        "--split",
        "evaluation",
        "--candidate-run-id",
        "journey-candidate-run-20260810",
        "--candidate-pool-id",
        "journey-frozen-pool-20260810",
        "--candidate-pool-frozen-at",
        "2026-08-10T08:00:00+08:00",
        "--candidate-source-artifact-id",
        "journey-candidate-export-20260810",
        "--known-answer-split-accessed-before-run",
        "development",
        "--ranking-method",
        "r3-static-ranking-policy-v1",
        "--evaluator-identity",
        "synthetic-journey-runner-not-human-gold",
        "--evaluated-at",
        "2026-08-10T09:00:00+08:00",
        "--output",
        str(output),
    ]


def _record_immutable_repository_relation(
    settings,
    *,
    paper_work_id: int,
    repository_work_id: int,
    commit_sha: str,
) -> dict:
    selected_text_sha256 = hashlib.sha256(
        (
            "Synthetic selected corpus: repository manifests, core cache policy, "
            "representative failure tests, and evaluation harness. "
            + SYNTHETIC_NOTICE
        ).encode("utf-8")
    ).hexdigest()
    relation = {
        "schema": "r3/paper-repository-relation/v1",
        "paper": {
            "work_id": paper_work_id,
            "identity": "synthetic paper fixture, not a real citation",
        },
        "repository": {
            "work_id": repository_work_id,
            "github_full_name": "synthetic-fixture/workflow-cache-0000",
        },
        "repository_revision": {
            "commit_sha": commit_sha,
            "commit_url": (
                "https://example.invalid/synthetic-fixture/"
                f"workflow-cache-0000/commit/{commit_sha}"
            ),
            "selected_text_sha256": selected_text_sha256,
        },
        "verification": {
            "foreign_code_executed": False,
            "archive_identity_checked": True,
            "selected_corpus_match": True,
            "notice": SYNTHETIC_NOTICE,
        },
    }
    with RadarStore(settings.database_path) as store:
        return store.record_paper_repository_relation(relation)


class ResearchWorkflowJourneyTests(unittest.TestCase):
    """Few, long journeys that mirror actual research work rather than demos."""

    def test_p1_summary_to_decision_export_and_restart_replays_three_times(self) -> None:
        replay_fingerprints: list[str] = []
        for replay in range(REPLAY_COUNT):
            with self.subTest(replay=replay), tempfile.TemporaryDirectory() as temporary:
                settings = make_settings(Path(temporary))
                fixture = _seed_phase_c_fixture(settings)
                manifest = seed_synthetic_research_workflows(
                    settings,
                    count=25,
                    seed=FIXTURE_SEED,
                )
                self.assertGreaterEqual(manifest.total_abstract_characters, 45_000)
                self.assertGreaterEqual(manifest.total_analysis_characters, 100_000)
                self.assertEqual(set(manifest.domain_counts), {item.key for item in DOMAINS})

                dashboard = _LocalDashboard(settings).start()
                try:
                    status, _, summary = dashboard.json_request(
                        "GET",
                        "/api/works?limit=25",
                    )
                    self.assertEqual(status, 200, summary)
                    self.assertEqual(summary["total"], 25)
                    self.assertEqual(len(summary["works"]), 25)
                    self.assertTrue(
                        all("analysis" not in item for item in summary["works"]),
                        "the 25-item scan must remain a summary page",
                    )
                    visible_domains = {
                        domain.key
                        for domain in DOMAINS
                        if any(
                            domain.display_name in item["title"]
                            for item in summary["works"]
                        )
                    }
                    self.assertEqual(visible_domains, {item.key for item in DOMAINS})

                    summarized = next(
                        item for item in summary["works"] if item.get("analysis_id")
                    )
                    detail_status, _, detail = dashboard.json_request(
                        "GET",
                        f"/api/work-analysis?work_id={int(summarized['id'])}",
                    )
                    self.assertEqual(detail_status, 200, detail)
                    self.assertGreater(
                        len(canonical_json(detail["analysis"])),
                        3_500,
                        "on-demand deep read must return a substantive analysis",
                    )
                    self.assertGreaterEqual(
                        len(detail["analysis"].get("evidence_anchors", [])),
                        8,
                    )

                    evidence_query = urlencode(
                        {
                            "issue_id": fixture["issue_id"],
                            "analysis_id": fixture["published_analysis_id"],
                        }
                    )
                    evidence_status, _, evidence = dashboard.json_request(
                        "GET",
                        f"/api/evidence?{evidence_query}",
                    )
                    self.assertEqual(evidence_status, 200, evidence)
                    self.assertEqual(
                        evidence["source"]["input_sha256"],
                        fixture["input_sha256"],
                    )
                    self.assertGreater(len(evidence["anchors"]), 0)

                    actions = (
                        ("save", None),
                        (
                            "defer",
                            "等待 advisor 核对 future reuse window 与 cache object 身份。",
                        ),
                        (
                            "reject",
                            "当前证据无法把 workflow semantic signal 与 recency baseline 隔离。",
                        ),
                    )
                    for action, reason in actions:
                        decision_payload = {
                            "issue_id": fixture["issue_id"],
                            "analysis_id": fixture["published_analysis_id"],
                            "action": action,
                            "note": (
                                "P1 research journey; evidence opened before decision; "
                                + SYNTHETIC_NOTICE
                            ),
                        }
                        if reason is not None:
                            decision_payload["reason"] = reason
                        decision_status, _, decision = dashboard.json_request(
                            "POST",
                            "/api/decision",
                            decision_payload,
                        )
                        self.assertEqual(decision_status, 201, decision)
                        refreshed_status, _, refreshed = dashboard.json_request(
                            "GET",
                            "/api/decision-slice?"
                            + urlencode({"issue_id": fixture["issue_id"], "all": 1}),
                        )
                        self.assertEqual(refreshed_status, 200, refreshed)
                        self.assertEqual(refreshed["items"][0]["decision"]["action"], action)

                    export_query = urlencode(
                        {
                            "issue_id": fixture["issue_id"],
                            "analysis_id": fixture["published_analysis_id"],
                            "format": "markdown",
                        }
                    )
                    export_status, export_headers, exported_before_restart = (
                        dashboard.request("GET", f"/api/export?{export_query}")
                    )
                    self.assertEqual(export_status, 200, exported_before_restart)
                    self.assertIn("charset=utf-8", export_headers["content-type"])
                    self.assertGreater(len(exported_before_restart), 500)
                finally:
                    dashboard.stop()

                # A browser refresh is weaker than this: the process and SQLite
                # connection are both replaced before the state is read again.
                dashboard.start()
                try:
                    refreshed_status, _, refreshed = dashboard.json_request(
                        "GET",
                        "/api/decision-slice?"
                        + urlencode({"issue_id": fixture["issue_id"], "all": 1}),
                    )
                    self.assertEqual(refreshed_status, 200, refreshed)
                    self.assertEqual(refreshed["items"][0]["decision"]["action"], "reject")
                    export_status, _, exported_after_restart = dashboard.request(
                        "GET",
                        f"/api/export?{export_query}",
                    )
                    self.assertEqual(export_status, 200, exported_after_restart)
                    self.assertEqual(exported_after_restart, exported_before_restart)
                finally:
                    dashboard.stop()

                replay_fingerprints.append(
                    hashlib.sha256(
                        canonical_json(
                            {
                                "fixture_sha256": manifest.fixture_sha256,
                                "summary_titles": [item["title"] for item in summary["works"]],
                            }
                        ).encode("utf-8")
                    ).hexdigest()
                )
        self.assertEqual(len(set(replay_fingerprints)), 1)

    def test_p2_immutable_paper_commit_handoff_never_executes_foreign_code(self) -> None:
        handoff_hashes: list[str] = []
        for replay in range(REPLAY_COUNT):
            with self.subTest(replay=replay), tempfile.TemporaryDirectory() as temporary:
                settings = make_settings(Path(temporary))
                fixture = _seed_phase_c_fixture(settings)
                manifest = seed_synthetic_research_workflows(
                    settings,
                    count=2,
                    seed=FIXTURE_SEED,
                )
                with RadarStore(settings.database_path) as store:
                    repository = store._connection.execute(
                        """
                        SELECT id, metadata_json FROM works
                        WHERE kind='repository' ORDER BY id DESC LIMIT 1
                        """
                    ).fetchone()
                assert repository is not None
                repository_metadata = json.loads(repository["metadata_json"])
                commit_sha = str(repository_metadata["frozen_revision"])
                relation = _record_immutable_repository_relation(
                    settings,
                    paper_work_id=int(fixture["published_work_id"]),
                    repository_work_id=int(repository["id"]),
                    commit_sha=commit_sha,
                )
                self.assertEqual(
                    relation["evidence"]["repository_revision"]["commit_sha"],
                    commit_sha,
                )
                self.assertFalse(
                    relation["evidence"]["verification"]["foreign_code_executed"]
                )

                dashboard = _LocalDashboard(settings).start()
                try:
                    query = urlencode(
                        {
                            "issue_id": fixture["issue_id"],
                            "analysis_id": fixture["published_analysis_id"],
                        }
                    )
                    status, _, body = dashboard.request(
                        "GET",
                        f"/api/reproduction-handoff?{query}",
                    )
                    repeated_status, _, repeated_body = dashboard.request(
                        "GET",
                        f"/api/reproduction-handoff?{query}",
                    )
                    self.assertEqual(status, 200, body)
                    self.assertEqual(repeated_status, 200, repeated_body)
                    self.assertEqual(body, repeated_body)
                    handoff = json.loads(body)
                    self.assertEqual(handoff["schema"], "r3/reproduction-handoff/v2")
                    self.assertEqual(
                        handoff["source_relation"]["evidence"]
                        ["repository_revision"]["commit_sha"],
                        commit_sha,
                    )
                    self.assertFalse(handoff["executable"])
                    self.assertEqual(
                        handoff["manual_confirmation"]["status"],
                        "pending",
                    )
                    self.assertGreaterEqual(len(handoff["risk_warnings"]), 4)
                    self.assertFalse(
                        handoff["source_relation"]["evidence"]
                        ["verification"]["foreign_code_executed"]
                    )
                    serialized = body.decode("utf-8")
                    for forbidden in (
                        "checkout_path",
                        "executed_command",
                        "shell_output",
                        "foreign_source_code",
                    ):
                        self.assertNotIn(forbidden, serialized)
                    handoff_hashes.append(
                        hashlib.sha256(
                            canonical_json(
                                {
                                    "commit_sha": commit_sha,
                                    "executable": handoff["executable"],
                                    "risk_warnings": handoff["risk_warnings"],
                                    "foreign_code_executed": handoff[
                                        "source_relation"
                                    ]["evidence"]["verification"][
                                        "foreign_code_executed"
                                    ],
                                }
                            ).encode("utf-8")
                        ).hexdigest()
                    )
                finally:
                    dashboard.stop()
                self.assertEqual(manifest.inserted_count, 2)
        self.assertEqual(len(set(handoff_hashes)), 1)

    def test_gold_y0_seventy_items_survive_sessions_tabs_pagination_and_lock(self) -> None:
        replay_signatures: list[dict] = []
        for replay in range(REPLAY_COUNT):
            with self.subTest(replay=replay), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                settings = make_settings(root)
                source_path = root / "四领域 70项 盲标源.json"
                _write_json(source_path, _four_domain_gold_source())
                dashboard = _LocalDashboard(settings).start()
                all_items: list[dict] = []
                try:
                    create_payload = {
                        "source_path": str(source_path.resolve()),
                        "reviewer_identity": (
                            "synthetic-journey-runner-not-human-gold"
                        ),
                        "creation_request_id": "four-domain-gold-journey",
                    }
                    create_status, _, created = dashboard.json_request(
                        "POST",
                        "/api/gold/reviews",
                        create_payload,
                    )
                    self.assertEqual(create_status, 201, created)
                    review_id = str(created["review"]["review_id"])
                    self.assertNotIn(str(source_path), canonical_json(created))

                    # Two browser tabs read the same revision. The first three
                    # pages are viewed in this process before an interruption.
                    first_pages = []
                    for offset in (0, 10, 20):
                        page_status, _, page = dashboard.json_request(
                            "GET",
                            f"/api/gold/reviews/{review_id}/y0?limit=10&offset={offset}",
                        )
                        self.assertEqual(page_status, 200, page)
                        first_pages.append(page)
                        all_items.extend(page["items"])
                    tab_a = first_pages[0]
                    tab_b_status, _, tab_b = dashboard.json_request(
                        "GET",
                        f"/api/gold/reviews/{review_id}/y0?limit=10&offset=0",
                    )
                    self.assertEqual(tab_b_status, 200, tab_b)
                    self.assertEqual(
                        tab_a["document_revision_sequence"],
                        tab_b["document_revision_sequence"],
                    )
                    blind_text = canonical_json(first_pages)
                    for forbidden in (
                        "AI_LEAK",
                        "codex_cli",
                        "must_read",
                        "publication_selected",
                        str(source_path),
                    ):
                        self.assertNotIn(forbidden, blind_text)

                    first_payload = _mechanical_y0_payload(
                        tab_a["items"][0],
                        sequence=0,
                        request_id="tab-a-first-label",
                    )
                    saved_status, _, saved = dashboard.json_request(
                        "POST",
                        f"/api/gold/reviews/{review_id}/y0",
                        first_payload,
                    )
                    self.assertEqual(saved_status, 200, saved)
                    self.assertEqual(
                        saved["review"]["document_revision_sequence"],
                        1,
                    )
                    retry_status, _, retry = dashboard.json_request(
                        "POST",
                        f"/api/gold/reviews/{review_id}/y0",
                        first_payload,
                    )
                    self.assertEqual(retry_status, 200, retry)
                    self.assertTrue(retry["review"]["idempotent"])

                    stale_payload = _mechanical_y0_payload(
                        tab_b["items"][1],
                        sequence=0,
                        request_id="tab-b-stale-label",
                    )
                    conflict_status, _, conflict = dashboard.json_request(
                        "POST",
                        f"/api/gold/reviews/{review_id}/y0",
                        stale_payload,
                    )
                    self.assertEqual(conflict_status, 409, conflict)
                    self.assertEqual(conflict, {"error": "gold_review_conflict"})

                    current_status, _, current = dashboard.json_request(
                        "GET",
                        f"/api/gold/reviews/{review_id}/y0?limit=10&offset=0",
                    )
                    self.assertEqual(current_status, 200, current)
                    sequence = int(current["document_revision_sequence"])
                    second_payload = _mechanical_y0_payload(
                        current["items"][1],
                        sequence=sequence,
                        request_id="tab-b-refetched-label",
                    )
                    second_status, _, second = dashboard.json_request(
                        "POST",
                        f"/api/gold/reviews/{review_id}/y0",
                        second_payload,
                    )
                    self.assertEqual(second_status, 200, second)
                    sequence = int(second["review"]["document_revision_sequence"])

                    for index, item in enumerate(all_items[2:23], start=2):
                        payload = _mechanical_y0_payload(
                            item,
                            sequence=sequence,
                            request_id=f"session-one-{index:02d}",
                        )
                        status, _, result = dashboard.json_request(
                            "POST",
                            f"/api/gold/reviews/{review_id}/y0",
                            payload,
                        )
                        self.assertEqual(status, 200, result)
                        sequence = int(result["review"]["document_revision_sequence"])
                    self.assertEqual(sequence, 23)
                finally:
                    dashboard.stop()

                # Process/connection loss after 23 labels. A new process sees
                # the persisted y0 state and supplies the remaining pages.
                dashboard.start()
                try:
                    resume_status, _, resumed = dashboard.json_request(
                        "GET",
                        f"/api/gold/reviews/{review_id}/y0?limit=10&offset=0",
                    )
                    self.assertEqual(resume_status, 200, resumed)
                    self.assertEqual(resumed["completed_count"], 23)
                    self.assertTrue(all(item["y0"] is not None for item in resumed["items"]))
                    for offset in (30, 40, 50, 60):
                        page_status, _, page = dashboard.json_request(
                            "GET",
                            f"/api/gold/reviews/{review_id}/y0?limit=10&offset={offset}",
                        )
                        self.assertEqual(page_status, 200, page)
                        all_items.extend(page["items"])
                    self.assertEqual(len(all_items), 70)
                    self.assertEqual(
                        len({item["item_id"] for item in all_items}),
                        70,
                    )
                    total_blind_characters = len(canonical_json(all_items))
                    self.assertGreater(total_blind_characters, 250_000)
                    visible_domains = {
                        domain.key
                        for domain in DOMAINS
                        if any(
                            domain.display_name in item["citation"]["title"]
                            for item in all_items
                        )
                    }
                    self.assertEqual(visible_domains, {item.key for item in DOMAINS})

                    for index, item in enumerate(all_items[23:51], start=23):
                        payload = _mechanical_y0_payload(
                            item,
                            sequence=sequence,
                            request_id=f"session-two-{index:02d}",
                        )
                        status, _, result = dashboard.json_request(
                            "POST",
                            f"/api/gold/reviews/{review_id}/y0",
                            payload,
                        )
                        self.assertEqual(status, 200, result)
                        sequence = int(result["review"]["document_revision_sequence"])
                    self.assertEqual(sequence, 51)
                finally:
                    dashboard.stop()

                dashboard.start()
                try:
                    resume_status, _, resumed = dashboard.json_request(
                        "GET",
                        f"/api/gold/reviews/{review_id}/y0?limit=10&offset=50",
                    )
                    self.assertEqual(resume_status, 200, resumed)
                    self.assertEqual(resumed["completed_count"], 51)
                    for index, item in enumerate(all_items[51:], start=51):
                        payload = _mechanical_y0_payload(
                            item,
                            sequence=sequence,
                            request_id=f"session-three-{index:02d}",
                        )
                        status, _, result = dashboard.json_request(
                            "POST",
                            f"/api/gold/reviews/{review_id}/y0",
                            payload,
                        )
                        self.assertEqual(status, 200, result)
                        sequence = int(result["review"]["document_revision_sequence"])
                    self.assertEqual(sequence, 70)

                    lock_payload = {
                        "request_id": "final-y0-lock",
                        "reviewer_identity": (
                            "synthetic-journey-runner-not-human-gold"
                        ),
                        "expected_document_revision_sequence": 70,
                    }
                    lock_status, _, locked = dashboard.json_request(
                        "POST",
                        f"/api/gold/reviews/{review_id}/lock",
                        lock_payload,
                    )
                    self.assertEqual(lock_status, 200, locked)
                    self.assertEqual(locked["review"]["status"], "y0_locked")
                    repeated_status, _, repeated = dashboard.json_request(
                        "POST",
                        f"/api/gold/reviews/{review_id}/lock",
                        lock_payload,
                    )
                    self.assertEqual(repeated_status, 200, repeated)
                    self.assertTrue(repeated["review"]["idempotent"])
                    unavailable_status, _, unavailable = dashboard.json_request(
                        "GET",
                        f"/api/gold/reviews/{review_id}/y0",
                    )
                    self.assertEqual(unavailable_status, 409, unavailable)
                    self.assertEqual(unavailable, {"error": "gold_y0_unavailable"})
                finally:
                    dashboard.stop()

                with RadarStore(settings.database_path) as store:
                    document = store.gold_review_document(review_id)
                    revision_counts = store._connection.execute(
                        """
                        SELECT COUNT(*) AS total,
                               COUNT(DISTINCT sequence) AS sequences,
                               COUNT(DISTINCT request_id) AS requests
                        FROM gold_review_revisions WHERE review_id=?
                        """,
                        (review_id,),
                    ).fetchone()
                    integrity = store._connection.execute(
                        "PRAGMA integrity_check"
                    ).fetchone()[0]
                    foreign_keys = store._connection.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchall()
                self.assertEqual(document["status"], "y0_locked")
                self.assertTrue(
                    all(item["y0"] is not None for item in document["document"]["items"])
                )
                self.assertEqual(tuple(revision_counts), (71, 71, 71))
                self.assertEqual(integrity, "ok")
                self.assertEqual(foreign_keys, [])
                replay_signatures.append(
                    {
                        "items": [item["item_id"] for item in all_items],
                        "blind_characters": total_blind_characters,
                        "sessions": 3,
                        "successful_labels": 70,
                        "stale_conflicts": 1,
                        "revision_count": 71,
                        "status": document["status"],
                        "human_gold_claim": False,
                    }
                )
        self.assertEqual(replay_signatures, [replay_signatures[0]] * REPLAY_COUNT)

    def test_external_known_answer_cli_freeze_and_evaluate_long_set_three_times(self) -> None:
        receipt_hashes: list[str] = []
        for replay in range(REPLAY_COUNT):
            with self.subTest(replay=replay), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "外部 已知答案 真实长度旅程"
                draft_path = root / "24项 四领域 草稿.json"
                frozen_path = root / "24项 四领域 冻结.json"
                candidates_path = root / "候选排名.json"
                receipt_path = root / "离线评测回执.json"
                draft = _draft_set()
                self.assertEqual(len(draft["items"]), 24)
                total_characters = sum(
                    len(item["abstract_or_description"])
                    for item in draft["items"]
                )
                self.assertGreater(total_characters, 100_000)
                self.assertEqual(
                    {
                        item["abstract_or_description"].split(" investigates ", 1)[1]
                        .split(" across ", 1)[0]
                        for item in draft["items"]
                    },
                    {
                        "agent workflow cache retention",
                        "embodied companion safety for older adults",
                        "single-cell perturbation response prediction",
                        "urban heat exposure and causal adaptation",
                    },
                )
                _write_json(draft_path, draft)

                freeze_console = io.StringIO()
                with redirect_stdout(freeze_console):
                    freeze_exit = main(
                        [
                            "known-answer-validate",
                            str(draft_path),
                            "--freeze",
                            "--frozen-at",
                            "2026-08-10T07:00:00+08:00",
                            "--frozen-by",
                            "synthetic-journey-freezer-not-human-gold",
                            "--output",
                            str(frozen_path),
                        ]
                    )
                self.assertEqual(freeze_exit, 0, freeze_console.getvalue())
                freeze_summary = json.loads(freeze_console.getvalue())
                self.assertFalse(freeze_summary["human_gold_claim"])
                frozen = json.loads(frozen_path.read_text(encoding="utf-8"))
                candidates = [
                    _candidate(item, rank)
                    for rank, item in enumerate(frozen["items"][12:], start=1)
                ]
                _write_json(candidates_path, candidates)

                evaluation_console = io.StringIO()
                with redirect_stdout(evaluation_console):
                    evaluate_exit = main(
                        _evaluation_args(frozen_path, candidates_path, receipt_path)
                    )
                self.assertEqual(evaluate_exit, 0, evaluation_console.getvalue())
                evaluation_summary = json.loads(evaluation_console.getvalue())
                self.assertFalse(evaluation_summary["human_gold_claim"])
                self.assertFalse(
                    evaluation_summary["market_or_recommendation_quality_claim"]
                )
                receipt = validate_known_answer_evaluation_receipt(
                    json.loads(receipt_path.read_text(encoding="utf-8"))
                )
                self.assertEqual(receipt["known_answer_set"]["item_count"], 12)
                self.assertEqual(len(receipt["matches"]), 12)
                self.assertGreater(
                    receipt["metrics"]["candidate_recall"]["denominator"],
                    0,
                )
                receipt_hashes.append(hashlib.sha256(receipt_path.read_bytes()).hexdigest())
        self.assertEqual(len(set(receipt_hashes)), 1)

    def test_eight_compressed_state_cycles_are_idempotent_recoverable_not_calendar_evidence(self) -> None:
        replay_results: list[dict] = []
        for replay in range(REPLAY_COUNT):
            with self.subTest(replay=replay), tempfile.TemporaryDirectory() as temporary:
                settings = make_settings(Path(temporary))
                fixture = _seed_phase_c_fixture(settings)
                created_at: str | None = None
                for cycle in range(1, 9):
                    # Every iteration opens a new connection to model process loss and
                    # recovery. It does not advance real dates or claim future value.
                    with RadarStore(settings.database_path) as store:
                        saved = store.save_research_decision(
                            issue_id=str(fixture["issue_id"]),
                            analysis_id=int(fixture["published_analysis_id"]),
                            action="defer",
                            reason=(
                                "需要真实 future-window 观察；本循环只检验状态恢复。"
                            ),
                            note=(
                                f"{SIMULATION_BOUNDARY}; compressed state cycle; "
                                + SYNTHETIC_NOTICE
                            ),
                            retrieval_hash=settings.retrieval_hash,
                            analysis_policy_hash=settings.analysis_policy_hash,
                        )
                        row = store._connection.execute(
                            """
                            SELECT created_at, action, reason, note
                            FROM research_decisions
                            WHERE issue_id=? AND analysis_id=?
                            """,
                            (
                                fixture["issue_id"],
                                fixture["published_analysis_id"],
                            ),
                        ).fetchone()
                        count = int(
                            store._connection.execute(
                                """
                                SELECT COUNT(*) FROM research_decisions
                                WHERE issue_id=? AND analysis_id=?
                                """,
                                (
                                    fixture["issue_id"],
                                    fixture["published_analysis_id"],
                                ),
                            ).fetchone()[0]
                        )
                        integrity = store._connection.execute(
                            "PRAGMA integrity_check"
                        ).fetchone()[0]
                        foreign_keys = store._connection.execute(
                            "PRAGMA foreign_key_check"
                        ).fetchall()
                    self.assertEqual(count, 1, f"cycle={cycle}")
                    self.assertEqual(integrity, "ok", f"cycle={cycle}")
                    self.assertEqual(foreign_keys, [], f"cycle={cycle}")
                    self.assertEqual(saved["action"], "defer")
                    self.assertIn(SIMULATION_BOUNDARY, str(row["note"]))
                    if created_at is None:
                        created_at = str(row["created_at"])
                    self.assertEqual(str(row["created_at"]), created_at)

                with RadarStore(settings.database_path) as recovered:
                    decision = recovered.decision_slice(
                        retrieval_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                        issue_id=str(fixture["issue_id"]),
                    )["items"][0]["decision"]
                    columns = {
                        str(row["name"])
                        for row in recovered._connection.execute(
                            "PRAGMA table_info(research_decisions)"
                        ).fetchall()
                    }
                self.assertEqual(decision["action"], "defer")
                self.assertIn(SIMULATION_BOUNDARY, decision["note"])
                reminder_fields = sorted(
                    columns.intersection(
                        {"reminder_at", "reminder_count", "reminder_decay"}
                    )
                )
                replay_results.append(
                    {
                        "cycles": 8,
                        "decision_rows": 1,
                        "action": decision["action"],
                        "boundary": SIMULATION_BOUNDARY,
                        # This is descriptive, not a gate against a future optional
                        # reminder model. The current production schema returns [].
                        "observed_reminder_fields": reminder_fields,
                    }
                )
        self.assertEqual(replay_results, [replay_results[0]] * REPLAY_COUNT)


if __name__ == "__main__":
    unittest.main()
