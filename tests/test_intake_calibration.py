from __future__ import annotations

import sqlite3
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from r3radar.calibration import (
    CalibrationError,
    _duration_calibration,
    evaluate_gold_set,
)
from r3radar.intake import (
    WEEKLY_POLICY_VERSION,
    WeeklyIntakeGate,
    WeeklyIntakePolicy,
    WeeklyIntakePolicyError,
)
from r3radar.models import AdmissionDecision, SourceRecord
from r3radar.sources import ArxivSource, GitHubSource, OpenAlexSource


def active_profile_v2() -> dict:
    return {
        "profile_version": 2,
        "queries": [
            {
                "id": "q1",
                "lane": "core",
                "sources": ["openalex", "arxiv", "github"],
            }
        ],
        "hosted_search": {"enabled": False},
        "intake": {
            "weekly": {
                "state": "active",
                "policy_version": WEEKLY_POLICY_VERSION,
                "window_days": 14,
                "overlap_days": 3,
                "maximum_admitted_candidates": 2,
                "source_query_caps": {
                    "openalex": 3,
                    "arxiv": 4,
                    "github": 5,
                },
                "query_caps": {"q1": 2},
                "lane_caps": {"core": 2},
                "capacity_basis": {
                    "derived_maximum_admitted_candidates": 2,
                },
            }
        },
    }


def admitted_decision() -> AdmissionDecision:
    return AdmissionDecision(
        admitted=True,
        code="admitted",
        lane="candidate",
        reason="Objective admission passed.",
    )


def paper(
    source_id: str,
    *,
    activity_date: str | None = "2026-07-25",
    doi: str | None = None,
) -> SourceRecord:
    metadata = {}
    if activity_date is not None:
        metadata["publication_date"] = activity_date
    return SourceRecord(
        source="openalex",
        source_id=source_id,
        kind="paper",
        title=f"Paper {source_id}",
        query_id="q1",
        year=2026,
        doi=doi,
        metadata=metadata,
    )


class WeeklyIntakePolicyTests(unittest.TestCase):
    def test_weekly_mode_fails_closed_without_explicit_profile_v2_activation(self):
        with self.assertRaisesRegex(
            WeeklyIntakePolicyError,
            "explicitly activated profile-v2",
        ):
            WeeklyIntakePolicy.from_config(
                {
                    "profile_version": 1,
                    "queries": [],
                    "hosted_search": {"enabled": False},
                }
            )

        proposed = active_profile_v2()
        proposed["intake"]["weekly"]["state"] = "proposed"
        with self.assertRaisesRegex(
            WeeklyIntakePolicyError,
            "must be active",
        ):
            WeeklyIntakePolicy.from_config(proposed)

    def test_active_policy_enforces_provider_and_query_retrieval_caps(self):
        policy = WeeklyIntakePolicy.from_config(active_profile_v2())

        self.assertEqual(
            policy.retrieval_limit(
                source="openalex",
                query_id="q1",
                requested_limit=None,
            ),
            2,
        )
        self.assertEqual(
            policy.retrieval_limit(
                source="github",
                query_id="q1",
                requested_limit=1,
            ),
            1,
        )

    def test_gate_defers_unknown_and_expired_dates(self):
        gate = WeeklyIntakeGate(
            WeeklyIntakePolicy.from_config(active_profile_v2()),
            now=datetime(2026, 7, 30, tzinfo=timezone.utc),
        )

        unknown = gate.decide(
            paper("unknown", activity_date=None),
            admitted_decision(),
            query_lane="core",
        )
        expired = gate.decide(
            paper("expired", activity_date="2026-07-01"),
            admitted_decision(),
            query_lane="core",
        )

        self.assertEqual(unknown.code, "weekly_date_unknown")
        self.assertFalse(unknown.admitted)
        self.assertEqual(expired.code, "weekly_outside_window")
        self.assertFalse(expired.admitted)

    def test_gate_counts_canonical_duplicates_once_and_enforces_capacity(self):
        policy_raw = active_profile_v2()
        policy_raw["queries"].append(
            {"id": "q2", "lane": "adjacent", "sources": ["openalex"]}
        )
        policy_raw["intake"]["weekly"]["query_caps"]["q2"] = 2
        policy_raw["intake"]["weekly"]["lane_caps"] = {
            "core": 1,
            "adjacent": 1,
        }
        gate = WeeklyIntakeGate(
            WeeklyIntakePolicy.from_config(policy_raw),
            now=datetime(2026, 7, 30, tzinfo=timezone.utc),
        )

        first = gate.decide(
            paper("one", doi="10.1/shared"),
            admitted_decision(),
            query_lane="core",
        )
        duplicate = gate.decide(
            paper("duplicate", doi="https://doi.org/10.1/shared"),
            admitted_decision(),
            query_lane="adjacent",
        )
        core_overflow = gate.decide(
            paper("core-overflow"),
            admitted_decision(),
            query_lane="core",
        )
        second_unique = gate.decide(
            paper("two"),
            admitted_decision(),
            query_lane="adjacent",
        )
        global_overflow = gate.decide(
            paper("three"),
            admitted_decision(),
            query_lane="adjacent",
        )

        self.assertTrue(first.admitted)
        self.assertTrue(duplicate.admitted)
        self.assertEqual(core_overflow.code, "weekly_lane_capacity_deferred")
        self.assertTrue(second_unique.admitted)
        self.assertEqual(global_overflow.code, "weekly_capacity_deferred")
        snapshot = gate.snapshot()
        self.assertEqual(snapshot["admitted_unique"], 2)
        self.assertEqual(snapshot["lane_counts"], {"adjacent": 1, "core": 1})

    def test_failed_ingest_reservation_can_be_rolled_back(self):
        gate = WeeklyIntakeGate(
            WeeklyIntakePolicy.from_config(active_profile_v2()),
            now=datetime(2026, 7, 30, tzinfo=timezone.utc),
        )

        decision, reservation = gate.reserve(
            paper("transient"),
            admitted_decision(),
            query_lane="core",
        )
        self.assertTrue(decision.admitted)
        self.assertEqual(gate.snapshot()["admitted_unique"], 1)

        gate.rollback(reservation)

        self.assertEqual(gate.snapshot()["admitted_unique"], 0)
        self.assertEqual(gate.snapshot()["lane_counts"], {"core": 0})


class GoldSetEvaluationTests(unittest.TestCase):
    def test_unlabeled_gold_set_never_computes_recall(self):
        gold_set = {
            "items": [
                {"item_id": "one", "work_id": 1, "human_label": None},
                {
                    "item_id": "two",
                    "work_id": 2,
                    "human_label": "known_important",
                },
            ]
        }

        result = evaluate_gold_set(gold_set, candidate_work_ids={1, 2})

        self.assertEqual(result["status"], "pending_human_verification")
        self.assertIsNone(result["recall_at_candidate"])
        self.assertFalse(result["passed"])

    def test_complete_human_labels_compute_recall_and_threshold(self):
        items = [
            {
                "item_id": f"known-{work_id}",
                "work_id": work_id,
                "human_label": "known_important",
            }
            for work_id in range(1, 11)
        ]
        items.append(
            {
                "item_id": "negative",
                "work_id": 99,
                "human_label": "hard_negative",
            }
        )

        passing = evaluate_gold_set(
            {"items": items},
            candidate_work_ids=set(range(1, 10)),
        )
        failing = evaluate_gold_set(
            {"items": items},
            candidate_work_ids=set(range(1, 9)),
        )

        self.assertEqual(passing["status"], "evaluated")
        self.assertEqual(passing["recall_at_candidate"], 0.9)
        self.assertTrue(passing["passed"])
        self.assertEqual(failing["recall_at_candidate"], 0.8)
        self.assertFalse(failing["passed"])


class _JsonClient:
    def __init__(self, payload: dict):
        self.payload = payload
        self.calls: list[dict] = []

    def request_json(self, endpoint, **kwargs):
        self.calls.append({"endpoint": endpoint, **kwargs})
        return self.payload, object(), 200


class _BytesClient:
    def __init__(self, body: bytes):
        self.body = body
        self.calls: list[dict] = []

    def request_bytes(self, endpoint, **kwargs):
        self.calls.append({"endpoint": endpoint, **kwargs})
        return self.body, object(), 200


class WeeklySourceAdapterTests(unittest.TestCase):
    job = {
        "query_id": "q1",
        "query_text": '"agent cache"',
        "weekly_since": "2026-07-13",
        "cursor": None,
        "page_no": 0,
        "result_count": 0,
    }
    source_config = {"page_size": 10, "max_results_per_query": 10}

    def test_openalex_uses_weekly_publication_filter(self):
        client = _JsonClient({"results": [], "meta": {"next_cursor": None}})
        source = OpenAlexSource(client, self.source_config, from_year=2020)

        with patch.dict("os.environ", {"OPENALEX_API_KEY": "test-key"}):
            list(source.pages(dict(self.job), result_limit=1))

        self.assertEqual(len(client.calls), 1)
        params = client.calls[0]["params"]
        self.assertEqual(params["filter"], "from_publication_date:2026-07-13")
        self.assertEqual(params["per-page"], 1)

    def test_arxiv_uses_weekly_submitted_date_range(self):
        client = _BytesClient(
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<feed xmlns="http://www.w3.org/2005/Atom"></feed>'
        )
        source = ArxivSource(client, self.source_config)

        list(source.pages(dict(self.job), result_limit=1))

        self.assertEqual(len(client.calls), 1)
        query = client.calls[0]["params"]["search_query"]
        self.assertIn("submittedDate:[202607130000 TO 999912312359]", query)
        self.assertEqual(client.calls[0]["params"]["max_results"], 1)
        self.assertEqual(client.calls[0]["params"]["sortBy"], "submittedDate")

    def test_arxiv_backfill_sorts_by_relevance(self):
        client = _BytesClient(
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<feed xmlns="http://www.w3.org/2005/Atom"></feed>'
        )
        source = ArxivSource(client, self.source_config)
        job = dict(self.job)
        job["weekly_since"] = ""

        list(source.pages(job, result_limit=1))

        self.assertEqual(client.calls[0]["params"]["sortBy"], "relevance")

    def test_github_uses_weekly_pushed_qualifier(self):
        client = _JsonClient({"items": [], "total_count": 0})
        source = GitHubSource(client, self.source_config)

        list(source.pages(dict(self.job), result_limit=1))

        self.assertEqual(len(client.calls), 1)
        params = client.calls[0]["params"]
        self.assertEqual(params["q"], '"agent cache" pushed:>=2026-07-13')
        self.assertEqual(params["per_page"], 1)


class CalibrationDurationTests(unittest.TestCase):
    def test_duration_calibration_rejects_run_without_measured_duration(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        self.addCleanup(connection.close)
        connection.execute(
            """
            CREATE TABLE model_invocations (
                invocation_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                work_id INTEGER,
                provider TEXT NOT NULL,
                duration_seconds REAL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO model_invocations
                (invocation_id, run_id, work_id, provider, duration_seconds)
            VALUES ('i1', 'run-1', 1, 'codex_cli', NULL)
            """
        )

        with self.assertRaisesRegex(
            CalibrationError,
            "no per-work model duration receipts",
        ):
            _duration_calibration(
                connection,
                run_id="run-1",
                maximum_runtime_seconds=6 * 60 * 60,
            )


if __name__ == "__main__":
    unittest.main()
