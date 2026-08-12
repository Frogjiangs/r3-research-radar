from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from r3radar.calibration import _weekly_replay
from r3radar.intake import WeeklyIntakeGate, WeeklyIntakePolicy
from r3radar.models import AdmissionDecision, SourceRecord
from r3radar.storage import RadarStore
from tests.test_core import make_settings


class WeeklyStableIdentityTests(unittest.TestCase):
    def test_calibration_replay_uses_stable_work_identity(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript(
            """
            CREATE TABLE query_jobs (
                id INTEGER PRIMARY KEY,
                source TEXT,
                query_id TEXT,
                lane TEXT
            );
            CREATE TABLE works (
                id INTEGER PRIMARY KEY,
                kind TEXT,
                title TEXT,
                year INTEGER,
                doi TEXT,
                arxiv_id TEXT,
                github_full_name TEXT
            );
            CREATE TABLE source_records (
                id INTEGER PRIMARY KEY,
                source TEXT,
                source_id TEXT,
                canonical_url TEXT,
                metadata_json TEXT
            );
            CREATE TABLE run_hits (
                run_id TEXT,
                query_job_id INTEGER,
                work_id INTEGER,
                source_record_id INTEGER,
                admitted INTEGER,
                admission_code TEXT,
                seen_at TEXT
            );
            INSERT INTO query_jobs VALUES (1, 'openalex', 'q1', 'core');
            INSERT INTO works VALUES (
                7, 'paper', 'Stable Replay Identity', 2026,
                NULL, NULL, NULL
            );
            INSERT INTO source_records VALUES (
                11, 'openalex', 'W7', 'https://example.test/7',
                '{"publication_date":"2026-07-29"}'
            );
            INSERT INTO run_hits VALUES (
                'run-1', 1, 7, 11, 1, 'admitted',
                '2026-07-30T00:00:00+00:00'
            );
            """
        )
        policy_raw = {
            "profile_version": 2,
            "intake": {
                "weekly": {
                    "state": "active",
                    "policy_version": "r3-weekly-intake-v1",
                    "window_days": 14,
                    "overlap_days": 3,
                    "maximum_admitted_candidates": 1,
                    "source_query_caps": {"openalex": 1},
                    "query_caps": {"q1": 1},
                    "lane_caps": {"core": 1},
                    "capacity_basis": {
                        "derived_maximum_admitted_candidates": 1
                    },
                }
            },
        }

        with patch("r3radar.calibration.WeeklyIntakeGate") as gate_class:
            gate = gate_class.return_value
            gate.reserve.return_value = (
                AdmissionDecision(True, "admitted", "candidate", "fixture"),
                ("provisional", "core"),
            )
            gate.snapshot.return_value = {"admitted_unique": 1}
            _weekly_replay(
                connection,
                run_id="run-1",
                policy_raw=policy_raw,
                reference_time=datetime(2026, 7, 30, tzinfo=timezone.utc),
            )

        self.assertEqual(
            gate.reserve.call_args.kwargs["identity_key"],
            "work:7",
        )
        self.assertEqual(
            gate.commit.call_args.kwargs["stable_identity_key"],
            "work:7",
        )
        connection.close()

    def test_alias_merge_and_restart_keep_one_capacity_identity(self) -> None:
        policy = WeeklyIntakePolicy(
            window_days=14,
            overlap_days=3,
            maximum_admitted_candidates=2,
            source_query_caps={"openalex": 2, "arxiv": 2},
            query_caps={"q1": 2},
            lane_caps={"core": 1, "adjacent": 1},
            capacity_basis={"derived_maximum_admitted_candidates": 2},
        )
        now = datetime(2026, 7, 30, tzinfo=timezone.utc)
        decision = AdmissionDecision(
            admitted=True,
            code="admitted",
            lane="candidate",
            reason="fixture",
        )
        first = SourceRecord(
            source="openalex",
            source_id="W-STABLE",
            kind="paper",
            title="Stable Identity Across Providers",
            query_id="q1",
            year=2026,
            metadata={"publication_date": "2026-07-25"},
        )
        alias = SourceRecord(
            source="arxiv",
            source_id="2607.12345",
            kind="paper",
            title="Stable Identity Across Providers",
            query_id="q1",
            year=2026,
            doi="10.1000/stable",
            metadata={"updated": "2026-07-26T00:00:00Z"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "weekly",
                )
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    jobs = store._connection.execute(
                        """
                        SELECT id, source FROM query_jobs
                        WHERE run_id=? AND source IN ('openalex','arxiv')
                        ORDER BY id
                        """,
                        (run_id,),
                    ).fetchall()
                job_by_source = {
                    str(row["source"]): int(row["id"]) for row in jobs
                }
                gate = WeeklyIntakeGate(policy, now=now)

                first_decision, first_reservation = gate.reserve(
                    first,
                    decision,
                    query_lane="core",
                )
                first_work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_by_source["openalex"],
                    record=first,
                    decision=first_decision,
                    raw_sha256="first",
                )
                gate.commit(
                    first_reservation,
                    stable_identity_key=f"work:{first_work_id}",
                )

                resolved = store.lookup_record_work_id(alias)
                self.assertEqual(resolved, first_work_id)
                alias_decision, alias_reservation = gate.reserve(
                    alias,
                    decision,
                    query_lane="adjacent",
                    identity_key=f"work:{resolved}",
                )
                alias_work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_by_source["arxiv"],
                    record=alias,
                    decision=alias_decision,
                    raw_sha256="alias",
                )
                gate.commit(
                    alias_reservation,
                    stable_identity_key=f"work:{alias_work_id}",
                )

                self.assertEqual(alias_work_id, first_work_id)
                self.assertEqual(gate.snapshot()["admitted_unique"], 1)
                persisted = store.admitted_run_intake_state(run_id)

            restored = WeeklyIntakeGate(policy, now=now, admitted=persisted)
            self.assertEqual(restored.snapshot()["admitted_unique"], 1)
            self.assertEqual(
                restored.snapshot()["lane_counts"],
                {"adjacent": 0, "core": 1},
            )


if __name__ == "__main__":
    unittest.main()
