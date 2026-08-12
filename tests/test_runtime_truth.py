from __future__ import annotations

import http.client
import io
import json
import os
import socket
import sqlite3
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from r3radar.__main__ import main
from r3radar.config import PROJECT_DIR, load_settings
from r3radar.onboarding import create_profile, doctor_report
from r3radar.runtime_status import inspect_database, run_status
from r3radar.storage import RadarStore, SCHEMA_VERSION
from r3radar.web import RadarHttpServer


def make_settings(root: Path, profile_id: str = "runtime-truth"):
    profile = root / f"{profile_id}.json"
    create_profile(
        profile,
        profile_id=profile_id,
        name="Runtime truth research radar",
        research_question=(
            "Which workflow-semantic signals predict reuse of short-lived "
            "agent cache objects better than recency and frequency?"
        ),
        decision_scope=(
            "Select evidence that can change one retention or eviction decision."
        ),
    )
    return load_settings(profile)


class RuntimeTruthTests(unittest.TestCase):
    def test_dashboard_uses_observed_run_state_instead_of_lease_only_fallback(self) -> None:
        javascript = (PROJECT_DIR / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const observedRun = status.runtime?.run || null", javascript)
        self.assertIn("observedRun?.state || run.status", javascript)
        self.assertIn("observedRun.active === true", javascript)

    def test_read_only_database_probe_distinguishes_missing_old_and_current(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            missing = root / "missing.sqlite3"
            self.assertEqual("missing", inspect_database(missing)["state"])
            self.assertFalse(missing.exists())

            old = root / "old.sqlite3"
            connection = sqlite3.connect(old)
            connection.executescript(
                """
                CREATE TABLE schema_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO schema_meta VALUES('schema_version', '1');
                """
            )
            connection.close()
            old_status = inspect_database(old)
            self.assertEqual("migration_required", old_status["state"])
            self.assertEqual(1, old_status["schema_version"])

            settings = make_settings(root, "current-runtime")
            with RadarStore(settings.database_path):
                pass
            current_status = inspect_database(settings.database_path)
            self.assertEqual("ready", current_status["state"])
            self.assertEqual(SCHEMA_VERSION, current_status["schema_version"])
            self.assertFalse(current_status["migration_required"])

    def test_corrupt_database_is_not_reported_ready(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            database = Path(raw) / "radar.sqlite3"
            database.write_bytes(b"not a sqlite database")
            status = inspect_database(database)
            self.assertIn(status["state"], {"corrupt", "unreadable"})
            self.assertFalse(status["readable"])

    def test_run_requires_live_owner_fresh_lease_and_token(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = make_settings(Path(raw))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                active = run_status(
                    store,
                    settings.config_hash,
                    settings.retrieval_hash,
                )
                self.assertEqual("active", active["state"])
                self.assertTrue(active["active"])
                self.assertEqual(os.getpid(), active["latest"]["owner_pid"])

                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                )
                with store._lock:
                    store._connection.execute(
                        """
                        UPDATE query_jobs
                        SET status='running', claim_lease_token='wrong-owner-token'
                        WHERE id=(SELECT MIN(id) FROM query_jobs WHERE run_id=?)
                        """,
                        (run_id,),
                    )
                mismatch = run_status(
                    store,
                    settings.config_hash,
                    settings.retrieval_hash,
                )
                self.assertEqual("lease_owner_mismatch", mismatch["state"])
                self.assertFalse(mismatch["active"])
                self.assertEqual(1, mismatch["latest"]["mismatched_claims"])
                with store._lock:
                    store._connection.execute(
                        """
                        UPDATE query_jobs
                        SET claim_lease_token=?
                        WHERE run_id=? AND status='running'
                        """,
                        (lease_token, run_id),
                    )

                expired = (
                    datetime.now(timezone.utc) - timedelta(minutes=1)
                ).isoformat(timespec="seconds")
                with store._lock:
                    store._connection.execute(
                        "UPDATE runs SET lease_expires_at=? WHERE id=?",
                        (expired, run_id),
                    )
                stale = run_status(
                    store,
                    settings.config_hash,
                    settings.retrieval_hash,
                )
                self.assertEqual("stale_lease", stale["state"])
                self.assertFalse(stale["active"])

    def test_health_and_status_expose_same_runtime_truth_and_local_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = make_settings(Path(raw))
            server = RadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with patch(
                    "r3radar.web.scheduler_status",
                    return_value={
                        "state": "absent",
                        "installed": False,
                        "observed": True,
                        "task_name": "R3 Research Radar",
                    },
                ):
                    payloads = []
                    for endpoint in ("/api/health", "/api/status"):
                        connection = http.client.HTTPConnection(
                            "127.0.0.1", port, timeout=5
                        )
                        connection.request(
                            "GET",
                            endpoint,
                            headers={
                                "Host": f"127.0.0.1:{port}",
                                "Connection": "close",
                            },
                        )
                        response = connection.getresponse()
                        payloads.append(json.loads(response.read()))
                        self.assertEqual(200, response.status)
                        connection.close()
                health, status = payloads
                self.assertTrue(health["ok"])
                self.assertEqual(settings.config_hash, health["instance"]["config_hash"])
                self.assertEqual("ready", health["runtime"]["database"]["state"])
                self.assertEqual("up", health["runtime"]["service"]["state"])
                self.assertEqual("ready", status["runtime"]["database"]["state"])
                self.assertEqual("up", status["runtime"]["service"]["state"])
                self.assertEqual("idle", status["runtime"]["run"]["state"])
                self.assertFalse(status["deep_read"]["active"])
                self.assertGreaterEqual(status["runtime"]["metrics"]["requests"], 1)
                cli_output = io.StringIO()
                with patch(
                    "r3radar.__main__.scheduler_status",
                    return_value={
                        "state": "absent",
                        "installed": False,
                        "observed": True,
                        "task_name": "R3 Research Radar",
                    },
                ), redirect_stdout(cli_output):
                    cli_exit = main(
                        [
                            "--config",
                            str(settings.config_path),
                            "status",
                            "--json",
                            "--port",
                            str(port),
                        ]
                    )
                cli = json.loads(cli_output.getvalue())
                self.assertEqual(0, cli_exit)
                self.assertEqual("running", cli["runtime"]["service"]["state"])
                self.assertEqual(
                    status["runtime"]["database"]["state"],
                    cli["runtime"]["database"]["state"],
                )
                self.assertEqual(
                    status["runtime"]["run"]["state"],
                    cli["runtime"]["run"]["state"],
                )
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

    def test_status_never_exposes_the_run_lease_token(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = make_settings(Path(raw))
            with RadarStore(settings.database_path) as store:
                store.create_or_resume_run(settings, "test")
            server = RadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "GET",
                    "/api/status",
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                payload = json.loads(response.read())
                connection.close()
                self.assertEqual(200, response.status)
                self.assertNotIn("lease_token", payload["latest_run"])
                self.assertTrue(payload["latest_run"]["lease_token_present"])
                self.assertNotIn('"lease_token":', json.dumps(payload["runtime"]))
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

    def test_doctor_rejects_a_different_r3_profile_on_the_same_port(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            running_settings = make_settings(root, "running-profile")
            expected_settings = make_settings(root, "expected-profile")
            server = RadarHttpServer(("127.0.0.1", 0), running_settings)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report = doctor_report(expected_settings, dashboard_port=port)
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()
            dashboard = next(
                check for check in report["checks"] if check["id"] == "dashboard_port"
            )
            self.assertEqual("running_other_profile", dashboard["service_state"])
            self.assertNotEqual("ready", report["status"])

    def test_cli_status_and_dashboard_fail_closed_without_a_database(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = make_settings(Path(raw))
            self.assertFalse(settings.database_path.exists())
            output = io.StringIO()
            with redirect_stdout(output):
                status_exit = main(
                    ["--config", str(settings.config_path), "status", "--json"]
                )
            payload = json.loads(output.getvalue())
            self.assertEqual(1, status_exit)
            self.assertEqual("missing", payload["runtime"]["database"]["state"])
            self.assertFalse(settings.database_path.exists())

            output = io.StringIO()
            with redirect_stdout(output):
                dashboard_exit = main(
                    ["--config", str(settings.config_path), "dashboard"]
                )
            failure = json.loads(output.getvalue())
            self.assertEqual(1, dashboard_exit)
            self.assertEqual("database_not_ready", failure["reason"])
            self.assertFalse(settings.database_path.exists())

    def test_dashboard_start_reports_port_ownership_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings = make_settings(Path(raw))
            with RadarStore(settings.database_path):
                pass
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = int(listener.getsockname()[1])
            output = io.StringIO()
            try:
                with redirect_stdout(output):
                    exit_code = main(
                        [
                            "--config",
                            str(settings.config_path),
                            "dashboard",
                            "--port",
                            str(port),
                        ]
                    )
            finally:
                listener.close()
            failure = json.loads(output.getvalue())
            self.assertEqual(1, exit_code)
            self.assertFalse(failure["ok"])
            self.assertEqual("dashboard_start_failed", failure["event"])
            self.assertIn(failure["error_type"], {"OSError", "PermissionError"})


if __name__ == "__main__":
    unittest.main()
