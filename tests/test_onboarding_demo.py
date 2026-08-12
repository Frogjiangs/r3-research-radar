from __future__ import annotations

import io
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from r3radar.__main__ import build_parser, main
from r3radar.config import PROJECT_DIR, load_settings
from r3radar.decision import build_evidence_context
from r3radar.demo import prepare_demo
from r3radar.onboarding import create_profile, doctor_report
from r3radar.storage import RadarStore
from r3radar.web import RadarHttpServer


class OnboardingTests(unittest.TestCase):
    def test_reprojection_cli_is_explicit_and_dry_run_by_default(self) -> None:
        parser = build_parser()

        dry_run = parser.parse_args(
            ["reproject-repositories", "--work-id", "7"]
        )
        applying = parser.parse_args(
            ["reproject-repositories", "--apply", "--work-id", "7"]
        )

        self.assertFalse(dry_run.apply)
        self.assertEqual([7], dry_run.work_ids)
        self.assertTrue(applying.apply)

    def test_explicit_workspace_root_is_relative_to_profile_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            profile_dir = root / "profile-home"
            profile_dir.mkdir()
            profile_path = profile_dir / "profile.json"
            profile = json.loads(
                (PROJECT_DIR / "config" / "profile.example.json").read_text(
                    encoding="utf-8"
                )
            )
            profile["workspace_root"] = "."
            profile_path.write_text(
                json.dumps(profile, ensure_ascii=False),
                encoding="utf-8",
            )

            settings = load_settings(profile_path)

            self.assertEqual(profile_dir.resolve(), settings.workspace_dir)
            self.assertEqual(
                (profile_dir / ".r3radar" / "agent-systems-radar" / "data").resolve(),
                settings.data_dir,
            )

    def test_explicit_workspace_rejects_runtime_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            profile_path = root / "profile.json"
            profile = json.loads(
                (PROJECT_DIR / "config" / "profile.example.json").read_text(
                    encoding="utf-8"
                )
            )
            profile["paths"]["data"] = "../outside"
            profile_path.write_text(
                json.dumps(profile, ensure_ascii=False),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "escapes workspace"):
                load_settings(profile_path)

    def test_create_profile_is_generic_loadable_and_non_overwriting(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            profile_path = Path(raw) / "my-profile.json"

            result = create_profile(
                profile_path,
                profile_id="my-agent-radar",
                name="My Agent Radar",
                research_question="Which agent-system results should I test?",
                decision_scope="Choose read, test, watch, or skip.",
            )
            profile_text = profile_path.read_text(encoding="utf-8")
            settings = load_settings(profile_path)

            self.assertTrue(result["ok"])
            self.assertEqual("my-agent-radar", settings.profile_id)
            self.assertNotIn("OPENAI_API_KEY", profile_text)
            self.assertNotIn("GITHUB_TOKEN", profile_text)
            self.assertNotRegex(profile_text, r"(?i)[A-Z]:[\\/]+Users[\\/]")
            with self.assertRaises(FileExistsError):
                create_profile(
                    profile_path,
                    profile_id="my-agent-radar",
                    name="Replacement",
                    research_question="Should not overwrite.",
                    decision_scope="Should not overwrite.",
                )

    def test_doctor_report_is_redacted_and_actionable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            profile_path = Path(raw) / "profile.json"
            create_profile(
                profile_path,
                profile_id="doctor-radar",
                name="Doctor Radar",
                research_question="Can the environment run this profile?",
                decision_scope="Check local readiness.",
            )
            settings = load_settings(profile_path)
            fake_github = "fake-github-value-must-not-appear"
            fake_openalex = "openalex-fake-value-must-not-appear"
            with patch.dict(
                os.environ,
                {
                    "GITHUB_TOKEN": fake_github,
                    "OPENALEX_API_KEY": fake_openalex,
                },
                clear=True,
            ):
                report = doctor_report(settings, dashboard_port=65534)

            serialized = json.dumps(report, ensure_ascii=False)
            self.assertNotIn(fake_github, serialized)
            self.assertNotIn(fake_openalex, serialized)
            self.assertNotIn(str(Path(raw).resolve()), serialized)
            self.assertFalse(report["secret_values_included"])
            self.assertIn(report["status"], {"ready", "degraded"})
            self.assertEqual(
                {
                    "full_pipeline_platform",
                    "workspace_boundary",
                    "runtime_directories",
                    "database",
                    "codex_cli",
                    "codex_authentication",
                    "openalex_key",
                    "github_token",
                    "dashboard_port",
                    "scheduler",
                    "model_data_flow",
                },
                {item["id"] for item in report["checks"]},
            )
            dashboard = next(
                item for item in report["checks"] if item["id"] == "dashboard_port"
            )
            self.assertEqual("not_running", dashboard["service_state"])
            self.assertIn("dashboard", dashboard["remediation"])

    def test_cli_quickstart_commands_work_without_network_or_model(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            profile_path = root / "profile.json"
            output = io.StringIO()
            with redirect_stdout(output):
                profile_exit = main(
                    [
                        "create-profile",
                        "--output",
                        str(profile_path),
                        "--profile-id",
                        "cli-radar",
                    ]
                )
            self.assertEqual(0, profile_exit)
            self.assertTrue(json.loads(output.getvalue())["ok"])

            output = io.StringIO()
            with redirect_stdout(output):
                doctor_exit = main(
                    [
                        "--config",
                        str(profile_path),
                        "doctor",
                        "--json",
                        "--port",
                        "65534",
                    ]
                )
            self.assertEqual(0, doctor_exit)
            self.assertIn(
                json.loads(output.getvalue())["status"],
                {"ready", "degraded"},
            )

            output = io.StringIO()
            with redirect_stdout(output):
                demo_exit = main(
                    [
                        "demo",
                        "--workspace",
                        str(root / "demo"),
                        "--prepare-only",
                    ]
                )
            demo_result = json.loads(output.getvalue())
            self.assertEqual(0, demo_exit)
            self.assertEqual(0, demo_result["network_calls"])
            self.assertEqual(0, demo_result["model_calls"])
            self.assertEqual(2, demo_result["counts"]["deep_read"])
            demo_database = Path(demo_result["database"])
            database_before = demo_database.read_bytes()
            output = io.StringIO()
            with redirect_stdout(output):
                reproject_exit = main(
                    [
                        "--config",
                        str(root / "demo" / "demo.profile.json"),
                        "reproject-repositories",
                    ]
                )
            reproject_result = json.loads(output.getvalue())
            self.assertEqual(0, reproject_exit)
            self.assertEqual("dry_run", reproject_result["mode"])
            self.assertEqual(0, reproject_result["candidate_count"])
            self.assertEqual(database_before, demo_database.read_bytes())


class DeterministicDemoTests(unittest.TestCase):
    def test_demo_is_complete_auditable_and_idempotently_reused(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)

            settings, first = prepare_demo(workspace)
            _, second = prepare_demo(workspace)

            self.assertFalse(first["reused"])
            self.assertTrue(second["reused"])
            self.assertNotIn(
                '"payload"',
                json.dumps(second["publication"], ensure_ascii=False),
            )
            self.assertEqual(0, first["network_calls"])
            self.assertEqual(0, first["model_calls"])
            self.assertEqual(2, first["counts"]["unique_works"])
            self.assertEqual(2, first["counts"]["deep_read"])
            self.assertTrue(Path(first["publication"]["report_path"]).is_file())
            with RadarStore(settings.database_path) as store:
                with store._lock:
                    rows = store._connection.execute(
                        """
                        SELECT provider, model, provider_receipt_json
                        FROM analyses
                        ORDER BY work_id
                        """
                    ).fetchall()
            self.assertEqual(2, len(rows))
            for row in rows:
                self.assertEqual("deterministic_fixture", row["provider"])
                self.assertEqual(
                    "deterministic-fixture-no-model-call",
                    row["model"],
                )
                receipt = json.loads(row["provider_receipt_json"])
                self.assertFalse(receipt["provider_invoked"])
                self.assertEqual(0, receipt["network_calls"])
                self.assertEqual(0, receipt["model_calls"])

    def test_demo_frozen_evidence_resolves_against_exact_source_revision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings, _ = prepare_demo(Path(raw))

            with RadarStore(settings.database_path) as store:
                publication = store.latest_publication(
                    retrieval_hash=settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertIsNotNone(publication)
                issue_id = str(publication["issue_id"])
                with store._lock:
                    rows = store._connection.execute(
                        """
                        SELECT analysis_id
                        FROM report_issue_items
                        WHERE issue_id=? AND selected=1
                        ORDER BY analysis_id
                        """,
                        (issue_id,),
                    ).fetchall()
                self.assertEqual(2, len(rows))
                for row in rows:
                    source = store.frozen_item_text_source(
                        issue_id=issue_id,
                        analysis_id=int(row["analysis_id"]),
                        retrieval_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    )
                    text = Path(source["text_path"]).read_text(encoding="utf-8")
                    evidence = build_evidence_context(
                        source["item"]["snapshot"],
                        text,
                        source["input_sha256"],
                    )
                    self.assertEqual(
                        source["input_sha256"],
                        evidence["source"]["input_sha256"],
                    )
                    self.assertGreater(len(evidence["anchors"]), 0)
                    for anchor in evidence["anchors"]:
                        self.assertEqual(
                            anchor["exact_substring"],
                            text[
                                int(anchor["anchor_start"]) : int(anchor["anchor_end"])
                            ],
                        )

    def test_demo_never_overwrites_an_unrecognized_database(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            database = workspace / "data" / "radar.sqlite3"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"not an R3 demo database")

            with self.assertRaisesRegex(RuntimeError, "unrecognized database"):
                prepare_demo(workspace)
            self.assertEqual(
                b"not an R3 demo database",
                database.read_bytes(),
            )


class DashboardProductTests(unittest.TestCase):
    def test_dashboard_bind_failure_preserves_the_socket_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings, _ = prepare_demo(Path(raw))
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = int(listener.getsockname()[1])
            try:
                with self.assertRaises(OSError) as caught:
                    RadarHttpServer(("127.0.0.1", port), settings)
            finally:
                listener.close()

            self.assertNotIsInstance(caught.exception, AttributeError)

    def test_status_exposes_safe_profile_identity_for_dynamic_branding(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings, _ = prepare_demo(Path(raw))
            server = RadarHttpServer(("127.0.0.1", 0), settings)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = int(server.server_address[1])
            try:
                health_connection = http.client.HTTPConnection(
                    "127.0.0.1",
                    port,
                    timeout=5,
                )
                health_connection.request(
                    "GET",
                    "/api/health",
                    headers={"Host": f"127.0.0.1:{port}"},
                )
                health_response = health_connection.getresponse()
                health_payload = json.loads(health_response.read())
                health_connection.close()
                connection = http.client.HTTPConnection(
                    "127.0.0.1",
                    port,
                    timeout=5,
                )
                connection.request(
                    "GET",
                    "/api/status",
                    headers={"Host": f"127.0.0.1:{port}"},
                )
                response = connection.getresponse()
                payload = json.loads(response.read())
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

            self.assertEqual(200, response.status)
            self.assertEqual(200, health_response.status)
            self.assertEqual("r3-research-radar", health_payload["service"])
            self.assertEqual("r3-deterministic-demo", payload["profile"]["id"])
            self.assertTrue(payload["profile"]["demo_mode"])
            self.assertIn("research_question", payload["profile"])
            self.assertEqual(
                "deterministic_fixture",
                payload["analysis_execution"]["provider"],
            )
            self.assertEqual(
                "no-model-call",
                payload["analysis_execution"]["model"],
            )
            self.assertEqual("smoke", payload["query_coverage"]["scope"])
            self.assertTrue(payload["query_coverage"]["plan_complete"])
            self.assertFalse(
                payload["query_coverage"]["complete_profile_run"]
            )
            self.assertTrue(
                payload["discovery_policy"]["high_recall_unfiltered"]
            )
            self.assertEqual(
                "requires_human_gold_set",
                payload["discovery_policy"]["quality_claim"],
            )
            self.assertNotIn(str(Path(raw).resolve()), json.dumps(payload))

    def test_doctor_distinguishes_running_r3_from_an_occupied_port(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            settings, _ = prepare_demo(Path(raw))
            server = RadarHttpServer(("127.0.0.1", 0), settings)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = int(server.server_address[1])
            try:
                report = doctor_report(settings, dashboard_port=port)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            check = next(
                item for item in report["checks"] if item["id"] == "dashboard_port"
            )
            self.assertEqual("running", check["service_state"])
            self.assertEqual("ok", check["status"])

            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            occupied_port = int(listener.getsockname()[1])
            try:
                occupied = doctor_report(settings, dashboard_port=occupied_port)
            finally:
                listener.close()
            occupied_check = next(
                item
                for item in occupied["checks"]
                if item["id"] == "dashboard_port"
            )
            self.assertEqual("occupied_unknown", occupied_check["service_state"])
            self.assertEqual("warning", occupied_check["status"])

    def test_dashboard_defaults_to_generic_compact_decision_inbox(self) -> None:
        html = (PROJECT_DIR / "static" / "index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn('data-view-mode="compact"', html)
        self.assertIn('id="operations-panel"', html)
        self.assertIn('id="view-mode-toggle"', html)
        self.assertIn('class="decision-brief"', html)
        self.assertIn('id="demo-banner"', html)
        self.assertNotIn("Agent 缓存研究雷达", html)
        javascript = (PROJECT_DIR / "static" / "app.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("检索计划", javascript)
        self.assertIn("批注已写入本地证据库", javascript)

    def test_cli_output_remains_utf8_when_parent_requests_gbk(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw) / "中文 demo"
            environment = os.environ.copy()
            environment["PYTHONIOENCODING"] = "gbk"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "r3radar",
                    "demo",
                    "--prepare-only",
                    "--workspace",
                    str(workspace),
                ],
                cwd=PROJECT_DIR,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            stdout = completed.stdout.decode("utf-8")
            stderr = completed.stderr.decode("utf-8")
            self.assertEqual(0, completed.returncode, stderr)
            payload = json.loads(stdout)
            self.assertTrue(payload["ok"])
            self.assertIn("中文 demo", payload["workspace"])


if __name__ == "__main__":
    unittest.main()
