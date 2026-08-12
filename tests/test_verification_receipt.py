from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "generate_verification_receipt.py"
SPEC = importlib.util.spec_from_file_location("r3_verification_receipt", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
RECEIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPT)


def make_source_root(root: Path) -> Path:
    source = root / "中文科研项目"
    (source / "r3radar").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "scripts").mkdir()
    (source / "r3radar" / "storage.py").write_text(
        "SCHEMA_VERSION = 22\n", encoding="utf-8"
    )
    (source / "r3radar" / "pipeline.py").write_text(
        "def rank_work(score):\n    return score >= 0.75\n",
        encoding="utf-8",
    )
    (source / "pyproject.toml").write_text(
        '[project]\nname="research-case"\n', encoding="utf-8"
    )
    return source


def write_unittest_case(source: Path, *, failing: bool) -> Path:
    path = source / "tests" / "test_agent_workflow.py"
    failure_line = (
        "    def test_retention_boundary(self):\n"
        "        self.assertLess(0.9, 0.2)\n"
        if failing
        else
        "    def test_retention_boundary(self):\n"
        "        self.assertGreater(0.9, 0.2)\n"
    )
    skip_case = (
        "    @unittest.skip('future-window label unavailable')\n"
        "    def test_future_window(self):\n"
        "        self.fail('not executed')\n"
    )
    path.write_text(
        "import unittest\n\n"
        "class WorkflowCacheStudy(unittest.TestCase):\n"
        "    def test_semantic_signal(self):\n"
        "        observations = ['plan', 'tool', 'reflection', 'reuse']\n"
        "        self.assertEqual(4, len(observations))\n"
        + failure_line
        + skip_case,
        encoding="utf-8",
    )
    return path


class VerificationReceiptTests(unittest.TestCase):
    def test_successful_real_unittest_and_chinese_path_are_captured(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = make_source_root(root)
            write_unittest_case(source, failing=False)
            command = [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(source / "tests"),
                "-p",
                "test_*.py",
            ]

            receipt = RECEIPT.build_receipt(
                command=command,
                source_root=source,
                working_directory=source,
                config_path=None,
                database_path=None,
                timeout_seconds=30,
                excerpt_limit=4000,
            )

            self.assertEqual("passed", receipt["status"])
            self.assertEqual(0, receipt["command"]["exit_code"])
            self.assertEqual(
                {
                    "passed": 2,
                    "failed": 0,
                    "errors": 0,
                    "skipped": 1,
                    "total": 3,
                },
                {
                    key: receipt["command"]["tests"][key]
                    for key in ("passed", "failed", "errors", "skipped", "total")
                },
            )
            self.assertEqual("parsed", receipt["command"]["tests"]["parsing_status"])
            self.assertRegex(receipt["source"]["manifest_sha256"], r"^[0-9a-f]{64}$")
            self.assertGreaterEqual(receipt["source"]["file_count"], 4)
            self.assertTrue(
                all(not Path(item["path"]).is_absolute() for item in receipt["source"]["files"])
            )

    def test_failing_unittest_writes_actual_failure_counts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = make_source_root(Path(raw))
            write_unittest_case(source, failing=True)
            receipt = RECEIPT.build_receipt(
                command=[
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    str(source / "tests"),
                ],
                source_root=source,
                working_directory=source,
                config_path=None,
                database_path=None,
                timeout_seconds=30,
                excerpt_limit=4000,
            )

            self.assertEqual("failed", receipt["status"])
            self.assertNotEqual(0, receipt["command"]["exit_code"])
            counts = receipt["command"]["tests"]
            self.assertEqual("parsed", counts["parsing_status"])
            self.assertEqual(1, counts["passed"])
            self.assertEqual(1, counts["failed"])
            self.assertEqual(1, counts["skipped"])
            self.assertEqual(3, counts["total"])

    def test_non_test_command_keeps_counts_null_and_redacts_secret_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = make_source_root(Path(raw))
            helper = source / "scripts" / "研究输出.py"
            helper.write_text(
                "import sys\nprint('token=' + sys.argv[-1])\nprint(__file__)\n",
                encoding="utf-8",
            )
            receipt = RECEIPT.build_receipt(
                command=[sys.executable, str(helper), "--token", "very-private-token"],
                source_root=source,
                working_directory=source,
                config_path=None,
                database_path=None,
                timeout_seconds=30,
                excerpt_limit=4000,
            )
            serialized = json.dumps(receipt, ensure_ascii=False)

            self.assertEqual("passed", receipt["status"])
            self.assertEqual("not_test_command", receipt["command"]["tests"]["parsing_status"])
            self.assertIsNone(receipt["command"]["tests"]["passed"])
            self.assertNotIn("very-private-token", serialized)
            self.assertNotIn(str(source), serialized)
            self.assertIn("<REDACTED>", serialized)
            self.assertIn("<SOURCE_ROOT>", serialized)

    def test_unrecognized_test_output_is_unknown_instead_of_inferred_from_exit(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = make_source_root(Path(raw))
            custom_test = source / "tests" / "test_custom_runner.py"
            custom_test.write_text(
                "print('custom research validation completed')\n",
                encoding="utf-8",
            )

            receipt = RECEIPT.build_receipt(
                command=[sys.executable, str(custom_test)],
                source_root=source,
                working_directory=source,
                config_path=None,
                database_path=None,
                timeout_seconds=30,
                excerpt_limit=4000,
            )

            self.assertEqual("passed", receipt["status"])
            self.assertEqual(0, receipt["command"]["exit_code"])
            counts = receipt["command"]["tests"]
            self.assertEqual("unknown", counts["parsing_status"])
            self.assertIsNone(counts["passed"])
            self.assertIsNone(counts["total"])

    def test_database_evidence_handles_healthy_corrupt_and_missing_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = make_source_root(Path(raw))
            healthy_path = source / "healthy.sqlite3"
            connection = sqlite3.connect(healthy_path)
            connection.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO schema_meta VALUES ('schema_version', '22')")
            connection.commit()
            connection.close()
            corrupt_path = source / "corrupt.sqlite3"
            corrupt_path.write_bytes(b"this is not sqlite")
            missing_path = source / "missing.sqlite3"

            healthy = RECEIPT.database_evidence(healthy_path, source)
            corrupt = RECEIPT.database_evidence(corrupt_path, source)
            missing = RECEIPT.database_evidence(missing_path, source)

            self.assertEqual("healthy", healthy["status"])
            self.assertEqual(22, healthy["schema_version"])
            self.assertEqual("ok", healthy["integrity_check"])
            self.assertEqual("invalid", corrupt["status"])
            self.assertEqual("unknown", corrupt["integrity_check"])
            self.assertEqual("unavailable", missing["status"])
            self.assertFalse(missing_path.exists())

            old_path = source / "old.sqlite3"
            connection = sqlite3.connect(old_path)
            connection.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO schema_meta VALUES ('schema_version', '21')")
            connection.commit()
            connection.close()
            old = RECEIPT.database_evidence(old_path, source)
            self.assertEqual("schema_mismatch", old["status"])
            self.assertFalse(old["schema_matches_expected"])

    def test_invalid_or_missing_config_is_explicit_and_never_hashed_as_policy(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = make_source_root(Path(raw))
            invalid_path = source / "bad-config.json"
            invalid_path.write_text('{"schema_version": "1.1"}', encoding="utf-8")
            missing_path = source / "missing-config.json"

            invalid = RECEIPT.config_evidence(invalid_path, source)
            missing = RECEIPT.config_evidence(missing_path, source)

            self.assertEqual("invalid", invalid["status"])
            self.assertRegex(invalid["file_sha256"], r"^[0-9a-f]{64}$")
            self.assertIsNone(invalid["analysis_policy_hash"])
            self.assertEqual("unavailable", missing["status"])
            self.assertIsNone(missing["config_hash"])

    def test_atomic_write_replaces_old_receipt_and_leaves_no_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "验证回执.json"
            output.write_text('{"old": true}', encoding="utf-8")
            payload = {"schema": RECEIPT.RECEIPT_SCHEMA, "status": "passed"}

            RECEIPT.atomic_write_json(output, payload)

            self.assertEqual(payload, json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual([], list(root.glob(f".{output.name}.*.tmp")))

    def test_public_project_config_produces_authoritative_policy_hashes(self) -> None:
        evidence = RECEIPT.config_evidence(
            PROJECT_ROOT / "config" / "profile.example.json",
            PROJECT_ROOT,
        )

        self.assertEqual("valid", evidence["status"], evidence.get("error"))
        self.assertEqual("1.1", evidence["schema_version"])
        for key in ("file_sha256", "config_hash", "retrieval_hash", "analysis_policy_hash"):
            self.assertRegex(str(evidence[key]), r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
