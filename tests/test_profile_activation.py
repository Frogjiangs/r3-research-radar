from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from r3radar.__main__ import main
from r3radar.config import (
    ProfileActivationError,
    _validate_auto_publish_providers,
    require_profile_production_activation,
)
from r3radar.model_integration import run_model_integration


def _settings(raw: dict, config_path: Path) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, config_path=config_path)


def _proposed_profile() -> dict:
    return {
        "profile_id": "r3-cache-value",
        "profile_version": 2,
        "intake": {
            "weekly": {
                "state": "proposed",
                "capacity_basis": {"source_run_id": "calibration-run"},
            }
        },
    }


_CANDIDATE_HASHES = {
    "config_hash": "b" * 64,
    "retrieval_hash": "c" * 64,
    "analysis_policy_hash": "d" * 64,
}


def _write_passing_receipt(
    directory: Path,
    *,
    candidate_run_id: str = "candidate-run",
    gold_source_run_id: str = "calibration-run",
) -> Path:
    path = directory / "gold-evaluation.json"
    path.write_text(
        json.dumps(
            {
                "schema": "r3/gold-set-evaluation/v1",
                "status": "evaluated",
                "item_count": 50,
                "unlabeled_count": 0,
                "known_important_count": 10,
                "known_important_found": 9,
                "recall_at_candidate": 0.9,
                "threshold": 0.9,
                "passed": True,
                "gold_set_sha256": "a" * 64,
                "gold_source_run_id": gold_source_run_id,
                "candidate_run_id": candidate_run_id,
                "candidate_settings_hashes": _CANDIDATE_HASHES,
                "candidate_run_identity": {
                    "profile_id": "r3-cache-value",
                    "profile_version": 2,
                    **_CANDIDATE_HASHES,
                },
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def _active_profile(directory: Path) -> dict:
    receipt_path = _write_passing_receipt(directory)
    raw = _proposed_profile()
    raw["intake"]["weekly"]["state"] = "active"
    raw["profile_activation"] = {
        "state": "active",
        "user_confirmation": {
            "confirmed": True,
            "confirmed_by": "user",
            "confirmed_at": "2026-07-30T12:00:00+08:00",
            "profile_id": raw["profile_id"],
            "profile_version": raw["profile_version"],
        },
        "gold_evaluation_receipt": {
            "path": str(receipt_path),
            "sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            "capacity_source_run_id": "calibration-run",
            "gold_source_run_id": "calibration-run",
            "candidate_run_id": "candidate-run",
            "candidate_settings_hashes": _CANDIDATE_HASHES,
        },
    }
    return raw


class ProfileActivationTests(unittest.TestCase):
    def test_legacy_profile_v1_remains_production_compatible(self) -> None:
        settings = _settings(
            {"profile_id": "r3-cache-value", "profile_version": 1},
            Path("legacy-v1.json"),
        )
        for operation in (
            "smoke",
            "run",
            "weekly",
            "report",
            "model-integration-test",
        ):
            require_profile_production_activation(settings, operation)

    def test_proposed_profile_v2_is_limited_to_calibration_and_read_only_paths(
        self,
    ) -> None:
        settings = _settings(_proposed_profile(), Path("profile-v2.proposed.json"))
        for operation in (
            "smoke",
            "run",
            "weekly",
            "report",
            "model-integration-test",
        ):
            with self.assertRaisesRegex(
                ProfileActivationError,
                "requires explicit activation",
            ):
                require_profile_production_activation(settings, operation)
        for operation in ("calibrate-intake", "evaluate-gold", "status", "dashboard"):
            require_profile_production_activation(settings, operation)

    def test_cli_fails_closed_before_all_named_production_entry_points(self) -> None:
        settings = _settings(_proposed_profile(), Path("profile-v2.proposed.json"))
        commands = (
            ["smoke", "--no-hosted-search", "--skip-analysis"],
            ["run", "--no-hosted-search"],
            ["weekly", "--no-hosted-search"],
            ["report", "--run-id", "terminal-run"],
            ["model-integration-test", "--provider", "codex_cli"],
        )
        with (
            patch("r3radar.__main__.load_settings", return_value=settings),
            patch("r3radar.__main__.RadarPipeline") as pipeline,
            patch("r3radar.__main__.generate_weekly_report") as report,
        ):
            for command in commands:
                output = io.StringIO()
                with redirect_stdout(output):
                    exit_code = main(command)
                self.assertEqual(exit_code, 2)
                payload = json.loads(output.getvalue())
                self.assertEqual(payload["status"], "profile_confirmation_required")
                self.assertEqual(payload["operation"], command[0])
            pipeline.assert_not_called()
            report.assert_not_called()

    def test_active_profile_requires_explicit_user_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = _active_profile(root)
            del raw["profile_activation"]["user_confirmation"]
            with self.assertRaisesRegex(
                ProfileActivationError,
                "explicit user confirmation",
            ):
                require_profile_production_activation(
                    _settings(raw, root / "profile-v2.json"),
                    "weekly",
                )

    def test_active_profile_rejects_a_changed_gold_evaluation_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = _active_profile(root)
            receipt_path = Path(
                raw["profile_activation"]["gold_evaluation_receipt"]["path"]
            )
            receipt_path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ProfileActivationError, "SHA-256 mismatch"):
                require_profile_production_activation(
                    _settings(raw, root / "profile-v2.json"),
                    "report",
                )

    def test_active_profile_rejects_candidate_that_is_its_gold_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = _active_profile(root)
            reference = raw["profile_activation"]["gold_evaluation_receipt"]
            reference["candidate_run_id"] = reference["gold_source_run_id"]
            with self.assertRaisesRegex(
                ProfileActivationError,
                "independent candidate run",
            ):
                require_profile_production_activation(
                    _settings(raw, root / "profile-v2.json"),
                    "run",
                )

    def test_active_profile_with_bound_passing_receipt_allows_production(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = _settings(_active_profile(root), root / "profile-v2.json")
            for operation in (
                "smoke",
                "run",
                "weekly",
                "report",
                "model-integration-test",
            ):
                require_profile_production_activation(settings, operation)

    def test_programmatic_model_integration_is_blocked_before_writes(self) -> None:
        settings = _settings(_proposed_profile(), Path("profile-v2.proposed.json"))
        with self.assertRaises(ProfileActivationError):
            run_model_integration(settings, provider="codex_cli")

    def test_llama_calibration_recomputes_declared_evidence_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "llama-calibration.json"
            evidence.write_text('{"passed":true}', encoding="utf-8")
            raw = {
                "analysis": {
                    "auto_publish_providers": ["llama_cpp"],
                    "llama_publication_calibration": {
                        "accepted": True,
                        "evidence_path": str(evidence),
                        "evidence_sha256": hashlib.sha256(evidence.read_bytes()).hexdigest(),
                    },
                }
            }
            _validate_auto_publish_providers(raw, config_path=root / "profile.json")
            evidence.write_text('{"passed":false}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                _validate_auto_publish_providers(raw, config_path=root / "profile.json")


if __name__ == "__main__":
    unittest.main()
