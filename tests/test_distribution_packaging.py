from __future__ import annotations

import importlib.util
import json
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from r3radar.config import _select_project_dir


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = PROJECT_ROOT / "scripts" / "build_distribution.py"
SPEC = importlib.util.spec_from_file_location("r3_build_distribution", BUILD_SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BUILD_DISTRIBUTION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILD_DISTRIBUTION
SPEC.loader.exec_module(BUILD_DISTRIBUTION)


def write_asset_root(root: Path) -> None:
    for relative in (
        "config/profile.example.json",
        "schemas/synthesis.schema.json",
        "static/index.html",
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("{}\n", encoding="utf-8")


class DistributionPackagingTests(unittest.TestCase):
    def test_asset_root_falls_back_to_installed_share_layout(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source_like = root / "venv" / "Lib" / "site-packages"
            installed_share = root / "venv" / "share" / "r3-research-radar"
            source_like.mkdir(parents=True)
            write_asset_root(installed_share)

            selected = _select_project_dir((source_like, installed_share))

            self.assertEqual(installed_share.resolve(), selected)

    def test_sdist_validator_rejects_a_private_research_profile(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive_path = Path(raw) / "r3_research_radar-0.2.0a1.tar.gz"
            root_name = "r3_research_radar-0.2.0a1"
            files = {
                "README.md": "safe\n",
                "pyproject.toml": "[project]\n",
                "r3radar/__main__.py": "safe\n",
                **{name: "{}\n" for name in BUILD_DISTRIBUTION.REQUIRED_ASSETS},
                "config/r3.v1.json": json.dumps({"private": True}),
            }
            staging = Path(raw) / root_name
            for relative, content in files.items():
                path = staging / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(staging, arcname=root_name)

            with self.assertRaisesRegex(
                BUILD_DISTRIBUTION.DistributionError,
                "config/r3.v1.json",
            ):
                BUILD_DISTRIBUTION._validate_sdist(archive_path)

    def test_wheel_validator_rejects_missing_runtime_assets(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            wheel_path = Path(raw) / "r3_research_radar-0.2.0a1-py3-none-any.whl"
            data_root = (
                "r3_research_radar-0.2.0a1.data/data/share/"
                "r3-research-radar/"
            )
            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(data_root + "static/index.html", "safe\n")

            with self.assertRaisesRegex(
                BUILD_DISTRIBUTION.DistributionError,
                "missing=",
            ):
                BUILD_DISTRIBUTION._validate_wheel(wheel_path)


if __name__ == "__main__":
    unittest.main()
