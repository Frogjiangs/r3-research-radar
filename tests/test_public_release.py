from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "package_public.py"
SPEC = importlib.util.spec_from_file_location("r3_package_public", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
PACKAGE_PUBLIC = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PACKAGE_PUBLIC
SPEC.loader.exec_module(PACKAGE_PUBLIC)


def write_file(root: Path, relative: str, content: str = "safe\n") -> None:
    path = root / Path(relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def valid_dashboard_jpeg() -> bytes:
    app0 = (
        b"\xff\xe0\x00\x10"
        b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    )
    sof0 = (
        b"\xff\xc0\x00\x0b"
        b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    )
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    return b"\xff\xd8" + app0 + sof0 + sos + b"\xff\xd9"


def minimal_project(root: Path, *, with_license: bool) -> None:
    exact_files = set(PACKAGE_PUBLIC.REQUIRED_EXACT_FILES)
    exact_files.remove("pyproject.toml")
    for relative in exact_files:
        write_file(root, relative)
    write_file(
        root,
        "pyproject.toml",
        (
            "[build-system]\n"
            "requires = [\"setuptools\"]\n"
            "build-backend = \"setuptools.build_meta\"\n"
        ),
    )
    write_file(
        root,
        "config/profile.example.json",
        json.dumps({"schema_version": "1.1"}) + "\n",
    )
    write_file(
        root,
        "config/demo.v1.json",
        json.dumps({"schema_version": "1.1", "demo_mode": True}) + "\n",
    )
    write_file(root, "r3radar/__init__.py")
    write_file(root, "r3radar/__main__.py")
    write_file(root, "schemas/example.schema.json", "{}\n")
    write_file(root, "static/index.html", "<main>safe</main>\n")
    write_file(root, "static/styles.css", "main { display: block; }\n")
    write_file(root, "static/app.js", "\"use strict\";\n")
    write_file(root, "tests/test_example.py", "def test_example(): pass\n")
    if with_license:
        write_file(root, "LICENSE", "Test license text.\n")


class PublicReleaseTests(unittest.TestCase):
    def test_check_allows_only_license_pending(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            minimal_project(root, with_license=False)

            audit = PACKAGE_PUBLIC.audit_public_source(root)

            self.assertEqual("PASS_WITH_LICENSE_PENDING", audit["status"])
            self.assertFalse(audit["production_ready"])
            self.assertEqual("pending", audit["license"]["status"])
            self.assertEqual("PASS", audit["scan"]["status"])
            self.assertEqual([], audit["scan"]["findings"])

    def test_production_build_requires_license(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "project"
            output = Path(raw) / "dist"
            minimal_project(root, with_license=False)

            with self.assertRaisesRegex(
                PACKAGE_PUBLIC.PublicReleaseError,
                "LICENSE is pending",
            ):
                PACKAGE_PUBLIC.build_public_bundle(output, root)
            self.assertFalse(output.exists())

    def test_check_rejects_personal_profile_packaging_reference(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            minimal_project(root, with_license=False)
            pyproject = root / "pyproject.toml"
            pyproject.write_text(
                pyproject.read_text(encoding="utf-8")
                + '"config/r3.workflow-cache-value.full-v1.json"\n',
                encoding="utf-8",
            )

            audit = PACKAGE_PUBLIC.audit_public_source(root)

            self.assertEqual("FAIL", audit["status"])
            self.assertIn(
                "forbidden_public_packaging_reference",
                {
                    finding["rule"]
                    for finding in audit["scan"]["findings"]
                },
            )

    def test_bundle_maps_profile_and_excludes_private_material(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "project"
            output = Path(raw) / "dist"
            minimal_project(root, with_license=True)
            profile = '{"schema_version":"1.1","name":"public-example"}\n'
            write_file(root, "config/profile.example.json", profile)
            write_file(root, "config/r3.v1.json", "private config\n")
            write_file(
                root,
                "config/r3.workflow-cache-value.full-v1.json",
                "private focus config\n",
            )
            write_file(root, "requirements/QUEUE_V3.json", "{}\n")
            write_file(root, "data/radar.sqlite3", "runtime database\n")
            write_file(root, "literature/private.txt", "private\n")
            write_file(root, "outputs/report.md", "private\n")
            write_file(root, ".venv/private.txt", "private\n")
            write_file(root, "node_modules/private.txt", "private\n")

            result = PACKAGE_PUBLIC.build_public_bundle(output, root)

            archive_path = output / result["archive_path"]
            with zipfile.ZipFile(archive_path) as archive:
                names = set(archive.namelist())
                self.assertEqual(
                    (root / "config" / "profile.example.json").read_bytes(),
                    archive.read("config/r3.v1.json"),
                )
                self.assertEqual(
                    (root / "config" / "profile.example.json").read_bytes(),
                    archive.read("config/profile.example.json"),
                )
                self.assertEqual(
                    (root / "config" / "demo.v1.json").read_bytes(),
                    archive.read("config/demo.v1.json"),
                )
                self.assertFalse(
                    any(name.startswith("requirements/") for name in names)
                )
                for forbidden in (
                    "config/r3.workflow-cache-value.full-v1.json",
                    "data/radar.sqlite3",
                    "literature/private.txt",
                    "outputs/report.md",
                    ".venv/private.txt",
                    "node_modules/private.txt",
                ):
                    self.assertNotIn(forbidden, names)
                manifest = json.loads(archive.read("manifest.json"))
                self.assertEqual("PASS", manifest["assurance"]["scan_status"])
                self.assertEqual(
                    0,
                    manifest["assurance"]["scan_finding_count"],
                )
                self.assertFalse(manifest["assurance"]["secrets_included"])
                self.assertFalse(
                    manifest["assurance"]["runtime_artifacts_included"]
                )

    def test_bundle_is_byte_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "project"
            minimal_project(root, with_license=True)

            first = PACKAGE_PUBLIC.build_public_bundle(
                Path(raw) / "dist-one",
                root,
            )
            second = PACKAGE_PUBLIC.build_public_bundle(
                Path(raw) / "dist-two",
                root,
            )

            self.assertEqual(first["bundle_id"], second["bundle_id"])
            self.assertEqual(first["archive_sha256"], second["archive_sha256"])
            self.assertEqual(
                (Path(raw) / "dist-one" / first["archive_path"]).read_bytes(),
                (Path(raw) / "dist-two" / second["archive_path"]).read_bytes(),
            )

    def test_existing_content_addressed_archive_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "project"
            output = Path(raw) / "dist"
            minimal_project(root, with_license=True)
            first = PACKAGE_PUBLIC.build_public_bundle(output, root)
            (output / first["archive_path"]).write_bytes(b"tampered")

            with self.assertRaisesRegex(
                PACKAGE_PUBLIC.PublicReleaseError,
                "does not match",
            ):
                PACKAGE_PUBLIC.build_public_bundle(output, root)

    def test_scan_detects_local_paths_credentials_and_sqlite(self) -> None:
        username = "local-user-12345"
        drive_path = "D:" + "\\Models\\private.bin"
        codex_path = "." + "codex" + "\\sessions"
        credential = "s" + "k-" + ("A" * 24)
        entries = [
            PACKAGE_PUBLIC.PublicEntry(
                Path("README.md"),
                "README.md",
                (
                    f"path={drive_path}\n"
                    f"private={codex_path}\n"
                    f"owner={username}\n"
                    f"credential={credential}\n"
                ).encode("utf-8"),
            ),
            PACKAGE_PUBLIC.PublicEntry(
                Path("radar.sqlite3"),
                "data/radar.sqlite3",
                PACKAGE_PUBLIC.SQLITE_HEADER + b"payload",
            ),
        ]

        with mock.patch.object(
            PACKAGE_PUBLIC,
            "_candidate_usernames",
            return_value=(username,),
        ):
            findings = PACKAGE_PUBLIC.scan_entries(entries)
        rules = {finding["rule"] for finding in findings}

        self.assertTrue(
            {
                "drive_absolute_path",
                "codex_private_path",
                "local_username",
                "credential_prefix",
                "runtime_or_private_path",
                "database_artifact_path",
                "sqlite_content",
            }.issubset(rules)
        )

    def test_scan_accepts_documented_placeholders(self) -> None:
        entry = PACKAGE_PUBLIC.PublicEntry(
            Path("README.md"),
            "README.md",
            (
                'OPENALEX_API_KEY = "<your-key>"\n'
                'github_token = "${GITHUB_TOKEN}"\n'
            ).encode("utf-8"),
        )

        self.assertEqual([], PACKAGE_PUBLIC.scan_entries([entry]))

    def test_scan_accepts_only_constrained_dashboard_jpeg(self) -> None:
        valid = [
            PACKAGE_PUBLIC.PublicEntry(
                Path(archive_path).name,
                archive_path,
                valid_dashboard_jpeg(),
            )
            for archive_path in PACKAGE_PUBLIC.PUBLIC_SCREENSHOTS
        ]
        metadata = PACKAGE_PUBLIC.PublicEntry(
            Path("dashboard.jpg"),
            "docs/assets/dashboard.jpg",
            valid_dashboard_jpeg().replace(
                b"\xff\xc0",
                b"\xff\xe1\x00\x08Exif\x00\x00\xff\xc0",
                1,
            ),
        )
        invalid = PACKAGE_PUBLIC.PublicEntry(
            Path("dashboard.jpg"),
            "docs/assets/dashboard.jpg",
            b"not a jpeg",
        )

        self.assertEqual([], PACKAGE_PUBLIC.scan_entries(valid))
        self.assertIn(
            "dashboard_jpeg_metadata",
            {
                finding["rule"]
                for finding in PACKAGE_PUBLIC.scan_entries([metadata])
            },
        )
        self.assertIn(
            "invalid_dashboard_jpeg",
            {
                finding["rule"]
                for finding in PACKAGE_PUBLIC.scan_entries([invalid])
            },
        )


if __name__ == "__main__":
    unittest.main()
