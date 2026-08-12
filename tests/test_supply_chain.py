from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "supply_chain.py"
SPEC = importlib.util.spec_from_file_location("r3_supply_chain", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
SUPPLY_CHAIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPLY_CHAIN)


def write_wheel(
    directory: Path,
    name: str,
    version: str,
    requires_dist: tuple[str, ...] = (),
) -> tuple[Path, str]:
    normalized = name.replace("-", "_")
    path = directory / f"{normalized}-{version}-py3-none-any.whl"
    metadata_lines = [
        "Metadata-Version: 2.1",
        f"Name: {name}",
        f"Version: {version}",
    ]
    metadata_lines.extend(f"Requires-Dist: {item}" for item in requires_dist)
    metadata = "\n".join(metadata_lines) + "\n"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{normalized}-{version}.dist-info/METADATA",
            metadata,
        )
        archive.writestr(
            f"{normalized}/_vendor/helper-9.9.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: helper\nVersion: 9.9\n",
        )
    return path, SUPPLY_CHAIN.sha256_file(path)


class SupplyChainTests(unittest.TestCase):
    def test_project_lock_and_direct_requirements_parse(self) -> None:
        lock = SUPPLY_CHAIN.parse_lock(PROJECT_ROOT / "requirements.lock")
        direct = SUPPLY_CHAIN.parse_direct_requirements(
            PROJECT_ROOT / "requirements.txt"
        )
        self.assertEqual(11, len(lock))
        self.assertEqual(
            {
                "httpx": "0.28.1",
                "pypdf": "6.14.2",
                "typing-extensions": "4.16.0",
            },
            direct,
        )
        self.assertTrue(set(direct).issubset(lock))
        self.assertEqual("26.1.2", lock["pip"]["version"])
        self.assertEqual("83.0.0", lock["setuptools"]["version"])
        self.assertTrue(all(item["hashes"] for item in lock.values()))

    def test_lock_rejects_unpinned_unhashed_url_and_non_sha256(self) -> None:
        invalid_cases = (
            "demo>=1\n--only-binary=:all:\n",
            "demo==1\n--only-binary=:all:\n",
            "demo @ https://example.invalid/demo.whl\n--only-binary=:all:\n",
            "demo @ git+https://example.invalid/demo.git\n--only-binary=:all:\n",
            "--editable demo==1\n--only-binary=:all:\n",
            "-e demo==1\n--only-binary=:all:\n",
            "demo==1 --hash=md5:00000000000000000000000000000000\n--only-binary=:all:\n",
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for index, content in enumerate(invalid_cases):
                path = root / f"invalid-{index}.lock"
                path.write_text(content, encoding="utf-8")
                with self.subTest(index=index):
                    with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                        SUPPLY_CHAIN.parse_lock(path)

    def test_lock_requires_binary_only_and_rejects_duplicate_package(self) -> None:
        sha = "0" * 64
        invalid_cases = (
            f"demo==1 --hash=sha256:{sha}\n",
            (
                "--only-binary=:all:\n"
                f"demo==1 --hash=sha256:{sha}\n"
                f"demo==1 --hash=sha256:{'1' * 64}\n"
            ),
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for index, content in enumerate(invalid_cases):
                path = root / f"invalid-{index}.lock"
                path.write_text(content, encoding="utf-8")
                with self.subTest(index=index):
                    with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                        SUPPLY_CHAIN.parse_lock(path)

    def test_verify_lock_checks_wheel_hash_version_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wheels = root / "wheels"
            wheels.mkdir()
            _, digest = write_wheel(wheels, "demo", "1.0")
            _, pip_digest = write_wheel(wheels, "pip", "26.1.2")
            _, setuptools_digest = write_wheel(wheels, "setuptools", "83.0.0")
            lock_path = root / "requirements.lock"
            lock_path.write_text(
                (
                    "--only-binary=:all:\n"
                    f"demo==1.0 --hash=sha256:{digest}\n"
                    f"pip==26.1.2 --hash=sha256:{pip_digest}\n"
                    f"setuptools==83.0.0 --hash=sha256:{setuptools_digest}\n"
                ),
                encoding="utf-8",
            )
            direct_path = root / "requirements.txt"
            direct_path.write_text("demo==1.0\n", encoding="utf-8")

            receipt = SUPPLY_CHAIN.verify_lock(lock_path, direct_path, wheels)

            self.assertEqual("PASS", receipt["status"])
            self.assertEqual(3, receipt["package_count"])
            demo = next(
                item for item in receipt["packages"]
                if item["normalized_name"] == "demo"
            )
            self.assertEqual(digest, demo["wheel"]["sha256"])

            extra, _ = write_wheel(wheels, "unexpected", "1.0")
            with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                SUPPLY_CHAIN.verify_lock(lock_path, direct_path, wheels)
            extra.unlink()

            junk = wheels / "not-a-wheel.txt"
            junk.write_text("not a wheel", encoding="utf-8")
            with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                SUPPLY_CHAIN.verify_lock(lock_path, direct_path, wheels)
            junk.unlink()

            demo_wheel = next(wheels.glob("demo-1.0-*.whl"))
            demo_wheel.unlink()
            with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                SUPPLY_CHAIN.verify_lock(lock_path, direct_path, wheels)
            demo_wheel, digest = write_wheel(wheels, "demo", "1.0")

            second_demo, _ = write_wheel(wheels, "demo", "1.1")
            with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                SUPPLY_CHAIN.verify_lock(lock_path, direct_path, wheels)
            second_demo.unlink()

            lock_path.write_text(
                (
                    "--only-binary=:all:\n"
                    f"demo==1.0 --hash=sha256:{'f' * 64}\n"
                    f"pip==26.1.2 --hash=sha256:{pip_digest}\n"
                    f"setuptools==83.0.0 --hash=sha256:{setuptools_digest}\n"
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                SUPPLY_CHAIN.verify_lock(lock_path, direct_path, wheels)

    def test_rebuild_and_sbom_reject_version_drift(self) -> None:
        lock_receipt = {
            "lock_sha256": "a" * 64,
            "packages": [
                {
                    "name": "demo",
                    "normalized_name": "demo",
                    "version": "1.0",
                    "hashes": ["b" * 64],
                    "direct": True,
                    "wheel": {
                        "filename": "demo-1.0-py3-none-any.whl",
                        "size": 10,
                        "sha256": "b" * 64,
                        "requires_dist": [],
                    },
                },
                {
                    "name": "pip",
                    "normalized_name": "pip",
                    "version": "26.1.2",
                    "hashes": ["c" * 64],
                    "direct": False,
                    "role": "bootstrap",
                    "wheel": {
                        "filename": "pip-26.1.2-py3-none-any.whl",
                        "size": 11,
                        "sha256": "c" * 64,
                        "requires_dist": [],
                    },
                },
                {
                    "name": "setuptools",
                    "normalized_name": "setuptools",
                    "version": "83.0.0",
                    "hashes": ["d" * 64],
                    "direct": False,
                    "role": "bootstrap",
                    "wheel": {
                        "filename": "setuptools-83.0.0-py3-none-any.whl",
                        "size": 12,
                        "sha256": "d" * 64,
                        "requires_dist": ["pip; extra == 'test'"],
                    },
                },
            ],
        }
        valid_inspect = {
            "installed": [
                {
                    "metadata": {
                        "name": "demo",
                        "version": "1.0",
                        "requires_dist": [],
                    }
                },
                {"metadata": {"name": "pip", "version": "26.1.2"}},
                {
                    "metadata": {
                        "name": "setuptools",
                        "version": "83.0.0",
                        "requires_dist": ["pip; extra == 'test'"],
                    }
                },
            ]
        }

        sbom = SUPPLY_CHAIN.build_sbom(lock_receipt, valid_inspect)

        self.assertEqual("CycloneDX", sbom["bomFormat"])
        self.assertEqual(3, len(sbom["components"]))
        self.assertEqual("pkg:pypi/demo@1.0", sbom["components"][0]["purl"])
        self.assertNotIn("dependencies", sbom)
        self.assertIn(
            "omitted",
            next(
                item["value"]
                for item in sbom["metadata"]["properties"]
                if item["name"] == "r3:dependency-graph"
            ),
        )

        drift = json.loads(json.dumps(valid_inspect))
        drift["installed"][0]["metadata"]["version"] = "2.0"
        with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
            SUPPLY_CHAIN.build_sbom(lock_receipt, drift)

    def test_rebuild_requires_bootstrap_and_rejects_bad_environment_entries(
        self,
    ) -> None:
        lock = {
            "demo": {"version": "1.0"},
            "pip": {"version": "26.1.2"},
            "setuptools": {"version": "83.0.0"},
        }
        valid = {
            "installed": [
                {"metadata": {"name": "demo", "version": "1.0"}},
                {"metadata": {"name": "pip", "version": "26.1.2"}},
                {"metadata": {"name": "setuptools", "version": "83.0.0"}},
            ]
        }
        self.assertEqual("PASS", SUPPLY_CHAIN.verify_rebuild(lock, valid)["status"])

        missing_bootstrap = {"demo": {"version": "1.0"}}
        with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
            SUPPLY_CHAIN.verify_rebuild(missing_bootstrap, valid)

        malformed = json.loads(json.dumps(valid))
        malformed["installed"][0]["metadata"].pop("version")
        with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
            SUPPLY_CHAIN.verify_rebuild(lock, malformed)

        duplicate = json.loads(json.dumps(valid))
        duplicate["installed"].append(
            {"metadata": {"name": "Demo", "version": "1.0"}}
        )
        with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
            SUPPLY_CHAIN.verify_rebuild(lock, duplicate)

        extra = json.loads(json.dumps(valid))
        extra["installed"].append(
            {"metadata": {"name": "unexpected", "version": "1.0"}}
        )
        with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
            SUPPLY_CHAIN.verify_rebuild(lock, extra)

    def test_osv_cardinality_failure_cannot_be_clean(self) -> None:
        original = SUPPLY_CHAIN.urllib.request.urlopen

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, size: int = -1) -> bytes:
                return b'{"results":[]}'

        SUPPLY_CHAIN.urllib.request.urlopen = lambda *args, **kwargs: Response()
        try:
            with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                SUPPLY_CHAIN.osv_query(
                    [
                        {
                            "normalized_name": "demo",
                            "version": "1.0",
                        }
                    ],
                    1.0,
                )
        finally:
            SUPPLY_CHAIN.urllib.request.urlopen = original

    def test_osv_any_finding_requires_review(self) -> None:
        original = SUPPLY_CHAIN.urllib.request.urlopen

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, size: int = -1) -> bytes:
                return b'{"results":[{"vulns":[{"id":"OSV-TEST","modified":"2026-01-01T00:00:00Z"}]}]}'

        SUPPLY_CHAIN.urllib.request.urlopen = lambda *args, **kwargs: Response()
        try:
            receipt = SUPPLY_CHAIN.osv_query(
                [{"normalized_name": "demo", "version": "1.0"}],
                1.0,
            )
        finally:
            SUPPLY_CHAIN.urllib.request.urlopen = original
        self.assertEqual("REVIEW_REQUIRED", receipt["status"])
        self.assertEqual(1, receipt["findings_count"])

    def test_osv_network_failure_cannot_be_clean(self) -> None:
        original = SUPPLY_CHAIN.urllib.request.urlopen

        def fail(*args, **kwargs):
            raise SUPPLY_CHAIN.urllib.error.URLError("offline")

        SUPPLY_CHAIN.urllib.request.urlopen = fail
        try:
            with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                SUPPLY_CHAIN.osv_query(
                    [{"normalized_name": "demo", "version": "1.0"}],
                    1.0,
                )
        finally:
            SUPPLY_CHAIN.urllib.request.urlopen = original

    def test_pypi_provenance_requires_exact_official_wheel(self) -> None:
        package = {
            "normalized_name": "demo",
            "version": "1.0",
            "wheel": {
                "filename": "demo-1.0-py3-none-any.whl",
                "sha256": "a" * 64,
                "size": 123,
            },
        }
        payload = {
            "info": {"name": "demo", "version": "1.0"},
            "urls": [
                {
                    "filename": "demo-1.0-py3-none-any.whl",
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/packages/demo.whl",
                    "digests": {"sha256": "a" * 64},
                    "size": 123,
                    "yanked": False,
                    "requires_python": ">=3.10",
                }
            ],
        }
        artifact = SUPPLY_CHAIN.verify_pypi_payload(package, payload, "b" * 64)
        self.assertEqual("a" * 64, artifact["sha256"])
        self.assertFalse(artifact["yanked"])

        mutations = (
            lambda item: item["urls"][0].update(
                {"url": "https://example.invalid/demo.whl"}
            ),
            lambda item: item["urls"][0]["digests"].update(
                {"sha256": "c" * 64}
            ),
            lambda item: item["urls"][0].update({"size": 999}),
            lambda item: item["urls"][0].update({"yanked": True}),
            lambda item: item["urls"][0].update({"packagetype": "sdist"}),
            lambda item: item["info"].update({"version": "2.0"}),
            lambda item: item["urls"].append(dict(item["urls"][0])),
        )
        for index, mutate in enumerate(mutations):
            invalid = json.loads(json.dumps(payload))
            mutate(invalid)
            with self.subTest(index=index):
                with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                    SUPPLY_CHAIN.verify_pypi_payload(
                        package,
                        invalid,
                        "b" * 64,
                    )

    def test_project_npm_lock_is_exact_and_integrity_bound(self) -> None:
        receipt = SUPPLY_CHAIN.verify_npm_lock(
            PROJECT_ROOT / "package.json",
            PROJECT_ROOT / "package-lock.json",
        )
        self.assertEqual("PASS", receipt["status"])
        self.assertEqual(3, receipt["lockfile_version"])
        self.assertEqual(7, receipt["package_entry_count"])
        self.assertTrue(receipt["all_entries_sha512_integrity"])
        self.assertTrue(receipt["all_resolved_official_registry_https"])

    def test_setup_uses_hashed_binary_lock_and_ignores_npm_scripts(self) -> None:
        setup = (PROJECT_ROOT / "scripts" / "SETUP.ps1").read_text(encoding="utf-8")
        self.assertIn('"requirements.lock"', setup)
        self.assertIn("--require-hashes", setup)
        self.assertIn("--only-binary=:all:", setup)
        self.assertIn("npm ci --ignore-scripts", setup)
        self.assertIn('$PythonMajorMinor -ne "3.10"', setup)
        self.assertIn('$PythonImplementation -ne "CPython"', setup)
        self.assertIn('$PythonPlatform -ne "win32"', setup)
        self.assertIn("verify-current-environment", setup)
        self.assertIn("-m pip check", setup)
        self.assertNotIn(
            '-r (Join-Path $ProjectRoot "requirements.txt")',
            setup,
        )

    def test_npm_lock_rejects_range_source_and_bad_integrity(self) -> None:
        base_package = {
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"dep": "1.0.0"},
        }
        base_lock = {
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "demo",
                    "version": "1.0.0",
                    "dependencies": {"dep": "1.0.0"},
                },
                "node_modules/dep": {
                    "version": "1.0.0",
                    "resolved": "https://registry.npmjs.org/dep/-/dep-1.0.0.tgz",
                    "integrity": "sha512-" + "A" * 88,
                },
            },
        }
        mutations = (
            lambda package, lock: package["dependencies"].update({"dep": "^1.0.0"}),
            lambda package, lock: lock["packages"]["node_modules/dep"].update(
                {"resolved": "https://example.invalid/dep.tgz"}
            ),
            lambda package, lock: lock["packages"]["node_modules/dep"].update(
                {"integrity": "sha512-not-base64"}
            ),
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for index, mutate in enumerate(mutations):
                package = json.loads(json.dumps(base_package))
                lock = json.loads(json.dumps(base_lock))
                mutate(package, lock)
                package_path = root / f"package-{index}.json"
                lock_path = root / f"lock-{index}.json"
                package_path.write_text(json.dumps(package), encoding="utf-8")
                lock_path.write_text(json.dumps(lock), encoding="utf-8")
                with self.subTest(index=index):
                    with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
                        SUPPLY_CHAIN.verify_npm_lock(package_path, lock_path)

    def test_metadata_response_size_is_bounded(self) -> None:
        class Response:
            def read(self, size: int) -> bytes:
                return b"x" * size

        with self.assertRaises(SUPPLY_CHAIN.SupplyChainError):
            SUPPLY_CHAIN.read_limited_response(Response(), 16)


if __name__ == "__main__":
    unittest.main()
