from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from email.parser import Parser
from pathlib import Path, PurePosixPath

from setuptools.build_meta import build_sdist, build_wheel


PROJECT_DIR = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "r3-research-radar"
REQUIRED_ASSETS = (
    "config/demo.v1.json",
    "config/profile.example.json",
    "schemas/capability_probe.schema.json",
    "schemas/chunk_analysis.schema.json",
    "schemas/external_known_answer_set_v1.schema.json",
    "schemas/gold_set_review_v2.schema.json",
    "schemas/hosted_search.schema.json",
    "schemas/known_answer_evaluation_receipt_v1.schema.json",
    "schemas/synthesis.schema.json",
    "schemas/synthesis_reduce.schema.json",
    "static/app.js",
    "static/gold-review.css",
    "static/gold-review.html",
    "static/gold-review.js",
    "static/index.html",
    "static/styles.css",
)
FORBIDDEN_DISTRIBUTION_PATHS = (
    "config/r3.v1.json",
    "config/r3.workflow-cache-value.focus-v1.json",
    "config/r3.workflow-cache-value.full-v1.json",
)


class DistributionError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reset_generated_directory(path: Path, *, allowed_parent: Path) -> None:
    target = path.resolve()
    parent = allowed_parent.resolve()
    if target.parent != parent:
        raise DistributionError(f"refusing to reset unexpected path: {target}")
    if target.exists():
        shutil.rmtree(target)


def _normalized_members(names: list[str]) -> set[str]:
    return {PurePosixPath(name).as_posix().lstrip("./") for name in names}


def _sdist_payload_names(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        names = _normalized_members(archive.getnames())
    roots = {name.split("/", 1)[0] for name in names if "/" in name}
    if len(roots) != 1:
        raise DistributionError("sdist must contain exactly one top-level directory")
    root = next(iter(roots))
    return {
        name.removeprefix(root + "/")
        for name in names
        if name.startswith(root + "/")
    }


def _wheel_payload_names(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        return _normalized_members(archive.namelist())


def _validate_sdist(path: Path) -> dict[str, object]:
    names = _sdist_payload_names(path)
    required = {"README.md", "pyproject.toml", "r3radar/__main__.py", *REQUIRED_ASSETS}
    missing = sorted(required - names)
    forbidden = sorted(name for name in FORBIDDEN_DISTRIBUTION_PATHS if name in names)
    if missing or forbidden:
        raise DistributionError(
            f"invalid sdist payload; missing={missing}; forbidden={forbidden}"
        )
    return {"member_count": len(names), "forbidden_paths_present": []}


def _validate_wheel(path: Path) -> dict[str, object]:
    names = _wheel_payload_names(path)
    data_prefixes = [
        name.split("share/r3-research-radar/", 1)[0] + "share/r3-research-radar/"
        for name in names
        if "share/r3-research-radar/" in name
    ]
    if not data_prefixes:
        raise DistributionError("wheel does not contain the R3 shared asset root")
    data_prefix = sorted(set(data_prefixes))[0]
    missing = sorted(
        asset for asset in REQUIRED_ASSETS if data_prefix + asset not in names
    )
    forbidden = sorted(
        asset
        for asset in FORBIDDEN_DISTRIBUTION_PATHS
        if data_prefix + asset in names
    )
    metadata_names = sorted(name for name in names if name.endswith(".dist-info/METADATA"))
    entry_names = sorted(
        name for name in names if name.endswith(".dist-info/entry_points.txt")
    )
    if missing or forbidden or len(metadata_names) != 1 or len(entry_names) != 1:
        raise DistributionError(
            "invalid wheel payload; "
            f"missing={missing}; forbidden={forbidden}; "
            f"metadata={len(metadata_names)}; entry_points={len(entry_names)}"
        )
    with zipfile.ZipFile(path) as archive:
        metadata = Parser().parsestr(archive.read(metadata_names[0]).decode("utf-8"))
        entry_points = archive.read(entry_names[0]).decode("utf-8")
        hashes = {
            asset: hashlib.sha256(archive.read(data_prefix + asset)).hexdigest()
            for asset in REQUIRED_ASSETS
        }
    if metadata.get("Name") != PACKAGE_NAME:
        raise DistributionError("wheel metadata has the wrong package name")
    python_specifiers = {
        item.strip() for item in str(metadata.get("Requires-Python") or "").split(",")
    }
    if python_specifiers != {">=3.10", "<3.11"}:
        raise DistributionError("wheel metadata lost the supported Python boundary")
    dependencies = {
        item.replace(" ", "") for item in (metadata.get_all("Requires-Dist") or [])
    }
    if dependencies != {
        "httpx==0.28.1",
        "pypdf==6.14.2",
        "typing_extensions==4.16.0",
    }:
        raise DistributionError(
            f"wheel dependency metadata does not match the lock inputs: {dependencies}"
        )
    expected_entry_points = {
        "r3radar = r3radar.__main__:main",
        "r3-radar = r3radar.__main__:main",
    }
    if not all(entry in entry_points for entry in expected_entry_points):
        raise DistributionError("wheel is missing an R3 console entry point")
    source_hashes = {
        asset: hashlib.sha256((PROJECT_DIR / asset).read_bytes()).hexdigest()
        for asset in REQUIRED_ASSETS
    }
    if hashes != source_hashes:
        raise DistributionError("wheel package-data hashes do not match source assets")
    return {
        "member_count": len(names),
        "asset_root": data_prefix,
        "asset_sha256": hashes,
        "forbidden_paths_present": [],
    }


def build_and_verify(output_dir: Path, receipt_path: Path) -> dict[str, object]:
    output = output_dir.resolve()
    receipt = receipt_path.resolve()
    output.mkdir(parents=True, exist_ok=True)
    _reset_generated_directory(PROJECT_DIR / "build", allowed_parent=PROJECT_DIR)
    _reset_generated_directory(
        PROJECT_DIR / "r3_research_radar.egg-info",
        allowed_parent=PROJECT_DIR,
    )
    for existing in output.glob("r3_research_radar-*"):
        if existing.is_file():
            existing.unlink()

    previous = Path.cwd()
    os.chdir(PROJECT_DIR)
    try:
        sdist_name = build_sdist(str(output))
        wheel_name = build_wheel(str(output))
    finally:
        os.chdir(previous)

    sdist_path = output / sdist_name
    wheel_path = output / wheel_name
    if not sdist_path.is_file() or not wheel_path.is_file():
        raise DistributionError("the build backend did not create both artifacts")
    payload = {
        "schema": "r3/distribution-build/v1",
        "status": "PASS",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "builder": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": sys.platform,
            "backend": "setuptools.build_meta",
        },
        "artifacts": {
            "sdist": {
                "path": str(sdist_path),
                "filename": sdist_path.name,
                "size": sdist_path.stat().st_size,
                "sha256": _sha256(sdist_path),
                **_validate_sdist(sdist_path),
            },
            "wheel": {
                "path": str(wheel_path),
                "filename": wheel_path.name,
                "size": wheel_path.stat().st_size,
                "sha256": _sha256(wheel_path),
                **_validate_wheel(wheel_path),
            },
        },
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt.with_name(receipt.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(receipt)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and validate clean R3 wheel/sdist artifacts."
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    result = build_and_verify(args.output_dir, args.receipt)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
