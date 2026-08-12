from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_UNCOMPRESSED_BYTES = 5 * 1024 * 1024


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _role(path: Path) -> str:
    top = path.parts[0]
    return {
        "r3radar": "application",
        "static": "interface",
        "schemas": "model_contract",
        "config": "configuration",
        "requirements": "governance",
        "scripts": "operation",
        "tests": "verification",
    }.get(top, "dependency")


def _source_files() -> list[Path]:
    patterns = (
        "r3radar/*.py",
        "static/*",
        "schemas/*.json",
        "config/*.json",
        "requirements/QUEUE_V3.json",
        "scripts/*.py",
        "scripts/*.ps1",
        "tests/*.py",
        "requirements.txt",
        "requirements.lock",
        "package.json",
        "package-lock.json",
        "README.md",
    )
    files: dict[str, Path] = {}
    for pattern in patterns:
        for path in PROJECT_DIR.glob(pattern):
            if path.is_file() and "__pycache__" not in path.parts:
                relative = path.relative_to(PROJECT_DIR).as_posix()
                files[relative] = path
    return [files[key] for key in sorted(files)]


def _evidence_records(values: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw in values:
        path = Path(raw).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"evidence file not found: {path}")
        data = path.read_bytes()
        records.append(
            {
                "path": str(path),
                "bytes": len(data),
                "sha256": _sha256_bytes(data),
            }
        )
    return sorted(records, key=lambda item: item["path"])


def build_bundle(
    *,
    phase: str,
    output_dir: Path,
    parent_bundle: str | None,
    evidence: list[str],
) -> dict[str, Any]:
    files = _source_files()
    file_records: list[dict[str, Any]] = []
    total = 0
    for path in files:
        data = path.read_bytes()
        total += len(data)
        relative = path.relative_to(PROJECT_DIR)
        file_records.append(
            {
                "path": relative.as_posix(),
                "bytes": len(data),
                "sha256": _sha256_bytes(data),
                "role": _role(relative),
            }
        )
    if total > MAX_UNCOMPRESSED_BYTES:
        raise RuntimeError(
            f"core bundle input is {total} bytes; limit is {MAX_UNCOMPRESSED_BYTES}"
        )
    manifest = {
        "schema": "r3/core-source-bundle/v1",
        "phase": phase,
        "parent_bundle": parent_bundle,
        "files": file_records,
        "evidence": _evidence_records(evidence),
        "limits": {
            "maximum_uncompressed_bytes": MAX_UNCOMPRESSED_BYTES,
            "runtime_data_included": False,
            "secrets_included": False,
        },
    }
    manifest_bytes = _canonical_json(manifest) + b"\n"
    bundle_id = _sha256_bytes(manifest_bytes)
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{phase}-{bundle_id}.zip"
    if archive_path.exists():
        existing_sha256 = _sha256_bytes(archive_path.read_bytes())
    else:
        with zipfile.ZipFile(
            archive_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            manifest_info = zipfile.ZipInfo("manifest.json", FIXED_ZIP_TIME)
            manifest_info.external_attr = 0o644 << 16
            archive.writestr(manifest_info, manifest_bytes)
            for record, path in zip(file_records, files, strict=True):
                info = zipfile.ZipInfo(record["path"], FIXED_ZIP_TIME)
                info.external_attr = 0o644 << 16
                archive.writestr(info, path.read_bytes())
        existing_sha256 = _sha256_bytes(archive_path.read_bytes())
    verification = {
        "schema": "r3/core-source-bundle-verification/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "bundle_id": bundle_id,
        "manifest_sha256": bundle_id,
        "archive_path": str(archive_path),
        "archive_sha256": existing_sha256,
        "file_count": len(file_records),
        "uncompressed_source_bytes": total,
        "matched_file_count": len(file_records),
        "failed_file_count": 0,
    }
    verification_path = output_dir / f"{phase}-{bundle_id}.verification.json"
    verification_path.write_text(
        json.dumps(verification, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return verification


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a bounded deterministic content-addressed R3 source bundle."
    )
    parser.add_argument("--phase", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--parent-bundle")
    parser.add_argument("--evidence", action="append", default=[])
    args = parser.parse_args()
    result = build_bundle(
        phase=args.phase,
        output_dir=args.output_dir.resolve(),
        parent_bundle=args.parent_bundle,
        evidence=args.evidence,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
