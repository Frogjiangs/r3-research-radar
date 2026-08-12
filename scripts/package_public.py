from __future__ import annotations

import argparse
import getpass
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


PROJECT_DIR = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_UNCOMPRESSED_BYTES = 10 * 1024 * 1024

# Public packaging is intentionally fail-closed. New files do not enter a
# release merely because they were added somewhere under the repository.
REQUIRED_EXACT_FILES = (
    ".gitignore",
    "README.md",
    "MANIFEST.in",
    "pyproject.toml",
    "requirements.txt",
    "requirements.lock",
    "package.json",
    "package-lock.json",
    "config/profile.example.json",
    "config/demo.v1.json",
    "scripts/package_public.py",
    "scripts/build_distribution.py",
    "scripts/SETUP.ps1",
    "scripts/RUN_SMOKE.ps1",
    "scripts/START_DASHBOARD.ps1",
    "scripts/supply_chain.py",
    ".github/workflows/ci.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
)
OPTIONAL_EXACT_FILES = (
    "LICENSE",
    "LICENSE.txt",
    "NOTICE",
    "NOTICE.txt",
    "THIRD_PARTY_NOTICES.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "CITATION.cff",
    "README.zh-CN.md",
    ".env.example",
    "docs/ARCHITECTURE.md",
    "docs/CAPABILITIES.md",
    "docs/EVALUATION.md",
    "docs/PRIVACY.md",
    "docs/SMALL_COMMERCIAL.md",
    "docs/assets/dashboard.jpg",
    "docs/assets/dashboard-mobile.jpg",
    "docs/assets/gold-review.jpg",
    "docs/assets/gold-review-mobile.jpg",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    "scripts/RUN_BACKFILL.ps1",
    "scripts/RUN_CONTINUITY_TEST.ps1",
    "scripts/RUN_SCHEDULED.ps1",
    "scripts/REGISTER_DAILY_TASK.ps1",
    "scripts/START_LLAMA_FALLBACK.ps1",
    "scripts/STOP_LLAMA_FALLBACK.ps1",
)
GLOB_ALLOWLIST = (
    ("r3radar", "*.py"),
    ("schemas", "*.json"),
    ("static", "*.html"),
    ("static", "*.css"),
    ("static", "*.js"),
    ("tests", "test_*.py"),
)
MAPPED_FILES = (
    ("config/profile.example.json", "config/r3.v1.json"),
)
FORBIDDEN_PUBLIC_REFERENCES = (
    "config/r3.workflow-cache-value.focus-v1.json",
    "config/r3.workflow-cache-value.full-v1.json",
)

FORBIDDEN_PATH_PARTS = frozenset(
    {
        ".codex",
        ".git",
        ".idea",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".venv",
        "__pycache__",
        "data",
        "literature",
        "node_modules",
        "outputs",
    }
)
FORBIDDEN_DATABASE_SUFFIXES = (
    ".db",
    ".sqlite",
    ".sqlite3",
    ".sqlite3-shm",
    ".sqlite3-wal",
)
SQLITE_HEADER = b"SQLite format 3\x00"
PUBLIC_SCREENSHOTS = frozenset(
    {
        "docs/assets/dashboard.jpg",
        "docs/assets/dashboard-mobile.jpg",
        "docs/assets/gold-review.jpg",
        "docs/assets/gold-review-mobile.jpg",
    }
)
MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024

DRIVE_ABSOLUTE_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:[A-Z]:[\\/])")
USER_HOME_RE = re.compile(
    r"(?i)(?:[A-Z]:[\\/]Users[\\/][^\\/\s\"']+|"
    r"/(?:home|Users)/[^/\s\"']+)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (?P<name>
        api[_-]?key
        |access[_-]?token
        |client[_-]?secret
        |github_token
        |openai_api_key
        |openalex_api_key
        |password
        |secret
    )
    \s*[:=]\s*
    (?P<quote>["'])
    (?P<value>[^"'\r\n]+)
    (?P=quote)
    """
)
SECRET_PREFIXES = (
    "s" + "k-",
    "s" + "k_live_",
    "r" + "k_live_",
    "g" + "hp_",
    "g" + "ho_",
    "g" + "hu_",
    "g" + "hs_",
    "github" + "_pat_",
    "gl" + "pat-",
    "AIza" + "Sy",
    "A" + "KIA",
    "A" + "SIA",
    "xox" + "b-",
    "xox" + "p-",
)
PRIVATE_KEY_MARKER = "-----BEGIN " + "PRIVATE KEY-----"
CODEX_PATH_RE = re.compile(
    re.escape("." + "codex") + r"(?:[\\/]|$)",
    re.IGNORECASE,
)


class PublicReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class PublicEntry:
    source_path: Path
    archive_path: str
    data: bytes


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _finding(
    rule: str,
    archive_path: str,
    *,
    severity: str = "error",
    line: int | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "rule": rule,
        "path": archive_path,
        "severity": severity,
    }
    if line is not None:
        result["line"] = line
    if detail is not None:
        result["detail"] = detail
    return result


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _scan_dashboard_screenshot(
    data: bytes,
    archive_path: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if len(data) > MAX_SCREENSHOT_BYTES:
        findings.append(
            _finding(
                "binary_asset_size_budget_exceeded",
                archive_path,
                detail=f"{len(data)} bytes exceeds {MAX_SCREENSHOT_BYTES}",
            )
        )
    if (
        len(data) < 32
        or not data.startswith(b"\xff\xd8")
        or not data.endswith(b"\xff\xd9")
    ):
        findings.append(_finding("invalid_dashboard_jpeg", archive_path))
        return findings

    cursor = 2
    saw_jfif = False
    dimensions: tuple[int, int] | None = None
    while cursor + 4 <= len(data):
        if data[cursor] != 0xFF:
            findings.append(_finding("invalid_dashboard_jpeg", archive_path))
            return findings
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            break
        marker = data[cursor]
        cursor += 1
        if marker in {0xD8, 0xD9} or 0xD0 <= marker <= 0xD7:
            continue
        if cursor + 2 > len(data):
            findings.append(_finding("invalid_dashboard_jpeg", archive_path))
            return findings
        segment_length = int.from_bytes(data[cursor : cursor + 2], "big")
        if segment_length < 2 or cursor + segment_length > len(data):
            findings.append(_finding("invalid_dashboard_jpeg", archive_path))
            return findings
        payload = data[cursor + 2 : cursor + segment_length]
        cursor += segment_length
        if marker == 0xE0:
            saw_jfif = payload.startswith(b"JFIF\x00")
        elif 0xE1 <= marker <= 0xEF or marker == 0xFE:
            findings.append(
                _finding(
                    "dashboard_jpeg_metadata",
                    archive_path,
                    detail=f"JPEG marker 0x{marker:02x} is not allowed",
                )
            )
        if marker in {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }:
            if len(payload) < 5:
                findings.append(_finding("invalid_dashboard_jpeg", archive_path))
                return findings
            dimensions = (
                int.from_bytes(payload[3:5], "big"),
                int.from_bytes(payload[1:3], "big"),
            )
        if marker == 0xDA:
            break

    if not saw_jfif:
        findings.append(_finding("dashboard_jpeg_missing_jfif", archive_path))
    if (
        dimensions is None
        or min(dimensions) <= 0
        or max(dimensions) > 4096
    ):
        findings.append(_finding("dashboard_jpeg_dimensions", archive_path))
    return findings


def _candidate_usernames() -> tuple[str, ...]:
    values = {
        getpass.getuser().strip(),
        os.getenv("USERNAME", "").strip(),
        os.getenv("USER", "").strip(),
        Path.home().name.strip(),
    }
    return tuple(
        sorted(
            (
                value
                for value in values
                if len(value) >= 3
                and value.casefold()
                not in {
                    "admin",
                    "administrator",
                    "root",
                    "runner",
                    "runneradmin",
                    "system",
                    "user",
                    "users",
                }
            ),
            key=str.casefold,
        )
    )


def _is_placeholder_secret(value: str) -> bool:
    normalized = value.strip()
    lowered = normalized.casefold()
    if not normalized:
        return True
    if (
        (normalized.startswith("<") and normalized.endswith(">"))
        or normalized.startswith("${")
        or normalized.startswith("$env:")
        or (normalized.startswith("%") and normalized.endswith("%"))
    ):
        return True
    if lowered in {"none", "null", "false", "redacted", "changeme"}:
        return True
    if any(
        marker in lowered
        for marker in ("your-", "your_", "example", "placeholder", "redacted")
    ):
        return True
    if re.fullmatch(r"[A-Z][A-Z0-9_]{5,}", normalized):
        return True
    return False


def scan_entries(entries: Iterable[PublicEntry]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    usernames = _candidate_usernames()
    for entry in entries:
        archive_path = PurePosixPath(entry.archive_path)
        folded_parts = {part.casefold() for part in archive_path.parts}
        forbidden = sorted(folded_parts & FORBIDDEN_PATH_PARTS)
        if forbidden:
            findings.append(
                _finding(
                    "runtime_or_private_path",
                    entry.archive_path,
                    detail="forbidden path component: " + ", ".join(forbidden),
                )
            )
        lowered_path = entry.archive_path.casefold()
        if lowered_path.endswith(FORBIDDEN_DATABASE_SUFFIXES):
            findings.append(_finding("database_artifact_path", entry.archive_path))
        if entry.data.startswith(SQLITE_HEADER):
            findings.append(_finding("sqlite_content", entry.archive_path))

        if entry.archive_path in PUBLIC_SCREENSHOTS:
            findings.extend(
                _scan_dashboard_screenshot(entry.data, entry.archive_path)
            )
            continue

        try:
            text = entry.data.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(_finding("non_utf8_content", entry.archive_path))
            continue

        if entry.archive_path == "pyproject.toml":
            for forbidden_reference in FORBIDDEN_PUBLIC_REFERENCES:
                offset = text.find(forbidden_reference)
                if offset >= 0:
                    findings.append(
                        _finding(
                            "forbidden_public_packaging_reference",
                            entry.archive_path,
                            line=_line_number(text, offset),
                            detail=(
                                "packaging metadata references an excluded "
                                f"personal profile: {forbidden_reference}"
                            ),
                        )
                    )

        match = DRIVE_ABSOLUTE_RE.search(text)
        if match:
            matched_tail = text[match.start() : match.start() + 80]
            synthetic_test_path = (
                entry.archive_path.startswith("tests/")
                and re.match(
                    r"(?i)[A-Z]:[\\/](?:private|example|test|tmp)[\\/]",
                    matched_tail,
                )
                is not None
            )
            findings.append(
                _finding(
                    "drive_absolute_path",
                    entry.archive_path,
                    severity="warning" if synthetic_test_path else "error",
                    line=_line_number(text, match.start()),
                    detail=(
                        "recognized synthetic test fixture path"
                        if synthetic_test_path
                        else None
                    ),
                )
            )
        match = USER_HOME_RE.search(text)
        if match:
            findings.append(
                _finding(
                    "user_home_path",
                    entry.archive_path,
                    line=_line_number(text, match.start()),
                )
            )
        match = CODEX_PATH_RE.search(text)
        if match:
            generic_documented_path = (
                entry.archive_path in {"README.md", "SECURITY.md"}
                and text[max(0, match.start() - 2) : match.start()] == "~/"
            )
            findings.append(
                _finding(
                    "codex_private_path",
                    entry.archive_path,
                    severity=(
                        "warning" if generic_documented_path else "error"
                    ),
                    line=_line_number(text, match.start()),
                    detail=(
                        "documented generic home-relative credential path"
                        if generic_documented_path
                        else None
                    ),
                )
            )
        for username in usernames:
            match = re.search(
                rf"(?<![A-Za-z0-9_.-]){re.escape(username)}"
                rf"(?![A-Za-z0-9_.-])",
                text,
                re.IGNORECASE,
            )
            if match:
                findings.append(
                    _finding(
                        "local_username",
                        entry.archive_path,
                        line=_line_number(text, match.start()),
                    )
                )
                break

        for prefix in SECRET_PREFIXES:
            match = re.search(
                r"(?<![A-Za-z0-9])"
                + re.escape(prefix)
                + r"[A-Za-z0-9_\-]{12,}",
                text,
            )
            if match:
                findings.append(
                    _finding(
                        "credential_prefix",
                        entry.archive_path,
                        line=_line_number(text, match.start()),
                    )
                )
                break
        private_key = text.find(PRIVATE_KEY_MARKER)
        if private_key >= 0:
            findings.append(
                _finding(
                    "private_key_material",
                    entry.archive_path,
                    line=_line_number(text, private_key),
                )
            )
        for match in SECRET_ASSIGNMENT_RE.finditer(text):
            value = match.group("value")
            if _is_placeholder_secret(value):
                continue
            findings.append(
                _finding(
                    "credential_assignment",
                    entry.archive_path,
                    line=_line_number(text, match.start()),
                    detail=f"non-placeholder value assigned to {match.group('name')}",
                )
            )

    return sorted(
        findings,
        key=lambda item: (
            item["path"],
            int(item.get("line") or 0),
            item["rule"],
        ),
    )


def _safe_read(
    project_dir: Path,
    source_relative: str,
    archive_relative: str,
) -> PublicEntry:
    root = project_dir.resolve()
    source = (root / Path(source_relative)).resolve()
    try:
        source.relative_to(root)
    except ValueError as exc:
        raise PublicReleaseError(
            f"allowlisted source escapes project root: {source_relative}"
        ) from exc
    if not source.is_file():
        raise FileNotFoundError(source_relative)
    archive_path = PurePosixPath(archive_relative)
    if (
        archive_path.is_absolute()
        or ".." in archive_path.parts
        or str(archive_path) in {"", "."}
    ):
        raise PublicReleaseError(f"invalid archive path: {archive_relative}")
    return PublicEntry(
        source_path=source,
        archive_path=archive_path.as_posix(),
        data=source.read_bytes(),
    )


def collect_public_entries(
    project_dir: Path,
) -> tuple[list[PublicEntry], list[dict[str, Any]]]:
    root = project_dir.resolve()
    entries: dict[str, PublicEntry] = {}
    structural_findings: list[dict[str, Any]] = []

    def add(source_relative: str, archive_relative: str | None = None) -> None:
        target = archive_relative or source_relative
        try:
            entry = _safe_read(root, source_relative, target)
        except FileNotFoundError:
            structural_findings.append(
                _finding(
                    "missing_required_source",
                    target,
                    detail=f"source file is missing: {source_relative}",
                )
            )
            return
        if entry.archive_path in entries:
            structural_findings.append(
                _finding(
                    "duplicate_archive_path",
                    entry.archive_path,
                    detail=f"second source: {source_relative}",
                )
            )
            return
        entries[entry.archive_path] = entry

    for relative in REQUIRED_EXACT_FILES:
        add(relative)
    for relative in OPTIONAL_EXACT_FILES:
        if (root / Path(relative)).is_file():
            add(relative)
    for source_relative, archive_relative in MAPPED_FILES:
        add(source_relative, archive_relative)
    for directory, pattern in GLOB_ALLOWLIST:
        directory_path = root / directory
        matches = (
            sorted(directory_path.glob(pattern))
            if directory_path.is_dir()
            else []
        )
        if not matches:
            structural_findings.append(
                _finding(
                    "empty_required_allowlist_group",
                    f"{directory}/{pattern}",
                )
            )
        for path in matches:
            if path.is_file():
                add(path.relative_to(root).as_posix())

    ordered = [entries[key] for key in sorted(entries)]
    total = sum(len(entry.data) for entry in ordered)
    if total > MAX_UNCOMPRESSED_BYTES:
        structural_findings.append(
            _finding(
                "source_size_budget_exceeded",
                ".",
                detail=f"{total} bytes exceeds {MAX_UNCOMPRESSED_BYTES}",
            )
        )
    return ordered, structural_findings


def _license_entry(entries: Iterable[PublicEntry]) -> PublicEntry | None:
    for entry in entries:
        if PurePosixPath(entry.archive_path).name.casefold() in {
            "license",
            "license.txt",
        }:
            return entry
    return None


def audit_public_source(project_dir: Path = PROJECT_DIR) -> dict[str, Any]:
    entries, structural_findings = collect_public_entries(project_dir)
    content_findings = scan_entries(entries)
    findings = sorted(
        structural_findings + content_findings,
        key=lambda item: (
            item["path"],
            int(item.get("line") or 0),
            item["rule"],
        ),
    )
    blocking_findings = [
        finding
        for finding in findings
        if finding.get("severity", "error") == "error"
    ]
    warning_findings = [
        finding
        for finding in findings
        if finding.get("severity") == "warning"
    ]
    license_entry = _license_entry(entries)
    if blocking_findings:
        status = "FAIL"
    elif license_entry is None:
        status = "PASS_WITH_LICENSE_PENDING"
    else:
        status = "PASS"
    return {
        "schema": "r3/public-source-audit/v1",
        "status": status,
        "production_ready": status == "PASS",
        "project_dir": str(project_dir.resolve()),
        "selected_file_count": len(entries),
        "selected_bytes": sum(len(entry.data) for entry in entries),
        "license": {
            "status": "present" if license_entry is not None else "pending",
            "required_for_build": True,
            "path": (
                license_entry.archive_path if license_entry is not None else None
            ),
        },
        "scan": {
            "status": "PASS" if not blocking_findings else "FAIL",
            "finding_count": len(findings),
            "blocking_finding_count": len(blocking_findings),
            "warning_count": len(warning_findings),
            "findings": findings,
            "rules": [
                "explicit_allowlist",
                "runtime_and_database_artifacts",
                "local_username_and_home_paths",
                "drive_absolute_paths",
                "codex_private_paths",
                "credential_patterns",
                "utf8_text_only",
                "dashboard_jpeg_contract",
            ],
        },
        "mapping": {
            source: destination
            for source, destination in MAPPED_FILES
        },
        "excluded_by_policy": [
            "requirements/**",
            "config/r3.v1.json",
            "config/r3.workflow-cache-value.*.json",
            "data/**",
            "literature/**",
            "outputs/**",
            ".venv/**",
            "node_modules/**",
        ],
        "_entries": entries,
    }


def _manifest(audit: dict[str, Any]) -> tuple[dict[str, Any], bytes, str]:
    entries: list[PublicEntry] = audit["_entries"]
    finding_count = int(audit["scan"]["finding_count"])
    manifest = {
        "schema": "r3/public-source-bundle/v1",
        "files": [
            {
                "path": entry.archive_path,
                "bytes": len(entry.data),
                "sha256": _sha256_bytes(entry.data),
            }
            for entry in entries
        ],
        "mapping": audit["mapping"],
        "assurance": {
            "scan_status": audit["scan"]["status"],
            "scan_rules": audit["scan"]["rules"],
            "scan_finding_count": finding_count,
            "scan_blocking_finding_count": audit["scan"][
                "blocking_finding_count"
            ],
            "scan_warning_count": audit["scan"]["warning_count"],
            "secrets_included": any(
                finding["rule"]
                in {
                    "credential_assignment",
                    "credential_prefix",
                    "private_key_material",
                }
                for finding in audit["scan"]["findings"]
            ),
            "runtime_artifacts_included": any(
                finding["rule"]
                in {
                    "database_artifact_path",
                    "runtime_or_private_path",
                    "sqlite_content",
                }
                for finding in audit["scan"]["findings"]
            ),
        },
        "limits": {
            "maximum_uncompressed_source_bytes": MAX_UNCOMPRESSED_BYTES,
            "actual_uncompressed_source_bytes": audit["selected_bytes"],
        },
    }
    manifest_bytes = _canonical_json(manifest) + b"\n"
    bundle_id = _sha256_bytes(manifest_bytes)
    return manifest, manifest_bytes, bundle_id


def _zip_bytes(
    manifest_bytes: bytes,
    entries: list[PublicEntry],
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        payloads = [("manifest.json", manifest_bytes)]
        payloads.extend(
            (entry.archive_path, entry.data)
            for entry in entries
        )
        for archive_name, data in payloads:
            info = zipfile.ZipInfo(archive_name, FIXED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)
    return buffer.getvalue()


def build_public_bundle(
    output_dir: Path,
    project_dir: Path = PROJECT_DIR,
) -> dict[str, Any]:
    audit = audit_public_source(project_dir)
    public_audit = {key: value for key, value in audit.items() if key != "_entries"}
    if audit["scan"]["status"] != "PASS":
        raise PublicReleaseError(
            "public source audit failed: "
            + json.dumps(public_audit["scan"]["findings"], ensure_ascii=False)
        )
    if audit["license"]["status"] != "present":
        raise PublicReleaseError(
            "public build blocked: LICENSE is pending; --check may be used "
            "for structural audit only"
        )

    _, manifest_bytes, bundle_id = _manifest(audit)
    output_root = output_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    archive_path = output_root / f"r3-research-radar-public-{bundle_id}.zip"
    entries: list[PublicEntry] = audit["_entries"]
    expected_archive = _zip_bytes(manifest_bytes, entries)
    if archive_path.exists():
        if archive_path.read_bytes() != expected_archive:
            raise PublicReleaseError(
                "existing content-addressed archive does not match the "
                f"audited source: {archive_path.name}"
            )
    else:
        temporary_path = output_root / (
            f".{archive_path.name}.{os.getpid()}.tmp"
        )
        try:
            temporary_path.write_bytes(expected_archive)
            if temporary_path.read_bytes() != expected_archive:
                raise PublicReleaseError(
                    "public archive write verification failed"
                )
            temporary_path.replace(archive_path)
        finally:
            temporary_path.unlink(missing_ok=True)
    archive_sha256 = _sha256_bytes(expected_archive)

    verification = {
        "schema": "r3/public-source-bundle-verification/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "PASS",
        "bundle_id": bundle_id,
        "manifest_sha256": bundle_id,
        "archive_path": archive_path.name,
        "archive_sha256": archive_sha256,
        "file_count": len(entries),
        "scan": public_audit["scan"],
        "license": public_audit["license"],
    }
    verification_path = (
        output_root
        / f"r3-research-radar-public-{bundle_id}.verification.json"
    )
    verification_path.write_text(
        json.dumps(verification, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return verification


def _public_audit(audit: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in audit.items() if key != "_entries"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Audit or build a deterministic, explicitly allowlisted public "
            "R3 source bundle."
        )
    )
    parser.add_argument(
        "--project-dir",
        type=Path,
        default=PROJECT_DIR,
        help=argparse.SUPPRESS,
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help=(
            "Audit structure and content without writing a ZIP. A missing "
            "LICENSE is reported as pending but does not fail this mode."
        ),
    )
    mode.add_argument(
        "--output-dir",
        type=Path,
        help="Build the production ZIP; this fails unless LICENSE is present.",
    )
    arguments = parser.parse_args(argv)

    if arguments.check:
        audit = _public_audit(audit_public_source(arguments.project_dir))
        print(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True))
        return 0 if audit["scan"]["status"] == "PASS" else 1

    assert arguments.output_dir is not None
    try:
        result = build_public_bundle(
            arguments.output_dir,
            arguments.project_dir,
        )
    except PublicReleaseError as exc:
        print(
            json.dumps(
                {
                    "schema": "r3/public-source-build-error/v1",
                    "status": "BLOCKED",
                    "reason": str(exc),
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
