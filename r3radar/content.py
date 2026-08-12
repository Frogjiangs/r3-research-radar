from __future__ import annotations

import io
import json
import re
import stat
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from .config import Settings
from .document_policy import (
    REPOSITORY_SELECTION_ALGORITHM_VERSION,
)
from .http_client import FetchError, RetryDeferredError, SafeHttpClient
from .pdf_parser import (
    PARSER_POLICY_VERSION,
    REQUIRED_PYPDF_VERSION,
    PdfParseError,
    parse_pdf_with_worker,
)
from .utils import (
    JsonlAuditLog,
    atomic_write_bytes,
    atomic_write_text,
    json_dumps,
    safe_slug,
    sha256_bytes,
    sha256_text,
)


@dataclass(frozen=True, slots=True)
class ContentResult:
    content_kind: str
    status: str
    source_url: str | None
    local_path: str | None
    text_path: str | None
    content_sha256: str | None
    text_sha256: str | None
    byte_count: int | None
    text_char_count: int | None
    page_count: int | None
    coverage: dict[str, Any]
    error: str | None = None


_TEXT_EXTENSIONS = {
    ".bib",
    ".c",
    ".cc",
    ".cfg",
    ".cmake",
    ".cpp",
    ".cs",
    ".css",
    ".csv",
    ".cu",
    ".cuh",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".ini",
    ".ipynb",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".lua",
    ".md",
    ".mjs",
    ".php",
    ".proto",
    ".ps1",
    ".py",
    ".r",
    ".rb",
    ".rs",
    ".rst",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".tex",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_TEXT_NAMES = {
    "authors",
    "changelog",
    "citation.cff",
    "cmakelists.txt",
    "code_of_conduct",
    "contributing",
    "dockerfile",
    "license",
    "makefile",
    "notice",
    "readme",
    "requirements",
}
_EXCLUDED_DIRS = {
    ".git",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "third_party",
    "vendor",
    "venv",
}
_REPOSITORY_REQUIRED_ROOT_NAMES = {
    "cargo.toml",
    "cmakelists.txt",
    "environment.yml",
    "go.mod",
    "makefile",
    "package.json",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
}
_REPOSITORY_AUXILIARY_DIR_ROLES = {
    "benchmark": "benchmark",
    "benchmarks": "benchmark",
    "config": "configuration",
    "configs": "configuration",
    "doc": "documentation",
    "docs": "documentation",
    "example": "example",
    "examples": "example",
    "sample": "example",
    "samples": "example",
    "script": "script",
    "scripts": "script",
    "test": "test",
    "tests": "test",
    "tool": "script",
    "tools": "script",
}
_REPOSITORY_ROLE_SCORES = {
    "root_metadata": 100,
    "core_source": 80,
    "test": 60,
    "documentation": 50,
    "example": 45,
    "benchmark": 42,
    "script": 40,
    "configuration": 35,
    "auxiliary_text": 20,
}
_REPOSITORY_CORE_CONTAINER_NAMES = {
    "app",
    "apps",
    "cpp",
    "java",
    "js",
    "lib",
    "libs",
    "package",
    "packages",
    "python",
    "src",
}
_REPOSITORY_ENTRYPOINT_STEMS = {
    "agent",
    "cache",
    "cli",
    "controller",
    "core",
    "engine",
    "eviction",
    "executor",
    "main",
    "manager",
    "memory",
    "policy",
    "predictor",
    "retention",
    "scheduler",
    "server",
    "workflow",
}
_REPOSITORY_RESEARCH_TERM_STOPWORDS = {
    "against",
    "complete",
    "decision",
    "from",
    "general",
    "into",
    "near",
    "non",
    "one",
    "style",
    "support",
    "system",
    "than",
    "then",
    "with",
}
_MAX_REPOSITORY_ARCHIVE_FILE_COUNT = 25000
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP_EOCD_MIN_SIZE = 22
_ZIP_EOCD_MAX_SEARCH = _ZIP_EOCD_MIN_SIZE + 65535


def _repository_archive_entry_count(body: bytes) -> int:
    search_start = max(0, len(body) - _ZIP_EOCD_MAX_SEARCH)
    eocd_offset = body.rfind(_ZIP_EOCD_SIGNATURE, search_start)
    while eocd_offset >= 0:
        if eocd_offset + _ZIP_EOCD_MIN_SIZE <= len(body):
            fields = struct.unpack_from("<4s4H2LH", body, eocd_offset)
            comment_length = fields[-1]
            if eocd_offset + _ZIP_EOCD_MIN_SIZE + comment_length == len(body):
                break
        eocd_offset = body.rfind(
            _ZIP_EOCD_SIGNATURE,
            search_start,
            eocd_offset,
        )
    if eocd_offset < 0:
        raise FetchError("repository archive has no valid ZIP end record")

    (
        _,
        disk_number,
        directory_disk,
        entries_on_disk,
        entry_count,
        _,
        _,
        _,
    ) = struct.unpack_from("<4s4H2LH", body, eocd_offset)
    if disk_number != 0 or directory_disk != 0:
        raise FetchError("multi-disk repository archives are not supported")

    if entries_on_disk == 0xFFFF or entry_count == 0xFFFF:
        locator_offset = eocd_offset - 20
        if locator_offset < 0:
            raise FetchError("repository ZIP64 locator is missing")
        (
            locator_signature,
            zip64_disk,
            zip64_offset,
            total_disks,
        ) = struct.unpack_from("<4sLQL", body, locator_offset)
        if (
            locator_signature != _ZIP64_LOCATOR_SIGNATURE
            or zip64_disk != 0
            or total_disks != 1
            or zip64_offset + 56 > len(body)
        ):
            raise FetchError("repository ZIP64 locator is invalid")
        zip64_fields = struct.unpack_from(
            "<4sQ2H2L4Q",
            body,
            zip64_offset,
        )
        (
            zip64_signature,
            zip64_record_size,
            _,
            _,
            zip64_disk_number,
            zip64_directory_disk,
            zip64_entries_on_disk,
            zip64_entry_count,
            _,
            _,
        ) = zip64_fields
        if (
            zip64_signature != _ZIP64_EOCD_SIGNATURE
            or zip64_record_size < 44
            or zip64_disk_number != 0
            or zip64_directory_disk != 0
            or zip64_entries_on_disk != zip64_entry_count
        ):
            raise FetchError("repository ZIP64 end record is invalid")
        entry_count = zip64_entry_count
        entries_on_disk = zip64_entries_on_disk

    if entries_on_disk != entry_count:
        raise FetchError("multi-disk repository archives are not supported")
    return int(entry_count)
def _eligible_text_path(path: PurePosixPath) -> tuple[bool, str]:
    lowered_parts = {part.casefold() for part in path.parts[:-1]}
    excluded = sorted(lowered_parts & _EXCLUDED_DIRS)
    if excluded:
        return False, f"excluded_directory:{excluded[0]}"
    name = path.name.casefold()
    stem = path.stem.casefold()
    if path.suffix.casefold() in _TEXT_EXTENSIONS:
        return True, "text_extension"
    if name in _TEXT_NAMES or stem in _TEXT_NAMES:
        return True, "text_name"
    return False, "non_text_extension"


def _safe_archive_path(name: str) -> PurePosixPath:
    if len(name) > 4096:
        raise FetchError("repository archive path exceeds safety limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in name):
        raise FetchError("repository archive path contains control characters")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or re.match(r"^[A-Za-z]:", name):
        raise FetchError("repository archive contains an unsafe path")
    return path


def _decode_text(value: bytes) -> tuple[str | None, str]:
    if b"\x00" in value[:8192]:
        return None, "binary_nul"
    for encoding in ("utf-8-sig", "utf-8"):
        try:
            return value.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return None, "not_utf8"


def _repository_relative_path(
    path: PurePosixPath,
    root_prefix: str | None,
) -> PurePosixPath:
    if root_prefix is not None and path.parts and path.parts[0] == root_prefix:
        return PurePosixPath(*path.parts[1:])
    return path


def _repository_file_role(path: PurePosixPath) -> tuple[str, int, bool]:
    lowered_parts = [part.casefold() for part in path.parts]
    name = path.name.casefold()
    stem = path.stem.casefold()
    if len(path.parts) == 1 and (
        name in _REPOSITORY_REQUIRED_ROOT_NAMES
        or stem == "readme"
        or name.startswith("requirements")
    ):
        role = "root_metadata"
        return role, _REPOSITORY_ROLE_SCORES[role], True
    for part in lowered_parts[:-1]:
        role = _REPOSITORY_AUXILIARY_DIR_ROLES.get(part)
        if role is not None:
            return role, _REPOSITORY_ROLE_SCORES[role], False
    if (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.js")
        or name.endswith(".test.ts")
    ):
        role = "test"
        return role, _REPOSITORY_ROLE_SCORES[role], False
    if path.suffix.casefold() in {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".cu",
        ".cuh",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".lua",
        ".mjs",
        ".php",
        ".proto",
        ".py",
        ".r",
        ".rb",
        ".rs",
        ".scala",
        ".sql",
        ".swift",
        ".ts",
        ".tsx",
    }:
        role = "core_source"
        return role, _REPOSITORY_ROLE_SCORES[role], False
    if path.suffix.casefold() in {".md", ".rst", ".tex", ".bib"}:
        role = "documentation"
    elif path.suffix.casefold() in {
        ".cfg",
        ".cmake",
        ".ini",
        ".json",
        ".toml",
        ".xml",
        ".yaml",
        ".yml",
    }:
        role = "configuration"
    else:
        role = "auxiliary_text"
    return role, _REPOSITORY_ROLE_SCORES[role], False


def _repository_research_terms(settings: Settings) -> tuple[str, ...]:
    values = [
        str(settings.raw.get("research_question") or ""),
        str(settings.raw.get("decision_scope") or ""),
    ]
    for query in settings.raw.get("queries") or []:
        if isinstance(query, dict):
            values.append(str(query.get("query") or ""))
    terms = {
        term
        for value in values
        for term in re.findall(r"[a-z][a-z0-9_+-]{2,}", value.casefold())
        if term not in _REPOSITORY_RESEARCH_TERM_STOPWORDS
    }
    return tuple(sorted(terms))


def _repository_core_group(path: PurePosixPath) -> str:
    directories = [part.casefold() for part in path.parts[:-1]]
    while directories and directories[0] in _REPOSITORY_CORE_CONTAINER_NAMES:
        directories.pop(0)
    if not directories:
        return "__root__"
    depth = 2 if len(directories) >= 2 else 1
    return "/".join(directories[:depth])


def _repository_core_priority(
    path: PurePosixPath,
    record: dict[str, Any],
    research_terms: tuple[str, ...],
) -> tuple[int, int, int, int, str]:
    normalized = str(path).casefold()
    matches = sum(1 for term in research_terms if term in normalized)
    stem_tokens = set(re.findall(r"[a-z][a-z0-9]+", path.stem.casefold()))
    entrypoint_matches = len(stem_tokens & _REPOSITORY_ENTRYPOINT_STEMS)
    record["research_term_matches"] = matches
    record["entrypoint_term_matches"] = entrypoint_matches
    record["core_group"] = _repository_core_group(path)
    return (
        -matches,
        -entrypoint_matches,
        len(path.parts),
        int(record["rendered_size_budget_bytes"]),
        normalized,
    )


class ContentProcessor:
    def __init__(
        self,
        settings: Settings,
        client_for_url: Callable[[str], SafeHttpClient],
        audit: JsonlAuditLog,
        run_id: str,
        heartbeat: Callable[[], None] | None = None,
    ):
        self.settings = settings
        self.client_for_url = client_for_url
        self.audit = audit
        self.run_id = run_id
        self.heartbeat = heartbeat
        self.config = settings.raw["documents"]
        self.pdf_config = settings.raw["pdf_parser"]

    def process(self, work: dict[str, Any]) -> ContentResult:
        if work["kind"] == "paper":
            return self._paper(work)
        if work["kind"] == "repository":
            return self._repository(work)
        return ContentResult(
            content_kind="unknown",
            status="unavailable",
            source_url=None,
            local_path=None,
            text_path=None,
            content_sha256=None,
            text_sha256=None,
            byte_count=None,
            text_char_count=None,
            page_count=None,
            coverage={"complete": False, "reason": "unsupported_kind"},
            error="Unsupported content kind.",
        )

    def _paper(self, work: dict[str, Any]) -> ContentResult:
        url = work.get("pdf_url")
        arxiv_id = work.get("arxiv_id")
        doi = str(work.get("doi") or "")
        if not arxiv_id and doi.casefold().startswith("10.48550/arxiv."):
            arxiv_id = doi.split("arxiv.", 1)[1]
        if arxiv_id and (
            not url
            or "doi.org/10.48550/arxiv." in str(url).casefold()
            or "arxiv.org/abs/" in str(url).casefold()
        ):
            url = f"https://arxiv.org/pdf/{arxiv_id}"
        if not url:
            return ContentResult(
                content_kind="paper_pdf",
                status="unavailable",
                source_url=None,
                local_path=None,
                text_path=None,
                content_sha256=None,
                text_sha256=None,
                byte_count=None,
                text_char_count=None,
                page_count=None,
                coverage={"complete": False, "reason": "no_pdf_url"},
                error="No full-text PDF URL was supplied by an admitted source.",
            )
        try:
            client = self.client_for_url(url)
            body, receipt, headers = client.request_bytes(
                url,
                max_bytes=int(self.config["max_download_bytes"]),
                raw_suffix="pdf",
                allowed_hosts=(
                    {"arxiv.org"}
                    if (urlsplit(url).hostname or "").casefold() == "arxiv.org"
                    else None
                ),
            )
            content_type = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if b"%PDF-" not in body[:1024]:
                raise FetchError(
                    "response does not contain a PDF header within the first 1024 bytes "
                    f"(content-type={content_type or 'missing'})"
                )
        except RetryDeferredError:
            raise
        except Exception as exc:
            self.audit.write(
                "paper_pdf_fetch_failed",
                component="content",
                run_id=self.run_id,
                severity="warning",
                details={
                    "work_id": int(work["id"]),
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                },
            )
            return ContentResult(
                content_kind="paper_pdf",
                status="unavailable",
                source_url=url,
                local_path=None,
                text_path=None,
                content_sha256=None,
                text_sha256=None,
                byte_count=None,
                text_char_count=None,
                page_count=None,
                coverage={
                    "complete": False,
                    "coverage_type": "text_layer",
                    "reason": "fetch_or_extract_error",
                    "failure_stage": "fetch",
                },
                error="The full-text PDF could not be retrieved and validated.",
            )

        digest = sha256_bytes(body)
        quarantine_path = (
            self.settings.literature_dir
            / "quarantine"
            / "pdf"
            / f"{digest}.pdf"
        )
        atomic_write_bytes(quarantine_path, body)
        raw_receipt = {
            "sha256": receipt.sha256,
            "path": receipt.path,
            "status_code": receipt.status_code,
            "final_url": receipt.final_url,
        }
        try:
            extraction = parse_pdf_with_worker(
                quarantine_path,
                expected_sha256=digest,
                expected_byte_count=len(body),
                config=self.pdf_config,
            )
        except PdfParseError as exc:
            return self._paper_incomplete_security(
                work_id=int(work["id"]),
                source_url=receipt.final_url,
                quarantine_path=quarantine_path,
                content_sha256=digest,
                byte_count=len(body),
                raw_receipt=raw_receipt,
                reason=exc.reason_code,
                failure_code=exc.failure_code,
                parser_receipt=exc.receipt,
                audit_error=None,
            )
        except Exception as exc:
            return self._paper_incomplete_security(
                work_id=int(work["id"]),
                source_url=receipt.final_url,
                quarantine_path=quarantine_path,
                content_sha256=digest,
                byte_count=len(body),
                raw_receipt=raw_receipt,
                reason="pdf_extract_worker_failed",
                failure_code="supervisor_error",
                parser_receipt={},
                audit_error=f"{type(exc).__name__}: {str(exc)[:500]}",
            )

        base = f"paper_{work['id']}_{digest}"
        pdf_path = self.settings.literature_dir / "documents" / f"{base}.pdf"
        text_path = (
            self.settings.literature_dir
            / "text"
            / f"{base}_{extraction.text_sha256}.txt"
        )
        if self.heartbeat is not None:
            self.heartbeat()
        try:
            if pdf_path.exists() and sha256_bytes(pdf_path.read_bytes()) != digest:
                raise RuntimeError("existing PDF artifact does not match its content address")
            if (
                text_path.exists()
                and sha256_bytes(text_path.read_bytes()) != extraction.text_sha256
            ):
                raise RuntimeError("existing text artifact does not match its content address")
            if not pdf_path.exists():
                atomic_write_bytes(pdf_path, body)
            if not text_path.exists():
                atomic_write_text(text_path, extraction.text)
        except Exception as exc:
            return self._paper_incomplete_security(
                work_id=int(work["id"]),
                source_url=receipt.final_url,
                quarantine_path=quarantine_path,
                content_sha256=digest,
                byte_count=len(body),
                raw_receipt=raw_receipt,
                reason="pdf_extract_worker_failed",
                failure_code="artifact_promotion_failed",
                parser_receipt=extraction.receipt,
                audit_error=f"{type(exc).__name__}: {str(exc)[:500]}",
            )

        page_text_non_whitespace = extraction.page_text_non_whitespace
        non_whitespace = sum(page_text_non_whitespace)
        empty_page_indices = [
            index
            for index, character_count in enumerate(
                page_text_non_whitespace,
                start=1,
            )
            if character_count == 0
        ]
        complete = (
            non_whitespace >= 500
            and not extraction.extraction_errors
            and not empty_page_indices
        )
        status = "ready" if complete else "incomplete"
        reason = None
        if non_whitespace < 500:
            reason = "insufficient_extractable_text"
        elif extraction.extraction_errors:
            reason = "page_extraction_errors"
        elif empty_page_indices:
            reason = "empty_text_layer_pages"
        coverage = {
            "complete": complete,
            "coverage_type": "text_layer",
            "security_status": "parsed_verified",
            "reason": reason,
            "page_count": extraction.page_count,
            "page_map": extraction.page_map,
            "page_text_non_whitespace": page_text_non_whitespace,
            "empty_page_indices": empty_page_indices,
            "extracted_non_whitespace_total": non_whitespace,
            "extraction_errors": extraction.extraction_errors,
            "parser": extraction.parser,
            "parser_receipt": extraction.receipt,
            "raw_receipt": raw_receipt,
        }
        self.audit.write(
            "paper_pdf_parse_verified",
            component="content",
            run_id=self.run_id,
            details={
                "work_id": int(work["id"]),
                "content_sha256": digest,
                "text_sha256": extraction.text_sha256,
                "page_count": extraction.page_count,
                "complete": complete,
                "reason": reason,
                "parser_receipt": extraction.receipt,
            },
        )
        return ContentResult(
            content_kind="paper_pdf",
            status=status,
            source_url=receipt.final_url,
            local_path=str(pdf_path),
            text_path=str(text_path),
            content_sha256=digest,
            text_sha256=extraction.text_sha256,
            byte_count=len(body),
            text_char_count=len(extraction.text),
            page_count=extraction.page_count,
            coverage=coverage,
            error=None if complete else f"PDF coverage incomplete: {reason}",
        )

    def _paper_incomplete_security(
        self,
        *,
        work_id: int,
        source_url: str,
        quarantine_path: Path,
        content_sha256: str,
        byte_count: int,
        raw_receipt: dict[str, Any],
        reason: str,
        failure_code: str,
        parser_receipt: dict[str, Any],
        audit_error: str | None,
    ) -> ContentResult:
        details = {
            "work_id": work_id,
            "content_sha256": content_sha256,
            "reason": reason,
            "failure_code": failure_code,
            "parser_receipt": parser_receipt,
        }
        if audit_error:
            details["audit_error"] = audit_error
        self.audit.write(
            "paper_pdf_parse_quarantined",
            component="content",
            run_id=self.run_id,
            severity="warning",
            details=details,
        )
        coverage = {
            "complete": False,
            "coverage_type": "text_layer",
            "security_status": "incomplete_security",
            "reason": reason,
            "failure_code": failure_code,
            "parser": {
                "id": "pypdf",
                "version": REQUIRED_PYPDF_VERSION,
                "policy_version": PARSER_POLICY_VERSION,
            },
            "parser_receipt": parser_receipt,
            "raw_receipt": raw_receipt,
        }
        message = (
            "PDF extraction exceeded its safety deadline and was terminated; "
            "the source remains quarantined."
            if reason == "pdf_extract_timeout"
            else (
                "The PDF was acquired but safe extraction did not complete; "
                "the source remains quarantined."
            )
        )
        return ContentResult(
            content_kind="paper_pdf",
            status="incomplete",
            source_url=source_url,
            local_path=str(quarantine_path),
            text_path=None,
            content_sha256=content_sha256,
            text_sha256=None,
            byte_count=byte_count,
            text_char_count=None,
            page_count=None,
            coverage=coverage,
            error=message,
        )

    def _repository(self, work: dict[str, Any]) -> ContentResult:
        full_name = work.get("github_full_name")
        if not full_name or "/" not in full_name:
            return self._repository_unavailable(None, "missing_github_full_name")
        metadata = json.loads(work.get("metadata_json") or "{}")
        default_branch = str(metadata.get("default_branch") or "HEAD")
        owner, repository = full_name.split("/", 1)
        branch_path = quote(default_branch, safe="/")
        url = (
            f"https://codeload.github.com/{quote(owner, safe='')}/"
            f"{quote(repository, safe='')}/zip/refs/heads/{branch_path}"
        )
        try:
            client = self.client_for_url(url)
            body, receipt, _ = client.request_bytes(
                url,
                max_bytes=int(self.config["max_repository_archive_bytes"]),
                raw_suffix="zip",
                allowed_hosts={"codeload.github.com"},
            )
            digest = sha256_bytes(body)
            base = f"repo_{work['id']}_{safe_slug(full_name, 50)}_{digest[:12]}"
            archive_path = self.settings.literature_dir / "documents" / f"{base}.zip"
            atomic_write_bytes(archive_path, body)
            result = self._read_repository_archive(body)
            text_digest = sha256_text(result["text"])
            inventory_text = json_dumps(result["inventory"], pretty=True) + "\n"
            inventory_digest = sha256_text(inventory_text)
            selection_hash = str(
                result["coverage"].get("selection_policy_hash") or ""
            )
            artifact_policy_hash = selection_hash or str(
                result["coverage"].get("inventory_sha256") or ""
            )
            text_base = (
                (
                    f"{base}_{artifact_policy_hash[:12]}_"
                    f"{text_digest[:12]}_{inventory_digest[:12]}"
                )
                if artifact_policy_hash
                else base
            )
            text_path = self.settings.literature_dir / "text" / f"{text_base}.txt"
            inventory_path = (
                self.settings.literature_dir
                / "text"
                / f"{text_base}.inventory.json"
            )
            atomic_write_text(text_path, result["text"])
            atomic_write_text(inventory_path, inventory_text)
            expected_inventory_digest = str(
                result["coverage"].get("inventory_sha256") or ""
            )
            if (
                expected_inventory_digest
                and expected_inventory_digest != inventory_digest
            ):
                raise FetchError(
                    "repository inventory serialization hash mismatch"
                )
            coverage = {
                **result["coverage"],
                "inventory_path": str(inventory_path),
                "raw_receipt": {
                    "sha256": receipt.sha256,
                    "path": receipt.path,
                    "status_code": receipt.status_code,
                    "final_url": receipt.final_url,
                },
            }
            status = "ready" if coverage["complete"] else "incomplete"
            return ContentResult(
                content_kind="repository_zip",
                status=status,
                source_url=receipt.final_url,
                local_path=str(archive_path),
                text_path=str(text_path),
                content_sha256=digest,
                text_sha256=text_digest,
                byte_count=len(body),
                text_char_count=len(result["text"]),
                page_count=None,
                coverage=coverage,
                error=None if status == "ready" else "Repository static-text coverage is incomplete.",
            )
        except RetryDeferredError:
            raise
        except Exception as exc:
            return self._repository_unavailable(
                url, f"{type(exc).__name__}: {str(exc)[:1000]}"
            )

    def _repository_unavailable(self, url: str | None, reason: str) -> ContentResult:
        return ContentResult(
            content_kind="repository_zip",
            status="unavailable",
            source_url=url,
            local_path=None,
            text_path=None,
            content_sha256=None,
            text_sha256=None,
            byte_count=None,
            text_char_count=None,
            page_count=None,
            coverage={"complete": False, "reason": "repository_fetch_or_read_error"},
            error=reason,
        )

    def _read_repository_archive(self, body: bytes) -> dict[str, Any]:
        if (
            _repository_archive_entry_count(body)
            > _MAX_REPOSITORY_ARCHIVE_FILE_COUNT
        ):
            raise FetchError("repository archive contains too many entries")
        selection = self.config.get("repository_corpus")
        if not isinstance(selection, dict):
            return self._read_repository_archive_legacy(body)
        return self._read_repository_archive_selected(body, selection)

    def _read_repository_archive_legacy(self, body: bytes) -> dict[str, Any]:
        max_total = int(self.config["max_repository_uncompressed_bytes"])
        max_text = int(self.config["max_repository_text_bytes"])
        max_single = int(self.config["max_single_text_file_bytes"])
        inventory: list[dict[str, Any]] = []
        text_parts: list[str] = []
        text_character_cursor = 0
        rendered_text_utf8_bytes = 0
        eligible_total = 0
        included_text_bytes = 0
        incomplete_reasons: list[str] = []
        total_uncompressed = 0
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            archive_infos = archive.infolist()
            if len(archive_infos) > _MAX_REPOSITORY_ARCHIVE_FILE_COUNT:
                raise FetchError("repository archive contains too many entries")
            for info in archive_infos:
                path = _safe_archive_path(info.filename)
                if info.is_dir():
                    continue
                total_uncompressed += info.file_size
                if total_uncompressed > max_total:
                    raise FetchError("repository archive exceeds uncompressed safety limit")
                mode = (info.external_attr >> 16) & 0xFFFF
                is_symlink = stat.S_ISLNK(mode)
                eligible, reason = _eligible_text_path(path)
                record: dict[str, Any] = {
                    "path": str(path),
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "eligible_text": eligible,
                    "decision": reason,
                    "included": False,
                }
                if is_symlink:
                    record["decision"] = "symlink_skipped"
                    inventory.append(record)
                    continue
                if info.file_size and info.compress_size == 0:
                    raise FetchError("repository archive contains a suspicious zero-size compressed entry")
                if info.compress_size and info.file_size / info.compress_size > 250:
                    raise FetchError("repository archive contains a suspicious compression ratio")
                if not eligible:
                    inventory.append(record)
                    continue
                lowered_parts = [part.casefold() for part in path.parts]
                is_large_generated_data = (
                    info.file_size > 131072
                    and path.suffix.casefold() in {".csv", ".json", ".jsonl", ".ndjson"}
                    and any(part in {"data", "dataset", "datasets"} for part in lowered_parts[:-1])
                )
                if is_large_generated_data:
                    record["decision"] = "generated_data_snapshot_excluded"
                    inventory.append(record)
                    continue
                eligible_total += info.file_size
                if info.file_size > max_single:
                    record["decision"] = "single_text_file_limit"
                    incomplete_reasons.append(f"oversized_text:{path}")
                    inventory.append(record)
                    continue
                if included_text_bytes + info.file_size > max_text:
                    record["decision"] = "repository_text_limit"
                    incomplete_reasons.append("repository_text_limit")
                    inventory.append(record)
                    continue
                value = archive.read(info)
                decoded, encoding = _decode_text(value)
                if decoded is None:
                    record["decision"] = encoding
                    incomplete_reasons.append(f"undecodable_text:{path}")
                    inventory.append(record)
                    continue
                separator = "" if not text_parts else "\n\n"
                evidence_anchor = f"=== FILE: {path} ==="
                rendered = (
                    f"{separator}{evidence_anchor}\n{decoded.rstrip()}\n"
                )
                rendered_bytes = len(rendered.encode("utf-8"))
                if rendered_text_utf8_bytes + rendered_bytes > max_text:
                    record["decision"] = "repository_text_limit"
                    incomplete_reasons.append("repository_text_limit")
                    inventory.append(record)
                    continue
                record["included"] = True
                record["decision"] = f"included:{encoding}"
                included_text_bytes += len(value)
                anchor_start = text_character_cursor + len(separator)
                record["evidence_anchor"] = evidence_anchor
                record["evidence_anchor_start"] = anchor_start
                record["evidence_anchor_end"] = (
                    anchor_start + len(evidence_anchor)
                )
                record["text_character_end"] = (
                    text_character_cursor + len(rendered)
                )
                text_parts.append(rendered)
                text_character_cursor += len(rendered)
                rendered_text_utf8_bytes += rendered_bytes
                inventory.append(record)
        text = "".join(text_parts) if text_parts else "\n"
        final_text_utf8_bytes = len(text.encode("utf-8"))
        if final_text_utf8_bytes > max_text:
            raise FetchError(
                "repository rendered text exceeds its safety limit"
            )
        if not text.strip():
            incomplete_reasons.append("no_eligible_text")
        complete = not incomplete_reasons
        inventory_hash = sha256_text(json_dumps(inventory, pretty=True) + "\n")
        coverage = {
            "complete": complete,
            "reason": None if complete else "static_text_coverage_limits_or_decode_failures",
            "coverage_scope": "legacy_all_eligible",
            "archive_file_count": len(inventory),
            "total_uncompressed_bytes": total_uncompressed,
            "eligible_text_bytes": eligible_total,
            "included_text_bytes": included_text_bytes,
            "final_text_utf8_bytes": final_text_utf8_bytes,
            "inventory_sha256": inventory_hash,
            "included_file_count": sum(1 for item in inventory if item["included"]),
            "trusted_anchor_count": sum(
                1
                for item in inventory
                if item.get("included") is True
                and item.get("evidence_anchor")
            ),
            "excluded_file_count": sum(1 for item in inventory if not item["included"]),
            "incomplete_reasons": sorted(set(incomplete_reasons)),
        }
        return {"text": text, "inventory": inventory, "coverage": coverage}

    def _read_repository_archive_selected(
        self,
        body: bytes,
        selection: dict[str, Any],
    ) -> dict[str, Any]:
        max_total = int(self.config["max_repository_uncompressed_bytes"])
        max_single = int(self.config["max_single_text_file_bytes"])
        max_selected = int(selection["max_selected_text_bytes"])
        max_auxiliary = int(selection["max_auxiliary_text_bytes"])
        max_core = max_selected - max_auxiliary
        policy = {
            "mode": str(selection["mode"]),
            "algorithm_version": REPOSITORY_SELECTION_ALGORITHM_VERSION,
            "max_selected_text_bytes": max_selected,
            "max_auxiliary_text_bytes": max_auxiliary,
            "max_single_text_file_bytes": max_single,
            "required_root_names": sorted(_REPOSITORY_REQUIRED_ROOT_NAMES),
            "auxiliary_directory_roles": dict(
                sorted(_REPOSITORY_AUXILIARY_DIR_ROLES.items())
            ),
            "role_scores": dict(sorted(_REPOSITORY_ROLE_SCORES.items())),
            "core_selection_strategy": "research_path_priority_round_robin_v1",
            "research_path_terms": list(_repository_research_terms(self.settings)),
            "text_extensions": sorted(_TEXT_EXTENSIONS),
            "text_names": sorted(_TEXT_NAMES),
            "excluded_directories": sorted(_EXCLUDED_DIRS),
        }
        policy_hash = sha256_text(json_dumps(policy))
        inventory: list[dict[str, Any]] = []
        candidates: list[tuple[zipfile.ZipInfo, PurePosixPath, dict[str, Any]]] = []
        total_uncompressed = 0
        eligible_total = 0
        incomplete_reasons: list[str] = []

        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            file_entries: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
            seen_archive_paths: set[str] = set()
            archive_infos = archive.infolist()
            if len(archive_infos) > _MAX_REPOSITORY_ARCHIVE_FILE_COUNT:
                raise FetchError("repository archive contains too many entries")
            for info in archive_infos:
                path = _safe_archive_path(info.filename)
                if info.is_dir():
                    continue
                archive_path_key = str(path).casefold()
                if archive_path_key in seen_archive_paths:
                    raise FetchError(
                        "repository archive contains duplicate or "
                        "case-conflicting paths"
                    )
                seen_archive_paths.add(archive_path_key)
                total_uncompressed += info.file_size
                if total_uncompressed > max_total:
                    raise FetchError(
                        "repository archive exceeds uncompressed safety limit"
                    )
                if info.file_size and info.compress_size == 0:
                    raise FetchError(
                        "repository archive contains a suspicious zero-size "
                        "compressed entry"
                    )
                if (
                    info.compress_size
                    and info.file_size / info.compress_size > 250
                ):
                    raise FetchError(
                        "repository archive contains a suspicious compression ratio"
                    )
                file_entries.append((info, path))

            first_parts = {
                path.parts[0]
                for _, path in file_entries
                if len(path.parts) > 1
            }
            root_prefix = (
                next(iter(first_parts))
                if len(first_parts) == 1
                and all(len(path.parts) > 1 for _, path in file_entries)
                else None
            )

            seen_repository_paths: set[str] = set()
            for info, path in file_entries:
                relative_path = _repository_relative_path(path, root_prefix)
                repository_path_key = str(relative_path).casefold()
                if repository_path_key in seen_repository_paths:
                    raise FetchError(
                        "repository archive contains duplicate or "
                        "case-conflicting repository paths"
                    )
                seen_repository_paths.add(repository_path_key)
                mode = (info.external_attr >> 16) & 0xFFFF
                is_symlink = stat.S_ISLNK(mode)
                eligible, reason = _eligible_text_path(path)
                marker = f"\n\n=== FILE: {relative_path} ===\n"
                rendered_size = (
                    len(marker.encode("utf-8")) + int(info.file_size) + 1
                )
                record: dict[str, Any] = {
                    "path": str(path),
                    "repository_path": str(relative_path),
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "rendered_size_budget_bytes": rendered_size,
                    "eligible_text": eligible,
                    "role": None,
                    "selection_score": 0,
                    "selection_reason": reason,
                    "decision": reason,
                    "included": False,
                }
                inventory.append(record)
                if is_symlink:
                    record["decision"] = "symlink_skipped"
                    record["selection_reason"] = "safety:symlink"
                    continue
                if not eligible:
                    continue
                lowered_parts = [part.casefold() for part in path.parts]
                is_large_generated_data = (
                    info.file_size > 131072
                    and path.suffix.casefold()
                    in {".csv", ".json", ".jsonl", ".ndjson"}
                    and any(
                        part in {"data", "dataset", "datasets"}
                        for part in lowered_parts[:-1]
                    )
                )
                if is_large_generated_data:
                    record["decision"] = "generated_data_snapshot_excluded"
                    record["selection_reason"] = (
                        "policy_excluded:generated_data_snapshot"
                    )
                    continue
                role, score, required = _repository_file_role(relative_path)
                record["role"] = role
                record["selection_score"] = score
                record["required_by_policy"] = required
                eligible_total += info.file_size
                if info.file_size > max_single:
                    record["decision"] = "single_text_file_limit"
                    record["selection_reason"] = "safety:single_text_file_limit"
                    if required:
                        incomplete_reasons.append(
                            f"required_oversized_text:{relative_path}"
                        )
                    continue
                record["selection_reason"] = (
                    f"required:{role}" if required else f"candidate:{role}"
                )
                candidates.append((info, relative_path, record))

            required_candidates = sorted(
                (item for item in candidates if item[2]["required_by_policy"]),
                key=lambda item: str(item[1]).casefold(),
            )
            research_terms = _repository_research_terms(self.settings)
            core_by_group: dict[
                str,
                list[tuple[zipfile.ZipInfo, PurePosixPath, dict[str, Any]]],
            ] = {}
            for item in candidates:
                record = item[2]
                if record["required_by_policy"] or record["role"] != "core_source":
                    continue
                group = _repository_core_group(item[1])
                core_by_group.setdefault(group, []).append(item)
            for group_candidates in core_by_group.values():
                group_candidates.sort(
                    key=lambda item: _repository_core_priority(
                        item[1], item[2], research_terms
                    )
                )
            core_group_order = sorted(
                core_by_group,
                key=lambda group: (
                    min(
                        _repository_core_priority(item[1], item[2], research_terms)
                        for item in core_by_group[group]
                    ),
                    group,
                ),
            )
            core_candidates: list[
                tuple[zipfile.ZipInfo, PurePosixPath, dict[str, Any]]
            ] = []
            while any(core_by_group.values()):
                for group in core_group_order:
                    group_candidates = core_by_group[group]
                    if group_candidates:
                        core_candidates.append(group_candidates.pop(0))
            auxiliary_by_role: dict[
                str,
                list[tuple[zipfile.ZipInfo, PurePosixPath, dict[str, Any]]],
            ] = {}
            for item in candidates:
                record = item[2]
                if record["required_by_policy"] or record["role"] == "core_source":
                    continue
                auxiliary_by_role.setdefault(str(record["role"]), []).append(item)
            for role_candidates in auxiliary_by_role.values():
                role_candidates.sort(
                    key=lambda item: (
                        int(item[2]["rendered_size_budget_bytes"]),
                        str(item[1]).casefold(),
                    )
                )
            selected: list[
                tuple[zipfile.ZipInfo, PurePosixPath, dict[str, Any]]
            ] = []
            selected_rendered_budget_bytes = 0
            core_rendered_budget_bytes = 0
            auxiliary_rendered_budget_bytes = 0

            def include_candidate(
                item: tuple[zipfile.ZipInfo, PurePosixPath, dict[str, Any]],
                *,
                corpus: str,
            ) -> bool:
                nonlocal selected_rendered_budget_bytes
                nonlocal core_rendered_budget_bytes
                nonlocal auxiliary_rendered_budget_bytes
                rendered_size = int(item[2]["rendered_size_budget_bytes"])
                if selected_rendered_budget_bytes + rendered_size > max_selected:
                    return False
                if corpus == "core":
                    if core_rendered_budget_bytes + rendered_size > max_core:
                        return False
                    core_rendered_budget_bytes += rendered_size
                else:
                    if (
                        auxiliary_rendered_budget_bytes + rendered_size
                        > max_auxiliary
                    ):
                        return False
                    auxiliary_rendered_budget_bytes += rendered_size
                selected_rendered_budget_bytes += rendered_size
                selected.append(item)
                return True

            for item in required_candidates:
                _, relative_path, record = item
                if not include_candidate(item, corpus="core"):
                    record["decision"] = "required_corpus_limit"
                    record["selection_reason"] = (
                        "required_excluded:selected_corpus_budget"
                    )
                    incomplete_reasons.append(
                        f"required_corpus_limit:{relative_path}"
                    )
            for item in core_candidates:
                if not include_candidate(item, corpus="core"):
                    record = item[2]
                    record["decision"] = "policy_core_budget"
                    record["selection_reason"] = (
                        "policy_excluded:core_source:core_budget"
                    )

            role_order = sorted(
                auxiliary_by_role,
                key=lambda role: (
                    -int(_REPOSITORY_ROLE_SCORES.get(role, 0)),
                    role,
                ),
            )
            if role_order:
                fair_share = max_auxiliary // len(role_order)
                for role in role_order:
                    role_candidates = auxiliary_by_role[role]
                    representative_index = next(
                        (
                            index
                            for index, item in enumerate(role_candidates)
                            if int(item[2]["rendered_size_budget_bytes"])
                            <= fair_share
                        ),
                        None,
                    )
                    if representative_index is None:
                        continue
                    representative = role_candidates.pop(representative_index)
                    if not include_candidate(
                        representative,
                        corpus="auxiliary",
                    ):
                        record = representative[2]
                        record["decision"] = "policy_auxiliary_budget"
                        record["selection_reason"] = (
                            f"policy_excluded:{record['role']}:"
                            "auxiliary_budget"
                        )

                while any(auxiliary_by_role.values()):
                    made_progress = False
                    for role in role_order:
                        role_candidates = auxiliary_by_role[role]
                        if not role_candidates:
                            continue
                        item = role_candidates.pop(0)
                        made_progress = True
                        if include_candidate(item, corpus="auxiliary"):
                            continue
                        record = item[2]
                        record["decision"] = "policy_auxiliary_budget"
                        record["selection_reason"] = (
                            f"policy_excluded:{record['role']}:"
                            "auxiliary_budget"
                        )
                    if not made_progress:
                        break

            for role_candidates in auxiliary_by_role.values():
                for item in role_candidates:
                    record = item[2]
                    record["decision"] = "policy_auxiliary_budget"
                    record["selection_reason"] = (
                        f"policy_excluded:{record['role']}:auxiliary_budget"
                    )

            text_parts: list[str] = []
            text_character_cursor = 0
            included_text_bytes = 0
            required_text_bytes = 0
            core_text_bytes = 0
            auxiliary_text_bytes = 0
            for info, relative_path, record in sorted(
                selected,
                key=lambda item: str(item[1]).casefold(),
            ):
                value = archive.read(info)
                decoded, encoding = _decode_text(value)
                if decoded is None:
                    record["decision"] = encoding
                    record["selection_reason"] = f"decode_failed:{encoding}"
                    incomplete_reasons.append(
                        f"selected_undecodable_text:{relative_path}"
                    )
                    continue
                record["included"] = True
                record["decision"] = f"included:{encoding}"
                record["selection_reason"] = (
                    f"selected:{record['role']}:"
                    + (
                        "required"
                        if record["required_by_policy"]
                        else "sampled_within_budget"
                    )
                )
                included_text_bytes += len(value)
                if record["required_by_policy"]:
                    required_text_bytes += len(value)
                elif record["role"] == "core_source":
                    core_text_bytes += len(value)
                else:
                    auxiliary_text_bytes += len(value)
                separator = "" if not text_parts else "\n\n"
                evidence_anchor = f"=== FILE: {relative_path} ==="
                rendered = (
                    f"{separator}{evidence_anchor}\n{decoded.rstrip()}\n"
                )
                anchor_start = text_character_cursor + len(separator)
                record["evidence_anchor"] = evidence_anchor
                record["evidence_anchor_start"] = anchor_start
                record["evidence_anchor_end"] = (
                    anchor_start + len(evidence_anchor)
                )
                record["text_character_end"] = (
                    text_character_cursor + len(rendered)
                )
                text_parts.append(rendered)
                text_character_cursor += len(rendered)

        text = "".join(text_parts) if text_parts else "\n"
        final_text_utf8_bytes = len(text.encode("utf-8"))
        if final_text_utf8_bytes > max_selected:
            raise FetchError(
                "selected repository corpus exceeds its rendered text budget"
            )
        if not text.strip():
            incomplete_reasons.append("no_selected_text")
        complete = not incomplete_reasons
        inventory.sort(
            key=lambda item: str(item.get("repository_path") or item["path"]).casefold()
        )
        inventory_hash = sha256_text(json_dumps(inventory, pretty=True) + "\n")
        coverage = {
            "complete": complete,
            "reason": (
                None
                if complete
                else "selected_repository_corpus_required_coverage_incomplete"
            ),
            "coverage_scope": "selected_repository_corpus",
            "selection_policy_id": str(selection["mode"]),
            "selection_algorithm_version": (
                REPOSITORY_SELECTION_ALGORITHM_VERSION
            ),
            "selection_policy_hash": policy_hash,
            "selection_policy": policy,
            "inventory_sha256": inventory_hash,
            "archive_root_prefix": root_prefix,
            "archive_file_count": len(inventory),
            "total_uncompressed_bytes": total_uncompressed,
            "eligible_text_bytes": eligible_total,
            "selected_rendered_budget_bytes": (
                selected_rendered_budget_bytes
            ),
            "core_rendered_budget_bytes": core_rendered_budget_bytes,
            "auxiliary_rendered_budget_bytes": (
                auxiliary_rendered_budget_bytes
            ),
            "final_text_utf8_bytes": final_text_utf8_bytes,
            "included_text_bytes": included_text_bytes,
            "required_text_bytes": required_text_bytes,
            "core_text_bytes": core_text_bytes,
            "auxiliary_text_bytes": auxiliary_text_bytes,
            "included_file_count": sum(
                1 for item in inventory if item["included"]
            ),
            "trusted_anchor_count": sum(
                1
                for item in inventory
                if item.get("included") is True
                and item.get("evidence_anchor")
            ),
            "excluded_file_count": sum(
                1 for item in inventory if not item["included"]
            ),
            "incomplete_reasons": sorted(set(incomplete_reasons)),
        }
        return {"text": text, "inventory": inventory, "coverage": coverage}
