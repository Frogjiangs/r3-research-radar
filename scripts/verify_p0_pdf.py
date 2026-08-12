from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from r3radar.config import load_settings  # noqa: E402
from r3radar.document_policy import (  # noqa: E402
    CURRENT_PDF_DOCUMENT_POLICY,
    CURRENT_PDF_DOCUMENT_POLICY_HASH,
    pdf_ready_coverage_matches_current_policy,
)
from r3radar.pdf_parser import parse_pdf_with_worker  # noqa: E402
from r3radar.storage import SCHEMA_VERSION  # noqa: E402


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _database_checks(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(
        f"{database.resolve().as_uri()}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_violations = len(
            connection.execute("PRAGMA foreign_key_check").fetchall()
        )
        status_rows = connection.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM documents
            WHERE content_kind='paper_pdf'
            GROUP BY status
            ORDER BY status
            """
        ).fetchall()
        documents = connection.execute(
            """
            SELECT status, local_path, text_path, content_sha256, text_sha256,
                   document_policy_hash, coverage_json
            FROM documents
            WHERE content_kind='paper_pdf'
            ORDER BY id
            """
        ).fetchall()
        schema_version_row = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        observation_count = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM document_processing_observations
                WHERE content_kind='paper_pdf'
                """
            ).fetchone()[0]
        )
    finally:
        connection.close()

    missing_artifacts = 0
    hash_mismatches = 0
    parser_receipts = 0
    current_policy_ready = 0
    stale_policy_ready = 0
    for row in documents:
        try:
            coverage = json.loads(row["coverage_json"] or "{}")
        except json.JSONDecodeError:
            coverage = {}
        if isinstance(coverage, dict) and isinstance(
            coverage.get("parser_receipt"),
            dict,
        ):
            parser_receipts += 1
        if row["status"] == "ready":
            if (
                row["document_policy_hash"]
                == CURRENT_PDF_DOCUMENT_POLICY_HASH
                and pdf_ready_coverage_matches_current_policy(coverage)
            ):
                current_policy_ready += 1
            else:
                stale_policy_ready += 1
        for path_key, hash_key in (
            ("local_path", "content_sha256"),
            ("text_path", "text_sha256"),
        ):
            raw_path = row[path_key]
            expected = row[hash_key]
            if not raw_path or not expected:
                continue
            artifact = Path(str(raw_path))
            if not artifact.is_file():
                missing_artifacts += 1
                continue
            if _sha256_file(artifact) != str(expected):
                hash_mismatches += 1

    return {
        "integrity_check": integrity,
        "foreign_key_violations": foreign_key_violations,
        "schema_version": (
            int(schema_version_row[0])
            if schema_version_row is not None
            else None
        ),
        "paper_pdf_statuses": {
            str(row["status"]): int(row["count"]) for row in status_rows
        },
        "paper_pdf_total": len(documents),
        "parser_receipt_present": parser_receipts,
        "legacy_without_parser_receipt": len(documents) - parser_receipts,
        "current_policy_ready": current_policy_ready,
        "stale_policy_ready": stale_policy_ready,
        "processing_observation_count": observation_count,
        "missing_artifacts": missing_artifacts,
        "hash_mismatches": hash_mismatches,
    }


def _pdf_canary(pdf_path: Path, config: dict[str, Any]) -> dict[str, Any]:
    byte_count = pdf_path.stat().st_size
    content_sha256 = _sha256_file(pdf_path)
    started = time.monotonic()
    extraction = parse_pdf_with_worker(
        pdf_path,
        expected_sha256=content_sha256,
        expected_byte_count=byte_count,
        config=config,
    )
    duration_ms = round((time.monotonic() - started) * 1000)
    empty_pages = [
        index
        for index, count in enumerate(
            extraction.page_text_non_whitespace,
            start=1,
        )
        if count == 0
    ]
    return {
        "file_name": pdf_path.name,
        "content_sha256": content_sha256,
        "byte_count": byte_count,
        "page_count": extraction.page_count,
        "text_sha256": extraction.text_sha256,
        "text_character_count": len(extraction.text),
        "non_whitespace_total": sum(extraction.page_text_non_whitespace),
        "empty_page_indices": empty_pages,
        "extraction_error_count": len(extraction.extraction_errors),
        "duration_ms": duration_ms,
        "parser": extraction.parser,
        "receipt": extraction.receipt,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--database")
    parser.add_argument("--pdf", required=True)
    parser.add_argument("--output")
    arguments = parser.parse_args()

    settings = load_settings(arguments.config)
    database = Path(arguments.database or settings.database_path).resolve(strict=True)
    pdf_path = Path(arguments.pdf).resolve(strict=True)
    payload = {
        "schema_version": "r3/p0-pdf-verification/v1",
        "generated_at_unix": int(time.time()),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "pypdf": importlib.metadata.version("pypdf"),
            "typing_extensions": importlib.metadata.version(
                "typing_extensions"
            ),
        },
        "document_policy": {
            "hash": CURRENT_PDF_DOCUMENT_POLICY_HASH,
            "manifest": CURRENT_PDF_DOCUMENT_POLICY,
        },
        "database": _database_checks(database),
        "pdf_canary": _pdf_canary(pdf_path, settings.raw["pdf_parser"]),
    }
    payload["checks"] = {
        "database_integrity": payload["database"]["integrity_check"] == "ok",
        "foreign_keys": payload["database"]["foreign_key_violations"] == 0,
        "database_schema": (
            payload["database"]["schema_version"] == SCHEMA_VERSION
        ),
        "no_stale_ready_pdf": (
            payload["database"]["stale_policy_ready"] == 0
        ),
        "current_artifact_hashes": (
            payload["database"]["missing_artifacts"] == 0
            and payload["database"]["hash_mismatches"] == 0
        ),
        "canary_worker_exit": payload["pdf_canary"]["receipt"]["return_code"] == 0,
        "canary_low_integrity": (
            payload["pdf_canary"]["parser"]["isolation"]["integrity_level"]
            == "appcontainer_low"
        ),
        "canary_credentials_absent": (
            payload["pdf_canary"]["parser"]["isolation"][
                "credential_environment_keys"
            ]
            == []
        ),
        "canary_appcontainer": (
            payload["pdf_canary"]["receipt"]["sandbox"]["container"]
            == "appcontainer"
            and payload["pdf_canary"]["receipt"]["sandbox"][
                "capability_count"
            ]
            == 0
            and payload["pdf_canary"]["receipt"]["sandbox"][
                "network_capability"
            ]
            is False
            and payload["pdf_canary"]["receipt"]["sandbox"][
                "dedicated_runtime"
            ]
            is True
        ),
        "canary_policy_code_identity": (
            payload["pdf_canary"]["receipt"]["worker_sha256"]
            == CURRENT_PDF_DOCUMENT_POLICY["code"]["worker_sha256"]
            and payload["pdf_canary"]["receipt"]["sandbox_sha256"]
            == CURRENT_PDF_DOCUMENT_POLICY["code"]["sandbox_sha256"]
        ),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if arguments.output:
        destination = Path(arguments.output).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(encoded, encoding="utf-8", newline="\n")
        os.replace(temporary, destination)
    print(encoded, end="")
    return 0 if all(payload["checks"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
