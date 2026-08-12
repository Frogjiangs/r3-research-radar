from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from r3radar.config import load_settings
from r3radar.evidence import (
    EvidenceExcerptError,
    canonicalize_evidence_excerpt,
    evidence_anchor_region,
)
from r3radar.utils import atomic_write_text, json_dumps, sha256_text, utc_now


_REQUEUEABLE_EVIDENCE_FAILURES = {
    "anchor_absent_from_chunk",
    "anchor_ambiguous",
    "excerpt_absent",
    "excerpt_ambiguous",
    "excerpt_too_long",
    "excerpt_unmappable",
    "unverifiable_anchor",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _column_digest(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    key_column: str = "id",
) -> str:
    digest = hashlib.sha256()
    for row in connection.execute(
        f"SELECT {key_column}, {column} FROM {table} ORDER BY {key_column}"  # noqa: S608
    ):
        digest.update(str(row[0]).encode("ascii"))
        digest.update(b"\0")
        if row[1] is None:
            digest.update(b"N")
        else:
            payload = str(row[1]).encode("utf-8")
            digest.update(b"V")
            digest.update(str(len(payload)).encode("ascii"))
            digest.update(b":")
            digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def _receipt_digests(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        "analysis_chunks.provider_receipt_json": _column_digest(
            connection, "analysis_chunks", "provider_receipt_json"
        ),
        "analysis_synthesis_nodes.provider_receipt_json": _column_digest(
            connection, "analysis_synthesis_nodes", "provider_receipt_json"
        ),
        "analyses.provider_receipt_json": _column_digest(
            connection, "analyses", "provider_receipt_json"
        ),
        "model_invocations.receipt_json": _column_digest(
            connection,
            "model_invocations",
            "receipt_json",
            key_column="invocation_id",
        ),
    }


def _active_state(connection: sqlite3.Connection) -> dict[str, int]:
    queries = {
        "running_runs": """
            SELECT COUNT(*) FROM runs
            WHERE status='running' OR lease_token IS NOT NULL
        """,
        "query_claims": """
            SELECT COUNT(*) FROM query_jobs
            WHERE status='running' OR claim_lease_token IS NOT NULL
        """,
        "verification_claims": """
            SELECT COUNT(*) FROM verification_tasks
            WHERE status='running' OR claim_lease_token IS NOT NULL
        """,
        "analysis_claims": """
            SELECT COUNT(*) FROM analysis_tasks
            WHERE status='running' OR claim_lease_token IS NOT NULL
        """,
        "scope_claims": """
            SELECT COUNT(*) FROM work_scopes
            WHERE state IN ('content_running','analysis_running')
               OR active_lease_token IS NOT NULL
        """,
    }
    return {
        name: int(connection.execute(sql).fetchone()[0])
        for name, sql in queries.items()
    }


def _project_chunk(
    row: sqlite3.Row,
    text_cache: dict[str, str],
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    detail: dict[str, Any] = {
        "chunk_id": int(row["chunk_id"]),
        "task_id": int(row["task_id"]),
        "work_id": int(row["work_id"]),
        "chunk_index": int(row["chunk_index"]),
    }
    try:
        text_path = str(row["text_path"] or "")
        if text_path not in text_cache:
            # Match the production deep-reader exactly. Path.read_text() enables
            # universal-newline translation and would change CRLF-bound hashes.
            text_cache[text_path] = Path(text_path).read_bytes().decode("utf-8")
        document_text = text_cache[text_path]
        if sha256_text(document_text) != str(row["text_sha256"]):
            raise ValueError("document_text_sha_mismatch")
        if str(row["task_input_sha256"]) != str(row["text_sha256"]):
            raise ValueError("analysis_input_revision_mismatch")

        span = json.loads(row["span_json"])
        start = int(span["character_start"])
        end = int(span["character_end"])
        chunk_text = document_text[start:end]
        if sha256_text(chunk_text) != str(row["chunk_input_sha256"]):
            raise ValueError("chunk_input_sha_mismatch")

        output = json.loads(row["output_json"])
        if not isinstance(output, dict):
            raise ValueError("chunk_output_not_object")
        evidence_items = output.get("evidence")
        if not isinstance(evidence_items, list) or not evidence_items:
            raise ValueError("chunk_evidence_missing")

        span_anchors = [
            str(value).strip()
            for value in span.get("anchors") or []
            if str(value).strip()
        ]
        character_anchor = f"characters:{start}-{end}"
        allowed_anchors = {*span_anchors, character_anchor}
        projected: list[dict[str, Any]] = []
        match_counts: dict[str, int] = {}
        for evidence in evidence_items:
            if not isinstance(evidence, dict):
                raise ValueError("evidence_item_not_object")
            anchor = str(evidence.get("anchor") or "").strip()
            if anchor not in allowed_anchors:
                raise ValueError("unverifiable_anchor")
            model_excerpt = str(
                evidence.get("model_excerpt", evidence.get("excerpt") or "")
            )
            anchor_text = evidence_anchor_region(
                chunk_text,
                anchor,
                [*span_anchors, character_anchor],
            )
            canonical = canonicalize_evidence_excerpt(model_excerpt, anchor_text)
            item = dict(evidence)
            item["anchor"] = anchor
            item["excerpt"] = canonical.excerpt
            item["model_excerpt"] = canonical.model_excerpt
            item["excerpt_match_method"] = canonical.match_method
            item["excerpt_provenance"] = canonical.provenance
            projected.append(item)
            match_counts[canonical.match_method] = (
                match_counts.get(canonical.match_method, 0) + 1
            )

        repaired = dict(output)
        repaired["evidence"] = projected
        detail["changed"] = repaired != output
        detail["evidence_count"] = len(projected)
        detail["match_counts"] = match_counts
        return repaired, detail
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        reason = exc.reason if isinstance(exc, EvidenceExcerptError) else str(exc)
        detail["failure"] = reason or type(exc).__name__
        return None, detail


def _scan(connection: sqlite3.Connection) -> tuple[list[tuple[int, str]], dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT
            chunk.id AS chunk_id,
            chunk.task_id,
            chunk.chunk_index,
            chunk.span_json,
            chunk.input_sha256 AS chunk_input_sha256,
            chunk.output_json,
            task.work_id,
            task.input_sha256 AS task_input_sha256,
            document.text_path,
            document.text_sha256
        FROM analysis_chunks AS chunk
        JOIN analysis_tasks AS task ON task.id=chunk.task_id
        JOIN documents AS document ON document.id=task.document_id
        WHERE chunk.status='completed'
          AND task.status IN ('completed','pending','retry','running')
        ORDER BY chunk.id
        """
    ).fetchall()
    updates: list[tuple[int, str]] = []
    failures: list[dict[str, Any]] = []
    match_counts: dict[str, int] = {}
    evidence_total = 0
    unchanged_chunks = 0
    text_cache: dict[str, str] = {}
    for row in rows:
        repaired, detail = _project_chunk(row, text_cache)
        if repaired is None:
            failures.append(detail)
            continue
        evidence_total += int(detail["evidence_count"])
        for method, count in detail["match_counts"].items():
            match_counts[method] = match_counts.get(method, 0) + int(count)
        if detail["changed"]:
            updates.append((int(row["chunk_id"]), json_dumps(repaired)))
        else:
            unchanged_chunks += 1
    blocking_failures = [
        failure
        for failure in failures
        if failure.get("failure") not in _REQUEUEABLE_EVIDENCE_FAILURES
    ]
    requeue_task_ids = sorted(
        {
            int(failure["task_id"])
            for failure in failures
            if failure.get("failure") in _REQUEUEABLE_EVIDENCE_FAILURES
        }
    )
    invalidated_status_ids = [
        int(row[0])
        for row in connection.execute(
            """
            SELECT id FROM analyses
            WHERE provenance_status LIKE 'invalidated_%'
              AND deep_read_status='complete'
            ORDER BY id
            """
        )
    ]
    summary = {
        "completed_chunks_scanned": len(rows),
        "evidence_items_scanned": evidence_total,
        "chunks_to_update": len(updates),
        "update_chunk_ids_sha256": sha256_text(
            ",".join(str(chunk_id) for chunk_id, _ in updates)
        ),
        "unchanged_chunks": unchanged_chunks,
        "match_counts": match_counts,
        "failure_count": len(failures),
        "failures": failures,
        "blocking_failure_count": len(blocking_failures),
        "blocking_failures": blocking_failures,
        "requeue_task_count": len(requeue_task_ids),
        "requeue_task_ids": requeue_task_ids,
        "invalidated_analysis_status_ids": invalidated_status_ids,
    }
    return updates, summary


def _requeue_invalid_tasks(
    connection: sqlite3.Connection,
    scan: dict[str, Any],
) -> dict[str, Any]:
    timestamp = utc_now()
    failures = [
        failure
        for failure in scan["failures"]
        if failure.get("failure") in _REQUEUEABLE_EVIDENCE_FAILURES
    ]
    failures_by_task: dict[int, list[dict[str, Any]]] = {}
    for failure in failures:
        failures_by_task.setdefault(int(failure["task_id"]), []).append(failure)
    invalidated_analysis_ids_from_scan = [
        int(value) for value in scan["invalidated_analysis_status_ids"]
    ]
    invalidated_task_ids: set[int] = set()
    if invalidated_analysis_ids_from_scan:
        placeholders = ",".join("?" for _ in invalidated_analysis_ids_from_scan)
        invalidated_task_ids = {
            int(row["task_id"])
            for row in connection.execute(
                f"""
                SELECT DISTINCT task_id
                FROM analyses
                WHERE id IN ({placeholders})
                """,
                invalidated_analysis_ids_from_scan,
            )
        }
    target_task_ids = sorted(set(failures_by_task) | invalidated_task_ids)

    invalidated_analysis_ids: list[int] = []
    requeued_work_ids: list[int] = []
    for task_id in target_task_ids:
        task_failures = failures_by_task.get(task_id, [])
        for failure in task_failures:
            connection.execute(
                """
                UPDATE analysis_chunks
                SET status='pending', error=?
                WHERE id=? AND task_id=?
                """,
                (
                    "strict anchor/excerpt repair required: "
                    + str(failure["failure"]),
                    int(failure["chunk_id"]),
                    task_id,
                ),
            )
        completed = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM analysis_chunks
                WHERE task_id=? AND status='completed'
                """,
                (task_id,),
            ).fetchone()[0]
        )
        task = connection.execute(
            """
            SELECT work_id, retrieval_hash FROM analysis_tasks
            WHERE id=? AND status IN ('completed','pending','retry')
            """,
            (task_id,),
        ).fetchone()
        if task is None or not task["retrieval_hash"]:
            raise RuntimeError(
                f"invalidated analysis task {task_id} lost its immutable scope"
            )
        connection.execute(
            """
            UPDATE analysis_tasks
            SET status='pending', chunk_done=?, attempts=0,
                completed_at=NULL, error=?, not_before=NULL,
                claimed_run_id=NULL, claim_lease_token=NULL, updated_at=?
            WHERE id=?
            """,
            (
                completed,
                (
                    f"strict anchor/excerpt repair requeued "
                    f"{len(task_failures)} chunk(s)"
                    if task_failures
                    else "strict anchor/excerpt repair requires reanalysis"
                ),
                timestamp,
                task_id,
            ),
        )
        analysis_rows = connection.execute(
            "SELECT id FROM analyses WHERE task_id=?",
            (task_id,),
        ).fetchall()
        invalidated_analysis_ids.extend(int(row["id"]) for row in analysis_rows)
        connection.execute(
            """
            UPDATE analyses
            SET provenance_status='invalidated_strict_anchor_excerpt',
                deep_read_status='invalidated'
            WHERE task_id=?
            """,
            (task_id,),
        )
        connection.execute(
            """
            UPDATE work_scopes
            SET state='analysis_pending', not_before=NULL,
                last_error=?, active_run_id=NULL, active_lease_token=NULL,
                last_seen_at=?
            WHERE work_id=? AND config_hash=?
            """,
            (
                "strict anchor/excerpt repair requires reanalysis",
                timestamp,
                int(task["work_id"]),
                str(task["retrieval_hash"]),
            ),
        )
        connection.execute(
            "UPDATE works SET state='analysis_pending', updated_at=? WHERE id=?",
            (timestamp, int(task["work_id"])),
        )
        requeued_work_ids.append(int(task["work_id"]))
    return {
        "requeued_task_ids": target_task_ids,
        "requeued_work_ids": sorted(set(requeued_work_ids)),
        "invalidated_analysis_ids": sorted(set(invalidated_analysis_ids)),
        "requeued_chunk_ids": sorted(int(item["chunk_id"]) for item in failures),
    }


def _connect(path: Path, *, read_only: bool) -> sqlite3.Connection:
    if not path.is_file():
        raise FileNotFoundError(f"database does not exist: {path}")
    if read_only:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    else:
        connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit and canonically project stored R3 evidence excerpts."
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup")
    parser.add_argument("--receipt")
    arguments = parser.parse_args()

    if arguments.apply and (not arguments.backup or not arguments.receipt):
        parser.error("--apply requires both --backup and --receipt")
    if not arguments.apply and (arguments.backup or arguments.receipt):
        parser.error("--backup and --receipt are valid only with --apply")

    settings = load_settings(arguments.config)
    database_path = settings.database_path.resolve()
    connection = _connect(database_path, read_only=not arguments.apply)
    try:
        if arguments.apply:
            connection.execute("BEGIN IMMEDIATE")
        else:
            connection.execute("BEGIN")
        active = _active_state(connection)
        if any(active.values()):
            if arguments.apply:
                connection.rollback()
            raise RuntimeError(f"active pipeline state blocks evidence repair: {active}")

        integrity_before = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        fk_before = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        if integrity_before != "ok" or fk_before:
            if arguments.apply:
                connection.rollback()
            raise RuntimeError(
                f"database preflight failed: integrity={integrity_before}, fk={fk_before}"
            )

        receipt_digests_before = _receipt_digests(connection)
        triggers_before = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name"
            )
        ]
        updates, scan = _scan(connection)
        receipt: dict[str, Any] = {
            "schema": "r3/evidence-excerpt-repair/v1",
            "generated_at": utc_now(),
            "mode": "apply" if arguments.apply else "dry_run",
            "database_path": str(database_path),
            "active_state": active,
            "integrity_before": integrity_before,
            "foreign_key_violations_before": fk_before,
            "provider_receipt_digests_before": receipt_digests_before,
            "database_triggers_before": triggers_before,
            "scan": scan,
        }
        if scan["blocking_failure_count"]:
            if arguments.apply:
                connection.rollback()
            receipt["status"] = "blocked_unrepairable_evidence"
            print(json_dumps(receipt, pretty=True))
            return 2

        if not arguments.apply:
            receipt["status"] = (
                "dry_run_pass_with_requeue"
                if (
                    scan["requeue_task_count"]
                    or scan["invalidated_analysis_status_ids"]
                )
                else "dry_run_pass"
            )
            print(json_dumps(receipt, pretty=True))
            return 0

        backup_path = Path(arguments.backup).resolve()
        receipt_path = Path(arguments.receipt).resolve()
        if backup_path == receipt_path:
            connection.rollback()
            raise ValueError("backup and receipt targets must be different")
        if backup_path.exists() or receipt_path.exists():
            connection.rollback()
            raise FileExistsError("backup and receipt targets must not already exist")
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        backup_source = _connect(database_path, read_only=True)
        backup_connection = sqlite3.connect(str(backup_path))
        try:
            # The writer connection intentionally holds BEGIN IMMEDIATE so no
            # writer can enter between backup and repair. Backing up from that
            # same connection self-locks in Python sqlite3, so use a separate
            # read-only source connection on the same locked snapshot.
            backup_source.backup(backup_connection)
        finally:
            backup_connection.close()
            backup_source.close()

        connection.executemany(
            "UPDATE analysis_chunks SET output_json=? WHERE id=?",
            [(output_json, chunk_id) for chunk_id, output_json in updates],
        )
        requeue = _requeue_invalid_tasks(connection, scan)
        connection.executemany(
            "UPDATE analyses SET deep_read_status='invalidated' WHERE id=?",
            [(analysis_id,) for analysis_id in scan["invalidated_analysis_status_ids"]],
        )
        integrity_after = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        fk_after = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        receipt_digests_after = _receipt_digests(connection)
        if (
            integrity_after != "ok"
            or fk_after
            or receipt_digests_after != receipt_digests_before
        ):
            connection.rollback()
            raise RuntimeError(
                "pre-commit repair verification failed; database was rolled back"
            )
        connection.commit()
        integrity_committed = str(
            connection.execute("PRAGMA integrity_check").fetchone()[0]
        )
        fk_committed = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        if integrity_committed != "ok" or fk_committed:
            raise RuntimeError(
                "post-commit verification failed; restore from the recorded backup"
            )
        receipt.update(
            {
                "status": "applied",
                "updated_chunks": len(updates),
                "normalized_invalidated_analysis_statuses": len(
                    scan["invalidated_analysis_status_ids"]
                ),
                "requeue": requeue,
                "backup_path": str(backup_path),
                "backup_sha256": _sha256_file(backup_path),
                "integrity_after": integrity_committed,
                "foreign_key_violations_after": fk_committed,
                "provider_receipt_digests_after": receipt_digests_after,
                "provider_receipts_unchanged": True,
            }
        )
        atomic_write_text(receipt_path, json_dumps(receipt, pretty=True))
        print(json_dumps(receipt, pretty=True))
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
