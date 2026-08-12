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

from r3radar.config import analysis_schema_policy_record, load_settings
from r3radar.storage import RadarStore
from r3radar.utils import atomic_write_text, json_dumps, utc_now


EXPECTED_POLICY_SHA256 = (
    "4d8ce922956a8550f61d8ca2cbcd70d9339ba597c056b3090f80647b97a79f00"
)
TARGET_WORK_IDS = (13, 14)
TARGET_TASK_IDS = (12, 13)


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
    *,
    key_column: str = "id",
) -> str:
    digest = hashlib.sha256()
    for row in connection.execute(
        f"SELECT {key_column}, {column} FROM {table} ORDER BY {key_column}"  # noqa: S608
    ):
        digest.update(str(row[0]).encode("utf-8"))
        digest.update(b"\0")
        payload = None if row[1] is None else str(row[1]).encode("utf-8")
        if payload is None:
            digest.update(b"N")
        else:
            digest.update(b"V")
            digest.update(str(len(payload)).encode("ascii"))
            digest.update(b":")
            digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def _immutable_digests(connection: sqlite3.Connection) -> dict[str, str]:
    return {
        "analysis_chunks.output_json": _column_digest(
            connection,
            "analysis_chunks",
            "output_json",
        ),
        "analysis_chunks.provider_receipt_json": _column_digest(
            connection,
            "analysis_chunks",
            "provider_receipt_json",
        ),
        "analysis_synthesis_nodes.output_json": _column_digest(
            connection,
            "analysis_synthesis_nodes",
            "output_json",
        ),
        "analysis_synthesis_nodes.provider_receipt_json": _column_digest(
            connection,
            "analysis_synthesis_nodes",
            "provider_receipt_json",
        ),
        "analyses.provider_receipt_json": _column_digest(
            connection,
            "analyses",
            "provider_receipt_json",
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
               OR claimed_run_id IS NOT NULL
        """,
        "scope_claims": """
            SELECT COUNT(*) FROM work_scopes
            WHERE state IN ('content_running','analysis_running')
               OR active_lease_token IS NOT NULL
               OR active_run_id IS NOT NULL
        """,
    }
    return {
        name: int(connection.execute(sql).fetchone()[0])
        for name, sql in queries.items()
    }


def _snapshot(connection: sqlite3.Connection) -> dict[str, Any]:
    connection.row_factory = sqlite3.Row
    task_rows = [
        dict(row)
        for row in connection.execute(
            """
            SELECT id, work_id, status, attempts, chunk_done, chunk_total,
                   config_hash, prompt_version, claimed_run_id, claim_lease_token
            FROM analysis_tasks
            WHERE id IN (?, ?)
            ORDER BY id
            """,
            TARGET_TASK_IDS,
        )
    ]
    chunk_rows = [
        dict(row)
        for row in connection.execute(
            """
            SELECT task_id, status, COUNT(*) AS count,
                   SUM(output_json IS NOT NULL) AS output_count,
                   SUM(provider_receipt_json IS NOT NULL) AS receipt_count
            FROM analysis_chunks
            WHERE task_id IN (?, ?)
            GROUP BY task_id, status
            ORDER BY task_id, status
            """,
            TARGET_TASK_IDS,
        )
    ]
    return {
        "active_state": _active_state(connection),
        "integrity": str(connection.execute("PRAGMA integrity_check").fetchone()[0]),
        "foreign_key_violations": len(
            connection.execute("PRAGMA foreign_key_check").fetchall()
        ),
        "tasks": task_rows,
        "chunks": chunk_rows,
        "synthesis_node_count": int(
            connection.execute(
                """
                SELECT COUNT(*) FROM analysis_synthesis_nodes
                WHERE task_id IN (?, ?)
                """,
                TARGET_TASK_IDS,
            ).fetchone()[0]
        ),
        "task_policy_counts": [
            dict(row)
            for row in connection.execute(
                """
                SELECT config_hash, COUNT(*) AS count
                FROM analysis_tasks GROUP BY config_hash ORDER BY config_hash
                """
            )
        ],
        "analysis_policy_counts": [
            dict(row)
            for row in connection.execute(
                """
                SELECT config_hash, COUNT(*) AS count
                FROM analyses GROUP BY config_hash ORDER BY config_hash
                """
            )
        ],
        "unexpected_prompt_count": int(
            connection.execute(
                """
                SELECT COUNT(*) FROM analysis_tasks
                WHERE prompt_version NOT LIKE ?
                """,
                (f"r3-deep-read-v4@{EXPECTED_POLICY_SHA256[:16]}@%",),
            ).fetchone()[0]
        ),
        "immutable_digests": _immutable_digests(connection),
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


def _validate_before(snapshot: dict[str, Any]) -> None:
    if any(snapshot["active_state"].values()):
        raise RuntimeError(f"active pipeline state blocks requeue: {snapshot['active_state']}")
    if snapshot["integrity"] != "ok" or snapshot["foreign_key_violations"]:
        raise RuntimeError("database integrity preflight failed")
    if snapshot["synthesis_node_count"] != 0:
        raise RuntimeError("target tasks unexpectedly contain synthesis nodes")
    if snapshot["unexpected_prompt_count"] != 0:
        raise RuntimeError("analysis task prompt policy prefix drifted")
    if snapshot["task_policy_counts"] != [
        {"config_hash": EXPECTED_POLICY_SHA256, "count": 318}
    ]:
        raise RuntimeError("analysis task policy population drifted")
    if snapshot["analysis_policy_counts"] != [
        {"config_hash": EXPECTED_POLICY_SHA256, "count": 31}
    ]:
        raise RuntimeError("analysis result policy population drifted")
    expected_tasks = [
        (12, 13, "failed", 24, 24),
        (13, 14, "failed", 27, 27),
    ]
    actual_tasks = [
        (
            int(row["id"]),
            int(row["work_id"]),
            str(row["status"]),
            int(row["chunk_done"]),
            int(row["chunk_total"]),
        )
        for row in snapshot["tasks"]
    ]
    if actual_tasks != expected_tasks:
        raise RuntimeError(f"target task state drifted: {actual_tasks}")
    if sum(int(row["count"]) for row in snapshot["chunks"]) != 51:
        raise RuntimeError("target chunk count drifted")
    if any(
        row["status"] != "completed"
        or int(row["count"]) != int(row["output_count"])
        or int(row["count"]) != int(row["receipt_count"])
        for row in snapshot["chunks"]
    ):
        raise RuntimeError("target chunks are not complete with outputs and receipts")


def _validate_after(before: dict[str, Any], after: dict[str, Any]) -> None:
    if any(after["active_state"].values()):
        raise RuntimeError("requeue left active claims")
    if after["integrity"] != "ok" or after["foreign_key_violations"]:
        raise RuntimeError("database integrity postflight failed")
    if after["immutable_digests"] != before["immutable_digests"]:
        raise RuntimeError("requeue changed immutable outputs or provider receipts")
    if after["task_policy_counts"] != before["task_policy_counts"]:
        raise RuntimeError("requeue changed task policy identity")
    if after["analysis_policy_counts"] != before["analysis_policy_counts"]:
        raise RuntimeError("requeue changed analysis policy identity")
    if after["chunks"] != before["chunks"]:
        raise RuntimeError("requeue changed completed chunk state")
    if after["synthesis_node_count"] != 0:
        raise RuntimeError("requeue unexpectedly created synthesis nodes")
    for row in after["tasks"]:
        if (
            row["status"] != "pending"
            or int(row["attempts"]) != 0
            or row["claimed_run_id"] is not None
            or row["claim_lease_token"] is not None
        ):
            raise RuntimeError(f"target task did not requeue cleanly: {dict(row)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Requeue only the two synthesis-schema compatibility failures."
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup")
    parser.add_argument("--receipt")
    arguments = parser.parse_args()
    if arguments.apply and (not arguments.backup or not arguments.receipt):
        parser.error("--apply requires --backup and --receipt")
    if not arguments.apply and (arguments.backup or arguments.receipt):
        parser.error("--backup and --receipt require --apply")

    settings = load_settings(arguments.config)
    if settings.analysis_policy_hash != EXPECTED_POLICY_SHA256:
        raise RuntimeError(
            "schema compatibility policy identity is not the expected frozen value"
        )
    schema_record = analysis_schema_policy_record(
        settings.project_dir,
        "synthesis_reduce.schema.json",
    )
    database_path = settings.database_path.resolve()
    connection = _connect(database_path, read_only=True)
    try:
        before = _snapshot(connection)
        _validate_before(before)
    finally:
        connection.close()

    result: dict[str, Any] = {
        "schema": "r3/synthesis-schema-compat-requeue/v1",
        "generated_at": utc_now(),
        "mode": "apply" if arguments.apply else "dry_run",
        "database_path": str(database_path),
        "analysis_policy_sha256": settings.analysis_policy_hash,
        "schema_policy_record": schema_record,
        "runtime_gates": {
            "covered_chunk_indices": "exact sorted equality and duplicate rejection",
            "evidence_anchors": (
                "non-empty strings, duplicate rejection and verified-anchor subset"
            ),
        },
        "before": before,
    }
    if not arguments.apply:
        result["status"] = "dry_run_pass"
        print(json_dumps(result, pretty=True))
        return 0

    backup_path = Path(arguments.backup).resolve()
    receipt_path = Path(arguments.receipt).resolve()
    if backup_path == receipt_path:
        raise ValueError("backup and receipt paths must differ")
    if backup_path.exists() or receipt_path.exists():
        raise FileExistsError("backup and receipt targets must not already exist")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    source = _connect(database_path, read_only=True)
    backup = sqlite3.connect(str(backup_path))
    try:
        source.backup(backup)
    finally:
        backup.close()
        source.close()

    store = RadarStore(database_path)
    try:
        requeued = [
            store.requeue_analysis(
                work_id,
                analysis_policy_hash=settings.analysis_policy_hash,
                provider="codex_cli",
            )
            for work_id in TARGET_WORK_IDS
        ]
    finally:
        store.close()

    connection = _connect(database_path, read_only=True)
    try:
        after = _snapshot(connection)
        _validate_after(before, after)
    finally:
        connection.close()
    result.update(
        {
            "status": "applied",
            "requeued": requeued,
            "backup_path": str(backup_path),
            "backup_sha256": _sha256_file(backup_path),
            "after": after,
            "immutable_outputs_and_receipts_unchanged": True,
        }
    )
    atomic_write_text(receipt_path, json_dumps(result, pretty=True))
    print(json_dumps(result, pretty=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
