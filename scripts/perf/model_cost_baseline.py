from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r3radar.utils import atomic_write_text  # noqa: E402


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _bucket(chunk_total: int) -> str:
    if chunk_total <= 24:
        return "01-24"
    if chunk_total <= 96:
        return "25-96"
    return "97-plus"


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    durations = [float(row["duration_seconds"]) for row in rows]
    calls = [float(row["model_calls"]) for row in rows]
    inputs = [float(row["input_tokens"]) for row in rows]
    outputs = [float(row["output_tokens"]) for row in rows]
    return {
        "analysis_count": len(rows),
        "duration_seconds_total": round(sum(durations), 3),
        "duration_seconds_p50": _percentile(durations, 0.50),
        "duration_seconds_p90": _percentile(durations, 0.90),
        "model_calls_total": int(sum(calls)),
        "model_calls_p50": _percentile(calls, 0.50),
        "model_calls_p90": _percentile(calls, 0.90),
        "input_tokens_total": int(sum(inputs)),
        "input_tokens_p50": _percentile(inputs, 0.50),
        "input_tokens_p90": _percentile(inputs, 0.90),
        "output_tokens_total": int(sum(outputs)),
        "output_tokens_p50": _percentile(outputs, 0.50),
        "output_tokens_p90": _percentile(outputs, 0.90),
    }


def build_receipt(database: Path, policy_hash: str) -> dict[str, Any]:
    before = {
        "size": database.stat().st_size,
        "mtime_ns": database.stat().st_mtime_ns,
        "sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
    }
    connection = sqlite3.connect(
        f"file:{database.resolve().as_posix()}?mode=ro", uri=True
    )
    connection.row_factory = sqlite3.Row
    try:
        raw_rows = connection.execute(
            """
            SELECT
              analysis.id AS analysis_id,
              work.id AS work_id,
              work.kind,
              task.chunk_total,
              analysis.provider,
              analysis.model,
              COUNT(invocation.invocation_id) AS model_calls,
              COALESCE(SUM(invocation.duration_seconds), 0) AS duration_seconds,
              COALESCE(SUM(invocation.input_tokens), 0) AS input_tokens,
              COALESCE(SUM(invocation.cached_input_tokens), 0) AS cached_input_tokens,
              COALESCE(SUM(invocation.output_tokens), 0) AS output_tokens
            FROM analyses analysis
            JOIN analysis_tasks task ON task.id=analysis.task_id
            JOIN works work ON work.id=analysis.work_id
            LEFT JOIN model_invocations invocation ON invocation.task_id=task.id
            WHERE analysis.config_hash=? AND analysis.deep_read_status='complete'
            GROUP BY analysis.id, work.id, work.kind, task.chunk_total,
                     analysis.provider, analysis.model
            ORDER BY analysis.id
            """,
            (policy_hash,),
        ).fetchall()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
        schema_row = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
    finally:
        connection.close()
    rows = [dict(row) for row in raw_rows]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[f"kind:{row['kind']}"].append(row)
        groups[f"chunks:{_bucket(int(row['chunk_total']))}"].append(row)
        groups[f"provider:{row['provider']}:{row['model'] or 'unknown'}"].append(row)
    after = {
        "size": database.stat().st_size,
        "mtime_ns": database.stat().st_mtime_ns,
        "sha256": hashlib.sha256(database.read_bytes()).hexdigest(),
    }
    return {
        "schema": "r3/model-cost-baseline/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_policy_hash": policy_hash,
        "database": {
            "sha256": before["sha256"],
            "schema_version": int(schema_row[0]) if schema_row else None,
            "integrity_check": integrity,
            "foreign_key_violations": foreign_keys,
            "unchanged": before == after,
        },
        "all": _summary(rows),
        "groups": {key: _summary(groups[key]) for key in sorted(groups)},
        "analyses": [
            {
                "analysis_id": int(row["analysis_id"]),
                "work_id": int(row["work_id"]),
                "kind": row["kind"],
                "chunk_total": int(row["chunk_total"]),
                "chunk_bucket": _bucket(int(row["chunk_total"])),
                "provider": row["provider"],
                "model": row["model"],
                "model_calls": int(row["model_calls"]),
                "duration_seconds": round(float(row["duration_seconds"]), 3),
                "input_tokens": int(row["input_tokens"]),
                "cached_input_tokens": int(row["cached_input_tokens"]),
                "output_tokens": int(row["output_tokens"]),
            }
            for row in rows
        ],
        "interpretation": {
            "monetary_cost": "unknown_not_inferred_from_tokens",
            "quality_claim": False,
            "concurrency_recommendation": "requires a fixed-content evidence-quality experiment",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = build_receipt(args.database.resolve(), args.policy_hash)
    atomic_write_text(
        args.output.resolve(),
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    print(json.dumps({"output": str(args.output), "all": receipt["all"]}))
    return 0 if receipt["database"]["unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
