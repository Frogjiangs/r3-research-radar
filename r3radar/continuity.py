from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from .config import Settings
from .storage import RadarStore
from .utils import JsonlAuditLog, atomic_write_text, json_dumps, sha256_text, utc_now


def _file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_database_copy(database_path: Path) -> dict[str, Any]:
    if not database_path.is_file():
        return {"present": False}
    source_hash_before = _file_sha256(database_path)
    with tempfile.TemporaryDirectory(prefix="r3-continuity-db-") as temporary:
        copy_path = Path(temporary) / "radar-copy.sqlite3"
        source = sqlite3.connect(
            f"file:{database_path.as_posix()}?mode=ro",
            uri=True,
        )
        destination = sqlite3.connect(copy_path)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        with RadarStore(copy_path) as store:
            with store._lock:
                integrity = str(
                    store._connection.execute("PRAGMA integrity_check").fetchone()[0]
                )
                foreign_key_violations = len(
                    store._connection.execute("PRAGMA foreign_key_check").fetchall()
                )
                schema_version = str(
                    store._connection.execute(
                        """
                        SELECT value FROM schema_meta
                        WHERE key='schema_version'
                        """
                    ).fetchone()[0]
                )
    source_hash_after = _file_sha256(database_path)
    if source_hash_before != source_hash_after:
        raise RuntimeError(
            "the live database changed during copy-only continuity verification"
        )
    if integrity != "ok" or foreign_key_violations:
        raise RuntimeError(
            "database-copy verification failed: "
            f"integrity={integrity}, foreign_keys={foreign_key_violations}"
        )
    return {
        "present": True,
        "source_sha256": source_hash_after,
        "migrated_copy_schema_version": schema_version,
        "integrity_check": integrity,
        "foreign_key_violations": foreign_key_violations,
    }


def _run_check(
    command: list[str],
    *,
    project_dir: Path,
    timeout_seconds: int,
    log_path: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=project_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            env=os.environ.copy(),
        )
        returncode = int(completed.returncode)
        output = completed.stdout or ""
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        output = str(exc.stdout or "") + "\nCHECK TIMED OUT\n"
        timed_out = True
    atomic_write_text(log_path, output)
    return {
        "command": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log_path": str(log_path),
        "log_sha256": sha256_text(output),
    }


def run_continuity_test(
    settings: Settings,
    *,
    iterations: int,
    max_seconds: int,
    resume_run_id: str | None = None,
) -> dict[str, Any]:
    if iterations <= 0 and max_seconds <= 0:
        raise ValueError("iterations or max_seconds must be positive")
    run_id = resume_run_id or (
        time.strftime("%Y%m%dT%H%M%S") + "_" + uuid.uuid4().hex[:8]
    )
    run_dir = settings.outputs_dir / "continuity" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_path = run_dir / "summary.json"
    audit = JsonlAuditLog(run_dir / "audit.jsonl")
    completed_iterations = 0
    failure_count = 0
    started_at = utc_now()
    if resume_run_id and summary_path.is_file():
        import json

        prior = json.loads(summary_path.read_text(encoding="utf-8"))
        completed_iterations = int(prior.get("completed_iterations") or 0)
        failure_count = int(prior.get("failure_count") or 0)
        started_at = str(prior.get("started_at") or started_at)
    started_monotonic = time.monotonic()
    database_check = _verify_database_copy(settings.database_path)
    audit.write(
        "continuity_started",
        component="continuity",
        run_id=run_id,
        details={
            "completed_iterations": completed_iterations,
            "requested_iterations": iterations,
            "max_seconds": max_seconds,
            "database_check": database_check,
        },
    )
    checks = (
        [
            sys.executable,
            "-m",
            "compileall",
            "-q",
            "r3radar",
            "tests",
        ],
        ["node", "--check", str(settings.project_dir / "static" / "app.js")],
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-q",
        ],
    )
    while True:
        elapsed = time.monotonic() - started_monotonic
        if iterations > 0 and completed_iterations >= iterations:
            break
        if max_seconds > 0 and elapsed >= max_seconds:
            break
        iteration = completed_iterations + 1
        iteration_dir = run_dir / f"iteration_{iteration:06d}"
        results = [
            _run_check(
                command,
                project_dir=settings.project_dir,
                timeout_seconds=600,
                log_path=iteration_dir / f"check_{index}.log",
            )
            for index, command in enumerate(checks, start=1)
        ]
        passed = all(result["returncode"] == 0 for result in results)
        completed_iterations = iteration
        if not passed:
            failure_count += 1
        if iteration == 1 or iteration % 25 == 0:
            database_check = _verify_database_copy(settings.database_path)
        summary = {
            "schema_version": "1.0",
            "run_id": run_id,
            "status": "running",
            "started_at": started_at,
            "updated_at": utc_now(),
            "requested_iterations": iterations,
            "max_seconds": max_seconds,
            "completed_iterations": completed_iterations,
            "failure_count": failure_count,
            "last_iteration_passed": passed,
            "last_results": results,
            "database_check": database_check,
        }
        atomic_write_text(summary_path, json_dumps(summary, pretty=True) + "\n")
        audit.write(
            "continuity_iteration_completed",
            component="continuity",
            run_id=run_id,
            severity="info" if passed else "error",
            details={
                "iteration": iteration,
                "passed": passed,
                "failure_count": failure_count,
                "results": results,
            },
        )
    database_check = _verify_database_copy(settings.database_path)
    final_summary = {
        "schema_version": "1.0",
        "run_id": run_id,
        "status": "passed" if failure_count == 0 else "failed",
        "started_at": started_at,
        "ended_at": utc_now(),
        "requested_iterations": iterations,
        "max_seconds": max_seconds,
        "completed_iterations": completed_iterations,
        "failure_count": failure_count,
        "elapsed_seconds": round(time.monotonic() - started_monotonic, 3),
        "database_check": database_check,
        "audit_path": str(audit.path),
        "summary_path": str(summary_path),
    }
    atomic_write_text(summary_path, json_dumps(final_summary, pretty=True) + "\n")
    audit.write(
        "continuity_finished",
        component="continuity",
        run_id=run_id,
        severity="info" if failure_count == 0 else "error",
        details=final_summary,
    )
    return final_summary
