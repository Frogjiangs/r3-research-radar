from __future__ import annotations

import ctypes
import http.client
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import SCHEMA_VERSION, RadarStore


DEFAULT_DASHBOARD_PORT = 8765
DEFAULT_SCHEDULED_TASK_NAME = "R3 Research Radar"
RUN_FRESHNESS_SECONDS = 3600
_REQUIRED_RUNTIME_TABLES = frozenset(
    {
        "analysis_tasks",
        "documents",
        "model_invocations",
        "runs",
        "schema_meta",
        "works",
    }
)


def _parse_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _age_seconds(value: object) -> int | None:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - parsed).total_seconds()))


def _process_state(pid: object) -> str:
    try:
        process_id = int(pid)
    except (TypeError, ValueError):
        return "missing"
    if process_id <= 0:
        return "missing"
    if process_id == os.getpid():
        return "alive"
    if os.name == "nt":
        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        open_process.restype = ctypes.c_void_p
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        get_exit_code.restype = ctypes.c_int
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        handle = open_process(
            process_query_limited_information,
            False,
            process_id,
        )
        if not handle:
            return "unobservable" if ctypes.get_last_error() == 5 else "dead"
        try:
            exit_code = ctypes.c_ulong()
            if not get_exit_code(handle, ctypes.byref(exit_code)):
                return "unobservable"
            return "alive" if exit_code.value == still_active else "dead"
        finally:
            close_handle(handle)
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return "dead"
    except PermissionError:
        return "unobservable"
    except OSError:
        return "dead"
    return "alive"


def inspect_database(database_path: Path) -> dict[str, Any]:
    """Inspect SQLite read-only without creating or migrating it."""

    path = database_path.resolve()
    result: dict[str, Any] = {
        "state": "missing",
        "readable": False,
        "schema_version": None,
        "expected_schema_version": SCHEMA_VERSION,
        "migration_required": True,
        "quick_check": None,
        "foreign_key_ok": None,
    }
    if not path.is_file():
        return result
    try:
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode=ro",
            uri=True,
            timeout=2,
        )
        connection.row_factory = sqlite3.Row
    except sqlite3.Error:
        result["state"] = "unreadable"
        return result
    try:
        quick_row = connection.execute("PRAGMA quick_check(1)").fetchone()
        quick_check = str(quick_row[0]) if quick_row is not None else "missing"
        result["quick_check"] = quick_check
        if quick_check != "ok":
            result["state"] = "corrupt"
            return result
        table_names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        missing_tables = sorted(_REQUIRED_RUNTIME_TABLES - table_names)
        result["missing_runtime_tables"] = missing_tables
        if "schema_meta" in table_names:
            version_row = connection.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()
        else:
            version_row = None
        try:
            version = int(version_row[0]) if version_row is not None else None
        except (TypeError, ValueError):
            result["state"] = "invalid_schema"
            result["readable"] = True
            return result
        foreign_key_row = connection.execute("PRAGMA foreign_key_check").fetchone()
        result["readable"] = True
        result["schema_version"] = version
        result["foreign_key_ok"] = foreign_key_row is None
        if version is None or version < SCHEMA_VERSION or missing_tables:
            result["state"] = "migration_required"
        elif version > SCHEMA_VERSION:
            result["state"] = "incompatible_newer_schema"
        elif foreign_key_row is not None:
            result["state"] = "foreign_key_error"
        else:
            result["state"] = "ready"
            result["migration_required"] = False
        return result
    except sqlite3.Error:
        result["state"] = "unreadable"
        return result
    finally:
        connection.close()


def scheduler_status(
    task_name: str = DEFAULT_SCHEDULED_TASK_NAME,
) -> dict[str, Any]:
    if os.name != "nt":
        return {
            "state": "unsupported",
            "installed": False,
            "observed": False,
            "task_name": task_name,
        }
    windows_root = os.environ.get("WINDIR") or os.environ.get("SystemRoot")
    if not windows_root:
        return {
            "state": "unobservable",
            "installed": False,
            "observed": False,
            "task_name": task_name,
        }
    windows_dir = Path(windows_root)
    task_file = windows_dir / "System32" / "Tasks" / task_name
    if not task_file.is_file():
        return {
            "state": "absent",
            "installed": False,
            "observed": True,
            "task_name": task_name,
        }
    try:
        completed = subprocess.run(
            [
                "schtasks.exe",
                "/Query",
                "/TN",
                task_name,
                "/FO",
                "CSV",
                "/NH",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {
            "state": "unobservable",
            "installed": False,
            "observed": False,
            "task_name": task_name,
        }
    if completed.returncode == 0 and completed.stdout.strip():
        state = "installed"
        installed = True
        observed = True
    else:
        state = "unobservable"
        installed = False
        observed = False
    return {
        "state": state,
        "installed": installed,
        "observed": observed,
        "task_name": task_name,
    }


def probe_dashboard_service(
    port: int,
    *,
    expected_config_hash: str | None = None,
) -> dict[str, Any]:
    if not 1 <= port <= 65535:
        return {"state": "invalid", "up": False, "port": port}
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
    try:
        connection.request(
            "GET",
            "/api/health",
            headers={"Host": f"127.0.0.1:{port}", "Connection": "close"},
        )
        response = connection.getresponse()
        body = response.read(1024 * 1024)
        payload = json.loads(body.decode("utf-8"))
        if not isinstance(payload, dict) or payload.get("service") != "r3-research-radar":
            return {"state": "occupied_unknown", "up": False, "port": port}
        instance = payload.get("instance")
        observed_hash = instance.get("config_hash") if isinstance(instance, dict) else None
        if expected_config_hash and observed_hash != expected_config_hash:
            return {
                "state": "running_other_profile",
                "up": False,
                "port": port,
            }
        healthy = response.status == 200 and payload.get("ok") is True
        return {
            "state": "running" if healthy else "running_degraded",
            "up": True,
            "port": port,
        }
    except (
        OSError,
        http.client.HTTPException,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        probe = __import__("socket").socket()
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return {"state": "occupied_unknown", "up": False, "port": port}
        finally:
            probe.close()
        return {"state": "not_running", "up": False, "port": port}
    finally:
        connection.close()


def run_status(store: RadarStore, config_hash: str, retrieval_hash: str) -> dict[str, Any]:
    latest = store.latest_run(config_hash)
    if latest is None:
        latest = store.latest_run_for_retrieval(retrieval_hash)
    with store._lock:
        success_row = store._connection.execute(
            """
            SELECT id, status, ended_at, updated_at
            FROM runs
            WHERE COALESCE(retrieval_hash, config_hash)=?
              AND status IN ('completed','completed_with_gaps')
            ORDER BY COALESCE(ended_at, updated_at) DESC
            LIMIT 1
            """,
            (retrieval_hash,),
        ).fetchone()
        claim_rows: list[sqlite3.Row] = []
        if latest is not None:
            claim_rows = store._connection.execute(
                """
                SELECT 'query' AS claim_type, claim_lease_token AS claim_token
                FROM query_jobs
                WHERE run_id=? AND status='running'
                UNION ALL
                SELECT 'verification', claim_lease_token
                FROM verification_tasks
                WHERE run_id=? AND status='running'
                UNION ALL
                SELECT 'analysis', claim_lease_token
                FROM analysis_tasks
                WHERE claimed_run_id=? AND status='running'
                UNION ALL
                SELECT 'scope', active_lease_token
                FROM work_scopes
                WHERE active_run_id=?
                  AND state IN ('content_running','analysis_running')
                """,
                (latest["id"], latest["id"], latest["id"], latest["id"]),
            ).fetchall()
    last_success = dict(success_row) if success_row is not None else None
    if latest is None:
        return {
            "state": "idle",
            "active": False,
            "latest": None,
            "last_success": last_success,
        }
    now = datetime.now(timezone.utc)
    lease_expires = _parse_timestamp(latest.get("lease_expires_at"))
    lease_fresh = bool(lease_expires is not None and lease_expires > now)
    owner_state = _process_state(latest.get("owner_pid"))
    lease_token_present = bool(latest.get("lease_token"))
    mismatched_claims = sum(
        row["claim_token"] != latest.get("lease_token") for row in claim_rows
    )
    claims_by_type: dict[str, int] = {}
    for row in claim_rows:
        claim_type = str(row["claim_type"])
        claims_by_type[claim_type] = claims_by_type.get(claim_type, 0) + 1
    running = latest.get("status") == "running"
    active = bool(
        running
        and lease_fresh
        and lease_token_present
        and owner_state == "alive"
        and mismatched_claims == 0
    )
    if active:
        state = "active"
    elif not running:
        state = str(latest.get("status") or "idle")
    elif not lease_fresh:
        state = "stale_lease"
    elif owner_state == "dead":
        state = "orphaned_owner"
    elif owner_state == "missing" or not lease_token_present:
        state = "owner_missing"
    elif mismatched_claims:
        state = "lease_owner_mismatch"
    else:
        state = "owner_unobservable"
    updated_age = _age_seconds(latest.get("updated_at"))
    return {
        "state": state,
        "active": active,
        "latest": {
            "id": latest.get("id"),
            "mode": latest.get("mode"),
            "status": latest.get("status"),
            "owner_pid": latest.get("owner_pid"),
            "owner_process_state": owner_state,
            "lease_token_present": lease_token_present,
            "lease_expires_at": latest.get("lease_expires_at"),
            "lease_fresh": lease_fresh,
            "active_claims": len(claim_rows),
            "active_claims_by_type": claims_by_type,
            "mismatched_claims": mismatched_claims,
            "updated_at": latest.get("updated_at"),
            "updated_age_seconds": updated_age,
            "fresh": updated_age is not None and updated_age <= RUN_FRESHNESS_SECONDS,
        },
        "last_success": last_success,
    }
