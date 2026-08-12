from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import PROJECT_DIR, Settings
from .runtime_status import (
    inspect_database,
    probe_dashboard_service,
    scheduler_status,
)
from .utils import atomic_write_text, json_dumps


PROFILE_TEMPLATE = PROJECT_DIR / "config" / "profile.example.json"
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def create_profile(
    output_path: Path,
    *,
    profile_id: str,
    name: str,
    research_question: str,
    decision_scope: str,
) -> dict[str, Any]:
    """Create a safe starter profile without overwriting an existing file."""

    if not _PROFILE_ID.fullmatch(profile_id):
        raise ValueError(
            "profile_id must be 2-64 lowercase letters, digits, dots, dashes, "
            "or underscores"
        )
    values = {
        "name": name.strip(),
        "research_question": research_question.strip(),
        "decision_scope": decision_scope.strip(),
    }
    missing = [key for key, value in values.items() if not value]
    if missing:
        raise ValueError(f"profile fields cannot be empty: {', '.join(missing)}")
    destination = output_path.resolve()
    if destination.exists():
        raise FileExistsError(f"profile already exists: {destination.name}")
    template = json.loads(PROFILE_TEMPLATE.read_text(encoding="utf-8"))
    template["profile_id"] = profile_id
    template["name"] = values["name"]
    template["research_question"] = values["research_question"]
    template["decision_scope"] = values["decision_scope"]
    template["workspace_root"] = "."
    template["paths"] = {
        "data": f".r3radar/{profile_id}/data",
        "literature": f".r3radar/{profile_id}/literature",
        "outputs": f".r3radar/{profile_id}/outputs",
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(destination, json_dumps(template, pretty=True) + "\n")
    return {
        "ok": True,
        "profile_id": profile_id,
        "profile_file": destination.name,
        "next": [
            f"r3radar --config {destination.name} doctor",
            f"r3radar --config {destination.name} init",
        ],
    }


def _check(
    check_id: str,
    status: str,
    summary: str,
    *,
    remediation: str | None = None,
    required: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": check_id,
        "status": status,
        "required": required,
        "summary": summary,
    }
    if remediation:
        result["remediation"] = remediation
    return result


def _codex_authentication_state(
    node: str | None,
    script: Path,
    *,
    check_auth: bool,
) -> str:
    if not node or not script.is_file():
        return "unavailable"
    if not check_auth:
        return "not_checked"
    allowed = {
        "APPDATA",
        "CODEX_HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "PATH",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed
    }
    try:
        completed = subprocess.run(
            [node, str(script), "login", "status"],
            cwd=PROJECT_DIR,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    return "authenticated" if completed.returncode == 0 else "not_authenticated"


def doctor_report(
    settings: Settings,
    *,
    check_auth: bool = False,
    dashboard_port: int = 8765,
) -> dict[str, Any]:
    """Return a diagnostic report that never exposes secret values or local paths."""

    checks: list[dict[str, Any]] = []
    full_platform = bool(
        os.name == "nt"
        and platform.python_implementation() == "CPython"
        and sys.version_info[:2] == (3, 10)
    )
    checks.append(
        _check(
            "full_pipeline_platform",
            "ok" if full_platform else "warning",
            (
                "Windows CPython 3.10 full-security path is available."
                if full_platform
                else "The full PDF AppContainer path is not supported here."
            ),
            remediation=(
                None
                if full_platform
                else "Use Windows 10/11 with CPython 3.10 for the supported "
                "full pipeline; other platforms are development-only."
            ),
            required=True,
        )
    )
    database = inspect_database(settings.database_path)
    database_state = str(database["state"])
    database_status = (
        "ok"
        if database_state == "ready"
        else "warning"
        if database_state in {"missing", "migration_required"}
        else "error"
    )
    database_summary = {
        "ready": "The SQLite database is readable and schema-current.",
        "missing": "The SQLite database has not been initialized.",
        "migration_required": "The SQLite database requires a controlled migration.",
        "incompatible_newer_schema": (
            "The SQLite database is newer than this R3 build."
        ),
        "corrupt": "The SQLite database failed its quick integrity check.",
        "foreign_key_error": "The SQLite database has foreign-key violations.",
        "invalid_schema": "The SQLite database schema version is invalid.",
        "unreadable": "The SQLite database cannot be read safely.",
    }.get(database_state, "The SQLite database state is unknown.")
    database_check = _check(
        "database",
        database_status,
        database_summary,
        remediation=(
            None
            if database_state == "ready"
            else "Run `r3radar --config <profile.json> init` after making a backup."
        ),
        required=database_status == "error",
    )
    database_check.update(database)
    checks.append(database_check)
    path_boundary_ok = all(
        path == settings.workspace_dir or settings.workspace_dir in path.parents
        for path in (
            settings.data_dir,
            settings.literature_dir,
            settings.outputs_dir,
        )
    )
    checks.append(
        _check(
            "workspace_boundary",
            "ok" if path_boundary_ok else "error",
            (
                "Runtime paths stay inside the configured workspace."
                if path_boundary_ok
                else "A runtime path escapes the configured workspace."
            ),
            remediation="Fix workspace_root and paths before running.",
            required=True,
        )
    )
    checks.append(
        _check(
            "runtime_directories",
            "ok"
            if all(
                path.is_dir() and os.access(path, os.W_OK)
                for path in (
                    settings.data_dir,
                    settings.literature_dir,
                    settings.outputs_dir,
                )
            )
            else "error",
            "Runtime directories exist and are writable.",
            remediation="Grant write access to the configured local workspace.",
            required=True,
        )
    )
    node = shutil.which("node")
    codex_script = (
        settings.project_dir
        / "node_modules"
        / "@openai"
        / "codex"
        / "bin"
        / "codex.js"
    )
    codex_assets = bool(node and codex_script.is_file())
    checks.append(
        _check(
            "codex_cli",
            "ok" if codex_assets else "warning",
            (
                "Pinned Codex CLI assets are installed."
                if codex_assets
                else "Pinned Codex CLI assets are not installed."
            ),
            remediation=(
                None
                if codex_assets
                else "Run the documented setup before a Codex-backed live scan."
            ),
        )
    )
    auth_state = _codex_authentication_state(
        node,
        codex_script,
        check_auth=check_auth,
    )
    checks.append(
        _check(
            "codex_authentication",
            (
                "ok"
                if auth_state == "authenticated"
                else "info"
                if auth_state == "not_checked"
                else "warning"
            ),
            {
                "authenticated": "Codex authentication is available.",
                "not_checked": "Codex authentication was not checked.",
                "not_authenticated": "Codex is not authenticated.",
                "unavailable": "Codex authentication cannot be checked.",
            }[auth_state],
            remediation=(
                "Run `codex login`, then repeat doctor with `--check-auth`."
                if auth_state == "not_authenticated"
                else None
            ),
        )
    )
    openalex_enabled = bool(
        settings.raw.get("sources", {}).get("openalex", {}).get("enabled")
    )
    checks.append(
        _check(
            "openalex_key",
            (
                "ok"
                if not openalex_enabled or bool(os.getenv("OPENALEX_API_KEY"))
                else "warning"
            ),
            (
                "OpenAlex is disabled or its key is present."
                if not openalex_enabled or bool(os.getenv("OPENALEX_API_KEY"))
                else "OpenAlex is enabled but no key is present."
            ),
            remediation=(
                "Set OPENALEX_API_KEY in the process environment; never write "
                "the value into a profile or issue."
                if openalex_enabled and not os.getenv("OPENALEX_API_KEY")
                else None
            ),
        )
    )
    checks.append(
        _check(
            "github_token",
            "ok" if os.getenv("GITHUB_TOKEN") else "info",
            (
                "A GitHub token is present."
                if os.getenv("GITHUB_TOKEN")
                else "No GitHub token is present; public rate limits apply."
            ),
        )
    )
    dashboard_probe = probe_dashboard_service(
        dashboard_port,
        expected_config_hash=settings.config_hash,
    )
    dashboard_state = str(dashboard_probe["state"])
    dashboard_status = {
        "running": "ok",
        "running_degraded": "warning",
        "running_other_profile": "warning",
        "not_running": "info",
        "occupied_unknown": "warning",
        "invalid": "error",
    }[dashboard_state]
    dashboard_summary = {
        "running": f"R3 dashboard is running on loopback port {dashboard_port}.",
        "running_degraded": (
            f"R3 dashboard is running but degraded on loopback port {dashboard_port}."
        ),
        "running_other_profile": (
            f"Another R3 profile is running on loopback port {dashboard_port}."
        ),
        "not_running": (
            f"R3 dashboard is not running; loopback port {dashboard_port} is available."
        ),
        "occupied_unknown": (
            f"Loopback port {dashboard_port} is occupied by an unknown service."
        ),
        "invalid": "Dashboard port is outside the valid range.",
    }[dashboard_state]
    dashboard_remediation = {
        "running": None,
        "running_degraded": "Inspect /api/health before relying on this dashboard.",
        "running_other_profile": (
            "Use that profile explicitly or choose another loopback port."
        ),
        "not_running": (
            f"Start `r3radar --config <profile.json> dashboard --port {dashboard_port}`."
        ),
        "occupied_unknown": (
            "Stop the conflicting local service or choose another loopback port; "
            "do not bind the dashboard directly to a public interface."
        ),
        "invalid": "Choose a dashboard port from 1 through 65535.",
    }[dashboard_state]
    dashboard_check = _check(
        "dashboard_port",
        dashboard_status,
        dashboard_summary,
        remediation=dashboard_remediation,
    )
    dashboard_check["service_state"] = dashboard_state
    checks.append(dashboard_check)
    scheduler = scheduler_status()
    scheduler_state = str(scheduler["state"])
    scheduler_check = _check(
        "scheduler",
        "ok" if scheduler_state == "installed" else "info",
        (
            "The R3 Windows scheduled task is installed."
            if scheduler_state == "installed"
            else "No R3 Windows scheduled task is currently observed."
            if scheduler_state == "absent"
            else "Scheduled-task state is not observable on this runtime."
        ),
    )
    scheduler_check.update(scheduler)
    checks.append(scheduler_check)
    remote_provider = (
        settings.raw.get("analysis", {}).get("primary_provider") == "codex_cli"
    )
    checks.append(
        _check(
            "model_data_flow",
            "info",
            (
                "Selected paper or repository content can be sent to the "
                "remote Codex provider."
                if remote_provider
                else "The configured primary analysis path is not Codex."
            ),
        )
    )
    required_errors = any(
        item["required"] and item["status"] == "error" for item in checks
    )
    warnings = sum(item["status"] == "warning" for item in checks)
    return {
        "schema": "r3/doctor/v1",
        "status": "blocked" if required_errors else "degraded" if warnings else "ready",
        "profile": {
            "id": settings.profile_id,
            "version": settings.profile_version,
        },
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": sys.platform,
        },
        "secret_values_included": False,
        "checks": checks,
    }
