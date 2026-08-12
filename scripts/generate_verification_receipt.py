from __future__ import annotations

import argparse
import ast
import datetime as dt
import hashlib
import importlib.util
import json
import os
import platform
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Sequence


RECEIPT_SCHEMA = "r3/verification-receipt/v1"
SOURCE_DIRECTORIES = ("r3radar", "scripts", "static", "schemas", "tests")
SOURCE_ROOT_FILES = (
    "pyproject.toml",
    "requirements.txt",
    "requirements.lock",
    "MANIFEST.in",
)
SOURCE_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".ps1",
    ".py",
    ".toml",
}
SECRET_OPTION_RE = re.compile(
    r"(?i)^(--?(?:api[-_]?key|token|password|secret|authorization))(?:=(.*))?$"
)
INLINE_SECRET_RE = re.compile(
    r"(?i)(api[-_]?key|token|password|secret|authorization)(\s*[:=]\s*)([^\s,;]+)"
)
WINDOWS_ABSOLUTE_RE = re.compile(r"(?i)(?<![\w])([A-Z]:[\\/][^\r\n\t\"']+)")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _relative_label(path: Path, root: Path, fallback: str) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return fallback


def _replace_known_path(text: str, path: Path, replacement: str) -> str:
    candidates = {str(path), str(path).replace("\\", "/")}
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path.absolute()
    candidates.update({str(resolved), str(resolved).replace("\\", "/")})
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate:
            text = text.replace(candidate, replacement)
    return text


def sanitize_text(text: str, source_root: Path, working_directory: Path) -> str:
    result = _replace_known_path(text, source_root, "<SOURCE_ROOT>")
    result = _replace_known_path(result, working_directory, "<WORKING_DIRECTORY>")
    result = _replace_known_path(result, Path.home(), "<USER_HOME>")
    result = INLINE_SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}<REDACTED>", result)
    result = WINDOWS_ABSOLUTE_RE.sub("<ABSOLUTE_PATH>", result)
    return result


def sanitize_command(
    command: Sequence[str], source_root: Path, working_directory: Path
) -> list[str]:
    sanitized: list[str] = []
    redact_next = False
    for raw in command:
        value = str(raw)
        if redact_next:
            sanitized.append("<REDACTED>")
            redact_next = False
            continue
        secret_match = SECRET_OPTION_RE.match(value)
        if secret_match:
            option = secret_match.group(1)
            if secret_match.group(2) is None:
                sanitized.append(option)
                redact_next = True
            else:
                sanitized.append(f"{option}=<REDACTED>")
            continue
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(source_root.resolve())
                sanitized.append(f"<SOURCE_ROOT>/{relative.as_posix()}")
                continue
            except (OSError, ValueError):
                sanitized.append(candidate.name or "<ABSOLUTE_PATH>")
                continue
        sanitized.append(
            sanitize_text(value, source_root, working_directory)
        )
    return sanitized


def summarize_stream(
    text: str,
    *,
    source_root: Path,
    working_directory: Path,
    excerpt_limit: int,
) -> dict[str, Any]:
    sanitized = sanitize_text(text, source_root, working_directory)
    encoded = sanitized.encode("utf-8", errors="replace")
    excerpt = sanitized[-excerpt_limit:] if excerpt_limit > 0 else ""
    return {
        "captured_character_count": len(text),
        "sanitized_byte_count_utf8": len(encoded),
        "line_count": len(text.splitlines()),
        "sanitized_sha256": sha256_bytes(encoded),
        "excerpt_truncated": len(sanitized) > len(excerpt),
        "excerpt": excerpt,
    }


def _looks_like_test_command(command: Sequence[str]) -> tuple[bool, str | None]:
    lowered = [str(item).casefold() for item in command]
    joined = " ".join(lowered)
    if "pytest" in joined or "py.test" in joined:
        return True, "pytest"
    if "unittest" in lowered or "-m unittest" in joined:
        return True, "unittest"
    if any(Path(item).name.casefold().startswith("test_") for item in lowered):
        return True, "unknown_test_runner"
    return False, None


def _empty_test_counts(status: str, framework: str | None) -> dict[str, Any]:
    return {
        "framework": framework,
        "parsing_status": status,
        "passed": None,
        "failed": None,
        "errors": None,
        "skipped": None,
        "xfailed": None,
        "xpassed": None,
        "total": None,
        "passed_is_derived": None,
    }


def parse_test_counts(command: Sequence[str], output: str) -> dict[str, Any]:
    is_test, framework = _looks_like_test_command(command)
    if not is_test:
        return _empty_test_counts("not_test_command", None)

    if framework == "unittest":
        total_matches = re.findall(r"Ran\s+(\d+)\s+tests?\b", output)
        terminal_matches = re.findall(
            r"(?m)^(OK|FAILED)(?:\s*\(([^\r\n]*)\))?\s*$",
            output,
        )
        if not total_matches or not terminal_matches:
            return _empty_test_counts("unknown", framework)
        total = int(total_matches[-1])
        terminal, details = terminal_matches[-1]
        metrics = {
            key.strip().casefold().replace(" ", "_"): int(value)
            for key, value in re.findall(
                r"([A-Za-z ]+?)\s*=\s*(\d+)", details or ""
            )
        }
        failed = metrics.get("failures", 0)
        errors = metrics.get("errors", 0)
        skipped = metrics.get("skipped", 0)
        xfailed = metrics.get("expected_failures", 0)
        xpassed = metrics.get("unexpected_successes", 0)
        passed = total - failed - errors - skipped - xfailed - xpassed
        if terminal == "OK" and (failed or errors or passed < 0):
            return _empty_test_counts("unknown", framework)
        if terminal == "FAILED" and not (failed or errors or xpassed):
            return _empty_test_counts("unknown", framework)
        return {
            "framework": framework,
            "parsing_status": "parsed",
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "skipped": skipped,
            "xfailed": xfailed,
            "xpassed": xpassed,
            "total": total,
            "passed_is_derived": True,
        }

    if framework == "pytest":
        summary_lines = [
            line.strip()
            for line in output.splitlines()
            if re.search(r"\b(?:passed|failed|error|errors|skipped|xfailed|xpassed)\b", line)
        ]
        for line in reversed(summary_lines):
            metrics = {
                key.casefold(): int(value)
                for value, key in re.findall(
                    r"(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed)\b",
                    line,
                )
            }
            if not metrics:
                continue
            counts = {
                "passed": metrics.get("passed", 0),
                "failed": metrics.get("failed", 0),
                "errors": metrics.get("error", 0) + metrics.get("errors", 0),
                "skipped": metrics.get("skipped", 0),
                "xfailed": metrics.get("xfailed", 0),
                "xpassed": metrics.get("xpassed", 0),
            }
            return {
                "framework": framework,
                "parsing_status": "parsed",
                **counts,
                "total": sum(counts.values()),
                "passed_is_derived": False,
            }
    return _empty_test_counts("unknown", framework)


def source_manifest(source_root: Path) -> dict[str, Any]:
    source_root = source_root.resolve()
    paths: set[Path] = set()
    for name in SOURCE_ROOT_FILES:
        candidate = source_root / name
        if candidate.is_file():
            paths.add(candidate)
    for directory_name in SOURCE_DIRECTORIES:
        directory = source_root / directory_name
        if not directory.is_dir():
            continue
        for candidate in directory.rglob("*"):
            if (
                candidate.is_file()
                and not candidate.is_symlink()
                and candidate.suffix.casefold() in SOURCE_SUFFIXES
                and "__pycache__" not in candidate.parts
            ):
                try:
                    candidate.resolve().relative_to(source_root)
                except (OSError, ValueError):
                    continue
                paths.add(candidate)
    entries: list[dict[str, Any]] = []
    for path in sorted(paths, key=lambda item: item.relative_to(source_root).as_posix()):
        relative = path.relative_to(source_root).as_posix()
        payload = path.read_bytes()
        entries.append(
            {
                "path": relative,
                "size_bytes": len(payload),
                "sha256": sha256_bytes(payload),
            }
        )
    canonical = json.dumps(
        entries,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "status": "captured" if entries else "empty",
        "file_count": len(entries),
        "manifest_sha256": sha256_bytes(canonical),
        "files": entries,
    }


def _load_config_module(source_root: Path):
    config_module_path = source_root / "r3radar" / "config.py"
    if not config_module_path.is_file():
        raise FileNotFoundError("r3radar/config.py is unavailable")
    module_name = f"_r3_receipt_config_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, config_module_path)
    if spec is None or spec.loader is None:
        raise ImportError("unable to load r3radar/config.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)
    return module


def config_evidence(config_path: Path | None, source_root: Path) -> dict[str, Any]:
    if config_path is None:
        return {"status": "not_requested"}
    path = config_path.resolve()
    label = _relative_label(path, source_root, path.name)
    if not path.is_file():
        return {
            "status": "unavailable",
            "path": label,
            "file_sha256": None,
            "schema_version": None,
            "config_hash": None,
            "retrieval_hash": None,
            "analysis_policy_hash": None,
        }
    evidence: dict[str, Any] = {
        "status": "invalid",
        "path": label,
        "file_sha256": sha256_file(path),
        "schema_version": None,
        "config_hash": None,
        "retrieval_hash": None,
        "analysis_policy_hash": None,
    }
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            evidence["schema_version"] = raw.get("schema_version")
        module = _load_config_module(source_root)
        settings = module.load_settings(path)
        evidence.update(
            {
                "status": "valid",
                "config_hash": settings.config_hash,
                "retrieval_hash": settings.retrieval_hash,
                "analysis_policy_hash": settings.analysis_policy_hash,
            }
        )
    except Exception as exc:
        evidence["error_type"] = type(exc).__name__
        evidence["error"] = sanitize_text(str(exc), source_root, source_root)
    return evidence


def expected_schema_version(source_root: Path) -> int | None:
    storage_path = source_root / "r3radar" / "storage.py"
    try:
        tree = ast.parse(storage_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeError):
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == "SCHEMA_VERSION"
                for target in node.targets
            ):
                try:
                    value = ast.literal_eval(node.value)
                except (TypeError, ValueError):
                    return None
                return value if isinstance(value, int) else None
    return None


def database_evidence(database_path: Path | None, source_root: Path) -> dict[str, Any]:
    expected = expected_schema_version(source_root)
    if database_path is None:
        return {
            "status": "not_requested",
            "expected_schema_version": expected,
        }
    path = database_path.resolve()
    label = _relative_label(path, source_root, path.name)
    evidence: dict[str, Any] = {
        "status": "unavailable",
        "path": label,
        "schema_version": None,
        "expected_schema_version": expected,
        "integrity_check": "unknown",
        "foreign_key_violation_count": None,
    }
    if not path.is_file():
        return evidence
    connection: sqlite3.Connection | None = None
    try:
        quoted = urllib.parse.quote(str(path).replace("\\", "/"), safe="/:")
        connection = sqlite3.connect(f"file:{quoted}?mode=ro", uri=True, timeout=5)
        connection.execute("PRAGMA query_only=ON")
        integrity_row = connection.execute("PRAGMA integrity_check").fetchone()
        integrity = str(integrity_row[0]) if integrity_row else "unknown"
        foreign_key_violations = len(
            connection.execute("PRAGMA foreign_key_check").fetchall()
        )
        schema_row = connection.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        schema_version: int | str | None = schema_row[0] if schema_row else None
        try:
            schema_version = int(schema_version) if schema_version is not None else None
        except (TypeError, ValueError):
            pass
        if integrity != "ok" or foreign_key_violations:
            status = "invalid"
        elif expected is not None and schema_version != expected:
            status = "schema_mismatch"
        else:
            status = "healthy"
        evidence.update(
            {
                "status": status,
                "schema_version": schema_version,
                "schema_matches_expected": (
                    schema_version == expected if expected is not None else None
                ),
                "integrity_check": integrity,
                "foreign_key_violation_count": foreign_key_violations,
            }
        )
    except (OSError, sqlite3.Error) as exc:
        evidence.update(
            {
                "status": "invalid",
                "error_type": type(exc).__name__,
                "error": sanitize_text(str(exc), source_root, source_root),
            }
        )
    finally:
        if connection is not None:
            connection.close()
    return evidence


def git_evidence(source_root: Path) -> dict[str, Any]:
    def run_git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(source_root), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )

    try:
        head = run_git("rev-parse", "HEAD")
        if head.returncode != 0:
            return {"status": "not_repository", "head_sha": None}
        tracked = run_git("ls-files", "--", ".")
        state = run_git("status", "--porcelain=v1", "--untracked-files=normal", "--", ".")
    except (OSError, subprocess.SubprocessError):
        return {"status": "unavailable", "head_sha": None}
    tracked_files = [line for line in tracked.stdout.splitlines() if line.strip()]
    status_bytes = state.stdout.encode("utf-8", errors="replace")
    return {
        "status": "captured" if tracked.returncode == 0 and state.returncode == 0 else "partial",
        "head_sha": head.stdout.strip() or None,
        "tracked_file_count": len(tracked_files) if tracked.returncode == 0 else None,
        "worktree_clean": not bool(state.stdout.strip()) if state.returncode == 0 else None,
        "head_binds_source": (
            bool(tracked_files) and not bool(state.stdout.strip())
            if tracked.returncode == 0 and state.returncode == 0
            else None
        ),
        "status_sha256": sha256_bytes(status_bytes) if state.returncode == 0 else None,
    }


def execute_command(
    command: Sequence[str],
    *,
    source_root: Path,
    working_directory: Path,
    timeout_seconds: float,
    excerpt_limit: int,
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.perf_counter()
    stdout = ""
    stderr = ""
    exit_code: int | None = None
    status = "launch_error"
    error_type: str | None = None
    error_message: str | None = None
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    try:
        result = subprocess.run(
            list(command),
            cwd=working_directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            env=environment,
        )
        stdout = result.stdout
        stderr = result.stderr
        exit_code = result.returncode
        status = "completed"
    except subprocess.TimeoutExpired as exc:
        status = "timeout"
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", errors="replace")
        stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode("utf-8", errors="replace")
        error_type = type(exc).__name__
        error_message = f"command exceeded {timeout_seconds:g} seconds"
    except OSError as exc:
        error_type = type(exc).__name__
        error_message = sanitize_text(str(exc), source_root, working_directory)
    ended_at = utc_now()
    duration_seconds = round(time.perf_counter() - started, 6)
    combined_output = stdout + "\n" + stderr
    evidence: dict[str, Any] = {
        "status": status,
        "argv": sanitize_command(command, source_root, working_directory),
        "working_directory": _relative_label(
            working_directory,
            source_root,
            "<EXTERNAL_WORKING_DIRECTORY>",
        ),
        "started_at_utc": started_at,
        "ended_at_utc": ended_at,
        "duration_seconds": duration_seconds,
        "exit_code": exit_code,
        "stdout": summarize_stream(
            stdout,
            source_root=source_root,
            working_directory=working_directory,
            excerpt_limit=excerpt_limit,
        ),
        "stderr": summarize_stream(
            stderr,
            source_root=source_root,
            working_directory=working_directory,
            excerpt_limit=excerpt_limit,
        ),
        "tests": parse_test_counts(command, combined_output),
    }
    if error_type:
        evidence["error_type"] = error_type
    if error_message:
        evidence["error"] = error_message
    return evidence


def build_receipt(
    *,
    command: Sequence[str],
    source_root: Path,
    working_directory: Path,
    config_path: Path | None,
    database_path: Path | None,
    timeout_seconds: float,
    excerpt_limit: int,
) -> dict[str, Any]:
    source_root = source_root.resolve()
    working_directory = working_directory.resolve()
    command_evidence = execute_command(
        command,
        source_root=source_root,
        working_directory=working_directory,
        timeout_seconds=timeout_seconds,
        excerpt_limit=excerpt_limit,
    )
    config = config_evidence(config_path, source_root)
    database = database_evidence(database_path, source_root)
    source = source_manifest(source_root)
    required_statuses = [command_evidence["status"] == "completed", source["status"] == "captured"]
    required_statuses.append(command_evidence["exit_code"] == 0)
    if config_path is not None:
        required_statuses.append(config["status"] == "valid")
    if database_path is not None:
        required_statuses.append(database["status"] == "healthy")
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "passed" if all(required_statuses) else "failed",
        "generated_at_utc": utc_now(),
        "generator": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.system(),
        },
        "command": command_evidence,
        "source": source,
        "git": git_evidence(source_root),
        "config": config,
        "database": database,
    }


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run one command and atomically write an evidence-grounded R3 "
            "verification receipt."
        )
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--working-directory", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--timeout-seconds", type=float, default=1800.0)
    parser.add_argument("--excerpt-characters", type=int, default=4000)
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command argv after -- (executed without a shell).",
    )
    args = parser.parse_args(argv)
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    if args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")
    if args.excerpt_characters < 0 or args.excerpt_characters > 20000:
        parser.error("--excerpt-characters must be between 0 and 20000")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    source_root = args.source_root.resolve()
    if not source_root.is_dir():
        raise SystemExit(f"source root is unavailable: {source_root}")
    working_directory = (
        args.working_directory.resolve()
        if args.working_directory is not None
        else source_root
    )
    receipt = build_receipt(
        command=args.command,
        source_root=source_root,
        working_directory=working_directory,
        config_path=args.config,
        database_path=args.database,
        timeout_seconds=args.timeout_seconds,
        excerpt_limit=args.excerpt_characters,
    )
    atomic_write_json(args.output.resolve(), receipt)
    print(
        json.dumps(
            {
                "schema": RECEIPT_SCHEMA,
                "status": receipt["status"],
                "output": args.output.name,
                "command_exit_code": receipt["command"]["exit_code"],
                "manifest_sha256": receipt["source"]["manifest_sha256"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
