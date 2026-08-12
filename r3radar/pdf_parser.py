from __future__ import annotations

import ctypes
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
import uuid
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .windows_appcontainer import (
    AppContainerProfile,
    SuspendedAppContainerProcess,
    build_safe_environment,
    ensure_profile,
    grant_dedicated_runtime_access,
    grant_task_directory_access,
    launch_suspended,
)


REQUEST_SCHEMA = "r3/pdf-parse-request/v1"
RESULT_SCHEMA = "r3/pdf-parse-result/v1"
PARSER_POLICY_VERSION = "r3-pdf-text-v1"
REQUIRED_PYPDF_VERSION = "6.14.2"
REQUIRED_TYPING_EXTENSIONS_VERSION = "4.16.0"
_ALLOWED_FAILURE_CODES = {
    "encrypted_pdf",
    "input_mismatch",
    "invalid_pdf",
    "limit_exceeded",
    "parser_error",
}
_RESULT_KEYS = {
    "schema",
    "request_id",
    "outcome",
    "parser",
    "input",
    "isolation",
    "document",
    "failure",
}
_RUNTIME_SCHEMA = "r3/pdf-appcontainer-runtime/v2"
_RUNTIME_MANIFEST_NAME = "runtime-manifest.json"
_RUNTIME_COPY_EXCLUDED_DIRECTORIES = {
    "__pycache__",
    "ensurepip",
    "idlelib",
    "site-packages",
    "test",
    "tkinter",
    "turtledemo",
}


@dataclass(frozen=True, slots=True)
class PdfExtraction:
    text: str
    text_sha256: str
    page_count: int
    page_map: list[dict[str, int]]
    page_text_non_whitespace: list[int]
    extraction_errors: list[dict[str, Any]]
    parser: dict[str, Any]
    receipt: dict[str, Any]


class PdfParseError(RuntimeError):
    def __init__(
        self,
        reason_code: str,
        failure_code: str,
        message: str,
        *,
        receipt: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.reason_code = reason_code
        self.failure_code = failure_code
        self.receipt = receipt or {}


@dataclass(frozen=True, slots=True)
class _PdfRuntime:
    root: Path
    interpreter: Path
    site_packages: Path
    manifest_sha256: str
    profile: AppContainerProfile


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _sha256_regular_file_exact(path: Path, expected_byte_count: int) -> str:
    metadata = os.lstat(path)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != expected_byte_count
        or getattr(metadata, "st_file_attributes", 0) & reparse_flag
    ):
        raise ValueError("staged artifact identity is invalid")
    digest = hashlib.sha256()
    remaining = expected_byte_count
    with path.open("rb", buffering=0) as handle:
        while remaining:
            block = handle.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("staged artifact ended before its trusted size")
            digest.update(block)
            remaining -= len(block)
        if handle.read(1):
            raise ValueError("staged artifact exceeds its trusted size")
    return digest.hexdigest()


def _staged_artifact_matches(
    path: Path,
    *,
    expected_byte_count: int,
    expected_sha256: str,
) -> bool:
    try:
        return (
            _sha256_regular_file_exact(path, expected_byte_count)
            == expected_sha256
        )
    except (OSError, ValueError):
        return False


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _strict_object(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} does not match the required schema")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _runtime_inventory(root: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.name == _RUNTIME_MANIFEST_NAME:
            continue
        if path.is_symlink():
            raise ValueError(f"runtime contains a symbolic link: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        files.append(
            {
                "path": relative,
                "sha256": _sha256_file(path),
                "byte_count": path.stat().st_size,
            }
        )
    return files


def _runtime_identifier(installed_version: str) -> str:
    raw = (
        f"python-{sys.version_info.major}.{sys.version_info.minor}."
        f"{sys.version_info.micro}-pypdf-{installed_version}-"
        f"typing-{REQUIRED_TYPING_EXTENSIONS_VERSION}-"
        f"{PARSER_POLICY_VERSION}"
    )
    return re.sub(r"[^A-Za-z0-9._-]+", "-", raw)


def _appcontainer_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "sandbox_environment_invalid",
            "LOCALAPPDATA is unavailable for the PDF AppContainer.",
        )
    root = (Path(local_app_data) / "R3ResearchRadar" / "pdf-sandbox").resolve()
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir() or root.is_symlink():
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "sandbox_environment_invalid",
            "The PDF AppContainer root is not a regular directory.",
        )
    return root


def _runtime_manifest(
    root: Path,
    *,
    runtime_id: str,
    installed_version: str,
    profile: AppContainerProfile,
) -> dict[str, Any]:
    return {
        "schema": _RUNTIME_SCHEMA,
        "runtime_id": runtime_id,
        "python_version": (
            f"{sys.version_info.major}.{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        ),
        "pypdf_version": installed_version,
        "typing_extensions_version": REQUIRED_TYPING_EXTENSIONS_VERSION,
        "parser_policy_version": PARSER_POLICY_VERSION,
        "appcontainer_profile": profile.name,
        "appcontainer_sid": profile.sid,
        "files": _runtime_inventory(root),
    }


def _verify_runtime(
    root: Path,
    *,
    runtime_id: str,
    installed_version: str,
    profile: AppContainerProfile,
) -> _PdfRuntime:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("the dedicated PDF runtime is missing or redirected")
    manifest_path = root / _RUNTIME_MANIFEST_NAME
    if (
        not manifest_path.is_file()
        or manifest_path.is_symlink()
        or manifest_path.stat().st_size > 16 * 1024 * 1024
    ):
        raise ValueError("the dedicated PDF runtime manifest is invalid")
    stored = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = _runtime_manifest(
        root,
        runtime_id=runtime_id,
        installed_version=installed_version,
        profile=profile,
    )
    if stored != expected:
        raise ValueError("the dedicated PDF runtime failed its hash manifest")
    interpreter = (root / "python.exe").resolve(strict=True)
    site_packages = (root / "Lib" / "site-packages").resolve(strict=True)
    if (
        not interpreter.is_file()
        or interpreter.is_symlink()
        or not site_packages.is_dir()
        or site_packages.is_symlink()
    ):
        raise ValueError("the dedicated PDF runtime layout is invalid")
    return _PdfRuntime(
        root=root,
        interpreter=interpreter,
        site_packages=site_packages,
        manifest_sha256=_sha256_text(_canonical_json(stored)),
        profile=profile,
    )


def _runtime_ignore(_directory: str, names: list[str]) -> set[str]:
    return {
        name
        for name in names
        if name in _RUNTIME_COPY_EXCLUDED_DIRECTORIES
        or name.casefold().endswith((".pyc", ".pyo"))
    }


def _build_runtime(
    destination: Path,
    *,
    runtime_id: str,
    installed_version: str,
    profile: AppContainerProfile,
) -> None:
    base = Path(sys.base_prefix).resolve(strict=True)
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            raise FileExistsError(destination)
    else:
        destination.mkdir(parents=True)
    for name in (
        "python.exe",
        "python3.dll",
        f"python{sys.version_info.major}{sys.version_info.minor}.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "LICENSE.txt",
    ):
        source = base / name
        if source.is_file():
            shutil.copy2(source, destination / name)
    if not (destination / "python.exe").is_file():
        raise ValueError("the base Python runtime has no python.exe")
    for directory_name in ("DLLs", "Lib"):
        source = base / directory_name
        if not source.is_dir():
            raise ValueError(f"the base Python runtime has no {directory_name}")
        shutil.copytree(
            source,
            destination / directory_name,
            ignore=_runtime_ignore,
        )

    specification = importlib.util.find_spec("pypdf")
    if specification is None or specification.origin is None:
        raise ValueError("the pinned pypdf package could not be located")
    pypdf_source = Path(specification.origin).resolve(strict=True).parent
    site_packages = destination / "Lib" / "site-packages"
    site_packages.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        pypdf_source,
        site_packages / "pypdf",
        ignore=_runtime_ignore,
    )
    source_site_packages = pypdf_source.parent
    dist_info_candidates = sorted(
        source_site_packages.glob(f"pypdf-{installed_version}.dist-info")
    )
    if len(dist_info_candidates) != 1:
        raise ValueError("the pinned pypdf distribution metadata is unavailable")
    shutil.copytree(
        dist_info_candidates[0],
        site_packages / dist_info_candidates[0].name,
        ignore=_runtime_ignore,
    )
    typing_extensions_source = source_site_packages / "typing_extensions.py"
    if not typing_extensions_source.is_file():
        raise ValueError("the pinned typing_extensions module is unavailable")
    shutil.copy2(
        typing_extensions_source,
        site_packages / "typing_extensions.py",
    )
    typing_dist_info_candidates = sorted(
        source_site_packages.glob(
            f"typing_extensions-{REQUIRED_TYPING_EXTENSIONS_VERSION}.dist-info"
        )
    )
    if len(typing_dist_info_candidates) != 1:
        raise ValueError(
            "the pinned typing_extensions distribution metadata is unavailable"
        )
    shutil.copytree(
        typing_dist_info_candidates[0],
        site_packages / typing_dist_info_candidates[0].name,
        ignore=_runtime_ignore,
    )
    manifest = _runtime_manifest(
        destination,
        runtime_id=runtime_id,
        installed_version=installed_version,
        profile=profile,
    )
    (destination / _RUNTIME_MANIFEST_NAME).write_text(
        _canonical_json(manifest) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    grant_dedicated_runtime_access(destination, profile)


def _ensure_runtime(installed_version: str) -> _PdfRuntime:
    try:
        profile = ensure_profile()
        root = _appcontainer_root() / "runtime"
        root.mkdir(parents=True, exist_ok=True)
        runtime_id = _runtime_identifier(installed_version)
        destination = root / runtime_id
        if not destination.exists():
            with tempfile.TemporaryDirectory(
                prefix=f".{runtime_id}.",
                dir=root,
            ) as temporary:
                staged = Path(temporary).resolve()
                _build_runtime(
                    staged,
                    runtime_id=runtime_id,
                    installed_version=installed_version,
                    profile=profile,
                )
                try:
                    staged.replace(destination)
                except OSError:
                    if not destination.is_dir():
                        raise
        return _verify_runtime(
            destination,
            runtime_id=runtime_id,
            installed_version=installed_version,
            profile=profile,
        )
    except PdfParseError:
        raise
    except Exception as exc:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "appcontainer_runtime_unavailable",
            "The dedicated PDF AppContainer runtime is unavailable.",
        ) from exc


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _JobBasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong),
        ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong),
        ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", wintypes.DWORD),
        ("TotalProcesses", wintypes.DWORD),
        ("ActiveProcesses", wintypes.DWORD),
        ("TotalTerminatedProcesses", wintypes.DWORD),
    ]


class _WindowsJob:
    _PROCESS_TIME = 0x00000002
    _ACTIVE_PROCESS = 0x00000008
    _PROCESS_MEMORY = 0x00000100
    _JOB_MEMORY = 0x00000200
    _KILL_ON_JOB_CLOSE = 0x00002000
    _BASIC_ACCOUNTING_INFORMATION = 1
    _EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self, *, cpu_seconds: int, memory_bytes: int):
        if os.name != "nt":
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "sandbox_unavailable",
                "The configured PDF sandbox is only available on Windows.",
            )
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateJobObjectW.argtypes = [
            wintypes.LPVOID,
            wintypes.LPCWSTR,
        ]
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
        ]
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.TerminateJobObject.argtypes = [
            wintypes.HANDLE,
            wintypes.UINT,
        ]
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._handle = self._kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            error = ctypes.get_last_error()
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "job_object_unavailable",
                f"Windows Job Object creation failed ({error}).",
            )
        information = _JobExtendedLimitInformation()
        information.BasicLimitInformation.PerProcessUserTimeLimit = (
            int(cpu_seconds) * 10_000_000
        )
        information.BasicLimitInformation.ActiveProcessLimit = 1
        information.BasicLimitInformation.LimitFlags = (
            self._PROCESS_TIME
            | self._ACTIVE_PROCESS
            | self._PROCESS_MEMORY
            | self._JOB_MEMORY
            | self._KILL_ON_JOB_CLOSE
        )
        information.ProcessMemoryLimit = int(memory_bytes)
        information.JobMemoryLimit = int(memory_bytes)
        if not self._kernel32.SetInformationJobObject(
            self._handle,
            self._EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            error = ctypes.get_last_error()
            self.close()
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "job_limits_unavailable",
                f"Windows Job Object limits could not be applied ({error}).",
            )

    @property
    def handle(self) -> int:
        if not self._handle:
            raise RuntimeError("the PDF Job Object is closed")
        return int(self._handle)

    def assign(self, process: SuspendedAppContainerProcess) -> None:
        try:
            process.assign_to_job(self.handle)
        except OSError as exc:
            self.terminate(92)
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "job_assignment_failed",
                "The PDF worker could not enter its Job Object.",
            ) from exc

    def accounting(self) -> dict[str, int]:
        basic = _JobBasicAccountingInformation()
        returned = wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
            self._handle,
            self._BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(basic),
            ctypes.sizeof(basic),
            ctypes.byref(returned),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "QueryInformationJobObject(accounting) failed")
        extended = _JobExtendedLimitInformation()
        if not self._kernel32.QueryInformationJobObject(
            self._handle,
            self._EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(extended),
            ctypes.sizeof(extended),
            ctypes.byref(returned),
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "QueryInformationJobObject(limits) failed")
        return {
            "total_user_time_100ns": int(basic.TotalUserTime),
            "total_kernel_time_100ns": int(basic.TotalKernelTime),
            "total_page_fault_count": int(basic.TotalPageFaultCount),
            "total_processes": int(basic.TotalProcesses),
            "active_processes": int(basic.ActiveProcesses),
            "total_terminated_processes": int(basic.TotalTerminatedProcesses),
            "peak_process_memory_bytes": int(extended.PeakProcessMemoryUsed),
            "peak_job_memory_bytes": int(extended.PeakJobMemoryUsed),
        }

    def terminate(self, exit_code: int) -> None:
        if self._handle:
            self._kernel32.TerminateJobObject(self._handle, int(exit_code))

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


class _WindowsPdfMutex:
    _WAIT_OBJECT_0 = 0
    _WAIT_ABANDONED = 0x80
    _WAIT_TIMEOUT = 258

    def __init__(self, *, timeout_seconds: int):
        if os.name != "nt":
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "sandbox_unavailable",
                "The PDF AppContainer mutex is only available on Windows.",
            )
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateMutexW.argtypes = [
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        self._kernel32.CreateMutexW.restype = wintypes.HANDLE
        self._kernel32.WaitForSingleObject.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
        ]
        self._kernel32.WaitForSingleObject.restype = wintypes.DWORD
        self._kernel32.ReleaseMutex.argtypes = [wintypes.HANDLE]
        self._kernel32.ReleaseMutex.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._handle = self._kernel32.CreateMutexW(
            None,
            False,
            "Local\\R3ResearchRadarPdfParserV1Serial",
        )
        if not self._handle:
            error = ctypes.get_last_error()
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "appcontainer_mutex_unavailable",
                f"The PDF AppContainer mutex could not be created ({error}).",
            )
        result = int(
            self._kernel32.WaitForSingleObject(
                self._handle,
                int(timeout_seconds) * 1000,
            )
        )
        if result not in {self._WAIT_OBJECT_0, self._WAIT_ABANDONED}:
            self.close(release=False)
            code = (
                "appcontainer_busy"
                if result == self._WAIT_TIMEOUT
                else "appcontainer_mutex_unavailable"
            )
            raise PdfParseError(
                "pdf_extract_worker_failed",
                code,
                "The serialized PDF AppContainer could not be acquired.",
            )
        self._owned = True

    def close(self, *, release: bool = True) -> None:
        handle = getattr(self, "_handle", None)
        if not handle:
            return
        if release and getattr(self, "_owned", False):
            self._kernel32.ReleaseMutex(handle)
        self._kernel32.CloseHandle(handle)
        self._handle = None
        self._owned = False

    def __enter__(self) -> _WindowsPdfMutex:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _validate_result(
    raw: Any,
    *,
    request_id: str,
    expected_sha256: str,
    expected_byte_count: int,
    limits: dict[str, int],
    installed_version: str,
) -> PdfExtraction:
    result = _strict_object(raw, _RESULT_KEYS, "result")
    if result["schema"] != RESULT_SCHEMA or result["request_id"] != request_id:
        raise ValueError("result identity does not match the request")
    parser = _strict_object(
        result["parser"],
        {
            "id",
            "version",
            "policy_version",
            "effective_options",
            "options_sha256",
        },
        "result.parser",
    )
    options = {"strict": False}
    if (
        parser["id"] != "pypdf"
        or parser["version"] != installed_version
        or parser["policy_version"] != PARSER_POLICY_VERSION
        or parser["effective_options"] != options
        or parser["options_sha256"] != _sha256_text(_canonical_json(options))
    ):
        raise ValueError("parser identity or options are invalid")
    input_value = _strict_object(
        result["input"],
        {"sha256", "byte_count"},
        "result.input",
    )
    if (
        input_value["sha256"] != expected_sha256
        or input_value["byte_count"] != expected_byte_count
    ):
        raise ValueError("worker input identity does not match the staged PDF")
    isolation = _strict_object(
        result["isolation"],
        {"integrity_level", "credential_environment_keys"},
        "result.isolation",
    )
    if isolation["integrity_level"] != "appcontainer_low":
        raise ValueError("worker did not report low-integrity AppContainer execution")
    if isolation["credential_environment_keys"] != []:
        raise ValueError("worker environment contains credential-like variables")

    if result["outcome"] == "failed":
        if result["document"] is not None:
            raise ValueError("failed result must not contain a document")
        failure = _strict_object(
            result["failure"],
            {"code", "error_type", "message"},
            "result.failure",
        )
        if failure["code"] not in _ALLOWED_FAILURE_CODES:
            raise ValueError("worker failure code is invalid")
        if not all(
            isinstance(failure[key], str)
            for key in ("code", "error_type", "message")
        ):
            raise ValueError("worker failure fields must be strings")
        raise PdfParseError(
            "pdf_extract_worker_failed",
            str(failure["code"]),
            "The PDF was quarantined because the parser rejected it.",
            receipt={
                "worker_outcome": "failed",
                "worker_failure_code": str(failure["code"]),
                "worker_error_type": str(failure["error_type"])[:120],
            },
        )
    if result["outcome"] != "parsed" or result["failure"] is not None:
        raise ValueError("worker outcome is invalid")

    document = _strict_object(
        result["document"],
        {
            "page_count",
            "rendered_character_count",
            "non_whitespace_total",
            "pages",
        },
        "result.document",
    )
    page_count = _positive_int(document["page_count"], "page_count")
    if page_count > limits["max_pages"]:
        raise ValueError("worker page count exceeds the parent limit")
    if not isinstance(document["pages"], list) or len(document["pages"]) != page_count:
        raise ValueError("worker page list is incomplete")

    rendered_pages: list[str] = []
    page_map: list[dict[str, int]] = []
    page_non_whitespace: list[int] = []
    extraction_errors: list[dict[str, Any]] = []
    offset = 0
    for index, raw_page in enumerate(document["pages"], start=1):
        page = _strict_object(
            raw_page,
            {
                "page",
                "text",
                "non_whitespace",
                "rendered_character_count",
                "rendered_sha256",
                "outcome",
                "error",
            },
            f"result.document.pages[{index}]",
        )
        if page["page"] != index or not isinstance(page["text"], str):
            raise ValueError("worker page order or text type is invalid")
        non_whitespace = len(re.sub(r"\s+", "", page["text"]))
        if (
            isinstance(page["non_whitespace"], bool)
            or page["non_whitespace"] != non_whitespace
        ):
            raise ValueError("worker page non-whitespace count is invalid")
        rendered = f"=== PAGE {index} ===\n{page['text']}\n"
        if (
            page["rendered_character_count"] != len(rendered)
            or page["rendered_sha256"] != _sha256_text(rendered)
        ):
            raise ValueError("worker page hash or length is invalid")
        error = page["error"]
        if error is None:
            expected_outcome = "empty" if non_whitespace == 0 else "ok"
        else:
            error_value = _strict_object(
                error,
                {"error_type", "message"},
                f"result.document.pages[{index}].error",
            )
            if not all(isinstance(value, str) for value in error_value.values()):
                raise ValueError("worker page error fields must be strings")
            expected_outcome = "error"
            extraction_errors.append(
                {
                    "page": index,
                    "error_type": error_value["error_type"][:120],
                    "error": error_value["message"][:240],
                }
            )
        if page["outcome"] != expected_outcome:
            raise ValueError("worker page outcome is inconsistent")
        start = offset
        offset += len(rendered)
        rendered_pages.append(rendered)
        page_map.append({"page": index, "start": start, "end": offset})
        page_non_whitespace.append(non_whitespace)

    text = "".join(rendered_pages)
    if (
        len(text) != document["rendered_character_count"]
        or len(text) > limits["max_output_characters"]
        or sum(page_non_whitespace) != document["non_whitespace_total"]
    ):
        raise ValueError("worker document totals are invalid")
    return PdfExtraction(
        text=text,
        text_sha256=_sha256_text(text),
        page_count=page_count,
        page_map=page_map,
        page_text_non_whitespace=page_non_whitespace,
        extraction_errors=extraction_errors,
        parser={
            **parser,
            "request_schema": REQUEST_SCHEMA,
            "result_schema": RESULT_SCHEMA,
            "isolation": isolation,
        },
        receipt={},
    )


def parse_pdf_with_worker(
    input_path: Path,
    *,
    expected_sha256: str,
    expected_byte_count: int,
    config: dict[str, Any],
    _worker_path: Path | None = None,
) -> PdfExtraction:
    installed_version = importlib.metadata.version("pypdf")
    if installed_version != REQUIRED_PYPDF_VERSION:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "unsupported_parser_version",
            (
                "The PDF parser dependency does not match the required "
                f"version {REQUIRED_PYPDF_VERSION}."
            ),
        )
    typing_extensions_version = importlib.metadata.version("typing_extensions")
    if typing_extensions_version != REQUIRED_TYPING_EXTENSIONS_VERSION:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "unsupported_parser_version",
            (
                "The PDF parser runtime dependency typing_extensions does not "
                f"match version {REQUIRED_TYPING_EXTENSIONS_VERSION}."
            ),
        )
    if config.get("backend") != "pypdf_worker":
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "unsupported_parser_backend",
            "The configured PDF parser backend is not allowed.",
        )
    if config.get("policy_version") != PARSER_POLICY_VERSION:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "unsupported_parser_policy",
            "The configured PDF parser policy is not allowed.",
        )
    limits = {
        "wall_timeout_seconds": _positive_int(
            config.get("wall_timeout_seconds"),
            "wall_timeout_seconds",
        ),
        "cpu_time_seconds": _positive_int(
            config.get("cpu_time_seconds"),
            "cpu_time_seconds",
        ),
        "memory_limit_bytes": _positive_int(
            config.get("memory_limit_bytes"),
            "memory_limit_bytes",
        ),
        "max_pages": _positive_int(config.get("max_pages"), "max_pages"),
        "max_output_characters": _positive_int(
            config.get("max_output_characters"),
            "max_output_characters",
        ),
        "max_result_bytes": _positive_int(
            config.get("max_result_bytes"),
            "max_result_bytes",
        ),
        "max_input_bytes": _positive_int(
            config.get("max_input_bytes"),
            "max_input_bytes",
        ),
    }
    source = Path(input_path).resolve(strict=True)
    if source.stat().st_size != expected_byte_count:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "input_mismatch",
            "The quarantined PDF size changed before parsing.",
        )
    if expected_byte_count > limits["max_input_bytes"]:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "limit_exceeded",
            "The quarantined PDF exceeds the parser input limit.",
        )
    if _sha256_file(source) != expected_sha256:
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "input_mismatch",
            "The quarantined PDF hash changed before parsing.",
        )

    package_dir = Path(__file__).resolve().parent
    sandbox_source = (package_dir / "pdf_sandbox.py").resolve(strict=True)
    worker_source = (_worker_path or (package_dir / "pdf_worker.py")).resolve(
        strict=True
    )
    sandbox_byte_count = sandbox_source.stat().st_size
    worker_byte_count = worker_source.stat().st_size
    sandbox_sha256 = _sha256_file(sandbox_source)
    worker_sha256 = _sha256_file(worker_source)
    runtime_started = time.monotonic()
    runtime = _ensure_runtime(installed_version)
    runtime_setup_ms = round((time.monotonic() - runtime_started) * 1000)
    request_id = uuid.uuid4().hex
    started = time.monotonic()
    receipt: dict[str, Any] = {
        "request_id": request_id,
        "parser_id": "pypdf",
        "parser_version": installed_version,
        "parser_policy_version": PARSER_POLICY_VERSION,
        "request_schema": REQUEST_SCHEMA,
        "result_schema": RESULT_SCHEMA,
        "sandbox_sha256": sandbox_sha256,
        "worker_sha256": worker_sha256,
        "runtime_manifest_sha256": runtime.manifest_sha256,
        "runtime_setup_ms": runtime_setup_ms,
        "limits": limits,
        "sandbox": {
            "environment": "allowlist",
            "container": "appcontainer",
            "integrity": "low",
            "capability_count": 0,
            "network_capability": False,
            "dedicated_runtime": True,
            "job_object": True,
            "active_process_limit": 1,
            "kill_on_job_close": True,
            "gate_before_untrusted_code": True,
            "create_suspended": True,
            "isolated_site_packages": True,
        },
    }
    job: _WindowsJob | None = None
    process: SuspendedAppContainerProcess | None = None
    jobs_root = _appcontainer_root() / "jobs"
    jobs_root.mkdir(parents=True, exist_ok=True)
    if not jobs_root.is_dir() or jobs_root.is_symlink():
        raise PdfParseError(
            "pdf_extract_worker_failed",
            "sandbox_environment_invalid",
            "The PDF AppContainer jobs root is invalid.",
            receipt=receipt,
        )
    with _WindowsPdfMutex(
        timeout_seconds=limits["wall_timeout_seconds"] + 60
    ), tempfile.TemporaryDirectory(prefix="r3-pdf-", dir=jobs_root) as temporary:
        job_dir = Path(temporary).resolve()
        receipt["job_id"] = job_dir.name
        staged_input = job_dir / "input.pdf"
        request_path = job_dir / "request.json"
        gate_path = job_dir / "start.gate"
        output_dir = job_dir / "output"
        sandbox_path = job_dir / "pdf_sandbox.py"
        worker_path = job_dir / "pdf_worker.py"
        output_dir.mkdir()
        shutil.copyfile(source, staged_input)
        shutil.copyfile(sandbox_source, sandbox_path)
        shutil.copyfile(worker_source, worker_path)

        def staged_artifacts_match() -> bool:
            return (
                _staged_artifact_matches(
                    staged_input,
                    expected_byte_count=expected_byte_count,
                    expected_sha256=expected_sha256,
                )
                and _staged_artifact_matches(
                    sandbox_path,
                    expected_byte_count=sandbox_byte_count,
                    expected_sha256=sandbox_sha256,
                )
                and _staged_artifact_matches(
                    worker_path,
                    expected_byte_count=worker_byte_count,
                    expected_sha256=worker_sha256,
                )
            )

        if not staged_artifacts_match():
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "input_mismatch",
                "A staged PDF or worker identity does not match its trusted source.",
                receipt=receipt,
            )
        request = {
            "schema": REQUEST_SCHEMA,
            "request_id": request_id,
            "input": {
                "path": "input.pdf",
                "sha256": expected_sha256,
                "byte_count": expected_byte_count,
            },
            "parser": {
                "id": "pypdf",
                "policy_version": PARSER_POLICY_VERSION,
                "options": {"strict": False},
            },
            "limits": {
                "max_input_bytes": limits["max_input_bytes"],
                "max_pages": limits["max_pages"],
                "max_output_characters": limits["max_output_characters"],
                "max_result_bytes": limits["max_result_bytes"],
            },
        }
        request_path.write_text(
            _canonical_json(request) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        try:
            grant_task_directory_access(job_dir, runtime.profile)
            environment = build_safe_environment(
                job_dir,
                executable=runtime.interpreter,
            )
        except Exception as exc:
            raise PdfParseError(
                "pdf_extract_worker_failed",
                "appcontainer_task_acl_unavailable",
                "The per-task PDF AppContainer boundary could not be prepared.",
                receipt=receipt,
            ) from exc
        arguments = [
            "-I",
            "-S",
            "-B",
            "-u",
            "-X",
            "utf8",
            str(sandbox_path),
            "--worker",
            str(worker_path),
            "--request",
            str(request_path),
            "--output-dir",
            str(output_dir),
            "--gate",
            str(gate_path),
            "--site-packages",
            str(runtime.site_packages),
        ]
        try:
            job = _WindowsJob(
                cpu_seconds=limits["cpu_time_seconds"],
                memory_bytes=limits["memory_limit_bytes"],
            )
            try:
                process = launch_suspended(
                    runtime.interpreter,
                    arguments,
                    current_directory=output_dir,
                    environment=environment,
                    profile=runtime.profile,
                )
            except Exception as exc:
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "appcontainer_launch_failed",
                    "The PDF worker could not be created inside its AppContainer.",
                    receipt=receipt,
                ) from exc
            receipt["sandbox"]["capability_count"] = process.capability_count
            receipt["sandbox"]["profile_sid_sha256"] = _sha256_text(
                runtime.profile.sid
            )
            job.assign(process)
            process.resume()
            try:
                gate_path.write_bytes(b"go\n")
            except OSError as exc:
                job.terminate(128)
                if not process.wait(10_000):
                    process.terminate(125)
                    process.wait(10_000)
                receipt.update(
                    {
                        "duration_ms": round(
                            (time.monotonic() - started) * 1000
                        ),
                        "return_code": process.poll(),
                        "termination": "gate_failure",
                    }
                )
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "sandbox_gate_unavailable",
                    (
                        "The PDF worker could not enter its gated execution "
                        "phase and was terminated."
                    ),
                    receipt=receipt,
                ) from exc
            wall_deadline = (
                time.monotonic() + limits["wall_timeout_seconds"]
            )
            cpu_limit_100ns = limits["cpu_time_seconds"] * 10_000_000
            while True:
                remaining_ms = max(
                    0,
                    round((wall_deadline - time.monotonic()) * 1000),
                )
                if remaining_ms == 0:
                    break
                if process.wait(min(100, remaining_ms)):
                    break
                try:
                    current_accounting = job.accounting()
                except OSError as exc:
                    job.terminate(127)
                    process.wait(10_000)
                    raise PdfParseError(
                        "pdf_extract_worker_failed",
                        "job_accounting_unavailable",
                        (
                            "The PDF worker Job Object accounting could not "
                            "be read while enforcing its CPU limit."
                        ),
                        receipt=receipt,
                    ) from exc
                observed_cpu_100ns = (
                    current_accounting["total_user_time_100ns"]
                    + current_accounting["total_kernel_time_100ns"]
                )
                if observed_cpu_100ns >= cpu_limit_100ns:
                    job.terminate(126)
                    if not process.wait(10_000):
                        process.terminate(125)
                    receipt["job_accounting"] = job.accounting()
                    receipt.update(
                        {
                            "duration_ms": round(
                                (time.monotonic() - started) * 1000
                            ),
                            "return_code": process.poll(),
                            "termination": "cpu_time_limit",
                        }
                    )
                    raise PdfParseError(
                        "pdf_extract_worker_failed",
                        "cpu_time_limit",
                        (
                            "PDF extraction exceeded its CPU-time limit and "
                            "was terminated."
                        ),
                        receipt=receipt,
                    )
            if process.poll() is None:
                job.terminate(124)
                if not process.wait(10_000):
                    process.terminate(125)
                return_code = process.poll()
                try:
                    receipt["job_accounting"] = job.accounting()
                except OSError as accounting_error:
                    receipt["job_accounting_error"] = type(
                        accounting_error
                    ).__name__
                receipt.update(
                    {
                        "duration_ms": round(
                            (time.monotonic() - started) * 1000
                        ),
                        "return_code": return_code,
                        "termination": "wall_timeout",
                    }
                )
                if not staged_artifacts_match():
                    raise PdfParseError(
                        "pdf_extract_worker_failed",
                        "staged_artifact_modified",
                        "A staged PDF or worker artifact changed during parsing.",
                        receipt=receipt,
                    )
                raise PdfParseError(
                    "pdf_extract_timeout",
                    "wall_timeout",
                    "PDF extraction exceeded its wall-clock limit and was terminated.",
                    receipt=receipt,
                )
            return_code = process.poll()
            if return_code is None:
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "worker_state_invalid",
                    "The PDF worker wait completed without an exit code.",
                    receipt=receipt,
                )
            try:
                receipt["job_accounting"] = job.accounting()
            except OSError as exc:
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "job_accounting_unavailable",
                    "The PDF worker Job Object accounting could not be read.",
                    receipt=receipt,
                ) from exc
            receipt.update(
                {
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "return_code": return_code,
                    "termination": "process_exit",
                }
            )
            if return_code != 0:
                diagnostic_path = output_dir / "bootstrap-error.json"
                if (
                    diagnostic_path.is_file()
                    and not diagnostic_path.is_symlink()
                    and diagnostic_path.stat().st_size <= 4096
                ):
                    try:
                        diagnostic = json.loads(
                            diagnostic_path.read_text(encoding="utf-8")
                        )
                        diagnostic = _strict_object(
                            diagnostic,
                            {"schema", "error_type", "message"},
                            "bootstrap diagnostic",
                        )
                        if diagnostic["schema"] == "r3/pdf-bootstrap-error/v1":
                            receipt["bootstrap_error_type"] = str(
                                diagnostic["error_type"]
                            )[:120]
                    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                        receipt["bootstrap_error_invalid"] = True
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "worker_nonzero_exit",
                    "The PDF worker exited without a trusted result.",
                    receipt=receipt,
            )
            if not staged_artifacts_match():
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "staged_artifact_modified",
                    "A staged PDF or worker artifact changed during parsing.",
                    receipt=receipt,
                )
            result_path = output_dir / "result.json"
            if not result_path.is_file() or result_path.is_symlink():
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "result_missing",
                    "The PDF worker did not produce a regular result file.",
                    receipt=receipt,
                )
            result_size = result_path.stat().st_size
            if result_size <= 0 or result_size > limits["max_result_bytes"]:
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "result_size_invalid",
                    "The PDF worker result exceeded its configured size boundary.",
                    receipt=receipt,
                )
            result_bytes = result_path.read_bytes()
            receipt["result_sha256"] = hashlib.sha256(result_bytes).hexdigest()
            receipt["result_byte_count"] = len(result_bytes)
            try:
                raw_result = json.loads(result_bytes.decode("utf-8"))
                extraction = _validate_result(
                    raw_result,
                    request_id=request_id,
                    expected_sha256=expected_sha256,
                    expected_byte_count=expected_byte_count,
                    limits=limits,
                    installed_version=installed_version,
                )
            except PdfParseError as exc:
                merged = {**receipt, **exc.receipt}
                raise PdfParseError(
                    exc.reason_code,
                    exc.failure_code,
                    str(exc),
                    receipt=merged,
                ) from exc
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise PdfParseError(
                    "pdf_extract_worker_failed",
                    "result_schema_invalid",
                    "The PDF worker result failed parent-side schema validation.",
                    receipt=receipt,
                ) from exc
            return PdfExtraction(
                text=extraction.text,
                text_sha256=extraction.text_sha256,
                page_count=extraction.page_count,
                page_map=extraction.page_map,
                page_text_non_whitespace=extraction.page_text_non_whitespace,
                extraction_errors=extraction.extraction_errors,
                parser=extraction.parser,
                receipt=receipt,
            )
        finally:
            active_exception = sys.exc_info()[0] is not None
            process_error: BaseException | None = None
            if process is not None:
                try:
                    process.close()
                except BaseException as exc:
                    process_error = exc
            if job is not None:
                job.close()
            if process_error is not None and not active_exception:
                raise process_error
