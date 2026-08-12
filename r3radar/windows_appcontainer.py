from __future__ import annotations

"""Small Windows AppContainer launcher for untrusted worker processes.

The module deliberately has no third-party dependencies.  It creates or reuses
one stable, zero-capability AppContainer profile, grants that profile access
only to a dedicated runtime copy and a per-task directory, and returns a
verified AppContainer process while its primary thread is still suspended.
The caller can therefore assign the process to a Job Object before resuming it.
"""

import ctypes
import os
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


DEFAULT_PROFILE_NAME = "R3ResearchRadarPdfParserV1"

_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_NO_WINDOW = 0x08000000
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009

_ERROR_ALREADY_EXISTS = 183
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_SUCCESS = 0
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_WAIT_FAILED = 0xFFFFFFFF
_STILL_ACTIVE = 259

_TOKEN_QUERY = 0x0008
_TOKEN_IS_APP_CONTAINER = 29
_TOKEN_CAPABILITIES = 30

_SE_FILE_OBJECT = 1
_DACL_SECURITY_INFORMATION = 0x00000004
_GRANT_ACCESS = 1
_TRUSTEE_IS_SID = 0
_TRUSTEE_IS_UNKNOWN = 0
_OBJECT_INHERIT_ACE = 0x00000001
_CONTAINER_INHERIT_ACE = 0x00000002

_DELETE = 0x00010000
_FILE_GENERIC_READ = 0x00120089
_FILE_GENERIC_WRITE = 0x00120116
_FILE_GENERIC_EXECUTE = 0x001200A0
_RUNTIME_ACCESS = _FILE_GENERIC_READ | _FILE_GENERIC_EXECUTE
_TASK_ACCESS = (
    _FILE_GENERIC_READ
    | _FILE_GENERIC_WRITE
    | _FILE_GENERIC_EXECUTE
    | _DELETE
)

_SAFE_ENVIRONMENT_NAMES = (
    "ALLUSERSPROFILE",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "COMPUTERNAME",
    "ComSpec",
    "DriverData",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "OS",
    "PATHEXT",
    "PROCESSOR_ARCHITECTURE",
    "PROCESSOR_IDENTIFIER",
    "PROCESSOR_LEVEL",
    "PROCESSOR_REVISION",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "PUBLIC",
    "SystemDrive",
    "SystemRoot",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE",
    "WINDIR",
)


class _SecurityCapabilities(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", wintypes.LPVOID),
        ("Capabilities", wintypes.LPVOID),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _StartupInfoEx(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _StartupInfo),
        ("lpAttributeList", wintypes.LPVOID),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class _Trustee(ctypes.Structure):
    _fields_ = [
        ("pMultipleTrustee", wintypes.LPVOID),
        ("MultipleTrusteeOperation", ctypes.c_int),
        ("TrusteeForm", ctypes.c_int),
        ("TrusteeType", ctypes.c_int),
        ("ptstrName", wintypes.LPVOID),
    ]


class _ExplicitAccess(ctypes.Structure):
    _fields_ = [
        ("grfAccessPermissions", wintypes.DWORD),
        ("grfAccessMode", ctypes.c_int),
        ("grfInheritance", wintypes.DWORD),
        ("Trustee", _Trustee),
    ]


@dataclass(frozen=True, slots=True)
class AppContainerProfile:
    name: str
    sid: str


@dataclass(frozen=True, slots=True)
class _WindowsApis:
    kernel32: Any
    advapi32: Any
    userenv: Any


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows AppContainer is only available on Windows")


def _raise_last_error(operation: str) -> None:
    error = ctypes.get_last_error()
    raise OSError(error, f"{operation} failed with Windows error {error}")


def _raise_status(operation: str, status: int) -> None:
    raise OSError(status, f"{operation} failed with Windows error {status}")


@lru_cache(maxsize=1)
def _apis() -> _WindowsApis:
    _require_windows()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    userenv = ctypes.WinDLL("userenv", use_last_error=True)

    kernel32.InitializeProcThreadAttributeList.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    kernel32.UpdateProcThreadAttribute.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.c_size_t,
        wintypes.LPVOID,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    kernel32.DeleteProcThreadAttributeList.argtypes = [wintypes.LPVOID]
    kernel32.DeleteProcThreadAttributeList.restype = None
    kernel32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfoEx),
        ctypes.POINTER(_ProcessInformation),
    ]
    kernel32.CreateProcessW.restype = wintypes.BOOL
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [
        wintypes.HANDLE,
        wintypes.UINT,
    ]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
    ]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSidToSidW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
    advapi32.IsValidSid.argtypes = [wintypes.LPVOID]
    advapi32.IsValidSid.restype = wintypes.BOOL
    advapi32.FreeSid.argtypes = [wintypes.LPVOID]
    advapi32.FreeSid.restype = wintypes.LPVOID
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.SetEntriesInAclW.argtypes = [
        wintypes.ULONG,
        ctypes.POINTER(_ExplicitAccess),
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    advapi32.SetEntriesInAclW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD

    userenv.CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    userenv.CreateAppContainerProfile.restype = ctypes.c_long
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    return _WindowsApis(
        kernel32=kernel32,
        advapi32=advapi32,
        userenv=userenv,
    )


def _close_handle(handle: int | None, operation: str = "CloseHandle") -> None:
    if handle and not _apis().kernel32.CloseHandle(wintypes.HANDLE(handle)):
        _raise_last_error(operation)


def _free_sid(sid: wintypes.LPVOID) -> None:
    if sid and _apis().advapi32.FreeSid(sid):
        _raise_last_error("FreeSid")


def _local_free(pointer: Any) -> None:
    if pointer and _apis().kernel32.LocalFree(pointer):
        _raise_last_error("LocalFree")


def _sid_to_string(sid: wintypes.LPVOID) -> str:
    apis = _apis()
    if not sid or not apis.advapi32.IsValidSid(sid):
        raise OSError("Windows returned an invalid AppContainer SID")
    text = wintypes.LPWSTR()
    if not apis.advapi32.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        _raise_last_error("ConvertSidToStringSidW")
    try:
        if not text.value:
            raise OSError("Windows returned an empty AppContainer SID")
        return text.value
    finally:
        _local_free(text)


def _hresult_win32_code(result: int) -> int | None:
    unsigned = ctypes.c_uint32(result).value
    if unsigned & 0xFFFF0000 == 0x80070000:
        return unsigned & 0xFFFF
    return None


def _derive_profile_sid(name: str) -> wintypes.LPVOID:
    sid = wintypes.LPVOID()
    result = int(
        _apis().userenv.DeriveAppContainerSidFromAppContainerName(
            name,
            ctypes.byref(sid),
        )
    )
    if result < 0:
        if sid:
            _free_sid(sid)
        raise OSError(
            ctypes.c_uint32(result).value,
            "DeriveAppContainerSidFromAppContainerName failed",
        )
    if not sid or not _apis().advapi32.IsValidSid(sid):
        if sid:
            _free_sid(sid)
        raise OSError("Windows returned an invalid derived AppContainer SID")
    return sid


def ensure_profile(
    name: str = DEFAULT_PROFILE_NAME,
) -> AppContainerProfile:
    """Create or reuse the stable zero-capability AppContainer profile."""

    _require_windows()
    if not name or "\0" in name:
        raise ValueError("profile name must be a non-empty string without NUL")
    sid = wintypes.LPVOID()
    result = int(
        _apis().userenv.CreateAppContainerProfile(
            name,
            name,
            "R3 isolated PDF parser",
            None,
            0,
            ctypes.byref(sid),
        )
    )
    if result < 0:
        if _hresult_win32_code(result) != _ERROR_ALREADY_EXISTS:
            if sid:
                _free_sid(sid)
            raise OSError(
                ctypes.c_uint32(result).value,
                "CreateAppContainerProfile failed",
            )
        if sid:
            _free_sid(sid)
        sid = _derive_profile_sid(name)
    try:
        return AppContainerProfile(name=name, sid=_sid_to_string(sid))
    finally:
        _free_sid(sid)


class _LocalSid:
    def __init__(self, value: str):
        self._pointer = wintypes.LPVOID()
        if not _apis().advapi32.ConvertStringSidToSidW(
            value,
            ctypes.byref(self._pointer),
        ):
            _raise_last_error("ConvertStringSidToSidW")
        if not self._pointer or not _apis().advapi32.IsValidSid(self._pointer):
            self.close()
            raise ValueError("profile SID is invalid")

    @property
    def pointer(self) -> wintypes.LPVOID:
        if not self._pointer:
            raise RuntimeError("SID has already been released")
        return self._pointer

    def close(self) -> None:
        if getattr(self, "_pointer", None):
            pointer = self._pointer
            self._pointer = wintypes.LPVOID()
            _local_free(pointer)

    def __enter__(self) -> _LocalSid:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _is_reparse_point(path: Path) -> bool:
    information = path.lstat()
    attributes = getattr(information, "st_file_attributes", 0)
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _collect_acl_targets(root: Path) -> list[Path]:
    if _is_reparse_point(root):
        raise ValueError(f"ACL target must not be a reparse point: {root}")
    targets = [root]
    if not root.is_dir():
        return targets
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            target = current_path / name
            if _is_reparse_point(target):
                raise ValueError(
                    f"ACL tree must not contain reparse points: {target}"
                )
            targets.append(target)
    return targets


def _grant_sid_access(
    path: Path,
    sid: wintypes.LPVOID,
    *,
    access_mask: int,
    inherit_to_children: bool,
) -> None:
    apis = _apis()
    old_dacl = wintypes.LPVOID()
    descriptor = wintypes.LPVOID()
    status = int(
        apis.advapi32.GetNamedSecurityInfoW(
            str(path),
            _SE_FILE_OBJECT,
            _DACL_SECURITY_INFORMATION,
            None,
            None,
            ctypes.byref(old_dacl),
            None,
            ctypes.byref(descriptor),
        )
    )
    if status != _ERROR_SUCCESS:
        _raise_status("GetNamedSecurityInfoW", status)
    new_dacl = wintypes.LPVOID()
    try:
        if not old_dacl:
            raise OSError(f"refusing to replace a null DACL on {path}")
        entry = _ExplicitAccess(
            grfAccessPermissions=access_mask,
            grfAccessMode=_GRANT_ACCESS,
            grfInheritance=(
                _OBJECT_INHERIT_ACE | _CONTAINER_INHERIT_ACE
                if inherit_to_children
                else 0
            ),
            Trustee=_Trustee(
                pMultipleTrustee=None,
                MultipleTrusteeOperation=0,
                TrusteeForm=_TRUSTEE_IS_SID,
                TrusteeType=_TRUSTEE_IS_UNKNOWN,
                ptstrName=sid,
            ),
        )
        status = int(
            apis.advapi32.SetEntriesInAclW(
                1,
                ctypes.byref(entry),
                old_dacl,
                ctypes.byref(new_dacl),
            )
        )
        if status != _ERROR_SUCCESS:
            _raise_status("SetEntriesInAclW", status)
        status = int(
            apis.advapi32.SetNamedSecurityInfoW(
                str(path),
                _SE_FILE_OBJECT,
                _DACL_SECURITY_INFORMATION,
                None,
                None,
                new_dacl,
                None,
            )
        )
        if status != _ERROR_SUCCESS:
            _raise_status("SetNamedSecurityInfoW", status)
    finally:
        cleanup_errors: list[BaseException] = []
        for pointer in (new_dacl, descriptor):
            try:
                _local_free(pointer)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            raise cleanup_errors[0]


def _resolve_acl_root(path: Path | str) -> Path:
    root = Path(path).resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"ACL root must be a directory: {root}")
    return root


def _contains_path(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _protected_source_paths() -> tuple[Path, ...]:
    return (
        Path(sys.executable).resolve(strict=True),
        Path(getattr(sys, "_base_executable", sys.executable)).resolve(
            strict=True
        ),
        Path(sys.prefix).resolve(strict=True),
        Path(sys.base_prefix).resolve(strict=True),
        Path(__file__).resolve(strict=True),
    )


def grant_dedicated_runtime_access(
    runtime_directory: Path | str,
    profile: AppContainerProfile,
) -> Path:
    """Grant read/execute only on a dedicated runtime copy.

    The function refuses a directory containing the active interpreter or this
    module, which prevents accidentally changing the source Python, venv, or
    project package ACL.  Existing descendants receive explicit ACEs; future
    descendants inherit the directory ACE.
    """

    root = _resolve_acl_root(runtime_directory)
    if any(
        _contains_path(root, candidate)
        for candidate in _protected_source_paths()
    ):
        raise ValueError(
            "runtime_directory must be a dedicated copy, not the active "
            "Python, venv, or project package"
        )
    targets = _collect_acl_targets(root)
    with _LocalSid(profile.sid) as sid:
        for target in targets:
            _grant_sid_access(
                target,
                sid.pointer,
                access_mask=_RUNTIME_ACCESS,
                inherit_to_children=target.is_dir(),
            )
    return root


def grant_task_directory_access(
    task_directory: Path | str,
    profile: AppContainerProfile,
) -> Path:
    """Grant modify access only to one dedicated per-task directory."""

    root = _resolve_acl_root(task_directory)
    if any(
        _contains_path(root, candidate)
        for candidate in _protected_source_paths()
    ):
        raise ValueError(
            "task_directory must not contain the active Python, venv, "
            "or project package"
        )
    targets = _collect_acl_targets(root)
    with _LocalSid(profile.sid) as sid:
        for target in targets:
            _grant_sid_access(
                target,
                sid.pointer,
                access_mask=_TASK_ACCESS,
                inherit_to_children=target.is_dir(),
            )
    return root


def build_safe_environment(
    temporary_directory: Path | str,
    *,
    executable: Path | str,
) -> dict[str, str]:
    """Build the tested Windows allowlist without inherited credential keys."""

    temporary = _resolve_acl_root(temporary_directory)
    executable_path = Path(executable).resolve(strict=True)
    if not executable_path.is_file():
        raise ValueError(f"executable must be a file: {executable_path}")
    environment = {
        name: value
        for name in _SAFE_ENVIRONMENT_NAMES
        if (value := os.environ.get(name))
    }
    system_root = environment.get("SystemRoot") or environment.get("WINDIR")
    if not system_root:
        raise RuntimeError("SystemRoot is unavailable")
    environment.update(
        {
            "APPDATA": str(temporary),
            "LOCALAPPDATA": str(temporary),
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "Path": os.pathsep.join(
                (
                    str(executable_path.parent),
                    str(Path(system_root) / "System32"),
                    system_root,
                )
            ),
            "SystemRoot": system_root,
            "WINDIR": system_root,
        }
    )
    return environment


def _environment_block(
    environment: Mapping[str, str],
) -> ctypes.Array[Any]:
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_name, raw_value in environment.items():
        name = str(raw_name)
        value = str(raw_value)
        folded = name.casefold()
        if not name or "=" in name or "\0" in name or "\0" in value:
            raise ValueError("environment names and values must be NUL-free")
        if folded in seen:
            raise ValueError(f"duplicate environment variable: {name}")
        seen.add(folded)
        entries.append((name, value))
    entries.sort(key=lambda item: item[0].casefold())
    block = "\0".join(f"{name}={value}" for name, value in entries) + "\0\0"
    if len(block) > 32767:
        raise ValueError("environment block exceeds 32767 Unicode characters")
    buffer = (ctypes.c_wchar * len(block))()
    for index, character in enumerate(block):
        buffer[index] = character
    return buffer


def _verify_process_token(process_handle: int) -> int:
    apis = _apis()
    token = wintypes.HANDLE()
    if not apis.advapi32.OpenProcessToken(
        wintypes.HANDLE(process_handle),
        _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        _raise_last_error("OpenProcessToken")
    try:
        is_app_container = wintypes.DWORD()
        returned = wintypes.DWORD()
        if not apis.advapi32.GetTokenInformation(
            token,
            _TOKEN_IS_APP_CONTAINER,
            ctypes.byref(is_app_container),
            ctypes.sizeof(is_app_container),
            ctypes.byref(returned),
        ):
            _raise_last_error("GetTokenInformation(TokenIsAppContainer)")
        if is_app_container.value != 1:
            raise OSError("created process is not an AppContainer process")

        required = wintypes.DWORD()
        if apis.advapi32.GetTokenInformation(
            token,
            _TOKEN_CAPABILITIES,
            None,
            0,
            ctypes.byref(required),
        ):
            raise OSError("TokenCapabilities size query unexpectedly succeeded")
        error = ctypes.get_last_error()
        if error != _ERROR_INSUFFICIENT_BUFFER or required.value == 0:
            raise OSError(
                error,
                "GetTokenInformation(TokenCapabilities) size query failed",
            )
        capabilities = ctypes.create_string_buffer(required.value)
        if not apis.advapi32.GetTokenInformation(
            token,
            _TOKEN_CAPABILITIES,
            capabilities,
            required.value,
            ctypes.byref(required),
        ):
            _raise_last_error("GetTokenInformation(TokenCapabilities)")
        count = ctypes.cast(
            capabilities,
            ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        if count != 0:
            raise OSError(
                f"created AppContainer unexpectedly has {count} capabilities"
            )
        return int(count)
    finally:
        _close_handle(int(token.value or 0), "CloseHandle(process token)")


class SuspendedAppContainerProcess:
    """Owns the handles for one verified, initially suspended process."""

    def __init__(
        self,
        process_information: _ProcessInformation,
        profile: AppContainerProfile,
        capability_count: int,
    ):
        self.profile = profile
        self.process_id = int(process_information.dwProcessId)
        self.thread_id = int(process_information.dwThreadId)
        self.capability_count = int(capability_count)
        self._process_handle = int(process_information.hProcess)
        self._thread_handle = int(process_information.hThread)
        self._resumed = False
        self._closed = False

    @property
    def process_handle(self) -> int:
        if self._closed:
            raise RuntimeError("process handles are closed")
        return self._process_handle

    @property
    def thread_handle(self) -> int:
        if self._closed:
            raise RuntimeError("process handles are closed")
        return self._thread_handle

    @property
    def resumed(self) -> bool:
        return self._resumed

    def assign_to_job(self, job_handle: int) -> None:
        if self._closed:
            raise RuntimeError("process handles are closed")
        if self._resumed:
            raise RuntimeError("the process must enter its Job before resume")
        if not job_handle:
            raise ValueError("job_handle must be a valid Windows handle")
        if not _apis().kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(job_handle),
            wintypes.HANDLE(self._process_handle),
        ):
            _raise_last_error("AssignProcessToJobObject")

    def resume(self) -> None:
        if self._closed:
            raise RuntimeError("process handles are closed")
        if self._resumed:
            raise RuntimeError("the primary thread has already been resumed")
        previous = int(
            _apis().kernel32.ResumeThread(
                wintypes.HANDLE(self._thread_handle)
            )
        )
        if previous == 0xFFFFFFFF:
            _raise_last_error("ResumeThread")
        if previous != 1:
            raise OSError(
                f"unexpected primary-thread suspend count: {previous}"
            )
        self._resumed = True

    def wait(self, timeout_ms: int | None = None) -> bool:
        if self._closed:
            raise RuntimeError("process handles are closed")
        if timeout_ms is None:
            timeout = 0xFFFFFFFF
        elif timeout_ms < 0 or timeout_ms > 0xFFFFFFFE:
            raise ValueError("timeout_ms is outside the Windows DWORD range")
        else:
            timeout = int(timeout_ms)
        result = int(
            _apis().kernel32.WaitForSingleObject(
                wintypes.HANDLE(self._process_handle),
                timeout,
            )
        )
        if result == _WAIT_OBJECT_0:
            return True
        if result == _WAIT_TIMEOUT:
            return False
        if result == _WAIT_FAILED:
            _raise_last_error("WaitForSingleObject")
        raise OSError(result, f"unexpected process wait result {result}")

    def poll(self) -> int | None:
        if self._closed:
            raise RuntimeError("process handles are closed")
        exit_code = wintypes.DWORD()
        if not _apis().kernel32.GetExitCodeProcess(
            wintypes.HANDLE(self._process_handle),
            ctypes.byref(exit_code),
        ):
            _raise_last_error("GetExitCodeProcess")
        return None if exit_code.value == _STILL_ACTIVE else int(exit_code.value)

    def terminate(self, exit_code: int = 1) -> None:
        if self._closed:
            raise RuntimeError("process handles are closed")
        if self.poll() is not None:
            return
        if not _apis().kernel32.TerminateProcess(
            wintypes.HANDLE(self._process_handle),
            int(exit_code),
        ):
            _raise_last_error("TerminateProcess")
        if not self.wait(5000):
            raise TimeoutError("terminated AppContainer process did not exit")

    def close(self) -> None:
        if self._closed:
            return
        errors: list[BaseException] = []
        if not self._resumed:
            try:
                self.terminate(125)
            except BaseException as exc:
                errors.append(exc)
        for handle, label in (
            (self._thread_handle, "CloseHandle(primary thread)"),
            (self._process_handle, "CloseHandle(process)"),
        ):
            try:
                _close_handle(handle, label)
            except BaseException as exc:
                errors.append(exc)
        self._thread_handle = 0
        self._process_handle = 0
        self._closed = True
        if errors:
            raise errors[0]

    def __enter__(self) -> SuspendedAppContainerProcess:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except BaseException:
            pass


def _close_failed_launch(process: _ProcessInformation) -> None:
    errors: list[BaseException] = []
    process_handle = int(process.hProcess or 0)
    thread_handle = int(process.hThread or 0)
    if process_handle:
        exit_code = wintypes.DWORD()
        if not _apis().kernel32.GetExitCodeProcess(
            wintypes.HANDLE(process_handle),
            ctypes.byref(exit_code),
        ):
            errors.append(
                OSError(
                    ctypes.get_last_error(),
                    "GetExitCodeProcess failed during launch cleanup",
                )
            )
        elif exit_code.value == _STILL_ACTIVE:
            if not _apis().kernel32.TerminateProcess(
                wintypes.HANDLE(process_handle),
                126,
            ):
                errors.append(
                    OSError(
                        ctypes.get_last_error(),
                        "TerminateProcess failed during launch cleanup",
                    )
                )
            else:
                wait_result = int(
                    _apis().kernel32.WaitForSingleObject(
                        wintypes.HANDLE(process_handle),
                        5000,
                    )
                )
                if wait_result != _WAIT_OBJECT_0:
                    errors.append(
                        OSError(
                            wait_result,
                            "process did not terminate during launch cleanup",
                        )
                    )
    for handle, label in (
        (thread_handle, "CloseHandle(primary thread)"),
        (process_handle, "CloseHandle(process)"),
    ):
        try:
            _close_handle(handle, label)
        except BaseException as exc:
            errors.append(exc)
    process.hThread = None
    process.hProcess = None
    if errors:
        raise errors[0]


def launch_suspended(
    executable: Path | str,
    arguments: Sequence[str],
    *,
    current_directory: Path | str,
    environment: Mapping[str, str],
    profile: AppContainerProfile | None = None,
) -> SuspendedAppContainerProcess:
    """Create a verified zero-capability AppContainer process, still suspended."""

    _require_windows()
    active_profile = profile or ensure_profile()
    executable_path = Path(executable).resolve(strict=True)
    current = Path(current_directory).resolve(strict=True)
    if not executable_path.is_file():
        raise ValueError(f"executable must be a file: {executable_path}")
    if not current.is_dir():
        raise ValueError(f"current_directory must be a directory: {current}")
    command_line = subprocess.list2cmdline(
        [str(executable_path), *(str(value) for value in arguments)]
    )
    if len(command_line) > 32767:
        raise ValueError("Windows command line exceeds 32767 characters")
    command_buffer = ctypes.create_unicode_buffer(command_line)
    environment_buffer = _environment_block(environment)

    apis = _apis()
    sid = _derive_profile_sid(active_profile.name)
    attribute_buffer: ctypes.Array[Any] | None = None
    attribute_list = wintypes.LPVOID()
    process = _ProcessInformation()
    created = False
    try:
        observed_sid = _sid_to_string(sid)
        if observed_sid != active_profile.sid:
            raise OSError("stable AppContainer profile SID changed unexpectedly")
        required = ctypes.c_size_t()
        ctypes.set_last_error(0)
        if apis.kernel32.InitializeProcThreadAttributeList(
            None,
            1,
            0,
            ctypes.byref(required),
        ):
            raise OSError(
                "InitializeProcThreadAttributeList size query unexpectedly succeeded"
            )
        error = ctypes.get_last_error()
        if error != _ERROR_INSUFFICIENT_BUFFER or required.value == 0:
            raise OSError(
                error,
                "InitializeProcThreadAttributeList size query failed",
            )
        attribute_buffer = ctypes.create_string_buffer(required.value)
        attribute_list = ctypes.cast(attribute_buffer, wintypes.LPVOID)
        if not apis.kernel32.InitializeProcThreadAttributeList(
            attribute_list,
            1,
            0,
            ctypes.byref(required),
        ):
            _raise_last_error("InitializeProcThreadAttributeList")

        security_capabilities = _SecurityCapabilities(
            AppContainerSid=sid,
            Capabilities=None,
            CapabilityCount=0,
            Reserved=0,
        )
        if not apis.kernel32.UpdateProcThreadAttribute(
            attribute_list,
            0,
            _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(security_capabilities),
            ctypes.sizeof(security_capabilities),
            None,
            None,
        ):
            _raise_last_error(
                "UpdateProcThreadAttribute(SecurityCapabilities)"
            )

        startup = _StartupInfoEx()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.lpAttributeList = attribute_list
        flags = (
            _CREATE_SUSPENDED
            | _CREATE_UNICODE_ENVIRONMENT
            | _EXTENDED_STARTUPINFO_PRESENT
            | _CREATE_NO_WINDOW
        )
        if not apis.kernel32.CreateProcessW(
            str(executable_path),
            command_buffer,
            None,
            None,
            False,
            flags,
            environment_buffer,
            str(current),
            ctypes.byref(startup),
            ctypes.byref(process),
        ):
            _raise_last_error("CreateProcessW(AppContainer)")
        created = True
        capability_count = _verify_process_token(int(process.hProcess))
        owned_process = SuspendedAppContainerProcess(
            process,
            active_profile,
            capability_count,
        )
        process.hProcess = None
        process.hThread = None
        return owned_process
    except BaseException as original:
        if created:
            try:
                _close_failed_launch(process)
            except BaseException as cleanup_error:
                raise cleanup_error from original
        raise
    finally:
        if attribute_list:
            apis.kernel32.DeleteProcThreadAttributeList(attribute_list)
        _free_sid(sid)
