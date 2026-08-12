from __future__ import annotations

"""Trusted Windows bootstrap for the untrusted PDF parser process.

This file intentionally imports only the standard library.  The parent creates
it inside a zero-capability AppContainer while suspended, assigns it to a
constrained Job Object, and only then resumes it and creates the gate file.
Before importing the actual PDF worker, this bootstrap verifies the kernel token
rather than trusting an environment claim.
"""

import argparse
import ctypes
import json
import os
import re
import runpy
import sys
import time
from ctypes import wintypes
from pathlib import Path


_TOKEN_QUERY = 0x0008
_TOKEN_INTEGRITY_LEVEL = 25
_TOKEN_IS_APP_CONTAINER = 29
_SECURITY_MANDATORY_LOW_RID = 0x1000


class _SidAndAttributes(ctypes.Structure):
    _fields_ = [
        ("Sid", wintypes.LPVOID),
        ("Attributes", wintypes.DWORD),
    ]


class _TokenMandatoryLabel(ctypes.Structure):
    _fields_ = [("Label", _SidAndAttributes)]


def _raise_last_error(operation: str) -> None:
    error = ctypes.get_last_error()
    raise OSError(error, f"{operation} failed with Windows error {error}")


def _verify_current_process_isolation() -> None:
    if os.name != "nt":
        raise RuntimeError("the PDF sandbox requires Windows AppContainer isolation")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
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
    advapi32.GetSidSubAuthorityCount.argtypes = [wintypes.LPVOID]
    advapi32.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi32.GetSidSubAuthority.argtypes = [wintypes.LPVOID, wintypes.DWORD]
    advapi32.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        _TOKEN_QUERY,
        ctypes.byref(token),
    ):
        _raise_last_error("OpenProcessToken")
    try:
        is_app_container = wintypes.DWORD()
        returned = wintypes.DWORD()
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_IS_APP_CONTAINER,
            ctypes.byref(is_app_container),
            ctypes.sizeof(is_app_container),
            ctypes.byref(returned),
        ):
            _raise_last_error("GetTokenInformation(TokenIsAppContainer)")
        if is_app_container.value != 1:
            raise RuntimeError("the PDF worker token is not an AppContainer")

        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            _TOKEN_INTEGRITY_LEVEL,
            None,
            0,
            ctypes.byref(required),
        )
        if required.value == 0:
            _raise_last_error("GetTokenInformation(TokenIntegrityLevel size)")
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            _TOKEN_INTEGRITY_LEVEL,
            buffer,
            required.value,
            ctypes.byref(required),
        ):
            _raise_last_error("GetTokenInformation(TokenIntegrityLevel)")
        label = ctypes.cast(
            buffer,
            ctypes.POINTER(_TokenMandatoryLabel),
        ).contents
        sid = label.Label.Sid
        count_pointer = advapi32.GetSidSubAuthorityCount(sid)
        if not count_pointer or count_pointer.contents.value == 0:
            raise RuntimeError("the PDF worker integrity SID is invalid")
        rid_pointer = advapi32.GetSidSubAuthority(
            sid,
            int(count_pointer.contents.value) - 1,
        )
        if not rid_pointer or int(rid_pointer.contents.value) > _SECURITY_MANDATORY_LOW_RID:
            raise RuntimeError("the PDF worker token is not low integrity")
    finally:
        kernel32.CloseHandle(token)

    os.environ["R3_PDF_SANDBOX_INTEGRITY"] = "appcontainer_low"


def _write_diagnostic(output_dir: Path, exc: BaseException) -> None:
    message = re.sub(
        r"[A-Za-z]:\\[^\s]+",
        "<local-path>",
        str(exc).replace("\r", " ").replace("\n", " "),
    )[:240]
    diagnostic = {
        "schema": "r3/pdf-bootstrap-error/v1",
        "error_type": type(exc).__name__[:120],
        "message": message,
    }
    try:
        (output_dir / "bootstrap-error.json").write_text(
            json.dumps(
                diagnostic,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
    except BaseException:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--site-packages", required=True)
    arguments = parser.parse_args()

    worker = Path(arguments.worker)
    request = Path(arguments.request)
    output_dir = Path(arguments.output_dir)
    gate = Path(arguments.gate)
    site_packages = Path(arguments.site_packages)
    if not all(
        path.is_absolute()
        for path in (worker, request, output_dir, gate, site_packages)
    ):
        return 93
    if not worker.is_file() or not request.is_file() or not output_dir.is_dir():
        return 93
    if not site_packages.is_dir() or site_packages.name.casefold() != "site-packages":
        return 93

    deadline = time.monotonic() + 15.0
    while not gate.is_file():
        if time.monotonic() >= deadline:
            return 91
        time.sleep(0.01)

    try:
        _verify_current_process_isolation()
        sys.path.insert(0, str(site_packages))
        sys.argv = [
            str(worker),
            "--request",
            str(request),
            "--output-dir",
            str(output_dir),
        ]
        try:
            runpy.run_path(str(worker), run_name="__main__")
        except SystemExit as exc:
            if exc.code not in (None, 0):
                raise
        return 0
    except BaseException as exc:
        _write_diagnostic(output_dir, exc)
        return 94


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:
        try:
            index = sys.argv.index("--output-dir")
            diagnostic_directory = Path(sys.argv[index + 1])
            _write_diagnostic(diagnostic_directory, exc)
        except BaseException:
            pass
        raise SystemExit(95)
