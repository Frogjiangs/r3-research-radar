from __future__ import annotations

"""Standalone pypdf worker.

The worker receives one immutable request and writes one bounded JSON result.
It does not import the R3 application, open the network, or decide whether a
document has sufficient coverage for deep reading.
"""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from pypdf import PdfReader, __version__ as pypdf_version
from pypdf.errors import FileNotDecryptedError, PdfReadError


REQUEST_SCHEMA = "r3/pdf-parse-request/v1"
RESULT_SCHEMA = "r3/pdf-parse-result/v1"
PARSER_POLICY_VERSION = "r3-pdf-text-v1"
_ALLOWED_FAILURE_CODES = {
    "encrypted_pdf",
    "input_mismatch",
    "invalid_pdf",
    "limit_exceeded",
    "parser_error",
}
_CREDENTIAL_MARKERS = (
    "API_KEY",
    "AUTH_TOKEN",
    "CODEX",
    "CREDENTIAL",
    "GITHUB_TOKEN",
    "OPENAI",
    "PASSWORD",
    "SECRET",
)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _strict_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} has an invalid schema")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _safe_message(exc: BaseException) -> str:
    value = str(exc).replace("\r", " ").replace("\n", " ")
    value = re.sub(r"[A-Za-z]:\\[^\s]+", "<local-path>", value)
    return value[:240]


def _base_result(
    *,
    request_id: str,
    input_sha256: str,
    byte_count: int,
) -> dict[str, Any]:
    options = {"strict": False}
    credential_keys = sorted(
        key
        for key in os.environ
        if any(marker in key.upper() for marker in _CREDENTIAL_MARKERS)
    )
    return {
        "schema": RESULT_SCHEMA,
        "request_id": request_id,
        "parser": {
            "id": "pypdf",
            "version": str(pypdf_version),
            "policy_version": PARSER_POLICY_VERSION,
            "effective_options": options,
            "options_sha256": _sha256_text(_canonical_json(options)),
        },
        "input": {
            "sha256": input_sha256,
            "byte_count": byte_count,
        },
        "isolation": {
            "integrity_level": os.environ.get(
                "R3_PDF_SANDBOX_INTEGRITY",
                "missing",
            ),
            "credential_environment_keys": credential_keys,
        },
    }


def _failure_result(
    base: dict[str, Any],
    *,
    code: str,
    error_type: str,
    message: str,
) -> dict[str, Any]:
    if code not in _ALLOWED_FAILURE_CODES:
        code = "parser_error"
    return {
        **base,
        "outcome": "failed",
        "document": None,
        "failure": {
            "code": code,
            "error_type": error_type[:120],
            "message": message[:240],
        },
    }


def _write_result(
    output_dir: Path,
    result: dict[str, Any],
    *,
    max_result_bytes: int,
) -> None:
    encoded = (_canonical_json(result) + "\n").encode("utf-8")
    if len(encoded) > max_result_bytes:
        base = {
            key: result[key]
            for key in ("schema", "request_id", "parser", "input", "isolation")
        }
        result = _failure_result(
            base,
            code="limit_exceeded",
            error_type="ResultSizeLimit",
            message="The parser result exceeded the configured JSON size limit.",
        )
        encoded = (_canonical_json(result) + "\n").encode("utf-8")
    temporary = output_dir / "result.json.tmp"
    destination = output_dir / "result.json"
    with temporary.open("xb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)


def _load_request(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    request = _strict_keys(
        raw,
        {"schema", "request_id", "input", "parser", "limits"},
        "request",
    )
    if request["schema"] != REQUEST_SCHEMA:
        raise ValueError("unsupported request schema")
    if not isinstance(request["request_id"], str) or not request["request_id"]:
        raise ValueError("request_id must be a non-empty string")
    input_value = _strict_keys(
        request["input"],
        {"path", "sha256", "byte_count"},
        "input",
    )
    if input_value["path"] != "input.pdf":
        raise ValueError("input path must be input.pdf")
    if not re.fullmatch(r"[0-9a-f]{64}", str(input_value["sha256"])):
        raise ValueError("input sha256 is invalid")
    _positive_int(input_value["byte_count"], "input byte_count")
    parser = _strict_keys(
        request["parser"],
        {"id", "policy_version", "options"},
        "parser",
    )
    if parser["id"] != "pypdf":
        raise ValueError("unsupported parser")
    if parser["policy_version"] != PARSER_POLICY_VERSION:
        raise ValueError("unsupported parser policy")
    if parser["options"] != {"strict": False}:
        raise ValueError("unsupported parser options")
    limits = _strict_keys(
        request["limits"],
        {
            "max_input_bytes",
            "max_pages",
            "max_output_characters",
            "max_result_bytes",
        },
        "limits",
    )
    for key in limits:
        _positive_int(limits[key], f"limits.{key}")
    return request


def _parse(request: dict[str, Any], request_path: Path) -> dict[str, Any]:
    input_config = request["input"]
    limits = request["limits"]
    input_path = request_path.parent / "input.pdf"
    body = input_path.read_bytes()
    observed_sha256 = _sha256_bytes(body)
    observed_size = len(body)
    base = _base_result(
        request_id=request["request_id"],
        input_sha256=str(input_config["sha256"]),
        byte_count=int(input_config["byte_count"]),
    )
    if (
        observed_sha256 != input_config["sha256"]
        or observed_size != input_config["byte_count"]
        or observed_size > limits["max_input_bytes"]
    ):
        return _failure_result(
            base,
            code="input_mismatch",
            error_type="InputIdentityMismatch",
            message="The staged PDF identity does not match the parent request.",
        )

    try:
        reader = PdfReader(input_path, strict=False)
        if reader.is_encrypted:
            try:
                decrypted = reader.decrypt("")
            except Exception:
                decrypted = 0
            if not decrypted:
                return _failure_result(
                    base,
                    code="encrypted_pdf",
                    error_type="FileNotDecryptedError",
                    message="The PDF is encrypted and no password is accepted.",
                )
        page_count = len(reader.pages)
        if page_count > limits["max_pages"]:
            return _failure_result(
                base,
                code="limit_exceeded",
                error_type="PageCountLimit",
                message="The PDF exceeds the configured page-count limit.",
            )

        pages: list[dict[str, Any]] = []
        rendered_total = 0
        non_whitespace_total = 0
        for index, page in enumerate(reader.pages, start=1):
            error: dict[str, str] | None = None
            try:
                extracted = (page.extract_text() or "").strip()
            except Exception as exc:
                extracted = ""
                error = {
                    "error_type": type(exc).__name__[:120],
                    "message": _safe_message(exc),
                }
            non_whitespace = len(re.sub(r"\s+", "", extracted))
            rendered = f"=== PAGE {index} ===\n{extracted}\n"
            rendered_total += len(rendered)
            if rendered_total > limits["max_output_characters"]:
                return _failure_result(
                    base,
                    code="limit_exceeded",
                    error_type="OutputCharacterLimit",
                    message="Extracted text exceeds the configured character limit.",
                )
            outcome = "error" if error else ("empty" if not non_whitespace else "ok")
            non_whitespace_total += non_whitespace
            pages.append(
                {
                    "page": index,
                    "text": extracted,
                    "non_whitespace": non_whitespace,
                    "rendered_character_count": len(rendered),
                    "rendered_sha256": _sha256_text(rendered),
                    "outcome": outcome,
                    "error": error,
                }
            )
        return {
            **base,
            "outcome": "parsed",
            "document": {
                "page_count": page_count,
                "rendered_character_count": rendered_total,
                "non_whitespace_total": non_whitespace_total,
                "pages": pages,
            },
            "failure": None,
        }
    except FileNotDecryptedError as exc:
        return _failure_result(
            base,
            code="encrypted_pdf",
            error_type=type(exc).__name__,
            message="The PDF is encrypted and cannot be parsed without a password.",
        )
    except PdfReadError as exc:
        return _failure_result(
            base,
            code="invalid_pdf",
            error_type=type(exc).__name__,
            message=_safe_message(exc),
        )
    except Exception as exc:
        return _failure_result(
            base,
            code="parser_error",
            error_type=type(exc).__name__,
            message=_safe_message(exc),
        )


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--request", required=True)
    parser.add_argument("--output-dir", required=True)
    arguments = parser.parse_args()
    request_path = Path(arguments.request)
    output_dir = Path(arguments.output_dir)
    if (
        not request_path.is_absolute()
        or not output_dir.is_absolute()
        or not request_path.is_file()
        or not output_dir.is_dir()
    ):
        return 96
    request = _load_request(request_path)
    result = _parse(request, request_path)
    max_result_bytes = int(request["limits"]["max_result_bytes"])
    _write_result(output_dir, result, max_result_bytes=max_result_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
