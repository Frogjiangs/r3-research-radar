from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .pdf_parser import (
    PARSER_POLICY_VERSION,
    REQUEST_SCHEMA,
    REQUIRED_PYPDF_VERSION,
    REQUIRED_TYPING_EXTENSIONS_VERSION,
    RESULT_SCHEMA,
)


PDF_DOCUMENT_POLICY_SCHEMA = "r3/pdf-document-policy/v1"
PDF_CONTENT_KIND = "paper_pdf"
REPOSITORY_CONTENT_KIND = "repository_zip"
REPOSITORY_SELECTION_POLICY_ID = "core_plus_sampled_aux_v1"
REPOSITORY_SELECTION_ALGORITHM_VERSION = "r3-repository-corpus-selection-v4"


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _is_sha256(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_plain_int(value: Any, *, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


_PACKAGE_DIR = Path(__file__).resolve().parent
CURRENT_PDF_DOCUMENT_POLICY = {
    "schema": PDF_DOCUMENT_POLICY_SCHEMA,
    "parser": {
        "id": "pypdf",
        "version": REQUIRED_PYPDF_VERSION,
        "runtime_dependencies": {
            "typing_extensions": REQUIRED_TYPING_EXTENSIONS_VERSION,
        },
        "policy_version": PARSER_POLICY_VERSION,
        "effective_options": {"strict": False},
    },
    "protocol": {
        "request_schema": REQUEST_SCHEMA,
        "result_schema": RESULT_SCHEMA,
    },
    "code": {
        "supervisor_sha256": _sha256_file(_PACKAGE_DIR / "pdf_parser.py"),
        "appcontainer_sha256": _sha256_file(
            _PACKAGE_DIR / "windows_appcontainer.py"
        ),
        "worker_sha256": _sha256_file(_PACKAGE_DIR / "pdf_worker.py"),
        "sandbox_sha256": _sha256_file(_PACKAGE_DIR / "pdf_sandbox.py"),
    },
}
CURRENT_PDF_DOCUMENT_POLICY_HASH = hashlib.sha256(
    _canonical_json(CURRENT_PDF_DOCUMENT_POLICY).encode("utf-8")
).hexdigest()


def current_pdf_document_policy_hash() -> str:
    return CURRENT_PDF_DOCUMENT_POLICY_HASH


def _coverage_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return None
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def pdf_ready_coverage_matches_current_policy(value: Any) -> bool:
    coverage = _coverage_object(value)
    if coverage is None:
        return False
    parser = coverage.get("parser")
    receipt = coverage.get("parser_receipt")
    if not isinstance(parser, dict) or not isinstance(receipt, dict):
        return False
    isolation = parser.get("isolation")
    if not isinstance(isolation, dict):
        return False
    expected_parser = CURRENT_PDF_DOCUMENT_POLICY["parser"]
    expected_protocol = CURRENT_PDF_DOCUMENT_POLICY["protocol"]
    expected_code = CURRENT_PDF_DOCUMENT_POLICY["code"]
    return bool(
        coverage.get("complete") is True
        and coverage.get("coverage_type") == "text_layer"
        and coverage.get("security_status") == "parsed_verified"
        and coverage.get("reason") is None
        and coverage.get("failure_code") in (None, "")
        and parser.get("id") == expected_parser["id"]
        and parser.get("version") == expected_parser["version"]
        and parser.get("policy_version") == expected_parser["policy_version"]
        and parser.get("effective_options") == expected_parser["effective_options"]
        and parser.get("request_schema") == expected_protocol["request_schema"]
        and parser.get("result_schema") == expected_protocol["result_schema"]
        and isolation.get("integrity_level") == "appcontainer_low"
        and isolation.get("credential_environment_keys") == []
        and receipt.get("parser_id") == expected_parser["id"]
        and receipt.get("parser_version") == expected_parser["version"]
        and receipt.get("parser_policy_version")
        == expected_parser["policy_version"]
        and receipt.get("request_schema") == expected_protocol["request_schema"]
        and receipt.get("result_schema") == expected_protocol["result_schema"]
        and receipt.get("worker_sha256") == expected_code["worker_sha256"]
        and receipt.get("sandbox_sha256") == expected_code["sandbox_sha256"]
        and receipt.get("return_code") == 0
        and receipt.get("termination") == "process_exit"
    )


def repository_ready_coverage_matches_policy(value: Any) -> bool:
    coverage = _coverage_object(value)
    if coverage is None or coverage.get("complete") is not True:
        return False
    if coverage.get("reason") not in (None, ""):
        return False
    scope = coverage.get("coverage_scope")
    if scope in (None, "", "legacy_all_eligible"):
        if "trusted_anchor_count" not in coverage:
            return True
        trusted_anchor_count = coverage.get("trusted_anchor_count")
        included_file_count = coverage.get("included_file_count")
        if not (
            _is_plain_int(trusted_anchor_count, minimum=1)
            and _is_plain_int(included_file_count, minimum=1)
        ):
            return False
        return bool(
            trusted_anchor_count == included_file_count
            and _is_sha256(coverage.get("inventory_sha256"))
            and isinstance(coverage.get("inventory_path"), str)
            and bool(str(coverage.get("inventory_path")).strip())
        )
    if scope != "selected_repository_corpus":
        return False
    policy = coverage.get("selection_policy")
    incomplete_reasons = coverage.get("incomplete_reasons")
    if not isinstance(policy, dict) or incomplete_reasons not in ([], ()):
        return False
    included_file_count = coverage.get("included_file_count")
    included_text_bytes = coverage.get("included_text_bytes")
    final_text_utf8_bytes = coverage.get("final_text_utf8_bytes")
    trusted_anchor_count = coverage.get("trusted_anchor_count")
    if not all(
        _is_plain_int(value, minimum=1)
        for value in (
            included_file_count,
            included_text_bytes,
            final_text_utf8_bytes,
            trusted_anchor_count,
        )
    ):
        return False
    policy_hash = hashlib.sha256(
        _canonical_json(policy).encode("utf-8")
    ).hexdigest()
    return bool(
        coverage.get("selection_policy_id")
        == REPOSITORY_SELECTION_POLICY_ID
        and coverage.get("selection_algorithm_version")
        == REPOSITORY_SELECTION_ALGORITHM_VERSION
        and policy.get("mode") == REPOSITORY_SELECTION_POLICY_ID
        and policy.get("algorithm_version")
        == REPOSITORY_SELECTION_ALGORITHM_VERSION
        and coverage.get("selection_policy_hash") == policy_hash
        and _is_sha256(coverage.get("selection_policy_hash"))
        and _is_sha256(coverage.get("inventory_sha256"))
        and isinstance(coverage.get("inventory_path"), str)
        and bool(str(coverage.get("inventory_path")).strip())
        and trusted_anchor_count == included_file_count
    )


def document_is_analysis_eligible(
    content_kind: Any,
    status: Any,
    document_policy_hash: Any,
    coverage: Any,
) -> bool:
    if content_kind == REPOSITORY_CONTENT_KIND:
        return bool(
            status == "ready"
            and repository_ready_coverage_matches_policy(coverage)
        )
    if content_kind != PDF_CONTENT_KIND:
        return status == "ready"
    return bool(
        status == "ready"
        and document_policy_hash == CURRENT_PDF_DOCUMENT_POLICY_HASH
        and pdf_ready_coverage_matches_current_policy(coverage)
    )


def require_current_pdf_ready_policy(
    *,
    content_kind: str,
    status: str,
    coverage: dict[str, Any],
) -> None:
    if content_kind != PDF_CONTENT_KIND or status != "ready":
        return
    if not pdf_ready_coverage_matches_current_policy(coverage):
        raise ValueError(
            "ready paper_pdf requires complete parsed_verified coverage "
            "from the current PDF document policy"
        )


def require_repository_ready_policy(
    *,
    content_kind: str,
    status: str,
    coverage: dict[str, Any],
    text_path: str | Path | None = None,
) -> None:
    if content_kind != REPOSITORY_CONTENT_KIND or status != "ready":
        return
    if not repository_ready_coverage_matches_policy(coverage):
        raise ValueError(
            "ready repository_zip requires complete auditable repository coverage"
        )
    selected_scope = (
        coverage.get("coverage_scope") == "selected_repository_corpus"
    )
    trusted_anchor_count = coverage.get("trusted_anchor_count", 0)
    if not _is_plain_int(trusted_anchor_count):
        raise ValueError(
            "ready repository coverage has invalid trusted anchor count"
        )
    if not selected_scope and trusted_anchor_count <= 0:
        return
    inventory_path = Path(str(coverage["inventory_path"]))
    if not inventory_path.is_file():
        raise ValueError(
            "ready selected repository corpus requires its inventory artifact"
        )
    inventory_bytes = inventory_path.read_bytes()
    if hashlib.sha256(inventory_bytes).hexdigest() != coverage["inventory_sha256"]:
        raise ValueError("selected repository inventory SHA-256 mismatch")
    try:
        inventory = json.loads(inventory_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("selected repository inventory is not valid UTF-8 JSON") from exc
    if not isinstance(inventory, list):
        raise ValueError("selected repository inventory must be a JSON list")
    included_count = sum(
        1
        for item in inventory
        if isinstance(item, dict) and item.get("included") is True
    )
    if included_count != coverage["included_file_count"]:
        raise ValueError("selected repository inventory count mismatch")
    if text_path is not None:
        selected_text_path = Path(text_path)
        if not selected_text_path.is_file():
            raise ValueError(
                "ready selected repository corpus requires its text artifact"
            )
        selected_text_bytes = selected_text_path.read_bytes()
        if len(selected_text_bytes) != coverage["final_text_utf8_bytes"]:
            raise ValueError("selected repository text byte count mismatch")
        try:
            selected_text = selected_text_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "selected repository text artifact is not UTF-8"
            ) from exc
        for item in inventory:
            if not isinstance(item, dict) or item.get("included") is not True:
                continue
            anchor = item.get("evidence_anchor")
            anchor_start = item.get("evidence_anchor_start")
            anchor_end = item.get("evidence_anchor_end")
            text_end = item.get("text_character_end")
            if not all(
                _is_plain_int(value)
                for value in (anchor_start, anchor_end, text_end)
            ):
                raise ValueError(
                    "selected repository inventory has invalid text spans"
                )
            if (
                not isinstance(anchor, str)
                or not anchor
                or anchor_end != anchor_start + len(anchor)
                or not 0 <= anchor_start < anchor_end <= text_end
                or text_end > len(selected_text)
                or selected_text[anchor_start:anchor_end] != anchor
            ):
                raise ValueError(
                    "selected repository inventory anchor span mismatch"
                )


def observation_receipt(coverage: dict[str, Any]) -> dict[str, Any]:
    receipt: dict[str, Any] = {}
    for key in ("parser_receipt", "raw_receipt"):
        value = coverage.get(key)
        if isinstance(value, dict):
            receipt[key] = value
    return receipt
