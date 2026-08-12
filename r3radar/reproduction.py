from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlsplit

from .config import Settings, canonical_json
from .content import ContentProcessor
from .decision import (
    DecisionExportError,
    snapshot_sha256,
    validate_frozen_snapshot,
)
from .http_client import RawResponseStore, SafeHttpClient
from .models import normalize_github_full_name
from .sources import GitHubSource
from .storage import RadarStore
from .utils import JsonlAuditLog, sha256_text, utc_now


HANDOFF_SCHEMA = "r3/reproduction-handoff/v2"
EXECUTION_POLICY = "manual-only-after-explicit-confirmation"

CONFIRMATION_CHECKS = (
    "source_identity_and_revision_reviewed",
    "license_and_usage_terms_reviewed",
    "external_code_and_dependencies_reviewed",
    "isolated_environment_and_network_policy_ready",
    "data_secrets_and_output_paths_reviewed",
)

RISK_WARNINGS = (
    "A frozen analysis is research evidence, not authorization to execute external code.",
    "The recorded source can change after publication; manually pin and hash the exact revision before use.",
    "Source URLs can identify papers rather than code; never infer an unrecorded repository or executable.",
    "Install scripts, dependencies, model files, datasets, and notebooks may execute code or contain unsafe content.",
    "Use a disposable isolated environment, exclude secrets, and keep network and output access denied by default.",
    "Review licenses, dataset terms, privacy constraints, and expected resource use before reproduction.",
)

SUGGESTED_STEPS = (
    "Verify the recorded title, URL, DOI, and repository identity against the frozen issue item.",
    "Manually select an exact source revision and record its URL, revision identifier, and cryptographic hash without executing it.",
    "Review licenses, entry points, install scripts, dependencies, data requirements, and expected resource use.",
    "Prepare a disposable isolated environment with no secrets and with network and writable paths denied by default.",
    "Complete every manual confirmation check before treating this handoff as executable.",
    "Run only the smallest manually approved reproduction procedure and capture commands, parameters, environment, seeds, and logs.",
    "Compare results with the frozen evidence anchors and record discrepancies instead of treating them as supporting evidence.",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ISSUE_ITEM_REQUIRED_KEYS = frozenset(
    {
        "issue_id",
        "analysis_id",
        "work_id",
        "input_sha256",
        "snapshot_sha256",
        "snapshot",
    }
)
_ISSUE_ITEM_ALLOWED_KEYS = _ISSUE_ITEM_REQUIRED_KEYS | frozenset(
    {
        "selection_bucket",
        "selected",
        "citation",
        "analysis",
        "coverage",
        "provider",
        "model",
        "tier",
        "score",
        "lane",
        "provenance_status",
        "decision",
    }
)
_MIRRORED_SNAPSHOT_FIELDS = (
    "citation",
    "analysis",
    "coverage",
    "provider",
    "model",
    "tier",
    "score",
    "lane",
    "provenance_status",
)
_CONFIRMATION_INPUT_KEYS = frozenset(
    {
        "confirmed",
        "confirmed_by",
        "confirmed_at",
        "checks",
    }
)
_CONFIRMATION_OUTPUT_KEYS = frozenset(
    {
        "status",
        "confirmed_by",
        "confirmed_at",
        "checks",
    }
)
_SOURCE_KEYS = frozenset(
    {
        "kind",
        "title",
        "url",
        "doi",
        "arxiv_id",
        "github_full_name",
    }
)
_MANIFEST_KEYS = frozenset(
    {
        "schema",
        "issue_id",
        "analysis_id",
        "work_id",
        "snapshot_sha256",
        "input_sha256",
        "source",
        "source_relation",
        "evidence_anchors",
        "risk_warnings",
        "manual_confirmation",
        "executable",
        "execution_policy",
        "suggested_steps",
        "manifest_sha256",
    }
)
_RELATION_WRAPPER_KEYS = frozenset(
    {"relation_sha256", "evidence", "created_at"}
)


class ReproductionHandoffError(ValueError):
    """Raised when a reproduction handoff cannot be proven safe and frozen."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ReproductionHandoffError(
            "reproduction handoff must contain deterministic JSON"
        ) from exc


def _json_copy(value: Any, *, field: str) -> Any:
    try:
        return json.loads(_canonical_json(value))
    except (json.JSONDecodeError, ReproductionHandoffError) as exc:
        raise ReproductionHandoffError(f"{field} is not valid JSON") from exc


def _require_text(
    value: Any,
    *,
    field: str,
    allow_none: bool = False,
) -> str | None:
    if value is None and allow_none:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or _CONTROL_CHARACTER.search(value)
    ):
        raise ReproductionHandoffError(f"{field} must be a safe non-empty string")
    return value


def _require_positive_integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ReproductionHandoffError(f"{field} must be a positive integer")
    return value


def _require_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ReproductionHandoffError(f"{field} must be a lowercase SHA-256")
    return value


def _validate_time(value: str | None, *, field: str) -> None:
    if value is None:
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReproductionHandoffError(
            f"{field} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise ReproductionHandoffError(f"{field} must include a timezone")


def _validate_issue_item(issue_item: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(issue_item, Mapping):
        raise ReproductionHandoffError("issue_item must be an object")
    if any(not isinstance(key, str) for key in issue_item):
        raise ReproductionHandoffError("issue_item keys must be strings")
    actual_keys = set(issue_item)
    missing = sorted(_ISSUE_ITEM_REQUIRED_KEYS - actual_keys)
    unexpected = sorted(actual_keys - _ISSUE_ITEM_ALLOWED_KEYS)
    if missing or unexpected:
        raise ReproductionHandoffError(
            "issue_item keys do not match the frozen storage interface "
            f"(missing={missing}, unexpected={unexpected})"
        )

    issue_id = _require_text(issue_item.get("issue_id"), field="issue_item.issue_id")
    analysis_id = _require_positive_integer(
        issue_item.get("analysis_id"),
        field="issue_item.analysis_id",
    )
    work_id = _require_positive_integer(
        issue_item.get("work_id"),
        field="issue_item.work_id",
    )
    input_sha256 = _require_sha256(
        issue_item.get("input_sha256"),
        field="issue_item.input_sha256",
    )
    recorded_snapshot_sha256 = _require_sha256(
        issue_item.get("snapshot_sha256"),
        field="issue_item.snapshot_sha256",
    )
    try:
        snapshot = validate_frozen_snapshot(issue_item.get("snapshot"))
        actual_snapshot_sha256 = snapshot_sha256(snapshot)
    except DecisionExportError as exc:
        raise ReproductionHandoffError(
            "issue_item snapshot failed strict validation"
        ) from exc

    if analysis_id != snapshot["analysis_id"]:
        raise ReproductionHandoffError(
            "issue_item.analysis_id does not bind the frozen snapshot"
        )
    if work_id != snapshot["work_id"]:
        raise ReproductionHandoffError(
            "issue_item.work_id does not bind the frozen snapshot"
        )
    if input_sha256 != snapshot["input_sha256"]:
        raise ReproductionHandoffError(
            "issue_item.input_sha256 does not bind the frozen snapshot"
        )
    if recorded_snapshot_sha256 != actual_snapshot_sha256:
        raise ReproductionHandoffError(
            "issue_item.snapshot_sha256 does not bind the frozen snapshot"
        )

    if "selected" in issue_item and not isinstance(issue_item["selected"], bool):
        raise ReproductionHandoffError("issue_item.selected must be a boolean")
    if "selection_bucket" in issue_item:
        _require_text(
            issue_item["selection_bucket"],
            field="issue_item.selection_bucket",
        )
    for field in _MIRRORED_SNAPSHOT_FIELDS:
        if field in issue_item and issue_item[field] != snapshot[field]:
            raise ReproductionHandoffError(
                f"issue_item.{field} does not match the frozen snapshot"
            )
    if "decision" in issue_item:
        decision = issue_item["decision"]
        if decision is not None and not isinstance(decision, Mapping):
            raise ReproductionHandoffError(
                "issue_item.decision must be an object or null"
            )
        _json_copy(decision, field="issue_item.decision")

    identity = {
        "issue_id": issue_id,
        "analysis_id": analysis_id,
        "work_id": work_id,
        "input_sha256": input_sha256,
        "snapshot_sha256": actual_snapshot_sha256,
    }
    return identity, snapshot


def _pending_confirmation() -> dict[str, Any]:
    return {
        "status": "pending",
        "confirmed_by": None,
        "confirmed_at": None,
        "checks": {name: False for name in CONFIRMATION_CHECKS},
    }


def _normalize_confirmation(
    value: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], bool]:
    if value is None:
        return _pending_confirmation(), False
    if not isinstance(value, Mapping):
        raise ReproductionHandoffError(
            "manual_confirmation must be an object or null"
        )
    if set(value) != _CONFIRMATION_INPUT_KEYS:
        missing = sorted(_CONFIRMATION_INPUT_KEYS - set(value))
        unexpected = sorted(set(value) - _CONFIRMATION_INPUT_KEYS)
        raise ReproductionHandoffError(
            "manual_confirmation keys do not match the schema "
            f"(missing={missing}, unexpected={unexpected})"
        )
    confirmed = value.get("confirmed")
    if not isinstance(confirmed, bool):
        raise ReproductionHandoffError(
            "manual_confirmation.confirmed must be a boolean"
        )
    confirmed_by = _require_text(
        value.get("confirmed_by"),
        field="manual_confirmation.confirmed_by",
        allow_none=True,
    )
    confirmed_at = _require_text(
        value.get("confirmed_at"),
        field="manual_confirmation.confirmed_at",
        allow_none=True,
    )
    _validate_time(
        confirmed_at,
        field="manual_confirmation.confirmed_at",
    )
    checks = value.get("checks")
    if not isinstance(checks, Mapping) or set(checks) != set(CONFIRMATION_CHECKS):
        raise ReproductionHandoffError(
            "manual_confirmation.checks must contain every required safety check"
        )
    if any(not isinstance(checks[name], bool) for name in CONFIRMATION_CHECKS):
        raise ReproductionHandoffError(
            "manual_confirmation checks must be booleans"
        )
    normalized_checks = {name: checks[name] for name in CONFIRMATION_CHECKS}

    if confirmed and (
        confirmed_by is None
        or confirmed_at is None
        or not all(normalized_checks.values())
    ):
        raise ReproductionHandoffError(
            "confirmed handoff requires reviewer, timestamp, and every safety check"
        )
    output = {
        "status": "confirmed" if confirmed else "pending",
        "confirmed_by": confirmed_by,
        "confirmed_at": confirmed_at,
        "checks": normalized_checks,
    }
    return output, confirmed


def _manifest_hash(value: Mapping[str, Any]) -> str:
    core = dict(value)
    core.pop("manifest_sha256", None)
    return hashlib.sha256(_canonical_json(core).encode("utf-8")).hexdigest()


def build_reproduction_handoff(
    issue_item: Mapping[str, Any],
    *,
    manual_confirmation: Mapping[str, Any] | None = None,
    source_relation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic static handoff without accessing external code."""

    identity, snapshot = _validate_issue_item(issue_item)
    confirmation, executable = _normalize_confirmation(manual_confirmation)
    citation = snapshot["citation"]
    manifest: dict[str, Any] = {
        "schema": HANDOFF_SCHEMA,
        **identity,
        "source": {
            "kind": citation["kind"],
            "title": citation["title"],
            "url": citation["best_url"],
            "doi": citation["doi"],
            "arxiv_id": citation["arxiv_id"],
            "github_full_name": citation["github_full_name"],
        },
        "source_relation": (
            _json_copy(dict(source_relation), field="source_relation")
            if source_relation is not None
            else None
        ),
        "evidence_anchors": list(snapshot["analysis"]["evidence_anchors"]),
        "risk_warnings": list(RISK_WARNINGS),
        "manual_confirmation": confirmation,
        "executable": executable,
        "execution_policy": EXECUTION_POLICY,
        "suggested_steps": list(SUGGESTED_STEPS),
    }
    manifest["manifest_sha256"] = _manifest_hash(manifest)
    return validate_reproduction_handoff(manifest)


def _metadata_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _metadata_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _metadata_strings(nested)


def _matching_github_url(metadata: dict[str, Any], full_name: str) -> str | None:
    expected = normalize_github_full_name(full_name)
    for value in _metadata_strings(metadata):
        for match in re.finditer(
            r"https?://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)",
            value,
            flags=re.IGNORECASE,
        ):
            repository = match.group(2).rstrip(".,;:)]}")
            if repository.casefold().endswith(".git"):
                repository = repository[:-4]
            candidate = normalize_github_full_name(
                f"{match.group(1)}/{repository}"
            )
            if candidate == expected:
                return match.group(0).rstrip(".,;:)]}")
    return None


def pin_paper_repository_relation(
    settings: Settings,
    *,
    paper_work_id: int,
    repository_work_id: int,
) -> dict[str, Any]:
    """Resolve and freeze one official paper-code relation without execution."""

    with RadarStore(settings.database_path) as store:
        inputs = store.paper_repository_relation_inputs(
            paper_work_id=paper_work_id,
            repository_work_id=repository_work_id,
            retrieval_hash=settings.retrieval_hash,
        )
    paper = inputs["paper"]
    repository = inputs["repository"]
    full_name = normalize_github_full_name(repository.get("github_full_name"))
    if full_name is None:
        raise ReproductionHandoffError(
            "repository relation endpoint has no verified GitHub identity"
        )
    matched_url = _matching_github_url(paper["metadata"], full_name)
    if matched_url is None:
        raise ReproductionHandoffError(
            "paper metadata does not contain the exact repository URL"
        )
    default_branch = str(repository["metadata"].get("default_branch") or "").strip()
    if not default_branch:
        raise ReproductionHandoffError(
            "repository metadata has no verified default branch"
        )

    audit = JsonlAuditLog(
        settings.outputs_dir / "reproduction-relations" / "audit.jsonl"
    )
    raw_store = RawResponseStore(settings.data_dir / "raw")
    client = SafeHttpClient(
        source="github-revision",
        delay_seconds=float(settings.raw["sources"]["github"]["delay_seconds"]),
        raw_store=raw_store,
        audit=audit,
        run_id=None,
        timeout_seconds=60,
        max_attempts=3,
    )
    try:
        source = GitHubSource(client, settings.raw["sources"]["github"])
        commit, commit_receipt = source.fetch_commit(full_name, default_branch)
        commit_sha = str(commit["sha"]).casefold()
        owner, repository_name = full_name.split("/", 1)
        archive_url = (
            f"https://codeload.github.com/{quote(owner, safe='')}/"
            f"{quote(repository_name, safe='')}/zip/{commit_sha}"
        )
        token = os.getenv("GITHUB_TOKEN", "").strip()
        headers = {"Accept": "application/zip"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        archive_bytes, archive_receipt, _ = client.request_bytes(
            archive_url,
            headers=headers,
            max_bytes=int(settings.raw["documents"]["max_repository_archive_bytes"]),
            raw_suffix="zip",
            allowed_hosts={"codeload.github.com"},
        )
    finally:
        client.close()

    processor = ContentProcessor(
        settings,
        lambda _url: (_ for _ in ()).throw(
            RuntimeError("relation pinning never performs unplanned network access")
        ),
        audit,
        "paper-repository-relation",
    )
    selected = processor._read_repository_archive(archive_bytes)
    selected_text_sha256 = sha256_text(str(selected["text"]))
    if (
        selected["coverage"].get("complete") is not True
        or selected["coverage"].get("coverage_scope")
        != "selected_repository_corpus"
        or selected_text_sha256 != str(repository["input_sha256"])
    ):
        raise ReproductionHandoffError(
            "immutable commit archive does not reproduce the stored selected corpus"
        )

    relation = {
        "schema": "r3/paper-repository-relation/v1",
        "relation_type": "official_code_url_in_verified_paper_record",
        "paper": {
            "work_id": int(paper["id"]),
            "title": str(paper["title"]),
            "url": paper.get("best_url"),
            "input_sha256": str(paper["input_sha256"]),
            "metadata_sha256": sha256_text(canonical_json(paper["metadata"])),
            "matched_repository_url": matched_url,
        },
        "repository": {
            "work_id": int(repository["id"]),
            "title": str(repository["title"]),
            "url": repository.get("best_url"),
            "github_full_name": full_name,
            "selected_text_sha256": str(repository["input_sha256"]),
            "coverage_scope": repository["coverage"].get("coverage_scope"),
            "selection_policy_hash": repository["coverage"].get(
                "selection_policy_hash"
            ),
        },
        "repository_revision": {
            "reference": default_branch,
            "commit_sha": commit_sha,
            "commit_url": str(commit["html_url"]),
            "commit_archive_url": archive_url,
            "commit_archive_sha256": archive_receipt.sha256,
            "selected_text_sha256": selected_text_sha256,
            "stored_content_archive_sha256": str(repository["content_sha256"]),
        },
        "verification": {
            "verified_at": utc_now(),
            "commit_api_receipt": asdict(commit_receipt),
            "commit_archive_receipt": asdict(archive_receipt),
            "selected_corpus_match": True,
            "foreign_code_executed": False,
        },
    }
    with RadarStore(settings.database_path) as store:
        return store.record_paper_repository_relation(relation)


def _validate_source(source: Any) -> None:
    if not isinstance(source, dict) or set(source) != _SOURCE_KEYS:
        raise ReproductionHandoffError("handoff source does not match the schema")
    if source.get("kind") not in {"paper", "repository"}:
        raise ReproductionHandoffError("handoff source kind is unsupported")
    _require_text(source.get("title"), field="handoff.source.title")
    for field in ("url", "doi", "arxiv_id", "github_full_name"):
        _require_text(
            source.get(field),
            field=f"handoff.source.{field}",
            allow_none=True,
        )
    url = source.get("url")
    if url is not None:
        parsed = urlsplit(url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ReproductionHandoffError(
                "handoff.source.url must be a public HTTP(S) URL"
            )


def _validate_source_relation(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != _RELATION_WRAPPER_KEYS:
        raise ReproductionHandoffError(
            "handoff source_relation does not match the schema"
        )
    relation_sha256 = _require_sha256(
        value.get("relation_sha256"),
        field="handoff.source_relation.relation_sha256",
    )
    evidence = value.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("schema") != (
        "r3/paper-repository-relation/v1"
    ):
        raise ReproductionHandoffError(
            "handoff source relation evidence is invalid"
        )
    if hashlib.sha256(_canonical_json(evidence).encode("utf-8")).hexdigest() != (
        relation_sha256
    ):
        raise ReproductionHandoffError(
            "handoff source relation hash does not match its evidence"
        )
    revision = evidence.get("repository_revision")
    if not isinstance(revision, dict):
        raise ReproductionHandoffError(
            "handoff source relation has no repository revision"
        )
    commit_sha = revision.get("commit_sha")
    if (
        not isinstance(commit_sha, str)
        or len(commit_sha) != 40
        or any(character not in "0123456789abcdef" for character in commit_sha)
    ):
        raise ReproductionHandoffError(
            "handoff source relation commit SHA is invalid"
        )
    _require_sha256(
        revision.get("selected_text_sha256"),
        field="handoff.source_relation.selected_text_sha256",
    )
    _require_text(value.get("created_at"), field="handoff.source_relation.created_at")
    _validate_time(
        str(value["created_at"]),
        field="handoff.source_relation.created_at",
    )


def _validate_confirmation_output(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != _CONFIRMATION_OUTPUT_KEYS:
        raise ReproductionHandoffError(
            "handoff manual_confirmation does not match the schema"
        )
    status = value.get("status")
    if status not in {"pending", "confirmed"}:
        raise ReproductionHandoffError(
            "handoff manual_confirmation status is invalid"
        )
    confirmed_by = _require_text(
        value.get("confirmed_by"),
        field="handoff.manual_confirmation.confirmed_by",
        allow_none=True,
    )
    confirmed_at = _require_text(
        value.get("confirmed_at"),
        field="handoff.manual_confirmation.confirmed_at",
        allow_none=True,
    )
    _validate_time(
        confirmed_at,
        field="handoff.manual_confirmation.confirmed_at",
    )
    checks = value.get("checks")
    if (
        not isinstance(checks, dict)
        or set(checks) != set(CONFIRMATION_CHECKS)
        or any(not isinstance(checks[name], bool) for name in CONFIRMATION_CHECKS)
    ):
        raise ReproductionHandoffError(
            "handoff manual_confirmation checks are invalid"
        )
    fully_confirmed = (
        status == "confirmed"
        and confirmed_by is not None
        and confirmed_at is not None
        and all(checks.values())
    )
    if status == "confirmed" and not fully_confirmed:
        raise ReproductionHandoffError(
            "handoff is marked confirmed without complete human confirmation"
        )
    return fully_confirmed


def validate_reproduction_handoff(
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate bindings and executable gating, returning a detached copy."""

    if not isinstance(manifest, Mapping):
        raise ReproductionHandoffError("handoff manifest must be an object")
    detached = _json_copy(dict(manifest), field="handoff manifest")
    if not isinstance(detached, dict) or set(detached) != _MANIFEST_KEYS:
        raise ReproductionHandoffError(
            "handoff manifest keys do not match the schema"
        )
    if detached.get("schema") != HANDOFF_SCHEMA:
        raise ReproductionHandoffError("handoff manifest schema is unsupported")
    _require_text(detached.get("issue_id"), field="handoff.issue_id")
    _require_positive_integer(
        detached.get("analysis_id"),
        field="handoff.analysis_id",
    )
    _require_positive_integer(detached.get("work_id"), field="handoff.work_id")
    _require_sha256(
        detached.get("snapshot_sha256"),
        field="handoff.snapshot_sha256",
    )
    _require_sha256(
        detached.get("input_sha256"),
        field="handoff.input_sha256",
    )
    _validate_source(detached.get("source"))
    _validate_source_relation(detached.get("source_relation"))

    anchors = detached.get("evidence_anchors")
    if (
        not isinstance(anchors, list)
        or not anchors
        or len(anchors) != len(set(anchors))
        or any(
            not isinstance(anchor, str)
            or not anchor.strip()
            or anchor != anchor.strip()
            or _CONTROL_CHARACTER.search(anchor)
            for anchor in anchors
        )
    ):
        raise ReproductionHandoffError("handoff evidence_anchors are invalid")
    if detached.get("risk_warnings") != list(RISK_WARNINGS):
        raise ReproductionHandoffError(
            "handoff risk warnings are missing or changed"
        )
    if detached.get("suggested_steps") != list(SUGGESTED_STEPS):
        raise ReproductionHandoffError(
            "handoff suggested steps are missing or changed"
        )
    if detached.get("execution_policy") != EXECUTION_POLICY:
        raise ReproductionHandoffError("handoff execution policy is invalid")

    fully_confirmed = _validate_confirmation_output(
        detached.get("manual_confirmation")
    )
    executable = detached.get("executable")
    if not isinstance(executable, bool):
        raise ReproductionHandoffError("handoff executable must be a boolean")
    if executable != fully_confirmed:
        raise ReproductionHandoffError(
            "handoff executable state is not bound to human confirmation"
        )

    recorded_hash = _require_sha256(
        detached.get("manifest_sha256"),
        field="handoff.manifest_sha256",
    )
    if recorded_hash != _manifest_hash(detached):
        raise ReproductionHandoffError(
            "handoff manifest_sha256 does not bind the manifest"
        )
    return detached


def render_reproduction_handoff(manifest: Mapping[str, Any]) -> bytes:
    """Return canonical UTF-8 JSON bytes for a validated handoff."""

    validated = validate_reproduction_handoff(manifest)
    return (_canonical_json(validated) + "\n").encode("utf-8")


__all__ = [
    "CONFIRMATION_CHECKS",
    "EXECUTION_POLICY",
    "HANDOFF_SCHEMA",
    "RISK_WARNINGS",
    "ReproductionHandoffError",
    "SUGGESTED_STEPS",
    "build_reproduction_handoff",
    "render_reproduction_handoff",
    "validate_reproduction_handoff",
]
