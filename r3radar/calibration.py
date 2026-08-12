from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sqlite3
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .config import Settings, canonical_json
from .intake import WeeklyIntakeGate, WeeklyIntakePolicy, record_activity_time
from .models import AdmissionDecision, SourceRecord
from .utils import atomic_write_text, json_dumps, utc_now


GOLD_SET_SCHEMA = "r3/gold-set-review/v1"
GOLD_SET_V2_SCHEMA = "r3/gold-set-review/v2"
CALIBRATION_SCHEMA = "r3/intake-calibration/v1"
_LABELS = (
    "known_important",
    "relevant_not_priority",
    "boundary",
    "hard_negative",
    "identity_or_version_conflict",
    "inaccessible",
    "recoverable_failure",
)
SEMANTIC_LABELS = (
    "known_important",
    "relevant_not_priority",
    "boundary",
    "hard_negative",
    "unjudged",
)
OPERATIONAL_STATUSES = (
    "normal",
    "inaccessible",
    "identity_or_version_conflict",
    "recoverable_failure",
)
AI_TREATMENTS = ("control", "ai_assisted")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GOLD_SET_KEYS = {"schema", "scope", "review", "sampling", "items"}
_GOLD_SCOPE_KEYS = {
    "run_id",
    "issue_id",
    "profile_id",
    "profile_version",
    "config_hash",
    "retrieval_hash",
    "analysis_policy_hash",
    "database_sha256_at_draft",
}
_GOLD_REVIEW_KEYS = {
    "status",
    "reviewer",
    "reviewed_at",
    "allowed_labels",
    "instructions",
}
_GOLD_ITEM_KEYS = {
    "item_id",
    "record_class",
    "work_id",
    "analysis_id",
    "input_sha256",
    "snapshot_sha256",
    "captured_as",
    "selection_bucket",
    "review_context",
    "frozen_snapshot",
    "human_label",
    "human_notes",
}


class CalibrationError(RuntimeError):
    pass


def _read_only_connection(database_path: Path) -> sqlite3.Connection:
    uri = database_path.resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _percentile(values: Iterable[float], percentile: float) -> float:
    ordered = sorted(max(0.0, float(value)) for value in values)
    if not ordered:
        raise CalibrationError("no measured model duration is available")
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _allocate_lane_caps(
    maximum: int,
    lanes: list[str],
    selected_by_lane: dict[str, int],
) -> dict[str, int]:
    if maximum < len(lanes):
        raise CalibrationError(
            "measured capacity cannot allocate at least one item to every lane"
        )
    total_weight = sum(max(1, selected_by_lane.get(lane, 0)) for lane in lanes)
    allocations = {lane: 1 for lane in lanes}
    remaining = maximum - len(lanes)
    fractional: list[tuple[float, str]] = []
    for lane in lanes:
        exact = remaining * max(1, selected_by_lane.get(lane, 0)) / total_weight
        whole = math.floor(exact)
        allocations[lane] += whole
        fractional.append((exact - whole, lane))
    unallocated = maximum - sum(allocations.values())
    for _, lane in sorted(fractional, key=lambda item: (-item[0], item[1]))[
        :unallocated
    ]:
        allocations[lane] += 1
    return allocations


def _query_yields(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    issue_id: str,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT
            q.source, q.query_id, q.lane,
            COUNT(*) AS observed_records,
            COUNT(DISTINCT rh.work_id) AS unique_candidates,
            COUNT(DISTINCT CASE WHEN rh.admitted=1 THEN rh.work_id END)
                AS objectively_admitted,
            COUNT(DISTINCT CASE WHEN rii.selected=1 THEN rh.work_id END)
                AS publication_selected
        FROM query_jobs q
        LEFT JOIN run_hits rh ON rh.query_job_id=q.id AND rh.run_id=q.run_id
        LEFT JOIN report_issue_items rii
          ON rii.issue_id=? AND rii.work_id=rh.work_id
        WHERE q.run_id=?
        GROUP BY q.source, q.query_id, q.lane
        ORDER BY q.source, q.query_id
        """,
        (issue_id, run_id),
    ).fetchall()
    return [dict(row) for row in rows]


def _duration_calibration(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    maximum_runtime_seconds: int,
) -> dict[str, Any]:
    rows = connection.execute(
        """
        SELECT provider, work_id, SUM(duration_seconds) AS full_read_seconds,
               COUNT(*) AS invocation_count
        FROM model_invocations
        WHERE run_id=? AND work_id IS NOT NULL AND duration_seconds>0
        GROUP BY provider, work_id
        ORDER BY provider, work_id
        """,
        (run_id,),
    ).fetchall()
    by_provider: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        by_provider[str(row["provider"])].append(float(row["full_read_seconds"]))
    provider = "codex_cli" if by_provider.get("codex_cli") else ""
    if not provider and by_provider:
        provider = sorted(by_provider)[0]
    if not provider:
        raise CalibrationError(
            "the selected run has no per-work model duration receipts"
        )
    durations = by_provider[provider]
    p50 = _percentile(durations, 0.50)
    p90 = _percentile(durations, 0.90)
    operating_fraction = 0.80
    usable_seconds = maximum_runtime_seconds * operating_fraction
    maximum = max(1, math.floor(usable_seconds / max(p90, 0.001)))
    return {
        "provider": provider,
        "sample_count": len(durations),
        "per_work_seconds": {
            "minimum": round(min(durations), 3),
            "p50": round(p50, 3),
            "p90": round(p90, 3),
            "maximum": round(max(durations), 3),
        },
        "runtime_seconds": maximum_runtime_seconds,
        "operating_fraction": operating_fraction,
        "usable_seconds": round(usable_seconds, 3),
        "derived_maximum_admitted_candidates": maximum,
        "derivation": "floor(runtime_seconds * operating_fraction / p90)",
        "provider_samples": {
            key: len(value) for key, value in sorted(by_provider.items())
        },
    }


def _diverse_unselected(
    rows: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        snapshot = json.loads(str(row["snapshot_json"]))
        groups[
            (
                str(snapshot.get("lane") or "unknown"),
                str(row["selection_bucket"]),
            )
        ].append(row)
    for values in groups.values():
        values.sort(key=lambda row: (str(row["snapshot_sha256"]), int(row["analysis_id"])))
    selected: list[dict[str, Any]] = []
    keys = sorted(groups)
    while len(selected) < limit and keys:
        remaining: list[tuple[str, str]] = []
        for key in keys:
            if groups[key] and len(selected) < limit:
                selected.append(groups[key].pop(0))
            if groups[key]:
                remaining.append(key)
        keys = remaining
    return selected


def _review_item_from_snapshot(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    snapshot = json.loads(str(row["snapshot_json"]))
    analysis = snapshot.get("analysis") or {}
    citation = snapshot.get("citation") or {}
    return {
        "item_id": f"analysis:{int(row['analysis_id'])}",
        "record_class": "complete_analysis",
        "work_id": int(row["work_id"]),
        "analysis_id": int(row["analysis_id"]),
        "input_sha256": str(row["input_sha256"]),
        "snapshot_sha256": str(row["snapshot_sha256"]),
        "captured_as": (
            "publication_selected" if int(row["selected"]) else "candidate_unselected"
        ),
        "selection_bucket": str(row["selection_bucket"]),
        "review_context": {
            "citation": citation,
            "provider": snapshot.get("provider"),
            "tier": snapshot.get("tier"),
            "score": snapshot.get("score"),
            "lane": snapshot.get("lane"),
            "summary_zh": analysis.get("summary_zh"),
            "r3_relationship": analysis.get("r3_relationship") or [],
            "limitations": analysis.get("limitations") or [],
            "uncertainties": analysis.get("uncertainties") or [],
            "evidence_anchors": analysis.get("evidence_anchors") or [],
        },
        "frozen_snapshot": snapshot,
        "human_label": None,
        "human_notes": None,
    }


def _operational_sentinels(
    connection: sqlite3.Connection,
    *,
    retrieval_hash: str,
    excluded_work_ids: set[int],
    excluded_input_sha256: set[str],
    limit: int,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT
            w.id AS work_id, w.canonical_key, w.kind, w.title, w.year,
            w.doi, w.arxiv_id, w.github_full_name, w.best_url,
            ws.state, ws.admission_code, ws.last_error,
            (
                SELECT d.status FROM documents d
                WHERE d.work_id=w.id
                ORDER BY d.updated_at DESC, d.id DESC LIMIT 1
            ) AS document_status,
            (
                SELECT COALESCE(d.text_sha256, d.content_sha256)
                FROM documents d
                WHERE d.work_id=w.id
                ORDER BY d.updated_at DESC, d.id DESC LIMIT 1
            ) AS input_sha256
        FROM work_scopes ws
        JOIN works w ON w.id=ws.work_id
        WHERE ws.config_hash=?
          AND (
              ws.state IN ('rejected','analysis_failed')
              OR EXISTS (
                  SELECT 1 FROM documents d
                  WHERE d.work_id=w.id
                    AND d.status IN ('unavailable','incomplete')
              )
          )
        ORDER BY
            CASE ws.state
              WHEN 'analysis_failed' THEN 0
              WHEN 'rejected' THEN 2
              ELSE 1
            END,
            w.id
        """,
        (retrieval_hash,),
    ).fetchall()
    sentinels: list[dict[str, Any]] = []
    seen_input_sha256 = set(excluded_input_sha256)
    for row in rows:
        work_id = int(row["work_id"])
        input_sha256 = row["input_sha256"]
        if (
            work_id in excluded_work_ids
            or (
                isinstance(input_sha256, str)
                and input_sha256 in seen_input_sha256
            )
        ):
            continue
        frozen = {
            "schema": "r3/gold-operational-sentinel/v1",
            "work_id": work_id,
            "canonical_key": str(row["canonical_key"]),
            "citation": {
                key: row[key]
                for key in (
                    "kind",
                    "title",
                    "year",
                    "doi",
                    "arxiv_id",
                    "github_full_name",
                    "best_url",
                )
            },
            "state": str(row["state"]),
            "admission_code": str(row["admission_code"]),
            "document_status": row["document_status"],
            "input_sha256": input_sha256,
            "error_present": bool(row["last_error"]),
        }
        snapshot_sha = hashlib.sha256(
            canonical_json(frozen).encode("utf-8")
        ).hexdigest()
        sentinels.append(
            {
                "item_id": f"work:{work_id}:operational",
                "record_class": "operational_sentinel",
                "work_id": work_id,
                "analysis_id": None,
                "input_sha256": input_sha256,
                "snapshot_sha256": snapshot_sha,
                "captured_as": "operational_sentinel",
                "selection_bucket": None,
                "review_context": frozen,
                "frozen_snapshot": frozen,
                "human_label": None,
                "human_notes": None,
            }
        )
        if isinstance(input_sha256, str):
            seen_input_sha256.add(input_sha256)
        if len(sentinels) >= limit:
            break
    return sentinels


def _gold_set_draft(
    connection: sqlite3.Connection,
    *,
    run: dict[str, Any],
    issue_id: str,
    database_sha256: str,
) -> dict[str, Any]:
    rows = connection.execute(
        """
        SELECT * FROM report_issue_items
        WHERE issue_id=? AND snapshot_json IS NOT NULL
        ORDER BY selected DESC, analysis_id
        """,
        (issue_id,),
    ).fetchall()
    selected = [dict(row) for row in rows if int(row["selected"]) == 1]
    unselected = [dict(row) for row in rows if int(row["selected"]) == 0]
    selected.sort(
        key=lambda row: (
            {
                "must_read": 0,
                "important": 1,
                "background": 2,
                "excluded_after_deep_read": 3,
            }.get(str(row["selection_bucket"]), 4),
            int(row["analysis_id"]),
        )
    )
    ordered_candidates = selected[:40] + _diverse_unselected(
        unselected,
        limit=len(unselected),
    )
    items: list[dict[str, Any]] = []
    seen_work_ids: set[int] = set()
    seen_input_sha256: set[str] = set()
    for row in ordered_candidates:
        item = _review_item_from_snapshot(row)
        work_id = int(item["work_id"])
        input_sha256 = str(item["input_sha256"])
        if work_id in seen_work_ids or input_sha256 in seen_input_sha256:
            continue
        items.append(item)
        seen_work_ids.add(work_id)
        seen_input_sha256.add(input_sha256)
        if len(items) >= 60:
            break
    sentinels = _operational_sentinels(
        connection,
        retrieval_hash=str(run["retrieval_hash"]),
        excluded_work_ids=seen_work_ids,
        excluded_input_sha256=seen_input_sha256,
        limit=min(10, 80 - len(items)),
    )
    items.extend(sentinels)
    if not 50 <= len(items) <= 80:
        raise CalibrationError(
            f"Gold Set draft must contain 50-80 items, found {len(items)}"
        )
    return {
        "schema": GOLD_SET_SCHEMA,
        "scope": {
            "run_id": str(run["id"]),
            "issue_id": issue_id,
            "profile_id": str(run["profile_id"]),
            "profile_version": int(run["profile_version"]),
            "config_hash": str(run["config_hash"]),
            "retrieval_hash": str(run["retrieval_hash"]),
            "analysis_policy_hash": str(run["analysis_policy_hash"]),
            "database_sha256_at_draft": database_sha256,
        },
        "review": {
            "status": "pending_human_verification",
            "reviewer": None,
            "reviewed_at": None,
            "allowed_labels": list(_LABELS),
            "instructions": (
                "Review the frozen evidence for every item. Set exactly one "
                "human_label and optional notes. Do not copy the model tier as truth."
            ),
        },
        "sampling": {
            "publication_selected_target": 40,
            "diverse_candidate_unselected_target": 20,
            "operational_sentinel_maximum": 10,
            "actual_count": len(items),
            "selection_bias_warning": (
                "This draft is built from an existing run and cannot establish "
                "external corpus recall until a human verifies the labels."
            ),
        },
        "items": items,
    }


def _require_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise CalibrationError(f"{field} must be a lowercase SHA-256")
    return value


def _require_nonempty_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CalibrationError(f"{field} must be a non-empty string")
    return value


def _validated_review_time(value: Any) -> str:
    reviewed_at = _require_nonempty_string(value, field="review.reviewed_at")
    try:
        parsed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CalibrationError(
            "review.reviewed_at must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise CalibrationError("review.reviewed_at must include a timezone")
    return reviewed_at


_GOLD_V2_KEYS = {
    "schema",
    "source",
    "scope",
    "review",
    "sampling",
    "items",
    "revisions",
}
_GOLD_V2_ITEM_KEYS = {
    "item_id",
    "record_class",
    "work_id",
    "analysis_id",
    "input_sha256",
    "snapshot_sha256",
    "captured_as",
    "selection_bucket",
    "review_context",
    "frozen_snapshot",
    "y0",
    "ai_assistance",
    "y1",
}
_GOLD_V2_REVIEW_KEYS = {
    "status",
    "reviewer_identity",
    "item_count",
    "gold_truth_basis",
    "blind_order_seed_sha256",
    "y0_locked_at",
    "y0_lock_sha256",
    "ai_revealed_at",
}
_REVISION_KEYS = {
    "sequence",
    "event",
    "item_id",
    "reviewer_identity",
    "submitted_at",
    "previous_revision_sha256",
    "payload",
    "revision_sha256",
}


def _validated_gold_time(value: Any, *, field: str) -> str:
    timestamp = _require_nonempty_string(value, field=field)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CalibrationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise CalibrationError(f"{field} must include a timezone")
    return timestamp


def _gold_revision_sha256(revision: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in revision.items() if key != "revision_sha256"}
    return hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest()


def _append_gold_revision(
    gold_set: dict[str, Any],
    *,
    event: str,
    item_id: str | None,
    reviewer_identity: str,
    submitted_at: str,
    payload: dict[str, Any],
) -> str:
    revisions = gold_set["revisions"]
    revision = {
        "sequence": len(revisions) + 1,
        "event": event,
        "item_id": item_id,
        "reviewer_identity": reviewer_identity,
        "submitted_at": submitted_at,
        "previous_revision_sha256": (
            revisions[-1]["revision_sha256"] if revisions else None
        ),
        "payload": copy.deepcopy(payload),
    }
    revision["revision_sha256"] = _gold_revision_sha256(revision)
    revisions.append(revision)
    return str(revision["revision_sha256"])


def _y0_lock_digest(gold_set: dict[str, Any]) -> str:
    payload = [
        {"item_id": item["item_id"], "y0": item["y0"]}
        for item in sorted(gold_set["items"], key=lambda value: value["item_id"])
    ]
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def convert_gold_set_v1_to_v2_preview(
    gold_set_v1: dict[str, Any],
    *,
    reviewer_identity: str,
    collection_kind: str = "run_derived",
    evaluation_split: str = "development",
) -> dict[str, Any]:
    """Create a fresh blind-review contract without mutating or importing v1 labels."""

    validated = _validate_gold_set(gold_set_v1)
    reviewer = _require_nonempty_string(
        reviewer_identity,
        field="reviewer_identity",
    )
    if len(validated["items"]) != 70:
        raise CalibrationError(
            "Gold v2 blind review requires exactly 70 frozen items"
        )
    if collection_kind not in {"run_derived", "external_known_answer"}:
        raise CalibrationError("collection_kind is invalid")
    if evaluation_split not in {"development", "evaluation"}:
        raise CalibrationError("evaluation_split is invalid")

    source_sha256 = hashlib.sha256(
        canonical_json(gold_set_v1).encode("utf-8")
    ).hexdigest()
    scope = copy.deepcopy(gold_set_v1["scope"])
    scope["collection_kind"] = collection_kind
    scope["evaluation_split"] = evaluation_split
    items = []
    for source_item in gold_set_v1["items"]:
        items.append(
            {
                key: copy.deepcopy(source_item[key])
                for key in (
                    "item_id",
                    "record_class",
                    "work_id",
                    "analysis_id",
                    "input_sha256",
                    "snapshot_sha256",
                    "captured_as",
                    "selection_bucket",
                    "review_context",
                    "frozen_snapshot",
                )
            }
            | {"y0": None, "ai_assistance": None, "y1": None}
        )
    blind_seed = hashlib.sha256(
        f"{source_sha256}:blind-order-v1".encode("utf-8")
    ).hexdigest()
    converted = {
        "schema": GOLD_SET_V2_SCHEMA,
        "source": {
            "schema": GOLD_SET_SCHEMA,
            "sha256": source_sha256,
            "import_mode": "review_reset_for_blind_y0",
        },
        "scope": scope,
        "review": {
            "status": "y0_in_progress",
            "reviewer_identity": reviewer,
            "item_count": 70,
            "gold_truth_basis": "blind_y0",
            "blind_order_seed_sha256": blind_seed,
            "y0_locked_at": None,
            "y0_lock_sha256": None,
            "ai_revealed_at": None,
        },
        "sampling": copy.deepcopy(gold_set_v1["sampling"]),
        "items": items,
        "revisions": [],
    }
    _validate_gold_set_v2(converted)
    return converted


def _blind_citation(item: dict[str, Any]) -> dict[str, Any]:
    context = item["review_context"]
    citation = context.get("citation") if isinstance(context, dict) else None
    if not isinstance(citation, dict):
        citation = context if isinstance(context, dict) else {}
    scalar_fields = {
        "title",
        "kind",
        "year",
        "doi",
        "arxiv_id",
        "github_full_name",
        "best_url",
        "canonical_url",
        "url",
        "abstract",
        "abstract_text",
        "description",
        "readme_excerpt",
    }
    result = {
        key: copy.deepcopy(citation[key])
        for key in scalar_fields
        if key in citation and isinstance(citation[key], (str, int))
    }
    authors = citation.get("authors")
    if isinstance(authors, list):
        safe_authors: list[Any] = []
        for author in authors:
            if isinstance(author, str):
                safe_authors.append(author)
            elif isinstance(author, dict):
                safe = {
                    key: author[key]
                    for key in ("name", "display_name", "orcid")
                    if isinstance(author.get(key), str)
                }
                if safe:
                    safe_authors.append(safe)
        result["authors"] = safe_authors
    elif isinstance(authors, str):
        result["authors"] = authors
    return result


def blind_gold_set_payload(gold_set: dict[str, Any]) -> dict[str, Any]:
    """Return a server-safe y0 view; model outputs are absent, not CSS-hidden."""

    validated = _validate_gold_set_v2(gold_set)
    review = gold_set["review"]
    if review["status"] != "y0_in_progress":
        raise CalibrationError("blind y0 payload is available only before y0 lock")
    seed = review["blind_order_seed_sha256"]
    ordered = sorted(
        gold_set["items"],
        key=lambda item: hashlib.sha256(
            f"{seed}:{item['item_id']}".encode("utf-8")
        ).hexdigest(),
    )
    items = []
    for item in ordered:
        frozen = item["frozen_snapshot"]
        operational_evidence = {}
        if item["record_class"] == "operational_sentinel":
            operational_evidence = {
                key: copy.deepcopy(frozen[key])
                for key in ("state", "document_status", "error_present")
                if key in frozen
            }
        items.append(
            {
                "item_id": item["item_id"],
                "record_class": item["record_class"],
                "citation": _blind_citation(item),
                "operational_evidence": operational_evidence,
                "y0": copy.deepcopy(item["y0"]),
            }
        )
    return {
        "schema": "r3/gold-set-blind-view/v1",
        "status": "y0_in_progress",
        "item_count": len(items),
        "completed_count": sum(item["y0"] is not None for item in items),
        "items": items,
        "validation": {
            "gold_truth_basis": "blind_y0",
            "all_y0_required_before_ai_reveal": True,
            "model_fields_in_response": False,
        },
    }


def submit_gold_y0(
    gold_set: dict[str, Any],
    *,
    item_id: str,
    reviewer_identity: str,
    semantic_label: str,
    operational_status: str,
    confidence: int | None,
    evidence_opened: bool,
    elapsed_ms: int,
    notes: str | None,
    submitted_at: str,
    expected_revision_sequence: int,
) -> dict[str, Any]:
    """Append one optimistic-concurrency y0 revision and return a new document."""

    _validate_gold_set_v2(gold_set)
    result = copy.deepcopy(gold_set)
    if result["review"]["status"] != "y0_in_progress":
        raise CalibrationError("y0 is locked and cannot be changed")
    reviewer = _require_nonempty_string(reviewer_identity, field="reviewer_identity")
    if reviewer != result["review"]["reviewer_identity"]:
        raise CalibrationError("reviewer_identity does not own this blind review")
    submitted = _validated_gold_time(submitted_at, field="submitted_at")
    if semantic_label not in SEMANTIC_LABELS:
        raise CalibrationError("semantic_label is invalid")
    if operational_status not in OPERATIONAL_STATUSES:
        raise CalibrationError("operational_status is invalid")
    if confidence is not None and (
        isinstance(confidence, bool) or not isinstance(confidence, int) or not 1 <= confidence <= 5
    ):
        raise CalibrationError("confidence must be null or an integer from 1 to 5")
    if semantic_label != "unjudged" and confidence is None:
        raise CalibrationError("a judged semantic label requires confidence")
    if not isinstance(evidence_opened, bool):
        raise CalibrationError("evidence_opened must be boolean")
    if isinstance(elapsed_ms, bool) or not isinstance(elapsed_ms, int) or elapsed_ms < 0:
        raise CalibrationError("elapsed_ms must be a non-negative integer")
    if notes is not None and not isinstance(notes, str):
        raise CalibrationError("notes must be text or null")
    item = next((value for value in result["items"] if value["item_id"] == item_id), None)
    if item is None:
        raise CalibrationError(f"unknown Gold v2 item_id: {item_id}")
    current_sequence = (
        int(item["y0"]["revision_sequence"]) if item["y0"] is not None else 0
    )
    if expected_revision_sequence != current_sequence:
        raise CalibrationError(
            "stale y0 submission: expected_revision_sequence does not match"
        )
    payload = {
        "semantic_label": semantic_label,
        "operational_status": operational_status,
        "confidence": confidence,
        "evidence_opened": evidence_opened,
        "elapsed_ms": elapsed_ms,
        "notes": notes,
        "submitted_at": submitted,
        "revision_sequence": current_sequence + 1,
    }
    revision_sha256 = _append_gold_revision(
        result,
        event="y0_submit",
        item_id=item_id,
        reviewer_identity=reviewer,
        submitted_at=submitted,
        payload=payload,
    )
    item["y0"] = payload | {"revision_sha256": revision_sha256}
    _validate_gold_set_v2(result)
    return result


def lock_gold_y0(
    gold_set: dict[str, Any],
    *,
    reviewer_identity: str,
    locked_at: str,
) -> dict[str, Any]:
    _validate_gold_set_v2(gold_set)
    result = copy.deepcopy(gold_set)
    if result["review"]["status"] != "y0_in_progress":
        raise CalibrationError("y0 can be locked exactly once")
    reviewer = _require_nonempty_string(reviewer_identity, field="reviewer_identity")
    if reviewer != result["review"]["reviewer_identity"]:
        raise CalibrationError("reviewer_identity does not own this blind review")
    missing = [item["item_id"] for item in result["items"] if item["y0"] is None]
    if missing:
        raise CalibrationError(
            f"all 70 y0 labels must be submitted before lock; missing {len(missing)}"
        )
    timestamp = _validated_gold_time(locked_at, field="locked_at")
    digest = _y0_lock_digest(result)
    result["review"].update(
        {
            "status": "y0_locked",
            "y0_locked_at": timestamp,
            "y0_lock_sha256": digest,
        }
    )
    _append_gold_revision(
        result,
        event="y0_lock",
        item_id=None,
        reviewer_identity=reviewer,
        submitted_at=timestamp,
        payload={"item_count": 70, "y0_lock_sha256": digest},
    )
    _validate_gold_set_v2(result)
    return result


def start_gold_y1(
    gold_set: dict[str, Any],
    *,
    reviewer_identity: str,
    assignments: dict[str, dict[str, Any]],
    revealed_at: str,
) -> dict[str, Any]:
    """Reveal a complete randomized assignment only after the blind truth is locked."""

    _validate_gold_set_v2(gold_set)
    result = copy.deepcopy(gold_set)
    if result["review"]["status"] != "y0_locked":
        raise CalibrationError("AI treatment cannot be revealed before all y0 labels lock")
    reviewer = _require_nonempty_string(reviewer_identity, field="reviewer_identity")
    if reviewer != result["review"]["reviewer_identity"]:
        raise CalibrationError("reviewer_identity does not own this review")
    timestamp = _validated_gold_time(revealed_at, field="revealed_at")
    item_ids = {item["item_id"] for item in result["items"]}
    if set(assignments) != item_ids:
        raise CalibrationError("AI assignments must cover exactly all 70 locked items")
    normalized: dict[str, dict[str, Any]] = {}
    for item_id in sorted(item_ids):
        assignment = assignments[item_id]
        if not isinstance(assignment, dict) or set(assignment) != {
            "ai_treatment",
            "ai_provider",
            "ai_model",
            "ai_prompt_sha256",
            "ai_payload",
        }:
            raise CalibrationError(f"AI assignment for {item_id} is invalid")
        treatment = assignment.get("ai_treatment")
        if treatment not in AI_TREATMENTS:
            raise CalibrationError(f"AI treatment for {item_id} is invalid")
        if treatment == "control":
            if any(
                assignment.get(field) is not None
                for field in (
                    "ai_provider",
                    "ai_model",
                    "ai_prompt_sha256",
                    "ai_payload",
                )
            ):
                raise CalibrationError("control assignments cannot carry model output")
        else:
            _require_nonempty_string(
                assignment.get("ai_provider"),
                field=f"assignments.{item_id}.ai_provider",
            )
            _require_nonempty_string(
                assignment.get("ai_model"),
                field=f"assignments.{item_id}.ai_model",
            )
            _require_sha256(
                assignment.get("ai_prompt_sha256"),
                field=f"assignments.{item_id}.ai_prompt_sha256",
            )
            if not isinstance(assignment.get("ai_payload"), dict):
                raise CalibrationError("ai_assisted assignments require an AI payload")
        normalized[item_id] = copy.deepcopy(assignment)
    for item in result["items"]:
        item["ai_assistance"] = normalized[item["item_id"]]
    assignments_sha256 = hashlib.sha256(
        canonical_json(normalized).encode("utf-8")
    ).hexdigest()
    result["review"].update(
        {"status": "y1_in_progress", "ai_revealed_at": timestamp}
    )
    _append_gold_revision(
        result,
        event="ai_reveal",
        item_id=None,
        reviewer_identity=reviewer,
        submitted_at=timestamp,
        payload={"item_count": 70, "assignments_sha256": assignments_sha256},
    )
    _validate_gold_set_v2(result)
    return result


def submit_gold_y1(
    gold_set: dict[str, Any],
    *,
    item_id: str,
    reviewer_identity: str,
    semantic_label: str,
    confidence: int | None,
    change_reason: str | None,
    submitted_at: str,
    expected_revision_sequence: int,
) -> dict[str, Any]:
    _validate_gold_set_v2(gold_set)
    result = copy.deepcopy(gold_set)
    if result["review"]["status"] not in {"y1_in_progress", "y1_complete"}:
        raise CalibrationError("y1 is unavailable before AI treatment reveal")
    reviewer = _require_nonempty_string(reviewer_identity, field="reviewer_identity")
    if reviewer != result["review"]["reviewer_identity"]:
        raise CalibrationError("reviewer_identity does not own this review")
    timestamp = _validated_gold_time(submitted_at, field="submitted_at")
    if semantic_label not in SEMANTIC_LABELS:
        raise CalibrationError("semantic_label is invalid")
    if confidence is not None and (
        isinstance(confidence, bool) or not isinstance(confidence, int) or not 1 <= confidence <= 5
    ):
        raise CalibrationError("confidence must be null or an integer from 1 to 5")
    if semantic_label != "unjudged" and confidence is None:
        raise CalibrationError("a judged semantic label requires confidence")
    if change_reason is not None and not isinstance(change_reason, str):
        raise CalibrationError("change_reason must be text or null")
    item = next((value for value in result["items"] if value["item_id"] == item_id), None)
    if item is None:
        raise CalibrationError(f"unknown Gold v2 item_id: {item_id}")
    current_sequence = (
        int(item["y1"]["revision_sequence"]) if item["y1"] is not None else 0
    )
    if expected_revision_sequence != current_sequence:
        raise CalibrationError(
            "stale y1 submission: expected_revision_sequence does not match"
        )
    changed = semantic_label != item["y0"]["semantic_label"]
    if changed and (change_reason is None or not change_reason.strip()):
        raise CalibrationError("change_reason is required when y1 differs from y0")
    payload = {
        "semantic_label": semantic_label,
        "confidence": confidence,
        "changed_after_ai": changed,
        "change_reason": change_reason,
        "submitted_at": timestamp,
        "revision_sequence": current_sequence + 1,
    }
    revision_sha256 = _append_gold_revision(
        result,
        event="y1_submit",
        item_id=item_id,
        reviewer_identity=reviewer,
        submitted_at=timestamp,
        payload=payload,
    )
    item["y1"] = payload | {"revision_sha256": revision_sha256}
    if all(value["y1"] is not None for value in result["items"]):
        result["review"]["status"] = "y1_complete"
    _validate_gold_set_v2(result)
    return result


def export_gold_v2_audit(gold_set: dict[str, Any]) -> dict[str, Any]:
    validated = _validate_gold_set_v2(gold_set)
    semantic_counts: dict[str, int] = defaultdict(int)
    operational_counts: dict[str, int] = defaultdict(int)
    for item in gold_set["items"]:
        if item["y0"] is not None:
            semantic_counts[item["y0"]["semantic_label"]] += 1
            operational_counts[item["y0"]["operational_status"]] += 1
    return {
        "schema": "r3/gold-set-audit-export/v2",
        "gold_set_schema": GOLD_SET_V2_SCHEMA,
        "gold_set_sha256": hashlib.sha256(
            canonical_json(gold_set).encode("utf-8")
        ).hexdigest(),
        "source_v1_sha256": gold_set["source"]["sha256"],
        "review_status": gold_set["review"]["status"],
        "reviewer_identity": gold_set["review"]["reviewer_identity"],
        "item_count": len(validated["items"]),
        "y0_locked_sha256": gold_set["review"]["y0_lock_sha256"],
        "revision_count": len(gold_set["revisions"]),
        "revision_head_sha256": (
            gold_set["revisions"][-1]["revision_sha256"]
            if gold_set["revisions"]
            else None
        ),
        "y0_semantic_counts": dict(sorted(semantic_counts.items())),
        "y0_operational_counts": dict(sorted(operational_counts.items())),
        "gold_truth_stage": "y0",
        "y1_role": "ai_assistance_feedback_only",
    }


def _validate_gold_set_v2(gold_set: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(gold_set, dict) or set(gold_set) != _GOLD_V2_KEYS:
        raise CalibrationError("Gold v2 document keys do not match the contract")
    if gold_set.get("schema") != GOLD_SET_V2_SCHEMA:
        raise CalibrationError(f"Gold v2 schema must be {GOLD_SET_V2_SCHEMA}")
    source = gold_set.get("source")
    if not isinstance(source, dict) or set(source) != {
        "schema",
        "sha256",
        "import_mode",
    }:
        raise CalibrationError("Gold v2 source metadata is invalid")
    if source.get("schema") != GOLD_SET_SCHEMA:
        raise CalibrationError("Gold v2 source must identify the frozen v1 schema")
    _require_sha256(source.get("sha256"), field="source.sha256")
    if source.get("import_mode") != "review_reset_for_blind_y0":
        raise CalibrationError("Gold v2 source import_mode is invalid")

    scope = gold_set.get("scope")
    expected_scope_keys = _GOLD_SCOPE_KEYS | {"collection_kind", "evaluation_split"}
    if not isinstance(scope, dict) or set(scope) != expected_scope_keys:
        raise CalibrationError("Gold v2 scope does not match the contract")
    if scope.get("collection_kind") not in {
        "run_derived",
        "external_known_answer",
    }:
        raise CalibrationError("scope.collection_kind is invalid")
    if scope.get("evaluation_split") not in {"development", "evaluation"}:
        raise CalibrationError("scope.evaluation_split is invalid")
    for field in ("run_id", "issue_id", "profile_id"):
        _require_nonempty_string(scope.get(field), field=f"scope.{field}")
    profile_version = scope.get("profile_version")
    if (
        isinstance(profile_version, bool)
        or not isinstance(profile_version, int)
        or profile_version <= 0
    ):
        raise CalibrationError("scope.profile_version must be a positive integer")
    for field in (
        "config_hash",
        "retrieval_hash",
        "analysis_policy_hash",
        "database_sha256_at_draft",
    ):
        _require_sha256(scope.get(field), field=f"scope.{field}")

    review = gold_set.get("review")
    if not isinstance(review, dict) or set(review) != _GOLD_V2_REVIEW_KEYS:
        raise CalibrationError("Gold v2 review metadata is invalid")
    status = review.get("status")
    if status not in {"y0_in_progress", "y0_locked", "y1_in_progress", "y1_complete"}:
        raise CalibrationError("Gold v2 review.status is invalid")
    _require_nonempty_string(
        review.get("reviewer_identity"),
        field="review.reviewer_identity",
    )
    if review.get("item_count") != 70 or review.get("gold_truth_basis") != "blind_y0":
        raise CalibrationError("Gold v2 requires 70 items and blind_y0 truth")
    _require_sha256(
        review.get("blind_order_seed_sha256"),
        field="review.blind_order_seed_sha256",
    )

    items = gold_set.get("items")
    if not isinstance(items, list) or len(items) != 70:
        raise CalibrationError("Gold v2 requires exactly 70 items")
    if not isinstance(gold_set.get("sampling"), dict):
        raise CalibrationError("Gold v2 sampling must be an object")
    if gold_set["sampling"].get("actual_count") != 70:
        raise CalibrationError("Gold v2 sampling.actual_count must equal 70")

    revisions = gold_set.get("revisions")
    if not isinstance(revisions, list):
        raise CalibrationError("Gold v2 revisions must be a list")
    previous_sha256: str | None = None
    y0_revision_heads: dict[str, str] = {}
    y0_revision_payloads: dict[str, dict[str, Any]] = {}
    y1_revision_heads: dict[str, str] = {}
    y1_revision_payloads: dict[str, dict[str, Any]] = {}
    lock_revision_payload: dict[str, Any] | None = None
    reveal_revision_payload: dict[str, Any] | None = None
    revision_stage = "y0"
    allowed_events = {"y0_submit", "y0_lock", "ai_reveal", "y1_submit"}
    for index, revision in enumerate(revisions, start=1):
        prefix = f"revisions[{index - 1}]"
        if not isinstance(revision, dict) or set(revision) != _REVISION_KEYS:
            raise CalibrationError(f"{prefix} does not match the revision contract")
        if revision.get("sequence") != index:
            raise CalibrationError(f"{prefix}.sequence is not append-only")
        if revision.get("event") not in allowed_events:
            raise CalibrationError(f"{prefix}.event is invalid")
        if revision.get("previous_revision_sha256") != previous_sha256:
            raise CalibrationError(f"{prefix} breaks the revision hash chain")
        _require_nonempty_string(
            revision.get("reviewer_identity"),
            field=f"{prefix}.reviewer_identity",
        )
        if revision.get("reviewer_identity") != review["reviewer_identity"]:
            raise CalibrationError(f"{prefix}.reviewer_identity changed")
        _validated_gold_time(revision.get("submitted_at"), field=f"{prefix}.submitted_at")
        if not isinstance(revision.get("payload"), dict):
            raise CalibrationError(f"{prefix}.payload must be an object")
        actual_revision_sha256 = _require_sha256(
            revision.get("revision_sha256"),
            field=f"{prefix}.revision_sha256",
        )
        if actual_revision_sha256 != _gold_revision_sha256(revision):
            raise CalibrationError(f"{prefix}.revision_sha256 is invalid")
        item_id = revision.get("item_id")
        if revision["event"] in {"y0_submit", "y1_submit"}:
            _require_nonempty_string(item_id, field=f"{prefix}.item_id")
            if revision["event"] == "y0_submit":
                if revision_stage != "y0":
                    raise CalibrationError("y0 revisions cannot follow the y0 lock")
                y0_revision_heads[str(item_id)] = actual_revision_sha256
                y0_revision_payloads[str(item_id)] = copy.deepcopy(revision["payload"])
            else:
                if revision_stage != "y1":
                    raise CalibrationError("y1 revisions require the AI reveal event")
                y1_revision_heads[str(item_id)] = actual_revision_sha256
                y1_revision_payloads[str(item_id)] = copy.deepcopy(revision["payload"])
        elif item_id is not None:
            raise CalibrationError(f"{prefix}.item_id must be null for batch events")
        elif revision["event"] == "y0_lock":
            if revision_stage != "y0" or lock_revision_payload is not None:
                raise CalibrationError("the y0 lock event must occur exactly once")
            revision_stage = "y0_locked"
            lock_revision_payload = copy.deepcopy(revision["payload"])
        elif revision["event"] == "ai_reveal":
            if revision_stage != "y0_locked" or reveal_revision_payload is not None:
                raise CalibrationError("the AI reveal event must follow the y0 lock once")
            revision_stage = "y1"
            reveal_revision_payload = copy.deepcopy(revision["payload"])
        previous_sha256 = actual_revision_sha256

    seen_item_ids: set[str] = set()
    seen_work_ids: set[int] = set()
    seen_input_sha256: set[str] = set()
    y0_complete = 0
    y1_complete = 0
    ai_complete = 0
    for index, item in enumerate(items):
        prefix = f"items[{index}]"
        if not isinstance(item, dict) or set(item) != _GOLD_V2_ITEM_KEYS:
            raise CalibrationError(f"{prefix} does not match the Gold v2 item contract")
        item_id = _require_nonempty_string(item.get("item_id"), field=f"{prefix}.item_id")
        if item_id in seen_item_ids:
            raise CalibrationError(f"duplicate Gold v2 item_id: {item_id}")
        seen_item_ids.add(item_id)
        work_id = item.get("work_id")
        if isinstance(work_id, bool) or not isinstance(work_id, int) or work_id <= 0:
            raise CalibrationError(f"{prefix}.work_id must be a positive integer")
        if work_id in seen_work_ids:
            raise CalibrationError(f"duplicate Gold v2 work_id: {work_id}")
        seen_work_ids.add(work_id)
        input_sha256 = item.get("input_sha256")
        if input_sha256 is not None:
            input_sha256 = _require_sha256(input_sha256, field=f"{prefix}.input_sha256")
            if input_sha256 in seen_input_sha256:
                raise CalibrationError(f"duplicate Gold v2 input_sha256: {input_sha256}")
            seen_input_sha256.add(input_sha256)
        frozen = item.get("frozen_snapshot")
        if not isinstance(frozen, dict) or frozen.get("work_id") != work_id:
            raise CalibrationError(f"{prefix}.frozen_snapshot identity mismatch")
        record_class = item.get("record_class")
        analysis_id = item.get("analysis_id")
        if record_class == "complete_analysis":
            if (
                isinstance(analysis_id, bool)
                or not isinstance(analysis_id, int)
                or analysis_id <= 0
                or item_id != f"analysis:{analysis_id}"
                or frozen.get("analysis_id") != analysis_id
                or frozen.get("input_sha256") != input_sha256
            ):
                raise CalibrationError(f"{prefix}.complete_analysis identity is invalid")
        elif record_class == "operational_sentinel":
            if analysis_id is not None or item_id != f"work:{work_id}:operational":
                raise CalibrationError(f"{prefix}.operational_sentinel identity is invalid")
        else:
            raise CalibrationError(f"{prefix}.record_class is invalid")
        expected_snapshot = hashlib.sha256(
            canonical_json(frozen).encode("utf-8")
        ).hexdigest()
        if (
            _require_sha256(
                item.get("snapshot_sha256"),
                field=f"{prefix}.snapshot_sha256",
            )
            != expected_snapshot
        ):
            raise CalibrationError(f"{prefix}.snapshot_sha256 is invalid")
        if not isinstance(item.get("review_context"), dict):
            raise CalibrationError(f"{prefix}.review_context must be an object")

        y0 = item.get("y0")
        if y0 is not None:
            expected_y0_keys = {
                "semantic_label",
                "operational_status",
                "confidence",
                "evidence_opened",
                "elapsed_ms",
                "notes",
                "submitted_at",
                "revision_sequence",
                "revision_sha256",
            }
            if not isinstance(y0, dict) or set(y0) != expected_y0_keys:
                raise CalibrationError(f"{prefix}.y0 is invalid")
            if y0.get("semantic_label") not in SEMANTIC_LABELS:
                raise CalibrationError(f"{prefix}.y0.semantic_label is invalid")
            if y0.get("operational_status") not in OPERATIONAL_STATUSES:
                raise CalibrationError(f"{prefix}.y0.operational_status is invalid")
            confidence = y0.get("confidence")
            if confidence is not None and (
                isinstance(confidence, bool)
                or not isinstance(confidence, int)
                or not 1 <= confidence <= 5
            ):
                raise CalibrationError(f"{prefix}.y0.confidence is invalid")
            if y0.get("semantic_label") != "unjudged" and confidence is None:
                raise CalibrationError(f"{prefix}.y0.confidence is required")
            if not isinstance(y0.get("evidence_opened"), bool):
                raise CalibrationError(f"{prefix}.y0.evidence_opened is invalid")
            elapsed_ms = y0.get("elapsed_ms")
            if isinstance(elapsed_ms, bool) or not isinstance(elapsed_ms, int) or elapsed_ms < 0:
                raise CalibrationError(f"{prefix}.y0.elapsed_ms is invalid")
            if y0.get("notes") is not None and not isinstance(y0.get("notes"), str):
                raise CalibrationError(f"{prefix}.y0.notes is invalid")
            _validated_gold_time(
                y0.get("submitted_at"),
                field=f"{prefix}.y0.submitted_at",
            )
            if y0.get("revision_sha256") != y0_revision_heads.get(item_id):
                raise CalibrationError(f"{prefix}.y0 does not match its revision head")
            y0_payload = {
                key: value
                for key, value in y0.items()
                if key != "revision_sha256"
            }
            if y0_payload != y0_revision_payloads.get(item_id):
                raise CalibrationError(f"{prefix}.y0 does not match its revision payload")
            y0_complete += 1

        ai_assistance = item.get("ai_assistance")
        if ai_assistance is not None:
            if not isinstance(ai_assistance, dict) or set(ai_assistance) != {
                "ai_treatment",
                "ai_provider",
                "ai_model",
                "ai_prompt_sha256",
                "ai_payload",
            }:
                raise CalibrationError(f"{prefix}.ai_assistance is invalid")
            if ai_assistance.get("ai_treatment") not in AI_TREATMENTS:
                raise CalibrationError(f"{prefix}.ai_treatment is invalid")
            if ai_assistance["ai_treatment"] == "control":
                if any(
                    ai_assistance.get(field) is not None
                    for field in (
                        "ai_provider",
                        "ai_model",
                        "ai_prompt_sha256",
                        "ai_payload",
                    )
                ):
                    raise CalibrationError(f"{prefix}.control carries model output")
            else:
                _require_nonempty_string(
                    ai_assistance.get("ai_provider"),
                    field=f"{prefix}.ai_provider",
                )
                _require_nonempty_string(
                    ai_assistance.get("ai_model"),
                    field=f"{prefix}.ai_model",
                )
                _require_sha256(
                    ai_assistance.get("ai_prompt_sha256"),
                    field=f"{prefix}.ai_prompt_sha256",
                )
                if not isinstance(ai_assistance.get("ai_payload"), dict):
                    raise CalibrationError(f"{prefix}.ai_payload is invalid")
            ai_complete += 1
        y1 = item.get("y1")
        if y1 is not None:
            if not isinstance(y1, dict) or set(y1) != {
                "semantic_label",
                "confidence",
                "changed_after_ai",
                "change_reason",
                "submitted_at",
                "revision_sequence",
                "revision_sha256",
            }:
                raise CalibrationError(f"{prefix}.y1 is invalid")
            if y1.get("semantic_label") not in SEMANTIC_LABELS:
                raise CalibrationError(f"{prefix}.y1.semantic_label is invalid")
            confidence = y1.get("confidence")
            if confidence is not None and (
                isinstance(confidence, bool)
                or not isinstance(confidence, int)
                or not 1 <= confidence <= 5
            ):
                raise CalibrationError(f"{prefix}.y1.confidence is invalid")
            if y1.get("semantic_label") != "unjudged" and confidence is None:
                raise CalibrationError(f"{prefix}.y1.confidence is required")
            _validated_gold_time(
                y1.get("submitted_at"),
                field=f"{prefix}.y1.submitted_at",
            )
            changed = y1["semantic_label"] != y0["semantic_label"]
            if y1.get("changed_after_ai") is not changed:
                raise CalibrationError(f"{prefix}.y1.changed_after_ai is inconsistent")
            if changed and not str(y1.get("change_reason") or "").strip():
                raise CalibrationError(f"{prefix}.y1.change_reason is required")
            if y1.get("revision_sha256") != y1_revision_heads.get(item_id):
                raise CalibrationError(f"{prefix}.y1 does not match its revision head")
            y1_payload = {
                key: value
                for key, value in y1.items()
                if key != "revision_sha256"
            }
            if y1_payload != y1_revision_payloads.get(item_id):
                raise CalibrationError(f"{prefix}.y1 does not match its revision payload")
            y1_complete += 1

    if status == "y0_in_progress":
        if revision_stage != "y0":
            raise CalibrationError("y0_in_progress cannot contain lock or reveal events")
        if review.get("y0_locked_at") is not None or review.get("y0_lock_sha256") is not None:
            raise CalibrationError("unlocked y0 cannot claim lock metadata")
        if ai_complete or y1_complete or review.get("ai_revealed_at") is not None:
            raise CalibrationError("AI data cannot exist before y0 lock")
    else:
        if y0_complete != 70:
            raise CalibrationError("locked Gold v2 requires all 70 y0 labels")
        _validated_gold_time(review.get("y0_locked_at"), field="review.y0_locked_at")
        if (
            _require_sha256(
                review.get("y0_lock_sha256"),
                field="review.y0_lock_sha256",
            )
            != _y0_lock_digest(gold_set)
        ):
            raise CalibrationError("Gold v2 y0 lock digest does not match blind truth")
        if lock_revision_payload != {
            "item_count": 70,
            "y0_lock_sha256": review["y0_lock_sha256"],
        }:
            raise CalibrationError("Gold v2 y0 lock revision does not bind blind truth")
    if status == "y0_locked":
        if revision_stage != "y0_locked":
            raise CalibrationError("y0_locked requires exactly one lock event")
        if ai_complete or y1_complete or review.get("ai_revealed_at") is not None:
            raise CalibrationError("locked y0 must not contain revealed AI data")
    if status in {"y1_in_progress", "y1_complete"}:
        if revision_stage != "y1":
            raise CalibrationError("y1 requires exactly one AI reveal event")
        if ai_complete != 70:
            raise CalibrationError("y1 requires AI assignments for all 70 items")
        _validated_gold_time(review.get("ai_revealed_at"), field="review.ai_revealed_at")
        normalized_assignments = {
            item["item_id"]: item["ai_assistance"]
            for item in sorted(items, key=lambda value: value["item_id"])
        }
        assignments_sha256 = hashlib.sha256(
            canonical_json(normalized_assignments).encode("utf-8")
        ).hexdigest()
        if reveal_revision_payload != {
            "item_count": 70,
            "assignments_sha256": assignments_sha256,
        }:
            raise CalibrationError("Gold v2 AI reveal revision does not bind assignments")
    if status == "y1_complete" and y1_complete != 70:
        raise CalibrationError("y1_complete requires all 70 feedback labels")
    return {
        "scope": scope,
        "review_status": status,
        "items": items,
        "unlabeled_count": 70 - y0_complete,
    }


def _validate_gold_set(gold_set: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(gold_set, dict) or set(gold_set) != _GOLD_SET_KEYS:
        raise CalibrationError(
            "Gold Set must contain exactly schema, scope, review, sampling and items"
        )
    if gold_set.get("schema") != GOLD_SET_SCHEMA:
        raise CalibrationError(f"Gold Set schema must be {GOLD_SET_SCHEMA}")

    scope = gold_set.get("scope")
    if not isinstance(scope, dict) or set(scope) != _GOLD_SCOPE_KEYS:
        raise CalibrationError("Gold Set scope does not match the required schema")
    for field in ("run_id", "issue_id", "profile_id"):
        _require_nonempty_string(scope.get(field), field=f"scope.{field}")
    profile_version = scope.get("profile_version")
    if (
        isinstance(profile_version, bool)
        or not isinstance(profile_version, int)
        or profile_version <= 0
    ):
        raise CalibrationError("scope.profile_version must be a positive integer")
    for field in (
        "config_hash",
        "retrieval_hash",
        "analysis_policy_hash",
        "database_sha256_at_draft",
    ):
        _require_sha256(scope.get(field), field=f"scope.{field}")

    review = gold_set.get("review")
    if not isinstance(review, dict) or set(review) != _GOLD_REVIEW_KEYS:
        raise CalibrationError("Gold Set review metadata does not match the schema")
    if review.get("allowed_labels") != list(_LABELS):
        raise CalibrationError("review.allowed_labels must match the frozen label set")
    _require_nonempty_string(review.get("instructions"), field="review.instructions")
    review_status = review.get("status")
    if review_status not in {"pending_human_verification", "human_verified"}:
        raise CalibrationError("review.status is invalid")
    if review_status == "pending_human_verification":
        if review.get("reviewer") is not None or review.get("reviewed_at") is not None:
            raise CalibrationError(
                "pending review must not claim reviewer or reviewed_at metadata"
            )
    else:
        _require_nonempty_string(review.get("reviewer"), field="review.reviewer")
        _validated_review_time(review.get("reviewed_at"))

    sampling = gold_set.get("sampling")
    if not isinstance(sampling, dict):
        raise CalibrationError("Gold Set sampling must be an object")
    items = gold_set.get("items")
    if not isinstance(items, list) or not 50 <= len(items) <= 80:
        raise CalibrationError("Gold Set must contain 50-80 items")
    if sampling.get("actual_count") != len(items):
        raise CalibrationError("sampling.actual_count must equal the item count")

    seen_item_ids: set[str] = set()
    seen_work_ids: set[int] = set()
    seen_input_sha256: set[str] = set()
    unlabeled = 0
    for index, item in enumerate(items):
        prefix = f"items[{index}]"
        if not isinstance(item, dict) or set(item) != _GOLD_ITEM_KEYS:
            raise CalibrationError(f"{prefix} does not match the required item schema")
        item_id = _require_nonempty_string(item.get("item_id"), field=f"{prefix}.item_id")
        if item_id in seen_item_ids:
            raise CalibrationError(f"duplicate Gold Set item_id: {item_id}")
        seen_item_ids.add(item_id)

        work_id = item.get("work_id")
        if isinstance(work_id, bool) or not isinstance(work_id, int) or work_id <= 0:
            raise CalibrationError(f"{prefix}.work_id must be a positive integer")
        if work_id in seen_work_ids:
            raise CalibrationError(f"duplicate Gold Set work_id: {work_id}")
        seen_work_ids.add(work_id)

        record_class = item.get("record_class")
        analysis_id = item.get("analysis_id")
        input_sha256 = item.get("input_sha256")
        if record_class == "complete_analysis":
            if (
                isinstance(analysis_id, bool)
                or not isinstance(analysis_id, int)
                or analysis_id <= 0
            ):
                raise CalibrationError(
                    f"{prefix}.analysis_id must identify a complete analysis"
                )
            if item_id != f"analysis:{analysis_id}":
                raise CalibrationError(f"{prefix}.item_id does not bind analysis_id")
            input_sha256 = _require_sha256(
                input_sha256,
                field=f"{prefix}.input_sha256",
            )
        elif record_class == "operational_sentinel":
            if analysis_id is not None:
                raise CalibrationError(
                    f"{prefix}.analysis_id must be null for a sentinel"
                )
            if item_id != f"work:{work_id}:operational":
                raise CalibrationError(f"{prefix}.item_id does not bind work_id")
            if input_sha256 is not None:
                input_sha256 = _require_sha256(
                    input_sha256,
                    field=f"{prefix}.input_sha256",
                )
        else:
            raise CalibrationError(f"{prefix}.record_class is invalid")
        if input_sha256 is not None:
            if input_sha256 in seen_input_sha256:
                raise CalibrationError(
                    f"duplicate Gold Set input_sha256: {input_sha256}"
                )
            seen_input_sha256.add(input_sha256)

        frozen_snapshot = item.get("frozen_snapshot")
        if not isinstance(frozen_snapshot, dict):
            raise CalibrationError(f"{prefix}.frozen_snapshot must be an object")
        if frozen_snapshot.get("work_id") != work_id:
            raise CalibrationError(f"{prefix}.frozen_snapshot work_id mismatch")
        if record_class == "complete_analysis":
            if frozen_snapshot.get("analysis_id") != analysis_id:
                raise CalibrationError(
                    f"{prefix}.frozen_snapshot analysis_id mismatch"
                )
            if frozen_snapshot.get("input_sha256") != input_sha256:
                raise CalibrationError(
                    f"{prefix}.frozen_snapshot input_sha256 mismatch"
                )
        expected_snapshot_sha256 = hashlib.sha256(
            canonical_json(frozen_snapshot).encode("utf-8")
        ).hexdigest()
        actual_snapshot_sha256 = _require_sha256(
            item.get("snapshot_sha256"),
            field=f"{prefix}.snapshot_sha256",
        )
        if actual_snapshot_sha256 != expected_snapshot_sha256:
            raise CalibrationError(
                f"{prefix}.snapshot_sha256 does not freeze frozen_snapshot"
            )

        if not isinstance(item.get("review_context"), dict):
            raise CalibrationError(f"{prefix}.review_context must be an object")
        label = item.get("human_label")
        if label is None:
            unlabeled += 1
        elif label not in _LABELS:
            raise CalibrationError(f"{prefix}.human_label is invalid")
        notes = item.get("human_notes")
        if notes is not None and not isinstance(notes, str):
            raise CalibrationError(f"{prefix}.human_notes must be text or null")

    if review_status == "human_verified" and unlabeled:
        raise CalibrationError(
            "human_verified review metadata requires every item to be labeled"
        )
    return {
        "scope": scope,
        "review_status": review_status,
        "items": items,
        "unlabeled_count": unlabeled,
    }


def evaluate_gold_set(
    gold_set: dict[str, Any],
    *,
    candidate_work_ids: set[int],
    same_source: bool = False,
) -> dict[str, Any]:
    if gold_set.get("schema") == GOLD_SET_V2_SCHEMA:
        validated_v2 = _validate_gold_set_v2(gold_set)
        if validated_v2["review_status"] == "y0_in_progress":
            return {
                "schema": "r3/gold-set-evaluation/v2",
                "status": "pending_blind_y0_lock",
                "item_count": 70,
                "unlabeled_count": validated_v2["unlabeled_count"],
                "gold_truth_stage": "y0",
                "known_important_count": 0,
                "eligible_semantic_denominator": 0,
                "operational_excluded_count": 0,
                "unjudged_excluded_count": 0,
                "coverage_at_candidate": None,
                "recall_at_candidate": None,
                "threshold": 0.90,
                "passed": False,
                "reason": "Gold truth is unavailable until all 70 blind y0 labels lock.",
            }
        eligible = [
            item
            for item in validated_v2["items"]
            if item["y0"]["operational_status"] == "normal"
            and item["y0"]["semantic_label"] != "unjudged"
        ]
        operational_excluded = sum(
            item["y0"]["operational_status"] != "normal"
            for item in validated_v2["items"]
        )
        unjudged_excluded = sum(
            item["y0"]["operational_status"] == "normal"
            and item["y0"]["semantic_label"] == "unjudged"
            for item in validated_v2["items"]
        )
        known = [
            item
            for item in eligible
            if item["y0"]["semantic_label"] == "known_important"
        ]
        base = {
            "schema": "r3/gold-set-evaluation/v2",
            "item_count": 70,
            "unlabeled_count": 0,
            "gold_truth_stage": "y0",
            "known_important_count": len(known),
            "eligible_semantic_denominator": len(eligible),
            "operational_excluded_count": operational_excluded,
            "unjudged_excluded_count": unjudged_excluded,
            "threshold": 0.90,
        }
        if not known:
            return base | {
                "status": "invalid_no_known_important",
                "coverage_at_candidate": None,
                "recall_at_candidate": None,
                "passed": False,
                "reason": "At least one eligible blind-y0 known-important item is required.",
            }
        found = [item for item in known if int(item["work_id"]) in candidate_work_ids]
        score = len(found) / len(known)
        result = base | {
            "known_important_found": len(found),
            "missing_known_important_item_ids": [
                str(item["item_id"])
                for item in known
                if int(item["work_id"]) not in candidate_work_ids
            ],
            "passed": False,
        }
        if same_source:
            return result | {
                "status": "same_source_coverage_only",
                "coverage_at_candidate": round(score, 6),
                "recall_at_candidate": None,
                "reason": (
                    "The candidate and Gold Set use the same retrieval source; "
                    "blind y0 remains truth, but this score is coverage only."
                ),
            }
        return result | {
            "status": "evaluated",
            "coverage_at_candidate": None,
            "recall_at_candidate": round(score, 6),
            "passed": score >= 0.90,
        }
    if gold_set.get("schema") is None and set(gold_set) == {"items"}:
        # Backward-compatible in-memory metric fragments are not persisted Gold
        # Sets. Every generated or file-backed Gold Set takes the strict path.
        items = gold_set.get("items")
        if not isinstance(items, list):
            raise CalibrationError("Gold Set items must be a list")
        invalid = [
            item.get("item_id")
            for item in items
            if item.get("human_label") not in _LABELS
            and item.get("human_label") is not None
        ]
        if invalid:
            raise CalibrationError(
                "Gold Set contains invalid labels: "
                + ", ".join(map(str, invalid[:10]))
            )
        validated = {
            "items": items,
            "review_status": (
                "human_verified"
                if all(item.get("human_label") is not None for item in items)
                else "pending_human_verification"
            ),
        }
    else:
        validated = _validate_gold_set(gold_set)
    items = validated["items"]
    unlabeled = [
        str(item.get("item_id"))
        for item in items
        if item.get("human_label") is None
    ]
    known = [
        item for item in items if item.get("human_label") == "known_important"
    ]
    if unlabeled or validated["review_status"] != "human_verified":
        return {
            "schema": "r3/gold-set-evaluation/v1",
            "status": "pending_human_verification",
            "item_count": len(items),
            "unlabeled_count": len(unlabeled),
            "unlabeled_item_ids": unlabeled,
            "known_important_count": len(known),
            "coverage_at_candidate": None,
            "recall_at_candidate": None,
            "threshold": 0.90,
            "passed": False,
            "reason": (
                "Recall is not computed until all labels and the human reviewer "
                "metadata are complete."
            ),
        }
    if not known:
        return {
            "schema": "r3/gold-set-evaluation/v1",
            "status": "invalid_no_known_important",
            "item_count": len(items),
            "unlabeled_count": 0,
            "known_important_count": 0,
            "coverage_at_candidate": None,
            "recall_at_candidate": None,
            "threshold": 0.90,
            "passed": False,
            "reason": "At least one human-verified known-important item is required.",
        }
    found = [
        item for item in known if int(item["work_id"]) in candidate_work_ids
    ]
    score = len(found) / len(known)
    if same_source:
        return {
            "schema": "r3/gold-set-evaluation/v1",
            "status": "same_source_coverage_only",
            "item_count": len(items),
            "unlabeled_count": 0,
            "known_important_count": len(known),
            "known_important_found": len(found),
            "missing_known_important_item_ids": [
                str(item["item_id"])
                for item in known
                if int(item["work_id"]) not in candidate_work_ids
            ],
            "coverage_at_candidate": round(score, 6),
            "recall_at_candidate": None,
            "threshold": 0.90,
            "passed": False,
            "reason": (
                "The candidate and Gold Set use the same retrieval source; this "
                "is coverage evidence and cannot satisfy the recall gate."
            ),
        }
    return {
        "schema": "r3/gold-set-evaluation/v1",
        "status": "evaluated",
        "item_count": len(items),
        "unlabeled_count": 0,
        "known_important_count": len(known),
        "known_important_found": len(found),
        "missing_known_important_item_ids": [
            str(item["item_id"])
            for item in known
            if int(item["work_id"]) not in candidate_work_ids
        ],
        "coverage_at_candidate": None,
        "recall_at_candidate": round(score, 6),
        "threshold": 0.90,
        "passed": score >= 0.90,
    }


def _candidate_work_ids(
    connection: sqlite3.Connection,
    *,
    run_id: str,
) -> set[int]:
    return {
        int(row[0])
        for row in connection.execute(
            "SELECT DISTINCT work_id FROM run_hits WHERE run_id=?",
            (run_id,),
        ).fetchall()
    }


def _require_run_settings_identity(
    run: sqlite3.Row | dict[str, Any],
    settings: Settings,
    *,
    context: str,
) -> None:
    expected = {
        "profile_id": settings.profile_id,
        "profile_version": settings.profile_version,
        "config_hash": settings.config_hash,
        "retrieval_hash": settings.retrieval_hash,
        "analysis_policy_hash": settings.analysis_policy_hash,
    }
    actual = {
        "profile_id": str(run["profile_id"]),
        "profile_version": int(run["profile_version"]),
        "config_hash": str(run["config_hash"]),
        "retrieval_hash": str(run["retrieval_hash"]),
        "analysis_policy_hash": str(run["analysis_policy_hash"]),
    }
    mismatches = [
        field for field in expected if actual[field] != expected[field]
    ]
    if mismatches:
        raise CalibrationError(
            f"{context} does not match current settings: "
            + ", ".join(mismatches)
        )


def _weekly_replay(
    connection: sqlite3.Connection,
    *,
    run_id: str,
    policy_raw: dict[str, Any],
    reference_time: datetime,
) -> dict[str, Any]:
    policy = WeeklyIntakePolicy.from_config(policy_raw)
    gate = WeeklyIntakeGate(policy, now=reference_time)
    rows = connection.execute(
        """
        SELECT
            q.source AS query_source, q.query_id, q.lane,
            rh.admitted, rh.admission_code,
            w.id AS work_id, w.kind, w.title, w.year,
            w.doi, w.arxiv_id, w.github_full_name,
            sr.source AS record_source, sr.source_id,
            sr.canonical_url, sr.metadata_json
        FROM run_hits rh
        JOIN query_jobs q ON q.id=rh.query_job_id
        JOIN works w ON w.id=rh.work_id
        JOIN source_records sr ON sr.id=rh.source_record_id
        WHERE rh.run_id=?
        ORDER BY q.id, rh.seen_at, sr.id
        """,
        (run_id,),
    ).fetchall()
    per_job_seen: dict[tuple[str, str], int] = defaultdict(int)
    fetched = 0
    admitted = 0
    for row in rows:
        job_key = (str(row["query_source"]), str(row["query_id"]))
        limit = policy.retrieval_limit(
            source=job_key[0],
            query_id=job_key[1],
            requested_limit=None,
        )
        if per_job_seen[job_key] >= limit:
            continue
        per_job_seen[job_key] += 1
        fetched += 1
        metadata = json.loads(str(row["metadata_json"]) or "{}")
        record = SourceRecord(
            source=str(row["record_source"]),
            source_id=str(row["source_id"]),
            kind=str(row["kind"]),
            title=str(row["title"]),
            query_id=str(row["query_id"]),
            year=row["year"],
            canonical_url=row["canonical_url"],
            doi=row["doi"],
            arxiv_id=row["arxiv_id"],
            github_full_name=row["github_full_name"],
            metadata=metadata if isinstance(metadata, dict) else {},
        )
        base = AdmissionDecision(
            admitted=bool(row["admitted"]),
            code=str(row["admission_code"]),
            lane="historical_replay",
            reason="Historical objective-admission result.",
        )
        stable_identity_key = f"work:{int(row['work_id'])}"
        decision, reservation = gate.reserve(
            record,
            base,
            query_lane=str(row["lane"]),
            identity_key=stable_identity_key,
        )
        if decision.admitted:
            gate.commit(
                reservation,
                stable_identity_key=stable_identity_key,
            )
            admitted += 1
    return {
        "schema": "r3/weekly-intake-replay/v1",
        "reference_time": reference_time.isoformat(),
        "historical_run_id": run_id,
        "retrieved_after_provider_query_caps": fetched,
        "admitted_record_occurrences": admitted,
        "gate": gate.snapshot(),
        "interpretation": (
            "This is a deterministic replay over captured run hits, not a claim "
            "about uncaptured web records."
        ),
    }


def _review_markdown(gold_set: dict[str, Any]) -> str:
    lines = [
        "# R3 Gold Set 人工核验清单",
        "",
        "这份清单只展示冻结证据的索引。请在 JSON 中为每项填写 `human_label`；"
        "不要直接复制模型 tier 作为真值。",
        "",
        f"- 条目数：{len(gold_set['items'])}",
        f"- 状态：`{gold_set['review']['status']}`",
        f"- Run：`{gold_set['scope']['run_id']}`",
        f"- Issue：`{gold_set['scope']['issue_id']}`",
        "",
        "| # | ID | 捕获状态 | 题名 | 模型层级 | 人工标签 |",
        "|---:|---|---|---|---|---|",
    ]
    for index, item in enumerate(gold_set["items"], start=1):
        context = item["review_context"]
        citation = context.get("citation") or context
        title = str(citation.get("title") or "").replace("|", "\\|")
        tier = str(context.get("tier") or "")
        lines.append(
            f"| {index} | `{item['item_id']}` | {item['captured_as']} | "
            f"{title} | {tier} | 待核验 |"
        )
    lines.extend(
        [
            "",
            "允许标签：`" + "`, `".join(_LABELS) + "`。",
            "",
            "只有全部条目均由人工核验、至少存在一个 `known_important`，"
            "且离线回放达到阈值后，Profile v2 才可能进入激活审查。",
        ]
    )
    return "\n".join(lines) + "\n"


def build_intake_calibration(
    settings: Settings,
    *,
    run_id: str,
    output_dir: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    database_sha256 = _sha256_file(settings.database_path)
    with closing(_read_only_connection(settings.database_path)) as connection:
        run_row = connection.execute(
            "SELECT * FROM runs WHERE id=?",
            (run_id,),
        ).fetchone()
        if run_row is None:
            raise CalibrationError(f"run {run_id} does not exist")
        run = dict(run_row)
        _require_run_settings_identity(
            run,
            settings,
            context="calibration run",
        )
        if run["status"] not in {"completed", "completed_with_gaps"}:
            raise CalibrationError("calibration requires an eligible terminal run")
        issue_row = connection.execute(
            "SELECT issue_id FROM report_issues WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if issue_row is None:
            raise CalibrationError("calibration requires a frozen run publication")
        issue_id = str(issue_row["issue_id"])
        yields = _query_yields(connection, run_id=run_id, issue_id=issue_id)
        capacity = _duration_calibration(
            connection,
            run_id=run_id,
            maximum_runtime_seconds=int(settings.raw["run"]["max_runtime_seconds"]),
        )
        lanes = sorted({str(query["lane"]) for query in settings.raw["queries"]})
        selected_by_lane: dict[str, int] = defaultdict(int)
        for row in yields:
            selected_by_lane[str(row["lane"])] += int(row["publication_selected"])
        lane_caps = _allocate_lane_caps(
            int(capacity["derived_maximum_admitted_candidates"]),
            lanes,
            selected_by_lane,
        )
        per_query_cap = max(
            1,
            math.ceil(
                int(capacity["derived_maximum_admitted_candidates"])
                / max(1, len(settings.raw["queries"]))
            ),
        )
        source_names = {
            str(source)
            for query in settings.raw["queries"]
            for source in query["sources"]
        }
        if settings.raw.get("hosted_search", {}).get("enabled"):
            source_names.add("codex_web")
        weekly_policy = {
            "state": "proposed",
            "policy_version": "r3-weekly-intake-v1",
            "window_days": 14,
            "overlap_days": 3,
            "maximum_admitted_candidates": int(
                capacity["derived_maximum_admitted_candidates"]
            ),
            "source_query_caps": {
                source: per_query_cap for source in sorted(source_names)
            },
            "query_caps": {
                str(query["id"]): per_query_cap
                for query in settings.raw["queries"]
            },
            "lane_caps": lane_caps,
            "capacity_basis": {
                "source_run_id": run_id,
                **capacity,
            },
        }
        proposed = json.loads(canonical_json(settings.raw))
        proposed["profile_version"] = max(2, int(settings.profile_version) + 1)
        proposed["intake"] = {"weekly": weekly_policy}
        proposed["analysis"]["auto_publish_providers"] = ["codex_cli"]
        measured_maximum = int(capacity["derived_maximum_admitted_candidates"])
        proposed["run"]["weekly_display_max"] = min(
            int(proposed["run"]["weekly_display_max"]),
            measured_maximum,
        )
        proposed["run"]["weekly_display_min"] = 0
        validated = json.loads(canonical_json(proposed))
        validated["intake"]["weekly"]["state"] = "active"
        policy = WeeklyIntakePolicy.from_config(validated)
        if policy.maximum_admitted_candidates != int(
            capacity["derived_maximum_admitted_candidates"]
        ):
            raise CalibrationError("proposed profile capacity failed validation")
        reference = datetime.now(timezone.utc)
        replay = _weekly_replay(
            connection,
            run_id=run_id,
            policy_raw=validated,
            reference_time=reference,
        )
        gold = _gold_set_draft(
            connection,
            run=run,
            issue_id=issue_id,
            database_sha256=database_sha256,
        )
        candidate_ids = _candidate_work_ids(connection, run_id=run_id)
        gold_evaluation = evaluate_gold_set(
            gold,
            candidate_work_ids=candidate_ids,
            same_source=True,
        )

    diff = {
        "schema": "r3/profile-diff/v1",
        "from": {
            "profile_id": settings.profile_id,
            "profile_version": settings.profile_version,
            "config_hash": settings.config_hash,
        },
        "to": {
            "profile_id": proposed["profile_id"],
            "profile_version": proposed["profile_version"],
            "activation_state": "proposed",
        },
        "changes": [
            {
                "path": "/profile_version",
                "from": settings.profile_version,
                "to": proposed["profile_version"],
                "reason": "Explicit version boundary for intake behavior.",
            },
            {
                "path": "/intake/weekly",
                "from": None,
                "to": weekly_policy,
                "reason": (
                    "Provider/query/date/lane/capacity boundaries prevent "
                    "unbounded weekly full-read admission."
                ),
            },
            {
                "path": "/analysis/auto_publish_providers",
                "from": settings.raw["analysis"].get("auto_publish_providers"),
                "to": ["codex_cli"],
                "reason": (
                    "Llama remains usable manually but cannot enter automatic "
                    "publication before a separate human-reviewed calibration."
                ),
            },
            {
                "path": "/run/weekly_display_min",
                "from": settings.raw["run"]["weekly_display_min"],
                "to": proposed["run"]["weekly_display_min"],
                "reason": (
                    "Remove a hard item quota: a valid weekly issue may contain "
                    "zero recommendations and must never be padded."
                ),
            },
            {
                "path": "/run/weekly_display_max",
                "from": settings.raw["run"]["weekly_display_max"],
                "to": proposed["run"]["weekly_display_max"],
                "reason": "Keep publication display inside measured six-hour capacity.",
            },
        ],
        "activation": {
            "requires_explicit_user_confirmation": True,
            "blocked_until_gold_set_verified": True,
            "current_gold_evaluation_status": gold_evaluation["status"],
        },
    }
    artifacts = {
        "query-yield.json": {
            "schema": "r3/query-yield/v1",
            "run_id": run_id,
            "issue_id": issue_id,
            "rows": yields,
        },
        "capacity-calibration.json": {
            "schema": "r3/full-read-capacity/v1",
            "run_id": run_id,
            **capacity,
        },
        "weekly-intake-replay.json": replay,
        "gold-set-draft.json": gold,
        "gold-set-evaluation.json": gold_evaluation,
        "profile-v2.proposed.json": proposed,
        "profile-v2.diff.json": diff,
    }
    for name, payload in artifacts.items():
        atomic_write_text(
            output_dir / name,
            json_dumps(payload, pretty=True) + "\n",
        )
    atomic_write_text(output_dir / "gold-set-review.md", _review_markdown(gold))
    artifact_hashes = {
        name: _sha256_file(output_dir / name)
        for name in sorted([*artifacts, "gold-set-review.md"])
    }
    receipt = {
        "schema": CALIBRATION_SCHEMA,
        "generated_at": utc_now(),
        "state": "awaiting_human_gold_review_and_profile_confirmation",
        "run_id": run_id,
        "issue_id": issue_id,
        "database": {
            "path": str(settings.database_path),
            "sha256": database_sha256,
        },
        "measured_capacity": capacity,
        "weekly_replay": replay,
        "gold_set": {
            "item_count": len(gold["items"]),
            "evaluation": gold_evaluation,
        },
        "profile_v2": {
            "state": "proposed",
            "automatic_publication_providers": ["codex_cli"],
            "explicit_confirmation_required": True,
        },
        "artifact_hashes": artifact_hashes,
    }
    atomic_write_text(
        output_dir / "phase-b-preactivation-receipt.json",
        json_dumps(receipt, pretty=True) + "\n",
    )
    return receipt


def evaluate_gold_set_file(
    settings: Settings,
    *,
    run_id: str,
    gold_set_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    gold_set = json.loads(gold_set_path.read_text(encoding="utf-8"))
    validated = (
        _validate_gold_set_v2(gold_set)
        if gold_set.get("schema") == GOLD_SET_V2_SCHEMA
        else _validate_gold_set(gold_set)
    )
    source_run_id = str(validated["scope"]["run_id"])
    if run_id == source_run_id:
        raise CalibrationError(
            "candidate run must differ from gold.scope.run_id; a run cannot "
            "establish its own recall"
        )
    with closing(_read_only_connection(settings.database_path)) as connection:
        source_run = connection.execute(
            """
            SELECT id, profile_id, profile_version, config_hash,
                   retrieval_hash, analysis_policy_hash
            FROM runs WHERE id=?
            """,
            (source_run_id,),
        ).fetchone()
        if source_run is None:
            raise CalibrationError("Gold Set source run is not present in the database")
        gold_scope = validated["scope"]
        source_identity = {
            "profile_id": str(source_run["profile_id"]),
            "profile_version": int(source_run["profile_version"]),
            "config_hash": str(source_run["config_hash"]),
            "retrieval_hash": str(source_run["retrieval_hash"]),
            "analysis_policy_hash": str(source_run["analysis_policy_hash"]),
        }
        expected_source_identity = {
            "profile_id": str(gold_scope["profile_id"]),
            "profile_version": int(gold_scope["profile_version"]),
            "config_hash": str(gold_scope["config_hash"]),
            "retrieval_hash": str(gold_scope["retrieval_hash"]),
            "analysis_policy_hash": str(gold_scope["analysis_policy_hash"]),
        }
        mismatches = [
            field
            for field in expected_source_identity
            if source_identity[field] != expected_source_identity[field]
        ]
        if mismatches:
            raise CalibrationError(
                "Gold Set scope does not match its source run: "
                + ", ".join(mismatches)
            )
        candidate_run = connection.execute(
            """
            SELECT id, profile_id, profile_version, config_hash,
                   retrieval_hash, analysis_policy_hash
            FROM runs WHERE id=?
            """,
            (run_id,),
        ).fetchone()
        if candidate_run is None:
            raise CalibrationError("candidate run is not present in the database")
        _require_run_settings_identity(
            candidate_run,
            settings,
            context="candidate run",
        )
        candidate_ids = _candidate_work_ids(connection, run_id=run_id)
        same_source = str(candidate_run["retrieval_hash"]) == str(
            source_run["retrieval_hash"]
        )
    result = evaluate_gold_set(
        gold_set,
        candidate_work_ids=candidate_ids,
        same_source=same_source,
    )
    result["evaluated_at"] = utc_now()
    result["gold_set_sha256"] = _sha256_file(gold_set_path)
    result["gold_source_run_id"] = source_run_id
    result["gold_source_run_identity"] = source_identity
    result["candidate_run_id"] = run_id
    candidate_identity = {
        "profile_id": str(candidate_run["profile_id"]),
        "profile_version": int(candidate_run["profile_version"]),
        "config_hash": str(candidate_run["config_hash"]),
        "retrieval_hash": str(candidate_run["retrieval_hash"]),
        "analysis_policy_hash": str(candidate_run["analysis_policy_hash"]),
    }
    result["candidate_run_identity"] = candidate_identity
    result["candidate_settings_hashes"] = {
        "config_hash": candidate_identity["config_hash"],
        "retrieval_hash": candidate_identity["retrieval_hash"],
        "analysis_policy_hash": candidate_identity["analysis_policy_hash"],
    }
    atomic_write_text(output_path, json_dumps(result, pretty=True) + "\n")
    return result
