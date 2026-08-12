from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit


KNOWN_ANSWER_SET_SCHEMA = "r3/external-known-answer-set/v1"
KNOWN_ANSWER_RECEIPT_SCHEMA = "r3/known-answer-evaluation-receipt/v1"
SOURCE_CATEGORIES = {
    "user_prior_list",
    "advisor_or_independent_researcher",
    "independent_database",
    "citation_chasing",
}
INDEPENDENCE_BASES = {
    "documented_before_r3_run",
    "nominated_by_external_researcher",
    "independent_query_or_export",
    "citation_chasing_from_external_seed",
}
IDENTITY_KINDS = {"paper", "repository", "dataset", "other"}
IDENTITY_TYPES = {"doi", "arxiv", "github", "openalex", "semantic_scholar", "url", "other"}
SPLITS = {"development", "evaluation"}
NOVELTY_STATES = {"novel", "known", "unknown"}


class KnownAnswerError(ValueError):
    """Raised when an external known-answer contract is unsafe or ambiguous."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    payload = value if isinstance(value, str) else _canonical_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _require_keys(value: dict[str, Any], expected: set[str], *, field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise KnownAnswerError(f"{field} keys are invalid; missing={missing}, extra={extra}")


def _require_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KnownAnswerError(f"{field} must be a non-empty string")
    return value.strip()


def _require_string_list(value: Any, *, field: str) -> list[str]:
    if not isinstance(value, list):
        raise KnownAnswerError(f"{field} must be a list")
    result = [_require_string(item, field=f"{field}[]") for item in value]
    if len(result) != len(set(result)):
        raise KnownAnswerError(f"{field} must not contain duplicates")
    return result


def _require_timestamp(value: Any, *, field: str) -> str:
    timestamp = _require_string(value, field=field)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise KnownAnswerError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise KnownAnswerError(f"{field} must include a timezone")
    return timestamp


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _normalise_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        raise KnownAnswerError("url identity must be an absolute HTTP(S) URL")
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip("/"), parts.query, "")
    )


def _normalise_identity(identity: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(identity, dict):
        raise KnownAnswerError(f"{field} must be an object")
    _require_keys(
        identity,
        {"status", "kind", "canonical_id_type", "canonical_id", "version", "version_required"},
        field=field,
    )
    status = identity["status"]
    if status not in {"verified", "missing"}:
        raise KnownAnswerError(f"{field}.status is invalid")
    kind = identity["kind"]
    if kind not in IDENTITY_KINDS:
        raise KnownAnswerError(f"{field}.kind is invalid")
    version_required = identity["version_required"]
    if not isinstance(version_required, bool):
        raise KnownAnswerError(f"{field}.version_required must be boolean")
    if status == "missing":
        if any(identity[key] is not None for key in ("canonical_id_type", "canonical_id", "version")):
            raise KnownAnswerError(f"{field} missing identity must not contain partial identifiers")
        if version_required:
            raise KnownAnswerError(f"{field} missing identity cannot require a version")
        return copy.deepcopy(identity)

    identity_type = identity["canonical_id_type"]
    if identity_type not in IDENTITY_TYPES:
        raise KnownAnswerError(f"{field}.canonical_id_type is invalid")
    canonical_id = _require_string(identity["canonical_id"], field=f"{field}.canonical_id")
    version = identity["version"]
    if version is not None:
        version = _require_string(version, field=f"{field}.version")

    if identity_type == "doi":
        canonical_id = re.sub(r"^(?:https?://(?:dx\.)?doi\.org/|doi:\s*)", "", canonical_id, flags=re.I).lower()
    elif identity_type == "arxiv":
        canonical_id = re.sub(r"^(?:https?://arxiv\.org/(?:abs|pdf)/|arxiv:\s*)", "", canonical_id, flags=re.I)
        canonical_id = canonical_id.removesuffix(".pdf")
        suffix = re.search(r"(v\d+)$", canonical_id, flags=re.I)
        if suffix:
            embedded_version = suffix.group(1).lower()
            canonical_id = canonical_id[: -len(suffix.group(1))]
            if version is not None and version.lower() != embedded_version:
                raise KnownAnswerError(f"{field} has conflicting embedded and explicit arXiv versions")
            version = embedded_version
        canonical_id = canonical_id.lower()
    elif identity_type == "github":
        canonical_id = re.sub(r"^https?://github\.com/", "", canonical_id, flags=re.I)
        canonical_id = canonical_id.removesuffix(".git").strip("/").lower()
        if canonical_id.count("/") != 1:
            raise KnownAnswerError(f"{field}.canonical_id must be owner/repository")
        if version is not None:
            version = version.lower()
    elif identity_type == "url":
        canonical_id = _normalise_url(canonical_id)
    else:
        canonical_id = canonical_id.casefold()
    if version_required and version is None:
        raise KnownAnswerError(f"{field}.version is required")
    return {
        "status": "verified",
        "kind": kind,
        "canonical_id_type": identity_type,
        "canonical_id": canonical_id,
        "version": version,
        "version_required": version_required,
    }


def _identity_base(identity: dict[str, Any]) -> tuple[str, str, str] | None:
    if identity["status"] != "verified":
        return None
    return (identity["kind"], identity["canonical_id_type"], identity["canonical_id"])


def _identity_exact(identity: dict[str, Any]) -> tuple[str, str, str, str | None] | None:
    base = _identity_base(identity)
    return None if base is None else (*base, identity["version"])


def _assignment_digest(set_id: str, items: Iterable[dict[str, Any]]) -> str:
    assignments = [
        {"item_id": item["item_id"], "split": item["split"]}
        for item in sorted(items, key=lambda row: row["item_id"])
    ]
    return _sha256({"set_id": set_id, "assignments": assignments})


def _set_digest(document: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(document)
    unsigned["freeze"]["set_sha256"] = None
    return _sha256(unsigned)


def validate_external_known_answer_set(document: dict[str, Any], *, require_frozen: bool = False) -> dict[str, Any]:
    """Validate and normalize an external known-answer set without altering it."""

    if not isinstance(document, dict):
        raise KnownAnswerError("known-answer set must be an object")
    result = copy.deepcopy(document)
    _require_keys(
        result,
        {"schema", "set_id", "title", "created_at", "collection_provenance", "split_policy", "freeze", "items"},
        field="known_answer_set",
    )
    if result["schema"] != KNOWN_ANSWER_SET_SCHEMA:
        raise KnownAnswerError(f"schema must be {KNOWN_ANSWER_SET_SCHEMA}")
    set_id = _require_string(result["set_id"], field="set_id")
    _require_string(result["title"], field="title")
    _require_timestamp(result["created_at"], field="created_at")

    provenance = result["collection_provenance"]
    if not isinstance(provenance, dict):
        raise KnownAnswerError("collection_provenance must be an object")
    _require_keys(
        provenance,
        {"created_by", "source_artifact_ids", "r3_candidate_artifact_ids", "independence_note"},
        field="collection_provenance",
    )
    _require_string(provenance["created_by"], field="collection_provenance.created_by")
    source_artifacts = _require_string_list(
        provenance["source_artifact_ids"], field="collection_provenance.source_artifact_ids"
    )
    if not source_artifacts:
        raise KnownAnswerError("collection_provenance.source_artifact_ids must not be empty")
    r3_artifacts = _require_string_list(
        provenance["r3_candidate_artifact_ids"], field="collection_provenance.r3_candidate_artifact_ids"
    )
    overlap = sorted(set(source_artifacts) & set(r3_artifacts))
    if overlap:
        raise KnownAnswerError(f"known answers are self-sourced from R3 candidate artifacts: {overlap}")
    _require_string(provenance["independence_note"], field="collection_provenance.independence_note")

    items = result["items"]
    if not isinstance(items, list) or not 20 <= len(items) <= 35:
        raise KnownAnswerError("external known-answer set must contain 20-35 items")

    split_policy = result["split_policy"]
    if not isinstance(split_policy, dict):
        raise KnownAnswerError("split_policy must be an object")
    _require_keys(
        split_policy,
        {"assignment_basis", "development_use", "evaluation_use", "assignment_sha256"},
        field="split_policy",
    )
    _require_string(split_policy["assignment_basis"], field="split_policy.assignment_basis")
    _require_string(split_policy["development_use"], field="split_policy.development_use")
    _require_string(split_policy["evaluation_use"], field="split_policy.evaluation_use")

    freeze = result["freeze"]
    if not isinstance(freeze, dict):
        raise KnownAnswerError("freeze must be an object")
    _require_keys(freeze, {"status", "frozen_at", "frozen_by", "set_sha256"}, field="freeze")
    if freeze["status"] not in {"draft", "frozen"}:
        raise KnownAnswerError("freeze.status is invalid")
    if freeze["status"] == "draft":
        if any(freeze[key] is not None for key in ("frozen_at", "frozen_by", "set_sha256")):
            raise KnownAnswerError("draft freeze metadata must be null")
        if split_policy["assignment_sha256"] is not None:
            raise KnownAnswerError("draft split assignment hash must be null")
    else:
        _require_timestamp(freeze["frozen_at"], field="freeze.frozen_at")
        _require_string(freeze["frozen_by"], field="freeze.frozen_by")
        if not isinstance(freeze["set_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", freeze["set_sha256"]):
            raise KnownAnswerError("freeze.set_sha256 must be a lowercase SHA-256")
        expected_assignment = _assignment_digest(set_id, result["items"])
        if split_policy["assignment_sha256"] != expected_assignment:
            raise KnownAnswerError("frozen development/evaluation assignment digest does not match")
        if freeze["set_sha256"] != _set_digest(result):
            raise KnownAnswerError("frozen known-answer set digest does not match")
    if require_frozen and freeze["status"] != "frozen":
        raise KnownAnswerError("evaluation requires a frozen known-answer set")

    item_ids: set[str] = set()
    exact_identities: set[tuple[str, str, str, str | None]] = set()
    split_counts = {split: 0 for split in SPLITS}
    for index, item in enumerate(items):
        field = f"items[{index}]"
        if not isinstance(item, dict):
            raise KnownAnswerError(f"{field} must be an object")
        _require_keys(
            item,
            {"item_id", "title", "abstract_or_description", "split", "source", "identity", "judgment", "duplicate_cluster_id"},
            field=field,
        )
        item_id = _require_string(item["item_id"], field=f"{field}.item_id")
        if item_id in item_ids:
            raise KnownAnswerError(f"duplicate item_id: {item_id}")
        item_ids.add(item_id)
        _require_string(item["title"], field=f"{field}.title")
        _require_string(item["abstract_or_description"], field=f"{field}.abstract_or_description")
        if item["split"] not in SPLITS:
            raise KnownAnswerError(f"{field}.split is invalid")
        split_counts[item["split"]] += 1

        source = item["source"]
        if not isinstance(source, dict):
            raise KnownAnswerError(f"{field}.source must be an object")
        _require_keys(
            source,
            {"category", "artifact_id", "reference_url", "collected_at", "independence_basis"},
            field=f"{field}.source",
        )
        if source["category"] not in SOURCE_CATEGORIES:
            raise KnownAnswerError(f"{field}.source.category is invalid")
        artifact_id = _require_string(source["artifact_id"], field=f"{field}.source.artifact_id")
        if artifact_id not in source_artifacts:
            raise KnownAnswerError(f"{field}.source.artifact_id is not declared in provenance")
        if artifact_id in r3_artifacts:
            raise KnownAnswerError(f"{field} is sourced from an R3 candidate artifact")
        _normalise_url(_require_string(source["reference_url"], field=f"{field}.source.reference_url"))
        _require_timestamp(source["collected_at"], field=f"{field}.source.collected_at")
        if source["independence_basis"] not in INDEPENDENCE_BASES:
            raise KnownAnswerError(f"{field}.source.independence_basis is invalid")

        identity = _normalise_identity(item["identity"], field=f"{field}.identity")
        item["identity"] = identity
        exact_identity = _identity_exact(identity)
        if exact_identity is not None:
            if exact_identity in exact_identities:
                raise KnownAnswerError(f"duplicate exact identity in known answers: {exact_identity}")
            exact_identities.add(exact_identity)

        judgment = item["judgment"]
        if not isinstance(judgment, dict):
            raise KnownAnswerError(f"{field}.judgment must be an object")
        _require_keys(
            judgment,
            {"status", "relevance_grade", "must_read", "judged_by", "judged_at", "notes"},
            field=f"{field}.judgment",
        )
        if judgment["status"] not in {"verified", "unknown"}:
            raise KnownAnswerError(f"{field}.judgment.status is invalid")
        if judgment["status"] == "unknown":
            if any(judgment[key] is not None for key in ("relevance_grade", "must_read", "judged_by", "judged_at")):
                raise KnownAnswerError(f"{field} unknown judgment must not contain an answer")
        else:
            grade = judgment["relevance_grade"]
            if not isinstance(grade, int) or isinstance(grade, bool) or grade not in {0, 1, 2, 3}:
                raise KnownAnswerError(f"{field}.judgment.relevance_grade is invalid")
            if not isinstance(judgment["must_read"], bool) or judgment["must_read"] != (grade == 3):
                raise KnownAnswerError(f"{field}.judgment.must_read must equal relevance_grade == 3")
            _require_string(judgment["judged_by"], field=f"{field}.judgment.judged_by")
            _require_timestamp(judgment["judged_at"], field=f"{field}.judgment.judged_at")
        if judgment["notes"] is not None and not isinstance(judgment["notes"], str):
            raise KnownAnswerError(f"{field}.judgment.notes must be string or null")
        if item["duplicate_cluster_id"] is not None:
            _require_string(item["duplicate_cluster_id"], field=f"{field}.duplicate_cluster_id")
    if not all(split_counts.values()):
        raise KnownAnswerError("both development and evaluation splits must contain items")
    return result


def freeze_external_known_answer_set(
    document: dict[str, Any], *, frozen_at: str, frozen_by: str
) -> dict[str, Any]:
    """Freeze split assignments and content; the returned digest detects later edits."""

    validated = validate_external_known_answer_set(document)
    if validated["freeze"]["status"] != "draft":
        raise KnownAnswerError("known-answer set is already frozen")
    validated["split_policy"]["assignment_sha256"] = _assignment_digest(
        validated["set_id"], validated["items"]
    )
    validated["freeze"] = {
        "status": "frozen",
        "frozen_at": _require_timestamp(frozen_at, field="frozen_at"),
        "frozen_by": _require_string(frozen_by, field="frozen_by"),
        "set_sha256": None,
    }
    validated["freeze"]["set_sha256"] = _set_digest(validated)
    return validate_external_known_answer_set(validated, require_frozen=True)


def _prepare_candidates(candidates: Any, *, field: str) -> list[dict[str, Any]]:
    if not isinstance(candidates, list):
        raise KnownAnswerError(f"{field} must be a list")
    result: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    ranks: set[int] = set()
    for index, candidate in enumerate(candidates):
        candidate = copy.deepcopy(candidate)
        item_field = f"{field}[{index}]"
        if not isinstance(candidate, dict):
            raise KnownAnswerError(f"{item_field} must be an object")
        _require_keys(
            candidate,
            {"candidate_id", "rank", "title", "identity", "duplicate_cluster_id", "novelty_status", "diversity_group", "verification_minutes"},
            field=item_field,
        )
        candidate_id = _require_string(candidate["candidate_id"], field=f"{item_field}.candidate_id")
        if candidate_id in candidate_ids:
            raise KnownAnswerError(f"duplicate candidate_id: {candidate_id}")
        candidate_ids.add(candidate_id)
        rank = candidate["rank"]
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1 or rank in ranks:
            raise KnownAnswerError(f"{item_field}.rank must be a unique positive integer")
        ranks.add(rank)
        _require_string(candidate["title"], field=f"{item_field}.title")
        candidate["identity"] = _normalise_identity(candidate["identity"], field=f"{item_field}.identity")
        for optional in ("duplicate_cluster_id", "diversity_group"):
            if candidate[optional] is not None:
                _require_string(candidate[optional], field=f"{item_field}.{optional}")
        if candidate["novelty_status"] not in NOVELTY_STATES:
            raise KnownAnswerError(f"{item_field}.novelty_status is invalid")
        minutes = candidate["verification_minutes"]
        if minutes is not None and (
            not isinstance(minutes, (int, float)) or isinstance(minutes, bool) or not math.isfinite(minutes) or minutes < 0
        ):
            raise KnownAnswerError(f"{item_field}.verification_minutes must be non-negative or null")
        result.append(candidate)
    result.sort(key=lambda row: row["rank"])
    if [row["rank"] for row in result] != list(range(1, len(result) + 1)):
        raise KnownAnswerError(f"{field} ranks must be contiguous from 1")
    return result


def _metric(value: float | None, *, numerator: int | float, denominator: int, unknown: int = 0) -> dict[str, Any]:
    return {
        "status": "complete" if value is not None else "unknown",
        "value": None if value is None else round(float(value), 6),
        "numerator": numerator,
        "denominator": denominator,
        "unknown_count": unknown,
    }


def _score_ranking(truth_items: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> dict[str, Any]:
    truth_by_base: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in truth_items:
        base = _identity_base(item["identity"])
        if base is not None:
            truth_by_base.setdefault(base, []).append(item)

    matches: dict[str, dict[str, Any]] = {}
    candidate_truth: dict[str, dict[str, Any]] = {}
    for item in truth_items:
        identity = item["identity"]
        base = _identity_base(identity)
        if base is None:
            matches[item["item_id"]] = {"status": "identity_missing", "candidate_id": None, "rank": None}
            continue
        same_base = [candidate for candidate in candidates if _identity_base(candidate["identity"]) == base]
        if identity["version_required"]:
            exact = [candidate for candidate in same_base if candidate["identity"]["version"] == identity["version"]]
            if exact:
                candidate = exact[0]
                status = "exact"
            elif any(candidate["identity"]["version"] is None for candidate in same_base):
                candidate = None
                status = "version_unknown"
            elif same_base:
                candidate = None
                status = "version_conflict"
            else:
                candidate = None
                status = "unmatched"
        elif same_base:
            candidate = same_base[0]
            status = "exact"
        else:
            candidate = None
            status = "unmatched"
        matches[item["item_id"]] = {
            "status": status,
            "candidate_id": candidate["candidate_id"] if candidate else None,
            "rank": candidate["rank"] if candidate else None,
        }
        if candidate is not None:
            existing = candidate_truth.get(candidate["candidate_id"])
            if existing is None or item["judgment"]["status"] == "verified":
                candidate_truth[candidate["candidate_id"]] = item

    known_positive = [
        item for item in truth_items
        if item["judgment"]["status"] == "verified" and item["judgment"]["relevance_grade"] > 0
    ]
    recalled_positive = [item for item in known_positive if matches[item["item_id"]]["status"] == "exact"]
    recall = _metric(
        len(recalled_positive) / len(known_positive) if known_positive else None,
        numerator=len(recalled_positive),
        denominator=len(known_positive),
        unknown=sum(1 for item in truth_items if item["judgment"]["status"] == "unknown"),
    )
    must_read = [
        item for item in truth_items
        if item["judgment"]["status"] == "verified" and item["judgment"]["must_read"]
    ]
    must_read_misses = [
        {
            "item_id": item["item_id"],
            "title": item["title"],
            "reason": matches[item["item_id"]]["status"],
        }
        for item in must_read
        if matches[item["item_id"]]["status"] != "exact"
    ]

    metrics: dict[str, Any] = {
        "candidate_recall": recall,
        "must_read_miss": {
            "status": "complete",
            "count": len(must_read_misses),
            "denominator": len(must_read),
            "items": must_read_misses,
        },
    }
    known_grades = sorted(
        [item["judgment"]["relevance_grade"] for item in truth_items if item["judgment"]["status"] == "verified"],
        reverse=True,
    )
    for k in (3, 5, 10):
        positions = candidates[:k]
        judged: list[int] = []
        for candidate in positions:
            truth = candidate_truth.get(candidate["candidate_id"])
            if truth is not None and truth["judgment"]["status"] == "verified":
                judged.append(truth["judgment"]["relevance_grade"])
        denominator = len(positions)
        unknown = denominator - len(judged)
        relevant = sum(grade > 0 for grade in judged)
        precision_value = relevant / denominator if denominator and unknown == 0 else None
        metrics[f"p_at_{k}"] = _metric(
            precision_value, numerator=relevant, denominator=denominator, unknown=unknown
        )
        if denominator and unknown == 0:
            dcg = sum((2**grade - 1) / math.log2(rank + 2) for rank, grade in enumerate(judged))
            ideal = known_grades[:denominator]
            idcg = sum((2**grade - 1) / math.log2(rank + 2) for rank, grade in enumerate(ideal))
            ndcg_value = dcg / idcg if idcg else None
        else:
            dcg = 0.0
            ndcg_value = None
        metrics[f"ndcg_at_{k}"] = _metric(
            ndcg_value, numerator=round(dcg, 6), denominator=denominator, unknown=unknown
        )

    exact_groups: dict[tuple[str, str, str, str | None], list[str]] = {}
    near_groups: dict[str, list[str]] = {}
    for candidate in candidates:
        exact = _identity_exact(candidate["identity"])
        if exact is not None:
            exact_groups.setdefault(exact, []).append(candidate["candidate_id"])
        cluster = candidate["duplicate_cluster_id"]
        if cluster is not None:
            near_groups.setdefault(cluster, []).append(candidate["candidate_id"])
    exact_duplicate_ids = [group for group in exact_groups.values() if len(group) > 1]
    near_duplicate_ids = [group for group in near_groups.values() if len(group) > 1]
    candidate_count = len(candidates)
    exact_excess = sum(len(group) - 1 for group in exact_duplicate_ids)
    near_excess = sum(len(group) - 1 for group in near_duplicate_ids)
    metrics["exact_duplicate_rate"] = _metric(
        exact_excess / candidate_count if candidate_count else None,
        numerator=exact_excess,
        denominator=candidate_count,
    ) | {"clusters": exact_duplicate_ids}
    metrics["near_duplicate_rate"] = _metric(
        near_excess / candidate_count if candidate_count else None,
        numerator=near_excess,
        denominator=candidate_count,
    ) | {"clusters": near_duplicate_ids, "basis": "explicit_duplicate_cluster_id_only"}

    top = candidates[:10]
    novelty_known = [candidate for candidate in top if candidate["novelty_status"] != "unknown"]
    novel_count = sum(candidate["novelty_status"] == "novel" for candidate in novelty_known)
    novelty_unknown = len(top) - len(novelty_known)
    metrics["novelty_at_10"] = _metric(
        novel_count / len(top) if top and novelty_unknown == 0 else None,
        numerator=novel_count,
        denominator=len(top),
        unknown=novelty_unknown,
    )
    diversity_known = [candidate["diversity_group"] for candidate in top if candidate["diversity_group"] is not None]
    diversity_unknown = len(top) - len(diversity_known)
    metrics["diversity_at_10"] = _metric(
        len(set(diversity_known)) / len(top) if top and diversity_unknown == 0 else None,
        numerator=len(set(diversity_known)),
        denominator=len(top),
        unknown=diversity_unknown,
    ) | {"basis": "explicit_diversity_group_ratio"}
    minutes = [candidate["verification_minutes"] for candidate in candidates if candidate["verification_minutes"] is not None]
    metrics["verification_minutes"] = {
        "status": "complete" if len(minutes) == candidate_count and candidate_count else "unknown",
        "value": round(sum(minutes), 3) if len(minutes) == candidate_count and candidate_count else None,
        "observed_sum": round(sum(minutes), 3),
        "denominator": candidate_count,
        "known_count": len(minutes),
        "unknown_count": candidate_count - len(minutes),
    }
    return {
        "metrics": metrics,
        "matches": [
            {"item_id": item["item_id"], **matches[item["item_id"]]}
            for item in truth_items
        ],
    }


def evaluate_external_known_answers(
    known_answer_set: dict[str, Any],
    *,
    split: str,
    candidates: list[dict[str, Any]],
    evaluation_context: dict[str, Any],
    evaluator_identity: str,
    evaluated_at: str,
    baselines: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Evaluate a frozen external set conservatively using exact, version-aware identity."""

    validated = validate_external_known_answer_set(known_answer_set, require_frozen=True)
    if split not in SPLITS:
        raise KnownAnswerError("split is invalid")
    if not isinstance(evaluation_context, dict):
        raise KnownAnswerError("evaluation_context must be an object")
    _require_keys(
        evaluation_context,
        {
            "candidate_run_id", "candidate_pool_id", "candidate_pool_frozen_at",
            "candidate_source_artifact_ids", "origin_known_answer_set_ids",
            "known_answer_splits_accessed_before_run", "ranking_method",
        },
        field="evaluation_context",
    )
    _require_string(evaluation_context["candidate_run_id"], field="evaluation_context.candidate_run_id")
    _require_string(evaluation_context["candidate_pool_id"], field="evaluation_context.candidate_pool_id")
    candidate_pool_frozen_at = _require_timestamp(
        evaluation_context["candidate_pool_frozen_at"],
        field="evaluation_context.candidate_pool_frozen_at",
    )
    candidate_artifacts = _require_string_list(
        evaluation_context["candidate_source_artifact_ids"],
        field="evaluation_context.candidate_source_artifact_ids",
    )
    origin_sets = _require_string_list(
        evaluation_context["origin_known_answer_set_ids"],
        field="evaluation_context.origin_known_answer_set_ids",
    )
    accessed_splits = _require_string_list(
        evaluation_context["known_answer_splits_accessed_before_run"],
        field="evaluation_context.known_answer_splits_accessed_before_run",
    )
    if any(value not in SPLITS for value in accessed_splits):
        raise KnownAnswerError("known_answer_splits_accessed_before_run contains an invalid split")
    _require_string(evaluation_context["ranking_method"], field="evaluation_context.ranking_method")
    if validated["set_id"] in origin_sets:
        raise KnownAnswerError("candidate pool was derived from this known-answer set")
    if split == "evaluation" and "evaluation" in accessed_splits:
        raise KnownAnswerError("evaluation split was accessed before the candidate run")
    known_artifacts = set(validated["collection_provenance"]["source_artifact_ids"])
    if evaluation_context["candidate_pool_id"] in known_artifacts:
        raise KnownAnswerError("candidate pool is itself a known-answer source artifact")
    artifact_overlap = sorted(known_artifacts & set(candidate_artifacts))
    if artifact_overlap:
        raise KnownAnswerError(f"candidate pool and known answers share source artifacts: {artifact_overlap}")
    if _parse_timestamp(validated["freeze"]["frozen_at"]) > _parse_timestamp(candidate_pool_frozen_at):
        raise KnownAnswerError("known-answer set was frozen after the candidate pool")

    prepared = _prepare_candidates(candidates, field="candidates")
    truth_items = [item for item in validated["items"] if item["split"] == split]
    scored = _score_ranking(truth_items, prepared)
    baseline_results: dict[str, Any] = {}
    for name, baseline_candidates in sorted((baselines or {}).items()):
        method = _require_string(name, field="baseline name")
        baseline_results[method] = _score_ranking(
            truth_items, _prepare_candidates(baseline_candidates, field=f"baselines.{method}")
        )["metrics"]

    comparisons: dict[str, Any] = {}
    for name, baseline_metrics in baseline_results.items():
        comparisons[name] = {}
        for metric_name in ("candidate_recall", "p_at_3", "p_at_5", "p_at_10", "ndcg_at_5", "ndcg_at_10"):
            primary = scored["metrics"][metric_name]["value"]
            baseline = baseline_metrics[metric_name]["value"]
            comparisons[name][metric_name] = {
                "status": "complete" if primary is not None and baseline is not None else "unknown",
                "delta": round(primary - baseline, 6) if primary is not None and baseline is not None else None,
            }

    receipt = {
        "schema": KNOWN_ANSWER_RECEIPT_SCHEMA,
        "known_answer_set": {
            "set_id": validated["set_id"],
            "set_sha256": validated["freeze"]["set_sha256"],
            "split": split,
            "split_assignment_sha256": validated["split_policy"]["assignment_sha256"],
            "item_count": len(truth_items),
        },
        "candidate_run": copy.deepcopy(evaluation_context),
        "evaluation": {
            "evaluator_identity": _require_string(evaluator_identity, field="evaluator_identity"),
            "evaluated_at": _require_timestamp(evaluated_at, field="evaluated_at"),
            "identity_matching": "exact_canonical_identity_and_required_version",
            "partial_judgment_policy": "metric_unknown_when_returned_positions_are_unjudged",
            "market_or_recommendation_quality_claim": False,
        },
        "metrics": scored["metrics"],
        "matches": scored["matches"],
        "baselines": baseline_results,
        "comparisons": comparisons,
        "warnings": [
            "Offline known-answer evidence does not establish market demand or end-to-end recommendation quality.",
            "Near-duplicates use explicit cluster identifiers only; titles are never fuzzy-matched.",
        ],
        "receipt_sha256": None,
    }
    receipt["receipt_sha256"] = _sha256({**receipt, "receipt_sha256": None})
    return receipt


def validate_known_answer_evaluation_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """Validate the immutable binding fields of an offline evaluation receipt."""

    if not isinstance(receipt, dict):
        raise KnownAnswerError("evaluation receipt must be an object")
    result = copy.deepcopy(receipt)
    _require_keys(
        result,
        {
            "schema", "known_answer_set", "candidate_run", "evaluation", "metrics",
            "matches", "baselines", "comparisons", "warnings", "receipt_sha256",
        },
        field="evaluation_receipt",
    )
    if result["schema"] != KNOWN_ANSWER_RECEIPT_SCHEMA:
        raise KnownAnswerError(f"receipt schema must be {KNOWN_ANSWER_RECEIPT_SCHEMA}")
    known_set = result["known_answer_set"]
    if not isinstance(known_set, dict):
        raise KnownAnswerError("known_answer_set receipt binding must be an object")
    _require_keys(
        known_set,
        {"set_id", "set_sha256", "split", "split_assignment_sha256", "item_count"},
        field="known_answer_set",
    )
    _require_string(known_set["set_id"], field="known_answer_set.set_id")
    for field_name in ("set_sha256", "split_assignment_sha256"):
        value = known_set[field_name]
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise KnownAnswerError(f"known_answer_set.{field_name} must be a lowercase SHA-256")
    if known_set["split"] not in SPLITS:
        raise KnownAnswerError("known_answer_set.split is invalid")
    if not isinstance(known_set["item_count"], int) or isinstance(known_set["item_count"], bool) or known_set["item_count"] < 1:
        raise KnownAnswerError("known_answer_set.item_count must be positive")
    evaluation = result["evaluation"]
    if not isinstance(evaluation, dict):
        raise KnownAnswerError("evaluation must be an object")
    _require_keys(
        evaluation,
        {
            "evaluator_identity", "evaluated_at", "identity_matching",
            "partial_judgment_policy", "market_or_recommendation_quality_claim",
        },
        field="evaluation",
    )
    _require_string(evaluation["evaluator_identity"], field="evaluation.evaluator_identity")
    _require_timestamp(evaluation["evaluated_at"], field="evaluation.evaluated_at")
    if evaluation["identity_matching"] != "exact_canonical_identity_and_required_version":
        raise KnownAnswerError("evaluation.identity_matching is invalid")
    if evaluation["partial_judgment_policy"] != "metric_unknown_when_returned_positions_are_unjudged":
        raise KnownAnswerError("evaluation.partial_judgment_policy is invalid")
    if evaluation["market_or_recommendation_quality_claim"] is not False:
        raise KnownAnswerError("offline receipt must not claim market or recommendation quality")
    if not isinstance(result["metrics"], dict) or not isinstance(result["matches"], list):
        raise KnownAnswerError("receipt metrics or matches are invalid")
    if not isinstance(result["baselines"], dict) or not isinstance(result["comparisons"], dict):
        raise KnownAnswerError("receipt baseline fields are invalid")
    _require_string_list(result["warnings"], field="warnings")
    receipt_sha256 = result["receipt_sha256"]
    if not isinstance(receipt_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_sha256):
        raise KnownAnswerError("receipt_sha256 must be a lowercase SHA-256")
    if receipt_sha256 != _sha256({**result, "receipt_sha256": None}):
        raise KnownAnswerError("evaluation receipt digest does not match")
    return result
