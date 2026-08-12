from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .codex_worker import planned_model_invocations, split_text
from .config import Settings, load_settings
from .content import ContentProcessor
from .document_policy import REPOSITORY_SELECTION_POLICY_ID
from .storage import RadarStore
from .utils import (
    atomic_write_text,
    json_dumps,
    sha256_bytes,
    sha256_text,
)


REPROJECTION_RECEIPT_SCHEMA = "r3/repository-reprojection/v1"


class _NoNetworkAudit:
    def write(self, *_: object, **__: object) -> None:
        return None


def _network_disabled(_: str) -> object:
    raise RuntimeError("repository reprojection never performs network access")


@dataclass
class _PreparedRepository:
    document: dict[str, Any]
    summary: dict[str, Any]
    selected_text: str
    inventory_text: str
    text_path: Path
    inventory_path: Path
    coverage: dict[str, Any]


def _chunk_count(
    settings: Settings,
    text: str,
    *,
    inventory: list[dict[str, Any]] | None = None,
) -> int:
    trusted_markers = None
    if inventory is not None:
        trusted_markers = [
            {
                "anchor": item["evidence_anchor"],
                "start": item["evidence_anchor_start"],
                "end": item["evidence_anchor_end"],
            }
            for item in inventory
            if isinstance(item, dict)
            and item.get("included") is True
            and isinstance(item.get("evidence_anchor"), str)
        ]
    return len(
        split_text(
            text,
            int(settings.raw["documents"]["chunk_characters"]),
            int(settings.raw["documents"]["chunk_overlap_characters"]),
            trusted_markers=trusted_markers,
        )
    )


def _call_plan(settings: Settings, chunk_total: int) -> dict[str, int]:
    planning = settings.raw["analysis"].get("budget_planning") or {}
    return planned_model_invocations(
        chunk_total=chunk_total,
        batch_chunk_count=int(
            settings.raw["analysis"]["batch_chunk_count"]
        ),
        synthesis_group_max_items=int(
            settings.raw["analysis"]["synthesis_group_max_items"]
        ),
        retry_reserve_invocations=int(
            planning.get("retry_reserve_invocations", 0)
        ),
    )


def _artifact_matches(path: Path, expected: bytes) -> bool | None:
    if not path.exists():
        return None
    if not path.is_file():
        return False
    return path.read_bytes() == expected


def _prepare_repository(
    settings: Settings,
    processor: ContentProcessor,
    document: dict[str, Any],
) -> _PreparedRepository:
    work_id = int(document["work_id"])
    archive_value = document.get("local_path")
    if not isinstance(archive_value, str) or not archive_value.strip():
        raise ValueError("ready repository has no local archive path")
    archive_path = Path(archive_value).resolve()
    if not archive_path.is_file():
        raise ValueError("local repository archive is unavailable")
    archive_size = archive_path.stat().st_size
    if archive_size > int(
        settings.raw["documents"]["max_repository_archive_bytes"]
    ):
        raise ValueError("local repository archive exceeds the configured limit")
    archive_bytes = archive_path.read_bytes()
    archive_sha256 = sha256_bytes(archive_bytes)
    if archive_sha256 != document.get("content_sha256"):
        raise ValueError("local repository archive SHA-256 does not match SQLite")
    recorded_bytes = document.get("byte_count")
    if recorded_bytes is not None and int(recorded_bytes) != len(archive_bytes):
        raise ValueError("local repository archive byte count does not match SQLite")

    selected = processor._read_repository_archive(archive_bytes)
    coverage = dict(selected["coverage"])
    if (
        coverage.get("complete") is not True
        or coverage.get("coverage_scope")
        != "selected_repository_corpus"
        or coverage.get("selection_policy_id")
        != REPOSITORY_SELECTION_POLICY_ID
    ):
        raise ValueError(
            "current repository selector did not produce complete selected coverage"
        )
    selected_text = str(selected["text"])
    inventory = selected["inventory"]
    if not selected_text.strip() or not isinstance(inventory, list):
        raise ValueError("selected repository corpus is empty or malformed")
    selected_text_sha256 = sha256_text(selected_text)
    inventory_text = json_dumps(inventory, pretty=True) + "\n"
    inventory_sha256 = sha256_text(inventory_text)
    if inventory_sha256 != coverage.get("inventory_sha256"):
        raise ValueError("selected repository inventory hash is inconsistent")

    policy_hash = str(coverage["selection_policy_hash"])
    text_base = (
        f"{archive_path.stem}_{policy_hash[:12]}_"
        f"{selected_text_sha256[:12]}_{inventory_sha256[:12]}"
    )
    text_path = settings.literature_dir / "text" / f"{text_base}.txt"
    inventory_path = (
        settings.literature_dir
        / "text"
        / f"{text_base}.inventory.json"
    )
    coverage["inventory_path"] = str(inventory_path)
    old_coverage = document.get("coverage")
    if isinstance(old_coverage, dict) and isinstance(
        old_coverage.get("raw_receipt"),
        dict,
    ):
        coverage["raw_receipt"] = old_coverage["raw_receipt"]
    coverage["reprojection_receipt"] = {
        "schema": REPROJECTION_RECEIPT_SCHEMA,
        "source_document_id": int(document["id"]),
        "source_content_sha256": archive_sha256,
        "source_text_sha256": document.get("text_sha256"),
        "selection_policy_hash": policy_hash,
        "inventory_sha256": inventory_sha256,
        "network_access": False,
    }

    old_chunks = None
    old_plan = None
    old_text_value = document.get("text_path")
    if isinstance(old_text_value, str) and old_text_value.strip():
        old_text_path = Path(old_text_value)
        if old_text_path.is_file():
            old_text = old_text_path.read_bytes().decode("utf-8")
            if sha256_text(old_text) == document.get("text_sha256"):
                old_chunks = _chunk_count(settings, old_text)
                old_plan = _call_plan(settings, old_chunks)
    selected_chunks = _chunk_count(
        settings,
        selected_text,
        inventory=inventory,
    )
    selected_plan = _call_plan(settings, selected_chunks)
    task_call_budget = int(
        settings.raw["analysis"]["budgets"]["max_invocations_per_task"]
    )
    budget_feasible = bool(
        selected_plan["planned_total"] <= task_call_budget
    )

    text_bytes = selected_text.encode("utf-8")
    inventory_bytes = inventory_text.encode("utf-8")
    text_artifact_match = _artifact_matches(text_path, text_bytes)
    inventory_artifact_match = _artifact_matches(
        inventory_path,
        inventory_bytes,
    )
    if text_artifact_match is False or inventory_artifact_match is False:
        raise ValueError(
            "a deterministic reprojection artifact path contains different data"
        )
    current_coverage = (
        old_coverage if isinstance(old_coverage, dict) else {}
    )
    would_change = bool(
        document.get("text_sha256") != selected_text_sha256
        or document.get("text_path") != str(text_path)
        or current_coverage.get("coverage_scope")
        != "selected_repository_corpus"
        or current_coverage.get("selection_policy_hash") != policy_hash
        or current_coverage.get("inventory_sha256") != inventory_sha256
        or text_artifact_match is not True
        or inventory_artifact_match is not True
    )
    summary = {
        "work_id": work_id,
        "title": str(document["title"]),
        "document_id": int(document["id"]),
        "archive_path": str(archive_path),
        "old_coverage_scope": current_coverage.get("coverage_scope"),
        "selection_policy_id": coverage["selection_policy_id"],
        "selection_policy_hash": policy_hash,
        "old_text_characters": document.get("text_char_count"),
        "selected_text_characters": len(selected_text),
        "old_chunks": old_chunks,
        "selected_chunks": selected_chunks,
        "old_estimated_calls": (
            old_plan["planned_total"] if old_plan is not None else None
        ),
        "selected_estimated_calls": selected_plan["planned_total"],
        "selected_minimum_calls": (
            selected_plan["planned_total"]
            - selected_plan["retry_reserve_invocations"]
        ),
        "selected_retry_reserve_calls": selected_plan[
            "retry_reserve_invocations"
        ],
        "task_call_budget": task_call_budget,
        "budget_headroom_calls": (
            task_call_budget - selected_plan["planned_total"]
        ),
        "budget_feasible": budget_feasible,
        "estimated_call_savings": (
            old_plan["planned_total"] - selected_plan["planned_total"]
            if old_plan is not None
            else None
        ),
        "included_file_count": coverage["included_file_count"],
        "excluded_file_count": coverage["excluded_file_count"],
        "text_path": str(text_path),
        "inventory_path": str(inventory_path),
        "text_sha256": selected_text_sha256,
        "inventory_sha256": inventory_sha256,
        "would_change": would_change,
        "status": (
            "ready"
            if budget_feasible or not would_change
            else "budget_blocked"
        ),
    }
    return _PreparedRepository(
        document=document,
        summary=summary,
        selected_text=selected_text,
        inventory_text=inventory_text,
        text_path=text_path,
        inventory_path=inventory_path,
        coverage=coverage,
    )


def _write_new_artifact(path: Path, value: str) -> bool:
    expected = value.encode("utf-8")
    current = _artifact_matches(path, expected)
    if current is True:
        return False
    if current is False:
        raise ValueError(
            "refusing to overwrite a different deterministic artifact"
        )
    atomic_write_text(path, value)
    return True


def reproject_repository_corpus(
    settings: Settings,
    *,
    apply: bool = False,
    work_ids: Sequence[int] | None = None,
) -> dict[str, Any]:
    selection = settings.raw["documents"].get("repository_corpus")
    if (
        not isinstance(selection, dict)
        or selection.get("mode") != REPOSITORY_SELECTION_POLICY_ID
    ):
        raise ValueError(
            "repository reprojection requires core_plus_sampled_aux_v1"
        )
    requested = (
        {int(work_id) for work_id in work_ids}
        if work_ids is not None
        else None
    )
    documents = RadarStore.read_ready_repository_documents(
        settings.database_path,
        retrieval_hash=settings.retrieval_hash,
    )
    available_ids = {int(document["work_id"]) for document in documents}
    if requested is not None:
        missing = sorted(requested - available_ids)
        if missing:
            raise ValueError(
                "requested work IDs are not ready repositories in this scope: "
                + ", ".join(str(value) for value in missing)
            )
        documents = [
            document
            for document in documents
            if int(document["work_id"]) in requested
        ]

    processor = ContentProcessor(
        settings,
        _network_disabled,
        _NoNetworkAudit(),  # type: ignore[arg-type]
        "repository-reprojection",
    )
    prepared: list[_PreparedRepository] = []
    summaries: list[dict[str, Any]] = []
    for document in documents:
        try:
            candidate = _prepare_repository(
                settings,
                processor,
                document,
            )
        except Exception as exc:
            summaries.append(
                {
                    "work_id": int(document["work_id"]),
                    "title": str(document["title"]),
                    "document_id": int(document["id"]),
                    "status": "blocked",
                    "reason": f"{type(exc).__name__}: {exc}",
                    "would_change": False,
                }
            )
            continue
        prepared.append(candidate)
        summaries.append(candidate.summary)

    result: dict[str, Any] = {
        "schema_version": "1.0",
        "mode": "apply" if apply else "dry_run",
        "profile_id": settings.profile_id,
        "profile_version": settings.profile_version,
        "retrieval_hash": settings.retrieval_hash,
        "analysis_policy_hash": settings.analysis_policy_hash,
        "selection_policy_id": REPOSITORY_SELECTION_POLICY_ID,
        "network_access": False,
        "candidate_count": len(summaries),
        "ready_count": sum(
            1
            for candidate in prepared
            if candidate.summary["status"] == "ready"
        ),
        "would_change_count": sum(
            1 for candidate in prepared if candidate.summary["would_change"]
        ),
        "applied_count": 0,
        "unchanged_count": sum(
            1
            for candidate in prepared
            if not candidate.summary["would_change"]
        ),
        "failed_count": sum(
            1
            for summary in summaries
            if summary["status"] in {"blocked", "budget_blocked"}
        ),
        "candidates": summaries,
    }
    if not apply:
        result["status"] = (
            "ready"
            if result["failed_count"] == 0
            else "ready_with_gaps"
        )
        return result

    for candidate in prepared:
        if candidate.summary["status"] == "budget_blocked":
            candidate.summary["apply_status"] = "blocked"
            candidate.summary["error"] = (
                "planned model calls exceed max_invocations_per_task"
            )
    changing = [
        candidate
        for candidate in prepared
        if candidate.summary["would_change"]
        and candidate.summary["budget_feasible"]
    ]
    if not changing:
        result["status"] = (
            "completed"
            if result["failed_count"] == 0
            else "completed_with_gaps"
        )
        return result

    with RadarStore(settings.database_path) as store:
        running_run = store.running_run()
        if running_run is not None:
            raise RuntimeError(
                "repository reprojection cannot apply while run "
                f"{running_run['id']} is active"
            )
        for candidate in changing:
            created_paths: list[Path] = []
            try:
                if _write_new_artifact(
                    candidate.text_path,
                    candidate.selected_text,
                ):
                    created_paths.append(candidate.text_path)
                if _write_new_artifact(
                    candidate.inventory_path,
                    candidate.inventory_text,
                ):
                    created_paths.append(candidate.inventory_path)
                storage_result = (
                    store.save_selected_repository_revision_and_queue(
                        work_id=int(candidate.document["work_id"]),
                        source_url=candidate.document.get("source_url"),
                        archive_path=str(
                            Path(candidate.document["local_path"]).resolve()
                        ),
                        text_path=str(candidate.text_path),
                        content_sha256=str(
                            candidate.document["content_sha256"]
                        ),
                        text_sha256=str(
                            candidate.summary["text_sha256"]
                        ),
                        byte_count=int(candidate.document["byte_count"]),
                        text_char_count=len(candidate.selected_text),
                        coverage=candidate.coverage,
                        analysis_provider=str(
                            settings.raw["analysis"]["primary_provider"]
                        ),
                        analysis_prompt_version=str(
                            settings.raw["analysis"]["prompt_version"]
                        ),
                        analysis_policy_hash=settings.analysis_policy_hash,
                        retrieval_hash=settings.retrieval_hash,
                        profile_id=settings.profile_id,
                        profile_version=settings.profile_version,
                    )
                )
            except Exception as exc:
                for path in reversed(created_paths):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                candidate.summary["apply_status"] = "failed"
                candidate.summary["error"] = f"{type(exc).__name__}: {exc}"
                result["failed_count"] += 1
                continue
            candidate.summary["apply_status"] = "applied"
            candidate.summary["storage_result"] = storage_result
            result["applied_count"] += 1

    result["status"] = (
        "completed"
        if result["failed_count"] == 0
        else "completed_with_gaps"
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reproject existing local repository ZIPs into the current "
            "auditable selected corpus. Dry-run is the default."
        )
    )
    parser.add_argument("--config")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="write new artifacts/revisions and queue only affected works",
    )
    parser.add_argument(
        "--work-id",
        action="append",
        type=int,
        dest="work_ids",
        help="limit the operation to one or more ready repository work IDs",
    )
    args = parser.parse_args(argv)
    settings = load_settings(args.config)
    result = reproject_repository_corpus(
        settings,
        apply=bool(args.apply),
        work_ids=args.work_ids,
    )
    print(json_dumps(result, pretty=True))
    return 0 if result["failed_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
