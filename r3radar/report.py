from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import (
    Settings,
    canonical_json,
    require_profile_production_activation,
)
from .storage import (
    PublicationConflictError,
    PublicationNotAllowedError,
    RadarStore,
)
from .utils import atomic_write_text, json_dumps, sha256_bytes, sha256_text


def _selection_bucket(item: dict[str, Any]) -> str:
    analysis = item["analysis"]
    relevance = float(analysis["scores"]["r3_relevance"])
    overall = float(item["score"])
    if relevance < 35 or item["tier"] == "out_of_scope_after_deep_read":
        return "excluded_after_deep_read"
    if overall >= 85 and relevance >= 80:
        return "must_read"
    if overall >= 68:
        return "important"
    return "background"


def _balanced_selection(
    candidates: list[dict[str, Any]],
    *,
    limit: int,
    frontier_ratio: float,
) -> list[dict[str, Any]]:
    eligible = [
        item
        for item in candidates
        if item["selection_bucket"] != "excluded_after_deep_read"
    ]
    frontier = [item for item in eligible if item["lane"] == "frontier"]
    other = [item for item in eligible if item["lane"] != "frontier"]
    frontier_target = round(limit * frontier_ratio)
    selected = frontier[:frontier_target] + other[: max(0, limit - frontier_target)]
    selected_ids = {item["id"] for item in selected}
    if len(selected) < limit:
        remaining = [item for item in eligible if item["id"] not in selected_ids]
        selected.extend(remaining[: limit - len(selected)])
    return sorted(selected, key=lambda item: (-float(item["score"]), int(item["id"])))


def _load_and_validate_run_summary(
    settings: Settings,
    store: RadarStore,
    *,
    run: dict[str, Any],
    run_summary: dict[str, Any] | None,
    frozen_summary: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Path]:
    run_id = str(run["id"])
    summary_path = settings.outputs_dir / "runs" / run_id / "summary.json"
    if run_summary is None:
        if not summary_path.is_file():
            if frozen_summary is None:
                raise PublicationNotAllowedError(
                    f"run {run_id} has no immutable summary.json"
                )
            atomic_write_text(
                summary_path,
                json_dumps(frozen_summary, pretty=True) + "\n",
            )
            run_summary = dict(frozen_summary)
        else:
            try:
                run_summary = json.loads(
                    summary_path.read_text(encoding="utf-8")
                )
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PublicationNotAllowedError(
                    f"run {run_id} summary.json is unreadable"
                ) from exc
    summary = dict(run_summary)
    expected_identity = {
        "run_id": run_id,
        "status": str(run["status"]),
        "config_hash": str(run["config_hash"]),
        "retrieval_hash": str(run["retrieval_hash"]),
        "analysis_policy_hash": str(run["analysis_policy_hash"]),
    }
    mismatches = {
        key: {"run": value, "summary": summary.get(key)}
        for key, value in expected_identity.items()
        if summary.get(key) != value
    }
    if mismatches:
        raise PublicationConflictError(
            "run summary identity does not match terminal database row: "
            + canonical_json(mismatches)
        )
    if summary.get("interrupted") or summary.get("fatal_error"):
        raise PublicationNotAllowedError(
            f"run {run_id} summary records interruption or fatal error"
        )
    if summary["status"] == "completed_with_gaps":
        visible = summary.get("visible_backlog")
        if not isinstance(visible, dict) or not visible.get(
            "eligible_for_completed_with_gaps"
        ):
            raise PublicationNotAllowedError(
                f"run {run_id} has unexplained or ineligible visible backlog"
            )
    summary_core = {
        key: value for key, value in summary.items() if key != "publication"
    }
    if (
        frozen_summary is not None
        and canonical_json(summary_core) != canonical_json(frozen_summary)
    ):
        raise PublicationConflictError(
            "run summary no longer matches its terminal frozen snapshot"
        )
    return summary, summary_path


def _snapshot_item(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    try:
        item["analysis"] = json.loads(item.pop("analysis_json"))
        item["coverage"] = json.loads(item.pop("coverage_json"))
        metadata = json.loads(item.pop("metadata_json"))
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PublicationConflictError(
            f"analysis {row.get('analysis_id')} has invalid persisted JSON"
        ) from exc
    if not isinstance(metadata, dict):
        metadata = {}
    item["metadata"] = metadata
    item["selection_bucket"] = _selection_bucket(item)
    snapshot = {
        "schema": "r3/publication-item-snapshot/v1",
        "analysis_id": int(item["analysis_id"]),
        "work_id": int(item["id"]),
        "input_sha256": str(item["input_sha256"]),
        "document_id": int(item["document_id"]),
        "citation": {
            "kind": item["kind"],
            "title": item["title"],
            "year": item["year"],
            "doi": item["doi"],
            "arxiv_id": item["arxiv_id"],
            "github_full_name": item["github_full_name"],
            "best_url": item["best_url"],
            "metadata": metadata,
        },
        "analysis": item["analysis"],
        "coverage": item["coverage"],
        "provider": item["provider"],
        "model": item["model"],
        "tier": item["tier"],
        "score": item["score"],
        "lane": item["lane"],
        "provenance_status": item["provenance_status"],
        "analysis_created_at": item["created_at"],
    }
    item["snapshot"] = snapshot
    item["snapshot_sha256"] = sha256_text(canonical_json(snapshot))
    return item


def _allowed_publication_providers(settings: Settings) -> set[str]:
    if settings.raw.get("demo_mode") is True:
        return {"deterministic_fixture"}
    configured = settings.raw["analysis"].get("auto_publish_providers")
    if configured is None:
        return {"codex_cli"}
    return {str(value) for value in configured}


def prepare_run_publication_candidates(
    settings: Settings,
    store: RadarStore,
) -> list[dict[str, Any]]:
    allowed = _allowed_publication_providers(settings)
    rows = store.list_complete_analyses(
        config_hash=settings.retrieval_hash,
        analysis_policy_hash=settings.analysis_policy_hash,
    )
    candidates = [
        _snapshot_item(row)
        for row in rows
        if str(row.get("provider")) in allowed
    ]
    candidates.sort(
        key=lambda item: (-float(item["score"]), int(item["analysis_id"]))
    )
    return candidates


def _render_markdown(payload: dict[str, Any]) -> str:
    counts = payload["counts"]
    publication = payload["publication"]
    living_diff = payload.get("living_diff") or {}
    diff_counts = living_diff.get("counts") or {}
    sections = [
        "# R3 科研雷达周报",
        "",
        f"- 刊期：`{payload['issue_id']}`",
        f"- 运行：`{publication['run_id']}`",
        f"- 运行终态：`{publication['terminal_status']}`",
        f"- 发布身份：`{publication['publication_key']}`",
        f"- 生成时间：{payload['generated_at']}",
        f"- 上一刊期：`{payload['previous_issue_id'] or '无（首期）'}`",
        f"- 当前完成全文深读：{counts['current_deep_read_complete']}",
        f"- 本期新增或更新：{counts['new_or_updated']}",
        f"- 本期展示：{counts['selected']}",
        (
            f"- 必读：{counts['must_read']}；重点：{counts['important']}；"
            f"背景：{counts['background']}"
        ),
        f"- 深读后排除：{counts['excluded_after_deep_read']}",
        (
            "- Living Diff："
            f"新增 {int(diff_counts.get('added', 0))}；"
            f"内容更新 {int(diff_counts.get('content_updated', 0))}；"
            f"分析更新 {int(diff_counts.get('analysis_updated', 0))}；"
            f"本期决策相关 {int(diff_counts.get('selected_changes', 0))}"
        ),
        "",
        "> 不为满足数量配额而填充低质量条目。未完成全文覆盖的候选不会进入本期排序。",
        "",
    ]
    if counts["legacy_or_unknown_provenance"]:
        sections.extend(
            [
                (
                    f"> 本期有 {counts['legacy_or_unknown_provenance']} 条历史记录缺少完整的 "
                    "append-only 观察或内容修订链，已明确标记，不得当作可回溯事实。"
                ),
                "",
            ]
        )
    sections.extend(["## Living Diff", ""])
    changes = living_diff.get("selected_changes") or []
    if not changes:
        sections.extend(
            ["本期没有新的决策相关变化；不会把历史条目误报为移除。", ""]
        )
    else:
        for change in changes:
            label = {
                "added": "新增",
                "content_updated": "内容修订",
                "analysis_updated": "分析修订",
            }.get(str(change.get("change_kind")), "更新")
            sections.append(
                f"- {label}：{change['title']}（{change['selection_bucket']}；"
                f"{float(change['score']):.1f}）"
            )
        sections.append("")
    for heading, key in (
        ("必读", "must_read"),
        ("重点", "important"),
        ("背景", "background"),
    ):
        items = payload[key]
        sections.extend([f"## {heading}", ""])
        if not items:
            sections.extend(["本期没有达到该层证据与相关性门槛的条目。", ""])
            continue
        for item in items:
            analysis = item["analysis"]
            sections.extend(
                [
                    f"### {item['title']}",
                    "",
                    (
                        f"- 综合分：{float(item['score']):.1f}；来源类型："
                        f"{item['kind']}；深读端：{item['provider']}"
                    ),
                    f"- 可追溯性：`{item['provenance_status']}`",
                    f"- 输入修订 SHA-256：`{item['input_sha256']}`",
                    f"- 冻结快照 SHA-256：`{item['snapshot_sha256']}`",
                    f"- 原始页面：{item['best_url'] or '未提供'}",
                    f"- 内容 SHA-256：`{item['coverage']['text_sha256']}`",
                    "",
                    analysis["summary_zh"],
                    "",
                    "**为什么与 R3 有关**",
                    "",
                    *[f"- {value}" for value in analysis["r3_relationship"]],
                    "",
                    "**关键证据锚点**",
                    "",
                    *[f"- {value}" for value in analysis["evidence_anchors"]],
                    "",
                ]
            )
    sections.extend(["## 深读后排除附录", ""])
    if payload["excluded_after_deep_read"]:
        sections.extend(
            [
                (
                    f"- {item['title']}（{float(item['score']):.1f}；"
                    f"可追溯性：`{item['provenance_status']}`）"
                )
                for item in payload["excluded_after_deep_read"]
            ]
        )
    else:
        sections.append("本期无深读后排除条目。")
    sections.append("")
    return "\n".join(sections)


def _verify_or_restore_file(path: Path, text: str, expected_sha256: str) -> None:
    if path.exists():
        actual = sha256_bytes(path.read_bytes())
        if actual != expected_sha256:
            raise PublicationConflictError(
                f"published artifact changed on disk: {path}"
            )
        return
    atomic_write_text(path, text)


def _restore_existing_publication(
    existing: dict[str, Any],
) -> dict[str, Any]:
    payload = existing["payload"]
    selection_text = json_dumps(payload, pretty=True) + "\n"
    report_text = _render_markdown(payload)
    payload_sha256 = sha256_text(canonical_json(payload))
    report_sha256 = sha256_text(report_text)
    selection_sha256 = sha256_text(selection_text)
    expected = {
        "payload_sha256": payload_sha256,
        "report_sha256": report_sha256,
        "selection_sha256": selection_sha256,
    }
    mismatches = {
        key: {"stored": existing.get(key), "recomputed": value}
        for key, value in expected.items()
        if existing.get(key) != value
    }
    if mismatches:
        raise PublicationConflictError(
            "published artifact hashes do not match the frozen payload: "
            + canonical_json(mismatches)
        )
    report_path = Path(str(existing["report_path"]))
    selection_path = Path(str(existing["selection_path"]))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    _verify_or_restore_file(report_path, report_text, report_sha256)
    _verify_or_restore_file(
        selection_path,
        selection_text,
        selection_sha256,
    )
    local_outbox = existing.get("local_outbox")
    if isinstance(local_outbox, dict):
        digest = local_outbox.get("digest")
        if not isinstance(digest, dict):
            raise PublicationConflictError(
                "local publication digest is unavailable"
            )
        digest_text = canonical_json(digest)
        digest_path = Path(str(local_outbox["digest_path"]))
        _verify_or_restore_file(
            digest_path,
            digest_text,
            str(local_outbox["digest_sha256"]),
        )
    return {
        "issue_id": str(existing["issue_id"]),
        "run_id": str(existing["run_id"]),
        "publication_key": str(existing["publication_key"]),
        "previous_issue_id": existing.get("previous_issue_id"),
        "output_dir": str(existing["output_dir"]),
        "report_path": str(report_path),
        "selection_path": str(selection_path),
        "payload_sha256": payload_sha256,
        "report_sha256": report_sha256,
        "selection_sha256": selection_sha256,
        "local_outbox": local_outbox,
        "counts": dict(existing["counts"]),
        "idempotent": True,
    }


def _living_diff(
    candidates: list[dict[str, Any]],
    *,
    selected_ids: set[int],
    previous_by_work: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    counts = {"added": 0, "content_updated": 0, "analysis_updated": 0}
    selected_changes: list[dict[str, Any]] = []
    for item in candidates:
        work_id = int(item["id"])
        previous = previous_by_work.get(work_id)
        if previous is None:
            change_kind = "added"
        elif str(previous["input_sha256"]) != str(item["input_sha256"]):
            change_kind = "content_updated"
        elif str(previous["snapshot_sha256"]) != str(item["snapshot_sha256"]):
            change_kind = "analysis_updated"
        else:
            continue
        counts[change_kind] += 1
        if work_id not in selected_ids:
            continue
        previous_snapshot = (
            dict(previous.get("snapshot") or {}) if previous is not None else {}
        )
        selected_changes.append(
            {
                "change_kind": change_kind,
                "work_id": work_id,
                "analysis_id": int(item["analysis_id"]),
                "title": str(item["title"]),
                "selection_bucket": str(item["selection_bucket"]),
                "score": float(item["score"]),
                "tier": str(item["tier"]),
                "input_sha256": str(item["input_sha256"]),
                "snapshot_sha256": str(item["snapshot_sha256"]),
                "previous_issue_id": (
                    str(previous["issue_id"]) if previous is not None else None
                ),
                "previous_score": previous_snapshot.get("score"),
                "previous_tier": previous_snapshot.get("tier"),
            }
        )
    counts["selected_changes"] = len(selected_changes)
    return {
        "schema": "r3/living-diff/v1",
        "semantics": "incremental_changes_only_no_implicit_removals",
        "counts": counts,
        "selected_changes": selected_changes,
    }


def generate_weekly_report(
    settings: Settings,
    store: RadarStore,
    *,
    run_id: str,
    run_summary: dict[str, Any] | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    require_profile_production_activation(settings, "report")
    run = store.require_publishable_run(run_id)
    if (
        str(run["config_hash"]) != settings.config_hash
        or str(run["retrieval_hash"]) != settings.retrieval_hash
        or str(run["analysis_policy_hash"]) != settings.analysis_policy_hash
    ):
        raise PublicationConflictError(
            "terminal run is outside the active profile/config scope"
        )
    existing_publication = store.validated_report_issue_for_run(run_id)
    if existing_publication is not None:
        return _restore_existing_publication(existing_publication)
    frozen = store.run_publication_snapshot(run_id)
    if frozen is None:
        raise PublicationNotAllowedError(
            f"run {run_id} has no terminal publication snapshot"
        )
    if (
        str(frozen["retrieval_hash"]) != settings.retrieval_hash
        or str(frozen["analysis_policy_hash"])
        != settings.analysis_policy_hash
        or str(frozen["terminal_status"]) != str(run["status"])
    ):
        raise PublicationConflictError(
            "terminal publication snapshot is outside the run identity"
        )
    summary, summary_path = _load_and_validate_run_summary(
        settings,
        store,
        run=run,
        run_summary=run_summary,
        frozen_summary=frozen["summary"],
    )
    issue_id = f"run_{run_id}"
    existing_issue = None
    published_ids = store.published_analysis_ids(exclude_issue_id=issue_id)
    previous_by_work = store.latest_published_snapshots_by_work(
        retrieval_hash=settings.retrieval_hash,
        analysis_policy_hash=settings.analysis_policy_hash,
    )
    all_rows = list(frozen["candidates"])
    configured_providers = settings.raw["analysis"].get(
        "auto_publish_providers"
    )
    candidates = [
        dict(row)
        for row in all_rows
        if int(row["analysis_id"]) not in published_ids
    ]
    candidates.sort(key=lambda item: (-float(item["score"]), int(item["id"])))
    maximum = int(settings.raw["run"]["weekly_display_max"])
    selected = _balanced_selection(
        candidates,
        limit=maximum,
        frontier_ratio=float(settings.raw["frontier_ratio"]),
    )
    selected_ids = {int(item["id"]) for item in selected}
    must_read = [
        item for item in selected if item["selection_bucket"] == "must_read"
    ][: int(settings.raw["run"]["must_read_max"])]
    must_read_ids = {int(item["id"]) for item in must_read}
    important = [
        item
        for item in selected
        if item["selection_bucket"] == "important"
        and int(item["id"]) not in must_read_ids
    ][: int(settings.raw["run"]["important_max"])]
    primary_ids = must_read_ids | {int(item["id"]) for item in important}
    background = [
        item for item in selected if int(item["id"]) not in primary_ids
    ]
    excluded = [
        item
        for item in candidates
        if item["selection_bucket"] == "excluded_after_deep_read"
    ]
    previous_issue_id = (
        str(existing_issue["previous_issue_id"])
        if existing_issue is not None and existing_issue["previous_issue_id"]
        else None
    )
    if existing_issue is None:
        previous_issue = store.latest_report_issue(
            retrieval_hash=settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
        )
        previous_issue_id = (
            str(previous_issue["issue_id"]) if previous_issue is not None else None
        )
    publication_key = sha256_text(
        canonical_json(
            {
                "schema": "r3/run-publication-key/v1",
                "run_id": run_id,
                "retrieval_hash": settings.retrieval_hash,
                "analysis_policy_hash": settings.analysis_policy_hash,
            }
        )
    )
    counts = {
        "current_deep_read_complete": len(all_rows),
        "new_or_updated": len(candidates),
        "deep_read_complete": len(candidates),
        "selected": len(selected),
        "must_read": len(must_read),
        "important": len(important),
        "background": len(background),
        "excluded_after_deep_read": len(excluded),
        "legacy_or_unknown_provenance": sum(
            1
            for item in candidates
            if item.get("provenance_status") != "append_only"
        ),
    }
    selection_policy = {
        "ranking_after_complete_deep_read_only": True,
        "weekly_display_max": maximum,
        "frontier_ratio_target": settings.raw["frontier_ratio"],
        "no_quota_padding": True,
    }
    if configured_providers is not None:
        selection_policy["auto_publish_providers"] = sorted(
            str(value) for value in configured_providers
        )
    payload = {
        "schema_version": "2.0",
        "issue_id": issue_id,
        "previous_issue_id": previous_issue_id,
        "profile_id": settings.profile_id,
        "profile_version": settings.profile_version,
        "config_hash": settings.config_hash,
        "retrieval_hash": settings.retrieval_hash,
        "analysis_policy_hash": settings.analysis_policy_hash,
        "generated_at": str(run["ended_at"]),
        "publication": {
            "publication_key": publication_key,
            "run_id": run_id,
            "terminal_status": str(run["status"]),
            "run_started_at": str(run["started_at"]),
            "run_ended_at": str(run["ended_at"]),
            "run_summary_path": str(summary_path),
        },
        "selection_policy": selection_policy,
        "counts": counts,
        "must_read": must_read,
        "important": important,
        "background": background,
        "excluded_after_deep_read": excluded,
        "selected_ids": sorted(selected_ids),
        "pipeline_counts": summary["counts"],
        "visible_backlog": summary.get("visible_backlog", {}),
    }
    payload["living_diff"] = _living_diff(
        candidates,
        selected_ids=selected_ids,
        previous_by_work=previous_by_work,
    )
    selection_text = json_dumps(payload, pretty=True) + "\n"
    report_text = _render_markdown(payload)
    selection_sha256 = sha256_text(selection_text)
    report_sha256 = sha256_text(report_text)
    payload_sha256 = sha256_text(canonical_json(payload))
    ended = datetime.fromisoformat(str(run["ended_at"]).replace("Z", "+00:00"))
    base_directory = (
        output_dir
        or settings.outputs_dir / "weekly" / ended.astimezone().strftime("%Y-%m-%d")
    )
    directory = base_directory / issue_id
    report_path = directory / "weekly_report.md"
    selection_path = directory / "weekly_selection.json"
    digest_path = directory / "local_digest.json"
    local_digest = {
        "schema": "r3/local-publication-digest/v1",
        "delivery_mode": "local_only",
        "external_delivery": False,
        "issue_id": issue_id,
        "previous_issue_id": previous_issue_id,
        "generated_at": str(run["ended_at"]),
        "payload_sha256": payload_sha256,
        "report_sha256": report_sha256,
        "selection_sha256": selection_sha256,
        "counts": counts,
        "living_diff": payload["living_diff"],
        "selected": [
            {
                "work_id": int(item["id"]),
                "analysis_id": int(item["analysis_id"]),
                "title": str(item["title"]),
                "selection_bucket": str(item["selection_bucket"]),
                "score": float(item["score"]),
                "snapshot_sha256": str(item["snapshot_sha256"]),
            }
            for item in selected
        ],
    }
    digest_text = canonical_json(local_digest)
    digest_sha256 = sha256_text(digest_text)
    base_directory.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{issue_id}.", dir=str(base_directory))
    )
    created = False
    try:
        atomic_write_text(staging / "weekly_selection.json", selection_text)
        atomic_write_text(staging / "weekly_report.md", report_text)
        atomic_write_text(staging / "local_digest.json", digest_text)
        record = store.record_report_issue(
            issue_id=issue_id,
            run_id=run_id,
            publication_key=publication_key,
            retrieval_hash=settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
            previous_issue_id=previous_issue_id,
            terminal_status=str(run["status"]),
            output_dir=str(directory),
            report_path=str(report_path),
            selection_path=str(selection_path),
            counts=counts,
            payload_sha256=payload_sha256,
            payload=payload,
            report_sha256=report_sha256,
            selection_sha256=selection_sha256,
            run_summary_path=str(summary_path),
            items=[
                {
                    "analysis_id": item["analysis_id"],
                    "work_id": item["id"],
                    "selection_bucket": item["selection_bucket"],
                    "selected": int(item["id"]) in selected_ids,
                    "input_sha256": item["input_sha256"],
                    "snapshot_sha256": item["snapshot_sha256"],
                    "snapshot": item["snapshot"],
                }
                for item in candidates
            ],
            outbox_digest=local_digest,
            outbox_digest_sha256=digest_sha256,
            outbox_digest_path=str(digest_path),
        )
        created = bool(record["created"])
        if created:
            if directory.exists():
                _verify_or_restore_file(
                    report_path,
                    report_text,
                    report_sha256,
                )
                _verify_or_restore_file(
                    selection_path,
                    selection_text,
                    selection_sha256,
                )
                _verify_or_restore_file(
                    digest_path,
                    digest_text,
                    digest_sha256,
                )
            else:
                os.replace(staging, directory)
        else:
            stored_report = Path(str(record["report_path"]))
            stored_selection = Path(str(record["selection_path"]))
            stored_report.parent.mkdir(parents=True, exist_ok=True)
            _verify_or_restore_file(stored_report, report_text, report_sha256)
            _verify_or_restore_file(
                stored_selection,
                selection_text,
                selection_sha256,
            )
            report_path = stored_report
            selection_path = stored_selection
            directory = Path(str(record["output_dir"]))
            stored_outbox = store.publication_outbox_for_issue(issue_id)
            if stored_outbox is None:
                raise PublicationConflictError(
                    "local publication outbox was not recorded"
                )
            digest_path = Path(str(stored_outbox["digest_path"]))
            _verify_or_restore_file(
                digest_path,
                digest_text,
                digest_sha256,
            )
    except BaseException:
        if created:
            store.remove_report_issue_if_payload(
                issue_id=issue_id,
                payload_sha256=payload_sha256,
            )
        raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
    return {
        "issue_id": issue_id,
        "run_id": run_id,
        "publication_key": publication_key,
        "previous_issue_id": previous_issue_id,
        "output_dir": str(directory),
        "report_path": str(report_path),
        "selection_path": str(selection_path),
        "payload_sha256": payload_sha256,
        "report_sha256": report_sha256,
        "selection_sha256": selection_sha256,
        "local_outbox": {
            "delivery_mode": "local_only",
            "state": "ready",
            "digest_path": str(digest_path),
            "digest_sha256": digest_sha256,
        },
        "counts": counts,
        "idempotent": not created,
    }
