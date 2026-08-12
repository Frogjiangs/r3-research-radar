from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PROJECT_DIR, Settings, load_settings
from .models import SourceRecord, objective_admission
from .report import generate_weekly_report, prepare_run_publication_candidates
from .storage import RadarStore
from .utils import atomic_write_text, json_dumps, sha256_bytes, sha256_text


DEMO_CONFIG = PROJECT_DIR / "config" / "demo.v1.json"
DEMO_MANIFEST_SCHEMA = "r3/deterministic-demo/v3"
DEMO_PROVIDER = "deterministic_fixture"


def _publication_summary(publication: dict[str, Any] | None) -> dict[str, Any] | None:
    if publication is None:
        return None
    return {
        key: publication.get(key)
        for key in (
            "issue_id",
            "run_id",
            "publication_key",
            "output_dir",
            "report_path",
            "selection_path",
            "payload_sha256",
            "report_sha256",
            "selection_sha256",
            "counts",
            "idempotent",
        )
        if publication.get(key) is not None
    }


def _analysis(
    work_id: int,
    *,
    kind: str,
    score: float,
    anchor: str,
) -> dict[str, Any]:
    paper = kind == "paper"
    scores = {
        "novelty": score - 6,
        "r3_relevance": score + 4,
        "evidence_strength": score - 2,
        "reuse_signal_value": score,
        "implementability": score + 1,
        "overall": score,
    }
    return {
        "candidate_id": work_id,
        "deep_read_status": "complete",
        "coverage": {
            "complete": True,
            "chunk_total": 1,
            "chunk_done": 1,
            "chunk_indices": [0],
            "gaps": [],
        },
        "summary_zh": (
            "这是一个明确标注的合成论文夹具，用来展示 R3 如何把完整阅读、证据、"
            "局限和研究决策放在同一张卡片中；它不是现实论文，也不构成文献事实。"
            if paper
            else
            "这是一个明确标注的合成仓库夹具，用来展示 R3 如何把代码结构、"
            "可迁移设计、风险和后续实验连接起来；它不对应真实 GitHub 仓库。"
        ),
        "problem": (
            "演示研究雷达如何区分相关线索、直接证据和仍未得到证明的结论。"
            if paper
            else "演示研究雷达如何从仓库材料中提炼可复用机制而不执行外部代码。"
        ),
        "method": (
            "使用一页静态合成文本和一个可核验锚点生成冻结分析。"
            if paper
            else "使用一个静态 ZIP、文件边界和一个可核验锚点生成冻结分析。"
        ),
        "evaluation": [
            "夹具完整覆盖一个确定性文本块，证据锚点可回到本地合成原文。",
            "Demo 不执行检索、下载、模型调用或第三方代码。",
        ],
        "limitations": [
            "合成夹具只能验证产品流程，不能衡量推荐准确率或模型质量。",
            "任何真实质量主张都需要独立的人类标注 Gold Set。",
        ],
        "r3_relationship": [
            (
                "展示论文证据如何进入“阅读、保存、实验或跳过”的研究决策。"
                if paper
                else "展示仓库证据如何与论文条目在同一决策界面中比较。"
            )
        ],
        "actionable_ideas": [
            (
                "创建真实 profile 后先运行小型 smoke，再决定是否投入深读预算。"
                if paper
                else "只对研究相关的核心实现、代表性测试和必要文档执行深读。"
            )
        ],
        "overlap_risks": [
            "不要把 deterministic demo 的结果当成现实研究结论或产品 benchmark。"
        ],
        "reproducibility": (
            "夹具由版本化代码本地生成；相同版本使用同一 profile 与文本内容。"
        ),
        "score_scale": "0_to_100",
        "scores": scores,
        "tier": "must_read" if paper else "important",
        "evidence_anchors": [anchor],
        "uncertainties": [
            "真实来源可访问性、模型差异和领域相关性不在本 Demo 的验证范围内。"
        ],
    }


def _write_demo_inputs(settings: Settings) -> dict[str, dict[str, Any]]:
    text_dir = settings.literature_dir / "text"
    document_dir = settings.literature_dir / "documents"
    text_dir.mkdir(parents=True, exist_ok=True)
    document_dir.mkdir(parents=True, exist_ok=True)

    paper_text = (
        "=== PAGE 1 ===\n"
        "DETERMINISTIC DEMO FIXTURE — NOT A REAL PAPER.\n"
        "The fixture demonstrates that a recommendation should expose evidence, "
        "limitations, and the next human decision.\n"
    )
    repository_text = (
        "=== FILE: README.md ===\n"
        "DETERMINISTIC DEMO FIXTURE — NOT A REAL REPOSITORY.\n"
        "The fixture demonstrates static code-oriented evidence without running "
        "third-party scripts or dependencies.\n"
    )
    paper_path = text_dir / "demo-paper.txt"
    repository_path = text_dir / "demo-repository.txt"
    atomic_write_text(paper_path, paper_text)
    atomic_write_text(repository_path, repository_text)
    archive_path = document_dir / "demo-repository.zip"
    with zipfile.ZipFile(
        archive_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr("README.md", repository_text)
    return {
        "paper": {
            "text_path": paper_path,
            "artifact_path": paper_path,
            "text": paper_text,
            "anchor": "=== PAGE 1 ===",
        },
        "repository": {
            "text_path": repository_path,
            "artifact_path": archive_path,
            "text": repository_text,
            "anchor": "=== FILE: README.md ===",
        },
    }


def _demo_settings(workspace: Path) -> Settings:
    workspace = workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    config_path = workspace / "demo.profile.json"
    raw = json.loads(DEMO_CONFIG.read_text(encoding="utf-8"))
    raw["workspace_root"] = str(workspace)
    atomic_write_text(config_path, json_dumps(raw, pretty=True) + "\n")
    return load_settings(config_path)


def _existing_demo(settings: Settings) -> dict[str, Any] | None:
    marker = settings.workspace_dir / "demo-manifest.json"
    if not marker.is_file():
        return None
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if (
        payload.get("schema") != DEMO_MANIFEST_SCHEMA
        or payload.get("config_hash") != settings.config_hash
        or not settings.database_path.is_file()
    ):
        return None
    with RadarStore(settings.database_path) as store:
        counts = store.dashboard_counts(
            settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
        )
        if counts["unique_works"] != 2 or counts["deep_read"] != 2:
            return None
        with store._lock:
            rows = store._connection.execute(
                """
                SELECT provider, model, provider_receipt_json
                FROM analyses
                ORDER BY work_id
                """
            ).fetchall()
        if len(rows) != 2:
            return None
        for row in rows:
            try:
                receipt = json.loads(row["provider_receipt_json"])
            except (TypeError, ValueError, json.JSONDecodeError):
                return None
            if (
                row["provider"] != DEMO_PROVIDER
                or row["model"] != "deterministic-fixture-no-model-call"
                or receipt.get("provider_invoked") is not False
                or receipt.get("network_calls") != 0
                or receipt.get("model_calls") != 0
            ):
                return None
        publication = store.latest_publication(
            retrieval_hash=settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
        )
    return {
        "ok": True,
        "reused": True,
        "workspace": str(settings.workspace_dir),
        "database": str(settings.database_path),
        "counts": counts,
        "publication": _publication_summary(publication),
        "network_calls": 0,
        "model_calls": 0,
    }


def prepare_demo(workspace: Path) -> tuple[Settings, dict[str, Any]]:
    """Build or reuse a deterministic two-item demo without network/model calls."""

    settings = _demo_settings(workspace)
    existing = _existing_demo(settings)
    if existing is not None:
        return settings, existing
    if settings.database_path.exists():
        raise RuntimeError(
            "The demo workspace contains an unrecognized database. "
            "Choose a new --workspace; R3 will not delete it automatically."
        )

    fixtures = _write_demo_inputs(settings)
    with RadarStore(settings.database_path) as store:
        run_id, resumed, lease_token = store.create_or_resume_run(
            settings,
            "deterministic_demo",
        )
        if resumed:
            raise RuntimeError("An incomplete demo run already exists.")
        store.seed_query_jobs(
            run_id,
            settings,
            include_hosted=False,
            lease_token=lease_token,
            smoke=True,
        )
        with store._lock:
            query_rows = store._connection.execute(
                """
                SELECT id, source, query_id
                FROM query_jobs
                WHERE run_id=?
                """,
                (run_id,),
            ).fetchall()
        query_ids = {
            (str(row["source"]), str(row["query_id"])): int(row["id"])
            for row in query_rows
        }
        records = [
            (
                "paper",
                SourceRecord(
                    source="openalex",
                    source_id="r3-demo-paper-fixture",
                    kind="paper",
                    title="[DEMO FIXTURE] Evidence-aware research paper",
                    query_id="q01",
                    metadata={"synthetic_fixture": True},
                ),
                query_ids[("openalex", "q01")],
            ),
            (
                "repository",
                SourceRecord(
                    source="github",
                    source_id="r3-demo-repository-fixture",
                    kind="repository",
                    title="[DEMO FIXTURE] Evidence-aware research repository",
                    query_id="g01",
                    metadata={"synthetic_fixture": True},
                ),
                query_ids[("github", "g01")],
            ),
        ]
        work_by_kind: dict[str, int] = {}
        for kind, record, query_job_id in records:
            fixture = fixtures[kind]
            work_id, _ = store.ingest_record(
                run_id=run_id,
                lease_token=lease_token,
                query_job_id=query_job_id,
                record=record,
                decision=objective_admission(record, settings.raw),
                raw_sha256=sha256_text(f"deterministic-demo:{kind}"),
            )
            work_by_kind[kind] = work_id
            artifact_path = Path(fixture["artifact_path"])
            text_path = Path(fixture["text_path"])
            store.save_document(
                work_id=work_id,
                content_kind=f"demo_{kind}_fixture",
                status="ready",
                source_url=None,
                local_path=str(artifact_path),
                text_path=str(text_path),
                content_sha256=sha256_bytes(artifact_path.read_bytes()),
                text_sha256=sha256_text(str(fixture["text"])),
                byte_count=artifact_path.stat().st_size,
                text_char_count=len(str(fixture["text"])),
                page_count=1 if kind == "paper" else None,
                coverage={
                    "complete": True,
                    "security_status": "deterministic_synthetic_fixture",
                    "reason": None,
                },
            )
        seeded = store.seed_analysis_tasks(
            DEMO_PROVIDER,
            settings.raw["analysis"]["prompt_version"],
            analysis_policy_hash=settings.analysis_policy_hash,
            retrieval_hash=settings.retrieval_hash,
            profile_id=settings.profile_id,
            profile_version=settings.profile_version,
        )
        if seeded != 2:
            raise RuntimeError(f"Expected two demo analysis tasks; got {seeded}.")
        for _ in range(2):
            task = store.claim_analysis_task(
                DEMO_PROVIDER,
                config_hash=settings.analysis_policy_hash,
                run_id=run_id,
                lease_token=lease_token,
            )
            if task is None:
                raise RuntimeError("Demo analysis task could not be claimed.")
            work_id = int(task["work_id"])
            kind = next(
                value for value, candidate in work_by_kind.items() if candidate == work_id
            )
            fixture = fixtures[kind]
            score = 86.0 if kind == "paper" else 81.0
            analysis = _analysis(
                work_id,
                kind=kind,
                score=score,
                anchor=str(fixture["anchor"]),
            )
            store.complete_analysis(
                task_id=int(task["id"]),
                work_id=work_id,
                provider=DEMO_PROVIDER,
                model="deterministic-fixture-no-model-call",
                prompt_version=str(task["prompt_version"]),
                deep_read_status="complete",
                tier=str(analysis["tier"]),
                score=score,
                analysis=analysis,
                coverage={
                    "complete": True,
                    "chunk_total": 1,
                    "chunk_done": 1,
                    "chunk_indices": [0],
                    "gaps": [],
                    "text_sha256": sha256_text(str(fixture["text"])),
                    "text_char_count": len(str(fixture["text"])),
                    "fixture": True,
                },
                receipt={
                    "schema": DEMO_MANIFEST_SCHEMA,
                    "fixture": True,
                    "provider_invoked": False,
                    "network_calls": 0,
                    "model_calls": 0,
                },
                run_id=run_id,
                lease_token=lease_token,
            )
        with store.transaction() as connection:
            now = datetime.now(timezone.utc).isoformat()
            connection.execute(
                """
                UPDATE query_jobs
                SET status='completed', claim_lease_token=NULL,
                    completed_at=COALESCE(completed_at, ?), updated_at=?
                WHERE run_id=? AND status IN ('pending','retry','running')
                """,
                (now, now, run_id),
            )
        summary = {
            "schema_version": "1.0",
            "run_id": run_id,
            "profile_id": settings.profile_id,
            "profile_version": settings.profile_version,
            "config_hash": settings.config_hash,
            "retrieval_hash": settings.retrieval_hash,
            "analysis_policy_hash": settings.analysis_policy_hash,
            "mode": "deterministic_demo",
            "status": "completed",
            "interrupted": False,
            "attention_required": False,
            "counts": store.dashboard_counts(
                settings.retrieval_hash,
                analysis_policy_hash=settings.analysis_policy_hash,
            ),
            "visible_backlog": {
                "present": False,
                "explained": False,
                "eligible_for_completed_with_gaps": False,
                "reason_codes": [],
            },
            "fatal_error": None,
            "demo": {
                "synthetic_fixture": True,
                "network_calls": 0,
                "model_calls": 0,
            },
        }
        store.complete_run_with_publication_snapshot(
            run_id,
            lease_token=lease_token,
            terminal_status="completed",
            error=None,
            retrieval_hash=settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
            summary=summary,
            candidates=prepare_run_publication_candidates(settings, store),
        )
        publication = generate_weekly_report(
            settings,
            store,
            run_id=run_id,
            run_summary=summary,
        )
        counts = store.dashboard_counts(
            settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
        )

    marker = {
        "schema": DEMO_MANIFEST_SCHEMA,
        "config_hash": settings.config_hash,
        "run_id": run_id,
        "synthetic_fixture": True,
        "network_calls": 0,
        "model_calls": 0,
    }
    atomic_write_text(
        settings.workspace_dir / "demo-manifest.json",
        json_dumps(marker, pretty=True) + "\n",
    )
    return settings, {
        "ok": True,
        "reused": False,
        "workspace": str(settings.workspace_dir),
        "database": str(settings.database_path),
        "run_id": run_id,
        "counts": counts,
        "publication": _publication_summary(publication),
        "network_calls": 0,
        "model_calls": 0,
    }
