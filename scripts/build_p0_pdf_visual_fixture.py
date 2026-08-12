from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from r3radar.config import DEFAULT_CONFIG, WORKSPACE_DIR, load_settings
from r3radar.document_policy import CURRENT_PDF_DOCUMENT_POLICY
from r3radar.models import SourceRecord, objective_admission
from r3radar.storage import RadarStore


def _ready_coverage() -> dict[str, Any]:
    policy = CURRENT_PDF_DOCUMENT_POLICY
    return {
        "complete": True,
        "coverage_type": "text_layer",
        "security_status": "parsed_verified",
        "reason": None,
        "failure_code": None,
        "page_count": 1,
        "parser": {
            "id": policy["parser"]["id"],
            "version": policy["parser"]["version"],
            "policy_version": policy["parser"]["policy_version"],
            "effective_options": policy["parser"]["effective_options"],
            "request_schema": policy["protocol"]["request_schema"],
            "result_schema": policy["protocol"]["result_schema"],
            "isolation": {
                "integrity_level": "appcontainer_low",
                "credential_environment_keys": [],
            },
        },
        "parser_receipt": {
            "parser_id": policy["parser"]["id"],
            "parser_version": policy["parser"]["version"],
            "parser_policy_version": policy["parser"]["policy_version"],
            "request_schema": policy["protocol"]["request_schema"],
            "result_schema": policy["protocol"]["result_schema"],
            "worker_sha256": policy["code"]["worker_sha256"],
            "sandbox_sha256": policy["code"]["sandbox_sha256"],
            "return_code": 0,
            "termination": "process_exit",
        },
    }


def build_fixture(root: Path) -> dict[str, Any]:
    fixture_root = root.resolve()
    try:
        fixture_root.relative_to(WORKSPACE_DIR)
    except ValueError as exc:
        raise ValueError("fixture root must stay inside the workspace") from exc
    if fixture_root == WORKSPACE_DIR:
        raise ValueError("fixture root cannot be the workspace root")
    fixture_root.mkdir(parents=True, exist_ok=True)

    config_path = fixture_root / "r3.visual.json"
    raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    relative_root = fixture_root.relative_to(WORKSPACE_DIR).as_posix()
    raw["paths"] = {
        "data": f"{relative_root}/data",
        "literature": f"{relative_root}/literature",
        "outputs": f"{relative_root}/outputs",
    }
    config_path.write_text(
        json.dumps(raw, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    settings = load_settings(config_path)
    for database_file in (
        settings.database_path,
        Path(f"{settings.database_path}-wal"),
        Path(f"{settings.database_path}-shm"),
    ):
        if database_file.is_file():
            database_file.unlink()

    cases = [
        (
            "timeout",
            "PDF 超时隔离示例",
            "incomplete",
            {
                "complete": False,
                "security_status": "incomplete_security",
                "reason": "pdf_extract_timeout",
                "failure_code": "wall_timeout",
            },
        ),
        (
            "worker",
            "PDF 解析进程失败示例",
            "incomplete",
            {
                "complete": False,
                "security_status": "incomplete_security",
                "reason": "pdf_extract_worker_failed",
                "failure_code": "worker_nonzero_exit",
            },
        ),
        (
            "scan",
            "扫描版 PDF 文字层不足示例",
            "incomplete",
            {
                "complete": False,
                "security_status": "parsed_verified",
                "reason": "insufficient_extractable_text",
                "failure_code": None,
            },
        ),
        (
            "no-pdf",
            "来源未提供 PDF 示例",
            "unavailable",
            {
                "complete": False,
                "security_status": "incomplete_security",
                "reason": "no_pdf_url",
                "failure_code": None,
            },
        ),
        (
            "reparse",
            "安全策略升级待重解析示例",
            "retry",
            {
                "complete": False,
                "security_status": "incomplete_security",
                "reason": "pdf_security_reparse_required",
                "failure_code": "document_policy_mismatch",
            },
        ),
    ]
    work_ids: dict[str, int] = {}
    with RadarStore(settings.database_path) as store:
        run_id, _, lease_token = store.create_or_resume_run(
            settings,
            "visual-fixture",
        )
        store.seed_query_jobs(
            run_id,
            settings,
            include_hosted=False,
            lease_token=lease_token,
            smoke=True,
        )
        query_job_id = int(
            store._connection.execute(
                """
                SELECT id FROM query_jobs
                WHERE run_id=? AND source='openalex'
                ORDER BY id LIMIT 1
                """,
                (run_id,),
            ).fetchone()["id"]
        )

        def ingest(
            key: str,
            title: str,
            *,
            pdf_url: str | None,
        ) -> int:
            record = SourceRecord(
                source="openalex",
                source_id=f"W-visual-{key}",
                kind="paper",
                title=f"{title} agent workflow cache",
                query_id="q01",
                year=2026,
                canonical_url=f"https://example.com/{key}",
                pdf_url=pdf_url,
            )
            work_id, _ = store.ingest_record(
                run_id=run_id,
                lease_token=lease_token,
                query_job_id=query_job_id,
                record=record,
                decision=objective_admission(record, settings.raw),
                raw_sha256=f"visual-raw-{key}",
            )
            return work_id

        for key, title, status, coverage in cases:
            pdf_url = None if key == "no-pdf" else f"https://example.com/{key}.pdf"
            work_id = ingest(key, title, pdf_url=pdf_url)
            work_ids[key] = work_id
            store.save_document(
                work_id=work_id,
                content_kind="paper_pdf",
                status=status,
                source_url=pdf_url,
                local_path=None,
                text_path=None,
                content_sha256=f"visual-pdf-{key}",
                text_sha256=None,
                byte_count=100,
                text_char_count=0,
                page_count=1,
                coverage=coverage,
                error=None,
            )

        recovered_id = ingest(
            "recovered",
            "重试后完整深读与反馈恢复示例",
            pdf_url="https://example.com/recovered.pdf",
        )
        work_ids["recovered"] = recovered_id
        store.save_document(
            work_id=recovered_id,
            content_kind="paper_pdf",
            status="ready",
            source_url="https://example.com/recovered.pdf",
            local_path="visual-recovered.pdf",
            text_path="visual-recovered.txt",
            content_sha256="visual-recovered-pdf",
            text_sha256="visual-recovered-text",
            byte_count=1000,
            text_char_count=5000,
            page_count=1,
            coverage=_ready_coverage(),
            error=None,
        )
        seeded = store.seed_analysis_tasks(
            "codex_cli",
            settings.raw["analysis"]["prompt_version"],
            analysis_policy_hash=settings.analysis_policy_hash,
            retrieval_hash=settings.retrieval_hash,
            profile_id=settings.profile_id,
            profile_version=settings.profile_version,
        )
        task = store.claim_analysis_task(
            "codex_cli",
            config_hash=settings.analysis_policy_hash,
            run_id=run_id,
            lease_token=lease_token,
        )
        if task is None:
            raise RuntimeError("recovered visual fixture did not seed analysis")
        store.complete_analysis(
            task_id=int(task["id"]),
            work_id=recovered_id,
            provider="codex_cli",
            model="visual-fixture",
            prompt_version=str(task["prompt_version"]),
            deep_read_status="complete",
            tier="important",
            score=88.0,
            analysis={
                "summary_zh": "该条目已通过完整 PDF 核验并完成深读。",
                "r3_relationship": ["可用于验证恢复后的价值判断展示。"],
                "evidence_anchors": ["第 1 页：视觉验收锚点。"],
                "scores": {"r3_relevance": 88},
            },
            coverage={"complete": True},
            receipt={"fixture": True},
            run_id=run_id,
            lease_token=lease_token,
        )
        store.add_feedback(
            recovered_id,
            "值得保存",
            "视觉验收反馈",
            retrieval_hash=settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
        )

    payload = {
        "schema": "r3/p0-pdf-visual-fixture/v1",
        "config": str(config_path),
        "database": str(settings.database_path),
        "work_ids": work_ids,
        "analysis_seeded": seeded,
    }
    (fixture_root / "fixture-manifest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args()
    print(
        json.dumps(
            build_fixture(arguments.root),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
