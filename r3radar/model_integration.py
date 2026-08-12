from __future__ import annotations

import time
import uuid
from dataclasses import replace
from typing import Any

from .codex_worker import CodexCli, CodexDeepReader, CodexInvocationError
from .config import Settings, require_profile_production_activation
from .llama_worker import LlamaCppRunner
from .models import SourceRecord, objective_admission
from .report import generate_weekly_report
from .storage import RadarStore
from .utils import (
    JsonlAuditLog,
    atomic_write_text,
    json_dumps,
    sha256_text,
    utc_now,
)


_FIXTURE_TEXT = """=== PAGE 1 ===
This integration fixture studies workflow-aware cache value prediction for agentic LLM serving.
Problem: a serving system must decide whether a transient KV-cache object will be reused soon.
Method: derive deterministic workflow-stage, tool-transition, and session-continuity signals, then estimate near-term reuse probability for one retention decision.
Evaluation: compare against LRU and frequency baselines on held-out workflow traces using AUROC, calibration error, hit rate, and saved prefill tokens.
Limitations: this fixture does not claim online deployment evidence, causal effects, or a complete serving architecture.
R3 relationship: it directly tests whether workflow semantics improve a bounded cache retention or eviction decision.
Reproducibility: all statements in this fixture are contained on this page and the page marker is the evidence anchor.
""" + ("The evidence remains intentionally repetitive for extraction coverage.\n" * 12)


def run_model_integration(
    base_settings: Settings,
    *,
    provider: str,
) -> dict[str, Any]:
    require_profile_production_activation(
        base_settings,
        "model-integration-test",
    )
    if provider not in {"codex_cli", "llama_cpp"}:
        raise ValueError("unsupported integration provider")
    integration_id = (
        f"{provider}-e2e-"
        + time.strftime("%Y%m%dT%H%M%S")
        + "_"
        + uuid.uuid4().hex[:8]
    )
    data_dir = base_settings.data_dir / "integration" / integration_id
    literature_dir = base_settings.literature_dir / "integration" / integration_id
    outputs_dir = base_settings.outputs_dir / "integration" / integration_id
    settings = replace(
        base_settings,
        data_dir=data_dir,
        literature_dir=literature_dir,
        outputs_dir=outputs_dir,
        database_path=data_dir / "radar.sqlite3",
    )
    settings.ensure_directories()
    text_path = settings.literature_dir / "text" / "fixture.txt"
    atomic_write_text(text_path, _FIXTURE_TEXT)
    audit = JsonlAuditLog(settings.outputs_dir / "audit.jsonl")
    with RadarStore(settings.database_path) as store:
        run_id, _, lease_token = store.create_or_resume_run(
            settings,
            "model-integration",
        )
        store.seed_query_jobs(
            run_id,
            settings,
            include_hosted=False,
            lease_token=lease_token,
            smoke=True,
        )
        with store._lock:
            query_job = store._connection.execute(
                """
                SELECT id FROM query_jobs
                WHERE run_id=? AND source='openalex'
                ORDER BY id LIMIT 1
                """,
                (run_id,),
            ).fetchone()
        if query_job is None:
            raise RuntimeError("integration fixture could not allocate a query job")
        record = SourceRecord(
            source="openalex",
            source_id="W-R3-MODEL-INTEGRATION",
            kind="paper",
            title="Workflow-Aware Cache Value Integration Fixture",
            query_id="q01",
            year=2026,
            canonical_url="https://example.com/r3-model-integration",
        )
        work_id, _ = store.ingest_record(
            run_id=run_id,
            lease_token=lease_token,
            query_job_id=int(query_job["id"]),
            record=record,
            decision=objective_admission(record, settings.raw),
            raw_sha256="model-integration-fixture",
        )
        store.save_document(
            work_id=work_id,
            content_kind="paper_pdf",
            status="ready",
            source_url=record.canonical_url,
            local_path=None,
            text_path=str(text_path),
            content_sha256="model-integration-pdf",
            text_sha256=sha256_text(_FIXTURE_TEXT),
            byte_count=len(_FIXTURE_TEXT.encode("utf-8")),
            text_char_count=len(_FIXTURE_TEXT),
            page_count=1,
            coverage={
                "complete": True,
                "page_count": 1,
                "coverage_type": "text_layer_complete",
            },
        )
        store.seed_analysis_tasks(
            provider,
            settings.raw["analysis"]["prompt_version"],
            analysis_policy_hash=settings.analysis_policy_hash,
            retrieval_hash=settings.retrieval_hash,
            profile_id=settings.profile_id,
            profile_version=settings.profile_version,
        )
        task = store.claim_analysis_task(
            provider,
            config_hash=settings.analysis_policy_hash,
            run_id=run_id,
            lease_token=lease_token,
        )
        if task is None:
            raise RuntimeError("integration analysis task was not claimable")
        if provider == "codex_cli":
            runner = CodexCli(settings, audit, run_id)
            if not runner.authenticated():
                raise CodexInvocationError("Pinned Codex CLI is not authenticated.")
        else:
            runner = LlamaCppRunner(settings, audit, run_id)
            if not runner.health():
                raise CodexInvocationError(
                    "Configured llama.cpp integration model is not ready."
                )
        reader = CodexDeepReader(
            settings,
            store,
            runner,
            audit,
            run_id,
            lease_token,
            provider_name=provider,
            deadline_monotonic=time.monotonic() + 1800,
        )
        started = time.monotonic()
        reader.analyze(task)
        elapsed = time.monotonic() - started
        with store._lock:
            analysis = store._connection.execute(
                """
                SELECT id, deep_read_status, tier, score, provenance_status
                FROM analyses WHERE work_id=?
                """,
                (work_id,),
            ).fetchone()
        if analysis is None or analysis["deep_read_status"] != "complete":
            raise RuntimeError("model integration did not produce a complete analysis")
        with store.transaction() as connection:
            connection.execute(
                """
                UPDATE query_jobs
                SET status='completed', claim_lease_token=NULL,
                    completed_at=COALESCE(completed_at, ?), updated_at=?
                WHERE run_id=? AND status IN ('pending','retry','running')
                """,
                (utc_now(), utc_now(), run_id),
            )
        store.pause_or_complete_run(
            run_id,
            paused=False,
            error=None,
            lease_token=lease_token,
            status_override="completed",
        )
        run_summary = {
            "schema_version": "1.0",
            "run_id": run_id,
            "profile_id": settings.profile_id,
            "profile_version": settings.profile_version,
            "config_hash": settings.config_hash,
            "retrieval_hash": settings.retrieval_hash,
            "analysis_policy_hash": settings.analysis_policy_hash,
            "mode": "model-integration",
            "status": "completed",
            "interrupted": False,
            "attention_required": False,
            "generated_at": utc_now(),
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
        }
        run_summary_path = settings.outputs_dir / "runs" / run_id / "summary.json"
        atomic_write_text(
            run_summary_path,
            json_dumps(run_summary, pretty=True) + "\n",
        )
        report = generate_weekly_report(
            settings,
            store,
            run_id=run_id,
            run_summary=run_summary,
            output_dir=settings.outputs_dir / "weekly",
        )
        return {
            "integration_id": integration_id,
            "provider": provider,
            "run_id": run_id,
            "work_id": work_id,
            "analysis_id": int(analysis["id"]),
            "deep_read_status": str(analysis["deep_read_status"]),
            "tier": str(analysis["tier"]),
            "score": float(analysis["score"]),
            "provenance_status": str(analysis["provenance_status"]),
            "model_usage": store.model_usage(task_id=int(task["id"])),
            "elapsed_seconds": round(elapsed, 3),
            "database_path": str(settings.database_path),
            "audit_path": str(audit.path),
            "report_path": report["report_path"],
            "selection_path": report["selection_path"],
        }
