from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from .codex_worker import (
    AnalysisBudgetPaused,
    CodexCli,
    CodexDeepReader,
    CodexHostedSearch,
    CodexInvocationError,
    CodexNonRetryableInvocationError,
)
from .config import Settings, require_profile_production_activation
from .content import ContentProcessor
from .http_client import (
    NonRetryableFetchError,
    RawResponseStore,
    RetryDeferredError,
    SafeHttpClient,
)
from .intake import WeeklyIntakeGate, WeeklyIntakePolicy
from .llama_worker import LlamaCppRunner
from .models import AdmissionDecision, SourceRecord, objective_admission
from .report import (
    generate_weekly_report,
    prepare_run_publication_candidates,
)
from .sources import ArxivSource, GitHubSource, OpenAlexSource
from .storage import RadarStore, RunAlreadyActiveError
from .utils import JsonlAuditLog, atomic_write_text, json_dumps, utc_now
from .verification import HostedResultVerifier, HostedVerificationRejectedError


@dataclass(frozen=True, slots=True)
class PipelineLimits:
    results_per_query: int | None = None
    content_items: int | None = None
    analysis_items: int | None = None
    hosted_jobs: int | None = None

    @classmethod
    def smoke(cls) -> "PipelineLimits":
        return cls(
            results_per_query=2,
            content_items=6,
            analysis_items=1,
            hosted_jobs=1,
        )


class TransferBudgetReached(RuntimeError):
    def __init__(
        self,
        *,
        previous_bytes: int,
        received_chunk_bytes: int,
        observed_bytes: int,
        limit_bytes: int,
        boundary_reason: str,
    ):
        super().__init__(
            "per-invocation transfer budget boundary reached after receiving "
            f"a response chunk ({previous_bytes}+{received_chunk_bytes}="
            f"{observed_bytes}, limit={limit_bytes}, reason={boundary_reason})"
        )
        self.previous_bytes = previous_bytes
        self.received_chunk_bytes = received_chunk_bytes
        self.observed_bytes = observed_bytes
        self.overshoot_bytes = max(0, observed_bytes - limit_bytes)
        self.boundary_reason = boundary_reason
        # Backward-compatible aliases for older evidence readers.
        self.current_bytes = observed_bytes
        self.next_bytes = received_chunk_bytes
        self.limit_bytes = limit_bytes


def _analysis_failure_should_retry(
    error: Exception,
    attempts: int,
) -> bool:
    return (
        attempts < 3
        and not isinstance(error, CodexNonRetryableInvocationError)
    )


class RadarPipeline:
    _BACKLOG_REASON_STAGES = {
        "transfer_budget_reached": {
            "official_query",
            "hosted_query",
            "hosted_verification",
            "content",
            "analysis",
        },
        "minimum_free_disk_boundary_reached": {
            "official_query",
            "hosted_query",
            "hosted_verification",
            "content",
            "analysis",
        },
        "content_item_budget_reached": {"content"},
        "runtime_budget_reached": {"all"},
        "analysis_budget_reached": {"analysis"},
    }
    _BACKLOG_STAGE_COMPONENTS = {
        "official_query": {
            "query_jobs.pending",
            "verification_tasks.pending",
            "work_scopes.admitted",
            "work_scopes.pending_analysis",
            "analysis_tasks.pending",
        },
        "hosted_query": {
            "query_jobs.pending",
            "verification_tasks.pending",
            "work_scopes.admitted",
            "work_scopes.pending_analysis",
            "analysis_tasks.pending",
        },
        "hosted_verification": {
            "verification_tasks.pending",
            "work_scopes.admitted",
            "work_scopes.pending_analysis",
            "analysis_tasks.pending",
        },
        "content": {
            "work_scopes.admitted",
            "work_scopes.pending_analysis",
            "analysis_tasks.pending",
        },
        "analysis": {
            "work_scopes.pending_analysis",
            "analysis_tasks.pending",
        },
        "all": {
            "query_jobs.pending",
            "verification_tasks.pending",
            "work_scopes.admitted",
            "work_scopes.pending_analysis",
            "analysis_tasks.pending",
        },
    }
    _BACKLOG_REASON_COMPONENT_OVERRIDES = {
        "content_item_budget_reached": {
            "work_scopes.admitted",
        },
        "analysis_budget_reached": {
            "work_scopes.pending_analysis",
            "analysis_tasks.pending",
        },
    }

    def __init__(
        self,
        settings: Settings,
        *,
        mode: str,
        include_official_sources: bool = True,
        include_hosted_search: bool = True,
        analysis_only: bool = False,
        limits: PipelineLimits | None = None,
        analysis_provider: str = "auto",
    ):
        if (
            not analysis_only
            and not include_official_sources
            and not include_hosted_search
        ):
            raise ValueError("at least one retrieval phase must be enabled")
        require_profile_production_activation(settings, mode)
        self.settings = settings
        self.mode = mode
        self.include_official_sources = include_official_sources
        self.include_hosted_search = include_hosted_search
        self.analysis_only = analysis_only
        self.limits = limits or PipelineLimits()
        self.analysis_provider = analysis_provider
        self.started_monotonic = time.monotonic()
        weekly_policy = (
            WeeklyIntakePolicy.from_config(settings.raw)
            if mode == "weekly"
            else None
        )
        self.store = RadarStore(settings.database_path)
        if analysis_only:
            self.run_mode = f"{mode}:analysis_only"
        elif not include_official_sources:
            self.run_mode = f"{mode}:hosted_supplement"
        elif not include_hosted_search:
            self.run_mode = f"{mode}:no_hosted"
        else:
            self.run_mode = mode
        self.run_id, self.resumed, self.lease_token = self.store.create_or_resume_run(
            settings,
            self.run_mode,
        )
        self.weekly_intake: WeeklyIntakeGate | None = None
        if weekly_policy is not None:
            run_record = self.store.run_record(self.run_id)
            if run_record is None:
                raise RuntimeError("weekly run identity disappeared after creation")
            started_at = datetime.fromisoformat(
                str(run_record["started_at"]).replace("Z", "+00:00")
            )
            self.weekly_intake = WeeklyIntakeGate(
                weekly_policy,
                now=started_at,
                admitted=self.store.admitted_run_intake_state(self.run_id),
            )
        self.run_dir = settings.outputs_dir / "runs" / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.audit = JsonlAuditLog(self.run_dir / "audit.jsonl")
        self.raw_store = RawResponseStore(settings.data_dir / "raw")
        self._clients: list[SafeHttpClient] = []
        self._source_clients: dict[str, SafeHttpClient] = {}
        self._content_clients: dict[str, SafeHttpClient] = {}
        self._fatal_error: str | None = None
        self._deferred_sources: set[str] = set()
        self._visible_backlog: dict[str, dict[str, Any]] = {}
        self._transfer_bytes_received = 0
        self._content_items_attempted = 0
        self._content_items_processed = 0
        self._retrieval_resource_exhausted = False
        self._interrupted = False

    def close(self) -> None:
        for client in self._clients:
            client.close()
        self.store.close()

    def __enter__(self) -> "RadarPipeline":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _expired(self) -> bool:
        return time.monotonic() - self.started_monotonic >= self.settings.max_runtime_seconds

    def _refresh_lease(self) -> None:
        self.store.refresh_run_lease(self.run_id, self.lease_token)

    def _run_resource_limit(self, key: str, default: int) -> int:
        return int(self.settings.raw.get("run", {}).get(key, default))

    def _transfer_observation_chunk_bytes(self) -> int:
        limit = self._run_resource_limit(
            "max_transfer_bytes_per_invocation",
            1024 * 1024 * 1024,
        )
        return min(
            SafeHttpClient.RESPONSE_CHUNK_BYTES,
            max(1, limit // 1024),
        )

    def _record_visible_backlog(
        self,
        reason_code: str,
        *,
        stage: str,
        **details: Any,
    ) -> None:
        allowed_stages = self._BACKLOG_REASON_STAGES.get(reason_code)
        if allowed_stages is None or stage not in allowed_stages:
            raise ValueError(
                f"invalid visible backlog reason/stage mapping: {reason_code}/{stage}"
            )
        if reason_code in self._visible_backlog:
            if self._visible_backlog[reason_code]["stage"] != stage:
                raise ValueError(
                    f"visible backlog reason already belongs to another stage: {reason_code}"
                )
            return
        payload = {"reason_code": reason_code, "stage": stage, **details}
        self._visible_backlog[reason_code] = payload
        self.audit.write(
            "visible_backlog_recorded",
            component="pipeline",
            run_id=self.run_id,
            severity="warning",
            details=payload,
        )

    def _consume_transfer_bytes(self, byte_count: int) -> None:
        amount = max(0, int(byte_count))
        limit = self._run_resource_limit(
            "max_transfer_bytes_per_invocation",
            1024 * 1024 * 1024,
        )
        previous = self._transfer_bytes_received
        self._transfer_bytes_received += amount
        if self._transfer_bytes_received > limit:
            raise TransferBudgetReached(
                previous_bytes=previous,
                received_chunk_bytes=amount,
                observed_bytes=self._transfer_bytes_received,
                limit_bytes=limit,
                boundary_reason="observation_chunk_exceeded_limit",
            )
        guard_band = self._transfer_observation_chunk_bytes()
        if limit - self._transfer_bytes_received < guard_band:
            raise TransferBudgetReached(
                previous_bytes=previous,
                received_chunk_bytes=amount,
                observed_bytes=self._transfer_bytes_received,
                limit_bytes=limit,
                boundary_reason="guard_band_reached",
            )

    def _record_transfer_backlog(
        self,
        exc: TransferBudgetReached,
        *,
        stage: str,
    ) -> None:
        self._retrieval_resource_exhausted = True
        self._record_visible_backlog(
            "transfer_budget_reached",
            stage=stage,
            observed_bytes=exc.observed_bytes,
            previous_bytes=exc.previous_bytes,
            boundary_crossing_chunk_bytes=exc.received_chunk_bytes,
            overshoot_bytes=exc.overshoot_bytes,
            boundary_reason=exc.boundary_reason,
            guard_band_bytes=self._transfer_observation_chunk_bytes(),
            limit_bytes=exc.limit_bytes,
        )

    def _resource_budget_available(self, *, stage: str) -> bool:
        if self._retrieval_resource_exhausted:
            return False
        transfer_limit = self._run_resource_limit(
            "max_transfer_bytes_per_invocation",
            1024 * 1024 * 1024,
        )
        guard_band = self._transfer_observation_chunk_bytes()
        if transfer_limit - self._transfer_bytes_received < guard_band:
            self._retrieval_resource_exhausted = True
            self._record_visible_backlog(
                "transfer_budget_reached",
                stage=stage,
                observed_bytes=self._transfer_bytes_received,
                previous_bytes=self._transfer_bytes_received,
                boundary_crossing_chunk_bytes=0,
                overshoot_bytes=0,
                boundary_reason="guard_band_before_request",
                guard_band_bytes=guard_band,
                limit_bytes=transfer_limit,
            )
            return False
        minimum_free = self._run_resource_limit(
            "minimum_free_disk_bytes",
            10 * 1024 * 1024 * 1024,
        )
        free_bytes = int(shutil.disk_usage(self.settings.data_dir).free)
        if free_bytes < minimum_free:
            self._retrieval_resource_exhausted = True
            self._record_visible_backlog(
                "minimum_free_disk_boundary_reached",
                stage=stage,
                free_bytes=free_bytes,
                minimum_free_bytes=minimum_free,
            )
            return False
        return True

    def _content_budget_available(self, attempted_items: int) -> bool:
        content_limit = self._run_resource_limit(
            "max_content_items_per_invocation",
            100,
        )
        if attempted_items >= content_limit:
            self._record_visible_backlog(
                "content_item_budget_reached",
                stage="content",
                attempted_items=attempted_items,
                limit_items=content_limit,
            )
            return False
        return self._resource_budget_available(stage="content")

    def run(self) -> dict[str, Any]:
        self.audit.write(
            "run_started",
            component="pipeline",
            run_id=self.run_id,
            details={
                "mode": self.mode,
                "run_mode": self.run_mode,
                "source_phases": {
                    "official": self.include_official_sources,
                    "hosted_supplement": self.include_hosted_search,
                    "analysis_only": self.analysis_only,
                },
                "resumed": self.resumed,
                "config_hash": self.settings.config_hash,
                "retrieval_hash": self.settings.retrieval_hash,
                "analysis_policy_hash": self.settings.analysis_policy_hash,
                "limits": asdict(self.limits),
                "resource_limits": {
                    "max_content_items_per_invocation": self._run_resource_limit(
                        "max_content_items_per_invocation",
                        100,
                    ),
                    "max_transfer_bytes_per_invocation": self._run_resource_limit(
                        "max_transfer_bytes_per_invocation",
                        1024 * 1024 * 1024,
                    ),
                    "minimum_free_disk_bytes": self._run_resource_limit(
                        "minimum_free_disk_bytes",
                        10 * 1024 * 1024 * 1024,
                    ),
                },
                "weekly_intake": (
                    self.weekly_intake.snapshot()
                    if self.weekly_intake is not None
                    else None
                ),
            },
        )
        try:
            self._refresh_lease()
            if not self.analysis_only:
                self.store.seed_query_jobs(
                    self.run_id,
                    self.settings,
                    self.include_hosted_search,
                    lease_token=self.lease_token,
                    smoke=self.mode == "smoke",
                    include_official=self.include_official_sources,
                )
                query_coverage = self.store.query_job_coverage(
                    self.run_id,
                    self.settings,
                )
                if not query_coverage["plan_complete"]:
                    raise RuntimeError(
                        "query plan persistence is incomplete: "
                        f"{query_coverage['missing_jobs']}"
                    )
                if self.include_official_sources:
                    self._collect_official_sources()
                if self.include_hosted_search and not self._expired():
                    self._refresh_lease()
                    self._collect_hosted_search()
                if not self._expired():
                    self._refresh_lease()
                    self._collect_content()
            if not self._expired():
                self._refresh_lease()
                self._analyze_ready_content()
        except RunAlreadyActiveError:
            self.audit.write(
                "run_superseded",
                component="pipeline",
                run_id=self.run_id,
                severity="warning",
                details={"reason": "run lease ownership was lost"},
            )
            raise
        except KeyboardInterrupt:
            self._interrupted = True
            self.audit.write(
                "run_interrupted",
                component="pipeline",
                run_id=self.run_id,
                severity="warning",
                details={"reason": "keyboard_interrupt"},
            )
        except Exception as exc:
            self._fatal_error = f"{type(exc).__name__}: {str(exc)[:2000]}"
            self.audit.write(
                "run_fatal_error",
                component="pipeline",
                run_id=self.run_id,
                severity="error",
                details={"error": self._fatal_error},
            )
        if self._expired():
            elapsed_seconds = round(
                time.monotonic() - self.started_monotonic,
                3,
            )
            self._record_visible_backlog(
                "runtime_budget_reached",
                stage="all",
                metric="elapsed_seconds",
                actual=elapsed_seconds,
                limit=self.settings.max_runtime_seconds,
                elapsed_seconds=elapsed_seconds,
                max_runtime_seconds=self.settings.max_runtime_seconds,
            )
        backlog_accounting = self._backlog_accounting()
        pending = bool(backlog_accounting["present"])
        attention = self._has_attention()
        if self._interrupted:
            final_status = "paused"
            paused = True
        elif self._fatal_error:
            paused = pending
            final_status = "paused_with_error" if paused else "failed"
        elif pending and backlog_accounting["explained"]:
            paused = False
            final_status = "completed_with_gaps"
        elif pending:
            paused = True
            final_status = "paused"
        elif attention:
            paused = False
            final_status = "completed_with_gaps"
        else:
            paused = False
            final_status = "completed"
        if final_status in {"completed", "completed_with_gaps"}:
            summary = self._write_summary(
                status=final_status,
                pending=pending,
                attention=attention,
                backlog_accounting=backlog_accounting,
            )
            publication_candidates = prepare_run_publication_candidates(
                self.settings,
                self.store,
            )
            self.store.complete_run_with_publication_snapshot(
                self.run_id,
                lease_token=self.lease_token,
                terminal_status=final_status,
                error=self._fatal_error,
                retrieval_hash=self.settings.retrieval_hash,
                analysis_policy_hash=self.settings.analysis_policy_hash,
                summary=summary,
                candidates=publication_candidates,
            )
        elif paused:
            self.store.pause_or_complete_run(
                self.run_id,
                paused=True,
                error=self._fatal_error,
                lease_token=self.lease_token,
                status_override=final_status,
            )
            summary = self._write_summary(
                status=final_status,
                pending=pending,
                attention=attention,
                backlog_accounting=backlog_accounting,
            )
        else:
            summary = self._write_summary(
                status=final_status,
                pending=pending,
                attention=attention,
                backlog_accounting=backlog_accounting,
            )
            self.store.pause_or_complete_run(
                self.run_id,
                paused=False,
                error=self._fatal_error,
                lease_token=self.lease_token,
                status_override=final_status,
            )
        if self.mode in {"run", "weekly"}:
            if final_status in {"completed", "completed_with_gaps"}:
                try:
                    publication = generate_weekly_report(
                        self.settings,
                        self.store,
                        run_id=self.run_id,
                        run_summary=summary,
                    )
                    summary["publication"] = {
                        "status": "published",
                        **publication,
                    }
                except Exception as exc:
                    summary["attention_required"] = True
                    summary["publication"] = {
                        "status": "failed",
                        "error": f"{type(exc).__name__}: {str(exc)[:2000]}",
                    }
                    self.audit.write(
                        "run_publication_failed",
                        component="report",
                        run_id=self.run_id,
                        severity="error",
                        details=summary["publication"],
                    )
            else:
                summary["publication"] = {
                    "status": "not_eligible",
                    "reason": f"run terminal status is {final_status}",
                }
            self._persist_summary(summary)
        self.audit.write(
            "run_finished",
            component="pipeline",
            run_id=self.run_id,
            severity="error" if self._fatal_error else "info",
            details=summary,
        )
        return summary

    def _new_source_client(self, source: str) -> SafeHttpClient:
        if source in self._source_clients:
            return self._source_clients[source]
        config = self.settings.raw["sources"][source]
        client = SafeHttpClient(
            source=source,
            delay_seconds=float(config["delay_seconds"]),
            raw_store=self.raw_store,
            audit=self.audit,
            run_id=self.run_id,
            slot_reserver=self.store.reserve_http_rate_slot,
            byte_consumer=self._consume_transfer_bytes,
            observation_chunk_bytes=self._transfer_observation_chunk_bytes(),
            deadline_monotonic=(
                self.started_monotonic + self.settings.max_runtime_seconds
            ),
        )
        self._source_clients[source] = client
        self._clients.append(client)
        return client

    def _collect_official_sources(self) -> None:
        source_objects: dict[str, Any] = {}
        if self.settings.raw["sources"]["openalex"]["enabled"]:
            if os.getenv("OPENALEX_API_KEY", "").strip():
                source_objects["openalex"] = OpenAlexSource(
                    self._new_source_client("openalex"),
                    self.settings.raw["sources"]["openalex"],
                    int(self.settings.raw["time_policy"]["technical_from_year"]),
                )
            else:
                blocked = self.store.block_query_jobs(
                    self.run_id,
                    lease_token=self.lease_token,
                    source="openalex",
                    reason="OPENALEX_API_KEY is not configured",
                )
                self.audit.write(
                    "source_blocked_missing_credential",
                    component="collector",
                    run_id=self.run_id,
                    severity="warning",
                    details={
                        "source": "openalex",
                        "environment_variable": "OPENALEX_API_KEY",
                        "blocked_jobs": blocked,
                    },
                )
        if self.settings.raw["sources"]["arxiv"]["enabled"]:
            source_objects["arxiv"] = ArxivSource(
                self._new_source_client("arxiv"),
                self.settings.raw["sources"]["arxiv"],
            )
        if self.settings.raw["sources"]["github"]["enabled"]:
            source_objects["github"] = GitHubSource(
                self._new_source_client("github"),
                self.settings.raw["sources"]["github"],
            )
        made_progress = True
        while made_progress and not self._expired():
            made_progress = False
            for source_name, source in source_objects.items():
                if (
                    self._expired()
                    or self._retrieval_resource_exhausted
                    or not self._resource_budget_available(stage="official_query")
                ):
                    return
                self._refresh_lease()
                if source_name in self._deferred_sources:
                    continue
                job = self.store.claim_query_job(
                    self.run_id,
                    self.lease_token,
                    job_kind="official",
                    source=source_name,
                )
                if job is None:
                    continue
                made_progress = True
                self._run_official_job(source, job)

    def _run_official_job(self, source: Any, job: dict[str, Any]) -> None:
        self.audit.write(
            "query_job_started",
            component="collector",
            run_id=self.run_id,
            details={
                "job_id": job["id"],
                "query_id": job["query_id"],
                "source": job["source"],
                "cursor": job.get("cursor"),
            },
        )
        try:
            saw_page = False
            source_job = (
                self.weekly_intake.source_job(job)
                if self.weekly_intake is not None
                else job
            )
            result_limit = self.limits.results_per_query
            if self.weekly_intake is not None:
                result_limit = self.weekly_intake.retrieval_limit(
                    job,
                    result_limit,
                )
            for page in source.pages(source_job, result_limit=result_limit):
                self._refresh_lease()
                saw_page = True
                for record in page.records:
                    decision = objective_admission(record, self.settings.raw)
                    intake_reservation = None
                    if self.weekly_intake is not None:
                        existing_work_id = self.store.lookup_record_work_id(
                            record
                        )
                        decision, intake_reservation = self.weekly_intake.reserve(
                            record,
                            decision,
                            query_lane=str(job["lane"]),
                            identity_key=(
                                f"work:{existing_work_id}"
                                if existing_work_id is not None
                                else None
                            ),
                        )
                    try:
                        work_id, _ = self.store.ingest_record(
                            run_id=self.run_id,
                            lease_token=self.lease_token,
                            query_job_id=int(job["id"]),
                            record=record,
                            decision=decision,
                            raw_sha256=page.receipt.sha256,
                            raw_path=page.receipt.path,
                        )
                        if self.weekly_intake is not None:
                            self.weekly_intake.commit(
                                intake_reservation,
                                stable_identity_key=f"work:{work_id}",
                            )
                    except BaseException:
                        if self.weekly_intake is not None:
                            self.weekly_intake.rollback(intake_reservation)
                        raise
                self.store.update_query_job(
                    int(job["id"]),
                    status="completed" if page.exhausted else "running",
                    cursor=page.next_cursor,
                    page_no=page.page_no,
                    result_count_delta=len(page.records),
                    lease_token=self.lease_token,
                )
                if self._expired():
                    if not page.exhausted:
                        self.store.update_query_job(
                            int(job["id"]),
                            status="pending",
                            lease_token=self.lease_token,
                        )
                    return
            if not saw_page:
                self._refresh_lease()
                self.store.update_query_job(
                    int(job["id"]),
                    status="completed",
                    page_no=int(job.get("page_no") or 0),
                    lease_token=self.lease_token,
                )
            self.audit.write(
                "query_job_completed",
                component="collector",
                run_id=self.run_id,
                details={"job_id": job["id"], "source": job["source"]},
            )
        except RunAlreadyActiveError:
            raise
        except TransferBudgetReached as exc:
            self.store.update_query_job(
                int(job["id"]),
                status="pending",
                error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                lease_token=self.lease_token,
            )
            self._record_transfer_backlog(exc, stage="official_query")
            self.audit.write(
                "query_job_paused_resource_budget",
                component="collector",
                run_id=self.run_id,
                severity="warning",
                details={
                    "job_id": job["id"],
                    "source": job["source"],
                    "reason": str(exc),
                },
            )
        except RetryDeferredError as exc:
            not_before = (
                datetime.now(timezone.utc) + timedelta(seconds=exc.retry_after_seconds)
            ).isoformat(timespec="seconds")
            self.store.update_query_job(
                int(job["id"]),
                status="retry",
                error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                not_before=not_before,
                lease_token=self.lease_token,
            )
            self.store.set_source_cooldown(
                str(job["source"]),
                not_before=not_before,
                reason=f"{type(exc).__name__}: {str(exc)[:1000]}",
            )
            self._deferred_sources.add(str(job["source"]))
            self.audit.write(
                "query_job_deferred",
                component="collector",
                run_id=self.run_id,
                severity="warning",
                details={
                    "job_id": job["id"],
                    "source": job["source"],
                    "retry_after_seconds": exc.retry_after_seconds,
                    "not_before": not_before,
                },
            )
        except NonRetryableFetchError as exc:
            self.store.update_query_job(
                int(job["id"]),
                status="failed",
                error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                lease_token=self.lease_token,
            )
            self.audit.write(
                "query_job_terminal_failure",
                component="collector",
                run_id=self.run_id,
                severity="error",
                details={
                    "job_id": job["id"],
                    "source": job["source"],
                    "error": f"{type(exc).__name__}: {str(exc)[:500]}",
                },
            )
        except Exception as exc:
            attempts = int(job.get("attempts") or 0) + 1
            retry = attempts < 3
            self.store.update_query_job(
                int(job["id"]),
                status="retry" if retry else "failed",
                error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                lease_token=self.lease_token,
            )
            self.audit.write(
                "query_job_failed",
                component="collector",
                run_id=self.run_id,
                severity="warning" if retry else "error",
                details={
                    "job_id": job["id"],
                    "source": job["source"],
                    "attempts": attempts,
                    "retry": retry,
                    "error": f"{type(exc).__name__}: {str(exc)[:500]}",
                },
            )

    def _make_codex(self) -> CodexCli | None:
        try:
            codex = CodexCli(self.settings, self.audit, self.run_id)
        except CodexInvocationError as exc:
            self.audit.write(
                "codex_unavailable",
                component="codex",
                run_id=self.run_id,
                severity="warning",
                details={"reason": str(exc)},
            )
            return None
        if not codex.authenticated():
            self.audit.write(
                "codex_unauthenticated",
                component="codex",
                run_id=self.run_id,
                severity="warning",
                details={"reason": "Pinned Codex CLI is not logged in."},
            )
            return None
        return codex

    def _collect_hosted_search(self) -> None:
        verifier = HostedResultVerifier(
            self._content_client_for_url,
            ArxivSource(
                self._new_source_client("arxiv"),
                self.settings.raw["sources"]["arxiv"],
            ),
            GitHubSource(
                self._new_source_client("github"),
                self.settings.raw["sources"]["github"],
            ),
        )
        codex = self._make_codex()
        if codex is not None:
            searcher = CodexHostedSearch(self.settings, codex)
            completed = 0
            while not self._expired():
                if (
                    self._retrieval_resource_exhausted
                    or not self._resource_budget_available(stage="hosted_query")
                ):
                    break
                if self.limits.hosted_jobs is not None and completed >= self.limits.hosted_jobs:
                    break
                job = self.store.claim_query_job(
                    self.run_id,
                    self.lease_token,
                    job_kind="hosted",
                )
                if job is None:
                    break
                try:
                    self._refresh_lease()
                    search_job = (
                        self.weekly_intake.source_job(job)
                        if self.weekly_intake is not None
                        else job
                    )
                    records, receipt = searcher.search(search_job)
                    if self.weekly_intake is not None:
                        hosted_limit = self.weekly_intake.retrieval_limit(
                            job,
                            self.limits.results_per_query,
                        )
                        records = records[:hosted_limit]
                        receipt = {
                            **receipt,
                            "weekly_query_cap": hosted_limit,
                            "result_count": len(records),
                        }
                    self.store.record_model_invocation(
                        run_id=self.run_id,
                        lease_token=self.lease_token,
                        receipt=receipt,
                    )
                    self._refresh_lease()
                    for record in records:
                        pending = AdmissionDecision(
                            admitted=False,
                            code="hosted_verification_pending",
                            lane="verification_pending",
                            reason="Hosted discovery awaits primary-source verification.",
                        )
                        work_id, _ = self.store.ingest_record(
                            run_id=self.run_id,
                            lease_token=self.lease_token,
                            query_job_id=int(job["id"]),
                            record=record,
                            decision=pending,
                            raw_sha256=None,
                        )
                        self.store.seed_verification_task(
                            run_id=self.run_id,
                            lease_token=self.lease_token,
                            query_job_id=int(job["id"]),
                            work_id=work_id,
                        )
                    self.store.update_query_job(
                        int(job["id"]),
                        status="completed",
                        page_no=1,
                        result_count_delta=len(records),
                        lease_token=self.lease_token,
                    )
                    self.audit.write(
                        "hosted_search_discoveries_persisted",
                        component="verification",
                        run_id=self.run_id,
                        details={
                            "query_id": job["query_id"],
                            "discovered_count": len(records),
                            "dropped_by_domain_count": len(
                                receipt.get("dropped_results") or []
                            ),
                        },
                    )
                    completed += 1
                except RunAlreadyActiveError:
                    raise
                except TransferBudgetReached as exc:
                    self.store.update_query_job(
                        int(job["id"]),
                        status="pending",
                        error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                        lease_token=self.lease_token,
                    )
                    self._record_transfer_backlog(exc, stage="hosted_query")
                    break
                except Exception as exc:
                    attempts = int(job.get("attempts") or 0) + 1
                    retry = attempts < 2
                    self.store.update_query_job(
                        int(job["id"]),
                        status="retry" if retry else "failed",
                        error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                        lease_token=self.lease_token,
                    )
                    self.audit.write(
                        "hosted_search_failed",
                        component="codex",
                        run_id=self.run_id,
                        severity="warning" if retry else "error",
                        details={
                            "job_id": job["id"],
                            "attempts": attempts,
                            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
                        },
                    )
                    if retry:
                        break
        self._verify_hosted_tasks(verifier)

    def _verify_hosted_tasks(self, verifier: HostedResultVerifier) -> None:
        while not self._expired():
            if (
                self._retrieval_resource_exhausted
                or not self._resource_budget_available(stage="hosted_verification")
            ):
                return
            task = self.store.claim_verification_task(
                self.run_id,
                self.lease_token,
            )
            if task is None:
                return
            record = SourceRecord(
                source="codex_web",
                source_id=f"work-{task['work_id']}",
                kind=str(task["kind"]),
                title=str(task["title"]),
                query_id=str(task["query_id"]),
                year=task.get("year"),
                canonical_url=task.get("best_url"),
                doi=task.get("doi"),
                arxiv_id=task.get("arxiv_id"),
                github_full_name=task.get("github_full_name"),
                pdf_url=task.get("pdf_url"),
                metadata=json.loads(task.get("metadata_json") or "{}"),
            )
            try:
                self._refresh_lease()
                verified, receipt = verifier.verify(record)
                self._refresh_lease()
                decision = objective_admission(verified, self.settings.raw)
                intake_reservation = None
                if self.weekly_intake is not None:
                    existing_work_id = self.store.lookup_record_work_id(
                        verified
                    )
                    decision, intake_reservation = self.weekly_intake.reserve(
                        verified,
                        decision,
                        query_lane=str(task["query_lane"]),
                        identity_key=(
                            f"work:{existing_work_id}"
                            if existing_work_id is not None
                            else None
                        ),
                    )
                try:
                    verified_work_id, _ = self.store.ingest_record(
                        run_id=self.run_id,
                        lease_token=self.lease_token,
                        query_job_id=int(task["query_job_id"]),
                        record=verified,
                        decision=decision,
                        raw_sha256=receipt.sha256,
                        raw_path=receipt.path,
                    )
                    if self.weekly_intake is not None:
                        self.weekly_intake.commit(
                            intake_reservation,
                            stable_identity_key=f"work:{verified_work_id}",
                        )
                except BaseException:
                    if self.weekly_intake is not None:
                        self.weekly_intake.rollback(intake_reservation)
                    raise
                self.store.resolve_verification_task(
                    int(task["id"]),
                    pending_work_id=int(task["work_id"]),
                    verified_work_id=verified_work_id,
                    decision=decision,
                    lease_token=self.lease_token,
                )
                self.audit.write(
                    "hosted_result_verified",
                    component="verification",
                    run_id=self.run_id,
                    details={
                        "task_id": task["id"],
                        "work_id": task["work_id"],
                        "verified_work_id": verified_work_id,
                        "decision_code": decision.code,
                        "admitted": decision.admitted,
                        "verified_source": verified.source,
                        "verification_sha256": receipt.sha256,
                    },
                )
            except RunAlreadyActiveError:
                raise
            except TransferBudgetReached as exc:
                self.store.update_verification_task(
                    int(task["id"]),
                    status="pending",
                    error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                    not_before=None,
                    lease_token=self.lease_token,
                )
                self._record_transfer_backlog(exc, stage="hosted_verification")
                return
            except HostedVerificationRejectedError as exc:
                decision = AdmissionDecision(
                    admitted=False,
                    code=exc.code,
                    lane="rejected",
                    reason=exc.reason,
                )
                self.store.resolve_verification_task(
                    int(task["id"]),
                    pending_work_id=int(task["work_id"]),
                    verified_work_id=int(task["work_id"]),
                    decision=decision,
                    lease_token=self.lease_token,
                )
                self.audit.write(
                    "hosted_result_rejected",
                    component="verification",
                    run_id=self.run_id,
                    severity="warning",
                    details={
                        "task_id": task["id"],
                        "work_id": task["work_id"],
                        "decision_code": decision.code,
                        "reason": decision.reason,
                    },
                )
            except RetryDeferredError as exc:
                not_before = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=exc.retry_after_seconds)
                ).isoformat(timespec="seconds")
                self.store.update_verification_task(
                    int(task["id"]),
                    status="retry",
                    error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                    not_before=not_before,
                    lease_token=self.lease_token,
                )
                self.audit.write(
                    "hosted_result_verification_deferred",
                    component="verification",
                    run_id=self.run_id,
                    severity="warning",
                    details={
                        "task_id": task["id"],
                        "work_id": task["work_id"],
                        "not_before": not_before,
                    },
                )
            except Exception as exc:
                attempts = int(task.get("attempts") or 0) + 1
                retry = attempts < 3
                not_before = None
                if retry:
                    not_before = (
                        datetime.now(timezone.utc) + timedelta(minutes=5)
                    ).isoformat(timespec="seconds")
                self.store.update_verification_task(
                    int(task["id"]),
                    status="retry" if retry else "failed",
                    error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                    not_before=not_before,
                    lease_token=self.lease_token,
                )
                self.audit.write(
                    "hosted_result_verification_failed",
                    component="verification",
                    run_id=self.run_id,
                    severity="warning" if retry else "error",
                    details={
                        "task_id": task["id"],
                        "work_id": task["work_id"],
                        "attempts": attempts,
                        "retry": retry,
                        "error": f"{type(exc).__name__}: {str(exc)[:500]}",
                    },
                )

    def _content_client_for_url(self, url: str) -> SafeHttpClient:
        host = (urlsplit(url).hostname or "unknown").casefold()
        if host not in self._content_clients:
            client = SafeHttpClient(
                source=f"content-{host}",
                delay_seconds=2.0,
                raw_store=self.raw_store,
                audit=self.audit,
                run_id=self.run_id,
                timeout_seconds=120,
                max_attempts=3,
                slot_reserver=self.store.reserve_http_rate_slot,
                byte_consumer=self._consume_transfer_bytes,
                observation_chunk_bytes=self._transfer_observation_chunk_bytes(),
                deadline_monotonic=(
                    self.started_monotonic + self.settings.max_runtime_seconds
                ),
            )
            self._content_clients[host] = client
            self._clients.append(client)
        return self._content_clients[host]

    def _collect_content(self) -> None:
        processor = ContentProcessor(
            self.settings,
            self._content_client_for_url,
            self.audit,
            self.run_id,
            heartbeat=self._refresh_lease,
        )
        count = 0
        while not self._expired():
            if not self._content_budget_available(count):
                return
            if self.limits.content_items is not None and count >= self.limits.content_items:
                return
            self._refresh_lease()
            work = self.store.claim_work_for_content(
                self.settings.retrieval_hash,
                run_id=self.run_id,
                lease_token=self.lease_token,
            )
            if work is None:
                return
            count += 1
            self._content_items_attempted = count
            try:
                result = processor.process(work)
            except TransferBudgetReached as exc:
                self.store.pause_content_work_for_resource(
                    int(work["id"]),
                    retrieval_hash=self.settings.retrieval_hash,
                    run_id=self.run_id,
                    lease_token=self.lease_token,
                    error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                )
                self._record_transfer_backlog(exc, stage="content")
                return
            except RetryDeferredError as exc:
                not_before = (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=exc.retry_after_seconds)
                ).isoformat(timespec="seconds")
                self.store.defer_content_work(
                    int(work["id"]),
                    retrieval_hash=self.settings.retrieval_hash,
                    run_id=self.run_id,
                    lease_token=self.lease_token,
                    not_before=not_before,
                    error=f"{type(exc).__name__}: {str(exc)[:1000]}",
                )
                self.audit.write(
                    "content_deferred",
                    component="content",
                    run_id=self.run_id,
                    severity="warning",
                    details={
                        "work_id": work["id"],
                        "retry_after_seconds": exc.retry_after_seconds,
                        "not_before": not_before,
                    },
                )
                continue
            self.store.save_document(
                work_id=int(work["id"]),
                content_kind=result.content_kind,
                status=result.status,
                source_url=result.source_url,
                local_path=result.local_path,
                text_path=result.text_path,
                content_sha256=result.content_sha256,
                text_sha256=result.text_sha256,
                byte_count=result.byte_count,
                text_char_count=result.text_char_count,
                page_count=result.page_count,
                coverage=result.coverage,
                error=result.error,
                run_id=self.run_id,
                lease_token=self.lease_token,
            )
            self._content_items_processed += 1
            self.audit.write(
                "content_processed",
                component="content",
                run_id=self.run_id,
                severity="info" if result.status == "ready" else "warning",
                details={
                    "work_id": work["id"],
                    "kind": work["kind"],
                    "status": result.status,
                    "content_sha256": result.content_sha256,
                    "text_sha256": result.text_sha256,
                    "error": result.error,
                },
            )

    def _select_analysis_runner(self) -> tuple[str, Any] | None:
        if self.analysis_provider not in {"auto", "codex_cli", "llama_cpp"}:
            raise ValueError("analysis_provider must be auto, codex_cli, or llama_cpp")
        if self.analysis_provider in {"auto", "codex_cli"}:
            codex = self._make_codex()
            if codex is not None:
                return "codex_cli", codex
            if self.analysis_provider == "codex_cli":
                return None
        llama = LlamaCppRunner(self.settings, self.audit, self.run_id)
        if llama.health():
            self.audit.write(
                "analysis_fallback_selected",
                component="pipeline",
                run_id=self.run_id,
                severity="warning",
                details={"provider": "llama_cpp", "reason": "Codex unavailable"},
            )
            return "llama_cpp", llama
        self.audit.write(
            "no_analysis_provider",
            component="pipeline",
            run_id=self.run_id,
            severity="warning",
            details={"codex_available": False, "llama_cpp_healthy": False},
        )
        return None

    def _analyze_ready_content(self) -> None:
        if self.limits.analysis_items == 0:
            return
        if not self._resource_budget_available(stage="analysis"):
            return
        selected = self._select_analysis_runner()
        if selected is None:
            return
        provider, runner = selected
        prompt_version = str(self.settings.raw["analysis"]["prompt_version"])
        if provider == "llama_cpp":
            superseded = self.store.supersede_analysis_tasks(
                analysis_policy_hash=self.settings.analysis_policy_hash,
                replacement_provider=provider,
            )
            if superseded:
                self.audit.write(
                    "analysis_tasks_superseded_for_fallback",
                    component="pipeline",
                    run_id=self.run_id,
                    severity="warning",
                    details={
                        "replacement_provider": provider,
                        "superseded_count": superseded,
                    },
                )
        self.store.seed_analysis_tasks(
            provider,
            prompt_version,
            analysis_policy_hash=self.settings.analysis_policy_hash,
            retrieval_hash=self.settings.retrieval_hash,
            profile_id=self.settings.profile_id,
            profile_version=self.settings.profile_version,
        )
        reader = CodexDeepReader(
            self.settings,
            self.store,
            runner,
            self.audit,
            self.run_id,
            self.lease_token,
            provider_name=provider,
            deadline_monotonic=(
                self.started_monotonic + self.settings.max_runtime_seconds
            ),
        )
        count = 0
        consecutive_failures = 0
        while not self._expired():
            if not self._resource_budget_available(stage="analysis"):
                return
            if self.limits.analysis_items is not None and count >= self.limits.analysis_items:
                return
            task = self.store.claim_analysis_task(
                provider,
                config_hash=self.settings.analysis_policy_hash,
                run_id=self.run_id,
                lease_token=self.lease_token,
            )
            if task is None:
                if self._wait_for_analysis_retry(provider):
                    continue
                return
            try:
                self._refresh_lease()
                reader.analyze(task)
                count += 1
                consecutive_failures = 0
            except RunAlreadyActiveError:
                raise
            except AnalysisBudgetPaused as exc:
                self.store.pause_analysis_task(
                    int(task["id"]),
                    str(exc),
                    run_id=self.run_id,
                    lease_token=self.lease_token,
                )
                self.audit.write(
                    "analysis_paused_budget",
                    component="analysis",
                    run_id=self.run_id,
                    severity="warning",
                    details={
                        "task_id": task["id"],
                        "work_id": task["work_id"],
                        "provider": provider,
                        "reason": str(exc),
                        "boundary_reason": exc.boundary_reason,
                        "metric": exc.metric,
                        "actual": exc.actual,
                        "limit": exc.limit,
                    },
                )
                self._record_visible_backlog(
                    "analysis_budget_reached",
                    stage="analysis",
                    task_id=int(task["id"]),
                    work_id=int(task["work_id"]),
                    provider=provider,
                    reason=str(exc),
                    boundary_reason=exc.boundary_reason,
                    metric=exc.metric,
                    actual=exc.actual,
                    limit=exc.limit,
                )
                return
            except Exception as exc:
                attempts = self.store.analysis_task_attempts(int(task["id"]))
                retry = _analysis_failure_should_retry(exc, attempts)
                self.store.fail_analysis_task(
                    int(task["id"]),
                    f"{type(exc).__name__}: {str(exc)[:1500]}",
                    run_id=self.run_id,
                    lease_token=self.lease_token,
                    retry=retry,
                )
                self.audit.write(
                    "analysis_failed",
                    component="analysis",
                    run_id=self.run_id,
                    severity="warning" if retry else "error",
                    details={
                        "task_id": task["id"],
                        "work_id": task["work_id"],
                        "provider": provider,
                        "attempts": attempts,
                        "retry": retry,
                        "error": f"{type(exc).__name__}: {str(exc)[:800]}",
                    },
                )
                consecutive_failures += 1
                if consecutive_failures >= 3:
                    return

    def _wait_for_analysis_retry(self, provider: str) -> bool:
        not_before = self.store.next_analysis_retry_at(
            provider,
            config_hash=self.settings.analysis_policy_hash,
            run_id=self.run_id,
            lease_token=self.lease_token,
        )
        if not not_before:
            return False
        try:
            retry_at = datetime.fromisoformat(
                str(not_before).replace("Z", "+00:00")
            )
        except ValueError:
            return False
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        retry_at = retry_at.astimezone(timezone.utc)
        wait_seconds = max(
            0.0,
            (retry_at - datetime.now(timezone.utc)).total_seconds(),
        )
        remaining_seconds = (
            self.settings.max_runtime_seconds
            - (time.monotonic() - self.started_monotonic)
        )
        cleanup_margin = int(
            self.settings.raw["analysis"].get(
                "cleanup_margin_seconds",
                120,
            )
        )
        if wait_seconds + cleanup_margin >= remaining_seconds:
            return False
        self.audit.write(
            "analysis_retry_wait_started",
            component="analysis",
            run_id=self.run_id,
            details={
                "provider": provider,
                "not_before": not_before,
                "wait_seconds": round(wait_seconds, 3),
            },
        )
        while not self._expired():
            wait_seconds = (
                retry_at - datetime.now(timezone.utc)
            ).total_seconds()
            if wait_seconds <= 0:
                return True
            self._refresh_lease()
            time.sleep(min(15.0, wait_seconds))
        return False

    def _pending_backlog_components(self) -> dict[str, int]:
        query_counts = self.store.pending_job_counts(self.run_id)
        verification_counts = self.store.verification_task_counts(self.run_id)
        analysis_counts = self.store.analysis_task_counts(
            self.settings.analysis_policy_hash
        )
        scope_counts = self.store.work_scope_state_counts(
            self.settings.retrieval_hash
        )
        owned_claims = self.store.run_owned_claim_counts(
            self.run_id,
            self.lease_token,
        )
        dashboard = self.store.dashboard_counts(
            self.settings.retrieval_hash,
            analysis_policy_hash=self.settings.analysis_policy_hash,
        )
        return {
            "query_jobs.pending": query_counts.get("pending", 0),
            "query_jobs.retry": query_counts.get("retry", 0),
            "query_jobs.running": query_counts.get("running", 0),
            "verification_tasks.pending": verification_counts.get("pending", 0),
            "verification_tasks.retry": verification_counts.get("retry", 0),
            "verification_tasks.running": verification_counts.get("running", 0),
            "work_scopes.admitted": scope_counts.get("admitted", 0),
            "work_scopes.content_retry": scope_counts.get("content_retry", 0),
            "work_scopes.content_running": scope_counts.get("content_running", 0),
            "work_scopes.analysis_running": scope_counts.get(
                "analysis_running",
                0,
            ),
            "work_scopes.pending_analysis": dashboard["pending_analysis"],
            "analysis_tasks.pending": analysis_counts.get("pending", 0),
            "analysis_tasks.retry": analysis_counts.get("retry", 0),
            "analysis_tasks.running": analysis_counts.get("running", 0),
            "owned_claims.query_jobs": owned_claims["query_jobs"],
            "owned_claims.verification_tasks": owned_claims[
                "verification_tasks"
            ],
            "owned_claims.analysis_tasks": owned_claims["analysis_tasks"],
            "owned_claims.work_scopes": owned_claims["work_scopes"],
        }

    def _backlog_accounting(
        self,
        *,
        accounted_at: str = "pre_finalization",
    ) -> dict[str, Any]:
        components = self._pending_backlog_components()
        positive = {key: value for key, value in components.items() if value > 0}
        covered_keys: set[str] = set()
        reasons: list[dict[str, Any]] = []
        for payload in self._visible_backlog.values():
            stage = str(payload["stage"])
            permitted = self._BACKLOG_REASON_COMPONENT_OVERRIDES.get(
                str(payload["reason_code"]),
                self._BACKLOG_STAGE_COMPONENTS[stage],
            )
            covered = {
                key: value
                for key, value in positive.items()
                if key in permitted
            }
            covered_keys.update(covered)
            reasons.append(
                {
                    **payload,
                    "covered_components": covered,
                }
            )
        unexplained = {
            key: value
            for key, value in positive.items()
            if key not in covered_keys
        }
        present = bool(positive)
        explained = bool(present and reasons and not unexplained)
        return {
            "accounted_at": accounted_at,
            "present": present,
            "explained": explained,
            "components": components,
            "covered_components": {
                key: value
                for key, value in positive.items()
                if key in covered_keys
            },
            "unexplained_components": unexplained,
            "reason_codes": [str(reason["reason_code"]) for reason in reasons],
            "reasons": reasons,
        }

    def _has_pending_work(self) -> bool:
        return bool(self._backlog_accounting()["present"])

    def _has_attention(self) -> bool:
        query_counts = self.store.pending_job_counts(self.run_id)
        verification_counts = self.store.verification_task_counts(self.run_id)
        dashboard = self.store.dashboard_counts(
            self.settings.retrieval_hash,
            analysis_policy_hash=self.settings.analysis_policy_hash,
        )
        return bool(
            query_counts.get("failed", 0)
            or query_counts.get("blocked", 0)
            or verification_counts.get("failed", 0)
            or dashboard.get("analysis_failed", 0)
            or dashboard.get("unverified", 0)
        )

    def _write_summary(
        self,
        *,
        status: str,
        pending: bool,
        attention: bool,
        backlog_accounting: dict[str, Any],
    ) -> dict[str, Any]:
        query_jobs = self.store.pending_job_counts(self.run_id)
        query_coverage = self.store.query_job_coverage(
            self.run_id,
            self.settings,
        )
        verification_tasks = self.store.verification_task_counts(self.run_id)
        counts = self.store.dashboard_counts(
            self.settings.retrieval_hash,
            analysis_policy_hash=self.settings.analysis_policy_hash,
        )
        persisted_backlog = self._backlog_accounting(
            accounted_at="post_finalization"
        )
        changed_components = {
            key: {
                "decision": backlog_accounting["components"][key],
                "persisted": persisted_backlog["components"][key],
            }
            for key in backlog_accounting["components"]
            if backlog_accounting["components"][key]
            != persisted_backlog["components"][key]
        }
        visible_backlog = {
            **persisted_backlog,
            "explained": bool(
                backlog_accounting["explained"]
                and persisted_backlog["explained"]
            ),
            "eligible_for_completed_with_gaps": bool(
                pending
                and backlog_accounting["explained"]
                and persisted_backlog["explained"]
                and status == "completed_with_gaps"
            ),
            "decision_snapshot": backlog_accounting,
            "persisted_snapshot": persisted_backlog,
            "finalization_changed_components": changed_components,
            "query_jobs": query_jobs,
            "query_coverage": query_coverage,
            "verification_tasks": verification_tasks,
            "pending_content": counts["pending_content"],
            "pending_analysis": counts["pending_analysis"],
        }
        summary = {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "profile_id": self.settings.profile_id,
            "profile_version": self.settings.profile_version,
            "config_hash": self.settings.config_hash,
            "retrieval_hash": self.settings.retrieval_hash,
            "analysis_policy_hash": self.settings.analysis_policy_hash,
            "mode": self.mode,
            "run_mode": self.run_mode,
            "source_phases": {
                "official": self.include_official_sources,
                "hosted_supplement": self.include_hosted_search,
                "analysis_only": self.analysis_only,
            },
            "resumed": self.resumed,
            "status": status,
            "interrupted": self._interrupted,
            "attention_required": attention,
            "generated_at": utc_now(),
            "elapsed_seconds": round(time.monotonic() - self.started_monotonic, 3),
            "query_jobs": query_jobs,
            "query_coverage": query_coverage,
            "verification_tasks": verification_tasks,
            "model_usage": self.store.model_usage(run_id=self.run_id),
            "weekly_intake": (
                self.weekly_intake.snapshot()
                if self.weekly_intake is not None
                else None
            ),
            "source_cooldowns": self.store.active_source_cooldowns(),
            "counts": counts,
            "visible_backlog": visible_backlog,
            "resources": {
                "transfer_bytes_received": self._transfer_bytes_received,
                "transfer_budget_overshoot_bytes": max(
                    0,
                    self._transfer_bytes_received
                    - self._run_resource_limit(
                        "max_transfer_bytes_per_invocation",
                        1024 * 1024 * 1024,
                    ),
                ),
                "maximum_observation_chunk_bytes": (
                    self._transfer_observation_chunk_bytes()
                ),
                "content_items_attempted": self._content_items_attempted,
                "content_items_processed": self._content_items_processed,
                "max_transfer_bytes_per_invocation": self._run_resource_limit(
                    "max_transfer_bytes_per_invocation",
                    1024 * 1024 * 1024,
                ),
                "max_content_items_per_invocation": self._run_resource_limit(
                    "max_content_items_per_invocation",
                    100,
                ),
                "minimum_free_disk_bytes": self._run_resource_limit(
                    "minimum_free_disk_bytes",
                    10 * 1024 * 1024 * 1024,
                ),
                "free_disk_bytes_at_summary": int(
                    shutil.disk_usage(self.settings.data_dir).free
                ),
            },
            "fatal_error": self._fatal_error,
            "audit_path": str(self.run_dir / "audit.jsonl"),
            "database_path": str(self.settings.database_path),
        }
        self._persist_summary(summary)
        return summary

    def _persist_summary(self, summary: dict[str, Any]) -> None:
        atomic_write_text(
            self.run_dir / "summary.json",
            json_dumps(summary, pretty=True) + "\n",
        )
        atomic_write_text(
            self.settings.outputs_dir / "latest_summary.json",
            json_dumps(summary, pretty=True) + "\n",
        )
        counts = summary["counts"]
        visible_backlog = summary["visible_backlog"]
        publication = summary.get("publication") or {}
        report = f"""# R3 Research Radar run

- Run: `{self.run_id}`
- Mode: `{self.mode}`
- Status: `{summary['status']}`
- Raw hits: {counts['raw_hits']}
- Unique works after deduplication: {counts['unique_works']}
- Admitted: {counts['admitted']}
- Deep-read complete: {counts['deep_read']}
- Full text unavailable: {counts['unavailable']}
- Coverage incomplete: {counts['incomplete']}
- Pending content: {counts['pending_content']}
- Pending analysis: {counts['pending_analysis']}
- Visible backlog explained: {visible_backlog['explained']}
- Visible backlog reasons: {', '.join(visible_backlog['reason_codes']) or 'none'}
- Publication status: {publication.get('status', 'not_attempted')}
- Publication issue: `{publication.get('issue_id', 'none')}`

The raw audit log is `{summary['audit_path']}`.
No item is counted as deep-read complete unless source coverage and every analysis chunk passed
the persisted coverage gate.
"""
        atomic_write_text(self.run_dir / "report.md", report)
