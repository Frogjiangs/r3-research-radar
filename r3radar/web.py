from __future__ import annotations

import base64
import json
import mimetypes
import os
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .calibration import CalibrationError
from .config import Settings
from .decision import build_evidence_context, render_export
from .reproduction import (
    ReproductionHandoffError,
    build_reproduction_handoff,
    render_reproduction_handoff,
)
from .runtime_status import inspect_database, run_status, scheduler_status
from .storage import (
    DecisionNotAllowedError,
    FeedbackNotAllowedError,
    GoldReviewConflictError,
    GoldReviewNotFoundError,
    PublicationConflictError,
    RadarStore,
)
from .utils import json_dumps


_SAFE_CONTENT_REASONS = frozenset(
    {
        "empty_text_layer_pages",
        "fetch_or_extract_error",
        "insufficient_extractable_text",
        "no_pdf_url",
        "page_extraction_errors",
        "pdf_extract_timeout",
        "pdf_extract_worker_failed",
        "pdf_security_reparse_required",
        "repository_fetch_or_read_error",
        "static_text_coverage_limits_or_decode_failures",
        "unsupported_kind",
    }
)
_SAFE_CONTENT_SECURITY_STATUSES = frozenset(
    {
        "incomplete_security",
        "parsed_verified",
    }
)
_SAFE_CONTENT_FAILURE_CODES = frozenset(
    {
        "artifact_promotion_failed",
        "appcontainer_busy",
        "appcontainer_launch_failed",
        "appcontainer_mutex_unavailable",
        "appcontainer_runtime_unavailable",
        "appcontainer_task_acl_unavailable",
        "cpu_time_limit",
        "document_policy_mismatch",
        "encrypted_pdf",
        "input_mismatch",
        "invalid_pdf",
        "job_assignment_failed",
        "job_accounting_unavailable",
        "job_limits_unavailable",
        "job_object_unavailable",
        "limit_exceeded",
        "low_integrity_output_unavailable",
        "parser_error",
        "result_missing",
        "result_schema_invalid",
        "result_size_invalid",
        "sandbox_environment_invalid",
        "sandbox_gate_unavailable",
        "sandbox_unavailable",
        "staged_artifact_modified",
        "supervisor_error",
        "unsupported_parser_backend",
        "unsupported_parser_policy",
        "unsupported_parser_version",
        "wall_timeout",
        "worker_nonzero_exit",
        "worker_state_invalid",
    }
)
_SAFE_RETRIEVAL_SOURCES = frozenset(
    {
        "arxiv",
        "codex_web",
        "github",
        "openalex",
    }
)


def _encode_works_cursor(
    *, offset: int, retrieval_hash: str, analysis_policy_hash: str
) -> str:
    payload = json.dumps(
        {
            "v": 1,
            "offset": int(offset),
            "retrieval_hash": retrieval_hash,
            "analysis_policy_hash": analysis_policy_hash,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def _decode_works_cursor(
    value: str, *, retrieval_hash: str, analysis_policy_hash: str
) -> int:
    if not value or len(value) > 512:
        raise ValueError("cursor is empty or too large")
    encoded = value.encode("ascii")
    encoded += b"=" * (-len(encoded) % 4)
    payload = json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True))
    if (
        not isinstance(payload, dict)
        or payload.get("v") != 1
        or payload.get("retrieval_hash") != retrieval_hash
        or payload.get("analysis_policy_hash") != analysis_policy_hash
        or isinstance(payload.get("offset"), bool)
        or not isinstance(payload.get("offset"), int)
        or int(payload["offset"]) < 0
    ):
        raise ValueError("cursor does not match the active research scope")
    return int(payload["offset"])
_EXPECTED_CLIENT_DISCONNECT_ERRORS = (
    BrokenPipeError,
    ConnectionAbortedError,
    ConnectionResetError,
)


def _gold_review_route(path: str) -> tuple[str, str] | None:
    parts = path.split("/")
    if (
        len(parts) == 6
        and parts[:4] == ["", "api", "gold", "reviews"]
        and parts[4]
        and len(parts[4]) <= 128
        and parts[5] in {"y0", "lock"}
    ):
        return parts[4], parts[5]
    return None


class RadarHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], settings: Settings):
        self.store: RadarStore | None = None
        self.started_at = time.time()
        self._metrics_lock = threading.Lock()
        self._request_count = 0
        self._request_error_count = 0
        self._expected_disconnect_count = 0
        self._latencies: list[float] = []
        self._scheduler_cache: tuple[float, dict[str, Any]] | None = None
        self._database_health_cache: tuple[float, dict[str, Any]] | None = None
        super().__init__(address, RadarHandler)
        self.settings = settings
        try:
            self.store = RadarStore(settings.database_path)
        except Exception:
            super().server_close()
            raise
        self.static_dir = settings.project_dir / "static"

    def server_close(self) -> None:
        store = self.store
        self.store = None
        if store is not None:
            store.close()
        super().server_close()

    def handle_error(
        self,
        request: Any,
        client_address: tuple[str, int],
    ) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, _EXPECTED_CLIENT_DISCONNECT_ERRORS):
            with self._metrics_lock:
                self._expected_disconnect_count += 1
            return
        with self._metrics_lock:
            self._request_error_count += 1
        super().handle_error(request, client_address)

    def record_request(self, duration_seconds: float) -> None:
        with self._metrics_lock:
            self._request_count += 1
            self._latencies.append(max(0.0, duration_seconds))
            if len(self._latencies) > 2048:
                del self._latencies[:-1024]

    def metrics_snapshot(self) -> dict[str, Any]:
        buckets = (0.01, 0.05, 0.1, 0.25, 1.0, 5.0)
        with self._metrics_lock:
            latencies = list(self._latencies)
            request_count = self._request_count
            error_count = self._request_error_count
            disconnect_count = self._expected_disconnect_count
        return {
            "requests": request_count,
            "errors": error_count,
            "expected_client_disconnects": disconnect_count,
            "latency_seconds": {
                f"le_{limit:g}": sum(value <= limit for value in latencies)
                for limit in buckets
            }
            | {"gt_5": sum(value > 5.0 for value in latencies)},
        }

    def observed_scheduler(self) -> dict[str, Any]:
        now = time.monotonic()
        cached = self._scheduler_cache
        if cached is not None and now - cached[0] < 60:
            return dict(cached[1])
        observed = scheduler_status()
        self._scheduler_cache = (now, observed)
        return dict(observed)

    def observed_database(self) -> dict[str, Any]:
        now = time.monotonic()
        cached = self._database_health_cache
        if cached is not None and now - cached[0] < 15:
            return dict(cached[1])
        observed = inspect_database(self.settings.database_path)
        self._database_health_cache = (now, observed)
        return dict(observed)

    def runtime_snapshot(self) -> dict[str, Any]:
        database = self.observed_database()
        run = run_status(
            self.store,
            self.settings.config_hash,
            self.settings.retrieval_hash,
        )
        return {
            "service": {
                "state": "up",
                "up": True,
                "pid": os.getpid(),
                "uptime_seconds": max(0, int(time.time() - self.started_at)),
            },
            "database": database,
            "run": run,
            "scheduler": self.observed_scheduler(),
            "metrics": self.metrics_snapshot(),
        }


class RadarHandler(BaseHTTPRequestHandler):
    server: RadarHttpServer
    protocol_version = "HTTP/1.1"

    def parse_request(self) -> bool:
        self._request_started_at = time.perf_counter()
        return super().parse_request()

    def handle_one_request(self) -> None:
        self._request_started_at: float | None = None
        try:
            super().handle_one_request()
        finally:
            if self._request_started_at is not None:
                self.server.record_request(
                    time.perf_counter() - self._request_started_at
                )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
        )
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    def _authority_is_local(self) -> bool:
        raw = (self.headers.get("Host") or "").strip()
        try:
            parts = urlsplit(f"//{raw}")
            hostname = (parts.hostname or "").casefold()
            port = parts.port
        except ValueError:
            return False
        expected_port = int(self.server.server_address[1])
        return (
            hostname in {"127.0.0.1", "localhost", "::1"}
            and (port is None or port == expected_port)
        )

    def _expected_origins(self) -> set[str]:
        port = int(self.server.server_address[1])
        return {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
        }

    def _latest_display_publication(self) -> tuple[dict[str, Any] | None, bool]:
        settings = self.server.settings
        publication = self.server.store.latest_publication(
            retrieval_hash=settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
        )
        if publication is not None:
            return publication, True
        publication = self.server.store.latest_publication_for_retrieval(
            settings.retrieval_hash
        )
        return (
            publication,
            bool(
                publication is not None
                and publication.get("analysis_policy_hash")
                == settings.analysis_policy_hash
            ),
        )

    def _publication_policy(self, issue_id: str | None = None) -> str | None:
        settings = self.server.settings
        if issue_id is not None:
            issue = self.server.store.report_issue_in_retrieval(
                issue_id=issue_id,
                retrieval_hash=settings.retrieval_hash,
            )
        else:
            issue = self.server.store.latest_report_issue(
                retrieval_hash=settings.retrieval_hash,
                analysis_policy_hash=settings.analysis_policy_hash,
            )
            if issue is None:
                issue = self.server.store.latest_report_issue_for_retrieval(
                    settings.retrieval_hash
                )
        if issue is None:
            return None
        return str(issue["analysis_policy_hash"])

    def _send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: Any) -> None:
        self._send_bytes(
            status,
            json_dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _send_download(
        self,
        *,
        body: bytes,
        content_type: str,
        filename: str,
    ) -> None:
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="{filename}"',
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if not self._authority_is_local():
            self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "invalid_host"})
            return
        parsed_path = urlsplit(self.path)
        path = parsed_path.path
        gold_route = _gold_review_route(path)
        if gold_route is not None and gold_route[1] == "y0":
            try:
                parameters = parse_qs(parsed_path.query)
                if set(parameters) - {"limit", "offset"}:
                    raise ValueError("unexpected Gold pagination field")
                limit = int((parameters.get("limit") or ["10"])[0])
                offset = int((parameters.get("offset") or ["0"])[0])
                payload = self.server.store.gold_review_blind_payload(
                    gold_route[0],
                    limit=limit,
                    offset=offset,
                )
            except GoldReviewNotFoundError:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "gold_review_not_found"},
                )
                return
            except (GoldReviewConflictError, CalibrationError):
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"error": "gold_y0_unavailable"},
                )
                return
            except ValueError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_gold_pagination"},
                )
                return
            self._send_json(HTTPStatus.OK, payload)
            return
        if path == "/api/health":
            runtime = self.server.runtime_snapshot()
            database_ready = runtime["database"]["state"] == "ready"
            self._send_json(
                HTTPStatus.OK if database_ready else HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "ok": database_ready,
                    "service": "r3-research-radar",
                    "loopback_only": True,
                    "instance": {
                        "profile_id": self.server.settings.profile_id,
                        "profile_version": self.server.settings.profile_version,
                        "config_hash": self.server.settings.config_hash,
                    },
                    "runtime": runtime,
                },
            )
            return
        if path == "/api/status":
            latest_run = self.server.store.latest_run(
                self.server.settings.config_hash
            )
            if latest_run is None:
                latest_run = self.server.store.latest_run_for_retrieval(
                    self.server.settings.retrieval_hash
                )
            if latest_run is not None:
                latest_run = dict(latest_run)
                latest_run["lease_token_present"] = bool(
                    latest_run.pop("lease_token", None)
                )
            run_policy_current = bool(
                latest_run is not None
                and (
                    latest_run.get("analysis_policy_hash")
                    or latest_run.get("config_hash")
                )
                == self.server.settings.analysis_policy_hash
            )
            if latest_run is not None:
                latest_run["analysis_policy_current"] = run_policy_current
            try:
                latest_publication, publication_policy_current = (
                    self._latest_display_publication()
                )
            except PublicationConflictError as exc:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": "publication_integrity_error",
                        "detail": str(exc),
                    },
                )
                return
            publication_summary = None
            if latest_publication is not None:
                publication_summary = {
                    key: latest_publication.get(key)
                    for key in (
                        "issue_id",
                        "run_id",
                        "publication_key",
                        "terminal_status",
                        "generated_at",
                        "payload_sha256",
                        "report_sha256",
                        "selection_sha256",
                        "counts",
                        "local_outbox",
                    )
                }
                publication_summary["analysis_policy_current"] = (
                    publication_policy_current
                )
            counts = self.server.store.dashboard_counts(
                self.server.settings.retrieval_hash,
                analysis_policy_hash=self.server.settings.analysis_policy_hash,
            )
            deep_read = self.server.store.deep_read_progress(
                self.server.settings.analysis_policy_hash,
                retrieval_hash=self.server.settings.retrieval_hash,
                run_id=(
                    str(latest_run["id"])
                    if latest_run is not None and run_policy_current
                    else None
                ),
            )
            deep_read["available_completed"] = counts["available_deep_read"]
            deep_read["historical_completed"] = max(
                0,
                counts["available_deep_read"] - counts["deep_read"],
            )
            runtime = self.server.runtime_snapshot()
            current_task = deep_read.get("current_task")
            deep_read_active = bool(
                runtime["run"]["active"]
                and isinstance(current_task, dict)
                and current_task.get("claimed_run_id")
                == runtime["run"].get("latest", {}).get("id")
            )
            deep_read["active"] = deep_read_active
            if deep_read.get("state") == "running" and not deep_read_active:
                deep_read["state"] = "stalled"
            codex_config = self.server.settings.raw["analysis"]["codex_cli"]
            profile = self.server.settings.raw
            query_coverage = (
                self.server.store.query_job_coverage(
                    str(latest_run["id"]),
                    self.server.settings,
                )
                if latest_run is not None
                else None
            )
            self._send_json(
                HTTPStatus.OK,
                {
                    "profile": {
                        "id": self.server.settings.profile_id,
                        "version": self.server.settings.profile_version,
                        "name": str(
                            profile.get("name") or "R3 Research Radar"
                        )[:200],
                        "research_question": str(
                            profile.get("research_question") or ""
                        )[:1000],
                        "decision_scope": str(
                            profile.get("decision_scope") or ""
                        )[:1000],
                        "demo_mode": bool(profile.get("demo_mode", False)),
                    },
                    "counts": counts,
                    "latest_run": latest_run,
                    "query_coverage": query_coverage,
                    "discovery_policy": {
                        "semantic_prefilter_enabled": not bool(
                            profile.get("admission", {}).get(
                                "no_semantic_prefilter",
                                True,
                            )
                        ),
                        "high_recall_unfiltered": bool(
                            profile.get("admission", {}).get(
                                "no_semantic_prefilter",
                                True,
                            )
                        ),
                        "quality_claim": "requires_human_gold_set",
                    },
                    "model_usage": (
                        self.server.store.model_usage(
                            run_id=str(latest_run["id"])
                        )
                        if latest_run
                        else self.server.store.model_usage()
                    ),
                    "deep_read": deep_read,
                    "runtime": runtime,
                    "analysis_execution": {
                        "provider": (
                            "deterministic_fixture"
                            if profile.get("demo_mode") is True
                            else self.server.settings.raw["analysis"].get(
                                "primary_provider"
                            )
                        ),
                        "model": (
                            "no-model-call"
                            if profile.get("demo_mode") is True
                            else codex_config.get("model")
                        ),
                        "reasoning_effort": (
                            None
                            if profile.get("demo_mode") is True
                            else codex_config.get("reasoning_effort")
                        ),
                    },
                    "source_cooldowns": self.server.store.active_source_cooldowns(),
                    "latest_publication": publication_summary,
                },
            )
            return
        if path == "/api/publication":
            try:
                publication, publication_policy_current = (
                    self._latest_display_publication()
                )
            except PublicationConflictError as exc:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": "publication_integrity_error",
                        "detail": str(exc),
                    },
                )
                return
            if publication is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "publication_not_found"},
                )
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "issue_id": publication["issue_id"],
                    "run_id": publication["run_id"],
                    "publication_key": publication["publication_key"],
                    "terminal_status": publication["terminal_status"],
                    "generated_at": publication["generated_at"],
                    "payload_sha256": publication["payload_sha256"],
                    "report_sha256": publication["report_sha256"],
                    "selection_sha256": publication["selection_sha256"],
                    "counts": publication["counts"],
                    "payload": publication["payload"],
                    "local_outbox": publication.get("local_outbox"),
                    "analysis_policy_current": publication_policy_current,
                },
            )
            return
        if path == "/api/decision-slice":
            parameters = parse_qs(parsed_path.query)
            issue_id = (parameters.get("issue_id") or [None])[0]
            show_all = (parameters.get("all") or ["0"])[0] == "1"
            try:
                publication_policy = self._publication_policy(issue_id)
                decision_slice = self.server.store.decision_slice(
                    retrieval_hash=self.server.settings.retrieval_hash,
                    analysis_policy_hash=(
                        publication_policy
                        or self.server.settings.analysis_policy_hash
                    ),
                    issue_id=issue_id,
                    pending_limit=None if show_all else 3,
                )
            except PublicationConflictError as exc:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": "publication_integrity_error",
                        "detail": str(exc),
                    },
                )
                return
            if decision_slice is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "publication_not_found"},
                )
                return
            decision_slice["analysis_policy_current"] = (
                publication_policy == self.server.settings.analysis_policy_hash
            )
            self._send_json(HTTPStatus.OK, decision_slice)
            return
        if path in {
            "/api/evidence",
            "/api/export",
            "/api/reproduction-handoff",
        }:
            parameters = parse_qs(parsed_path.query)
            try:
                issue_id = str(parameters["issue_id"][0])
                analysis_id = int(parameters["analysis_id"][0])
                publication_policy = self._publication_policy(issue_id)
                if publication_policy is None:
                    raise DecisionNotAllowedError(
                        "publication is unavailable in the active retrieval scope"
                    )
                if path == "/api/evidence":
                    source = self.server.store.frozen_item_text_source(
                        issue_id=issue_id,
                        analysis_id=analysis_id,
                        retrieval_hash=self.server.settings.retrieval_hash,
                        analysis_policy_hash=publication_policy,
                    )
                    text = Path(source["text_path"]).read_text(
                        encoding="utf-8"
                    )
                    result = build_evidence_context(
                        source["item"]["snapshot"],
                        text,
                        source["input_sha256"],
                    )
                    result["source"] = {
                        **dict(result.get("source") or {}),
                        "input_sha256": source["input_sha256"],
                        "document_id": source["document_id"],
                    }
                    result["anchors"] = [
                        {
                            **anchor,
                            "excerpt": anchor["exact_substring"],
                            "start": anchor["anchor_start"],
                        }
                        for anchor in result.get("anchors") or []
                    ]
                    self._send_json(HTTPStatus.OK, result)
                    return
                item = self.server.store.frozen_issue_item(
                    issue_id=issue_id,
                    analysis_id=analysis_id,
                    retrieval_hash=self.server.settings.retrieval_hash,
                    analysis_policy_hash=publication_policy,
                )
                if path == "/api/reproduction-handoff":
                    manifest = build_reproduction_handoff(
                        item,
                        source_relation=(
                            self.server.store.paper_repository_relation_for_work(
                                int(item["work_id"])
                            )
                        ),
                    )
                    self._send_download(
                        body=render_reproduction_handoff(manifest),
                        content_type="application/json; charset=utf-8",
                        filename=f"r3-reproduction-{analysis_id}.json",
                    )
                    return
                format_name = str(parameters["format"][0])
                artifact = render_export(
                    item["snapshot"],
                    item["decision"],
                    format_name,
                )
                self._send_download(
                    body=artifact.content,
                    content_type=artifact.content_type,
                    filename=artifact.filename,
                )
                return
            except ReproductionHandoffError as exc:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": "reproduction_handoff_integrity_error",
                        "detail": str(exc),
                    },
                )
                return
            except DecisionNotAllowedError:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {"error": "decision_requires_published_item"},
                )
                return
            except PublicationConflictError as exc:
                self._send_json(
                    HTTPStatus.CONFLICT,
                    {
                        "error": "frozen_evidence_integrity_error",
                        "detail": str(exc),
                    },
                )
                return
            except (KeyError, OSError, TypeError, ValueError):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_decision_request"},
                )
                return
        if path == "/api/work-analysis":
            parameters = parse_qs(parsed_path.query)
            try:
                work_id = int((parameters.get("work_id") or [""])[0])
                if work_id <= 0:
                    raise ValueError("work_id must be positive")
            except ValueError:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_work_id"},
                )
                return
            analysis = self.server.store.dashboard_work_analysis(
                work_id=work_id,
                config_hash=self.server.settings.retrieval_hash,
                analysis_policy_hash=self.server.settings.analysis_policy_hash,
            )
            if analysis is None:
                self._send_json(
                    HTTPStatus.NOT_FOUND,
                    {"error": "analysis_not_found"},
                )
                return
            self._send_json(HTTPStatus.OK, analysis)
            return
        if path == "/api/works":
            parameters = parse_qs(parsed_path.query)
            try:
                limit = max(
                    1,
                    min(100, int((parameters.get("limit") or ["25"])[0])),
                )
                cursor_value = (parameters.get("cursor") or [None])[0]
                if cursor_value is not None:
                    offset = _decode_works_cursor(
                        cursor_value,
                        retrieval_hash=self.server.settings.retrieval_hash,
                        analysis_policy_hash=(
                            self.server.settings.analysis_policy_hash
                        ),
                    )
                else:
                    offset = max(
                        0,
                        int((parameters.get("offset") or ["0"])[0]),
                    )
            except (UnicodeError, ValueError, json.JSONDecodeError):
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "invalid_pagination"},
                )
                return
            works = self.server.store.list_dashboard_works(
                config_hash=self.server.settings.retrieval_hash,
                analysis_policy_hash=self.server.settings.analysis_policy_hash,
                limit=limit,
                offset=offset,
            )
            for work in works:
                raw_sources = work.get("retrieval_sources")
                work["retrieval_sources"] = [
                    source
                    for source in raw_sources
                    if isinstance(source, str) and source in _SAFE_RETRIEVAL_SOURCES
                ] if isinstance(raw_sources, list) else []
                raw_coverage = work.pop("content_coverage_json", None)
                coverage: dict[str, Any] = {}
                if raw_coverage:
                    try:
                        candidate = json.loads(raw_coverage)
                        if isinstance(candidate, dict):
                            coverage = candidate
                    except json.JSONDecodeError:
                        pass
                for source_key, destination_key, allowlist in (
                    ("reason", "content_reason", _SAFE_CONTENT_REASONS),
                    (
                        "security_status",
                        "content_security_status",
                        _SAFE_CONTENT_SECURITY_STATUSES,
                    ),
                    (
                        "failure_code",
                        "content_failure_code",
                        _SAFE_CONTENT_FAILURE_CODES,
                    ),
                ):
                    value = coverage.get(source_key)
                    work[destination_key] = value if value in allowlist else None
            total = self.server.store.dashboard_work_total(
                config_hash=self.server.settings.retrieval_hash
            )
            has_more = offset + len(works) < total
            self._send_json(
                HTTPStatus.OK,
                {
                    "works": works,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "has_more": has_more,
                    "next_cursor": (
                        _encode_works_cursor(
                            offset=offset + len(works),
                            retrieval_hash=self.server.settings.retrieval_hash,
                            analysis_policy_hash=(
                                self.server.settings.analysis_policy_hash
                            ),
                        )
                        if has_more
                        else None
                    ),
                },
            )
            return
        if path in {"/", "/index.html"}:
            self._send_static("index.html")
            return
        if path == "/gold-review":
            self._send_static("gold-review.html")
            return
        if path in {
            "/app.js",
            "/styles.css",
            "/gold-review.js",
            "/gold-review.css",
        }:
            self._send_static(path.lstrip("/"))
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:
        if not self._authority_is_local():
            self._send_json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "invalid_host"})
            return
        path = urlsplit(self.path).path
        gold_route = _gold_review_route(path)
        is_gold_create = path == "/api/gold/reviews"
        if (
            path not in {"/api/feedback", "/api/decision"}
            and not is_gold_create
            and gold_route is None
        ):
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        origin = self.headers.get("Origin")
        if origin not in self._expected_origins():
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid_origin"})
            return
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip()
        if content_type.casefold() != "application/json":
            self._send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "json_required"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        maximum_length = 65536 if is_gold_create or gold_route else 16384
        if length <= 0 or length > maximum_length:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_body_size"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("JSON request body must be an object")
            if is_gold_create:
                allowed = {
                    "source_path",
                    "reviewer_identity",
                    "creation_request_id",
                    "collection_kind",
                    "evaluation_split",
                }
                if set(payload) - allowed:
                    raise ValueError("unexpected Gold review creation field")
                source_path = payload["source_path"]
                if not isinstance(source_path, str) or len(source_path) > 32768:
                    raise ValueError("source_path is invalid")
                result = self.server.store.create_gold_review_from_v1_file(
                    source_path=Path(source_path),
                    reviewer_identity=str(payload["reviewer_identity"]),
                    creation_request_id=str(payload["creation_request_id"]),
                    collection_kind=str(
                        payload.get("collection_kind") or "run_derived"
                    ),
                    evaluation_split=str(
                        payload.get("evaluation_split") or "development"
                    ),
                )
                self._send_json(
                    HTTPStatus.OK if result["idempotent"] else HTTPStatus.CREATED,
                    {"ok": True, "review": result},
                )
                return
            if gold_route is not None:
                review_id, gold_action = gold_route
                if gold_action == "y0":
                    allowed = {
                        "request_id",
                        "item_id",
                        "reviewer_identity",
                        "semantic_label",
                        "operational_status",
                        "confidence",
                        "evidence_opened",
                        "elapsed_ms",
                        "notes",
                        "submitted_at",
                        "expected_item_revision_sequence",
                        "expected_document_revision_sequence",
                    }
                    if set(payload) - allowed:
                        raise ValueError("unexpected Gold y0 field")
                    result = self.server.store.save_gold_y0(
                        review_id=review_id,
                        request_id=str(payload["request_id"]),
                        item_id=str(payload["item_id"]),
                        reviewer_identity=str(payload["reviewer_identity"]),
                        semantic_label=str(payload["semantic_label"]),
                        operational_status=str(payload["operational_status"]),
                        confidence=payload.get("confidence"),
                        evidence_opened=payload["evidence_opened"],
                        elapsed_ms=payload["elapsed_ms"],
                        notes=payload.get("notes"),
                        submitted_at=(
                            str(payload["submitted_at"])
                            if payload.get("submitted_at") is not None
                            else None
                        ),
                        expected_item_revision_sequence=payload[
                            "expected_item_revision_sequence"
                        ],
                        expected_document_revision_sequence=payload[
                            "expected_document_revision_sequence"
                        ],
                    )
                else:
                    allowed = {
                        "request_id",
                        "reviewer_identity",
                        "locked_at",
                        "expected_document_revision_sequence",
                    }
                    if set(payload) - allowed:
                        raise ValueError("unexpected Gold y0 lock field")
                    result = self.server.store.lock_gold_y0_review(
                        review_id=review_id,
                        request_id=str(payload["request_id"]),
                        reviewer_identity=str(payload["reviewer_identity"]),
                        locked_at=(
                            str(payload["locked_at"])
                            if payload.get("locked_at") is not None
                            else None
                        ),
                        expected_document_revision_sequence=payload[
                            "expected_document_revision_sequence"
                        ],
                    )
                self._send_json(HTTPStatus.OK, {"ok": True, "review": result})
                return
            if path == "/api/decision":
                issue_id = str(payload["issue_id"])
                publication_policy = self._publication_policy(issue_id)
                if publication_policy is None:
                    raise DecisionNotAllowedError(
                        "publication is unavailable in the active retrieval scope"
                    )
                decision = self.server.store.save_research_decision(
                    issue_id=issue_id,
                    analysis_id=int(payload["analysis_id"]),
                    action=str(payload["action"]),
                    reason=payload.get("reason"),
                    note=payload.get("note"),
                    retrieval_hash=self.server.settings.retrieval_hash,
                    analysis_policy_hash=publication_policy,
                )
                self._send_json(
                    HTTPStatus.CREATED,
                    {"ok": True, "decision": decision},
                )
                return
            work_id = int(payload["work_id"])
            rating = str(payload["rating"])
            comment = payload.get("comment")
            if comment is not None:
                comment = str(comment)[:4000]
            self.server.store.add_feedback(
                work_id,
                rating,
                comment,
                retrieval_hash=self.server.settings.retrieval_hash,
                analysis_policy_hash=self.server.settings.analysis_policy_hash,
            )
        except GoldReviewNotFoundError:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "gold_review_not_found"},
            )
            return
        except GoldReviewConflictError:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "gold_review_conflict"},
            )
            return
        except CalibrationError:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_gold_review"},
            )
            return
        except (OSError, UnicodeError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "invalid_gold_source"},
            )
            return
        except DecisionNotAllowedError:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "decision_requires_published_item"},
            )
            return
        except PublicationConflictError as exc:
            self._send_json(
                HTTPStatus.CONFLICT,
                {
                    "error": "publication_integrity_error",
                    "detail": str(exc),
                },
            )
            return
        except FeedbackNotAllowedError:
            self._send_json(
                HTTPStatus.CONFLICT,
                {"error": "feedback_requires_complete_deep_read"},
            )
            return
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "error": (
                        "invalid_gold_request"
                        if is_gold_create or gold_route is not None
                        else
                        "invalid_decision"
                        if path == "/api/decision"
                        else "invalid_feedback"
                    )
                },
            )
            return
        self._send_json(HTTPStatus.CREATED, {"ok": True})

    def _send_static(self, filename: str) -> None:
        path = (self.server.static_dir / filename).resolve()
        try:
            path.relative_to(self.server.static_dir.resolve())
        except ValueError:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid_path"})
            return
        if not path.is_file():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type == "application/javascript":
            content_type += "; charset=utf-8"
        self._send_bytes(HTTPStatus.OK, path.read_bytes(), content_type)


def serve(
    settings: Settings,
    host: str = "127.0.0.1",
    port: int = 8765,
    *,
    emit_receipts: bool = False,
) -> None:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("The R3 dashboard may only listen on the loopback interface.")
    server = RadarHttpServer((host, port), settings)
    if emit_receipts:
        print(
            json_dumps(
                {
                    "ok": True,
                    "event": "dashboard_started",
                    "service": "r3-research-radar",
                    "host": host,
                    "port": int(server.server_address[1]),
                    "pid": os.getpid(),
                    "profile_id": settings.profile_id,
                    "config_hash": settings.config_hash,
                }
            ),
            flush=True,
        )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        metrics = server.metrics_snapshot()
        server.server_close()
        if emit_receipts:
            print(
                json_dumps(
                    {
                        "ok": True,
                        "event": "dashboard_stopped",
                        "service": "r3-research-radar",
                        "host": host,
                        "port": int(server.server_address[1]),
                        "pid": os.getpid(),
                        "metrics": metrics,
                    }
                ),
                flush=True,
            )
