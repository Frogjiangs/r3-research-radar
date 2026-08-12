from __future__ import annotations

import copy
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .config import Settings, canonical_json
from .document_policy import (
    PDF_CONTENT_KIND,
    REPOSITORY_CONTENT_KIND,
    current_pdf_document_policy_hash,
    document_is_analysis_eligible,
    observation_receipt,
    require_current_pdf_ready_policy,
    require_repository_ready_policy,
)
from .models import AdmissionDecision, SourceRecord, normalize_title
from .utils import json_dumps, sha256_bytes, sha256_text, utc_now


SCHEMA_VERSION = 23


class RunAlreadyActiveError(RuntimeError):
    pass


def _analysis_exclusive_run_mode(mode: str) -> bool:
    return mode in {"run", "weekly", "smoke"} or mode.startswith(
        ("run:", "weekly:", "smoke:")
    )


def planned_query_job_specs(
    settings: Settings,
    *,
    include_hosted: bool,
    smoke: bool = False,
    include_official: bool = True,
) -> list[dict[str, str]]:
    """Return the exact auditable query/source jobs for one run phase."""

    specs: list[dict[str, str]] = []
    queries = settings.raw["queries"]
    if include_official:
        if smoke:
            selected_queries: list[dict[str, Any]] = []
            selected_sources: set[str] = set()
            for query in queries:
                for source in query["sources"]:
                    if source not in selected_sources:
                        selected_queries.append({**query, "sources": [source]})
                        selected_sources.add(source)
            official_queries = selected_queries
        else:
            official_queries = queries
        for query in official_queries:
            for source in query["sources"]:
                specs.append(
                    {
                        "query_id": str(query["id"]),
                        "source": str(source),
                        "lane": str(query["lane"]),
                        "query_text": str(query["query"]),
                        "job_kind": "official",
                    }
                )
    hosted = settings.raw.get("hosted_search", {})
    if include_hosted and hosted.get("enabled"):
        max_queries = int(hosted.get("max_queries_per_run", 0))
        configured_ids = hosted.get("query_ids") or []
        by_id = {query["id"]: query for query in queries}
        selected = [
            by_id[query_id] for query_id in configured_ids if query_id in by_id
        ]
        if not selected:
            selected = [
                query
                for query in queries
                if query["lane"] in {"core", "adjacent", "escape"}
            ]
        selected = selected[: 1 if smoke else max_queries]
        for query in selected:
            specs.append(
                {
                    "query_id": f"web-{query['id']}",
                    "source": "codex_web",
                    "lane": str(query["lane"]),
                    "query_text": str(query["query"]),
                    "job_kind": "hosted",
                }
            )
    return specs


class FeedbackNotAllowedError(RuntimeError):
    pass


class PublicationNotAllowedError(RuntimeError):
    pass


class PublicationConflictError(RuntimeError):
    pass


class DecisionNotAllowedError(RuntimeError):
    pass


class GoldReviewNotFoundError(RuntimeError):
    pass


class GoldReviewConflictError(RuntimeError):
    pass


_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS profiles (
    profile_id TEXT NOT NULL,
    profile_version INTEGER NOT NULL,
    config_hash TEXT NOT NULL,
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (profile_id, profile_version)
);

CREATE TABLE IF NOT EXISTS profile_snapshots (
    config_hash TEXT PRIMARY KEY,
    retrieval_hash TEXT,
    analysis_policy_hash TEXT,
    profile_id TEXT NOT NULL,
    profile_version INTEGER NOT NULL,
    config_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    profile_version INTEGER NOT NULL,
    config_hash TEXT NOT NULL,
    retrieval_hash TEXT,
    analysis_policy_hash TEXT,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    invocation_count INTEGER NOT NULL DEFAULT 1,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ended_at TEXT,
    deadline_at TEXT NOT NULL,
    stats_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    owner_pid INTEGER,
    lease_token TEXT,
    lease_expires_at TEXT,
    FOREIGN KEY (profile_id, profile_version)
        REFERENCES profiles(profile_id, profile_version)
);
CREATE INDEX IF NOT EXISTS idx_runs_resume
    ON runs(profile_id, profile_version, mode, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS query_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    query_id TEXT NOT NULL,
    source TEXT NOT NULL,
    lane TEXT NOT NULL,
    query_text TEXT NOT NULL,
    job_kind TEXT NOT NULL DEFAULT 'official',
    status TEXT NOT NULL DEFAULT 'pending',
    cursor TEXT,
    page_no INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    result_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    not_before TEXT,
    claim_lease_token TEXT,
    started_at TEXT,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(run_id, query_id, source, job_kind),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_query_jobs_claim
    ON query_jobs(run_id, status, id);

CREATE TABLE IF NOT EXISTS source_cooldowns (
    source TEXT PRIMARY KEY,
    not_before TEXT NOT NULL,
    reason TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS http_rate_slots (
    slot_key TEXT PRIMARY KEY,
    next_request_at REAL NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    canonical_url TEXT,
    metadata_json TEXT NOT NULL,
    raw_sha256 TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(source, source_id)
);

CREATE TABLE IF NOT EXISTS source_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_record_id INTEGER NOT NULL,
    run_id TEXT NOT NULL,
    query_job_id INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    metadata_sha256 TEXT NOT NULL,
    revision_key TEXT,
    raw_sha256 TEXT,
    raw_path TEXT,
    FOREIGN KEY (source_record_id) REFERENCES source_records(id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (query_job_id) REFERENCES query_jobs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_source_observations_record
    ON source_observations(source_record_id, id);

CREATE TABLE IF NOT EXISTS works (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    normalized_title TEXT NOT NULL,
    year INTEGER,
    doi TEXT,
    arxiv_id TEXT,
    github_full_name TEXT,
    best_url TEXT,
    pdf_url TEXT,
    lane TEXT NOT NULL,
    state TEXT NOT NULL,
    admission_code TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_works_state ON works(state, id);
CREATE INDEX IF NOT EXISTS idx_works_title ON works(normalized_title);

CREATE TABLE IF NOT EXISTS work_scopes (
    work_id INTEGER NOT NULL,
    config_hash TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_version INTEGER NOT NULL,
    lane TEXT NOT NULL,
    state TEXT NOT NULL,
    admission_code TEXT NOT NULL,
    not_before TEXT,
    last_error TEXT,
    active_run_id TEXT,
    active_lease_token TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY(work_id, config_hash),
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_work_scopes_config
    ON work_scopes(config_hash, state, work_id);

CREATE TABLE IF NOT EXISTS work_aliases (
    alias TEXT PRIMARY KEY,
    work_id INTEGER NOT NULL,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS work_sources (
    work_id INTEGER NOT NULL,
    source_record_id INTEGER NOT NULL,
    PRIMARY KEY(work_id, source_record_id),
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE,
    FOREIGN KEY (source_record_id) REFERENCES source_records(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS run_hits (
    run_id TEXT NOT NULL,
    work_id INTEGER NOT NULL,
    query_job_id INTEGER NOT NULL,
    source_record_id INTEGER NOT NULL,
    admitted INTEGER NOT NULL,
    admission_code TEXT NOT NULL,
    admission_reason TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    PRIMARY KEY(run_id, query_job_id, source_record_id),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE,
    FOREIGN KEY (query_job_id) REFERENCES query_jobs(id) ON DELETE CASCADE,
    FOREIGN KEY (source_record_id) REFERENCES source_records(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS verification_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    query_job_id INTEGER NOT NULL,
    work_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    not_before TEXT,
    error TEXT,
    claim_lease_token TEXT,
    verified_work_id INTEGER,
    resolution TEXT,
    decision_code TEXT,
    started_at TEXT,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(run_id, work_id),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (query_job_id) REFERENCES query_jobs(id) ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE,
    FOREIGN KEY (verified_work_id) REFERENCES works(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_verification_tasks_claim
    ON verification_tasks(run_id, status, not_before, id);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    work_id INTEGER NOT NULL,
    content_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    source_url TEXT,
    local_path TEXT,
    text_path TEXT,
    content_sha256 TEXT,
    text_sha256 TEXT,
    byte_count INTEGER,
    text_char_count INTEGER,
    page_count INTEGER,
    document_policy_hash TEXT,
    coverage_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(work_id, content_kind),
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status, id);
CREATE INDEX IF NOT EXISTS idx_documents_work_latest
    ON documents(work_id, updated_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS content_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    work_id INTEGER NOT NULL,
    content_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    source_url TEXT,
    local_path TEXT,
    text_path TEXT,
    content_sha256 TEXT,
    text_sha256 TEXT,
    byte_count INTEGER,
    text_char_count INTEGER,
    page_count INTEGER,
    coverage_json TEXT NOT NULL,
    error TEXT,
    observed_at TEXT NOT NULL,
    UNIQUE(work_id, content_kind, content_sha256, text_sha256),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_content_revisions_work
    ON content_revisions(work_id, id);

CREATE TABLE IF NOT EXISTS document_processing_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL,
    work_id INTEGER NOT NULL,
    content_kind TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT NOT NULL,
    document_policy_hash TEXT,
    source_url TEXT,
    local_path TEXT,
    text_path TEXT,
    content_sha256 TEXT,
    text_sha256 TEXT,
    byte_count INTEGER,
    text_char_count INTEGER,
    page_count INTEGER,
    coverage_json TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    error TEXT,
    observed_at TEXT NOT NULL,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_document_processing_observations_document
    ON document_processing_observations(document_id, id);

CREATE TABLE IF NOT EXISTS analysis_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    work_id INTEGER NOT NULL,
    document_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    config_hash TEXT,
    retrieval_hash TEXT,
    profile_id TEXT,
    profile_version INTEGER,
    input_sha256 TEXT,
    claimed_run_id TEXT,
    claim_lease_token TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    chunk_total INTEGER NOT NULL DEFAULT 0,
    chunk_done INTEGER NOT NULL DEFAULT 0,
    phase TEXT NOT NULL DEFAULT 'queued',
    phase_done INTEGER NOT NULL DEFAULT 0,
    phase_total INTEGER NOT NULL DEFAULT 0,
    phase_updated_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT,
    not_before TEXT,
    UNIQUE(work_id, document_id, provider, prompt_version),
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE,
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_analysis_tasks_claim
    ON analysis_tasks(status, id);
CREATE INDEX IF NOT EXISTS idx_analysis_tasks_dashboard
    ON analysis_tasks(work_id, config_hash, status, updated_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS analysis_chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    chunk_index INTEGER NOT NULL,
    span_json TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    output_json TEXT,
    provider_receipt_json TEXT,
    error TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(task_id, chunk_index),
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS analysis_synthesis_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL,
    level INTEGER NOT NULL,
    node_index INTEGER NOT NULL,
    input_sha256 TEXT NOT NULL,
    covered_chunk_indices_json TEXT NOT NULL,
    output_json TEXT NOT NULL,
    provider_receipt_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(task_id, level, node_index),
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_analysis_synthesis_nodes_task
    ON analysis_synthesis_nodes(task_id, level, node_index);

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL UNIQUE,
    work_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    model TEXT,
    prompt_version TEXT NOT NULL,
    config_hash TEXT,
    retrieval_hash TEXT,
    profile_id TEXT,
    profile_version INTEGER,
    deep_read_status TEXT NOT NULL,
    tier TEXT,
    score REAL,
    analysis_json TEXT NOT NULL,
    coverage_json TEXT NOT NULL,
    provider_receipt_json TEXT NOT NULL,
    provenance_status TEXT NOT NULL DEFAULT 'legacy_or_unknown',
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_analyses_tier ON analyses(tier, score DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_dashboard
    ON analyses(work_id, deep_read_status, config_hash, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_dashboard_retrieval
    ON analyses(work_id, deep_read_status, retrieval_hash, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS model_invocations (
    invocation_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    task_id INTEGER,
    work_id INTEGER,
    provider TEXT NOT NULL,
    purpose TEXT NOT NULL,
    model TEXT,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    cached_input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_output_tokens INTEGER NOT NULL DEFAULT 0,
    duration_seconds REAL NOT NULL DEFAULT 0,
    receipt_sha256 TEXT NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES analysis_tasks(id) ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_model_invocations_run
    ON model_invocations(run_id, created_at);
CREATE INDEX IF NOT EXISTS idx_model_invocations_task
    ON model_invocations(task_id, created_at);

CREATE TABLE IF NOT EXISTS report_issues (
    issue_id TEXT PRIMARY KEY,
    run_id TEXT,
    publication_key TEXT,
    retrieval_hash TEXT NOT NULL,
    analysis_policy_hash TEXT NOT NULL,
    previous_issue_id TEXT,
    terminal_status TEXT,
    generated_at TEXT NOT NULL,
    output_dir TEXT NOT NULL,
    report_path TEXT NOT NULL,
    selection_path TEXT NOT NULL,
    counts_json TEXT NOT NULL,
    payload_sha256 TEXT,
    payload_json TEXT,
    report_sha256 TEXT,
    selection_sha256 TEXT,
    run_summary_path TEXT,
    FOREIGN KEY (previous_issue_id) REFERENCES report_issues(issue_id),
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_report_issues_scope
    ON report_issues(retrieval_hash, analysis_policy_hash, generated_at);

CREATE TABLE IF NOT EXISTS report_issue_items (
    issue_id TEXT NOT NULL,
    analysis_id INTEGER NOT NULL,
    work_id INTEGER NOT NULL,
    selection_bucket TEXT NOT NULL,
    selected INTEGER NOT NULL,
    input_sha256 TEXT,
    snapshot_sha256 TEXT,
    snapshot_json TEXT,
    PRIMARY KEY(issue_id, analysis_id),
    FOREIGN KEY (issue_id) REFERENCES report_issues(issue_id) ON DELETE CASCADE,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_report_issue_items_analysis
    ON report_issue_items(analysis_id);

CREATE TABLE IF NOT EXISTS publication_outbox (
    issue_id TEXT PRIMARY KEY,
    delivery_mode TEXT NOT NULL,
    state TEXT NOT NULL,
    digest_sha256 TEXT NOT NULL,
    digest_json TEXT NOT NULL,
    digest_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (issue_id) REFERENCES report_issues(issue_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS paper_repository_relations (
    paper_work_id INTEGER NOT NULL,
    repository_work_id INTEGER NOT NULL,
    commit_sha TEXT NOT NULL,
    relation_sha256 TEXT NOT NULL,
    relation_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(paper_work_id, repository_work_id),
    FOREIGN KEY (paper_work_id) REFERENCES works(id) ON DELETE CASCADE,
    FOREIGN KEY (repository_work_id) REFERENCES works(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS run_publication_snapshots (
    run_id TEXT PRIMARY KEY,
    retrieval_hash TEXT NOT NULL,
    analysis_policy_hash TEXT NOT NULL,
    terminal_status TEXT NOT NULL,
    summary_sha256 TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    candidates_sha256 TEXT NOT NULL,
    candidates_json TEXT NOT NULL,
    candidate_count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS research_decisions (
    issue_id TEXT NOT NULL,
    analysis_id INTEGER NOT NULL,
    work_id INTEGER NOT NULL,
    input_sha256 TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(issue_id, analysis_id),
    FOREIGN KEY (issue_id, analysis_id)
        REFERENCES report_issue_items(issue_id, analysis_id)
        ON DELETE CASCADE,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_research_decisions_action
    ON research_decisions(action, updated_at);

CREATE TABLE IF NOT EXISTS gold_reviews (
    review_id TEXT PRIMARY KEY,
    creation_request_id TEXT NOT NULL UNIQUE,
    creation_request_sha256 TEXT NOT NULL,
    source_schema TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    source_file_sha256 TEXT NOT NULL,
    source_path TEXT NOT NULL,
    status TEXT NOT NULL,
    reviewer_identity TEXT NOT NULL,
    item_count INTEGER NOT NULL,
    initial_document_sha256 TEXT NOT NULL,
    initial_document_json TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    document_json TEXT NOT NULL,
    current_revision_sequence INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    locked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_gold_reviews_status
    ON gold_reviews(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS gold_review_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event TEXT NOT NULL,
    item_id TEXT,
    request_id TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    previous_document_sha256 TEXT NOT NULL,
    document_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    revision_sha256 TEXT NOT NULL,
    revision_json TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE(review_id, sequence),
    UNIQUE(review_id, request_id),
    FOREIGN KEY (review_id) REFERENCES gold_reviews(review_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_gold_review_revisions_review
    ON gold_review_revisions(review_id, sequence);
CREATE TRIGGER IF NOT EXISTS gold_review_revisions_no_update
BEFORE UPDATE ON gold_review_revisions
BEGIN
    SELECT RAISE(ABORT, 'gold review revisions are append-only');
END;
CREATE TRIGGER IF NOT EXISTS gold_review_revisions_no_delete
BEFORE DELETE ON gold_review_revisions
BEGIN
    SELECT RAISE(ABORT, 'gold review revisions are append-only');
END;

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    work_id INTEGER NOT NULL,
    rating TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_feedback_work_latest
    ON feedback(work_id, id DESC);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    component TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT,
    details_json TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, id);
"""


class RadarStore:
    def __init__(
        self,
        database_path: Path,
        *,
        _migration_fault_injector: Callable[[str], None] | None = None,
    ):
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.database_path = database_path
        self._connection = sqlite3.connect(
            database_path,
            timeout=30,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self.document_policy_hash = current_pdf_document_policy_hash()
        self._connection.create_function(
            "r3_document_is_analysis_eligible",
            4,
            lambda content_kind, status, policy_hash, coverage_json: int(
                document_is_analysis_eligible(
                    content_kind,
                    status,
                    policy_hash,
                    coverage_json,
                )
            ),
            deterministic=True,
        )
        self._lock = threading.RLock()
        self._migration_fault_injector = _migration_fault_injector
        self._migration_from_version: int | None = None
        self._migration_step = "not_started"
        self._migration_started = False
        self._gold_review_validation_cache: dict[
            str, tuple[str, int, dict[str, Any]]
        ] = {}
        try:
            self._initialize_database()
        except BaseException as exc:
            migration_started = self._migration_started
            old_version = self._migration_from_version
            failed_step = self._migration_step
            try:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
            finally:
                self._connection.close()
            if not migration_started or not isinstance(exc, Exception):
                raise
            old_version_text = (
                "uninitialized" if old_version is None else str(old_version)
            )
            raise RuntimeError(
                "database schema migration failed "
                f"(old_version={old_version_text}, "
                f"target_version={SCHEMA_VERSION}, step={failed_step}); "
                "migration changes were rolled back or had not begun. "
                "Reopen the database with the same or newer R3 version to retry. "
                f"Cause: {type(exc).__name__}: {exc}"
            ) from exc

    def _migration_checkpoint(self, step: str) -> None:
        self._migration_step = step
        if self._migration_fault_injector is not None:
            self._migration_fault_injector(step)

    def _assert_current_schema_contract(self) -> None:
        required_columns = {
            "runs": {"id", "status", "lease_token"},
            "gold_reviews": {
                "review_id",
                "creation_request_id",
                "creation_request_sha256",
                "source_sha256",
                "source_path",
                "status",
                "reviewer_identity",
                "item_count",
                "initial_document_sha256",
                "initial_document_json",
                "document_sha256",
                "document_json",
                "current_revision_sequence",
            },
            "gold_review_revisions": {
                "review_id",
                "sequence",
                "event",
                "request_id",
                "request_sha256",
                "previous_document_sha256",
                "document_sha256",
                "status",
                "revision_sha256",
                "revision_json",
                "submitted_at",
                "received_at",
            },
        }
        missing: list[str] = []
        for table, columns in required_columns.items():
            table_exists = self._connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if table_exists is None:
                missing.append(table)
                continue
            actual_columns = {
                str(row["name"])
                for row in self._connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            missing.extend(
                f"{table}.{column}"
                for column in sorted(columns - actual_columns)
            )
        required_triggers = {
            "gold_review_revisions_no_update",
            "gold_review_revisions_no_delete",
        }
        actual_triggers = {
            str(row["name"])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        missing.extend(sorted(required_triggers - actual_triggers))
        if missing:
            raise RuntimeError(
                "database schema version is current but its required contract "
                "is incomplete: " + ", ".join(missing)
            )

    def _initialize_database(self) -> None:
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA busy_timeout=30000")
            existing_schema_version: int | None = None
            has_schema_meta = self._connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type='table' AND name='schema_meta'
                """
            ).fetchone()
            if has_schema_meta:
                schema_row = self._connection.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()
                if schema_row is not None:
                    try:
                        existing_schema_version = int(schema_row["value"])
                    except (TypeError, ValueError) as exc:
                        raise RuntimeError("database schema version is invalid") from exc
                    if existing_schema_version > SCHEMA_VERSION:
                        raise RuntimeError(
                            "database schema version "
                            f"{existing_schema_version} is newer than supported "
                            f"version {SCHEMA_VERSION}"
                        )
                    if existing_schema_version == SCHEMA_VERSION:
                        self._assert_current_schema_contract()
                        return
            self._migration_from_version = existing_schema_version
            self._migration_started = True
            self._migration_checkpoint("before_schema")
            self._connection.executescript("BEGIN IMMEDIATE;\n" + _SCHEMA)
            self._migration_checkpoint("after_schema")
            query_job_columns = {
                row["name"]
                for row in self._connection.execute("PRAGMA table_info(query_jobs)").fetchall()
            }
            if "not_before" not in query_job_columns:
                self._connection.execute("ALTER TABLE query_jobs ADD COLUMN not_before TEXT")
            if "claim_lease_token" not in query_job_columns:
                self._connection.execute(
                    "ALTER TABLE query_jobs ADD COLUMN claim_lease_token TEXT"
                )
            self._migration_checkpoint("after_query_job_columns")
            run_columns = {
                row["name"]
                for row in self._connection.execute("PRAGMA table_info(runs)").fetchall()
            }
            if "retrieval_hash" not in run_columns:
                self._connection.execute("ALTER TABLE runs ADD COLUMN retrieval_hash TEXT")
            if "analysis_policy_hash" not in run_columns:
                self._connection.execute(
                    "ALTER TABLE runs ADD COLUMN analysis_policy_hash TEXT"
                )
            if "owner_pid" not in run_columns:
                self._connection.execute("ALTER TABLE runs ADD COLUMN owner_pid INTEGER")
            if "lease_token" not in run_columns:
                self._connection.execute("ALTER TABLE runs ADD COLUMN lease_token TEXT")
            if "lease_expires_at" not in run_columns:
                self._connection.execute(
                    "ALTER TABLE runs ADD COLUMN lease_expires_at TEXT"
                )
            self._connection.execute(
                """
                UPDATE runs
                SET retrieval_hash=COALESCE(retrieval_hash, config_hash),
                    analysis_policy_hash=COALESCE(analysis_policy_hash, config_hash)
                """
            )
            snapshot_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(profile_snapshots)"
                ).fetchall()
            }
            if "retrieval_hash" not in snapshot_columns:
                self._connection.execute(
                    "ALTER TABLE profile_snapshots ADD COLUMN retrieval_hash TEXT"
                )
            if "analysis_policy_hash" not in snapshot_columns:
                self._connection.execute(
                    "ALTER TABLE profile_snapshots ADD COLUMN analysis_policy_hash TEXT"
                )
            document_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(documents)"
                ).fetchall()
            }
            if "document_policy_hash" not in document_columns:
                self._connection.execute(
                    "ALTER TABLE documents ADD COLUMN document_policy_hash TEXT"
                )
            self._connection.execute(
                """
                INSERT INTO source_cooldowns(source, not_before, reason, updated_at)
                SELECT
                    source, MAX(not_before), 'migrated from deferred query job', ?
                FROM query_jobs
                WHERE status='retry' AND not_before IS NOT NULL AND not_before>?
                GROUP BY source
                ON CONFLICT(source) DO UPDATE SET
                    not_before=MAX(source_cooldowns.not_before, excluded.not_before),
                    reason=CASE
                        WHEN excluded.not_before>=source_cooldowns.not_before
                        THEN excluded.reason
                        ELSE source_cooldowns.reason
                    END,
                    updated_at=excluded.updated_at
                """,
                (utc_now(), utc_now()),
            )
            analysis_task_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(analysis_tasks)"
                ).fetchall()
            }
            if "profile_id" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN profile_id TEXT"
                )
            if "config_hash" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN config_hash TEXT"
                )
            if "retrieval_hash" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN retrieval_hash TEXT"
                )
            if "profile_version" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN profile_version INTEGER"
                )
            if "input_sha256" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN input_sha256 TEXT"
                )
            if "claimed_run_id" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN claimed_run_id TEXT"
                )
            if "claim_lease_token" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN claim_lease_token TEXT"
                )
            if "not_before" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN not_before TEXT"
                )
            if "phase" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks "
                    "ADD COLUMN phase TEXT NOT NULL DEFAULT 'queued'"
                )
            if "phase_done" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks "
                    "ADD COLUMN phase_done INTEGER NOT NULL DEFAULT 0"
                )
            if "phase_total" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks "
                    "ADD COLUMN phase_total INTEGER NOT NULL DEFAULT 0"
                )
            if "phase_updated_at" not in analysis_task_columns:
                self._connection.execute(
                    "ALTER TABLE analysis_tasks ADD COLUMN phase_updated_at TEXT"
                )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_analysis_tasks_claim_v2
                ON analysis_tasks(status, not_before, id)
                """
            )
            work_scope_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(work_scopes)"
                ).fetchall()
            }
            if "not_before" not in work_scope_columns:
                self._connection.execute(
                    "ALTER TABLE work_scopes ADD COLUMN not_before TEXT"
                )
            if "last_error" not in work_scope_columns:
                self._connection.execute(
                    "ALTER TABLE work_scopes ADD COLUMN last_error TEXT"
                )
            if "active_run_id" not in work_scope_columns:
                self._connection.execute(
                    "ALTER TABLE work_scopes ADD COLUMN active_run_id TEXT"
                )
            if "active_lease_token" not in work_scope_columns:
                self._connection.execute(
                    "ALTER TABLE work_scopes ADD COLUMN active_lease_token TEXT"
                )
            verification_task_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(verification_tasks)"
                ).fetchall()
            }
            if "verified_work_id" not in verification_task_columns:
                self._connection.execute(
                    "ALTER TABLE verification_tasks ADD COLUMN verified_work_id INTEGER"
                )
            if "resolution" not in verification_task_columns:
                self._connection.execute(
                    "ALTER TABLE verification_tasks ADD COLUMN resolution TEXT"
                )
            if "decision_code" not in verification_task_columns:
                self._connection.execute(
                    "ALTER TABLE verification_tasks ADD COLUMN decision_code TEXT"
                )
            if "claim_lease_token" not in verification_task_columns:
                self._connection.execute(
                    "ALTER TABLE verification_tasks ADD COLUMN claim_lease_token TEXT"
                )
            analysis_columns = {
                row["name"]
                for row in self._connection.execute("PRAGMA table_info(analyses)").fetchall()
            }
            if "profile_id" not in analysis_columns:
                self._connection.execute("ALTER TABLE analyses ADD COLUMN profile_id TEXT")
            if "config_hash" not in analysis_columns:
                self._connection.execute("ALTER TABLE analyses ADD COLUMN config_hash TEXT")
            if "retrieval_hash" not in analysis_columns:
                self._connection.execute(
                    "ALTER TABLE analyses ADD COLUMN retrieval_hash TEXT"
                )
            if "profile_version" not in analysis_columns:
                self._connection.execute(
                    "ALTER TABLE analyses ADD COLUMN profile_version INTEGER"
                )
            if "provenance_status" not in analysis_columns:
                self._connection.execute(
                    """
                    ALTER TABLE analyses
                    ADD COLUMN provenance_status TEXT NOT NULL
                    DEFAULT 'legacy_or_unknown'
                    """
                )
            report_issue_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(report_issues)"
                ).fetchall()
            }
            for column, declaration in (
                ("run_id", "TEXT"),
                ("publication_key", "TEXT"),
                ("terminal_status", "TEXT"),
                ("payload_sha256", "TEXT"),
                ("payload_json", "TEXT"),
                ("report_sha256", "TEXT"),
                ("selection_sha256", "TEXT"),
                ("run_summary_path", "TEXT"),
            ):
                if column not in report_issue_columns:
                    self._connection.execute(
                        f"ALTER TABLE report_issues ADD COLUMN {column} {declaration}"
                    )
            report_item_columns = {
                row["name"]
                for row in self._connection.execute(
                    "PRAGMA table_info(report_issue_items)"
                ).fetchall()
            }
            for column in ("input_sha256", "snapshot_sha256", "snapshot_json"):
                if column not in report_item_columns:
                    self._connection.execute(
                        f"ALTER TABLE report_issue_items ADD COLUMN {column} TEXT"
                    )
            self._connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_report_issues_run
                ON report_issues(run_id) WHERE run_id IS NOT NULL
                """
            )
            self._connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS idx_report_issues_publication_key
                ON report_issues(publication_key)
                WHERE publication_key IS NOT NULL
                """
            )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO profile_snapshots(
                    config_hash, retrieval_hash, analysis_policy_hash,
                    profile_id, profile_version, config_json, created_at
                )
                SELECT config_hash, config_hash, config_hash,
                       profile_id, profile_version, config_json, created_at
                FROM profiles
                """
            )
            self._connection.execute(
                """
                INSERT INTO work_scopes(
                    work_id, config_hash, profile_id, profile_version,
                    lane, state, admission_code, first_seen_at, last_seen_at
                )
                SELECT
                    rh.work_id, COALESCE(r.retrieval_hash, r.config_hash),
                    r.profile_id, r.profile_version,
                    w.lane, w.state, w.admission_code,
                    MIN(rh.seen_at), MAX(rh.seen_at)
                FROM run_hits rh
                JOIN runs r ON r.id=rh.run_id
                JOIN works w ON w.id=rh.work_id
                GROUP BY rh.work_id, COALESCE(r.retrieval_hash, r.config_hash)
                ON CONFLICT(work_id, config_hash) DO UPDATE SET
                    first_seen_at=MIN(work_scopes.first_seen_at, excluded.first_seen_at),
                    last_seen_at=MAX(work_scopes.last_seen_at, excluded.last_seen_at)
                """
            )
            self._connection.execute(
                """
                UPDATE analysis_tasks AS t
                SET profile_id=(
                        SELECT ws.profile_id FROM work_scopes ws
                        WHERE ws.work_id=t.work_id LIMIT 1
                    ),
                    profile_version=(
                        SELECT ws.profile_version FROM work_scopes ws
                        WHERE ws.work_id=t.work_id LIMIT 1
                    )
                WHERE t.profile_id IS NULL
                  AND (
                    SELECT COUNT(DISTINCT ws.profile_id || ':' || ws.profile_version)
                    FROM work_scopes ws WHERE ws.work_id=t.work_id
                  )=1
                """
            )
            self._connection.execute(
                """
                UPDATE analyses AS a
                SET profile_id=(
                        SELECT t.profile_id FROM analysis_tasks t WHERE t.id=a.task_id
                    ),
                    profile_version=(
                        SELECT t.profile_version FROM analysis_tasks t WHERE t.id=a.task_id
                    )
                WHERE a.profile_id IS NULL
                """
            )
            self._connection.execute(
                """
                UPDATE analyses AS a
                SET config_hash=(
                    SELECT COALESCE(r.analysis_policy_hash, r.config_hash)
                    FROM run_hits rh
                    JOIN runs r ON r.id=rh.run_id
                    WHERE rh.work_id=a.work_id
                      AND r.started_at<=a.created_at
                    ORDER BY r.started_at DESC
                    LIMIT 1
                )
                WHERE a.config_hash IS NULL
                """
            )
            self._connection.execute(
                """
                UPDATE analysis_tasks AS t
                SET config_hash=COALESCE(
                    (
                        SELECT a.config_hash FROM analyses a WHERE a.task_id=t.id
                    ),
                    (
                        SELECT COALESCE(r.analysis_policy_hash, r.config_hash)
                        FROM run_hits rh
                        JOIN runs r ON r.id=rh.run_id
                        WHERE rh.work_id=t.work_id
                          AND r.started_at<=COALESCE(t.started_at, t.updated_at)
                        ORDER BY r.started_at DESC
                        LIMIT 1
                    )
                )
                WHERE t.config_hash IS NULL
                """
            )
            self._connection.execute(
                """
                UPDATE analysis_tasks AS t
                SET retrieval_hash=(
                    SELECT COALESCE(r.retrieval_hash, r.config_hash)
                    FROM run_hits rh
                    JOIN runs r ON r.id=rh.run_id
                    WHERE rh.work_id=t.work_id
                      AND r.started_at<=COALESCE(t.started_at, t.updated_at)
                    ORDER BY r.started_at DESC
                    LIMIT 1
                )
                WHERE t.retrieval_hash IS NULL
                """
            )
            self._connection.execute(
                """
                UPDATE analyses AS a
                SET retrieval_hash=(
                    SELECT t.retrieval_hash FROM analysis_tasks t WHERE t.id=a.task_id
                )
                WHERE a.retrieval_hash IS NULL
                """
            )
            self._connection.execute(
                """
                UPDATE analysis_tasks AS t
                SET input_sha256=(
                    SELECT COALESCE(d.text_sha256, d.content_sha256)
                    FROM documents d WHERE d.id=t.document_id
                )
                WHERE t.input_sha256 IS NULL
                """
            )
            self._migration_checkpoint("after_data_backfills")
            self._migrate_document_policy_state(self._connection)
            self._migration_checkpoint("after_document_policy")
            self._assert_current_schema_contract()
            self._migration_checkpoint("before_schema_version")
            self._connection.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._migration_checkpoint("after_schema_version")
            self._connection.execute("COMMIT")
            self._migration_started = False

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "RadarStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")

    @staticmethod
    def _coverage_dict(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
            except (TypeError, ValueError, json.JSONDecodeError):
                return {}
            if isinstance(decoded, dict):
                return decoded
        return {}

    @classmethod
    def _append_document_processing_observation(
        cls,
        connection: sqlite3.Connection,
        document: sqlite3.Row | dict[str, Any],
        *,
        event_type: str,
        observed_at: str,
    ) -> None:
        row = dict(document)
        coverage = cls._coverage_dict(row.get("coverage_json"))
        connection.execute(
            """
            INSERT INTO document_processing_observations(
                document_id, work_id, content_kind, event_type, status,
                document_policy_hash, source_url, local_path, text_path,
                content_sha256, text_sha256, byte_count, text_char_count,
                page_count, coverage_json, receipt_json, error, observed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(row["id"]),
                int(row["work_id"]),
                str(row["content_kind"]),
                event_type,
                str(row["status"]),
                row.get("document_policy_hash"),
                row.get("source_url"),
                row.get("local_path"),
                row.get("text_path"),
                row.get("content_sha256"),
                row.get("text_sha256"),
                row.get("byte_count"),
                row.get("text_char_count"),
                row.get("page_count"),
                json_dumps(coverage),
                json_dumps(observation_receipt(coverage)),
                row.get("error"),
                observed_at,
            ),
        )

    def _migrate_document_policy_state(
        self,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        timestamp = utc_now()
        transaction_context = (
            nullcontext(connection) if connection is not None else self.transaction()
        )
        with transaction_context as connection:
            legacy_rows = connection.execute(
                """
                SELECT d.*
                FROM documents d
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM document_processing_observations observation
                    WHERE observation.document_id=d.id
                )
                ORDER BY d.id
                """
            ).fetchall()
            for row in legacy_rows:
                self._append_document_processing_observation(
                    connection,
                    row,
                    event_type="legacy_snapshot",
                    observed_at=timestamp,
                )

            stale_rows = connection.execute(
                """
                SELECT *
                FROM documents
                WHERE content_kind=?
                  AND status='ready'
                  AND NOT r3_document_is_analysis_eligible(
                      content_kind,
                      status,
                      document_policy_hash,
                      coverage_json
                  )
                ORDER BY id
                """,
                (PDF_CONTENT_KIND,),
            ).fetchall()
            for stale in stale_rows:
                work_id = int(stale["work_id"])
                document_id = int(stale["id"])
                coverage = self._coverage_dict(stale["coverage_json"])
                coverage.update(
                    {
                        "complete": False,
                        "security_status": "incomplete_security",
                        "reason": "pdf_security_reparse_required",
                        "failure_code": "document_policy_mismatch",
                        "document_policy_invalidation": {
                            "reason": "document_policy_stale",
                            "previous_document_policy_hash": stale[
                                "document_policy_hash"
                            ],
                            "required_document_policy_hash": self.document_policy_hash,
                            "invalidated_at": timestamp,
                        },
                    }
                )
                error = (
                    "The PDF document policy changed; content must be safely "
                    "reprocessed before analysis."
                )
                connection.execute(
                    """
                    UPDATE documents
                    SET status='retry', coverage_json=?, error=?, updated_at=?
                    WHERE id=? AND status='ready'
                    """,
                    (json_dumps(coverage), error, timestamp, document_id),
                )
                connection.execute(
                    """
                    UPDATE analysis_tasks
                    SET status='superseded',
                        error='superseded because the PDF document policy changed',
                        claimed_run_id=NULL, claim_lease_token=NULL,
                        not_before=NULL, updated_at=?
                    WHERE document_id=?
                      AND status IN ('pending','retry','running')
                    """,
                    (timestamp, document_id),
                )
                connection.execute(
                    "UPDATE works SET state='content_retry', updated_at=? WHERE id=?",
                    (timestamp, work_id),
                )
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state='content_retry', not_before=NULL,
                        last_error=?, active_run_id=NULL,
                        active_lease_token=NULL, last_seen_at=?
                    WHERE work_id=?
                      AND state NOT IN ('rejected','verification_pending')
                    """,
                    (error, timestamp, work_id),
                )
                invalidated = connection.execute(
                    "SELECT * FROM documents WHERE id=?",
                    (document_id,),
                ).fetchone()
                self._append_document_processing_observation(
                    connection,
                    invalidated,
                    event_type="policy_invalidated",
                    observed_at=timestamp,
                )

            retry_rows = connection.execute(
                """
                SELECT *
                FROM documents
                WHERE content_kind=? AND status='retry'
                ORDER BY id
                """,
                (PDF_CONTENT_KIND,),
            ).fetchall()
            for retry_row in retry_rows:
                coverage = self._coverage_dict(retry_row["coverage_json"])
                invalidation = coverage.get("document_policy_invalidation")
                if not (
                    isinstance(invalidation, dict)
                    and invalidation.get("reason") == "document_policy_stale"
                ):
                    continue
                if (
                    coverage.get("reason")
                    == "pdf_security_reparse_required"
                    and coverage.get("failure_code")
                    == "document_policy_mismatch"
                ):
                    continue
                coverage.update(
                    {
                        "complete": False,
                        "security_status": "incomplete_security",
                        "reason": "pdf_security_reparse_required",
                        "failure_code": "document_policy_mismatch",
                    }
                )
                connection.execute(
                    """
                    UPDATE documents
                    SET coverage_json=?, updated_at=?
                    WHERE id=? AND status='retry'
                    """,
                    (
                        json_dumps(coverage),
                        timestamp,
                        int(retry_row["id"]),
                    ),
                )
                normalized = connection.execute(
                    "SELECT * FROM documents WHERE id=?",
                    (int(retry_row["id"]),),
                ).fetchone()
                self._append_document_processing_observation(
                    connection,
                    normalized,
                    event_type="policy_invalidation_normalized",
                    observed_at=timestamp,
                )

    @staticmethod
    def _require_run_lease(
        connection: sqlite3.Connection,
        run_id: str,
        lease_token: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM runs
            WHERE id=? AND status='running' AND lease_token=?
            """,
            (run_id, lease_token),
        ).fetchone()
        if row is None:
            raise RunAlreadyActiveError("run lease was lost")

    def register_profile(self, settings: Settings) -> None:
        with self.transaction() as connection:
            config_json = canonical_json(settings.raw)
            timestamp = utc_now()
            connection.execute(
                """
                INSERT OR IGNORE INTO profile_snapshots(
                    config_hash, retrieval_hash, analysis_policy_hash,
                    profile_id, profile_version, config_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    settings.config_hash,
                    settings.retrieval_hash,
                    settings.analysis_policy_hash,
                    settings.profile_id,
                    settings.profile_version,
                    config_json,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO profiles(
                    profile_id, profile_version, config_hash, config_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(profile_id, profile_version) DO UPDATE SET
                    config_hash=excluded.config_hash,
                    config_json=excluded.config_json
                """,
                (
                    settings.profile_id,
                    settings.profile_version,
                    settings.config_hash,
                    config_json,
                    timestamp,
                ),
            )

    def create_or_resume_run(
        self,
        settings: Settings,
        mode: str,
    ) -> tuple[str, bool, str]:
        self.register_profile(settings)
        now = datetime.now(timezone.utc)
        now_text = now.isoformat(timespec="seconds")
        deadline = (now + timedelta(seconds=settings.max_runtime_seconds)).isoformat(
            timespec="seconds"
        )
        lease_token = str(uuid.uuid4())
        lease_expires_at = (now + timedelta(minutes=30)).isoformat(timespec="seconds")
        with self.transaction() as connection:
            stale_analysis_runs = connection.execute(
                """
                SELECT id, lease_token
                FROM runs
                WHERE status='running'
                  AND COALESCE(analysis_policy_hash, config_hash)=?
                  AND (
                      lease_expires_at IS NULL
                      OR lease_expires_at<=?
                  )
                ORDER BY updated_at
                """,
                (
                    settings.analysis_policy_hash,
                    now_text,
                ),
            ).fetchall()
            for stale_run in stale_analysis_runs:
                stale_run_id = str(stale_run["id"])
                stale_token = stale_run["lease_token"]
                connection.execute(
                    """
                    UPDATE query_jobs
                    SET status='pending',
                        attempts=CASE
                            WHEN status='running' THEN MAX(attempts-1, 0)
                            ELSE attempts
                        END,
                        error='recovered expired run lease',
                        not_before=NULL, claim_lease_token=NULL, updated_at=?
                    WHERE run_id=?
                      AND (status='running' OR claim_lease_token IS NOT NULL)
                    """,
                    (now_text, stale_run_id),
                )
                connection.execute(
                    """
                    UPDATE analysis_tasks
                    SET status='retry',
                        attempts=CASE
                            WHEN status='running' THEN MAX(attempts-1, 0)
                            ELSE attempts
                        END,
                        error='recovered expired run lease',
                        claimed_run_id=NULL, claim_lease_token=NULL,
                        not_before=NULL, updated_at=?
                    WHERE status='running'
                      AND (
                          claimed_run_id=?
                          OR (? IS NOT NULL AND claim_lease_token=?)
                          OR (
                              claimed_run_id IS NULL
                              AND claim_lease_token IS NULL
                              AND config_hash=?
                          )
                      )
                    """,
                    (
                        now_text,
                        stale_run_id,
                        stale_token,
                        stale_token,
                        settings.analysis_policy_hash,
                    ),
                )
                connection.execute(
                    """
                    UPDATE analysis_tasks
                    SET claimed_run_id=NULL, claim_lease_token=NULL,
                        updated_at=?
                    WHERE status!='running'
                      AND (
                          claimed_run_id=?
                          OR (? IS NOT NULL AND claim_lease_token=?)
                      )
                    """,
                    (
                        now_text,
                        stale_run_id,
                        stale_token,
                        stale_token,
                    ),
                )
                connection.execute(
                    """
                    UPDATE verification_tasks
                    SET status='retry',
                        attempts=CASE
                            WHEN status='running' THEN MAX(attempts-1, 0)
                            ELSE attempts
                        END,
                        error='recovered expired run lease',
                        not_before=NULL, claim_lease_token=NULL, updated_at=?
                    WHERE run_id=?
                      AND (status='running' OR claim_lease_token IS NOT NULL)
                    """,
                    (now_text, stale_run_id),
                )
                connection.execute(
                    """
                    UPDATE works
                    SET state=CASE
                            WHEN state='content_running' THEN 'content_retry'
                            WHEN state='analysis_running' THEN 'analysis_pending'
                            ELSE state
                        END,
                        updated_at=?
                    WHERE id IN (
                        SELECT work_id
                        FROM work_scopes
                        WHERE (
                            active_run_id=?
                            OR (? IS NOT NULL AND active_lease_token=?)
                        )
                          AND state IN (
                              'content_running',
                              'analysis_running'
                          )
                    )
                    """,
                    (
                        now_text,
                        stale_run_id,
                        stale_token,
                        stale_token,
                    ),
                )
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state=CASE
                            WHEN state='content_running' THEN 'content_retry'
                            WHEN state='analysis_running' THEN 'analysis_pending'
                            ELSE state
                        END,
                        active_run_id=NULL, active_lease_token=NULL,
                        last_seen_at=?
                    WHERE (
                        active_run_id=?
                        OR (? IS NOT NULL AND active_lease_token=?)
                    )
                    """,
                    (
                        now_text,
                        stale_run_id,
                        stale_token,
                        stale_token,
                    ),
                )
                connection.execute(
                    """
                    UPDATE runs
                    SET status='paused', updated_at=?, ended_at=?,
                        error='recovered expired run lease',
                        owner_pid=NULL, lease_token=NULL,
                        lease_expires_at=NULL
                    WHERE id=? AND status='running'
                    """,
                    (now_text, now_text, stale_run_id),
                )
                connection.execute(
                    """
                    INSERT INTO events(
                        run_id, timestamp, severity, component,
                        event_type, message, details_json
                    ) VALUES (?, ?, 'warning', 'storage', ?, ?, ?)
                    """,
                    (
                        stale_run_id,
                        now_text,
                        "expired_run_lease_recovered",
                        "released stale claims before starting a compatible run",
                        json_dumps(
                            {
                                "analysis_policy_hash": (
                                    settings.analysis_policy_hash
                                ),
                                "previous_lease_token_present": (
                                    stale_token is not None
                                ),
                            }
                        ),
                    ),
                )
            conflicting_analysis_run = None
            if _analysis_exclusive_run_mode(mode):
                conflicting_analysis_run = connection.execute(
                    """
                    SELECT id, mode
                    FROM runs
                    WHERE status='running'
                      AND lease_expires_at IS NOT NULL
                      AND lease_expires_at>?
                      AND COALESCE(analysis_policy_hash, config_hash)=?
                      AND (
                          mode IN ('run', 'weekly', 'smoke')
                          OR mode LIKE 'run:%'
                          OR mode LIKE 'weekly:%'
                          OR mode LIKE 'smoke:%'
                      )
                    ORDER BY updated_at DESC
                    LIMIT 1
                    """,
                    (
                        now_text,
                        settings.analysis_policy_hash,
                    ),
                ).fetchone()
            if conflicting_analysis_run is not None:
                raise RunAlreadyActiveError(
                    "runs are mutually exclusive for the same analysis "
                    "policy; active run "
                    f"{conflicting_analysis_run['id']} uses mode "
                    f"{conflicting_analysis_run['mode']}"
                )
            row = connection.execute(
                """
                SELECT id, status, lease_token, lease_expires_at FROM runs
                WHERE profile_id=? AND profile_version=? AND config_hash=? AND mode=?
                  AND status IN ('paused', 'running')
                ORDER BY updated_at DESC LIMIT 1
                """,
                (
                    settings.profile_id,
                    settings.profile_version,
                    settings.config_hash,
                    mode,
                ),
            ).fetchone()
            if row:
                if (
                    row["status"] == "running"
                    and row["lease_expires_at"]
                    and str(row["lease_expires_at"]) > now_text
                ):
                    raise RunAlreadyActiveError(
                        f"run {row['id']} already has an active lease"
                    )
                run_id = str(row["id"])
                stale_lease_token = row["lease_token"]
                connection.execute(
                    """
                    UPDATE runs
                    SET status='running', invocation_count=invocation_count+1,
                        updated_at=?, deadline_at=?, ended_at=NULL, error=NULL,
                        owner_pid=?, lease_token=?, lease_expires_at=?
                    WHERE id=?
                    """,
                    (
                        now_text,
                        deadline,
                        os.getpid(),
                        lease_token,
                        lease_expires_at,
                        run_id,
                    ),
                )
                reconciled = connection.execute(
                    """
                    UPDATE analysis_tasks AS task
                    SET status='completed',
                        completed_at=COALESCE(
                            completed_at,
                            (
                                SELECT analysis.created_at
                                FROM analyses analysis
                                WHERE analysis.task_id=task.id
                                  AND analysis.deep_read_status='complete'
                                  AND analysis.provenance_status NOT LIKE 'invalidated_%'
                                ORDER BY analysis.created_at DESC
                                LIMIT 1
                            )
                        ),
                        error=NULL, not_before=NULL,
                        claimed_run_id=NULL, claim_lease_token=NULL,
                        updated_at=?
                    WHERE task.status IN ('pending','retry','running')
                      AND task.config_hash=?
                      AND task.retrieval_hash=?
                      AND task.profile_id=?
                      AND task.profile_version=?
                      AND EXISTS (
                          SELECT 1
                          FROM analyses analysis
                          WHERE analysis.task_id=task.id
                            AND analysis.deep_read_status='complete'
                            AND analysis.provenance_status NOT LIKE 'invalidated_%'
                      )
                      AND EXISTS (
                          SELECT 1
                          FROM documents current_document
                          WHERE current_document.id=task.document_id
                            AND COALESCE(
                                current_document.text_sha256,
                                current_document.content_sha256
                            )=task.input_sha256
                            AND r3_document_is_analysis_eligible(
                                current_document.content_kind,
                                current_document.status,
                                current_document.document_policy_hash,
                                current_document.coverage_json
                            )
                      )
                    """,
                    (
                        now_text,
                        settings.analysis_policy_hash,
                        settings.retrieval_hash,
                        settings.profile_id,
                        settings.profile_version,
                    ),
                ).rowcount
                if reconciled:
                    connection.execute(
                        """
                        INSERT INTO events(
                            run_id, timestamp, severity, component,
                            event_type, message, details_json
                        ) VALUES (?, ?, 'warning', 'storage', ?, ?, ?)
                        """,
                        (
                            run_id,
                            now_text,
                            "completed_analysis_tasks_reconciled",
                            "restored task state from persisted complete analyses",
                            json_dumps(
                                {
                                    "task_count": int(reconciled),
                                    "reason": "persisted_complete_analysis",
                                }
                            ),
                        ),
                    )
                if stale_lease_token is None:
                    connection.execute(
                        """
                        UPDATE query_jobs
                        SET status='pending', attempts=MAX(attempts-1, 0),
                            claim_lease_token=NULL, updated_at=?
                        WHERE run_id=? AND claim_lease_token IS NULL
                          AND status='running'
                        """,
                        (now_text, run_id),
                    )
                    connection.execute(
                        """
                        UPDATE analysis_tasks
                        SET status='retry', attempts=MAX(attempts-1, 0),
                            error='recovered legacy running task',
                            claimed_run_id=NULL, claim_lease_token=NULL,
                            not_before=NULL, updated_at=?
                        WHERE status='running' AND claim_lease_token IS NULL
                          AND (
                              claimed_run_id=?
                              OR (
                                  claimed_run_id IS NULL
                                  AND config_hash=?
                              )
                          )
                        """,
                        (now_text, run_id, settings.analysis_policy_hash),
                    )
                    connection.execute(
                        """
                        UPDATE verification_tasks
                        SET status='retry', attempts=MAX(attempts-1, 0),
                            error='recovered legacy running task',
                            claim_lease_token=NULL, updated_at=?
                        WHERE run_id=? AND claim_lease_token IS NULL
                          AND status='running'
                        """,
                        (now_text, run_id),
                    )
                    connection.execute(
                        """
                        UPDATE work_scopes
                        SET state=CASE
                            WHEN state='content_running' THEN 'content_retry'
                            WHEN state='analysis_running' THEN 'analysis_pending'
                            ELSE state
                        END,
                        active_run_id=NULL, active_lease_token=NULL,
                        last_seen_at=?
                        WHERE config_hash=?
                          AND state IN ('content_running','analysis_running')
                          AND (
                              active_run_id=?
                              OR (
                                  active_run_id IS NULL
                                  AND active_lease_token IS NULL
                              )
                          )
                        """,
                        (now_text, settings.retrieval_hash, run_id),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE query_jobs
                        SET status='pending', attempts=MAX(attempts-1, 0),
                            claim_lease_token=NULL, updated_at=?
                        WHERE run_id=? AND claim_lease_token=?
                          AND status='running'
                        """,
                        (now_text, run_id, stale_lease_token),
                    )
                    connection.execute(
                        """
                        UPDATE analysis_tasks
                        SET status='retry', attempts=MAX(attempts-1, 0),
                            error='recovered stale running task',
                            claimed_run_id=NULL, claim_lease_token=NULL,
                            not_before=NULL, updated_at=?
                        WHERE claimed_run_id=? AND claim_lease_token=?
                          AND status='running'
                        """,
                        (now_text, run_id, stale_lease_token),
                    )
                    connection.execute(
                        """
                        UPDATE verification_tasks
                        SET status='retry', attempts=MAX(attempts-1, 0),
                            error='recovered stale running task',
                            claim_lease_token=NULL, updated_at=?
                        WHERE run_id=? AND claim_lease_token=?
                          AND status='running'
                        """,
                        (now_text, run_id, stale_lease_token),
                    )
                    connection.execute(
                        """
                        UPDATE work_scopes
                        SET state=CASE
                            WHEN state='content_running' THEN 'content_retry'
                            WHEN state='analysis_running' THEN 'analysis_pending'
                            ELSE state
                        END,
                        active_run_id=NULL, active_lease_token=NULL,
                        last_seen_at=?
                        WHERE active_run_id=? AND active_lease_token=?
                          AND state IN ('content_running','analysis_running')
                        """,
                        (now_text, run_id, stale_lease_token),
                    )
                return run_id, True, lease_token
            run_id = str(uuid.uuid4())
            timestamp = utc_now()
            connection.execute(
                """
                INSERT INTO runs(
                    id, profile_id, profile_version, config_hash,
                    retrieval_hash, analysis_policy_hash, mode, status,
                    started_at, updated_at, deadline_at,
                    owner_pid, lease_token, lease_expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    settings.profile_id,
                    settings.profile_version,
                    settings.config_hash,
                    settings.retrieval_hash,
                    settings.analysis_policy_hash,
                    mode,
                    timestamp,
                    timestamp,
                    deadline,
                    os.getpid(),
                    lease_token,
                    lease_expires_at,
                ),
            )
            return run_id, False, lease_token

    def refresh_run_lease(
        self,
        run_id: str,
        lease_token: str,
        *,
        seconds: int = 1800,
    ) -> None:
        expires_at = (
            datetime.now(timezone.utc) + timedelta(seconds=max(60, seconds))
        ).isoformat(timespec="seconds")
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE runs
                SET lease_expires_at=?, updated_at=?
                WHERE id=? AND lease_token=? AND status='running'
                """,
                (expires_at, utc_now(), run_id, lease_token),
            )
            if cursor.rowcount != 1:
                raise RunAlreadyActiveError("run lease was lost")

    def seed_query_jobs(
        self,
        run_id: str,
        settings: Settings,
        include_hosted: bool,
        *,
        lease_token: str,
        smoke: bool = False,
        include_official: bool = True,
    ) -> int:
        specs = planned_query_job_specs(
            settings,
            include_hosted=include_hosted,
            smoke=smoke,
            include_official=include_official,
        )
        rows = [
            (
                run_id,
                spec["query_id"],
                spec["source"],
                spec["lane"],
                spec["query_text"],
                spec["job_kind"],
                utc_now(),
            )
            for spec in specs
        ]
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            before = connection.total_changes
            connection.executemany(
                """
                INSERT OR IGNORE INTO query_jobs(
                    run_id, query_id, source, lane, query_text, job_kind, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            return connection.total_changes - before

    def claim_query_job(
        self,
        run_id: str,
        lease_token: str,
        job_kind: str = "official",
        source: str | None = None,
    ) -> dict[str, Any] | None:
        now = utc_now()
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            if source is None:
                row = connection.execute(
                    """
                    SELECT q.* FROM query_jobs q
                    WHERE q.run_id=? AND q.job_kind=? AND q.status IN ('pending', 'retry')
                      AND (q.not_before IS NULL OR q.not_before<=?)
                      AND NOT EXISTS (
                        SELECT 1 FROM source_cooldowns c
                        WHERE c.source=q.source AND c.not_before>?
                      )
                    ORDER BY q.id LIMIT 1
                    """,
                    (run_id, job_kind, now, now),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT q.* FROM query_jobs q
                    WHERE q.run_id=? AND q.job_kind=? AND q.source=?
                      AND q.status IN ('pending', 'retry')
                      AND (q.not_before IS NULL OR q.not_before<=?)
                      AND NOT EXISTS (
                        SELECT 1 FROM source_cooldowns c
                        WHERE c.source=q.source AND c.not_before>?
                      )
                    ORDER BY q.id LIMIT 1
                    """,
                    (run_id, job_kind, source, now, now),
                ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE query_jobs
                SET status='running', attempts=attempts+1, started_at=COALESCE(started_at, ?),
                    updated_at=?, error=NULL, claim_lease_token=?
                WHERE id=?
                """,
                (utc_now(), utc_now(), lease_token, row["id"]),
            )
            return dict(row)

    def reserve_http_rate_slot(
        self,
        slot_key: str,
        delay_seconds: float,
    ) -> float:
        now = time.time()
        delay = max(0.0, float(delay_seconds))
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT next_request_at FROM http_rate_slots
                WHERE slot_key=?
                """,
                (slot_key,),
            ).fetchone()
            reserved_at = max(
                now,
                float(row["next_request_at"]) if row is not None else now,
            )
            connection.execute(
                """
                INSERT INTO http_rate_slots(
                    slot_key, next_request_at, updated_at
                ) VALUES (?, ?, ?)
                ON CONFLICT(slot_key) DO UPDATE SET
                    next_request_at=excluded.next_request_at,
                    updated_at=excluded.updated_at
                """,
                (slot_key, reserved_at + delay, utc_now()),
            )
        return max(0.0, reserved_at - now)

    def set_source_cooldown(
        self,
        source: str,
        *,
        not_before: str,
        reason: str | None = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO source_cooldowns(source, not_before, reason, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    not_before=CASE
                        WHEN excluded.not_before > source_cooldowns.not_before
                        THEN excluded.not_before
                        ELSE source_cooldowns.not_before
                    END,
                    reason=CASE
                        WHEN excluded.not_before >= source_cooldowns.not_before
                        THEN excluded.reason
                        ELSE source_cooldowns.reason
                    END,
                    updated_at=excluded.updated_at
                """,
                (source, not_before, reason, utc_now()),
            )

    def block_query_jobs(
        self,
        run_id: str,
        *,
        lease_token: str,
        source: str,
        reason: str,
    ) -> int:
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            cursor = connection.execute(
                """
                UPDATE query_jobs
                SET status='blocked', error=?, updated_at=?
                WHERE run_id=? AND source=? AND status IN ('pending','retry')
                """,
                (reason[:2000], utc_now(), run_id, source),
            )
            return max(0, int(cursor.rowcount))

    def active_source_cooldowns(self) -> list[dict[str, Any]]:
        now = utc_now()
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT source, not_before, reason, updated_at
                FROM source_cooldowns
                WHERE not_before>?
                ORDER BY not_before, source
                """,
                (now,),
            ).fetchall()
            return [dict(row) for row in rows]

    def update_query_job(
        self,
        job_id: int,
        *,
        status: str,
        cursor: str | None = None,
        page_no: int | None = None,
        result_count_delta: int = 0,
        error: str | None = None,
        not_before: str | None = None,
        lease_token: str,
    ) -> None:
        completed_at = utc_now() if status == "completed" else None
        retained_claim = lease_token if status == "running" else None
        with self.transaction() as connection:
            owner = connection.execute(
                """
                SELECT run_id FROM query_jobs
                WHERE id=? AND status='running' AND claim_lease_token=?
                """,
                (job_id, lease_token),
            ).fetchone()
            if owner is None:
                raise RunAlreadyActiveError("query job ownership was lost")
            self._require_run_lease(
                connection,
                str(owner["run_id"]),
                lease_token,
            )
            cursor_result = connection.execute(
                """
                UPDATE query_jobs
                SET status=?, cursor=COALESCE(?, cursor), page_no=COALESCE(?, page_no),
                    result_count=result_count+?, error=?, not_before=?,
                    claim_lease_token=?, updated_at=?, completed_at=?
                WHERE id=? AND status='running' AND claim_lease_token=?
                """,
                (
                    status,
                    cursor,
                    page_no,
                    result_count_delta,
                    error,
                    not_before,
                    retained_claim,
                    utc_now(),
                    completed_at,
                    job_id,
                    lease_token,
                ),
            )
            if cursor_result.rowcount != 1:
                raise RunAlreadyActiveError("query job ownership was lost")

    @staticmethod
    def _record_aliases(record: SourceRecord) -> list[str]:
        aliases = [
            record.canonical_key(),
            f"source:{record.source.casefold()}:{record.source_id.casefold()}",
        ]
        title = normalize_title(record.title)
        if title:
            aliases.append(f"title:{sha256_text(title)[:24]}")
        if record.doi:
            aliases.append(f"doi:{record.doi}")
        if record.arxiv_id:
            aliases.append(f"arxiv:{record.arxiv_id}")
        if record.github_full_name:
            aliases.append(f"github:{record.github_full_name}")
        if record.canonical_url:
            aliases.append(f"url:{sha256_text(record.canonical_url.casefold())[:24]}")
        return list(dict.fromkeys(aliases))

    @staticmethod
    def _record_revision_key(record: SourceRecord) -> str | None:
        if record.source == "github":
            payload = {
                "source": record.source,
                "source_id": record.source_id,
                "pushed_at": record.metadata.get("pushed_at"),
                "updated_at": record.metadata.get("updated_at"),
                "default_branch": record.metadata.get("default_branch"),
            }
        elif record.source == "arxiv":
            payload = {
                "source": record.source,
                "source_id": record.source_id,
                "updated": record.metadata.get("updated"),
            }
        else:
            return None
        if not any(value for key, value in payload.items() if key not in {"source", "source_id"}):
            return None
        return sha256_text(json_dumps(payload))

    def lookup_record_work_id(self, record: SourceRecord) -> int | None:
        record.normalized()
        aliases = self._record_aliases(record)
        placeholders = ",".join("?" for _ in aliases)
        with self._lock:
            source_bound_rows = self._connection.execute(
                """
                SELECT w.*
                FROM source_records sr
                JOIN work_sources ws ON ws.source_record_id=sr.id
                JOIN works w ON w.id=ws.work_id
                WHERE sr.source=? AND sr.source_id=?
                ORDER BY w.id
                """,
                (record.source, record.source_id),
            ).fetchall()
            if len(source_bound_rows) > 1:
                raise ValueError(
                    "one source identity maps to multiple works; manual repair is required"
                )
            if source_bound_rows:
                candidate = source_bound_rows[0]
                identity_conflict = (
                    candidate["kind"] != record.kind
                    or (
                        record.doi
                        and candidate["doi"]
                        and record.doi != candidate["doi"]
                    )
                    or (
                        record.arxiv_id
                        and candidate["arxiv_id"]
                        and record.arxiv_id != candidate["arxiv_id"]
                    )
                    or (
                        record.github_full_name
                        and candidate["github_full_name"]
                        and record.github_full_name
                        != candidate["github_full_name"]
                    )
                )
                if identity_conflict:
                    raise ValueError(
                        "stable source identity conflicts with the existing canonical work"
                    )
                return int(candidate["id"])
            candidate_rows = self._connection.execute(
                f"""
                SELECT DISTINCT w.* FROM works w
                LEFT JOIN work_aliases a ON a.work_id=w.id
                WHERE a.alias IN ({placeholders})
                   OR lower(w.best_url)=lower(?)
                ORDER BY w.id
                """,
                [*aliases, record.canonical_url or ""],
            ).fetchall()
        for candidate in candidate_rows:
            if candidate["kind"] != record.kind:
                continue
            identifier_conflict = (
                bool(record.doi and candidate["doi"])
                and record.doi != candidate["doi"]
            ) or (
                bool(record.arxiv_id and candidate["arxiv_id"])
                and record.arxiv_id != candidate["arxiv_id"]
            ) or (
                bool(record.github_full_name and candidate["github_full_name"])
                and record.github_full_name != candidate["github_full_name"]
            )
            if identifier_conflict:
                continue
            strong_identifier_match = (
                bool(record.doi and candidate["doi"])
                and record.doi == candidate["doi"]
            ) or (
                bool(record.arxiv_id and candidate["arxiv_id"])
                and record.arxiv_id == candidate["arxiv_id"]
            ) or (
                bool(record.github_full_name and candidate["github_full_name"])
                and record.github_full_name == candidate["github_full_name"]
            )
            if (
                record.year
                and candidate["year"]
                and abs(int(record.year) - int(candidate["year"])) > 1
                and not strong_identifier_match
            ):
                continue
            return int(candidate["id"])
        return None

    def ingest_record(
        self,
        *,
        run_id: str,
        lease_token: str,
        query_job_id: int,
        record: SourceRecord,
        decision: AdmissionDecision,
        raw_sha256: str | None,
        raw_path: str | None = None,
    ) -> tuple[int, bool]:
        record.normalized()
        aliases = self._record_aliases(record)
        timestamp = utc_now()
        metadata_json = json_dumps(record.metadata)
        revision_key = self._record_revision_key(record)
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            previous_source = connection.execute(
                """
                SELECT id, metadata_json FROM source_records
                WHERE source=? AND source_id=?
                """,
                (record.source, record.source_id),
            ).fetchone()
            source_bound_work = None
            if previous_source is not None:
                bound_rows = connection.execute(
                    """
                    SELECT w.*
                    FROM work_sources ws
                    JOIN works w ON w.id=ws.work_id
                    WHERE ws.source_record_id=?
                    ORDER BY w.id
                    """,
                    (previous_source["id"],),
                ).fetchall()
                if len(bound_rows) > 1:
                    raise ValueError(
                        "one source identity maps to multiple works; manual repair is required"
                    )
                if bound_rows:
                    source_bound_work = bound_rows[0]
                    identity_conflict = (
                        source_bound_work["kind"] != record.kind
                        or (
                            record.doi
                            and source_bound_work["doi"]
                            and record.doi != source_bound_work["doi"]
                        )
                        or (
                            record.arxiv_id
                            and source_bound_work["arxiv_id"]
                            and record.arxiv_id != source_bound_work["arxiv_id"]
                        )
                        or (
                            record.github_full_name
                            and source_bound_work["github_full_name"]
                            and record.github_full_name
                            != source_bound_work["github_full_name"]
                        )
                    )
                    if identity_conflict:
                        raise ValueError(
                            "stable source identity conflicts with the existing canonical work"
                        )
            previous_revision_key = None
            if previous_source is not None:
                previous_record = SourceRecord(
                    source=record.source,
                    source_id=record.source_id,
                    kind=record.kind,
                    title=record.title,
                    query_id=record.query_id,
                    metadata=json.loads(previous_source["metadata_json"]),
                )
                previous_revision_key = self._record_revision_key(previous_record)
            revision_changed = bool(
                revision_key
                and previous_revision_key
                and revision_key != previous_revision_key
            )
            connection.execute(
                """
                INSERT INTO source_records(
                    source, source_id, kind, title, canonical_url, metadata_json,
                    raw_sha256, first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source, source_id) DO UPDATE SET
                    title=excluded.title,
                    canonical_url=COALESCE(excluded.canonical_url, source_records.canonical_url),
                    metadata_json=excluded.metadata_json,
                    raw_sha256=COALESCE(excluded.raw_sha256, source_records.raw_sha256),
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    record.source,
                    record.source_id,
                    record.kind,
                    record.title,
                    record.canonical_url,
                    metadata_json,
                    raw_sha256,
                    timestamp,
                    timestamp,
                ),
            )
            source_row = connection.execute(
                "SELECT id FROM source_records WHERE source=? AND source_id=?",
                (record.source, record.source_id),
            ).fetchone()
            source_record_id = int(source_row["id"])
            connection.execute(
                """
                INSERT INTO source_observations(
                    source_record_id, run_id, query_job_id, observed_at,
                    metadata_json, metadata_sha256, revision_key, raw_sha256, raw_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_record_id,
                    run_id,
                    query_job_id,
                    timestamp,
                    metadata_json,
                    sha256_text(metadata_json),
                    revision_key,
                    raw_sha256,
                    raw_path,
                ),
            )
            placeholders = ",".join("?" for _ in aliases)
            candidate_rows = connection.execute(
                f"""
                SELECT DISTINCT w.* FROM works w
                LEFT JOIN work_aliases a ON a.work_id=w.id
                WHERE a.alias IN ({placeholders})
                   OR lower(w.best_url)=lower(?)
                ORDER BY w.id
                """,
                [*aliases, record.canonical_url or ""],
            ).fetchall()
            work_row = source_bound_work
            for candidate in candidate_rows:
                if work_row is not None:
                    break
                if candidate["kind"] != record.kind:
                    continue
                identifier_conflict = (
                    bool(record.doi and candidate["doi"])
                    and record.doi != candidate["doi"]
                ) or (
                    bool(record.arxiv_id and candidate["arxiv_id"])
                    and record.arxiv_id != candidate["arxiv_id"]
                ) or (
                    bool(record.github_full_name and candidate["github_full_name"])
                    and record.github_full_name != candidate["github_full_name"]
                )
                if identifier_conflict:
                    continue
                strong_identifier_match = (
                    bool(record.doi and candidate["doi"])
                    and record.doi == candidate["doi"]
                ) or (
                    bool(record.arxiv_id and candidate["arxiv_id"])
                    and record.arxiv_id == candidate["arxiv_id"]
                ) or (
                    bool(record.github_full_name and candidate["github_full_name"])
                    and record.github_full_name == candidate["github_full_name"]
                )
                if (
                    record.year
                    and candidate["year"]
                    and abs(int(record.year) - int(candidate["year"])) > 1
                    and not strong_identifier_match
                ):
                    continue
                work_row = candidate
                break
            created = work_row is None
            if created:
                state = "admitted" if decision.admitted else "rejected"
                if decision.code == "hosted_verification_pending":
                    state = "verification_pending"
                cursor = connection.execute(
                    """
                    INSERT INTO works(
                        canonical_key, kind, title, normalized_title, year, doi, arxiv_id,
                        github_full_name, best_url, pdf_url, lane, state, admission_code,
                        metadata_json, first_seen_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.canonical_key(),
                        record.kind,
                        record.title,
                        normalize_title(record.title),
                        record.year,
                        record.doi,
                        record.arxiv_id,
                        record.github_full_name,
                        record.canonical_url,
                        record.pdf_url,
                        decision.lane,
                        state,
                        decision.code,
                        metadata_json,
                        timestamp,
                        timestamp,
                    ),
                )
                work_id = int(cursor.lastrowid)
            else:
                work_id = int(work_row["id"])
                prior_metadata = json.loads(work_row["metadata_json"])
                source_variants = dict(prior_metadata.get("source_variants") or {})
                source_variants[record.source] = record.metadata
                merged_metadata = dict(record.metadata)
                merged_metadata["source_variants"] = source_variants
                connection.execute(
                    """
                    UPDATE works SET
                        title=CASE WHEN length(?) > length(title) THEN ? ELSE title END,
                        normalized_title=CASE WHEN length(?) > length(title) THEN ? ELSE normalized_title END,
                        year=COALESCE(year, ?),
                        doi=COALESCE(doi, ?),
                        arxiv_id=COALESCE(arxiv_id, ?),
                        github_full_name=COALESCE(github_full_name, ?),
                        best_url=COALESCE(?, best_url),
                        pdf_url=COALESCE(?, pdf_url),
                        metadata_json=?,
                        updated_at=?
                    WHERE id=?
                    """,
                    (
                        record.title,
                        record.title,
                        record.title,
                        normalize_title(record.title),
                        record.year,
                        record.doi,
                        record.arxiv_id,
                        record.github_full_name,
                        record.canonical_url,
                        record.pdf_url,
                        json_dumps(merged_metadata),
                        timestamp,
                        work_id,
                    ),
                )
                if work_row["state"] == "verification_pending" and decision.admitted:
                    connection.execute(
                        """
                        UPDATE works
                        SET state='admitted', admission_code=?, lane=?, updated_at=?
                        WHERE id=?
                        """,
                        (decision.code, decision.lane, timestamp, work_id),
                    )
            connection.executemany(
                "INSERT OR IGNORE INTO work_aliases(alias, work_id) VALUES (?, ?)",
                [(alias, work_id) for alias in aliases],
            )
            connection.execute(
                "INSERT OR IGNORE INTO work_sources(work_id, source_record_id) VALUES (?, ?)",
                (work_id, source_record_id),
            )
            connection.execute(
                """
                INSERT INTO run_hits(
                    run_id, work_id, query_job_id, source_record_id, admitted,
                    admission_code, admission_reason, seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id, query_job_id, source_record_id) DO UPDATE SET
                    work_id=excluded.work_id,
                    admitted=excluded.admitted,
                    admission_code=excluded.admission_code,
                    admission_reason=excluded.admission_reason,
                    seen_at=excluded.seen_at
                """,
                (
                    run_id,
                    work_id,
                    query_job_id,
                    source_record_id,
                    1 if decision.admitted else 0,
                    decision.code,
                    decision.reason,
                    timestamp,
                ),
            )
            run_profile = connection.execute(
                """
                SELECT profile_id, profile_version,
                       COALESCE(retrieval_hash, config_hash) AS retrieval_hash
                FROM runs WHERE id=?
                """,
                (run_id,),
            ).fetchone()
            if run_profile is None:
                raise ValueError(f"run {run_id} does not exist")
            profile_state = "rejected"
            if decision.code == "hosted_verification_pending":
                profile_state = "verification_pending"
            if decision.admitted:
                ready_document = connection.execute(
                    """
                    SELECT 1 FROM documents
                    WHERE work_id=?
                      AND r3_document_is_analysis_eligible(
                          content_kind,
                          status,
                          document_policy_hash,
                          coverage_json
                      )
                    LIMIT 1
                    """,
                    (work_id,),
                ).fetchone()
                profile_state = "content_ready" if ready_document else "admitted"
            connection.execute(
                """
                INSERT INTO work_scopes(
                    work_id, config_hash, profile_id, profile_version, lane, state,
                    admission_code, first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(work_id, config_hash) DO UPDATE SET
                    lane=CASE
                        WHEN excluded.state!='rejected' THEN excluded.lane
                        ELSE work_scopes.lane
                    END,
                    state=CASE
                        WHEN excluded.state='rejected' THEN work_scopes.state
                        WHEN work_scopes.state IN (
                            'content_retry','content_running','content_ready',
                            'analysis_pending','analysis_running',
                            'analysis_failed','analyzed'
                        ) THEN work_scopes.state
                        ELSE excluded.state
                    END,
                    admission_code=CASE
                        WHEN excluded.state!='rejected' THEN excluded.admission_code
                        ELSE work_scopes.admission_code
                    END,
                    last_seen_at=excluded.last_seen_at
                """,
                (
                    work_id,
                    str(run_profile["retrieval_hash"]),
                    str(run_profile["profile_id"]),
                    int(run_profile["profile_version"]),
                    decision.lane,
                    profile_state,
                    decision.code,
                    timestamp,
                    timestamp,
                ),
            )
            terminal_rejection = decision.code in {
                "retracted",
                "archived_repository",
            }
            if terminal_rejection:
                reason = f"source revoked admission: {decision.code}"
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state='rejected', admission_code=?,
                        not_before=NULL, last_error=?,
                        active_run_id=NULL, active_lease_token=NULL,
                        last_seen_at=?
                    WHERE work_id=? AND config_hash=?
                    """,
                    (
                        decision.code,
                        reason,
                        timestamp,
                        work_id,
                        str(run_profile["retrieval_hash"]),
                    ),
                )
                connection.execute(
                    """
                    UPDATE analysis_tasks
                    SET status='superseded', error=?, not_before=NULL,
                        claimed_run_id=NULL, claim_lease_token=NULL,
                        updated_at=?
                    WHERE work_id=? AND retrieval_hash=?
                      AND status IN ('pending','retry','running')
                      AND NOT EXISTS (
                          SELECT 1 FROM work_scopes remaining
                          WHERE remaining.work_id=analysis_tasks.work_id
                            AND remaining.state!='rejected'
                      )
                    """,
                    (
                        reason,
                        timestamp,
                        work_id,
                        str(run_profile["retrieval_hash"]),
                    ),
                )
                connection.execute(
                    """
                    UPDATE works
                    SET state=CASE
                            WHEN EXISTS (
                                SELECT 1 FROM work_scopes remaining
                                WHERE remaining.work_id=works.id
                                  AND remaining.state!='rejected'
                            )
                            THEN state ELSE 'rejected'
                        END,
                        admission_code=CASE
                            WHEN EXISTS (
                                SELECT 1 FROM work_scopes remaining
                                WHERE remaining.work_id=works.id
                                  AND remaining.state!='rejected'
                            )
                            THEN admission_code ELSE ?
                        END,
                        updated_at=?
                    WHERE id=?
                    """,
                    (decision.code, timestamp, work_id),
                )
            if revision_changed and not terminal_rejection:
                connection.execute(
                    """
                    UPDATE works
                    SET state='content_retry', updated_at=?
                    WHERE id=?
                    """,
                    (timestamp, work_id),
                )
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state='content_retry', not_before=NULL,
                        last_error='source revision changed', active_run_id=NULL,
                        active_lease_token=NULL,
                        last_seen_at=?
                    WHERE work_id=?
                      AND state NOT IN ('rejected','verification_pending')
                    """,
                    (timestamp, work_id),
                )
            return work_id, created

    def seed_verification_task(
        self,
        *,
        run_id: str,
        lease_token: str,
        query_job_id: int,
        work_id: int,
    ) -> int:
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO verification_tasks(
                    run_id, query_job_id, work_id, status, updated_at
                ) VALUES (?, ?, ?, 'pending', ?)
                """,
                (run_id, query_job_id, work_id, utc_now()),
            )
            return max(0, int(cursor.rowcount))

    def claim_verification_task(
        self,
        run_id: str,
        lease_token: str,
    ) -> dict[str, Any] | None:
        now = utc_now()
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            row = connection.execute(
                """
                SELECT
                    task.*, q.query_id, q.lane AS query_lane, q.source AS query_source,
                    w.kind, w.title, w.year, w.best_url, w.pdf_url,
                    w.doi, w.arxiv_id, w.github_full_name, w.metadata_json
                FROM verification_tasks task
                JOIN query_jobs q ON q.id=task.query_job_id
                JOIN works w ON w.id=task.work_id
                WHERE task.run_id=?
                  AND task.status IN ('pending','retry')
                  AND (task.not_before IS NULL OR task.not_before<=?)
                ORDER BY task.id
                LIMIT 1
                """,
                (run_id, now),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE verification_tasks
                SET status='running', attempts=attempts+1,
                    started_at=COALESCE(started_at, ?), updated_at=?, error=NULL,
                    claim_lease_token=?
                WHERE id=?
                """,
                (now, now, lease_token, row["id"]),
            )
            return dict(row)

    def update_verification_task(
        self,
        task_id: int,
        *,
        status: str,
        error: str | None = None,
        not_before: str | None = None,
        lease_token: str,
    ) -> None:
        completed_at = utc_now() if status == "completed" else None
        with self.transaction() as connection:
            owner = connection.execute(
                """
                SELECT run_id FROM verification_tasks
                WHERE id=? AND status='running' AND claim_lease_token=?
                """,
                (task_id, lease_token),
            ).fetchone()
            if owner is None:
                raise RunAlreadyActiveError("verification task ownership was lost")
            self._require_run_lease(
                connection,
                str(owner["run_id"]),
                lease_token,
            )
            cursor = connection.execute(
                """
                UPDATE verification_tasks
                SET status=?, error=?, not_before=?, claim_lease_token=NULL,
                    updated_at=?, completed_at=?
                WHERE id=? AND status='running' AND claim_lease_token=?
                """,
                (
                    status,
                    error[:2000] if error else None,
                    not_before,
                    utc_now(),
                    completed_at,
                    task_id,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RunAlreadyActiveError("verification task ownership was lost")

    def resolve_verification_task(
        self,
        task_id: int,
        *,
        pending_work_id: int,
        verified_work_id: int,
        decision: AdmissionDecision,
        lease_token: str,
    ) -> None:
        """Atomically resolve a hosted discovery, including identity replacement."""
        timestamp = utc_now()
        with self.transaction() as connection:
            task = connection.execute(
                """
                SELECT id, run_id, work_id, status, claim_lease_token
                FROM verification_tasks
                WHERE id=?
                """,
                (task_id,),
            ).fetchone()
            if task is None:
                raise ValueError(f"verification task {task_id} does not exist")
            if int(task["work_id"]) != pending_work_id:
                raise ValueError("verification task does not own the pending work")
            if task["status"] != "running":
                raise ValueError(
                    f"verification task {task_id} is not running "
                    f"(status={task['status']})"
                )
            if task["claim_lease_token"] != lease_token:
                raise RunAlreadyActiveError("verification task ownership was lost")
            self._require_run_lease(
                connection,
                str(task["run_id"]),
                lease_token,
            )

            if pending_work_id != verified_work_id:
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state='rejected', admission_code='hosted_identity_replaced',
                        not_before=NULL, last_error=NULL, active_run_id=NULL,
                        active_lease_token=NULL,
                        last_seen_at=?
                    WHERE work_id=? AND state='verification_pending'
                    """,
                    (timestamp, pending_work_id),
                )
                connection.execute(
                    """
                    UPDATE works
                    SET state='rejected',
                        admission_code='hosted_identity_replaced',
                        updated_at=?
                    WHERE id=? AND state='verification_pending'
                    """,
                    (timestamp, pending_work_id),
                )
                resolution = "identity_replaced"
            elif decision.admitted:
                ready_document = connection.execute(
                    """
                    SELECT 1 FROM documents
                    WHERE work_id=?
                      AND r3_document_is_analysis_eligible(
                          content_kind,
                          status,
                          document_policy_hash,
                          coverage_json
                      )
                    LIMIT 1
                    """,
                    (verified_work_id,),
                ).fetchone()
                resolved_state = "content_ready" if ready_document else "admitted"
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state=?, lane=?, admission_code=?,
                        not_before=NULL, last_error=NULL, active_run_id=NULL,
                        active_lease_token=NULL,
                        last_seen_at=?
                    WHERE work_id=? AND state='verification_pending'
                    """,
                    (
                        resolved_state,
                        decision.lane,
                        decision.code,
                        timestamp,
                        pending_work_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE works
                    SET state=?, lane=?, admission_code=?, updated_at=?
                    WHERE id=? AND state='verification_pending'
                    """,
                    (
                        resolved_state,
                        decision.lane,
                        decision.code,
                        timestamp,
                        pending_work_id,
                    ),
                )
                resolution = "admitted"
            else:
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state='rejected', lane=?, admission_code=?,
                        not_before=NULL, last_error=NULL, active_run_id=NULL,
                        active_lease_token=NULL,
                        last_seen_at=?
                    WHERE work_id=? AND state='verification_pending'
                    """,
                    (
                        decision.lane,
                        decision.code,
                        timestamp,
                        pending_work_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE works
                    SET state='rejected', lane=?, admission_code=?, updated_at=?
                    WHERE id=? AND state='verification_pending'
                    """,
                    (
                        decision.lane,
                        decision.code,
                        timestamp,
                        pending_work_id,
                    ),
                )
                resolution = "rejected"

            connection.execute(
                """
                UPDATE verification_tasks
                SET status='completed', verified_work_id=?, resolution=?,
                    decision_code=?, error=NULL, not_before=NULL,
                    claim_lease_token=NULL, updated_at=?, completed_at=?
                WHERE id=? AND status='running' AND claim_lease_token=?
                """,
                (
                    verified_work_id,
                    resolution,
                    decision.code,
                    timestamp,
                    timestamp,
                    task_id,
                    lease_token,
                ),
            )

    def verification_task_counts(self, run_id: str) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM verification_tasks
                WHERE run_id=?
                GROUP BY status
                """,
                (run_id,),
            ).fetchall()
            return {str(row["status"]): int(row["count"]) for row in rows}

    def run_owned_claim_counts(
        self,
        run_id: str,
        lease_token: str,
    ) -> dict[str, int]:
        with self._lock:
            connection = self._connection
            return {
                "query_jobs": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM query_jobs
                        WHERE run_id=?
                          AND (status='running' OR claim_lease_token IS NOT NULL)
                        """,
                        (run_id,),
                    ).fetchone()[0]
                ),
                "verification_tasks": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM verification_tasks
                        WHERE run_id=?
                          AND (status='running' OR claim_lease_token IS NOT NULL)
                        """,
                        (run_id,),
                    ).fetchone()[0]
                ),
                "analysis_tasks": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM analysis_tasks
                        WHERE claimed_run_id=? OR claim_lease_token=?
                        """,
                        (run_id, lease_token),
                    ).fetchone()[0]
                ),
                "work_scopes": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM work_scopes
                        WHERE active_run_id=? OR active_lease_token=?
                        """,
                        (run_id, lease_token),
                    ).fetchone()[0]
                ),
            }

    def claim_work_for_content(
        self,
        config_hash: str,
        *,
        run_id: str,
        lease_token: str,
    ) -> dict[str, Any] | None:
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            row = connection.execute(
                """
                SELECT w.* FROM works w
                JOIN work_scopes ws ON ws.work_id=w.id
                WHERE ws.config_hash=?
                  AND ws.state IN ('admitted', 'content_retry')
                  AND (ws.not_before IS NULL OR ws.not_before<=?)
                ORDER BY w.id LIMIT 1
                """,
                (config_hash, utc_now()),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE work_scopes
                SET state='content_running', not_before=NULL, last_error=NULL,
                    active_run_id=?, active_lease_token=?, last_seen_at=?
                WHERE work_id=? AND config_hash=?
                """,
                (run_id, lease_token, utc_now(), row["id"], config_hash),
            )
            connection.execute(
                "UPDATE works SET state='content_running', updated_at=? WHERE id=?",
                (utc_now(), row["id"]),
            )
            return dict(row)

    def defer_content_work(
        self,
        work_id: int,
        *,
        retrieval_hash: str,
        run_id: str,
        lease_token: str,
        not_before: str,
        error: str,
    ) -> None:
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            cursor = connection.execute(
                """
                UPDATE work_scopes
                SET state='content_retry', not_before=?, last_error=?,
                    active_run_id=NULL, active_lease_token=NULL, last_seen_at=?
                WHERE work_id=? AND config_hash=?
                  AND active_run_id=? AND active_lease_token=?
                """,
                (
                    not_before,
                    error[:2000],
                    utc_now(),
                    work_id,
                    retrieval_hash,
                    run_id,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("content work is not in the requested retrieval scope")
            connection.execute(
                "UPDATE works SET state='content_retry', updated_at=? WHERE id=?",
                (utc_now(), work_id),
            )

    def pause_content_work_for_resource(
        self,
        work_id: int,
        *,
        retrieval_hash: str,
        run_id: str,
        lease_token: str,
        error: str,
    ) -> None:
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            timestamp = utc_now()
            cursor = connection.execute(
                """
                UPDATE work_scopes
                SET state='admitted', not_before=NULL, last_error=?,
                    active_run_id=NULL, active_lease_token=NULL, last_seen_at=?
                WHERE work_id=? AND config_hash=?
                  AND state='content_running'
                  AND active_run_id=? AND active_lease_token=?
                """,
                (
                    error[:2000],
                    timestamp,
                    work_id,
                    retrieval_hash,
                    run_id,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("content work is not in the requested retrieval scope")
            connection.execute(
                "UPDATE works SET state='admitted', updated_at=? WHERE id=?",
                (timestamp, work_id),
            )

    def save_document(
        self,
        *,
        work_id: int,
        content_kind: str,
        status: str,
        source_url: str | None,
        local_path: str | None,
        text_path: str | None,
        content_sha256: str | None,
        text_sha256: str | None,
        byte_count: int | None,
        text_char_count: int | None,
        page_count: int | None,
        coverage: dict[str, Any],
        error: str | None = None,
        run_id: str | None = None,
        lease_token: str | None = None,
    ) -> int:
        require_current_pdf_ready_policy(
            content_kind=content_kind,
            status=status,
            coverage=coverage,
        )
        require_repository_ready_policy(
            content_kind=content_kind,
            status=status,
            coverage=coverage,
            text_path=text_path,
        )
        timestamp = utc_now()
        with self.transaction() as connection:
            document_id, _ = self._save_document_in_transaction(
                connection,
                work_id=work_id,
                content_kind=content_kind,
                status=status,
                source_url=source_url,
                local_path=local_path,
                text_path=text_path,
                content_sha256=content_sha256,
                text_sha256=text_sha256,
                byte_count=byte_count,
                text_char_count=text_char_count,
                page_count=page_count,
                coverage=coverage,
                error=error,
                timestamp=timestamp,
                run_id=run_id,
                lease_token=lease_token,
            )
            return document_id

    def _save_document_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        work_id: int,
        content_kind: str,
        status: str,
        source_url: str | None,
        local_path: str | None,
        text_path: str | None,
        content_sha256: str | None,
        text_sha256: str | None,
        byte_count: int | None,
        text_char_count: int | None,
        page_count: int | None,
        coverage: dict[str, Any],
        error: str | None,
        timestamp: str,
        run_id: str | None,
        lease_token: str | None,
    ) -> tuple[int, bool]:
        document_policy_hash = (
            self.document_policy_hash
            if content_kind == PDF_CONTENT_KIND
            else None
        )
        if (run_id is None) != (lease_token is None):
            raise ValueError("run_id and lease_token must be provided together")
        if run_id is not None and lease_token is not None:
            self._require_run_lease(connection, run_id, lease_token)
            ownership = connection.execute(
                """
                SELECT 1 FROM work_scopes
                WHERE work_id=? AND active_run_id=? AND active_lease_token=?
                  AND state='content_running'
                LIMIT 1
                """,
                (work_id, run_id, lease_token),
            ).fetchone()
            if ownership is None:
                raise RunAlreadyActiveError(
                    "content work ownership was lost before saving"
                )
        previous_document = connection.execute(
            """
            SELECT id, content_sha256, text_sha256
            FROM documents
            WHERE work_id=? AND content_kind=?
            """,
            (work_id, content_kind),
        ).fetchone()
        connection.execute(
            """
            INSERT INTO documents(
                work_id, content_kind, status, source_url, local_path, text_path,
                content_sha256, text_sha256, byte_count, text_char_count, page_count,
                document_policy_hash, coverage_json, error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(work_id, content_kind) DO UPDATE SET
                status=excluded.status,
                source_url=excluded.source_url,
                local_path=excluded.local_path,
                text_path=excluded.text_path,
                content_sha256=excluded.content_sha256,
                text_sha256=excluded.text_sha256,
                byte_count=excluded.byte_count,
                text_char_count=excluded.text_char_count,
                page_count=excluded.page_count,
                document_policy_hash=excluded.document_policy_hash,
                coverage_json=excluded.coverage_json,
                error=excluded.error,
                updated_at=excluded.updated_at
            """,
            (
                work_id,
                content_kind,
                status,
                source_url,
                local_path,
                text_path,
                content_sha256,
                text_sha256,
                byte_count,
                text_char_count,
                page_count,
                document_policy_hash,
                json_dumps(coverage),
                error,
                timestamp,
                timestamp,
            ),
        )
        row = connection.execute(
            "SELECT * FROM documents WHERE work_id=? AND content_kind=?",
            (work_id, content_kind),
        ).fetchone()
        previous_content_identity = None
        if previous_document is not None:
            previous_content_identity = (
                previous_document["text_sha256"]
                or previous_document["content_sha256"]
            )
        current_content_identity = text_sha256 or content_sha256
        if (
            previous_document is not None
            and previous_content_identity != current_content_identity
        ):
            connection.execute(
                """
                UPDATE analysis_tasks
                SET status='superseded',
                    error='superseded because document content changed',
                    updated_at=?
                WHERE document_id=?
                  AND status IN ('pending','retry','running')
                """,
                (timestamp, int(row["id"])),
            )
        coverage_json = json_dumps(coverage)
        revision_cursor = connection.execute(
            """
            INSERT INTO content_revisions(
                document_id, work_id, content_kind, status, source_url,
                local_path, text_path, content_sha256, text_sha256,
                byte_count, text_char_count, page_count, coverage_json,
                error, observed_at
            )
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            WHERE NOT EXISTS (
                SELECT 1 FROM content_revisions
                WHERE document_id=?
                  AND content_sha256 IS ?
                  AND text_sha256 IS ?
            )
            """,
            (
                int(row["id"]),
                work_id,
                content_kind,
                status,
                source_url,
                local_path,
                text_path,
                content_sha256,
                text_sha256,
                byte_count,
                text_char_count,
                page_count,
                coverage_json,
                error,
                timestamp,
                int(row["id"]),
                content_sha256,
                text_sha256,
            ),
        )
        self._append_document_processing_observation(
            connection,
            row,
            event_type="save",
            observed_at=timestamp,
        )
        work_state = "content_unavailable"
        if status == "ready":
            work_state = "content_ready"
        elif status == "retry":
            work_state = "content_retry"
        elif status == "incomplete":
            work_state = "content_incomplete"
        connection.execute(
            "UPDATE works SET state=?, updated_at=? WHERE id=?",
            (work_state, timestamp, work_id),
        )
        connection.execute(
            """
            UPDATE work_scopes
            SET state=?, not_before=NULL, last_error=?,
                active_run_id=NULL, active_lease_token=NULL, last_seen_at=?
            WHERE work_id=?
              AND state IN (
                'admitted','content_retry','content_running',
                'content_unavailable','content_incomplete'
              )
            """,
            (work_state, error, timestamp, work_id),
        )
        return int(row["id"]), revision_cursor.rowcount == 1

    @classmethod
    def read_ready_repository_documents(
        cls,
        database_path: Path,
        *,
        retrieval_hash: str,
    ) -> list[dict[str, Any]]:
        source = database_path.resolve()
        if not source.is_file():
            raise ValueError("repository reprojection database is unavailable")
        source_wal = Path(f"{source}-wal")

        def source_state() -> tuple[tuple[str, int, int], ...]:
            state: list[tuple[str, int, int]] = []
            for path in (source, source_wal):
                try:
                    stat = path.stat()
                except FileNotFoundError:
                    continue
                state.append((path.name, stat.st_size, stat.st_mtime_ns))
            return tuple(state)

        with tempfile.TemporaryDirectory(
            prefix="r3radar-reprojection-read-"
        ) as temporary:
            snapshot = Path(temporary) / "radar.sqlite3"
            snapshot_wal = Path(f"{snapshot}-wal")
            for _ in range(3):
                before = source_state()
                try:
                    shutil.copyfile(source, snapshot)
                    if source_wal.is_file():
                        shutil.copyfile(source_wal, snapshot_wal)
                    else:
                        try:
                            snapshot_wal.unlink()
                        except FileNotFoundError:
                            pass
                except FileNotFoundError:
                    continue
                if before == source_state():
                    break
            else:
                raise RunAlreadyActiveError(
                    "database changed while creating a read-only snapshot"
                )

            connection = sqlite3.connect(snapshot)
            connection.row_factory = sqlite3.Row
            try:
                connection.execute("PRAGMA query_only=ON")
                quick_check = connection.execute(
                    "PRAGMA quick_check"
                ).fetchone()[0]
                if quick_check != "ok":
                    raise ValueError(
                        f"repository reprojection snapshot failed quick_check: "
                        f"{quick_check}"
                    )
                rows = connection.execute(
                    """
                    SELECT
                        d.*, w.title, w.kind, ws.state AS scope_state,
                        ws.active_run_id AS scope_active_run_id,
                        ws.active_lease_token AS scope_active_lease_token
                    FROM documents d
                    JOIN works w ON w.id=d.work_id
                    JOIN work_scopes ws
                      ON ws.work_id=d.work_id AND ws.config_hash=?
                    WHERE d.content_kind=?
                      AND d.status='ready'
                    ORDER BY d.work_id
                    """,
                    (retrieval_hash, REPOSITORY_CONTENT_KIND),
                ).fetchall()
                result: list[dict[str, Any]] = []
                for row in rows:
                    document = dict(row)
                    document["coverage"] = cls._coverage_dict(
                        document.pop("coverage_json")
                    )
                    result.append(document)
                return result
            finally:
                connection.close()

    def save_selected_repository_revision_and_queue(
        self,
        *,
        work_id: int,
        source_url: str | None,
        archive_path: str,
        text_path: str,
        content_sha256: str,
        text_sha256: str,
        byte_count: int,
        text_char_count: int,
        coverage: dict[str, Any],
        analysis_provider: str,
        analysis_prompt_version: str,
        analysis_policy_hash: str,
        retrieval_hash: str,
        profile_id: str,
        profile_version: int,
    ) -> dict[str, Any]:
        if coverage.get("coverage_scope") != "selected_repository_corpus":
            raise ValueError(
                "repository reprojection requires selected-corpus coverage"
            )
        for label, value in (
            ("analysis_provider", analysis_provider),
            ("analysis_prompt_version", analysis_prompt_version),
            ("analysis_policy_hash", analysis_policy_hash),
            ("retrieval_hash", retrieval_hash),
            ("profile_id", profile_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} must be a non-empty string")
        if type(profile_version) is not int or profile_version < 1:
            raise ValueError("profile_version must be a positive integer")
        require_repository_ready_policy(
            content_kind=REPOSITORY_CONTENT_KIND,
            status="ready",
            coverage=coverage,
            text_path=text_path,
        )
        archive_file = Path(archive_path)
        if not archive_file.is_file():
            raise ValueError("repository reprojection archive is unavailable")
        archive_bytes = archive_file.read_bytes()
        if (
            len(archive_bytes) != byte_count
            or sha256_bytes(archive_bytes) != content_sha256
        ):
            raise ValueError(
                "repository reprojection archive identity is inconsistent"
            )
        text_file = Path(text_path)
        try:
            selected_text = text_file.read_bytes().decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "repository reprojection text is not valid UTF-8"
            ) from exc
        if (
            len(selected_text) != text_char_count
            or sha256_text(selected_text) != text_sha256
        ):
            raise ValueError(
                "repository reprojection text identity is inconsistent"
            )
        timestamp = utc_now()
        coverage_json = json_dumps(coverage)
        with self.transaction() as connection:
            running_run = connection.execute(
                """
                SELECT id FROM runs
                WHERE status='running'
                LIMIT 1
                """
            ).fetchone()
            if running_run is not None:
                raise RunAlreadyActiveError(
                    "repository reprojection cannot apply while a run is active"
                )
            current = connection.execute(
                """
                SELECT * FROM documents
                WHERE work_id=? AND content_kind=?
                """,
                (work_id, REPOSITORY_CONTENT_KIND),
            ).fetchone()
            if current is None or current["status"] != "ready":
                raise ValueError(
                    f"work {work_id} has no ready repository document"
                )
            if (
                current["local_path"] is None
                or Path(str(current["local_path"])).resolve()
                != Path(archive_path).resolve()
                or current["content_sha256"] != content_sha256
            ):
                raise ValueError(
                    "repository archive identity changed during reprojection"
                )
            scope = connection.execute(
                """
                SELECT state, active_run_id, active_lease_token
                FROM work_scopes
                WHERE work_id=? AND config_hash=?
                """,
                (work_id, retrieval_hash),
            ).fetchone()
            if scope is None:
                raise ValueError(
                    f"work {work_id} is not in the requested retrieval scope"
                )
            active_scope = connection.execute(
                """
                SELECT config_hash, state
                FROM work_scopes
                WHERE work_id=?
                  AND (
                    active_run_id IS NOT NULL
                    OR active_lease_token IS NOT NULL
                    OR state IN ('content_running', 'analysis_running')
                  )
                LIMIT 1
                """,
                (work_id,),
            ).fetchone()
            if active_scope is not None:
                raise RunAlreadyActiveError(
                    "repository reprojection cannot modify a work with an "
                    "active retrieval scope"
                )
            active_task = connection.execute(
                """
                SELECT id FROM analysis_tasks
                WHERE work_id=?
                  AND (
                    status='running'
                    OR claimed_run_id IS NOT NULL
                    OR claim_lease_token IS NOT NULL
                  )
                LIMIT 1
                """,
                (work_id,),
            ).fetchone()
            if active_task is not None:
                raise RunAlreadyActiveError(
                    "repository reprojection cannot replace an active analysis task"
                )

            unchanged = bool(
                current["status"] == "ready"
                and current["source_url"] == source_url
                and current["local_path"] == archive_path
                and current["text_path"] == text_path
                and current["content_sha256"] == content_sha256
                and current["text_sha256"] == text_sha256
                and int(current["byte_count"] or 0) == int(byte_count)
                and int(current["text_char_count"] or 0)
                == int(text_char_count)
                and current["coverage_json"] == coverage_json
                and current["error"] is None
            )
            revision_created = False
            if unchanged:
                document_id = int(current["id"])
            else:
                document_id, revision_created = (
                    self._save_document_in_transaction(
                        connection,
                        work_id=work_id,
                        content_kind=REPOSITORY_CONTENT_KIND,
                        status="ready",
                        source_url=source_url,
                        local_path=archive_path,
                        text_path=text_path,
                        content_sha256=content_sha256,
                        text_sha256=text_sha256,
                        byte_count=byte_count,
                        text_char_count=text_char_count,
                        page_count=None,
                        coverage=coverage,
                        error=None,
                        timestamp=timestamp,
                        run_id=None,
                        lease_token=None,
                    )
                )

            scoped_prompt_version = (
                f"{analysis_prompt_version}@{analysis_policy_hash[:16]}"
            )
            task_prompt_version = (
                f"{scoped_prompt_version}@{text_sha256}"
            )
            task = connection.execute(
                """
                SELECT id, status, claimed_run_id, claim_lease_token
                FROM analysis_tasks
                WHERE work_id=? AND document_id=? AND provider=?
                  AND prompt_version=?
                """,
                (
                    work_id,
                    document_id,
                    analysis_provider,
                    task_prompt_version,
                ),
            ).fetchone()
            task_created = False
            if task is None:
                cursor = connection.execute(
                    """
                    INSERT INTO analysis_tasks(
                        work_id, document_id, provider, prompt_version,
                        config_hash, retrieval_hash, profile_id,
                        profile_version, input_sha256, status, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        work_id,
                        document_id,
                        analysis_provider,
                        task_prompt_version,
                        analysis_policy_hash,
                        retrieval_hash,
                        profile_id,
                        profile_version,
                        text_sha256,
                        timestamp,
                    ),
                )
                task_id = int(cursor.lastrowid)
                task_status = "pending"
                task_created = True
            else:
                task_id = int(task["id"])
                task_status = str(task["status"])
                if (
                    task["claimed_run_id"] is not None
                    or task["claim_lease_token"] is not None
                    or task_status == "running"
                ):
                    raise RunAlreadyActiveError(
                        "repository reprojection task became active"
                    )
                completed = connection.execute(
                    """
                    SELECT 1 FROM analyses
                    WHERE task_id=? AND deep_read_status='complete'
                    LIMIT 1
                    """,
                    (task_id,),
                ).fetchone()
                if task_status != "completed" or completed is None:
                    connection.execute(
                        """
                        UPDATE analysis_tasks
                        SET status='pending', attempts=0, error=NULL,
                            not_before=NULL, claimed_run_id=NULL,
                            claim_lease_token=NULL, updated_at=?
                        WHERE id=?
                        """,
                        (timestamp, task_id),
                    )
                    task_status = "pending"

            scope_state = (
                "analyzed" if task_status == "completed" else "analysis_pending"
            )
            connection.execute(
                """
                UPDATE work_scopes
                SET state=?, last_error=NULL, not_before=NULL,
                    active_run_id=NULL, active_lease_token=NULL,
                    last_seen_at=?
                WHERE work_id=? AND config_hash=?
                """,
                (scope_state, timestamp, work_id, retrieval_hash),
            )
            connection.execute(
                "UPDATE works SET state=?, updated_at=? WHERE id=?",
                (scope_state, timestamp, work_id),
            )
            return {
                "work_id": work_id,
                "document_id": document_id,
                "document_changed": not unchanged,
                "revision_created": revision_created,
                "task_id": task_id,
                "task_created": task_created,
                "task_status": task_status,
            }

    def seed_analysis_tasks(
        self,
        provider: str,
        prompt_version: str,
        *,
        analysis_policy_hash: str,
        retrieval_hash: str,
        profile_id: str,
        profile_version: int,
    ) -> int:
        timestamp = utc_now()
        scoped_prompt_version = f"{prompt_version}@{analysis_policy_hash[:16]}"
        with self.transaction() as connection:
            reactivated = connection.execute(
                """
                UPDATE analysis_tasks AS task
                SET status='pending', attempts=0, error=NULL,
                    claimed_run_id=NULL, claim_lease_token=NULL,
                    not_before=NULL, updated_at=?
                WHERE task.provider=?
                  AND task.config_hash=?
                  AND task.status='superseded'
                  AND EXISTS (
                    SELECT 1
                    FROM documents d
                    JOIN work_scopes ws
                      ON ws.work_id=d.work_id AND ws.config_hash=?
                    WHERE d.id=task.document_id
                      AND r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                      AND task.input_sha256=
                          COALESCE(d.text_sha256, d.content_sha256)
                      AND ws.state IN (
                          'content_ready','analysis_pending',
                          'analysis_running','analysis_failed','analyzed'
                      )
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM analysis_tasks completed_task
                    JOIN analyses a ON a.task_id=completed_task.id
                    JOIN documents current_document
                      ON current_document.id=completed_task.document_id
                    WHERE completed_task.work_id=task.work_id
                      AND completed_task.config_hash=?
                      AND r3_document_is_analysis_eligible(
                          current_document.content_kind,
                          current_document.status,
                          current_document.document_policy_hash,
                          current_document.coverage_json
                      )
                      AND completed_task.input_sha256=COALESCE(
                          current_document.text_sha256,
                          current_document.content_sha256
                      )
                      AND a.deep_read_status='complete'
                  )
                """,
                (
                    timestamp,
                    provider,
                    analysis_policy_hash,
                    retrieval_hash,
                    analysis_policy_hash,
                ),
            ).rowcount
            before_insert = connection.total_changes
            connection.execute(
                """
                INSERT OR IGNORE INTO analysis_tasks(
                    work_id, document_id, provider, prompt_version, config_hash, retrieval_hash,
                    profile_id, profile_version, input_sha256, status, updated_at
                )
                SELECT d.work_id, d.id, ?,
                       ? || '@' ||
                           COALESCE(d.text_sha256, d.content_sha256, 'missing'),
                       ?, ?, ?, ?,
                       COALESCE(d.text_sha256, d.content_sha256),
                       'pending', ?
                FROM documents d
                JOIN work_scopes ws
                  ON ws.work_id=d.work_id AND ws.config_hash=?
                WHERE r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                  AND ws.state IN (
                      'content_ready','analysis_pending',
                      'analysis_running','analysis_failed','analyzed'
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM analysis_tasks completed_task
                    JOIN analyses a ON a.task_id=completed_task.id
                    WHERE completed_task.work_id=d.work_id
                      AND completed_task.config_hash=?
                      AND completed_task.input_sha256=
                          COALESCE(d.text_sha256, d.content_sha256)
                      AND a.deep_read_status='complete'
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM analysis_tasks existing
                    WHERE existing.work_id=d.work_id
                      AND existing.document_id=d.id
                      AND existing.provider=?
                      AND existing.config_hash=?
                      AND existing.prompt_version=(
                          ? || '@' ||
                              COALESCE(d.text_sha256, d.content_sha256, 'missing')
                      )
                      AND existing.status IN ('pending','retry','running','completed')
                  )
                """,
                (
                    provider,
                    scoped_prompt_version,
                    analysis_policy_hash,
                    retrieval_hash,
                    profile_id,
                    profile_version,
                    timestamp,
                    retrieval_hash,
                    analysis_policy_hash,
                    provider,
                    analysis_policy_hash,
                    scoped_prompt_version,
                ),
            )
            inserted = connection.total_changes - before_insert
            connection.execute(
                """
                UPDATE work_scopes AS ws
                SET state='analysis_pending', active_run_id=NULL,
                    active_lease_token=NULL, last_seen_at=?
                WHERE ws.config_hash=?
                  AND ws.state IN (
                      'content_ready','analyzed',
                      'analysis_pending','analysis_failed'
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM documents d
                    JOIN analysis_tasks task ON task.document_id=d.id
                    WHERE d.work_id=ws.work_id
                      AND r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                      AND task.config_hash=?
                      AND task.status IN ('pending','retry')
                      AND task.input_sha256=
                          COALESCE(d.text_sha256, d.content_sha256)
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM documents d
                    JOIN analysis_tasks task ON task.document_id=d.id
                    JOIN analyses a ON a.task_id=task.id
                    WHERE d.work_id=ws.work_id
                      AND task.config_hash=?
                      AND r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                      AND task.input_sha256=
                          COALESCE(d.text_sha256, d.content_sha256)
                      AND a.deep_read_status='complete'
                  )
                """,
                (
                    timestamp,
                    retrieval_hash,
                    analysis_policy_hash,
                    analysis_policy_hash,
                ),
            )
            connection.execute(
                """
                UPDATE work_scopes AS ws
                SET state='analyzed', active_run_id=NULL,
                    active_lease_token=NULL, last_error=NULL, last_seen_at=?
                WHERE ws.config_hash=?
                  AND ws.state IN (
                      'content_ready','analysis_pending',
                      'analysis_failed','analyzed'
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM documents current_document
                    JOIN analysis_tasks completed_task
                      ON completed_task.document_id=current_document.id
                    JOIN analyses completed_analysis
                      ON completed_analysis.task_id=completed_task.id
                    WHERE current_document.work_id=ws.work_id
                      AND r3_document_is_analysis_eligible(
                          current_document.content_kind,
                          current_document.status,
                          current_document.document_policy_hash,
                          current_document.coverage_json
                      )
                      AND completed_task.config_hash=?
                      AND completed_task.input_sha256=COALESCE(
                          current_document.text_sha256,
                          current_document.content_sha256
                      )
                      AND completed_analysis.deep_read_status='complete'
                  )
                """,
                (
                    timestamp,
                    retrieval_hash,
                    analysis_policy_hash,
                ),
            )
            return max(0, int(reactivated)) + inserted

    def supersede_analysis_tasks(
        self,
        *,
        analysis_policy_hash: str,
        replacement_provider: str,
    ) -> int:
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_tasks
                SET status='superseded',
                    error=?,
                    claimed_run_id=NULL,
                    claim_lease_token=NULL,
                    not_before=NULL,
                    updated_at=?
                WHERE config_hash=?
                  AND provider!=?
                  AND status IN ('pending','retry')
                """,
                (
                    f"superseded by fallback provider {replacement_provider}",
                    utc_now(),
                    analysis_policy_hash,
                    replacement_provider,
                ),
            )
            return max(0, int(cursor.rowcount))

    def analysis_task_counts(self, analysis_policy_hash: str) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT task.status, COUNT(*) AS count
                FROM analysis_tasks task
                JOIN documents d ON d.id=task.document_id
                WHERE task.config_hash=?
                  AND r3_document_is_analysis_eligible(
                      d.content_kind,
                      d.status,
                      d.document_policy_hash,
                      d.coverage_json
                  )
                  AND task.input_sha256=
                      COALESCE(d.text_sha256, d.content_sha256)
                GROUP BY task.status
                """,
                (analysis_policy_hash,),
            ).fetchall()
            return {str(row["status"]): int(row["count"]) for row in rows}

    def deep_read_progress(
        self,
        analysis_policy_hash: str,
        *,
        retrieval_hash: str | None = None,
        run_id: str | None = None,
        stale_after_seconds: int = 600,
    ) -> dict[str, Any]:
        with self._lock:
            count_rows = self._connection.execute(
                """
                SELECT task.status, COUNT(*) AS count
                FROM analysis_tasks task
                JOIN documents d ON d.id=task.document_id
                WHERE task.config_hash=?
                  AND task.status!='superseded'
                  AND r3_document_is_analysis_eligible(
                      d.content_kind,
                      d.status,
                      d.document_policy_hash,
                      d.coverage_json
                  )
                  AND task.input_sha256=
                      COALESCE(d.text_sha256, d.content_sha256)
                  AND (
                      ? IS NULL OR EXISTS (
                          SELECT 1
                          FROM work_scopes scope
                          WHERE scope.work_id=task.work_id
                            AND scope.config_hash=?
                      )
                  )
                GROUP BY task.status
                """,
                (analysis_policy_hash, retrieval_hash, retrieval_hash),
            ).fetchall()
            counts = {
                str(row["status"]): int(row["count"])
                for row in count_rows
            }
            current_row = self._connection.execute(
                """
                SELECT
                    task.id, task.work_id, task.provider, task.status,
                    task.chunk_total, task.chunk_done, task.started_at,
                    task.updated_at, task.claimed_run_id,
                    task.phase, task.phase_done, task.phase_total,
                    task.phase_updated_at,
                    (
                        SELECT COUNT(*)
                        FROM model_invocations invocation
                        WHERE invocation.task_id=task.id
                    ) AS model_invocation_count,
                    (
                        SELECT COUNT(*)
                        FROM analysis_synthesis_nodes node
                        WHERE node.task_id=task.id
                    ) AS synthesis_node_count,
                    w.title, w.kind
                FROM analysis_tasks task
                JOIN works w ON w.id=task.work_id
                JOIN documents d ON d.id=task.document_id
                WHERE task.config_hash=?
                  AND task.status='running'
                  AND r3_document_is_analysis_eligible(
                      d.content_kind,
                      d.status,
                      d.document_policy_hash,
                      d.coverage_json
                  )
                  AND task.input_sha256=
                      COALESCE(d.text_sha256, d.content_sha256)
                  AND (? IS NULL OR task.claimed_run_id=?)
                  AND (
                      ? IS NULL OR EXISTS (
                          SELECT 1
                          FROM work_scopes scope
                          WHERE scope.work_id=task.work_id
                            AND scope.config_hash=?
                      )
                  )
                ORDER BY
                    CASE WHEN task.claimed_run_id=? THEN 0 ELSE 1 END,
                    task.updated_at DESC,
                    task.id DESC
                LIMIT 1
                """,
                (
                    analysis_policy_hash,
                    run_id,
                    run_id,
                    retrieval_hash,
                    retrieval_hash,
                    run_id,
                ),
            ).fetchone()
            current = dict(current_row) if current_row is not None else None
            latest_receipt = None
            if current is not None:
                receipt_row = self._connection.execute(
                    """
                    SELECT created_at, duration_seconds
                    FROM model_invocations
                    WHERE task_id=?
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (int(current["id"]),),
                ).fetchone()
                if receipt_row is not None:
                    latest_receipt = dict(receipt_row)
            if run_id is not None:
                run_row = self._connection.execute(
                    """
                    SELECT id, status, lease_expires_at
                    FROM runs
                    WHERE id=?
                    """,
                    (run_id,),
                ).fetchone()
            else:
                run_row = self._connection.execute(
                    """
                    SELECT id, status, lease_expires_at
                    FROM runs
                    WHERE analysis_policy_hash=? OR config_hash=?
                    ORDER BY started_at DESC
                    LIMIT 1
                    """,
                    (analysis_policy_hash, analysis_policy_hash),
                ).fetchone()
            run = dict(run_row) if run_row is not None else None

        def parse_timestamp(value: object) -> datetime | None:
            if not value:
                return None
            try:
                parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except ValueError:
                return None
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)

        now = datetime.now(timezone.utc)
        activity_candidates = []
        if current is not None:
            activity_candidates.append(current.get("updated_at"))
        if latest_receipt is not None:
            activity_candidates.append(latest_receipt.get("created_at"))
        parsed_activity = [
            parsed
            for parsed in (parse_timestamp(value) for value in activity_candidates)
            if parsed is not None
        ]
        last_activity = max(parsed_activity) if parsed_activity else None
        activity_age_seconds = (
            max(0, int((now - last_activity).total_seconds()))
            if last_activity is not None
            else None
        )
        lease_expires_at = parse_timestamp(
            run.get("lease_expires_at") if run is not None else None
        )
        run_active = bool(
            run is not None
            and run.get("status") == "running"
            and lease_expires_at is not None
            and lease_expires_at > now
        )

        completed = counts.get("completed", 0)
        running = counts.get("running", 0)
        queued = counts.get("pending", 0) + counts.get("retry", 0)
        failed = counts.get("failed", 0)
        total = sum(counts.values())
        if current is not None:
            stalled = (
                not run_active
                or activity_age_seconds is None
                or activity_age_seconds >= max(60, int(stale_after_seconds))
            )
            state = "stalled" if stalled else "running"
        elif queued:
            if run_active:
                state = "queued"
            elif run is not None and run.get("status") in {
                "paused",
                "completed_with_gaps",
                "failed",
            }:
                state = "paused"
            else:
                state = "waiting"
        elif failed:
            state = "attention"
        elif total and completed == total:
            state = "complete"
        else:
            state = "idle"

        if current is not None:
            current["last_model_receipt_at"] = (
                latest_receipt.get("created_at")
                if latest_receipt is not None
                else None
            )
            current["last_model_duration_seconds"] = (
                round(float(latest_receipt["duration_seconds"]), 3)
                if latest_receipt is not None
                and latest_receipt.get("duration_seconds") is not None
                else None
            )

        return {
            "state": state,
            "total": total,
            "completed": completed,
            "running": running,
            "queued": queued,
            "failed": failed,
            "retrying": counts.get("retry", 0),
            "current_task": current,
            "last_activity_at": (
                last_activity.isoformat(timespec="seconds")
                if last_activity is not None
                else None
            ),
            "last_activity_age_seconds": activity_age_seconds,
            "stale_after_seconds": max(60, int(stale_after_seconds)),
            "run_id": run.get("id") if run is not None else None,
            "run_status": run.get("status") if run is not None else None,
            "lease_expires_at": (
                run.get("lease_expires_at") if run is not None else None
            ),
        }

    def work_scope_state_counts(self, retrieval_hash: str) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT state, COUNT(*) AS count
                FROM work_scopes
                WHERE config_hash=?
                GROUP BY state
                """,
                (retrieval_hash,),
            ).fetchall()
            return {str(row["state"]): int(row["count"]) for row in rows}

    def claim_analysis_task(
        self,
        provider: str,
        *,
        config_hash: str,
        run_id: str,
        lease_token: str,
    ) -> dict[str, Any] | None:
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            row = connection.execute(
                """
                SELECT
                    t.*, w.title, w.kind, w.year, w.best_url, w.github_full_name,
                    d.content_kind, d.status AS document_status,
                    d.document_policy_hash,
                    d.text_path, d.text_sha256, d.coverage_json,
                    COALESCE(claiming_run.retrieval_hash, claiming_run.config_hash)
                        AS claim_retrieval_hash
                FROM analysis_tasks t
                JOIN runs claiming_run ON claiming_run.id=?
                JOIN works w ON w.id=t.work_id
                JOIN documents d ON d.id=t.document_id
                JOIN work_scopes ws
                  ON ws.work_id=t.work_id
                 AND ws.config_hash=COALESCE(
                     claiming_run.retrieval_hash,
                     claiming_run.config_hash
                 )
                WHERE t.provider=? AND t.config_hash=?
                  AND t.status IN ('pending', 'retry')
                  AND (t.not_before IS NULL OR t.not_before<=?)
                  AND r3_document_is_analysis_eligible(
                      d.content_kind,
                      d.status,
                      d.document_policy_hash,
                      d.coverage_json
                  )
                  AND t.input_sha256=COALESCE(d.text_sha256, d.content_sha256)
                  AND ws.state IN ('content_ready','analysis_pending','analyzed')
                ORDER BY t.id LIMIT 1
                """,
                (run_id, provider, config_hash, utc_now()),
            ).fetchone()
            if row is None:
                return None
            timestamp = utc_now()
            connection.execute(
                """
                UPDATE analysis_tasks
                SET status='running', attempts=attempts+1,
                    started_at=COALESCE(started_at, ?), updated_at=?, error=NULL,
                    claimed_run_id=?, claim_lease_token=?, not_before=NULL,
                    phase='preparing', phase_done=0, phase_total=0,
                    phase_updated_at=?
                WHERE id=?
                """,
                (
                    timestamp,
                    timestamp,
                    run_id,
                    lease_token,
                    timestamp,
                    row["id"],
                ),
            )
            connection.execute(
                "UPDATE works SET state='analysis_running', updated_at=? WHERE id=?",
                (timestamp, row["work_id"]),
            )
            connection.execute(
                """
                UPDATE work_scopes
                SET state='analysis_running', active_run_id=?,
                    active_lease_token=?, last_seen_at=?
                WHERE work_id=? AND config_hash=?
                """,
                (
                    run_id,
                    lease_token,
                    timestamp,
                    row["work_id"],
                    row["claim_retrieval_hash"],
                ),
            )
            return dict(row)

    def next_analysis_retry_at(
        self,
        provider: str,
        *,
        config_hash: str,
        run_id: str,
        lease_token: str,
    ) -> str | None:
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            row = connection.execute(
                """
                SELECT MIN(t.not_before) AS not_before
                FROM analysis_tasks t
                JOIN runs claiming_run ON claiming_run.id=?
                JOIN documents d ON d.id=t.document_id
                JOIN work_scopes ws
                  ON ws.work_id=t.work_id
                 AND ws.config_hash=COALESCE(
                     claiming_run.retrieval_hash,
                     claiming_run.config_hash
                 )
                WHERE t.provider=? AND t.config_hash=?
                  AND t.status='retry'
                  AND t.not_before IS NOT NULL
                  AND r3_document_is_analysis_eligible(
                      d.content_kind,
                      d.status,
                      d.document_policy_hash,
                      d.coverage_json
                  )
                  AND t.input_sha256=COALESCE(
                      d.text_sha256,
                      d.content_sha256
                  )
                  AND ws.state IN (
                      'content_ready',
                      'analysis_pending',
                      'analyzed'
                  )
                """,
                (run_id, provider, config_hash),
            ).fetchone()
        if row is None or row["not_before"] is None:
            return None
        return str(row["not_before"])

    def prepare_chunks(
        self,
        task_id: int,
        chunks: list[dict[str, Any]],
        *,
        lease_token: str,
    ) -> None:
        timestamp = utc_now()
        with self.transaction() as connection:
            owner = connection.execute(
                """
                SELECT 1
                FROM analysis_tasks task
                JOIN runs r ON r.id=task.claimed_run_id
                WHERE task.id=? AND task.status='running'
                  AND task.claim_lease_token=?
                  AND r.status='running' AND r.lease_token=?
                """,
                (task_id, lease_token, lease_token),
            ).fetchone()
            if owner is None:
                raise RunAlreadyActiveError("analysis chunk ownership was lost")
            for chunk in chunks:
                existing = connection.execute(
                    """
                    SELECT input_sha256 FROM analysis_chunks
                    WHERE task_id=? AND chunk_index=?
                    """,
                    (task_id, chunk["index"]),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO analysis_chunks(
                            task_id, chunk_index, span_json, input_sha256, status, updated_at
                        ) VALUES (?, ?, ?, ?, 'pending', ?)
                        """,
                        (
                            task_id,
                            chunk["index"],
                            json_dumps(chunk["span"]),
                            chunk["sha256"],
                            timestamp,
                        ),
                    )
                elif existing["input_sha256"] != chunk["sha256"]:
                    connection.execute(
                        """
                        UPDATE analysis_chunks
                        SET span_json=?, input_sha256=?, status='pending', output_json=NULL,
                            provider_receipt_json=NULL, error=NULL, updated_at=?
                        WHERE task_id=? AND chunk_index=?
                        """,
                        (
                            json_dumps(chunk["span"]),
                            chunk["sha256"],
                            timestamp,
                            task_id,
                            chunk["index"],
                        ),
                    )
            connection.execute(
                """
                DELETE FROM analysis_chunks
                WHERE task_id=? AND chunk_index>=?
                """,
                (task_id, len(chunks)),
            )
            connection.execute(
                "UPDATE analysis_tasks SET chunk_total=?, updated_at=? WHERE id=?",
                (len(chunks), timestamp, task_id),
            )

    def update_analysis_progress(
        self,
        *,
        task_id: int,
        phase: str,
        phase_done: int,
        phase_total: int,
        lease_token: str,
    ) -> None:
        hierarchical_level_phase = (
            phase.startswith("hierarchical_synthesis_l")
            and phase.removeprefix("hierarchical_synthesis_l").isdigit()
            and int(phase.removeprefix("hierarchical_synthesis_l")) > 0
        )
        if phase not in {
            "preparing",
            "chunk_reading",
            "hierarchical_synthesis",
            "final_synthesis",
            "complete",
        } and not hierarchical_level_phase:
            raise ValueError("unsupported analysis progress phase")
        if phase_done < 0 or phase_total < 0 or phase_done > phase_total:
            raise ValueError("invalid analysis phase progress")
        timestamp = utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE analysis_tasks
                SET phase=?, phase_done=?, phase_total=?,
                    phase_updated_at=?, updated_at=?
                WHERE id=? AND status='running' AND claim_lease_token=?
                  AND EXISTS (
                      SELECT 1 FROM runs r
                      WHERE r.id=analysis_tasks.claimed_run_id
                        AND r.status='running' AND r.lease_token=?
                  )
                """,
                (
                    phase,
                    phase_done,
                    phase_total,
                    timestamp,
                    timestamp,
                    task_id,
                    lease_token,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RunAlreadyActiveError(
                    "analysis progress ownership was lost"
                )

    def chunk_statuses(self, task_id: int) -> dict[int, dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM analysis_chunks WHERE task_id=? ORDER BY chunk_index",
                (task_id,),
            ).fetchall()
            return {int(row["chunk_index"]): dict(row) for row in rows}

    def save_chunk_result(
        self,
        *,
        task_id: int,
        chunk_index: int,
        output: dict[str, Any],
        receipt: dict[str, Any],
        lease_token: str,
    ) -> None:
        with self.transaction() as connection:
            owner = connection.execute(
                """
                SELECT 1
                FROM analysis_tasks task
                JOIN runs r ON r.id=task.claimed_run_id
                WHERE task.id=? AND task.status='running'
                  AND task.claim_lease_token=?
                  AND r.status='running' AND r.lease_token=?
                """,
                (task_id, lease_token, lease_token),
            ).fetchone()
            if owner is None:
                raise RunAlreadyActiveError("analysis chunk ownership was lost")
            connection.execute(
                """
                UPDATE analysis_chunks
                SET status='completed', output_json=?, provider_receipt_json=?,
                    error=NULL, updated_at=?
                WHERE task_id=? AND chunk_index=?
                """,
                (
                    json_dumps(output),
                    json_dumps(receipt),
                    utc_now(),
                    task_id,
                    chunk_index,
                ),
            )
            completed = connection.execute(
                """
                SELECT COUNT(*) AS count FROM analysis_chunks
                WHERE task_id=? AND status='completed'
                """,
                (task_id,),
            ).fetchone()["count"]
            connection.execute(
                """
                UPDATE analysis_tasks
                SET chunk_done=?, attempts=0, phase='chunk_reading',
                    phase_done=?, phase_total=chunk_total,
                    phase_updated_at=?, updated_at=?
                WHERE id=?
                """,
                (
                    completed,
                    completed,
                    utc_now(),
                    utc_now(),
                    task_id,
                ),
            )
            connection.execute(
                "DELETE FROM analysis_synthesis_nodes WHERE task_id=?",
                (task_id,),
            )

    def reset_analysis_chunk(
        self,
        *,
        task_id: int,
        chunk_index: int,
        lease_token: str,
        error: str,
    ) -> None:
        with self.transaction() as connection:
            owner = connection.execute(
                """
                SELECT 1
                FROM analysis_tasks task
                JOIN runs r ON r.id=task.claimed_run_id
                WHERE task.id=? AND task.status='running'
                  AND task.claim_lease_token=?
                  AND r.status='running' AND r.lease_token=?
                """,
                (task_id, lease_token, lease_token),
            ).fetchone()
            if owner is None:
                raise RunAlreadyActiveError("analysis chunk ownership was lost")
            connection.execute(
                """
                UPDATE analysis_chunks
                SET status='pending', error=?, updated_at=?
                WHERE task_id=? AND chunk_index=?
                """,
                (error, utc_now(), task_id, chunk_index),
            )
            completed = connection.execute(
                """
                SELECT COUNT(*) AS count FROM analysis_chunks
                WHERE task_id=? AND status='completed'
                """,
                (task_id,),
            ).fetchone()["count"]
            connection.execute(
                """
                UPDATE analysis_tasks
                SET chunk_done=?, attempts=0, phase='chunk_reading',
                    phase_done=?, phase_total=chunk_total,
                    phase_updated_at=?, updated_at=?
                WHERE id=?
                """,
                (
                    completed,
                    completed,
                    utc_now(),
                    utc_now(),
                    task_id,
                ),
            )
            connection.execute(
                "DELETE FROM analysis_synthesis_nodes WHERE task_id=?",
                (task_id,),
            )

    def invalidate_synthesis_nodes(
        self,
        *,
        task_id: int,
        lease_token: str,
    ) -> None:
        with self.transaction() as connection:
            owner = connection.execute(
                """
                SELECT 1
                FROM analysis_tasks task
                JOIN runs r ON r.id=task.claimed_run_id
                WHERE task.id=? AND task.status='running'
                  AND task.claim_lease_token=?
                  AND r.status='running' AND r.lease_token=?
                """,
                (task_id, lease_token, lease_token),
            ).fetchone()
            if owner is None:
                raise RunAlreadyActiveError("analysis chunk ownership was lost")
            connection.execute(
                "DELETE FROM analysis_synthesis_nodes WHERE task_id=?",
                (task_id,),
            )

    def load_synthesis_node(
        self,
        *,
        task_id: int,
        level: int,
        node_index: int,
        input_sha256: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM analysis_synthesis_nodes
                WHERE task_id=? AND level=? AND node_index=? AND input_sha256=?
                """,
                (task_id, level, node_index, input_sha256),
            ).fetchone()
            return dict(row) if row is not None else None

    def save_synthesis_node(
        self,
        *,
        task_id: int,
        level: int,
        node_index: int,
        input_sha256: str,
        covered_chunk_indices: list[int],
        output: dict[str, Any],
        receipt: dict[str, Any],
        lease_token: str,
    ) -> None:
        with self.transaction() as connection:
            owner = connection.execute(
                """
                SELECT 1
                FROM analysis_tasks task
                JOIN runs r ON r.id=task.claimed_run_id
                WHERE task.id=? AND task.status='running'
                  AND task.claim_lease_token=?
                  AND r.status='running' AND r.lease_token=?
                """,
                (task_id, lease_token, lease_token),
            ).fetchone()
            if owner is None:
                raise RunAlreadyActiveError("analysis synthesis ownership was lost")
            connection.execute(
                """
                INSERT INTO analysis_synthesis_nodes(
                    task_id, level, node_index, input_sha256,
                    covered_chunk_indices_json, output_json,
                    provider_receipt_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id, level, node_index) DO UPDATE SET
                    input_sha256=excluded.input_sha256,
                    covered_chunk_indices_json=excluded.covered_chunk_indices_json,
                    output_json=excluded.output_json,
                    provider_receipt_json=excluded.provider_receipt_json,
                    updated_at=excluded.updated_at
                """,
                (
                    task_id,
                    level,
                    node_index,
                    input_sha256,
                    json_dumps(covered_chunk_indices),
                    json_dumps(output),
                    json_dumps(receipt),
                    utc_now(),
                ),
            )

    def synthesis_node_receipts(self, task_id: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT level, node_index, input_sha256,
                       covered_chunk_indices_json, provider_receipt_json
                FROM analysis_synthesis_nodes
                WHERE task_id=?
                ORDER BY level, node_index
                """,
                (task_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def synthesis_node_count(
        self,
        task_id: int,
        *,
        level: int | None = None,
    ) -> int:
        level_clause = " AND level=?" if level is not None else ""
        parameters: tuple[Any, ...] = (
            (task_id, level) if level is not None else (task_id,)
        )
        with self._lock:
            row = self._connection.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM analysis_synthesis_nodes
                WHERE task_id=?
                {level_clause}
                """,
                parameters,
            ).fetchone()
            return int(row["count"])

    def fail_analysis_task(
        self,
        task_id: int,
        error: str,
        *,
        run_id: str,
        lease_token: str,
        retry: bool = True,
        retry_after_seconds: int = 300,
    ) -> bool:
        status = "retry" if retry else "failed"
        timestamp = utc_now()
        not_before = None
        if retry:
            not_before = (
                datetime.now(timezone.utc)
                + timedelta(seconds=max(1, retry_after_seconds))
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            row = connection.execute(
                """
                SELECT
                    task.work_id, task.config_hash,
                    COALESCE(r.retrieval_hash, r.config_hash)
                        AS claim_retrieval_hash
                FROM analysis_tasks task
                JOIN runs r ON r.id=task.claimed_run_id
                WHERE task.id=? AND task.status='running'
                  AND task.claimed_run_id=? AND task.claim_lease_token=?
                """,
                (task_id, run_id, lease_token),
            ).fetchone()
            if row is None:
                return False
            cursor = connection.execute(
                """
                UPDATE analysis_tasks
                SET status=?, error=?, not_before=?,
                    claimed_run_id=NULL, claim_lease_token=NULL, updated_at=?
                WHERE id=? AND status='running'
                  AND claimed_run_id=? AND claim_lease_token=?
                """,
                (
                    status,
                    error[:2000],
                    not_before,
                    timestamp,
                    task_id,
                    run_id,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                return False
            work_state = "analysis_pending" if retry else "analysis_failed"
            connection.execute(
                "UPDATE works SET state=?, updated_at=? WHERE id=?",
                (work_state, timestamp, row["work_id"]),
            )
            connection.execute(
                """
                UPDATE work_scopes AS scope
                SET state=?, active_run_id=NULL, active_lease_token=NULL,
                    last_error=?, last_seen_at=?
                WHERE scope.work_id=?
                  AND scope.state IN (
                      'content_ready','analysis_pending','analysis_running',
                      'analysis_failed','analyzed'
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM profile_snapshots snapshot
                    WHERE COALESCE(
                              snapshot.retrieval_hash,
                              snapshot.config_hash
                          )=scope.config_hash
                      AND COALESCE(
                              snapshot.analysis_policy_hash,
                              snapshot.config_hash
                          )=?
                  )
                """,
                (
                    work_state,
                    error[:2000],
                    timestamp,
                    row["work_id"],
                    row["config_hash"],
                ),
            )
            return True

    def pause_analysis_task(
        self,
        task_id: int,
        reason: str,
        *,
        run_id: str,
        lease_token: str,
    ) -> bool:
        timestamp = utc_now()
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            row = connection.execute(
                """
                SELECT
                    task.work_id, task.config_hash,
                    COALESCE(r.retrieval_hash, r.config_hash)
                        AS claim_retrieval_hash
                FROM analysis_tasks task
                JOIN runs r ON r.id=task.claimed_run_id
                WHERE task.id=? AND task.status='running'
                  AND task.claimed_run_id=? AND task.claim_lease_token=?
                """,
                (task_id, run_id, lease_token),
            ).fetchone()
            if row is None:
                return False
            cursor = connection.execute(
                """
                UPDATE analysis_tasks
                SET status='pending', attempts=MAX(attempts-1, 0),
                    error=?, not_before=NULL,
                    claimed_run_id=NULL, claim_lease_token=NULL,
                    updated_at=?
                WHERE id=? AND status='running'
                  AND claimed_run_id=? AND claim_lease_token=?
                """,
                (
                    reason[:2000],
                    timestamp,
                    task_id,
                    run_id,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                return False
            connection.execute(
                "UPDATE works SET state='analysis_pending', updated_at=? WHERE id=?",
                (timestamp, row["work_id"]),
            )
            connection.execute(
                """
                UPDATE work_scopes AS scope
                SET state='analysis_pending', active_run_id=NULL,
                    active_lease_token=NULL, last_error=?, last_seen_at=?
                WHERE scope.work_id=?
                  AND scope.state IN (
                      'content_ready','analysis_pending','analysis_running',
                      'analysis_failed','analyzed'
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM profile_snapshots snapshot
                    WHERE COALESCE(
                              snapshot.retrieval_hash,
                              snapshot.config_hash
                          )=scope.config_hash
                      AND COALESCE(
                              snapshot.analysis_policy_hash,
                              snapshot.config_hash
                          )=?
                  )
                """,
                (
                    reason[:2000],
                    timestamp,
                    row["work_id"],
                    row["config_hash"],
                ),
            )
            return True

    def analysis_task_attempts(self, task_id: int) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT attempts FROM analysis_tasks WHERE id=?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f"analysis task {task_id} does not exist")
            return int(row["attempts"])

    def complete_analysis(
        self,
        *,
        task_id: int,
        work_id: int,
        provider: str,
        model: str | None,
        prompt_version: str,
        deep_read_status: str,
        tier: str | None,
        score: float | None,
        analysis: dict[str, Any],
        coverage: dict[str, Any],
        receipt: dict[str, Any],
        run_id: str,
        lease_token: str,
    ) -> None:
        timestamp = utc_now()
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            task = connection.execute(
                """
                SELECT
                    task.config_hash, task.retrieval_hash,
                    task.profile_id, task.profile_version,
                    task.work_id, task.input_sha256, task.status,
                    task.claimed_run_id, task.claim_lease_token,
                    COALESCE(d.text_sha256, d.content_sha256) AS current_input_sha256,
                    r3_document_is_analysis_eligible(
                        d.content_kind,
                        d.status,
                        d.document_policy_hash,
                        d.coverage_json
                    ) AS document_is_analysis_eligible
                FROM analysis_tasks task
                JOIN documents d ON d.id=task.document_id
                WHERE task.id=?
                """,
                (task_id,),
            ).fetchone()
            if task is None or not task["config_hash"]:
                raise ValueError("analysis task has no immutable config scope")
            if int(task["work_id"]) != work_id:
                raise ValueError("analysis task/work identity mismatch")
            if (
                task["status"] != "running"
                or task["claimed_run_id"] != run_id
                or task["claim_lease_token"] != lease_token
                or task["input_sha256"] != task["current_input_sha256"]
                or int(task["document_is_analysis_eligible"] or 0) != 1
            ):
                raise RunAlreadyActiveError(
                    "analysis task ownership or document revision was lost"
                )
            provenance_status = connection.execute(
                """
                SELECT CASE
                    WHEN EXISTS (
                        SELECT 1
                        FROM work_sources provenance_link
                        JOIN source_observations observation
                          ON observation.source_record_id=
                             provenance_link.source_record_id
                        WHERE provenance_link.work_id=?
                          AND observation.observed_at<=?
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM content_revisions revision
                        WHERE revision.work_id=?
                          AND COALESCE(
                              revision.text_sha256,
                              revision.content_sha256
                          )=?
                          AND revision.observed_at<=?
                    )
                    THEN 'append_only'
                    ELSE 'legacy_or_unknown'
                END
                """,
                (
                    work_id,
                    timestamp,
                    work_id,
                    task["input_sha256"],
                    timestamp,
                ),
            ).fetchone()[0]
            connection.execute(
                """
                INSERT INTO analyses(
                    task_id, work_id, provider, model, prompt_version, config_hash, retrieval_hash,
                    profile_id, profile_version, deep_read_status, tier, score,
                    analysis_json, coverage_json, provider_receipt_json,
                    provenance_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    provider=excluded.provider,
                    model=excluded.model,
                    config_hash=excluded.config_hash,
                    retrieval_hash=excluded.retrieval_hash,
                    profile_id=excluded.profile_id,
                    profile_version=excluded.profile_version,
                    deep_read_status=excluded.deep_read_status,
                    tier=excluded.tier,
                    score=excluded.score,
                    analysis_json=excluded.analysis_json,
                    coverage_json=excluded.coverage_json,
                    provider_receipt_json=excluded.provider_receipt_json,
                    provenance_status=excluded.provenance_status,
                    created_at=excluded.created_at
                """,
                (
                    task_id,
                    work_id,
                    provider,
                    model,
                    prompt_version,
                    str(task["config_hash"]),
                    str(task["retrieval_hash"]),
                    str(task["profile_id"]),
                    int(task["profile_version"]),
                    deep_read_status,
                    tier,
                    score,
                    json_dumps(analysis),
                    json_dumps(coverage),
                    json_dumps(receipt),
                    provenance_status,
                    timestamp,
                ),
            )
            connection.execute(
                """
                UPDATE analysis_tasks
                SET status='completed', completed_at=?, updated_at=?, error=NULL,
                    phase='complete', phase_done=1, phase_total=1,
                    phase_updated_at=?,
                    claimed_run_id=NULL, claim_lease_token=NULL,
                    not_before=NULL
                WHERE id=? AND status='running'
                  AND claimed_run_id=? AND claim_lease_token=?
                """,
                (
                    timestamp,
                    timestamp,
                    timestamp,
                    task_id,
                    run_id,
                    lease_token,
                ),
            )
            connection.execute(
                "UPDATE works SET state='analyzed', updated_at=? WHERE id=?",
                (timestamp, work_id),
            )
            connection.execute(
                """
                UPDATE work_scopes AS scope
                SET state='analyzed', active_run_id=NULL, active_lease_token=NULL,
                    last_error=NULL, last_seen_at=?
                WHERE scope.work_id=?
                  AND scope.state IN (
                      'content_ready','analysis_pending','analysis_running',
                      'analysis_failed','analyzed'
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM profile_snapshots snapshot
                    WHERE COALESCE(
                              snapshot.retrieval_hash,
                              snapshot.config_hash
                          )=scope.config_hash
                      AND COALESCE(
                              snapshot.analysis_policy_hash,
                              snapshot.config_hash
                          )=?
                  )
                """,
                (
                    timestamp,
                    work_id,
                    task["config_hash"],
                ),
            )

    def record_model_invocation(
        self,
        *,
        run_id: str,
        lease_token: str,
        receipt: dict[str, Any],
        task_id: int | None = None,
        work_id: int | None = None,
    ) -> None:
        receipt_json = json_dumps(receipt)
        receipt_sha256 = sha256_text(receipt_json)
        invocation_id = str(receipt.get("invocation_id") or receipt_sha256)
        usage = receipt.get("usage")
        if not isinstance(usage, dict):
            usage = {}

        def token_count(*values: Any) -> int:
            for value in values:
                try:
                    parsed = int(value)
                except (TypeError, ValueError):
                    continue
                return max(0, parsed)
            return 0

        prompt_details = usage.get("prompt_tokens_details")
        if not isinstance(prompt_details, dict):
            prompt_details = {}
        completion_details = usage.get("completion_tokens_details")
        if not isinstance(completion_details, dict):
            completion_details = {}
        input_tokens = token_count(
            usage.get("input_tokens"),
            usage.get("prompt_tokens"),
        )
        cached_input_tokens = token_count(
            usage.get("cached_input_tokens"),
            prompt_details.get("cached_tokens"),
        )
        output_tokens = token_count(
            usage.get("output_tokens"),
            usage.get("completion_tokens"),
        )
        reasoning_output_tokens = token_count(
            usage.get("reasoning_output_tokens"),
            completion_details.get("reasoning_tokens"),
        )
        try:
            duration_seconds = max(0.0, float(receipt.get("duration_seconds") or 0))
        except (TypeError, ValueError):
            duration_seconds = 0.0
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            existing = connection.execute(
                """
                SELECT receipt_sha256 FROM model_invocations
                WHERE invocation_id=?
                """,
                (invocation_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["receipt_sha256"]) != receipt_sha256:
                    raise ValueError(
                        "model invocation id was reused with a different receipt"
                    )
                return
            if task_id is not None:
                task = connection.execute(
                    """
                    SELECT work_id, status, claimed_run_id, claim_lease_token
                    FROM analysis_tasks
                    WHERE id=?
                    """,
                    (task_id,),
                ).fetchone()
                if task is None:
                    raise ValueError("model invocation references an unknown task")
                if work_id is None or int(task["work_id"]) != int(work_id):
                    raise ValueError("model invocation task/work identity mismatch")
                if (
                    task["status"] != "running"
                    or task["claimed_run_id"] != run_id
                    or task["claim_lease_token"] != lease_token
                ):
                    raise RunAlreadyActiveError(
                        "model invocation task ownership was lost"
                    )
            connection.execute(
                """
                INSERT INTO model_invocations(
                    invocation_id, run_id, task_id, work_id,
                    provider, purpose, model,
                    input_tokens, cached_input_tokens, output_tokens,
                    reasoning_output_tokens, duration_seconds,
                    receipt_sha256, receipt_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    invocation_id,
                    run_id,
                    task_id,
                    work_id,
                    str(receipt.get("provider") or "unknown"),
                    str(receipt.get("purpose") or "unknown"),
                    str(receipt.get("model") or "") or None,
                    input_tokens,
                    cached_input_tokens,
                    output_tokens,
                    reasoning_output_tokens,
                    duration_seconds,
                    receipt_sha256,
                    receipt_json,
                    str(receipt.get("completed_at") or utc_now()),
                ),
            )

    def model_usage(
        self,
        *,
        run_id: str | None = None,
        task_id: int | None = None,
        work_id: int | None = None,
    ) -> dict[str, int | float]:
        clauses: list[str] = []
        parameters: list[Any] = []
        for column, value in (
            ("run_id", run_id),
            ("task_id", task_id),
            ("work_id", work_id),
        ):
            if value is None:
                continue
            clauses.append(f"{column}=?")
            parameters.append(value)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            row = self._connection.execute(
                f"""
                SELECT
                    COUNT(*) AS invocation_count,
                    COALESCE(SUM(input_tokens), 0) AS input_tokens,
                    COALESCE(SUM(cached_input_tokens), 0) AS cached_input_tokens,
                    COALESCE(SUM(output_tokens), 0) AS output_tokens,
                    COALESCE(SUM(reasoning_output_tokens), 0)
                        AS reasoning_output_tokens,
                    COALESCE(SUM(duration_seconds), 0) AS duration_seconds
                FROM model_invocations
                {where}
                """,
                tuple(parameters),
            ).fetchone()
        return {
            "invocation_count": int(row["invocation_count"]),
            "input_tokens": int(row["input_tokens"]),
            "cached_input_tokens": int(row["cached_input_tokens"]),
            "output_tokens": int(row["output_tokens"]),
            "reasoning_output_tokens": int(row["reasoning_output_tokens"]),
            "duration_seconds": round(float(row["duration_seconds"]), 3),
        }

    def admitted_run_intake_state(self, run_id: str) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT w.id AS work_id, q.lane
                FROM run_hits rh
                JOIN works w ON w.id=rh.work_id
                JOIN query_jobs q ON q.id=rh.query_job_id
                WHERE rh.run_id=? AND rh.admitted=1
                ORDER BY rh.seen_at, q.id, w.id
                """,
                (run_id,),
            ).fetchall()
        return [
            (f"work:{int(row['work_id'])}", str(row["lane"]))
            for row in rows
        ]

    @staticmethod
    def _gold_request_id(value: str, *, field: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 128:
            raise ValueError(f"{field} must contain 1-128 characters")
        return normalized

    @staticmethod
    def _gold_reviewer_identity(value: str) -> str:
        normalized = value.strip()
        if not normalized or len(normalized) > 200:
            raise ValueError("reviewer_identity must contain 1-200 characters")
        return normalized

    @staticmethod
    def _gold_document_sha256(document: dict[str, Any]) -> str:
        return sha256_text(canonical_json(document))

    @classmethod
    def _validated_gold_review_row(
        cls,
        row: sqlite3.Row | dict[str, Any],
    ) -> dict[str, Any]:
        from .calibration import _validate_gold_set_v2

        result = dict(row)
        try:
            document = json.loads(str(result["document_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GoldReviewConflictError(
                "stored Gold review document is corrupted"
            ) from exc
        try:
            _validate_gold_set_v2(document)
        except Exception as exc:
            raise GoldReviewConflictError(
                "stored Gold review document violates the v2 contract"
            ) from exc
        document_sha256 = cls._gold_document_sha256(document)
        if document_sha256 != str(result["document_sha256"]):
            raise GoldReviewConflictError(
                "stored Gold review document hash does not match"
            )
        if (
            str(document["source"]["sha256"]) != str(result["source_sha256"])
            or str(document["review"]["status"]) != str(result["status"])
            or str(document["review"]["reviewer_identity"])
            != str(result["reviewer_identity"])
            or int(document["review"]["item_count"]) != int(result["item_count"])
            or len(document["revisions"])
            != int(result["current_revision_sequence"])
        ):
            raise GoldReviewConflictError(
                "stored Gold review metadata does not match its document"
            )
        result["document"] = document
        return result

    @staticmethod
    def _gold_review_summary(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "review_id": str(row["review_id"]),
            "status": str(row["status"]),
            "reviewer_identity": str(row["reviewer_identity"]),
            "item_count": int(row["item_count"]),
            "document_sha256": str(row["document_sha256"]),
            "document_revision_sequence": int(
                row["current_revision_sequence"]
            ),
            "source_v1_sha256": str(row["source_sha256"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "locked_at": row.get("locked_at"),
        }

    def gold_review_document(self, review_id: str) -> dict[str, Any]:
        normalized_review_id = self._gold_request_id(
            review_id,
            field="review_id",
        )
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM gold_reviews WHERE review_id=?",
                (normalized_review_id,),
            ).fetchone()
            if row is not None:
                cached = self._gold_review_validation_cache.get(
                    normalized_review_id
                )
                if (
                    cached is not None
                    and cached[0] == str(row["document_sha256"])
                    and cached[1] == int(row["current_revision_sequence"])
                ):
                    return copy.deepcopy(cached[2])
            revision_rows = self._connection.execute(
                """
                SELECT sequence, event, item_id, previous_document_sha256,
                       document_sha256, status, revision_sha256,
                       revision_json, submitted_at
                FROM gold_review_revisions
                WHERE review_id=? ORDER BY sequence
                """,
                (normalized_review_id,),
            ).fetchall()
        if row is None:
            raise GoldReviewNotFoundError("Gold review does not exist")
        validated = self._validated_gold_review_row(row)
        current_sequence = int(validated["current_revision_sequence"])
        try:
            initial_document = json.loads(str(validated["initial_document_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GoldReviewConflictError(
                "stored initial Gold review document is corrupted"
            ) from exc
        if (
            not isinstance(initial_document, dict)
            or initial_document.get("revisions") != []
            or self._gold_document_sha256(initial_document)
            != str(validated["initial_document_sha256"])
        ):
            raise GoldReviewConflictError(
                "stored initial Gold review document hash does not match"
            )
        if len(revision_rows) != current_sequence:
            raise GoldReviewConflictError(
                "stored Gold review revision count does not match"
            )
        expected_previous_document_sha256 = str(
            validated["initial_document_sha256"]
        )
        document_revisions = validated["document"]["revisions"]
        replay_document = json.loads(canonical_json(initial_document))
        for index, revision_row in enumerate(revision_rows, start=1):
            try:
                revision = json.loads(str(revision_row["revision_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise GoldReviewConflictError(
                    "stored Gold review revision is corrupted"
                ) from exc
            if (
                int(revision_row["sequence"]) != index
                or str(revision_row["previous_document_sha256"])
                != expected_previous_document_sha256
                or not isinstance(revision, dict)
                or revision != document_revisions[index - 1]
                or str(revision_row["event"]) != str(revision.get("event"))
                or revision_row["item_id"] != revision.get("item_id")
                or str(revision_row["submitted_at"])
                != str(revision.get("submitted_at"))
                or str(revision_row["revision_sha256"])
                != str(revision.get("revision_sha256"))
            ):
                raise GoldReviewConflictError(
                    "stored Gold review revision chain does not match"
                )
            replay_document["revisions"].append(revision)
            if revision["event"] == "y0_submit":
                replay_item = next(
                    (
                        item
                        for item in replay_document["items"]
                        if item["item_id"] == revision["item_id"]
                    ),
                    None,
                )
                if replay_item is None:
                    raise GoldReviewConflictError(
                        "stored Gold review revision names an unknown item"
                    )
                replay_item["y0"] = dict(revision["payload"]) | {
                    "revision_sha256": revision["revision_sha256"]
                }
            elif revision["event"] == "y0_lock":
                replay_document["review"].update(
                    {
                        "status": "y0_locked",
                        "y0_locked_at": revision["submitted_at"],
                        "y0_lock_sha256": revision["payload"].get(
                            "y0_lock_sha256"
                        ),
                    }
                )
            else:
                raise GoldReviewConflictError(
                    "stored Gold review contains an unsupported persisted event"
                )
            replay_sha256 = self._gold_document_sha256(replay_document)
            if (
                replay_sha256 != str(revision_row["document_sha256"])
                or str(revision_row["status"])
                != str(replay_document["review"]["status"])
            ):
                raise GoldReviewConflictError(
                    "stored Gold review revision result does not match replay"
                )
            expected_previous_document_sha256 = replay_sha256
        if (
            expected_previous_document_sha256 != str(validated["document_sha256"])
            or (
                current_sequence == 0
                and str(validated["initial_document_sha256"])
                != str(validated["document_sha256"])
            )
        ):
            raise GoldReviewConflictError(
                "stored Gold review revision head does not match"
            )
        if replay_document != validated["document"]:
            raise GoldReviewConflictError(
                "stored Gold review document does not match revision replay"
            )
        with self._lock:
            self._gold_review_validation_cache[normalized_review_id] = (
                str(validated["document_sha256"]),
                current_sequence,
                copy.deepcopy(validated),
            )
        return validated

    def create_gold_review_from_v1_file(
        self,
        *,
        source_path: Path,
        reviewer_identity: str,
        creation_request_id: str,
        collection_kind: str = "run_derived",
        evaluation_split: str = "development",
    ) -> dict[str, Any]:
        """Import an explicitly named local v1 artifact into a fresh blind review."""

        from .calibration import convert_gold_set_v1_to_v2_preview

        reviewer = self._gold_reviewer_identity(reviewer_identity)
        request_id = self._gold_request_id(
            creation_request_id,
            field="creation_request_id",
        )
        request_sha256 = sha256_text(
            canonical_json(
                {
                    "source_path": str(source_path),
                    "reviewer_identity": reviewer,
                    "collection_kind": collection_kind,
                    "evaluation_split": evaluation_split,
                }
            )
        )
        with self._lock:
            existing = self._connection.execute(
                "SELECT * FROM gold_reviews WHERE creation_request_id=?",
                (request_id,),
            ).fetchone()
        if existing is not None:
            validated = self._validated_gold_review_row(existing)
            if (
                str(validated["reviewer_identity"]) != reviewer
                or str(validated["creation_request_sha256"]) != request_sha256
            ):
                raise GoldReviewConflictError(
                    "creation_request_id already belongs to another request"
                )
            return self._gold_review_summary(validated) | {"idempotent": True}

        if not source_path.is_absolute():
            raise ValueError("source_path must be an explicit absolute local path")
        resolved = source_path.resolve(strict=True)
        if str(resolved).startswith("\\\\"):
            raise ValueError("source_path must identify a local, non-UNC file")
        if not resolved.is_file():
            raise ValueError("source_path must identify a local JSON file")
        stat = resolved.stat()
        if stat.st_size <= 0 or stat.st_size > 16 * 1024 * 1024:
            raise ValueError("Gold v1 file size is outside the 1-16777216 byte limit")
        source_bytes = resolved.read_bytes()
        if len(source_bytes) <= 0 or len(source_bytes) > 16 * 1024 * 1024:
            raise ValueError("Gold v1 file size is outside the 1-16777216 byte limit")
        try:
            source_document = json.loads(source_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Gold v1 file is not valid UTF-8 JSON") from exc
        if not isinstance(source_document, dict):
            raise ValueError("Gold v1 file root must be a JSON object")
        converted = convert_gold_set_v1_to_v2_preview(
            source_document,
            reviewer_identity=reviewer,
            collection_kind=collection_kind,
            evaluation_split=evaluation_split,
        )
        review_id = str(uuid.uuid4())
        timestamp = utc_now()
        document_json = canonical_json(converted)
        document_sha256 = sha256_text(document_json)
        source_file_sha256 = sha256_bytes(source_bytes)
        try:
            with self.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO gold_reviews(
                        review_id, creation_request_id, creation_request_sha256,
                        source_schema, source_sha256, source_file_sha256,
                        source_path, status, reviewer_identity, item_count,
                        initial_document_sha256, initial_document_json,
                        document_sha256, document_json,
                        current_revision_sequence, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 70, ?, ?, ?, ?, 0, ?, ?)
                    """,
                    (
                        review_id,
                        request_id,
                        request_sha256,
                        str(converted["source"]["schema"]),
                        str(converted["source"]["sha256"]),
                        source_file_sha256,
                        str(resolved),
                        str(converted["review"]["status"]),
                        reviewer,
                        document_sha256,
                        document_json,
                        document_sha256,
                        document_json,
                        timestamp,
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            with self._lock:
                existing = self._connection.execute(
                    "SELECT * FROM gold_reviews WHERE creation_request_id=?",
                    (request_id,),
                ).fetchone()
            if existing is None:
                raise
            validated = self._validated_gold_review_row(existing)
            if (
                str(validated["reviewer_identity"]) != reviewer
                or str(validated["creation_request_sha256"]) != request_sha256
            ):
                raise GoldReviewConflictError(
                    "creation_request_id already belongs to another request"
                ) from exc
            return self._gold_review_summary(validated) | {"idempotent": True}
        return self._gold_review_summary(
            self.gold_review_document(review_id)
        ) | {"idempotent": False}

    def gold_review_blind_payload(
        self,
        review_id: str,
        *,
        limit: int = 10,
        offset: int = 0,
    ) -> dict[str, Any]:
        from .calibration import blind_gold_set_payload

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer")
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise ValueError("offset must be an integer")
        normalized_limit = max(1, min(limit, 25))
        normalized_offset = max(0, offset)
        row = self.gold_review_document(review_id)
        if str(row["status"]) != "y0_in_progress":
            raise GoldReviewConflictError("blind y0 review is already locked")
        payload = blind_gold_set_payload(row["document"])
        all_items = payload["items"]
        payload["items"] = all_items[
            normalized_offset : normalized_offset + normalized_limit
        ]
        payload["review_id"] = str(row["review_id"])
        payload["document_revision_sequence"] = int(
            row["current_revision_sequence"]
        )
        payload["document_sha256"] = str(row["document_sha256"])
        payload["limit"] = normalized_limit
        payload["offset"] = normalized_offset
        payload["has_more"] = (
            normalized_offset + len(payload["items"]) < len(all_items)
        )
        payload["next_offset"] = (
            normalized_offset + len(payload["items"])
            if payload["has_more"]
            else None
        )
        return payload

    def _existing_gold_revision(
        self,
        connection: sqlite3.Connection,
        *,
        review_id: str,
        request_id: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            """
            SELECT * FROM gold_review_revisions
            WHERE review_id=? AND request_id=?
            """,
            (review_id, request_id),
        ).fetchone()
        if row is None:
            return None
        if str(row["request_sha256"]) != request_sha256:
            raise GoldReviewConflictError(
                "request_id was already used with a different payload"
            )
        review = connection.execute(
            """
            SELECT source_sha256, item_count, status, document_sha256,
                   current_revision_sequence
            FROM gold_reviews WHERE review_id=?
            """,
            (review_id,),
        ).fetchone()
        if review is None:
            raise GoldReviewConflictError("Gold revision has no parent review")
        return {
            "review_id": review_id,
            "status": str(review["status"]),
            "document_sha256": str(review["document_sha256"]),
            "document_revision_sequence": int(
                review["current_revision_sequence"]
            ),
            "source_v1_sha256": str(review["source_sha256"]),
            "item_count": int(review["item_count"]),
            "idempotent": True,
        }

    def save_gold_y0(
        self,
        *,
        review_id: str,
        request_id: str,
        item_id: str,
        reviewer_identity: str,
        semantic_label: str,
        operational_status: str,
        confidence: int | None,
        evidence_opened: bool,
        elapsed_ms: int,
        notes: str | None,
        submitted_at: str | None,
        expected_item_revision_sequence: int,
        expected_document_revision_sequence: int,
    ) -> dict[str, Any]:
        from .calibration import submit_gold_y0

        normalized_review_id = self._gold_request_id(review_id, field="review_id")
        normalized_request_id = self._gold_request_id(request_id, field="request_id")
        reviewer = self._gold_reviewer_identity(reviewer_identity)
        if not item_id or len(item_id) > 256:
            raise ValueError("item_id must contain 1-256 characters")
        for field, value in (
            ("expected_item_revision_sequence", expected_item_revision_sequence),
            ("expected_document_revision_sequence", expected_document_revision_sequence),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{field} must be a non-negative integer")
        if notes is not None and len(notes) > 8000:
            raise ValueError("notes must not exceed 8000 characters")
        request_payload = {
            "event": "y0_submit",
            "item_id": item_id,
            "reviewer_identity": reviewer,
            "semantic_label": semantic_label,
            "operational_status": operational_status,
            "confidence": confidence,
            "evidence_opened": evidence_opened,
            "elapsed_ms": elapsed_ms,
            "notes": notes,
            "submitted_at": submitted_at,
            "expected_item_revision_sequence": expected_item_revision_sequence,
            "expected_document_revision_sequence": expected_document_revision_sequence,
        }
        request_sha256 = sha256_text(canonical_json(request_payload))
        with self.transaction() as connection:
            existing_revision = self._existing_gold_revision(
                connection,
                review_id=normalized_review_id,
                request_id=normalized_request_id,
                request_sha256=request_sha256,
            )
            if existing_revision is not None:
                return existing_revision
            row = connection.execute(
                "SELECT * FROM gold_reviews WHERE review_id=?",
                (normalized_review_id,),
            ).fetchone()
            if row is None:
                raise GoldReviewNotFoundError("Gold review does not exist")
            current = self._validated_gold_review_row(row)
            current_sequence = int(current["current_revision_sequence"])
            if expected_document_revision_sequence != current_sequence:
                raise GoldReviewConflictError(
                    "stale Gold review document revision"
                )
            if str(current["status"]) != "y0_in_progress":
                raise GoldReviewConflictError(
                    "Gold y0 is locked and cannot be changed"
                )
            effective_submitted_at = submitted_at or utc_now()
            updated = submit_gold_y0(
                current["document"],
                item_id=item_id,
                reviewer_identity=reviewer,
                semantic_label=semantic_label,
                operational_status=operational_status,
                confidence=confidence,
                evidence_opened=evidence_opened,
                elapsed_ms=elapsed_ms,
                notes=notes,
                submitted_at=effective_submitted_at,
                expected_revision_sequence=expected_item_revision_sequence,
            )
            next_sequence = current_sequence + 1
            if len(updated["revisions"]) != next_sequence:
                raise GoldReviewConflictError(
                    "Gold revision sequence is inconsistent"
                )
            document_json = canonical_json(updated)
            document_sha256 = sha256_text(document_json)
            revision = updated["revisions"][-1]
            connection.execute(
                """
                INSERT INTO gold_review_revisions(
                    review_id, sequence, event, item_id, request_id,
                    request_sha256, previous_document_sha256,
                    document_sha256, status, revision_sha256, revision_json,
                    submitted_at, received_at
                ) VALUES (?, ?, 'y0_submit', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_review_id,
                    next_sequence,
                    item_id,
                    normalized_request_id,
                    request_sha256,
                    str(current["document_sha256"]),
                    document_sha256,
                    str(updated["review"]["status"]),
                    str(revision["revision_sha256"]),
                    canonical_json(revision),
                    effective_submitted_at,
                    utc_now(),
                ),
            )
            cursor = connection.execute(
                """
                UPDATE gold_reviews
                SET status=?, document_sha256=?, document_json=?,
                    current_revision_sequence=?, updated_at=?
                WHERE review_id=? AND current_revision_sequence=?
                  AND document_sha256=?
                """,
                (
                    str(updated["review"]["status"]),
                    document_sha256,
                    document_json,
                    next_sequence,
                    utc_now(),
                    normalized_review_id,
                    current_sequence,
                    str(current["document_sha256"]),
                ),
            )
            if cursor.rowcount != 1:
                raise GoldReviewConflictError(
                    "Gold review changed while saving"
                )
        with self._lock:
            self._gold_review_validation_cache.pop(normalized_review_id, None)
        return {
            "review_id": normalized_review_id,
            "status": str(updated["review"]["status"]),
            "document_sha256": document_sha256,
            "document_revision_sequence": next_sequence,
            "source_v1_sha256": str(updated["source"]["sha256"]),
            "item_count": 70,
            "idempotent": False,
        }

    def lock_gold_y0_review(
        self,
        *,
        review_id: str,
        request_id: str,
        reviewer_identity: str,
        locked_at: str | None,
        expected_document_revision_sequence: int,
    ) -> dict[str, Any]:
        from .calibration import lock_gold_y0

        normalized_review_id = self._gold_request_id(review_id, field="review_id")
        normalized_request_id = self._gold_request_id(request_id, field="request_id")
        reviewer = self._gold_reviewer_identity(reviewer_identity)
        if (
            isinstance(expected_document_revision_sequence, bool)
            or not isinstance(expected_document_revision_sequence, int)
            or expected_document_revision_sequence < 0
        ):
            raise ValueError(
                "expected_document_revision_sequence must be a non-negative integer"
            )
        request_payload = {
            "event": "y0_lock",
            "reviewer_identity": reviewer,
            "locked_at": locked_at,
            "expected_document_revision_sequence": expected_document_revision_sequence,
        }
        request_sha256 = sha256_text(canonical_json(request_payload))
        with self.transaction() as connection:
            existing_revision = self._existing_gold_revision(
                connection,
                review_id=normalized_review_id,
                request_id=normalized_request_id,
                request_sha256=request_sha256,
            )
            if existing_revision is not None:
                return existing_revision
            row = connection.execute(
                "SELECT * FROM gold_reviews WHERE review_id=?",
                (normalized_review_id,),
            ).fetchone()
            if row is None:
                raise GoldReviewNotFoundError("Gold review does not exist")
            current = self._validated_gold_review_row(row)
            current_sequence = int(current["current_revision_sequence"])
            if expected_document_revision_sequence != current_sequence:
                raise GoldReviewConflictError(
                    "stale Gold review document revision"
                )
            if str(current["status"]) != "y0_in_progress":
                raise GoldReviewConflictError("Gold y0 can be locked exactly once")
            effective_locked_at = locked_at or utc_now()
            updated = lock_gold_y0(
                current["document"],
                reviewer_identity=reviewer,
                locked_at=effective_locked_at,
            )
            next_sequence = current_sequence + 1
            if len(updated["revisions"]) != next_sequence:
                raise GoldReviewConflictError(
                    "Gold revision sequence is inconsistent"
                )
            document_json = canonical_json(updated)
            document_sha256 = sha256_text(document_json)
            revision = updated["revisions"][-1]
            connection.execute(
                """
                INSERT INTO gold_review_revisions(
                    review_id, sequence, event, item_id, request_id,
                    request_sha256, previous_document_sha256,
                    document_sha256, status, revision_sha256, revision_json,
                    submitted_at, received_at
                ) VALUES (?, ?, 'y0_lock', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_review_id,
                    next_sequence,
                    normalized_request_id,
                    request_sha256,
                    str(current["document_sha256"]),
                    document_sha256,
                    str(updated["review"]["status"]),
                    str(revision["revision_sha256"]),
                    canonical_json(revision),
                    effective_locked_at,
                    utc_now(),
                ),
            )
            cursor = connection.execute(
                """
                UPDATE gold_reviews
                SET status='y0_locked', document_sha256=?, document_json=?,
                    current_revision_sequence=?, updated_at=?, locked_at=?
                WHERE review_id=? AND current_revision_sequence=?
                  AND document_sha256=?
                """,
                (
                    document_sha256,
                    document_json,
                    next_sequence,
                    utc_now(),
                    effective_locked_at,
                    normalized_review_id,
                    current_sequence,
                    str(current["document_sha256"]),
                ),
            )
            if cursor.rowcount != 1:
                raise GoldReviewConflictError(
                    "Gold review changed while locking"
                )
        with self._lock:
            self._gold_review_validation_cache.pop(normalized_review_id, None)
        return {
            "review_id": normalized_review_id,
            "status": "y0_locked",
            "document_sha256": document_sha256,
            "document_revision_sequence": next_sequence,
            "source_v1_sha256": str(updated["source"]["sha256"]),
            "item_count": 70,
            "y0_lock_sha256": str(updated["review"]["y0_lock_sha256"]),
            "idempotent": False,
        }

    def add_feedback(
        self,
        work_id: int,
        rating: str,
        comment: str | None,
        *,
        retrieval_hash: str,
        analysis_policy_hash: str,
    ) -> None:
        if rating not in {"改变思路", "值得保存", "一般背景", "无关"}:
            raise ValueError("invalid feedback rating")
        with self.transaction() as connection:
            eligible = connection.execute(
                """
                SELECT 1
                FROM work_scopes ws
                JOIN documents current_document ON current_document.id=(
                    SELECT candidate_document.id
                    FROM documents candidate_document
                    WHERE candidate_document.work_id=ws.work_id
                    ORDER BY
                        candidate_document.updated_at DESC,
                        candidate_document.id DESC
                    LIMIT 1
                )
                JOIN analysis_tasks task
                  ON task.work_id=ws.work_id
                 AND task.document_id=current_document.id
                 AND task.config_hash=?
                 AND task.input_sha256=COALESCE(
                     current_document.text_sha256,
                     current_document.content_sha256
                 )
                JOIN analyses analysis
                  ON analysis.task_id=task.id
                 AND analysis.work_id=ws.work_id
                 AND analysis.config_hash=?
                 AND analysis.deep_read_status='complete'
                WHERE ws.work_id=?
                  AND ws.config_hash=?
                  AND ws.state='analyzed'
                  AND r3_document_is_analysis_eligible(
                      current_document.content_kind,
                      current_document.status,
                      current_document.document_policy_hash,
                      current_document.coverage_json
                  )
                LIMIT 1
                """,
                (
                    analysis_policy_hash,
                    analysis_policy_hash,
                    work_id,
                    retrieval_hash,
                ),
            ).fetchone()
            if eligible is None:
                raise FeedbackNotAllowedError(
                    "feedback requires a complete deep read in the current scope"
                )
            connection.execute(
                "INSERT INTO feedback(work_id, rating, comment, created_at) VALUES (?, ?, ?, ?)",
                (work_id, rating, comment, utc_now()),
            )

    def event(
        self,
        *,
        run_id: str | None,
        component: str,
        event_type: str,
        severity: str = "info",
        message: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO events(
                    run_id, timestamp, severity, component, event_type, message, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    utc_now(),
                    severity,
                    component,
                    event_type,
                    message,
                    json_dumps(details or {}),
                ),
            )

    @staticmethod
    def _validated_publication_snapshot_payloads(
        summary: Any,
        candidates: Any,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], str, str]:
        if not isinstance(summary, dict):
            raise PublicationConflictError(
                "run publication snapshot summary must be an object"
            )
        if not isinstance(candidates, list):
            raise PublicationConflictError(
                "run publication snapshot candidates must be a list"
            )
        normalized_candidates: list[dict[str, Any]] = []
        analysis_ids: set[int] = set()
        for raw_item in candidates:
            if not isinstance(raw_item, dict):
                raise PublicationConflictError(
                    "run publication snapshot candidate must be an object"
                )
            item = dict(raw_item)
            try:
                analysis_id = int(item["analysis_id"])
            except (KeyError, TypeError, ValueError) as exc:
                raise PublicationConflictError(
                    "run publication snapshot candidate has invalid analysis_id"
                ) from exc
            if analysis_id in analysis_ids:
                raise PublicationConflictError(
                    "run publication snapshot contains duplicate analysis_id"
                )
            analysis_ids.add(analysis_id)
            snapshot = item.get("snapshot")
            snapshot_sha256 = item.get("snapshot_sha256")
            if not isinstance(snapshot, dict) or not isinstance(
                snapshot_sha256, str
            ):
                raise PublicationConflictError(
                    "run publication snapshot candidate has no frozen evidence"
                )
            if sha256_text(canonical_json(snapshot)) != snapshot_sha256:
                raise PublicationConflictError(
                    "run publication candidate snapshot hash mismatch"
                )
            normalized_candidates.append(item)
        summary_sha256 = sha256_text(canonical_json(summary))
        candidates_sha256 = sha256_text(canonical_json(normalized_candidates))
        return (
            dict(summary),
            normalized_candidates,
            summary_sha256,
            candidates_sha256,
        )

    def complete_run_with_publication_snapshot(
        self,
        run_id: str,
        *,
        lease_token: str,
        terminal_status: str,
        error: str | None,
        retrieval_hash: str,
        analysis_policy_hash: str,
        summary: dict[str, Any],
        candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if terminal_status not in {"completed", "completed_with_gaps"}:
            raise ValueError(
                "publication snapshot requires a publishable terminal status"
            )
        (
            normalized_summary,
            normalized_candidates,
            summary_sha256,
            candidates_sha256,
        ) = self._validated_publication_snapshot_payloads(summary, candidates)
        expected_summary = {
            "run_id": run_id,
            "status": terminal_status,
            "retrieval_hash": retrieval_hash,
            "analysis_policy_hash": analysis_policy_hash,
        }
        mismatches = {
            key: {"expected": value, "actual": normalized_summary.get(key)}
            for key, value in expected_summary.items()
            if normalized_summary.get(key) != value
        }
        if mismatches:
            raise PublicationConflictError(
                "run publication summary identity mismatch: "
                + canonical_json(mismatches)
            )
        timestamp = utc_now()
        with self.transaction() as connection:
            self._require_run_lease(connection, run_id, lease_token)
            run = connection.execute(
                """
                SELECT retrieval_hash, analysis_policy_hash
                FROM runs WHERE id=?
                """,
                (run_id,),
            ).fetchone()
            if (
                run is None
                or str(run["retrieval_hash"]) != retrieval_hash
                or str(run["analysis_policy_hash"]) != analysis_policy_hash
            ):
                raise PublicationConflictError(
                    "run publication snapshot is outside the run identity"
                )
            connection.execute(
                """
                INSERT INTO run_publication_snapshots(
                    run_id, retrieval_hash, analysis_policy_hash,
                    terminal_status, summary_sha256, summary_json,
                    candidates_sha256, candidates_json,
                    candidate_count, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    retrieval_hash=excluded.retrieval_hash,
                    analysis_policy_hash=excluded.analysis_policy_hash,
                    terminal_status=excluded.terminal_status,
                    summary_sha256=excluded.summary_sha256,
                    summary_json=excluded.summary_json,
                    candidates_sha256=excluded.candidates_sha256,
                    candidates_json=excluded.candidates_json,
                    candidate_count=excluded.candidate_count,
                    created_at=excluded.created_at
                """,
                (
                    run_id,
                    retrieval_hash,
                    analysis_policy_hash,
                    terminal_status,
                    summary_sha256,
                    canonical_json(normalized_summary),
                    candidates_sha256,
                    canonical_json(normalized_candidates),
                    len(normalized_candidates),
                    timestamp,
                ),
            )
            cursor = connection.execute(
                """
                UPDATE runs
                SET status=?, updated_at=?, ended_at=?, error=?,
                    owner_pid=NULL, lease_token=NULL, lease_expires_at=NULL
                WHERE id=? AND status='running' AND lease_token=?
                """,
                (
                    terminal_status,
                    timestamp,
                    timestamp,
                    error,
                    run_id,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                raise RunAlreadyActiveError(
                    "cannot finish a run after losing its lease"
                )
        return {
            "run_id": run_id,
            "terminal_status": terminal_status,
            "ended_at": timestamp,
            "summary_sha256": summary_sha256,
            "candidates_sha256": candidates_sha256,
            "candidate_count": len(normalized_candidates),
        }

    def run_publication_snapshot(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM run_publication_snapshots WHERE run_id=?",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            summary = json.loads(result["summary_json"])
            candidates = json.loads(result["candidates_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PublicationConflictError(
                "run publication snapshot JSON is corrupted"
            ) from exc
        (
            normalized_summary,
            normalized_candidates,
            summary_sha256,
            candidates_sha256,
        ) = self._validated_publication_snapshot_payloads(summary, candidates)
        if (
            summary_sha256 != str(result["summary_sha256"])
            or candidates_sha256 != str(result["candidates_sha256"])
            or len(normalized_candidates) != int(result["candidate_count"])
        ):
            raise PublicationConflictError(
                "run publication snapshot integrity check failed"
            )
        result["summary"] = normalized_summary
        result["candidates"] = normalized_candidates
        return result

    def pause_or_complete_run(
        self,
        run_id: str,
        *,
        paused: bool,
        error: str | None = None,
        lease_token: str | None = None,
        status_override: str | None = None,
    ) -> None:
        status = status_override or (
            "paused" if paused else ("failed" if error else "completed")
        )
        with self.transaction() as connection:
            if paused and lease_token is not None:
                self._require_run_lease(connection, run_id, lease_token)
                now = utc_now()
                connection.execute(
                    """
                    UPDATE query_jobs
                    SET status='pending',
                        attempts=CASE
                            WHEN status='running' THEN MAX(attempts-1, 0)
                            ELSE attempts
                        END,
                        error='run paused; query is resumable',
                        not_before=NULL, claim_lease_token=NULL, updated_at=?
                    WHERE run_id=?
                      AND (status='running' OR claim_lease_token IS NOT NULL)
                    """,
                    (now, run_id),
                )
                connection.execute(
                    """
                    UPDATE analysis_tasks
                    SET status='retry',
                        attempts=CASE
                            WHEN status='running' THEN MAX(attempts-1, 0)
                            ELSE attempts
                        END,
                        error='run paused; analysis is resumable',
                        claimed_run_id=NULL, claim_lease_token=NULL,
                        not_before=NULL, updated_at=?
                    WHERE status='running'
                      AND (claimed_run_id=? OR claim_lease_token=?)
                    """,
                    (now, run_id, lease_token),
                )
                connection.execute(
                    """
                    UPDATE analysis_tasks
                    SET claimed_run_id=NULL, claim_lease_token=NULL,
                        updated_at=?
                    WHERE status!='running'
                      AND (claimed_run_id=? OR claim_lease_token=?)
                    """,
                    (now, run_id, lease_token),
                )
                connection.execute(
                    """
                    UPDATE verification_tasks
                    SET status='retry',
                        attempts=CASE
                            WHEN status='running' THEN MAX(attempts-1, 0)
                            ELSE attempts
                        END,
                        error='run paused; verification is resumable',
                        not_before=NULL, claim_lease_token=NULL, updated_at=?
                    WHERE run_id=?
                      AND (status='running' OR claim_lease_token IS NOT NULL)
                    """,
                    (now, run_id),
                )
                connection.execute(
                    """
                    UPDATE works
                    SET state=CASE
                            WHEN state='content_running' THEN 'content_retry'
                            WHEN state='analysis_running' THEN 'analysis_pending'
                            ELSE state
                        END,
                        updated_at=?
                    WHERE id IN (
                        SELECT work_id
                        FROM work_scopes
                        WHERE (active_run_id=? OR active_lease_token=?)
                          AND state IN ('content_running','analysis_running')
                    )
                    """,
                    (now, run_id, lease_token),
                )
                connection.execute(
                    """
                    UPDATE work_scopes
                    SET state=CASE
                            WHEN state='content_running' THEN 'content_retry'
                            WHEN state='analysis_running' THEN 'analysis_pending'
                            ELSE state
                        END,
                        active_run_id=NULL, active_lease_token=NULL,
                        last_seen_at=?
                    WHERE active_run_id=? OR active_lease_token=?
                    """,
                    (now, run_id, lease_token),
                )
            if lease_token is None:
                connection.execute(
                    """
                    UPDATE runs
                    SET status=?, updated_at=?, ended_at=?, error=?,
                        owner_pid=NULL, lease_token=NULL, lease_expires_at=NULL
                    WHERE id=?
                    """,
                    (status, utc_now(), utc_now(), error, run_id),
                )
            else:
                cursor = connection.execute(
                    """
                    UPDATE runs
                    SET status=?, updated_at=?, ended_at=?, error=?,
                        owner_pid=NULL, lease_token=NULL, lease_expires_at=NULL
                    WHERE id=? AND lease_token=?
                    """,
                    (status, utc_now(), utc_now(), error, run_id, lease_token),
                )
                if cursor.rowcount != 1:
                    raise RunAlreadyActiveError("cannot finish a run after losing its lease")

    def dashboard_counts(
        self,
        config_hash: str | None = None,
        *,
        analysis_policy_hash: str | None = None,
    ) -> dict[str, int]:
        if config_hash is None:
            queries: dict[str, tuple[str, tuple[Any, ...]]] = {
                "raw_hits": ("SELECT COUNT(*) FROM run_hits", ()),
                "unique_works": ("SELECT COUNT(*) FROM works", ()),
                "admitted": (
                    """
                    SELECT COUNT(*) FROM works
                    WHERE state NOT IN ('rejected','verification_pending')
                    """,
                    (),
                ),
                "rejected": ("SELECT COUNT(*) FROM works WHERE state='rejected'", ()),
                "unverified": (
                    "SELECT COUNT(*) FROM works WHERE state='verification_pending'",
                    (),
                ),
                "deep_read": (
                    """
                    SELECT COUNT(DISTINCT a.work_id)
                    FROM analyses a
                    JOIN analysis_tasks task ON task.id=a.task_id
                    JOIN documents d ON d.id=task.document_id
                    JOIN works current_work ON current_work.id=a.work_id
                    WHERE a.deep_read_status='complete'
                      AND current_work.state='analyzed'
                      AND r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                      AND task.input_sha256=
                          COALESCE(d.text_sha256, d.content_sha256)
                    """,
                    (),
                ),
                "unavailable": (
                    "SELECT COUNT(DISTINCT work_id) FROM documents WHERE status='unavailable'",
                    (),
                ),
                "incomplete": (
                    "SELECT COUNT(DISTINCT work_id) FROM documents WHERE status='incomplete'",
                    (),
                ),
                "pending_content": (
                    """
                    SELECT COUNT(*) FROM works
                    WHERE state IN ('admitted','content_retry','content_running')
                    """,
                    (),
                ),
                "pending_analysis": (
                    """
                    SELECT COUNT(DISTINCT works.id)
                    FROM works
                    JOIN documents d ON d.work_id=works.id
                    WHERE works.state IN (
                        'content_ready','analysis_pending',
                        'analysis_running','analyzed'
                    )
                      AND r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                      AND NOT EXISTS (
                        SELECT 1
                        FROM analyses a
                        JOIN analysis_tasks task ON task.id=a.task_id
                        JOIN documents current_document
                          ON current_document.id=task.document_id
                        WHERE a.work_id=works.id
                          AND a.deep_read_status='complete'
                          AND r3_document_is_analysis_eligible(
                              current_document.content_kind,
                              current_document.status,
                              current_document.document_policy_hash,
                              current_document.coverage_json
                          )
                          AND task.input_sha256=COALESCE(
                              current_document.text_sha256,
                              current_document.content_sha256
                          )
                      )
                    """,
                    (),
                ),
                "analysis_failed": (
                    "SELECT COUNT(*) FROM works WHERE state='analysis_failed'",
                    (),
                ),
            }
        else:
            scoped = (config_hash,)
            analysis_scope = analysis_policy_hash or config_hash
            queries = {
                "raw_hits": (
                    """
                    SELECT COUNT(*) FROM run_hits rh
                    JOIN runs r ON r.id=rh.run_id
                    WHERE COALESCE(r.retrieval_hash, r.config_hash)=?
                    """,
                    scoped,
                ),
                "unique_works": (
                    "SELECT COUNT(*) FROM work_scopes WHERE config_hash=?",
                    scoped,
                ),
                "admitted": (
                    """
                    SELECT COUNT(*) FROM work_scopes
                    WHERE config_hash=?
                      AND state NOT IN ('rejected','verification_pending')
                    """,
                    scoped,
                ),
                "rejected": (
                    """
                    SELECT COUNT(*) FROM work_scopes
                    WHERE config_hash=? AND state='rejected'
                    """,
                    scoped,
                ),
                "unverified": (
                    """
                    SELECT COUNT(*) FROM work_scopes
                    WHERE config_hash=? AND state='verification_pending'
                    """,
                    scoped,
                ),
                "deep_read": (
                    """
                    SELECT COUNT(DISTINCT a.work_id)
                    FROM analyses a
                    JOIN analysis_tasks task ON task.id=a.task_id
                    JOIN documents d ON d.id=task.document_id
                    JOIN work_scopes ws ON ws.work_id=a.work_id
                    WHERE ws.config_hash=? AND a.config_hash=?
                      AND ws.state='analyzed'
                      AND a.deep_read_status='complete'
                      AND r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                      AND task.input_sha256=
                          COALESCE(d.text_sha256, d.content_sha256)
                    """,
                    (config_hash, analysis_scope),
                ),
                "available_deep_read": (
                    """
                    SELECT COUNT(DISTINCT a.work_id)
                    FROM analyses a
                    JOIN analysis_tasks task ON task.id=a.task_id
                    JOIN documents d ON d.id=task.document_id
                    JOIN work_scopes ws ON ws.work_id=a.work_id
                    WHERE ws.config_hash=?
                      AND ws.state IN (
                          'content_ready','analysis_pending',
                          'analysis_running','analysis_failed','analyzed'
                      )
                      AND a.deep_read_status='complete'
                      AND (
                          a.config_hash=?
                          OR (
                              COALESCE(a.config_hash, '')<>?
                              AND COALESCE(
                                  a.retrieval_hash,
                                  task.retrieval_hash
                              )=?
                          )
                      )
                      AND r3_document_is_analysis_eligible(
                          d.content_kind,
                          d.status,
                          d.document_policy_hash,
                          d.coverage_json
                      )
                      AND task.input_sha256=
                          COALESCE(d.text_sha256, d.content_sha256)
                    """,
                    (
                        config_hash,
                        analysis_scope,
                        analysis_scope,
                        config_hash,
                    ),
                ),
                "unavailable": (
                    """
                    SELECT COUNT(DISTINCT d.work_id)
                    FROM documents d
                    JOIN work_scopes ws ON ws.work_id=d.work_id
                    WHERE ws.config_hash=? AND d.status='unavailable'
                    """,
                    scoped,
                ),
                "incomplete": (
                    """
                    SELECT COUNT(DISTINCT d.work_id)
                    FROM documents d
                    JOIN work_scopes ws ON ws.work_id=d.work_id
                    WHERE ws.config_hash=? AND d.status='incomplete'
                    """,
                    scoped,
                ),
                "pending_content": (
                    """
                    SELECT COUNT(*) FROM work_scopes
                    WHERE config_hash=?
                      AND state IN ('admitted','content_retry','content_running')
                    """,
                    scoped,
                ),
                "pending_analysis": (
                    """
                    SELECT COUNT(*) FROM work_scopes ws
                    WHERE ws.config_hash=?
                      AND ws.state IN (
                          'content_ready','analysis_pending',
                          'analysis_running','analyzed'
                      )
                      AND EXISTS (
                        SELECT 1 FROM documents ready_document
                        WHERE ready_document.work_id=ws.work_id
                          AND r3_document_is_analysis_eligible(
                              ready_document.content_kind,
                              ready_document.status,
                              ready_document.document_policy_hash,
                              ready_document.coverage_json
                          )
                      )
                      AND NOT EXISTS (
                        SELECT 1
                        FROM analyses a
                        JOIN analysis_tasks task ON task.id=a.task_id
                        JOIN documents current_document
                          ON current_document.id=task.document_id
                        WHERE a.work_id=ws.work_id
                          AND a.config_hash=?
                          AND a.deep_read_status='complete'
                          AND r3_document_is_analysis_eligible(
                              current_document.content_kind,
                              current_document.status,
                              current_document.document_policy_hash,
                              current_document.coverage_json
                          )
                          AND task.input_sha256=COALESCE(
                              current_document.text_sha256,
                              current_document.content_sha256
                          )
                      )
                    """,
                    (config_hash, analysis_scope),
                ),
                "analysis_failed": (
                    """
                    SELECT COUNT(*) FROM work_scopes
                    WHERE config_hash=? AND state='analysis_failed'
                    """,
                    scoped,
                ),
            }
        with self._lock:
            result = {
                name: int(self._connection.execute(sql, params).fetchone()[0])
                for name, (sql, params) in queries.items()
            }
        result.setdefault("available_deep_read", result["deep_read"])
        return result

    def list_dashboard_works(
        self,
        *,
        config_hash: str,
        analysis_policy_hash: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        analysis_scope = analysis_policy_hash or config_hash
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                    w.id, w.kind, w.title, w.year, w.best_url,
                    ws.lane, ws.state, ws.admission_code,
                    content_document.status AS content_status,
                    content_document.coverage_json AS content_coverage_json,
                    (
                        SELECT GROUP_CONCAT(source)
                        FROM (
                            SELECT DISTINCT source_record.source AS source
                            FROM work_sources source_mapping
                            JOIN source_records source_record
                              ON source_record.id=source_mapping.source_record_id
                            WHERE source_mapping.work_id=w.id
                            ORDER BY source_record.source
                        ) AS source_list
                    ) AS retrieval_sources_csv,
                    a.id AS analysis_id,
                    a.provider, a.model, a.deep_read_status, a.tier, a.score,
                    a.config_hash AS analysis_policy_hash,
                    active_task.provider AS analysis_task_provider,
                    active_task.status AS analysis_task_status,
                    active_task.chunk_done AS analysis_chunk_done,
                    active_task.chunk_total AS analysis_chunk_total,
                    active_task.attempts AS analysis_attempts,
                    CASE WHEN a.id IS NOT NULL THEN (
                        SELECT rating FROM feedback f
                        WHERE f.work_id=w.id
                        ORDER BY f.id DESC LIMIT 1
                    ) END AS feedback_rating
                FROM work_scopes ws
                JOIN works w ON w.id=ws.work_id
                LEFT JOIN documents content_document ON content_document.id=(
                    SELECT candidate_document.id
                    FROM documents candidate_document
                    WHERE candidate_document.work_id=w.id
                    ORDER BY candidate_document.updated_at DESC, candidate_document.id DESC
                    LIMIT 1
                )
                LEFT JOIN analyses a ON a.id=(
                    SELECT candidate.id
                    FROM analyses candidate
                    JOIN analysis_tasks candidate_task
                      ON candidate_task.id=candidate.task_id
                    JOIN documents candidate_document
                      ON candidate_document.id=candidate_task.document_id
                    WHERE candidate.work_id=w.id
                      AND (
                          candidate.config_hash=?
                          OR (
                              COALESCE(candidate.config_hash, '')<>?
                              AND COALESCE(
                                  candidate.retrieval_hash,
                                  candidate_task.retrieval_hash
                              )=?
                          )
                      )
                      AND ws.state IN (
                          'content_ready','analysis_pending',
                          'analysis_running','analysis_failed','analyzed'
                      )
                      AND candidate.deep_read_status='complete'
                      AND r3_document_is_analysis_eligible(
                          candidate_document.content_kind,
                          candidate_document.status,
                          candidate_document.document_policy_hash,
                          candidate_document.coverage_json
                      )
                      AND candidate_task.input_sha256=COALESCE(
                          candidate_document.text_sha256,
                          candidate_document.content_sha256
                    )
                    ORDER BY
                      CASE WHEN candidate.config_hash=? THEN 0 ELSE 1 END,
                      CASE candidate.provider
                        WHEN 'codex_cli' THEN 0
                        WHEN 'llama_cpp' THEN 1
                        ELSE 2
                      END,
                      candidate.created_at DESC,
                      candidate.id DESC
                    LIMIT 1
                )
                LEFT JOIN analysis_tasks active_task ON active_task.id=(
                    SELECT candidate_task.id
                    FROM analysis_tasks candidate_task
                    JOIN documents candidate_document
                      ON candidate_document.id=candidate_task.document_id
                    WHERE candidate_task.work_id=w.id
                      AND candidate_task.config_hash=?
                      AND r3_document_is_analysis_eligible(
                          candidate_document.content_kind,
                          candidate_document.status,
                          candidate_document.document_policy_hash,
                          candidate_document.coverage_json
                      )
                      AND candidate_task.input_sha256=COALESCE(
                          candidate_document.text_sha256,
                          candidate_document.content_sha256
                      )
                    ORDER BY
                      CASE candidate_task.status
                        WHEN 'running' THEN 0
                        WHEN 'retry' THEN 1
                        WHEN 'pending' THEN 2
                        WHEN 'failed' THEN 3
                        WHEN 'completed' THEN 4
                        ELSE 5
                      END,
                      candidate_task.updated_at DESC,
                      candidate_task.id DESC
                    LIMIT 1
                )
                WHERE ws.config_hash=?
                ORDER BY
                    CASE a.tier WHEN 'must_read' THEN 0 WHEN 'important' THEN 1 ELSE 2 END,
                    COALESCE(a.score, -1) DESC,
                    w.id DESC
                LIMIT ? OFFSET ?
                """,
                (
                    analysis_scope,
                    analysis_scope,
                    config_hash,
                    analysis_scope,
                    analysis_scope,
                    config_hash,
                    max(1, min(limit, 500)),
                    max(0, offset),
                ),
            ).fetchall()
            works: list[dict[str, Any]] = []
            for row in rows:
                work = dict(row)
                raw_sources = str(work.pop("retrieval_sources_csv") or "")
                work["retrieval_sources"] = [
                    source
                    for source in raw_sources.split(",")
                    if source
                ]
                selected_policy = work.pop("analysis_policy_hash", None)
                work["analysis_policy_current"] = (
                    selected_policy == analysis_scope
                    if work.get("deep_read_status") == "complete"
                    else None
                )
                works.append(work)
            return works

    def dashboard_work_analysis(
        self,
        *,
        work_id: int,
        config_hash: str,
        analysis_policy_hash: str | None = None,
    ) -> dict[str, Any] | None:
        """Return one current-scope deep read without inflating list responses."""

        analysis_scope = analysis_policy_hash or config_hash
        with self._lock:
            row = self._connection.execute(
                """
                SELECT
                    a.id AS analysis_id, a.work_id, a.provider, a.model,
                    a.deep_read_status, a.tier, a.score, a.analysis_json,
                    a.config_hash AS analysis_policy_hash
                FROM analyses a
                JOIN analysis_tasks task ON task.id=a.task_id
                JOIN documents document ON document.id=task.document_id
                JOIN work_scopes scope
                  ON scope.work_id=a.work_id AND scope.config_hash=?
                WHERE a.work_id=?
                  AND (
                      a.config_hash=?
                      OR (
                          COALESCE(a.config_hash, '')<>?
                          AND COALESCE(a.retrieval_hash, task.retrieval_hash)=?
                      )
                  )
                  AND scope.state IN (
                      'content_ready','analysis_pending','analysis_running',
                      'analysis_failed','analyzed'
                  )
                  AND a.deep_read_status='complete'
                  AND r3_document_is_analysis_eligible(
                      document.content_kind,
                      document.status,
                      document.document_policy_hash,
                      document.coverage_json
                  )
                  AND task.input_sha256=COALESCE(
                      document.text_sha256, document.content_sha256
                  )
                ORDER BY
                  CASE WHEN a.config_hash=? THEN 0 ELSE 1 END,
                  CASE a.provider
                    WHEN 'codex_cli' THEN 0
                    WHEN 'llama_cpp' THEN 1
                    ELSE 2
                  END,
                  a.created_at DESC,
                  a.id DESC
                LIMIT 1
                """,
                (
                    config_hash,
                    int(work_id),
                    analysis_scope,
                    analysis_scope,
                    config_hash,
                    analysis_scope,
                ),
            ).fetchone()
            if row is None:
                return None
            result = dict(row)
            try:
                analysis = json.loads(str(result.pop("analysis_json")))
            except (TypeError, json.JSONDecodeError):
                return None
            if not isinstance(analysis, dict):
                return None
            result["analysis"] = analysis
            selected_policy = result.pop("analysis_policy_hash", None)
            result["analysis_policy_current"] = selected_policy == analysis_scope
            return result

    def dashboard_work_total(self, *, config_hash: str) -> int:
        with self._lock:
            return int(
                self._connection.execute(
                    """
                    SELECT COUNT(*) FROM work_scopes
                    WHERE config_hash=?
                    """,
                    (config_hash,),
                ).fetchone()[0]
            )

    def list_complete_analyses(
        self,
        *,
        config_hash: str,
        analysis_policy_hash: str | None = None,
    ) -> list[dict[str, Any]]:
        analysis_scope = analysis_policy_hash or config_hash
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                    w.id, a.id AS analysis_id,
                    w.kind, w.title, w.year, w.doi, w.arxiv_id,
                    w.github_full_name, w.best_url, w.metadata_json, ws.lane,
                    a.provider, a.model, a.tier, a.score, a.analysis_json,
                    a.coverage_json, a.created_at,
                    selected_task.input_sha256,
                    selected_task.document_id,
                    COALESCE(
                        a.provenance_status,
                        'legacy_or_unknown'
                    ) AS provenance_status
                FROM work_scopes ws
                JOIN works w ON w.id=ws.work_id
                JOIN analyses a ON a.id=(
                    SELECT candidate.id
                    FROM analyses candidate
                    JOIN analysis_tasks candidate_task
                      ON candidate_task.id=candidate.task_id
                    JOIN documents candidate_document
                      ON candidate_document.id=candidate_task.document_id
                    WHERE candidate.work_id=w.id
                      AND candidate.config_hash=?
                      AND candidate.deep_read_status='complete'
                      AND r3_document_is_analysis_eligible(
                          candidate_document.content_kind,
                          candidate_document.status,
                          candidate_document.document_policy_hash,
                          candidate_document.coverage_json
                      )
                      AND candidate_task.input_sha256=COALESCE(
                          candidate_document.text_sha256,
                          candidate_document.content_sha256
                      )
                    ORDER BY
                      CASE candidate.provider
                        WHEN 'codex_cli' THEN 0
                        WHEN 'llama_cpp' THEN 1
                        ELSE 2
                      END,
                      candidate.created_at DESC,
                      candidate.id DESC
                    LIMIT 1
                )
                JOIN analysis_tasks selected_task ON selected_task.id=a.task_id
                WHERE ws.config_hash=?
                  AND ws.state='analyzed'
                ORDER BY a.score DESC, w.id
                """,
                (analysis_scope, config_hash),
            ).fetchall()
            return [dict(row) for row in rows]

    def running_run(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM runs
                WHERE status='running'
                ORDER BY started_at DESC
                LIMIT 1
                """
            ).fetchone()
            return dict(row) if row else None

    def latest_run(self, config_hash: str | None = None) -> dict[str, Any] | None:
        with self._lock:
            if config_hash is None:
                row = self._connection.execute(
                    "SELECT * FROM runs ORDER BY started_at DESC LIMIT 1"
                ).fetchone()
            else:
                row = self._connection.execute(
                    """
                    SELECT * FROM runs
                    WHERE config_hash=?
                    ORDER BY started_at DESC LIMIT 1
                    """,
                    (config_hash,),
                ).fetchone()
            return dict(row) if row else None

    def latest_run_for_retrieval(
        self,
        retrieval_hash: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM runs
                WHERE COALESCE(retrieval_hash, config_hash)=?
                ORDER BY started_at DESC LIMIT 1
                """,
                (retrieval_hash,),
            ).fetchone()
            return dict(row) if row else None

    def run_record(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM runs WHERE id=?",
                (run_id,),
            ).fetchone()
            return dict(row) if row is not None else None

    def latest_report_issue(
        self,
        *,
        retrieval_hash: str,
        analysis_policy_hash: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM report_issues
                WHERE retrieval_hash=? AND analysis_policy_hash=?
                  AND run_id IS NOT NULL
                ORDER BY generated_at DESC, issue_id DESC
                LIMIT 1
                """,
                (retrieval_hash, analysis_policy_hash),
            ).fetchone()
            return dict(row) if row is not None else None

    def latest_report_issue_for_retrieval(
        self,
        retrieval_hash: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM report_issues
                WHERE retrieval_hash=? AND run_id IS NOT NULL
                ORDER BY generated_at DESC, issue_id DESC
                LIMIT 1
                """,
                (retrieval_hash,),
            ).fetchone()
            return dict(row) if row is not None else None

    def report_issue_in_retrieval(
        self,
        *,
        issue_id: str,
        retrieval_hash: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM report_issues
                WHERE issue_id=? AND retrieval_hash=? AND run_id IS NOT NULL
                """,
                (issue_id, retrieval_hash),
            ).fetchone()
            return dict(row) if row is not None else None

    def report_issue_for_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM report_issues WHERE run_id=?",
                (run_id,),
            ).fetchone()
            return dict(row) if row is not None else None

    def _validated_report_issue(
        self,
        row: dict[str, Any],
    ) -> dict[str, Any]:
        decoded = dict(row)
        values: dict[str, dict[str, Any]] = {}
        for key in ("counts_json", "payload_json"):
            raw = decoded.pop(key, None)
            try:
                value = json.loads(raw) if isinstance(raw, str) else None
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PublicationConflictError(
                    f"published {key} is corrupted"
                ) from exc
            if not isinstance(value, dict):
                raise PublicationConflictError(
                    f"published {key} must be a JSON object"
                )
            values[key.removesuffix("_json")] = value
        payload = values["payload"]
        counts = values["counts"]
        expected_payload_sha256 = decoded.get("payload_sha256")
        if (
            not isinstance(expected_payload_sha256, str)
            or sha256_text(canonical_json(payload)) != expected_payload_sha256
        ):
            raise PublicationConflictError(
                "published payload integrity check failed"
            )
        if payload.get("counts") != counts:
            raise PublicationConflictError(
                "published counts do not match the frozen payload"
            )
        issue_id = str(decoded["issue_id"])
        publication = payload.get("publication")
        if (
            payload.get("issue_id") != issue_id
            or not isinstance(publication, dict)
            or publication.get("run_id") != decoded.get("run_id")
            or publication.get("terminal_status")
            != decoded.get("terminal_status")
        ):
            raise PublicationConflictError(
                "published payload identity does not match its database row"
            )
        with self._lock:
            item_rows = self._connection.execute(
                """
                SELECT analysis_id, work_id, selected, input_sha256,
                       snapshot_sha256, snapshot_json
                FROM report_issue_items
                WHERE issue_id=?
                ORDER BY analysis_id
                """,
                (issue_id,),
            ).fetchall()
        for item_row in item_rows:
            try:
                snapshot = json.loads(item_row["snapshot_json"])
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PublicationConflictError(
                    "published item snapshot JSON is corrupted"
                ) from exc
            try:
                item_is_valid = bool(
                    isinstance(snapshot, dict)
                    and sha256_text(canonical_json(snapshot))
                    == str(item_row["snapshot_sha256"])
                    and int(snapshot.get("analysis_id", -1))
                    == int(item_row["analysis_id"])
                    and int(snapshot.get("work_id", -1))
                    == int(item_row["work_id"])
                    and str(snapshot.get("input_sha256"))
                    == str(item_row["input_sha256"])
                )
            except (TypeError, ValueError):
                item_is_valid = False
            if not item_is_valid:
                raise PublicationConflictError(
                    "published item snapshot integrity check failed"
                )
        expected_count = counts.get("new_or_updated")
        if (
            not isinstance(expected_count, int)
            or expected_count != len(item_rows)
        ):
            raise PublicationConflictError(
                "published item count does not match the frozen payload"
            )
        decoded.update(values)
        return decoded

    def validated_report_issue_for_run(
        self,
        run_id: str,
    ) -> dict[str, Any] | None:
        row = self.report_issue_for_run(run_id)
        if row is None:
            return None
        result = self._validated_report_issue(row)
        result["local_outbox"] = self.publication_outbox_for_issue(
            str(result["issue_id"])
        )
        return result

    def latest_publication(
        self,
        *,
        retrieval_hash: str,
        analysis_policy_hash: str,
    ) -> dict[str, Any] | None:
        row = self.latest_report_issue(
            retrieval_hash=retrieval_hash,
            analysis_policy_hash=analysis_policy_hash,
        )
        if row is None:
            return None
        result = self._validated_report_issue(row)
        result["local_outbox"] = self.publication_outbox_for_issue(
            str(result["issue_id"])
        )
        return result

    def latest_publication_for_retrieval(
        self,
        retrieval_hash: str,
    ) -> dict[str, Any] | None:
        row = self.latest_report_issue_for_retrieval(retrieval_hash)
        if row is None:
            return None
        result = self._validated_report_issue(row)
        result["local_outbox"] = self.publication_outbox_for_issue(
            str(result["issue_id"])
        )
        return result

    def _publication_for_issue(
        self,
        *,
        issue_id: str | None,
        retrieval_hash: str,
        analysis_policy_hash: str,
    ) -> dict[str, Any] | None:
        if issue_id is None:
            return self.latest_publication(
                retrieval_hash=retrieval_hash,
                analysis_policy_hash=analysis_policy_hash,
            )
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM report_issues
                WHERE issue_id=? AND retrieval_hash=?
                  AND analysis_policy_hash=? AND run_id IS NOT NULL
                """,
                (issue_id, retrieval_hash, analysis_policy_hash),
            ).fetchone()
        if row is None:
            return None
        result = self._validated_report_issue(dict(row))
        result["local_outbox"] = self.publication_outbox_for_issue(
            str(result["issue_id"])
        )
        return result

    @staticmethod
    def _decision_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return {
            "action": str(row["action"]),
            "reason": row["reason"],
            "note": row["note"],
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def frozen_issue_item(
        self,
        *,
        issue_id: str,
        analysis_id: int,
        retrieval_hash: str,
        analysis_policy_hash: str,
        require_selected: bool = True,
    ) -> dict[str, Any]:
        publication = self._publication_for_issue(
            issue_id=issue_id,
            retrieval_hash=retrieval_hash,
            analysis_policy_hash=analysis_policy_hash,
        )
        if publication is None:
            raise DecisionNotAllowedError(
                "decision requires a publication in the active scope"
            )
        with self._lock:
            row = self._connection.execute(
                """
                SELECT item.*, decision.action, decision.reason, decision.note,
                       decision.created_at AS decision_created_at,
                       decision.updated_at AS decision_updated_at
                FROM report_issue_items item
                LEFT JOIN research_decisions decision
                  ON decision.issue_id=item.issue_id
                 AND decision.analysis_id=item.analysis_id
                WHERE item.issue_id=? AND item.analysis_id=?
                """,
                (issue_id, analysis_id),
            ).fetchone()
        if row is None or (require_selected and not bool(row["selected"])):
            raise DecisionNotAllowedError(
                "decision requires a selected frozen publication item"
            )
        try:
            snapshot = json.loads(row["snapshot_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PublicationConflictError(
                "frozen decision item JSON is corrupted"
            ) from exc
        if (
            not isinstance(snapshot, dict)
            or sha256_text(canonical_json(snapshot))
            != str(row["snapshot_sha256"])
        ):
            raise PublicationConflictError(
                "frozen decision item integrity check failed"
            )
        decision_row = None
        if row["action"] is not None:
            decision_row = {
                "action": row["action"],
                "reason": row["reason"],
                "note": row["note"],
                "created_at": row["decision_created_at"],
                "updated_at": row["decision_updated_at"],
            }
        return {
            "issue_id": issue_id,
            "analysis_id": int(row["analysis_id"]),
            "work_id": int(row["work_id"]),
            "input_sha256": str(row["input_sha256"]),
            "snapshot_sha256": str(row["snapshot_sha256"]),
            "selection_bucket": str(row["selection_bucket"]),
            "selected": bool(row["selected"]),
            "snapshot": snapshot,
            "citation": dict(snapshot.get("citation") or {}),
            "analysis": dict(snapshot.get("analysis") or {}),
            "coverage": dict(snapshot.get("coverage") or {}),
            "provider": snapshot.get("provider"),
            "model": snapshot.get("model"),
            "tier": snapshot.get("tier"),
            "score": snapshot.get("score"),
            "lane": snapshot.get("lane"),
            "provenance_status": snapshot.get("provenance_status"),
            "decision": (
                {
                    "action": str(decision_row["action"]),
                    "reason": decision_row["reason"],
                    "note": decision_row["note"],
                    "created_at": str(decision_row["created_at"]),
                    "updated_at": str(decision_row["updated_at"]),
                }
                if decision_row is not None
                else None
            ),
        }

    def decision_slice(
        self,
        *,
        retrieval_hash: str,
        analysis_policy_hash: str,
        issue_id: str | None = None,
        pending_limit: int | None = None,
    ) -> dict[str, Any] | None:
        latest_publication = self._publication_for_issue(
            issue_id=issue_id,
            retrieval_hash=retrieval_hash,
            analysis_policy_hash=analysis_policy_hash,
        )
        if latest_publication is None:
            return None

        def ordered_analysis_ids(candidate: dict[str, Any]) -> list[int]:
            payload = candidate["payload"]
            result: list[int] = []
            for bucket in ("must_read", "important", "background"):
                for item in payload.get(bucket) or []:
                    if not isinstance(item, dict) or "analysis_id" not in item:
                        raise PublicationConflictError(
                            "published decision order is corrupted"
                        )
                    result.append(int(item["analysis_id"]))
            if result:
                return result
            with self._lock:
                rows = self._connection.execute(
                    """
                    SELECT analysis_id
                    FROM report_issue_items
                    WHERE issue_id=? AND selected=1
                    ORDER BY
                        CASE selection_bucket
                            WHEN 'must_read' THEN 0
                            WHEN 'important' THEN 1
                            ELSE 2
                        END,
                        analysis_id
                    """,
                    (str(candidate["issue_id"]),),
                ).fetchall()
            return [int(row["analysis_id"]) for row in rows]

        publication = latest_publication
        ordered_ids = ordered_analysis_ids(publication)
        carried_forward = False
        if issue_id is None and not ordered_ids:
            visited = {str(publication["issue_id"])}
            previous_issue_id = publication.get("previous_issue_id")
            while previous_issue_id:
                normalized_issue_id = str(previous_issue_id)
                if normalized_issue_id in visited:
                    raise PublicationConflictError(
                        "published issue chain contains a cycle"
                    )
                visited.add(normalized_issue_id)
                previous = self._publication_for_issue(
                    issue_id=normalized_issue_id,
                    retrieval_hash=retrieval_hash,
                    analysis_policy_hash=analysis_policy_hash,
                )
                if previous is None:
                    raise PublicationConflictError(
                        "published issue chain is broken"
                    )
                previous_ids = ordered_analysis_ids(previous)
                if previous_ids:
                    publication = previous
                    ordered_ids = previous_ids
                    carried_forward = True
                    break
                previous_issue_id = previous.get("previous_issue_id")

        remaining_count = 0
        returned_ids = ordered_ids
        if pending_limit is not None:
            normalized_limit = max(1, min(int(pending_limit), 100))
            with self._lock:
                decided_rows = self._connection.execute(
                    """
                    SELECT analysis_id
                    FROM research_decisions
                    WHERE issue_id=?
                    """,
                    (str(publication["issue_id"]),),
                ).fetchall()
            decided_ids = {int(row["analysis_id"]) for row in decided_rows}
            pending_ids = [
                analysis_id
                for analysis_id in ordered_ids
                if analysis_id not in decided_ids
            ]
            returned_ids = pending_ids[:normalized_limit]
            remaining_count = max(0, len(pending_ids) - len(returned_ids))
        items = [
            self.frozen_issue_item(
                issue_id=str(publication["issue_id"]),
                analysis_id=analysis_id,
                retrieval_hash=retrieval_hash,
                analysis_policy_hash=analysis_policy_hash,
            )
            for analysis_id in returned_ids
        ]
        return {
            "issue": {
                "issue_id": str(publication["issue_id"]),
                "run_id": str(publication["run_id"]),
                "generated_at": str(publication["generated_at"]),
                "payload_sha256": str(publication["payload_sha256"]),
                "counts": dict(publication["counts"]),
                "living_diff": dict(
                    publication["payload"].get("living_diff") or {}
                ),
                "local_outbox": (
                    {
                        key: publication["local_outbox"].get(key)
                        for key in (
                            "delivery_mode",
                            "state",
                            "digest_sha256",
                            "digest_path",
                        )
                    }
                    if isinstance(publication.get("local_outbox"), dict)
                    else None
                ),
            },
            "latest_issue": {
                "issue_id": str(latest_publication["issue_id"]),
                "run_id": str(latest_publication["run_id"]),
                "generated_at": str(latest_publication["generated_at"]),
                "payload_sha256": str(latest_publication["payload_sha256"]),
                "counts": dict(latest_publication["counts"]),
                "living_diff": dict(
                    latest_publication["payload"].get("living_diff") or {}
                ),
                "local_outbox": (
                    {
                        key: latest_publication["local_outbox"].get(key)
                        for key in (
                            "delivery_mode",
                            "state",
                            "digest_sha256",
                            "digest_path",
                        )
                    }
                    if isinstance(latest_publication.get("local_outbox"), dict)
                    else None
                ),
            },
            "carried_forward": carried_forward,
            "items": items,
            "remaining_count": remaining_count,
        }

    def save_research_decision(
        self,
        *,
        issue_id: str,
        analysis_id: int,
        action: str,
        reason: str | None,
        note: str | None,
        retrieval_hash: str,
        analysis_policy_hash: str,
    ) -> dict[str, Any]:
        allowed_actions = {
            "save",
            "defer",
            "reject",
            "request_deep_read",
        }
        normalized_action = action.strip()
        if normalized_action not in allowed_actions:
            raise ValueError("unsupported research decision action")
        normalized_reason = reason.strip() if isinstance(reason, str) else None
        normalized_note = note.strip() if isinstance(note, str) else None
        if normalized_reason == "":
            normalized_reason = None
        if normalized_note == "":
            normalized_note = None
        if normalized_action != "save" and not normalized_reason:
            raise ValueError(
                "defer, reject and request_deep_read require a reason"
            )
        if normalized_reason and len(normalized_reason) > 2000:
            raise ValueError("research decision reason is too long")
        if normalized_note and len(normalized_note) > 8000:
            raise ValueError("research decision note is too long")
        item = self.frozen_issue_item(
            issue_id=issue_id,
            analysis_id=analysis_id,
            retrieval_hash=retrieval_hash,
            analysis_policy_hash=analysis_policy_hash,
        )
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO research_decisions(
                    issue_id, analysis_id, work_id,
                    input_sha256, snapshot_sha256,
                    action, reason, note, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(issue_id, analysis_id) DO UPDATE SET
                    action=excluded.action,
                    reason=excluded.reason,
                    note=excluded.note,
                    updated_at=excluded.updated_at
                """,
                (
                    issue_id,
                    analysis_id,
                    int(item["work_id"]),
                    str(item["input_sha256"]),
                    str(item["snapshot_sha256"]),
                    normalized_action,
                    normalized_reason,
                    normalized_note,
                    timestamp,
                    timestamp,
                ),
            )
        saved = self.frozen_issue_item(
            issue_id=issue_id,
            analysis_id=analysis_id,
            retrieval_hash=retrieval_hash,
            analysis_policy_hash=analysis_policy_hash,
        )
        return dict(saved["decision"])

    def frozen_item_text_source(
        self,
        *,
        issue_id: str,
        analysis_id: int,
        retrieval_hash: str,
        analysis_policy_hash: str,
    ) -> dict[str, Any]:
        item = self.frozen_issue_item(
            issue_id=issue_id,
            analysis_id=analysis_id,
            retrieval_hash=retrieval_hash,
            analysis_policy_hash=analysis_policy_hash,
        )
        snapshot = item["snapshot"]
        document_id = snapshot.get("document_id")
        if isinstance(document_id, bool) or not isinstance(document_id, int):
            raise PublicationConflictError(
                "frozen item has no valid document identity"
            )
        with self._lock:
            document = self._connection.execute(
                """
                SELECT id, text_path,
                       COALESCE(text_sha256, content_sha256) AS input_sha256
                FROM documents WHERE id=?
                """,
                (document_id,),
            ).fetchone()
        if (
            document is None
            or str(document["input_sha256"]) != str(item["input_sha256"])
            or not document["text_path"]
        ):
            raise PublicationConflictError(
                "same-revision source text is unavailable"
            )
        return {
            "item": item,
            "document_id": document_id,
            "input_sha256": str(item["input_sha256"]),
            "text_path": str(document["text_path"]),
        }

    def require_publishable_run(self, run_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM runs WHERE id=?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise PublicationNotAllowedError(f"run {run_id} does not exist")
            run = dict(row)
        if run["status"] not in {"completed", "completed_with_gaps"}:
            raise PublicationNotAllowedError(
                f"run {run_id} is not terminal-publishable: {run['status']}"
            )
        if not run.get("ended_at"):
            raise PublicationNotAllowedError(
                f"run {run_id} has no terminal ended_at"
            )
        if run.get("lease_token") is not None:
            raise PublicationNotAllowedError(
                f"run {run_id} still owns an active lease"
            )
        return run

    def published_analysis_ids(
        self,
        *,
        exclude_issue_id: str | None = None,
    ) -> set[int]:
        with self._lock:
            if exclude_issue_id is None:
                rows = self._connection.execute(
                    """
                    SELECT DISTINCT item.analysis_id
                    FROM report_issue_items item
                    """
                ).fetchall()
            else:
                rows = self._connection.execute(
                    """
                    SELECT DISTINCT item.analysis_id
                    FROM report_issue_items item
                    WHERE item.issue_id<>?
                    """,
                    (exclude_issue_id,),
                ).fetchall()
            return {int(row["analysis_id"]) for row in rows}

    def latest_published_snapshots_by_work(
        self,
        *,
        retrieval_hash: str,
        analysis_policy_hash: str,
    ) -> dict[int, dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT item.work_id, item.issue_id, item.analysis_id,
                       item.input_sha256, item.snapshot_sha256,
                       item.snapshot_json, issue.generated_at
                FROM report_issue_items item
                JOIN report_issues issue ON issue.issue_id=item.issue_id
                WHERE issue.retrieval_hash=? AND issue.analysis_policy_hash=?
                ORDER BY issue.generated_at DESC, issue.issue_id DESC,
                         item.analysis_id DESC
                """,
                (retrieval_hash, analysis_policy_hash),
            ).fetchall()
        result: dict[int, dict[str, Any]] = {}
        for row in rows:
            work_id = int(row["work_id"])
            if work_id in result:
                continue
            try:
                snapshot = json.loads(row["snapshot_json"])
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise PublicationConflictError(
                    "published history snapshot JSON is corrupted"
                ) from exc
            if (
                not isinstance(snapshot, dict)
                or sha256_text(canonical_json(snapshot))
                != str(row["snapshot_sha256"])
                or int(snapshot.get("work_id", -1)) != work_id
            ):
                raise PublicationConflictError(
                    "published history snapshot integrity check failed"
                )
            result[work_id] = {
                "issue_id": str(row["issue_id"]),
                "analysis_id": int(row["analysis_id"]),
                "input_sha256": str(row["input_sha256"]),
                "snapshot_sha256": str(row["snapshot_sha256"]),
                "snapshot": snapshot,
            }
        return result

    def publication_outbox_for_issue(
        self,
        issue_id: str,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM publication_outbox WHERE issue_id=?",
                (issue_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        try:
            digest = json.loads(result.pop("digest_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PublicationConflictError(
                "local publication digest JSON is corrupted"
            ) from exc
        if (
            not isinstance(digest, dict)
            or digest.get("issue_id") != issue_id
            or digest.get("delivery_mode") != "local_only"
            or sha256_text(canonical_json(digest))
            != str(result["digest_sha256"])
        ):
            raise PublicationConflictError(
                "local publication digest integrity check failed"
            )
        result["digest"] = digest
        return result

    def paper_repository_relation_inputs(
        self,
        *,
        paper_work_id: int,
        repository_work_id: int,
        retrieval_hash: str,
    ) -> dict[str, Any]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT w.id, w.kind, w.title, w.best_url, w.github_full_name,
                       w.metadata_json, d.source_url, d.content_sha256,
                       COALESCE(d.text_sha256, d.content_sha256) AS input_sha256,
                       d.text_path, d.coverage_json
                FROM works w
                JOIN work_scopes scope
                  ON scope.work_id=w.id AND scope.config_hash=?
                JOIN documents d ON d.work_id=w.id
                WHERE w.id IN (?, ?) AND d.status='ready'
                ORDER BY w.id
                """,
                (retrieval_hash, paper_work_id, repository_work_id),
            ).fetchall()
        by_id = {int(row["id"]): dict(row) for row in rows}
        if set(by_id) != {paper_work_id, repository_work_id}:
            raise ValueError(
                "paper and repository must both have ready content in the active scope"
            )
        paper = by_id[paper_work_id]
        repository = by_id[repository_work_id]
        if paper["kind"] != "paper" or repository["kind"] != "repository":
            raise ValueError("relation endpoints must be one paper and one repository")
        try:
            paper["metadata"] = json.loads(paper.pop("metadata_json"))
            repository["metadata"] = json.loads(repository.pop("metadata_json"))
            paper["coverage"] = json.loads(paper.pop("coverage_json"))
            repository["coverage"] = json.loads(repository.pop("coverage_json"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("relation endpoint metadata is corrupted") from exc
        return {"paper": paper, "repository": repository}

    def record_paper_repository_relation(
        self,
        relation: dict[str, Any],
    ) -> dict[str, Any]:
        if relation.get("schema") != "r3/paper-repository-relation/v1":
            raise ValueError("paper-repository relation schema is unsupported")
        paper = relation.get("paper")
        repository = relation.get("repository")
        revision = relation.get("repository_revision")
        if not all(isinstance(value, dict) for value in (paper, repository, revision)):
            raise ValueError("paper-repository relation is incomplete")
        paper_id = int(paper["work_id"])
        repository_id = int(repository["work_id"])
        commit_sha = str(revision.get("commit_sha") or "")
        if (
            paper_id <= 0
            or repository_id <= 0
            or len(commit_sha) != 40
            or any(character not in "0123456789abcdef" for character in commit_sha)
        ):
            raise ValueError("paper-repository relation identity is invalid")
        relation_sha256 = sha256_text(canonical_json(relation))
        timestamp = utc_now()
        with self.transaction() as connection:
            existing = connection.execute(
                """
                SELECT * FROM paper_repository_relations
                WHERE paper_work_id=? AND repository_work_id=?
                """,
                (paper_id, repository_id),
            ).fetchone()
            if existing is not None:
                if str(existing["relation_sha256"]) != relation_sha256:
                    raise PublicationConflictError(
                        "paper-repository relation changed; refusing overwrite"
                    )
                return self.paper_repository_relation_for_work(paper_id) or {}
            connection.execute(
                """
                INSERT INTO paper_repository_relations(
                    paper_work_id, repository_work_id, commit_sha,
                    relation_sha256, relation_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    paper_id,
                    repository_id,
                    commit_sha,
                    relation_sha256,
                    json_dumps(relation),
                    timestamp,
                ),
            )
        return self.paper_repository_relation_for_work(paper_id) or {}

    def paper_repository_relation_for_work(
        self,
        work_id: int,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM paper_repository_relations
                WHERE paper_work_id=? OR repository_work_id=?
                ORDER BY created_at DESC, paper_work_id, repository_work_id
                LIMIT 1
                """,
                (work_id, work_id),
            ).fetchone()
        if row is None:
            return None
        try:
            relation = json.loads(row["relation_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PublicationConflictError(
                "paper-repository relation JSON is corrupted"
            ) from exc
        if (
            not isinstance(relation, dict)
            or sha256_text(canonical_json(relation))
            != str(row["relation_sha256"])
            or int(relation.get("paper", {}).get("work_id", -1))
            != int(row["paper_work_id"])
            or int(relation.get("repository", {}).get("work_id", -1))
            != int(row["repository_work_id"])
            or str(relation.get("repository_revision", {}).get("commit_sha"))
            != str(row["commit_sha"])
        ):
            raise PublicationConflictError(
                "paper-repository relation integrity check failed"
            )
        return {
            "relation_sha256": str(row["relation_sha256"]),
            "evidence": relation,
            "created_at": str(row["created_at"]),
        }

    def record_report_issue(
        self,
        *,
        issue_id: str,
        run_id: str,
        publication_key: str,
        retrieval_hash: str,
        analysis_policy_hash: str,
        previous_issue_id: str | None,
        terminal_status: str,
        output_dir: str,
        report_path: str,
        selection_path: str,
        counts: dict[str, Any],
        payload_sha256: str,
        payload: dict[str, Any],
        report_sha256: str,
        selection_sha256: str,
        run_summary_path: str,
        items: list[dict[str, Any]],
        outbox_digest: dict[str, Any],
        outbox_digest_sha256: str,
        outbox_digest_path: str,
    ) -> dict[str, Any]:
        run = self.require_publishable_run(run_id)
        generated_at = str(run["ended_at"])
        with self.transaction() as connection:
            existing = connection.execute(
                """
                SELECT * FROM report_issues
                WHERE run_id=? OR publication_key=?
                ORDER BY generated_at DESC, issue_id DESC
                LIMIT 1
                """,
                (run_id, publication_key),
            ).fetchone()
            if existing is not None:
                existing_row = dict(existing)
                if (
                    str(existing_row["run_id"]) != run_id
                    or str(existing_row["publication_key"]) != publication_key
                    or str(existing_row["issue_id"]) != issue_id
                    or str(existing_row["payload_sha256"]) != payload_sha256
                    or str(existing_row["report_sha256"]) != report_sha256
                    or str(existing_row["selection_sha256"]) != selection_sha256
                ):
                    raise PublicationConflictError(
                        "run-bound publication payload changed; refusing overwrite"
                    )
                existing_row["created"] = False
                return existing_row
            current = connection.execute(
                """
                SELECT issue_id FROM report_issues
                WHERE retrieval_hash=? AND analysis_policy_hash=?
                  AND run_id IS NOT NULL
                ORDER BY generated_at DESC, issue_id DESC
                LIMIT 1
                """,
                (retrieval_hash, analysis_policy_hash),
            ).fetchone()
            current_id = str(current["issue_id"]) if current is not None else None
            if current_id != previous_issue_id:
                raise RunAlreadyActiveError(
                    "another report issue was published concurrently"
                )
            analysis_ids = [int(item["analysis_id"]) for item in items]
            if analysis_ids:
                placeholders = ",".join("?" for _ in analysis_ids)
                already_published = connection.execute(
                    f"""
                    SELECT item.analysis_id
                    FROM report_issue_items item
                    WHERE item.analysis_id IN ({placeholders})
                    LIMIT 1
                    """,
                    analysis_ids,
                ).fetchone()
                if already_published is not None:
                    raise PublicationConflictError(
                        "an analysis in this issue was already published"
                    )
            connection.execute(
                """
                INSERT INTO report_issues(
                    issue_id, run_id, publication_key,
                    retrieval_hash, analysis_policy_hash,
                    previous_issue_id, terminal_status, generated_at,
                    output_dir, report_path, selection_path, counts_json,
                    payload_sha256, payload_json, report_sha256,
                    selection_sha256, run_summary_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    issue_id,
                    run_id,
                    publication_key,
                    retrieval_hash,
                    analysis_policy_hash,
                    previous_issue_id,
                    terminal_status,
                    generated_at,
                    output_dir,
                    report_path,
                    selection_path,
                    json_dumps(counts),
                    payload_sha256,
                    json_dumps(payload),
                    report_sha256,
                    selection_sha256,
                    run_summary_path,
                ),
            )
            connection.executemany(
                """
                INSERT INTO report_issue_items(
                    issue_id, analysis_id, work_id,
                    selection_bucket, selected, input_sha256,
                    snapshot_sha256, snapshot_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        issue_id,
                        int(item["analysis_id"]),
                        int(item["work_id"]),
                        str(item["selection_bucket"]),
                        1 if item["selected"] else 0,
                        str(item["input_sha256"]),
                        str(item["snapshot_sha256"]),
                        json_dumps(item["snapshot"]),
                    )
                    for item in items
                ],
            )
            if (
                outbox_digest.get("issue_id") != issue_id
                or outbox_digest.get("delivery_mode") != "local_only"
                or sha256_text(canonical_json(outbox_digest))
                != outbox_digest_sha256
            ):
                raise PublicationConflictError(
                    "local publication digest does not match its issue"
                )
            connection.execute(
                """
                INSERT INTO publication_outbox(
                    issue_id, delivery_mode, state, digest_sha256,
                    digest_json, digest_path, created_at
                ) VALUES (?, 'local_only', 'ready', ?, ?, ?, ?)
                """,
                (
                    issue_id,
                    outbox_digest_sha256,
                    json_dumps(outbox_digest),
                    outbox_digest_path,
                    generated_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM report_issues WHERE issue_id=?",
                (issue_id,),
            ).fetchone()
            result = dict(row)
            result["created"] = True
            return result

    def remove_report_issue_if_payload(
        self,
        *,
        issue_id: str,
        payload_sha256: str,
    ) -> bool:
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                DELETE FROM report_issues
                WHERE issue_id=? AND payload_sha256=?
                """,
                (issue_id, payload_sha256),
            )
            return cursor.rowcount == 1

    def repair_analysis_scores(self) -> int:
        from .ranking import normalize_and_rank

        repaired = 0
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT id, analysis_json FROM analyses ORDER BY id"
            ).fetchall()
            for row in rows:
                analysis = json.loads(row["analysis_json"])
                overall, tier, changed = normalize_and_rank(analysis)
                if not changed:
                    continue
                connection.execute(
                    """
                    UPDATE analyses
                    SET score=?, tier=?, analysis_json=?
                    WHERE id=?
                    """,
                    (overall, tier, json_dumps(analysis), row["id"]),
                )
                repaired += 1
        return repaired

    def requeue_run_failures(self, run_id: str) -> dict[str, int]:
        timestamp = utc_now()
        with self.transaction() as connection:
            run = connection.execute(
                "SELECT status FROM runs WHERE id=?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise ValueError(f"run {run_id} does not exist")
            if run["status"] == "running":
                raise ValueError(
                    f"run {run_id} is still running; refusing maintenance requeue"
                )
            query_cursor = connection.execute(
                """
                UPDATE query_jobs
                SET status='pending', attempts=0, error=NULL, not_before=NULL,
                    claim_lease_token=NULL, updated_at=?
                WHERE run_id=? AND status IN ('failed','blocked')
                """,
                (timestamp, run_id),
            )
            verification_cursor = connection.execute(
                """
                UPDATE verification_tasks
                SET status='pending', attempts=0, error=NULL, not_before=NULL,
                    claim_lease_token=NULL, updated_at=?, completed_at=NULL
                WHERE run_id=? AND status IN ('retry','failed')
                """,
                (timestamp, run_id),
            )
            return {
                "query_jobs": max(0, int(query_cursor.rowcount)),
                "verification_tasks": max(
                    0,
                    int(verification_cursor.rowcount),
                ),
            }

    def requeue_content(self, work_id: int, *, retrieval_hash: str) -> None:
        timestamp = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT state FROM work_scopes
                WHERE work_id=? AND config_hash=?
                """,
                (work_id, retrieval_hash),
            ).fetchone()
            if row is None:
                raise ValueError(f"work {work_id} is not in the current retrieval scope")
            if row["state"] not in {
                "content_unavailable",
                "content_incomplete",
                "content_retry",
            }:
                raise ValueError(
                    f"work {work_id} is not unavailable or incomplete (state={row['state']})"
                )
            connection.execute(
                "UPDATE works SET state='content_retry', updated_at=? WHERE id=?",
                (timestamp, work_id),
            )
            connection.execute(
                """
                UPDATE work_scopes
                SET state='content_retry', active_run_id=NULL,
                    active_lease_token=NULL, last_seen_at=?
                WHERE work_id=? AND config_hash=?
                """,
                (timestamp, work_id, retrieval_hash),
            )
            connection.execute(
                """
                UPDATE documents SET status='retry', updated_at=?, error=NULL
                WHERE work_id=?
                """,
                (timestamp, work_id),
            )
            documents = connection.execute(
                "SELECT * FROM documents WHERE work_id=? ORDER BY id",
                (work_id,),
            ).fetchall()
            for document in documents:
                self._append_document_processing_observation(
                    connection,
                    document,
                    event_type="content_requeued",
                    observed_at=timestamp,
                )

    def requeue_analysis(
        self,
        work_id: int,
        *,
        analysis_policy_hash: str,
        provider: str | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT
                    task.id, task.provider, task.error,
                    task.config_hash
                FROM analysis_tasks task
                JOIN documents d ON d.id=task.document_id
                WHERE task.work_id=?
                  AND task.config_hash=?
                  AND task.status='failed'
                  AND r3_document_is_analysis_eligible(
                      d.content_kind,
                      d.status,
                      d.document_policy_hash,
                      d.coverage_json
                  )
                  AND task.input_sha256=COALESCE(d.text_sha256, d.content_sha256)
                  AND EXISTS (
                    SELECT 1
                    FROM work_scopes scope
                    JOIN profile_snapshots snapshot
                      ON COALESCE(
                             snapshot.retrieval_hash,
                             snapshot.config_hash
                         )=scope.config_hash
                    WHERE scope.work_id=task.work_id
                      AND scope.state IN (
                          'analysis_failed','content_ready','analysis_pending'
                      )
                      AND COALESCE(
                              snapshot.analysis_policy_hash,
                              snapshot.config_hash
                          )=task.config_hash
                  )
                  AND (? IS NULL OR task.provider=?)
                ORDER BY task.updated_at DESC, task.id DESC
                LIMIT 1
                """,
                (
                    work_id,
                    analysis_policy_hash,
                    provider,
                    provider,
                ),
            ).fetchone()
            if row is None:
                raise ValueError(
                    f"work {work_id} has no failed current analysis task in this policy scope"
                )
            previous_error = row["error"]
            cursor = connection.execute(
                """
                UPDATE analysis_tasks
                SET status='pending', attempts=0, error=NULL, not_before=NULL,
                    claimed_run_id=NULL, claim_lease_token=NULL,
                    started_at=NULL, completed_at=NULL, updated_at=?
                WHERE id=? AND status='failed'
                """,
                (timestamp, row["id"]),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("analysis task changed while it was being requeued")
            connection.execute(
                "UPDATE works SET state='analysis_pending', updated_at=? WHERE id=?",
                (timestamp, work_id),
            )
            connection.execute(
                """
                UPDATE work_scopes AS scope
                SET state='analysis_pending', last_error=NULL,
                    active_run_id=NULL, active_lease_token=NULL,
                    last_seen_at=?
                WHERE scope.work_id=?
                  AND scope.state IN (
                      'analysis_failed','content_ready','analysis_pending'
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM profile_snapshots snapshot
                    WHERE COALESCE(
                              snapshot.retrieval_hash,
                              snapshot.config_hash
                          )=scope.config_hash
                      AND COALESCE(
                              snapshot.analysis_policy_hash,
                              snapshot.config_hash
                          )=?
                  )
                """,
                (timestamp, work_id, row["config_hash"]),
            )
            return {
                "task_id": int(row["id"]),
                "work_id": work_id,
                "provider": str(row["provider"]),
                "previous_error": previous_error,
            }

    def quarantine_unverified_hosted_discoveries(self, *, retrieval_hash: str) -> int:
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE work_scopes AS scope
                SET state='verification_pending', admission_code='hosted_verification_pending',
                    active_run_id=NULL, active_lease_token=NULL, last_seen_at=?
                WHERE scope.config_hash=?
                  AND scope.state NOT IN ('rejected','verification_pending')
                  AND EXISTS (
                    SELECT 1 FROM work_sources ws
                    JOIN source_records sr ON sr.id=ws.source_record_id
                    WHERE ws.work_id=scope.work_id AND sr.source='codex_web'
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM work_sources ws
                    JOIN source_records sr ON sr.id=ws.source_record_id
                    WHERE ws.work_id=scope.work_id AND sr.source!='codex_web'
                  )
                """,
                (utc_now(), retrieval_hash),
            )
            return max(0, int(cursor.rowcount))

    def pending_job_counts(self, run_id: str) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT status, COUNT(*) AS count FROM query_jobs
                WHERE run_id=? GROUP BY status
                """,
                (run_id,),
            ).fetchall()
            return {str(row["status"]): int(row["count"]) for row in rows}

    def query_job_coverage(
        self,
        run_id: str,
        settings: Settings,
    ) -> dict[str, Any]:
        run = self.run_record(run_id)
        if run is None:
            raise ValueError("run does not exist")
        mode = str(run["mode"])
        base_mode = mode.split(":", 1)[0]
        analysis_only = mode.endswith(":analysis_only")
        hosted_only = mode.endswith(":hosted_supplement")
        no_hosted = mode.endswith(":no_hosted")
        smoke = base_mode == "smoke" or mode == "deterministic_demo"
        include_official = not analysis_only and not hosted_only
        include_hosted = (
            not analysis_only
            and not no_hosted
            and mode != "deterministic_demo"
        )
        expected = planned_query_job_specs(
            settings,
            include_hosted=include_hosted,
            smoke=smoke,
            include_official=include_official,
        )
        with self._lock:
            actual = [
                dict(row)
                for row in self._connection.execute(
                    """
                    SELECT query_id, source, job_kind, status
                    FROM query_jobs WHERE run_id=? ORDER BY id
                    """,
                    (run_id,),
                ).fetchall()
            ]
        key = lambda item: (
            str(item["query_id"]),
            str(item["source"]),
            str(item["job_kind"]),
        )
        expected_by_key = {key(item): item for item in expected}
        actual_by_key = {key(item): item for item in actual}
        missing_keys = sorted(set(expected_by_key) - set(actual_by_key))
        unexpected_keys = sorted(set(actual_by_key) - set(expected_by_key))
        by_status: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for item in actual:
            status = str(item["status"])
            source = str(item["source"])
            by_status[status] = by_status.get(status, 0) + 1
            by_source[source] = by_source.get(source, 0) + 1
        terminal_statuses = {"completed", "failed", "blocked"}
        terminal_jobs = sum(
            count for status, count in by_status.items() if status in terminal_statuses
        )
        configured_ids = {str(query["id"]) for query in settings.raw["queries"]}
        scheduled_official_ids = {
            str(item["query_id"])
            for item in actual
            if item["job_kind"] == "official"
        }
        scope = (
            "analysis_only"
            if analysis_only
            else "smoke"
            if smoke
            else "hosted_only"
            if hosted_only
            else "official_only"
            if no_hosted
            else "full"
        )
        plan_complete = not missing_keys and not unexpected_keys
        complete_profile_run = bool(
            base_mode in {"run", "weekly"}
            and include_official
            and (
                not settings.raw.get("hosted_search", {}).get("enabled")
                or include_hosted
            )
        )
        return {
            "run_id": run_id,
            "scope": scope,
            "complete_profile_run": complete_profile_run,
            "configured_query_ids": len(configured_ids),
            "scheduled_official_query_ids": len(scheduled_official_ids),
            "expected_jobs": len(expected),
            "scheduled_jobs": len(actual),
            "terminal_jobs": terminal_jobs,
            "successful_jobs": int(by_status.get("completed", 0)),
            "plan_complete": plan_complete,
            "execution_complete": bool(plan_complete and terminal_jobs == len(actual)),
            "missing_jobs": [
                {
                    "query_id": query_id,
                    "source": source,
                    "job_kind": job_kind,
                }
                for query_id, source, job_kind in missing_keys
            ],
            "unexpected_jobs": [
                {
                    "query_id": query_id,
                    "source": source,
                    "job_kind": job_kind,
                }
                for query_id, source, job_kind in unexpected_keys
            ],
            "by_status": dict(sorted(by_status.items())),
            "by_source": dict(sorted(by_source.items())),
        }
