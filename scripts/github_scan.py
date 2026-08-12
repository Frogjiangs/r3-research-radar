#!/usr/bin/env python3
"""Auditable GitHub Issues/Discussions scan for researcher workflow evidence.

The scanner intentionally stores only query metadata and small issue/discussion
metadata samples. It never writes request headers, tokens, bodies, or comments.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Iterable


API_HOST = "api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "r3-researcher-behavior-scan/1.0"


ANCHORS: tuple[dict[str, str], ...] = (
    # Reference managers and their research-facing plugins.
    {"category": "zotero_plugins", "tool": "Zotero", "anchor": "repo:zotero/zotero"},
    {
        "category": "zotero_plugins",
        "tool": "Zotero Better BibTeX",
        "anchor": "repo:retorquere/zotero-better-bibtex",
    },
    {
        "category": "zotero_plugins",
        "tool": "Zotero Better Notes",
        "anchor": "repo:windingwind/zotero-better-notes",
    },
    {
        "category": "zotero_plugins",
        "tool": "Obsidian Zotero Integration",
        "anchor": "repo:obsidian-community/obsidian-zotero-integration",
    },
    {
        "category": "zotero_plugins",
        "tool": "Obsidian ZotLit",
        "anchor": "repo:aidenlx/zotlit",
    },
    {"category": "reference_managers", "tool": "JabRef", "anchor": "repo:JabRef/jabref"},
    {"category": "reference_managers", "tool": "Zettlr", "anchor": "repo:Zettlr/Zettlr"},
    {"category": "reference_managers", "tool": "Mendeley", "anchor": '"Mendeley"'},
    {"category": "reference_managers", "tool": "EndNote", "anchor": '"EndNote"'},
    {"category": "reference_managers", "tool": "ReadCube Papers", "anchor": '"ReadCube Papers"'},
    # PKM / notebooks / annotation.
    {
        "category": "pkm",
        "tool": "Obsidian",
        "anchor": "repo:obsidianmd/obsidian-releases",
    },
    {
        "category": "pkm",
        "tool": "Obsidian Dataview",
        "anchor": "repo:blacksmithgu/obsidian-dataview",
    },
    {
        "category": "pkm",
        "tool": "Obsidian Tasks",
        "anchor": "repo:obsidian-tasks-group/obsidian-tasks",
    },
    {"category": "pkm", "tool": "Logseq", "anchor": "repo:logseq/logseq"},
    {"category": "pkm", "tool": "JupyterLab", "anchor": "repo:jupyterlab/jupyterlab"},
    {"category": "pkm", "tool": "Jupyter Notebook", "anchor": "repo:jupyter/notebook"},
    {"category": "annotation", "tool": "Hypothesis", "anchor": "repo:hypothesis/h"},
    # Scholarly metadata and discovery clients/platform mentions.
    {"category": "scholarly_clients", "tool": "PyAlex", "anchor": "repo:J535D165/pyalex"},
    {
        "category": "scholarly_clients",
        "tool": "Semantic Scholar Python",
        "anchor": "repo:danielnsilva/semanticscholar",
    },
    {"category": "scholarly_clients", "tool": "OpenAlex", "anchor": '"OpenAlex"'},
    {
        "category": "scholarly_clients",
        "tool": "Semantic Scholar",
        "anchor": '"Semantic Scholar"',
    },
    {"category": "citation_graph", "tool": "ResearchRabbit", "anchor": '"ResearchRabbit"'},
    {
        "category": "citation_graph",
        "tool": "Connected Papers",
        "anchor": '"Connected Papers"',
    },
    {"category": "citation_graph", "tool": "Litmaps", "anchor": '"Litmaps"'},
    {"category": "citation_graph", "tool": "Inciteful", "anchor": '"Inciteful"'},
    {"category": "citation_graph", "tool": "scite", "anchor": '"scite.ai"'},
    # Research agents and AI-assisted synthesis.
    {
        "category": "research_agents",
        "tool": "PaperQA",
        "anchor": "repo:Future-House/paper-qa",
    },
    {"category": "research_agents", "tool": "STORM", "anchor": "repo:stanford-oval/storm"},
    {
        "category": "research_agents",
        "tool": "GPT Researcher",
        "anchor": "repo:assafelovic/gpt-researcher",
    },
    {
        "category": "research_agents",
        "tool": "Open Deep Research",
        "anchor": "repo:langchain-ai/open_deep_research",
    },
    {"category": "research_agents", "tool": "Elicit", "anchor": '"Elicit AI"'},
    {"category": "research_agents", "tool": "Consensus", "anchor": '"Consensus AI"'},
    # Systematic review and evidence-screening tools.
    {
        "category": "systematic_review",
        "tool": "ASReview",
        "anchor": "repo:asreview/asreview",
    },
    {
        "category": "systematic_review",
        "tool": "CoLRev",
        "anchor": "repo:CoLRev-Environment/colrev",
    },
    {"category": "systematic_review", "tool": "Rayyan", "anchor": '"Rayyan"'},
    {"category": "systematic_review", "tool": "Covidence", "anchor": '"Covidence"'},
    {
        "category": "systematic_review",
        "tool": "Systematic review tools",
        "anchor": '"systematic review"',
    },
    # Read-later, feeds, and alerting.
    {
        "category": "read_later_rss",
        "tool": "Omnivore",
        "anchor": "repo:omnivore-app/omnivore",
    },
    {"category": "read_later_rss", "tool": "Wallabag", "anchor": "repo:wallabag/wallabag"},
    {"category": "read_later_rss", "tool": "FreshRSS", "anchor": "repo:FreshRSS/FreshRSS"},
    {"category": "read_later_rss", "tool": "Miniflux", "anchor": "repo:miniflux/v2"},
    {
        "category": "paper_alerts",
        "tool": "arXiv Sanity",
        "anchor": "repo:karpathy/arxiv-sanity-lite",
    },
    {"category": "paper_alerts", "tool": "Paper alerts", "anchor": '"paper alerts"'},
)


INTENTS: tuple[tuple[str, str], ...] = (
    ("workflow", "workflow"),
    ("notification", "notification"),
    ("alert", "alert"),
    ("noise", "noise"),
    ("duplicate", "duplicate"),
    ("dedup", "deduplication"),
    ("export", "export"),
    ("import", "import"),
    ("annotation", "annotation"),
    ("highlight", "highlight"),
    ("team", "team"),
    ("collaboration", "collaboration"),
    ("privacy", "privacy"),
    ("trust", "trust"),
    ("hallucination", "hallucination"),
    ("accuracy", "accuracy"),
    ("relevance", "relevance"),
    ("ranking", "ranking"),
    ("recommendation", "recommendation"),
    ("search", "search"),
    ("filter", "filter"),
    ("citation", "citation"),
    ("reference", "reference"),
    ("metadata", "metadata"),
    ("pdf", "PDF"),
    ("full_text", '"full text"'),
    ("markdown", "markdown"),
    ("latex", "LaTeX"),
    ("sync", "sync"),
    ("offline", "offline"),
    ("tagging", "tagging"),
    ("collection", "collection"),
    ("folder", "folder"),
    ("graph", "graph"),
    ("discovery", "discovery"),
    ("feed", "feed"),
    ("rss", "RSS"),
    ("update", "update"),
    ("api", "API"),
    ("rate_limit", '"rate limit"'),
    ("cache", "cache"),
    ("provenance", "provenance"),
    ("reproducibility", "reproducible"),
)


DISCUSSION_REPOS: tuple[tuple[str, str], ...] = (
    ("zotero", "zotero"),
    ("retorquere", "zotero-better-bibtex"),
    ("obsidian-community", "obsidian-zotero-integration"),
    ("aidenlx", "zotlit"),
    ("logseq", "logseq"),
    ("jupyterlab", "jupyterlab"),
    ("jupyter", "notebook"),
    ("JabRef", "jabref"),
    ("Future-House", "paper-qa"),
    ("stanford-oval", "storm"),
    ("assafelovic", "gpt-researcher"),
    ("asreview", "asreview"),
    ("omnivore-app", "omnivore"),
    ("FreshRSS", "FreshRSS"),
    ("miniflux", "v2"),
    ("langchain-ai", "open_deep_research"),
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def write_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"invalid JSONL at {path}:{line_number}") from exc
            if isinstance(value, dict):
                rows.append(value)
    return rows


def load_github_token() -> tuple[str, str]:
    token = os.getenv("GITHUB_TOKEN", "").strip() or os.getenv("GH_TOKEN", "").strip()
    if token:
        return token, "process_environment"
    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                token = str(winreg.QueryValueEx(key, "GITHUB_TOKEN")[0]).strip()
            if token:
                return token, "windows_user_environment"
        except (FileNotFoundError, OSError):
            pass
    return "", "unauthenticated"


class GitHubClient:
    def __init__(self, token: str, minimum_interval: float) -> None:
        self._token = token
        self._minimum_interval = minimum_interval
        self._connection: http.client.HTTPSConnection | None = None
        self._last_request_started = 0.0
        self.last_rate: dict[str, Any] = {}

    def _headers(self, *, content_type: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if content_type:
            headers["Content-Type"] = "application/json"
        return headers

    def _connect(self) -> http.client.HTTPSConnection:
        if self._connection is None:
            self._connection = http.client.HTTPSConnection(API_HOST, timeout=45)
        return self._connection

    def _close(self) -> None:
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None

    def _pace(self) -> None:
        elapsed = time.monotonic() - self._last_request_started
        remaining = self._minimum_interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
        self._last_request_started = time.monotonic()

    @staticmethod
    def _rate_from_headers(headers: http.client.HTTPMessage) -> dict[str, Any]:
        def as_int(name: str) -> int | None:
            raw = headers.get(name)
            if raw is None:
                return None
            try:
                return int(raw)
            except ValueError:
                return None

        return {
            "resource": headers.get("x-ratelimit-resource"),
            "limit": as_int("x-ratelimit-limit"),
            "remaining": as_int("x-ratelimit-remaining"),
            "used": as_int("x-ratelimit-used"),
            "reset_epoch": as_int("x-ratelimit-reset"),
            "retry_after_seconds": as_int("retry-after"),
        }

    def request_json(
        self, method: str, path: str, *, payload: dict[str, Any] | None = None
    ) -> tuple[int, dict[str, Any], dict[str, Any], float]:
        encoded = None
        if payload is not None:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        last_error = "request_failed"
        for attempt in range(1, 4):
            self._pace()
            started = time.monotonic()
            try:
                connection = self._connect()
                connection.request(
                    method,
                    path,
                    body=encoded,
                    headers=self._headers(content_type=payload is not None),
                )
                response = connection.getresponse()
                body = response.read()
                elapsed_ms = round((time.monotonic() - started) * 1000, 1)
                rate = self._rate_from_headers(response.headers)
                self.last_rate = rate
                try:
                    parsed = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    parsed = {}
                if not isinstance(parsed, dict):
                    parsed = {}
                status = int(response.status)
                if status in {502, 503, 504} and attempt < 3:
                    self._close()
                    time.sleep(2**attempt)
                    continue
                return status, parsed, rate, elapsed_ms
            except (OSError, http.client.HTTPException, TimeoutError):
                last_error = "transport_error"
                self._close()
                if attempt < 3:
                    time.sleep(2**attempt)
                    continue
        raise RuntimeError(last_error)

    @staticmethod
    def wait_for_rate_limit(rate: dict[str, Any]) -> float:
        retry_after = rate.get("retry_after_seconds")
        if isinstance(retry_after, int) and retry_after > 0:
            wait = min(retry_after + 1, 180)
            time.sleep(wait)
            return float(wait)
        remaining = rate.get("remaining")
        reset_epoch = rate.get("reset_epoch")
        if remaining == 0 and isinstance(reset_epoch, int):
            wait = max(1.0, min(float(reset_epoch) - time.time() + 2.0, 180.0))
            time.sleep(wait)
            return wait
        return 0.0


def candidate_queries() -> Iterable[dict[str, str]]:
    # Intent-first round robin ensures every tool family is reached before the
    # scan can finish on high-volume repositories alone.
    for intent, term in INTENTS:
        for anchor in ANCHORS:
            query = f"{anchor['anchor']} is:issue in:title,body {term}"
            yield {
                "category": anchor["category"],
                "tool": anchor["tool"],
                "intent": intent,
                "query": query,
            }


def issue_sample(item: dict[str, Any]) -> dict[str, Any]:
    repository_url = str(item.get("repository_url") or "")
    repository = repository_url.rsplit("/repos/", 1)[-1] if "/repos/" in repository_url else ""
    labels: list[str] = []
    for label in item.get("labels") or []:
        if isinstance(label, dict) and label.get("name"):
            labels.append(str(label["name"])[:120])
    return {
        "url": str(item.get("html_url") or ""),
        "repository": repository,
        "number": item.get("number"),
        "title": str(item.get("title") or "")[:300],
        "state": item.get("state"),
        "comments": item.get("comments"),
        "created_at": item.get("created_at"),
        "updated_at": item.get("updated_at"),
        "labels": labels[:12],
        "is_pull_request": "pull_request" in item,
    }


def search_issues(
    client: GitHubClient,
    *,
    output_dir: Path,
    target: int,
    max_attempts: int,
    per_page: int,
) -> None:
    query_log = output_dir / "queries.jsonl"
    results_log = output_dir / "results.jsonl"
    existing = load_jsonl(query_log)
    completed = {
        str(row.get("query"))
        for row in existing
        if row.get("source_kind") == "github_issue_search"
        and row.get("http_status") == 200
        and row.get("parsed") is True
    }
    productive = sum(
        1
        for row in existing
        if row.get("source_kind") == "github_issue_search"
        and row.get("productive_effective") is True
    )
    attempts_this_run = 0
    for candidate in candidate_queries():
        if productive >= target or attempts_this_run >= max_attempts:
            break
        query = candidate["query"]
        if query in completed:
            continue
        attempts_this_run += 1
        path = "/search/issues?" + urllib.parse.urlencode(
            {
                "q": query,
                "sort": "comments",
                "order": "desc",
                "per_page": per_page,
            }
        )
        status = 0
        parsed = False
        result_count = 0
        samples: list[dict[str, Any]] = []
        error_code: str | None = None
        rate: dict[str, Any] = {}
        elapsed_ms = 0.0
        waited_seconds = 0.0
        try:
            status, payload, rate, elapsed_ms = client.request_json("GET", path)
            if status == 200 and isinstance(payload.get("total_count"), int):
                parsed = True
                result_count = int(payload["total_count"])
                samples = [
                    issue_sample(item)
                    for item in (payload.get("items") or [])
                    if isinstance(item, dict)
                ]
            elif status in {403, 429}:
                error_code = "rate_limited"
                waited_seconds = client.wait_for_rate_limit(rate)
            elif status == 422:
                error_code = "query_validation_failed"
            else:
                error_code = f"http_{status}"
        except RuntimeError as exc:
            error_code = str(exc)[:80]
        is_productive = status == 200 and parsed and result_count > 0
        record = {
            "schema": "r3/github-query/v1",
            "executed_at": utc_now(),
            "query_id": stable_id(f"github_issue_search\n{query}"),
            "source_kind": "github_issue_search",
            "endpoint": "/search/issues",
            **candidate,
            "http_status": status,
            "parsed": parsed,
            "result_count": result_count,
            "productive_effective": is_productive,
            "sample_count": len(samples),
            "elapsed_ms": elapsed_ms,
            "waited_seconds": waited_seconds,
            "rate_limit": rate,
            "error_code": error_code,
        }
        write_jsonl(query_log, record)
        if is_productive:
            productive += 1
            write_jsonl(
                results_log,
                {
                    "schema": "r3/github-result/v1",
                    "captured_at": record["executed_at"],
                    "query_id": record["query_id"],
                    "source_kind": "github_issue_search",
                    "category": candidate["category"],
                    "tool": candidate["tool"],
                    "intent": candidate["intent"],
                    "query": query,
                    "result_count": result_count,
                    "samples": samples,
                },
            )
        if attempts_this_run % 20 == 0 or productive >= target:
            print(
                json.dumps(
                    {
                        "event": "progress",
                        "attempts_this_run": attempts_this_run,
                        "productive_total": productive,
                        "target": target,
                        "rate_remaining": rate.get("remaining"),
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )


GRAPHQL_DISCUSSIONS = """
query RepositoryDiscussions($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    hasDiscussionsEnabled
    discussions(first: 25, orderBy: {field: UPDATED_AT, direction: DESC}) {
      totalCount
      nodes {
        number
        title
        url
        createdAt
        updatedAt
        answerChosenAt
        category { name }
        comments { totalCount }
      }
    }
  }
}
""".strip()


def capture_discussions(client: GitHubClient, output_dir: Path) -> None:
    query_log = output_dir / "queries.jsonl"
    results_log = output_dir / "results.jsonl"
    existing = load_jsonl(query_log)
    completed_ids = {
        str(row.get("query_id"))
        for row in existing
        if row.get("source_kind") == "github_discussion_snapshot"
        and row.get("http_status") == 200
        and row.get("parsed") is True
    }
    for owner, name in DISCUSSION_REPOS:
        logical_query = f"repo:{owner}/{name} discussions:first=25 order=updated"
        query_id = stable_id(f"github_discussion_snapshot\n{logical_query}")
        if query_id in completed_ids:
            continue
        status = 0
        parsed = False
        result_count = 0
        samples: list[dict[str, Any]] = []
        error_code: str | None = None
        elapsed_ms = 0.0
        rate: dict[str, Any] = {}
        try:
            status, payload, rate, elapsed_ms = client.request_json(
                "POST",
                "/graphql",
                payload={
                    "query": GRAPHQL_DISCUSSIONS,
                    "variables": {"owner": owner, "name": name},
                },
            )
            repository = (payload.get("data") or {}).get("repository")
            errors = payload.get("errors")
            if status == 200 and isinstance(repository, dict) and not errors:
                discussions = repository.get("discussions") or {}
                result_count = int(discussions.get("totalCount") or 0)
                for node in discussions.get("nodes") or []:
                    if not isinstance(node, dict):
                        continue
                    category = node.get("category") or {}
                    comments = node.get("comments") or {}
                    samples.append(
                        {
                            "url": str(node.get("url") or ""),
                            "repository": str(repository.get("nameWithOwner") or ""),
                            "number": node.get("number"),
                            "title": str(node.get("title") or "")[:300],
                            "category": str(category.get("name") or "")[:120],
                            "comments": comments.get("totalCount"),
                            "created_at": node.get("createdAt"),
                            "updated_at": node.get("updatedAt"),
                            "answered": bool(node.get("answerChosenAt")),
                        }
                    )
                parsed = True
            elif errors:
                error_code = "graphql_error"
            else:
                error_code = f"http_{status}"
        except RuntimeError as exc:
            error_code = str(exc)[:80]
        has_content = status == 200 and parsed and result_count > 0
        record = {
            "schema": "r3/github-query/v1",
            "executed_at": utc_now(),
            "query_id": query_id,
            "source_kind": "github_discussion_snapshot",
            "endpoint": "/graphql",
            "category": "repository_discussions",
            "tool": f"{owner}/{name}",
            "intent": "recent_discussions",
            "query": logical_query,
            "http_status": status,
            "parsed": parsed,
            "result_count": result_count,
            # This is a bounded repository snapshot, not a search query. Keep
            # it out of productive-effective search totals even when nonempty.
            "productive_effective": False,
            "snapshot_has_content": has_content,
            "counted_as_effective_search": False,
            "sample_count": len(samples),
            "elapsed_ms": elapsed_ms,
            "waited_seconds": 0.0,
            "rate_limit": rate,
            "error_code": error_code,
        }
        write_jsonl(query_log, record)
        if has_content:
            write_jsonl(
                results_log,
                {
                    "schema": "r3/github-result/v1",
                    "captured_at": record["executed_at"],
                    "query_id": query_id,
                    "source_kind": "github_discussion_snapshot",
                    "category": "repository_discussions",
                    "tool": f"{owner}/{name}",
                    "intent": "recent_discussions",
                    "query": logical_query,
                    "result_count": result_count,
                    "samples": samples,
                },
            )


def counter_dict(counter: collections.Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def make_audit_summary(
    output_dir: Path, credential_source: str, target: int, stop_reason: str
) -> dict[str, Any]:
    queries = load_jsonl(output_dir / "queries.jsonl")
    results = load_jsonl(output_dir / "results.jsonl")
    issue_rows = [row for row in queries if row.get("source_kind") == "github_issue_search"]
    discussion_rows = [
        row for row in queries if row.get("source_kind") == "github_discussion_snapshot"
    ]
    productive_issues = [row for row in issue_rows if row.get("productive_effective") is True]
    discussion_snapshots_with_content = [
        row for row in discussion_rows if row.get("snapshot_has_content") is True
    ]
    sampled_urls: list[str] = []
    for result in results:
        for sample in result.get("samples") or []:
            if isinstance(sample, dict) and sample.get("url"):
                sampled_urls.append(str(sample["url"]))
    category_attempts = collections.Counter(str(row.get("category")) for row in issue_rows)
    category_productive = collections.Counter(
        str(row.get("category")) for row in productive_issues
    )
    intent_attempts = collections.Counter(str(row.get("intent")) for row in issue_rows)
    intent_productive = collections.Counter(str(row.get("intent")) for row in productive_issues)
    statuses = collections.Counter(str(row.get("http_status")) for row in queries)
    limits = [
        row.get("rate_limit")
        for row in queries
        if isinstance(row.get("rate_limit"), dict) and row["rate_limit"].get("limit") is not None
    ]
    summary = {
        "schema": "r3/github-scan-audit/v1",
        "generated_at": utc_now(),
        "target_productive_issue_queries": target,
        "configured_stop_reason": stop_reason,
        "planned_unique_issue_query_candidates": len(ANCHORS) * len(INTENTS),
        "unique_queries_executed": len({str(row.get("query")) for row in queries}),
        "issue_queries": {
            "attempted_unique": len({str(row.get("query")) for row in issue_rows}),
            "successful_parsed": sum(
                row.get("http_status") == 200 and row.get("parsed") is True for row in issue_rows
            ),
            "productive_effective": len(productive_issues),
            "zero_result": sum(
                row.get("http_status") == 200
                and row.get("parsed") is True
                and int(row.get("result_count") or 0) == 0
                for row in issue_rows
            ),
            "failed_or_unparsed": sum(
                not (row.get("http_status") == 200 and row.get("parsed") is True)
                for row in issue_rows
            ),
            "result_count_sum_not_deduplicated": sum(
                int(row.get("result_count") or 0) for row in productive_issues
            ),
        },
        "discussion_snapshots": {
            "attempted_unique": len({str(row.get("query")) for row in discussion_rows}),
            "successful_parsed": sum(
                row.get("http_status") == 200 and row.get("parsed") is True
                for row in discussion_rows
            ),
            "with_content": len(discussion_snapshots_with_content),
            "counted_as_effective_search": False,
            "reported_total_count_sum_not_deduplicated": sum(
                int(row.get("result_count") or 0)
                for row in discussion_snapshots_with_content
            ),
        },
        "samples": {
            "url_observations": len(sampled_urls),
            "unique_urls": len(set(sampled_urls)),
            "duplicate_url_observations": len(sampled_urls) - len(set(sampled_urls)),
            "body_or_comment_text_stored": False,
        },
        "coverage": {
            "category_attempts": counter_dict(category_attempts),
            "category_productive": counter_dict(category_productive),
            "intent_attempts": counter_dict(intent_attempts),
            "intent_productive": counter_dict(intent_productive),
        },
        "http_statuses": counter_dict(statuses),
        "rate_limit_observations": {
            "observed_limits": sorted(
                {int(rate["limit"]) for rate in limits if rate.get("limit") is not None}
            ),
            "minimum_remaining_seen": min(
                (int(rate["remaining"]) for rate in limits if rate.get("remaining") is not None),
                default=None,
            ),
            "maximum_waited_seconds": max(
                (float(row.get("waited_seconds") or 0.0) for row in queries), default=0.0
            ),
        },
        "credential_handling": {
            "source": credential_source,
            "token_written_to_disk": False,
            "request_headers_written_to_disk": False,
            "credential_value_logged": False,
        },
        "counting_rule": (
            "productive_effective iff the official GitHub response was HTTP 200, "
            "JSON was parsed, and result_count was greater than zero"
        ),
        "limitations": [
            "GitHub issue search reports at most 1000 retrievable matches for a query.",
            "Stored samples are the five most-commented matches, not a random sample.",
            "Issue result counts overlap across queries and must not be summed as unique users or issues.",
            "Discussion snapshots include only the 25 most recently updated discussions per repository.",
            "GitHub contributors are not representative of all academic researchers.",
        ],
    }
    return summary


def validate_outputs(output_dir: Path) -> dict[str, Any]:
    query_path = output_dir / "queries.jsonl"
    result_path = output_dir / "results.jsonl"
    audit_path = output_dir / "audit_summary.json"
    persona_path = output_dir / "persona_findings.md"
    queries = load_jsonl(query_path)
    results = load_jsonl(result_path)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    issue_rows = [row for row in queries if row.get("source_kind") == "github_issue_search"]
    discussion_rows = [
        row for row in queries if row.get("source_kind") == "github_discussion_snapshot"
    ]
    productive_issue_ids = {
        str(row.get("query_id"))
        for row in issue_rows
        if row.get("productive_effective") is True
    }
    discussion_with_content_ids = {
        str(row.get("query_id"))
        for row in discussion_rows
        if row.get("snapshot_has_content") is True
    }
    issue_result_ids = {
        str(row.get("query_id"))
        for row in results
        if row.get("source_kind") == "github_issue_search"
    }
    discussion_result_ids = {
        str(row.get("query_id"))
        for row in results
        if row.get("source_kind") == "github_discussion_snapshot"
    }
    sample_urls: list[str] = []
    for result in results:
        for sample in result.get("samples") or []:
            if isinstance(sample, dict) and sample.get("url"):
                sample_urls.append(str(sample["url"]))
    forbidden_keys = {
        "authorization",
        "request_headers",
        "token",
        "body",
        "comment_body",
        "comments_text",
    }

    def keys_are_safe(value: Any) -> bool:
        if isinstance(value, dict):
            return not (forbidden_keys & {str(key).lower() for key in value}) and all(
                keys_are_safe(item) for item in value.values()
            )
        if isinstance(value, list):
            return all(keys_are_safe(item) for item in value)
        return True

    persona_text = persona_path.read_text(encoding="utf-8")
    persona_urls = set(re.findall(r"https://github\.com/[^)\s]+", persona_text))
    token, _ = load_github_token()
    persisted_text = (
        query_path.read_text(encoding="utf-8")
        + result_path.read_text(encoding="utf-8")
        + audit_path.read_text(encoding="utf-8")
        + persona_text
    )
    checks = {
        "query_jsonl_nonempty": bool(queries),
        "result_jsonl_nonempty": bool(results),
        "query_ids_unique": len({str(row.get("query_id")) for row in queries})
        == len(queries),
        "query_strings_unique": len({str(row.get("query")) for row in queries})
        == len(queries),
        "issue_productive_rule_exact": all(
            bool(row.get("productive_effective"))
            == (
                row.get("http_status") == 200
                and row.get("parsed") is True
                and int(row.get("result_count") or 0) > 0
            )
            for row in issue_rows
        ),
        "discussion_snapshots_not_counted_as_search": all(
            row.get("productive_effective") is False
            and row.get("counted_as_effective_search") is False
            for row in discussion_rows
        ),
        "issue_results_match_productive_queries": issue_result_ids == productive_issue_ids,
        "discussion_results_match_nonempty_snapshots": discussion_result_ids
        == discussion_with_content_ids,
        "audit_issue_count_matches": int(
            audit["issue_queries"]["productive_effective"]
        )
        == len(productive_issue_ids),
        "audit_discussion_count_matches": int(audit["discussion_snapshots"]["attempted_unique"])
        == len(discussion_rows),
        "audit_unique_sample_urls_matches": int(audit["samples"]["unique_urls"])
        == len(set(sample_urls)),
        "all_sample_urls_are_github_https": all(
            urllib.parse.urlparse(url).scheme == "https"
            and urllib.parse.urlparse(url).netloc == "github.com"
            for url in sample_urls
        ),
        "persona_evidence_urls_present_in_samples": persona_urls.issubset(set(sample_urls)),
        "no_forbidden_sensitive_or_long_text_keys": keys_are_safe(queries)
        and keys_are_safe(results),
        "credential_value_not_persisted": not token or token not in persisted_text,
        "audit_declares_no_bodies": audit["samples"]["body_or_comment_text_stored"] is False,
        "persona_exists_and_nonempty": len(persona_text.strip()) > 1000,
    }

    def file_receipt(path: Path) -> dict[str, Any]:
        payload = path.read_bytes()
        return {
            "path": str(path),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "line_count": payload.count(b"\n"),
        }

    report = {
        "schema": "r3/github-scan-validation/v1",
        "generated_at": utc_now(),
        "ok": all(checks.values()),
        "checks": checks,
        "counts": {
            "query_rows": len(queries),
            "issue_query_rows": len(issue_rows),
            "productive_issue_queries": len(productive_issue_ids),
            "discussion_snapshot_rows": len(discussion_rows),
            "discussion_snapshots_with_content": len(discussion_with_content_ids),
            "result_rows": len(results),
            "sample_url_observations": len(sample_urls),
            "unique_sample_urls": len(set(sample_urls)),
            "persona_evidence_urls": len(persona_urls),
        },
        "files": [
            file_receipt(query_path),
            file_receipt(result_path),
            file_receipt(audit_path),
            file_receipt(persona_path),
            file_receipt(Path(__file__).resolve()),
        ],
    }
    return report


def parse_args() -> argparse.Namespace:
    workspace = Path(__file__).resolve().parents[3]
    default_output = workspace / "outputs" / "r3_researcher_behavior_20260728" / "github"
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=default_output)
    parser.add_argument("--target", type=int, default=280)
    parser.add_argument("--max-attempts", type=int, default=900)
    parser.add_argument("--per-page", type=int, default=5)
    parser.add_argument("--minimum-interval", type=float, default=None)
    parser.add_argument("--skip-discussions", action="store_true")
    parser.add_argument("--discussions-only", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--stop-reason", default="configured_productive_target")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.target < 1 or args.max_attempts < 1 or not 1 <= args.per_page <= 100:
        raise SystemExit("invalid positive target/max-attempts or per-page outside 1..100")
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if args.validate_only:
        validation = validate_outputs(output_dir)
        validation_path = output_dir / "validation.json"
        validation_path.write_text(
            json.dumps(validation, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            json.dumps(
                {
                    "event": "validation_complete",
                    "validation": str(validation_path),
                    "ok": validation["ok"],
                    "checks": len(validation["checks"]),
                },
                ensure_ascii=False,
            )
        )
        return 0 if validation["ok"] else 3
    token, credential_source = load_github_token()
    minimum_interval = args.minimum_interval
    if minimum_interval is None:
        minimum_interval = 2.2 if token else 6.2
    client = GitHubClient(token, minimum_interval)
    if not args.discussions_only:
        search_issues(
            client,
            output_dir=output_dir,
            target=args.target,
            max_attempts=args.max_attempts,
            per_page=args.per_page,
        )
    if not args.skip_discussions and token:
        capture_discussions(client, output_dir)
    summary = make_audit_summary(
        output_dir, credential_source, args.target, args.stop_reason
    )
    summary_path = output_dir / "audit_summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "event": "complete",
                "audit_summary": str(summary_path),
                "productive_issue_queries": summary["issue_queries"]["productive_effective"],
                "discussion_snapshots_with_content": summary["discussion_snapshots"][
                    "with_content"
                ],
                "unique_sample_urls": summary["samples"]["unique_urls"],
            },
            ensure_ascii=False,
        )
    )
    return 0 if summary["issue_queries"]["productive_effective"] >= args.target else 2


if __name__ == "__main__":
    raise SystemExit(main())
