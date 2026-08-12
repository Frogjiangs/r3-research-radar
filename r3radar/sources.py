from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Iterator
from urllib.parse import quote

from .http_client import RawReceipt, SafeHttpClient
from .models import (
    SourceRecord,
    normalize_arxiv_id,
    normalize_doi,
    normalize_github_full_name,
)


def compile_arxiv_query(value: str) -> str:
    concepts: list[str] = []
    for match in re.finditer(r'"([^"]+)"|(\S+)', value):
        term = " ".join((match.group(1) or match.group(2) or "").split())
        if not term:
            continue
        escaped = term.replace("\\", "\\\\").replace('"', '\\"')
        exact = f'all:"{escaped}"'
        if match.group(1) is None:
            concepts.append(exact)
            continue
        words = [
            word
            for word in re.split(r"[\s_-]+", term)
            if word
        ]
        if len(words) <= 1:
            concepts.append(exact)
            continue
        word_atoms = [
            f'all:"{word.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
            for word in words
        ]
        concepts.append(f"({exact} OR ({' AND '.join(word_atoms)}))")
    if not concepts:
        raise ValueError("arXiv query has no usable terms")
    return concepts[0] if len(concepts) == 1 else f"({' AND '.join(concepts)})"


@dataclass(frozen=True, slots=True)
class SourcePage:
    records: list[SourceRecord]
    next_cursor: str | None
    page_no: int
    receipt: RawReceipt
    exhausted: bool


class OpenAlexSource:
    endpoint = "https://api.openalex.org/works"

    def __init__(self, client: SafeHttpClient, config: dict[str, Any], from_year: int):
        self.client = client
        self.config = config
        self.from_year = from_year

    def pages(self, job: dict[str, Any], result_limit: int | None = None) -> Iterator[SourcePage]:
        page_size = min(100, int(self.config["page_size"]))
        maximum = min(
            int(self.config["max_results_per_query"]),
            result_limit if result_limit is not None else 10**9,
        )
        cursor = job.get("cursor") or "*"
        page_no = int(job.get("page_no") or 0)
        total = int(job.get("result_count") or 0)
        api_key = os.getenv("OPENALEX_API_KEY", "").strip()
        if not api_key:
            raise ValueError("OPENALEX_API_KEY is required by the current OpenAlex API")
        weekly_since = str(job.get("weekly_since") or "").strip()
        from_publication_date = (
            weekly_since if weekly_since else f"{self.from_year}-01-01"
        )
        while total < maximum:
            params: dict[str, Any] = {
                "search": job["query_text"],
                "filter": f"from_publication_date:{from_publication_date}",
                "per-page": min(page_size, maximum - total),
                "cursor": cursor,
                "api_key": api_key,
            }
            payload, receipt, _ = self.client.request_json(
                self.endpoint,
                params=params,
                allowed_hosts={"api.openalex.org"},
            )
            raw_results = payload.get("results") or []
            records = [self._parse(item, job["query_id"]) for item in raw_results]
            records = [record for record in records if record is not None]
            next_cursor = (payload.get("meta") or {}).get("next_cursor")
            page_no += 1
            total += len(raw_results)
            exhausted = not raw_results or not next_cursor or total >= maximum
            yield SourcePage(records, next_cursor, page_no, receipt, exhausted)
            if exhausted:
                return
            cursor = next_cursor

    @staticmethod
    def _parse(item: dict[str, Any], query_id: str) -> SourceRecord | None:
        title = str(item.get("title") or item.get("display_name") or "").strip()
        source_id = str(item.get("id") or "").rsplit("/", 1)[-1]
        if not source_id:
            return None
        ids = item.get("ids") or {}
        primary = item.get("primary_location") or {}
        best_oa = item.get("best_oa_location") or {}
        open_access = item.get("open_access") or {}
        pdf_url = best_oa.get("pdf_url") or primary.get("pdf_url")
        doi = normalize_doi(item.get("doi"))
        arxiv_id = None
        possible_arxiv_urls = [
            *ids.values(),
            primary.get("landing_page_url"),
            best_oa.get("landing_page_url"),
            open_access.get("oa_url"),
        ]
        for value in possible_arxiv_urls:
            if isinstance(value, str) and "arxiv.org/" in value:
                arxiv_id = normalize_arxiv_id(value)
                break
        if not arxiv_id and doi and doi.startswith("10.48550/arxiv."):
            arxiv_id = normalize_arxiv_id(doi.split("arxiv.", 1)[1])
        if not pdf_url and arxiv_id:
            pdf_url = f"https://arxiv.org/pdf/{arxiv_id}"
        authors = []
        for authorship in item.get("authorships") or []:
            author = authorship.get("author") or {}
            if author.get("display_name"):
                authors.append(author["display_name"])
        metadata = {
            "openalex_id": item.get("id"),
            "type": item.get("type"),
            "publication_date": item.get("publication_date"),
            "cited_by_count": item.get("cited_by_count"),
            "authors": authors,
            "primary_location": primary,
            "best_oa_location": best_oa,
            "open_access": open_access,
            "is_retracted": bool(item.get("is_retracted")),
        }
        return SourceRecord(
            source="openalex",
            source_id=source_id,
            kind="paper",
            title=title,
            query_id=query_id,
            year=item.get("publication_year"),
            canonical_url=primary.get("landing_page_url") or item.get("id"),
            doi=doi,
            arxiv_id=arxiv_id,
            pdf_url=pdf_url,
            language=item.get("language"),
            retracted=bool(item.get("is_retracted")),
            metadata=metadata,
        )


class ArxivSource:
    endpoint = "https://export.arxiv.org/api/query"
    atom = "{http://www.w3.org/2005/Atom}"
    arxiv = "{http://arxiv.org/schemas/atom}"

    def __init__(self, client: SafeHttpClient, config: dict[str, Any]):
        self.client = client
        self.config = config

    def pages(self, job: dict[str, Any], result_limit: int | None = None) -> Iterator[SourcePage]:
        page_size = min(100, int(self.config["page_size"]))
        maximum = min(
            int(self.config["max_results_per_query"]),
            result_limit if result_limit is not None else 10**9,
        )
        start = int(job.get("cursor") or (int(job.get("page_no") or 0) * page_size))
        page_no = int(job.get("page_no") or 0)
        total = int(job.get("result_count") or 0)
        query = compile_arxiv_query(str(job["query_text"]))
        weekly_since = str(job.get("weekly_since") or "").replace("-", "")
        if weekly_since:
            query = (
                f"({query}) AND submittedDate:"
                f"[{weekly_since}0000 TO 999912312359]"
            )
        while total < maximum:
            body, receipt, _ = self.client.request_bytes(
                self.endpoint,
                params={
                    "search_query": query,
                    "start": start,
                    "max_results": min(page_size, maximum - total),
                    "sortBy": "submittedDate" if weekly_since else "relevance",
                    "sortOrder": "descending",
                },
                max_bytes=20 * 1024 * 1024,
                raw_suffix="atom",
                allowed_hosts={"export.arxiv.org"},
            )
            root = ET.fromstring(body)
            entries = root.findall(f"{self.atom}entry")
            records = [self._parse(entry, job["query_id"]) for entry in entries]
            page_no += 1
            total += len(entries)
            start += len(entries)
            exhausted = not entries or len(entries) < page_size or total >= maximum
            yield SourcePage(records, str(start), page_no, receipt, exhausted)
            if exhausted:
                return

    def fetch_by_id(
        self, arxiv_id: str, query_id: str
    ) -> tuple[SourceRecord, RawReceipt]:
        body, receipt, _ = self.client.request_bytes(
            self.endpoint,
            params={"id_list": arxiv_id, "max_results": 1},
            max_bytes=5 * 1024 * 1024,
            raw_suffix="atom",
            allowed_hosts={"export.arxiv.org"},
        )
        root = ET.fromstring(body)
        entry = root.find(f"{self.atom}entry")
        if entry is None:
            raise ValueError(f"arXiv did not return metadata for {arxiv_id}")
        record = self._parse(entry, query_id)
        if record.arxiv_id != normalize_arxiv_id(arxiv_id):
            raise ValueError("arXiv metadata returned an unexpected identifier")
        return record, receipt

    def _parse(self, entry: ET.Element, query_id: str) -> SourceRecord:
        entry_id = (entry.findtext(f"{self.atom}id") or "").strip()
        arxiv_id = normalize_arxiv_id(entry_id)
        title = " ".join((entry.findtext(f"{self.atom}title") or "").split())
        published = entry.findtext(f"{self.atom}published") or ""
        year = int(published[:4]) if re.match(r"^\d{4}", published) else None
        doi = entry.findtext(f"{self.arxiv}doi")
        links: dict[str, str] = {}
        pdf_url = None
        for link in entry.findall(f"{self.atom}link"):
            href = link.attrib.get("href")
            if not href:
                continue
            rel = link.attrib.get("rel") or link.attrib.get("title") or "alternate"
            links[rel] = href
            if link.attrib.get("title") == "pdf" or link.attrib.get("type") == "application/pdf":
                pdf_url = href
        categories = [
            category.attrib.get("term")
            for category in entry.findall(f"{self.atom}category")
            if category.attrib.get("term")
        ]
        authors = [
            (author.findtext(f"{self.atom}name") or "").strip()
            for author in entry.findall(f"{self.atom}author")
        ]
        return SourceRecord(
            source="arxiv",
            source_id=arxiv_id or entry_id,
            kind="paper",
            title=title,
            query_id=query_id,
            year=year,
            canonical_url=entry_id,
            doi=normalize_doi(doi),
            arxiv_id=arxiv_id,
            pdf_url=pdf_url or (f"https://arxiv.org/pdf/{arxiv_id}" if arxiv_id else None),
            metadata={
                "summary": " ".join((entry.findtext(f"{self.atom}summary") or "").split()),
                "published": published,
                "updated": entry.findtext(f"{self.atom}updated"),
                "authors": authors,
                "categories": categories,
                "links": links,
                "comment": entry.findtext(f"{self.arxiv}comment"),
                "journal_ref": entry.findtext(f"{self.arxiv}journal_ref"),
            },
        )


class GitHubSource:
    endpoint = "https://api.github.com/search/repositories"

    def __init__(self, client: SafeHttpClient, config: dict[str, Any]):
        self.client = client
        self.config = config

    def pages(self, job: dict[str, Any], result_limit: int | None = None) -> Iterator[SourcePage]:
        page_size = min(100, int(self.config["page_size"]))
        maximum = min(
            int(self.config["max_results_per_query"]),
            result_limit if result_limit is not None else 1000,
            1000,
        )
        page = int(job.get("cursor") or (int(job.get("page_no") or 0) + 1))
        page_no = int(job.get("page_no") or 0)
        total = int(job.get("result_count") or 0)
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        weekly_since = str(job.get("weekly_since") or "").strip()
        query_text = str(job["query_text"])
        if weekly_since:
            query_text = f"{query_text} pushed:>={weekly_since}"
        while total < maximum:
            payload, receipt, _ = self.client.request_json(
                self.endpoint,
                params={
                    "q": query_text,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": min(page_size, maximum - total),
                    "page": page,
                },
                headers=headers,
                allowed_hosts={"api.github.com"},
            )
            items = payload.get("items") or []
            records = [self._parse(item, job["query_id"]) for item in items]
            page_no += 1
            total += len(items)
            page += 1
            exhausted = (
                not items
                or len(items) < page_size
                or total >= maximum
                or total >= int(payload.get("total_count") or 0)
            )
            yield SourcePage(records, str(page), page_no, receipt, exhausted)
            if exhausted:
                return

    def fetch_repository(
        self, full_name: str, query_id: str
    ) -> tuple[SourceRecord, RawReceipt]:
        normalized_name = normalize_github_full_name(full_name)
        if normalized_name is None:
            raise ValueError("GitHub full name is empty")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        owner, repository = normalized_name.split("/", 1)
        payload, receipt, _ = self.client.request_json(
            f"https://api.github.com/repos/{quote(owner, safe='')}/{quote(repository, safe='')}",
            headers=headers,
            allowed_hosts={"api.github.com"},
        )
        record = self._parse(payload, query_id)
        if record.github_full_name != normalized_name:
            raise ValueError("GitHub API returned an unexpected repository identity")
        return record, receipt

    def fetch_commit(
        self,
        full_name: str,
        reference: str,
    ) -> tuple[dict[str, Any], RawReceipt]:
        normalized_name = normalize_github_full_name(full_name)
        if normalized_name is None:
            raise ValueError("GitHub full name is empty")
        normalized_reference = reference.strip()
        if not normalized_reference or len(normalized_reference) > 200:
            raise ValueError("GitHub commit reference is invalid")
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        token = os.getenv("GITHUB_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        owner, repository = normalized_name.split("/", 1)
        payload, receipt, _ = self.client.request_json(
            (
                f"https://api.github.com/repos/{quote(owner, safe='')}/"
                f"{quote(repository, safe='')}/commits/"
                f"{quote(normalized_reference, safe='')}"
            ),
            headers=headers,
            allowed_hosts={"api.github.com"},
        )
        commit_sha = str(payload.get("sha") or "").casefold()
        html_url = str(payload.get("html_url") or "")
        if (
            len(commit_sha) != 40
            or any(character not in "0123456789abcdef" for character in commit_sha)
            or f"/{commit_sha}" not in html_url.casefold()
        ):
            raise ValueError("GitHub API returned an invalid commit identity")
        return payload, receipt

    @staticmethod
    def _parse(item: dict[str, Any], query_id: str) -> SourceRecord:
        full_name = str(item.get("full_name") or "")
        normalized_name = normalize_github_full_name(full_name)
        return SourceRecord(
            source="github",
            source_id=str(item.get("id") or full_name),
            kind="repository",
            title=full_name or str(item.get("name") or ""),
            query_id=query_id,
            year=None,
            canonical_url=item.get("html_url"),
            github_full_name=normalized_name,
            language=item.get("language"),
            archived=bool(item.get("archived")),
            metadata={
                "description": item.get("description"),
                "default_branch": item.get("default_branch"),
                "stargazers_count": item.get("stargazers_count"),
                "forks_count": item.get("forks_count"),
                "watchers_count": item.get("watchers_count"),
                "open_issues_count": item.get("open_issues_count"),
                "created_at": item.get("created_at"),
                "updated_at": item.get("updated_at"),
                "pushed_at": item.get("pushed_at"),
                "fork": bool(item.get("fork")),
                "archived": bool(item.get("archived")),
                "disabled": bool(item.get("disabled")),
                "license": item.get("license"),
                "topics": item.get("topics") or [],
                "size_kb": item.get("size"),
                "owner_type": (item.get("owner") or {}).get("type"),
            },
        )
