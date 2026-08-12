from __future__ import annotations

from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import parse_qs, urljoin, urlsplit

from .http_client import FetchError, RawReceipt, SafeHttpClient
from .models import SourceRecord, normalize_title
from .sources import ArxivSource, GitHubSource


class HostedVerificationRejectedError(ValueError):
    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


class _CitationMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self._in_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value for key, value in attrs if value is not None}
        if tag.casefold() == "meta":
            key = (values.get("name") or values.get("property") or "").casefold()
            content = values.get("content")
            if key and content and key not in self.meta:
                self.meta[key] = content.strip()
        elif tag.casefold() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join(" ".join(self._title_parts).split())


def _content_value(content: dict[str, Any], key: str) -> Any:
    value = content.get(key)
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


class HostedResultVerifier:
    def __init__(
        self,
        client_for_url: Callable[[str], SafeHttpClient],
        arxiv: ArxivSource,
        github: GitHubSource,
    ):
        self.client_for_url = client_for_url
        self.arxiv = arxiv
        self.github = github

    def verify(self, record: SourceRecord) -> tuple[SourceRecord, RawReceipt]:
        host = (urlsplit(record.canonical_url or "").hostname or "").casefold()
        if record.arxiv_id or host == "arxiv.org":
            if not record.arxiv_id:
                raise FetchError("arXiv discovery has no verifiable arXiv identifier")
            verified, receipt = self.arxiv.fetch_by_id(record.arxiv_id, record.query_id)
            return self._with_discovery(verified, record, receipt, "arxiv_api"), receipt
        if record.kind == "repository" or host == "github.com":
            if not record.github_full_name:
                raise FetchError("GitHub discovery has no owner/repository identifier")
            verified, receipt = self.github.fetch_repository(
                record.github_full_name, record.query_id
            )
            return self._with_discovery(verified, record, receipt, "github_api"), receipt
        if host == "openreview.net":
            return self._openreview(record)
        return self._official_html(record)

    @staticmethod
    def _with_discovery(
        verified: SourceRecord,
        discovered: SourceRecord,
        receipt: RawReceipt,
        method: str,
    ) -> SourceRecord:
        verified.metadata["hosted_discovery"] = {
            "title": discovered.title,
            "url": discovered.canonical_url,
            "reason": discovered.metadata.get("discovery_reason"),
            "search_receipt": discovered.metadata.get("hosted_search_receipt"),
            "verification_method": method,
            "verification_sha256": receipt.sha256,
        }
        return verified

    def _openreview(self, record: SourceRecord) -> tuple[SourceRecord, RawReceipt]:
        parts = urlsplit(record.canonical_url or "")
        forum = (parse_qs(parts.query).get("id") or [None])[0]
        if not forum:
            raise HostedVerificationRejectedError(
                "openreview_url_missing_submission_identity",
                "OpenReview URL has no forum identifier",
            )
        client = self.client_for_url("https://api2.openreview.net")
        payload, receipt, _ = client.request_json(
            "https://api2.openreview.net/notes",
            params={"forum": forum, "limit": 100},
            allowed_hosts={"api2.openreview.net"},
        )
        notes = payload.get("notes") or []
        if not notes:
            raise FetchError("OpenReview API returned no notes for the forum")
        candidates = [
            note
            for note in notes
            if str(note.get("id") or "") == forum
            and str(note.get("forum") or forum) == forum
            and _content_value(note.get("content") or {}, "title")
        ]
        if not candidates:
            raise FetchError("OpenReview API returned no titled root submission")
        note = candidates[0]
        content = note.get("content") or {}
        title = str(_content_value(content, "title") or "").strip()
        if not title:
            raise FetchError("OpenReview submission title is empty")
        verified = SourceRecord(
            source="openreview",
            source_id=str(note.get("id") or forum),
            kind="paper",
            title=title,
            query_id=record.query_id,
            year=record.year,
            canonical_url=f"https://openreview.net/forum?id={forum}",
            pdf_url=f"https://openreview.net/pdf?id={forum}",
            metadata={
                "forum": forum,
                "venue": _content_value(content, "venue"),
                "authors": _content_value(content, "authors") or [],
            },
        )
        return self._with_discovery(verified, record, receipt, "openreview_api"), receipt

    def _official_html(self, record: SourceRecord) -> tuple[SourceRecord, RawReceipt]:
        url = record.canonical_url or ""
        client = self.client_for_url(url)
        body, receipt, headers = client.request_bytes(
            url,
            max_bytes=8 * 1024 * 1024,
            raw_suffix="html",
        )
        content_type = headers.get("Content-Type", "").casefold()
        if "html" not in content_type and not body.lstrip().startswith(b"<"):
            raise FetchError("Official page did not return HTML")
        parser = _CitationMetadataParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        title = (
            parser.meta.get("citation_title")
            or parser.meta.get("dc.title")
            or parser.meta.get("og:title")
            or parser.title
        )
        title = " ".join((title or "").split())
        if not title:
            raise FetchError("Official page has no verifiable title metadata")
        pdf_url = parser.meta.get("citation_pdf_url")
        if pdf_url:
            pdf_url = urljoin(receipt.final_url, pdf_url)
        verified = SourceRecord(
            source="official_web",
            source_id=receipt.sha256[:32],
            kind=record.kind,
            title=title,
            query_id=record.query_id,
            year=record.year,
            canonical_url=receipt.final_url,
            doi=record.doi,
            pdf_url=pdf_url,
            metadata={
                "citation_metadata": parser.meta,
                "discovered_normalized_title": normalize_title(record.title),
                "verified_normalized_title": normalize_title(title),
            },
        )
        return self._with_discovery(verified, record, receipt, "official_html"), receipt
