from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import asdict, dataclass, field
from typing import Any


_DOI_PREFIX = re.compile(r"^(?:https?://(?:dx\.)?doi\.org/|doi:\s*)", re.IGNORECASE)
_ARXIV_VERSION = re.compile(r"v\d+$", re.IGNORECASE)
_NON_ALNUM = re.compile(r"[^\w]+", re.UNICODE)
_GITHUB_OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def normalize_doi(value: str | None) -> str | None:
    if not value:
        return None
    normalized = _DOI_PREFIX.sub("", value.strip()).lower()
    return normalized or None


def normalize_arxiv_id(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().rsplit("/", 1)[-1]
    normalized = _ARXIV_VERSION.sub("", normalized)
    return normalized.lower() or None


def normalize_title(value: str) -> str:
    folded = unicodedata.normalize("NFKC", value).casefold()
    return _NON_ALNUM.sub(" ", folded).strip()


def normalize_github_full_name(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.strip().split("/")
    if len(parts) != 2:
        raise ValueError("GitHub full name must contain exactly owner/repository")
    owner, repository = parts
    if not _GITHUB_OWNER.fullmatch(owner):
        raise ValueError("invalid GitHub owner")
    if (
        not _GITHUB_REPOSITORY.fullmatch(repository)
        or repository in {".", ".."}
        or ".." in repository
    ):
        raise ValueError("invalid GitHub repository")
    return f"{owner}/{repository}".casefold()


@dataclass(slots=True)
class SourceRecord:
    source: str
    source_id: str
    kind: str
    title: str
    query_id: str
    year: int | None = None
    canonical_url: str | None = None
    doi: str | None = None
    arxiv_id: str | None = None
    github_full_name: str | None = None
    pdf_url: str | None = None
    language: str | None = None
    retracted: bool = False
    archived: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalized(self) -> "SourceRecord":
        self.title = " ".join((self.title or "").split())
        self.doi = normalize_doi(self.doi)
        self.arxiv_id = normalize_arxiv_id(self.arxiv_id)
        if not self.arxiv_id and self.doi and self.doi.startswith("10.48550/arxiv."):
            self.arxiv_id = normalize_arxiv_id(self.doi.split("arxiv.", 1)[1])
        if self.github_full_name:
            self.github_full_name = normalize_github_full_name(self.github_full_name)
        return self

    def canonical_key(self) -> str:
        self.normalized()
        if self.kind == "repository" and self.github_full_name:
            return f"github:{self.github_full_name}"
        if self.doi:
            return f"doi:{self.doi}"
        if self.arxiv_id:
            return f"arxiv:{self.arxiv_id}"
        title_key = normalize_title(self.title)
        digest = hashlib.sha256(title_key.encode("utf-8")).hexdigest()[:24]
        year_key = str(self.year) if self.year is not None else "unknown"
        return f"title:{self.kind}:{year_key}:{digest}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    admitted: bool
    code: str
    lane: str
    reason: str


def objective_admission(record: SourceRecord, config: dict[str, Any]) -> AdmissionDecision:
    admission = config["admission"]
    time_policy = config["time_policy"]
    if record.kind not in {"paper", "repository"}:
        return AdmissionDecision(False, "unsupported_kind", "rejected", "Unsupported record kind.")
    if admission.get("require_title", True) and not record.title.strip():
        return AdmissionDecision(False, "missing_title", "rejected", "Record has no usable title.")
    if admission.get("exclude_retracted", True) and record.retracted:
        return AdmissionDecision(False, "retracted", "rejected", "Source marks the work as retracted.")
    if (
        record.kind == "repository"
        and admission.get("exclude_github_archived", True)
        and record.archived
    ):
        return AdmissionDecision(False, "archived_repository", "rejected", "Repository is archived.")
    if record.kind == "paper" and record.year:
        lower = int(time_policy["technical_from_year"])
        priority = int(time_policy["priority_from_year"])
        if record.year < lower:
            if time_policy.get("older_foundational_lane", False):
                return AdmissionDecision(
                    True,
                    "foundational_lane",
                    "foundational",
                    "Older work is retained in the explicitly configured foundational lane.",
                )
            return AdmissionDecision(False, "outside_time_scope", "rejected", "Outside configured years.")
        if record.year >= priority:
            return AdmissionDecision(True, "admitted", "frontier", "Within priority time scope.")
    return AdmissionDecision(True, "admitted", "mature", "Passed objective admission gates.")
