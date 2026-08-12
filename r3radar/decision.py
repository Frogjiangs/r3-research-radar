from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit


FROZEN_SNAPSHOT_SCHEMA = "r3/publication-item-snapshot/v1"
EVIDENCE_CONTEXT_SCHEMA = "r3/evidence-context/v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CHARACTER_ANCHOR = re.compile(r"^characters:(0|[1-9][0-9]*)-(0|[1-9][0-9]*)$")
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_SNAPSHOT_KEYS = frozenset(
    {
        "schema",
        "analysis_id",
        "work_id",
        "input_sha256",
        "document_id",
        "citation",
        "analysis",
        "coverage",
        "provider",
        "model",
        "tier",
        "score",
        "lane",
        "provenance_status",
        "analysis_created_at",
    }
)
_CITATION_KEYS = frozenset(
    {
        "kind",
        "title",
        "year",
        "doi",
        "arxiv_id",
        "github_full_name",
        "best_url",
        "metadata",
    }
)
_ANALYSIS_REQUIRED_KEYS = frozenset(
    {
        "candidate_id",
        "deep_read_status",
        "coverage",
        "summary_zh",
        "problem",
        "method",
        "evaluation",
        "limitations",
        "r3_relationship",
        "actionable_ideas",
        "overlap_risks",
        "reproducibility",
        "score_scale",
        "scores",
        "tier",
        "evidence_anchors",
        "uncertainties",
    }
)
_ANALYSIS_OPTIONAL_KEYS = frozenset({"score_normalization"})
_SCORE_KEYS = frozenset(
    {
        "novelty",
        "r3_relevance",
        "evidence_strength",
        "reuse_signal_value",
        "implementability",
        "overall",
    }
)
_LIST_TEXT_FIELDS = (
    "evaluation",
    "limitations",
    "r3_relationship",
    "actionable_ideas",
    "overlap_risks",
    "uncertainties",
)
_TIERS = {
    "must_read",
    "important",
    "background",
    "out_of_scope_after_deep_read",
}
_FORMATS = {
    "csl-json": ("csl.json", "application/vnd.citationstyles.csl+json; charset=utf-8"),
    "bibtex": ("bib", "application/x-bibtex; charset=utf-8"),
    "ris": ("ris", "application/x-research-info-systems; charset=utf-8"),
    "markdown": ("md", "text/markdown; charset=utf-8"),
}
_FORMAT_ALIASES = {
    "csl": "csl-json",
    "csl_json": "csl-json",
    "csljson": "csl-json",
    "bib": "bibtex",
    "md": "markdown",
}


class DecisionExportError(ValueError):
    """Raised when frozen evidence cannot be safely validated or exported."""


@dataclass(frozen=True, slots=True)
class ExportArtifact:
    format: str
    content: bytes
    content_type: str
    filename: str
    sha256: str


def _canonical_json(value: Any, *, pretty: bool = False) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise DecisionExportError("value is not deterministic JSON") from exc


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_exact_keys(
    value: Mapping[str, Any],
    expected: frozenset[str],
    *,
    field: str,
) -> None:
    actual = set(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    raise DecisionExportError(
        f"{field} keys do not match the frozen schema "
        f"(missing={missing}, unexpected={unexpected})"
    )


def _require_positive_integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DecisionExportError(f"{field} must be a positive integer")
    return value


def _require_sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DecisionExportError(f"{field} must be a lowercase SHA-256")
    return value


def _require_text(
    value: Any,
    *,
    field: str,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise DecisionExportError(f"{field} must be a string")
    if _CONTROL_CHARACTER.search(value):
        raise DecisionExportError(f"{field} contains unsafe control characters")
    if not allow_empty and not value.strip():
        raise DecisionExportError(f"{field} must not be empty")
    return value


def _optional_text(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field=field)


def _require_number(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionExportError(f"{field} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise DecisionExportError(f"{field} must be a finite number")
    return result


def _validate_url(value: str | None, *, field: str) -> None:
    if value is None:
        return
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise DecisionExportError(f"{field} must be a public HTTP(S) URL")


def _validated_json_copy(value: Any, *, field: str) -> Any:
    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        return json.loads(serialized)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DecisionExportError(f"{field} must contain deterministic JSON") from exc


def _validate_analysis(analysis: Any, *, work_id: int, tier: str, score: float) -> None:
    if not isinstance(analysis, dict):
        raise DecisionExportError("snapshot.analysis must be an object")
    actual_keys = set(analysis)
    missing = sorted(_ANALYSIS_REQUIRED_KEYS - actual_keys)
    unexpected = sorted(
        actual_keys - _ANALYSIS_REQUIRED_KEYS - _ANALYSIS_OPTIONAL_KEYS
    )
    if missing or unexpected:
        raise DecisionExportError(
            "snapshot.analysis keys do not match the frozen schema "
            f"(missing={missing}, unexpected={unexpected})"
        )
    if analysis.get("candidate_id") != work_id:
        raise DecisionExportError("snapshot.analysis.candidate_id does not bind work_id")
    if analysis.get("deep_read_status") != "complete":
        raise DecisionExportError("only complete deep-read snapshots can be exported")
    if analysis.get("tier") != tier:
        raise DecisionExportError("snapshot tier does not match analysis tier")
    if analysis.get("score_scale") != "0_to_100":
        raise DecisionExportError("snapshot analysis must use the normalized 0_to_100 scale")

    for field in ("summary_zh", "problem", "method"):
        _require_text(analysis.get(field), field=f"snapshot.analysis.{field}")
    _require_text(
        analysis.get("reproducibility"),
        field="snapshot.analysis.reproducibility",
        allow_empty=True,
    )
    for field in _LIST_TEXT_FIELDS:
        values = analysis.get(field)
        if not isinstance(values, list) or any(
            not isinstance(item, str)
            or not item.strip()
            or _CONTROL_CHARACTER.search(item)
            for item in values
        ):
            raise DecisionExportError(
                f"snapshot.analysis.{field} must be a list of non-empty strings"
            )

    scores = analysis.get("scores")
    if not isinstance(scores, dict):
        raise DecisionExportError("snapshot.analysis.scores must be an object")
    _require_exact_keys(scores, _SCORE_KEYS, field="snapshot.analysis.scores")
    for key, value in scores.items():
        number = _require_number(value, field=f"snapshot.analysis.scores.{key}")
        if not 0 <= number <= 100:
            raise DecisionExportError(
                f"snapshot.analysis.scores.{key} must be between 0 and 100"
            )
    if not math.isclose(
        float(scores["overall"]),
        score,
        rel_tol=0.0,
        abs_tol=1e-9,
    ):
        raise DecisionExportError("snapshot score does not match analysis overall score")

    coverage = analysis.get("coverage")
    if not isinstance(coverage, dict) or coverage.get("complete") is not True:
        raise DecisionExportError("snapshot.analysis.coverage must be complete")
    chunk_total = _require_positive_integer(
        coverage.get("chunk_total"),
        field="snapshot.analysis.coverage.chunk_total",
    )
    indices = coverage.get("chunk_indices")
    if (
        not isinstance(indices, list)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in indices)
        or len(indices) != len(set(indices))
        or sorted(indices) != list(range(chunk_total))
    ):
        raise DecisionExportError(
            "snapshot.analysis.coverage.chunk_indices must cover every chunk exactly once"
        )
    gaps = coverage.get("gaps")
    if not isinstance(gaps, list) or gaps:
        raise DecisionExportError("snapshot.analysis.coverage.gaps must be empty")

    anchors = analysis.get("evidence_anchors")
    if (
        not isinstance(anchors, list)
        or not anchors
        or any(
            not isinstance(anchor, str)
            or not anchor.strip()
            or anchor != anchor.strip()
            or _CONTROL_CHARACTER.search(anchor)
            for anchor in anchors
        )
        or len(anchors) != len(set(anchors))
    ):
        raise DecisionExportError(
            "snapshot.analysis.evidence_anchors must be unique non-empty strings"
        )


def _validate_top_level_coverage(coverage: Any, *, input_sha256: str) -> None:
    if not isinstance(coverage, dict):
        raise DecisionExportError("snapshot.coverage must be an object")
    required = {
        "complete",
        "text_sha256",
        "text_char_count",
        "chunk_total",
        "chunk_done",
        "chunk_indices",
    }
    missing = sorted(required - set(coverage))
    if missing:
        raise DecisionExportError(f"snapshot.coverage is missing fields: {missing}")
    if coverage.get("complete") is not True:
        raise DecisionExportError("snapshot.coverage must be complete")
    if coverage.get("text_sha256") != input_sha256:
        raise DecisionExportError("snapshot.coverage.text_sha256 does not bind input_sha256")
    text_char_count = coverage.get("text_char_count")
    if (
        isinstance(text_char_count, bool)
        or not isinstance(text_char_count, int)
        or text_char_count <= 0
    ):
        raise DecisionExportError(
            "snapshot.coverage.text_char_count must be a positive integer"
        )
    chunk_total = _require_positive_integer(
        coverage.get("chunk_total"),
        field="snapshot.coverage.chunk_total",
    )
    if coverage.get("chunk_done") != chunk_total:
        raise DecisionExportError("snapshot.coverage must record every chunk as done")
    indices = coverage.get("chunk_indices")
    if (
        not isinstance(indices, list)
        or any(isinstance(item, bool) or not isinstance(item, int) for item in indices)
        or sorted(indices) != list(range(chunk_total))
        or len(indices) != len(set(indices))
    ):
        raise DecisionExportError(
            "snapshot.coverage.chunk_indices must cover every chunk exactly once"
        )


def validate_frozen_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached JSON copy of one frozen publication snapshot."""

    if not isinstance(snapshot, Mapping):
        raise DecisionExportError("snapshot must be an object")
    frozen = _validated_json_copy(dict(snapshot), field="snapshot")
    _require_exact_keys(frozen, _SNAPSHOT_KEYS, field="snapshot")
    if frozen.get("schema") != FROZEN_SNAPSHOT_SCHEMA:
        raise DecisionExportError("snapshot schema is unsupported")

    _require_positive_integer(
        frozen.get("analysis_id"),
        field="snapshot.analysis_id",
    )
    work_id = _require_positive_integer(frozen.get("work_id"), field="snapshot.work_id")
    _require_positive_integer(
        frozen.get("document_id"),
        field="snapshot.document_id",
    )
    input_sha256 = _require_sha256(
        frozen.get("input_sha256"),
        field="snapshot.input_sha256",
    )

    citation = frozen.get("citation")
    if not isinstance(citation, dict):
        raise DecisionExportError("snapshot.citation must be an object")
    _require_exact_keys(citation, _CITATION_KEYS, field="snapshot.citation")
    kind = citation.get("kind")
    if kind not in {"paper", "repository"}:
        raise DecisionExportError("snapshot.citation.kind is unsupported")
    _require_text(citation.get("title"), field="snapshot.citation.title")
    year = citation.get("year")
    if year is not None and (
        isinstance(year, bool)
        or not isinstance(year, int)
        or year < 1
        or year > 9999
    ):
        raise DecisionExportError("snapshot.citation.year must be null or a valid year")
    for field in ("doi", "arxiv_id", "github_full_name"):
        _optional_text(citation.get(field), field=f"snapshot.citation.{field}")
    best_url = _optional_text(
        citation.get("best_url"),
        field="snapshot.citation.best_url",
    )
    _validate_url(best_url, field="snapshot.citation.best_url")
    if not isinstance(citation.get("metadata"), dict):
        raise DecisionExportError("snapshot.citation.metadata must be an object")

    tier = _require_text(frozen.get("tier"), field="snapshot.tier")
    if tier not in _TIERS:
        raise DecisionExportError("snapshot.tier is unsupported")
    score = _require_number(frozen.get("score"), field="snapshot.score")
    if not 0 <= score <= 100:
        raise DecisionExportError("snapshot.score must be between 0 and 100")
    _validate_analysis(frozen.get("analysis"), work_id=work_id, tier=tier, score=score)
    _validate_top_level_coverage(frozen.get("coverage"), input_sha256=input_sha256)

    for field in ("provider", "lane", "provenance_status", "analysis_created_at"):
        _require_text(frozen.get(field), field=f"snapshot.{field}")
    _optional_text(frozen.get("model"), field="snapshot.model")
    return frozen


def snapshot_sha256(snapshot: Mapping[str, Any]) -> str:
    frozen = validate_frozen_snapshot(snapshot)
    return _sha256_text(_canonical_json(frozen))


def _literal_occurrences(text: str, needle: str) -> list[int]:
    positions: list[int] = []
    start = 0
    while True:
        index = text.find(needle, start)
        if index < 0:
            return positions
        positions.append(index)
        start = index + 1


def build_evidence_context(
    snapshot: Mapping[str, Any],
    text: str,
    input_sha256: str,
) -> dict[str, Any]:
    """Resolve every frozen evidence anchor against one exact text revision."""

    frozen = validate_frozen_snapshot(snapshot)
    if not isinstance(text, str):
        raise DecisionExportError("text must be a string")
    supplied_sha256 = _require_sha256(input_sha256, field="input_sha256")
    if supplied_sha256 != frozen["input_sha256"]:
        raise DecisionExportError("input_sha256 does not match the frozen snapshot")
    actual_sha256 = _sha256_text(text)
    if actual_sha256 != supplied_sha256:
        raise DecisionExportError("text bytes do not match input_sha256")
    if len(text) != int(frozen["coverage"]["text_char_count"]):
        raise DecisionExportError("text length does not match frozen coverage")

    contexts: list[dict[str, Any]] = []
    for anchor in frozen["analysis"]["evidence_anchors"]:
        character_match = _CHARACTER_ANCHOR.fullmatch(anchor)
        if character_match is not None:
            start = int(character_match.group(1))
            end = int(character_match.group(2))
            if start >= end or end > len(text):
                raise DecisionExportError(
                    f"evidence anchor is outside the frozen text revision: {anchor}"
                )
            exact = text[start:end]
            anchor_kind = "character_span"
        else:
            if anchor.startswith("characters:"):
                raise DecisionExportError(f"malformed character evidence anchor: {anchor}")
            occurrences = _literal_occurrences(text, anchor)
            if not occurrences:
                raise DecisionExportError(
                    f"evidence anchor is absent from the frozen text revision: {anchor}"
                )
            if len(occurrences) != 1:
                raise DecisionExportError(
                    f"evidence anchor is ambiguous in the frozen text revision: {anchor}"
                )
            start = occurrences[0]
            end = start + len(anchor)
            exact = text[start:end]
            anchor_kind = "literal_substring"

        context_start = max(0, start - 240)
        context_end = min(len(text), end + 240)
        context = text[context_start:context_end]
        contexts.append(
            {
                "anchor": anchor,
                "kind": anchor_kind,
                "anchor_start": start,
                "anchor_end": end,
                "exact_substring": exact,
                "context_start": context_start,
                "context_end": context_end,
                "context": context,
                "context_sha256": _sha256_text(context),
            }
        )

    return {
        "schema": EVIDENCE_CONTEXT_SCHEMA,
        "source": {
            "work_id": frozen["work_id"],
            "analysis_id": frozen["analysis_id"],
            "document_id": frozen["document_id"],
            "input_sha256": supplied_sha256,
            "text_char_count": len(text),
            "snapshot_sha256": _sha256_text(_canonical_json(frozen)),
        },
        "anchors": contexts,
    }


def _single_line(value: str) -> str:
    return " ".join(value.split())


def _authors(citation: Mapping[str, Any]) -> list[str]:
    metadata = citation.get("metadata")
    if not isinstance(metadata, dict):
        return []
    candidates: list[Any] = []
    if isinstance(metadata.get("authors"), list):
        candidates.extend(metadata["authors"])
    variants = metadata.get("source_variants")
    if isinstance(variants, dict):
        for source in sorted(variants):
            variant = variants[source]
            if isinstance(variant, dict) and isinstance(variant.get("authors"), list):
                candidates.extend(variant["authors"])
    authors: list[str] = []
    for value in candidates:
        if not isinstance(value, str):
            continue
        normalized = _single_line(value)
        if normalized and normalized not in authors:
            authors.append(normalized)
    return authors


def _citation_key(snapshot: Mapping[str, Any]) -> str:
    return f"r3_work_{int(snapshot['work_id'])}"


def _decision_note(decision: Mapping[str, Any] | None) -> str | None:
    if decision is None:
        return None
    frozen = _validated_json_copy(dict(decision), field="decision")
    if not isinstance(frozen, dict):
        raise DecisionExportError("decision must be an object")
    return "R3 decision: " + _canonical_json(frozen)


def _csl_record(snapshot: Mapping[str, Any], decision: Mapping[str, Any] | None) -> dict[str, Any]:
    citation = snapshot["citation"]
    result: dict[str, Any] = {
        "id": _citation_key(snapshot),
        "type": "article" if citation["kind"] == "paper" else "software",
        "title": _single_line(citation["title"]),
    }
    authors = _authors(citation)
    if authors:
        result["author"] = [{"literal": author} for author in authors]
    if citation["year"] is not None:
        result["issued"] = {"date-parts": [[int(citation["year"])]]}
    if citation["doi"] is not None:
        result["DOI"] = citation["doi"]
    if citation["best_url"] is not None:
        result["URL"] = citation["best_url"]
    if citation["arxiv_id"] is not None:
        result["archive"] = "arXiv"
        result["archive_location"] = citation["arxiv_id"]
    note = _decision_note(decision)
    if note is not None:
        result["note"] = note
    return result


_BIBTEX_ESCAPE = {
    "\\": r"\textbackslash{}",
    "{": r"\{",
    "}": r"\}",
    "#": r"\#",
    "$": r"\$",
    "%": r"\%",
    "&": r"\&",
    "_": r"\_",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def _bibtex_escape(value: str) -> str:
    return "".join(_BIBTEX_ESCAPE.get(character, character) for character in value)


def _render_bibtex(
    snapshot: Mapping[str, Any],
    decision: Mapping[str, Any] | None,
) -> str:
    citation = snapshot["citation"]
    fields: list[tuple[str, str]] = [
        ("title", _single_line(citation["title"])),
    ]
    authors = _authors(citation)
    if authors:
        fields.append(("author", " and ".join(authors)))
    if citation["year"] is not None:
        fields.append(("year", str(citation["year"])))
    if citation["doi"] is not None:
        fields.append(("doi", citation["doi"]))
    if citation["arxiv_id"] is not None:
        fields.extend(
            [
                ("eprint", citation["arxiv_id"]),
                ("archivePrefix", "arXiv"),
            ]
        )
    if citation["best_url"] is not None:
        fields.append(("url", citation["best_url"]))
    note = _decision_note(decision)
    if note is not None:
        fields.append(("note", note))

    entry_type = "article" if citation["kind"] == "paper" else "misc"
    lines = [f"@{entry_type}{{{_citation_key(snapshot)},"]
    for index, (name, value) in enumerate(fields):
        comma = "," if index < len(fields) - 1 else ""
        lines.append(f"  {name} = {{{_bibtex_escape(_single_line(value))}}}{comma}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_ris(
    snapshot: Mapping[str, Any],
    decision: Mapping[str, Any] | None,
) -> str:
    citation = snapshot["citation"]
    lines = [
        "TY  - " + ("JOUR" if citation["kind"] == "paper" else "COMP"),
        f"ID  - {_citation_key(snapshot)}",
        f"TI  - {_single_line(citation['title'])}",
    ]
    lines.extend(f"AU  - {author}" for author in _authors(citation))
    if citation["year"] is not None:
        lines.append(f"PY  - {citation['year']}")
    if citation["doi"] is not None:
        lines.append(f"DO  - {_single_line(citation['doi'])}")
    if citation["arxiv_id"] is not None:
        lines.append(f"AN  - arXiv:{_single_line(citation['arxiv_id'])}")
    if citation["best_url"] is not None:
        lines.append(f"UR  - {_single_line(citation['best_url'])}")
    note = _decision_note(decision)
    if note is not None:
        lines.append(f"N1  - {_single_line(note)}")
    lines.append("ER  -")
    return "\n".join(lines) + "\n"


def _markdown_code(value: str) -> str:
    longest = max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)
    fence = "`" * max(1, longest + 1)
    padding = " " if value.startswith("`") or value.endswith("`") else ""
    return f"{fence}{padding}{value}{padding}{fence}"


def _render_markdown(
    snapshot: Mapping[str, Any],
    decision: Mapping[str, Any] | None,
) -> str:
    citation = snapshot["citation"]
    analysis = snapshot["analysis"]
    authors = _authors(citation)
    snapshot_hash = _sha256_text(_canonical_json(snapshot))
    lines = [
        "# R3 Evidence Card",
        "",
        f"- Citation key: {_markdown_code(_citation_key(snapshot))}",
        f"- Title: {_markdown_code(_single_line(citation['title']))}",
        f"- Kind: {_markdown_code(citation['kind'])}",
        f"- Work ID: {snapshot['work_id']}",
        f"- Analysis ID: {snapshot['analysis_id']}",
        f"- Document ID: {snapshot['document_id']}",
        f"- Input SHA-256: {_markdown_code(snapshot['input_sha256'])}",
        f"- Snapshot SHA-256: {_markdown_code(snapshot_hash)}",
        f"- Provider: {_markdown_code(snapshot['provider'])}",
        f"- Tier: {_markdown_code(snapshot['tier'])}",
        f"- Score: {float(snapshot['score']):.2f}",
        f"- Authors: {', '.join(_markdown_code(author) for author in authors) if authors else 'not provided in frozen snapshot'}",
        f"- Year: {citation['year'] if citation['year'] is not None else 'not provided in frozen snapshot'}",
        f"- DOI: {_markdown_code(citation['doi']) if citation['doi'] is not None else 'not provided in frozen snapshot'}",
    ]
    if citation["arxiv_id"] is not None:
        lines.append(f"- arXiv: {_markdown_code(citation['arxiv_id'])}")
    if citation["github_full_name"] is not None:
        lines.append(f"- GitHub: {_markdown_code(citation['github_full_name'])}")
    if citation["best_url"] is not None:
        lines.append(f"- URL: {_markdown_code(citation['best_url'])}")

    lines.extend(
        [
            "",
            "## Summary",
            "",
            analysis["summary_zh"],
            "",
            "## Problem",
            "",
            analysis["problem"],
            "",
            "## Method",
            "",
            analysis["method"],
            "",
            "## Evidence anchors",
            "",
            *[
                f"- {_markdown_code(anchor)}"
                for anchor in analysis["evidence_anchors"]
            ],
            "",
            "## Limitations",
            "",
            *(
                [f"- {value}" for value in analysis["limitations"]]
                or ["- None recorded in the frozen analysis."]
            ),
            "",
            "## Uncertainties",
            "",
            *(
                [f"- {value}" for value in analysis["uncertainties"]]
                or ["- None recorded in the frozen analysis."]
            ),
        ]
    )
    if decision is not None:
        decision_copy = _validated_json_copy(dict(decision), field="decision")
        lines.extend(
            [
                "",
                "## Decision",
                "",
                "```json",
                _canonical_json(decision_copy, pretty=True),
                "```",
            ]
        )
    return "\n".join(lines) + "\n"


def _normalize_format(value: str) -> str:
    if not isinstance(value, str):
        raise DecisionExportError("format must be a string")
    normalized = value.strip().casefold()
    normalized = _FORMAT_ALIASES.get(normalized, normalized)
    if normalized not in _FORMATS:
        raise DecisionExportError(
            "format must be one of: " + ", ".join(sorted(_FORMATS))
        )
    return normalized


def safe_export_filename(
    snapshot: Mapping[str, Any],
    format: str,
) -> str:
    frozen = validate_frozen_snapshot(snapshot)
    normalized_format = _normalize_format(format)
    extension = _FORMATS[normalized_format][0]
    title = unicodedata.normalize("NFKD", frozen["citation"]["title"])
    ascii_title = title.encode("ascii", "ignore").decode("ascii")
    slug = _UNSAFE_FILENAME.sub("-", ascii_title.strip()).strip("-._")
    slug = (slug or "work")[:64].rstrip("-._") or "work"
    filename = f"r3-{frozen['work_id']}-{slug}.{extension}"
    if (
        filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or _CONTROL_CHARACTER.search(filename)
    ):
        raise DecisionExportError("generated export filename is unsafe")
    return filename


def render_export(
    snapshot: Mapping[str, Any],
    decision: Mapping[str, Any] | None,
    format: str,
) -> ExportArtifact:
    """Render one deterministic, read-only export from a frozen snapshot."""

    frozen = validate_frozen_snapshot(snapshot)
    if decision is not None and not isinstance(decision, Mapping):
        raise DecisionExportError("decision must be an object or null")
    decision_copy = (
        _validated_json_copy(dict(decision), field="decision")
        if decision is not None
        else None
    )
    normalized_format = _normalize_format(format)
    if normalized_format == "csl-json":
        text = _canonical_json([_csl_record(frozen, decision_copy)], pretty=True) + "\n"
    elif normalized_format == "bibtex":
        text = _render_bibtex(frozen, decision_copy)
    elif normalized_format == "ris":
        text = _render_ris(frozen, decision_copy)
    else:
        text = _render_markdown(frozen, decision_copy)
    content = text.encode("utf-8")
    return ExportArtifact(
        format=normalized_format,
        content=content,
        content_type=_FORMATS[normalized_format][1],
        filename=safe_export_filename(frozen, normalized_format),
        sha256=hashlib.sha256(content).hexdigest(),
    )


__all__ = [
    "DecisionExportError",
    "EVIDENCE_CONTEXT_SCHEMA",
    "ExportArtifact",
    "FROZEN_SNAPSHOT_SCHEMA",
    "build_evidence_context",
    "render_export",
    "safe_export_filename",
    "snapshot_sha256",
    "validate_frozen_snapshot",
]
