from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any


NORMALIZED_UNIQUE_MATCH = "nfkc_casefold_whitespace_unique"
LITERAL_MATCH = "literal_substring"
_DOCUMENT_MARKER = re.compile(r"^=== (?:PAGE|FILE):?.*?===$", re.MULTILINE)


class EvidenceExcerptError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CanonicalEvidenceExcerpt:
    excerpt: str
    model_excerpt: str
    match_method: str
    provenance: str


def normalized_evidence_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def evidence_anchor_region(
    chunk_text: str,
    anchor: str,
    allowed_anchors: list[str],
    *,
    trusted_anchor_regions: list[dict[str, Any]] | None = None,
) -> str:
    normalized_anchor = anchor.strip()
    normalized_allowed = [
        str(value).strip() for value in allowed_anchors if str(value).strip()
    ]
    if normalized_anchor not in normalized_allowed:
        raise EvidenceExcerptError("unverifiable_anchor")
    if normalized_anchor.startswith("characters:"):
        return chunk_text

    if trusted_anchor_regions is not None:
        matches: list[tuple[int, int]] = []
        for record in trusted_anchor_regions:
            if not isinstance(record, dict):
                raise EvidenceExcerptError("trusted_anchor_region_invalid")
            record_anchor = record.get("anchor")
            start = record.get("start")
            end = record.get("end")
            if (
                not isinstance(record_anchor, str)
                or type(start) is not int
                or type(end) is not int
                or not 0 <= start < end <= len(chunk_text)
            ):
                raise EvidenceExcerptError("trusted_anchor_region_invalid")
            if record_anchor.strip() == normalized_anchor:
                matches.append((start, end))
        if len(matches) > 1:
            raise EvidenceExcerptError("anchor_ambiguous")
        if not matches:
            raise EvidenceExcerptError("anchor_absent_from_chunk")
        start, end = matches[0]
        return chunk_text[start:end]

    markers = list(_DOCUMENT_MARKER.finditer(chunk_text))
    matches = [match for match in markers if match.group(0) == normalized_anchor]
    if len(matches) > 1:
        raise EvidenceExcerptError("anchor_ambiguous")
    if matches:
        start = matches[0].start()
        end = next(
            (
                marker.start()
                for marker in markers
                if marker.start() > matches[0].start()
            ),
            len(chunk_text),
        )
        return chunk_text[start:end]

    # split_text carries the marker immediately preceding a chunk as its first
    # anchor. The marker itself can therefore be outside this overlapped chunk.
    if normalized_allowed and normalized_anchor == normalized_allowed[0]:
        end = markers[0].start() if markers else len(chunk_text)
        return chunk_text[:end]
    raise EvidenceExcerptError("anchor_absent_from_chunk")


def _normalized_text_with_source_spans(
    value: str,
) -> tuple[str, list[tuple[int, int]]]:
    characters: list[str] = []
    source_spans: list[tuple[int, int]] = []
    pending_whitespace: tuple[int, int] | None = None

    for source_index, source_character in enumerate(value):
        transformed = unicodedata.normalize("NFKC", source_character).casefold()
        for character in transformed:
            if character.isspace():
                if characters:
                    if pending_whitespace is None:
                        pending_whitespace = (source_index, source_index + 1)
                    else:
                        pending_whitespace = (
                            pending_whitespace[0],
                            source_index + 1,
                        )
                continue
            if pending_whitespace is not None:
                characters.append(" ")
                source_spans.append(pending_whitespace)
                pending_whitespace = None
            characters.append(character)
            source_spans.append((source_index, source_index + 1))

    return "".join(characters), source_spans


def canonicalize_evidence_excerpt(
    model_excerpt: str,
    chunk_text: str,
    *,
    word_limit: int = 25,
    character_limit: int = 320,
) -> CanonicalEvidenceExcerpt:
    if not model_excerpt or not model_excerpt.strip():
        raise EvidenceExcerptError("excerpt_absent")

    if model_excerpt in chunk_text:
        canonical = model_excerpt
        match_method = LITERAL_MATCH
        provenance = "provider_literal_substring"
    else:
        normalized_excerpt = normalized_evidence_text(model_excerpt)
        if not normalized_excerpt:
            raise EvidenceExcerptError("excerpt_absent")
        normalized_chunk = normalized_evidence_text(chunk_text)
        first = normalized_chunk.find(normalized_excerpt)
        if first < 0:
            raise EvidenceExcerptError("excerpt_absent")
        if normalized_chunk.find(normalized_excerpt, first + 1) >= 0:
            raise EvidenceExcerptError("excerpt_ambiguous")

        mapped_chunk, source_spans = _normalized_text_with_source_spans(chunk_text)
        if mapped_chunk != normalized_chunk:
            raise EvidenceExcerptError("excerpt_unmappable")
        last = first + len(normalized_excerpt) - 1
        if first >= len(source_spans) or last >= len(source_spans):
            raise EvidenceExcerptError("excerpt_unmappable")
        source_start = source_spans[first][0]
        source_end = source_spans[last][1]
        canonical = chunk_text[source_start:source_end]
        if normalized_evidence_text(canonical) != normalized_excerpt:
            raise EvidenceExcerptError("excerpt_unmappable")
        match_method = NORMALIZED_UNIQUE_MATCH
        provenance = "provider_normalized_unique_projection_to_chunk_literal"

    if len(canonical.split()) > word_limit:
        raise EvidenceExcerptError("excerpt_too_long")
    if len(canonical) > character_limit:
        raise EvidenceExcerptError("excerpt_too_long")
    return CanonicalEvidenceExcerpt(
        excerpt=canonical,
        model_excerpt=model_excerpt,
        match_method=match_method,
        provenance=provenance,
    )
