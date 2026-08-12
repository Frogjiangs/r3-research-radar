from __future__ import annotations

import hashlib
import json
import unittest

from r3radar.decision import (
    DecisionExportError,
    ExportArtifact,
    build_evidence_context,
    render_export,
    validate_frozen_snapshot,
)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def frozen_snapshot(
    text: str,
    *,
    title: str = "Workflow-Aware Cache Reuse",
    authors: list[str] | None = None,
    year: int | None = 2026,
    doi: str | None = "10.1234/r3.2026.7",
    evidence_anchors: list[str] | None = None,
) -> dict:
    input_sha256 = sha256_text(text)
    anchors = evidence_anchors or ["=== PAGE 1 ===", "Exact cache reuse evidence."]
    scores = {
        "novelty": 80.0,
        "r3_relevance": 90.0,
        "evidence_strength": 85.0,
        "reuse_signal_value": 90.0,
        "implementability": 75.0,
        "overall": 85.0,
    }
    analysis_coverage = {
        "chunk_total": 1,
        "chunk_indices": [0],
        "complete": True,
        "gaps": [],
    }
    return {
        "schema": "r3/publication-item-snapshot/v1",
        "analysis_id": 17,
        "work_id": 7,
        "input_sha256": input_sha256,
        "document_id": 11,
        "citation": {
            "kind": "paper",
            "title": title,
            "year": year,
            "doi": doi,
            "arxiv_id": "2607.01234",
            "github_full_name": None,
            "best_url": "https://example.org/paper",
            "metadata": {"authors": authors} if authors is not None else {},
        },
        "analysis": {
            "candidate_id": 7,
            "deep_read_status": "complete",
            "coverage": analysis_coverage,
            "summary_zh": "该工作分析工作流感知缓存复用。",
            "problem": "重复工作流上下文浪费计算。",
            "method": "按步骤识别可复用上下文。",
            "evaluation": ["离线复现实验"],
            "limitations": ["尚未在线验证"],
            "r3_relationship": ["直接支持 R3 决策"],
            "actionable_ideas": ["构造最小回放"],
            "overlap_risks": [],
            "reproducibility": "提供静态实验说明。",
            "score_scale": "0_to_100",
            "scores": scores,
            "tier": "must_read",
            "evidence_anchors": anchors,
            "uncertainties": ["生产负载收益未知"],
        },
        "coverage": {
            "complete": True,
            "source_coverage": {"complete": True},
            "text_path": "frozen.txt",
            "text_sha256": input_sha256,
            "text_char_count": len(text),
            "chunk_total": 1,
            "chunk_done": 1,
            "chunk_indices": [0],
        },
        "provider": "codex_cli",
        "model": "gpt-test",
        "tier": "must_read",
        "score": 85.0,
        "lane": "frontier",
        "provenance_status": "append_only",
        "analysis_created_at": "2026-07-30T08:00:00+00:00",
    }


class FrozenSnapshotValidationTests(unittest.TestCase):
    text = (
        "=== PAGE 1 ===\n"
        "Exact cache reuse evidence.\n"
        "A deterministic follow-up sentence.\n"
    )

    def test_strict_snapshot_integrity_accepts_detached_valid_copy(self) -> None:
        original = frozen_snapshot(self.text)

        validated = validate_frozen_snapshot(original)

        self.assertEqual(validated, original)
        self.assertIsNot(validated, original)
        self.assertIsNot(validated["analysis"], original["analysis"])

    def test_missing_or_cross_revision_fields_fail_closed(self) -> None:
        missing = frozen_snapshot(self.text)
        missing.pop("document_id")
        with self.assertRaisesRegex(DecisionExportError, "missing=.*document_id"):
            validate_frozen_snapshot(missing)

        mismatched_candidate = frozen_snapshot(self.text)
        mismatched_candidate["analysis"]["candidate_id"] = 999
        with self.assertRaisesRegex(DecisionExportError, "does not bind work_id"):
            validate_frozen_snapshot(mismatched_candidate)

        mismatched_revision = frozen_snapshot(self.text)
        mismatched_revision["coverage"]["text_sha256"] = "0" * 64
        with self.assertRaisesRegex(DecisionExportError, "does not bind input_sha256"):
            validate_frozen_snapshot(mismatched_revision)


class EvidenceContextTests(unittest.TestCase):
    def test_literal_and_character_anchors_resolve_to_exact_substrings(self) -> None:
        text = "prefix\n=== PAGE 1 ===\nExact evidence.\nsuffix"
        character_start = text.index("Exact evidence.")
        character_end = character_start + len("Exact evidence.")
        snapshot = frozen_snapshot(
            text,
            evidence_anchors=[
                "=== PAGE 1 ===",
                f"characters:{character_start}-{character_end}",
            ],
        )

        result = build_evidence_context(snapshot, text, sha256_text(text))

        self.assertEqual(result["source"]["input_sha256"], sha256_text(text))
        self.assertEqual(len(result["anchors"]), 2)
        marker, character = result["anchors"]
        self.assertEqual(marker["exact_substring"], "=== PAGE 1 ===")
        self.assertEqual(
            text[marker["context_start"] : marker["context_end"]],
            marker["context"],
        )
        self.assertEqual(character["exact_substring"], "Exact evidence.")
        self.assertEqual(character["kind"], "character_span")

    def test_wrong_revision_missing_and_ambiguous_anchors_fail_closed(self) -> None:
        unique_text = "prefix Exact evidence. suffix"
        unique = frozen_snapshot(
            unique_text,
            evidence_anchors=["Exact evidence."],
        )
        with self.assertRaisesRegex(DecisionExportError, "does not match"):
            build_evidence_context(unique, unique_text, "0" * 64)

        absent = frozen_snapshot(unique_text, evidence_anchors=["missing"])
        with self.assertRaisesRegex(DecisionExportError, "is absent"):
            build_evidence_context(absent, unique_text, sha256_text(unique_text))

        repeated_text = "repeat then repeat"
        ambiguous = frozen_snapshot(repeated_text, evidence_anchors=["repeat"])
        with self.assertRaisesRegex(DecisionExportError, "is ambiguous"):
            build_evidence_context(
                ambiguous,
                repeated_text,
                sha256_text(repeated_text),
            )


class DeterministicExportTests(unittest.TestCase):
    text = (
        "=== PAGE 1 ===\n"
        "Exact cache reuse evidence.\n"
        "A deterministic follow-up sentence.\n"
    )

    def test_all_formats_are_byte_stable_and_have_safe_metadata(self) -> None:
        snapshot = frozen_snapshot(
            self.text,
            title="../Unsafe\\Title: Cache?*",
            authors=["Ada Lovelace", "张三"],
        )
        decision = {
            "status": "saved",
            "reason": "Supports the next controlled experiment.",
            "decided_at": "2026-07-30T08:30:00+00:00",
        }

        for export_format in ("csl-json", "bibtex", "ris", "markdown"):
            with self.subTest(export_format=export_format):
                first = render_export(snapshot, decision, export_format)
                second = render_export(snapshot, decision, export_format)
                self.assertIsInstance(first, ExportArtifact)
                self.assertEqual(first, second)
                self.assertEqual(first.sha256, hashlib.sha256(first.content).hexdigest())
                self.assertNotIn("/", first.filename)
                self.assertNotIn("\\", first.filename)
                self.assertNotIn("..", first.filename)
                self.assertIn("charset=utf-8", first.content_type)
                self.assertNotIn(b"generated_at", first.content)

    def test_real_citation_fields_are_preserved(self) -> None:
        snapshot = frozen_snapshot(self.text, authors=["Ada Lovelace", "张三"])

        csl = json.loads(render_export(snapshot, None, "csl-json").content)
        self.assertEqual(csl[0]["author"], [{"literal": "Ada Lovelace"}, {"literal": "张三"}])
        self.assertEqual(csl[0]["issued"], {"date-parts": [[2026]]})
        self.assertEqual(csl[0]["DOI"], "10.1234/r3.2026.7")

        bibtex = render_export(snapshot, None, "bibtex").content.decode("utf-8")
        self.assertIn("author = {Ada Lovelace and 张三}", bibtex)
        self.assertIn("year = {2026}", bibtex)
        self.assertIn("doi = {10.1234/r3.2026.7}", bibtex)

        ris = render_export(snapshot, None, "ris").content.decode("utf-8")
        self.assertIn("AU  - Ada Lovelace\n", ris)
        self.assertIn("AU  - 张三\n", ris)
        self.assertIn("PY  - 2026\n", ris)
        self.assertIn("DO  - 10.1234/r3.2026.7\n", ris)

    def test_missing_authors_year_and_doi_are_omitted_not_invented(self) -> None:
        snapshot = frozen_snapshot(
            self.text,
            authors=None,
            year=None,
            doi=None,
        )

        csl = json.loads(render_export(snapshot, None, "csl-json").content)[0]
        self.assertNotIn("author", csl)
        self.assertNotIn("issued", csl)
        self.assertNotIn("DOI", csl)

        bibtex = render_export(snapshot, None, "bibtex").content.decode("utf-8")
        self.assertNotIn("\n  author =", bibtex)
        self.assertNotIn("\n  year =", bibtex)
        self.assertNotIn("\n  doi =", bibtex)

        ris = render_export(snapshot, None, "ris").content.decode("utf-8")
        self.assertNotIn("\nAU  -", ris)
        self.assertNotIn("\nPY  -", ris)
        self.assertNotIn("\nDO  -", ris)

        markdown = render_export(snapshot, None, "markdown").content.decode("utf-8")
        self.assertIn("Authors: not provided in frozen snapshot", markdown)
        self.assertIn("Year: not provided in frozen snapshot", markdown)
        self.assertIn("DOI: not provided in frozen snapshot", markdown)

    def test_unsupported_format_and_non_json_decision_are_rejected(self) -> None:
        snapshot = frozen_snapshot(self.text)
        with self.assertRaisesRegex(DecisionExportError, "format must be one of"):
            render_export(snapshot, None, "docx")
        with self.assertRaisesRegex(DecisionExportError, "deterministic JSON"):
            render_export(snapshot, {"bad": object()}, "markdown")


if __name__ == "__main__":
    unittest.main()
