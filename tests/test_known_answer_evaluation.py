from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from r3radar.__main__ import main
from r3radar.known_answers import (
    KNOWN_ANSWER_RECEIPT_SCHEMA,
    KNOWN_ANSWER_SET_SCHEMA,
    KnownAnswerError,
    evaluate_external_known_answers,
    freeze_external_known_answer_set,
    validate_external_known_answer_set,
    validate_known_answer_evaluation_receipt,
)


DOMAINS = (
    "agent workflow cache retention",
    "embodied companion safety for older adults",
    "single-cell perturbation response prediction",
    "urban heat exposure and causal adaptation",
)


def _identity(index: int) -> dict:
    if index % 6 == 0:
        return {
            "status": "verified",
            "kind": "repository",
            "canonical_id_type": "github",
            "canonical_id": f"research-lab/long-workflow-{index}",
            "version": f"{index:040x}",
            "version_required": True,
        }
    if index % 6 == 1:
        return {
            "status": "verified",
            "kind": "paper",
            "canonical_id_type": "arxiv",
            "canonical_id": f"2608.{10000 + index}",
            "version": "v2",
            "version_required": True,
        }
    return {
        "status": "verified",
        "kind": "paper",
        "canonical_id_type": "doi",
        "canonical_id": f"10.9999/example.invalid.{index}",
        "version": None,
        "version_required": False,
    }


def _long_description(index: int) -> str:
    domain = DOMAINS[index % len(DOMAINS)]
    paragraph = (
        f"Synthetic-realistic study {index} investigates {domain} across a multi-stage "
        "research workflow. It defines a population or workload, a decision object, a "
        "future observation window, competing baselines, ablations, failure conditions, "
        "and an evidence-preserving reproduction handoff. The protocol records source "
        "identity, immutable revision when relevant, inaccessible evidence, negative "
        "results, subgroup risks, and the time needed for a researcher to verify claims. "
    )
    return paragraph * 9


def _draft_set(*, unknown_judgment_index: int | None = None, missing_identity_index: int | None = None) -> dict:
    source_ids = [f"external-artifact-{group}" for group in range(4)]
    items = []
    for index in range(24):
        category = (
            "user_prior_list",
            "advisor_or_independent_researcher",
            "independent_database",
            "citation_chasing",
        )[index % 4]
        basis = (
            "documented_before_r3_run",
            "nominated_by_external_researcher",
            "independent_query_or_export",
            "citation_chasing_from_external_seed",
        )[index % 4]
        if index == missing_identity_index:
            identity = {
                "status": "missing",
                "kind": "paper",
                "canonical_id_type": None,
                "canonical_id": None,
                "version": None,
                "version_required": False,
            }
        else:
            identity = _identity(index)
        if index == unknown_judgment_index:
            judgment = {
                "status": "unknown",
                "relevance_grade": None,
                "must_read": None,
                "judged_by": None,
                "judged_at": None,
                "notes": "No independent assessor answer is available.",
            }
        else:
            grade = 3 if index in {1, 6, 12, 13, 18} else (2 if index % 3 else 1)
            judgment = {
                "status": "verified",
                "relevance_grade": grade,
                "must_read": grade == 3,
                "judged_by": "synthetic-fixture-assessor-not-a-human-claim",
                "judged_at": "2026-08-09T10:00:00+08:00",
                "notes": "Test-only answer for contract behavior; never a real Gold label.",
            }
        items.append(
            {
                "item_id": f"external-{index:02d}",
                "title": (
                    "Same visible title with version-specific evidence"
                    if index in {12, 13}
                    else f"{DOMAINS[index % 4].title()}: longitudinal protocol {index}"
                ),
                "abstract_or_description": _long_description(index),
                "split": "development" if index < 12 else "evaluation",
                "source": {
                    "category": category,
                    "artifact_id": source_ids[index % 4],
                    "reference_url": f"https://example.invalid/external-source/{index}",
                    "collected_at": "2026-08-08T09:00:00+08:00",
                    "independence_basis": basis,
                },
                "identity": identity,
                "judgment": judgment,
                "duplicate_cluster_id": None,
            }
        )
    # Same title and same arXiv work, but distinct frozen versions. Titles must never match them.
    for index, version in ((12, "v1"), (13, "v2")):
        items[index]["identity"] = {
            "status": "verified",
            "kind": "paper",
            "canonical_id_type": "arxiv",
            "canonical_id": "2608.42424",
            "version": version,
            "version_required": True,
        }
    return {
        "schema": KNOWN_ANSWER_SET_SCHEMA,
        "set_id": "external-cross-domain-24-v1",
        "title": "Synthetic realistic cross-domain known-answer contract fixture",
        "created_at": "2026-08-08T08:00:00+08:00",
        "collection_provenance": {
            "created_by": "fixture-builder",
            "source_artifact_ids": source_ids,
            "r3_candidate_artifact_ids": ["r3-run-candidate-export-001"],
            "independence_note": (
                "Each item is attributed to a pre-existing or independently collected "
                "artifact; the fixture explicitly excludes the R3 candidate export."
            ),
        },
        "split_policy": {
            "assignment_basis": "Domain-stratified alternating allocation fixed before candidate ranking.",
            "development_use": "May be inspected for parser and ranking development.",
            "evaluation_use": "Must remain unseen until the candidate pool is frozen.",
            "assignment_sha256": None,
        },
        "freeze": {"status": "draft", "frozen_at": None, "frozen_by": None, "set_sha256": None},
        "items": items,
    }


def _frozen_set(**kwargs) -> dict:
    return freeze_external_known_answer_set(
        _draft_set(**kwargs),
        frozen_at="2026-08-09T12:00:00+08:00",
        frozen_by="fixture-freezer",
    )


def _candidate(item: dict, rank: int, **overrides) -> dict:
    candidate = {
        "candidate_id": f"candidate-{rank:02d}",
        "rank": rank,
        "title": item["title"],
        "identity": copy.deepcopy(item["identity"]),
        "duplicate_cluster_id": None,
        "novelty_status": "novel" if rank % 2 else "known",
        "diversity_group": DOMAINS[(rank - 1) % 4],
        "verification_minutes": 1.5 + rank / 10,
    }
    candidate.update(overrides)
    return candidate


def _context(**overrides) -> dict:
    context = {
        "candidate_run_id": "independent-candidate-run-20260810",
        "candidate_pool_id": "frozen-candidate-pool-001",
        "candidate_pool_frozen_at": "2026-08-10T08:00:00+08:00",
        "candidate_source_artifact_ids": ["r3-run-candidate-export-002"],
        "origin_known_answer_set_ids": [],
        "known_answer_splits_accessed_before_run": ["development"],
        "ranking_method": "r3-static-ranking-policy-v1",
    }
    context.update(overrides)
    return context


class ExternalKnownAnswerContractTests(unittest.TestCase):
    def test_freezes_24_long_cross_domain_items_and_detects_split_mutation(self) -> None:
        frozen = _frozen_set()
        self.assertEqual(len(frozen["items"]), 24)
        self.assertGreater(sum(len(item["abstract_or_description"]) for item in frozen["items"]), 100_000)
        self.assertRegex(frozen["freeze"]["set_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(frozen["split_policy"]["assignment_sha256"], r"^[0-9a-f]{64}$")
        mutated = copy.deepcopy(frozen)
        mutated["items"][0]["split"] = "evaluation"
        with self.assertRaisesRegex(KnownAnswerError, "assignment digest"):
            validate_external_known_answer_set(mutated, require_frozen=True)

    def test_rejects_too_small_and_self_sourced_sets(self) -> None:
        small = _draft_set()
        small["items"] = small["items"][:19]
        with self.assertRaisesRegex(KnownAnswerError, "20-35"):
            validate_external_known_answer_set(small)

        self_sourced = _draft_set()
        self_sourced["collection_provenance"]["r3_candidate_artifact_ids"].append("external-artifact-0")
        with self.assertRaisesRegex(KnownAnswerError, "self-sourced"):
            validate_external_known_answer_set(self_sourced)

    def test_rejects_partial_missing_identity_and_false_human_answer_shape(self) -> None:
        partial = _draft_set()
        partial["items"][5]["identity"] = {
            "status": "missing",
            "kind": "paper",
            "canonical_id_type": "doi",
            "canonical_id": None,
            "version": None,
            "version_required": False,
        }
        with self.assertRaisesRegex(KnownAnswerError, "partial identifiers"):
            validate_external_known_answer_set(partial)

        unknown = _draft_set(unknown_judgment_index=19)
        unknown["items"][19]["judgment"]["must_read"] = False
        with self.assertRaisesRegex(KnownAnswerError, "must not contain an answer"):
            validate_external_known_answer_set(unknown)


class ExternalKnownAnswerEvaluationTests(unittest.TestCase):
    def test_exact_version_aware_matching_ignores_same_title(self) -> None:
        frozen = _frozen_set()
        evaluation_items = frozen["items"][12:]
        candidates = [_candidate(item, rank) for rank, item in enumerate(evaluation_items, 1)]
        # Keep the visible title but replace the v1 identity with v3. The v2 item still matches.
        candidates[0]["identity"]["version"] = "v3"
        receipt = evaluate_external_known_answers(
            frozen,
            split="evaluation",
            candidates=candidates,
            evaluation_context=_context(),
            evaluator_identity="offline-fixture-runner",
            evaluated_at="2026-08-10T09:00:00+08:00",
        )
        by_item = {row["item_id"]: row for row in receipt["matches"]}
        self.assertEqual(by_item["external-12"]["status"], "version_conflict")
        self.assertEqual(by_item["external-13"]["status"], "exact")
        self.assertEqual(receipt["metrics"]["must_read_miss"]["count"], 1)
        self.assertEqual(receipt["schema"], KNOWN_ANSWER_RECEIPT_SCHEMA)
        self.assertFalse(receipt["evaluation"]["market_or_recommendation_quality_claim"])

    def test_unknown_identity_and_unjudged_positions_keep_metrics_unknown(self) -> None:
        frozen = _frozen_set(unknown_judgment_index=15, missing_identity_index=20)
        evaluation_items = frozen["items"][12:]
        candidates = [_candidate(item, rank) for rank, item in enumerate(evaluation_items, 1)]
        receipt = evaluate_external_known_answers(
            frozen,
            split="evaluation",
            candidates=candidates,
            evaluation_context=_context(),
            evaluator_identity="offline-fixture-runner",
            evaluated_at="2026-08-10T09:00:00+08:00",
        )
        matches = {row["item_id"]: row for row in receipt["matches"]}
        self.assertEqual(matches["external-20"]["status"], "identity_missing")
        self.assertEqual(receipt["metrics"]["p_at_5"]["status"], "unknown")
        self.assertGreater(receipt["metrics"]["p_at_5"]["unknown_count"], 0)

    def test_reports_explicit_duplicate_clusters_novelty_diversity_and_minutes(self) -> None:
        frozen = _frozen_set()
        evaluation_items = frozen["items"][12:]
        candidates = [_candidate(item, rank) for rank, item in enumerate(evaluation_items, 1)]
        candidates[1]["duplicate_cluster_id"] = "explicit-family-a"
        candidates[2]["duplicate_cluster_id"] = "explicit-family-a"
        candidates[3]["verification_minutes"] = None
        candidates[4]["novelty_status"] = "unknown"
        candidates[5]["diversity_group"] = None
        receipt = evaluate_external_known_answers(
            frozen,
            split="evaluation",
            candidates=candidates,
            evaluation_context=_context(),
            evaluator_identity="offline-fixture-runner",
            evaluated_at="2026-08-10T09:00:00+08:00",
        )
        metrics = receipt["metrics"]
        self.assertEqual(metrics["near_duplicate_rate"]["basis"], "explicit_duplicate_cluster_id_only")
        self.assertEqual(metrics["near_duplicate_rate"]["numerator"], 1)
        self.assertEqual(metrics["novelty_at_10"]["status"], "unknown")
        self.assertEqual(metrics["diversity_at_10"]["status"], "unknown")
        self.assertEqual(metrics["verification_minutes"]["status"], "unknown")
        self.assertGreater(metrics["verification_minutes"]["observed_sum"], 0)

    def test_rejects_evaluation_leakage_and_shared_candidate_artifacts(self) -> None:
        frozen = _frozen_set()
        candidates = [_candidate(item, rank) for rank, item in enumerate(frozen["items"][12:], 1)]
        with self.assertRaisesRegex(KnownAnswerError, "accessed before"):
            evaluate_external_known_answers(
                frozen,
                split="evaluation",
                candidates=candidates,
                evaluation_context=_context(known_answer_splits_accessed_before_run=["evaluation"]),
                evaluator_identity="offline-fixture-runner",
                evaluated_at="2026-08-10T09:00:00+08:00",
            )
        with self.assertRaisesRegex(KnownAnswerError, "share source artifacts"):
            evaluate_external_known_answers(
                frozen,
                split="evaluation",
                candidates=candidates,
                evaluation_context=_context(candidate_source_artifact_ids=["external-artifact-2"]),
                evaluator_identity="offline-fixture-runner",
                evaluated_at="2026-08-10T09:00:00+08:00",
            )
        with self.assertRaisesRegex(KnownAnswerError, "frozen after"):
            evaluate_external_known_answers(
                frozen,
                split="evaluation",
                candidates=candidates,
                evaluation_context=_context(candidate_pool_frozen_at="2026-08-09T11:59:59+08:00"),
                evaluator_identity="offline-fixture-runner",
                evaluated_at="2026-08-10T09:00:00+08:00",
            )

    def test_zero_results_and_simple_baseline_have_explicit_denominators(self) -> None:
        frozen = _frozen_set()
        evaluation_items = frozen["items"][12:]
        primary = [_candidate(item, rank) for rank, item in enumerate(evaluation_items, 1)]
        baseline = [_candidate(evaluation_items[0], 1)]
        receipt = evaluate_external_known_answers(
            frozen,
            split="evaluation",
            candidates=primary,
            baselines={"keyword_recency_baseline": baseline},
            evaluation_context=_context(),
            evaluator_identity="offline-fixture-runner",
            evaluated_at="2026-08-10T09:00:00+08:00",
        )
        self.assertEqual(receipt["metrics"]["candidate_recall"]["value"], 1.0)
        self.assertEqual(receipt["metrics"]["p_at_10"]["denominator"], 10)
        self.assertEqual(receipt["baselines"]["keyword_recency_baseline"]["candidate_recall"]["numerator"], 1)
        self.assertEqual(receipt["comparisons"]["keyword_recency_baseline"]["candidate_recall"]["status"], "complete")
        self.assertEqual(
            validate_known_answer_evaluation_receipt(receipt)["receipt_sha256"],
            receipt["receipt_sha256"],
        )
        tampered = copy.deepcopy(receipt)
        tampered["metrics"]["candidate_recall"]["value"] = 0.0
        with self.assertRaisesRegex(KnownAnswerError, "digest does not match"):
            validate_known_answer_evaluation_receipt(tampered)

        empty = evaluate_external_known_answers(
            frozen,
            split="evaluation",
            candidates=[],
            evaluation_context=_context(candidate_run_id="empty-run"),
            evaluator_identity="offline-fixture-runner",
            evaluated_at="2026-08-10T09:05:00+08:00",
        )
        self.assertEqual(empty["metrics"]["candidate_recall"]["numerator"], 0)
        self.assertGreater(empty["metrics"]["candidate_recall"]["denominator"], 0)
        self.assertEqual(empty["metrics"]["p_at_3"]["status"], "unknown")
        self.assertEqual(empty["metrics"]["p_at_3"]["denominator"], 0)


class ExternalKnownAnswerCliTests(unittest.TestCase):
    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _evaluate_args(
        known_set: Path,
        candidates: Path,
        output: Path,
        *extra: str,
    ) -> list[str]:
        return [
            "known-answer-evaluate",
            "--known-answer-set",
            str(known_set),
            "--candidates",
            str(candidates),
            "--split",
            "evaluation",
            "--candidate-run-id",
            "independent-candidate-run-20260810",
            "--candidate-pool-id",
            "frozen-candidate-pool-001",
            "--candidate-pool-frozen-at",
            "2026-08-10T08:00:00+08:00",
            "--candidate-source-artifact-id",
            "r3-run-candidate-export-002",
            "--known-answer-split-accessed-before-run",
            "development",
            "--ranking-method",
            "r3-static-ranking-policy-v1",
            "--evaluator-identity",
            "offline-fixture-runner-not-a-human-gold-claim",
            "--evaluated-at",
            "2026-08-10T09:00:00+08:00",
            "--output",
            str(output),
            *extra,
        ]

    def test_chinese_space_path_freeze_preview_and_frozen_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "外部 已知答案 工作区"
            draft_path = root / "输入 集合.json"
            frozen_path = root / "冻结 集合.json"
            self._write_json(draft_path, _draft_set())

            console = io.StringIO()
            with redirect_stdout(console):
                result = main(
                    [
                        "known-answer-validate",
                        str(draft_path),
                        "--freeze",
                        "--frozen-at",
                        "2026-08-09T12:00:00+08:00",
                        "--frozen-by",
                        "independent-fixture-freezer-not-human-gold",
                        "--output",
                        str(frozen_path),
                    ]
                )
            summary = json.loads(console.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(summary["status"], "freeze_preview")
            self.assertEqual(summary["item_count"], 24)
            self.assertFalse(summary["human_gold_claim"])
            self.assertEqual(
                validate_external_known_answer_set(
                    json.loads(frozen_path.read_text(encoding="utf-8")),
                    require_frozen=True,
                )["freeze"]["status"],
                "frozen",
            )

            console = io.StringIO()
            with redirect_stdout(console):
                result = main(
                    [
                        "known-answer-validate",
                        str(frozen_path),
                        "--require-frozen",
                    ]
                )
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(console.getvalue())["status"], "valid_frozen")

    def test_invalid_set_fails_without_writing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            input_path = root / "invalid.json"
            output_path = root / "must-not-exist.json"
            invalid = _draft_set()
            invalid["items"] = invalid["items"][:19]
            self._write_json(input_path, invalid)

            console = io.StringIO()
            with redirect_stdout(console):
                result = main(
                    [
                        "known-answer-validate",
                        str(input_path),
                        "--output",
                        str(output_path),
                    ]
                )
            self.assertEqual(result, 2)
            self.assertFalse(output_path.exists())
            self.assertIn("20-35", json.loads(console.getvalue())["error"])

    def test_evaluation_rejects_shared_source_without_half_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            known_path = root / "frozen.json"
            candidates_path = root / "candidates.json"
            output_path = root / "receipt.json"
            frozen = _frozen_set()
            candidates = [
                _candidate(item, rank)
                for rank, item in enumerate(frozen["items"][12:], 1)
            ]
            self._write_json(known_path, frozen)
            self._write_json(candidates_path, candidates)
            args = self._evaluate_args(known_path, candidates_path, output_path)
            source_index = args.index("r3-run-candidate-export-002")
            args[source_index] = "external-artifact-2"

            console = io.StringIO()
            with redirect_stdout(console):
                result = main(args)
            self.assertEqual(result, 2)
            self.assertFalse(output_path.exists())
            self.assertIn("share source artifacts", json.loads(console.getvalue())["error"])

    def test_zero_results_baseline_and_non_overwrite_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "离线 评测"
            known_path = root / "冻结集合.json"
            candidates_path = root / "零结果.json"
            baseline_path = root / "关键词 基线.json"
            output_path = root / "结果 回执.json"
            self._write_json(known_path, _frozen_set())
            self._write_json(candidates_path, [])
            self._write_json(baseline_path, [])
            args = self._evaluate_args(
                known_path,
                candidates_path,
                output_path,
                "--baseline",
                f"keyword_recency={baseline_path}",
            )

            console = io.StringIO()
            with redirect_stdout(console):
                result = main(args)
            self.assertEqual(result, 0)
            summary = json.loads(console.getvalue())
            receipt = validate_known_answer_evaluation_receipt(
                json.loads(output_path.read_text(encoding="utf-8"))
            )
            self.assertEqual(summary["candidate_count"], 0)
            self.assertFalse(summary["human_gold_claim"])
            self.assertFalse(summary["market_or_recommendation_quality_claim"])
            self.assertEqual(receipt["metrics"]["candidate_recall"]["numerator"], 0)
            self.assertGreater(receipt["metrics"]["candidate_recall"]["denominator"], 0)
            self.assertIn("keyword_recency", receipt["baselines"])

            before = output_path.read_bytes()
            console = io.StringIO()
            with redirect_stdout(console):
                result = main(args)
            self.assertEqual(result, 2)
            self.assertEqual(output_path.read_bytes(), before)
            self.assertIn("already exists", json.loads(console.getvalue())["error"])

            output_path.write_text('{"stale":true}\n', encoding="utf-8")
            console = io.StringIO()
            with redirect_stdout(console):
                result = main([*args, "--force"])
            self.assertEqual(result, 0)
            validate_known_answer_evaluation_receipt(
                json.loads(output_path.read_text(encoding="utf-8"))
            )


if __name__ == "__main__":
    unittest.main()
