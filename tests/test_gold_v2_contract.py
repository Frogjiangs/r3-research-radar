from __future__ import annotations

import copy
import hashlib
import unittest

from r3radar.calibration import (
    GOLD_SET_SCHEMA,
    GOLD_SET_V2_SCHEMA,
    CalibrationError,
    _LABELS,
    _validate_gold_set_v2,
    blind_gold_set_payload,
    convert_gold_set_v1_to_v2_preview,
    evaluate_gold_set,
    export_gold_v2_audit,
    lock_gold_y0,
    start_gold_y1,
    submit_gold_y0,
    submit_gold_y1,
)
from r3radar.config import canonical_json


def _sha256(value: object) -> str:
    text = value if isinstance(value, str) else canonical_json(value)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _realistic_v1_gold(*, item_count: int = 70) -> dict:
    items = []
    for work_id in range(1, item_count + 1):
        operational = work_id > max(0, item_count - 10)
        input_sha256 = _sha256(f"workflow-cache-input-{work_id}")
        citation = {
            "kind": "repository" if work_id % 5 == 0 else "paper",
            "authors": [
                {
                    "display_name": f"Researcher {work_id}",
                    "score": "AI_LEAK_AUTHOR_SCORE",
                }
            ],
            "title": (
                f"Workflow-semantic cache reuse and retention study {work_id}: "
                "multi-step agent traces, short-lived objects, and eviction decisions"
            ),
            "year": 2024 + work_id % 3,
            "canonical_url": f"https://example.invalid/research/{work_id}",
            "abstract": (
                "This frozen source abstract describes a multi-stage research workflow "
                "that compares semantic workflow state with recency and frequency "
                "heuristics over future reuse windows. It records object identity, "
                "decision horizon, counterfactual retention cost, failure boundaries, "
                "and reproducibility constraints. " * 5
            ),
        }
        if operational:
            snapshot = {
                "schema": "r3/gold-operational-sentinel/v1",
                "work_id": work_id,
                "citation": citation,
                "state": "analysis_failed",
                "document_status": "incomplete",
                "input_sha256": input_sha256,
                "error_present": True,
            }
            item = {
                "item_id": f"work:{work_id}:operational",
                "record_class": "operational_sentinel",
                "work_id": work_id,
                "analysis_id": None,
                "input_sha256": input_sha256,
                "snapshot_sha256": _sha256(snapshot),
                "captured_as": "operational_sentinel",
                "selection_bucket": None,
                "review_context": snapshot,
                "frozen_snapshot": snapshot,
                "human_label": "inaccessible" if work_id == item_count else None,
                "human_notes": None,
            }
        else:
            snapshot = {
                "schema": "r3/publication-item-snapshot/v1",
                "analysis_id": work_id,
                "work_id": work_id,
                "input_sha256": input_sha256,
                "citation": citation,
                "provider": "codex_cli",
                "tier": "must_read" if work_id <= 10 else "background",
                "score": 0.99 - work_id / 1000,
                "analysis": {
                    "summary_zh": f"AI_LEAK_SUMMARY_{work_id}",
                    "evidence_anchors": [f"AI_LEAK_ANCHOR_{work_id}"],
                },
            }
            item = {
                "item_id": f"analysis:{work_id}",
                "record_class": "complete_analysis",
                "work_id": work_id,
                "analysis_id": work_id,
                "input_sha256": input_sha256,
                "snapshot_sha256": _sha256(snapshot),
                "captured_as": (
                    "publication_selected" if work_id <= 40 else "candidate_unselected"
                ),
                "selection_bucket": "must_read" if work_id <= 10 else "background",
                "review_context": {
                    "citation": citation,
                    "provider": "codex_cli",
                    "tier": "AI_LEAK_TIER",
                    "score": 0.99,
                    "summary_zh": f"AI_LEAK_SUMMARY_{work_id}",
                    "evidence_anchors": [f"AI_LEAK_ANCHOR_{work_id}"],
                },
                "frozen_snapshot": snapshot,
                "human_label": "known_important" if work_id == 1 else None,
                "human_notes": None,
            }
        items.append(item)
    return {
        "schema": GOLD_SET_SCHEMA,
        "scope": {
            "run_id": "workflow-cache-source-run",
            "issue_id": "workflow-cache-issue",
            "profile_id": "r3-cache-value",
            "profile_version": 1,
            "config_hash": "a" * 64,
            "retrieval_hash": "b" * 64,
            "analysis_policy_hash": "c" * 64,
            "database_sha256_at_draft": "d" * 64,
        },
        "review": {
            "status": "pending_human_verification",
            "reviewer": None,
            "reviewed_at": None,
            "allowed_labels": list(_LABELS),
            "instructions": "Review every frozen item without treating model output as truth.",
        },
        "sampling": {
            "actual_count": item_count,
            "selection_bias_warning": "Run-derived sample; external recall is separate.",
        },
        "items": items,
    }


def _submit_all_y0(gold: dict) -> dict:
    result = gold
    for index, item in enumerate(gold["items"]):
        if index < 10:
            semantic_label = "known_important"
            operational_status = "normal"
            confidence = 5
        elif index == 10:
            semantic_label = "unjudged"
            operational_status = "normal"
            confidence = None
        elif index >= 60:
            semantic_label = "relevant_not_priority"
            operational_status = "inaccessible"
            confidence = 2
        else:
            semantic_label = "relevant_not_priority"
            operational_status = "normal"
            confidence = 4
        result = submit_gold_y0(
            result,
            item_id=item["item_id"],
            reviewer_identity="researcher-local",
            semantic_label=semantic_label,
            operational_status=operational_status,
            confidence=confidence,
            evidence_opened=index % 2 == 0,
            elapsed_ms=45_000 + index * 1_000,
            notes="Checked source evidence and workflow-cache fit.",
            submitted_at=f"2026-08-10T10:{index // 60:02d}:{index % 60:02d}+08:00",
            expected_revision_sequence=0,
        )
    return result


def _ai_assignments(gold: dict) -> dict[str, dict]:
    assignments = {}
    for index, item in enumerate(gold["items"]):
        if index % 2:
            assignments[item["item_id"]] = {
                "ai_treatment": "control",
                "ai_provider": None,
                "ai_model": None,
                "ai_prompt_sha256": None,
                "ai_payload": None,
            }
        else:
            assignments[item["item_id"]] = {
                "ai_treatment": "ai_assisted",
                "ai_provider": "codex_cli",
                "ai_model": "gpt-5.6-sol",
                "ai_prompt_sha256": "e" * 64,
                "ai_payload": {
                    "tier": "important",
                    "score": 0.87,
                    "summary_zh": "Only visible after the blind y0 lock.",
                },
            }
    return assignments


class GoldV2BlindContractTests(unittest.TestCase):
    def test_conversion_is_non_mutating_resets_v1_labels_and_requires_70_items(self) -> None:
        v1 = _realistic_v1_gold()
        original = copy.deepcopy(v1)

        v2 = convert_gold_set_v1_to_v2_preview(
            v1,
            reviewer_identity="researcher-local",
        )

        self.assertEqual(v1, original)
        self.assertEqual(v2["schema"], GOLD_SET_V2_SCHEMA)
        self.assertEqual(v2["source"]["sha256"], _sha256(original))
        self.assertTrue(all(item["y0"] is None for item in v2["items"]))
        self.assertNotIn("human_label", v2["items"][0])
        with self.assertRaisesRegex(CalibrationError, "exactly 70"):
            convert_gold_set_v1_to_v2_preview(
                _realistic_v1_gold(item_count=69),
                reviewer_identity="researcher-local",
            )

    def test_blind_response_uses_allowlist_and_breaks_model_rank_order(self) -> None:
        v2 = convert_gold_set_v1_to_v2_preview(
            _realistic_v1_gold(),
            reviewer_identity="researcher-local",
        )

        first = blind_gold_set_payload(v2)
        second = blind_gold_set_payload(v2)
        serialized = canonical_json(first)

        self.assertEqual(first, second)
        self.assertNotEqual(
            [item["item_id"] for item in first["items"]],
            [item["item_id"] for item in v2["items"]],
        )
        for leak in (
            "AI_LEAK_TIER",
            "AI_LEAK_SUMMARY_1",
            "AI_LEAK_ANCHOR_1",
            "AI_LEAK_AUTHOR_SCORE",
            "publication_selected",
            "candidate_unselected",
            "codex_cli",
        ):
            self.assertNotIn(leak, serialized)
        forbidden_keys = {
            "selected",
            "captured_as",
            "selection_bucket",
            "tier",
            "score",
            "provider",
            "summary_zh",
            "evidence_anchors",
            "analysis",
        }

        def keys(value):
            if isinstance(value, dict):
                return set(value) | set().union(*(keys(child) for child in value.values()))
            if isinstance(value, list):
                return set().union(*(keys(child) for child in value)) if value else set()
            return set()

        self.assertFalse(keys(first) & forbidden_keys)

    def test_partial_review_cannot_lock_or_reveal_and_rejects_stale_tab(self) -> None:
        v2 = convert_gold_set_v1_to_v2_preview(
            _realistic_v1_gold(),
            reviewer_identity="researcher-local",
        )
        first_id = v2["items"][0]["item_id"]
        partial = submit_gold_y0(
            v2,
            item_id=first_id,
            reviewer_identity="researcher-local",
            semantic_label="known_important",
            operational_status="normal",
            confidence=5,
            evidence_opened=True,
            elapsed_ms=82_000,
            notes="Verified against the frozen source abstract.",
            submitted_at="2026-08-10T10:00:00+08:00",
            expected_revision_sequence=0,
        )
        with self.assertRaisesRegex(CalibrationError, "stale y0 submission"):
            submit_gold_y0(
                partial,
                item_id=first_id,
                reviewer_identity="researcher-local",
                semantic_label="boundary",
                operational_status="normal",
                confidence=3,
                evidence_opened=True,
                elapsed_ms=90_000,
                notes=None,
                submitted_at="2026-08-10T10:01:00+08:00",
                expected_revision_sequence=0,
            )
        with self.assertRaisesRegex(CalibrationError, "all 70"):
            lock_gold_y0(
                partial,
                reviewer_identity="researcher-local",
                locked_at="2026-08-10T11:30:00+08:00",
            )
        with self.assertRaisesRegex(CalibrationError, "cannot be revealed"):
            start_gold_y1(
                partial,
                reviewer_identity="researcher-local",
                assignments=_ai_assignments(partial),
                revealed_at="2026-08-10T11:31:00+08:00",
            )
        resumed = blind_gold_set_payload(partial)
        saved = next(item for item in resumed["items"] if item["item_id"] == first_id)
        self.assertEqual(saved["y0"]["semantic_label"], "known_important")


class GoldV2LockedTruthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        draft = convert_gold_set_v1_to_v2_preview(
            _realistic_v1_gold(),
            reviewer_identity="researcher-local",
        )
        cls.labeled = _submit_all_y0(draft)
        cls.locked = lock_gold_y0(
            cls.labeled,
            reviewer_identity="researcher-local",
            locked_at="2026-08-10T12:00:00+08:00",
        )

    def test_lock_is_immutable_and_hash_detects_truth_tampering(self) -> None:
        with self.assertRaisesRegex(CalibrationError, "locked"):
            submit_gold_y0(
                self.locked,
                item_id=self.locked["items"][0]["item_id"],
                reviewer_identity="researcher-local",
                semantic_label="hard_negative",
                operational_status="normal",
                confidence=5,
                evidence_opened=True,
                elapsed_ms=1,
                notes=None,
                submitted_at="2026-08-10T12:01:00+08:00",
                expected_revision_sequence=1,
            )
        tampered = copy.deepcopy(self.locked)
        tampered["items"][0]["y0"]["semantic_label"] = "hard_negative"
        with self.assertRaisesRegex(CalibrationError, "revision payload|lock digest"):
            _validate_gold_set_v2(tampered)

    def test_y1_feedback_never_replaces_blind_y0_gold_truth(self) -> None:
        revealed = start_gold_y1(
            self.locked,
            reviewer_identity="researcher-local",
            assignments=_ai_assignments(self.locked),
            revealed_at="2026-08-10T12:10:00+08:00",
        )
        first = revealed["items"][0]
        changed = submit_gold_y1(
            revealed,
            item_id=first["item_id"],
            reviewer_identity="researcher-local",
            semantic_label="hard_negative",
            confidence=4,
            change_reason="AI evidence exposed a task/object mismatch.",
            submitted_at="2026-08-10T12:12:00+08:00",
            expected_revision_sequence=0,
        )

        result = evaluate_gold_set(
            changed,
            candidate_work_ids=set(range(1, 10)),
            same_source=False,
        )

        self.assertEqual(result["gold_truth_stage"], "y0")
        self.assertEqual(result["known_important_count"], 10)
        self.assertEqual(result["recall_at_candidate"], 0.9)
        self.assertTrue(result["passed"])
        self.assertEqual(result["operational_excluded_count"], 10)
        self.assertEqual(result["unjudged_excluded_count"], 1)

    def test_audit_export_binds_source_lock_and_revision_chain(self) -> None:
        receipt = export_gold_v2_audit(self.locked)
        self.assertEqual(receipt["item_count"], 70)
        self.assertEqual(receipt["gold_truth_stage"], "y0")
        self.assertEqual(receipt["y1_role"], "ai_assistance_feedback_only")
        self.assertEqual(receipt["revision_count"], 71)
        self.assertEqual(
            receipt["revision_head_sha256"],
            self.locked["revisions"][-1]["revision_sha256"],
        )
        tampered = copy.deepcopy(self.locked)
        tampered["revisions"][0]["payload"]["notes"] = "silently changed"
        with self.assertRaisesRegex(CalibrationError, "revision_sha256"):
            export_gold_v2_audit(tampered)


if __name__ == "__main__":
    unittest.main()
