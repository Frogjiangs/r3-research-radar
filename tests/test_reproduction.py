from __future__ import annotations

import copy
import hashlib
import json
import unittest

from r3radar.decision import snapshot_sha256
from r3radar.reproduction import (
    CONFIRMATION_CHECKS,
    HANDOFF_SCHEMA,
    ReproductionHandoffError,
    build_reproduction_handoff,
    render_reproduction_handoff,
    validate_reproduction_handoff,
)
from tests.test_decision_exports import frozen_snapshot


TEXT = (
    "=== PAGE 1 ===\n"
    "Exact cache reuse evidence.\n"
    "A deterministic follow-up sentence.\n"
)


def frozen_issue_item(snapshot: dict | None = None) -> dict:
    snapshot = snapshot or frozen_snapshot(TEXT)
    return {
        "issue_id": "issue-2026-07-30",
        "analysis_id": snapshot["analysis_id"],
        "work_id": snapshot["work_id"],
        "input_sha256": snapshot["input_sha256"],
        "snapshot_sha256": snapshot_sha256(snapshot),
        "selection_bucket": "must_read",
        "selected": True,
        "snapshot": snapshot,
        "citation": copy.deepcopy(snapshot["citation"]),
        "analysis": copy.deepcopy(snapshot["analysis"]),
        "coverage": copy.deepcopy(snapshot["coverage"]),
        "provider": snapshot["provider"],
        "model": snapshot["model"],
        "tier": snapshot["tier"],
        "score": snapshot["score"],
        "lane": snapshot["lane"],
        "provenance_status": snapshot["provenance_status"],
        "decision": None,
    }


def complete_confirmation(*, confirmed: bool = True) -> dict:
    return {
        "confirmed": confirmed,
        "confirmed_by": "manual-reviewer",
        "confirmed_at": "2026-07-30T10:30:00+08:00",
        "checks": {name: True for name in CONFIRMATION_CHECKS},
    }


class ReproductionHandoffTests(unittest.TestCase):
    def test_pending_handoff_is_deterministic_and_not_executable(self) -> None:
        item = frozen_issue_item()

        first = build_reproduction_handoff(item)
        second = build_reproduction_handoff(copy.deepcopy(item))
        first_bytes = render_reproduction_handoff(first)

        self.assertEqual(first, second)
        self.assertEqual(first_bytes, render_reproduction_handoff(second))
        self.assertEqual(first["schema"], HANDOFF_SCHEMA)
        self.assertEqual(first["issue_id"], item["issue_id"])
        self.assertEqual(first["analysis_id"], item["analysis_id"])
        self.assertEqual(first["work_id"], item["work_id"])
        self.assertEqual(first["snapshot_sha256"], item["snapshot_sha256"])
        self.assertEqual(first["input_sha256"], item["input_sha256"])
        self.assertEqual(first["source"]["url"], "https://example.org/paper")
        self.assertEqual(first["source"]["doi"], "10.1234/r3.2026.7")
        self.assertEqual(first["manual_confirmation"]["status"], "pending")
        self.assertFalse(first["executable"])
        self.assertGreaterEqual(len(first["risk_warnings"]), 4)
        self.assertGreaterEqual(len(first["suggested_steps"]), 5)
        self.assertNotIn("generated_at", first)
        self.assertEqual(json.loads(first_bytes), first)

    def test_only_complete_explicit_confirmation_marks_executable(self) -> None:
        item = frozen_issue_item()
        pending = build_reproduction_handoff(
            item,
            manual_confirmation=complete_confirmation(confirmed=False),
        )
        confirmed = build_reproduction_handoff(
            item,
            manual_confirmation=complete_confirmation(),
        )

        self.assertFalse(pending["executable"])
        self.assertEqual(pending["manual_confirmation"]["status"], "pending")
        self.assertTrue(confirmed["executable"])
        self.assertEqual(
            confirmed["manual_confirmation"]["status"],
            "confirmed",
        )

        incomplete = complete_confirmation()
        incomplete["checks"]["external_code_and_dependencies_reviewed"] = False
        with self.assertRaisesRegex(
            ReproductionHandoffError,
            "every safety check",
        ):
            build_reproduction_handoff(
                item,
                manual_confirmation=incomplete,
            )

    def test_executable_cannot_be_injected_or_detached_from_confirmation(self) -> None:
        item = frozen_issue_item()
        injected = complete_confirmation(confirmed=False)
        injected["executable"] = True
        with self.assertRaises(ReproductionHandoffError):
            build_reproduction_handoff(item, manual_confirmation=injected)

        manifest = build_reproduction_handoff(item)
        manifest["executable"] = True
        with self.assertRaisesRegex(
            ReproductionHandoffError,
            "not bound to human confirmation",
        ):
            validate_reproduction_handoff(manifest)

    def test_issue_item_identity_hash_and_mirrors_fail_closed(self) -> None:
        base = frozen_issue_item()
        mutations = []
        wrong_analysis = copy.deepcopy(base)
        wrong_analysis["analysis_id"] += 1
        mutations.append(wrong_analysis)
        wrong_input = copy.deepcopy(base)
        wrong_input["input_sha256"] = "0" * 64
        mutations.append(wrong_input)
        wrong_snapshot_hash = copy.deepcopy(base)
        wrong_snapshot_hash["snapshot_sha256"] = "1" * 64
        mutations.append(wrong_snapshot_hash)
        wrong_mirror = copy.deepcopy(base)
        wrong_mirror["citation"]["title"] = "Tampered title"
        mutations.append(wrong_mirror)

        for item in mutations:
            with self.subTest(item=item):
                with self.assertRaises(ReproductionHandoffError):
                    build_reproduction_handoff(item)

    def test_missing_url_and_doi_remain_explicitly_absent(self) -> None:
        snapshot = frozen_snapshot(TEXT, doi=None)
        snapshot["citation"]["best_url"] = None
        snapshot["citation"]["arxiv_id"] = None
        item = frozen_issue_item(snapshot)

        manifest = build_reproduction_handoff(item)

        self.assertIsNone(manifest["source"]["url"])
        self.assertIsNone(manifest["source"]["doi"])
        self.assertIsNone(manifest["source"]["arxiv_id"])
        rendered = render_reproduction_handoff(manifest).decode("utf-8")
        self.assertNotIn("10.1234/", rendered)
        self.assertNotIn("example.org", rendered)

    def test_manifest_hash_detects_static_handoff_tampering(self) -> None:
        manifest = build_reproduction_handoff(frozen_issue_item())
        manifest["source"]["title"] = "Changed after handoff"

        with self.assertRaisesRegex(
            ReproductionHandoffError,
            "manifest_sha256",
        ):
            validate_reproduction_handoff(manifest)

    def test_handoff_binds_verified_paper_repository_commit_relation(self) -> None:
        evidence = {
            "schema": "r3/paper-repository-relation/v1",
            "paper": {"work_id": 7},
            "repository": {"work_id": 8},
            "repository_revision": {
                "commit_sha": "a" * 40,
                "selected_text_sha256": "b" * 64,
            },
        }
        relation = {
            "relation_sha256": hashlib.sha256(
                json.dumps(
                    evidence,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            "evidence": evidence,
            "created_at": "2026-07-30T10:30:00+08:00",
        }

        manifest = build_reproduction_handoff(
            frozen_issue_item(),
            source_relation=relation,
        )

        self.assertEqual(manifest["source_relation"], relation)
        self.assertFalse(manifest["executable"])
        tampered = copy.deepcopy(relation)
        tampered["evidence"]["repository_revision"]["commit_sha"] = "c" * 40
        with self.assertRaisesRegex(
            ReproductionHandoffError,
            "hash does not match",
        ):
            build_reproduction_handoff(
                frozen_issue_item(),
                source_relation=tampered,
            )


if __name__ == "__main__":
    unittest.main()
