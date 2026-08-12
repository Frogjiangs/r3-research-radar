from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from r3radar.storage import RadarStore  # noqa: E402
from r3radar.utils import atomic_write_text  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exercise 70-item Gold persistence without creating human labels."
    )
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    source_before = {
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "size_bytes": source.stat().st_size,
        "mtime_ns": source.stat().st_mtime_ns,
    }
    with tempfile.TemporaryDirectory() as raw:
        database = Path(raw) / "gold-mechanics.sqlite3"
        started = time.perf_counter()
        with RadarStore(database) as store:
            created = store.create_gold_review_from_v1_file(
                source_path=source,
                reviewer_identity="automated-mechanics-not-human",
                creation_request_id="gold-mechanics-import-v1",
            )
            review_id = str(created["review_id"])
            blind = store.gold_review_blind_payload(
                review_id, limit=25, offset=0
            )
            items = list(blind["items"])
            offset = len(items)
            while blind["has_more"]:
                blind = store.gold_review_blind_payload(
                    review_id, limit=25, offset=offset
                )
                items.extend(blind["items"])
                offset += len(blind["items"])
            sequence = int(created["document_revision_sequence"])
            save_started = time.perf_counter()
            for index, item in enumerate(items):
                saved = store.save_gold_y0(
                    review_id=review_id,
                    request_id=f"mechanical-y0-{index:03d}",
                    item_id=str(item["item_id"]),
                    reviewer_identity="automated-mechanics-not-human",
                    semantic_label="unjudged",
                    operational_status="normal",
                    confidence=None,
                    evidence_opened=False,
                    elapsed_ms=0,
                    notes="AUTOMATED MECHANICS ONLY; NOT A HUMAN LABEL",
                    submitted_at=None,
                    expected_item_revision_sequence=0,
                    expected_document_revision_sequence=sequence,
                )
                sequence = int(saved["document_revision_sequence"])
            saved_seconds = time.perf_counter() - save_started
            locked = store.lock_gold_y0_review(
                review_id=review_id,
                request_id="mechanical-lock-000",
                reviewer_identity="automated-mechanics-not-human",
                locked_at=None,
                expected_document_revision_sequence=sequence,
            )
            integrity = store._connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            foreign_keys = len(
                store._connection.execute("PRAGMA foreign_key_check").fetchall()
            )
        reopen_started = time.perf_counter()
        with RadarStore(database) as reopened:
            document = reopened.gold_review_document(review_id)
        reopen_seconds = time.perf_counter() - reopen_started
        receipt = {
            "schema": "r3/gold-mechanics-benchmark/v1",
            "automated_mechanics_only": True,
            "human_labels": 0,
            "gold_quality_claim": False,
            "source": source_before,
            "item_count": len(items),
            "submitted_semantic_label": "unjudged",
            "revision_sequence": int(locked["document_revision_sequence"]),
            "status": document["status"],
            "save_and_lock_seconds": round(saved_seconds, 3),
            "cold_reopen_and_chain_replay_seconds": round(reopen_seconds, 3),
            "total_seconds": round(time.perf_counter() - started, 3),
            "database_bytes": database.stat().st_size,
            "integrity_check": integrity,
            "foreign_key_violations": foreign_keys,
            "source_unchanged": source_before
            == {
                "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "size_bytes": source.stat().st_size,
                "mtime_ns": source.stat().st_mtime_ns,
            },
        }
    atomic_write_text(
        args.output.resolve(),
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
    return 0 if (
        receipt["item_count"] == 70
        and receipt["revision_sequence"] == 71
        and receipt["status"] == "y0_locked"
        and receipt["integrity_check"] == "ok"
        and receipt["foreign_key_violations"] == 0
        and receipt["source_unchanged"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
