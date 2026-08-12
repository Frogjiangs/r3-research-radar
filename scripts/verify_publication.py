from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify one run-bound R3 publication across SQLite and artifacts."
    )
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    connection = sqlite3.connect(args.database)
    connection.row_factory = sqlite3.Row
    try:
        issue = connection.execute(
            """
            SELECT * FROM report_issues
            WHERE run_id=?
            """,
            (args.run_id,),
        ).fetchone()
        if issue is None:
            raise RuntimeError("run-bound publication is missing")
        selection_path = Path(str(issue["selection_path"]))
        report_path = Path(str(issue["report_path"]))
        selection_sha256 = _sha256(selection_path)
        report_sha256 = _sha256(report_path)
        item_count = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM report_issue_items
                WHERE issue_id=?
                """,
                (issue["issue_id"],),
            ).fetchone()[0]
        )
        frozen_count = int(
            connection.execute(
                """
                SELECT COUNT(*) FROM report_issue_items
                WHERE issue_id=? AND input_sha256 IS NOT NULL
                  AND snapshot_sha256 IS NOT NULL
                  AND snapshot_json IS NOT NULL
                """,
                (issue["issue_id"],),
            ).fetchone()[0]
        )
        result = {
            "schema": "r3/publication-verification/v1",
            "ok": (
                connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                and not connection.execute("PRAGMA foreign_key_check").fetchall()
                and selection_sha256 == issue["selection_sha256"]
                and report_sha256 == issue["report_sha256"]
                and frozen_count == item_count
            ),
            "schema_version": connection.execute(
                """
                SELECT value FROM schema_meta
                WHERE key='schema_version'
                """
            ).fetchone()[0],
            "integrity": connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0],
            "foreign_key_violations": len(
                connection.execute("PRAGMA foreign_key_check").fetchall()
            ),
            "issue_id": issue["issue_id"],
            "run_id": issue["run_id"],
            "publication_key": issue["publication_key"],
            "terminal_status": issue["terminal_status"],
            "payload_sha256": issue["payload_sha256"],
            "selection_sha256": selection_sha256,
            "report_sha256": report_sha256,
            "item_count": item_count,
            "frozen_item_count": frozen_count,
        }
    finally:
        connection.close()
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
