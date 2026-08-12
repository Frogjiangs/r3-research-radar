from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from pypdf import PdfWriter
from pypdf.generic import (
    DecodedStreamObject,
    DictionaryObject,
    NameObject,
)

from r3radar.config import DEFAULT_CONFIG, PROJECT_DIR, Settings
from r3radar.http_client import RawReceipt
from r3radar.models import SourceRecord, objective_admission
from r3radar.pipeline import PipelineLimits, RadarPipeline


def _make_settings(root: Path) -> Settings:
    raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    data_dir = root / "data"
    literature_dir = root / "literature"
    outputs_dir = root / "outputs"
    for path in (data_dir, literature_dir, outputs_dir):
        path.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        raw=raw,
        config_path=DEFAULT_CONFIG,
        project_dir=PROJECT_DIR,
        workspace_dir=root,
        data_dir=data_dir,
        literature_dir=literature_dir,
        outputs_dir=outputs_dir,
        database_path=data_dir / "radar.sqlite3",
    )
    settings.ensure_directories()
    return settings


def _pdf_from_streams(streams: list[bytes | None]) -> bytes:
    output = io.BytesIO()
    writer = PdfWriter()
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
            NameObject("/Encoding"): NameObject("/WinAnsiEncoding"),
        }
    )
    font_reference = writer._add_object(font)
    for stream_bytes in streams:
        page = writer.add_blank_page(width=612, height=792)
        page[NameObject("/Resources")] = DictionaryObject(
            {
                NameObject("/Font"): DictionaryObject(
                    {NameObject("/F1"): font_reference}
                )
            }
        )
        if stream_bytes is not None:
            content = DecodedStreamObject()
            content.set_data(stream_bytes)
            page[NameObject("/Contents")] = writer._add_object(content)
    writer.write(output)
    return output.getvalue()


def _normal_pdf() -> bytes:
    pages = [
        "NORMAL_QUEUE_PAGE_ONE " + ("agent workflow cache evidence " * 30),
        "NORMAL_QUEUE_PAGE_TWO " + ("serving reuse value prediction " * 30),
    ]
    streams: list[bytes] = []
    for value in pages:
        escaped = (
            value.replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
        )
        streams.append(
            b"BT /F1 10 Tf 40 740 Td ("
            + escaped.encode("latin-1")
            + b") Tj ET"
        )
    return _pdf_from_streams(streams)


class _FixturePdfClient:
    def __init__(self, payloads: dict[str, bytes]):
        self.payloads = payloads
        self.requests: list[str] = []

    def request_bytes(
        self,
        url: str,
        **_: Any,
    ) -> tuple[bytes, RawReceipt, dict[str, str]]:
        self.requests.append(url)
        body = self.payloads[url]
        digest = hashlib.sha256(body).hexdigest()
        return (
            body,
            RawReceipt(
                sha256=digest,
                path=f"memory/{digest}.pdf.gz",
                byte_count=len(body),
                status_code=200,
                final_url=url,
                fetched_at="fixture",
            ),
            {"Content-Type": "application/pdf"},
        )


@unittest.skipUnless(os.name == "nt", "P0 PDF pipeline requires Windows AppContainer")
class PdfPipelineQueueE2ETests(unittest.TestCase):
    def test_incomplete_pdf_does_not_stop_queue_or_seed_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = _make_settings(Path(temporary))
            blank_url = "https://example.com/blank.pdf"
            normal_url = "https://example.com/normal.pdf"
            client = _FixturePdfClient(
                {
                    blank_url: _pdf_from_streams([None, None, None]),
                    normal_url: _normal_pdf(),
                }
            )
            with RadarPipeline(
                settings,
                mode="test",
                include_hosted_search=False,
                limits=PipelineLimits(content_items=2, analysis_items=0),
            ) as pipeline:
                pipeline.store.seed_query_jobs(
                    pipeline.run_id,
                    settings,
                    include_hosted=False,
                    lease_token=pipeline.lease_token,
                    smoke=True,
                )
                with pipeline.store._lock:
                    query_job_id = int(
                        pipeline.store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='openalex'
                            ORDER BY id
                            LIMIT 1
                            """,
                            (pipeline.run_id,),
                        ).fetchone()["id"]
                    )

                work_ids: list[int] = []
                for source_id, title, pdf_url in (
                    (
                        "W-pdf-queue-blank",
                        "Blank Agent Workflow Cache Queue Fixture",
                        blank_url,
                    ),
                    (
                        "W-pdf-queue-normal",
                        "Normal Agent Workflow Cache Queue Fixture",
                        normal_url,
                    ),
                ):
                    record = SourceRecord(
                        source="openalex",
                        source_id=source_id,
                        kind="paper",
                        title=title,
                        query_id="q01",
                        year=2026,
                        canonical_url=pdf_url,
                        pdf_url=pdf_url,
                    )
                    decision = objective_admission(record, settings.raw)
                    self.assertTrue(decision.admitted)
                    work_id, _ = pipeline.store.ingest_record(
                        run_id=pipeline.run_id,
                        lease_token=pipeline.lease_token,
                        query_job_id=query_job_id,
                        record=record,
                        decision=decision,
                        raw_sha256=f"raw-{source_id}",
                    )
                    work_ids.append(work_id)

                claimed_work_ids: list[int] = []
                original_claim = pipeline.store.claim_work_for_content

                def recording_claim(
                    config_hash: str,
                    *,
                    run_id: str,
                    lease_token: str,
                ) -> dict[str, Any] | None:
                    work = original_claim(
                        config_hash,
                        run_id=run_id,
                        lease_token=lease_token,
                    )
                    if work is not None:
                        claimed_work_ids.append(int(work["id"]))
                    return work

                pipeline.store.claim_work_for_content = recording_claim
                pipeline._content_client_for_url = lambda _url: client
                pipeline._collect_content()

                self.assertEqual(claimed_work_ids, work_ids)
                self.assertEqual(client.requests, [blank_url, normal_url])
                with pipeline.store._lock:
                    documents = pipeline.store._connection.execute(
                        """
                        SELECT work_id, status, coverage_json
                        FROM documents
                        WHERE work_id IN (?, ?)
                        ORDER BY work_id
                        """,
                        tuple(work_ids),
                    ).fetchall()
                    scopes = pipeline.store._connection.execute(
                        """
                        SELECT work_id, config_hash, state,
                               active_run_id, active_lease_token
                        FROM work_scopes
                        WHERE work_id IN (?, ?)
                        ORDER BY work_id
                        """,
                        tuple(work_ids),
                    ).fetchall()
                    observed_run_ids = pipeline.store._connection.execute(
                        """
                        SELECT DISTINCT run_id
                        FROM run_hits
                        WHERE work_id IN (?, ?)
                        ORDER BY run_id
                        """,
                        tuple(work_ids),
                    ).fetchall()

                self.assertEqual(
                    [row["status"] for row in documents],
                    ["incomplete", "ready"],
                )
                blank_coverage = json.loads(documents[0]["coverage_json"])
                normal_coverage = json.loads(documents[1]["coverage_json"])
                self.assertFalse(blank_coverage["complete"])
                self.assertEqual(
                    blank_coverage["reason"],
                    "insufficient_extractable_text",
                )
                self.assertTrue(normal_coverage["complete"])
                self.assertEqual(
                    [row["state"] for row in scopes],
                    ["content_incomplete", "content_ready"],
                )
                self.assertTrue(
                    all(
                        row["config_hash"] == settings.retrieval_hash
                        and row["active_run_id"] is None
                        and row["active_lease_token"] is None
                        for row in scopes
                    )
                )
                self.assertEqual(
                    [row["run_id"] for row in observed_run_ids],
                    [pipeline.run_id],
                )

                seeded = pipeline.store.seed_analysis_tasks(
                    "codex_cli",
                    settings.raw["analysis"]["prompt_version"],
                    analysis_policy_hash=settings.analysis_policy_hash,
                    retrieval_hash=settings.retrieval_hash,
                    profile_id=settings.profile_id,
                    profile_version=settings.profile_version,
                )
                self.assertEqual(seeded, 1)
                with pipeline.store._lock:
                    analysis_tasks = pipeline.store._connection.execute(
                        """
                        SELECT work_id, status
                        FROM analysis_tasks
                        ORDER BY id
                        """
                    ).fetchall()
                self.assertEqual(
                    [(int(row["work_id"]), row["status"]) for row in analysis_tasks],
                    [(work_ids[1], "pending")],
                )

                audit_events = [
                    json.loads(line)
                    for line in pipeline.audit.path.read_text(
                        encoding="utf-8"
                    ).splitlines()
                    if line.strip()
                ]
                parse_events = [
                    event
                    for event in audit_events
                    if event["event_type"] == "paper_pdf_parse_verified"
                ]
                processed_events = [
                    event
                    for event in audit_events
                    if event["event_type"] == "content_processed"
                ]
                self.assertEqual(
                    [
                        (
                            int(event["details"]["work_id"]),
                            bool(event["details"]["complete"]),
                        )
                        for event in parse_events
                    ],
                    [(work_ids[0], False), (work_ids[1], True)],
                )
                self.assertEqual(
                    [
                        (
                            int(event["details"]["work_id"]),
                            event["details"]["status"],
                        )
                        for event in processed_events
                    ],
                    [(work_ids[0], "incomplete"), (work_ids[1], "ready")],
                )
                ordered_markers = [
                    (
                        event["event_type"],
                        int(event["details"]["work_id"]),
                    )
                    for event in audit_events
                    if event["event_type"]
                    in {"paper_pdf_parse_verified", "content_processed"}
                ]
                self.assertEqual(
                    ordered_markers,
                    [
                        ("paper_pdf_parse_verified", work_ids[0]),
                        ("content_processed", work_ids[0]),
                        ("paper_pdf_parse_verified", work_ids[1]),
                        ("content_processed", work_ids[1]),
                    ],
                )
