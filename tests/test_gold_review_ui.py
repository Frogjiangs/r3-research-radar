from __future__ import annotations

import http.client
import hashlib
import json
import subprocess
import tempfile
import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path

from r3radar.config import PROJECT_DIR, canonical_json
from r3radar.web import RadarHttpServer
from tests.test_core import make_settings
from tests.test_gold_v2_contract import _realistic_v1_gold


class _GoldStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        values = dict(attrs)
        self.elements.append((tag, values))
        if values.get("id"):
            self.ids.add(str(values["id"]))


def _request(
    port: int,
    method: str,
    path: str,
    payload: dict | None = None,
) -> tuple[int, str, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Host": f"127.0.0.1:{port}"}
    if body is not None:
        headers |= {
            "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{port}",
        }
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    response_body = response.read()
    result = (
        int(response.status),
        response.getheader("Content-Type") or "",
        response_body,
    )
    connection.close()
    return result


class GoldReviewUiStaticTests(unittest.TestCase):
    def test_page_exposes_blind_newcomer_workflow_and_accessible_controls(self) -> None:
        html = (PROJECT_DIR / "static" / "gold-review.html").read_text(
            encoding="utf-8"
        )
        parser = _GoldStructureParser()
        parser.feed(html)
        required_ids = {
            "create-form",
            "source-path",
            "resume-form",
            "review-workspace",
            "conflict-banner",
            "review-progress",
            "review-card",
            "item-title",
            "annotation-form",
            "confidence-fieldset",
            "evidence-opened",
            "live-status",
            "open-lock-dialog",
            "lock-dialog",
            "lock-confirmation",
        }
        self.assertTrue(required_ids.issubset(parser.ids))

        self.assertIn('role="status" aria-live="polite"', html)
        self.assertIn('role="alert"', html)
        self.assertIn('aria-busy="false"', html)
        self.assertIn('href="#review-workspace"', html)
        self.assertIn('value="unjudged"', html)
        self.assertIn('value="identity_or_version_conflict"', html)
        self.assertIn("暂不判断", html)
        self.assertIn("不会被算作负例", html)
        self.assertIn("独立判断，不是自动生成的标准答案", html)
        self.assertIn("下一阶段是单独的随机化 y1 辅助评估", html)
        self.assertIn("请显式粘贴本机已有文件的完整路径", html)
        source_inputs = [
            attrs
            for tag, attrs in parser.elements
            if tag == "input" and attrs.get("id") == "source-path"
        ]
        self.assertEqual(len(source_inputs), 1)
        self.assertNotIn("value", source_inputs[0])

    def test_styles_cover_phone_desktop_focus_and_long_content(self) -> None:
        css = (PROJECT_DIR / "static" / "gold-review.css").read_text(
            encoding="utf-8"
        )
        self.assertIn("@media (max-width: 430px)", css)
        self.assertIn("@media (max-width: 720px)", css)
        self.assertIn("button:focus-visible", css)
        self.assertIn("input:focus-visible", css)
        self.assertIn("overflow-wrap: anywhere", css)
        self.assertIn("max-height: 19em", css)
        self.assertIn("min-width: 320px", css)
        self.assertIn("[hidden] { display: none !important; }", css)

    def test_javascript_is_syntax_valid_and_enforces_blind_contract(self) -> None:
        javascript_path = PROJECT_DIR / "static" / "gold-review.js"
        syntax = subprocess.run(
            ["node", "--check", str(javascript_path)],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        node_program = f"""
          const assert = require('assert');
          const hooks = require({json.dumps(str(javascript_path))});
          const payload = {{
            schema: 'r3/gold-set-blind-view/v1',
            status: 'y0_in_progress',
            item_count: 70,
            completed_count: 12,
            document_revision_sequence: 14,
            items: [{{
              item_id: 'analysis:1',
              record_class: 'complete_analysis',
              citation: {{
                title: 'A'.repeat(620),
                abstract: 'B'.repeat(6400),
                canonical_url: 'https://example.invalid/real-evidence'
              }},
              operational_evidence: {{}},
              y0: null
            }}]
          }};
          assert.strictEqual(hooks.validateBlindPayload(payload), payload);
          assert.throws(
            () => hooks.validateBlindPayload({{...payload, items: [{{...payload.items[0], citation: {{tier: 'must_read'}}}}]}}),
            /不应出现/
          );
          assert.throws(
            () => hooks.validateBlindPayload({{...payload, nested: {{model: 'remote-model'}}}}),
            /不应出现/
          );
          assert.strictEqual(hooks.canLock(70, 70), true);
          assert.strictEqual(hooks.canLock(69, 70), false);
          assert.strictEqual(hooks.canLock(500, 500), false);
          assert.strictEqual(hooks.confidenceNeedsReview({{semantic_label: 'known_important', confidence: 2}}), true);
          assert.strictEqual(hooks.confidenceNeedsReview({{semantic_label: 'unjudged', confidence: null}}), false);
          const submission = hooks.makeSubmission({{
            reviewId: 'review-real-001',
            reviewerIdentity: 'researcher-local',
            item: {{item_id: 'analysis:1', y0: {{revision_sequence: 2}}}},
            documentRevisionSequence: 19,
            values: {{
              semanticLabel: 'unjudged',
              operationalStatus: 'inaccessible',
              confidence: 5,
              evidenceOpened: false,
              notes: '缺少全文，当前能力范围内不能可靠判断。'
            }},
            elapsedMs: 184321,
            stableRequestId: 'retry-stable-request-id'
          }});
          assert.strictEqual(submission.request_id, 'retry-stable-request-id');
          assert.strictEqual(submission.confidence, null);
          assert.strictEqual(submission.expected_item_revision_sequence, 2);
          assert.strictEqual(submission.expected_document_revision_sequence, 19);
          assert.strictEqual(submission.elapsed_ms, 184321);
          assert.throws(() => hooks.makeSubmission({{
            reviewId: 'r', reviewerIdentity: 'u', item: {{item_id: 'x', y0: null}},
            documentRevisionSequence: 0,
            values: {{semanticLabel: 'known_important', operationalStatus: 'normal', confidence: null, evidenceOpened: false, notes: ''}},
            elapsedMs: 1, stableRequestId: 'x'
          }}), /置信度/);
          process.stdout.write('gold-ui-hooks-ok');
        """
        functional = subprocess.run(
            ["node", "-e", node_program],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(functional.returncode, 0, functional.stderr)
        self.assertEqual(functional.stdout, "gold-ui-hooks-ok")

        javascript = javascript_path.read_text(encoding="utf-8")
        self.assertIn("BroadcastChannel", javascript)
        self.assertIn("expected_item_revision_sequence", javascript)
        self.assertIn("expected_document_revision_sequence", javascript)
        self.assertIn("pendingPayload", javascript)
        self.assertIn("AUTOSAVE_DELAY_MS", javascript)
        self.assertIn("event.altKey && event.key === \"ArrowLeft\"", javascript)
        self.assertNotIn("innerHTML", javascript)


class GoldReviewUiHttpWorkflowTests(unittest.TestCase):
    def test_realistic_seventy_item_workflow_serves_ui_and_blind_pages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = _realistic_v1_gold()
            # Preserve realistic workload length while explicitly exercising
            # title overflow, absent abstracts, and inaccessible evidence.
            source["items"][0]["review_context"]["citation"]["title"] = (
                "Agent workflow cache objects across planner, retriever, tool, " * 18
            )
            source["items"][0]["frozen_snapshot"]["citation"]["title"] = source[
                "items"
            ][0]["review_context"]["citation"]["title"]
            for index in (2, 17, 41):
                source["items"][index]["review_context"]["citation"].pop(
                    "abstract", None
                )
                source["items"][index]["frozen_snapshot"]["citation"].pop(
                    "abstract", None
                )
            for item in source["items"]:
                item["snapshot_sha256"] = hashlib.sha256(
                    canonical_json(item["frozen_snapshot"]).encode("utf-8")
                ).hexdigest()
            source_path = root / "gold-realistic-70.json"
            source_path.write_text(
                json.dumps(source, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            server = RadarHttpServer(("127.0.0.1", 0), make_settings(root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = int(server.server_address[1])
                html_status, html_type, html_body = _request(
                    port, "GET", "/gold-review"
                )
                js_status, js_type, js_body = _request(
                    port, "GET", "/gold-review.js"
                )
                css_status, css_type, css_body = _request(
                    port, "GET", "/gold-review.css"
                )
                create_status, _, create_body = _request(
                    port,
                    "POST",
                    "/api/gold/reviews",
                    {
                        "source_path": str(source_path.resolve()),
                        "reviewer_identity": "researcher-real-workflow",
                        "creation_request_id": "ui-http-realistic-create-001",
                    },
                )
                created = json.loads(create_body)
                review_id = created["review"]["review_id"]
                first_status, _, first_body = _request(
                    port,
                    "GET",
                    f"/api/gold/reviews/{review_id}/y0?limit=25&offset=0",
                )
                middle_status, _, middle_body = _request(
                    port,
                    "GET",
                    f"/api/gold/reviews/{review_id}/y0?limit=25&offset=25",
                )
                last_status, _, last_body = _request(
                    port,
                    "GET",
                    f"/api/gold/reviews/{review_id}/y0?limit=25&offset=50",
                )
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

            self.assertEqual(
                (
                    html_status,
                    js_status,
                    css_status,
                    create_status,
                    first_status,
                    middle_status,
                    last_status,
                ),
                (200, 200, 200, 201, 200, 200, 200),
            )
            self.assertIn("text/html", html_type)
            self.assertIn("javascript", js_type)
            self.assertIn("text/css", css_type)
            self.assertIn(b"Gold y0", html_body)
            self.assertIn(b"validateBlindPayload", js_body)
            self.assertIn(b"max-width: 430px", css_body)
            self.assertNotIn(str(source_path).encode("utf-8"), create_body)

            pages = [json.loads(first_body), json.loads(middle_body), json.loads(last_body)]
            all_items = [item for page in pages for item in page["items"]]
            self.assertEqual(len(all_items), 70)
            self.assertEqual(len({item["item_id"] for item in all_items}), 70)
            self.assertGreater(
                sum(len(str(item["citation"].get("abstract", ""))) for item in all_items),
                55_000,
            )
            self.assertTrue(
                any(len(str(item["citation"].get("title", ""))) > 600 for item in all_items)
            )
            self.assertTrue(
                any(not item["citation"].get("abstract") for item in all_items)
            )
            self.assertEqual(
                sum(item["record_class"] == "operational_sentinel" for item in all_items),
                10,
            )
            serialized = json.dumps(pages, ensure_ascii=False)
            for leak in (
                "AI_LEAK",
                "must_read",
                "publication_selected",
                "candidate_unselected",
                "codex_cli",
                str(source_path),
            ):
                self.assertNotIn(leak, serialized)


if __name__ == "__main__":
    unittest.main()
