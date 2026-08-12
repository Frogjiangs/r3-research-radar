import http.client
import json
import subprocess
import tempfile
import textwrap
import threading
import unittest
from html.parser import HTMLParser
from pathlib import Path

from r3radar.config import PROJECT_DIR
from r3radar.web import RadarHttpServer
from tests.fixtures.synthetic_research_workflows import (
    seed_synthetic_research_workflows,
)
from tests.test_core import make_settings


class _StructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.attributes: dict[str, dict[str, str | None]] = {}

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = dict(attrs)
        element_id = values.get("id")
        if element_id:
            self.ids.append(element_id)
            self.attributes[element_id] = {"tag": tag, **values}
        if tag == "body":
            self.attributes["body"] = {"tag": tag, **values}


def _request(port: int, path: str) -> tuple[int, str, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
    response = connection.getresponse()
    body = response.read()
    content_type = response.getheader("Content-Type") or ""
    status = int(response.status)
    connection.close()
    return status, content_type, body


class DecisionOperationsUiTests(unittest.TestCase):
    def test_decision_mode_precedes_collapsed_operations_and_candidate_library(self) -> None:
        html = (PROJECT_DIR / "static" / "index.html").read_text(encoding="utf-8")
        parser = _StructureParser()
        parser.feed(html)

        self.assertEqual(parser.attributes["body"]["data-workspace-mode"], "decision")
        self.assertLess(parser.ids.index("decision-panel"), parser.ids.index("operations-panel"))
        self.assertLess(
            parser.ids.index("operations-panel"),
            parser.ids.index("candidate-browser-heading"),
        )
        self.assertEqual(parser.attributes["operations-panel"]["tag"], "details")
        self.assertNotIn("open", parser.attributes["operations-panel"])
        self.assertEqual(
            parser.attributes["decision-scope-toggle"]["aria-controls"],
            "decision-items",
        )
        for required in (
            "decision-core",
            "decision-signals",
            "decision-boundaries",
            "same-revision",
            "signal-outcome",
        ):
            self.assertIn(f'class="{required}', html)

        javascript = (PROJECT_DIR / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const DECISION_FOCUS_LIMIT = 3", javascript)
        self.assertIn('operations.open = false', javascript)
        self.assertIn('"/api/decision-slice?all=1"', javascript)
        self.assertIn('new URLSearchParams({limit: "25"})', javascript)
        self.assertIn("/api/work-analysis?work_id=", javascript)
        lazy_detail = javascript.split("/api/work-analysis?work_id=", 1)[1].split(
            "} catch (error)", 1
        )[0]
        self.assertNotIn(
            "renderWorks()",
            lazy_detail,
            "lazy detail must update its card in place instead of resetting focus",
        )
        self.assertIn("当前接口尚未采集使用后的研究结果", javascript)
        self.assertIn("不能声称主张与代码属于同一 revision", javascript)

        styles = (PROJECT_DIR / "static" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("@media (max-width: 650px)", styles)
        self.assertIn(".decision-core, .decision-signals { grid-template-columns: 1fr; }", styles)
        self.assertIn("button:focus-visible", styles)
        self.assertIn("summary:focus-visible", styles)

    def test_focus_slice_is_three_but_expanded_view_preserves_every_item(self) -> None:
        javascript_path = PROJECT_DIR / "static" / "app.js"
        node_script = textwrap.dedent(
            f"""
            const fs = require('fs');
            const vm = require('vm');
            const source = fs.readFileSync({json.dumps(str(javascript_path))}, 'utf8');
            const beforeBoot = source.split(
              'document.querySelector("#state-filter").addEventListener'
            )[0];
            const context = {{console}};
            vm.createContext(context);
            vm.runInContext(beforeBoot, context);
            const result = vm.runInContext(`
              (() => {{
                const items = [
                  {{analysis_id: 1, decision: {{}}}},
                  {{analysis_id: 2, decision: {{}}}},
                  {{analysis_id: 3, decision: {{}}}},
                  {{analysis_id: 4, decision: {{}}}},
                  {{analysis_id: 5, decision: {{action: 'save'}}}}
                ];
                decisionExpanded = false;
                const focused = decisionItemsForView(items).map(x => x.analysis_id);
                decisionExpanded = true;
                const expanded = decisionItemsForView(items).map(x => x.analysis_id);
                return JSON.stringify({{focused, expanded}});
              }})()
            `, context);
            process.stdout.write(result);
            """
        )
        completed = subprocess.run(
            ["node", "-e", node_script],
            cwd=PROJECT_DIR,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["focused"], [1, 2, 3])
        self.assertEqual(result["expanded"], [1, 2, 3, 4, 5])

    def test_realistic_long_workflow_serves_bounded_ui_and_lazy_summary_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            manifest = seed_synthetic_research_workflows(settings, count=16)
            self.assertGreaterEqual(manifest.total_abstract_characters, 30_000)
            self.assertGreaterEqual(manifest.total_analysis_characters, 70_000)

            server = RadarHttpServer(("127.0.0.1", 0), settings)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = int(server.server_address[1])
                html_status, html_type, html_body = _request(port, "/")
                js_status, js_type, js_body = _request(port, "/app.js")
                css_status, css_type, css_body = _request(port, "/styles.css")
                works_status, _, works_body = _request(port, "/api/works?limit=25")
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

            self.assertEqual((html_status, js_status, css_status, works_status), (200, 200, 200, 200))
            self.assertIn("text/html", html_type)
            self.assertIn("javascript", js_type)
            self.assertIn("text/css", css_type)
            self.assertIn(b'data-workspace-mode="decision"', html_body)
            self.assertIn(b"DECISION_FOCUS_LIMIT = 3", js_body)

            payload = json.loads(works_body)
            self.assertEqual(payload["total"], 16)
            self.assertEqual(len(payload["works"]), 16)
            self.assertTrue(
                all("analysis" not in work for work in payload["works"]),
                "long deep-read JSON must stay behind /api/work-analysis",
            )
            self.assertTrue(
                all(str(work["title"]).startswith("[SYNTHETIC]") for work in payload["works"])
            )


if __name__ == "__main__":
    unittest.main()
