from __future__ import annotations

import gzip
import hashlib
import http.client
import io
import json
import os
import queue
import re
import socket
import socketserver
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

from r3radar.__main__ import build_parser, main
from r3radar.codex_worker import (
    AnalysisBudgetPaused,
    CodexCli,
    CodexDeepReader,
    CodexHostedSearch,
    CodexInvocationError,
    CodexNonRetryableInvocationError,
    CodexResult,
    _WindowsKillOnCloseJob,
    planned_model_invocations,
    _resume_windows_process,
    split_text,
)
from r3radar.config import (
    DEFAULT_CONFIG,
    PROJECT_DIR,
    Settings,
    analysis_schema_policy_record,
    load_settings,
)
from r3radar.content import ContentProcessor
from r3radar.document_policy import (
    CURRENT_PDF_DOCUMENT_POLICY,
    CURRENT_PDF_DOCUMENT_POLICY_HASH,
    repository_ready_coverage_matches_policy,
    require_repository_ready_policy,
)
from r3radar.evidence import (
    EvidenceExcerptError,
    canonicalize_evidence_excerpt,
    evidence_anchor_region,
)
from r3radar.http_client import (
    FetchError,
    NonRetryableFetchError,
    RawReceipt,
    RawResponseStore,
    RetryDeferredError,
    SafeHttpClient,
)
from r3radar.llama_worker import LlamaCppRunner
from r3radar.models import (
    AdmissionDecision,
    SourceRecord,
    normalize_arxiv_id,
    normalize_doi,
    normalize_github_full_name,
    objective_admission,
)
from r3radar.pdf_parser import (
    PARSER_POLICY_VERSION,
    REQUIRED_PYPDF_VERSION,
    REQUEST_SCHEMA,
    RESULT_SCHEMA,
    PdfParseError,
    _WindowsPdfMutex,
    _validate_result,
    parse_pdf_with_worker,
)
from r3radar.pipeline import (
    RadarPipeline,
    TransferBudgetReached,
    _analysis_failure_should_retry,
)
from r3radar.ranking import normalize_and_rank
from r3radar.report import (
    generate_weekly_report,
    prepare_run_publication_candidates,
)
from r3radar.sources import compile_arxiv_query
from r3radar.storage import (
    SCHEMA_VERSION,
    FeedbackNotAllowedError,
    PublicationConflictError,
    PublicationNotAllowedError,
    RadarStore,
    RunAlreadyActiveError,
)
from r3radar.utils import JsonlAuditLog, json_dumps, sha256_text
from r3radar.verification import (
    HostedResultVerifier,
    HostedVerificationRejectedError,
    _CitationMetadataParser,
)
from r3radar.web import RadarHandler, RadarHttpServer


def make_settings(root: Path) -> Settings:
    raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    raw["documents"].pop("repository_corpus", None)
    raw["analysis"].pop("max_parallel_batches", None)
    raw["analysis"].pop("budget_planning", None)
    raw["analysis"].pop("output_detail", None)
    raw["documents"]["chunk_characters"] = 180
    raw["documents"]["chunk_overlap_characters"] = 20
    raw["analysis"]["batch_chunk_count"] = 2
    data = root / "data"
    literature = root / "literature"
    outputs = root / "outputs"
    for path in (data, literature, outputs):
        path.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        raw=raw,
        config_path=DEFAULT_CONFIG,
        project_dir=PROJECT_DIR,
        workspace_dir=root,
        data_dir=data,
        literature_dir=literature,
        outputs_dir=outputs,
        database_path=data / "radar.sqlite3",
    )
    settings.ensure_directories()
    return settings


def terminal_publication_summary(
    store: RadarStore,
    settings: Settings,
    *,
    run_id: str,
    lease_token: str,
    status: str = "completed",
) -> dict[str, object]:
    with store.transaction() as connection:
        now = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            UPDATE query_jobs
            SET status='completed', claim_lease_token=NULL,
                completed_at=COALESCE(completed_at, ?), updated_at=?
            WHERE run_id=? AND status IN ('pending','retry','running')
            """,
            (now, now, run_id),
        )
    summary = {
        "schema_version": "1.0",
        "run_id": run_id,
        "profile_id": settings.profile_id,
        "profile_version": settings.profile_version,
        "config_hash": settings.config_hash,
        "retrieval_hash": settings.retrieval_hash,
        "analysis_policy_hash": settings.analysis_policy_hash,
        "mode": "test",
        "status": status,
        "interrupted": False,
        "attention_required": False,
        "counts": store.dashboard_counts(
            settings.retrieval_hash,
            analysis_policy_hash=settings.analysis_policy_hash,
        ),
        "visible_backlog": {
            "present": False,
            "explained": False,
            "eligible_for_completed_with_gaps": False,
            "reason_codes": [],
        },
        "fatal_error": None,
    }
    store.complete_run_with_publication_snapshot(
        run_id,
        lease_token=lease_token,
        terminal_status=status,
        error=None,
        retrieval_hash=settings.retrieval_hash,
        analysis_policy_hash=settings.analysis_policy_hash,
        summary=summary,
        candidates=prepare_run_publication_candidates(settings, store),
    )
    return summary


def current_pdf_ready_coverage(**updates: object) -> dict[str, object]:
    parser_policy = CURRENT_PDF_DOCUMENT_POLICY["parser"]
    protocol = CURRENT_PDF_DOCUMENT_POLICY["protocol"]
    code = CURRENT_PDF_DOCUMENT_POLICY["code"]
    coverage: dict[str, object] = {
        "complete": True,
        "coverage_type": "text_layer",
        "security_status": "parsed_verified",
        "reason": None,
        "parser": {
            "id": parser_policy["id"],
            "version": parser_policy["version"],
            "policy_version": parser_policy["policy_version"],
            "effective_options": parser_policy["effective_options"],
            "request_schema": protocol["request_schema"],
            "result_schema": protocol["result_schema"],
            "isolation": {
                "integrity_level": "appcontainer_low",
                "credential_environment_keys": [],
            },
        },
        "parser_receipt": {
            "parser_id": parser_policy["id"],
            "parser_version": parser_policy["version"],
            "parser_policy_version": parser_policy["policy_version"],
            "request_schema": protocol["request_schema"],
            "result_schema": protocol["result_schema"],
            "worker_sha256": code["worker_sha256"],
            "sandbox_sha256": code["sandbox_sha256"],
            "return_code": 0,
            "termination": "process_exit",
        },
    }
    coverage.update(updates)
    return coverage


def public_dns_resolver(
    _hostname: str,
    port: int,
    **_: object,
) -> list[tuple[object, ...]]:
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", port),
        )
    ]


class ModelTests(unittest.TestCase):
    def test_codex_cli_passes_and_records_project_reasoning_effort(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["codex_cli"]["reasoning_effort"] = "max"
            audit = JsonlAuditLog(settings.outputs_dir / "audit.jsonl")
            observed_commands: list[list[str]] = []

            def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                observed_commands.append(command)
                response_path = Path(
                    command[command.index("--output-last-message") + 1]
                )
                response_path.write_text('{"ok":true}', encoding="utf-8")
                stdout = "\n".join(
                    [
                        json.dumps(
                            {
                                "type": "thread.started",
                                "thread_id": "reasoning-fixture",
                            }
                        ),
                        json.dumps(
                            {
                                "type": "turn.completed",
                                "usage": {
                                    "input_tokens": 10,
                                    "cached_input_tokens": 5,
                                    "output_tokens": 2,
                                },
                            }
                        ),
                    ]
                )
                return subprocess.CompletedProcess(
                    args=command,
                    returncode=0,
                    stdout=stdout,
                    stderr="",
                )

            codex = CodexCli(
                settings,
                audit,
                "reasoning-effort-test",
                runner=runner,
            )
            result = codex.run_structured(
                prompt="bounded reasoning fixture",
                schema_path=PROJECT_DIR / "schemas" / "chunk_analysis.schema.json",
                purpose="reasoning_fixture",
            )

            command = observed_commands[0]
            override_index = command.index("--config")
            self.assertEqual(
                command[override_index + 1],
                'model_reasoning_effort="max"',
            )
            self.assertEqual(result.receipt["reasoning_effort"], "max")
            self.assertEqual(result.payload, {"ok": True})

    def test_codex_schema_error_uses_event_payload_and_is_non_retryable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            audit = JsonlAuditLog(settings.outputs_dir / "audit.jsonl")
            event_message = json.dumps(
                {
                    "type": "error",
                    "error": {
                        "type": "invalid_request_error",
                        "code": "invalid_json_schema",
                        "message": "'uniqueItems' is not permitted.",
                    },
                    "status": 400,
                }
            )
            runner = Mock(
                return_value=subprocess.CompletedProcess(
                    args=[],
                    returncode=1,
                    stdout="\n".join(
                        [
                            json.dumps(
                                {
                                    "type": "thread.started",
                                    "thread_id": "thread-fixture",
                                }
                            ),
                            json.dumps(
                                {
                                    "type": "turn.failed",
                                    "error": {"message": event_message},
                                }
                            ),
                        ]
                    ),
                    stderr="",
                )
            )
            codex = CodexCli(
                settings,
                audit,
                "schema-error-test",
                runner=runner,
            )
            with self.assertRaises(
                CodexNonRetryableInvocationError
            ) as raised:
                codex.run_structured(
                    prompt="bounded schema fixture",
                    schema_path=(
                        PROJECT_DIR
                        / "schemas"
                        / "synthesis_reduce.schema.json"
                    ),
                    purpose="schema_fixture",
                )

            self.assertIn("HTTP 400 invalid_json_schema", str(raised.exception))
            self.assertIn("uniqueItems", str(raised.exception))
            self.assertFalse(
                _analysis_failure_should_retry(raised.exception, attempts=1)
            )
            self.assertTrue(
                _analysis_failure_should_retry(
                    RuntimeError("transient"),
                    attempts=1,
                )
            )
            audit_event = json.loads(
                audit.path.read_text(encoding="utf-8").splitlines()[-1]
            )
            self.assertEqual(
                audit_event["details"]["event_error_code"],
                "invalid_json_schema",
            )
            self.assertIn(
                "uniqueItems",
                audit_event["details"]["event_error_tail"],
            )
            self.assertEqual(
                audit_event["details"]["receipt"]["schema_sha256"],
                hashlib.sha256(
                    (
                        PROJECT_DIR
                        / "schemas"
                        / "synthesis_reduce.schema.json"
                    ).read_bytes()
                ).hexdigest(),
            )

    def test_keyboard_interrupt_terminates_the_active_codex_process_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            audit = JsonlAuditLog(settings.outputs_dir / "audit.jsonl")
            process = Mock()
            process.pid = 43210
            process.poll.return_value = None
            process.communicate.side_effect = KeyboardInterrupt
            process.wait.return_value = 0
            kill_job = Mock()
            with (
                patch(
                    "r3radar.codex_worker.subprocess.run",
                    return_value=Mock(returncode=0),
                ) as taskkill,
                patch(
                    "r3radar.codex_worker.subprocess.Popen",
                    return_value=process,
                ),
                patch(
                    "r3radar.codex_worker._WindowsKillOnCloseJob",
                    return_value=kill_job,
                ),
                patch(
                    "r3radar.codex_worker._resume_windows_process",
                ) as resume_process,
            ):
                codex = CodexCli(settings, audit, "interrupt-test")
                with self.assertRaises(KeyboardInterrupt):
                    codex.run_structured(
                        prompt="bounded interrupt fixture",
                        schema_path=(
                            PROJECT_DIR
                            / "schemas"
                            / "chunk_analysis.schema.json"
                        ),
                        purpose="interrupt_fixture",
                    )

            process.communicate.assert_called_once()
            process.wait.assert_called_once_with(timeout=15)
            resume_process.assert_called_once_with(process)
            kill_job.close.assert_called_once()
            taskkill.assert_called_once()
            command = taskkill.call_args.args[0]
            self.assertEqual(command[:2], ["taskkill", "/PID"])
            self.assertEqual(command[2], "43210")
            events = [
                json.loads(line)
                for line in audit.path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(events[-1]["event_type"], "codex_interrupted")

    def test_keyboard_interrupt_terminates_codex_authentication_process_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            audit = JsonlAuditLog(settings.outputs_dir / "audit.jsonl")
            process = Mock()
            process.pid = 43211
            process.poll.return_value = None
            process.communicate.side_effect = KeyboardInterrupt
            process.wait.return_value = 0
            kill_job = Mock()
            with (
                patch(
                    "r3radar.codex_worker.subprocess.run",
                    return_value=Mock(returncode=0),
                ) as taskkill,
                patch(
                    "r3radar.codex_worker.subprocess.Popen",
                    return_value=process,
                ),
                patch(
                    "r3radar.codex_worker._WindowsKillOnCloseJob",
                    return_value=kill_job,
                ),
                patch(
                    "r3radar.codex_worker._resume_windows_process",
                ) as resume_process,
            ):
                codex = CodexCli(settings, audit, "auth-interrupt-test")
                with self.assertRaises(KeyboardInterrupt):
                    codex.authenticated()

            process.communicate.assert_called_once_with(input=None, timeout=30)
            process.wait.assert_called_once_with(timeout=15)
            resume_process.assert_called_once_with(process)
            kill_job.close.assert_called_once()
            taskkill.assert_called_once()
            self.assertEqual(taskkill.call_args.args[0][2], "43211")

    @unittest.skipUnless(os.name == "nt", "Windows job object fixture")
    def test_windows_suspended_job_closes_the_immediate_spawn_race(self) -> None:
        parent_code = (
            "import subprocess,sys;"
            "child_code=("
            "\"import json,subprocess,sys,time;\""
            "\"grand=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);\""
            "\"open(sys.argv[1],'w',encoding='utf-8').write(json.dumps({'child':__import__('os').getpid(),'grandchild':grand.pid}));\""
            "\"time.sleep(60)\""
            ");"
            "child=subprocess.Popen([sys.executable,'-c',child_code,sys.argv[1]],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "print(child.pid,flush=True)"
        )

        def process_is_running(pid: int) -> bool:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetExitCodeProcess.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return False
                return exit_code.value == 259
            finally:
                kernel32.CloseHandle(handle)

        with tempfile.TemporaryDirectory() as temporary:
            receipt_path = Path(temporary) / "descendants.json"
            base_python = getattr(sys, "_base_executable", sys.executable)
            creationflags = (
                subprocess.CREATE_NO_WINDOW
                | subprocess.CREATE_NEW_PROCESS_GROUP
                | 0x00000004
            )
            process = subprocess.Popen(
                [base_python, "-c", parent_code, str(receipt_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                creationflags=creationflags,
            )
            job = _WindowsKillOnCloseJob(process)
            _resume_windows_process(process)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, stderr)
            child_pid = int(stdout.strip())
            deadline = time.monotonic() + 10
            while not receipt_path.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(receipt_path.exists())
            descendants = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(descendants["child"], child_pid)
            self.assertTrue(process_is_running(descendants["child"]))
            self.assertTrue(process_is_running(descendants["grandchild"]))

            job.close()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not any(process_is_running(pid) for pid in descendants.values()):
                    break
                time.sleep(0.02)
            self.assertFalse(process_is_running(descendants["child"]))
            self.assertFalse(process_is_running(descendants["grandchild"]))

    @unittest.skipUnless(os.name == "nt", "Windows job object fixture")
    def test_codex_authentication_closes_immediate_descendants_after_root_exit(
        self,
    ) -> None:
        def process_is_running(pid: int) -> bool:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetExitCodeProcess.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return False
            try:
                exit_code = wintypes.DWORD()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return False
                return exit_code.value == 259
            finally:
                kernel32.CloseHandle(handle)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            audit = JsonlAuditLog(settings.outputs_dir / "auth-job-audit.jsonl")
            receipt_path = root / "auth-descendants.json"
            script_path = root / "auth_fixture.py"
            child_code = (
                "import json,os,subprocess,sys,time;"
                "grand=subprocess.Popen("
                "[sys.executable,'-c','import time;time.sleep(60)'],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL);"
                "open(sys.argv[1],'w',encoding='utf-8').write("
                "json.dumps({'child':os.getpid(),'grandchild':grand.pid}));"
                "time.sleep(60)"
            )
            script_path.write_text(
                "import pathlib,subprocess,sys,time\n"
                f"receipt=pathlib.Path({str(receipt_path)!r})\n"
                f"child_code={child_code!r}\n"
                "subprocess.Popen("
                "[sys.executable,'-c',child_code,str(receipt)],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL)\n"
                "deadline=time.monotonic()+10\n"
                "while not receipt.exists() and time.monotonic()<deadline:\n"
                "    time.sleep(0.01)\n"
                "print('Logged in',flush=True)\n",
                encoding="utf-8",
                newline="\n",
            )
            codex = CodexCli(settings, audit, "auth-job-test")
            codex.node = getattr(sys, "_base_executable", sys.executable)
            codex.script = script_path

            self.assertTrue(codex.authenticated())
            self.assertTrue(receipt_path.exists())
            descendants = json.loads(receipt_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not any(process_is_running(pid) for pid in descendants.values()):
                    break
                time.sleep(0.02)
            self.assertFalse(process_is_running(descendants["child"]))
            self.assertFalse(process_is_running(descendants["grandchild"]))

    def test_run_resource_limits_reject_zero_and_boolean_values(self) -> None:
        for invalid in (0, False):
            with self.subTest(invalid=invalid):
                with tempfile.TemporaryDirectory() as temporary:
                    raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
                    raw["run"]["max_transfer_bytes_per_invocation"] = invalid
                    config_path = Path(temporary) / "invalid.json"
                    config_path.write_text(
                        json.dumps(raw, ensure_ascii=False),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(
                        ValueError,
                        "run.max_transfer_bytes_per_invocation",
                    ):
                        load_settings(config_path)

    def test_deep_read_execution_config_rejects_unbounded_parallelism(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
            raw["analysis"]["max_parallel_batches"] = 3
            config_path = Path(temporary) / "invalid-parallel.json"
            config_path.write_text(
                json.dumps(raw, ensure_ascii=False),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "max_parallel_batches",
                ):
                    load_settings(config_path)

    def test_deep_read_execution_config_rejects_unknown_reasoning_effort(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
            raw["analysis"]["codex_cli"]["reasoning_effort"] = "unbounded"
            config_path = Path(temporary) / "invalid-reasoning.json"
            config_path.write_text(
                json.dumps(raw, ensure_ascii=False),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "reasoning_effort",
            ):
                load_settings(config_path)

    def test_repository_corpus_config_rejects_auxiliary_budget_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
            raw["documents"]["repository_corpus"][
                "max_auxiliary_text_bytes"
            ] = (
                raw["documents"]["repository_corpus"][
                    "max_selected_text_bytes"
                ]
                + 1
            )
            config_path = Path(temporary) / "invalid-corpus.json"
            config_path.write_text(
                json.dumps(raw, ensure_ascii=False),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "auxiliary text budget",
            ):
                load_settings(config_path)

    def test_pdf_document_policy_hash_covers_runtime_and_isolation_code(self) -> None:
        policy = CURRENT_PDF_DOCUMENT_POLICY
        self.assertEqual(
            policy["parser"]["runtime_dependencies"]["typing_extensions"],
            "4.16.0",
        )
        code = policy["code"]
        expected_files = {
            "supervisor_sha256": "pdf_parser.py",
            "appcontainer_sha256": "windows_appcontainer.py",
            "worker_sha256": "pdf_worker.py",
            "sandbox_sha256": "pdf_sandbox.py",
        }
        for key, filename in expected_files.items():
            self.assertEqual(
                code[key],
                hashlib.sha256(
                    (PROJECT_DIR / "r3radar" / filename).read_bytes()
                ).hexdigest(),
            )
        canonical = json.dumps(
            policy,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            CURRENT_PDF_DOCUMENT_POLICY_HASH,
            hashlib.sha256(canonical).hexdigest(),
        )

    def test_arxiv_query_keeps_pairwise_topic_anchors_without_all_term_and(self) -> None:
        self.assertEqual(
            compile_arxiv_query('"agent workflow" "KV cache" reuse'),
            '((all:"agent workflow" OR (all:"agent" AND all:"workflow")) AND '
            '(all:"KV cache" OR (all:"KV" AND all:"cache")) AND all:"reuse")',
        )
        self.assertEqual(
            compile_arxiv_query('"prefix cache" "agent workflow"'),
            '((all:"prefix cache" OR (all:"prefix" AND all:"cache")) AND '
            '(all:"agent workflow" OR (all:"agent" AND all:"workflow")))',
        )

    def test_identifier_normalization_and_objective_gates(self) -> None:
        self.assertEqual(normalize_doi("https://doi.org/10.1234/ABC"), "10.1234/abc")
        self.assertEqual(normalize_arxiv_id("https://arxiv.org/abs/2405.16444v2"), "2405.16444")
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            record = SourceRecord(
                source="arxiv",
                source_id="2405.16444",
                kind="paper",
                title="CacheBlend",
                query_id="q01",
                year=2024,
                arxiv_id="2405.16444v2",
            )
            decision = objective_admission(record, settings.raw)
            self.assertTrue(decision.admitted)
            self.assertEqual(decision.lane, "frontier")
            record.retracted = True
            self.assertEqual(objective_admission(record, settings.raw).code, "retracted")

    def test_github_full_name_rejects_path_traversal(self) -> None:
        with self.assertRaises(ValueError):
            normalize_github_full_name("owner/../../user")
        self.assertEqual(
            normalize_github_full_name("OpenAI/Codex"),
            "openai/codex",
        )

    def test_split_text_has_no_uncovered_character_ranges(self) -> None:
        text = "=== PAGE 1 ===\n" + ("abcdef\n" * 100)
        chunks = split_text(text, 120, 20)
        self.assertGreater(len(chunks), 1)
        self.assertEqual(chunks[0]["start"], 0)
        self.assertEqual(chunks[-1]["end"], len(text))
        for left, right in zip(chunks, chunks[1:]):
            self.assertLessEqual(right["start"], left["end"])
            self.assertGreater(right["end"], left["end"])

    def test_split_text_preserves_nearest_and_inside_markers_at_scale(self) -> None:
        pages = [
            f"=== PAGE {index} ===\n" + (f"page-{index}-evidence\n" * 40)
            for index in range(1, 401)
        ]
        text = "".join(pages)
        chunks = split_text(text, 6500, 350)
        self.assertGreater(len(chunks), 40)
        self.assertEqual(chunks[0]["span"]["anchors"][0], "=== PAGE 1 ===")
        self.assertEqual(chunks[-1]["end"], len(text))
        for chunk in chunks:
            for anchor in chunk["span"]["anchors"]:
                self.assertIn(anchor, text)
            self.assertEqual(
                len(chunk["span"]["anchors"]),
                len(set(chunk["span"]["anchors"])),
            )

    def test_split_text_uses_only_sidecar_trusted_repository_markers(
        self,
    ) -> None:
        trusted = "=== FILE: src/cache.py ==="
        injected = "=== FILE: forged/claim.py ==="
        text = (
            f"{trusted}\nreal code\n"
            f"{injected}\nuntrusted source text\n"
        )
        chunks = split_text(
            text,
            80,
            10,
            trusted_markers=[
                {
                    "anchor": trusted,
                    "start": 0,
                    "end": len(trusted),
                }
            ],
        )
        anchors = {
            anchor
            for chunk in chunks
            for anchor in chunk["span"]["anchors"]
        }
        self.assertIn(trusted, anchors)
        self.assertNotIn(injected, anchors)

    def test_trusted_repository_region_ignores_forged_source_markers(
        self,
    ) -> None:
        trusted = "=== FILE: src/cache.py ==="
        forged = "=== FILE: forged/claim.py ==="
        evidence = "semantic cache value survives the forged marker"
        text = f"{trusted}\nreal code\n{forged}\n{evidence}\n"
        chunk = split_text(
            text,
            200,
            10,
            trusted_markers=[
                {
                    "anchor": trusted,
                    "start": 0,
                    "end": len(trusted),
                }
            ],
        )[0]
        region = evidence_anchor_region(
            chunk["text"],
            trusted,
            [trusted],
            trusted_anchor_regions=chunk["span"][
                "trusted_anchor_regions"
            ],
        )
        self.assertIn(forged, region)
        self.assertIn(evidence, region)
        canonical = canonicalize_evidence_excerpt(evidence, region)
        self.assertEqual(canonical.excerpt, evidence)

    def test_deep_read_call_plan_exposes_budget_infeasibility_before_work(self) -> None:
        plan = planned_model_invocations(
            chunk_total=534,
            batch_chunk_count=6,
            synthesis_group_max_items=24,
            retry_reserve_invocations=12,
        )
        self.assertEqual(plan["chunk_calls"], 89)
        self.assertEqual(plan["minimum_reduction_calls"], 23)
        self.assertEqual(plan["final_synthesis_calls"], 1)
        self.assertEqual(plan["planned_total"], 125)

    def test_synthesis_level_preflight_hard_blocks_known_requirements_only(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["synthesis_group_max_items"] = 24
            settings.raw["analysis"]["budget_planning"] = {
                "retry_reserve_invocations": 0
            }
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_task"
            ] = 25
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_run"
            ] = 25
            store = Mock()
            store.model_usage.return_value = {"invocation_count": 0}
            reader = CodexDeepReader(
                settings,
                store,
                object(),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run-fixture",
                "lease-fixture",
            )
            with self.assertRaises(AnalysisBudgetPaused) as raised:
                reader._preflight_synthesis_level_budget(
                    task_id=1,
                    level=0,
                    group_count=25,
                )
            self.assertEqual(
                raised.exception.boundary_reason,
                "known_synthesis_requirement_exceeds_limit",
            )
            self.assertEqual(raised.exception.actual, 26)
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_task"
            ] = 24
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_run"
            ] = 24
            with self.assertRaises(AnalysisBudgetPaused) as conditional:
                reader._preflight_synthesis_level_budget(
                    task_id=1,
                    level=0,
                    group_count=24,
                )
            self.assertEqual(conditional.exception.actual, 25)

    def test_synthesis_level_preflight_reuses_only_validated_current_nodes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["synthesis_group_max_items"] = 24
            settings.raw["analysis"]["budget_planning"] = {
                "retry_reserve_invocations": 0
            }
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_task"
            ] = 2
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_run"
            ] = 2
            store = Mock()
            store.model_usage.return_value = {"invocation_count": 0}
            reader = CodexDeepReader(
                settings,
                store,
                object(),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run-fixture",
                "lease-fixture",
            )
            reader._preflight_synthesis_level_budget(
                task_id=1,
                level=0,
                group_count=25,
                reusable_current_level_nodes=25,
            )

    def test_corrupt_synthesis_node_is_not_validated_for_budget_reuse(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            store = Mock()
            reader = CodexDeepReader(
                settings,
                store,
                object(),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run-fixture",
                "lease-fixture",
            )
            invalid_coverages = (
                ('["not-an-int"]', [0]),
                ("[0]", "0"),
                ("[true]", [0]),
            )
            for stored_coverage, output_coverage in invalid_coverages:
                with self.subTest(
                    stored_coverage=stored_coverage,
                    output_coverage=output_coverage,
                ):
                    store.load_synthesis_node.return_value = {
                        "covered_chunk_indices_json": stored_coverage,
                        "output_json": json.dumps(
                            {
                                "candidate_id": 7,
                                "level": 0,
                                "node_index": 0,
                                "summary_zh": "损坏的历史节点",
                                "covered_chunk_indices": output_coverage,
                                "evidence_anchors": ["=== FILE core.py ==="],
                            }
                        ),
                    }
                    validated = reader._validated_synthesis_node(
                        task={"id": 1, "work_id": 7},
                        level=0,
                        node_index=0,
                        input_sha256="expected-input",
                        covered=[0],
                        allowed_anchors={"=== FILE core.py ==="},
                    )
                    self.assertIsNone(validated)

    def test_analysis_policy_hash_tracks_semantic_model_settings_not_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            original_analysis_hash = settings.analysis_policy_hash
            original_retrieval_hash = settings.retrieval_hash
            original_model = settings.raw["analysis"]["codex_cli"]["model"]
            original_effort = settings.raw["analysis"]["codex_cli"].get(
                "reasoning_effort"
            )
            settings.raw["analysis"]["budgets"]["max_invocations_per_run"] += 1
            self.assertEqual(
                settings.analysis_policy_hash,
                original_analysis_hash,
            )
            settings.raw["analysis"]["max_parallel_batches"] = 2
            settings.raw["analysis"]["budget_planning"] = {
                "retry_reserve_invocations": 12
            }
            self.assertEqual(
                settings.analysis_policy_hash,
                original_analysis_hash,
            )
            settings.raw["analysis"]["output_detail"] = "concise_evidence"
            self.assertNotEqual(
                settings.analysis_policy_hash,
                original_analysis_hash,
            )
            settings.raw["analysis"].pop("output_detail")
            settings.raw["analysis"]["codex_cli"]["model"] = "different-model"
            self.assertNotEqual(
                settings.analysis_policy_hash,
                original_analysis_hash,
            )
            settings.raw["analysis"]["codex_cli"]["model"] = original_model
            settings.raw["analysis"]["codex_cli"]["reasoning_effort"] = (
                "xhigh" if original_effort == "max" else "max"
            )
            self.assertNotEqual(
                settings.analysis_policy_hash,
                original_analysis_hash,
            )
            self.assertEqual(settings.retrieval_hash, original_retrieval_hash)

    def test_zero_to_ten_scores_are_normalized_before_tiering(self) -> None:
        analysis = {
            "score_scale": "0_to_10",
            "scores": {
                "novelty": 8,
                "r3_relevance": 7,
                "evidence_strength": 7.5,
                "reuse_signal_value": 6.5,
                "implementability": 8,
                "overall": 7.3,
            },
            "tier": "out_of_scope_after_deep_read",
        }
        overall, tier, changed = normalize_and_rank(analysis)
        self.assertTrue(changed)
        self.assertEqual(overall, 73.0)
        self.assertEqual(tier, "important")
        self.assertEqual(analysis["scores"]["r3_relevance"], 70.0)

    def test_explicit_zero_to_hundred_low_scores_are_not_amplified(self) -> None:
        analysis = {
            "score_scale": "0_to_100",
            "scores": {
                "novelty": 5,
                "r3_relevance": 8,
                "evidence_strength": 10,
                "reuse_signal_value": 6,
                "implementability": 9,
                "overall": 0,
            },
            "tier": "important",
        }
        overall, tier, _ = normalize_and_rank(analysis)
        self.assertEqual(overall, 7.55)
        self.assertEqual(tier, "out_of_scope_after_deep_read")
        self.assertEqual(analysis["scores"]["evidence_strength"], 10.0)


class HttpTests(unittest.TestCase):
    def test_http_client_accounts_every_success_response_byte(self) -> None:
        body = b"bounded-transfer-receipt"
        consumed: list[int] = []

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
                byte_consumer=consumed.append,
            )
            try:
                downloaded, _, _ = client.request_bytes(
                    "https://example.com/file",
                    max_bytes=1024,
                    raw_suffix="bin",
                    allowed_hosts={"example.com"},
                )
            finally:
                client.close()

        self.assertEqual(downloaded, body)
        self.assertEqual(sum(consumed), len(body))

    def test_http_client_accounts_retry_terminal_and_redirect_bodies(self) -> None:
        retry_bodies = [b"rate-limited", b"x" * (1024 * 1024 + 17)]
        redirect_body = b"redirect-receipt"
        final_body = b"redirect-target"
        terminal_body = b"terminal-not-found"
        consumed: list[int] = []

        retry_calls = 0

        def retry_handler(_request: httpx.Request) -> httpx.Response:
            nonlocal retry_calls
            body = retry_bodies[retry_calls]
            retry_calls += 1
            status = 429 if retry_calls == 1 else 500
            headers = {"Retry-After": "0"} if status == 429 else {}
            return httpx.Response(status, headers=headers, content=body)

        redirect_calls = 0

        def redirect_handler(_request: httpx.Request) -> httpx.Response:
            nonlocal redirect_calls
            redirect_calls += 1
            if redirect_calls == 1:
                return httpx.Response(
                    302,
                    headers={"Location": "https://example.com/final"},
                    content=redirect_body,
                )
            return httpx.Response(200, content=final_body)

        def terminal_handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, content=terminal_body)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def make_client(
                source: str,
                handler: object,
                *,
                max_attempts: int = 1,
            ) -> SafeHttpClient:
                return SafeHttpClient(
                    source=source,
                    delay_seconds=0,
                    raw_store=RawResponseStore(root / "raw"),
                    audit=JsonlAuditLog(root / f"{source}.audit.jsonl"),
                    run_id="run",
                    transport=httpx.MockTransport(handler),
                    resolver=public_dns_resolver,
                    byte_consumer=consumed.append,
                    sleeper=lambda _seconds: None,
                    max_attempts=max_attempts,
                )

            retry_client = make_client("retry", retry_handler, max_attempts=2)
            redirect_client = make_client("redirect", redirect_handler)
            terminal_client = make_client("terminal", terminal_handler)
            try:
                with self.assertRaises(FetchError):
                    retry_client.request_bytes(
                        "https://example.com/retry",
                        max_bytes=2 * 1024 * 1024,
                        raw_suffix="bin",
                        allowed_hosts={"example.com"},
                    )
                downloaded, _, _ = redirect_client.request_bytes(
                    "https://example.com/start",
                    max_bytes=1024,
                    raw_suffix="bin",
                    allowed_hosts={"example.com"},
                )
                with self.assertRaises(NonRetryableFetchError):
                    terminal_client.request_bytes(
                        "https://example.com/missing",
                        max_bytes=1024,
                        raw_suffix="bin",
                        allowed_hosts={"example.com"},
                    )
            finally:
                retry_client.close()
                redirect_client.close()
                terminal_client.close()

            expected = (
                sum(len(body) for body in retry_bodies)
                + len(redirect_body)
                + len(final_body)
                + len(terminal_body)
            )
            self.assertEqual(downloaded, final_body)
            self.assertEqual(sum(consumed), expected)
            retry_events = [
                json.loads(line)
                for line in (root / "retry.audit.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if json.loads(line)["event_type"] == "http_retry"
            ]
            self.assertEqual(
                retry_events[-1]["details"]["response_bytes"],
                len(retry_bodies[-1]),
            )
            self.assertEqual(
                retry_events[-1]["details"]["captured_response_bytes"],
                1024 * 1024,
            )

    def test_every_server_error_status_body_is_accounted(self) -> None:
        statuses = (500, 501, 505, 511, 599)
        consumed: list[int] = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = 0
            for status in statuses:
                body = f"server-error-{status}".encode("ascii")
                expected += len(body)
                client = SafeHttpClient(
                    source=f"status-{status}",
                    delay_seconds=0,
                    raw_store=RawResponseStore(root / "raw"),
                    audit=JsonlAuditLog(root / f"{status}.audit.jsonl"),
                    run_id="run",
                    transport=httpx.MockTransport(
                        lambda _request, code=status, payload=body: httpx.Response(
                            code,
                            content=payload,
                        )
                    ),
                    resolver=public_dns_resolver,
                    byte_consumer=consumed.append,
                    max_attempts=1,
                )
                try:
                    with self.assertRaises(FetchError):
                        client.request_bytes(
                            "https://example.com/server-error",
                            max_bytes=1024,
                            raw_suffix="bin",
                            allowed_hosts={"example.com"},
                        )
                finally:
                    client.close()

            self.assertEqual(sum(consumed), expected)

    def test_non_followed_redirect_and_terminal_status_bodies_are_accounted(
        self,
    ) -> None:
        statuses = (300, 304, 418)
        consumed: list[int] = []

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = 0
            for status in statuses:
                body = f"terminal-status-{status}".encode("ascii")
                expected += len(body)
                client = SafeHttpClient(
                    source=f"terminal-{status}",
                    delay_seconds=0,
                    raw_store=RawResponseStore(root / "raw"),
                    audit=JsonlAuditLog(root / f"{status}.audit.jsonl"),
                    run_id="run",
                    transport=httpx.MockTransport(
                        lambda _request, code=status, payload=body: httpx.Response(
                            code,
                            content=payload,
                        )
                    ),
                    resolver=public_dns_resolver,
                    byte_consumer=consumed.append,
                )
                try:
                    with self.assertRaises(NonRetryableFetchError):
                        client.request_bytes(
                            "https://example.com/terminal",
                            max_bytes=1024,
                            raw_suffix="bin",
                            allowed_hosts={"example.com"},
                        )
                finally:
                    client.close()

            self.assertEqual(sum(consumed), expected)

    def test_transfer_crossing_chunk_is_counted_and_not_saved(self) -> None:
        body = b"x" * (SafeHttpClient.RESPONSE_CHUNK_BYTES * 2)

        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            settings.raw["run"]["max_transfer_bytes_per_invocation"] = 5
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                client = SafeHttpClient(
                    source="crossing",
                    delay_seconds=0,
                    raw_store=pipeline.raw_store,
                    audit=pipeline.audit,
                    run_id=pipeline.run_id,
                    transport=httpx.MockTransport(handler),
                    resolver=public_dns_resolver,
                    byte_consumer=pipeline._consume_transfer_bytes,
                    observation_chunk_bytes=(
                        pipeline._transfer_observation_chunk_bytes()
                    ),
                )
                try:
                    with self.assertRaises(TransferBudgetReached) as raised:
                        client.request_bytes(
                            "https://example.com/file",
                            max_bytes=len(body),
                            raw_suffix="bin",
                            allowed_hosts={"example.com"},
                        )
                finally:
                    client.close()
                pipeline._record_transfer_backlog(
                    raised.exception,
                    stage="content",
                )
                self.assertEqual(pipeline._transfer_bytes_received, 5)
                self.assertLess(pipeline._transfer_bytes_received, len(body))
                self.assertEqual(
                    pipeline._visible_backlog["transfer_budget_reached"][
                        "observed_bytes"
                    ],
                    5,
                )
                self.assertEqual(
                    pipeline._visible_backlog["transfer_budget_reached"][
                        "overshoot_bytes"
                    ],
                    0,
                )
                self.assertEqual(list((settings.data_dir / "raw").rglob("*.gz")), [])

    def test_transfer_budget_is_aggregate_across_http_clients(self) -> None:
        bodies = (b"1234", b"56")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            settings.raw["run"]["max_transfer_bytes_per_invocation"] = 5
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                clients: list[SafeHttpClient] = []
                for index, body in enumerate(bodies):
                    client = SafeHttpClient(
                        source=f"aggregate-{index}",
                        delay_seconds=0,
                        raw_store=pipeline.raw_store,
                        audit=pipeline.audit,
                        run_id=pipeline.run_id,
                        transport=httpx.MockTransport(
                            lambda _request, payload=body: httpx.Response(
                                200,
                                content=payload,
                            )
                        ),
                        resolver=public_dns_resolver,
                        byte_consumer=pipeline._consume_transfer_bytes,
                        observation_chunk_bytes=(
                            pipeline._transfer_observation_chunk_bytes()
                        ),
                    )
                    clients.append(client)
                try:
                    first, _, _ = clients[0].request_bytes(
                        "https://example.com/first",
                        max_bytes=1024,
                        raw_suffix="bin",
                        allowed_hosts={"example.com"},
                    )
                    with self.assertRaises(TransferBudgetReached) as raised:
                        clients[1].request_bytes(
                            "https://example.com/second",
                            max_bytes=1024,
                            raw_suffix="bin",
                            allowed_hosts={"example.com"},
                        )
                finally:
                    for client in clients:
                        client.close()

                self.assertEqual(first, bodies[0])
                self.assertEqual(pipeline._transfer_bytes_received, 5)
                self.assertLessEqual(pipeline._transfer_bytes_received, 5)
                self.assertEqual(raised.exception.observed_bytes, 5)
                self.assertEqual(raised.exception.overshoot_bytes, 0)
                self.assertEqual(
                    raised.exception.boundary_reason,
                    "guard_band_reached",
                )
                stored = list((settings.data_dir / "raw").rglob("*.gz"))
                self.assertEqual(len(stored), 1)
                self.assertEqual(gzip.decompress(stored[0].read_bytes()), bodies[0])

    def test_raw_response_store_is_deterministic_and_rebuilds_invalid_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RawResponseStore(Path(temporary))
            body = (b"deterministic raw response\n" * 1000) + bytes(range(256))

            digest, path = store.save("test", body, "json")
            original_archive = path.read_bytes()

            self.assertEqual(digest, hashlib.sha256(body).hexdigest())
            self.assertEqual(gzip.decompress(original_archive), body)
            self.assertEqual(int.from_bytes(original_archive[4:8], "little"), 0)

            for invalid_archive in (
                b"not a gzip archive",
                gzip.compress(b"different raw response", mtime=0),
            ):
                path.write_bytes(invalid_archive)
                rebuilt_digest, rebuilt_path = store.save("test", body, "json")
                self.assertEqual(rebuilt_digest, digest)
                self.assertEqual(rebuilt_path, path)
                self.assertEqual(path.read_bytes(), original_archive)
                self.assertEqual(gzip.decompress(path.read_bytes()), body)

    def test_raw_response_store_concurrent_same_digest_is_complete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RawResponseStore(Path(temporary))
            body = bytes(range(256)) * 4096
            writer_count = 12
            start = threading.Barrier(writer_count)
            results: list[tuple[str, Path]] = []
            failures: list[BaseException] = []

            def save_body() -> None:
                try:
                    start.wait()
                    results.append(store.save("test", body, "json"))
                except BaseException as exc:
                    failures.append(exc)

            writers = [
                threading.Thread(target=save_body)
                for _ in range(writer_count)
            ]
            for writer in writers:
                writer.start()
            for writer in writers:
                writer.join()

            self.assertEqual(failures, [])
            self.assertEqual(len(results), writer_count)
            self.assertEqual(
                {digest for digest, _ in results},
                {hashlib.sha256(body).hexdigest()},
            )
            self.assertEqual(len({path for _, path in results}), 1)
            path = results[0][1]
            self.assertEqual(gzip.decompress(path.read_bytes()), body)
            self.assertEqual(list(path.parent.glob(".raw-response-*.tmp")), [])

    def test_raw_response_store_multiple_instances_serialize_same_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            writer_count = 12
            stores = [RawResponseStore(root) for _ in range(writer_count)]
            body = bytes(range(256)) * 256
            start = threading.Barrier(writer_count)
            results: list[tuple[str, Path]] = []
            failures: list[BaseException] = []
            active_writers = 0
            max_active_writers = 0
            write_calls = 0
            active_guard = threading.Lock()
            original_write_atomic = RawResponseStore._write_atomic

            def observe_write(_path: Path, _body: bytes, _digest: str) -> None:
                nonlocal active_writers, max_active_writers, write_calls
                with active_guard:
                    active_writers += 1
                    write_calls += 1
                    max_active_writers = max(
                        max_active_writers,
                        active_writers,
                    )
                try:
                    time.sleep(0.02)
                    original_write_atomic(_path, _body, _digest)
                finally:
                    with active_guard:
                        active_writers -= 1

            def save_body(store: RawResponseStore) -> None:
                try:
                    start.wait()
                    results.append(store.save("test", body, "json"))
                except BaseException as exc:
                    failures.append(exc)

            with patch.object(
                RawResponseStore,
                "_write_atomic",
                side_effect=observe_write,
            ):
                writers = [
                    threading.Thread(target=save_body, args=(store,))
                    for store in stores
                ]
                for writer in writers:
                    writer.start()
                for writer in writers:
                    writer.join(timeout=5)

            self.assertFalse(any(writer.is_alive() for writer in writers))
            self.assertEqual(failures, [])
            self.assertEqual(len(results), writer_count)
            self.assertEqual(max_active_writers, 1)
            self.assertEqual(write_calls, 1)
            self.assertEqual(len({path for _, path in results}), 1)
            self.assertEqual(
                {digest for digest, _ in results},
                {hashlib.sha256(body).hexdigest()},
            )
            path = results[0][1]
            self.assertEqual(gzip.decompress(path.read_bytes()), body)
            self.assertEqual(list(path.parent.glob(".raw-response-*.tmp")), [])
            self.assertEqual(RawResponseStore._path_locks, {})

    def test_raw_response_store_permission_error_retries_until_matching_winner(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RawResponseStore(Path(temporary))
            body = b"matching publication winner"
            digest, path = store.save("test", body, "json")
            denied = PermissionError(13, "denied")

            with (
                patch(
                    "r3radar.http_client.os.replace",
                    side_effect=denied,
                ) as replace_mock,
                patch.object(
                    RawResponseStore,
                    "_matches_body",
                    side_effect=[False, False, True],
                ) as match_mock,
                patch("r3radar.http_client.time.sleep") as sleep_mock,
            ):
                RawResponseStore._write_atomic(path, body, digest)

            replace_mock.assert_called_once()
            self.assertEqual(match_mock.call_count, 3)
            self.assertEqual(
                [item.args[0] for item in sleep_mock.call_args_list],
                [0.01, 0.02],
            )
            self.assertEqual(gzip.decompress(path.read_bytes()), body)
            self.assertEqual(list(path.parent.glob(".raw-response-*.tmp")), [])

    def test_raw_response_store_permission_error_without_matching_winner_raises_and_cleans_temp(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RawResponseStore(Path(temporary))
            body = b"fail closed publication"
            digest, path = store.save("test", body, "json")
            path.write_bytes(b"invalid target")
            denied = PermissionError(13, "denied")

            with (
                patch(
                    "r3radar.http_client.os.replace",
                    side_effect=denied,
                ) as replace_mock,
                patch.object(
                    RawResponseStore,
                    "_matches_body",
                    return_value=False,
                ) as match_mock,
                patch("r3radar.http_client.time.sleep") as sleep_mock,
            ):
                with self.assertRaises(PermissionError) as caught:
                    store.save("test", body, "json")

            self.assertIs(caught.exception, denied)
            replace_mock.assert_called_once()
            self.assertEqual(match_mock.call_count, 6)
            self.assertEqual(
                [item.args[0] for item in sleep_mock.call_args_list],
                [0.01, 0.02, 0.04, 0.08],
            )
            self.assertEqual(path.read_bytes(), b"invalid target")
            self.assertEqual(list(path.parent.glob(".raw-response-*.tmp")), [])
            self.assertEqual(RawResponseStore._path_locks, {})

            rebuilt_digest, rebuilt_path = store.save("test", body, "json")
            self.assertEqual(rebuilt_digest, digest)
            self.assertEqual(rebuilt_path, path)
            self.assertEqual(gzip.decompress(path.read_bytes()), body)
            self.assertEqual(RawResponseStore._path_locks, {})

    def test_rfc2544_fake_ip_is_allowed_only_for_an_explicit_host_allowlist(
        self,
    ) -> None:
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200, json={"ok": True})

        def fake_ip_resolver(
            _hostname: str,
            port: int,
            **_: object,
        ) -> list[tuple[object, ...]]:
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("198.18.0.42", port),
                )
            ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=fake_ip_resolver,
            )
            try:
                payload, _, _ = client.request_json(
                    "https://api.example/api",
                    allowed_hosts={"api.example"},
                )
                self.assertEqual(payload, {"ok": True})
            finally:
                client.close()
            self.assertEqual(calls, 1)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=fake_ip_resolver,
            )
            try:
                with self.assertRaises(NonRetryableFetchError):
                    client.request_json("https://api.example/api")
            finally:
                client.close()
            self.assertEqual(calls, 1)

    def test_hostname_resolving_to_private_address_is_blocked_preflight(self) -> None:
        calls = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(200, json={"unexpected": True})

        def private_resolver(
            _hostname: str,
            port: int,
            **_: object,
        ) -> list[tuple[object, ...]]:
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", port),
                )
            ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=private_resolver,
            )
            try:
                with self.assertRaises(NonRetryableFetchError):
                    client.request_json(
                        "https://internal.example/api",
                        allowed_hosts={"internal.example"},
                    )
            finally:
                client.close()
            self.assertEqual(calls, 0)

    def test_redirect_to_disallowed_host_is_blocked_before_second_request(self) -> None:
        requested_hosts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_hosts.append(request.url.host)
            return httpx.Response(
                302,
                headers={"Location": "http://127.0.0.1/private"},
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
            )
            try:
                with self.assertRaises(NonRetryableFetchError):
                    client.request_json(
                        "https://example.com/api",
                        allowed_hosts={"example.com"},
                    )
            finally:
                client.close()
            self.assertEqual(requested_hosts, ["example.com"])

    def test_terminal_403_is_not_retried(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(403, json={"blocked": True})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
            )
            try:
                with self.assertRaises(RetryDeferredError) as raised:
                    client.request_json(
                        "https://example.com/api",
                        allowed_hosts={"example.com"},
                    )
            finally:
                client.close()
            self.assertEqual(calls, 1)
            self.assertEqual(raised.exception.retry_after_seconds, 60)

    def test_openalex_reset_header_is_delta_seconds(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429,
                headers={"X-RateLimit-Reset": "43200"},
                json={"limited": True},
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="openalex",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
            )
            try:
                with self.assertRaises(RetryDeferredError) as raised:
                    client.request_json(
                        "https://api.openalex.org/works",
                        allowed_hosts={"api.openalex.org"},
                    )
            finally:
                client.close()
            self.assertEqual(raised.exception.retry_after_seconds, 43200)

    def test_retry_after_and_raw_receipt(self) -> None:
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return httpx.Response(429, headers={"Retry-After": "0"}, json={"wait": True})
            return httpx.Response(200, json={"ok": True})

        waits: list[float] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
                sleeper=waits.append,
            )
            try:
                payload, receipt, _ = client.request_json(
                    "https://example.com/api",
                    allowed_hosts={"example.com"},
                )
            finally:
                client.close()
            self.assertEqual(payload, {"ok": True})
            self.assertEqual(calls, 2)
            self.assertTrue(Path(receipt.path).is_file())
            self.assertGreaterEqual(len(waits), 1)

    def test_http_timeout_is_bounded_by_remaining_run_budget(self) -> None:
        observed_timeouts: list[dict[str, float]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            observed_timeouts.append(dict(request.extensions["timeout"]))
            return httpx.Response(200, json={"ok": True})

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                timeout_seconds=60,
                deadline_monotonic=105,
                monotonic=lambda: 100,
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
            )
            try:
                payload, _, _ = client.request_json(
                    "https://example.com/api",
                    allowed_hosts={"example.com"},
                )
            finally:
                client.close()

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(len(observed_timeouts), 1)
        for timeout in observed_timeouts[0].values():
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 5)

    def test_http_client_does_not_retry_after_run_deadline(self) -> None:
        clock = [100.0]
        calls = 0
        waits: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            clock[0] = 106.0
            raise httpx.ReadTimeout("slow upstream", request=request)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                timeout_seconds=60,
                max_attempts=4,
                deadline_monotonic=105,
                monotonic=lambda: clock[0],
                sleeper=waits.append,
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
            )
            try:
                with self.assertRaises(RetryDeferredError) as raised:
                    client.request_json(
                        "https://example.com/api",
                        allowed_hosts={"example.com"},
                    )
            finally:
                client.close()

        self.assertEqual(calls, 1)
        self.assertEqual(waits, [])
        self.assertEqual(raised.exception.retry_after_seconds, 0)

    def test_long_retry_after_is_deferred_without_sleeping(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, headers={"Retry-After": "3600"}, json={"wait": True})

        waits: list[float] = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = SafeHttpClient(
                source="test",
                delay_seconds=0,
                raw_store=RawResponseStore(root / "raw"),
                audit=JsonlAuditLog(root / "audit.jsonl"),
                run_id="run",
                transport=httpx.MockTransport(handler),
                resolver=public_dns_resolver,
                sleeper=waits.append,
                max_inline_retry_seconds=30,
            )
            try:
                with self.assertRaises(RetryDeferredError) as raised:
                    client.request_json(
                        "https://example.com/api",
                        allowed_hosts={"example.com"},
                    )
            finally:
                client.close()
            self.assertEqual(raised.exception.retry_after_seconds, 3600)
            self.assertEqual(waits, [])


class LlamaTests(unittest.TestCase):
    def test_context_preflight_blocks_generation_before_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["llama_cpp"]["managed_server"]["context"] = 100
            settings.raw["analysis"]["llama_cpp"]["chunk_max_tokens"] = 80
            runner = LlamaCppRunner(
                settings,
                JsonlAuditLog(settings.outputs_dir / "llama-audit.jsonl"),
                "llama-test",
            )
            model_response = httpx.Response(
                200,
                json={"data": [{"id": runner.model}]},
                request=httpx.Request("GET", f"{runner.base_url}/models"),
            )
            token_response = httpx.Response(
                200,
                json={"input_tokens": 30},
                request=httpx.Request(
                    "POST",
                    f"{runner.base_url}/chat/completions/input_tokens",
                ),
            )
            with patch("r3radar.llama_worker.httpx.get", return_value=model_response):
                with patch(
                    "r3radar.llama_worker.httpx.post",
                    return_value=token_response,
                ) as post:
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "would exceed",
                    ):
                        runner.run_structured(
                            prompt="fixture",
                            schema_path=PROJECT_DIR
                            / "schemas"
                            / "hosted_search.schema.json",
                            purpose="chunk_fixture",
                        )
            self.assertEqual(post.call_count, 1)

    def test_context_preflight_receipt_records_exact_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            runner = LlamaCppRunner(
                settings,
                JsonlAuditLog(settings.outputs_dir / "llama-audit.jsonl"),
                "llama-test",
            )
            model_response = httpx.Response(
                200,
                json={"data": [{"id": runner.model}]},
                request=httpx.Request("GET", f"{runner.base_url}/models"),
            )
            token_response = httpx.Response(
                200,
                json={"input_tokens": 42},
                request=httpx.Request(
                    "POST",
                    f"{runner.base_url}/chat/completions/input_tokens",
                ),
            )
            completion_response = httpx.Response(
                200,
                json={
                    "model": runner.model,
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"content": "{}"},
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 42,
                        "completion_tokens": 2,
                    },
                },
                request=httpx.Request(
                    "POST",
                    f"{runner.base_url}/chat/completions",
                ),
            )
            with patch("r3radar.llama_worker.httpx.get", return_value=model_response):
                with patch(
                    "r3radar.llama_worker.httpx.post",
                    side_effect=[token_response, completion_response],
                ):
                    result = runner.run_structured(
                        prompt="fixture",
                        schema_path=PROJECT_DIR
                        / "schemas"
                        / "hosted_search.schema.json",
                        purpose="chunk_fixture",
                    )
            self.assertEqual(result.receipt["input_tokens_preflight"], 42)
            self.assertEqual(
                result.receipt["reserved_output_tokens"],
                settings.raw["analysis"]["llama_cpp"]["chunk_max_tokens"],
            )
            self.assertEqual(
                result.receipt["context_window"],
                settings.raw["analysis"]["llama_cpp"]["managed_server"]["context"],
            )


class _TrackingRadarHttpServer(RadarHttpServer):
    def __init__(self, address: tuple[str, int], settings: Settings):
        self.injected_faults: queue.Queue[BaseException] = queue.Queue()
        self.observed_errors: queue.Queue[BaseException | None] = queue.Queue()
        self.completed_requests: queue.Queue[tuple[str, int]] = queue.Queue()
        self._request_count_lock = threading.Lock()
        self.request_threads_started = 0
        self.request_threads_completed = 0
        self.request_threads_active = 0
        self.request_threads_high_water = 0
        self.request_threads: list[threading.Thread] = []
        super().__init__(address, settings)

    def handle_error(
        self,
        request: object,
        client_address: tuple[str, int],
    ) -> None:
        self.observed_errors.put(sys.exc_info()[1])
        super().handle_error(request, client_address)

    def process_request_thread(
        self,
        request: object,
        client_address: tuple[str, int],
    ) -> None:
        with self._request_count_lock:
            self.request_threads.append(threading.current_thread())
            self.request_threads_started += 1
            self.request_threads_active += 1
            self.request_threads_high_water = max(
                self.request_threads_high_water,
                self.request_threads_active,
            )
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._request_count_lock:
                self.request_threads_completed += 1
                self.request_threads_active -= 1
            self.completed_requests.put(client_address)


class _QueuedFaultHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        fault = self.server.injected_faults.get(timeout=5)
        raise fault


class WebTests(unittest.TestCase):
    def test_dashboard_suppresses_only_expected_client_disconnect_errors(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            server = RadarHttpServer(("127.0.0.1", 0), settings)
            try:
                for error in (
                    ConnectionResetError(10054, "reset fixture"),
                    BrokenPipeError(32, "broken pipe fixture"),
                    ConnectionAbortedError(10053, "aborted fixture"),
                ):
                    captured = io.StringIO()
                    with patch("sys.stderr", captured):
                        try:
                            raise error
                        except type(error):
                            server.handle_error(None, ("127.0.0.1", 45678))
                    self.assertEqual(captured.getvalue(), "")

                for error in (
                    RuntimeError("unexpected-handler-fixture"),
                    ConnectionRefusedError(10061, "refused-is-not-allowlisted"),
                    PermissionError(13, "permission-is-not-allowlisted"),
                ):
                    captured = io.StringIO()
                    with patch("sys.stderr", captured):
                        try:
                            raise error
                        except type(error):
                            server.handle_error(None, ("127.0.0.1", 45678))
                    error_output = captured.getvalue()
                    self.assertIn(
                        "Exception occurred during processing",
                        error_output,
                    )
                    self.assertIn(type(error).__name__, error_output)
                    self.assertIn(str(error), error_output)
            finally:
                server.server_close()

    def test_dashboard_survives_100_disconnect_exceptions_and_releases_threads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            server = _TrackingRadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            with server.store._lock:
                server.store._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

            def database_fingerprint() -> tuple[object, ...]:
                with server.store._lock:
                    connection = server.store._connection
                    dump_hash = hashlib.sha256(
                        "\n".join(connection.iterdump()).encode("utf-8")
                    ).hexdigest()
                    return (
                        connection.total_changes,
                        dump_hash,
                        connection.execute("PRAGMA integrity_check").fetchone()[0],
                        tuple(connection.execute("PRAGMA foreign_key_check")),
                        connection.execute(
                            "SELECT COUNT(*) FROM feedback"
                        ).fetchone()[0],
                        connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                        hashlib.sha256(
                            settings.database_path.read_bytes()
                        ).hexdigest(),
                        settings.database_path.stat().st_size,
                        settings.database_path.stat().st_mtime_ns,
                    )

            database_before = database_fingerprint()
            server.RequestHandlerClass = _QueuedFaultHandler
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            captured = io.StringIO()
            with patch("sys.stderr", captured):
                try:
                    observed_types: list[type[BaseException]] = []
                    for iteration in range(100):
                        fault: BaseException
                        if iteration % 3 == 0:
                            fault = ConnectionResetError(10054, "reset fixture")
                        elif iteration % 3 == 1:
                            fault = BrokenPipeError(32, "broken pipe fixture")
                        else:
                            fault = ConnectionAbortedError(
                                10053,
                                "aborted fixture",
                            )
                        server.injected_faults.put(fault)
                        client = socket.create_connection(
                            ("127.0.0.1", port),
                            timeout=5,
                        )
                        client.close()
                        server.completed_requests.get(timeout=5)
                        observed = server.observed_errors.get(timeout=5)
                        self.assertIsNotNone(observed)
                        observed_types.append(type(observed))

                    self.assertEqual(
                        observed_types.count(ConnectionResetError),
                        34,
                    )
                    self.assertEqual(
                        observed_types.count(BrokenPipeError),
                        33,
                    )
                    self.assertEqual(
                        observed_types.count(ConnectionAbortedError),
                        33,
                    )
                    self.assertEqual(captured.getvalue(), "")

                    server.RequestHandlerClass = RadarHandler
                    connection = http.client.HTTPConnection(
                        "127.0.0.1",
                        port,
                        timeout=5,
                    )
                    connection.request(
                        "GET",
                        "/api/status",
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Connection": "close",
                        },
                    )
                    response = connection.getresponse()
                    payload = json.loads(response.read())
                    self.assertEqual(response.status, 200)
                    self.assertEqual(payload["counts"]["unique_works"], 0)
                    connection.close()
                    server.completed_requests.get(timeout=5)
                    self.assertTrue(server.observed_errors.empty())
                    self.assertEqual(database_fingerprint(), database_before)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    server.server_close()

            self.assertFalse(thread.is_alive())
            for request_thread in server.request_threads:
                request_thread.join(timeout=5)
            self.assertTrue(
                all(
                    not request_thread.is_alive()
                    for request_thread in server.request_threads
                )
            )
            self.assertEqual(server.socket.fileno(), -1)
            self.assertEqual(server.request_threads_started, 101)
            self.assertEqual(server.request_threads_completed, 101)
            self.assertEqual(server.request_threads_active, 0)
            self.assertGreaterEqual(server.request_threads_high_water, 1)
            self.assertEqual(captured.getvalue(), "")
            database_file_after_close = (
                hashlib.sha256(settings.database_path.read_bytes()).hexdigest(),
                settings.database_path.stat().st_size,
                settings.database_path.stat().st_mtime_ns,
            )
            self.assertEqual(database_file_after_close, database_before[-3:])
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(("127.0.0.1", port))
            finally:
                probe.close()

    def test_dashboard_handles_keepalive_reset_after_complete_response(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            server = _TrackingRadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            captured = io.StringIO()
            client = socket.create_connection(("127.0.0.1", port), timeout=5)
            with patch("sys.stderr", captured):
                try:
                    client.sendall(
                        (
                            "GET /api/status HTTP/1.1\r\n"
                            f"Host: 127.0.0.1:{port}\r\n"
                            "Connection: keep-alive\r\n"
                            "\r\n"
                        ).encode("ascii")
                    )
                    received = b""
                    while b"\r\n\r\n" not in received:
                        chunk = client.recv(4096)
                        self.assertTrue(chunk)
                        received += chunk
                    header_bytes, body = received.split(b"\r\n\r\n", 1)
                    header_lines = header_bytes.decode("iso-8859-1").split("\r\n")
                    self.assertIn(" 200 ", header_lines[0])
                    content_length = int(
                        next(
                            line.split(":", 1)[1].strip()
                            for line in header_lines[1:]
                            if line.casefold().startswith("content-length:")
                        )
                    )
                    while len(body) < content_length:
                        chunk = client.recv(content_length - len(body))
                        self.assertTrue(chunk)
                        body += chunk
                    json.loads(body[:content_length])
                    linger = struct.pack("hh" if os.name == "nt" else "ii", 1, 0)
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                    client.close()
                    server.completed_requests.get(timeout=5)
                    observed = server.observed_errors.get(timeout=5)
                    self.assertIsInstance(
                        observed,
                        (ConnectionResetError, BrokenPipeError),
                    )
                    self.assertEqual(captured.getvalue(), "")
                finally:
                    client.close()
                    server.shutdown()
                    thread.join(timeout=5)
                    server.server_close()

            self.assertFalse(thread.is_alive())
            self.assertEqual(captured.getvalue(), "")

    def test_dashboard_handles_expected_disconnects_from_response_write(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            server = _TrackingRadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            captured = io.StringIO()
            with patch("sys.stderr", captured):
                try:
                    for fault in (
                        BrokenPipeError(32, "write fixture"),
                        ConnectionAbortedError(10053, "aborted write fixture"),
                    ):
                        with self.subTest(fault_type=type(fault).__name__):
                            with patch.object(
                                socketserver._SocketWriter,
                                "write",
                                side_effect=fault,
                            ):
                                client = socket.create_connection(
                                    ("127.0.0.1", port),
                                    timeout=5,
                                )
                                client.sendall(
                                    (
                                        "GET /api/status HTTP/1.1\r\n"
                                        f"Host: 127.0.0.1:{port}\r\n"
                                        "Connection: close\r\n"
                                        "\r\n"
                                    ).encode("ascii")
                                )
                                server.completed_requests.get(timeout=5)
                                client.close()
                            observed = server.observed_errors.get(timeout=5)
                            self.assertIsInstance(observed, type(fault))
                            self.assertEqual(captured.getvalue(), "")

                            connection = http.client.HTTPConnection(
                                "127.0.0.1",
                                port,
                                timeout=5,
                            )
                            connection.request(
                                "GET",
                                "/api/status",
                                headers={
                                    "Host": f"127.0.0.1:{port}",
                                    "Connection": "close",
                                },
                            )
                            response = connection.getresponse()
                            response.read()
                            self.assertEqual(response.status, 200)
                            connection.close()
                            server.completed_requests.get(timeout=5)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    server.server_close()

            self.assertFalse(thread.is_alive())
            self.assertEqual(captured.getvalue(), "")

    def test_dashboard_keeps_database_operational_errors_visible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            server = _TrackingRadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            with server.store._lock:
                feedback_before = server.store._connection.execute(
                    "SELECT COUNT(*) FROM feedback"
                ).fetchone()[0]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            captured = io.StringIO()
            body = json.dumps({"work_id": 1, "rating": "无关"}).encode("utf-8")
            with patch("sys.stderr", captured):
                try:
                    with patch.object(
                        server.store,
                        "add_feedback",
                        side_effect=sqlite3.OperationalError(
                            "sentinel-db-operational-fault"
                        ),
                    ):
                        connection = http.client.HTTPConnection(
                            "127.0.0.1",
                            port,
                            timeout=5,
                        )
                        connection.request(
                            "POST",
                            "/api/feedback",
                            body=body,
                            headers={
                                "Host": f"127.0.0.1:{port}",
                                "Origin": f"http://127.0.0.1:{port}",
                                "Content-Type": "application/json",
                                "Content-Length": str(len(body)),
                                "Connection": "close",
                            },
                        )
                        try:
                            with self.assertRaises(
                                http.client.RemoteDisconnected
                            ):
                                connection.getresponse()
                        finally:
                            connection.close()
                        server.completed_requests.get(timeout=5)

                    observed = server.observed_errors.get(timeout=5)
                    self.assertIsInstance(observed, sqlite3.OperationalError)
                    error_output = captured.getvalue()
                    self.assertIn("sqlite3.OperationalError", error_output)
                    self.assertIn("sentinel-db-operational-fault", error_output)

                    connection = http.client.HTTPConnection(
                        "127.0.0.1",
                        port,
                        timeout=5,
                    )
                    connection.request(
                        "GET",
                        "/api/status",
                        headers={
                            "Host": f"127.0.0.1:{port}",
                            "Connection": "close",
                        },
                    )
                    response = connection.getresponse()
                    response.read()
                    self.assertEqual(response.status, 200)
                    connection.close()
                    server.completed_requests.get(timeout=5)
                    with server.store._lock:
                        feedback_after = server.store._connection.execute(
                            "SELECT COUNT(*) FROM feedback"
                        ).fetchone()[0]
                    self.assertEqual(feedback_after, feedback_before)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    server.server_close()

            self.assertFalse(thread.is_alive())

    def test_dashboard_rejects_foreign_host_origin_and_simple_content_type(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            server = RadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "GET",
                    "/api/status",
                    headers={"Host": "attacker.example"},
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 421)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "GET",
                    "/api/status",
                    headers={"Host": f"127.0.0.1:{port}"},
                )
                response = connection.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["counts"]["unique_works"], 0)
                self.assertEqual(payload["model_usage"]["invocation_count"], 0)
                self.assertEqual(payload["deep_read"]["state"], "idle")
                self.assertEqual(payload["deep_read"]["total"], 0)
                self.assertEqual(
                    response.getheader("Cross-Origin-Resource-Policy"),
                    "same-origin",
                )
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "GET",
                    "/api/works?limit=500&offset=0",
                    headers={"Host": f"127.0.0.1:{port}"},
                )
                response = connection.getresponse()
                payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["total"], 0)
                self.assertFalse(payload["has_more"])
                connection.close()

                body = json.dumps(
                    {"work_id": 1, "rating": "无关"}
                ).encode("utf-8")
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "POST",
                    "/api/feedback",
                    body=body,
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Origin": "http://localhost:3000",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 403)
                connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "POST",
                    "/api/feedback",
                    body=body,
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Origin": f"http://127.0.0.1:{port}",
                        "Content-Type": "text/plain",
                    },
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 415)
                connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()

    def test_dashboard_exposes_only_safe_pdf_failure_codes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='openalex'
                            LIMIT 1
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W-dashboard-pdf-timeout",
                    kind="paper",
                    title="Dashboard PDF Timeout Fixture",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="raw",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="incomplete",
                    source_url="https://example.com/timeout.pdf",
                    local_path="C:/private/quarantine/timeout.pdf",
                    text_path=None,
                    content_sha256="pdf-sha",
                    text_sha256=None,
                    byte_count=100,
                    text_char_count=None,
                    page_count=None,
                    coverage={
                        "complete": False,
                        "security_status": "incomplete_security",
                        "reason": "pdf_extract_timeout",
                        "failure_code": "wall_timeout",
                        "private_debug": "C:/private/secret/path",
                    },
                    error="Traceback: C:/private/secret/path",
                )
                malicious_record = SourceRecord(
                    source="openalex",
                    source_id="W-dashboard-private-errors",
                    kind="paper",
                    title="Dashboard Private Error Fixture",
                    query_id="q01",
                    year=2026,
                )
                malicious_work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=malicious_record,
                    decision=objective_admission(malicious_record, settings.raw),
                    raw_sha256="raw-private",
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "current PDF document policy",
                ):
                    store.save_document(
                        work_id=malicious_work_id,
                        content_kind="paper_pdf",
                        status="ready",
                        source_url="https://example.com/private.pdf",
                        local_path="C:/private/documents/private.pdf",
                        text_path="C:/private/documents/private.txt",
                        content_sha256="private-pdf-sha",
                        text_sha256="private-text-sha",
                        byte_count=100,
                        text_char_count=1000,
                        page_count=1,
                        coverage={
                            "complete": True,
                            "security_status": "C:/private/security/status",
                            "reason": "<script>private reason</script>",
                            "failure_code": "Traceback: C:/private/failure/path",
                        },
                        error="Traceback: C:/private/content/error",
                    )
                store.save_document(
                    work_id=malicious_work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url="https://example.com/private.pdf",
                    local_path="C:/private/documents/private.pdf",
                    text_path="C:/private/documents/private.txt",
                    content_sha256="private-pdf-sha",
                    text_sha256="private-text-sha",
                    byte_count=100,
                    text_char_count=1000,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(),
                    error=None,
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings.analysis_policy_hash,
                        retrieval_hash=settings.retrieval_hash,
                        profile_id=settings.profile_id,
                        profile_version=settings.profile_version,
                    ),
                    1,
                )
                malicious_task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertIsNotNone(malicious_task)
                self.assertTrue(
                    store.fail_analysis_task(
                        int(malicious_task["id"]),
                        "Traceback: C:/private/analysis/error",
                        run_id=run_id,
                        lease_token=lease_token,
                        retry=False,
                    )
                )
            server = RadarHttpServer(("127.0.0.1", 0), settings)
            port = int(server.server_address[1])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request(
                    "GET",
                    "/api/works?limit=10&offset=0",
                    headers={"Host": f"127.0.0.1:{port}"},
                )
                response = connection.getresponse()
                payload = json.loads(response.read())
                connection.close()
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["total"], 2)
                by_title = {item["title"]: item for item in payload["works"]}
                work = by_title["Dashboard PDF Timeout Fixture"]
                self.assertEqual(work["content_status"], "incomplete")
                self.assertEqual(work["retrieval_sources"], ["openalex"])
                self.assertEqual(work["content_reason"], "pdf_extract_timeout")
                self.assertEqual(
                    work["content_security_status"],
                    "incomplete_security",
                )
                self.assertEqual(work["content_failure_code"], "wall_timeout")
                serialized = json.dumps(work)
                self.assertNotIn("private_debug", serialized)
                self.assertNotIn("private/secret", serialized)
                self.assertNotIn("content_coverage_json", work)
                self.assertNotIn("analysis_error", work)

                malicious = by_title["Dashboard Private Error Fixture"]
                self.assertIsNone(malicious["content_reason"])
                self.assertEqual(
                    malicious["content_security_status"],
                    "parsed_verified",
                )
                self.assertIsNone(malicious["content_failure_code"])
                malicious_serialized = json.dumps(malicious)
                self.assertNotIn("private/", malicious_serialized)
                self.assertNotIn("<script>", malicious_serialized)
                self.assertNotIn("Traceback", malicious_serialized)
                self.assertNotIn("analysis_error", malicious)

                feedback_body = json.dumps(
                    {"work_id": work_id, "rating": "无关"}
                ).encode("utf-8")
                connection = http.client.HTTPConnection(
                    "127.0.0.1",
                    port,
                    timeout=5,
                )
                connection.request(
                    "POST",
                    "/api/feedback",
                    body=feedback_body,
                    headers={
                        "Host": f"127.0.0.1:{port}",
                        "Origin": f"http://127.0.0.1:{port}",
                        "Content-Type": "application/json",
                    },
                )
                feedback_response = connection.getresponse()
                feedback_payload = json.loads(feedback_response.read())
                connection.close()
                self.assertEqual(feedback_response.status, 409)
                self.assertEqual(
                    feedback_payload["error"],
                    "feedback_requires_complete_deep_read",
                )
                with server.store._lock:
                    feedback_count = int(
                        server.store._connection.execute(
                            "SELECT COUNT(*) FROM feedback"
                        ).fetchone()[0]
                    )
                self.assertEqual(feedback_count, 0)
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()


class StorageTests(unittest.TestCase):
    def test_legacy_schema_migrates_publication_snapshot_outbox_and_relations(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "legacy.sqlite3"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                CREATE TABLE schema_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT INTO schema_meta(key, value) VALUES('schema_version', '16');
                CREATE TABLE report_issues (
                    issue_id TEXT PRIMARY KEY,
                    retrieval_hash TEXT NOT NULL,
                    analysis_policy_hash TEXT NOT NULL,
                    previous_issue_id TEXT,
                    generated_at TEXT NOT NULL,
                    output_dir TEXT NOT NULL,
                    report_path TEXT NOT NULL,
                    selection_path TEXT NOT NULL,
                    counts_json TEXT NOT NULL
                );
                CREATE TABLE report_issue_items (
                    issue_id TEXT NOT NULL,
                    analysis_id INTEGER NOT NULL,
                    work_id INTEGER NOT NULL,
                    selection_bucket TEXT NOT NULL,
                    selected INTEGER NOT NULL,
                    PRIMARY KEY(issue_id, analysis_id)
                );
                """
            )
            connection.close()
            with RadarStore(database) as store:
                with store._lock:
                    issue_columns = {
                        row["name"]
                        for row in store._connection.execute(
                            "PRAGMA table_info(report_issues)"
                        ).fetchall()
                    }
                    item_columns = {
                        row["name"]
                        for row in store._connection.execute(
                            "PRAGMA table_info(report_issue_items)"
                        ).fetchall()
                    }
                    task_columns = {
                        row["name"]
                        for row in store._connection.execute(
                            "PRAGMA table_info(analysis_tasks)"
                        ).fetchall()
                    }
                    version = store._connection.execute(
                        """
                        SELECT value FROM schema_meta
                        WHERE key='schema_version'
                        """
                    ).fetchone()["value"]
                    support_tables = {
                        row["name"]
                        for row in store._connection.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type='table' AND name IN (
                            'publication_outbox',
                            'paper_repository_relations'
                        )
                        """
                        ).fetchall()
                    }
                self.assertEqual(version, str(SCHEMA_VERSION))
                self.assertEqual(
                    support_tables,
                    {"publication_outbox", "paper_repository_relations"},
                )
                self.assertTrue(
                    {
                        "run_id",
                        "publication_key",
                        "terminal_status",
                        "payload_sha256",
                        "payload_json",
                        "report_sha256",
                        "selection_sha256",
                        "run_summary_path",
                    }.issubset(issue_columns)
                )
                self.assertTrue(
                    {
                        "input_sha256",
                        "snapshot_sha256",
                        "snapshot_json",
                    }.issubset(item_columns)
                )
                self.assertTrue(
                    {
                        "phase",
                        "phase_done",
                        "phase_total",
                        "phase_updated_at",
                    }.issubset(task_columns)
                )

    def test_running_or_paused_run_cannot_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "publication-gate",
                )
                with self.assertRaisesRegex(
                    PublicationNotAllowedError,
                    "not terminal-publishable",
                ):
                    generate_weekly_report(
                        settings,
                        store,
                        run_id=run_id,
                        run_summary={},
                    )
                store.pause_or_complete_run(
                    run_id,
                    paused=True,
                    error=None,
                    lease_token=lease_token,
                    status_override="paused",
                )
                with self.assertRaisesRegex(
                    PublicationNotAllowedError,
                    "not terminal-publishable",
                ):
                    generate_weekly_report(
                        settings,
                        store,
                        run_id=run_id,
                        run_summary={},
                    )

    def test_transfer_and_disk_budgets_create_explained_visible_backlog(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["run"]["max_transfer_bytes_per_invocation"] = 5
            settings.raw["run"]["max_content_items_per_invocation"] = 1
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                pipeline._consume_transfer_bytes(4)
                with self.assertRaises(TransferBudgetReached) as raised:
                    pipeline._consume_transfer_bytes(1)
                pipeline._record_transfer_backlog(
                    raised.exception,
                    stage="official_query",
                )
                self.assertEqual(pipeline._transfer_bytes_received, 5)
                self.assertFalse(
                    pipeline._resource_budget_available(stage="official_query")
                )
                self.assertIn(
                    "transfer_budget_reached",
                    pipeline._visible_backlog,
                )

            with RadarPipeline(
                settings,
                mode="disk-boundary",
                include_hosted_search=False,
            ) as pipeline:
                with patch(
                    "r3radar.pipeline.shutil.disk_usage",
                    return_value=Mock(free=0),
                ):
                    self.assertFalse(
                        pipeline._resource_budget_available(stage="analysis")
                    )
                self.assertIn(
                    "minimum_free_disk_boundary_reached",
                    pipeline._visible_backlog,
                )
                self.assertEqual(
                    pipeline._visible_backlog[
                        "minimum_free_disk_boundary_reached"
                    ]["stage"],
                    "analysis",
                )

            with RadarPipeline(
                settings,
                mode="content-boundary",
                include_hosted_search=False,
            ) as pipeline:
                self.assertFalse(pipeline._content_budget_available(1))
                self.assertIn(
                    "content_item_budget_reached",
                    pipeline._visible_backlog,
                )

    def test_content_limit_counts_100_attempts_and_never_claims_101st(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["run"]["max_content_items_per_invocation"] = 100
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                works = [
                    {"id": work_id, "kind": "paper"}
                    for work_id in range(1, 102)
                ]
                processor = Mock()
                processor.process.side_effect = RetryDeferredError(
                    "deferred fixture",
                    60,
                )
                with (
                    patch(
                        "r3radar.pipeline.ContentProcessor",
                        return_value=processor,
                    ),
                    patch.object(
                        pipeline.store,
                        "claim_work_for_content",
                        side_effect=works,
                    ) as claim,
                    patch.object(pipeline.store, "defer_content_work") as defer,
                    patch.object(pipeline, "_refresh_lease"),
                ):
                    pipeline._collect_content()

                self.assertEqual(claim.call_count, 100)
                self.assertEqual(defer.call_count, 100)
                self.assertEqual(pipeline._content_items_attempted, 100)
                self.assertEqual(pipeline._content_items_processed, 0)
                self.assertEqual(
                    pipeline._visible_backlog["content_item_budget_reached"][
                        "attempted_items"
                    ],
                    100,
                )

    def test_low_disk_prevents_analysis_runner_selection_and_task_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                with (
                    patch(
                        "r3radar.pipeline.shutil.disk_usage",
                        return_value=Mock(free=0),
                    ),
                    patch.object(
                        pipeline,
                        "_select_analysis_runner",
                    ) as select_runner,
                    patch.object(
                        pipeline.store,
                        "seed_analysis_tasks",
                    ) as seed_tasks,
                    patch.object(
                        pipeline.store,
                        "claim_analysis_task",
                    ) as claim_task,
                ):
                    pipeline._analyze_ready_content()

                select_runner.assert_not_called()
                seed_tasks.assert_not_called()
                claim_task.assert_not_called()
                reason = pipeline._visible_backlog[
                    "minimum_free_disk_boundary_reached"
                ]
                self.assertEqual(reason["stage"], "analysis")
                self.assertEqual(reason["free_bytes"], 0)

    def test_content_reason_cannot_explain_pending_query_jobs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                def stop_at_budget() -> None:
                    pipeline._record_visible_backlog(
                        "content_item_budget_reached",
                        stage="content",
                        attempted_items=100,
                        limit_items=100,
                    )

                with (
                    patch.object(
                        pipeline,
                        "_collect_official_sources",
                        side_effect=stop_at_budget,
                    ),
                    patch.object(pipeline, "_collect_content"),
                    patch.object(pipeline, "_analyze_ready_content"),
                ):
                    summary = pipeline.run()

                self.assertEqual(summary["status"], "paused")
                self.assertTrue(summary["visible_backlog"]["present"])
                self.assertFalse(summary["visible_backlog"]["explained"])
                self.assertFalse(
                    summary["visible_backlog"]["eligible_for_completed_with_gaps"]
                )
                self.assertEqual(
                    summary["visible_backlog"]["unexplained_components"],
                    {"query_jobs.pending": 27},
                )
                self.assertEqual(
                    summary["visible_backlog"]["reason_codes"],
                    ["content_item_budget_reached"],
                )
                persisted = json.loads(
                    (pipeline.run_dir / "summary.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    persisted["visible_backlog"]["unexplained_components"],
                    {"query_jobs.pending": 27},
                )
                with pipeline.store._lock:
                    run = pipeline.store._connection.execute(
                        "SELECT status, lease_token FROM runs WHERE id=?",
                        (pipeline.run_id,),
                    ).fetchone()
                self.assertEqual(run["status"], "paused")
                self.assertIsNone(run["lease_token"])

    def test_exact_content_backlog_finishes_as_completed_with_gaps(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                def stop_at_budget() -> None:
                    timestamp = datetime.now(timezone.utc).isoformat()
                    with pipeline.store.transaction() as connection:
                        connection.execute(
                            "UPDATE query_jobs SET status='completed' WHERE run_id=?",
                            (pipeline.run_id,),
                        )
                        cursor = connection.execute(
                            """
                            INSERT INTO works(
                                canonical_key, kind, title, normalized_title, year,
                                best_url, lane, state, admission_code, metadata_json,
                                first_seen_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                "fixture:content-backlog",
                                "paper",
                                "Content backlog fixture",
                                "content backlog fixture",
                                2026,
                                "https://example.com/fixture",
                                "primary",
                                "admitted",
                                "fixture_admitted",
                                "{}",
                                timestamp,
                                timestamp,
                            ),
                        )
                        work_id = int(cursor.lastrowid)
                        connection.execute(
                            """
                            INSERT INTO work_scopes(
                                work_id, config_hash, profile_id, profile_version,
                                lane, state, admission_code, first_seen_at, last_seen_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                work_id,
                                settings.retrieval_hash,
                                settings.profile_id,
                                settings.profile_version,
                                "primary",
                                "admitted",
                                "fixture_admitted",
                                timestamp,
                                timestamp,
                            ),
                        )
                    pipeline._record_visible_backlog(
                        "content_item_budget_reached",
                        stage="content",
                        attempted_items=100,
                        limit_items=100,
                    )

                with (
                    patch.object(
                        pipeline,
                        "_collect_official_sources",
                        side_effect=stop_at_budget,
                    ),
                    patch.object(pipeline, "_collect_content"),
                    patch.object(pipeline, "_analyze_ready_content"),
                ):
                    summary = pipeline.run()

                self.assertEqual(summary["status"], "completed_with_gaps")
                self.assertTrue(summary["visible_backlog"]["explained"])
                self.assertEqual(
                    summary["visible_backlog"]["covered_components"],
                    {"work_scopes.admitted": 1},
                )
                self.assertEqual(
                    summary["visible_backlog"]["unexplained_components"],
                    {},
                )
                persisted = json.loads(
                    (pipeline.run_dir / "summary.json").read_text(encoding="utf-8")
                )
                self.assertEqual(persisted["visible_backlog"], summary["visible_backlog"])
                audit_events = [
                    json.loads(line)
                    for line in (pipeline.run_dir / "audit.jsonl")
                    .read_text(encoding="utf-8")
                    .splitlines()
                ]
                self.assertEqual(
                    audit_events[-1]["details"]["visible_backlog"],
                    summary["visible_backlog"],
                )
                with pipeline.store._lock:
                    run = pipeline.store._connection.execute(
                        "SELECT status, lease_token FROM runs WHERE id=?",
                        (pipeline.run_id,),
                    ).fetchone()
                self.assertEqual(run["status"], "completed_with_gaps")
                self.assertIsNone(run["lease_token"])

    def test_unknown_retry_stays_paused_even_with_runtime_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                def create_unknown_retries() -> None:
                    with pipeline.store.transaction() as connection:
                        connection.execute(
                            """
                            UPDATE query_jobs
                            SET status='retry', error='unclassified retry'
                            WHERE run_id=?
                            """,
                            (pipeline.run_id,),
                        )
                    pipeline._record_visible_backlog(
                        "runtime_budget_reached",
                        stage="all",
                        max_runtime_seconds=1,
                    )

                with (
                    patch.object(
                        pipeline,
                        "_collect_official_sources",
                        side_effect=create_unknown_retries,
                    ),
                    patch.object(pipeline, "_collect_content"),
                    patch.object(pipeline, "_analyze_ready_content"),
                ):
                    summary = pipeline.run()

                self.assertEqual(summary["status"], "paused")
                self.assertEqual(
                    summary["visible_backlog"]["unexplained_components"],
                    {"query_jobs.retry": 27},
                )

    def test_runtime_budget_receipt_has_structured_actual_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["run"]["max_runtime_seconds"] = 1
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                pipeline.started_monotonic = time.monotonic() - 2
                with (
                    patch.object(pipeline, "_collect_official_sources"),
                    patch.object(pipeline, "_collect_content"),
                    patch.object(pipeline, "_analyze_ready_content"),
                ):
                    summary = pipeline.run()

                boundary = next(
                    reason
                    for reason in summary["visible_backlog"]["reasons"]
                    if reason["reason_code"] == "runtime_budget_reached"
                )
                self.assertEqual(boundary["metric"], "elapsed_seconds")
                self.assertGreaterEqual(boundary["actual"], 2)
                self.assertEqual(boundary["limit"], 1)
                self.assertEqual(boundary["elapsed_seconds"], boundary["actual"])
                self.assertEqual(boundary["max_runtime_seconds"], 1)

    def test_pipeline_http_clients_share_the_run_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["run"]["max_runtime_seconds"] = 123
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                expected = pipeline.started_monotonic + 123
                source_client = pipeline._new_source_client("arxiv")
                content_client = pipeline._content_client_for_url(
                    "https://arxiv.org/pdf/1234.5678"
                )

                self.assertEqual(source_client.deadline_monotonic, expected)
                self.assertEqual(content_client.deadline_monotonic, expected)

    def test_analysis_budget_receipt_has_structured_actual_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                task = {"id": 41, "work_id": 42}
                reader = Mock()
                reader.analyze.side_effect = AnalysisBudgetPaused(
                    "fixture invocation limit reached",
                    boundary_reason="model_usage_limit_reached",
                    metric="max_invocations_per_run",
                    actual=7,
                    limit=7,
                )
                with (
                    patch.object(
                        pipeline,
                        "_select_analysis_runner",
                        return_value=("codex_cli", object()),
                    ),
                    patch.object(pipeline.store, "seed_analysis_tasks"),
                    patch.object(
                        pipeline.store,
                        "claim_analysis_task",
                        return_value=task,
                    ),
                    patch.object(
                        pipeline.store,
                        "pause_analysis_task",
                        return_value=True,
                    ),
                    patch("r3radar.pipeline.CodexDeepReader", return_value=reader),
                ):
                    pipeline._analyze_ready_content()

                boundary = pipeline._visible_backlog["analysis_budget_reached"]
                self.assertEqual(
                    boundary["boundary_reason"],
                    "model_usage_limit_reached",
                )
                self.assertEqual(boundary["metric"], "max_invocations_per_run")
                self.assertEqual(boundary["actual"], 7)
                self.assertEqual(boundary["limit"], 7)
                events = [
                    json.loads(line)
                    for line in (pipeline.run_dir / "audit.jsonl")
                    .read_text(encoding="utf-8")
                    .splitlines()
                ]
                paused = next(
                    event
                    for event in events
                    if event["event_type"] == "analysis_paused_budget"
                )
                self.assertEqual(paused["details"]["actual"], 7)
                self.assertEqual(paused["details"]["limit"], 7)

    def test_invalid_reason_stage_mapping_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                with self.assertRaisesRegex(
                    ValueError,
                    "invalid visible backlog reason/stage mapping",
                ):
                    pipeline._record_visible_backlog(
                        "content_item_budget_reached",
                        stage="official_query",
                        attempted_items=100,
                        limit_items=100,
                    )

    def test_keyboard_interrupt_pauses_and_releases_all_owned_claims(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                def claim_then_interrupt() -> None:
                    claimed = pipeline.store.claim_query_job(
                        pipeline.run_id,
                        pipeline.lease_token,
                        job_kind="official",
                    )
                    self.assertIsNotNone(claimed)
                    raise KeyboardInterrupt

                with patch.object(
                    pipeline,
                    "_collect_official_sources",
                    side_effect=claim_then_interrupt,
                ):
                    summary = pipeline.run()

                self.assertEqual(summary["status"], "paused")
                self.assertTrue(summary["interrupted"])
                self.assertFalse(summary["visible_backlog"]["explained"])
                self.assertEqual(
                    summary["visible_backlog"]["decision_snapshot"]["components"][
                        "query_jobs.pending"
                    ],
                    26,
                )
                self.assertEqual(
                    summary["visible_backlog"]["decision_snapshot"]["components"][
                        "query_jobs.running"
                    ],
                    1,
                )
                self.assertEqual(
                    summary["visible_backlog"]["components"]["query_jobs.pending"],
                    27,
                )
                self.assertEqual(
                    summary["visible_backlog"]["components"]["query_jobs.running"],
                    0,
                )
                self.assertEqual(summary["query_jobs"]["pending"], 27)
                self.assertNotIn("running", summary["query_jobs"])
                self.assertEqual(
                    summary["visible_backlog"]["finalization_changed_components"],
                    {
                        "query_jobs.pending": {
                            "decision": 26,
                            "persisted": 27,
                        },
                        "query_jobs.running": {
                            "decision": 1,
                            "persisted": 0,
                        },
                        "owned_claims.query_jobs": {
                            "decision": 1,
                            "persisted": 0,
                        },
                    },
                )
                persisted_summary = json.loads(
                    (pipeline.run_dir / "summary.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    persisted_summary["visible_backlog"],
                    summary["visible_backlog"],
                )
                with pipeline.store._lock:
                    run = pipeline.store._connection.execute(
                        """
                        SELECT status, lease_token, lease_expires_at
                        FROM runs WHERE id=?
                        """,
                        (pipeline.run_id,),
                    ).fetchone()
                    claims = pipeline.store._connection.execute(
                        """
                        SELECT
                            SUM(status='running') AS running,
                            SUM(claim_lease_token IS NOT NULL) AS claimed,
                            SUM(attempts) AS attempts
                        FROM query_jobs WHERE run_id=?
                        """,
                        (pipeline.run_id,),
                    ).fetchone()
                self.assertEqual(run["status"], "paused")
                self.assertIsNone(run["lease_token"])
                self.assertIsNone(run["lease_expires_at"])
                self.assertEqual(int(claims["running"]), 0)
                self.assertEqual(int(claims["claimed"]), 0)
                self.assertEqual(int(claims["attempts"]), 0)

    def test_interrupt_atomically_releases_every_claim_type_and_legacy_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                def claim_everything_then_interrupt() -> None:
                    query = pipeline.store.claim_query_job(
                        pipeline.run_id,
                        pipeline.lease_token,
                        job_kind="official",
                    )
                    self.assertIsNotNone(query)
                    timestamp = datetime.now(timezone.utc).isoformat()
                    with pipeline.store.transaction() as connection:
                        work_ids: list[int] = []
                        for suffix, state in (
                            ("verification", "verification_pending"),
                            ("content", "content_running"),
                            ("analysis", "analysis_running"),
                        ):
                            cursor = connection.execute(
                                """
                                INSERT INTO works(
                                    canonical_key, kind, title, normalized_title,
                                    lane, state, admission_code, metadata_json,
                                    first_seen_at, updated_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    f"interrupt:{suffix}",
                                    "paper",
                                    f"Interrupt {suffix}",
                                    f"interrupt {suffix}",
                                    "primary",
                                    state,
                                    "interrupt_fixture",
                                    "{}",
                                    timestamp,
                                    timestamp,
                                ),
                            )
                            work_ids.append(int(cursor.lastrowid))
                        verification_id, content_id, analysis_id = work_ids
                        for work_id, state, active in (
                            (verification_id, "verification_pending", False),
                            (content_id, "content_running", True),
                            (analysis_id, "analysis_running", True),
                        ):
                            connection.execute(
                                """
                                INSERT INTO work_scopes(
                                    work_id, config_hash, profile_id, profile_version,
                                    lane, state, admission_code,
                                    active_run_id, active_lease_token,
                                    first_seen_at, last_seen_at
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                                (
                                    work_id,
                                    settings.retrieval_hash,
                                    settings.profile_id,
                                    settings.profile_version,
                                    "primary",
                                    state,
                                    "interrupt_fixture",
                                    pipeline.run_id if active else None,
                                    pipeline.lease_token if active else None,
                                    timestamp,
                                    timestamp,
                                ),
                            )
                        connection.execute(
                            """
                            INSERT INTO verification_tasks(
                                run_id, query_job_id, work_id, status, attempts,
                                claim_lease_token, started_at, updated_at
                            ) VALUES (?, ?, ?, 'running', 1, ?, ?, ?)
                            """,
                            (
                                pipeline.run_id,
                                int(query["id"]),
                                verification_id,
                                pipeline.lease_token,
                                timestamp,
                                timestamp,
                            ),
                        )
                        document = connection.execute(
                            """
                            INSERT INTO documents(
                                work_id, content_kind, status, content_sha256,
                                text_sha256, coverage_json, created_at, updated_at
                            ) VALUES (?, 'html', 'ready', ?, ?, '{}', ?, ?)
                            """,
                            (
                                analysis_id,
                                "a" * 64,
                                "b" * 64,
                                timestamp,
                                timestamp,
                            ),
                        )
                        connection.execute(
                            """
                            INSERT INTO analysis_tasks(
                                work_id, document_id, provider, prompt_version,
                                config_hash, retrieval_hash, profile_id,
                                profile_version, input_sha256, claimed_run_id,
                                claim_lease_token, status, attempts, started_at,
                                updated_at
                            ) VALUES (?, ?, 'codex_cli', 'fixture', ?, ?, ?, ?, ?,
                                      ?, ?, 'running', 1, ?, ?)
                            """,
                            (
                                analysis_id,
                                int(document.lastrowid),
                                settings.analysis_policy_hash,
                                settings.retrieval_hash,
                                settings.profile_id,
                                settings.profile_version,
                                "b" * 64,
                                pipeline.run_id,
                                pipeline.lease_token,
                                timestamp,
                                timestamp,
                            ),
                        )
                    raise KeyboardInterrupt

                with patch.object(
                    pipeline,
                    "_collect_official_sources",
                    side_effect=claim_everything_then_interrupt,
                ):
                    summary = pipeline.run()

                self.assertEqual(summary["status"], "paused")
                self.assertTrue(summary["interrupted"])
                with pipeline.store._lock:
                    connection = pipeline.store._connection
                    run = connection.execute(
                        """
                        SELECT status, lease_token, lease_expires_at
                        FROM runs WHERE id=?
                        """,
                        (pipeline.run_id,),
                    ).fetchone()
                    query_claims = connection.execute(
                        """
                        SELECT COUNT(*) FROM query_jobs
                        WHERE run_id=? AND (
                            status='running' OR claim_lease_token IS NOT NULL
                        )
                        """,
                        (pipeline.run_id,),
                    ).fetchone()[0]
                    verification = connection.execute(
                        """
                        SELECT status, attempts, claim_lease_token
                        FROM verification_tasks WHERE run_id=?
                        """,
                        (pipeline.run_id,),
                    ).fetchone()
                    analysis = connection.execute(
                        """
                        SELECT status, attempts, claimed_run_id, claim_lease_token
                        FROM analysis_tasks
                        """
                    ).fetchone()
                    scope_rows = connection.execute(
                        """
                        SELECT w.canonical_key, w.state AS legacy_state,
                               ws.state AS scope_state, ws.active_run_id,
                               ws.active_lease_token
                        FROM work_scopes ws
                        JOIN works w ON w.id=ws.work_id
                        WHERE w.canonical_key IN (
                            'interrupt:content', 'interrupt:analysis'
                        )
                        ORDER BY w.canonical_key
                        """
                    ).fetchall()

                self.assertEqual(run["status"], "paused")
                self.assertIsNone(run["lease_token"])
                self.assertIsNone(run["lease_expires_at"])
                self.assertEqual(int(query_claims), 0)
                self.assertEqual(dict(verification), {
                    "status": "retry",
                    "attempts": 0,
                    "claim_lease_token": None,
                })
                self.assertEqual(dict(analysis), {
                    "status": "retry",
                    "attempts": 0,
                    "claimed_run_id": None,
                    "claim_lease_token": None,
                })
                self.assertEqual(
                    [dict(row) for row in scope_rows],
                    [
                        {
                            "canonical_key": "interrupt:analysis",
                            "legacy_state": "analysis_pending",
                            "scope_state": "analysis_pending",
                            "active_run_id": None,
                            "active_lease_token": None,
                        },
                        {
                            "canonical_key": "interrupt:content",
                            "legacy_state": "content_retry",
                            "scope_state": "content_retry",
                            "active_run_id": None,
                            "active_lease_token": None,
                        },
                    ],
                )

    def test_pause_preserves_completed_analysis_task_with_legacy_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "completed-analysis-pause-fixture",
                )
                timestamp = datetime.now(timezone.utc).isoformat()
                with store.transaction() as connection:
                    work = connection.execute(
                        """
                        INSERT INTO works(
                            canonical_key, kind, title, normalized_title,
                            lane, state, admission_code, metadata_json,
                            first_seen_at, updated_at
                        ) VALUES (
                            'interrupt:completed-analysis', 'paper',
                            'Completed analysis', 'completed analysis',
                            'primary', 'analyzed', 'fixture', '{}', ?, ?
                        )
                        """,
                        (timestamp, timestamp),
                    )
                    work_id = int(work.lastrowid)
                    document = connection.execute(
                        """
                        INSERT INTO documents(
                            work_id, content_kind, status, content_sha256,
                            text_sha256, coverage_json, created_at, updated_at
                        ) VALUES (?, 'html', 'ready', ?, ?, '{}', ?, ?)
                        """,
                        (
                            work_id,
                            "e" * 64,
                            "f" * 64,
                            timestamp,
                            timestamp,
                        ),
                    )
                    task = connection.execute(
                        """
                        INSERT INTO analysis_tasks(
                            work_id, document_id, provider, prompt_version,
                            config_hash, retrieval_hash, profile_id,
                            profile_version, input_sha256, claimed_run_id,
                            claim_lease_token, status, attempts, started_at,
                            completed_at, updated_at
                        ) VALUES (?, ?, 'codex_cli', 'fixture', ?, ?, ?, ?, ?,
                                  ?, ?, 'completed', 1, ?, ?, ?)
                        """,
                        (
                            work_id,
                            int(document.lastrowid),
                            settings.analysis_policy_hash,
                            settings.retrieval_hash,
                            settings.profile_id,
                            settings.profile_version,
                            "f" * 64,
                            run_id,
                            lease_token,
                            timestamp,
                            timestamp,
                            timestamp,
                        ),
                    )
                    task_id = int(task.lastrowid)
                    connection.execute(
                        """
                        INSERT INTO analyses(
                            task_id, work_id, provider, prompt_version,
                            deep_read_status, analysis_json, coverage_json,
                            provider_receipt_json, created_at
                        ) VALUES (
                            ?, ?, 'codex_cli', 'fixture', 'complete',
                            '{}', '{}', '{}', ?
                        )
                        """,
                        (task_id, work_id, timestamp),
                    )

                store.pause_or_complete_run(
                    run_id,
                    paused=True,
                    lease_token=lease_token,
                )

                with store._lock:
                    completed_task = store._connection.execute(
                        """
                        SELECT status, attempts, completed_at, error,
                               claimed_run_id, claim_lease_token
                        FROM analysis_tasks WHERE id=?
                        """,
                        (task_id,),
                    ).fetchone()
                    analysis_count = store._connection.execute(
                        "SELECT COUNT(*) FROM analyses WHERE task_id=?",
                        (task_id,),
                    ).fetchone()[0]
                self.assertEqual(
                    dict(completed_task),
                    {
                        "status": "completed",
                        "attempts": 1,
                        "completed_at": timestamp,
                        "error": None,
                        "claimed_run_id": None,
                        "claim_lease_token": None,
                    },
                )
                self.assertEqual(int(analysis_count), 1)

                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE analysis_tasks
                        SET status='retry',
                            error='run paused; analysis is resumable'
                        WHERE id=?
                        """,
                        (task_id,),
                    )
                resumed_run_id, resumed, resumed_lease = (
                    store.create_or_resume_run(
                        settings,
                        "completed-analysis-pause-fixture",
                    )
                )
                self.assertEqual(resumed_run_id, run_id)
                self.assertTrue(resumed)
                self.assertTrue(resumed_lease)
                with store._lock:
                    reconciled_task = store._connection.execute(
                        """
                        SELECT status, attempts, completed_at, error,
                               claimed_run_id, claim_lease_token
                        FROM analysis_tasks WHERE id=?
                        """,
                        (task_id,),
                    ).fetchone()
                    reconciliation_event = store._connection.execute(
                        """
                        SELECT event_type, details_json
                        FROM events
                        WHERE run_id=? AND event_type=?
                        """,
                        (
                            run_id,
                            "completed_analysis_tasks_reconciled",
                        ),
                    ).fetchone()
                self.assertEqual(
                    dict(reconciled_task),
                    {
                        "status": "completed",
                        "attempts": 1,
                        "completed_at": timestamp,
                        "error": None,
                        "claimed_run_id": None,
                        "claim_lease_token": None,
                    },
                )
                self.assertIsNotNone(reconciliation_event)
                self.assertEqual(
                    json.loads(reconciliation_event["details_json"]),
                    {
                        "reason": "persisted_complete_analysis",
                        "task_count": 1,
                    },
                )
                store.pause_or_complete_run(
                    resumed_run_id,
                    paused=True,
                    lease_token=resumed_lease,
                )
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE analysis_tasks
                        SET status='retry',
                            error='strict evidence reanalysis required'
                        WHERE id=?
                        """,
                        (task_id,),
                    )
                    connection.execute(
                        """
                        UPDATE analyses
                        SET provenance_status='invalidated_strict_anchor_excerpt'
                        WHERE task_id=?
                        """,
                        (task_id,),
                    )
                invalidated_run_id, resumed_again, invalidated_lease = (
                    store.create_or_resume_run(
                        settings,
                        "completed-analysis-pause-fixture",
                    )
                )
                self.assertEqual(invalidated_run_id, run_id)
                self.assertTrue(resumed_again)
                with store._lock:
                    invalidated_task = store._connection.execute(
                        "SELECT status, error FROM analysis_tasks WHERE id=?",
                        (task_id,),
                    ).fetchone()
                self.assertEqual(
                    dict(invalidated_task),
                    {
                        "status": "retry",
                        "error": "strict evidence reanalysis required",
                    },
                )
                store.pause_or_complete_run(
                    invalidated_run_id,
                    paused=True,
                    lease_token=invalidated_lease,
                )

    def test_ineligible_analysis_claim_is_visible_and_forces_recovery_pause(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
            ) as pipeline:
                def create_ineligible_running_claim() -> None:
                    timestamp = datetime.now(timezone.utc).isoformat()
                    with pipeline.store.transaction() as connection:
                        connection.execute(
                            "UPDATE query_jobs SET status='completed' WHERE run_id=?",
                            (pipeline.run_id,),
                        )
                        work = connection.execute(
                            """
                            INSERT INTO works(
                                canonical_key, kind, title, normalized_title,
                                lane, state, admission_code, metadata_json,
                                first_seen_at, updated_at
                            ) VALUES (
                                'ineligible:analysis-running', 'paper',
                                'Ineligible analysis running',
                                'ineligible analysis running', 'primary',
                                'analysis_running', 'fixture', '{}', ?, ?
                            )
                            """,
                            (timestamp, timestamp),
                        )
                        work_id = int(work.lastrowid)
                        connection.execute(
                            """
                            INSERT INTO work_scopes(
                                work_id, config_hash, profile_id, profile_version,
                                lane, state, admission_code, active_run_id,
                                active_lease_token, first_seen_at, last_seen_at
                            ) VALUES (?, ?, ?, ?, 'primary', 'analysis_running',
                                      'fixture', ?, ?, ?, ?)
                            """,
                            (
                                work_id,
                                settings.retrieval_hash,
                                settings.profile_id,
                                settings.profile_version,
                                pipeline.run_id,
                                pipeline.lease_token,
                                timestamp,
                                timestamp,
                            ),
                        )
                        document = connection.execute(
                            """
                            INSERT INTO documents(
                                work_id, content_kind, status, content_sha256,
                                text_sha256, coverage_json, created_at, updated_at
                            ) VALUES (?, 'html', 'unavailable', ?, ?, '{}', ?, ?)
                            """,
                            (
                                work_id,
                                "c" * 64,
                                "d" * 64,
                                timestamp,
                                timestamp,
                            ),
                        )
                        connection.execute(
                            """
                            INSERT INTO analysis_tasks(
                                work_id, document_id, provider, prompt_version,
                                config_hash, retrieval_hash, profile_id,
                                profile_version, input_sha256, claimed_run_id,
                                claim_lease_token, status, attempts, started_at,
                                updated_at
                            ) VALUES (?, ?, 'codex_cli', 'fixture', ?, ?, ?, ?, ?,
                                      ?, ?, 'running', 1, ?, ?)
                            """,
                            (
                                work_id,
                                int(document.lastrowid),
                                settings.analysis_policy_hash,
                                settings.retrieval_hash,
                                settings.profile_id,
                                settings.profile_version,
                                "d" * 64,
                                pipeline.run_id,
                                pipeline.lease_token,
                                timestamp,
                                timestamp,
                            ),
                        )

                with (
                    patch.object(
                        pipeline,
                        "_collect_official_sources",
                        side_effect=create_ineligible_running_claim,
                    ),
                    patch.object(pipeline, "_collect_content"),
                    patch.object(pipeline, "_analyze_ready_content"),
                ):
                    summary = pipeline.run()

                self.assertEqual(summary["status"], "paused")
                decision = summary["visible_backlog"]["decision_snapshot"]
                self.assertEqual(
                    decision["unexplained_components"],
                    {
                        "work_scopes.analysis_running": 1,
                        "owned_claims.analysis_tasks": 1,
                        "owned_claims.work_scopes": 1,
                    },
                )
                self.assertEqual(
                    summary["visible_backlog"]["persisted_snapshot"][
                        "unexplained_components"
                    ],
                    {},
                )
                with pipeline.store._lock:
                    connection = pipeline.store._connection
                    task = connection.execute(
                        """
                        SELECT status, claimed_run_id, claim_lease_token
                        FROM analysis_tasks
                        """
                    ).fetchone()
                    states = connection.execute(
                        """
                        SELECT w.state AS legacy_state, ws.state AS scope_state,
                               ws.active_run_id, ws.active_lease_token
                        FROM works w
                        JOIN work_scopes ws ON ws.work_id=w.id
                        WHERE w.canonical_key='ineligible:analysis-running'
                        """
                    ).fetchone()
                self.assertEqual(dict(task), {
                    "status": "retry",
                    "claimed_run_id": None,
                    "claim_lease_token": None,
                })
                self.assertEqual(dict(states), {
                    "legacy_state": "analysis_pending",
                    "scope_state": "analysis_pending",
                    "active_run_id": None,
                    "active_lease_token": None,
                })

    def test_hosted_supplement_phase_has_no_official_jobs_or_identity_overlap(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_official_sources=False,
                include_hosted_search=True,
                analysis_provider="codex_cli",
            ) as pipeline:
                self.assertEqual(pipeline.run_mode, "run:hosted_supplement")
                inserted = pipeline.store.seed_query_jobs(
                    pipeline.run_id,
                    settings,
                    include_hosted=True,
                    lease_token=pipeline.lease_token,
                    smoke=False,
                    include_official=False,
                )
                self.assertEqual(
                    inserted,
                    len(settings.raw["hosted_search"]["query_ids"]),
                )
                with pipeline.store._lock:
                    rows = pipeline.store._connection.execute(
                        """
                        SELECT job_kind, source, COUNT(*) AS count
                        FROM query_jobs
                        WHERE run_id=?
                        GROUP BY job_kind, source
                        """,
                        (pipeline.run_id,),
                    ).fetchall()
                self.assertEqual(
                    [dict(row) for row in rows],
                    [
                        {
                            "job_kind": "hosted",
                            "source": "codex_web",
                            "count": len(
                                settings.raw["hosted_search"]["query_ids"]
                            ),
                        }
                    ],
                )

    def test_query_coverage_distinguishes_full_smoke_and_missing_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_official_sources=True,
                include_hosted_search=True,
                analysis_provider="codex_cli",
            ) as pipeline:
                pipeline.store.seed_query_jobs(
                    pipeline.run_id,
                    settings,
                    include_hosted=True,
                    lease_token=pipeline.lease_token,
                    smoke=False,
                    include_official=True,
                )
                coverage = pipeline.store.query_job_coverage(
                    pipeline.run_id,
                    settings,
                )
                expected_official = sum(
                    len(query["sources"])
                    for query in settings.raw["queries"]
                )
                expected_hosted = len(
                    settings.raw["hosted_search"]["query_ids"]
                )
                self.assertEqual("full", coverage["scope"])
                self.assertTrue(coverage["plan_complete"])
                self.assertTrue(coverage["complete_profile_run"])
                self.assertEqual(
                    expected_official + expected_hosted,
                    coverage["expected_jobs"],
                )
                self.assertEqual(
                    coverage["expected_jobs"],
                    coverage["scheduled_jobs"],
                )
                self.assertEqual([], coverage["missing_jobs"])

                with pipeline.store._lock:
                    pipeline.store._connection.execute(
                        "DELETE FROM query_jobs WHERE run_id=? AND query_id='q08'",
                        (pipeline.run_id,),
                    )
                    pipeline.store._connection.commit()
                incomplete = pipeline.store.query_job_coverage(
                    pipeline.run_id,
                    settings,
                )
                self.assertFalse(incomplete["plan_complete"])
                self.assertEqual(2, len(incomplete["missing_jobs"]))
                pipeline.store.pause_or_complete_run(
                    pipeline.run_id,
                    paused=True,
                    lease_token=pipeline.lease_token,
                )

            with RadarPipeline(
                settings,
                mode="smoke",
                include_official_sources=True,
                include_hosted_search=True,
                analysis_provider="codex_cli",
            ) as smoke_pipeline:
                smoke_pipeline.store.seed_query_jobs(
                    smoke_pipeline.run_id,
                    settings,
                    include_hosted=True,
                    lease_token=smoke_pipeline.lease_token,
                    smoke=True,
                    include_official=True,
                )
                smoke_coverage = smoke_pipeline.store.query_job_coverage(
                    smoke_pipeline.run_id,
                    settings,
                )
                self.assertEqual("smoke", smoke_coverage["scope"])
                self.assertTrue(smoke_coverage["plan_complete"])
                self.assertFalse(smoke_coverage["complete_profile_run"])
                smoke_pipeline.store.pause_or_complete_run(
                    smoke_pipeline.run_id,
                    paused=True,
                    lease_token=smoke_pipeline.lease_token,
                )

    def test_retrieval_phase_cli_flags_are_explicit_and_mutually_exclusive(
        self,
    ) -> None:
        parser = build_parser()
        official = parser.parse_args(["run", "--no-hosted-search"])
        supplement = parser.parse_args(["run", "--hosted-only"])
        analysis_only = parser.parse_args(["run", "--analysis-only"])
        self.assertTrue(official.no_hosted_search)
        self.assertFalse(official.hosted_only)
        self.assertTrue(supplement.hosted_only)
        self.assertFalse(supplement.no_hosted_search)
        self.assertTrue(analysis_only.analysis_only)
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["run", "--no-hosted-search", "--hosted-only"]
            )
        with self.assertRaises(SystemExit):
            parser.parse_args(
                ["run", "--analysis-only", "--hosted-only"]
            )

    def test_cli_returns_130_for_an_interrupted_pipeline_summary(self) -> None:
        pipeline = Mock()
        pipeline.run.return_value = {
            "interrupted": True,
            "status": "paused",
        }
        pipeline_type = Mock()
        pipeline_type.return_value.__enter__ = Mock(return_value=pipeline)
        pipeline_type.return_value.__exit__ = Mock(return_value=False)
        with patch("r3radar.__main__.RadarPipeline", pipeline_type):
            exit_code = main(
                [
                    "--config",
                    str(DEFAULT_CONFIG),
                    "run",
                    "--no-hosted-search",
                ]
            )
        self.assertEqual(exit_code, 130)

    def test_pipeline_refuses_a_run_with_no_retrieval_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with self.assertRaisesRegex(
                ValueError,
                "at least one retrieval phase must be enabled",
            ):
                RadarPipeline(
                    settings,
                    mode="run",
                    include_official_sources=False,
                    include_hosted_search=False,
                )

    def test_pipeline_allows_explicit_analysis_only_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_official_sources=False,
                include_hosted_search=False,
                analysis_only=True,
            ) as pipeline:
                self.assertTrue(pipeline.analysis_only)
                self.assertEqual(pipeline.run_mode, "run:analysis_only")

    def test_analysis_only_run_skips_every_retrieval_and_content_stage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="smoke",
                include_official_sources=False,
                include_hosted_search=False,
                analysis_only=True,
            ) as pipeline:
                with (
                    patch.object(
                        pipeline.store,
                        "seed_query_jobs",
                    ) as seed_queries,
                    patch.object(
                        pipeline,
                        "_collect_official_sources",
                    ) as collect_official,
                    patch.object(
                        pipeline,
                        "_collect_hosted_search",
                    ) as collect_hosted,
                    patch.object(
                        pipeline,
                        "_collect_content",
                    ) as collect_content,
                    patch.object(
                        pipeline,
                        "_analyze_ready_content",
                    ) as analyze,
                ):
                    summary = pipeline.run()
                seed_queries.assert_not_called()
                collect_official.assert_not_called()
                collect_hosted.assert_not_called()
                collect_content.assert_not_called()
                analyze.assert_called_once_with()
                self.assertEqual(summary["status"], "completed")
                self.assertTrue(
                    summary["source_phases"]["analysis_only"]
                )

    def test_explicit_run_failure_requeue_resets_terminal_query_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "smoke",
                )
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store.transaction() as connection:
                    rows = connection.execute(
                        "SELECT id FROM query_jobs WHERE run_id=? ORDER BY id LIMIT 2",
                        (run_id,),
                    ).fetchall()
                    self.assertEqual(len(rows), 2)
                    connection.execute(
                        """
                        UPDATE query_jobs
                        SET status='failed', attempts=3, error='network policy changed'
                        WHERE id=?
                        """,
                        (rows[0]["id"],),
                    )
                    connection.execute(
                        """
                        UPDATE query_jobs
                        SET status='blocked', attempts=1, error='credential was absent'
                        WHERE id=?
                        """,
                        (rows[1]["id"],),
                    )
                store.pause_or_complete_run(
                    run_id,
                    paused=True,
                    lease_token=lease_token,
                )
                result = store.requeue_run_failures(run_id)
                self.assertEqual(result["query_jobs"], 2)
                with store._lock:
                    retried = store._connection.execute(
                        """
                        SELECT status, attempts, error FROM query_jobs
                        WHERE id IN (?, ?) ORDER BY id
                        """,
                        (rows[0]["id"], rows[1]["id"]),
                    ).fetchall()
                self.assertTrue(all(row["status"] == "pending" for row in retried))
                self.assertTrue(all(row["attempts"] == 0 for row in retried))
                self.assertTrue(all(row["error"] is None for row in retried))

    def test_future_database_schema_is_refused_without_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "future.sqlite3"
            connection = sqlite3.connect(database_path)
            try:
                connection.execute(
                    "CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO schema_meta(key, value) VALUES('schema_version', '999')"
                )
                connection.commit()
            finally:
                connection.close()
            with self.assertRaisesRegex(RuntimeError, "newer than supported"):
                RadarStore(database_path)
            connection = sqlite3.connect(database_path)
            try:
                version = connection.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(version, "999")

    def test_schema_ten_database_adds_analysis_not_before_before_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path):
                pass
            connection = sqlite3.connect(settings.database_path)
            try:
                connection.execute("DROP INDEX IF EXISTS idx_analysis_tasks_claim_v2")
                connection.execute(
                    "ALTER TABLE analysis_tasks DROP COLUMN not_before"
                )
                connection.execute(
                    "ALTER TABLE analyses DROP COLUMN provenance_status"
                )
                connection.execute(
                    """
                    UPDATE schema_meta SET value='10'
                    WHERE key='schema_version'
                    """
                )
                connection.commit()
            finally:
                connection.close()
            with RadarStore(settings.database_path) as migrated:
                with migrated._lock:
                    columns = {
                        row["name"]
                        for row in migrated._connection.execute(
                            "PRAGMA table_info(analysis_tasks)"
                        ).fetchall()
                    }
                    indexes = {
                        row["name"]
                        for row in migrated._connection.execute(
                            "PRAGMA index_list(analysis_tasks)"
                        ).fetchall()
                    }
                    analysis_columns = {
                        row["name"]
                        for row in migrated._connection.execute(
                            "PRAGMA table_info(analyses)"
                        ).fetchall()
                    }
                    version = migrated._connection.execute(
                        """
                        SELECT value FROM schema_meta
                        WHERE key='schema_version'
                        """
                    ).fetchone()["value"]
            self.assertIn("not_before", columns)
            self.assertIn("idx_analysis_tasks_claim_v2", indexes)
            self.assertIn("provenance_status", analysis_columns)
            self.assertEqual(version, str(SCHEMA_VERSION))

    def test_legacy_ready_pdf_analysis_is_hidden_and_requeued_for_reparse(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "legacy-policy-fixture",
                )
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='openalex'
                            LIMIT 1
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W-legacy-document-policy",
                    kind="paper",
                    title="Legacy PDF Policy Fixture",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="legacy-raw",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url="https://example.com/legacy.pdf",
                    local_path="legacy.pdf",
                    text_path="legacy.txt",
                    content_sha256="legacy-pdf-sha",
                    text_sha256="legacy-text-sha",
                    byte_count=100,
                    text_char_count=1000,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(page_count=1),
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings.analysis_policy_hash,
                        retrieval_hash=settings.retrieval_hash,
                        profile_id=settings.profile_id,
                        profile_version=settings.profile_version,
                    ),
                    1,
                )
                task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertIsNotNone(task)
                store.complete_analysis(
                    task_id=int(task["id"]),
                    work_id=work_id,
                    provider="codex_cli",
                    model="fixture",
                    prompt_version=str(task["prompt_version"]),
                    deep_read_status="complete",
                    tier="important",
                    score=80,
                    analysis={"scores": {"r3_relevance": 80}},
                    coverage={"complete": True},
                    receipt={"fixture": True},
                    run_id=run_id,
                    lease_token=lease_token,
                )
                with store._lock:
                    completed_task = store._connection.execute(
                        """
                        SELECT status, claimed_run_id, claim_lease_token,
                               not_before
                        FROM analysis_tasks WHERE id=?
                        """,
                        (int(task["id"]),),
                    ).fetchone()
                self.assertEqual(
                    dict(completed_task),
                    {
                        "status": "completed",
                        "claimed_run_id": None,
                        "claim_lease_token": None,
                        "not_before": None,
                    },
                )
                self.assertEqual(
                    len(
                        store.list_complete_analyses(
                            config_hash=settings.retrieval_hash,
                            analysis_policy_hash=settings.analysis_policy_hash,
                        )
                    ),
                    1,
                )

            connection = sqlite3.connect(settings.database_path)
            try:
                connection.execute(
                    """
                    UPDATE documents
                    SET status='ready', coverage_json=?, error=NULL
                    WHERE work_id=? AND content_kind='paper_pdf'
                    """,
                    (json.dumps({"complete": True}), work_id),
                )
                connection.execute(
                    "DROP TABLE document_processing_observations"
                )
                connection.execute(
                    "ALTER TABLE documents DROP COLUMN document_policy_hash"
                )
                connection.execute(
                    """
                    UPDATE schema_meta SET value='15'
                    WHERE key='schema_version'
                    """
                )
                connection.commit()
            finally:
                connection.close()

            with RadarStore(settings.database_path) as migrated:
                with migrated._lock:
                    document = migrated._connection.execute(
                        """
                        SELECT * FROM documents
                        WHERE work_id=? AND content_kind='paper_pdf'
                        """,
                        (work_id,),
                    ).fetchone()
                    observations = migrated._connection.execute(
                        """
                        SELECT event_type, status, coverage_json, receipt_json
                        FROM document_processing_observations
                        WHERE document_id=?
                        ORDER BY id
                        """,
                        (document["id"],),
                    ).fetchall()
                    historical_analysis_count = int(
                        migrated._connection.execute(
                            "SELECT COUNT(*) FROM analyses WHERE work_id=?",
                            (work_id,),
                        ).fetchone()[0]
                    )
                    integrity = migrated._connection.execute(
                        "PRAGMA integrity_check"
                    ).fetchone()[0]
                    foreign_key_violations = migrated._connection.execute(
                        "PRAGMA foreign_key_check"
                    ).fetchall()
                self.assertEqual(document["status"], "retry")
                self.assertIsNone(document["document_policy_hash"])
                invalidated_coverage = json.loads(document["coverage_json"])
                self.assertFalse(invalidated_coverage["complete"])
                self.assertEqual(
                    invalidated_coverage["security_status"],
                    "incomplete_security",
                )
                self.assertEqual(
                    invalidated_coverage["reason"],
                    "pdf_security_reparse_required",
                )
                self.assertEqual(
                    invalidated_coverage["failure_code"],
                    "document_policy_mismatch",
                )
                self.assertEqual(
                    [row["event_type"] for row in observations],
                    ["legacy_snapshot", "policy_invalidated"],
                )
                self.assertEqual(
                    json.loads(observations[0]["coverage_json"]),
                    {"complete": True},
                )
                self.assertEqual(json.loads(observations[0]["receipt_json"]), {})
                self.assertEqual(historical_analysis_count, 1)
                self.assertEqual(integrity, "ok")
                self.assertEqual(foreign_key_violations, [])
                counts = migrated.dashboard_counts(
                    settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(counts["deep_read"], 0)
                self.assertEqual(counts["pending_content"], 1)
                self.assertEqual(
                    migrated.list_complete_analyses(
                        config_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    ),
                    [],
                )
                dashboard = migrated.list_dashboard_works(
                    config_hash=settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(dashboard[0]["state"], "content_retry")
                self.assertNotIn("analysis_json", dashboard[0])
                self.assertIsNone(
                    migrated.dashboard_work_analysis(
                        work_id=work_id,
                        config_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    )
                )
                self.assertIsNone(dashboard[0]["feedback_rating"])
                with self.assertRaises(FeedbackNotAllowedError):
                    migrated.add_feedback(
                        work_id,
                        "值得保存",
                        None,
                        retrieval_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    )
                claimed = migrated.claim_work_for_content(
                    settings.retrieval_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertIsNotNone(claimed)
                self.assertEqual(int(claimed["id"]), work_id)

    def test_active_run_lease_prevents_a_second_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                store.create_or_resume_run(settings, "test")
                with self.assertRaises(RunAlreadyActiveError):
                    store.create_or_resume_run(settings, "test")

    def test_analysis_only_and_full_runs_are_mutually_exclusive(self) -> None:
        for first_mode, second_mode in (
            ("run", "run:analysis_only"),
            ("run:analysis_only", "run"),
        ):
            with self.subTest(first_mode=first_mode):
                with tempfile.TemporaryDirectory() as temporary:
                    settings = make_settings(Path(temporary))
                    with RadarStore(settings.database_path) as store:
                        store.create_or_resume_run(settings, first_mode)
                        with self.assertRaisesRegex(
                            RunAlreadyActiveError,
                            "mutually exclusive",
                        ):
                            store.create_or_resume_run(settings, second_mode)

    def test_budget_only_config_change_cannot_start_parallel_full_run(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings_a = make_settings(root)
            settings_b = make_settings(root)
            settings_b.raw["analysis"]["budgets"][
                "max_invocations_per_run"
            ] += 1
            self.assertEqual(
                settings_a.analysis_policy_hash,
                settings_b.analysis_policy_hash,
            )
            self.assertNotEqual(settings_a.config_hash, settings_b.config_hash)
            with RadarStore(settings_a.database_path) as store:
                store.create_or_resume_run(settings_a, "run")
                with self.assertRaisesRegex(
                    RunAlreadyActiveError,
                    "same analysis policy",
                ):
                    store.create_or_resume_run(
                        settings_b,
                        "run:no_hosted",
                    )

    def test_expired_cross_config_run_releases_shared_analysis_claim(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings_a = make_settings(root)
            settings_b = make_settings(root)
            settings_b.raw["analysis"]["budgets"][
                "max_invocations_per_run"
            ] += 1
            self.assertEqual(
                settings_a.analysis_policy_hash,
                settings_b.analysis_policy_hash,
            )
            with RadarStore(settings_a.database_path) as store:
                first_run, _, first_token = store.create_or_resume_run(
                    settings_a,
                    "run",
                )
                store.seed_query_jobs(
                    first_run,
                    settings_a,
                    include_hosted=False,
                    lease_token=first_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='openalex'
                            """,
                            (first_run,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="expired-cross-config",
                    kind="paper",
                    title="Expired Cross Config Claim",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=first_run,
                    lease_token=first_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings_a.raw),
                    raw_sha256="expired-cross-config",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url=None,
                    local_path="fixture.pdf",
                    text_path="fixture.txt",
                    content_sha256="pdf",
                    text_sha256="text",
                    byte_count=3,
                    text_char_count=4,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(),
                )
                store.seed_analysis_tasks(
                    "codex_cli",
                    settings_a.raw["analysis"]["prompt_version"],
                    analysis_policy_hash=settings_a.analysis_policy_hash,
                    retrieval_hash=settings_a.retrieval_hash,
                    profile_id=settings_a.profile_id,
                    profile_version=settings_a.profile_version,
                )
                first_task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings_a.analysis_policy_hash,
                    run_id=first_run,
                    lease_token=first_token,
                )
                with store.transaction() as connection:
                    connection.execute(
                        "UPDATE runs SET lease_expires_at=? WHERE id=?",
                        (
                            (
                                datetime.now(timezone.utc)
                                - timedelta(seconds=1)
                            ).isoformat(timespec="seconds"),
                            first_run,
                        ),
                    )
                second_run, resumed, second_token = (
                    store.create_or_resume_run(
                        settings_b,
                        "run:no_hosted",
                    )
                )
                self.assertFalse(resumed)
                self.assertNotEqual(second_run, first_run)
                with store._lock:
                    stale_run = store._connection.execute(
                        "SELECT status FROM runs WHERE id=?",
                        (first_run,),
                    ).fetchone()
                    released_task = store._connection.execute(
                        """
                        SELECT status, claimed_run_id, claim_lease_token
                        FROM analysis_tasks WHERE id=?
                        """,
                        (first_task["id"],),
                    ).fetchone()
                self.assertEqual(stale_run["status"], "paused")
                self.assertEqual(released_task["status"], "retry")
                self.assertIsNone(released_task["claimed_run_id"])
                self.assertIsNone(released_task["claim_lease_token"])
                reclaimed = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings_b.analysis_policy_hash,
                    run_id=second_run,
                    lease_token=second_token,
                )
                self.assertEqual(
                    int(reclaimed["id"]),
                    int(first_task["id"]),
                )

    def test_analysis_loop_waits_for_its_only_deferred_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarPipeline(
                settings,
                mode="run",
                include_hosted_search=False,
                analysis_only=True,
                analysis_provider="codex_cli",
            ) as pipeline:
                deferred_at = (
                    datetime.now(timezone.utc) - timedelta(seconds=1)
                ).isoformat()
                task = {"id": 7, "work_id": 11}
                reader = Mock()
                with (
                    patch.object(
                        pipeline,
                        "_select_analysis_runner",
                        return_value=("codex_cli", object()),
                    ),
                    patch.object(
                        pipeline,
                        "_resource_budget_available",
                        return_value=True,
                    ),
                    patch.object(pipeline, "_expired", return_value=False),
                    patch.object(
                        pipeline.store,
                        "seed_analysis_tasks",
                    ),
                    patch.object(
                        pipeline.store,
                        "claim_analysis_task",
                        side_effect=[None, task, None],
                    ),
                    patch.object(
                        pipeline.store,
                        "next_analysis_retry_at",
                        side_effect=[deferred_at, None],
                    ),
                    patch(
                        "r3radar.pipeline.CodexDeepReader",
                        return_value=reader,
                    ),
                ):
                    pipeline._analyze_ready_content()
                reader.analyze.assert_called_once_with(task)

    def test_legacy_null_lease_running_query_is_recovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, token = store.create_or_resume_run(settings, "legacy")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=token,
                    smoke=True,
                )
                claimed = store.claim_query_job(
                    run_id,
                    token,
                    job_kind="official",
                    source="openalex",
                )
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE runs
                        SET lease_token=NULL, lease_expires_at=NULL
                        WHERE id=?
                        """,
                        (run_id,),
                    )
                    connection.execute(
                        """
                        UPDATE query_jobs SET claim_lease_token=NULL
                        WHERE id=?
                        """,
                        (claimed["id"],),
                    )
                resumed_run, resumed, new_token = store.create_or_resume_run(
                    settings,
                    "legacy",
                )
                self.assertTrue(resumed)
                self.assertEqual(resumed_run, run_id)
                with store._lock:
                    recovered = store._connection.execute(
                        """
                        SELECT status, attempts, claim_lease_token
                        FROM query_jobs WHERE id=?
                        """,
                        (claimed["id"],),
                    ).fetchone()
                self.assertEqual(recovered["status"], "pending")
                self.assertEqual(recovered["attempts"], 0)
                self.assertIsNone(recovered["claim_lease_token"])
                reclaimed = store.claim_query_job(
                    run_id,
                    new_token,
                    job_kind="official",
                    source="openalex",
                )
                self.assertEqual(int(reclaimed["id"]), int(claimed["id"]))

    def test_http_rate_slot_is_shared_across_store_instances(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as first_store:
                with RadarStore(settings.database_path) as second_store:
                    with patch(
                        "r3radar.storage.time.time",
                        return_value=100.0,
                    ):
                        first_wait = first_store.reserve_http_rate_slot(
                            "http:export.arxiv.org",
                            3.3,
                        )
                        second_wait = second_store.reserve_http_rate_slot(
                            "http:export.arxiv.org",
                            3.3,
                        )
            self.assertEqual(first_wait, 0.0)
            self.assertAlmostEqual(second_wait, 3.3)

    def test_model_invocation_ledger_is_idempotent_and_sums_usage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "usage-ledger",
                )
                receipt = {
                    "invocation_id": "invocation-1",
                    "provider": "codex_cli",
                    "purpose": "hosted_search_q01",
                    "model": "fixture",
                    "duration_seconds": 1.25,
                    "usage": {
                        "input_tokens": 120,
                        "cached_input_tokens": 20,
                        "output_tokens": 30,
                        "reasoning_output_tokens": 5,
                    },
                }
                store.record_model_invocation(
                    run_id=run_id,
                    lease_token=lease_token,
                    receipt=receipt,
                )
                store.record_model_invocation(
                    run_id=run_id,
                    lease_token=lease_token,
                    receipt=receipt,
                )
                self.assertEqual(
                    store.model_usage(run_id=run_id),
                    {
                        "invocation_count": 1,
                        "input_tokens": 120,
                        "cached_input_tokens": 20,
                        "output_tokens": 30,
                        "reasoning_output_tokens": 5,
                        "duration_seconds": 1.25,
                    },
                )
                conflicting = dict(receipt)
                conflicting["purpose"] = "different"
                with self.assertRaisesRegex(ValueError, "reused"):
                    store.record_model_invocation(
                        run_id=run_id,
                        lease_token=lease_token,
                        receipt=conflicting,
                    )

    def test_stable_source_identity_survives_title_and_url_correction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='openalex'",
                            (run_id,),
                        ).fetchone()["id"]
                    )
                first = SourceRecord(
                    source="openalex",
                    source_id="W-STABLE",
                    kind="paper",
                    title="Initial title",
                    query_id="q01",
                    year=2025,
                    canonical_url="https://openalex.org/W-STABLE",
                )
                second = SourceRecord(
                    source="openalex",
                    source_id="W-STABLE",
                    kind="paper",
                    title="Corrected and expanded title",
                    query_id="q01",
                    year=2025,
                    canonical_url="https://openalex.org/works/W-STABLE",
                )
                first_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=first,
                    decision=objective_admission(first, settings.raw),
                    raw_sha256="raw-one",
                )
                second_id, created = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=second,
                    decision=objective_admission(second, settings.raw),
                    raw_sha256="raw-two",
                )
                self.assertFalse(created)
                self.assertEqual(second_id, first_id)
                self.assertEqual(
                    store.dashboard_counts(
                        settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    )["raw_hits"],
                    1,
                )
                with store._lock:
                    work_count = store._connection.execute(
                        "SELECT COUNT(*) FROM works"
                    ).fetchone()[0]
                    mapping_count = store._connection.execute(
                        """
                        SELECT COUNT(*) FROM work_sources
                        WHERE source_record_id=(
                            SELECT id FROM source_records
                            WHERE source='openalex' AND source_id='W-STABLE'
                        )
                        """
                    ).fetchone()[0]
                    observation_count = store._connection.execute(
                        "SELECT COUNT(*) FROM source_observations"
                    ).fetchone()[0]
                self.assertEqual(work_count, 1)
                self.assertEqual(mapping_count, 1)
                self.assertEqual(observation_count, 2)

    def test_terminal_rejection_is_scoped_and_hides_historical_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings_a = make_settings(root)
            with RadarStore(settings_a.database_path) as store:
                run_a, _, token_a = store.create_or_resume_run(settings_a, "profile-a")
                store.seed_query_jobs(
                    run_a,
                    settings_a,
                    include_hosted=False,
                    lease_token=token_a,
                    smoke=True,
                )
                with store._lock:
                    job_a = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='github'",
                            (run_a,),
                        ).fetchone()["id"]
                    )
                active = SourceRecord(
                    source="github",
                    source_id="owner/repo",
                    kind="repository",
                    title="Scoped Archive Fixture",
                    query_id="q01",
                    canonical_url="https://github.com/owner/repo",
                    github_full_name="owner/repo",
                )
                work_id, _ = store.ingest_record(
                    run_id=run_a,
                    lease_token=token_a,
                    query_job_id=job_a,
                    record=active,
                    decision=objective_admission(active, settings_a.raw),
                    raw_sha256="active",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="repository_archive",
                    status="ready",
                    source_url=active.canonical_url,
                    local_path="repo.zip",
                    text_path="repo.txt",
                    content_sha256="archive",
                    text_sha256="text",
                    byte_count=10,
                    text_char_count=10,
                    page_count=None,
                    coverage={"complete": True},
                )
                store.seed_analysis_tasks(
                    "codex_cli",
                    settings_a.raw["analysis"]["prompt_version"],
                    analysis_policy_hash=settings_a.analysis_policy_hash,
                    retrieval_hash=settings_a.retrieval_hash,
                    profile_id=settings_a.profile_id,
                    profile_version=settings_a.profile_version,
                )
                task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings_a.analysis_policy_hash,
                    run_id=run_a,
                    lease_token=token_a,
                )
                store.complete_analysis(
                    task_id=int(task["id"]),
                    work_id=work_id,
                    provider="codex_cli",
                    model="fixture",
                    prompt_version=str(task["prompt_version"]),
                    deep_read_status="complete",
                    tier="important",
                    score=80,
                    analysis={"scores": {"r3_relevance": 80}},
                    coverage={"complete": True},
                    receipt={"fixture": True},
                    run_id=run_a,
                    lease_token=token_a,
                )
                store.add_feedback(
                    work_id,
                    "值得保存",
                    "complete deep-read fixture",
                    retrieval_hash=settings_a.retrieval_hash,
                    analysis_policy_hash=settings_a.analysis_policy_hash,
                )
                self.assertEqual(
                    store.list_dashboard_works(
                        config_hash=settings_a.retrieval_hash,
                        analysis_policy_hash=settings_a.analysis_policy_hash,
                    )[0]["feedback_rating"],
                    "值得保存",
                )

                archived = SourceRecord(
                    source="github",
                    source_id="owner/repo",
                    kind="repository",
                    title="Scoped Archive Fixture",
                    query_id="q01",
                    canonical_url="https://github.com/owner/repo",
                    github_full_name="owner/repo",
                    archived=True,
                )
                decision_a = objective_admission(archived, settings_a.raw)
                self.assertEqual(decision_a.code, "archived_repository")
                store.ingest_record(
                    run_id=run_a,
                    lease_token=token_a,
                    query_job_id=job_a,
                    record=archived,
                    decision=decision_a,
                    raw_sha256="archived-a",
                )
                counts_a = store.dashboard_counts(
                    settings_a.retrieval_hash,
                    analysis_policy_hash=settings_a.analysis_policy_hash,
                )
                self.assertEqual(counts_a["deep_read"], 0)
                self.assertEqual(counts_a["rejected"], 1)
                self.assertEqual(
                    store.list_complete_analyses(
                        config_hash=settings_a.retrieval_hash,
                        analysis_policy_hash=settings_a.analysis_policy_hash,
                    ),
                    [],
                )

                raw_b = json.loads(json.dumps(settings_a.raw))
                raw_b["admission"]["exclude_github_archived"] = False
                settings_b = Settings(
                    raw=raw_b,
                    config_path=settings_a.config_path,
                    project_dir=settings_a.project_dir,
                    workspace_dir=settings_a.workspace_dir,
                    data_dir=settings_a.data_dir,
                    literature_dir=settings_a.literature_dir,
                    outputs_dir=settings_a.outputs_dir,
                    database_path=settings_a.database_path,
                )
                self.assertNotEqual(
                    settings_b.retrieval_hash,
                    settings_a.retrieval_hash,
                )
                self.assertEqual(
                    settings_b.analysis_policy_hash,
                    settings_a.analysis_policy_hash,
                )
                run_b, _, token_b = store.create_or_resume_run(settings_b, "profile-b")
                store.seed_query_jobs(
                    run_b,
                    settings_b,
                    include_hosted=False,
                    lease_token=token_b,
                    smoke=True,
                )
                with store._lock:
                    job_b = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='github'",
                            (run_b,),
                        ).fetchone()["id"]
                    )
                decision_b = objective_admission(archived, settings_b.raw)
                self.assertTrue(decision_b.admitted)
                same_work, _ = store.ingest_record(
                    run_id=run_b,
                    lease_token=token_b,
                    query_job_id=job_b,
                    record=archived,
                    decision=decision_b,
                    raw_sha256="archived-b-allowed",
                )
                self.assertEqual(same_work, work_id)
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings_b.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings_b.analysis_policy_hash,
                        retrieval_hash=settings_b.retrieval_hash,
                        profile_id=settings_b.profile_id,
                        profile_version=settings_b.profile_version,
                    ),
                    0,
                )
                counts_b = store.dashboard_counts(
                    settings_b.retrieval_hash,
                    analysis_policy_hash=settings_b.analysis_policy_hash,
                )
                self.assertEqual(counts_b["deep_read"], 1)
                self.assertEqual(counts_b["pending_analysis"], 0)
                self.assertEqual(
                    len(
                        store.list_complete_analyses(
                            config_hash=settings_b.retrieval_hash,
                            analysis_policy_hash=settings_b.analysis_policy_hash,
                        )
                    ),
                    1,
                )

    def test_terminal_analysis_failure_requires_and_accepts_explicit_requeue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='openalex'",
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W-RETRY",
                    kind="paper",
                    title="Explicit Retry Fixture",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="retry-one",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url=None,
                    local_path="paper.pdf",
                    text_path="paper.txt",
                    content_sha256="pdf",
                    text_sha256="text",
                    byte_count=10,
                    text_char_count=10,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(),
                )
                store.seed_analysis_tasks(
                    "codex_cli",
                    settings.raw["analysis"]["prompt_version"],
                    analysis_policy_hash=settings.analysis_policy_hash,
                    retrieval_hash=settings.retrieval_hash,
                    profile_id=settings.profile_id,
                    profile_version=settings.profile_version,
                )
                task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertTrue(
                    store.fail_analysis_task(
                        int(task["id"]),
                        "terminal fixture failure",
                        run_id=run_id,
                        lease_token=lease_token,
                        retry=False,
                    )
                )
                store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="retry-two",
                )
                with store._lock:
                    state = store._connection.execute(
                        """
                        SELECT state FROM work_scopes
                        WHERE work_id=? AND config_hash=?
                        """,
                        (work_id, settings.retrieval_hash),
                    ).fetchone()["state"]
                self.assertEqual(state, "analysis_failed")
                result = store.requeue_analysis(
                    work_id,
                    analysis_policy_hash=settings.analysis_policy_hash,
                    provider="codex_cli",
                )
                self.assertEqual(result["task_id"], int(task["id"]))
                reclaimed = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertEqual(int(reclaimed["id"]), int(task["id"]))

    def test_shared_pending_analysis_completes_every_compatible_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings_a = make_settings(root)
            raw_b = json.loads(json.dumps(settings_a.raw))
            raw_b["queries"][0]["query"] += " scope-b"
            settings_b = Settings(
                raw=raw_b,
                config_path=settings_a.config_path,
                project_dir=settings_a.project_dir,
                workspace_dir=settings_a.workspace_dir,
                data_dir=settings_a.data_dir,
                literature_dir=settings_a.literature_dir,
                outputs_dir=settings_a.outputs_dir,
                database_path=settings_a.database_path,
            )
            self.assertNotEqual(settings_a.retrieval_hash, settings_b.retrieval_hash)
            self.assertEqual(
                settings_a.analysis_policy_hash,
                settings_b.analysis_policy_hash,
            )
            with RadarStore(settings_a.database_path) as store:
                run_a, _, token_a = store.create_or_resume_run(settings_a, "scope-a")
                store.seed_query_jobs(
                    run_a,
                    settings_a,
                    include_hosted=False,
                    lease_token=token_a,
                    smoke=True,
                )
                with store._lock:
                    job_a = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='openalex'",
                            (run_a,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W-SHARED-PENDING",
                    kind="paper",
                    title="Shared Pending Fixture",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_a,
                    lease_token=token_a,
                    query_job_id=job_a,
                    record=record,
                    decision=objective_admission(record, settings_a.raw),
                    raw_sha256="scope-a",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url=None,
                    local_path="shared.pdf",
                    text_path="shared.txt",
                    content_sha256="pdf",
                    text_sha256="text",
                    byte_count=10,
                    text_char_count=10,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(),
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings_a.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings_a.analysis_policy_hash,
                        retrieval_hash=settings_a.retrieval_hash,
                        profile_id=settings_a.profile_id,
                        profile_version=settings_a.profile_version,
                    ),
                    1,
                )
                run_b, _, token_b = store.create_or_resume_run(settings_b, "scope-b")
                store.seed_query_jobs(
                    run_b,
                    settings_b,
                    include_hosted=False,
                    lease_token=token_b,
                    smoke=True,
                )
                with store._lock:
                    job_b = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='openalex'",
                            (run_b,),
                        ).fetchone()["id"]
                    )
                same_work, _ = store.ingest_record(
                    run_id=run_b,
                    lease_token=token_b,
                    query_job_id=job_b,
                    record=record,
                    decision=objective_admission(record, settings_b.raw),
                    raw_sha256="scope-b",
                )
                self.assertEqual(same_work, work_id)
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings_b.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings_b.analysis_policy_hash,
                        retrieval_hash=settings_b.retrieval_hash,
                        profile_id=settings_b.profile_id,
                        profile_version=settings_b.profile_version,
                    ),
                    0,
                )
                task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings_b.analysis_policy_hash,
                    run_id=run_b,
                    lease_token=token_b,
                )
                self.assertEqual(
                    task["claim_retrieval_hash"],
                    settings_b.retrieval_hash,
                )
                self.assertTrue(
                    store.fail_analysis_task(
                        int(task["id"]),
                        "shared terminal fixture",
                        run_id=run_b,
                        lease_token=token_b,
                        retry=False,
                    )
                )
                with store._lock:
                    failed_states = {
                        row["config_hash"]: row["state"]
                        for row in store._connection.execute(
                            """
                            SELECT config_hash, state FROM work_scopes
                            WHERE work_id=?
                            """,
                            (work_id,),
                        ).fetchall()
                    }
                self.assertEqual(
                    failed_states,
                    {
                        settings_a.retrieval_hash: "analysis_failed",
                        settings_b.retrieval_hash: "analysis_failed",
                    },
                )
                store.requeue_analysis(
                    work_id,
                    analysis_policy_hash=settings_b.analysis_policy_hash,
                    provider="codex_cli",
                )
                task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings_b.analysis_policy_hash,
                    run_id=run_b,
                    lease_token=token_b,
                )
                self.assertIsNotNone(task)
                store.complete_analysis(
                    task_id=int(task["id"]),
                    work_id=work_id,
                    provider="codex_cli",
                    model="fixture",
                    prompt_version=str(task["prompt_version"]),
                    deep_read_status="complete",
                    tier="important",
                    score=80,
                    analysis={"scores": {"r3_relevance": 80}},
                    coverage={"complete": True},
                    receipt={"fixture": True},
                    run_id=run_b,
                    lease_token=token_b,
                )
                for settings in (settings_a, settings_b):
                    counts = store.dashboard_counts(
                        settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    )
                    self.assertEqual(counts["deep_read"], 1)
                    self.assertEqual(counts["pending_analysis"], 0)

    def test_same_title_with_conflicting_dois_is_not_merged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? LIMIT 1",
                            (run_id,),
                        ).fetchone()["id"]
                    )
                ids = []
                for source_id, doi in (("W-a", "10.1234/a"), ("W-b", "10.1234/b")):
                    record = SourceRecord(
                        source="openalex",
                        source_id=source_id,
                        kind="paper",
                        title="A deliberately shared title",
                        query_id="q01",
                        year=2025,
                        doi=doi,
                    )
                    work_id, _ = store.ingest_record(
                        run_id=run_id,
                        lease_token=lease_token,
                        query_job_id=job_id,
                        record=record,
                        decision=objective_admission(record, settings.raw),
                        raw_sha256=source_id,
                    )
                    ids.append(work_id)
                self.assertNotEqual(ids[0], ids[1])
                self.assertEqual(store.dashboard_counts()["unique_works"], 2)

    def test_title_fallback_does_not_merge_different_years_or_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    jobs = {
                        row["source"]: int(row["id"])
                        for row in store._connection.execute(
                            """
                            SELECT id, source FROM query_jobs
                            WHERE run_id=?
                            """,
                            (run_id,),
                        ).fetchall()
                    }
                records = [
                    SourceRecord(
                        source="openalex",
                        source_id="old-paper",
                        kind="paper",
                        title="Shared Ambiguous Title",
                        query_id="q01",
                        year=2000,
                    ),
                    SourceRecord(
                        source="openalex",
                        source_id="new-paper",
                        kind="paper",
                        title="Shared Ambiguous Title",
                        query_id="q01",
                        year=2025,
                    ),
                    SourceRecord(
                        source="github",
                        source_id="owner/shared-title",
                        kind="repository",
                        title="Shared Ambiguous Title",
                        query_id="q01",
                        github_full_name="owner/shared-title",
                    ),
                ]
                work_ids = []
                for record in records:
                    work_id, _ = store.ingest_record(
                        run_id=run_id,
                        lease_token=lease_token,
                        query_job_id=jobs[record.source],
                        record=record,
                        decision=objective_admission(record, settings.raw),
                        raw_sha256=record.source_id,
                    )
                    work_ids.append(work_id)
                self.assertEqual(len(set(work_ids)), 3)

    def test_source_cooldown_blocks_jobs_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                first_run, _, first_token = store.create_or_resume_run(settings, "first")
                store.seed_query_jobs(
                    first_run,
                    settings,
                    include_hosted=False,
                    lease_token=first_token,
                    smoke=True,
                )
                not_before = (
                    datetime.now(timezone.utc) + timedelta(hours=1)
                ).isoformat(timespec="seconds")
                store.set_source_cooldown(
                    "openalex",
                    not_before=not_before,
                    reason="HTTP 429",
                )
                second_run, _, second_token = store.create_or_resume_run(settings, "second")
                store.seed_query_jobs(
                    second_run,
                    settings,
                    include_hosted=False,
                    lease_token=second_token,
                    smoke=True,
                )
                self.assertIsNone(
                    store.claim_query_job(
                        second_run,
                        second_token,
                        job_kind="official",
                        source="openalex",
                    )
                )
                self.assertIsNotNone(
                    store.claim_query_job(
                        second_run,
                        second_token,
                        job_kind="official",
                        source="arxiv",
                    )
                )
                cooldowns = store.active_source_cooldowns()
                self.assertEqual(cooldowns[0]["source"], "openalex")
                self.assertEqual(cooldowns[0]["not_before"], not_before)

    def test_cross_source_title_alias_deduplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    jobs = store._connection.execute(
                        "SELECT id, source, query_id FROM query_jobs WHERE run_id=? ORDER BY id",
                        (run_id,),
                    ).fetchall()
                first = SourceRecord(
                    source="openalex",
                    source_id="W1",
                    kind="paper",
                    title="Workflow Aware Cache Value",
                    query_id="q01",
                    year=2025,
                    doi="10.1/example",
                )
                second = SourceRecord(
                    source="arxiv",
                    source_id="2501.00001",
                    kind="paper",
                    title="Workflow-Aware Cache Value",
                    query_id="q01",
                    year=2025,
                    arxiv_id="2501.00001",
                )
                job_by_source = {row["source"]: int(row["id"]) for row in jobs}
                first_id, first_created = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_by_source["openalex"],
                    record=first,
                    decision=objective_admission(first, settings.raw),
                    raw_sha256="a",
                )
                second_id, second_created = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_by_source["arxiv"],
                    record=second,
                    decision=objective_admission(second, settings.raw),
                    raw_sha256="b",
                )
                self.assertTrue(first_created)
                self.assertFalse(second_created)
                self.assertEqual(first_id, second_id)
                self.assertEqual(store.dashboard_counts()["unique_works"], 1)
                self.assertEqual(store.dashboard_counts()["raw_hits"], 2)
                dashboard = store.list_dashboard_works(
                    config_hash=settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(
                    dashboard[0]["retrieval_sources"],
                    ["arxiv", "openalex"],
                )

    def test_explicit_content_retry_clears_terminal_document_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? LIMIT 1", (run_id,)
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W-retry",
                    kind="paper",
                    title="Retry Fixture",
                    query_id="q01",
                    year=2025,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="raw",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="unavailable",
                    source_url=None,
                    local_path=None,
                    text_path=None,
                    content_sha256=None,
                    text_sha256=None,
                    byte_count=None,
                    text_char_count=None,
                    page_count=None,
                    coverage={"complete": False},
                    error="old failure",
                )
                store.requeue_content(
                    work_id,
                    retrieval_hash=settings.retrieval_hash,
                )
                with store._lock:
                    row = store._connection.execute(
                        """
                        SELECT w.state, d.status, d.error
                        FROM works w JOIN documents d ON d.work_id=w.id
                        WHERE w.id=?
                        """,
                        (work_id,),
                    ).fetchone()
                self.assertEqual(row["state"], "content_retry")
                self.assertEqual(row["status"], "retry")
                self.assertIsNone(row["error"])
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="retry",
                    source_url="https://example.com/retry.pdf",
                    local_path=None,
                    text_path=None,
                    content_sha256="retry-content",
                    text_sha256=None,
                    byte_count=100,
                    text_char_count=0,
                    page_count=1,
                    coverage={
                        "complete": False,
                        "security_status": "incomplete_security",
                        "reason": "pdf_security_reparse_required",
                        "failure_code": "document_policy_mismatch",
                    },
                )
                with store._lock:
                    saved_retry_state = store._connection.execute(
                        "SELECT state FROM works WHERE id=?",
                        (work_id,),
                    ).fetchone()["state"]
                self.assertEqual(saved_retry_state, "content_retry")

    def test_source_and_content_revision_trigger_a_new_deep_read_task(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='github'
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )

                def repository(pushed_at: str) -> SourceRecord:
                    return SourceRecord(
                        source="github",
                        source_id="owner/repo",
                        kind="repository",
                        title="Revision Fixture",
                        query_id="q01",
                        canonical_url="https://github.com/owner/repo",
                        github_full_name="owner/repo",
                        metadata={
                            "pushed_at": pushed_at,
                            "updated_at": pushed_at,
                            "default_branch": "main",
                        },
                    )

                first = repository("2026-07-01T00:00:00Z")
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=first,
                    decision=objective_admission(first, settings.raw),
                    raw_sha256="raw-v1",
                    raw_path="raw/github/v1.json.gz",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="repository_archive",
                    status="ready",
                    source_url=first.canonical_url,
                    local_path="repo-v1.zip",
                    text_path="repo-v1.txt",
                    content_sha256="archive-v1",
                    text_sha256="text-v1",
                    byte_count=10,
                    text_char_count=7,
                    page_count=None,
                    coverage={"complete": True},
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings.analysis_policy_hash,
                        retrieval_hash=settings.retrieval_hash,
                        profile_id=settings.profile_id,
                        profile_version=settings.profile_version,
                    ),
                    1,
                )
                first_task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertIsNotNone(first_task)
                store.complete_analysis(
                    task_id=int(first_task["id"]),
                    work_id=work_id,
                    provider="codex_cli",
                    model="fixture",
                    prompt_version=str(first_task["prompt_version"]),
                    deep_read_status="complete",
                    tier="important",
                    score=80,
                    analysis={"scores": {"r3_relevance": 80}},
                    coverage={"complete": True},
                    receipt={"fixture": True},
                    run_id=run_id,
                    lease_token=lease_token,
                )

                second = repository("2026-07-02T00:00:00Z")
                second_work_id, created = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=second,
                    decision=objective_admission(second, settings.raw),
                    raw_sha256="raw-v2",
                    raw_path="raw/github/v2.json.gz",
                )
                self.assertFalse(created)
                self.assertEqual(second_work_id, work_id)
                update_window_counts = store.dashboard_counts(
                    settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(update_window_counts["deep_read"], 0)
                self.assertEqual(update_window_counts["pending_content"], 1)
                self.assertEqual(
                    store.list_complete_analyses(
                        config_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    ),
                    [],
                )
                update_window_rows = store.list_dashboard_works(
                    config_hash=settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(len(update_window_rows), 1)
                self.assertNotIn("analysis_json", update_window_rows[0])
                self.assertIsNone(
                    store.dashboard_work_analysis(
                        work_id=work_id,
                        config_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    )
                )
                claimed = store.claim_work_for_content(
                    settings.retrieval_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertIsNotNone(claimed)
                self.assertEqual(int(claimed["id"]), work_id)

                store.save_document(
                    work_id=work_id,
                    content_kind="repository_archive",
                    status="ready",
                    source_url=second.canonical_url,
                    local_path="repo-v2.zip",
                    text_path="repo-v2.txt",
                    content_sha256="archive-v2",
                    text_sha256="text-v2",
                    byte_count=11,
                    text_char_count=8,
                    page_count=None,
                    coverage={"complete": True},
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings.analysis_policy_hash,
                        retrieval_hash=settings.retrieval_hash,
                        profile_id=settings.profile_id,
                        profile_version=settings.profile_version,
                    ),
                    1,
                )
                current_counts = store.dashboard_counts(
                    settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(current_counts["deep_read"], 0)
                self.assertEqual(current_counts["pending_analysis"], 1)
                self.assertEqual(
                    store.list_complete_analyses(
                        config_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    ),
                    [],
                )
                with store._lock:
                    revisions = store._connection.execute(
                        """
                        SELECT content_sha256, text_sha256
                        FROM content_revisions
                        WHERE work_id=? ORDER BY id
                        """,
                        (work_id,),
                    ).fetchall()
                    tasks = store._connection.execute(
                        """
                        SELECT status, prompt_version
                        FROM analysis_tasks
                        WHERE work_id=? ORDER BY id
                        """,
                        (work_id,),
                    ).fetchall()
                    observations = store._connection.execute(
                        """
                        SELECT raw_path FROM source_observations
                        ORDER BY id
                        """
                    ).fetchall()
                self.assertEqual(
                    [(row["content_sha256"], row["text_sha256"]) for row in revisions],
                    [("archive-v1", "text-v1"), ("archive-v2", "text-v2")],
                )
                self.assertEqual([row["status"] for row in tasks], ["completed", "pending"])
                self.assertTrue(tasks[0]["prompt_version"].endswith("@text-v1"))
                self.assertTrue(tasks[1]["prompt_version"].endswith("@text-v2"))
                self.assertEqual(
                    [row["raw_path"] for row in observations],
                    ["raw/github/v1.json.gz", "raw/github/v2.json.gz"],
                )

    def test_hosted_rejection_resolves_pending_scope_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=True,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND job_kind='hosted'
                            LIMIT 1
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )
                pending_record = SourceRecord(
                    source="codex_web",
                    source_id="hosted-1",
                    kind="paper",
                    title="Retracted Hosted Result",
                    query_id="web-q01",
                    year=2026,
                    canonical_url="https://arxiv.org/abs/2601.00001",
                    arxiv_id="2601.00001",
                )
                pending_decision = AdmissionDecision(
                    admitted=False,
                    code="hosted_verification_pending",
                    lane="verification_pending",
                    reason="awaiting primary source",
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=pending_record,
                    decision=pending_decision,
                    raw_sha256=None,
                )
                store.seed_verification_task(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    work_id=work_id,
                )
                task = store.claim_verification_task(run_id, lease_token)
                self.assertIsNotNone(task)

                verified = SourceRecord(
                    source="arxiv",
                    source_id="2601.00001",
                    kind="paper",
                    title="Retracted Hosted Result",
                    query_id="web-q01",
                    year=2026,
                    canonical_url="https://arxiv.org/abs/2601.00001",
                    arxiv_id="2601.00001",
                    retracted=True,
                )
                decision = objective_admission(verified, settings.raw)
                verified_work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=verified,
                    decision=decision,
                    raw_sha256="verified",
                    raw_path="raw/arxiv/verified.atom.gz",
                )
                store.resolve_verification_task(
                    int(task["id"]),
                    pending_work_id=work_id,
                    verified_work_id=verified_work_id,
                    decision=decision,
                    lease_token=lease_token,
                )
                with store._lock:
                    scope = store._connection.execute(
                        """
                        SELECT state, admission_code FROM work_scopes
                        WHERE work_id=? AND config_hash=?
                        """,
                        (work_id, settings.retrieval_hash),
                    ).fetchone()
                    resolved = store._connection.execute(
                        """
                        SELECT status, resolution, decision_code, verified_work_id
                        FROM verification_tasks WHERE id=?
                        """,
                        (task["id"],),
                    ).fetchone()
                self.assertEqual(scope["state"], "rejected")
                self.assertEqual(scope["admission_code"], "retracted")
                self.assertEqual(resolved["status"], "completed")
                self.assertEqual(resolved["resolution"], "rejected")
                self.assertEqual(resolved["decision_code"], "retracted")
                self.assertEqual(int(resolved["verified_work_id"]), work_id)

    def test_stale_lease_cannot_finish_reclaimed_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, first_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=True,
                    lease_token=first_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND job_kind='hosted'
                            LIMIT 1
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="codex_web",
                    source_id="hosted-lease",
                    kind="paper",
                    title="Hosted Lease Fixture",
                    query_id="web-q01",
                    year=2026,
                    canonical_url="https://arxiv.org/abs/2601.00002",
                    arxiv_id="2601.00002",
                )
                pending = AdmissionDecision(
                    admitted=False,
                    code="hosted_verification_pending",
                    lane="verification_pending",
                    reason="awaiting primary source",
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=first_token,
                    query_job_id=job_id,
                    record=record,
                    decision=pending,
                    raw_sha256="hosted",
                )
                store.seed_verification_task(
                    run_id=run_id,
                    lease_token=first_token,
                    query_job_id=job_id,
                    work_id=work_id,
                )
                first_claim = store.claim_verification_task(run_id, first_token)
                with store.transaction() as connection:
                    connection.execute(
                        "UPDATE runs SET lease_expires_at=? WHERE id=?",
                        (
                            (
                                datetime.now(timezone.utc) - timedelta(seconds=1)
                            ).isoformat(timespec="seconds"),
                            run_id,
                        ),
                    )
                _, resumed, second_token = store.create_or_resume_run(settings, "test")
                self.assertTrue(resumed)
                second_claim = store.claim_verification_task(run_id, second_token)
                self.assertEqual(int(second_claim["id"]), int(first_claim["id"]))
                with self.assertRaises(RunAlreadyActiveError):
                    store.update_verification_task(
                        int(first_claim["id"]),
                        status="completed",
                        lease_token=first_token,
                    )
                store.update_verification_task(
                    int(second_claim["id"]),
                    status="retry",
                    error="current owner",
                    lease_token=second_token,
                )
                with store._lock:
                    task = store._connection.execute(
                        """
                        SELECT status, attempts, error, claim_lease_token
                        FROM verification_tasks WHERE id=?
                        """,
                        (second_claim["id"],),
                    ).fetchone()
                self.assertEqual(task["status"], "retry")
                self.assertEqual(task["attempts"], 1)
                self.assertEqual(task["error"], "current owner")
                self.assertIsNone(task["claim_lease_token"])

    def test_failed_fallback_can_return_to_superseded_primary_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='openalex'
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="fallback-work",
                    kind="paper",
                    title="Fallback Round Trip",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="raw",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url=None,
                    local_path=None,
                    text_path="fixture.txt",
                    content_sha256="pdf",
                    text_sha256="text",
                    byte_count=3,
                    text_char_count=4,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(),
                )
                seed_args = {
                    "analysis_policy_hash": settings.analysis_policy_hash,
                    "retrieval_hash": settings.retrieval_hash,
                    "profile_id": settings.profile_id,
                    "profile_version": settings.profile_version,
                }
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        **seed_args,
                    ),
                    1,
                )
                self.assertEqual(
                    store.supersede_analysis_tasks(
                        analysis_policy_hash=settings.analysis_policy_hash,
                        replacement_provider="llama_cpp",
                    ),
                    1,
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "llama_cpp",
                        settings.raw["analysis"]["prompt_version"],
                        **seed_args,
                    ),
                    1,
                )
                llama_task = store.claim_analysis_task(
                    "llama_cpp",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertIsNotNone(llama_task)
                self.assertTrue(
                    store.fail_analysis_task(
                        int(llama_task["id"]),
                        "fallback unavailable",
                        run_id=run_id,
                        lease_token=lease_token,
                        retry=False,
                    )
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        **seed_args,
                    ),
                    1,
                )
                self.assertIsNotNone(
                    store.claim_analysis_task(
                        "codex_cli",
                        config_hash=settings.analysis_policy_hash,
                        run_id=run_id,
                        lease_token=lease_token,
                    )
                )

    def test_stale_lease_cannot_update_reclaimed_query_or_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, first_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=first_token,
                    smoke=True,
                )
                first_claim = store.claim_query_job(
                    run_id,
                    first_token,
                    job_kind="official",
                    source="openalex",
                )
                self.assertIsNotNone(first_claim)
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE runs SET lease_expires_at=?
                        WHERE id=?
                        """,
                        (
                            (
                                datetime.now(timezone.utc) - timedelta(seconds=1)
                            ).isoformat(timespec="seconds"),
                            run_id,
                        ),
                    )
                resumed_run, resumed, second_token = store.create_or_resume_run(
                    settings,
                    "test",
                )
                self.assertTrue(resumed)
                self.assertEqual(resumed_run, run_id)
                second_claim = store.claim_query_job(
                    run_id,
                    second_token,
                    job_kind="official",
                    source="openalex",
                )
                self.assertEqual(int(second_claim["id"]), int(first_claim["id"]))
                with self.assertRaises(RunAlreadyActiveError):
                    store.update_query_job(
                        int(first_claim["id"]),
                        status="completed",
                        result_count_delta=99,
                        lease_token=first_token,
                    )
                stale_record = SourceRecord(
                    source="openalex",
                    source_id="stale-write",
                    kind="paper",
                    title="Stale Write",
                    query_id="q01",
                    year=2026,
                )
                with self.assertRaises(RunAlreadyActiveError):
                    store.ingest_record(
                        run_id=run_id,
                        lease_token=first_token,
                        query_job_id=int(first_claim["id"]),
                        record=stale_record,
                        decision=objective_admission(stale_record, settings.raw),
                        raw_sha256="stale",
                    )
                with store._lock:
                    query = store._connection.execute(
                        """
                        SELECT status, result_count, claim_lease_token
                        FROM query_jobs WHERE id=?
                        """,
                        (first_claim["id"],),
                    ).fetchone()
                    source_count = store._connection.execute(
                        "SELECT COUNT(*) FROM source_records"
                    ).fetchone()[0]
                self.assertEqual(query["status"], "running")
                self.assertEqual(query["result_count"], 0)
                self.assertEqual(query["claim_lease_token"], second_token)
                self.assertEqual(source_count, 0)

    def test_stale_lease_cannot_write_reclaimed_analysis_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, first_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=first_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='openalex'
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="lease-analysis",
                    kind="paper",
                    title="Lease Analysis",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=first_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="raw",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url=None,
                    local_path=None,
                    text_path="fixture.txt",
                    content_sha256="pdf",
                    text_sha256="text",
                    byte_count=3,
                    text_char_count=4,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(),
                )
                store.seed_analysis_tasks(
                    "codex_cli",
                    settings.raw["analysis"]["prompt_version"],
                    analysis_policy_hash=settings.analysis_policy_hash,
                    retrieval_hash=settings.retrieval_hash,
                    profile_id=settings.profile_id,
                    profile_version=settings.profile_version,
                )
                first_task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=first_token,
                )
                with store.transaction() as connection:
                    connection.execute(
                        "UPDATE runs SET lease_expires_at=? WHERE id=?",
                        (
                            (
                                datetime.now(timezone.utc) - timedelta(seconds=1)
                            ).isoformat(timespec="seconds"),
                            run_id,
                        ),
                    )
                _, _, second_token = store.create_or_resume_run(settings, "test")
                second_task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=second_token,
                )
                self.assertEqual(int(second_task["id"]), int(first_task["id"]))
                chunks = [
                    {
                        "index": 0,
                        "span": {"character_start": 0, "character_end": 4},
                        "sha256": "chunk",
                    }
                ]
                with self.assertRaises(RunAlreadyActiveError):
                    store.prepare_chunks(
                        int(first_task["id"]),
                        chunks,
                        lease_token=first_token,
                    )
                store.prepare_chunks(
                    int(second_task["id"]),
                    chunks,
                    lease_token=second_token,
                )
                with self.assertRaises(RunAlreadyActiveError):
                    store.save_chunk_result(
                        task_id=int(first_task["id"]),
                        chunk_index=0,
                        output={"writer": "stale"},
                        receipt={"writer": "stale"},
                        lease_token=first_token,
                    )
                store.save_chunk_result(
                    task_id=int(second_task["id"]),
                    chunk_index=0,
                    output={"writer": "current"},
                    receipt={"writer": "current"},
                    lease_token=second_token,
                )
                row = store.chunk_statuses(int(second_task["id"]))[0]
                self.assertEqual(json.loads(row["output_json"])["writer"], "current")


    def test_pdf_security_state_blocks_analysis_and_revision_identity_is_stable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            """
                            SELECT id FROM query_jobs
                            WHERE run_id=? AND source='openalex'
                            LIMIT 1
                            """,
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W-pdf-security",
                    kind="paper",
                    title="PDF Security State Fixture",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="raw-observation",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="incomplete",
                    source_url="https://example.com/security.pdf",
                    local_path="quarantine/security.pdf",
                    text_path=None,
                    content_sha256="pdf-sha",
                    text_sha256=None,
                    byte_count=100,
                    text_char_count=None,
                    page_count=None,
                    coverage={
                        "complete": False,
                        "security_status": "incomplete_security",
                        "reason": "pdf_extract_timeout",
                        "failure_code": "wall_timeout",
                    },
                    error="safe extraction timed out",
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings.analysis_policy_hash,
                        retrieval_hash=settings.retrieval_hash,
                        profile_id=settings.profile_id,
                        profile_version=settings.profile_version,
                    ),
                    0,
                )
                dashboard = store.list_dashboard_works(
                    config_hash=settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(dashboard[0]["state"], "content_incomplete")
                visible_coverage = json.loads(
                    dashboard[0]["content_coverage_json"]
                )
                self.assertEqual(
                    visible_coverage["security_status"],
                    "incomplete_security",
                )
                self.assertEqual(
                    visible_coverage["reason"],
                    "pdf_extract_timeout",
                )

                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="incomplete",
                    source_url="https://example.com/security.pdf",
                    local_path="documents/security.pdf",
                    text_path="text/security-text-sha.txt",
                    content_sha256="pdf-sha",
                    text_sha256="text-sha",
                    byte_count=100,
                    text_char_count=400,
                    page_count=1,
                    coverage={
                        "complete": False,
                        "security_status": "parsed_verified",
                        "reason": "insufficient_extractable_text",
                    },
                    error="coverage incomplete",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url="https://example.com/security.pdf",
                    local_path="documents/security.pdf",
                    text_path="text/security-text-sha.txt",
                    content_sha256="pdf-sha",
                    text_sha256="text-sha",
                    byte_count=100,
                    text_char_count=400,
                    page_count=1,
                    coverage=current_pdf_ready_coverage(),
                )
                with store._lock:
                    current = store._connection.execute(
                        """
                        SELECT id, status, document_policy_hash, coverage_json
                        FROM documents
                        WHERE work_id=? AND content_kind='paper_pdf'
                        """,
                        (work_id,),
                    ).fetchone()
                    revision_count = int(
                        store._connection.execute(
                            """
                            SELECT COUNT(*) FROM content_revisions
                            WHERE work_id=? AND content_kind='paper_pdf'
                            """,
                            (work_id,),
                        ).fetchone()[0]
                    )
                    observations = store._connection.execute(
                        """
                        SELECT event_type, status, receipt_json
                        FROM document_processing_observations
                        WHERE document_id=?
                        ORDER BY id
                        """,
                        (current["id"],),
                    ).fetchall()
                self.assertEqual(current["status"], "ready")
                self.assertEqual(
                    current["document_policy_hash"],
                    CURRENT_PDF_DOCUMENT_POLICY_HASH,
                )
                self.assertTrue(json.loads(current["coverage_json"])["complete"])
                self.assertEqual(revision_count, 2)
                self.assertEqual(len(observations), 3)
                self.assertTrue(
                    all(row["event_type"] == "save" for row in observations)
                )
                self.assertEqual(
                    json.loads(observations[-1]["receipt_json"])[
                        "parser_receipt"
                    ]["worker_sha256"],
                    CURRENT_PDF_DOCUMENT_POLICY["code"]["worker_sha256"],
                )
                self.assertEqual(
                    store.seed_analysis_tasks(
                        "codex_cli",
                        settings.raw["analysis"]["prompt_version"],
                        analysis_policy_hash=settings.analysis_policy_hash,
                        retrieval_hash=settings.retrieval_hash,
                        profile_id=settings.profile_id,
                        profile_version=settings.profile_version,
                    ),
                    1,
                )


class ContentTests(unittest.TestCase):
    def _archive(self, files: dict[str, bytes]) -> bytes:
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in files.items():
                archive.writestr(name, value)
        return stream.getvalue()

    def _pdf_from_streams(self, streams: list[bytes | None]) -> bytes:
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

    def _text_pdf(self) -> bytes:
        page_one = (
            "NORMAL_PAGE_ONE_SENTINEL "
            + ("workflow cache evidence value prediction " * 20)
        )
        page_two = (
            "NORMAL_PAGE_TWO_SENTINEL "
            + ("agent serving reuse retention decision " * 20)
        )

        def content(value: str) -> bytes:
            escaped = (
                value.replace("\\", "\\\\")
                .replace("(", "\\(")
                .replace(")", "\\)")
            )
            return (
                b"BT /F1 10 Tf 40 740 Td ("
                + escaped.encode("latin-1")
                + b") Tj ET"
            )

        return self._pdf_from_streams([content(page_one), content(page_two)])

    def _blank_pdf(self, page_count: int = 3) -> bytes:
        return self._pdf_from_streams([None for _ in range(page_count)])

    def _encrypted_pdf(self) -> bytes:
        source = PdfReader(io.BytesIO(self._text_pdf()))
        output = io.BytesIO()
        writer = PdfWriter()
        writer.append_pages_from_reader(source)
        writer.encrypt("r3-test-password")
        writer.write(output)
        return output.getvalue()

    def _process_pdf(
        self,
        settings: Settings,
        body: bytes,
        *,
        work_id: int = 1,
    ):
        receipt = RawReceipt(
            sha256=hashlib.sha256(body).hexdigest(),
            path="raw/test.pdf.gz",
            byte_count=len(body),
            status_code=200,
            final_url="https://example.com/paper.pdf",
            fetched_at="now",
        )

        class FakeClient:
            def request_bytes(self, *_: object, **__: object):
                return body, receipt, {"Content-Type": "application/pdf"}

        processor = ContentProcessor(
            settings,
            lambda _: FakeClient(),
            JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
            "run",
        )
        return processor._paper(
            {
                "id": work_id,
                "pdf_url": "https://example.com/paper.pdf",
                "arxiv_id": None,
                "doi": None,
            }
        )

    def _write_probe_worker(
        self,
        path: Path,
        *,
        workspace_target: Path,
        wrong_input_identity: bool = False,
        network_target: tuple[str, int] = ("1.1.1.1", 443),
    ) -> None:
        source = r'''
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--request", required=True)
parser.add_argument("--output-dir", required=True)
args = parser.parse_args()
request = json.loads(Path(args.request).read_text(encoding="utf-8"))
output = Path(args.output_dir)
target = Path(__TARGET__)
try:
    target.read_text(encoding="utf-8")
    read_blocked = False
except OSError:
    read_blocked = True
try:
    target.write_text("violation", encoding="utf-8")
    write_blocked = False
except OSError:
    write_blocked = True
created_target = target.parent / "appcontainer-created.txt"
try:
    created_target.write_text("violation", encoding="utf-8")
    create_blocked = False
except OSError:
    create_blocked = True
renamed_target = target.parent / "appcontainer-renamed.txt"
try:
    target.rename(renamed_target)
    rename_blocked = False
except OSError:
    rename_blocked = True
try:
    target.unlink()
    delete_blocked = False
except OSError:
    delete_blocked = True
credential_keys = (
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "OPENALEX_API_KEY",
    "ANTHROPIC_API_KEY",
)
credential_absent = all(os.environ.get(key) is None for key in credential_keys)
try:
    network = socket.create_connection(
        (__NETWORK_HOST__, __NETWORK_PORT__),
        timeout=1,
    )
    network.close()
    network_blocked = False
except OSError:
    network_blocked = True
child_marker = output / "child-escaped.txt"
child_code = (
    "from pathlib import Path; "
    + "Path(" + repr(str(child_marker)) + ").write_text('violation')"
)
try:
    child = subprocess.run(
        [sys.executable, "-c", child_code],
        check=False,
        timeout=5,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_blocked = child.returncode != 0 and not child_marker.exists()
except (OSError, subprocess.SubprocessError):
    child_blocked = not child_marker.exists()
text = (
    f"read_blocked={int(read_blocked)};"
    f"write_blocked={int(write_blocked)};"
    f"create_blocked={int(create_blocked)};"
    f"rename_blocked={int(rename_blocked)};"
    f"delete_blocked={int(delete_blocked)};"
    f"credential_absent={int(credential_absent)};"
    f"network_blocked={int(network_blocked)};"
    f"child_blocked={int(child_blocked)}"
)
rendered = f"=== PAGE 1 ===\n{text}\n"
options = {"strict": False}
reported_input = {
    "sha256": request["input"]["sha256"],
    "byte_count": request["input"]["byte_count"],
}
if __WRONG_INPUT__:
    reported_input["sha256"] = "0" * 64
result = {
    "schema": "r3/pdf-parse-result/v1",
    "request_id": request["request_id"],
    "outcome": "parsed",
    "parser": {
        "id": "pypdf",
        "version": "__PYPDF_VERSION__",
        "policy_version": "r3-pdf-text-v1",
        "effective_options": options,
        "options_sha256": hashlib.sha256(
            json.dumps(
                options,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
    },
    "input": reported_input,
    "isolation": {
        "integrity_level": os.environ.get("R3_PDF_SANDBOX_INTEGRITY", "missing"),
        "credential_environment_keys": [],
    },
    "document": {
        "page_count": 1,
        "rendered_character_count": len(rendered),
        "non_whitespace_total": len(re.sub(r"\s+", "", text)),
        "pages": [
            {
                "page": 1,
                "text": text,
                "non_whitespace": len(re.sub(r"\s+", "", text)),
                "rendered_character_count": len(rendered),
                "rendered_sha256": hashlib.sha256(
                    rendered.encode("utf-8")
                ).hexdigest(),
                "outcome": "ok",
                "error": None,
            }
        ],
    },
    "failure": None,
}
(output / "result.json").write_text(
    json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
'''
        source = source.replace("__TARGET__", repr(str(workspace_target)))
        source = source.replace(
            "__WRONG_INPUT__",
            "True" if wrong_input_identity else "False",
        )
        source = source.replace("__PYPDF_VERSION__", REQUIRED_PYPDF_VERSION)
        source = source.replace("__NETWORK_HOST__", repr(network_target[0]))
        source = source.replace("__NETWORK_PORT__", str(network_target[1]))
        path.write_text(source, encoding="utf-8", newline="\n")

    def test_repository_inventory_and_dependency_exclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            audit = JsonlAuditLog(settings.outputs_dir / "audit.jsonl")
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                audit,
                "run",
            )
            body = self._archive(
                {
                    "repo/README.md": b"# Demo\n",
                    "repo/src/cache.py": b"def value():\n    return 1\n",
                    "repo/node_modules/pkg/index.js": b"ignored\n",
                    "repo/image.png": b"\x89PNG\r\n",
                }
            )
            result = processor._read_repository_archive(body)
            self.assertTrue(result["coverage"]["complete"])
            self.assertIn("=== FILE: repo/README.md ===", result["text"])
            self.assertNotIn("node_modules/pkg", result["text"])
            self.assertEqual(result["coverage"]["included_file_count"], 2)

    def test_repository_text_cap_is_visible_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["documents"]["max_repository_text_bytes"] = 8
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            result = processor._read_repository_archive(
                self._archive({"repo/a.py": b"123456", "repo/b.py": b"abcdef"})
            )
            self.assertFalse(result["coverage"]["complete"])
            self.assertIn("repository_text_limit", result["coverage"]["incomplete_reasons"])

    def test_large_generated_dataset_is_inventoried_but_not_deep_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            result = processor._read_repository_archive(
                self._archive(
                    {
                        "repo/src/app.py": b"print('ok')\n",
                        "repo/data/archive.json": b"".join(
                            hashlib.sha256(str(index).encode()).hexdigest().encode()
                            for index in range(3000)
                        ),
                    }
                )
            )
            self.assertTrue(result["coverage"]["complete"])
            decisions = {item["path"]: item["decision"] for item in result["inventory"]}
            self.assertEqual(
                decisions["repo/data/archive.json"],
                "generated_data_snapshot_excluded",
            )
            self.assertNotIn("archive.json", result["text"])

    def test_repository_structural_corpus_is_deterministic_and_auditable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["documents"]["repository_corpus"] = {
                "mode": "core_plus_sampled_aux_v1",
                "max_selected_text_bytes": 240,
                "max_auxiliary_text_bytes": 110,
            }
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            files = {
                "repo/README.md": b"# Demo\n",
                "repo/src/cache.py": b"def value():\n    return 1\n",
                "repo/tests/test_cache.py": b"assert value()\n",
                "repo/docs/design.md": b"Design notes\n",
                "repo/scripts/bench.py": b"print('bench')\n",
            }
            first = processor._read_repository_archive(self._archive(files))
            second = processor._read_repository_archive(
                self._archive(dict(reversed(list(files.items()))))
            )
            self.assertTrue(first["coverage"]["complete"])
            self.assertEqual(
                first["coverage"]["coverage_scope"],
                "selected_repository_corpus",
            )
            self.assertEqual(first["text"], second["text"])
            self.assertEqual(
                first["coverage"]["inventory_sha256"],
                second["coverage"]["inventory_sha256"],
            )
            included = {
                item["repository_path"]: item["included"]
                for item in first["inventory"]
            }
            self.assertTrue(included["README.md"])
            self.assertTrue(included["src/cache.py"])
            self.assertTrue(included["tests/test_cache.py"])
            self.assertTrue(included["docs/design.md"])
            self.assertFalse(included["scripts/bench.py"])
            self.assertIn("=== FILE: README.md ===", first["text"])
            self.assertIn("docs/design.md", first["text"])
            scripts_record = next(
                item
                for item in first["inventory"]
                if item["repository_path"] == "scripts/bench.py"
            )
            self.assertEqual(scripts_record["role"], "script")
            self.assertIn("policy_excluded", scripts_record["selection_reason"])
            self.assertEqual(
                first["coverage"]["inventory_sha256"],
                sha256_text(json_dumps(first["inventory"], pretty=True) + "\n"),
            )
            self.assertLessEqual(
                first["coverage"]["final_text_utf8_bytes"],
                240,
            )

    def test_selected_repository_decode_failure_blocks_ready_coverage(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["documents"]["repository_corpus"] = {
                "mode": "core_plus_sampled_aux_v1",
                "max_selected_text_bytes": 200,
                "max_auxiliary_text_bytes": 80,
            }
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            result = processor._read_repository_archive(
                self._archive(
                    {
                        "repo/src/cache.py": b"print('ok')\n",
                        "repo/docs/design.md": b"\xff",
                    }
                )
            )
            self.assertFalse(result["coverage"]["complete"])
            self.assertIn(
                "selected_undecodable_text:docs/design.md",
                result["coverage"]["incomplete_reasons"],
            )

    def test_repository_selector_bounds_large_core_without_false_incomplete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["documents"]["repository_corpus"] = {
                "mode": "core_plus_sampled_aux_v1",
                "max_selected_text_bytes": 180,
                "max_auxiliary_text_bytes": 40,
            }
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            result = processor._read_repository_archive(
                self._archive(
                    {
                        "repo/README.md": b"# Demo\n",
                        **{
                            f"repo/src/module_{index}.py": (
                                f"def value_{index}(): return {index}\n"
                            ).encode()
                            for index in range(8)
                        },
                    }
                )
            )
            self.assertTrue(result["coverage"]["complete"])
            excluded_core = [
                item
                for item in result["inventory"]
                if item["decision"] == "policy_core_budget"
            ]
            self.assertTrue(excluded_core)
            self.assertLessEqual(
                result["coverage"]["final_text_utf8_bytes"],
                180,
            )

    def test_repository_selector_prioritizes_research_paths_and_balances_groups(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["research_question"] = (
                "Can workflow cache eviction predict near-term reuse value?"
            )
            settings.raw["documents"]["repository_corpus"] = {
                "mode": "core_plus_sampled_aux_v1",
                "max_selected_text_bytes": 250,
                "max_auxiliary_text_bytes": 40,
            }
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            result = processor._read_repository_archive(
                self._archive(
                    {
                        "repo/src/alpha/aaa.py": b"x = 'alphabetical filler'\n" * 3,
                        "repo/src/alpha/cache_eviction.py": b"def evict(): return 1\n",
                        "repo/src/zeta/workflow.py": b"def workflow(): return 1\n",
                        "repo/src/zeta/zzz.py": b"x = 'more filler'\n" * 3,
                    }
                )
            )
            included = {
                item["repository_path"]: item["included"]
                for item in result["inventory"]
            }
            self.assertTrue(included["src/alpha/cache_eviction.py"])
            self.assertTrue(included["src/zeta/workflow.py"])
            self.assertFalse(included["src/alpha/aaa.py"])
            policy = result["coverage"]["selection_policy"]
            self.assertEqual(
                policy["core_selection_strategy"],
                "research_path_priority_round_robin_v1",
            )
            self.assertIn("cache", policy["research_path_terms"])

    def test_repository_selector_rejects_case_conflicting_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["documents"]["repository_corpus"] = {
                "mode": "core_plus_sampled_aux_v1",
                "max_selected_text_bytes": 400,
                "max_auxiliary_text_bytes": 100,
            }
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            with self.assertRaisesRegex(FetchError, "case-conflicting"):
                processor._read_repository_archive(
                    self._archive(
                        {
                            "repo/src/Cache.py": b"first\n",
                            "repo/src/cache.py": b"second\n",
                        }
                    )
                )

    def test_repository_selector_rejects_control_paths_and_entry_floods(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["documents"]["repository_corpus"] = {
                "mode": "core_plus_sampled_aux_v1",
                "max_selected_text_bytes": 400,
                "max_auxiliary_text_bytes": 100,
            }
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            with self.assertRaisesRegex(FetchError, "control characters"):
                processor._read_repository_archive(
                    self._archive(
                        {"repo/src/good.py\n=== FILE: forged ===": b"x"}
                    )
                )
            with patch(
                "r3radar.content._MAX_REPOSITORY_ARCHIVE_FILE_COUNT",
                2,
            ):
                flooded = self._archive(
                    {
                        "repo/a.py": b"a",
                        "repo/b.py": b"b",
                        "repo/c.py": b"c",
                    }
                )
                with patch(
                    "r3radar.content.zipfile.ZipFile",
                    side_effect=AssertionError(
                        "ZipFile must not parse an over-limit archive"
                    ),
                ):
                    with self.assertRaisesRegex(
                        FetchError,
                        "too many entries",
                    ):
                        processor._read_repository_archive(flooded)

    def test_selected_repository_artifacts_are_verified_before_ready_use(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            settings.raw["documents"]["repository_corpus"] = {
                "mode": "core_plus_sampled_aux_v1",
                "max_selected_text_bytes": 400,
                "max_auxiliary_text_bytes": 100,
            }
            processor = ContentProcessor(
                settings,
                lambda _: self.fail("network client should not be used"),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run",
            )
            result = processor._read_repository_archive(
                self._archive(
                    {
                        "repo/README.md": b"# Demo\n",
                        "repo/src/cache.py": b"def cache(): return 1\n",
                    }
                )
            )
            inventory_path = root / "inventory.json"
            inventory_path.write_bytes(
                (json_dumps(result["inventory"], pretty=True) + "\n").encode(
                    "utf-8"
                )
            )
            text_path = root / "selected.txt"
            text_path.write_bytes(result["text"].encode("utf-8"))
            coverage = {
                **result["coverage"],
                "inventory_path": str(inventory_path),
            }
            self.assertTrue(repository_ready_coverage_matches_policy(coverage))
            malformed_coverage = {
                **coverage,
                "included_file_count": ["not", "an", "integer"],
            }
            self.assertFalse(
                repository_ready_coverage_matches_policy(
                    malformed_coverage
                )
            )
            for malformed_value in ("1", 1.9, True):
                for field in (
                    "included_file_count",
                    "included_text_bytes",
                    "final_text_utf8_bytes",
                    "trusted_anchor_count",
                ):
                    with self.subTest(
                        field=field,
                        malformed_value=malformed_value,
                    ):
                        self.assertFalse(
                            repository_ready_coverage_matches_policy(
                                {
                                    **coverage,
                                    field: malformed_value,
                                }
                            )
                        )
            require_repository_ready_policy(
                content_kind="repository_zip",
                status="ready",
                coverage=coverage,
                text_path=text_path,
            )
            inventory_path.write_bytes(b"[]\n")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                require_repository_ready_policy(
                    content_kind="repository_zip",
                    status="ready",
                    coverage=coverage,
                    text_path=text_path,
                )

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_real_pdf_worker_preserves_text_pages_hashes_and_immutable_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            body = self._text_pdf()
            result = self._process_pdf(settings, body)
            self.assertEqual(result.status, "ready")
            self.assertTrue(result.coverage["complete"])
            self.assertEqual(result.coverage["security_status"], "parsed_verified")
            self.assertEqual(result.coverage["parser"]["version"], REQUIRED_PYPDF_VERSION)
            self.assertEqual(
                result.coverage["parser"]["isolation"]["integrity_level"],
                "appcontainer_low",
            )
            parser_receipt = result.coverage["parser_receipt"]
            self.assertEqual(
                parser_receipt["sandbox"]["container"],
                "appcontainer",
            )
            self.assertEqual(
                parser_receipt["sandbox"]["capability_count"],
                0,
            )
            self.assertFalse(
                parser_receipt["sandbox"]["network_capability"],
            )
            self.assertEqual(parser_receipt["termination"], "process_exit")
            self.assertEqual(parser_receipt["return_code"], 0)
            self.assertGreaterEqual(
                parser_receipt["job_accounting"]["total_processes"],
                1,
            )
            self.assertEqual(result.page_count, 2)
            self.assertIn("NORMAL_PAGE_ONE_SENTINEL", Path(result.text_path).read_text())
            self.assertIn("NORMAL_PAGE_TWO_SENTINEL", Path(result.text_path).read_text())
            self.assertIn(result.content_sha256, Path(result.local_path).name)
            self.assertIn(result.text_sha256, Path(result.text_path).name)
            self.assertEqual(
                hashlib.sha256(Path(result.local_path).read_bytes()).hexdigest(),
                result.content_sha256,
            )
            self.assertEqual(
                hashlib.sha256(Path(result.text_path).read_bytes()).hexdigest(),
                result.text_sha256,
            )
            page_map = result.coverage["page_map"]
            self.assertEqual(page_map[0]["start"], 0)
            self.assertEqual(page_map[-1]["end"], result.text_char_count)
            self.assertEqual(page_map[0]["end"], page_map[1]["start"])
            quarantine_path = (
                settings.literature_dir
                / "quarantine"
                / "pdf"
                / f"{result.content_sha256}.pdf"
            )
            self.assertTrue(quarantine_path.is_file())
            self.assertEqual(
                hashlib.sha256(quarantine_path.read_bytes()).hexdigest(),
                result.content_sha256,
            )

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_blank_pdf_pages_cannot_pass_full_text_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            result = self._process_pdf(settings, self._blank_pdf(45))
            self.assertEqual(result.status, "incomplete")
            self.assertEqual(result.coverage["reason"], "insufficient_extractable_text")
            self.assertEqual(len(result.coverage["empty_page_indices"]), 45)
            self.assertEqual(result.coverage["extracted_non_whitespace_total"], 0)
            self.assertEqual(result.coverage["security_status"], "parsed_verified")

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_truncated_and_encrypted_pdfs_remain_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            normal = self._text_pdf()
            cases = {
                "truncated": normal[: max(64, len(normal) // 3)],
                "encrypted": self._encrypted_pdf(),
            }
            for index, (name, body) in enumerate(cases.items(), start=1):
                with self.subTest(name=name):
                    result = self._process_pdf(settings, body, work_id=index)
                    self.assertEqual(result.status, "incomplete")
                    self.assertEqual(
                        result.coverage["security_status"],
                        "incomplete_security",
                    )
                    self.assertEqual(
                        result.coverage["reason"],
                        "pdf_extract_worker_failed",
                    )
                    self.assertIn(
                        result.coverage["failure_code"],
                        {"invalid_pdf", "encrypted_pdf"},
                    )
                    self.assertIsNone(result.text_path)
                    self.assertTrue(Path(result.local_path).is_file())
                    self.assertEqual(
                        hashlib.sha256(Path(result.local_path).read_bytes()).hexdigest(),
                        result.content_sha256,
                    )

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_inline_image_regression_and_page_limit_exit_within_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["pdf_parser"]["wall_timeout_seconds"] = 3
            unterminated_inline_image = self._pdf_from_streams(
                [b"q BI /W 1 /H 1 /CS /RGB /BPC 8 ID \x00\x00\x00"]
            )
            started = time.monotonic()
            image_result = self._process_pdf(settings, unterminated_inline_image)
            self.assertLess(time.monotonic() - started, 8)
            self.assertEqual(image_result.status, "incomplete")
            self.assertEqual(
                image_result.coverage["security_status"],
                "parsed_verified",
            )
            self.assertEqual(
                image_result.coverage["reason"],
                "insufficient_extractable_text",
            )
            self.assertEqual(
                image_result.coverage["extraction_errors"],
                [
                    {
                        "page": 1,
                        "error_type": "PdfReadError",
                        "error": "Unexpected end of stream.",
                    }
                ],
            )
            self.assertEqual(
                image_result.coverage["parser_receipt"]["return_code"],
                0,
            )
            settings.raw["pdf_parser"]["max_pages"] = 2
            page_result = self._process_pdf(settings, self._blank_pdf(3), work_id=2)
            self.assertEqual(page_result.status, "incomplete")
            self.assertEqual(
                page_result.coverage["security_status"],
                "incomplete_security",
            )
            self.assertEqual(page_result.coverage["failure_code"], "limit_exceeded")

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_worker_timeout_is_terminated_and_mapped_to_incomplete_security(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            body = self._blank_pdf(1)
            input_path = root / "input.pdf"
            input_path.write_bytes(body)
            helper = root / "sleep_worker.py"
            helper.write_text(
                "import time\ntime.sleep(30)\n",
                encoding="utf-8",
            )
            config = dict(settings.raw["pdf_parser"])
            config.update(
                {
                    "wall_timeout_seconds": 1,
                    "cpu_time_seconds": 10,
                    "memory_limit_bytes": 268435456,
                }
            )
            jobs_root = (
                Path(os.environ["LOCALAPPDATA"])
                / "R3ResearchRadar"
                / "pdf-sandbox"
                / "jobs"
            )
            started = time.monotonic()
            with self.assertRaises(PdfParseError) as raised:
                parse_pdf_with_worker(
                    input_path,
                    expected_sha256=hashlib.sha256(body).hexdigest(),
                    expected_byte_count=len(body),
                    config=config,
                    _worker_path=helper,
                )
            self.assertEqual(raised.exception.reason_code, "pdf_extract_timeout")
            self.assertEqual(raised.exception.failure_code, "wall_timeout")
            self.assertEqual(
                raised.exception.receipt["termination"],
                "wall_timeout",
            )
            self.assertIsNotNone(raised.exception.receipt["return_code"])
            self.assertIn("job_accounting", raised.exception.receipt)
            self.assertNotIn("result_sha256", raised.exception.receipt)
            self.assertLess(time.monotonic() - started, 8)
            owned_job_dir = jobs_root / raised.exception.receipt["job_id"]
            self.assertFalse(
                owned_job_dir.exists(),
                f"owned PDF sandbox job was not cleaned: {owned_job_dir.name}",
            )

            processor = ContentProcessor(
                settings,
                lambda _: self.fail("patched parser path should not fetch"),
                JsonlAuditLog(settings.outputs_dir / "audit-timeout.jsonl"),
                "run",
            )
            with patch(
                "r3radar.content.parse_pdf_with_worker",
                side_effect=PdfParseError(
                    "pdf_extract_timeout",
                    "wall_timeout",
                    "timeout",
                    receipt={"termination": "wall_timeout"},
                ),
            ):
                result = self._process_pdf(settings, body, work_id=2)
            self.assertEqual(result.status, "incomplete")
            self.assertEqual(result.coverage["reason"], "pdf_extract_timeout")
            self.assertEqual(
                result.coverage["security_status"],
                "incomplete_security",
            )
            self.assertIsNone(result.text_path)

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_gate_failure_terminates_worker_cleans_task_and_allows_next_pdf(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            body = self._blank_pdf(1)
            input_path = root / "input.pdf"
            input_path.write_bytes(body)
            jobs_root = (
                Path(os.environ["LOCALAPPDATA"])
                / "R3ResearchRadar"
                / "pdf-sandbox"
                / "jobs"
            )
            original_write_bytes = Path.write_bytes

            def fail_gate(path: Path, data: bytes) -> int:
                if path.name == "start.gate":
                    raise OSError("injected gate failure")
                return original_write_bytes(path, data)

            started = time.monotonic()
            with patch.object(
                Path,
                "write_bytes",
                autospec=True,
                side_effect=fail_gate,
            ):
                with self.assertRaises(PdfParseError) as raised:
                    parse_pdf_with_worker(
                        input_path,
                        expected_sha256=hashlib.sha256(body).hexdigest(),
                        expected_byte_count=len(body),
                        config=settings.raw["pdf_parser"],
                    )
            self.assertEqual(
                raised.exception.failure_code,
                "sandbox_gate_unavailable",
            )
            self.assertEqual(
                raised.exception.receipt["termination"],
                "gate_failure",
            )
            self.assertIsNotNone(raised.exception.receipt["return_code"])
            self.assertLess(time.monotonic() - started, 8)
            owned_job_dir = jobs_root / raised.exception.receipt["job_id"]
            self.assertFalse(
                owned_job_dir.exists(),
                f"owned PDF sandbox job was not cleaned: {owned_job_dir.name}",
            )

            extraction = parse_pdf_with_worker(
                input_path,
                expected_sha256=hashlib.sha256(body).hexdigest(),
                expected_byte_count=len(body),
                config=settings.raw["pdf_parser"],
            )
            self.assertEqual(extraction.page_count, 1)

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_parent_rejects_crash_invalid_json_and_wrong_input_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            body = self._blank_pdf(1)
            input_path = root / "input.pdf"
            input_path.write_bytes(body)
            config = dict(settings.raw["pdf_parser"])
            config["wall_timeout_seconds"] = 5
            helpers = {
                "crash": (
                    "import os\nos._exit(73)\n",
                    "worker_nonzero_exit",
                ),
                "invalid_json": (
                    "import argparse\nfrom pathlib import Path\n"
                    "p=argparse.ArgumentParser(add_help=False);"
                    "p.add_argument('--request');p.add_argument('--output-dir');"
                    "a=p.parse_args();"
                    "Path(a.output_dir,'result.json').write_text('not-json')\n",
                    "result_schema_invalid",
                ),
            }
            for name, (source, expected_failure) in helpers.items():
                with self.subTest(name=name):
                    helper = root / f"{name}_worker.py"
                    helper.write_text(source, encoding="utf-8")
                    with self.assertRaises(PdfParseError) as raised:
                        parse_pdf_with_worker(
                            input_path,
                            expected_sha256=hashlib.sha256(body).hexdigest(),
                            expected_byte_count=len(body),
                            config=config,
                            _worker_path=helper,
                        )
                    self.assertEqual(
                        raised.exception.failure_code,
                        expected_failure,
                    )

            with self.assertRaises(PdfParseError) as raised:
                parse_pdf_with_worker(
                    input_path,
                    expected_sha256=hashlib.sha256(body).hexdigest(),
                    expected_byte_count=len(body) + 1,
                    config=config,
                )
            self.assertEqual(raised.exception.failure_code, "input_mismatch")
            with self.assertRaises(PdfParseError) as raised:
                parse_pdf_with_worker(
                    input_path,
                    expected_sha256="0" * 64,
                    expected_byte_count=len(body),
                    config=config,
                )
            self.assertEqual(raised.exception.failure_code, "input_mismatch")

            wrong_hash_helper = root / "wrong_hash_worker.py"
            target = root / "workspace-sentinel.txt"
            target.write_text("unchanged", encoding="utf-8")
            self._write_probe_worker(
                wrong_hash_helper,
                workspace_target=target,
                wrong_input_identity=True,
            )
            with self.assertRaises(PdfParseError) as raised:
                parse_pdf_with_worker(
                    input_path,
                    expected_sha256=hashlib.sha256(body).hexdigest(),
                    expected_byte_count=len(body),
                    config=config,
                    _worker_path=wrong_hash_helper,
                )
            self.assertEqual(
                raised.exception.failure_code,
                "result_schema_invalid",
            )
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

            partial_result_helper = root / "partial_result_then_crash.py"
            self._write_probe_worker(
                partial_result_helper,
                workspace_target=target,
            )
            partial_result_helper.write_text(
                partial_result_helper.read_text(encoding="utf-8")
                + "\nos._exit(73)\n",
                encoding="utf-8",
                newline="\n",
            )
            with self.assertRaises(PdfParseError) as raised:
                parse_pdf_with_worker(
                    input_path,
                    expected_sha256=hashlib.sha256(body).hexdigest(),
                    expected_byte_count=len(body),
                    config=config,
                    _worker_path=partial_result_helper,
                )
            self.assertEqual(
                raised.exception.failure_code,
                "worker_nonzero_exit",
            )
            self.assertNotIn("result_sha256", raised.exception.receipt)

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_parent_bounded_recheck_rejects_staged_artifact_tampering(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            body = self._blank_pdf(1)
            input_path = root / "input.pdf"
            input_path.write_bytes(body)
            config = dict(settings.raw["pdf_parser"])
            config["wall_timeout_seconds"] = 5
            helpers = {
                "sparse_replacement": (
                    "from pathlib import Path\n"
                    "artifact=Path(__file__)\n"
                    "with artifact.open('wb') as handle:\n"
                    "    handle.seek(1024 * 1024 * 1024)\n"
                    "    handle.write(b'x')\n"
                ),
                "deleted_worker": (
                    "from pathlib import Path\n"
                    "Path(__file__).unlink()\n"
                ),
                "deleted_sandbox": (
                    "from pathlib import Path\n"
                    "Path(__file__).with_name('pdf_sandbox.py').unlink()\n"
                ),
            }
            for name, source in helpers.items():
                with self.subTest(name=name):
                    helper = root / f"{name}.py"
                    helper.write_text(source, encoding="utf-8", newline="\n")
                    started = time.monotonic()
                    with self.assertRaises(PdfParseError) as raised:
                        parse_pdf_with_worker(
                            input_path,
                            expected_sha256=hashlib.sha256(body).hexdigest(),
                            expected_byte_count=len(body),
                            config=config,
                            _worker_path=helper,
                        )
                    self.assertEqual(
                        raised.exception.failure_code,
                        "staged_artifact_modified",
                    )
                    self.assertLess(time.monotonic() - started, 8)
                    self.assertNotIn("result_sha256", raised.exception.receipt)

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_low_integrity_strips_credentials_blocks_workspace_write_and_children(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            body = self._blank_pdf(1)
            input_path = root / "input.pdf"
            input_path.write_bytes(body)
            target = root / "workspace-sentinel.txt"
            target.write_text("unchanged", encoding="utf-8")
            child_control = root / "child-control.txt"
            control = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path;"
                        f"Path({str(child_control)!r}).write_text('control')"
                    ),
                ],
                check=False,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertEqual(control.returncode, 0)
            self.assertEqual(
                child_control.read_text(encoding="utf-8"),
                "control",
            )
            child_control.unlink()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(2)
                host, port = listener.getsockname()
                with socket.create_connection((host, port), timeout=1):
                    control, _ = listener.accept()
                    control.close()
                helper = root / "probe_worker.py"
                self._write_probe_worker(
                    helper,
                    workspace_target=target,
                    network_target=(host, port),
                )
                credential_environment = {
                    "OPENAI_API_KEY": "must-not-leak",
                    "GITHUB_TOKEN": "must-not-leak",
                    "OPENALEX_API_KEY": "must-not-leak",
                    "ANTHROPIC_API_KEY": "must-not-leak",
                }
                with patch.dict(os.environ, credential_environment):
                    extraction = parse_pdf_with_worker(
                        input_path,
                        expected_sha256=hashlib.sha256(body).hexdigest(),
                        expected_byte_count=len(body),
                        config=settings.raw["pdf_parser"],
                        _worker_path=helper,
                    )
                listener.settimeout(0.2)
                with self.assertRaises(socket.timeout):
                    listener.accept()
            self.assertIn("read_blocked=1", extraction.text)
            self.assertIn("write_blocked=1", extraction.text)
            self.assertIn("create_blocked=1", extraction.text)
            self.assertIn("rename_blocked=1", extraction.text)
            self.assertIn("delete_blocked=1", extraction.text)
            self.assertIn("credential_absent=1", extraction.text)
            self.assertIn("network_blocked=1", extraction.text)
            self.assertIn("child_blocked=1", extraction.text)
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")
            self.assertFalse((root / "appcontainer-created.txt").exists())
            self.assertFalse((root / "appcontainer-renamed.txt").exists())

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_pdf_bootstrap_refuses_to_run_outside_appcontainer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_dir = root / "output"
            output_dir.mkdir()
            site_packages = root / "site-packages"
            site_packages.mkdir()
            request_path = root / "request.json"
            request_path.write_text("{}\n", encoding="utf-8")
            gate_path = root / "start.gate"
            gate_path.write_bytes(b"go\n")
            marker = root / "worker-ran.txt"
            worker_path = root / "worker.py"
            worker_path.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('violation')\n",
                encoding="utf-8",
                newline="\n",
            )
            sandbox_path = (
                PROJECT_DIR
                / "r3radar"
                / "pdf_sandbox.py"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-u",
                    "-X",
                    "utf8",
                    str(sandbox_path),
                    "--worker",
                    str(worker_path),
                    "--request",
                    str(request_path),
                    "--output-dir",
                    str(output_dir),
                    "--gate",
                    str(gate_path),
                    "--site-packages",
                    str(site_packages),
                ],
                check=False,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertEqual(completed.returncode, 94)
            self.assertFalse(marker.exists())
            diagnostic = json.loads(
                (output_dir / "bootstrap-error.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                diagnostic["schema"],
                "r3/pdf-bootstrap-error/v1",
            )

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_job_object_enforces_cpu_and_memory_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            body = self._blank_pdf(1)
            input_path = root / "input.pdf"
            input_path.write_bytes(body)
            cases = {
                "cpu": (
                    "while True:\n    pass\n",
                    {
                        "cpu_time_seconds": 1,
                        "memory_limit_bytes": 268435456,
                        "wall_timeout_seconds": 8,
                    },
                ),
                "memory": (
                    "chunks=[]\nwhile True:\n    chunks.append(bytearray(16777216))\n",
                    {
                        "cpu_time_seconds": 8,
                        "memory_limit_bytes": 100663296,
                        "wall_timeout_seconds": 8,
                    },
                ),
            }
            for name, (source, overrides) in cases.items():
                with self.subTest(name=name):
                    helper = root / f"{name}_limit_worker.py"
                    helper.write_text(source, encoding="utf-8")
                    config = dict(settings.raw["pdf_parser"])
                    config.update(overrides)
                    started = time.monotonic()
                    with self.assertRaises(PdfParseError) as raised:
                        parse_pdf_with_worker(
                            input_path,
                            expected_sha256=hashlib.sha256(body).hexdigest(),
                            expected_byte_count=len(body),
                            config=config,
                            _worker_path=helper,
                        )
                    self.assertIn(
                        raised.exception.failure_code,
                        {
                            "cpu_time_limit",
                            "worker_nonzero_exit",
                            "result_missing",
                        },
                    )
                    if name == "cpu":
                        self.assertEqual(
                            raised.exception.failure_code,
                            "cpu_time_limit",
                        )
                        self.assertEqual(
                            raised.exception.receipt["termination"],
                            "cpu_time_limit",
                        )
                        accounting = raised.exception.receipt["job_accounting"]
                        observed_cpu_100ns = (
                            accounting["total_user_time_100ns"]
                            + accounting["total_kernel_time_100ns"]
                        )
                        self.assertGreaterEqual(observed_cpu_100ns, 10_000_000)
                    if name == "memory":
                        self.assertEqual(
                            raised.exception.failure_code,
                            "worker_nonzero_exit",
                        )
                        self.assertEqual(
                            raised.exception.receipt["bootstrap_error_type"],
                            "MemoryError",
                        )
                        accounting = raised.exception.receipt["job_accounting"]
                        self.assertGreaterEqual(
                            accounting["peak_job_memory_bytes"],
                            64 * 1024 * 1024,
                        )
                        self.assertLessEqual(
                            accounting["peak_job_memory_bytes"],
                            overrides["memory_limit_bytes"],
                        )
                    self.assertLess(time.monotonic() - started, 8)

    def test_parent_result_schema_validation_rejects_identity_and_total_mutations(
        self,
    ) -> None:
        request_id = "request-1"
        expected_sha256 = "a" * 64
        expected_byte_count = 1234
        page_text = "schema validation sentinel"
        rendered = f"=== PAGE 1 ===\n{page_text}\n"
        options = {"strict": False}
        options_sha256 = hashlib.sha256(
            json.dumps(
                options,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        baseline = {
            "schema": RESULT_SCHEMA,
            "request_id": request_id,
            "outcome": "parsed",
            "parser": {
                "id": "pypdf",
                "version": REQUIRED_PYPDF_VERSION,
                "policy_version": PARSER_POLICY_VERSION,
                "effective_options": options,
                "options_sha256": options_sha256,
            },
            "input": {
                "sha256": expected_sha256,
                "byte_count": expected_byte_count,
            },
            "isolation": {
                "integrity_level": "appcontainer_low",
                "credential_environment_keys": [],
            },
            "document": {
                "page_count": 1,
                "rendered_character_count": len(rendered),
                "non_whitespace_total": len(re.sub(r"\s+", "", page_text)),
                "pages": [
                    {
                        "page": 1,
                        "text": page_text,
                        "non_whitespace": len(
                            re.sub(r"\s+", "", page_text)
                        ),
                        "rendered_character_count": len(rendered),
                        "rendered_sha256": hashlib.sha256(
                            rendered.encode("utf-8")
                        ).hexdigest(),
                        "outcome": "ok",
                        "error": None,
                    }
                ],
            },
            "failure": None,
        }
        limits = {
            "max_pages": 10,
            "max_output_characters": 10000,
        }
        extraction = _validate_result(
            baseline,
            request_id=request_id,
            expected_sha256=expected_sha256,
            expected_byte_count=expected_byte_count,
            limits=limits,
            installed_version=REQUIRED_PYPDF_VERSION,
        )
        self.assertEqual(extraction.text, rendered)

        def change(path: tuple[object, ...], value: object):
            def apply(target: dict[str, object]) -> None:
                current: object = target
                for key in path[:-1]:
                    current = current[key]  # type: ignore[index]
                current[path[-1]] = value  # type: ignore[index]

            return apply

        mutations = {
            "extra_root_key": lambda value: value.__setitem__(
                "unexpected",
                True,
            ),
            "result_schema": change(("schema",), "r3/untrusted/v1"),
            "request_id": change(("request_id",), "request-2"),
            "parser_version": change(
                ("parser", "version"),
                "0.0.0",
            ),
            "parser_options_hash": change(
                ("parser", "options_sha256"),
                "0" * 64,
            ),
            "input_hash": change(("input", "sha256"), "0" * 64),
            "isolation": change(
                ("isolation", "integrity_level"),
                "medium",
            ),
            "credential_environment": change(
                ("isolation", "credential_environment_keys"),
                ["OPENAI_API_KEY"],
            ),
            "page_order": change(
                ("document", "pages", 0, "page"),
                2,
            ),
            "page_hash": change(
                ("document", "pages", 0, "rendered_sha256"),
                "0" * 64,
            ),
            "page_non_whitespace": change(
                ("document", "pages", 0, "non_whitespace"),
                999,
            ),
            "document_total": change(
                ("document", "rendered_character_count"),
                len(rendered) + 1,
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                candidate = json.loads(json.dumps(baseline))
                mutate(candidate)
                with self.assertRaises(ValueError):
                    _validate_result(
                        candidate,
                        request_id=request_id,
                        expected_sha256=expected_sha256,
                        expected_byte_count=expected_byte_count,
                        limits=limits,
                        installed_version=REQUIRED_PYPDF_VERSION,
                    )

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_appcontainer_mutex_serializes_tasks_and_reports_busy(self) -> None:
        first_entered = threading.Event()
        release_first = threading.Event()
        second_started = threading.Event()
        second_entered = threading.Event()
        sequence: list[str] = []
        active = 0
        maximum_active = 0
        state_lock = threading.Lock()
        errors: list[BaseException] = []

        def enter(label: str, hold: threading.Event | None = None) -> None:
            nonlocal active, maximum_active
            try:
                if label == "second":
                    second_started.set()
                with _WindowsPdfMutex(timeout_seconds=5):
                    with state_lock:
                        active += 1
                        maximum_active = max(maximum_active, active)
                        sequence.append(f"{label}:enter")
                    if label == "first":
                        first_entered.set()
                    else:
                        second_entered.set()
                    if hold is not None:
                        hold.wait(3)
                    with state_lock:
                        sequence.append(f"{label}:exit")
                        active -= 1
            except BaseException as exc:
                errors.append(exc)

        first = threading.Thread(
            target=enter,
            args=("first", release_first),
        )
        second = threading.Thread(target=enter, args=("second",))
        first.start()
        self.assertTrue(first_entered.wait(2))
        second.start()
        self.assertTrue(second_started.wait(2))
        time.sleep(0.2)
        self.assertFalse(second_entered.is_set())
        release_first.set()
        first.join(5)
        second.join(5)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(maximum_active, 1)
        self.assertEqual(
            sequence,
            [
                "first:enter",
                "first:exit",
                "second:enter",
                "second:exit",
            ],
        )

        busy_failures: list[str] = []
        with _WindowsPdfMutex(timeout_seconds=2):
            def contend() -> None:
                try:
                    with _WindowsPdfMutex(timeout_seconds=1):
                        busy_failures.append("unexpected_acquire")
                except PdfParseError as exc:
                    busy_failures.append(exc.failure_code)

            contender = threading.Thread(target=contend)
            contender.start()
            contender.join(3)
            self.assertFalse(contender.is_alive())
        self.assertEqual(busy_failures, ["appcontainer_busy"])

    @unittest.skipUnless(os.name == "nt", "P0 PDF sandbox is Windows-specific")
    def test_parser_failure_does_not_block_the_next_pdf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            broken = self._text_pdf()[:100]
            first = self._process_pdf(settings, broken, work_id=1)
            second = self._process_pdf(settings, self._text_pdf(), work_id=2)
            self.assertEqual(first.status, "incomplete")
            self.assertEqual(
                first.coverage["security_status"],
                "incomplete_security",
            )
            self.assertEqual(second.status, "ready")
            self.assertTrue(second.coverage["complete"])


class FakeStructuredRunner:
    def __init__(self, candidate_id: int, content_sha: str):
        self.candidate_id = candidate_id
        self.content_sha = content_sha
        self.calls: list[str] = []
        self.prompts: list[str] = []

    def run_structured(
        self,
        *,
        prompt: str,
        schema_path: Path,
        purpose: str,
        web_search: bool = False,
        timeout_seconds: int | None = None,
    ) -> CodexResult:
        self.calls.append(purpose)
        self.prompts.append(prompt)
        receipt = {
            "provider": "fake",
            "purpose": purpose,
            "model": "fake-model",
            "invocation_id": purpose,
        }
        if schema_path.name == "chunk_analysis.schema.json":
            import re

            indices = [int(value) for value in re.findall(r'chunk_index="(\d+)"', prompt)]
            return CodexResult(
                payload={
                    "candidate_id": self.candidate_id,
                    "content_sha256": self.content_sha,
                    "chunks": [
                        {
                            "chunk_index": index,
                            "coverage_confirmed": True,
                            "summary_zh": f"块 {index}",
                            "methods": [],
                            "evaluation": [],
                            "limitations": [],
                            "r3_connections": ["缓存复用信号"],
                            "evidence": [
                                {
                                    "anchor": "=== PAGE 1 ===",
                                    "claim_zh": "存在可追溯证据",
                                    "excerpt": "workflow cache evidence",
                                }
                            ],
                            "uncertainties": [],
                        }
                        for index in indices
                    ],
                },
                receipt=receipt,
            )
        input_payload = json.loads(prompt.split("INPUT:\n", 1)[1])
        if schema_path.name == "synthesis_reduce.schema.json":
            anchors: set[str] = set()

            def collect(value: object) -> None:
                if isinstance(value, dict):
                    for evidence in value.get("evidence") or []:
                        if isinstance(evidence, dict) and evidence.get("anchor"):
                            anchors.add(str(evidence["anchor"]))
                    for anchor in value.get("evidence_anchors") or []:
                        if anchor:
                            anchors.add(str(anchor))
                    for nested in value.values():
                        collect(nested)
                elif isinstance(value, list):
                    for nested in value:
                        collect(nested)

            collect(input_payload["findings"])
            return CodexResult(
                payload={
                    "candidate_id": self.candidate_id,
                    "level": input_payload["level"],
                    "node_index": input_payload["node_index"],
                    "covered_chunk_indices": input_payload[
                        "covered_chunk_indices"
                    ],
                    "summary_zh": "分层归并",
                    "methods": [],
                    "evaluation": [],
                    "limitations": [],
                    "r3_connections": ["缓存复用信号"],
                    "actionable_ideas": [],
                    "evidence_anchors": sorted(anchors),
                    "uncertainties": [],
                },
                receipt=receipt,
            )
        chunk_total = int(input_payload["chunk_total"])
        expected_indices = [int(value) for value in input_payload["expected_chunk_indices"]]
        return CodexResult(
            payload={
                "candidate_id": self.candidate_id,
                "deep_read_status": "complete",
                "coverage": {
                    "chunk_total": chunk_total,
                    "chunk_indices": expected_indices,
                    "complete": True,
                    "gaps": [],
                },
                "summary_zh": "完整综合",
                "problem": "缓存价值预测",
                "method": "工作流信号",
                "evaluation": ["离线评估"],
                "limitations": ["尚未在线验证"],
                "r3_relationship": ["直接相关"],
                "actionable_ideas": ["构造最小实验"],
                "overlap_risks": [],
                "reproducibility": "有静态证据",
                "score_scale": "0_to_100",
                "scores": {
                    "novelty": 80,
                    "r3_relevance": 90,
                    "evidence_strength": 75,
                    "reuse_signal_value": 90,
                    "implementability": 85,
                    "overall": 0,
                },
                "tier": "background",
                "evidence_anchors": ["=== PAGE 1 ==="],
                "uncertainties": [],
            },
            receipt=receipt,
        )


class DeepReadTests(unittest.TestCase):
    def test_synthesis_reduce_schema_patch_preserves_policy_identity(self) -> None:
        record = analysis_schema_policy_record(
            PROJECT_DIR,
            "synthesis_reduce.schema.json",
        )
        self.assertEqual(
            record["actual_sha256"],
            "abfd5db717fd3659bf4e28501e4d2434d426301a26e5a33519debe6ba3628d7c",
        )
        self.assertEqual(
            record["policy_sha256"],
            "42a142d051c9fad8834e9cf3ef57fa08009969c0f780f98372e094eb0c385162",
        )
        self.assertEqual(
            record["removed_paths"],
            (
                "$.properties.covered_chunk_indices.uniqueItems",
                "$.properties.evidence_anchors.uniqueItems",
            ),
        )
        settings = load_settings(DEFAULT_CONFIG)
        self.assertEqual(
            settings.analysis_policy_hash,
            "31885d2982a0e94c06096d4812e28d0a44e18b1da88bc4b2a0b2ff0cc47894cd",
        )

    def test_schema_compatibility_mapping_is_exact_sha_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project_dir = Path(temporary)
            schema_dir = project_dir / "schemas"
            schema_dir.mkdir()
            source = (
                PROJECT_DIR
                / "schemas"
                / "synthesis_reduce.schema.json"
            ).read_bytes()
            changed = source + b"\n"
            (schema_dir / "synthesis_reduce.schema.json").write_bytes(changed)
            record = analysis_schema_policy_record(
                project_dir,
                "synthesis_reduce.schema.json",
            )
            changed_sha = hashlib.sha256(changed).hexdigest()
            self.assertEqual(record["actual_sha256"], changed_sha)
            self.assertEqual(record["policy_sha256"], changed_sha)
            self.assertIsNone(record["compatibility_reason"])

    def test_synthesis_reduce_anchor_gate_rejects_duplicates(self) -> None:
        allowed = {"=== PAGE 1 ===", "=== PAGE 2 ==="}
        self.assertEqual(
            CodexDeepReader._verified_unique_anchor_set(
                ["=== PAGE 1 ===", "=== PAGE 2 ==="],
                allowed,
            ),
            allowed,
        )
        self.assertIsNone(
            CodexDeepReader._verified_unique_anchor_set(
                ["=== PAGE 1 ===", "=== PAGE 1 ==="],
                allowed,
            )
        )
        self.assertIsNone(
            CodexDeepReader._verified_unique_anchor_set(
                ["=== PAGE 1 ===", ""],
                allowed,
            )
        )
        self.assertIsNone(
            CodexDeepReader._verified_unique_anchor_set(
                ["=== PAGE 1 ===", 2],
                allowed,
            )
        )
        self.assertIsNone(
            CodexDeepReader._verified_unique_anchor_set(
                ["=== PAGE 1 ===", "=== PAGE 3 ==="],
                allowed,
            )
        )

    def test_synthesis_reduce_prompt_forbids_identity_increment(self) -> None:
        prompt = CodexDeepReader._reduce_synthesis_prompt(
            {
                "candidate_id": 13,
                "level": 0,
                "node_index": 0,
                "covered_chunk_indices": [0, 1],
            }
        )
        self.assertIn(
            "candidate_id, level, and node_index must each copy the exact",
            prompt,
        )
        self.assertIn("do not increment", prompt)
        self.assertIn('"level": 0', prompt)

    def test_synthesis_reduce_schema_uses_provider_supported_subset(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "synthesis_reduce.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        def collect_unique_items(value: object, path: str = "$") -> list[str]:
            found: list[str] = []
            if isinstance(value, dict):
                for key, nested in value.items():
                    nested_path = f"{path}.{key}"
                    if key == "uniqueItems":
                        found.append(nested_path)
                    found.extend(collect_unique_items(nested, nested_path))
            elif isinstance(value, list):
                for index, nested in enumerate(value):
                    found.extend(
                        collect_unique_items(nested, f"{path}[{index}]")
                    )
            return found

        self.assertEqual(collect_unique_items(schema), [])

    def test_evidence_excerpt_preserves_literal_substring(self) -> None:
        excerpt = "Exact  source evidence."
        result = canonicalize_evidence_excerpt(
            excerpt,
            f"prefix\n{excerpt}\nsuffix",
        )
        self.assertEqual(result.excerpt, excerpt)
        self.assertEqual(result.model_excerpt, excerpt)
        self.assertEqual(result.match_method, "literal_substring")
        self.assertEqual(result.provenance, "provider_literal_substring")

    def test_evidence_excerpt_uniquely_maps_normalized_text_to_literal_source(
        self,
    ) -> None:
        result = canonicalize_evidence_excerpt(
            "the agent cache works.",
            "prefix\nThe Ａgent  Cache\nWorks.\nsuffix",
        )
        self.assertEqual(result.excerpt, "The Ａgent  Cache\nWorks.")
        self.assertEqual(result.model_excerpt, "the agent cache works.")
        self.assertEqual(
            result.match_method,
            "nfkc_casefold_whitespace_unique",
        )

    def test_evidence_excerpt_rejects_ambiguous_or_absent_normalized_text(
        self,
    ) -> None:
        for excerpt, reason in (
            ("AGENT CACHE", "excerpt_ambiguous"),
            ("missing evidence", "excerpt_absent"),
        ):
            with self.subTest(reason=reason):
                with self.assertRaises(EvidenceExcerptError) as raised:
                    canonicalize_evidence_excerpt(
                        excerpt,
                        "Agent cache / agent cache",
                    )
                self.assertEqual(raised.exception.reason, reason)

    def test_evidence_word_limit_is_applied_to_canonical_literal(self) -> None:
        source_excerpt = " ".join(f"Word{index}" for index in range(26))
        with self.assertRaises(EvidenceExcerptError) as raised:
            canonicalize_evidence_excerpt(
                source_excerpt.casefold(),
                source_excerpt,
            )
        self.assertEqual(raised.exception.reason, "excerpt_too_long")

    def test_evidence_character_limit_rejects_unspaced_long_excerpt(self) -> None:
        source_excerpt = "证" * 321
        with self.assertRaises(EvidenceExcerptError) as raised:
            canonicalize_evidence_excerpt(source_excerpt, source_excerpt)
        self.assertEqual(raised.exception.reason, "excerpt_too_long")

    def test_evidence_anchor_region_prevents_cross_page_binding(self) -> None:
        chunk = (
            "page one carryover evidence\n"
            "=== PAGE 2 ===\n"
            "page two exact evidence"
        )
        allowed = [
            "=== PAGE 1 ===",
            "=== PAGE 2 ===",
            "characters:100-172",
        ]
        page_one = evidence_anchor_region(chunk, "=== PAGE 1 ===", allowed)
        page_two = evidence_anchor_region(chunk, "=== PAGE 2 ===", allowed)
        self.assertIn("page one carryover evidence", page_one)
        self.assertNotIn("page two exact evidence", page_one)
        self.assertIn("page two exact evidence", page_two)
        with self.assertRaises(EvidenceExcerptError) as raised:
            canonicalize_evidence_excerpt("page two exact evidence", page_one)
        self.assertEqual(raised.exception.reason, "excerpt_absent")

    def test_canonical_evidence_strips_anchor_before_persisting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            reader = CodexDeepReader(
                settings,
                Mock(),
                object(),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run-fixture",
                "lease-fixture",
            )
            projected, rejected = reader._canonical_evidence(
                {
                    "span": {
                        "character_start": 0,
                        "character_end": 42,
                        "anchors": ["=== PAGE 1 ==="],
                    },
                    "text": "=== PAGE 1 ===\nExact source evidence.",
                },
                [
                    {
                        "anchor": "  === PAGE 1 ===  ",
                        "claim_zh": "可核验",
                        "excerpt": "Exact source evidence.",
                    }
                ],
                reject_on_any_failure=True,
            )
            self.assertEqual(rejected, {})
            self.assertEqual(projected[0]["anchor"], "=== PAGE 1 ===")

    def test_resume_reprojects_legacy_completed_chunk_before_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            store = Mock()
            reader = CodexDeepReader(
                settings,
                store,
                object(),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run-fixture",
                "lease-fixture",
            )
            stored_output = {
                "chunk_index": 0,
                "coverage_confirmed": True,
                "summary_zh": "摘要",
                "evidence": [
                    {
                        "anchor": "=== PAGE 1 ===",
                        "claim_zh": "可核验",
                        "excerpt": "agent cache works.",
                    }
                ],
            }
            reader._reproject_completed_chunks(
                {"id": 3, "work_id": 7},
                [
                    {
                        "index": 0,
                        "span": {
                            "character_start": 0,
                            "character_end": 42,
                            "anchors": ["=== PAGE 1 ==="],
                        },
                        "text": "=== PAGE 1 ===\nAgent  Cache\nWorks.",
                    }
                ],
                {
                    0: {
                        "status": "completed",
                        "output_json": json.dumps(stored_output),
                        "provider_receipt_json": json.dumps(
                            {"invocation_id": "legacy"}
                        ),
                    }
                },
            )
            saved = store.save_chunk_result.call_args.kwargs
            evidence = saved["output"]["evidence"][0]
            self.assertEqual(evidence["excerpt"], "Agent  Cache\nWorks.")
            self.assertEqual(evidence["model_excerpt"], "agent cache works.")
            self.assertEqual(
                evidence["excerpt_match_method"],
                "nfkc_casefold_whitespace_unique",
            )
            self.assertEqual(saved["receipt"]["invocation_id"], "legacy")
            store.reset_analysis_chunk.assert_not_called()
            store.invalidate_synthesis_nodes.assert_called_once_with(
                task_id=3,
                lease_token="lease-fixture",
            )

    def test_resume_resets_legacy_chunk_when_projection_is_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            store = Mock()
            reader = CodexDeepReader(
                settings,
                store,
                object(),
                JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                "run-fixture",
                "lease-fixture",
            )
            reader._reproject_completed_chunks(
                {"id": 3, "work_id": 7},
                [
                    {
                        "index": 0,
                        "span": {
                            "character_start": 0,
                            "character_end": 42,
                            "anchors": ["=== PAGE 1 ==="],
                        },
                        "text": "Agent cache / agent cache",
                    }
                ],
                {
                    0: {
                        "status": "completed",
                        "output_json": json.dumps(
                            {
                                "evidence": [
                                    {
                                        "anchor": "=== PAGE 1 ===",
                                        "excerpt": "AGENT CACHE",
                                    }
                                ]
                            }
                        ),
                        "provider_receipt_json": json.dumps(
                            {"invocation_id": "legacy"}
                        ),
                    }
                },
            )
            store.save_chunk_result.assert_not_called()
            store.reset_analysis_chunk.assert_called_once()
            self.assertIn(
                "excerpt_ambiguous",
                store.reset_analysis_chunk.call_args.kwargs["error"],
            )
            store.invalidate_synthesis_nodes.assert_called_once()

    def test_chunk_validation_drops_bad_extra_evidence_but_keeps_strict_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            store = Mock()
            audit = JsonlAuditLog(settings.outputs_dir / "audit.jsonl")
            reader = CodexDeepReader(
                settings,
                store,
                object(),
                audit,
                "run-fixture",
                "lease-fixture",
            )
            batch = [
                {
                    "index": 0,
                    "span": {
                        "character_start": 0,
                        "character_end": 42,
                        "anchors": ["=== PAGE 1 ==="],
                    },
                    "text": "=== PAGE 1 ===\nExact source evidence.",
                }
            ]
            result = CodexResult(
                payload={
                    "candidate_id": 7,
                    "content_sha256": "content-sha",
                    "chunks": [
                        {
                            "chunk_index": 0,
                            "coverage_confirmed": True,
                            "summary_zh": "摘要",
                            "evidence": [
                                {
                                    "anchor": "=== PAGE 1 ===",
                                    "claim_zh": "可核验",
                                    "excerpt": "Exact source evidence.",
                                },
                                {
                                    "anchor": "=== PAGE 1 ===",
                                    "claim_zh": "不可核验",
                                    "excerpt": "Invented evidence.",
                                },
                            ],
                        }
                    ],
                },
                receipt={"invocation_id": "fixture"},
            )

            reader._validate_and_save_batch(
                {"id": 3, "work_id": 7},
                "content-sha",
                batch,
                result,
            )

            saved = store.save_chunk_result.call_args.kwargs["output"]
            self.assertEqual(len(saved["evidence"]), 1)
            self.assertEqual(saved["evidence"][0]["claim_zh"], "可核验")
            self.assertEqual(
                saved["evidence"][0]["excerpt_match_method"],
                "literal_substring",
            )
            self.assertEqual(
                saved["evidence"][0]["model_excerpt"],
                "Exact source evidence.",
            )
            audit_text = (settings.outputs_dir / "audit.jsonl").read_text(
                encoding="utf-8"
            )
            self.assertIn('"event_type":"chunk_evidence_rejected"', audit_text)
            self.assertIn('"excerpt_absent":1', audit_text)

    def test_chunk_prompt_lists_exact_anchor_and_excerpt_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "prompt-fixture",
                )
                reader = CodexDeepReader(
                    settings,
                    store,
                    object(),
                    JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                    run_id,
                    lease_token,
                )
                prompt = reader._chunk_prompt(
                    {
                        "work_id": 1,
                        "title": "Fixture",
                        "kind": "paper",
                        "year": 2026,
                    },
                    "content-sha",
                    [
                        {
                            "index": 0,
                            "span": {
                                "character_start": 0,
                                "character_end": 42,
                                "anchors": ["=== PAGE 1 ==="],
                            },
                            "text": "=== PAGE 1 ===\nExact source evidence.",
                        }
                    ],
                )
                self.assertIn(
                    'ALLOWED_EVIDENCE_ANCHORS ["=== PAGE 1 ===","characters:0-42"]',
                    prompt,
                )
                self.assertIn("copied byte-for-byte", prompt)
                self.assertIn("Do not translate, normalize, paraphrase", prompt)
                self.assertIn("at most 320 Unicode", prompt)

    def test_selected_repository_prompt_discloses_scope_and_compacts_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["output_detail"] = "concise_evidence"
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "selected-corpus-prompt",
                )
                reader = CodexDeepReader(
                    settings,
                    store,
                    object(),
                    JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                    run_id,
                    lease_token,
                )
                prompt = reader._chunk_prompt(
                    {
                        "work_id": 1,
                        "title": "Fixture",
                        "kind": "repository",
                        "year": 2026,
                        "coverage_json": json.dumps(
                            {
                                "coverage_scope": (
                                    "selected_repository_corpus"
                                ),
                                "selection_policy_id": (
                                    "core_plus_sampled_aux_v1"
                                ),
                            }
                        ),
                    },
                    "content-sha",
                    [
                        {
                            "index": 0,
                            "span": {
                                "character_start": 0,
                                "character_end": 20,
                                "anchors": ["=== FILE: src/a.py ==="],
                            },
                            "text": (
                                "=== FILE: src/a.py ===\n"
                                "workflow cache evidence"
                            ),
                        }
                    ],
                )
                self.assertIn("complete policy-selected repository corpus", prompt)
                self.assertIn("not every file in the archive", prompt)
                self.assertIn("one or two sentences", prompt)
                self.assertLess(
                    prompt.index("OUTPUT-DETAIL RULE"),
                    prompt.index("HEADER:"),
                )
                reduce_prompt = reader._reduce_synthesis_prompt(
                    {
                        "candidate_id": 1,
                        "source_coverage_scope": (
                            "selected_repository_corpus"
                        ),
                        "selection_policy_id": (
                            "core_plus_sampled_aux_v1"
                        ),
                        "output_detail": "concise_evidence",
                        "findings": [],
                    }
                )
                self.assertIn(
                    "not every archive file",
                    reduce_prompt,
                )
                self.assertLess(
                    reduce_prompt.index("OUTPUT-DETAIL RULE"),
                    reduce_prompt.index("INPUT:"),
                )
                self.assertLess(
                    reduce_prompt.index("SOURCE-SCOPE RULE"),
                    reduce_prompt.index("INPUT:"),
                )
                synthesis_prompt = reader._synthesis_prompt(
                    {
                        "work_id": 1,
                        "title": "Fixture",
                        "kind": "repository",
                        "year": 2026,
                        "coverage_json": json.dumps(
                            {
                                "coverage_scope": (
                                    "selected_repository_corpus"
                                ),
                                "selection_policy_id": (
                                    "core_plus_sampled_aux_v1"
                                ),
                            }
                        ),
                    },
                    "content-sha",
                    [
                        {
                            "covered_chunk_indices": [0],
                            "finding": {
                                "evidence_anchors": [
                                    "=== FILE: src/a.py ==="
                                ]
                            },
                        }
                    ],
                    expected_indices=[0],
                    finding_kind="chunk_findings",
                )
                self.assertIn(
                    "never claim whole-repository file coverage",
                    synthesis_prompt,
                )
                self.assertLess(
                    synthesis_prompt.index("OUTPUT-DETAIL RULE"),
                    synthesis_prompt.index("INPUT:"),
                )
                self.assertLess(
                    synthesis_prompt.index("SOURCE-SCOPE RULE"),
                    synthesis_prompt.index("INPUT:"),
                )

    def test_budget_preflight_estimate_does_not_trigger_hard_pause(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["batch_chunk_count"] = 6
            settings.raw["analysis"]["synthesis_group_max_items"] = 24
            settings.raw["analysis"]["budget_planning"] = {
                "retry_reserve_invocations": 12
            }
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_task"
            ] = 110
            runner = Mock()
            store = Mock()
            store.model_usage.return_value = {
                "invocation_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            reader = CodexDeepReader(
                settings,
                store,
                runner,
                JsonlAuditLog(settings.outputs_dir / "budget-preflight.jsonl"),
                "run",
                "lease",
            )
            reader._preflight_invocation_budget(14, 534)
            runner.run_structured.assert_not_called()
            record = json.loads(
                (
                    settings.outputs_dir / "budget-preflight.jsonl"
                ).read_text(encoding="utf-8").strip()
            )
            details = record["details"]
            self.assertEqual(details["known_required_calls"], 90)
            self.assertEqual(details["task_invocations_known_projected"], 90)
            self.assertEqual(
                details["task_invocations_estimated_projected"],
                125,
            )
            self.assertFalse(details["completion_guaranteed"])
            self.assertTrue(details["hard_limit_enforced_before_every_call"])

    def test_budget_preflight_hard_blocks_known_calls_before_model_use(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["batch_chunk_count"] = 6
            settings.raw["analysis"]["synthesis_group_max_items"] = 24
            settings.raw["analysis"]["budget_planning"] = {
                "retry_reserve_invocations": 0
            }
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_task"
            ] = 100
            settings.raw["analysis"]["budgets"][
                "max_invocations_per_run"
            ] = 200
            store = Mock()

            def usage(**kwargs: object) -> dict[str, int]:
                return {
                    "invocation_count": (
                        100 if kwargs.get("task_id") == 14 else 10
                    ),
                    "input_tokens": 0,
                    "output_tokens": 0,
                }

            store.model_usage.side_effect = usage
            reader = CodexDeepReader(
                settings,
                store,
                Mock(),
                JsonlAuditLog(settings.outputs_dir / "budget-resume.jsonl"),
                "run",
                "lease",
            )
            with self.assertRaises(AnalysisBudgetPaused) as raised:
                reader._preflight_invocation_budget(
                    14,
                    534,
                    pending_chunk_total=0,
                    reusable_synthesis_nodes=20,
                )
            self.assertEqual(
                raised.exception.metric,
                "known_projected_task_model_invocations",
            )
            self.assertEqual(raised.exception.actual, 101)
            self.assertEqual(raised.exception.limit, 100)
            self.assertEqual(
                raised.exception.boundary_reason,
                "known_model_invocation_requirement_exceeds_limit",
            )

    def test_two_batch_workers_overlap_but_commit_in_batch_order(self) -> None:
        class ConcurrentRunner:
            def __init__(self) -> None:
                self.barrier = threading.Barrier(2)
                self.lock = threading.Lock()
                self.active = 0
                self.max_active = 0

            def run_structured(self, **kwargs: object) -> CodexResult:
                purpose = str(kwargs["purpose"])
                with self.lock:
                    self.active += 1
                    self.max_active = max(self.max_active, self.active)
                self.barrier.wait(timeout=2)
                if purpose.endswith("chunks_0_0"):
                    time.sleep(0.03)
                with self.lock:
                    self.active -= 1
                return CodexResult(
                    payload={},
                    receipt={
                        "provider": "fake",
                        "purpose": purpose,
                        "invocation_id": purpose,
                        "usage": {},
                    },
                )

        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["batch_chunk_count"] = 1
            settings.raw["analysis"]["max_parallel_batches"] = 2
            store = Mock()
            store.model_usage.return_value = {
                "invocation_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            runner = ConcurrentRunner()
            reader = CodexDeepReader(
                settings,
                store,
                runner,
                JsonlAuditLog(settings.outputs_dir / "parallel.jsonl"),
                "run",
                "lease",
            )
            saved: list[int] = []
            reader._validate_and_save_batch = (
                lambda task, content_sha, batch, result: saved.append(
                    int(batch[0]["index"])
                )
            )
            pending = [
                {
                    "index": index,
                    "span": {
                        "character_start": index,
                        "character_end": index + 1,
                        "anchors": [],
                    },
                    "text": str(index),
                }
                for index in range(2)
            ]
            reader._process_pending_chunk_batches(
                {
                    "id": 14,
                    "work_id": 9,
                    "title": "Concurrent fixture",
                    "kind": "repository",
                },
                "sha",
                pending,
            )
            self.assertEqual(runner.max_active, 2)
            self.assertEqual(saved, [0, 1])

    def test_two_synthesis_workers_overlap_but_persist_in_node_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["max_parallel_batches"] = 2
            settings.raw["analysis"]["synthesis_group_max_items"] = 2
            settings.raw["analysis"]["synthesis_input_character_budget"] = 10000
            store = Mock()
            store.model_usage.return_value = {
                "invocation_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            store.load_synthesis_node.return_value = None
            reader = CodexDeepReader(
                settings,
                store,
                object(),
                JsonlAuditLog(settings.outputs_dir / "parallel-synthesis.jsonl"),
                "run",
                "lease",
            )
            reader._prompt_window_fits_budget = Mock(return_value=True)
            barrier = threading.Barrier(2)
            active_lock = threading.Lock()
            active = 0
            max_active = 0

            def invoke(**kwargs: object) -> CodexResult:
                nonlocal active, max_active
                prompt = str(kwargs["prompt"])
                input_payload = json.loads(prompt.split("INPUT:\n", 1)[1])
                with active_lock:
                    active += 1
                    max_active = max(max_active, active)
                barrier.wait(timeout=2)
                if int(input_payload["node_index"]) == 0:
                    time.sleep(0.03)
                with active_lock:
                    active -= 1
                return CodexResult(
                    payload={
                        "candidate_id": 9,
                        "level": int(input_payload["level"]),
                        "node_index": int(input_payload["node_index"]),
                        "covered_chunk_indices": input_payload[
                            "covered_chunk_indices"
                        ],
                        "summary_zh": "无损汇总",
                        "methods": [],
                        "evaluation": [],
                        "limitations": [],
                        "r3_connections": [],
                        "actionable_ideas": [],
                        "uncertainties": [],
                        "evidence_anchors": input_payload[
                            "allowed_evidence_anchors"
                        ],
                    },
                    receipt={
                        "provider": "fake",
                        "invocation_id": str(input_payload["node_index"]),
                    },
                )

            reader._invoke = invoke
            saved_nodes: list[int] = []
            store.save_synthesis_node.side_effect = (
                lambda **kwargs: saved_nodes.append(int(kwargs["node_index"]))
            )
            chunk_outputs = [
                {
                    "summary_zh": f"{index}-" + ("x" * 3000),
                    "evidence": [
                        {
                            "anchor": f"=== PAGE {index + 1} ===",
                            "claim_zh": "fixture",
                            "excerpt": "fixture",
                        }
                    ],
                }
                for index in range(4)
            ]

            reduced = reader._hierarchical_findings(
                {
                    "id": 14,
                    "work_id": 9,
                    "title": "Parallel synthesis fixture",
                    "kind": "paper",
                },
                "sha",
                chunk_outputs,
            )

            self.assertEqual(max_active, 2)
            self.assertEqual(saved_nodes, [0, 1])
            self.assertEqual(
                [
                    index
                    for item in reduced
                    for index in item["covered_chunk_indices"]
                ],
                [0, 1, 2, 3],
            )

    def test_parallel_batches_fall_back_to_serial_near_token_limit(self) -> None:
        class SlowRunner:
            def __init__(self) -> None:
                self.lock = threading.Lock()
                self.active = 0
                self.max_active = 0
                self.calls = 0

            def run_structured(self, **kwargs: object) -> CodexResult:
                with self.lock:
                    self.active += 1
                    self.calls += 1
                    self.max_active = max(self.max_active, self.active)
                time.sleep(0.02)
                with self.lock:
                    self.active -= 1
                purpose = str(kwargs["purpose"])
                return CodexResult(
                    payload={},
                    receipt={
                        "provider": "fake",
                        "purpose": purpose,
                        "invocation_id": purpose,
                        "usage": {},
                    },
                )

        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["batch_chunk_count"] = 1
            settings.raw["analysis"]["max_parallel_batches"] = 2
            store = Mock()
            store.model_usage.return_value = {
                "invocation_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            runner = SlowRunner()
            reader = CodexDeepReader(
                settings,
                store,
                runner,
                JsonlAuditLog(settings.outputs_dir / "serial-fallback.jsonl"),
                "run",
                "lease",
            )
            pending = [
                {
                    "index": index,
                    "span": {
                        "character_start": index,
                        "character_end": index + 1,
                        "anchors": [],
                    },
                    "text": "x" * 200,
                }
                for index in range(2)
            ]
            task = {
                "id": 14,
                "work_id": 9,
                "title": "Token-bound fixture",
                "kind": "repository",
            }
            one_prompt = reader._chunk_prompt(task, "sha", [pending[0]])
            settings.raw["analysis"]["budgets"][
                "max_input_tokens_per_task"
            ] = reader._estimated_input_tokens(one_prompt) + 100
            saved: list[int] = []
            reader._validate_and_save_batch = (
                lambda task, content_sha, batch, result: saved.append(
                    int(batch[0]["index"])
                )
            )
            reader._process_pending_chunk_batches(
                task,
                "sha",
                pending,
            )
            self.assertEqual(runner.calls, 2)
            self.assertEqual(runner.max_active, 1)
            self.assertEqual(saved, [0, 1])

    def test_failed_provider_call_consumes_conservative_budget_receipt(
        self,
    ) -> None:
        class FailingRunner:
            model = "fixture-model"

            def run_structured(self, **kwargs: object) -> CodexResult:
                raise CodexInvocationError("provider failed")

        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            store = Mock()
            store.model_usage.return_value = {
                "invocation_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            reader = CodexDeepReader(
                settings,
                store,
                FailingRunner(),
                JsonlAuditLog(settings.outputs_dir / "failed-call.jsonl"),
                "run",
                "lease",
            )
            with self.assertRaisesRegex(CodexInvocationError, "provider failed"):
                reader._invoke(
                    prompt="bounded prompt",
                    schema_path=(
                        settings.project_dir
                        / "schemas"
                        / "chunk_analysis.schema.json"
                    ),
                    purpose="failure-fixture",
                    task_id=14,
                    work_id=9,
                )
            receipt = store.record_model_invocation.call_args.kwargs[
                "receipt"
            ]
            self.assertEqual(receipt["attempt_status"], "failed")
            self.assertEqual(
                receipt["usage_accounting"],
                "conservative_failure_reservation",
            )
            self.assertGreater(receipt["usage"]["input_tokens"], 0)
            self.assertGreater(receipt["usage"]["output_tokens"], 0)
            self.assertEqual(reader._inflight_run_invocations, 0)

    def test_post_persistence_lease_error_does_not_double_account(self) -> None:
        class SuccessfulRunner:
            model = "fixture-model"

            def run_structured(self, **kwargs: object) -> CodexResult:
                return CodexResult(
                    payload={"ok": True},
                    receipt={
                        "provider": "codex_cli",
                        "invocation_id": "one-success",
                        "purpose": "lease-fixture",
                        "usage": {
                            "input_tokens": 10,
                            "output_tokens": 5,
                        },
                    },
                )

        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            store = Mock()
            store.model_usage.return_value = {
                "invocation_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            }
            store.refresh_run_lease.side_effect = [
                None,
                RuntimeError("lease refresh failed"),
            ]
            reader = CodexDeepReader(
                settings,
                store,
                SuccessfulRunner(),
                JsonlAuditLog(settings.outputs_dir / "lease-error.jsonl"),
                "run",
                "lease",
            )
            with self.assertRaisesRegex(RuntimeError, "lease refresh failed"):
                reader._invoke(
                    prompt="bounded prompt",
                    schema_path=(
                        settings.project_dir
                        / "schemas"
                        / "chunk_analysis.schema.json"
                    ),
                    purpose="lease-fixture",
                    task_id=14,
                    work_id=9,
                )
            self.assertEqual(store.record_model_invocation.call_count, 1)
            self.assertEqual(reader._inflight_run_invocations, 0)
            self.assertEqual(reader._inflight_run_input_tokens, 0)
            self.assertEqual(reader._inflight_run_output_tokens, 0)

    def test_persisted_run_usage_pauses_before_exceeding_model_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))
            settings.raw["analysis"]["budgets"]["max_invocations_per_run"] = 1
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(
                    settings,
                    "budget-fixture",
                )
                store.record_model_invocation(
                    run_id=run_id,
                    lease_token=lease_token,
                    receipt={
                        "invocation_id": "already-spent",
                        "provider": "codex_cli",
                        "purpose": "fixture",
                        "usage": {},
                    },
                )
                reader = CodexDeepReader(
                    settings,
                    store,
                    FakeStructuredRunner(1, "unused"),
                    JsonlAuditLog(settings.outputs_dir / "budget-audit.jsonl"),
                    run_id,
                    lease_token,
                )
                with self.assertRaisesRegex(
                    AnalysisBudgetPaused,
                    "max_invocations_per_run",
                ) as raised:
                    reader._enforce_model_budget(999)
                self.assertEqual(
                    raised.exception.boundary_reason,
                    "model_usage_limit_reached",
                )
                self.assertEqual(
                    raised.exception.metric,
                    "max_invocations_per_run",
                )
                self.assertEqual(raised.exception.actual, 2)
                self.assertEqual(raised.exception.limit, 1)

    def test_every_chunk_required_before_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            text = "=== PAGE 1 ===\n" + ("workflow cache evidence\n" * 35)
            text_path = settings.literature_dir / "text" / "paper.txt"
            text_path.write_bytes(text.encode("utf-8"))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='openalex'",
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W1",
                    kind="paper",
                    title="Deep Read Fixture",
                    query_id="q01",
                    year=2025,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="raw",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url="https://example.com/paper.pdf",
                    local_path=None,
                    text_path=str(text_path),
                    content_sha256="pdf",
                    text_sha256=sha256_text(text),
                    byte_count=10,
                    text_char_count=len(text),
                    page_count=1,
                    coverage=current_pdf_ready_coverage(page_count=1),
                )
                store.seed_analysis_tasks(
                    "codex_cli",
                    settings.raw["analysis"]["prompt_version"],
                    analysis_policy_hash=settings.analysis_policy_hash,
                    retrieval_hash=settings.retrieval_hash,
                    profile_id=settings.profile_id,
                    profile_version=settings.profile_version,
                )
                task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                self.assertIsNotNone(task)
                runner = FakeStructuredRunner(work_id, sha256_text(text))
                reader = CodexDeepReader(
                    settings,
                    store,
                    runner,
                    JsonlAuditLog(settings.outputs_dir / "audit.jsonl"),
                    run_id,
                    lease_token,
                )
                reader.analyze(task)
                counts = store.dashboard_counts(
                    settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(counts["deep_read"], 1)
                with store._lock:
                    analysis = store._connection.execute(
                        "SELECT * FROM analyses WHERE work_id=?", (work_id,)
                    ).fetchone()
                self.assertEqual(analysis["deep_read_status"], "complete")
                self.assertEqual(analysis["provenance_status"], "append_only")
                coverage = json.loads(analysis["coverage_json"])
                self.assertEqual(coverage["chunk_done"], coverage["chunk_total"])
                self.assertGreater(coverage["chunk_total"], 1)
                usage = store.model_usage(task_id=int(task["id"]))
                self.assertEqual(
                    usage["invocation_count"],
                    len(set(runner.calls)),
                )
                synthesis_prompt = next(
                    prompt
                    for purpose, prompt in zip(runner.calls, runner.prompts)
                    if purpose.endswith("_synthesis")
                )
                self.assertIn(
                    '"allowed_evidence_anchors": [',
                    synthesis_prompt,
                )
                self.assertIn(
                    "copied byte-for-byte",
                    synthesis_prompt,
                )
                run_summary = terminal_publication_summary(
                    store,
                    settings,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE works
                        SET title='Changed before delayed publication'
                        WHERE id=?
                        """,
                        (work_id,),
                    )
                report = generate_weekly_report(
                    settings,
                    store,
                    run_id=run_id,
                    run_summary=run_summary,
                    output_dir=settings.outputs_dir / "test-weekly",
                )
                self.assertEqual(report["counts"]["selected"], 1)
                self.assertFalse(report["idempotent"])
                frozen_payload = json.loads(
                    Path(report["selection_path"]).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    frozen_payload["must_read"][0]["title"],
                    "Deep Read Fixture",
                )
                self.assertEqual(
                    frozen_payload["living_diff"]["counts"]["added"],
                    1,
                )
                self.assertEqual(
                    frozen_payload["living_diff"]["counts"][
                        "selected_changes"
                    ],
                    1,
                )
                outbox = report["local_outbox"]
                self.assertEqual(outbox["delivery_mode"], "local_only")
                self.assertEqual(outbox["state"], "ready")
                self.assertTrue(Path(outbox["digest_path"]).is_file())
                stored_outbox = store.publication_outbox_for_issue(
                    report["issue_id"]
                )
                self.assertIsNotNone(stored_outbox)
                self.assertFalse(stored_outbox["digest"]["external_delivery"])
                self.assertEqual(
                    stored_outbox["digest_sha256"],
                    outbox["digest_sha256"],
                )
                self.assertTrue(Path(report["report_path"]).is_file())
                self.assertIn(
                    "- 可追溯性：`append_only`",
                    Path(report["report_path"]).read_text(encoding="utf-8"),
                )
                self.assertEqual(
                    store.published_analysis_ids(),
                    {int(analysis["id"])},
                )
                second_report = generate_weekly_report(
                    settings,
                    store,
                    run_id=run_id,
                    run_summary=run_summary,
                    output_dir=settings.outputs_dir / "test-weekly",
                )
                self.assertTrue(second_report["idempotent"])
                self.assertEqual(second_report["payload_sha256"], report["payload_sha256"])
                self.assertEqual(second_report["report_path"], report["report_path"])
                self.assertEqual(second_report["selection_path"], report["selection_path"])
                self.assertEqual(
                    second_report["local_outbox"]["digest_sha256"],
                    outbox["digest_sha256"],
                )
                server = RadarHttpServer(("127.0.0.1", 0), settings)
                port = int(server.server_address[1])
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    for endpoint in ("/api/status", "/api/publication"):
                        connection = http.client.HTTPConnection(
                            "127.0.0.1",
                            port,
                            timeout=5,
                        )
                        connection.request(
                            "GET",
                            endpoint,
                            headers={"Host": f"127.0.0.1:{port}"},
                        )
                        response = connection.getresponse()
                        api_payload = json.loads(response.read())
                        connection.close()
                        self.assertEqual(response.status, 200)
                        publication_payload = (
                            api_payload["latest_publication"]
                            if endpoint == "/api/status"
                            else api_payload
                        )
                        self.assertEqual(
                            publication_payload["issue_id"],
                            report["issue_id"],
                        )
                        self.assertEqual(
                            publication_payload["run_id"],
                            run_id,
                        )
                        self.assertEqual(
                            publication_payload["payload_sha256"],
                            report["payload_sha256"],
                        )
                        self.assertEqual(
                            publication_payload["local_outbox"]["state"],
                            "ready",
                        )
                finally:
                    server.shutdown()
                    thread.join(timeout=5)
                    server.server_close()

                next_raw = json.loads(json.dumps(settings.raw))
                next_raw["analysis"]["prompt_version"] = "r3-deep-read-next-policy"
                next_settings = Settings(
                    raw=next_raw,
                    config_path=settings.config_path,
                    project_dir=settings.project_dir,
                    workspace_dir=settings.workspace_dir,
                    data_dir=settings.data_dir,
                    literature_dir=settings.literature_dir,
                    outputs_dir=settings.outputs_dir,
                    database_path=settings.database_path,
                )
                self.assertEqual(
                    next_settings.retrieval_hash,
                    settings.retrieval_hash,
                )
                self.assertNotEqual(
                    next_settings.analysis_policy_hash,
                    settings.analysis_policy_hash,
                )
                historical_counts = store.dashboard_counts(
                    next_settings.retrieval_hash,
                    analysis_policy_hash=next_settings.analysis_policy_hash,
                )
                self.assertEqual(historical_counts["deep_read"], 0)
                self.assertEqual(historical_counts["available_deep_read"], 1)
                self.assertEqual(historical_counts["pending_analysis"], 1)
                historical_work = store.list_dashboard_works(
                    config_hash=next_settings.retrieval_hash,
                    analysis_policy_hash=next_settings.analysis_policy_hash,
                )[0]
                self.assertNotIn("analysis_json", historical_work)
                self.assertFalse(historical_work["analysis_policy_current"])
                historical_analysis = store.dashboard_work_analysis(
                    work_id=work_id,
                    config_hash=next_settings.retrieval_hash,
                    analysis_policy_hash=next_settings.analysis_policy_hash,
                )
                self.assertIsNotNone(historical_analysis)
                self.assertTrue(historical_analysis["analysis"])
                self.assertFalse(
                    historical_analysis["analysis_policy_current"]
                )
                self.assertEqual(
                    store.latest_run_for_retrieval(
                        next_settings.retrieval_hash
                    )["id"],
                    run_id,
                )
                self.assertEqual(
                    store.latest_publication_for_retrieval(
                        next_settings.retrieval_hash
                    )["issue_id"],
                    report["issue_id"],
                )

                historical_server = RadarHttpServer(
                    ("127.0.0.1", 0),
                    next_settings,
                )
                historical_port = int(historical_server.server_address[1])
                historical_thread = threading.Thread(
                    target=historical_server.serve_forever,
                    daemon=True,
                )
                historical_thread.start()
                try:
                    api_payloads: dict[str, dict[str, object]] = {}
                    for endpoint in (
                        "/api/status",
                        "/api/publication",
                        "/api/works",
                        f"/api/work-analysis?work_id={work_id}",
                        "/api/decision-slice",
                    ):
                        connection = http.client.HTTPConnection(
                            "127.0.0.1",
                            historical_port,
                            timeout=5,
                        )
                        connection.request(
                            "GET",
                            endpoint,
                            headers={
                                "Host": f"127.0.0.1:{historical_port}"
                            },
                        )
                        response = connection.getresponse()
                        api_payloads[endpoint] = json.loads(response.read())
                        connection.close()
                        self.assertEqual(response.status, 200)
                    status_payload = api_payloads["/api/status"]
                    self.assertFalse(
                        status_payload["latest_run"]["analysis_policy_current"]
                    )
                    self.assertFalse(
                        status_payload["latest_publication"][
                            "analysis_policy_current"
                        ]
                    )
                    self.assertEqual(
                        status_payload["deep_read"]["historical_completed"],
                        1,
                    )
                    works_payload = api_payloads["/api/works"]
                    self.assertFalse(
                        works_payload["works"][0]["analysis_policy_current"]
                    )
                    self.assertNotIn(
                        "analysis", works_payload["works"][0]
                    )
                    analysis_payload = api_payloads[
                        f"/api/work-analysis?work_id={work_id}"
                    ]
                    self.assertTrue(analysis_payload["analysis"])
                    self.assertFalse(
                        analysis_payload["analysis_policy_current"]
                    )
                    self.assertFalse(
                        api_payloads["/api/publication"][
                            "analysis_policy_current"
                        ]
                    )
                    decision_payload = api_payloads["/api/decision-slice"]
                    self.assertFalse(
                        decision_payload["analysis_policy_current"]
                    )
                    decision_item = decision_payload["items"][0]
                    body = json.dumps(
                        {
                            "issue_id": report["issue_id"],
                            "analysis_id": decision_item["analysis_id"],
                            "action": "save",
                            "reason": "",
                            "note": "historical policy decision",
                        }
                    ).encode("utf-8")
                    connection = http.client.HTTPConnection(
                        "127.0.0.1",
                        historical_port,
                        timeout=5,
                    )
                    connection.request(
                        "POST",
                        "/api/decision",
                        body=body,
                        headers={
                            "Host": f"127.0.0.1:{historical_port}",
                            "Origin": f"http://127.0.0.1:{historical_port}",
                            "Content-Type": "application/json",
                        },
                    )
                    response = connection.getresponse()
                    response.read()
                    connection.close()
                    self.assertEqual(response.status, 201)
                finally:
                    historical_server.shutdown()
                    historical_thread.join(timeout=5)
                    historical_server.server_close()

                frozen_report = Path(report["report_path"]).read_bytes()
                Path(report["report_path"]).write_bytes(
                    frozen_report.replace(b"\n", b"\r\n")
                )
                with self.assertRaisesRegex(
                    PublicationConflictError,
                    "changed on disk",
                ):
                    generate_weekly_report(
                        settings,
                        store,
                        run_id=run_id,
                        run_summary=run_summary,
                        output_dir=settings.outputs_dir / "test-weekly",
                    )
                Path(report["report_path"]).write_bytes(frozen_report)
                with store.transaction() as connection:
                    original_payload_json = connection.execute(
                        """
                        SELECT payload_json FROM report_issues
                        WHERE run_id=?
                        """,
                        (run_id,),
                    ).fetchone()["payload_json"]
                    connection.execute(
                        """
                        UPDATE report_issues SET payload_json='{'
                        WHERE run_id=?
                        """,
                        (run_id,),
                    )
                with self.assertRaisesRegex(
                    PublicationConflictError,
                    "payload_json is corrupted",
                ):
                    store.latest_publication(
                        retrieval_hash=settings.retrieval_hash,
                        analysis_policy_hash=settings.analysis_policy_hash,
                    )
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE report_issues SET payload_json=?
                        WHERE run_id=?
                        """,
                        (original_payload_json, run_id),
                    )
                frozen_selection = Path(report["selection_path"]).read_bytes()
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE works SET title='Changed after terminal publication'
                        WHERE id=?
                        """,
                        (work_id,),
                    )
                replay_after_mutation = generate_weekly_report(
                    settings,
                    store,
                    run_id=run_id,
                    run_summary=run_summary,
                    output_dir=settings.outputs_dir / "test-weekly",
                )
                self.assertTrue(replay_after_mutation["idempotent"])
                self.assertEqual(
                    replay_after_mutation["payload_sha256"],
                    report["payload_sha256"],
                )
                self.assertEqual(
                    Path(report["selection_path"]).read_bytes(),
                    frozen_selection,
                )
                with store.transaction() as connection:
                    connection.execute(
                        """
                        UPDATE analyses
                        SET provenance_status='legacy_or_unknown'
                        WHERE id=?
                        """,
                        (analysis["id"],),
                    )
                frozen = store.list_complete_analyses(
                    config_hash=settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                )
                self.assertEqual(
                    frozen[0]["provenance_status"],
                    "legacy_or_unknown",
                )

    def test_large_deep_read_uses_persistent_exact_coverage_reduction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = make_settings(root)
            settings.raw["analysis"]["synthesis_input_character_budget"] = 10000
            settings.raw["analysis"]["synthesis_group_max_items"] = 8
            text = "=== PAGE 1 ===\n" + ("workflow cache evidence\n" * 620)
            text_path = settings.literature_dir / "text" / "large-paper.txt"
            text_path.write_bytes(text.encode("utf-8"))
            with RadarStore(settings.database_path) as store:
                run_id, _, lease_token = store.create_or_resume_run(settings, "test")
                store.seed_query_jobs(
                    run_id,
                    settings,
                    include_hosted=False,
                    lease_token=lease_token,
                    smoke=True,
                )
                with store._lock:
                    job_id = int(
                        store._connection.execute(
                            "SELECT id FROM query_jobs WHERE run_id=? AND source='openalex'",
                            (run_id,),
                        ).fetchone()["id"]
                    )
                record = SourceRecord(
                    source="openalex",
                    source_id="W-LARGE",
                    kind="paper",
                    title="Large Deep Read Fixture",
                    query_id="q01",
                    year=2026,
                )
                work_id, _ = store.ingest_record(
                    run_id=run_id,
                    lease_token=lease_token,
                    query_job_id=job_id,
                    record=record,
                    decision=objective_admission(record, settings.raw),
                    raw_sha256="raw-large",
                )
                store.save_document(
                    work_id=work_id,
                    content_kind="paper_pdf",
                    status="ready",
                    source_url="https://example.com/large.pdf",
                    local_path=None,
                    text_path=str(text_path),
                    content_sha256="pdf-large",
                    text_sha256=sha256_text(text),
                    byte_count=len(text),
                    text_char_count=len(text),
                    page_count=1,
                    coverage=current_pdf_ready_coverage(page_count=1),
                )
                store.seed_analysis_tasks(
                    "codex_cli",
                    settings.raw["analysis"]["prompt_version"],
                    analysis_policy_hash=settings.analysis_policy_hash,
                    retrieval_hash=settings.retrieval_hash,
                    profile_id=settings.profile_id,
                    profile_version=settings.profile_version,
                )
                task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                class PausingRunner(FakeStructuredRunner):
                    def __init__(self, candidate_id: int, content_sha: str):
                        super().__init__(candidate_id, content_sha)
                        self.reduce_calls = 0

                    def run_structured(self, **kwargs: object) -> CodexResult:
                        schema_path = kwargs["schema_path"]
                        if (
                            isinstance(schema_path, Path)
                            and schema_path.name == "synthesis_reduce.schema.json"
                        ):
                            self.reduce_calls += 1
                            if self.reduce_calls == 3:
                                raise AnalysisBudgetPaused("fixture budget boundary")
                        return super().run_structured(**kwargs)

                runner = PausingRunner(work_id, sha256_text(text))
                reader = CodexDeepReader(
                    settings,
                    store,
                    runner,
                    JsonlAuditLog(settings.outputs_dir / "audit-large.jsonl"),
                    run_id,
                    lease_token,
                )
                with self.assertRaises(AnalysisBudgetPaused):
                    reader.analyze(task)
                self.assertTrue(
                    store.pause_analysis_task(
                        int(task["id"]),
                        "fixture budget boundary",
                        run_id=run_id,
                        lease_token=lease_token,
                    )
                )
                with store._lock:
                    paused = store._connection.execute(
                        """
                        SELECT status, attempts, chunk_done, chunk_total
                        FROM analysis_tasks WHERE id=?
                        """,
                        (task["id"],),
                    ).fetchone()
                    paused_node_count = int(
                        store._connection.execute(
                            """
                            SELECT COUNT(*) FROM analysis_synthesis_nodes
                            WHERE task_id=?
                            """,
                            (task["id"],),
                        ).fetchone()[0]
                    )
                self.assertEqual(paused["status"], "pending")
                self.assertEqual(paused["attempts"], 0)
                self.assertEqual(paused["chunk_done"], paused["chunk_total"])
                self.assertGreater(paused_node_count, 0)
                resumed_task = store.claim_analysis_task(
                    "codex_cli",
                    config_hash=settings.analysis_policy_hash,
                    run_id=run_id,
                    lease_token=lease_token,
                )
                resumed_runner = FakeStructuredRunner(work_id, sha256_text(text))
                resumed_reader = CodexDeepReader(
                    settings,
                    store,
                    resumed_runner,
                    JsonlAuditLog(settings.outputs_dir / "audit-large.jsonl"),
                    run_id,
                    lease_token,
                )
                resumed_reader.analyze(resumed_task)
                self.assertTrue(
                    any("synthesis_reduce" in purpose for purpose in runner.calls)
                )
                self.assertFalse(
                    any("_chunks_" in purpose for purpose in resumed_runner.calls)
                )
                with store._lock:
                    node_count = int(
                        store._connection.execute(
                            """
                            SELECT COUNT(*) FROM analysis_synthesis_nodes
                            WHERE task_id=?
                            """,
                            (task["id"],),
                        ).fetchone()[0]
                    )
                    analysis = store._connection.execute(
                        "SELECT coverage_json FROM analyses WHERE task_id=?",
                        (task["id"],),
                    ).fetchone()
                self.assertGreater(node_count, 0)
                coverage = json.loads(analysis["coverage_json"])
                self.assertEqual(
                    coverage["chunk_indices"],
                    list(range(coverage["chunk_total"])),
                )


class HostedSearchTests(unittest.TestCase):
    def test_non_official_domain_is_objectively_dropped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = make_settings(Path(temporary))

            class FakeCodex:
                def run_structured(self, **_: object) -> CodexResult:
                    return CodexResult(
                        payload={
                            "query_id": "web-q01",
                            "query": "cache",
                            "results": [
                                {
                                    "kind": "paper",
                                    "title": "Official",
                                    "official_url": "https://arxiv.org/abs/2501.00001",
                                    "year": 2025,
                                    "doi": None,
                                    "arxiv_id": "2501.00001",
                                    "github_full_name": None,
                                    "pdf_url": None,
                                    "discovery_reason": "official",
                                },
                                {
                                    "kind": "paper",
                                    "title": "Blog",
                                    "official_url": "https://example.com/post",
                                    "year": 2025,
                                    "doi": None,
                                    "arxiv_id": None,
                                    "github_full_name": None,
                                    "pdf_url": None,
                                    "discovery_reason": "secondary",
                                },
                                {
                                    "kind": "paper",
                                    "title": "OpenReview search page",
                                    "official_url": "https://openreview.net/search",
                                    "year": 2025,
                                    "doi": None,
                                    "arxiv_id": None,
                                    "github_full_name": None,
                                    "pdf_url": None,
                                    "discovery_reason": "missing submission identity",
                                },
                            ],
                            "search_notes": [],
                        },
                        receipt={"prompt_sha256": "x", "provider": "fake"},
                    )

            search = CodexHostedSearch(settings, FakeCodex())
            records, receipt = search.search(
                {"query_id": "web-q01", "query_text": "cache"}
            )
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].arxiv_id, "2501.00001")
            self.assertEqual(len(receipt["dropped_results"]), 2)
            self.assertEqual(
                receipt["dropped_results"][1]["reason"],
                "openreview_url_missing_submission_identity",
            )

    def test_official_html_citation_metadata_parser(self) -> None:
        parser = _CitationMetadataParser()
        parser.feed(
            """
            <html><head>
            <title>Fallback title</title>
            <meta name="citation_title" content="Verified Paper Title">
            <meta name="citation_pdf_url" content="/paper.pdf">
            </head></html>
            """
        )
        self.assertEqual(parser.meta["citation_title"], "Verified Paper Title")
        self.assertEqual(parser.meta["citation_pdf_url"], "/paper.pdf")

    def test_arxiv_discovery_is_replaced_by_primary_api_metadata(self) -> None:
        from r3radar.http_client import RawReceipt

        receipt = RawReceipt(
            sha256="verified-sha",
            path="raw.atom.gz",
            byte_count=100,
            status_code=200,
            final_url="https://export.arxiv.org/api/query",
            fetched_at="now",
        )

        class FakeArxiv:
            def fetch_by_id(self, arxiv_id: str, query_id: str):
                return (
                    SourceRecord(
                        source="arxiv",
                        source_id=arxiv_id,
                        kind="paper",
                        title="Primary title",
                        query_id=query_id,
                        year=2025,
                        arxiv_id=arxiv_id,
                    ),
                    receipt,
                )

        verifier = HostedResultVerifier(
            lambda _: self.fail("generic HTTP should not be used"),
            FakeArxiv(),
            object(),
        )
        discovered = SourceRecord(
            source="codex_web",
            source_id="discovery",
            kind="paper",
            title="Possibly wrong title",
            query_id="web-q01",
            canonical_url="https://arxiv.org/abs/2501.00001",
            arxiv_id="2501.00001",
            metadata={"discovery_reason": "search"},
        )
        verified, returned_receipt = verifier.verify(discovered)
        self.assertEqual(verified.source, "arxiv")
        self.assertEqual(verified.title, "Primary title")
        self.assertEqual(returned_receipt.sha256, "verified-sha")
        self.assertEqual(
            verified.metadata["hosted_discovery"]["verification_method"],
            "arxiv_api",
        )

    def test_openreview_verifier_selects_root_submission_not_review(self) -> None:
        from r3radar.http_client import RawReceipt

        receipt = RawReceipt(
            sha256="openreview-sha",
            path="raw.json.gz",
            byte_count=100,
            status_code=200,
            final_url="https://api2.openreview.net/notes",
            fetched_at="now",
        )

        class FakeClient:
            def request_json(self, *_: object, **__: object):
                return (
                    {
                        "notes": [
                            {
                                "id": "review1",
                                "forum": "paper1",
                                "content": {"title": {"value": "Review title"}},
                            },
                            {
                                "id": "paper1",
                                "forum": "paper1",
                                "content": {"title": {"value": "Submission title"}},
                            },
                        ]
                    },
                    receipt,
                    {},
                )

        verifier = HostedResultVerifier(
            lambda _: FakeClient(),
            object(),
            object(),
        )
        discovered = SourceRecord(
            source="codex_web",
            source_id="discovery",
            kind="paper",
            title="Search title",
            query_id="web-q01",
            canonical_url="https://openreview.net/forum?id=paper1",
        )
        verified, _ = verifier.verify(discovered)
        self.assertEqual(verified.source_id, "paper1")
        self.assertEqual(verified.title, "Submission title")

    def test_openreview_url_without_submission_identity_is_terminally_rejected(
        self,
    ) -> None:
        verifier = HostedResultVerifier(
            lambda _: self.fail("HTTP must not run for a malformed OpenReview URL"),
            object(),
            object(),
        )
        discovered = SourceRecord(
            source="codex_web",
            source_id="discovery",
            kind="paper",
            title="Search page",
            query_id="web-q01",
            canonical_url="https://openreview.net/search",
        )
        with self.assertRaisesRegex(
            HostedVerificationRejectedError,
            "no forum identifier",
        ) as raised:
            verifier.verify(discovered)
        self.assertEqual(
            raised.exception.code,
            "openreview_url_missing_submission_identity",
        )


if __name__ == "__main__":
    unittest.main()
