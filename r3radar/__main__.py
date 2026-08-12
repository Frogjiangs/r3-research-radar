from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .calibration import build_intake_calibration, evaluate_gold_set_file
from .config import (
    PRODUCTION_PROFILE_OPERATIONS,
    ProfileActivationError,
    load_settings,
    require_profile_production_activation,
)
from .continuity import run_continuity_test
from .demo import prepare_demo
from .intake import WeeklyIntakePolicyError
from .known_answers import (
    KnownAnswerError,
    evaluate_external_known_answers,
    freeze_external_known_answer_set,
    validate_external_known_answer_set,
)
from .model_integration import run_model_integration
from .onboarding import create_profile, doctor_report
from .pipeline import PipelineLimits, RadarPipeline
from .recovery import RecoveryError, create_verified_backup, verify_backup
from .report import generate_weekly_report
from .reproduction import (
    ReproductionHandoffError,
    pin_paper_repository_relation,
)
from .reprojection import reproject_repository_corpus
from .runtime_status import (
    DEFAULT_DASHBOARD_PORT,
    inspect_database,
    probe_dashboard_service,
    run_status,
    scheduler_status,
)
from .storage import (
    PublicationConflictError,
    PublicationNotAllowedError,
    RadarStore,
)
from .utils import atomic_write_text, json_dumps
from .web import serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="R3 decision-grade research radar for papers and code"
    )
    parser.add_argument("--config", type=Path, help="Path to the R3 profile JSON.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser(
        "create-profile",
        help="Create a non-overwriting starter research profile.",
    )
    create.add_argument("--output", type=Path, default=Path("r3.profile.json"))
    create.add_argument("--profile-id", default="my-research-radar")
    create.add_argument("--name", default="My Research Radar")
    create.add_argument(
        "--question",
        default=(
            "Which recent papers and open-source repositories should change "
            "my next research decision?"
        ),
    )
    create.add_argument(
        "--decision-scope",
        default=(
            "Decide whether each item should be read, tested, adopted, watched, "
            "or skipped."
        ),
    )

    demo = subparsers.add_parser(
        "demo",
        help="Prepare a deterministic two-item demo without network or model calls.",
    )
    demo.add_argument("--workspace", type=Path, default=Path(".r3-demo"))
    demo.add_argument("--port", type=int, default=DEFAULT_DASHBOARD_PORT)
    demo.add_argument(
        "--prepare-only",
        action="store_true",
        help="Prepare and verify the demo without starting its dashboard.",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="Check the local profile, runtime, provider, and loopback boundary.",
    )
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--check-auth", action="store_true")
    doctor.add_argument("--port", type=int, default=DEFAULT_DASHBOARD_PORT)

    subparsers.add_parser("init", help="Create directories and initialize SQLite.")

    smoke = subparsers.add_parser("smoke", help="Run a bounded real-network smoke test.")
    smoke_phases = smoke.add_mutually_exclusive_group()
    smoke_phases.add_argument("--no-hosted-search", action="store_true")
    smoke_phases.add_argument("--hosted-only", action="store_true")
    smoke.add_argument(
        "--analysis-provider",
        choices=["auto", "codex_cli", "llama_cpp"],
        default="auto",
    )
    smoke.add_argument("--skip-analysis", action="store_true")

    run = subparsers.add_parser("run", help="Run or resume the full R3 backfill.")
    run_phases = run.add_mutually_exclusive_group()
    run_phases.add_argument("--no-hosted-search", action="store_true")
    run_phases.add_argument("--hosted-only", action="store_true")
    run_phases.add_argument(
        "--analysis-only",
        action="store_true",
        help="Resume existing analysis tasks without retrieval or content fetching.",
    )
    run.add_argument(
        "--analysis-provider",
        choices=["auto", "codex_cli", "llama_cpp"],
        default="auto",
    )

    weekly = subparsers.add_parser(
        "weekly",
        help="Run or resume the bounded incremental weekly profile.",
    )
    weekly_phases = weekly.add_mutually_exclusive_group()
    weekly_phases.add_argument("--no-hosted-search", action="store_true")
    weekly_phases.add_argument("--hosted-only", action="store_true")
    weekly.add_argument(
        "--analysis-provider",
        choices=["auto", "codex_cli", "llama_cpp"],
        default="auto",
    )

    dashboard = subparsers.add_parser("dashboard", help="Start the loopback-only dashboard.")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=DEFAULT_DASHBOARD_PORT)

    status = subparsers.add_parser("status", help="Print current counts.")
    status.add_argument("--json", action="store_true")
    status.add_argument("--port", type=int, default=DEFAULT_DASHBOARD_PORT)

    subparsers.add_parser(
        "repair-scores",
        help="Normalize legacy 0-10 model scores to the required 0-100 scale.",
    )

    retry_run = subparsers.add_parser(
        "retry-run-failures",
        help="Explicitly requeue terminal query and verification failures after a fix.",
    )
    retry_run.add_argument("run_id")

    retry_content = subparsers.add_parser(
        "retry-content",
        help="Explicitly requeue one unavailable or incomplete work after a fetcher/config fix.",
    )
    retry_content.add_argument("work_id", type=int)

    retry_analysis = subparsers.add_parser(
        "retry-analysis",
        help="Explicitly requeue one terminal failed deep-read task.",
    )
    retry_analysis.add_argument("work_id", type=int)
    retry_analysis.add_argument(
        "--provider",
        choices=["codex_cli", "llama_cpp"],
    )

    subparsers.add_parser(
        "quarantine-unverified",
        help="Move Codex-only discoveries without primary-source verification out of admission.",
    )

    reproject = subparsers.add_parser(
        "reproject-repositories",
        help=(
            "Rebuild ready repository corpora with the current selector; "
            "dry-run is the default."
        ),
    )
    reproject.add_argument(
        "--apply",
        action="store_true",
        help="Write selected-corpus revisions and queue only affected works.",
    )
    reproject.add_argument(
        "--work-id",
        action="append",
        type=int,
        dest="work_ids",
        help="Limit the operation to one or more ready repository work IDs.",
    )

    report = subparsers.add_parser(
        "report",
        help="Idempotently publish one eligible terminal run.",
    )
    report.add_argument("--run-id", required=True)

    relation = subparsers.add_parser(
        "pin-paper-repository",
        help=(
            "Verify and freeze one official paper-to-GitHub commit relation "
            "without executing repository code."
        ),
    )
    relation.add_argument("--paper-work-id", required=True, type=int)
    relation.add_argument("--repository-work-id", required=True, type=int)

    feedback = subparsers.add_parser("feedback", help="Record four-level feedback.")
    feedback.add_argument("work_id", type=int)
    feedback.add_argument(
        "rating",
        choices=["改变思路", "值得保存", "一般背景", "无关"],
    )
    feedback.add_argument("--comment")

    continuity = subparsers.add_parser(
        "continuity-test",
        help="Run resumable repeated regression and copy-only database checks.",
    )
    continuity.add_argument("--iterations", type=int, default=100)
    continuity.add_argument("--max-seconds", type=int, default=0)
    continuity.add_argument("--resume-run-id")

    model_integration = subparsers.add_parser(
        "model-integration-test",
        help="Run one isolated real-provider deep read and report generation.",
    )
    model_integration.add_argument(
        "--provider",
        choices=["codex_cli", "llama_cpp"],
        required=True,
    )

    calibrate = subparsers.add_parser(
        "calibrate-intake",
        help="Build the Phase-B capacity, Gold Set and profile-v2 proposal artifacts.",
    )
    calibrate.add_argument("--run-id", required=True)
    calibrate.add_argument("--output-dir", type=Path, required=True)

    evaluate_gold = subparsers.add_parser(
        "evaluate-gold",
        help="Evaluate a fully human-labeled Gold Set without changing the profile.",
    )
    evaluate_gold.add_argument("--run-id", required=True)
    evaluate_gold.add_argument("--gold-set", type=Path, required=True)
    evaluate_gold.add_argument("--output", type=Path, required=True)

    known_answer_validate = subparsers.add_parser(
        "known-answer-validate",
        help="Validate or preview-freeze one independent external known-answer set.",
    )
    known_answer_validate.add_argument("input", type=Path)
    known_answer_mode = known_answer_validate.add_mutually_exclusive_group()
    known_answer_mode.add_argument(
        "--freeze",
        action="store_true",
        help="Preview a frozen document; --frozen-at and --frozen-by are required.",
    )
    known_answer_mode.add_argument(
        "--require-frozen",
        action="store_true",
        help="Require and verify an already-frozen set and its digests.",
    )
    known_answer_validate.add_argument("--frozen-at")
    known_answer_validate.add_argument("--frozen-by")
    known_answer_validate.add_argument(
        "--output",
        type=Path,
        help="Write the validated or preview-frozen document to this explicit path.",
    )
    known_answer_validate.add_argument(
        "--force",
        action="store_true",
        help="Atomically replace --output if it already exists.",
    )

    known_answer_evaluate = subparsers.add_parser(
        "known-answer-evaluate",
        help="Evaluate a frozen candidate ranking against an independent known-answer split.",
    )
    known_answer_evaluate.add_argument("--known-answer-set", type=Path, required=True)
    known_answer_evaluate.add_argument("--candidates", type=Path, required=True)
    known_answer_evaluate.add_argument(
        "--baseline",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Add a named baseline candidate JSON list; may be repeated.",
    )
    known_answer_evaluate.add_argument(
        "--split",
        choices=["development", "evaluation"],
        required=True,
    )
    known_answer_evaluate.add_argument("--candidate-run-id", required=True)
    known_answer_evaluate.add_argument("--candidate-pool-id", required=True)
    known_answer_evaluate.add_argument(
        "--candidate-pool-frozen-at",
        required=True,
        help="ISO-8601 retrieval/candidate-pool cutoff, including timezone.",
    )
    known_answer_evaluate.add_argument(
        "--candidate-source-artifact-id",
        action="append",
        required=True,
        dest="candidate_source_artifact_ids",
    )
    known_answer_evaluate.add_argument(
        "--origin-known-answer-set-id",
        action="append",
        default=[],
        dest="origin_known_answer_set_ids",
    )
    known_answer_evaluate.add_argument(
        "--known-answer-split-accessed-before-run",
        action="append",
        choices=["development", "evaluation"],
        default=[],
        dest="known_answer_splits_accessed_before_run",
    )
    known_answer_evaluate.add_argument("--ranking-method", required=True)
    known_answer_evaluate.add_argument("--evaluator-identity", required=True)
    known_answer_evaluate.add_argument("--evaluated-at", required=True)
    known_answer_evaluate.add_argument("--output", type=Path, required=True)
    known_answer_evaluate.add_argument(
        "--force",
        action="store_true",
        help="Atomically replace --output if it already exists.",
    )

    backup = subparsers.add_parser(
        "backup",
        help="Create one non-overwriting verified SQLite backup and manifest.",
    )
    backup.add_argument("--output-dir", type=Path, required=True)
    backup.add_argument("--name")

    verify_backup_parser = subparsers.add_parser(
        "verify-backup",
        help="Verify a SQLite backup read-only against its manifest.",
    )
    verify_backup_parser.add_argument("backup_path", type=Path)
    verify_backup_parser.add_argument("--manifest", type=Path)
    return parser


def _read_json_document(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_explicit_json(path: Path, value: object, *, force: bool) -> None:
    destination = path.resolve()
    text = json_dumps(value, pretty=True) + "\n"
    if force:
        atomic_write_text(destination, text)
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise FileExistsError(f"output already exists: {destination}") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _parse_named_candidate_files(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        name = name.strip()
        raw_path = raw_path.strip()
        if not separator or not name or not raw_path:
            raise ValueError("--baseline must use NAME=PATH")
        if name in result:
            raise ValueError(f"duplicate baseline name: {name}")
        result[name] = Path(raw_path)
    return result


def _known_answer_set_summary(
    document: dict[str, object],
    *,
    status: str,
    output: Path | None,
) -> dict[str, object]:
    items = document["items"]
    assert isinstance(items, list)
    split_counts = {
        split: sum(1 for item in items if isinstance(item, dict) and item.get("split") == split)
        for split in ("development", "evaluation")
    }
    judgment_counts = {
        state: sum(
            1
            for item in items
            if isinstance(item, dict)
            and isinstance(item.get("judgment"), dict)
            and item["judgment"].get("status") == state
        )
        for state in ("verified", "unknown")
    }
    freeze = document["freeze"]
    split_policy = document["split_policy"]
    assert isinstance(freeze, dict) and isinstance(split_policy, dict)
    return {
        "ok": True,
        "status": status,
        "schema": document["schema"],
        "set_id": document["set_id"],
        "item_count": len(items),
        "split_counts": split_counts,
        "judgment_counts": judgment_counts,
        "freeze_status": freeze["status"],
        "set_sha256": freeze["set_sha256"],
        "assignment_sha256": split_policy["assignment_sha256"],
        "output": str(output.resolve()) if output is not None else None,
        "output_written": output is not None,
        "evidence_class": "declared_external_known_answer_contract",
        "source_independence_status": "declared_and_contract_checked_not_externally_verified",
        "human_gold_claim": False,
    }


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, OSError):
            pass
    args = build_parser().parse_args(argv)
    if args.command == "create-profile":
        try:
            result = create_profile(
                args.output,
                profile_id=args.profile_id,
                name=args.name,
                research_question=args.question,
                decision_scope=args.decision_scope,
            )
        except (FileExistsError, OSError, ValueError) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "profile_not_created",
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        print(json_dumps(result, pretty=True))
        return 0
    if args.command == "demo":
        try:
            settings, result = prepare_demo(args.workspace)
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "demo_not_prepared",
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        print(json_dumps(result, pretty=True), flush=True)
        if args.prepare_only:
            return 0
        try:
            serve(
                settings,
                host="127.0.0.1",
                port=args.port,
                emit_receipts=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "event": "dashboard_start_failed",
                        "port": args.port,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                ),
                flush=True,
            )
            return 1
        return 0
    if args.command == "known-answer-validate":
        try:
            if args.force and args.output is None:
                raise ValueError("--force requires --output")
            document = _read_json_document(args.input.resolve())
            if not isinstance(document, dict):
                raise KnownAnswerError("known-answer set must be an object")
            if args.freeze:
                if not args.frozen_at or not args.frozen_by:
                    raise ValueError("--freeze requires --frozen-at and --frozen-by")
                processed = freeze_external_known_answer_set(
                    document,
                    frozen_at=args.frozen_at,
                    frozen_by=args.frozen_by,
                )
                status = "freeze_preview"
            else:
                if args.frozen_at or args.frozen_by:
                    raise ValueError("--frozen-at and --frozen-by require --freeze")
                processed = validate_external_known_answer_set(
                    document,
                    require_frozen=bool(args.require_frozen),
                )
                status = (
                    "valid_frozen"
                    if processed["freeze"]["status"] == "frozen"
                    else "valid_draft"
                )
            if args.output is not None:
                _write_explicit_json(args.output, processed, force=bool(args.force))
            print(
                json_dumps(
                    _known_answer_set_summary(
                        processed,
                        status=status,
                        output=args.output,
                    ),
                    pretty=True,
                )
            )
            return 0
        except (
            FileExistsError,
            json.JSONDecodeError,
            KnownAnswerError,
            OSError,
            ValueError,
        ) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "known_answer_validation_failed",
                        "error": str(exc),
                        "output_written": False,
                    },
                    pretty=True,
                )
            )
            return 2
    if args.command == "known-answer-evaluate":
        try:
            known_answer_set = _read_json_document(args.known_answer_set.resolve())
            candidates = _read_json_document(args.candidates.resolve())
            if not isinstance(known_answer_set, dict):
                raise KnownAnswerError("known-answer set must be an object")
            if not isinstance(candidates, list):
                raise KnownAnswerError("candidate JSON must be a list")
            baselines = {
                name: _read_json_document(path.resolve())
                for name, path in _parse_named_candidate_files(args.baseline).items()
            }
            if any(not isinstance(rows, list) for rows in baselines.values()):
                raise KnownAnswerError("each baseline candidate JSON must be a list")
            receipt = evaluate_external_known_answers(
                known_answer_set,
                split=args.split,
                candidates=candidates,
                baselines=baselines,
                evaluation_context={
                    "candidate_run_id": args.candidate_run_id,
                    "candidate_pool_id": args.candidate_pool_id,
                    "candidate_pool_frozen_at": args.candidate_pool_frozen_at,
                    "candidate_source_artifact_ids": args.candidate_source_artifact_ids,
                    "origin_known_answer_set_ids": args.origin_known_answer_set_ids,
                    "known_answer_splits_accessed_before_run": (
                        args.known_answer_splits_accessed_before_run
                    ),
                    "ranking_method": args.ranking_method,
                },
                evaluator_identity=args.evaluator_identity,
                evaluated_at=args.evaluated_at,
            )
            _write_explicit_json(args.output, receipt, force=bool(args.force))
            print(
                json_dumps(
                    {
                        "ok": True,
                        "status": "known_answer_evaluation_written",
                        "schema": receipt["schema"],
                        "set_id": receipt["known_answer_set"]["set_id"],
                        "split": receipt["known_answer_set"]["split"],
                        "item_count": receipt["known_answer_set"]["item_count"],
                        "candidate_count": len(candidates),
                        "baseline_count": len(receipt["baselines"]),
                        "receipt_sha256": receipt["receipt_sha256"],
                        "output": str(args.output.resolve()),
                        "output_written": True,
                        "evidence_class": "offline_external_known_answer_evaluation",
                        "source_independence_status": (
                            "declared_and_contract_checked_not_externally_verified"
                        ),
                        "human_gold_claim": False,
                        "market_or_recommendation_quality_claim": False,
                    },
                    pretty=True,
                )
            )
            return 0
        except (
            FileExistsError,
            json.JSONDecodeError,
            KnownAnswerError,
            OSError,
            ValueError,
        ) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "known_answer_evaluation_failed",
                        "error": str(exc),
                        "output_written": False,
                    },
                    pretty=True,
                )
            )
            return 2
    try:
        settings = load_settings(args.config)
        if args.command in PRODUCTION_PROFILE_OPERATIONS:
            require_profile_production_activation(settings, args.command)
    except ProfileActivationError as exc:
        print(
            json_dumps(
                {
                    "ok": False,
                    "status": "profile_confirmation_required",
                    "operation": args.command,
                    "error": str(exc),
                },
                pretty=True,
            )
        )
        return 2
    if args.command == "doctor":
        result = doctor_report(
            settings,
            check_auth=args.check_auth,
            dashboard_port=args.port,
        )
        if args.json:
            print(json_dumps(result, pretty=True))
        else:
            print(f"R3 doctor: {result['status']}")
            for check in result["checks"]:
                print(
                    f"[{str(check['status']).upper()}] "
                    f"{check['id']}: {check['summary']}"
                )
                if check.get("remediation"):
                    print(f"  Fix: {check['remediation']}")
        return 1 if result["status"] == "blocked" else 0
    if args.command == "init":
        with RadarStore(settings.database_path):
            pass
        print(
            json_dumps(
                {
                    "ok": True,
                    "database": str(settings.database_path),
                    "outputs": str(settings.outputs_dir),
                },
                pretty=True,
            )
        )
        return 0
    if args.command in {"smoke", "run", "weekly"}:
        analysis_only = bool(getattr(args, "analysis_only", False))
        limits = PipelineLimits.smoke() if args.command == "smoke" else PipelineLimits()
        if args.command == "smoke" and args.skip_analysis:
            limits = PipelineLimits(
                results_per_query=limits.results_per_query,
                content_items=limits.content_items,
                analysis_items=0,
                hosted_jobs=limits.hosted_jobs,
            )
        try:
            with RadarPipeline(
                settings,
                mode=args.command,
                include_official_sources=(
                    not args.hosted_only and not analysis_only
                ),
                include_hosted_search=(
                    not args.no_hosted_search and not analysis_only
                ),
                analysis_only=analysis_only,
                limits=limits,
                analysis_provider=args.analysis_provider,
            ) as pipeline:
                summary = pipeline.run()
        except WeeklyIntakePolicyError as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "profile_confirmation_required",
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 2
        print(json_dumps(summary, pretty=True))
        if summary.get("interrupted"):
            return 130
        if summary["status"] in {"failed", "paused_with_error"}:
            return 1
        if (summary.get("publication") or {}).get("status") == "failed":
            return 1
        if summary["status"] == "completed_with_gaps":
            return 2
        return 0
    if args.command == "dashboard":
        database = inspect_database(settings.database_path)
        if database["state"] != "ready":
            print(
                json_dumps(
                    {
                        "ok": False,
                        "event": "dashboard_start_failed",
                        "reason": "database_not_ready",
                        "database": database,
                    },
                    pretty=True,
                )
            )
            return 1
        try:
            serve(
                settings,
                host=args.host,
                port=args.port,
                emit_receipts=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "event": "dashboard_start_failed",
                        "port": args.port,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        return 0
    if args.command == "calibrate-intake":
        receipt = build_intake_calibration(
            settings,
            run_id=args.run_id,
            output_dir=args.output_dir.resolve(),
        )
        print(json_dumps(receipt, pretty=True))
        return 0
    if args.command == "evaluate-gold":
        result = evaluate_gold_set_file(
            settings,
            run_id=args.run_id,
            gold_set_path=args.gold_set.resolve(),
            output_path=args.output.resolve(),
        )
        print(json_dumps(result, pretty=True))
        return 0 if result.get("passed") else 2
    if args.command == "backup":
        try:
            result = create_verified_backup(
                settings.database_path,
                args.output_dir.resolve(),
                backup_name=args.name,
            )
        except RecoveryError as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "backup_failed",
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        print(json_dumps({"ok": True, **result}, pretty=True))
        return 0
    if args.command == "verify-backup":
        try:
            result = verify_backup(
                args.backup_path.resolve(),
                args.manifest.resolve() if args.manifest else None,
            )
        except RecoveryError as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "backup_verification_failed",
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        print(json_dumps({"ok": True, **result}, pretty=True))
        return 0
    if args.command == "status":
        database = inspect_database(settings.database_path)
        service = probe_dashboard_service(
            args.port,
            expected_config_hash=settings.config_hash,
        )
        scheduler = scheduler_status()
        if database["state"] != "ready":
            payload = {
                "runtime": {
                    "service": service,
                    "database": database,
                    "run": {
                        "state": "unknown",
                        "active": False,
                        "latest": None,
                        "last_success": None,
                    },
                    "scheduler": scheduler,
                },
                "counts": None,
                "latest_run": None,
                "query_coverage": None,
                "model_usage": None,
            }
            print(json_dumps(payload, pretty=True))
            return 1
        with RadarStore(settings.database_path) as store:
            latest_run = store.latest_run(settings.config_hash)
            if latest_run is not None:
                latest_run = dict(latest_run)
                latest_run["lease_token_present"] = bool(
                    latest_run.pop("lease_token", None)
                )
            payload = {
                "runtime": {
                    "service": service,
                    "database": database,
                    "run": run_status(
                        store,
                        settings.config_hash,
                        settings.retrieval_hash,
                    ),
                    "scheduler": scheduler,
                },
                "counts": store.dashboard_counts(
                    settings.retrieval_hash,
                    analysis_policy_hash=settings.analysis_policy_hash,
                ),
                "latest_run": latest_run,
                "query_coverage": (
                    store.query_job_coverage(
                        str(latest_run["id"]),
                        settings,
                    )
                    if latest_run
                    else None
                ),
                "model_usage": (
                    store.model_usage(run_id=str(latest_run["id"]))
                    if latest_run
                    else store.model_usage()
                ),
            }
        if args.json:
            print(json_dumps(payload, pretty=True))
        else:
            print(f"service: {payload['runtime']['service']['state']}")
            print(f"database: {payload['runtime']['database']['state']}")
            print(f"run: {payload['runtime']['run']['state']}")
            print(f"scheduler: {payload['runtime']['scheduler']['state']}")
            coverage = payload.get("query_coverage")
            if coverage:
                print(f"query_scope: {coverage['scope']}")
                print(
                    "query_plan: "
                    f"{coverage['scheduled_jobs']}/{coverage['expected_jobs']}"
                )
                print(
                    "query_terminal: "
                    f"{coverage['terminal_jobs']}/{coverage['scheduled_jobs']}"
                )
                print(
                    "complete_profile_run: "
                    f"{str(bool(coverage['complete_profile_run'])).lower()}"
                )
            for key, value in payload["counts"].items():
                print(f"{key}: {value}")
        return 0
    if args.command == "repair-scores":
        with RadarStore(settings.database_path) as store:
            repaired = store.repair_analysis_scores()
            store.event(
                run_id=None,
                component="maintenance",
                event_type="analysis_scores_repaired",
                details={"repaired_count": repaired},
            )
        print(json_dumps({"ok": True, "repaired_count": repaired}, pretty=True))
        return 0
    if args.command == "retry-run-failures":
        with RadarStore(settings.database_path) as store:
            result = store.requeue_run_failures(args.run_id)
            store.event(
                run_id=args.run_id,
                component="maintenance",
                event_type="run_failures_requeued",
                details=result,
            )
        print(json_dumps({"ok": True, "run_id": args.run_id, **result}, pretty=True))
        return 0
    if args.command == "retry-content":
        with RadarStore(settings.database_path) as store:
            store.requeue_content(
                args.work_id,
                retrieval_hash=settings.retrieval_hash,
            )
            store.event(
                run_id=None,
                component="maintenance",
                event_type="content_requeued",
                details={"work_id": args.work_id},
            )
        print(json_dumps({"ok": True, "work_id": args.work_id}, pretty=True))
        return 0
    if args.command == "retry-analysis":
        with RadarStore(settings.database_path) as store:
            result = store.requeue_analysis(
                args.work_id,
                analysis_policy_hash=settings.analysis_policy_hash,
                provider=args.provider,
            )
            store.event(
                run_id=None,
                component="maintenance",
                event_type="analysis_requeued",
                details=result,
            )
        print(json_dumps({"ok": True, **result}, pretty=True))
        return 0
    if args.command == "quarantine-unverified":
        with RadarStore(settings.database_path) as store:
            quarantined = store.quarantine_unverified_hosted_discoveries(
                retrieval_hash=settings.retrieval_hash
            )
            store.event(
                run_id=None,
                component="maintenance",
                event_type="unverified_hosted_discoveries_quarantined",
                details={"quarantined_count": quarantined},
            )
        print(json_dumps({"ok": True, "quarantined_count": quarantined}, pretty=True))
        return 0
    if args.command == "reproject-repositories":
        try:
            result = reproject_repository_corpus(
                settings,
                apply=bool(args.apply),
                work_ids=args.work_ids,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "repository_reprojection_failed",
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        print(json_dumps({"ok": True, **result}, pretty=True))
        return 0 if result["failed_count"] == 0 else 1
    if args.command == "report":
        try:
            with RadarStore(settings.database_path) as store:
                result = generate_weekly_report(
                    settings,
                    store,
                    run_id=args.run_id,
                )
        except (PublicationNotAllowedError, PublicationConflictError) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "run_id": args.run_id,
                        "error": type(exc).__name__,
                        "message": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        print(json_dumps({"ok": True, **result}, pretty=True))
        return 0
    if args.command == "pin-paper-repository":
        try:
            result = pin_paper_repository_relation(
                settings,
                paper_work_id=args.paper_work_id,
                repository_work_id=args.repository_work_id,
            )
        except (OSError, RuntimeError, ValueError, ReproductionHandoffError) as exc:
            print(
                json_dumps(
                    {
                        "ok": False,
                        "status": "paper_repository_relation_failed",
                        "error": str(exc),
                    },
                    pretty=True,
                )
            )
            return 1
        print(json_dumps({"ok": True, **result}, pretty=True))
        return 0
    if args.command == "feedback":
        with RadarStore(settings.database_path) as store:
            store.add_feedback(
                args.work_id,
                args.rating,
                args.comment,
                retrieval_hash=settings.retrieval_hash,
                analysis_policy_hash=settings.analysis_policy_hash,
            )
        print("feedback_saved")
        return 0
    if args.command == "continuity-test":
        result = run_continuity_test(
            settings,
            iterations=args.iterations,
            max_seconds=args.max_seconds,
            resume_run_id=args.resume_run_id,
        )
        print(json_dumps(result, pretty=True))
        return 0 if result["status"] == "passed" else 1
    if args.command == "model-integration-test":
        result = run_model_integration(
            settings,
            provider=args.provider,
        )
        print(json_dumps(result, pretty=True))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
