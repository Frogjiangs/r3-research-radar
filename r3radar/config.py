from __future__ import annotations

import hashlib
import json
import os
import string
import sysconfig
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_SOURCE_PROJECT_DIR = Path(__file__).resolve().parents[1]
_REQUIRED_ASSET_PATHS = (
    Path("config/profile.example.json"),
    Path("schemas/synthesis.schema.json"),
    Path("static/index.html"),
)


def _select_project_dir(candidates: tuple[Path, ...]) -> Path:
    """Select the source tree or installed data-files root containing R3 assets."""

    for candidate in candidates:
        resolved = candidate.resolve()
        if all((resolved / relative).is_file() for relative in _REQUIRED_ASSET_PATHS):
            return resolved
    return candidates[0].resolve()


PROJECT_DIR = _select_project_dir(
    (
        _SOURCE_PROJECT_DIR,
        Path(sysconfig.get_path("data")) / "share" / "r3-research-radar",
    )
)
WORKSPACE_DIR = PROJECT_DIR.parents[1]
_PRIVATE_DEFAULT_CONFIG = PROJECT_DIR / "config" / "r3.v1.json"
DEFAULT_CONFIG = (
    _PRIVATE_DEFAULT_CONFIG
    if _PRIVATE_DEFAULT_CONFIG.is_file()
    else PROJECT_DIR / "config" / "profile.example.json"
)
CONFIG_SCHEMA_VERSION = "1.1"
PRODUCTION_PROFILE_OPERATIONS = frozenset(
    {"smoke", "run", "weekly", "report", "model-integration-test"}
)
_PDF_PARSER_KEYS = {
    "backend",
    "policy_version",
    "wall_timeout_seconds",
    "cpu_time_seconds",
    "memory_limit_bytes",
    "max_input_bytes",
    "max_pages",
    "max_output_characters",
    "max_result_bytes",
}
_RUN_RESOURCE_KEYS = {
    "max_content_items_per_invocation",
    "max_transfer_bytes_per_invocation",
    "minimum_free_disk_bytes",
}
_ANALYSIS_SCHEMA_POLICY_COMPATIBILITY = {
    (
        "synthesis_reduce.schema.json",
        "abfd5db717fd3659bf4e28501e4d2434d426301a26e5a33519debe6ba3628d7c",
    ): {
        "policy_sha256": (
            "42a142d051c9fad8834e9cf3ef57fa080"
            "09969c0f780f98372e094eb0c385162"
        ),
        "reason": "provider-compatible removal of runtime-enforced uniqueItems",
        "removed_paths": (
            "$.properties.covered_chunk_indices.uniqueItems",
            "$.properties.evidence_anchors.uniqueItems",
        ),
    }
}


class ProfileActivationError(ValueError):
    """Raised when a proposed or unverified profile reaches a production path."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def analysis_schema_policy_record(project_dir: Path, name: str) -> dict[str, Any]:
    actual_sha256 = hashlib.sha256(
        (project_dir / "schemas" / name).read_bytes()
    ).hexdigest()
    compatibility = _ANALYSIS_SCHEMA_POLICY_COMPATIBILITY.get(
        (name, actual_sha256)
    )
    if compatibility is None:
        return {
            "name": name,
            "actual_sha256": actual_sha256,
            "policy_sha256": actual_sha256,
            "compatibility_reason": None,
            "removed_paths": (),
        }
    return {
        "name": name,
        "actual_sha256": actual_sha256,
        "policy_sha256": str(compatibility["policy_sha256"]),
        "compatibility_reason": str(compatibility["reason"]),
        "removed_paths": tuple(compatibility["removed_paths"]),
    }


@dataclass(frozen=True)
class Settings:
    raw: dict[str, Any]
    config_path: Path
    project_dir: Path
    workspace_dir: Path
    data_dir: Path
    literature_dir: Path
    outputs_dir: Path
    database_path: Path

    @property
    def profile_id(self) -> str:
        return str(self.raw["profile_id"])

    @property
    def profile_version(self) -> int:
        return int(self.raw["profile_version"])

    @property
    def profile_hash(self) -> str:
        return self.retrieval_hash

    @property
    def config_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.raw).encode("utf-8")).hexdigest()

    @property
    def retrieval_hash(self) -> str:
        source_scope = {
            name: {"enabled": bool(config.get("enabled", False))}
            for name, config in self.raw["sources"].items()
        }
        payload = {
            "scope_version": "r3-retrieval-v1",
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "research_question": self.raw["research_question"],
            "decision_scope": self.raw["decision_scope"],
            "languages": self.raw["languages"],
            "time_policy": self.raw["time_policy"],
            "sources": source_scope,
            "hosted_official_domains": self.raw["hosted_search"]["official_domains"],
            "queries": self.raw["queries"],
            "admission": self.raw["admission"],
        }
        if "intake" in self.raw:
            payload["intake"] = self.raw["intake"]
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @property
    def analysis_policy_hash(self) -> str:
        schema_hashes = {
            name: analysis_schema_policy_record(
                self.project_dir,
                name,
            )["policy_sha256"]
            for name in (
                "chunk_analysis.schema.json",
                "synthesis_reduce.schema.json",
                "synthesis.schema.json",
            )
        }
        analysis = self.raw["analysis"]
        codex = analysis["codex_cli"]
        llama = analysis["llama_cpp"]
        payload = {
            "scope_version": "r3-analysis-v2",
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "research_question": self.raw["research_question"],
            "decision_scope": self.raw["decision_scope"],
            "documents": {
                "chunk_characters": self.raw["documents"]["chunk_characters"],
                "chunk_overlap_characters": self.raw["documents"][
                    "chunk_overlap_characters"
                ],
            },
            "prompt_version": analysis["prompt_version"],
            "batch_chunk_count": analysis["batch_chunk_count"],
            "synthesis_group_max_items": analysis["synthesis_group_max_items"],
            "synthesis_input_character_budget": analysis[
                "synthesis_input_character_budget"
            ],
            "primary_provider": analysis["primary_provider"],
            "fallback_provider": analysis["fallback_provider"],
            "codex_model": str(codex.get("model") or "codex_configured_default"),
            "llama": {
                "model": llama["model"],
                "temperature": llama["temperature"],
                "chunk_max_tokens": llama["chunk_max_tokens"],
                "synthesis_max_tokens": llama["synthesis_max_tokens"],
            },
            "schemas": schema_hashes,
            "ranking_policy_version": "r3-ranking-v1",
        }
        if "auto_publish_providers" in analysis:
            payload["auto_publish_providers"] = sorted(
                str(value) for value in analysis["auto_publish_providers"]
            )
        if "output_detail" in analysis:
            payload["output_detail"] = str(analysis["output_detail"])
        if "reasoning_effort" in codex:
            payload["codex_reasoning_effort"] = str(codex["reasoning_effort"])
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @property
    def max_runtime_seconds(self) -> int:
        return int(self.raw["run"]["max_runtime_seconds"])

    def ensure_directories(self) -> None:
        for path in (self.data_dir, self.literature_dir, self.outputs_dir):
            path.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "repositories").mkdir(parents=True, exist_ok=True)
        (self.literature_dir / "documents").mkdir(parents=True, exist_ok=True)
        (self.literature_dir / "quarantine" / "pdf").mkdir(
            parents=True,
            exist_ok=True,
        )
        (self.literature_dir / "text").mkdir(parents=True, exist_ok=True)


def _resolve_workspace_path(workspace: Path, value: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    return candidate.resolve()


def _configured_workspace_dir(
    raw: dict[str, Any],
    *,
    config_path: Path | None = None,
) -> Path:
    """Resolve an explicit standalone workspace without breaking legacy layouts."""

    value = raw.get("workspace_root")
    if value is None:
        return WORKSPACE_DIR
    if not isinstance(value, str) or not value.strip():
        raise ValueError("workspace_root must be a non-empty path string")
    candidate = Path(value)
    if not candidate.is_absolute():
        base = config_path.parent if config_path is not None else PROJECT_DIR
        candidate = base / candidate
    return candidate.resolve()


def _validate_pdf_parser_config(raw: dict[str, Any]) -> None:
    value = raw.get("pdf_parser")
    if not isinstance(value, dict) or set(value) != _PDF_PARSER_KEYS:
        raise ValueError("pdf_parser must match the required configuration schema")
    if value.get("backend") != "pypdf_worker":
        raise ValueError("unsupported pdf_parser backend")
    if value.get("policy_version") != "r3-pdf-text-v1":
        raise ValueError("unsupported pdf_parser policy_version")
    for key in _PDF_PARSER_KEYS - {"backend", "policy_version"}:
        item = value.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise ValueError(f"pdf_parser.{key} must be a positive integer")
    documents = raw.get("documents")
    if not isinstance(documents, dict):
        raise ValueError("documents must be an object")
    max_download_bytes = documents.get("max_download_bytes")
    if (
        isinstance(max_download_bytes, bool)
        or not isinstance(max_download_bytes, int)
        or max_download_bytes <= 0
    ):
        raise ValueError("documents.max_download_bytes must be a positive integer")
    if int(value["max_input_bytes"]) > max_download_bytes:
        raise ValueError(
            "pdf_parser.max_input_bytes cannot exceed documents.max_download_bytes"
        )
    if int(value["wall_timeout_seconds"]) > 600:
        raise ValueError("pdf_parser.wall_timeout_seconds cannot exceed 600")


def _validate_repository_corpus_config(raw: dict[str, Any]) -> None:
    documents = raw.get("documents")
    if not isinstance(documents, dict):
        raise ValueError("documents must be an object")
    selection = documents.get("repository_corpus")
    if selection is None:
        return
    required_keys = {
        "mode",
        "max_selected_text_bytes",
        "max_auxiliary_text_bytes",
    }
    if not isinstance(selection, dict) or set(selection) != required_keys:
        raise ValueError(
            "documents.repository_corpus must contain mode, "
            "max_selected_text_bytes, and max_auxiliary_text_bytes"
        )
    if selection.get("mode") != "core_plus_sampled_aux_v1":
        raise ValueError("unsupported documents.repository_corpus.mode")
    for key in required_keys - {"mode"}:
        value = selection.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(
                f"documents.repository_corpus.{key} must be a positive integer"
            )
    selected = int(selection["max_selected_text_bytes"])
    auxiliary = int(selection["max_auxiliary_text_bytes"])
    repository_limit = documents.get("max_repository_text_bytes")
    if (
        isinstance(repository_limit, bool)
        or not isinstance(repository_limit, int)
        or repository_limit <= 0
    ):
        raise ValueError(
            "documents.max_repository_text_bytes must be a positive integer"
        )
    if auxiliary >= selected:
        raise ValueError(
            "repository auxiliary text budget must be smaller than "
            "selected text budget"
        )
    if selected > repository_limit:
        raise ValueError(
            "repository selected text budget cannot exceed "
            "documents.max_repository_text_bytes"
        )


def _validate_run_resource_config(raw: dict[str, Any]) -> None:
    run = raw.get("run")
    if not isinstance(run, dict):
        raise ValueError("run must be an object")
    for key in _RUN_RESOURCE_KEYS:
        if key not in run:
            continue
        value = run.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"run.{key} must be a positive integer")


def _validate_optional_intake_config(raw: dict[str, Any]) -> None:
    intake = raw.get("intake")
    if intake is None:
        return
    if not isinstance(intake, dict) or not isinstance(intake.get("weekly"), dict):
        raise ValueError("intake.weekly must be an object")
    state = intake["weekly"].get("state")
    if state not in {"proposed", "active"}:
        raise ValueError("intake.weekly.state must be proposed or active")
    from .intake import WeeklyIntakePolicy

    validation_raw = json.loads(canonical_json(raw))
    validation_raw["intake"]["weekly"]["state"] = "active"
    WeeklyIntakePolicy.from_config(validation_raw)


def _validate_auto_publish_providers(
    raw: dict[str, Any],
    *,
    config_path: Path,
) -> None:
    analysis = raw.get("analysis")
    if not isinstance(analysis, dict):
        return
    providers = analysis.get("auto_publish_providers")
    if providers is None:
        return
    if (
        not isinstance(providers, list)
        or not providers
        or any(
            not isinstance(value, str)
            or value not in {"codex_cli", "llama_cpp"}
            for value in providers
        )
        or len(set(providers)) != len(providers)
    ):
        raise ValueError(
            "analysis.auto_publish_providers must be a unique non-empty provider list"
        )
    if "llama_cpp" in providers:
        calibration = analysis.get("llama_publication_calibration")
        if (
            not isinstance(calibration, dict)
            or calibration.get("accepted") is not True
            or not _is_sha256(calibration.get("evidence_sha256"))
        ):
            raise ValueError(
                "llama_cpp automatic publication requires accepted calibration evidence"
            )
        evidence_path_value = calibration.get("evidence_path")
        if evidence_path_value is not None:
            if not isinstance(evidence_path_value, str) or not evidence_path_value.strip():
                raise ValueError("llama calibration evidence_path must be a file path")
            evidence_path = Path(evidence_path_value)
            if not evidence_path.is_absolute():
                evidence_path = config_path.parent / evidence_path
            try:
                evidence_bytes = evidence_path.resolve().read_bytes()
            except OSError as exc:
                raise ValueError("llama calibration evidence file is unavailable") from exc
            if hashlib.sha256(evidence_bytes).hexdigest() != str(
                calibration["evidence_sha256"]
            ).casefold():
                raise ValueError("llama calibration evidence SHA-256 mismatch")


def _validate_analysis_execution_config(raw: dict[str, Any]) -> None:
    analysis = raw.get("analysis")
    if not isinstance(analysis, dict):
        raise ValueError("analysis must be an object")
    parallel = analysis.get("max_parallel_batches", 1)
    if (
        isinstance(parallel, bool)
        or not isinstance(parallel, int)
        or not 1 <= parallel <= 2
    ):
        raise ValueError("analysis.max_parallel_batches must be one or two")
    codex = analysis.get("codex_cli")
    if not isinstance(codex, dict):
        raise ValueError("analysis.codex_cli must be an object")
    reasoning_effort = codex.get("reasoning_effort")
    if reasoning_effort is not None and reasoning_effort not in {
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
        "ultra",
    }:
        raise ValueError(
            "analysis.codex_cli.reasoning_effort must be low, medium, high, "
            "xhigh, max, or ultra"
        )
    planning = analysis.get("budget_planning")
    if planning is not None:
        if not isinstance(planning, dict) or set(planning) != {
            "retry_reserve_invocations"
        }:
            raise ValueError(
                "analysis.budget_planning must contain only "
                "retry_reserve_invocations"
            )
        reserve = planning.get("retry_reserve_invocations")
        if (
            isinstance(reserve, bool)
            or not isinstance(reserve, int)
            or not 0 <= reserve <= 100
        ):
            raise ValueError(
                "analysis.budget_planning.retry_reserve_invocations must be "
                "an integer from zero to 100"
            )
    output_detail = analysis.get("output_detail")
    if output_detail is not None and output_detail not in {
        "full",
        "concise_evidence",
    }:
        raise ValueError(
            "analysis.output_detail must be full or concise_evidence"
        )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in string.hexdigits for character in value)
    )


def profile_activation_state(raw: dict[str, Any]) -> str:
    """Return the production activation state without mutating the profile."""

    try:
        version = int(raw.get("profile_version", 1))
    except (TypeError, ValueError):
        return "invalid"
    if version < 2:
        return "legacy"
    intake = raw.get("intake")
    weekly = intake.get("weekly") if isinstance(intake, dict) else None
    if not isinstance(weekly, dict):
        return "proposed"
    state = weekly.get("state")
    return str(state) if state in {"proposed", "active"} else "invalid"


def _validate_active_profile_receipt(
    raw: dict[str, Any],
    *,
    config_path: Path,
) -> None:
    activation = raw.get("profile_activation")
    if not isinstance(activation, dict) or activation.get("state") != "active":
        raise ProfileActivationError(
            "active profile-v2 requires profile_activation.state=active"
        )

    confirmation = activation.get("user_confirmation")
    if (
        not isinstance(confirmation, dict)
        or confirmation.get("confirmed") is not True
        or confirmation.get("confirmed_by") != "user"
        or not isinstance(confirmation.get("confirmed_at"), str)
        or not str(confirmation["confirmed_at"]).strip()
        or confirmation.get("profile_id") != raw.get("profile_id")
        or confirmation.get("profile_version") != raw.get("profile_version")
    ):
        raise ProfileActivationError(
            "active profile-v2 requires explicit user confirmation bound to "
            "the exact profile id and version"
        )

    reference = activation.get("gold_evaluation_receipt")
    capacity_source_run_id = (
        raw.get("intake", {})
        .get("weekly", {})
        .get("capacity_basis", {})
        .get("source_run_id")
    )
    candidate_settings_hashes = (
        reference.get("candidate_settings_hashes")
        if isinstance(reference, dict)
        else None
    )
    if (
        not isinstance(reference, dict)
        or not isinstance(reference.get("path"), str)
        or not str(reference["path"]).strip()
        or not _is_sha256(reference.get("sha256"))
        or not isinstance(capacity_source_run_id, str)
        or not capacity_source_run_id
        or reference.get("capacity_source_run_id") != capacity_source_run_id
        or not isinstance(reference.get("gold_source_run_id"), str)
        or not str(reference["gold_source_run_id"]).strip()
        or not isinstance(reference.get("candidate_run_id"), str)
        or not str(reference["candidate_run_id"]).strip()
        or reference["candidate_run_id"] == reference["gold_source_run_id"]
        or not isinstance(candidate_settings_hashes, dict)
        or set(candidate_settings_hashes)
        != {"config_hash", "retrieval_hash", "analysis_policy_hash"}
        or any(not _is_sha256(value) for value in candidate_settings_hashes.values())
    ):
        raise ProfileActivationError(
            "active profile-v2 requires a path, SHA-256, capacity source, "
            "Gold source, independent candidate run and candidate-settings "
            "hash bound Gold evaluation receipt"
        )
    receipt_path = Path(str(reference["path"]))
    if not receipt_path.is_absolute():
        receipt_path = config_path.parent / receipt_path
    receipt_path = receipt_path.resolve()
    try:
        receipt_bytes = receipt_path.read_bytes()
    except OSError as exc:
        raise ProfileActivationError(
            f"Gold evaluation receipt is unavailable: {receipt_path}"
        ) from exc
    actual_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    if actual_sha256 != str(reference["sha256"]).casefold():
        raise ProfileActivationError("Gold evaluation receipt SHA-256 mismatch")
    try:
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileActivationError(
            "Gold evaluation receipt must be valid UTF-8 JSON"
        ) from exc
    candidate_identity = (
        receipt.get("candidate_run_identity")
        if isinstance(receipt, dict)
        else None
    )
    if (
        not isinstance(receipt, dict)
        or receipt.get("schema") != "r3/gold-set-evaluation/v1"
        or receipt.get("status") != "evaluated"
        or receipt.get("passed") is not True
        or receipt.get("unlabeled_count") != 0
        or not _is_sha256(receipt.get("gold_set_sha256"))
        or not isinstance(receipt.get("candidate_run_id"), str)
        or not str(receipt["candidate_run_id"]).strip()
        or receipt.get("gold_source_run_id") != reference["gold_source_run_id"]
        or receipt.get("candidate_run_id") != reference["candidate_run_id"]
        or receipt.get("candidate_settings_hashes") != candidate_settings_hashes
        or not isinstance(candidate_identity, dict)
        or set(candidate_identity)
        != {
            "profile_id",
            "profile_version",
            "config_hash",
            "retrieval_hash",
            "analysis_policy_hash",
        }
        or candidate_identity.get("profile_id") != raw.get("profile_id")
        or candidate_identity.get("profile_version") != raw.get("profile_version")
        or any(
            candidate_identity.get(field) != candidate_settings_hashes[field]
            for field in (
                "config_hash",
                "retrieval_hash",
                "analysis_policy_hash",
            )
        )
    ):
        raise ProfileActivationError(
            "Gold evaluation receipt must be complete, human-labeled and passing"
        )
    try:
        recall = float(receipt["recall_at_candidate"])
        threshold = float(receipt["threshold"])
        item_count = int(receipt["item_count"])
        known_important = int(receipt["known_important_count"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileActivationError(
            "Gold evaluation receipt metrics are missing or invalid"
        ) from exc
    if (
        not 50 <= item_count <= 80
        or known_important <= 0
        or threshold < 0.90
        or recall < threshold
    ):
        raise ProfileActivationError(
            "Gold evaluation receipt does not meet the activation thresholds"
        )


def require_profile_production_activation(
    settings: Settings,
    operation: str,
) -> None:
    """Fail closed before a production run or publication path is entered."""

    if operation not in PRODUCTION_PROFILE_OPERATIONS:
        return
    state = profile_activation_state(settings.raw)
    if state == "legacy":
        return
    if state != "active":
        raise ProfileActivationError(
            f"profile-v2 is {state}; {operation} requires explicit activation "
            "after a passing human Gold evaluation"
        )
    _validate_active_profile_receipt(
        settings.raw,
        config_path=settings.config_path,
    )


def load_settings(config_path: str | Path | None = None) -> Settings:
    path = Path(config_path or os.getenv("R3_RADAR_CONFIG") or DEFAULT_CONFIG).resolve()
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise ValueError("unsupported config schema_version")
    _validate_pdf_parser_config(raw)
    _validate_repository_corpus_config(raw)
    _validate_run_resource_config(raw)
    _validate_optional_intake_config(raw)
    _validate_auto_publish_providers(raw, config_path=path)
    _validate_analysis_execution_config(raw)
    workspace_dir = _configured_workspace_dir(raw, config_path=path)
    paths = raw.get("paths") or {}
    data_dir = _resolve_workspace_path(workspace_dir, str(paths["data"]))
    literature_dir = _resolve_workspace_path(
        workspace_dir,
        str(paths["literature"]),
    )
    outputs_dir = _resolve_workspace_path(workspace_dir, str(paths["outputs"]))
    for candidate in (data_dir, literature_dir, outputs_dir):
        try:
            candidate.relative_to(workspace_dir)
        except ValueError as exc:
            raise ValueError(f"configured path escapes workspace: {candidate}") from exc
    settings = Settings(
        raw=raw,
        config_path=path,
        project_dir=PROJECT_DIR,
        workspace_dir=workspace_dir,
        data_dir=data_dir,
        literature_dir=literature_dir,
        outputs_dir=outputs_dir,
        database_path=data_dir / "radar.sqlite3",
    )
    if profile_activation_state(raw) == "active":
        _validate_active_profile_receipt(
            raw,
            config_path=path,
        )
    settings.ensure_directories()
    return settings
