from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from r3radar.config import canonical_json
from r3radar.document_policy import CURRENT_PDF_DOCUMENT_POLICY
from r3radar.storage import RadarStore
from r3radar.utils import sha256_text


FIXTURE_SCHEMA = "r3/synthetic-realistic-research-workflows/v1"
FIXTURE_SEED = 20260810
SYNTHETIC_NOTICE = (
    "SYNTHETIC-REALISTIC TEST DATA: this record is not a real publication, "
    "repository, clinical claim, DOI, citation, or model result."
)


@dataclass(frozen=True)
class DomainTemplate:
    key: str
    display_name: str
    research_question: str
    decision: str
    boundary: str
    methods: tuple[str, ...]


DOMAINS = (
    DomainTemplate(
        key="workflow_cache_kv",
        display_name="Agent workflow cache / KV serving",
        research_question=(
            "在多步 Agent workflow 中，workflow 语义与上下文信息能否比 recency、"
            "frequency 等无语义 heuristic 更准确地预测短生命周期 cache object 的未来复用价值？"
        ),
        decision=(
            "决定是否把 workflow-state feature 加入单一 retention/eviction policy，"
            "并以 future-window reuse、tail latency、policy regret 与显存占用共同判定。"
        ),
        boundary=(
            "不得把 prefix hit rate 当作未来复用价值；必须区分 KV block、prefix、session、"
            "tool result cache 与 application object，并固定预测窗口和驱逐动作。"
        ),
        methods=(
            "trace replay with step-labelled agent trajectories",
            "recency/frequency/size/cost matched ablation",
            "single-decision retention or eviction policy",
            "future-window reuse and policy-regret evaluation",
        ),
    ),
    DomainTemplate(
        key="elder_companion_hri",
        display_name="Older-adult companion embodied AI / HRI",
        research_question=(
            "具身陪伴 Agent 在不同认知、感官与居住条件的老年人中，何时能改善持续互动，"
            "何时会增加依赖、隐私或误导风险？"
        ),
        decision=(
            "决定某项交互机制是否值得进入共创访谈或小规模部署，并保留人群、环境、时长、"
            "对照、照护者介入和退出机制。"
        ),
        boundary=(
            "不得从短期健康志愿者外推到认知障碍或独居人群；接受度不等于临床获益，"
            "实验室演示不等于家庭长期部署。"
        ),
        methods=(
            "participatory design with older adults and caregivers",
            "home versus laboratory deployment comparison",
            "longitudinal adherence and correction logging",
            "privacy, dependency and wrong-person recall audit",
        ),
    ),
    DomainTemplate(
        key="developer_agent_systems",
        display_name="Developer research agents / software systems",
        research_question=(
            "面向真实代码库的研究 Agent 能否在冻结 revision 上形成可复现的 claim-to-evidence 链，"
            "并在依赖、测试和许可证边界内交付 non-executable handoff？"
        ),
        decision=(
            "决定项目是否进入复现队列、只作机制借鉴或明确排除；核对 commit、环境、指标、"
            "issue 活跃度和 supply-chain 风险。"
        ),
        boundary=(
            "README 声明、星标和一次通过的 demo 不能替代冻结 commit 的实现核验；"
            "同名模块、漂移分支和未锁定依赖必须显式暴露。"
        ),
        methods=(
            "immutable revision and dependency inventory",
            "claim-to-file-and-line evidence mapping",
            "known-answer reproduction task",
            "failure recovery and non-executing export validation",
        ),
    ),
    DomainTemplate(
        key="clinical_bioinformatics",
        display_name="Clinical / bioinformatics evidence workflow",
        research_question=(
            "一个生物标志物或分析管线的报告性能能否在独立队列、不同平台和预先定义终点下复现，"
            "并足以改变下一步研究设计？"
        ),
        decision=(
            "决定是否进入外部验证、方法对照或排除；记录队列纳排、样本量、缺失值、"
            "reference standard、批次效应与数据可用性。"
        ),
        boundary=(
            "本夹具不提供医疗建议；单队列回顾性相关、训练集交叉验证和缺失亚组信息"
            "不得被表述为临床有效性或普适结论。"
        ),
        methods=(
            "pre-specified cohort inclusion and exclusion criteria",
            "external validation with platform-shift analysis",
            "calibration, discrimination and subgroup reporting",
            "dataset and analysis-version provenance audit",
        ),
    ),
)


@dataclass(frozen=True)
class SyntheticFixtureManifest:
    schema: str
    seed: int
    requested_count: int
    inserted_count: int
    domain_counts: dict[str, int]
    kind_counts: dict[str, int]
    lifecycle_counts: dict[str, int]
    analysis_count: int
    feedback_count: int
    decision_count: int
    near_duplicate_count: int
    version_drift_count: int
    missing_full_text_count: int
    retry_count: int
    total_abstract_characters: int
    total_analysis_characters: int
    fixture_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "seed": self.seed,
            "requested_count": self.requested_count,
            "inserted_count": self.inserted_count,
            "domain_counts": self.domain_counts,
            "kind_counts": self.kind_counts,
            "lifecycle_counts": self.lifecycle_counts,
            "analysis_count": self.analysis_count,
            "feedback_count": self.feedback_count,
            "decision_count": self.decision_count,
            "near_duplicate_count": self.near_duplicate_count,
            "version_drift_count": self.version_drift_count,
            "missing_full_text_count": self.missing_full_text_count,
            "retry_count": self.retry_count,
            "total_abstract_characters": self.total_abstract_characters,
            "total_analysis_characters": self.total_analysis_characters,
            "fixture_sha256": self.fixture_sha256,
        }


def _json(value: Any) -> str:
    return canonical_json(value)


def _stable_hex(*parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode("utf-8")).hexdigest()


def _paper_coverage() -> dict[str, Any]:
    parser = CURRENT_PDF_DOCUMENT_POLICY["parser"]
    protocol = CURRENT_PDF_DOCUMENT_POLICY["protocol"]
    code = CURRENT_PDF_DOCUMENT_POLICY["code"]
    return {
        "complete": True,
        "coverage_type": "text_layer",
        "security_status": "parsed_verified",
        "reason": None,
        "failure_code": None,
        "parser": {
            "id": parser["id"],
            "version": parser["version"],
            "policy_version": parser["policy_version"],
            "effective_options": parser["effective_options"],
            "request_schema": protocol["request_schema"],
            "result_schema": protocol["result_schema"],
            "isolation": {
                "integrity_level": "appcontainer_low",
                "credential_environment_keys": [],
            },
        },
        "parser_receipt": {
            "parser_id": parser["id"],
            "parser_version": parser["version"],
            "parser_policy_version": parser["policy_version"],
            "request_schema": protocol["request_schema"],
            "result_schema": protocol["result_schema"],
            "worker_sha256": code["worker_sha256"],
            "sandbox_sha256": code["sandbox_sha256"],
            "return_code": 0,
            "termination": "process_exit",
        },
    }


def _abstract(domain: DomainTemplate, index: int, kind: str) -> str:
    paragraphs = (
        f"研究问题：{domain.research_question}",
        f"决策用途：{domain.decision}",
        "研究设计：本测试记录模拟一项完整研究输入，包含背景、对象、比较条件、可观察终点、"
        f"失效条件和可追溯版本。候选类型为 {kind}，场景编号为 {index:04d}。",
        "方法链：" + "；".join(domain.methods) + "。",
        "预期证据：主结果、负结果、亚组、资源成本、数据缺失、复现环境与时间窗口必须分开记录；"
        "搜索命中、摘要相关或项目热度都不能被当作最终证据。",
        f"外推边界：{domain.boundary}",
        "状态链：发现 → 身份归一化 → 近重复核验 → 全文或冻结 revision 获取 → 深读 → "
        "证据门 → 研究动作 → 后验复核。任一阶段失败时保留失败码、重试时间和排除理由。",
        "数据声明：" + SYNTHETIC_NOTICE,
    )
    # Three passes create an abstract comparable to a long structured abstract or
    # repository research note, while each pass has a distinct audit purpose.
    return "\n\n".join(
        paragraphs
        + tuple(
            f"审计补充 {pass_index + 1}：{paragraph}"
            for pass_index, paragraph in enumerate(paragraphs[:7])
        )
        + tuple(
            f"复核视角 {pass_index + 1}：{paragraph}"
            for pass_index, paragraph in enumerate(paragraphs[1:6])
        )
    )


def _analysis(domain: DomainTemplate, index: int, kind: str) -> dict[str, Any]:
    anchors = []
    for anchor_index, method in enumerate(domain.methods * 2, start=1):
        anchors.append(
            {
                "anchor": f"SYNTHETIC SECTION {anchor_index}: {domain.key}",
                "claim_zh": (
                    f"合成证据 {anchor_index} 只用于检验 {domain.display_name} 工作流中的"
                    f"结构化展示、分页与按需加载；它不是现实研究结论。"
                ),
                "excerpt": (
                    f"{SYNTHETIC_NOTICE} Method under test: {method}. "
                    f"The observable decision is: {domain.decision} "
                    f"The no-extrapolation boundary is: {domain.boundary} "
                    "A valid reader must keep null fields unknown, distinguish discovery from "
                    "evidence, and retain the frozen input identity across feedback and export."
                ),
                "excerpt_match_method": "synthetic_exact_fixture",
            }
        )
    return {
        "schema": "r3/synthetic-analysis/v1",
        "synthetic_realistic": True,
        "citation_status": "not_a_real_citation",
        "summary_zh": (
            f"[合成测试，非真实结论] {domain.display_name} 场景 {index:04d}。"
            f"该条目用于回答：{domain.research_question}"
        ),
        "r3_relationship": [domain.decision, domain.boundary],
        "methods": list(domain.methods),
        "evaluation": [
            "固定输入身份后比较候选排序、证据完整性、人工核验负担与后验研究动作。",
            "对同一数据库重复请求并比较有序 ID、响应摘要哈希、p50/p95 与载荷大小。",
            "对缺失全文、重试、版本漂移和近重复分别保留可观察状态，不用模型填补未知项。",
        ],
        "limitations": [
            domain.boundary,
            "synthetic-realistic fixture 只能验证工程鲁棒性，不能证明检索召回率、科研价值或临床有效性。",
        ],
        "actionable_ideas": [
            "只在冻结证据上保存研究动作。",
            "将详情延迟到用户展开时加载。",
            "未来周期价值必须由真实后验复核，而不是同日模拟。",
        ],
        "evidence_anchors": anchors,
        "workflow_state": {
            "question": domain.research_question,
            "object_kind": kind,
            "future_window": "explicit_but_synthetic",
            "decision": domain.decision,
            "unknowns": ["external_validity", "future_usefulness", "human_gold_label"],
        },
    }


def _lifecycle(index: int) -> str:
    selector = index % 16
    if selector <= 8 or selector == 15:
        return "analyzed"
    if selector in (9, 10):
        return "analysis_running"
    if selector in (11, 12):
        return "analysis_retry"
    if selector == 13:
        return "missing_full_text"
    return "version_drift"


def seed_synthetic_research_workflows(
    settings: Any,
    *,
    count: int,
    seed: int = FIXTURE_SEED,
) -> SyntheticFixtureManifest:
    """Seed one deterministic UI/storage load without network or model calls.

    The generated records are deliberately realistic in length and lifecycle
    variety, but every identity and claim is visibly synthetic. The fixture is
    appropriate for storage/API/UI scale tests, not retrieval-quality claims.
    """
    if count < 1 or count > 5000:
        raise ValueError("count must be between 1 and 5000")

    base_time = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)
    domain_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    lifecycle_counts: Counter[str] = Counter()
    total_abstract_characters = 0
    total_analysis_characters = 0
    analysis_count = 0
    feedback_count = 0
    decision_count = 0
    near_duplicate_count = 0
    version_drift_count = 0
    missing_full_text_count = 0
    retry_count = 0
    fingerprint_rows: list[dict[str, Any]] = []

    with RadarStore(settings.database_path) as store:
        with store.transaction() as connection:
            issue_id = f"synthetic-realistic-{seed}-{count}"
            connection.execute(
                """
                INSERT INTO report_issues(
                    issue_id, run_id, publication_key, retrieval_hash,
                    analysis_policy_hash, generated_at, output_dir, report_path,
                    selection_path, counts_json
                ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    issue_id,
                    f"synthetic-realistic:{seed}:{count}",
                    settings.retrieval_hash,
                    settings.analysis_policy_hash,
                    base_time.isoformat(),
                    "synthetic://outputs",
                    "synthetic://report.md",
                    "synthetic://selection.json",
                    _json({"synthetic_realistic": True, "count": count}),
                ),
            )

            for index in range(count):
                domain = DOMAINS[index % len(DOMAINS)]
                pair_index = index // 2
                kind = "paper" if index % 2 == 0 else "repository"
                lifecycle = _lifecycle(index)
                observed_at = (base_time + timedelta(minutes=index)).isoformat()
                shared_stem = (
                    f"[SYNTHETIC] {domain.display_name}: decision study {pair_index:04d}"
                )
                title = (
                    f"{shared_stem} — empirical paper"
                    if kind == "paper"
                    else f"{shared_stem} — frozen implementation"
                )
                normalized_title = shared_stem.casefold()
                duplicate_group = None
                if index > 0 and index % 13 == 0:
                    duplicate_group = f"near-duplicate-{index // 13:03d}"
                    normalized_title = (
                        f"[synthetic] {domain.display_name}: decision study "
                        f"{max(0, (index - 4) // 2):04d}"
                    ).casefold()
                    near_duplicate_count += 1

                abstract = _abstract(domain, index, kind)
                total_abstract_characters += len(abstract)
                commit_sha = _stable_hex(seed, "commit", pair_index)[:40]
                metadata = {
                    "schema": FIXTURE_SCHEMA,
                    "synthetic_realistic": True,
                    "notice": SYNTHETIC_NOTICE,
                    "fixture_seed": seed,
                    "fixture_index": index,
                    "domain": domain.key,
                    "research_question": domain.research_question,
                    "abstract": abstract,
                    "duplicate_group": duplicate_group,
                    "paired_topic": pair_index,
                    "frozen_revision": commit_sha if kind == "repository" else None,
                    "future_usefulness": None,
                    "human_gold_label": None,
                }
                canonical_key = f"synthetic-realistic:{seed}:{index:05d}"
                work_row = connection.execute(
                    """
                    INSERT INTO works(
                        canonical_key, kind, title, normalized_title, year,
                        github_full_name, best_url, lane, state, admission_code,
                        metadata_json, first_seen_at, updated_at
                    ) VALUES (?, ?, ?, ?, 2026, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        canonical_key,
                        kind,
                        title,
                        normalized_title,
                        (
                            f"synthetic-fixture/{domain.key}-{pair_index:04d}"
                            if kind == "repository"
                            else None
                        ),
                        f"https://example.invalid/r3-fixture/{seed}/{index}",
                        "core" if index % 5 else "exploration",
                        "analyzed" if lifecycle in {"analyzed", "version_drift"} else (
                            "analysis_running" if lifecycle == "analysis_running" else (
                                "analysis_pending" if lifecycle == "analysis_retry" else "content_unavailable"
                            )
                        ),
                        "synthetic_fixture_only",
                        _json(metadata),
                        observed_at,
                        observed_at,
                    ),
                )
                work_id = int(work_row.lastrowid)
                scope_state = {
                    "analyzed": "analyzed",
                    "analysis_running": "analysis_running",
                    "analysis_retry": "analysis_pending",
                    "missing_full_text": "content_unavailable",
                    "version_drift": "analyzed",
                }[lifecycle]
                connection.execute(
                    """
                    INSERT INTO work_scopes(
                        work_id, config_hash, profile_id, profile_version,
                        lane, state, admission_code, last_error,
                        first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        work_id,
                        settings.retrieval_hash,
                        settings.profile_id,
                        settings.profile_version,
                        "core" if index % 5 else "exploration",
                        scope_state,
                        "synthetic_fixture_only",
                        (
                            "synthetic upstream unavailable; retry retained"
                            if lifecycle == "analysis_retry"
                            else (
                                "synthetic full text intentionally missing"
                                if lifecycle == "missing_full_text"
                                else None
                            )
                        ),
                        observed_at,
                        observed_at,
                    ),
                )

                source = "openalex" if kind == "paper" else "github"
                source_row = connection.execute(
                    """
                    INSERT INTO source_records(
                        source, source_id, kind, title, canonical_url,
                        metadata_json, raw_sha256, first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source,
                        f"synthetic:{seed}:{index}",
                        kind,
                        title,
                        f"https://example.invalid/r3-fixture/{seed}/{index}",
                        _json(metadata),
                        sha256_text(abstract),
                        observed_at,
                        observed_at,
                    ),
                )
                connection.execute(
                    "INSERT INTO work_sources(work_id, source_record_id) VALUES (?, ?)",
                    (work_id, int(source_row.lastrowid)),
                )

                content_kind = "paper_pdf" if kind == "paper" else "repository_zip"
                document_status = "failed" if lifecycle == "missing_full_text" else "ready"
                coverage = (
                    {
                        "complete": False,
                        "reason": "synthetic_missing_full_text",
                        "security_status": "not_processed",
                    }
                    if document_status == "failed"
                    else (
                        _paper_coverage()
                        if kind == "paper"
                        else {
                            "complete": True,
                            "coverage_scope": "legacy_all_eligible",
                            "reason": None,
                            "security_status": "archive_validated",
                        }
                    )
                )
                document_text = abstract + "\n\n" + SYNTHETIC_NOTICE
                current_text_sha = sha256_text(document_text)
                document_row = connection.execute(
                    """
                    INSERT INTO documents(
                        work_id, content_kind, status, source_url, text_path,
                        content_sha256, text_sha256, byte_count,
                        text_char_count, page_count, document_policy_hash,
                        coverage_json, error, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        work_id,
                        content_kind,
                        document_status,
                        f"https://example.invalid/r3-fixture/{seed}/{index}/content",
                        f"synthetic://fixture/{seed}/{index}.txt",
                        _stable_hex(seed, "content", index),
                        current_text_sha,
                        len(document_text.encode("utf-8")),
                        len(document_text),
                        12 + index % 30 if kind == "paper" else None,
                        store.document_policy_hash if kind == "paper" else None,
                        _json(coverage),
                        (
                            "synthetic fixture: full text unavailable"
                            if document_status == "failed"
                            else None
                        ),
                        observed_at,
                        observed_at,
                    ),
                )
                document_id = int(document_row.lastrowid)

                analysis_id = None
                if lifecycle != "missing_full_text":
                    task_input_sha = (
                        _stable_hex(seed, "stale-input", index)
                        if lifecycle == "version_drift"
                        else current_text_sha
                    )
                    task_status = {
                        "analyzed": "completed",
                        "analysis_running": "running",
                        "analysis_retry": "retry",
                        "version_drift": "completed",
                    }[lifecycle]
                    task_row = connection.execute(
                        """
                        INSERT INTO analysis_tasks(
                            work_id, document_id, provider, prompt_version,
                            config_hash, retrieval_hash, profile_id,
                            profile_version, input_sha256, status, chunk_total,
                            chunk_done, phase, phase_done, phase_total, attempts,
                            started_at, updated_at, completed_at, error, not_before
                        ) VALUES (?, ?, 'deterministic_fixture', ?, ?, ?, ?, ?, ?, ?,
                                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            work_id,
                            document_id,
                            settings.raw["analysis"]["prompt_version"],
                            settings.analysis_policy_hash,
                            settings.retrieval_hash,
                            settings.profile_id,
                            settings.profile_version,
                            task_input_sha,
                            task_status,
                            36 + index % 48,
                            (36 + index % 48) if task_status == "completed" else index % 17,
                            "complete" if task_status == "completed" else "chunk_analysis",
                            1 if task_status == "completed" else index % 17,
                            1 if task_status == "completed" else 36 + index % 48,
                            2 if task_status == "retry" else 1,
                            observed_at,
                            observed_at,
                            observed_at if task_status == "completed" else None,
                            (
                                "synthetic retryable provider interruption"
                                if task_status == "retry"
                                else None
                            ),
                            (
                                (base_time + timedelta(days=1, minutes=index)).isoformat()
                                if task_status == "retry"
                                else None
                            ),
                        ),
                    )
                    task_id = int(task_row.lastrowid)
                    if task_status == "retry":
                        retry_count += 1
                    if task_status == "completed":
                        analysis = _analysis(domain, index, kind)
                        analysis_json = _json(analysis)
                        total_analysis_characters += len(analysis_json)
                        analysis_row = connection.execute(
                            """
                            INSERT INTO analyses(
                                task_id, work_id, provider, model, prompt_version,
                                config_hash, retrieval_hash, profile_id,
                                profile_version, deep_read_status, tier, score,
                                analysis_json, coverage_json,
                                provider_receipt_json, provenance_status, created_at
                            ) VALUES (?, ?, 'deterministic_fixture', 'no-model-call',
                                      ?, ?, ?, ?, ?, 'complete', ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                task_id,
                                work_id,
                                settings.raw["analysis"]["prompt_version"],
                                settings.analysis_policy_hash,
                                settings.retrieval_hash,
                                settings.profile_id,
                                settings.profile_version,
                                ("must_read", "important", "background")[index % 3],
                                round(97.0 - (index % 900) / 10.0, 1),
                                analysis_json,
                                _json(
                                    {
                                        "complete": True,
                                        "synthetic_realistic": True,
                                        "covered_sections": len(analysis["evidence_anchors"]),
                                    }
                                ),
                                _json(
                                    {
                                        "fixture": True,
                                        "model_call": False,
                                        "schema": FIXTURE_SCHEMA,
                                    }
                                ),
                                "synthetic_fixture_only",
                                observed_at,
                            ),
                        )
                        analysis_id = int(analysis_row.lastrowid)
                        analysis_count += 1

                if lifecycle == "version_drift":
                    version_drift_count += 1
                if lifecycle == "missing_full_text":
                    missing_full_text_count += 1

                if analysis_id is not None and lifecycle == "analyzed" and index % 7 == 0:
                    connection.execute(
                        """
                        INSERT INTO feedback(work_id, rating, comment, created_at)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            work_id,
                            "useful" if index % 14 == 0 else "not_useful",
                            "synthetic workflow feedback; not a human Gold label",
                            observed_at,
                        ),
                    )
                    feedback_count += 1

                if analysis_id is not None and lifecycle == "analyzed" and index % 11 == 0:
                    snapshot = {
                        "synthetic_realistic": True,
                        "work_id": work_id,
                        "analysis_id": analysis_id,
                        "title": title,
                        "input_sha256": current_text_sha,
                    }
                    snapshot_json = _json(snapshot)
                    snapshot_sha = sha256_text(snapshot_json)
                    connection.execute(
                        """
                        INSERT INTO report_issue_items(
                            issue_id, analysis_id, work_id, selection_bucket,
                            selected, input_sha256, snapshot_sha256, snapshot_json
                        ) VALUES (?, ?, ?, 'synthetic_pilot', 1, ?, ?, ?)
                        """,
                        (
                            issue_id,
                            analysis_id,
                            work_id,
                            current_text_sha,
                            snapshot_sha,
                            snapshot_json,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO research_decisions(
                            issue_id, analysis_id, work_id, input_sha256,
                            snapshot_sha256, action, reason, note,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            issue_id,
                            analysis_id,
                            work_id,
                            current_text_sha,
                            snapshot_sha,
                            ("reproduce", "read", "watch")[index % 3],
                            "synthetic decision used to exercise persistence and export states",
                            "not a human research decision",
                            observed_at,
                            observed_at,
                        ),
                    )
                    decision_count += 1

                if kind == "repository" and index > 0:
                    paper_work_id = work_id - 1
                    relation = {
                        "schema": "r3/synthetic-paper-repository-relation/v1",
                        "synthetic_realistic": True,
                        "paper_work_id": paper_work_id,
                        "repository_work_id": work_id,
                        "commit_sha": commit_sha,
                        "relation": "same synthetic research scenario",
                    }
                    relation_json = _json(relation)
                    connection.execute(
                        """
                        INSERT INTO paper_repository_relations(
                            paper_work_id, repository_work_id, commit_sha,
                            relation_sha256, relation_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            paper_work_id,
                            work_id,
                            commit_sha,
                            sha256_text(relation_json),
                            relation_json,
                            observed_at,
                        ),
                    )

                domain_counts[domain.key] += 1
                kind_counts[kind] += 1
                lifecycle_counts[lifecycle] += 1
                fingerprint_rows.append(
                    {
                        "index": index,
                        "canonical_key": canonical_key,
                        "domain": domain.key,
                        "kind": kind,
                        "lifecycle": lifecycle,
                        "title_sha256": sha256_text(title),
                        "abstract_sha256": sha256_text(abstract),
                    }
                )

    fingerprint = {
        "schema": FIXTURE_SCHEMA,
        "seed": seed,
        "count": count,
        "rows": fingerprint_rows,
    }
    return SyntheticFixtureManifest(
        schema=FIXTURE_SCHEMA,
        seed=seed,
        requested_count=count,
        inserted_count=count,
        domain_counts=dict(sorted(domain_counts.items())),
        kind_counts=dict(sorted(kind_counts.items())),
        lifecycle_counts=dict(sorted(lifecycle_counts.items())),
        analysis_count=analysis_count,
        feedback_count=feedback_count,
        decision_count=decision_count,
        near_duplicate_count=near_duplicate_count,
        version_drift_count=version_drift_count,
        missing_full_text_count=missing_full_text_count,
        retry_count=retry_count,
        total_abstract_characters=total_abstract_characters,
        total_analysis_characters=total_analysis_characters,
        fixture_sha256=sha256_text(_json(fingerprint)),
    )
