"use strict";

const labels = {
  raw_hits: "原始命中",
  unique_works: "去重后",
  admitted: "客观准入",
  rejected: "已拒绝",
  unverified: "待官方核验",
  deep_read: "当前策略深读",
  available_deep_read: "可查看深读",
  unavailable: "全文不可用",
  incomplete: "覆盖不完整",
  pending_content: "待取内容",
  pending_analysis: "待深读",
  analysis_failed: "深读失败",
};

const stateLabels = {
  admitted: "待取全文",
  analysis_failed: "深读失败",
  analysis_pending: "深读排队",
  analysis_running: "正在深读",
  analyzed: "已深读",
  content_incomplete: "覆盖不完整",
  content_ready: "全文已就绪",
  content_retry: "全文待重试",
  content_running: "正在获取全文",
  content_unavailable: "全文不可用",
  rejected: "已拒绝",
  verification_pending: "待官方核验",
};

const deepReadStateLabels = {
  attention: "需要处理",
  complete: "本批完成",
  idle: "暂无任务",
  loading: "载入中",
  paused: "已暂停",
  queued: "等待领取",
  running: "正在深读",
  stalled: "疑似停滞",
  unavailable: "状态不可用",
  waiting: "等待启动",
};

const deepReadPhaseLabels = {
  preparing: "准备全文",
  chunk_reading: "分块阅读",
  hierarchical_synthesis: "分层汇总",
  final_synthesis: "最终综合",
  complete: "完成",
};

const DEEP_READ_POLL_INTERVAL_MS = 15_000;

const contentReasonMessages = {
  empty_text_layer_pages: "部分页面没有可提取文字，尚未达到完整全文覆盖。",
  fetch_or_extract_error: "全文获取或解析失败，尚未完成全文核验。",
  insufficient_extractable_text:
    "可提取文字过少，可能是扫描版或缺少文字层，尚未达到完整全文覆盖。",
  no_pdf_url: "来源未提供可访问的全文 PDF，尚未完成全文核验。",
  page_extraction_errors: "部分页面解析失败，尚未达到完整全文覆盖。",
  pdf_extract_timeout:
    "PDF 已取得，但解析超过安全时限并已安全终止；该条目未进入深读。",
  pdf_extract_worker_failed:
    "PDF 已取得，但隔离解析进程未正常完成；该条目未进入深读。",
  pdf_security_reparse_required:
    "PDF 解析安全策略已升级，既有解析结果不再视为已核验；完成安全重解析前，该条目不进入深读。",
};

const contentFailureMessages = {
  cpu_time_limit: "PDF 隔离解析超过 CPU 安全上限并已终止；该条目未进入深读。",
  encrypted_pdf: "PDF 已取得，但文件加密且未提供密码；该条目未进入深读。",
  input_mismatch: "PDF 隔离副本的内容身份核验失败；该条目未进入深读。",
  invalid_pdf: "PDF 已取得，但文件结构无效或已损坏；该条目未进入深读。",
  limit_exceeded: "PDF 解析触及页数或输出安全上限并已停止；该条目未进入深读。",
  result_schema_invalid: "PDF 解析结果未通过父进程结构核验；该条目未进入深读。",
  sandbox_gate_unavailable: "PDF 隔离解析未能进入受控执行阶段并已终止；该条目未进入深读。",
  unsupported_parser_version: "PDF 解析器版本未通过安全基线核验；该条目未进入深读。",
  worker_nonzero_exit: "PDF 受限解析进程异常退出；该条目未进入深读。",
};

let allWorks = [];
let nextWorksCursor = null;
let decisionSlice = {
  issue: null,
  items: [],
  remaining_count: 0,
  publication_missing: false,
  analysis_policy_current: true,
};
let decisionExpanded = false;
let loadedWorksCount = 0;
let loadedWorksTotal = 0;
let fullRefreshInFlight = false;
let statusRefreshInFlight = false;
let refreshGeneration = 0;
let feedbackSubmissionsInFlight = 0;
let feedbackMutationGeneration = 0;
let fallbackProgressSignature = null;
let fallbackLastActivityMs = null;
let viewMode = "compact";

const DECISION_FOCUS_LIMIT = 3;
const decisionActionLabels = {
  save: "已保存",
  defer: "已暂缓",
  reject: "已排除",
  request_deep_read: "待补充深读",
};
const evidenceCache = new Map();
const sourceLabels = {
  arxiv: "arXiv",
  codex_web: "Codex Web",
  github: "GitHub",
  openalex: "OpenAlex",
};

function storedViewMode() {
  try {
    return window.localStorage.getItem("r3-view-mode") === "deep"
      ? "deep"
      : "compact";
  } catch (_error) {
    return "compact";
  }
}

function applyViewMode(mode, persist = true) {
  viewMode = mode === "deep" ? "deep" : "compact";
  document.body.dataset.viewMode = viewMode;
  const toggle = document.querySelector("#view-mode-toggle");
  const deep = viewMode === "deep";
  toggle.setAttribute("aria-pressed", String(deep));
  toggle.textContent = deep ? "切换精简视图" : "展开深度信息";
  if (persist) {
    try {
      window.localStorage.setItem("r3-view-mode", viewMode);
    } catch (_error) {
      // The dashboard remains usable when browser storage is disabled.
    }
  }
}

function retrievalSources(work) {
  return Array.isArray(work?.retrieval_sources)
    ? work.retrieval_sources.filter((source) => typeof source === "string")
    : [];
}

function sourceLabel(source) {
  return sourceLabels[source] || source;
}

function shortIdentifier(value) {
  const text = String(value || "");
  return text.length > 20
    ? `${text.slice(0, 12)}…${text.slice(-4)}`
    : text;
}

function populateSourceFilter() {
  const filter = document.querySelector("#source-filter");
  const previous = filter.value;
  const sources = [...new Set(allWorks.flatMap(retrievalSources))].sort();
  const allOption = document.createElement("option");
  allOption.value = "";
  allOption.textContent = "全部来源";
  const options = sources.map((source) => {
    const option = document.createElement("option");
    option.value = source;
    option.textContent = sourceLabel(source);
    return option;
  });
  filter.replaceChildren(allOption, ...options);
  filter.value = sources.includes(previous) ? previous : "";
}

function contentMessage(work) {
  if (work.content_reason === "pdf_extract_worker_failed") {
    return (
      contentFailureMessages[work.content_failure_code] ||
      contentReasonMessages.pdf_extract_worker_failed
    );
  }
  const knownMessage = contentReasonMessages[work.content_reason];
  if (knownMessage) return knownMessage;
  if (work.state === "content_incomplete") {
    return "内容覆盖未完成，该条目未进入深读。";
  }
  if (work.state === "content_unavailable") {
    return "全文当前不可用，尚未完成全文核验。";
  }
  return "";
}

function textNodeList(items) {
  const list = document.createElement("ul");
  for (const item of items || []) {
    const li = document.createElement("li");
    li.textContent = item;
    list.appendChild(li);
  }
  return list;
}

function decisionKey(issueId, analysisId) {
  return `${issueId}:${analysisId}`;
}

function exportUrl(issueId, analysisId, format) {
  const parameters = new URLSearchParams({
    issue_id: issueId,
    analysis_id: String(analysisId),
    format,
  });
  return `/api/export?${parameters.toString()}`;
}

function evidenceUrl(issueId, analysisId) {
  const parameters = new URLSearchParams({
    issue_id: issueId,
    analysis_id: String(analysisId),
  });
  return `/api/evidence?${parameters.toString()}`;
}

function reproductionUrl(issueId, analysisId) {
  const parameters = new URLSearchParams({
    issue_id: issueId,
    analysis_id: String(analysisId),
  });
  return `/api/reproduction-handoff?${parameters.toString()}`;
}

function responseError(payload, fallback) {
  if (payload && typeof payload === "object") {
    return String(payload.message || payload.error || fallback);
  }
  return fallback;
}

async function responsePayload(response) {
  const contentType = response.headers.get("Content-Type") || "";
  if (!contentType.includes("application/json")) return null;
  try {
    return await response.json();
  } catch (_error) {
    return null;
  }
}

function normalizedTextItems(values) {
  const candidates = Array.isArray(values) ? values : [values];
  return candidates
    .map((value) => {
      if (typeof value === "string") return value.trim();
      if (!value || typeof value !== "object") return "";
      return String(value.claim_zh || value.excerpt || value.anchor || "").trim();
    })
    .filter(Boolean);
}

function appendAnalysisSection(container, headingText, values) {
  const items = normalizedTextItems(values);
  if (!items.length) return;
  const heading = document.createElement("strong");
  heading.textContent = headingText;
  container.append(heading, textNodeList(items));
}

function renderAnalysis(container, analysis) {
  container.replaceChildren();
  if (!analysis || typeof analysis !== "object") {
    container.textContent = "该冻结条目没有可展示的分析内容。";
    return;
  }
  appendAnalysisSection(container, "方法", analysis.methods || analysis.method);
  appendAnalysisSection(container, "评估", analysis.evaluation);
  appendAnalysisSection(container, "可复现性", analysis.reproducibility);
  if (!container.childNodes.length) {
    container.textContent = "该冻结条目没有补充分析字段。";
  }
}

function evidenceAnchorNode(anchor, index) {
  const section = document.createElement("section");
  section.className = "evidence-anchor";
  const heading = document.createElement("h4");
  heading.textContent = `证据 ${index + 1}`;
  const excerpt = document.createElement("blockquote");
  excerpt.textContent = String(anchor?.excerpt || "未提供原文摘录");
  section.append(heading, excerpt);
  if (anchor?.context) {
    const context = document.createElement("pre");
    context.className = "evidence-context";
    context.textContent = String(anchor.context);
    section.appendChild(context);
  }
  if (anchor?.start != null) {
    const position = document.createElement("p");
    position.className = "evidence-position";
    position.textContent = `冻结文本起始位置：${anchor.start}`;
    section.appendChild(position);
  }
  return section;
}

function renderEvidence(container, payload) {
  container.replaceChildren();
  const source = payload?.source || {};
  const identity = document.createElement("p");
  identity.className = "evidence-identity";
  identity.textContent =
    `输入 SHA-256：${source.input_sha256 || "未知"} · ` +
    `文档 ID：${source.document_id ?? "未知"}`;
  container.appendChild(identity);
  const anchors = Array.isArray(payload?.anchors) ? payload.anchors : [];
  if (!anchors.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = "该冻结条目没有可展示的原文证据。";
    container.appendChild(empty);
    return;
  }
  anchors.forEach((anchor, index) => {
    container.appendChild(evidenceAnchorNode(anchor, index));
  });
}

async function loadEvidence(details, item) {
  const container = details.querySelector(".evidence-content");
  const key = decisionKey(item.issue_id, item.analysis_id);
  if (evidenceCache.has(key)) {
    renderEvidence(container, evidenceCache.get(key));
    return;
  }
  container.textContent = "正在载入冻结证据…";
  try {
    const response = await fetch(evidenceUrl(item.issue_id, item.analysis_id));
    const payload = await responsePayload(response);
    if (!response.ok) {
      throw new Error(responseError(payload, "Evidence API request failed"));
    }
    evidenceCache.set(key, payload || {});
    renderEvidence(container, payload || {});
  } catch (error) {
    container.textContent = `证据载入失败：${error.message}`;
  }
}

function isPendingDecision(item) {
  return !item?.decision?.action;
}

function decisionItemsForView(items) {
  if (decisionExpanded) return items;
  return items.filter(isPendingDecision).slice(0, DECISION_FOCUS_LIMIT);
}

function renderDecisionCard(item, issueId) {
  const template = document.querySelector("#decision-template");
  const fragment = template.content.cloneNode(true);
  const card = fragment.querySelector(".decision-card");
  const citation = item.citation || {};
  const analysis = item.analysis || {};
  const decision = item.decision || {};
  const resolvedIssueId = String(item.issue_id || issueId || "");
  const stableCardId = `decision-${resolvedIssueId}-${String(item.analysis_id)}`
    .replace(/[^A-Za-z0-9_-]/g, "-");

  card.dataset.issueId = resolvedIssueId;
  card.dataset.analysisId = String(item.analysis_id);
  card.setAttribute("aria-labelledby", `${stableCardId}-title`);
  fragment.querySelector(".decision-kind").textContent =
    citation.kind === "repository" ? "仓库" : "论文";

  const snapshot = fragment.querySelector(".snapshot-badge");
  const snapshotHash = String(item.snapshot_sha256 || "");
  snapshot.textContent = snapshotHash
    ? `快照 ${snapshotHash.slice(0, 12)}`
    : "快照身份缺失";
  snapshot.title = snapshotHash || "未提供 snapshot_sha256";

  const title = fragment.querySelector(".decision-title");
  title.id = `${stableCardId}-title`;
  title.textContent = citation.title || `条目 ${item.work_id}`;
  if (citation.best_url) {
    title.href = citation.best_url;
  } else {
    title.removeAttribute("href");
    title.removeAttribute("target");
  }
  fragment.querySelector(".decision-meta").textContent = [
    citation.year,
    citation.doi ? `DOI ${citation.doi}` : null,
    citation.arxiv_id ? `arXiv ${citation.arxiv_id}` : null,
    citation.github_full_name,
    `分析 ${item.analysis_id}`,
  ]
    .filter(Boolean)
    .join(" · ");
  fragment.querySelector(".decision-abstract").textContent =
    analysis.summary_zh || "该冻结条目没有摘要。";
  const brief = decisionBrief({
    analysis,
    deep_read_status: analysis.deep_read_status || "complete",
    state: "analyzed",
  });
  const evidenceAnchors = normalizedTextItems(analysis.evidence_anchors);
  const semanticScore = analysis?.scores?.r3_relevance;
  const scoreScale = analysis.score_scale;
  const problem = firstUsefulText(analysis.problem);
  const method = firstUsefulText(analysis.method || analysis.methods);
  const claim = [
    problem ? `问题：${problem}` : "问题：未记录",
    method ? `机制/方法：${method}` : "机制/方法：未记录",
  ].join("；");
  fragment.querySelector(".decision-why-now").textContent = brief.why;
  fragment.querySelector(".decision-claim").textContent = claim;
  fragment.querySelector(".decision-evidence-status").textContent =
    evidenceAnchors.length > 0
      ? `${evidenceAnchors.length} 个冻结证据锚点；展开原文后可逐项核验。`
      : "冻结分析未记录证据锚点；不能据此确认主张。";
  fragment.querySelector(".signal-semantic").textContent =
    typeof semanticScore === "number" && Number.isFinite(semanticScore)
      ? `${semanticScore}${scoreScale ? `（${scoreScale}）` : "（量表未记录）"}`
      : "未记录独立语义分数；请依据上方关系说明判断。";
  fragment.querySelector(".signal-action").textContent = decision.action
    ? decisionActionLabels[decision.action] || decision.action
    : "待人工决定；系统尚未执行阅读、保存或排除。";
  fragment.querySelector(".signal-outcome").textContent =
    "未记录；当前接口尚未采集使用后的研究结果。";

  const metadata = citation.metadata || {};
  const revision = [
    metadata.frozen_revision,
    metadata.commit_sha,
    metadata.github_commit_sha,
  ].find(
    (value) =>
      typeof value === "string" && /^[0-9a-f]{40}$/i.test(value.trim()),
  );
  const snapshotIdentity = snapshotHash
    ? snapshotHash.slice(0, 12)
    : "未知";
  fragment.querySelector(".same-revision").textContent =
    citation.kind === "repository"
      ? revision
        ? `仓库 revision ${revision.trim().toLowerCase()}；决策内容快照 ${snapshotIdentity}。`
        : `决策内容快照 ${snapshotIdentity}；仓库 commit 未由当前接口提供，不能声称主张与代码属于同一 revision。`
      : `论文内容绑定决策快照 ${snapshotIdentity}；仓库 revision 不适用。`;
  const limitations = normalizedTextItems([
    ...(Array.isArray(analysis.limitations) ? analysis.limitations : [analysis.limitations]),
    ...(Array.isArray(analysis.uncertainties) ? analysis.uncertainties : [analysis.uncertainties]),
  ]);
  fragment.querySelector(".decision-limitations").textContent = limitations.length
    ? limitations.join("；")
    : "未记录限制或不确定性；这不等于没有限制。";
  const risks = normalizedTextItems(analysis.overlap_risks);
  fragment.querySelector(".decision-cost-risk").textContent = risks.length
    ? `验证成本未单独记录；已记录风险：${risks.join("；")}`
    : "验证成本未单独记录；分析也未记录风险，这不等于零成本或零风险。";
  const changes = normalizedTextItems(analysis.actionable_ideas);
  fragment.querySelector(".decision-change").textContent = changes.length
    ? changes.join("；")
    : "未记录可执行变化；需人工决定下一步。";
  renderAnalysis(fragment.querySelector(".analysis-content"), analysis);

  const evidenceDetails = fragment.querySelector(".frozen-evidence");
  evidenceDetails.addEventListener("toggle", () => {
    if (evidenceDetails.open) loadEvidence(evidenceDetails, {
      ...item,
      issue_id: resolvedIssueId,
    });
  });

  for (const link of fragment.querySelectorAll(".export-links a")) {
    link.href = link.classList.contains("reproduction-link")
      ? reproductionUrl(resolvedIssueId, item.analysis_id)
      : exportUrl(
          resolvedIssueId,
          item.analysis_id,
          link.dataset.format,
        );
  }

  const form = fragment.querySelector(".decision-form");
  form.elements.issue_id.value = resolvedIssueId;
  form.elements.analysis_id.value = String(item.analysis_id);
  form.elements.action.value = decision.action || "";
  form.elements.reason.value = decision.reason || "";
  form.elements.note.value = decision.note || "";
  form.addEventListener("submit", saveDecision);
  return fragment;
}

function renderDecisionSlice() {
  const issue = decisionSlice.issue;
  const items = Array.isArray(decisionSlice.items) ? decisionSlice.items : [];
  const remaining = Math.max(0, Number(decisionSlice.remaining_count || 0));
  const pendingReturned = items.filter(isPendingDecision).length;
  const visibleItems = decisionItemsForView(items);
  const summary = document.querySelector("#decision-summary");
  const changeSummary = document.querySelector("#issue-change-summary");
  const state = document.querySelector("#decision-state");
  const container = document.querySelector("#decision-items");
  const toggle = document.querySelector("#decision-scope-toggle");
  container.replaceChildren();

  if (!issue) {
    summary.textContent = decisionSlice.publication_missing
      ? "本轮为试运行，尚未生成冻结刊期；已完成的深读结论可在下方候选卡片查看。"
      : "尚无冻结刊期。零推荐是合法结果，不会自动填充低质量条目。";
    state.textContent = "";
    changeSummary.hidden = true;
    changeSummary.textContent = "";
    toggle.hidden = true;
    return;
  }

  const counts = issue.counts || {};
  const generated = issue.generated_at
    ? new Date(issue.generated_at).toLocaleString("zh-CN")
    : "时间未知";
  const latestIssue = decisionSlice.latest_issue || issue;
  const historicalPolicy = decisionSlice.analysis_policy_current === false;
  const carryForwardPrefix = decisionSlice.carried_forward
    ? `当前增量刊期 ${shortIdentifier(latestIssue.issue_id)} 无新增推荐；` +
      "继续显示上一有效刊期 "
    : historicalPolicy
      ? "历史策略刊期 "
      : "刊期 ";
  summary.textContent =
    `${carryForwardPrefix}${shortIdentifier(issue.issue_id)} · ${generated} · ` +
    `已返回 ${items.length} 项 · 待决 ${pendingReturned} 项` +
    (remaining ? ` · 另有 ${remaining} 项` : "");
  summary.title = `冻结刊期：${issue.issue_id}`;
  const diffCounts = issue.living_diff?.counts || {};
  const outbox = issue.local_outbox;
  if (issue.living_diff?.schema) {
    changeSummary.hidden = false;
    changeSummary.textContent =
      `本期变化：新增 ${Number(diffCounts.added || 0)} · ` +
      `内容更新 ${Number(diffCounts.content_updated || 0)} · ` +
      `分析更新 ${Number(diffCounts.analysis_updated || 0)} · ` +
      `决策相关 ${Number(diffCounts.selected_changes || 0)}。` +
      (outbox?.state === "ready"
        ? " 本地摘要已进入 outbox；未配置任何外部发送。"
        : " 当前为历史刊期，尚无本地 outbox 摘要。 ");
    changeSummary.title = outbox?.digest_sha256
      ? `本地摘要 SHA-256：${outbox.digest_sha256}`
      : "";
  } else {
    changeSummary.hidden = true;
    changeSummary.textContent = "";
    changeSummary.title = "";
  }

  const canExpand =
    decisionExpanded ||
    remaining > 0 ||
    visibleItems.length < items.length ||
    pendingReturned > DECISION_FOCUS_LIMIT;
  toggle.hidden = !canExpand;
  toggle.textContent = decisionExpanded ? "仅看少量待决项" : "展开全部";
  toggle.setAttribute("aria-expanded", String(decisionExpanded));

  if (!visibleItems.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    if (!items.length && !remaining && Number(counts.selected || 0) === 0) {
      empty.textContent =
        "本刊期没有达到门槛的推荐项。这是合法空态，不会用低质量条目补足数量。";
    } else if (!decisionExpanded && pendingReturned === 0) {
      empty.textContent = "当前没有待决项；可展开全部查看已保存的决定。";
    } else {
      empty.textContent = "当前视图没有可展示的决策条目。";
    }
    container.appendChild(empty);
    state.textContent = "";
    return;
  }

  for (const item of visibleItems) {
    container.appendChild(renderDecisionCard(item, issue.issue_id));
  }
  state.textContent = decisionExpanded
    ? "正在显示 API 返回的全部条目。"
    : `聚焦显示前 ${visibleItems.length} 个待决项。`;
  if (historicalPolicy) {
    state.textContent +=
      " 所有决定仍绑定该冻结刊期，不会被记作当前 Max 策略的分析结果。";
  }
}

async function fetchDecisionSlice(expanded) {
  const endpoint = expanded ? "/api/decision-slice?all=1" : "/api/decision-slice";
  const response = await fetch(endpoint);
  const payload = await responsePayload(response);
  if (response.status === 404 && payload?.error === "publication_not_found") {
    return {
      issue: null,
      latest_issue: null,
      carried_forward: false,
      items: [],
      remaining_count: 0,
      publication_missing: true,
      analysis_policy_current: true,
    };
  }
  if (!response.ok) {
    throw new Error(responseError(payload, "Decision slice API request failed"));
  }
  if (!payload || typeof payload !== "object") {
    throw new Error("Decision slice API returned an invalid payload");
  }
  return {
    issue: payload.issue || null,
    latest_issue: payload.latest_issue || payload.issue || null,
    carried_forward: Boolean(payload.carried_forward),
    items: Array.isArray(payload.items) ? payload.items : [],
    remaining_count: Math.max(0, Number(payload.remaining_count || 0)),
    publication_missing: false,
    analysis_policy_current: payload.analysis_policy_current !== false,
  };
}

async function refreshDecisionSlice() {
  const state = document.querySelector("#decision-state");
  state.textContent = "正在刷新研究决策…";
  try {
    decisionSlice = await fetchDecisionSlice(decisionExpanded);
    renderDecisionSlice();
    return true;
  } catch (error) {
    state.textContent = `研究决策载入失败：${error.message}`;
    return false;
  }
}

async function saveDecision(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const status = form.querySelector(".decision-save-status");
  const payload = {
    issue_id: form.elements.issue_id.value,
    analysis_id: Number(form.elements.analysis_id.value),
    action: form.elements.action.value,
    reason: form.elements.reason.value.trim(),
    note: form.elements.note.value.trim(),
  };
  status.textContent = "保存中…";
  button.disabled = true;
  try {
    const response = await fetch("/api/decision", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const result = await responsePayload(response);
    if (!response.ok) {
      throw new Error(responseError(result, "Decision API request failed"));
    }
    status.textContent = "已保存，正在刷新…";
    const refreshed = await refreshDecisionSlice();
    if (refreshed) {
      document.querySelector("#decision-state").textContent =
        "决策已保存，并已从服务器恢复最新状态。";
    } else {
      status.textContent = "决策已保存，但刷新失败；请使用页面刷新重试。";
    }
  } catch (error) {
    status.textContent = `保存失败：${error.message}`;
  } finally {
    button.disabled = false;
  }
}

function renderMetrics(counts) {
  const container = document.querySelector("#metrics");
  container.replaceChildren();
  for (const [key, label] of Object.entries(labels)) {
    const card = document.createElement("div");
    card.className = "metric";
    const number = document.createElement("strong");
    number.textContent = String(counts[key] ?? 0);
    const caption = document.createElement("span");
    caption.textContent = label;
    card.append(number, caption);
    container.appendChild(card);
  }
}

function workStateText(work) {
  return work.state === "content_retry" &&
    work.content_reason === "pdf_security_reparse_required"
    ? "等待安全重解析"
    : stateLabels[work.state] || work.state;
}

function workMetaText(work) {
  const analysisProgress =
    Number(work.analysis_chunk_total || 0) > 0
      ? `深读 ${Number(work.analysis_chunk_done || 0)}/${Number(work.analysis_chunk_total)}`
      : "";
  const sources = retrievalSources(work);
  const sourceMetadata = sources.length
    ? `来源：${sources.map(sourceLabel).join(" / ")}`
    : "来源：未记录";
  const analysisProvider = work.provider || work.analysis_task_provider;
  const hasCompleteAnalysis = Boolean(
    work.analysis && work.deep_read_status === "complete",
  );
  return [
    work.year,
    sourceMetadata,
    analysisProvider ? `分析：${analysisProvider}` : "",
    analysisProgress,
    hasCompleteAnalysis ? work.feedback_rating : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

function firstUsefulText(values) {
  return normalizedTextItems(values)[0] || "";
}

function decisionBrief(work) {
  const analysis = work.analysis;
  if (!analysis || work.deep_read_status !== "complete") {
    const reason = contentMessage(work);
    return {
      why: "尚未形成通过证据门禁的推荐结论。",
      change:
        work.state === "analysis_running"
          ? "等待当前深读完成后再决定是否阅读、测试或采用。"
          : "先解决内容获取、覆盖或分析状态，再投入研究时间。",
      gap:
        reason ||
        "当前条目的相关性、机制和可迁移价值尚未得到完整证据支持。",
    };
  }
  return {
    why:
      firstUsefulText(analysis.r3_relationship) ||
      analysis.summary_zh ||
      "完整深读已通过，但尚未给出更具体的关系说明。",
    change:
      firstUsefulText(analysis.actionable_ideas) ||
      "结合原文证据决定阅读、实验、采用、观察或跳过。",
    gap:
      firstUsefulText(analysis.limitations) ||
      firstUsefulText(analysis.uncertainties) ||
      "分析未列出明确局限；仍需人工核对证据后决策。",
  };
}

function captureWorkInteractionState() {
  const state = new Map();
  for (const card of document.querySelectorAll("#works .work[data-work-id]")) {
    const form = card.querySelector(".feedback-form");
    const details = card.querySelector("details");
    const active = document.activeElement;
    const focusedField =
      form && active instanceof HTMLElement && form.contains(active)
        ? active.getAttribute("name")
        : null;
    state.set(card.dataset.workId, {
      rating: form?.elements?.rating?.value || "",
      comment: form?.elements?.comment?.value || "",
      dirty: form?.dataset?.dirty === "true",
      detailsOpen: Boolean(details?.open),
      focusedField,
      selectionStart:
        focusedField && typeof active.selectionStart === "number"
          ? active.selectionStart
          : null,
      selectionEnd:
        focusedField && typeof active.selectionEnd === "number"
          ? active.selectionEnd
          : null,
    });
  }
  return state;
}

function restoreWorkInteractionState(state) {
  for (const card of document.querySelectorAll("#works .work[data-work-id]")) {
    const saved = state.get(card.dataset.workId);
    if (!saved) continue;
    const form = card.querySelector(".feedback-form");
    if (saved.dirty && form?.elements?.rating) {
      form.elements.rating.value = saved.rating;
    }
    if (saved.dirty && form?.elements?.comment) {
      form.elements.comment.value = saved.comment;
    }
    if (saved.dirty && form) form.dataset.dirty = "true";
    const details = card.querySelector("details");
    if (details && saved.detailsOpen) details.open = true;
    const focused = saved.focusedField
      ? form?.elements?.[saved.focusedField]
      : null;
    if (focused instanceof HTMLElement) {
      focused.focus();
      if (
        typeof focused.setSelectionRange === "function" &&
        saved.selectionStart != null &&
        saved.selectionEnd != null
      ) {
        focused.setSelectionRange(saved.selectionStart, saved.selectionEnd);
      }
    }
  }
}

function workStructureSignature(work) {
  return JSON.stringify({
    id: work.id,
    kind: work.kind,
    title: work.title,
    year: work.year,
    state: work.state,
    best_url: work.best_url,
    retrieval_sources: retrievalSources(work),
    deep_read_status: work.deep_read_status,
    analysis_task_status: work.analysis_task_status,
    content_reason: work.content_reason,
    content_failure_code: work.content_failure_code,
    tier: work.tier,
    score: work.score,
    feedback_rating: work.feedback_rating,
    provider: work.provider,
    analysis_task_provider: work.analysis_task_provider,
    analysis: work.analysis || null,
  });
}

function workSnapshotNeedsRender(nextWorks) {
  if (nextWorks.length !== allWorks.length) return true;
  const previousById = new Map(allWorks.map((work) => [String(work.id), work]));
  return nextWorks.some((work) => {
    const previous = previousById.get(String(work.id));
    return (
      !previous ||
      workStructureSignature(previous) !== workStructureSignature(work)
    );
  });
}

function updateLiveWorkCards(nextWorks) {
  if (workSnapshotNeedsRender(nextWorks)) {
    if (feedbackSubmissionsInFlight > 0) return;
    const interactionState = captureWorkInteractionState();
    allWorks = nextWorks;
    populateSourceFilter();
    renderWorks();
    restoreWorkInteractionState(interactionState);
    return;
  }

  allWorks = nextWorks;
  const nextById = new Map(nextWorks.map((work) => [String(work.id), work]));
  for (const card of document.querySelectorAll("#works .work[data-work-id]")) {
    const work = nextById.get(card.dataset.workId);
    if (!work) continue;
    const stateTag = card.querySelector(".state");
    stateTag.textContent = workStateText(work);
    stateTag.classList.toggle("state-incomplete", work.state === "content_incomplete");
    stateTag.classList.toggle("state-unavailable", work.state === "content_unavailable");
    card.querySelector(".meta").textContent = workMetaText(work);
  }
}

function renderWorkAnalysisDetails(container, work, historicalAnalysis) {
  container.replaceChildren();
  const heading = document.createElement("strong");
  heading.textContent = historicalAnalysis
    ? "历史深读与 R3 的关系"
    : "与 R3 的关系";
  const relationships = normalizedTextItems(work.analysis?.r3_relationship);
  const evidence = document.createElement("strong");
  evidence.textContent = "证据锚点";
  const anchors = normalizedTextItems(work.analysis?.evidence_anchors);
  container.append(
    heading,
    relationships.length
      ? textNodeList(relationships)
      : document.createTextNode("未记录关系说明。"),
    evidence,
    anchors.length
      ? textNodeList(anchors)
      : document.createTextNode("未记录证据锚点。"),
  );
}

function renderWorks() {
  const state = document.querySelector("#state-filter").value;
  const source = document.querySelector("#source-filter").value;
  const needle = document.querySelector("#text-filter").value.trim().toLocaleLowerCase();
  const container = document.querySelector("#works");
  container.replaceChildren();
  const template = document.querySelector("#work-template");
  const selected = allWorks.filter((work) => {
    const stateMatch = !state || work.state === state;
    const sourceMatch = !source || retrievalSources(work).includes(source);
    const corpus = `${work.title || ""} ${work.analysis?.summary_zh || ""}`.toLocaleLowerCase();
    return stateMatch && sourceMatch && (!needle || corpus.includes(needle));
  });
  for (const work of selected) {
    const fragment = template.content.cloneNode(true);
    const card = fragment.querySelector(".work");
    card.dataset.workId = String(work.id);
    fragment.querySelector(".kind").textContent = work.kind === "paper" ? "论文" : "仓库";
    const stateTag = fragment.querySelector(".state");
    stateTag.textContent = workStateText(work);
    if (work.state === "content_incomplete") stateTag.classList.add("state-incomplete");
    if (work.state === "content_unavailable") stateTag.classList.add("state-unavailable");
    const hasCompleteAnalysis = Boolean(
      work.analysis_id && work.deep_read_status === "complete",
    );
    const historicalAnalysis =
      hasCompleteAnalysis && work.analysis_policy_current === false;
    const policyTag = fragment.querySelector(".analysis-policy");
    policyTag.textContent = historicalAnalysis ? "历史策略结果" : "";
    policyTag.hidden = !historicalAnalysis;
    const tierTag = fragment.querySelector(".tier");
    tierTag.textContent = hasCompleteAnalysis ? work.tier || "" : "";
    tierTag.hidden = !tierTag.textContent;
    const scoreTag = fragment.querySelector(".score");
    scoreTag.textContent =
      !hasCompleteAnalysis || work.score == null
        ? ""
        : `综合 ${Number(work.score).toFixed(1)}`;
    scoreTag.hidden = !scoreTag.textContent;
    const link = fragment.querySelector(".title");
    link.textContent = work.title;
    link.href = work.best_url || "#";
    const meta = fragment.querySelector(".meta");
    meta.textContent = workMetaText(work);
    const brief = decisionBrief(work);
    fragment.querySelector(".brief-why").textContent = brief.why;
    fragment.querySelector(".brief-change").textContent = brief.change;
    fragment.querySelector(".brief-gap").textContent = brief.gap;
    const noticeMessage = contentMessage(work);
    if (noticeMessage) {
      const notice = document.createElement("p");
      notice.className =
        work.state === "content_unavailable"
          ? "content-notice content-notice-unavailable"
          : "content-notice content-notice-incomplete";
      notice.textContent = noticeMessage;
      meta.after(notice);
    }
    fragment.querySelector(".summary").textContent =
      work.analysis?.summary_zh ||
      (hasCompleteAnalysis
        ? "深读已完成；展开时按需载入完整分析与证据锚点。"
        : "尚未形成完整深读结论。");
    const details = fragment.querySelector(".details-content");
    if (work.analysis) {
      renderWorkAnalysisDetails(details, work, historicalAnalysis);
    } else if (hasCompleteAnalysis) {
      details.textContent = "展开后载入完整深读证据。";
      const disclosure = fragment.querySelector("details");
      disclosure.querySelector("summary").textContent = "载入深读证据";
      disclosure.addEventListener("toggle", async () => {
        if (!disclosure.open || work.analysis || disclosure.dataset.loading === "true") {
          return;
        }
        disclosure.dataset.loading = "true";
        details.textContent = "正在载入深读证据…";
        try {
          const response = await fetch(
            `/api/work-analysis?work_id=${encodeURIComponent(work.id)}`,
          );
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          const payload = await response.json();
          work.analysis = payload.analysis;
          work.analysis_policy_current = payload.analysis_policy_current;
          const loadedHistorical = payload.analysis_policy_current === false;
          renderWorkAnalysisDetails(details, work, loadedHistorical);
          disclosure.querySelector("summary").textContent = loadedHistorical
            ? "历史策略证据与 R3 关系"
            : "证据与 R3 关系";
          disclosure.dataset.loading = "false";
        } catch (error) {
          details.textContent = `深读证据载入失败：${error.message}`;
          disclosure.dataset.loading = "false";
        }
      });
    } else {
      details.textContent = noticeMessage
        ? `${noticeMessage} 未完成全文核验，因此没有评分、分层或推荐结论。`
        : work.analysis_task_status === "failed"
          ? "当前深读尚未完成；最近一次任务失败，详细原因仅保留在本地审计日志。"
          : "当前状态尚无可展示的完整证据链。";
    }
    if (!hasCompleteAnalysis) {
      fragment.querySelector("details > summary").textContent = "未完成原因";
    }
    const form = fragment.querySelector(".feedback-form");
    if (!hasCompleteAnalysis || historicalAnalysis) {
      const blocked = document.createElement("p");
      blocked.className = "feedback-blocked-message";
      blocked.textContent = historicalAnalysis
        ? "这是可追溯的历史策略结果；当前 Max 策略完成前仅供阅读，反馈不会错绑到新策略。"
        : "未完成全文核验，暂不评价研究价值。";
      form.classList.add("feedback-blocked");
      form.replaceChildren(blocked);
    } else {
      form.elements.work_id.value = String(work.id);
      if (work.feedback_rating) form.elements.rating.value = work.feedback_rating;
      const markDirty = () => {
        form.dataset.dirty = "true";
      };
      form.addEventListener("input", markDirty);
      form.addEventListener("change", markDirty);
      form.addEventListener("submit", saveFeedback);
    }
    container.appendChild(fragment);
  }
  if (!selected.length) {
    const empty = document.createElement("p");
    empty.className = "empty-state";
    empty.textContent = allWorks.length
      ? "没有符合当前筛选条件的条目。"
      : "还没有候选条目。可先运行 `r3radar demo` 查看零网络演示，" +
        "再用 `r3radar create-profile` 创建自己的研究画像。";
    container.appendChild(empty);
  }
  const loadMore = document.querySelector("#load-more-works");
  loadMore.hidden = !nextWorksCursor;
  loadMore.textContent = nextWorksCursor
    ? `加载更多（已载入 ${allWorks.length}/${loadedWorksTotal}）`
    : `已载入 ${allWorks.length}/${loadedWorksTotal}`;
}

async function saveFeedback(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const status = form.querySelector(".feedback-status");
  const button = form.querySelector('button[type="submit"]');
  const workId = Number(form.elements.work_id.value);
  status.textContent = "保存中…";
  button.disabled = true;
  feedbackSubmissionsInFlight += 1;
  feedbackMutationGeneration += 1;
  let submissionReleased = false;
  try {
    const response = await fetch("/api/feedback", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        work_id: workId,
        rating: form.elements.rating.value,
        comment: form.elements.comment.value,
      }),
    });
    status.textContent = response.ok ? "已保存" : "保存失败";
    if (response.ok) {
      form.dataset.dirty = "false";
      feedbackSubmissionsInFlight -= 1;
      submissionReleased = true;
      await refresh();
      const refreshedForm = Array.from(
        document.querySelectorAll("form.feedback-form"),
      ).find(
        (candidate) => Number(candidate.elements.work_id?.value) === workId,
      );
      const refreshedStatus = refreshedForm?.querySelector(".feedback-status");
      if (refreshedStatus) {
        refreshedStatus.textContent = "已保存（批注已写入本地证据库）";
      }
    }
  } catch (error) {
    status.textContent = `保存失败：${error.message}`;
  } finally {
    if (!submissionReleased) feedbackSubmissionsInFlight -= 1;
    button.disabled = false;
  }
}

async function fetchWorksPage(cursor = null) {
  const parameters = new URLSearchParams({limit: "25"});
  if (cursor) parameters.set("cursor", cursor);
  const response = await fetch(`/api/works?${parameters.toString()}`);
  if (!response.ok) throw new Error("Works API request failed");
  const page = await response.json();
  return {
    works: Array.isArray(page.works) ? page.works : [],
    total: Number(page.total || 0),
    nextCursor:
      typeof page.next_cursor === "string" && page.next_cursor
        ? page.next_cursor
        : null,
  };
}

function formatElapsed(seconds) {
  const value = Math.max(0, Math.floor(Number(seconds) || 0));
  if (value < 15) return "刚刚";
  if (value < 60) return `${value} 秒前`;
  if (value < 3600) return `${Math.floor(value / 60)} 分钟前`;
  if (value < 86400) {
    const hours = Math.floor(value / 3600);
    const minutes = Math.floor((value % 3600) / 60);
    return minutes ? `${hours} 小时 ${minutes} 分钟前` : `${hours} 小时前`;
  }
  return `${Math.floor(value / 86400)} 天前`;
}

function formatDuration(seconds) {
  const value = Math.max(0, Math.round(Number(seconds) || 0));
  if (value < 60) return `${value} 秒`;
  const minutes = Math.floor(value / 60);
  const remainder = value % 60;
  return remainder ? `${minutes} 分 ${remainder} 秒` : `${minutes} 分钟`;
}

function deriveDeepReadStatus(status, works) {
  const rows = Array.isArray(works) ? works : [];
  const completedRows = rows.filter(
    (work) => work.deep_read_status === "complete" || work.state === "analyzed",
  );
  const runningRows = rows.filter(
    (work) =>
      work.analysis_task_status === "running" ||
      work.state === "analysis_running",
  );
  const queuedRows = rows.filter(
    (work) =>
      ["pending", "retry"].includes(work.analysis_task_status) ||
      work.state === "analysis_pending",
  );
  const failedRows = rows.filter(
    (work) =>
      work.analysis_task_status === "failed" ||
      work.state === "analysis_failed",
  );
  const currentWork = runningRows[0] || null;
  const run = status.latest_run || null;
  const invocationCount = Number(status.model_usage?.invocation_count || 0);
  const signature = [
    currentWork?.id || "",
    currentWork?.analysis_chunk_done || 0,
    currentWork?.analysis_chunk_total || 0,
    invocationCount,
    completedRows.length,
    queuedRows.length,
    failedRows.length,
  ].join(":");
  const runUpdatedAt = Date.parse(run?.updated_at || "");
  if (fallbackProgressSignature !== signature) {
    fallbackProgressSignature = signature;
    fallbackLastActivityMs = Date.now();
  } else if (fallbackLastActivityMs == null && Number.isFinite(runUpdatedAt)) {
    fallbackLastActivityMs = runUpdatedAt;
  }
  const activityAgeSeconds =
    fallbackLastActivityMs == null
      ? null
      : Math.max(0, Math.floor((Date.now() - fallbackLastActivityMs) / 1000));
  const leaseExpiresAt = Date.parse(run?.lease_expires_at || "");
  const observedRun = status.runtime?.run || null;
  const runActive = observedRun
    ? observedRun.active === true
    : Boolean(
        run?.status === "running" &&
          Number.isFinite(leaseExpiresAt) &&
          leaseExpiresAt > Date.now(),
      );
  const total =
    completedRows.length +
    runningRows.length +
    queuedRows.length +
    failedRows.length;
  let state = "idle";
  if (currentWork) {
    state =
      !runActive || activityAgeSeconds == null || activityAgeSeconds >= 600
        ? "stalled"
        : "running";
  } else if (queuedRows.length) {
    state = runActive
      ? "queued"
      : ["paused", "completed_with_gaps", "failed"].includes(run?.status)
        ? "paused"
        : "waiting";
  } else if (failedRows.length) {
    state = "attention";
  } else if (total && completedRows.length === total) {
    state = "complete";
  }
  return {
    state,
    total,
    completed: completedRows.length,
    running: runningRows.length,
    queued: queuedRows.length,
    failed: failedRows.length,
    retrying: rows.filter((work) => work.analysis_task_status === "retry").length,
    current_task: currentWork
      ? {
          id: currentWork.analysis_task_id || currentWork.id,
          work_id: currentWork.id,
          title: currentWork.title,
          kind: currentWork.kind,
          provider: currentWork.provider || currentWork.analysis_task_provider,
          chunk_done: Number(currentWork.analysis_chunk_done || 0),
          chunk_total: Number(currentWork.analysis_chunk_total || 0),
          last_model_duration_seconds: null,
        }
      : null,
    last_activity_at:
      fallbackLastActivityMs == null
        ? null
        : new Date(fallbackLastActivityMs).toISOString(),
    last_activity_age_seconds: activityAgeSeconds,
    stale_after_seconds: 600,
    run_id: run?.id || null,
    run_status: run?.status || null,
    lease_expires_at: run?.lease_expires_at || null,
  };
}

function renderDeepReadStatus(deepRead, execution = {}) {
  const panel = document.querySelector("#deep-read-panel");
  const stateTag = document.querySelector("#deep-read-state");
  const summary = document.querySelector("#deep-read-summary");
  const title = document.querySelector("#deep-read-title");
  const progressText = document.querySelector("#deep-read-progress-text");
  const lastActivity = document.querySelector("#deep-read-last-activity");
  const progress = document.querySelector("#deep-read-progress");
  const message = document.querySelector("#deep-read-message");
  const refreshState = document.querySelector("#deep-read-refresh-state");

  if (!deepRead || typeof deepRead !== "object") {
    panel.dataset.state = "unavailable";
    stateTag.textContent = deepReadStateLabels.unavailable;
    summary.textContent = "当前服务尚未返回独立的深读状态。";
    title.textContent = "无法读取深读任务";
    progressText.textContent = "尚无进度";
    lastActivity.textContent = "尚无活动记录";
    progress.hidden = true;
    message.textContent = "可使用页面刷新重试；后台任务不会因页面状态缺失而被自动停止。";
    for (const id of [
      "deep-read-completed",
      "deep-read-running",
      "deep-read-queued",
      "deep-read-failed",
    ]) {
      document.querySelector(`#${id}`).textContent = "—";
    }
    refreshState.textContent = "每 15 秒自动重试";
    return;
  }

  const state = deepRead.state || "unavailable";
  const total = Number(deepRead.total || 0);
  const completed = Number(deepRead.completed || 0);
  const running = Number(deepRead.running || 0);
  const queued = Number(deepRead.queued || 0);
  const failed = Number(deepRead.failed || 0);
  const historicalCompleted = Number(deepRead.historical_completed || 0);
  const model = String(execution.model || "").trim();
  const effort = String(execution.reasoning_effort || "").trim();
  const executionLabel = [model, effort ? `思考强度 ${effort}` : ""]
    .filter(Boolean)
    .join(" · ");
  const current = deepRead.current_task;
  panel.dataset.state = state;
  stateTag.textContent = deepReadStateLabels[state] || state;
  summary.textContent = total
    ? `${executionLabel ? `${executionLabel}；` : ""}本批共 ${total} 项：` +
      `${completed} 项已完成，${queued} 项等待处理。`
    : historicalCompleted
      ? `${executionLabel ? `${executionLabel}；` : ""}当前策略尚无已完成任务；` +
        `已有 ${historicalCompleted} 份历史策略结果可在下方阅读。`
      : `${executionLabel ? `${executionLabel}；` : ""}当前分析策略下暂无深读任务。`;
  document.querySelector("#deep-read-completed").textContent = String(completed);
  document.querySelector("#deep-read-running").textContent = String(running);
  document.querySelector("#deep-read-queued").textContent = String(queued);
  document.querySelector("#deep-read-failed").textContent = String(failed);

  if (current) {
    const chunkDone = Number(current.chunk_done || 0);
    const chunkTotal = Number(current.chunk_total || 0);
    const rawPhase = String(current.phase || "");
    const hierarchicalLevelMatch =
      /^hierarchical_synthesis_l([1-9]\d*)$/.exec(rawPhase);
    const phase =
      hierarchicalLevelMatch
        ? "hierarchical_synthesis"
        : deepReadPhaseLabels[rawPhase] != null
          ? rawPhase
        : chunkTotal
          ? "chunk_reading"
          : "preparing";
    const phaseLabel = hierarchicalLevelMatch
      ? `分层汇总（第 ${hierarchicalLevelMatch[1]} 层）`
      : deepReadPhaseLabels[phase];
    const phaseDone =
      current.phase_done == null
        ? phase === "chunk_reading"
          ? chunkDone
          : 0
        : Number(current.phase_done);
    const phaseTotal =
      current.phase_total == null
        ? phase === "chunk_reading"
          ? chunkTotal
          : 0
        : Number(current.phase_total);
    title.textContent = current.title || `任务 ${current.id}`;
    if (phase === "chunk_reading" && chunkTotal) {
      progressText.textContent =
        `${phaseLabel} · ${chunkDone}/${chunkTotal} 个全文块`;
    } else if (phaseTotal > 0) {
      progressText.textContent =
        `${phaseLabel} · ${phaseDone}/${phaseTotal}`;
    } else {
      progressText.textContent = phaseLabel;
    }
    progress.hidden = false;
    if (phaseTotal > 0) {
      progress.max = phaseTotal;
      progress.value = Math.min(phaseDone, phaseTotal);
    } else {
      progress.max = 1;
      progress.removeAttribute("value");
    }
    const activityAge = deepRead.last_activity_age_seconds;
    lastActivity.textContent =
      activityAge == null
        ? "尚无活动记录"
        : `最近进度：${formatElapsed(activityAge)}`;
    const lastDuration = current.last_model_duration_seconds;
    if (state === "stalled") {
      message.textContent =
        `超过 ${formatDuration(deepRead.stale_after_seconds)} 没有新的阶段进度或模型回执，` +
        "请检查后台进程与运行租约。";
    } else {
      const phaseMessages = {
        preparing: "正在核对全文、内容哈希与分块计划。",
        chunk_reading: "模型正在分批处理全文；每批结果通过证据校验并落库后，块数才会前进。",
        hierarchical_synthesis:
          `全文分块已完成（${chunkDone}/${chunkTotal}）；正在把块级发现分层压缩为可综合证据。`,
        final_synthesis:
          `全文分块已完成（${chunkDone}/${chunkTotal}）；正在生成最终研究判断与评分。`,
        complete: "当前条目的全文阅读、分层汇总和最终综合均已完成。",
      };
      const invocationCount = Number(current.model_invocation_count || 0);
      message.textContent =
        (phaseMessages[phase] || "深读任务正在推进。") +
        (invocationCount ? ` 本任务已记录 ${invocationCount} 次模型调用。` : "") +
        (lastDuration == null
          ? ""
          : ` 最近一次模型处理耗时 ${formatDuration(lastDuration)}。`);
    }
  } else {
    progress.hidden = true;
    progress.removeAttribute("value");
    progressText.textContent = "当前没有正在处理的全文";
    lastActivity.textContent =
      deepRead.last_activity_age_seconds == null
        ? "尚无活动记录"
        : `最近进度：${formatElapsed(deepRead.last_activity_age_seconds)}`;
    if (state === "complete") {
      title.textContent = "本批深读已全部完成";
      message.textContent = "所有已纳入任务均已形成可追溯的完整深读结果。";
    } else if (state === "attention") {
      title.textContent = "存在需要处理的深读失败";
      message.textContent = "失败详情保留在本地审计记录中，页面仅显示安全摘要。";
    } else if (state === "paused") {
      title.textContent = "剩余任务等待续跑";
      message.textContent = "当前运行已停止或触及边界；队列仍保留，不会丢失进度。";
    } else if (state === "queued" || state === "waiting") {
      title.textContent = "深读任务正在排队";
      message.textContent =
        state === "queued"
          ? "后台运行正常，任务将由流水线自动领取。"
          : "队列已保存，等待下一次后台运行自动领取。";
    } else {
      title.textContent = historicalCompleted
        ? "当前策略尚未启动深读"
        : "暂无深读任务";
      message.textContent = historicalCompleted
        ? `历史 ${historicalCompleted} 份结果仍完整保留并明确标注；` +
          "它们不会计入当前策略完成数。"
        : "新的合格全文进入分析队列后，这里会自动显示进度。";
    }
  }

  const refreshedAt = new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date());
  refreshState.textContent = `每 15 秒自动更新 · ${refreshedAt} 已刷新`;
}

function renderStatus(status, works = null) {
  renderMetrics(status.counts);
  const profile = status.profile || {};
  const profileName = String(profile.name || "R3 Research Radar");
  const researchQuestion = String(
    profile.research_question || "论文与代码的决策级研究雷达",
  );
  document.querySelector("#app-title").textContent = profileName;
  document.querySelector("#app-subtitle").textContent = researchQuestion;
  document.title = `${profileName} · R3`;
  document.querySelector("#demo-banner").hidden = !profile.demo_mode;
  const run = status.latest_run;
  const observedRun = status.runtime?.run || null;
  const queryCoverage = status.query_coverage || null;
  const coverageScopeLabels = {
    full: "完整配置检索",
    smoke: "冒烟检索",
    hosted_only: "仅 Hosted 补充",
    official_only: "仅官方来源",
    analysis_only: "仅分析续跑",
  };
  const coverageLabel = queryCoverage
    ? coverageScopeLabels[queryCoverage.scope] || queryCoverage.scope
    : "检索范围未知";
  document.querySelector("#run-state").textContent = run
    ? `${run.analysis_policy_current === false ? "历史策略运行 · " : ""}` +
      `${coverageLabel}${queryCoverage?.plan_complete === false ? " · 计划缺项" : ""}` +
      ` · ${observedRun?.state || run.status} · ${run.id.slice(0, 8)}`
    : "尚无运行";
  const cooldowns = status.source_cooldowns || [];
  const details = [`已加载 ${loadedWorksCount} / ${loadedWorksTotal} 条`];
  if (status.runtime) {
    details.push(
      `服务 ${status.runtime.service?.state || "unknown"}` +
        `，数据库 ${status.runtime.database?.state || "unknown"}` +
        `，调度 ${status.runtime.scheduler?.state || "unknown"}`,
    );
  }
  if (queryCoverage) {
    details.push(
      `检索计划 ${Number(queryCoverage.scheduled_jobs || 0)}/` +
        `${Number(queryCoverage.expected_jobs || 0)}，` +
        `终态 ${Number(queryCoverage.terminal_jobs || 0)}/` +
        `${Number(queryCoverage.scheduled_jobs || 0)}，` +
        `成功 ${Number(queryCoverage.successful_jobs || 0)}`,
    );
    if (!queryCoverage.complete_profile_run) {
      details.push("该运行不是完整配置检索，不代表全部查询已执行");
    }
    if (!queryCoverage.plan_complete) {
      details.push(
        `检索计划缺少 ${Number(queryCoverage.missing_jobs?.length || 0)} 个任务`,
      );
    }
  }
  if (status.discovery_policy?.high_recall_unfiltered) {
    details.push(
      "高召回发现模式：未做语义预筛，候选需经证据深读和人工反馈判定相关性",
    );
  }
  const publication = status.latest_publication;
  if (publication) {
    details.push(
      `${publication.analysis_policy_current === false ? "历史策略刊期" : "刊期"} ` +
        `${shortIdentifier(publication.issue_id)} · ` +
        `冻结运行 ${shortIdentifier(publication.run_id)} · ` +
        `冻结终态 ${publication.terminal_status}`,
    );
  } else {
    details.push("尚无可发布的终态刊期");
  }
  const usage = status.model_usage || {};
  details.push(
    `模型调用 ${Number(usage.invocation_count || 0)} 次` +
      `，输入 ${Number(usage.input_tokens || 0).toLocaleString()} tokens` +
      `，输出 ${Number(usage.output_tokens || 0).toLocaleString()} tokens`,
  );
  details.push(
    ...cooldowns.map((item) => `${item.source} 暂停至 ${item.not_before}`),
  );
  document.querySelector("#run-details").textContent = details.join("；");
  const deepRead =
    status.deep_read ||
    deriveDeepReadStatus(status, Array.isArray(works) ? works : allWorks);
  renderDeepReadStatus(deepRead, status.analysis_execution || {});
  const operations = document.querySelector("#operations-panel");
  const deepReadTotal = Number(deepRead.total || 0);
  const deepReadCompleted = Number(deepRead.completed || 0);
  const deepReadQueued = Number(deepRead.queued || 0);
  const deepReadRunning = Number(deepRead.running || 0);
  document.querySelector("#operations-summary").textContent =
    `${deepReadStateLabels[deepRead.state] || deepRead.state || "状态未知"} · ` +
    `深读 ${deepReadCompleted}/${deepReadTotal}` +
    (deepReadRunning ? ` · 正在处理 ${deepReadRunning}` : "") +
    (deepReadQueued ? ` · 排队 ${deepReadQueued}` : "");
  if (operations.dataset.initialized !== "true") {
    // Decision mode keeps operations collapsed. The summary still exposes live
    // attention states without displacing the user's 0–3 current actions.
    operations.open = false;
    operations.dataset.initialized = "true";
  }
  operations.dataset.attention = ["attention", "stalled"].includes(
    deepRead.state,
  )
    ? "true"
    : "false";
}

async function refreshStatusOnly() {
  if (document.hidden || fullRefreshInFlight || statusRefreshInFlight) return;
  statusRefreshInFlight = true;
  const generation = refreshGeneration;
  const refreshState = document.querySelector("#deep-read-refresh-state");
  try {
    const response = await fetch("/api/status");
    if (!response.ok) throw new Error("Status API request failed");
    const status = await response.json();
    if (generation !== refreshGeneration || fullRefreshInFlight) return;
    renderStatus(status, allWorks);
  } catch (error) {
    if (generation === refreshGeneration && !fullRefreshInFlight) {
      refreshState.textContent = `自动更新失败：${error.message}；15 秒后重试`;
    }
  } finally {
    statusRefreshInFlight = false;
  }
}

async function refresh() {
  if (fullRefreshInFlight || feedbackSubmissionsInFlight > 0) return;
  fullRefreshInFlight = true;
  refreshGeneration += 1;
  const feedbackGeneration = feedbackMutationGeneration;
  const button = document.querySelector("#refresh");
  button.disabled = true;
  button.textContent = "刷新中…";
  try {
    const [statusResponse, worksPayload] = await Promise.all([
      fetch("/api/status"),
      fetchWorksPage(),
      refreshDecisionSlice(),
    ]);
    if (!statusResponse.ok) throw new Error("Status API request failed");
    const status = await statusResponse.json();
    loadedWorksCount = worksPayload.works.length;
    loadedWorksTotal = worksPayload.total;
    nextWorksCursor = worksPayload.nextCursor;
    renderStatus(status, worksPayload.works);
    if (
      feedbackSubmissionsInFlight === 0 &&
      feedbackGeneration === feedbackMutationGeneration
    ) {
      const interactionState = captureWorkInteractionState();
      allWorks = worksPayload.works;
      populateSourceFilter();
      renderWorks();
      restoreWorkInteractionState(interactionState);
    }
  } finally {
    fullRefreshInFlight = false;
    button.disabled = false;
    button.textContent = "刷新";
  }
}

async function loadMoreWorks() {
  const button = document.querySelector("#load-more-works");
  if (!nextWorksCursor || button.disabled) return;
  button.disabled = true;
  button.textContent = "正在载入下一页…";
  try {
    const page = await fetchWorksPage(nextWorksCursor);
    const existing = new Set(allWorks.map((work) => String(work.id)));
    const additions = page.works.filter(
      (work) => !existing.has(String(work.id)),
    );
    if (!additions.length && page.nextCursor) {
      throw new Error("分页游标没有产生新条目");
    }
    allWorks = [...allWorks, ...additions];
    loadedWorksCount = allWorks.length;
    loadedWorksTotal = page.total;
    nextWorksCursor = page.nextCursor;
    populateSourceFilter();
    renderWorks();
  } catch (error) {
    button.textContent = `加载失败：${error.message}`;
  } finally {
    button.disabled = false;
  }
}

document.querySelector("#state-filter").addEventListener("change", renderWorks);
document.querySelector("#source-filter").addEventListener("change", renderWorks);
document.querySelector("#text-filter").addEventListener("input", renderWorks);
document.querySelector("#view-mode-toggle").addEventListener("click", () => {
  applyViewMode(viewMode === "compact" ? "deep" : "compact");
});
document.querySelector("#decision-scope-toggle").addEventListener("click", () => {
  decisionExpanded = !decisionExpanded;
  renderDecisionSlice();
  if (decisionExpanded && Number(decisionSlice.remaining_count || 0) > 0) {
    refreshDecisionSlice();
  }
});
document.querySelector("#refresh").addEventListener("click", () => {
  refresh().catch((error) => {
    document.querySelector("#run-state").textContent = `刷新失败：${error.message}`;
  });
});
document.querySelector("#load-more-works").addEventListener("click", loadMoreWorks);
applyViewMode(storedViewMode(), false);
refresh().catch((error) => {
  document.querySelector("#run-state").textContent = `载入失败：${error.message}`;
});
window.setInterval(refreshStatusOnly, DEEP_READ_POLL_INTERVAL_MS);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshStatusOnly();
});
