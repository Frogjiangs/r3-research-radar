"use strict";

(function goldReviewApplication(globalScope) {
  const PAGE_SIZE = 10;
  const AUTOSAVE_DELAY_MS = 2200;
  const ACTIVE_REVIEW_KEY = "r3.gold-review.active.v1";
  const DRAFT_PREFIX = "r3.gold-review.draft.v1:";
  const REVISION_SIGNAL_PREFIX = "r3.gold-review.revision.v1:";
  const FORBIDDEN_RESPONSE_FIELDS = new Set([
    "tier",
    "score",
    "selected",
    "selection_bucket",
    "captured_as",
    "provider",
    "model",
    "analysis",
    "ai_assistance",
    "frozen_snapshot",
    "review_context",
    "source_path",
  ]);
  const SEMANTIC_LABELS = new Set([
    "known_important",
    "relevant_not_priority",
    "boundary",
    "hard_negative",
    "unjudged",
  ]);
  const OPERATIONAL_STATUSES = new Set([
    "normal",
    "inaccessible",
    "identity_or_version_conflict",
    "recoverable_failure",
  ]);

  function containsForbiddenField(value) {
    if (Array.isArray(value)) {
      return value.some(containsForbiddenField);
    }
    if (value && typeof value === "object") {
      return Object.entries(value).some(
        ([key, nested]) => FORBIDDEN_RESPONSE_FIELDS.has(key) || containsForbiddenField(nested),
      );
    }
    return false;
  }

  function validateBlindPayload(payload) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("盲标接口返回了无效数据。");
    }
    if (containsForbiddenField(payload)) {
      throw new Error("盲标响应包含不应出现的模型或筛选字段，页面已停止显示。");
    }
    if (
      payload.schema !== "r3/gold-set-blind-view/v1"
      || payload.status !== "y0_in_progress"
      || !Array.isArray(payload.items)
      || !Number.isInteger(payload.item_count)
      || !Number.isInteger(payload.completed_count)
      || !Number.isInteger(payload.document_revision_sequence)
    ) {
      throw new Error("盲标接口合同不匹配，页面已停止显示。");
    }
    for (const item of payload.items) {
      if (
        !item || typeof item !== "object" || typeof item.item_id !== "string"
        || !item.citation || typeof item.citation !== "object"
        || !(item.y0 === null || typeof item.y0 === "object")
      ) {
        throw new Error("盲标条目结构无效。");
      }
    }
    return payload;
  }

  function canLock(completedCount, itemCount) {
    return Number.isInteger(completedCount)
      && Number.isInteger(itemCount)
      && itemCount === 70
      && completedCount === itemCount;
  }

  function confidenceNeedsReview(y0) {
    return Boolean(
      y0
      && y0.semantic_label !== "unjudged"
      && Number.isInteger(y0.confidence)
      && y0.confidence <= 2,
    );
  }

  function itemRevisionSequence(item) {
    return item && item.y0 && Number.isInteger(item.y0.revision_sequence)
      ? item.y0.revision_sequence
      : 0;
  }

  function requestId(prefix) {
    if (globalScope.crypto && typeof globalScope.crypto.randomUUID === "function") {
      return `${prefix}-${globalScope.crypto.randomUUID()}`;
    }
    return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  }

  function makeSubmission({
    reviewId,
    reviewerIdentity,
    item,
    documentRevisionSequence,
    values,
    elapsedMs,
    stableRequestId,
  }) {
    if (!reviewId || !reviewerIdentity || !item || !item.item_id) {
      throw new Error("标注会话缺少必要身份信息。");
    }
    if (!SEMANTIC_LABELS.has(values.semanticLabel)) {
      throw new Error("请选择语义价值。");
    }
    if (!OPERATIONAL_STATUSES.has(values.operationalStatus)) {
      throw new Error("请选择材料操作状态。");
    }
    const confidence = values.semanticLabel === "unjudged" ? null : values.confidence;
    if (values.semanticLabel !== "unjudged" && !Number.isInteger(confidence)) {
      throw new Error("已判断的条目需要选择 1–5 置信度。");
    }
    return {
      request_id: stableRequestId,
      item_id: item.item_id,
      reviewer_identity: reviewerIdentity,
      semantic_label: values.semanticLabel,
      operational_status: values.operationalStatus,
      confidence,
      evidence_opened: Boolean(values.evidenceOpened),
      elapsed_ms: Math.max(0, Math.round(elapsedMs)),
      notes: values.notes.trim() || null,
      submitted_at: new Date().toISOString(),
      expected_item_revision_sequence: itemRevisionSequence(item),
      expected_document_revision_sequence: documentRevisionSequence,
    };
  }

  const testHooks = Object.freeze({
    validateBlindPayload,
    containsForbiddenField,
    canLock,
    confidenceNeedsReview,
    itemRevisionSequence,
    makeSubmission,
  });
  globalScope.R3GoldReviewTestHooks = testHooks;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = testHooks;
  }

  if (typeof document === "undefined") {
    return;
  }

  const element = (selector) => document.querySelector(selector);
  const elements = {
    entryPanel: element("#entry-panel"),
    createForm: element("#create-form"),
    sourcePath: element("#source-path"),
    reviewerIdentity: element("#reviewer-identity"),
    resumeForm: element("#resume-form"),
    resumeReviewId: element("#resume-review-id"),
    resumeReviewer: element("#resume-reviewer"),
    entryStatus: element("#entry-status"),
    workspace: element("#review-workspace"),
    progress: element("#review-progress"),
    progressCount: element("#progress-count"),
    positionLabel: element("#position-label"),
    saveState: element("#save-state"),
    previous: element("#previous-item"),
    next: element("#next-item"),
    lowConfidence: element("#review-low-confidence"),
    conflictBanner: element("#conflict-banner"),
    reloadConflict: element("#reload-conflict"),
    card: element("#review-card"),
    recordKind: element("#record-kind"),
    itemState: element("#item-state"),
    title: element("#item-title"),
    authors: element("#item-authors"),
    identifiers: element("#item-identifiers"),
    abstract: element("#item-abstract"),
    evidenceLink: element("#evidence-link"),
    operationalEvidence: element("#operational-evidence"),
    annotationForm: element("#annotation-form"),
    confidenceFieldset: element("#confidence-fieldset"),
    evidenceOpened: element("#evidence-opened"),
    notes: element("#annotation-notes"),
    saveAnnotation: element("#save-annotation"),
    saveOnly: element("#save-only"),
    openLockDialog: element("#open-lock-dialog"),
    lockExplanation: element("#lock-explanation"),
    lockDialog: element("#lock-dialog"),
    lockConfirmation: element("#lock-confirmation"),
    confirmLock: element("#confirm-lock"),
    liveStatus: element("#live-status"),
  };

  const state = {
    reviewId: "",
    reviewerIdentity: "",
    pageOffset: 0,
    pageItems: [],
    currentIndex: 0,
    itemCount: 70,
    completedCount: 0,
    documentRevisionSequence: 0,
    itemStartedAt: Date.now(),
    dirty: false,
    saving: false,
    conflict: false,
    autosaveTimer: null,
    revisionChannel: null,
  };

  function storageGet(key) {
    try {
      const raw = globalScope.localStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch (_error) {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      globalScope.localStorage.setItem(key, JSON.stringify(value));
    } catch (_error) {
      // The review remains usable when private-mode storage is unavailable.
    }
  }

  function storageRemove(key) {
    try {
      globalScope.localStorage.removeItem(key);
    } catch (_error) {
      // Nothing else is required when storage is unavailable.
    }
  }

  function draftKey(itemId) {
    return `${DRAFT_PREFIX}${state.reviewId}:${itemId}`;
  }

  function announce(message) {
    elements.liveStatus.textContent = "";
    globalScope.setTimeout(() => { elements.liveStatus.textContent = message; }, 20);
  }

  async function requestJson(url, options = {}) {
    const response = await globalScope.fetch(url, {
      headers: options.body ? { "Content-Type": "application/json" } : undefined,
      ...options,
    });
    let payload;
    try {
      payload = await response.json();
    } catch (_error) {
      throw new Error(`服务器返回了无法解析的响应（HTTP ${response.status}）。`);
    }
    if (!response.ok) {
      const error = new Error(payload.error || `HTTP ${response.status}`);
      error.status = response.status;
      error.code = payload.error;
      throw error;
    }
    return payload;
  }

  function readableError(error) {
    const codes = {
      gold_review_conflict: "保存冲突：另一个标签页或进程已经更新了这轮标注。",
      gold_y0_unavailable: "这轮 y0 已不可继续，通常表示它已经锁定。",
      gold_review_not_found: "没有找到这个 Review ID。",
      invalid_gold_pagination: "分页参数无效。",
      invalid_origin: "请求来源不是当前本机页面。",
      invalid_gold_request: "输入不符合 Gold y0 合同，请检查文件、标识和当前版本后重试。",
      invalid_request: "输入不符合 Gold y0 合同，请检查后重试。",
    };
    return codes[error.code] || error.message || "发生未知错误。";
  }

  function formatAuthors(authors) {
    if (typeof authors === "string") return authors;
    if (!Array.isArray(authors)) return "";
    return authors.map((author) => {
      if (typeof author === "string") return author;
      return author && (author.display_name || author.name || author.orcid) || "";
    }).filter(Boolean).join("、");
  }

  function citationUrl(citation) {
    return citation.best_url || citation.canonical_url || citation.url || "";
  }

  function currentItem() {
    return state.pageItems[state.currentIndex] || null;
  }

  function currentAbsoluteIndex() {
    return state.pageOffset + state.currentIndex;
  }

  function formValues() {
    const semantic = elements.annotationForm.querySelector('input[name="semantic_label"]:checked');
    const operational = elements.annotationForm.querySelector('input[name="operational_status"]:checked');
    const confidence = elements.annotationForm.querySelector('input[name="confidence"]:checked');
    return {
      semanticLabel: semantic ? semantic.value : "",
      operationalStatus: operational ? operational.value : "",
      confidence: confidence ? Number(confidence.value) : null,
      evidenceOpened: elements.evidenceOpened.checked,
      notes: elements.notes.value,
    };
  }

  function setRadio(name, value) {
    elements.annotationForm.querySelectorAll(`input[name="${name}"]`).forEach((input) => {
      input.checked = String(input.value) === String(value);
    });
  }

  function saveLocalDraft() {
    const item = currentItem();
    if (!item) return;
    storageSet(draftKey(item.item_id), {
      values: formValues(),
      itemRevisionSequence: itemRevisionSequence(item),
      documentRevisionSequence: state.documentRevisionSequence,
      updatedAt: new Date().toISOString(),
    });
  }

  function updateConfidenceState() {
    const values = formValues();
    const unjudged = values.semanticLabel === "unjudged";
    elements.confidenceFieldset.disabled = unjudged;
    if (unjudged) setRadio("confidence", null);
  }

  function updateProgress() {
    elements.progress.max = state.itemCount;
    elements.progress.value = state.completedCount;
    elements.progress.textContent = `${state.completedCount} / ${state.itemCount}`;
    elements.progressCount.textContent = `${state.completedCount} / ${state.itemCount}`;
    elements.positionLabel.textContent = `第 ${Math.min(currentAbsoluteIndex() + 1, state.itemCount)} 条，共 ${state.itemCount} 条`;
    elements.previous.disabled = currentAbsoluteIndex() <= 0 || state.saving;
    elements.next.disabled = currentAbsoluteIndex() >= state.itemCount - 1 || state.saving;
    const ready = canLock(state.completedCount, state.itemCount) && !state.conflict && !state.saving;
    elements.openLockDialog.disabled = !ready;
    elements.lockExplanation.textContent = ready
      ? "70 条均已保存。请先复核低置信度条目，再决定是否执行不可撤销的锁定。"
      : `${state.itemCount - state.completedCount} 条尚未保存；半标状态不能锁定。`;
  }

  function renderItem({ preserveDraft = true, focusHeading = true } = {}) {
    const item = currentItem();
    if (!item) {
      elements.title.textContent = "当前分页没有可显示的条目";
      return;
    }
    const citation = item.citation;
    elements.recordKind.textContent = item.record_class === "operational_sentinel"
      ? "操作边界样本"
      : (citation.kind || "研究材料");
    elements.itemState.textContent = item.y0 ? "已保存，可复核" : "未标注";
    elements.itemState.classList.toggle("saved", Boolean(item.y0));
    elements.title.textContent = citation.title || citation.github_full_name || "无题名记录";
    elements.authors.textContent = formatAuthors(citation.authors);
    const identifiers = [citation.year, citation.doi, citation.arxiv_id, citation.github_full_name]
      .filter((value) => value !== undefined && value !== null && String(value).trim())
      .map(String);
    elements.identifiers.textContent = identifiers.join(" · ");
    const abstract = citation.abstract || citation.abstract_text || citation.description || citation.readme_excerpt || "";
    elements.abstract.textContent = abstract || "该记录没有可用摘要。请依据题名和可访问的原始证据判断；证据不足时选择“暂不判断”。";
    elements.abstract.classList.toggle("missing", !abstract);
    const url = citationUrl(citation);
    elements.evidenceLink.hidden = !url;
    if (url) elements.evidenceLink.href = url;
    elements.operationalEvidence.hidden = Object.keys(item.operational_evidence || {}).length === 0;
    elements.operationalEvidence.textContent = elements.operationalEvidence.hidden
      ? ""
      : `采集状态证据：${Object.entries(item.operational_evidence).map(([key, value]) => `${key}=${String(value)}`).join("；")}`;

    const source = item.y0 || {
      semantic_label: "",
      operational_status: "normal",
      confidence: null,
      evidence_opened: false,
      notes: "",
    };
    const draft = preserveDraft ? storageGet(draftKey(item.item_id)) : null;
    const values = draft && draft.itemRevisionSequence === itemRevisionSequence(item)
      ? draft.values
      : {
          semanticLabel: source.semantic_label,
          operationalStatus: source.operational_status,
          confidence: source.confidence,
          evidenceOpened: source.evidence_opened,
          notes: source.notes || "",
        };
    setRadio("semantic_label", values.semanticLabel);
    setRadio("operational_status", values.operationalStatus || "normal");
    setRadio("confidence", values.confidence);
    elements.evidenceOpened.checked = Boolean(values.evidenceOpened);
    elements.notes.value = values.notes || "";
    state.dirty = Boolean(draft);
    state.itemStartedAt = Date.now();
    updateConfidenceState();
    elements.saveState.textContent = state.dirty ? "已恢复本机草稿，尚未写入服务器" : (item.y0 ? "已保存" : "尚未修改");
    elements.saveState.className = state.dirty ? "warning-state" : "";
    updateProgress();
    if (focusHeading) elements.title.focus({ preventScroll: true });
  }

  function markDirty() {
    if (!currentItem() || state.saving || state.conflict) return;
    state.dirty = true;
    saveLocalDraft();
    elements.saveState.textContent = "草稿已保存在本机";
    elements.saveState.className = "warning-state";
    globalScope.clearTimeout(state.autosaveTimer);
    const values = formValues();
    const complete = values.semanticLabel
      && values.operationalStatus
      && (values.semanticLabel === "unjudged" || Number.isInteger(values.confidence));
    if (complete) {
      state.autosaveTimer = globalScope.setTimeout(() => {
        saveCurrent({ moveAfter: false, automatic: true }).catch(() => {});
      }, AUTOSAVE_DELAY_MS);
    }
  }

  function configureRevisionSignals() {
    if (state.revisionChannel) state.revisionChannel.close();
    state.revisionChannel = null;
    if (typeof globalScope.BroadcastChannel === "function") {
      state.revisionChannel = new globalScope.BroadcastChannel(`r3-gold-review:${state.reviewId}`);
      state.revisionChannel.onmessage = (event) => receiveRevisionSignal(event.data);
    }
  }

  function broadcastRevision(sequence) {
    const signal = { reviewId: state.reviewId, sequence, sender: requestId("tab") };
    if (state.revisionChannel) state.revisionChannel.postMessage(signal);
    storageSet(`${REVISION_SIGNAL_PREFIX}${state.reviewId}`, signal);
  }

  function receiveRevisionSignal(signal) {
    if (
      signal && signal.reviewId === state.reviewId
      && Number.isInteger(signal.sequence)
      && signal.sequence > state.documentRevisionSequence
    ) {
      showConflict("另一个标签页已保存更新；自动保存已暂停。请载入最新版本后继续。");
    }
  }

  function showConflict(message) {
    state.conflict = true;
    globalScope.clearTimeout(state.autosaveTimer);
    elements.conflictBanner.hidden = false;
    elements.saveState.textContent = "检测到版本冲突，当前草稿未覆盖服务器";
    elements.saveState.className = "warning-state";
    elements.saveAnnotation.disabled = true;
    elements.saveOnly.disabled = true;
    updateProgress();
    announce(message);
  }

  async function loadPage(offset, { preserveDraft = true, focusHeading = true } = {}) {
    elements.card.setAttribute("aria-busy", "true");
    const normalizedOffset = Math.max(0, Math.min(offset, state.itemCount - 1));
    const pageOffset = Math.floor(normalizedOffset / PAGE_SIZE) * PAGE_SIZE;
    try {
      const payload = validateBlindPayload(await requestJson(
        `/api/gold/reviews/${encodeURIComponent(state.reviewId)}/y0?limit=${PAGE_SIZE}&offset=${pageOffset}`,
      ));
      state.pageOffset = payload.offset;
      state.pageItems = payload.items;
      state.currentIndex = Math.min(normalizedOffset - payload.offset, Math.max(0, payload.items.length - 1));
      state.itemCount = payload.item_count;
      state.completedCount = payload.completed_count;
      state.documentRevisionSequence = payload.document_revision_sequence;
      state.conflict = false;
      elements.conflictBanner.hidden = true;
      elements.saveAnnotation.disabled = false;
      elements.saveOnly.disabled = false;
      renderItem({ preserveDraft, focusHeading });
    } finally {
      elements.card.setAttribute("aria-busy", "false");
    }
  }

  async function openReview(reviewId, reviewerIdentity, offset = 0) {
    state.reviewId = reviewId.trim();
    state.reviewerIdentity = reviewerIdentity.trim();
    if (!state.reviewId || !state.reviewerIdentity) {
      throw new Error("Review ID 和标注者标识不能为空。");
    }
    storageSet(ACTIVE_REVIEW_KEY, {
      reviewId: state.reviewId,
      reviewerIdentity: state.reviewerIdentity,
    });
    configureRevisionSignals();
    await loadPage(offset, { focusHeading: false });
    elements.entryPanel.hidden = true;
    elements.workspace.hidden = false;
    const url = new URL(globalScope.location.href);
    url.searchParams.set("review", state.reviewId);
    globalScope.history.replaceState(null, "", url);
    elements.title.focus();
  }

  async function saveCurrent({ moveAfter, automatic = false }) {
    if (state.saving || state.conflict || !state.dirty) return true;
    globalScope.clearTimeout(state.autosaveTimer);
    const item = currentItem();
    const values = formValues();
    let payload;
    try {
      const storedDraft = storageGet(draftKey(item.item_id));
      const retry = storedDraft
        && storedDraft.pendingPayload
        && JSON.stringify(storedDraft.values) === JSON.stringify(values)
        && storedDraft.itemRevisionSequence === itemRevisionSequence(item)
        && storedDraft.documentRevisionSequence === state.documentRevisionSequence;
      payload = retry ? storedDraft.pendingPayload : makeSubmission({
          reviewId: state.reviewId,
          reviewerIdentity: state.reviewerIdentity,
          item,
          documentRevisionSequence: state.documentRevisionSequence,
          values,
          elapsedMs: Date.now() - state.itemStartedAt,
          stableRequestId: requestId("y0"),
        });
    } catch (error) {
      elements.saveState.textContent = error.message;
      elements.saveState.className = "error-state";
      if (!automatic) announce(error.message);
      return false;
    }
    state.saving = true;
    elements.saveAnnotation.disabled = true;
    elements.saveOnly.disabled = true;
    elements.saveState.textContent = automatic ? "正在自动保存…" : "正在保存…";
    elements.saveState.className = "";
    storageSet(draftKey(item.item_id), {
      values,
      pendingPayload: payload,
      itemRevisionSequence: itemRevisionSequence(item),
      documentRevisionSequence: state.documentRevisionSequence,
      updatedAt: new Date().toISOString(),
    });
    try {
      const response = await requestJson(
        `/api/gold/reviews/${encodeURIComponent(state.reviewId)}/y0`,
        { method: "POST", body: JSON.stringify(payload) },
      );
      const wasUnlabeled = item.y0 === null;
      const nextRevision = itemRevisionSequence(item) + 1;
      item.y0 = {
        semantic_label: payload.semantic_label,
        operational_status: payload.operational_status,
        confidence: payload.confidence,
        evidence_opened: payload.evidence_opened,
        notes: payload.notes,
        revision_sequence: nextRevision,
      };
      state.documentRevisionSequence = response.review.document_revision_sequence;
      if (wasUnlabeled) state.completedCount += 1;
      state.dirty = false;
      storageRemove(draftKey(item.item_id));
      elements.saveState.textContent = automatic ? "已自动保存" : "已保存";
      elements.saveState.className = "";
      elements.itemState.textContent = "已保存，可复核";
      elements.itemState.classList.add("saved");
      broadcastRevision(state.documentRevisionSequence);
      updateProgress();
      announce(`第 ${currentAbsoluteIndex() + 1} 条已保存。`);
      if (moveAfter && currentAbsoluteIndex() < state.itemCount - 1) {
        await goToAbsolute(currentAbsoluteIndex() + 1, { saveBefore: false });
      }
      return true;
    } catch (error) {
      if (error.status === 409) {
        showConflict("保存未覆盖服务器：另一个标签页或进程已先更新。当前草稿仍保留在本机。");
      } else {
        elements.saveState.textContent = `${readableError(error)} 草稿仍保存在本机。`;
        elements.saveState.className = "error-state";
        announce(elements.saveState.textContent);
      }
      return false;
    } finally {
      state.saving = false;
      if (!state.conflict) {
        elements.saveAnnotation.disabled = false;
        elements.saveOnly.disabled = false;
      }
      updateProgress();
    }
  }

  async function goToAbsolute(index, { saveBefore = true } = {}) {
    if (saveBefore && state.dirty) {
      const saved = await saveCurrent({ moveAfter: false });
      if (!saved) return;
    }
    if (index < 0 || index >= state.itemCount) return;
    if (index >= state.pageOffset && index < state.pageOffset + state.pageItems.length) {
      state.currentIndex = index - state.pageOffset;
      renderItem();
    } else {
      await loadPage(index);
    }
  }

  async function findLowConfidence() {
    if (state.dirty && !(await saveCurrent({ moveAfter: false }))) return;
    elements.lowConfidence.disabled = true;
    elements.saveState.textContent = "正在检查 70 条已保存判断…";
    try {
      for (let offset = 0; offset < state.itemCount; offset += 25) {
        const payload = validateBlindPayload(await requestJson(
          `/api/gold/reviews/${encodeURIComponent(state.reviewId)}/y0?limit=25&offset=${offset}`,
        ));
        const localIndex = payload.items.findIndex((item) => confidenceNeedsReview(item.y0));
        if (localIndex >= 0) {
          await goToAbsolute(offset + localIndex, { saveBefore: false });
          announce(`已定位到第 ${offset + localIndex + 1} 条低置信度判断。`);
          return;
        }
      }
      elements.saveState.textContent = "没有置信度 1–2 的已判断条目";
      announce("没有需要集中复核的低置信度条目。");
    } catch (error) {
      elements.saveState.textContent = readableError(error);
      elements.saveState.className = "error-state";
    } finally {
      elements.lowConfidence.disabled = false;
    }
  }

  async function lockReview() {
    if (!canLock(state.completedCount, state.itemCount) || state.dirty || state.conflict) {
      announce("只有 70 条全部保存且没有冲突时才能锁定。");
      return;
    }
    elements.confirmLock.disabled = true;
    try {
      const response = await requestJson(
        `/api/gold/reviews/${encodeURIComponent(state.reviewId)}/lock`,
        {
          method: "POST",
          body: JSON.stringify({
            request_id: requestId("y0-lock"),
            reviewer_identity: state.reviewerIdentity,
            locked_at: new Date().toISOString(),
            expected_document_revision_sequence: state.documentRevisionSequence,
          }),
        },
      );
      state.documentRevisionSequence = response.review.document_revision_sequence;
      storageRemove(ACTIVE_REVIEW_KEY);
      elements.lockDialog.close();
      elements.annotationForm.querySelectorAll("input, textarea, button").forEach((control) => { control.disabled = true; });
      elements.openLockDialog.disabled = true;
      elements.lockExplanation.textContent = "y0 已锁定。独立判断不会再修改；下一步应进入单独的随机化 y1 辅助评估，而不是在本页揭示 AI 结果。";
      elements.saveState.textContent = "y0 已锁定";
      announce("70 条 y0 已锁定。下一阶段是 y1 辅助评估。此页没有展示 AI 结果。");
    } catch (error) {
      elements.lockDialog.close();
      if (error.status === 409) showConflict("锁定冲突：服务器版本已经变化，请先载入最新版本。");
      else announce(readableError(error));
    }
  }

  elements.createForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    elements.entryStatus.textContent = "正在导入本机文件并创建盲标任务…";
    elements.entryStatus.className = "inline-status";
    const sourcePath = elements.sourcePath.value.trim();
    const reviewerIdentity = elements.reviewerIdentity.value.trim();
    if (!sourcePath || !reviewerIdentity) return;
    try {
      const response = await requestJson("/api/gold/reviews", {
        method: "POST",
        body: JSON.stringify({
          source_path: sourcePath,
          reviewer_identity: reviewerIdentity,
          creation_request_id: requestId("create"),
        }),
      });
      elements.sourcePath.value = "";
      await openReview(response.review.review_id, reviewerIdentity, 0);
      announce("盲标任务已创建。文件路径未保存在页面中。");
    } catch (error) {
      elements.entryStatus.textContent = readableError(error);
      elements.entryStatus.className = "inline-status error-state";
    }
  });

  elements.resumeForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    elements.entryStatus.textContent = "正在恢复盲标进度…";
    elements.entryStatus.className = "inline-status";
    try {
      await openReview(elements.resumeReviewId.value, elements.resumeReviewer.value, 0);
      announce("已载入服务器进度和本机草稿。");
    } catch (error) {
      elements.entryStatus.textContent = readableError(error);
      elements.entryStatus.className = "inline-status error-state";
    }
  });

  elements.annotationForm.addEventListener("input", () => {
    updateConfidenceState();
    markDirty();
  });
  elements.annotationForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await saveCurrent({ moveAfter: true });
  });
  elements.saveOnly.addEventListener("click", () => saveCurrent({ moveAfter: false }));
  elements.previous.addEventListener("click", () => goToAbsolute(currentAbsoluteIndex() - 1));
  elements.next.addEventListener("click", () => goToAbsolute(currentAbsoluteIndex() + 1));
  elements.lowConfidence.addEventListener("click", findLowConfidence);
  elements.evidenceLink.addEventListener("click", () => {
    elements.evidenceOpened.checked = true;
    markDirty();
  });
  elements.reloadConflict.addEventListener("click", async () => {
    const index = currentAbsoluteIndex();
    try {
      await loadPage(index, { preserveDraft: true });
      announce("已载入服务器最新版本；若草稿对应的条目未被他处修改，仍可继续保存。请重新核对当前选择。");
    } catch (error) {
      announce(readableError(error));
    }
  });
  elements.openLockDialog.addEventListener("click", () => {
    if (!canLock(state.completedCount, state.itemCount) || state.dirty) return;
    elements.lockConfirmation.checked = false;
    elements.confirmLock.disabled = true;
    elements.lockDialog.showModal();
  });
  elements.lockConfirmation.addEventListener("change", () => {
    elements.confirmLock.disabled = !elements.lockConfirmation.checked;
  });
  elements.confirmLock.addEventListener("click", (event) => {
    event.preventDefault();
    if (elements.lockConfirmation.checked) lockReview();
  });

  globalScope.addEventListener("storage", (event) => {
    if (event.key === `${REVISION_SIGNAL_PREFIX}${state.reviewId}` && event.newValue) {
      try { receiveRevisionSignal(JSON.parse(event.newValue)); } catch (_error) { /* ignore malformed local signals */ }
    }
  });

  globalScope.addEventListener("keydown", (event) => {
    if (elements.workspace.hidden || state.saving) return;
    const tag = event.target && event.target.tagName && event.target.tagName.toLowerCase();
    const editingText = tag === "input" || tag === "textarea";
    if (!editingText && /^[1-5]$/.test(event.key)) {
      const input = elements.annotationForm.querySelectorAll('input[name="semantic_label"]')[Number(event.key) - 1];
      if (input) {
        input.checked = true;
        updateConfidenceState();
        markDirty();
        input.focus();
        event.preventDefault();
      }
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
      event.preventDefault();
      saveCurrent({ moveAfter: false });
    } else if (event.altKey && event.key === "ArrowLeft") {
      event.preventDefault();
      goToAbsolute(currentAbsoluteIndex() - 1);
    } else if (event.altKey && event.key === "ArrowRight") {
      event.preventDefault();
      goToAbsolute(currentAbsoluteIndex() + 1);
    }
  });

  (async function boot() {
    const active = storageGet(ACTIVE_REVIEW_KEY);
    const reviewFromUrl = new URL(globalScope.location.href).searchParams.get("review");
    if (active && active.reviewId && active.reviewerIdentity) {
      elements.resumeReviewId.value = active.reviewId;
      elements.resumeReviewer.value = active.reviewerIdentity;
    }
    if (reviewFromUrl && active && active.reviewId === reviewFromUrl) {
      try {
        await openReview(active.reviewId, active.reviewerIdentity, 0);
        announce("已自动恢复上次盲标任务。");
      } catch (error) {
        elements.entryStatus.textContent = readableError(error);
        elements.entryStatus.className = "inline-status error-state";
      }
    } else if (reviewFromUrl) {
      elements.resumeReviewId.value = reviewFromUrl;
      elements.resumeReviewer.focus();
      elements.entryStatus.textContent = "请输入原标注者标识以继续这轮盲标。";
    }
  })();
}(typeof globalThis !== "undefined" ? globalThis : window));
