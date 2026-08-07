(() => {
  "use strict";

  const API_ROOT = "/token-tool/api";
  const state = {
    view: "mailboxes",
    mailboxes: { page: 1, total: 0 },
    uploads: { page: 1, total: 0 },
    pageSize: 50,
    searchTimer: null,
    toastTimer: null
  };
  const elements = {
    tabs: Array.from(document.querySelectorAll("[data-view]")),
    search: document.querySelector("#searchInput"),
    action: document.querySelector("#actionFilter"),
    refresh: document.querySelector("#refreshButton"),
    mailboxTable: document.querySelector("#mailboxTable"),
    mailboxBody: document.querySelector("#mailboxTable tbody"),
    uploadTable: document.querySelector("#uploadTable"),
    uploadBody: document.querySelector("#uploadTable tbody"),
    empty: document.querySelector("#emptyState"),
    title: document.querySelector("#viewTitle"),
    total: document.querySelector("#totalText"),
    loading: document.querySelector("#loadingText"),
    page: document.querySelector("#pageText"),
    previous: document.querySelector("#previousButton"),
    next: document.querySelector("#nextButton"),
    toast: document.querySelector("#toast")
  };

  function currentState() {
    return state[state.view];
  }

  function formatTime(value) {
    const date = new Date(String(value || ""));
    return Number.isNaN(date.getTime())
      ? "-"
      : date.toLocaleString("zh-CN", { hour12: false });
  }

  function showToast(message) {
    window.clearTimeout(state.toastTimer);
    elements.toast.textContent = message;
    elements.toast.classList.add("is-visible");
    state.toastTimer = window.setTimeout(() => elements.toast.classList.remove("is-visible"), 1800);
  }

  async function copyText(value) {
    try {
      await navigator.clipboard.writeText(value);
      showToast("邮箱已复制");
    } catch {
      showToast("复制失败");
    }
  }

  function cell(text, className = "") {
    const item = document.createElement("td");
    item.textContent = text;
    if (className) item.className = className;
    item.title = text;
    return item;
  }

  function emailCell(email) {
    const item = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy-button";
    button.textContent = email;
    button.title = "复制邮箱";
    button.addEventListener("click", () => copyText(email));
    item.append(button);
    return item;
  }

  function urlCell(url) {
    const item = document.createElement("td");
    if (!url) {
      item.textContent = "-";
      item.className = "muted";
      return item;
    }
    const wrapper = document.createElement("div");
    wrapper.className = "url-cell";
    const text = document.createElement("span");
    text.className = "url-text";
    text.textContent = url;
    text.title = url;
    const link = document.createElement("a");
    link.className = "url-link";
    link.href = url;
    link.target = "_blank";
    link.rel = "noreferrer noopener";
    link.textContent = "打开";
    wrapper.append(text, link);
    item.append(wrapper);
    return item;
  }

  function renderMailboxes(items) {
    elements.mailboxBody.replaceChildren();
    const start = (state.mailboxes.page - 1) * state.pageSize;
    items.forEach((item, index) => {
      const row = document.createElement("tr");
      row.append(cell(String(start + index + 1), "index-column"));
      row.append(emailCell(String(item.email || "")));
      const statusCell = document.createElement("td");
      const status = document.createElement("span");
      status.className = "status-tag";
      status.textContent = "可用";
      statusCell.append(status);
      row.append(statusCell);
      row.append(urlCell(String(item.mailbox_url || "")));
      row.append(cell(formatTime(item.first_uploaded_at)));
      row.append(cell(formatTime(item.last_uploaded_at)));
      row.append(cell(String(item.upload_count || 0), "count-column"));
      elements.mailboxBody.append(row);
    });
  }

  function actionLabel(action) {
    return { created: "新增", updated: "更新", duplicate: "重复" }[action] || action || "-";
  }

  function renderUploads(items) {
    elements.uploadBody.replaceChildren();
    const start = (state.uploads.page - 1) * state.pageSize;
    items.forEach((item, index) => {
      const row = document.createElement("tr");
      row.append(cell(String(start + index + 1), "index-column"));
      row.append(cell(formatTime(item.uploaded_at)));
      row.append(emailCell(String(item.email || "")));
      const actionCell = document.createElement("td");
      const tag = document.createElement("span");
      tag.className = `action-tag action-${String(item.action || "")}`;
      tag.textContent = actionLabel(item.action);
      actionCell.append(tag);
      row.append(actionCell);
      row.append(urlCell(String(item.submitted_url || "")));
      row.append(urlCell(item.action === "updated" ? String(item.previous_url || "") : ""));
      const batch = String(item.batch_id || "");
      row.append(cell(batch.length > 12 ? `${batch.slice(0, 12)}…` : batch, "batch-column"));
      elements.uploadBody.append(row);
    });
  }

  function updateChrome() {
    const current = currentState();
    const pages = Math.max(1, Math.ceil(current.total / state.pageSize));
    elements.title.textContent = state.view === "mailboxes" ? "唯一邮箱" : "上传记录";
    elements.total.textContent = `${current.total} 条`;
    elements.page.textContent = `第 ${current.page} / ${pages} 页`;
    elements.previous.disabled = current.page <= 1;
    elements.next.disabled = current.page >= pages;
    elements.empty.hidden = current.total > 0;
  }

  async function requestJson(url) {
    const response = await fetch(url, { cache: "no-store", credentials: "same-origin" });
    if (response.status === 401) {
      window.location.href = "/token-tool/mailboxes/login";
      throw new Error("登录已失效");
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) throw new Error(payload.error || "加载失败");
    return payload;
  }

  async function load() {
    const current = currentState();
    const query = new URLSearchParams({
      page: String(current.page),
      page_size: String(state.pageSize)
    });
    const search = elements.search.value.trim();
    if (search) query.set("search", search);
    if (state.view === "uploads" && elements.action.value) query.set("action", elements.action.value);
    elements.loading.textContent = "加载中";
    elements.refresh.disabled = true;
    try {
      const payload = await requestJson(`${API_ROOT}/${state.view}?${query}`);
      current.total = Number(payload.total || 0);
      if (state.view === "mailboxes") renderMailboxes(payload.items || []);
      else renderUploads(payload.items || []);
      updateChrome();
    } catch (error) {
      showToast(error.message || "加载失败");
    } finally {
      elements.loading.textContent = "";
      elements.refresh.disabled = false;
    }
  }

  function selectView(view) {
    state.view = view;
    elements.tabs.forEach((tab) => {
      const selected = tab.dataset.view === view;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", String(selected));
    });
    elements.mailboxTable.hidden = view !== "mailboxes";
    elements.uploadTable.hidden = view !== "uploads";
    elements.action.hidden = view !== "uploads";
    load();
  }

  elements.tabs.forEach((tab) => tab.addEventListener("click", () => selectView(tab.dataset.view)));
  elements.refresh.addEventListener("click", load);
  elements.search.addEventListener("input", () => {
    window.clearTimeout(state.searchTimer);
    state.mailboxes.page = 1;
    state.uploads.page = 1;
    state.searchTimer = window.setTimeout(load, 250);
  });
  elements.action.addEventListener("change", () => {
    state.uploads.page = 1;
    load();
  });
  elements.previous.addEventListener("click", () => {
    currentState().page = Math.max(1, currentState().page - 1);
    load();
  });
  elements.next.addEventListener("click", () => {
    currentState().page += 1;
    load();
  });

  load();
})();
