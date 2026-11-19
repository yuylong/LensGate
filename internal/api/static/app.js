const state = {
  flows: [],
  alerts: [],
  rules: [],
  stats: null,
  search: "",
  confidence: "",
  selected: null,
  detail: null,
  detailToken: null,
  sseExpanded: false,
};

// 单次最多直接渲染的 SSE 事件数，其余通过按钮展开，避免超长流阻塞页面。
const SSE_PAGE = 200;

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtTime(v) {
  if (!v) return "-";
  const d = new Date(v);
  if (isNaN(d.getTime())) return String(v);
  return d.toLocaleTimeString("zh-CN", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function fmtFull(v) {
  if (!v) return "-";
  const d = new Date(v);
  if (isNaN(d.getTime())) return String(v);
  return d.toLocaleString("zh-CN", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function badge(text, cls) {
  return `<span class="badge ${esc(cls || "")}">${esc(text || "-")}</span>`;
}

function confBadge(c) {
  return badge(c || "not_ai", c || "not_ai");
}

function levelBadge(l) {
  return badge(l || "low", l || "low");
}

// 客户端指纹由后端依据请求头推断（UA 可伪造），这里只做展示映射。
const CLIENT_LABELS = {
  browser: "浏览器·直接",
  "browser-fetch": "浏览器·JS",
  // 已预置的 AI 应用 / Agent
  trae: "Trae",
  copilot: "GitHub Copilot",
  "claude-code": "Claude Code",
  cursor: "Cursor",
  windsurf: "Windsurf",
  cline: "Cline",
  continue: "Continue",
  aider: "Aider",
  codex: "Codex CLI",
  "gemini-cli": "Gemini CLI",
  electron: "Electron 应用",
  // SDK / 框架 / 工具
  "openai-python-sdk": "Python SDK",
  "openai-node-sdk": "Node SDK",
  "openai-sdk": "其他 SDK",
  langchain: "LangChain",
  llamaindex: "LlamaIndex",
  openrouter: "OpenRouter",
  hertz: "Hertz (Go)",
  curl: "curl",
  postman: "Postman",
  "python-http": "Python HTTP",
  "go-http-client": "Go HTTP",
  "node-http": "Node HTTP",
  powershell: "PowerShell",
  unknown: "未知",
};

const CLIENT_IDE = new Set([
  "trae", "copilot", "claude-code", "cursor", "windsurf",
  "cline", "continue", "aider", "codex", "gemini-cli",
]);

function clientLabel(k) {
  return CLIENT_LABELS[k] || k || "未知";
}

function clientGroup(k) {
  if (!k || k === "unknown") return "c-unknown";
  if (CLIENT_IDE.has(k)) return "c-ide";
  if (k.startsWith("openai") || k === "langchain" || k === "llamaindex" ||
      k === "openrouter" || k === "electron") return "c-agent";
  if (k.startsWith("browser")) return "c-browser";
  return "c-cli";
}

// 未识别时直接展示原始 User-Agent，避免“未知”丢失可用信息。
function clientBadge(kind, detail) {
  const raw = String(detail || "").trim();
  if (!kind || kind === "unknown") {
    if (!raw) {
      return `<span class="badge client c-unknown" title="客户端未声明 User-Agent">未声明 UA</span>`;
    }
    return `<span class="badge client c-unknown mono" title="未匹配已知指纹，原始 User-Agent：${esc(raw)}">${esc(raw)}</span>`;
  }
  return `<span class="badge client ${clientGroup(kind)}" title="${esc(kind)} · 依据请求头指纹推断，可被伪造">${esc(clientLabel(kind))}</span>`;
}

async function getJSON(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(url + " -> " + res.status);
  return res.json();
}

function renderStats() {
  const st = state.stats || { by_confidence: {} };
  const conf = st.by_confidence || {};
  $("statFlows").textContent = st.total_flows || 0;
  $("statAlerts").textContent = st.total_alerts || 0;
  $("statConfirmed").textContent = conf.confirmed || 0;
  $("statSuspect").textContent = (conf.compatible || 0) + (conf.suspected || 0);
}

function flowMatches(f) {
  if (state.confidence && f.confidence !== state.confidence) return false;
  if (!state.search) return true;
  const q = state.search.toLowerCase();
  const hay = [
    f.host, f.path, f.model, f.protocol_family, f.api_variant,
    f.client_kind, f.client_detail,
    (f.findings || []).map((x) => x.rule_id + " " + x.rule_name).join(" "),
  ].join(" ").toLowerCase();
  return hay.includes(q);
}

function renderFlows() {
  const rows = state.flows.filter(flowMatches);
  $("flowCount").textContent = `显示 ${rows.length} / ${state.flows.length} 条`;
  const body = $("flowRows");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="9" class="empty">暂无流量。把应用的代理指向控制台显示的地址，或先运行演示客户端。</td></tr>`;
    return;
  }
  body.innerHTML = rows.map((f, idx) => {
    const usage = f.usage ? `${f.usage.total || (f.usage.input + f.usage.output)}` : "-";
    const hits = (f.findings || []).map((x) => `${x.rule_id}`).join(", ");
    return `<tr data-idx="${idx}" data-flow-id="${esc(f.id)}">
      <td class="muted">${esc(fmtTime(f.started_at))}</td>
      <td><div class="host">${esc(f.host || "-")}</div><div class="path">${esc(f.method || "")} ${esc(f.path || "")}</div></td>
      <td>${esc(f.api_variant || f.protocol_family || "-")}${f.stream ? "<br><span class=\"muted\">stream</span>" : ""}</td>
      <td>${confBadge(f.confidence)}</td>
      <td>${clientBadge(f.client_kind, f.client_detail)}</td>
      <td>${esc(f.model || "-")}</td>
      <td class="mono">${esc(usage)}</td>
      <td>${esc(f.status || "-")}</td>
      <td>${hits ? badge(hits, "high") : '<span class="muted">-</span>'}</td>
    </tr>`;
  }).join("");

  body.querySelectorAll("tr[data-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const f = rows[Number(tr.dataset.idx)];
      openDrawer(f);
    });
  });
  markSelectedRow();
}

function markSelectedRow() {
  document.querySelectorAll("#flowRows tr[data-flow-id]").forEach((tr) => {
    tr.classList.toggle("selected", !!state.selected && tr.dataset.flowId === state.selected.id);
  });
}

function openDrawer(f) {
  if (!f) return;
  state.selected = f;
  state.detail = null;
  state.sseExpanded = false;
  state.detailToken = f.id;
  $("drawerTitle").textContent = "流量详情 · " + (f.id || "-");
  $("drawerSub").textContent = [f.method, f.host, f.path].filter(Boolean).join(" ");
  $("flowDrawer").classList.add("open");
  $("flowDrawer").setAttribute("aria-hidden", "false");
  $("drawerOverlay").classList.add("open");
  markSelectedRow();
  $("drawerBody").innerHTML = '<div class="muted drawer-loading">正在加载详情…</div>';

  const token = f.id;
  getJSON("/api/flows/" + encodeURIComponent(token))
    .then((d) => {
      if (state.detailToken !== token) return;
      state.detail = d;
      renderDrawer();
    })
    .catch((err) => {
      if (state.detailToken !== token) return;
      // not_ai 流量按约定不保留正文；历史流量也可能没有详情落盘，退化为摘要展示。
      const hint = f.confidence === "not_ai"
        ? "该流量被判定为 not_ai，按隐私约定不保存正文详情。"
        : `详情加载失败：${esc(err.message)}。该流量可能早于详情落盘功能。`;
      $("drawerBody").innerHTML =
        `<div class="muted drawer-loading">${hint}</div>` +
        section("基础信息", baseInfo(null, f), true) +
        section("协议识别", protocolInfo(f), true) +
        section("命中规则", findingsInfo(f), true);
      markHits($("drawerBody"), f.findings);
    });
}

function closeDrawer() {
  state.detailToken = null;
  state.detail = null;
  state.selected = null;
  $("flowDrawer").classList.remove("open");
  $("flowDrawer").setAttribute("aria-hidden", "true");
  $("drawerOverlay").classList.remove("open");
  markSelectedRow();
}

function section(title, body, open) {
  return `<details class="sec"${open ? " open" : ""}><summary>${esc(title)}</summary><div class="sec-body">${body}</div></details>`;
}

function kv(items) {
  const rows = items.filter(([, v]) => v !== undefined && v !== null && v !== "");
  if (!rows.length) return '<div class="muted">无</div>';
  return `<div class="kv">${rows.map(([k, v]) => `<div class="k">${esc(k)}</div><div class="v">${v}</div>`).join("")}</div>`;
}

function prettyJSON(text) {
  const t = String(text == null ? "" : text).trim();
  if (!t) return "";
  try {
    return JSON.stringify(JSON.parse(t), null, 2);
  } catch (_) {
    return t;
  }
}

function charCount(text) {
  const n = String(text == null ? "" : text).length;
  return n > 1024 ? (n / 1024).toFixed(1) + "K 字符" : n + " 字符";
}

function truncBadge(flag) {
  return flag ? '<span class="badge medium">已截断</span> ' : "";
}

function headerList(headers) {
  if (!headers || !headers.length) return '<div class="muted">无</div>';
  const rows = headers.map((h) =>
    (h.values || []).map((v) => `<div class="hrow"><span class="hname">${esc(h.name)}</span><span class="hval">${esc(v)}</span></div>`).join("")
  ).join("");
  return `<div class="headers">${rows}</div>`;
}

function toolCallList(calls, prefix) {
  if (!calls || !calls.length) return "";
  return `<div class="toolcalls">${calls.map((tc, j) => `
    <div class="toolcall" data-field="${esc(prefix)}[${j}]">
      <div class="toolcall-head">${esc(tc.name || "(未命名)")}${tc.id ? `<span class="muted">${esc(tc.id)}</span>` : ""}</div>
      <pre class="code">${esc(prettyJSON(tc.arguments) || "(无参数)")}</pre>
    </div>`).join("")}</div>`;
}

function messageList(messages) {
  if (!messages || !messages.length) return '<div class="muted">未解析出 messages</div>';
  return `<div class="msgs">${messages.map((m, i) => `
    <div class="msg" data-field="messages[${i}]">
      <div class="msg-head">${badge(m.role || "?", "")}<span class="muted">messages[${i}]</span></div>
      <div data-field="messages[${i}].content"><pre class="code">${esc(m.content || "(空)")}</pre></div>
      ${toolCallList(m.tool_calls, `messages[${i}].tool_calls`)}
    </div>`).join("")}</div>`;
}

function toolList(tools) {
  if (!tools || !tools.length) return "";
  return `<div class="tools">${tools.map((t, i) => `
    <div class="tool" data-field="tools[${i}]">
      <div class="tool-head">${esc(t.name || "(未命名)")}</div>
      <div class="muted">${esc(t.description || "无描述")}</div>
    </div>`).join("")}</div>`;
}

function sseList(events) {
  if (!events || !events.length) return "";
  const limit = state.sseExpanded ? events.length : SSE_PAGE;
  const items = events.slice(0, limit).map((ev, i) => `
    <details class="sse-item">
      <summary>#${i + 1} ${esc(ev.event || "message")}</summary>
      <pre class="code">${esc(prettyJSON(ev.data) || "(空)")}</pre>
    </details>`).join("");
  const more = events.length > limit
    ? `<button class="btn ghost" data-more-sse="1" style="margin-top:8px">显示全部 ${events.length} 条事件</button>`
    : "";
  return `<div class="sub-title">SSE 事件（${events.length}）</div>${items}${more}`;
}

function baseInfo(d, f) {
  const r = (d && d.request) || {};
  return kv([
    ["ID", `<span class="mono">${esc(f.id || "-")}</span>`],
    ["开始时间", esc(fmtFull(f.started_at))],
    ["结束时间", esc(fmtFull(f.ended_at))],
    ["耗时", esc(f.duration_ms == null ? "-" : f.duration_ms + " ms")],
    ["接入方式", esc(f.ingress || "-")],
    ["源 → 目的", `<span class="mono">${esc(f.src || "-")} → ${esc(f.dst || "-")}</span>`],
    ["原始目的", `<span class="mono">${esc(f.original_dst || "-")}</span>`],
    ["SNI", esc(f.sni || "-")],
    ["ALPN", esc(((d && d.alpn) || []).join(", ") || "-")],
    ["TLS", d ? (d.is_tls ? "是" : "否") : "-"],
    ["方法", esc(r.method || f.method || "-")],
    ["主机", esc(r.host || f.host || "-")],
    ["路径", `<span class="mono">${esc(r.path || f.path || "-")}</span>`],
    ["查询串", `<span class="mono">${esc(r.query || "-")}</span>`],
    ["状态码", esc(f.status || "-")],
  ]);
}

function protocolInfo(f) {
  const evidence = (f.evidence || []).map((e) => `<li>${esc(e)}</li>`).join("");
  const body = kv([
    ["协议族", esc(f.protocol_family || "-")],
    ["API 变体", esc(f.api_variant || "-")],
    ["置信度", confBadge(f.confidence)],
    ["客户端", clientBadge(f.client_kind, f.client_detail)],
    ["客户端明细", esc(f.client_detail || "-")],
    ["客户端依据", esc(f.client_reason || "-")],
    ["模型", esc(f.model || "-")],
    ["流式", f.stream ? "是" : "否"],
    ["解析状态", esc((f.parse_status || []).join(", ") || "-")],
  ]);
  const list = evidence ? `<div class="sub-title">分类依据</div><ul class="evidence">${evidence}</ul>` : "";
  return body + list;
}

function requestInfo(d) {
  const r = d.request || {};
  const parts = [kv([
    ["Content-Type", esc(r.content_type || "-")],
    ["模型", esc(r.model || "-")],
    ["流式", r.stream ? "是" : "否"],
    ["请求体", r.body ? truncBadge(r.body_truncated) + `<span class="muted">${esc(charCount(r.body))}</span>` : '<span class="muted">空</span>'],
    ["请求摘要", esc((d.flow && d.flow.request_summary) || "-")],
  ])];
  parts.push('<div class="sub-title" data-field="request.headers">请求头（敏感头已脱敏）</div>' + headerList(r.headers));
  if (r.messages && r.messages.length) parts.push('<div class="sub-title">messages</div>' + messageList(r.messages));
  if (r.instructions) parts.push(`<div class="sub-title" data-field="instructions">instructions</div><pre class="code">${esc(r.instructions)}</pre>`);
  if (r.input) parts.push(`<div class="sub-title" data-field="input">input</div><pre class="code">${esc(r.input)}</pre>`);
  if (r.tools && r.tools.length) parts.push('<div class="sub-title">tools</div>' + toolList(r.tools));
  if (r.body) parts.push(`<details class="sub"><summary>请求体</summary><pre class="code">${esc(prettyJSON(r.body))}</pre></details>`);
  return parts.join("");
}

function responseInfo(d) {
  const r = d.response || {};
  const f = d.flow || {};
  const parts = [kv([
    ["状态码", esc(r.status || "-")],
    ["Content-Type", esc(r.content_type || "-")],
    ["响应摘要", esc(f.response_summary || "-")],
    ["分片数", esc(r.chunks == null ? "-" : r.chunks)],
    ["完成", r.completed ? '<span class="badge confirmed">completed</span>' : '<span class="badge medium">未完成</span>'],
    ["错误", esc(r.error || "-")],
    ["响应体", r.body ? truncBadge(r.body_truncated) + `<span class="muted">${esc(charCount(r.body))}</span>` : '<span class="muted">空</span>'],
  ])];
  parts.push('<div class="sub-title" data-field="response.headers">响应头</div>' + headerList(r.headers));
  if (r.text) parts.push(`<div class="sub-title" data-field="response.text">聚合文本</div><pre class="code">${esc(r.text)}</pre>`);
  if (r.finish_reason || r.object) {
    parts.push(kv([
      ["finish_reason", esc(r.finish_reason || "-")],
      ["object", esc(r.object || "-")],
    ]));
  }
  if (r.tool_calls && r.tool_calls.length) parts.push('<div class="sub-title">响应 tool_calls</div>' + toolCallList(r.tool_calls, "response.tool_calls"));
  if (r.sse && r.sse.length) parts.push(sseList(r.sse));
  if (r.body) parts.push(`<details class="sub"><summary>响应体</summary><pre class="code">${esc(prettyJSON(r.body))}</pre></details>`);
  return parts.join("");
}

function usageInfo(f) {
  const u = f.usage || {};
  const total = u.total != null ? u.total : (u.input != null && u.output != null ? u.input + u.output : null);
  if (u.input == null && u.output == null && total == null) return '<div class="muted">未解析到 usage</div>';
  return kv([
    ["input", esc(u.input == null ? "-" : u.input)],
    ["output", esc(u.output == null ? "-" : u.output)],
    ["total", esc(total == null ? "-" : total)],
  ]);
}

function findingsInfo(f) {
  const list = f.findings || [];
  if (!list.length) return '<div class="muted">未命中检测规则</div>';
  return list.map((x) => `
    <div class="finding">
      <div class="head">${esc(x.rule_id)} ${esc(x.rule_name)} ${levelBadge(x.level)} ${badge(x.direction || "-", "")}</div>
      <div class="meta">字段：<span class="mono">${esc(x.field_path || "-")}</span></div>
      <div class="meta">证据：<span class="mono">${esc(x.evidence || "-")}</span></div>
      <div class="meta">${esc(x.explanation || "")}</div>
    </div>`).join("");
}

function rawRequest(d) {
  const r = d.request || {};
  const target = (r.path || "/") + (r.query ? "?" + r.query : "");
  const lines = [`${r.method || "GET"} ${target} HTTP/1.1`];
  if (r.host) lines.push(`Host: ${r.host}`);
  (r.headers || []).forEach((h) => (h.values || []).forEach((v) => lines.push(`${h.name}: ${v}`)));
  return lines.join("\n") + "\n\n" + (r.body || "");
}

function rawResponse(d) {
  const r = d.response || {};
  const lines = [`HTTP/1.1 ${r.status || 0}`];
  (r.headers || []).forEach((h) => (h.values || []).forEach((v) => lines.push(`${h.name}: ${v}`)));
  return lines.join("\n") + "\n\n" + (r.body || "");
}

function rawInfo(d) {
  return `<details class="sub"><summary>raw request</summary><pre class="code">${esc(rawRequest(d))}</pre></details>
    <details class="sub"><summary>raw response</summary><pre class="code">${esc(rawResponse(d))}</pre></details>`;
}

// 命中规则的 field_path 可能带 .name/.arguments 后缀，逐级回退匹配最近的容器。
function markHits(root, findings) {
  (findings || []).forEach((x) => {
    let path = x.field_path || "";
    while (path) {
      const el = root.querySelector(`[data-field="${path.replace(/["\\]/g, "\\$&")}"]`);
      if (el) {
        el.classList.add("hit");
        break;
      }
      const i = path.lastIndexOf(".");
      path = i > 0 ? path.slice(0, i) : "";
    }
  });
}

function renderDrawer() {
  const d = state.detail;
  if (!d) return;
  const f = d.flow || state.selected || {};
  const openState = [];
  $("drawerBody").querySelectorAll("details.sec").forEach((el) => openState.push(el.open));

  $("drawerBody").innerHTML = [
    section("基础信息", baseInfo(d, f), true),
    section("协议识别", protocolInfo(f), true),
    section("请求", requestInfo(d), true),
    section("响应", responseInfo(d), true),
    section("Token 用量", usageInfo(f), false),
    section("命中规则", findingsInfo(f), true),
    section("原始数据", rawInfo(d), false),
  ].join("");

  $("drawerBody").querySelectorAll("details.sec").forEach((el, i) => {
    if (i < openState.length) el.open = openState[i];
  });
  markHits($("drawerBody"), f.findings);
}

function renderAlerts() {
  const body = $("alertRows");
  if (!state.alerts.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">暂无告警。</td></tr>`;
    return;
  }
  body.innerHTML = state.alerts.map((a) => `
    <tr>
      <td class="muted">${esc(fmtTime(a.created_at))}</td>
      <td>${levelBadge(a.level)}</td>
      <td>${esc(a.rule_id)}<br><span class="muted">${esc(a.rule_name)}</span></td>
      <td><div class="host">${esc(a.host || "-")}</div><div class="path">${esc(a.path || "")}</div></td>
      <td class="path">${esc(a.field_path)}</td>
      <td class="path">${esc(a.evidence)}</td>
    </tr>`).join("");
}

function renderRules() {
  const el = $("ruleCards");
  el.innerHTML = state.rules.map((r) => `
    <div class="rule-card">
      <div class="rule-meta">${levelBadge(r.level)} ${badge(r.direction, "")}</div>
      <h3>${esc(r.id)} · ${esc(r.name)}</h3>
      <p>${esc(r.explanation)}</p>
    </div>`).join("");
}

async function loadStatus() {
  try {
    const st = await getJSON("/api/status");
    $("statProxy").textContent = st.proxy_addr;
    $("statIngress").textContent = (st.ingresses || []).join(" / ");
    $("statusDot").className = "dot on";
    $("statusText").textContent = "运行中 · v" + st.version;
  } catch (err) {
    $("statusDot").className = "dot off";
    $("statusText").textContent = "连接失败";
  }
}

async function loadAll() {
  const [flows, alerts, rules, stats] = await Promise.all([
    getJSON("/api/flows?limit=500"),
    getJSON("/api/alerts?limit=500"),
    getJSON("/api/rules"),
    getJSON("/api/stats"),
  ]);
  state.flows = flows || [];
  state.alerts = alerts || [];
  state.rules = rules || [];
  state.stats = stats || {};
  renderStats();
  renderFlows();
  renderAlerts();
  renderRules();
}

function connectEvents() {
  const es = new EventSource("/api/events");
  es.addEventListener("flow", (e) => {
    try {
      const ev = JSON.parse(e.data);
      if (ev.flow) {
        state.flows.unshift(ev.flow);
        state.flows = state.flows.slice(0, 500);
        renderFlows();
        refreshStats();
      }
    } catch (_) {}
  });
  es.addEventListener("alert", (e) => {
    try {
      const ev = JSON.parse(e.data);
      if (ev.alert) {
        state.alerts.unshift(ev.alert);
        state.alerts = state.alerts.slice(0, 500);
        renderAlerts();
        refreshStats();
      }
    } catch (_) {}
  });
  es.onerror = () => {
    $("statusDot").className = "dot off";
    $("statusText").textContent = "实时连接断开，重试中…";
  };
}

let statsTimer = null;
function refreshStats() {
  clearTimeout(statsTimer);
  statsTimer = setTimeout(async () => {
    try {
      state.stats = await getJSON("/api/stats");
      renderStats();
    } catch (_) {}
  }, 250);
}

function bind() {
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      tab.classList.add("active");
      $("panel-" + tab.dataset.tab).classList.add("active");
    });
  });
  $("search").addEventListener("input", (e) => {
    state.search = e.target.value.trim();
    renderFlows();
  });
  $("confidenceFilter").addEventListener("change", (e) => {
    state.confidence = e.target.value;
    renderFlows();
  });
  $("btnRefresh").addEventListener("click", () => loadAll().catch(() => {}));
  $("btnCA").addEventListener("click", () => window.open("/api/ca.pem", "_blank"));

  // 抽屉关闭方式：关闭按钮 / 遮罩 / ESC；列表的筛选与滚动状态不受影响。
  $("drawerClose").addEventListener("click", closeDrawer);
  $("drawerOverlay").addEventListener("click", closeDrawer);
  $("drawerBody").addEventListener("click", (e) => {
    if (e.target.closest("[data-more-sse]")) {
      state.sseExpanded = true;
      renderDrawer();
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && $("flowDrawer").classList.contains("open")) {
      e.preventDefault();
      closeDrawer();
    }
  });
}

async function main() {
  bind();
  await loadStatus();
  try {
    await loadAll();
  } catch (err) {
    console.error(err);
  }
  connectEvents();
  setInterval(loadStatus, 15000);
}

main();
