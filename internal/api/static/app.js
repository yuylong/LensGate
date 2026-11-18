const state = {
  flows: [],
  alerts: [],
  rules: [],
  stats: null,
  search: "",
  confidence: "",
  selected: null,
};

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

function badge(text, cls) {
  return `<span class="badge ${esc(cls || "")}">${esc(text || "-")}</span>`;
}

function confBadge(c) {
  return badge(c || "not_ai", c || "not_ai");
}

function levelBadge(l) {
  return badge(l || "low", l || "low");
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
    (f.findings || []).map((x) => x.rule_id + " " + x.rule_name).join(" "),
  ].join(" ").toLowerCase();
  return hay.includes(q);
}

function renderFlows() {
  const rows = state.flows.filter(flowMatches);
  $("flowCount").textContent = `显示 ${rows.length} / ${state.flows.length} 条`;
  const body = $("flowRows");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="8" class="empty">暂无流量。把应用的代理指向控制台显示的地址，或先运行演示客户端。</td></tr>`;
    return;
  }
  body.innerHTML = rows.map((f, idx) => {
    const usage = f.usage ? `${f.usage.total || (f.usage.input + f.usage.output)}` : "-";
    const hits = (f.findings || []).map((x) => `${x.rule_id}`).join(", ");
    return `<tr data-idx="${idx}">
      <td class="muted">${esc(fmtTime(f.started_at))}</td>
      <td><div class="host">${esc(f.host || "-")}</div><div class="path">${esc(f.method || "")} ${esc(f.path || "")}</div></td>
      <td>${esc(f.api_variant || f.protocol_family || "-")}${f.stream ? "<br><span class=\"muted\">stream</span>" : ""}</td>
      <td>${confBadge(f.confidence)}</td>
      <td>${esc(f.model || "-")}</td>
      <td class="mono">${esc(usage)}</td>
      <td>${esc(f.status || "-")}</td>
      <td>${hits ? badge(hits, "high") : '<span class="muted">-</span>'}</td>
    </tr>`;
  }).join("");

  body.querySelectorAll("tr[data-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const f = rows[Number(tr.dataset.idx)];
      state.selected = f;
      showDetail(f);
    });
  });
}

function showDetail(f) {
  const el = $("flowDetail");
  el.classList.remove("hidden");
  const evidence = (f.evidence || []).join("  ·  ");
  const findings = (f.findings || []).map((x) => `
    <div class="finding">
      <div class="head">${esc(x.rule_id)} ${esc(x.rule_name)} ${levelBadge(x.level)}</div>
      <div class="meta">${esc(x.direction)} · ${esc(x.field_path)} · 证据：${esc(x.evidence)}</div>
      <div class="meta">${esc(x.explanation)}</div>
    </div>`).join("");
  el.innerHTML = `
    <h3>流量详情 · ${esc(f.id)}</h3>
    <div class="grid">
      <div class="field"><span class="k">接入方式 / 目的</span><span class="v">${esc(f.ingress)} → ${esc(f.dst || "-")}${f.sni ? " (SNI " + esc(f.sni) + ")" : ""}</span></div>
      <div class="field"><span class="k">分类依据</span><span class="v">${esc(f.protocol_family)} / ${esc(f.api_variant || "-")}<br>${esc(evidence)}</span></div>
      <div class="field"><span class="k">请求摘要</span><span class="v">${esc(f.request_summary || "-")}</span></div>
      <div class="field"><span class="k">响应摘要</span><span class="v">${esc(f.response_summary || "-")}</span></div>
      <div class="field"><span class="k">解析状态</span><span class="v">${esc((f.parse_status || []).join(", ") || "-")}</span></div>
      <div class="field"><span class="k">耗时</span><span class="v">${esc(f.duration_ms)} ms</span></div>
    </div>
    ${findings || '<div class="muted" style="margin-top:12px">未命中检测规则</div>'}
  `;
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
