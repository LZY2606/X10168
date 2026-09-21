"use strict";
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function nowLocalInput() {
  const d = new Date();
  d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
  return d.toISOString().slice(0, 19);
}
$("at").value = nowLocalInput();
$("pAt").value = "2017-01-01T00:00:00";

function localToUtc(v) {
  if (!v) return new Date().toISOString();
  return new Date(v.length === 19 ? v + "Z" : v).toISOString();
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: { "Content-Type": "application/json" },
    body: opts.body ? JSON.stringify(opts.body) : undefined
  });
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { error: text }; }
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { data });
  return data;
}

async function loadSession() {
  const s = await api("/api/session");
  $("rev").textContent = s.revision;
  $("anchors").innerHTML = s.anchors.length
    ? s.anchors.map((a) => `
      <div class="anchor-item">
        <span><span class="pill ok">prio ${a.priority}</span>
          <b>${esc(a.subject)}</b><br><span class="tag">${esc(a.fingerprint)}</span></span>
        <button class="danger" onclick="delAnchor('${esc(a.id)}')">删除</button>
      </div>`).join("")
    : `<div class="muted">暂无 anchor —— 没有任何显式信任锚时，所有链都不会通过。</div>`;
  $("policies").innerHTML = s.policyEntries.length
    ? s.policyEntries.map((p) => `
      <div class="anchor-item">
        <span><b>${esc(p.kind === "min-key-size" ? "最小长度 " + p.target + "≥" + p.minSize
            : "退役 " + p.target)}</b>
          <span class="muted">@${esc(p.effectiveAt)}</span><br>
          <span class="muted">${esc(p.reason)}</span> <span class="tag">${esc(p.id)}</span></span>
        <button class="danger" onclick="delPolicy('${esc(p.id)}')">删除</button>
      </div>`).join("")
    : `<div class="muted">无自定义策略（内置默认策略仅在程序侧提供；页面会话以服务端当前列表为准）。</div>`;
}

async function addAnchors() {
  try {
    await api("/api/anchors", { method: "POST", body: {
      pem: $("anchorPem").value, priority: Number($("anchorPrio").value)
    }});
    $("anchorPem").value = "";
    await loadSession();
  } catch (e) { alert("添加 anchor 失败: " + (e.data ? JSON.stringify(e.data.pemErrors || e.data.error) : e.message)); }
}
async function delAnchor(id) {
  await api("/api/anchors?id=" + encodeURIComponent(id), { method: "DELETE", body: { id } });
  await loadSession();
}
async function addPolicy() {
  try {
    await api("/api/policy", { method: "POST", body: {
      kind: $("pKind").value, target: $("pTarget").value.trim(),
      minSize: Number($("pSize").value), reason: $("pReason").value,
      effectiveAt: localToUtc($("pAt").value)
    }});
    await loadSession();
  } catch (e) { alert("策略失败: " + e.message); }
}
async function delPolicy(id) {
  await api("/api/policy?id=" + encodeURIComponent(id), { method: "DELETE", body: { id } });
  await loadSession();
}

let lastProof = null;

async function runCheck(withProof) {
  $("errors").innerHTML = ""; $("chains").innerHTML = ""; $("proofWrap").style.display = "none";
  $("summary").textContent = "检查中…";
  const payload = {
    pem: $("pem").value,
    verifyAt: localToUtc($("at").value),
    host: $("host").value.trim(),
    eku: $("eku").value,
    leafFingerprint: $("leaf").value.trim()
  };
  try {
    const r = await api(withProof ? "/api/proof" : "/api/check", { method: "POST", body: payload });
    if (withProof) { lastProof = r; renderProof(r); }
    renderResult(r);
    await loadSession();
  } catch (e) {
    $("summary").textContent = "检查失败";
    const d = e.data || {};
    let html = `<div class="errbox">${esc(e.message)}</div>`;
    (d.pemErrors || []).forEach((x) => html +=
      `<div class="errbox">块#${x.blockIndex} ${esc(x.label || "")} <b>${esc(x.code)}</b>：${esc(x.message)}</div>`);
    $("errors").innerHTML = html;
  }
}

function renderResult(r) {
  const total = r.candidates.length;
  const sel = r.selectedChain;
  $("summary").innerHTML = sel
    ? `验证时刻 <b>${esc(r.verifyAt)}</b> · 候选链 <b>${total}</b> · 已选择 <span class="pill ok">合格</span> 长度 ${sel.length} · anchor <b>${esc(sel.anchorId)}</b>`
    : `验证时刻 <b>${esc(r.verifyAt)}</b> · 候选链 <b>${total}</b> · <span class="pill bad">无合格链</span>`;

  let errs = "";
  (r.pemErrors || []).forEach((x) => errs +=
    `<div class="errbox">块#${x.blockIndex} ${esc(x.label || "")} <b>${esc(x.code)}</b>：${esc(x.message)}</div>`);
  if (r.duplicateBlocks) errs += `<div class="muted">已按 DER 指纹去重，丢弃重复块 ${r.duplicateBlocks} 个。</div>`;
  $("errors").innerHTML = errs;

  $("chains").innerHTML = r.candidates.map((c, idx) => renderChain(c, idx)).join("");
}

function renderChain(c, idx) {
  const badge = c.selected ? `<span class="pill ok">已选择</span>`
    : c.accepted ? `<span class="pill ok">合格</span>`
    : c.complete ? `<span class="pill bad">不合格</span>`
    : `<span class="pill warn">不完整</span>`;
  const certs = c.certificates.map((x, i) => `
    <div class="cert">
      <div class="sub">#${i} ${esc(x.subject)} ${x.isCa ? '<span class="pill warn">CA</span>' : '<span class="pill ok">EE</span>'}</div>
      <div class="kv">签发者: ${esc(x.issuer)}</div>
      <div class="kv">有效期: ${esc(x.notBefore)} → ${esc(x.notAfter)} · ${esc(x.signatureAlgorithm)} · ${esc(x.key)}</div>
      <div class="kv">SAN: ${esc(x.san.map((s) => s.value).join(", ") || "-")} · pathLen=${x.pathLenConstraint ?? "-"}</div>
      <div class="tag">${esc(x.fingerprint)}</div>
    </div>`).join("");
  const findings = (c.findings || []).map((f) => `
    <div class="finding ${f.code.startsWith("ANCHOR_") ? "info" : ""}">
      <b>${esc(f.code)}</b> 定位于 ${esc(f.location)}<br>${esc(f.detail)}
      ${f.constraint ? `<div class="tag">约束: ${esc(f.constraint)}</div>` : ""}
    </div>`).join("");
  return `<div class="chain ${c.selected ? "sel" : ""}">
    <div class="chain-head">${badge}
      <span>链 #${idx + 1} · 长度 ${c.length} · anchor=${esc(c.anchorId || "—")}（prio ${c.anchorPriority ?? "—"}）</span>
      <span class="tag">${esc(c.chainFingerprint)}</span>
    </div>
    ${certs}
    ${findings ? `<div class="cert">${findings}</div>` : ""}
  </div>`;
}

function renderProof(p) {
  $("proofWrap").style.display = "block";
  $("proof").textContent = JSON.stringify(p, null, 2);
  const blob = new Blob([JSON.stringify(p, null, 2)], { type: "application/json" });
  $("proofDownload").href = URL.createObjectURL(blob);
  $("proofDownload").innerHTML = '<button class="secondary" type="button">下载 proof.json</button>';
}
function copyProof() {
  if (!lastProof) return;
  navigator.clipboard.writeText(JSON.stringify(lastProof, null, 2));
}

loadSession().catch((e) => { $("summary").textContent = "会话加载失败: " + e.message; });
