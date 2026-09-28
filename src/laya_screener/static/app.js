const $ = (selector) => document.querySelector(selector);
const results = new Map();
let selected = null;

const LABELS = {
  phishing: "Phishing",
  asks_credentials: "Asks for a sign-in",
  asks_payment: "Asks to move money",
};
const ATTACKS = {
  credential_theft: "Credential theft",
  payment_fraud: "Payment fraud",
  malware: "Malware",
  ordinary: "Ordinary email",
};
const PRESSURE = ["No pressure", "Normal deadline", "Urgency or secrecy"];

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

const pct = (p) => `${Math.round(p * 100)}%`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${response.status} ${await response.text()}`);
  return response.json();
}

function renderStats() {
  const all = [...results.values()].filter(Boolean);
  const count = (v) => all.filter((r) => r.verdict === v).length;
  const latency = all.length ? Math.round(all.reduce((s, r) => s + r.laya.latency_ms, 0) / all.length) : 0;
  $("#stats").innerHTML = [
    ["deliver", count("deliver"), "Delivered"],
    ["warn", count("warn"), "Warned"],
    ["quarantine", count("quarantine"), "Quarantined"],
    ["", all.length ? `${latency} ms` : "–", "Laya / email"],
  ].map(([cls, value, label]) => `<div class="stat ${cls}"><b style="${cls ? "color:var(--c)" : ""}">${value}</b><span>${label}</span></div>`).join("");
}

function row(id, preview) {
  const li = document.createElement("li");
  li.className = "row";
  li.dataset.id = id;
  li.innerHTML = `<span class="dot pending"></span>
    <div style="min-width:0"><div class="who">${esc(preview.from_name || preview.from)}</div><div class="subj">${esc(preview.subject)}</div></div>
    <div class="meta">screening…</div>`;
  li.addEventListener("click", () => select(id));
  $("#list").prepend(li);
  $("#empty").hidden = true;
  return li;
}

function settle(li, result) {
  li.querySelector(".dot").className = `dot ${result.verdict}`;
  li.querySelector(".meta").innerHTML = `<span class="badge ${result.verdict}">${result.verdict}</span><br>${Math.round(result.laya.latency_ms)} ms`;
}

function bar(label, p, hot) {
  return `<div class="bar ${hot && p >= 0.5 ? "hot" : ""}"><span>${esc(label)}</span><span class="track"><i style="width:${pct(p)}"></i></span><span class="v">${pct(p)}</span></div>`;
}

function select(id) {
  selected = id;
  document.querySelectorAll(".row").forEach((el) => el.classList.toggle("selected", el.dataset.id === id));
  const r = results.get(id);
  if (!r) return;
  const e = r.email;
  const auth = ["spf", "dkim", "dmarc"]
    .filter((m) => e.auth[m])
    .map((m) => `<span class="chip ${e.auth[m] === "pass" ? "pass" : "fail"}">${m.toUpperCase()} ${esc(e.auth[m])}</span>`).join("");
  const attacks = Object.entries(r.laya.attack_probs).sort((a, b) => b[1] - a[1])
    .map(([k, p]) => bar(ATTACKS[k] ?? k, p, k !== "ordinary")).join("");
  const pressure = r.laya.pressure_probs.map((p, i) => bar(PRESSURE[i], p, i === 2)).join("");
  const signals = r.signals.length
    ? r.signals.map((s) => `<div class="signal"><span class="sev ${s.severity}">${s.severity}</span><div><b>${esc(s.title)}</b><span>${esc(s.detail)}</span></div></div>`).join("")
    : `<p class="none">No technical red flags in the headers, links or attachments.</p>`;

  $("#detail").innerHTML = `
    <div class="head">
      <span class="badge ${r.verdict}">${r.verdict}</span>
      <h2>${esc(e.subject)}</h2>
      <div class="from">From <b>${esc(e.from.name)}</b> &lt;${esc(e.from.address)}&gt;${e.reply_to ? ` · Reply-To ${esc(e.reply_to.address)}` : ""}</div>
      <div class="auth">${auth}${e.attachments.map((a) => `<span class="chip">📎 ${esc(a.filename)}</span>`).join("")}</div>
    </div>
    <div class="verdict ${r.verdict}">
      <div><div class="word">${r.verdict}</div><div class="risk">risk ${r.risk}/100</div></div>
      <div><div class="meter"><i style="width:${r.risk}%"></i></div>
        <ul class="reasons">${r.reasons.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
    </div>
    <div class="grid2">
      <div class="card">
        <h3>Laya's reading <small>${esc(r.laya.model)} · ${Math.round(r.laya.latency_ms)} ms</small></h3>
        ${bar(LABELS.phishing, r.laya.phishing, true)}
        ${bar(LABELS.asks_credentials, r.laya.asks_credentials, true)}
        ${bar(LABELS.asks_payment, r.laya.asks_payment, true)}
        <div class="sub">What it wants</div>${attacks}
        <div class="sub">Pressure</div>${pressure}
      </div>
      <div class="card">
        <h3>Evidence from headers, links, files <small>${r.signals.length} found</small></h3>
        ${signals}
        <div class="sub">Body</div>
        <pre class="body">${esc(e.body_preview)}</pre>
      </div>
    </div>`;
}

async function play() {
  const button = $("#play");
  button.disabled = true;
  results.clear();
  $("#list").innerHTML = "";
  renderStats();
  try {
    const samples = await api("/api/samples");
    for (const sample of samples) {
      const li = row(sample.file, sample);
      const result = await api(`/api/samples/${encodeURIComponent(sample.file)}/screen`, {});
      results.set(sample.file, result);
      settle(li, result);
      renderStats();
      select(sample.file);
      await sleep(Number(new URLSearchParams(location.search).get("pace") ?? 1100));
    }
  } finally {
    button.disabled = false;
  }
}

async function screenOwn(form) {
  const data = Object.fromEntries(new FormData(form));
  const id = `own-${Date.now()}`;
  const li = row(id, { from: data.from || "you", subject: data.subject || "(no subject)" });
  const looksRaw = /^[\w-]+:\s/m.test(data.body) && /\n\s*\n/.test(data.body) && !data.subject;
  const result = await api("/api/screen", looksRaw ? { raw: data.body } : { from: data.from, subject: data.subject, body: data.body });
  results.set(id, result);
  settle(li, result);
  renderStats();
  select(id);
}

async function boot() {
  renderStats();
  try {
    const health = await api("/api/health");
    $("#status").textContent = health.ready ? `Laya ready · ${health.device}` : "loading Laya…";
    $("#status").classList.toggle("ready", health.ready);
    if (!health.ready) setTimeout(boot, 1500);
  } catch {
    $("#status").textContent = "server offline";
    setTimeout(boot, 2000);
  }
}

$("#play").addEventListener("click", play);
$("#own").addEventListener("click", () => $("#dialog").showModal());
$("#own-form").addEventListener("submit", (event) => {
  if (event.submitter?.value === "screen") screenOwn(event.target).catch((err) => alert(err.message));
});
boot();
if (new URLSearchParams(location.search).has("autoplay")) play();
