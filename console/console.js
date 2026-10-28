// Airlock console. All server data is inserted with textContent, never as HTML.
"use strict";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

const state = { source: null, buttons: [] };

const AGENT = "agent";

function setList(id, items, cls, emptyText, emptyCls) {
  const ul = $(id);
  ul.replaceChildren();
  if (!items.length) {
    ul.append(el("li", emptyCls, emptyText));
    return;
  }
  for (const t of items) ul.append(el("li", cls, t));
}

function scrollLog() {
  const log = $("log");
  log.scrollTop = log.scrollHeight;
}

function addAgentLine(text) {
  const li = el("li", "agent-line");
  li.append(el("span", "seq", ""), el("span", "agent-tag", "Agent"), el("span", "", text));
  $("log").append(li);
  scrollLog();
}

function addVerdict(ev) {
  const li = $("t-verdict").content.firstElementChild.cloneNode(true);
  li.classList.add(`is-${ev.decision}`);
  li.querySelector(".seq").textContent = String(ev.seq).padStart(2, "0");

  const inbound = ev.direction === "inbound";
  // Inbound: the tool's content travels toward the agent. Outbound: the agent's call
  // travels toward the tool. The gate sits between them.
  li.querySelector(".node-a").textContent = inbound ? ev.tool : AGENT;
  li.querySelector(".node-b").textContent = inbound ? AGENT : ev.tool;

  const v = li.querySelector(".v");
  v.textContent = ev.decision;
  v.classList.add(`v-${ev.decision}`);
  li.querySelector(".dir").textContent = inbound ? "Inbound · result" : "Outbound · call";
  li.querySelector(".rules").textContent = ev.rules.map((r) => r[0]).join(" · ");

  let reason;
  if (ev.rules.length) reason = ev.rules.map((r) => r[1]).join(" ");
  else reason = inbound ? "Nothing suspicious in the returned content." : "Arguments within policy.";
  if (ev.quarantined) {
    reason += inbound ? " The agent receives a neutral placeholder instead."
                      : " The call never executed.";
  }
  li.querySelector(".reason").textContent = reason;
  li.querySelector(".detail").textContent = ev.detail;
  $("log").append(li);
  scrollLog();
}

function setChain(audit) {
  const v = $("chain-value");
  if (!audit) {
    v.className = "chain-value";
    v.textContent = "no entries yet";
    return;
  }
  v.className = `chain-value ${audit.verified ? "ok" : "broken"}`;
  v.textContent = `${audit.entries} entries · head ${audit.head.slice(0, 12)}… · ` +
                  (audit.verified ? "verified" : "BROKEN");
}

function lock(running, activeId) {
  for (const b of state.buttons) {
    b.disabled = running;
    b.setAttribute("aria-current", String(b.dataset.id === activeId));
  }
}

function runScenario(sc) {
  if (state.source) return;
  lock(true, sc.id);
  $("log").replaceChildren();
  $("log-title").textContent = `Inspection log · ${sc.title}`;
  setList("without", [], "", "Replaying unguarded…", "pending");
  setList("with", [], "", "Running through Airlock…", "pending");
  setChain(null);

  const es = new EventSource(`/api/run?scenario=${encodeURIComponent(sc.id)}`);
  state.source = es;
  const finish = () => {
    es.close();
    state.source = null;
    lock(false, sc.id);
  };

  es.onmessage = (msg) => {
    const item = JSON.parse(msg.data);
    if (item.type === "counterfactual") {
      setList("without", item.leaks, "leak", "Nothing would have left.", "muted");
    } else if (item.type === "agent") {
      addAgentLine(item.text);
    } else if (item.type === "verdict") {
      addVerdict(item);
    } else if (item.type === "done") {
      setList("with", item.leaks, "leak", "Nothing left. Attack contained.", "safe");
      setChain(item.audit);
      $("log").append(el("li", "done-line",
        `Run complete · ${item.audit.entries} decisions recorded in the hash chain`));
      scrollLog();
      finish();
    }
  };
  es.onerror = () => {
    if (!state.source) return;
    setList("with", [], "", "Connection to the console server lost.", "pending");
    finish();
  };
}

async function init() {
  const res = await fetch("/api/scenarios");
  const data = await res.json();

  const p = data.policy;
  $("p-org").textContent = p.org_domain;
  $("p-domains").textContent = p.domains.join(", ") || "none";
  $("p-pii").textContent = `${p.pii_threshold} records`;
  $("p-model").textContent = data.classifier ? "qwen2.5:7b via Ollama" : "off (rules only)";

  const ol = $("scenarios");
  data.scenarios.forEach((sc, i) => {
    const li = el("li");
    const b = el("button", "scenario");
    b.type = "button";
    b.dataset.id = sc.id;
    b.setAttribute("aria-current", "false");
    b.append(
      el("span", "scenario-num", String(i + 1).padStart(2, "0")),
      el("span", "scenario-title", sc.title),
      el("span", "scenario-attack", sc.attack),
      el("span", "scenario-key", `key ${i + 1}`),
    );
    b.addEventListener("click", () => runScenario(sc));
    state.buttons.push(b);
    li.append(b);
    ol.append(li);
  });

  document.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    const sc = data.scenarios[Number(e.key) - 1];
    if (sc) runScenario(sc);
  });

  const auto = new URLSearchParams(location.search).get("run");
  const pick = data.scenarios.find((s) => s.id === auto);
  if (pick) runScenario(pick);
}

init().catch(() => {
  $("log").replaceChildren(el("li", "empty", "Could not reach the console server. Start it with: python -m airlock.server"));
});
