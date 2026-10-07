// Claimed-PnL Verifier UI. All server data is inserted as text nodes, never parsed as HTML.
"use strict";

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v; else n.setAttribute(k, v);
  }
  for (const kid of kids) {
    if (kid === null || kid === undefined) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

const money = (x) => (x === null || x === undefined) ? "n/a"
  : (x < 0 ? "-$" : "$") + Math.abs(x).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const pct = (x) => (x === null || x === undefined) ? "n/a"
  : (x >= 0 ? "+" : "") + (x * 100).toLocaleString(undefined, { minimumFractionDigits: 1, maximumFractionDigits: 1 }) + "%";
const sign = (x) => (x > 0.005 ? "pos" : x < -0.005 ? "neg" : "");
const date = (ms) => ms ? new Date(ms).toISOString().slice(0, 10) : "n/a";

function numRow(label, value, cls = "", indent = false, note = "") {
  return el("tr", { class: cls },
    el("td", indent ? { class: "ind" } : {}, label, note ? el("span", { class: "muted" }, "  " + note) : null),
    el("td", { class: "v " + sign(value) }, money(value)));
}

function render(r) {
  const out = document.getElementById("out");
  out.replaceChildren();
  for (const e of r.errors || []) out.append(el("div", { class: "card err" }, e));
  if (!r.pnl) return;
  const v = r.verdict, m = r.pnl;

  const vs = el("div", { class: "vs" });
  if (r.claim) vs.append(el("div", { class: "k" }, "Claimed"), el("div", {}, v.claimed));
  vs.append(el("div", { class: "k" }, "On-chain"), el("div", {}, v.observed));
  out.append(el("div", { class: "card verdict " + v.level }, el("h2", {}, v.headline), vs));

  // PnL breakdown
  const t = el("table", { class: "nums" });
  t.append(
    numRow("Net PnL (period)", m.net, "total"),
    numRow("Realised on perps", m.realised, "", true),
    numRow("price PnL on closed trades", m.realised_price_pnl, "", true),
    numRow("fees paid", -m.fees, "", true),
    numRow("funding", m.funding, "", true),
    numRow("Change in open-position value", m.unrealised_change, "", true,
           (m.window_start_ms ? "incl. positions carried into the period; " : "") + "open now: " + money(m.unrealised_now)),
  );
  if (Math.abs(m.spot_net) > 0.005) t.append(numRow("Spot (exchange figure)", m.spot_net, "", true));
  const cap = el("p", { class: "muted" },
    `Return ${pct(m.return_pct)} on average capital of ${money(m.avg_capital)} ` +
    `(start balance ${money(m.start_value)}, net deposits/withdrawals ${money(m.net_flows)}). ` +
    `Period: ${m.window_start_ms ? date(m.window_start_ms) : "all time"} → ${date(m.window_end_ms)} (${m.window_days.toFixed(1)} days).`);
  out.append(el("div", { class: "card" }, el("h3", {}, "Realised vs unrealised, net of fees"), t, cap));

  // Evidence
  const wr = m.win_rate === null ? "n/a" : Math.round(m.win_rate * 100) + "%";
  const pills = el("div", { class: "pills" },
    el("span", { class: "pill" }, el("b", {}, String(m.closing_trades)), " completed trades"),
    el("span", { class: "pill" }, el("b", {}, `${m.wins} / ${m.losses}`), " won / lost"),
    el("span", { class: "pill" }, "win rate ", el("b", {}, wr)),
    el("span", { class: "pill" }, el("b", {}, String(m.fills)), " perp fills"),
    el("span", { class: "pill" }, el("b", {}, String(m.active_days)), " active days"),
    m.best_trade_share !== null ? el("span", { class: "pill" }, "best trade = ",
      el("b", {}, Math.round(m.best_trade_share * 100) + "%"), " of gross profit") : null,
  );
  const reasons = el("ul", {});
  for (const x of v.reasons || []) reasons.append(el("li", {}, x));
  out.append(el("div", { class: "card" },
    el("h3", {}, "What the result rests on  ", el("span", { class: "str " + v.evidence_strength }, v.evidence_strength)),
    pills, reasons));

  if ((m.open_positions || []).length) {
    const pt = el("table", { class: "nums" });
    for (const p of m.open_positions) {
      pt.append(el("tr", {},
        el("td", {}, `${p.coin}  ${p.size > 0 ? "long" : "short"} ${Math.abs(p.size)} @ ${p.entry}` +
          (p.leverage ? `  (${p.leverage}x)` : "")),
        el("td", { class: "v " + sign(p.unrealised) }, money(p.unrealised))));
    }
    out.append(el("div", { class: "card" }, el("h3", {}, "Open positions now"), pt));
  }

  const notes = el("ul", {});
  for (const w of m.warnings || []) notes.append(el("li", {}, w));
  if (m.reconciled !== null) {
    notes.append(el("li", {}, m.reconciled
      ? `Data check passed: our all-time perp PnL rebuilt from fills (${money(m.recomputed_all_time)}) matches the exchange's figure (${money(m.exchange_all_time)}).`
      : `Data check: our all-time perp PnL from fills (${money(m.recomputed_all_time)}) differs from the exchange's (${money(m.exchange_all_time)}).`));
  }
  if (r.claim && (r.claim.notes || []).length) for (const n of r.claim.notes) notes.append(el("li", {}, "Claim " + n));
  out.append(el("div", { class: "card" }, el("h3", {}, "Data notes"), notes,
    el("p", { class: "muted" }, r.disclaimer)));
}

async function run() {
  const btn = document.getElementById("go");
  const out = document.getElementById("out");
  const address = document.getElementById("addr").value.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    out.replaceChildren(el("div", { class: "card err" }, "Enter a 0x… wallet address (42 characters)."));
    return;
  }
  btn.disabled = true; btn.textContent = "Fetching on-chain history…";
  out.replaceChildren(el("div", { class: "card muted" }, "Loading fills, funding and transfers. Busy wallets can take up to a minute."));
  try {
    const res = await fetch("/api/pnl", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ address, claim: document.getElementById("claim").value,
                             days: document.getElementById("days").value || null }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    render(data);
  } catch (e) {
    out.replaceChildren(el("div", { class: "card err" }, "Error: " + e.message));
  } finally {
    btn.disabled = false; btn.textContent = "Verify";
  }
}

document.getElementById("go").addEventListener("click", run);
for (const id of ["addr", "claim", "days"]) {
  document.getElementById(id).addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
}
for (const ex of document.querySelectorAll(".ex")) {
  ex.addEventListener("click", () => { document.getElementById("claim").value = ex.dataset.claim; });
}
