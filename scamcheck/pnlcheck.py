"""Claimed-PnL verifier: check "my bot made X%" against a wallet's real record.

Data source: Hyperliquid (public L1; fills, fees, funding, transfers and account
value history are readable for any address, no key).

How the numbers are built (all USDC):

    net (window)      = exchange-reported PnL for the window: change in account
                        value minus deposits/withdrawals (HL ``pnlHistory``),
                        perps + spot. This is the headline number.
    realised (perps)  = sum over perp fills in window of closedPnl - fee
                        + funding payments in window          [recomputed from fills]
    unrealised now    = mark-to-market of currently open perp positions
    change in unrealised over window = perp net - realised     [so the parts add up]
    spot              = total net - perp net                   [exchange figure]
    return %          = net / Modified-Dietz average capital
                        (start value + time-weighted external flows)

Why not just sum fills for a window: a position opened before the window and
closed inside it carries pre-window price moves in its closedPnl. On live
accounts the fill-only window sum was off by 20k+ USDC vs the equity change.
Only the all-time view can be fully rebuilt from fills, and there we RECONCILE
our recomputation with the exchange's figure as a data-quality check.

Verified against live accounts (Oct 2026). Pitfalls each worth >$1k:
* ``fee`` already includes ``builderFee``; adding it double-counts.
* The fills API keeps only recent history; older fills are gone. Detected by
  comparing the first fill with the first funding/PnL activity, then reported.
* Spot fills' closedPnl ignores the cost basis of transferred-in tokens, so spot
  is never recomputed from fills.

"Trades the result rests on": position round trips (flat -> flat) per coin,
net of fees. We report the count, win rate, concentration (share of gross profit
from the best / top-3 trips) and a t-statistic. Under 30 trips, or one trip
providing most of the profit, means the result cannot separate skill from luck.

The tool cannot prove the wallet belongs to whoever made the claim.
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field

from .hyperliquid import AccountData

DAY_MS = 86_400_000
MIN_TRADES = 30
MIN_CAPITAL = 100.0  # below this, % returns are noise (a $20 account doubling is not evidence)
RECON_TOL_ABS = 5.0
RECON_TOL_REL = 0.01


# --------------------------------------------------------------------------
# Claim parsing
# --------------------------------------------------------------------------

UNIT_DAYS = {"day": 1, "week": 7, "month": 30, "year": 365}
_NUM = r"(\d[\d,]*(?:\.\d+)?)"


@dataclass
class Claim:
    text: str
    pct: float | None = None             # claimed return as a fraction (3.4 = +340%)
    usd: float | None = None             # claimed profit in USD
    window_days: float | None = None     # lookback the claim refers to
    rate_unit_days: float | None = None  # "5% per day" -> 1 (a rate, not a total)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _num(s: str) -> float:
    return float(s.replace(",", ""))


def _usd(n: str, suffix: str | None) -> float:
    return _num(n) * {"k": 1e3, "m": 1e6}.get((suffix or "").lower(), 1)


def parse_claim(text: str) -> Claim:
    c = Claim(text=(text or "").strip())
    t = c.text.lower()
    if not t:
        return c

    # "$500 -> $5,000", "turned 500 into 5k"
    m = re.search(rf"\$?\s*{_NUM}\s*(k|m)?\b\s*(?:usd[ct]?)?\s*(?:->|→|=>|to|into)\s*\$?\s*{_NUM}\s*(k|m)?\b", t)
    if m and re.search(r"turn|grew|grow|->|→|=>|into|from", t):
        a, b = _usd(m.group(1), m.group(2)), _usd(m.group(3), m.group(4))
        if a > 0 and b > 0:
            c.pct, c.usd = b / a - 1, b - a
            c.notes.append(f"read as ${a:,.0f} → ${b:,.0f}")

    if c.pct is None:
        m = re.search(rf"([+-]?)\s*{_NUM}\s*%", t)
        if m:
            c.pct = (-1 if m.group(1) == "-" else 1) * _num(m.group(2)) / 100
        else:
            m = re.search(rf"\b{_NUM}\s*x\b", t)
            if m:
                mult = _num(m.group(1))
                c.pct = mult - 1
                c.notes.append(f"read {mult:g}x as {c.pct * 100:,.0f}% return")

    if c.usd is None:
        m = re.search(rf"\$\s*{_NUM}\s*(k|m)?\b|\b{_NUM}\s*(k|m)?\s*(?:usd[ct]?|dollars|bucks)\b", t)
        if m:
            c.usd = _usd(m.group(1) or m.group(3), m.group(2) or m.group(4))

    # Window first: "in a week" is a window, "a week" alone ("10% a week") is a rate.
    m = re.search(rf"\b(?:in|over|last|past|within|after|for)\s+(?:the\s+|a\s+|an\s+|one\s+)?"
                  rf"(?:{_NUM}\s*)?(day|week|month|year)s?\b", t)
    window_span = m.span() if m else None
    if m:
        c.window_days = (_num(m.group(1)) if m.group(1) else 1) * UNIT_DAYS[m.group(2)]

    for m in re.finditer(r"\b(?:per|a|an|each|every)\s+(day|week|month|year)\b|"
                         r"\b(daily|weekly|monthly|yearly|annually)\b", t):
        if window_span and window_span[0] <= m.start() < window_span[1]:
            continue
        if c.pct is not None:
            unit = m.group(1) or {"daily": "day", "weekly": "week", "monthly": "month",
                                  "yearly": "year", "annually": "year"}[m.group(2)]
            c.rate_unit_days = UNIT_DAYS[unit]
        break

    if c.window_days:
        pass
    elif re.search(r"\bthis (week|month|year)\b", t):
        c.window_days = UNIT_DAYS[re.search(r"\bthis (week|month|year)\b", t).group(1)]
    elif re.search(r"\btoday\b", t):
        c.window_days = 1
    if c.rate_unit_days and not c.window_days:
        c.notes.append("rate claim: compared over the last 30 days")
    return c


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _f(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def is_spot(coin: str) -> bool:
    return coin.startswith("@") or "/" in coin


def _at(points: list, ts: int) -> float | None:
    """Value of a [ts, "value"] history at ts (last point at or before ts).

    Before the first point the account had no history: HL represents that as
    zero value / zero PnL, so return 0.0.
    """
    if not points:
        return None
    if ts < int(points[0][0]):
        return 0.0
    best = None
    for p_ts, v in points:
        if int(p_ts) <= ts:
            best = _f(v)
        else:
            break
    return best


_SERIES = [("day", "perpDay"), ("week", "perpWeek"), ("month", "perpMonth"), ("allTime", "perpAllTime")]


def _series(portfolio: dict, key: str, start_ms: int, perp: bool) -> list:
    """Finest-grained HL history that covers start_ms (allTime is coarse)."""
    for total_name, perp_name in _SERIES:
        h = (portfolio.get(perp_name if perp else total_name) or {}).get(key) or []
        if h and (start_ms == 0 and total_name == "allTime" or start_ms and int(h[0][0]) <= start_ms):
            return h
    return (portfolio.get("perpAllTime" if perp else "allTime") or {}).get(key) or []


def _window_change(portfolio: dict, key: str, start_ms: int, perp: bool) -> float | None:
    h = _series(portfolio, key, start_ms, perp)
    if not h:
        return None
    a = 0.0 if start_ms == 0 else _at(h, start_ms)
    return None if a is None else _f(h[-1][1]) - a


def round_trips(fills: list[dict]) -> tuple[list[float], int]:
    """Split perp fills into position round trips (flat -> ... -> flat) per coin.

    Returns (net PnL after fees of each completed trip, number of trips still
    open). A flip (long -> short in one fill) closes one trip and opens the next.
    A trip already open when the history starts is counted from the first fill.
    """
    closed: list[float] = []
    cur: dict[str, float | None] = {}
    eps = 1e-12
    for f in fills:
        coin = f["coin"]
        start = _f(f.get("startPosition"))
        end = start + _f(f.get("sz")) * (1 if f.get("side") == "B" else -1)
        fee = _f(f.get("fee")) if (f.get("feeToken") or "USDC") == "USDC" else 0.0
        if cur.get(coin) is None:
            cur[coin] = 0.0
        elif abs(start) < eps and cur[coin]:
            closed.append(cur[coin])  # missed the flat fill (e.g. liquidation record)
            cur[coin] = 0.0
        cur[coin] += _f(f.get("closedPnl")) - fee
        if abs(end) < eps:
            closed.append(cur[coin])
            cur[coin] = None
        elif start * end < 0:  # flipped through zero
            closed.append(cur[coin])
            cur[coin] = 0.0
    return closed, sum(1 for v in cur.values() if v is not None)


def _flow_usd(delta: dict, address: str) -> float:
    """Signed external cash flow into the account (USDC); 0 if internal/unknown."""
    t = delta.get("type")
    if t == "deposit":
        return _f(delta.get("usdc"))
    if t == "withdraw":
        return -(_f(delta.get("usdc")) + _f(delta.get("fee")))
    if t in ("send", "spotTransfer", "internalTransfer", "subAccountTransfer"):
        amt = _f(delta.get("usdcValue") or delta.get("usdc") or delta.get("amount"))
        dest = (delta.get("destination") or "").lower()
        src = (delta.get("user") or "").lower()
        if dest == address and src != address:
            return amt
        if src == address and dest != address:
            return -(amt + _f(delta.get("fee")))
        return 0.0
    if t == "vaultDeposit":
        return -_f(delta.get("usdc"))
    if t in ("vaultWithdraw", "vaultDistribution"):
        return _f(delta.get("netWithdrawnUsd") or delta.get("usdc"))
    return 0.0  # accountClassTransfer (spot<->perp) etc. are internal


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


@dataclass
class PnLReport:
    address: str
    window_start_ms: int          # 0 = all time
    window_end_ms: int
    window_days: float
    # headline (exchange equity-based, perps + spot)
    net: float
    perp_net: float
    spot_net: float
    # perp decomposition (recomputed from fills)
    realised_price_pnl: float
    fees: float
    funding: float
    realised: float
    unrealised_change: float
    unrealised_now: float
    gross_before_costs: float
    # capital
    start_value: float | None
    net_flows: float
    avg_capital: float | None
    return_pct: float | None
    account_value_now: float
    open_positions: list[dict]
    # trade evidence
    fills: int
    spot_fills: int
    closing_trades: int
    open_trips: int
    wins: int
    losses: int
    win_rate: float | None
    best_trade_share: float | None
    top3_share: float | None
    t_stat: float | None
    active_days: int
    coins: list[str]
    first_fill_ms: int | None
    last_fill_ms: int | None
    # data quality
    fills_complete: bool
    recomputed_all_time: float | None
    exchange_all_time: float | None
    reconciliation_diff: float | None
    reconciled: bool | None
    warnings: list[str]

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def compute_pnl(acc: AccountData, window_start_ms: int = 0, now_ms: int | None = None) -> PnLReport:
    now_ms = now_ms or acc.fetched_at_ms or int(time.time() * 1000)
    addr = acc.address.lower()
    warnings = list(acc.warnings)
    pf = acc.portfolio or {}

    # ---- when did the account start? clamp the window to it
    perp_all = (pf.get("perpAllTime") or {}).get("pnlHistory") or []
    total_all = (pf.get("allTime") or {}).get("pnlHistory") or []
    starts = [int(h[0][0]) for h in (perp_all, total_all) if h]
    starts += [int(x["time"]) for x in (acc.fills[:1] + acc.funding[:1] + acc.ledger[:1])]
    first_activity = min(starts) if starts else now_ms
    if window_start_ms and window_start_ms < first_activity:
        warnings.append("The account is younger than the requested period, so it is measured from its first activity.")
        window_start_ms = 0
    days = (now_ms - (window_start_ms or first_activity)) / DAY_MS

    # ---- exchange-reported (equity) PnL: the headline
    total_net = _window_change(pf, "pnlHistory", window_start_ms, perp=False)
    perp_net_hl = _window_change(pf, "pnlHistory", window_start_ms, perp=True)

    # ---- perp decomposition from fills
    in_window = [f for f in acc.fills if window_start_ms <= int(f["time"]) <= now_ms]
    spot_fills = [f for f in in_window if is_spot(f["coin"])]
    fills = [f for f in in_window if not is_spot(f["coin"])]
    price_pnl = sum(_f(f.get("closedPnl")) for f in fills)
    fees = sum(_f(f.get("fee")) for f in fills if (f.get("feeToken") or "USDC") == "USDC")  # includes builder fee
    odd_fee = sum(1 for f in fills if (f.get("feeToken") or "USDC") != "USDC")
    if odd_fee:
        warnings.append(f"{odd_fee} perp fills paid fees in a non-USDC token; those fees are not deducted.")
    funding = sum(_f(x["delta"].get("usdc")) for x in acc.funding if window_start_ms <= int(x["time"]) <= now_ms)
    realised = price_pnl - fees + funding

    positions, unrealised_now = [], 0.0
    for ap in (acc.state or {}).get("assetPositions", []) or []:
        p = ap.get("position", {})
        u = _f(p.get("unrealizedPnl"))
        unrealised_now += u
        positions.append({"coin": p.get("coin"), "size": _f(p.get("szi")), "entry": _f(p.get("entryPx")),
                          "value": _f(p.get("positionValue")), "unrealised": u,
                          "leverage": (p.get("leverage") or {}).get("value")})

    # ---- is the fill history complete for this window?
    first_fill = int(acc.fills[0]["time"]) if acc.fills else None
    other_first = [int(x["time"]) for x in acc.funding[:1]]
    other_first += [int(p[0]) for p in perp_all if _f(p[1]) != 0][:1]
    earliest_perp_activity = min(other_first) if other_first else None
    fills_complete = not acc.fills_truncated
    if earliest_perp_activity is not None and (first_fill is None or earliest_perp_activity < first_fill - DAY_MS):
        cutoff = first_fill or now_ms
        if window_start_ms < cutoff:
            fills_complete = False
            warnings.append("The exchange no longer serves this wallet's oldest fills, so the trade-level "
                            "breakdown for this period is partial. The net PnL headline is unaffected.")

    # ---- all-time reconciliation: recomputed perp PnL vs exchange
    recomputed_all = exchange_all = diff = None
    reconciled = None
    if perp_all:
        all_perp = [f for f in acc.fills if not is_spot(f["coin"])]
        recomputed_all = (sum(_f(f.get("closedPnl")) - (_f(f.get("fee")) if (f.get("feeToken") or "USDC") == "USDC" else 0)
                              for f in all_perp)
                          + sum(_f(x["delta"].get("usdc")) for x in acc.funding) + unrealised_now)
        exchange_all = _f(perp_all[-1][1])
        diff = recomputed_all - exchange_all
        reconciled = abs(diff) <= max(RECON_TOL_ABS, RECON_TOL_REL * abs(exchange_all))
        if not reconciled and fills_complete:
            warnings.append(f"Recomputed perp PnL differs from the exchange's own figure by ${diff:,.2f}; "
                            "treat the trade-level breakdown with caution.")

    # ---- headline numbers (fall back to fills if HL history is missing)
    if perp_net_hl is None:
        perp_net_hl = realised + unrealised_now
        warnings.append("Exchange PnL history unavailable; using the fill-based estimate.")
    if total_net is None:
        total_net = perp_net_hl
    spot_net = total_net - perp_net_hl
    if spot_fills or abs(spot_net) > 1:
        warnings.append("Spot trading is included in net PnL using the exchange's figure; it is not broken down by trade.")
    unrealised_change = perp_net_hl - realised

    # ---- capital base (Modified Dietz)
    av_hist = _series(pf, "accountValueHistory", window_start_ms, perp=False)
    t0 = window_start_ms or first_activity
    start_value = (_at(av_hist, window_start_ms) or 0.0) if window_start_ms else 0.0
    T = max(1, now_ms - t0)
    flows = [(int(l["time"]), _flow_usd(l.get("delta", {}), addr)) for l in acc.ledger
             if t0 <= int(l["time"]) <= now_ms]
    flows = [(ts, v) for ts, v in flows if v]
    net_flows = sum(v for _, v in flows)
    avg_capital = start_value + sum(v * (now_ms - ts) / T for ts, v in flows)
    if avg_capital <= 0:
        avg_capital = None
        warnings.append("Could not establish a capital base (no balance or deposits found), so no % return.")
    elif avg_capital < 100:
        warnings.append(f"Average capital is only ${avg_capital:,.2f}; % returns on tiny balances are not meaningful.")
    return_pct = total_net / avg_capital if avg_capital else None

    # ---- trade evidence: round trips
    closing, open_trips = round_trips(fills)
    wins = sum(1 for x in closing if x > 0)
    losses = sum(1 for x in closing if x < 0)
    top = sorted((x for x in closing if x > 0), reverse=True)
    gross_profit = sum(top)
    t_stat = None
    if len(closing) >= 2:
        mean = sum(closing) / len(closing)
        var = sum((x - mean) ** 2 for x in closing) / (len(closing) - 1)
        t_stat = mean / math.sqrt(var / len(closing)) if var > 0 else None

    return PnLReport(
        address=addr, window_start_ms=window_start_ms, window_end_ms=now_ms, window_days=days,
        net=total_net, perp_net=perp_net_hl, spot_net=spot_net,
        realised_price_pnl=price_pnl, fees=fees, funding=funding, realised=realised,
        unrealised_change=unrealised_change, unrealised_now=unrealised_now,
        gross_before_costs=perp_net_hl + fees - funding + spot_net,
        start_value=start_value, net_flows=net_flows, avg_capital=avg_capital, return_pct=return_pct,
        account_value_now=_f(((acc.state or {}).get("marginSummary") or {}).get("accountValue")),
        open_positions=positions,
        fills=len(fills), spot_fills=len(spot_fills), closing_trades=len(closing), open_trips=open_trips,
        wins=wins, losses=losses, win_rate=wins / len(closing) if closing else None,
        best_trade_share=top[0] / gross_profit if gross_profit > 0 else None,
        top3_share=sum(top[:3]) / gross_profit if gross_profit > 0 else None,
        t_stat=t_stat, active_days=len({int(f["time"]) // DAY_MS for f in in_window}),
        coins=sorted({f["coin"] for f in in_window}),
        first_fill_ms=int(in_window[0]["time"]) if in_window else None,
        last_fill_ms=int(in_window[-1]["time"]) if in_window else None,
        fills_complete=fills_complete, recomputed_all_time=recomputed_all, exchange_all_time=exchange_all,
        reconciliation_diff=diff, reconciled=reconciled, warnings=warnings,
    )


# --------------------------------------------------------------------------
# Claim vs evidence
# --------------------------------------------------------------------------

VERDICTS = {
    "CONSISTENT": "On-chain results back up the claim",
    "OVERSTATED": "The claim is bigger than the real result",
    "GROSSLY_OVERSTATED": "The claim is far bigger than the real result",
    "CONTRADICTED": "The wallet lost money over this period",
    "UNVERIFIABLE": "This wallet's data can't verify the claim",
    "NO_CLAIM": "Wallet results (no claim to compare)",
}


@dataclass
class ClaimVerdict:
    level: str
    headline: str
    claimed: str
    observed: str
    comparable_claim_pct: float | None
    observed_pct: float | None
    evidence_strength: str  # none | thin | moderate | solid
    reasons: list[str]

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _pct(x: float | None) -> str:
    if x is None:
        return "n/a"
    if math.isinf(x):
        return "+∞%"
    return f"{x * 100:+,.1f}%"


def evidence_strength(r: PnLReport) -> tuple[str, list[str]]:
    why: list[str] = []
    if r.closing_trades == 0:
        return "none", ["No completed trades in this period: the result is open positions, fees and funding only."]
    if r.closing_trades < MIN_TRADES:
        why.append(f"Only {r.closing_trades} completed trades; under {MIN_TRADES} can't separate skill from luck.")
    if r.best_trade_share is not None and r.best_trade_share >= 0.5 and r.closing_trades > 1:
        why.append(f"One trade produced {r.best_trade_share:.0%} of all gross profit.")
    elif r.top3_share is not None and r.top3_share >= 0.8 and r.closing_trades >= 5:
        why.append(f"The top 3 trades produced {r.top3_share:.0%} of all gross profit.")
    if abs(r.unrealised_now) > max(1.0, abs(r.realised)) and abs(r.unrealised_now) > 0.5 * abs(r.net):
        why.append("Much of the result sits in open positions, which can reverse before profit is banked.")
    if r.t_stat is not None and abs(r.t_stat) < 2 and r.closing_trades >= MIN_TRADES:
        why.append(f"Per-trade results are noisy (t = {r.t_stat:.2f}): not distinguishable from zero.")
    if not r.fills_complete:
        why.append("Trade-level history is partial for this period.")
    if not why:
        tail = f", t = {r.t_stat:.2f}" if r.t_stat is not None else ""
        return "solid", [f"{r.closing_trades} completed trades, no single trade dominates{tail}."]
    thin = r.closing_trades < MIN_TRADES or (r.best_trade_share or 0) >= 0.5
    return ("thin" if thin else "moderate"), why


def judge(claim: Claim | None, r: PnLReport) -> ClaimVerdict:
    strength, why = evidence_strength(r)
    observed = f"{_pct(r.return_pct)} (${r.net:,.2f} net) over {r.window_days:,.1f} days"
    if claim is None or (claim.pct is None and claim.usd is None):
        return ClaimVerdict("NO_CLAIM", VERDICTS["NO_CLAIM"], "-", observed, None, r.return_pct, strength, why)
    if r.fills == 0 and r.spot_fills == 0 and not r.open_positions:
        return ClaimVerdict("UNVERIFIABLE", VERDICTS["UNVERIFIABLE"], claim.text, observed, None, r.return_pct,
                            strength, ["This wallet made no trades in the period."] + why)

    claimed_str = claim.text
    target = claim.pct
    if target is not None and claim.rate_unit_days and r.window_days > 0:
        try:
            target = (1 + target) ** (r.window_days / claim.rate_unit_days) - 1
        except OverflowError:
            target = float("inf")
        claimed_str += f" → {_pct(target)} over {r.window_days:,.0f} days if true"

    if target is not None and claim.usd is None and r.avg_capital is not None and r.avg_capital < MIN_CAPITAL:
        return ClaimVerdict("UNVERIFIABLE", VERDICTS["UNVERIFIABLE"], claimed_str, observed, target, r.return_pct,
                            strength, [f"Average capital was only ${r.avg_capital:,.2f}: a % claim on a balance "
                                       f"under ${MIN_CAPITAL:,.0f} proves nothing either way."] + why)
    if target is not None and r.return_pct is not None:
        ratio = 0.0 if math.isinf(target) or target == 0 else r.return_pct / target
        positive_claim = target > 0
    elif claim.usd is not None:
        ratio = r.net / claim.usd if claim.usd else 0.0
        positive_claim = claim.usd > 0
    else:
        return ClaimVerdict("UNVERIFIABLE", VERDICTS["UNVERIFIABLE"], claim.text, observed, target, None, strength,
                            ["No capital base, so a % claim can't be checked."] + why)

    if r.net < 0 and positive_claim:
        level = "CONTRADICTED"
    elif ratio >= 0.8:
        level = "CONSISTENT"
    elif ratio >= 0.5:
        level = "OVERSTATED"
    else:
        level = "GROSSLY_OVERSTATED"

    reasons: list[str] = []
    costs = r.fees - r.funding
    if level != "CONSISTENT" and target and not math.isinf(target) and r.avg_capital and costs > 0:
        gross_pct = r.gross_before_costs / r.avg_capital
        if gross_pct / target >= 0.8:
            reasons.append(f"The claim matches the result *before* fees and funding ({_pct(gross_pct)}); "
                           f"${costs:,.2f} of costs make up the difference.")
    if r.realised < 0 < r.net:
        reasons.append("Closed trades lost money; the profit is open-position mark-to-market.")
    if level == "CONSISTENT" and strength != "solid":
        reasons.append("The numbers match, but the evidence behind them is weak (see below).")
    return ClaimVerdict(level, VERDICTS[level], claimed_str, observed, target, r.return_pct, strength, reasons + why)


def window_start_for(claim: Claim | None, now_ms: int, days: float | None) -> int:
    d = days or (claim.window_days if claim else None) or (30 if claim and claim.rate_unit_days else None)
    return int(now_ms - d * DAY_MS) if d else 0
