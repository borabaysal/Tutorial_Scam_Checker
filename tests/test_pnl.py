"""Claimed-PnL verifier tests. Offline: fixtures mirror the live Hyperliquid
field shapes observed in Oct 2026; every expected number is hand-computed."""

from __future__ import annotations

import pytest

from scamcheck import hyperliquid as hl
from scamcheck.hyperliquid import AccountData, fetch_account, order_fills
from scamcheck.pnlcheck import (Claim, compute_pnl, evidence_strength, judge, parse_claim, round_trips,
                                window_start_for)
from scamcheck.pnlverify import verify

ADDR = "0x" + "ab" * 20
DAY = 86_400_000
T0 = 1_780_000_000_000          # account start
NOW = T0 + 40 * DAY


def fill(t, coin, side, sz, px, start, closed=0.0, fee=0.0, tid=None, oid=None, fee_token="USDC"):
    return {"coin": coin, "px": str(px), "sz": str(sz), "side": side, "time": t, "startPosition": str(start),
            "dir": "", "closedPnl": str(closed), "hash": "0x0", "oid": oid or t, "crossed": True,
            "fee": str(fee), "tid": tid or t, "feeToken": fee_token}


def hist(*pts):
    return [[t, str(v)] for t, v in pts]


def portfolio(total_pnl, perp_pnl, av):
    p = {"accountValueHistory": av, "pnlHistory": total_pnl, "vlm": "0"}
    q = {"accountValueHistory": av, "pnlHistory": perp_pnl, "vlm": "0"}
    return {"allTime": p, "perpAllTime": q}


def simple_account(**kw):
    """Deposit 1000 at T0; two BTC round trips; one open ETH long.

    Trip 1: +120 closed, fee 2+2   -> +116
    Trip 2: -30 closed,  fee 1+1   -> -32
    Funding: -4
    Open ETH long: fee 1, unrealised +50
    realised = 120-30 - (2+2+1+1+1) + (-4) = 79 ; net = 79 + 50 = 129
    """
    fills = [
        fill(T0 + 1 * DAY, "BTC", "B", 1, 100, 0, fee=2),
        fill(T0 + 2 * DAY, "BTC", "A", 1, 220, 1, closed=120, fee=2),
        fill(T0 + 3 * DAY, "BTC", "A", 1, 200, 0, fee=1),
        fill(T0 + 4 * DAY, "BTC", "B", 1, 230, -1, closed=-30, fee=1),
        fill(T0 + 5 * DAY, "ETH", "B", 2, 10, 0, fee=1),
    ]
    funding = [{"time": T0 + 2 * DAY, "hash": "0x0", "delta": {"type": "funding", "coin": "BTC", "usdc": "-4"}}]
    ledger = [{"time": T0, "hash": "0x1", "delta": {"type": "deposit", "usdc": "1000"}}]
    state = {"assetPositions": [{"position": {"coin": "ETH", "szi": "2", "entryPx": "10", "positionValue": "70",
                                              "unrealizedPnl": "50", "leverage": {"value": 3}}}],
             "marginSummary": {"accountValue": "1129"}}
    pnl = hist((T0, 0), (NOW, 129))
    av = hist((T0, 1000), (NOW, 1129))
    acc = AccountData(address=ADDR, fills=fills, funding=funding, ledger=ledger, state=state,
                      portfolio=portfolio(pnl, pnl, av), fetched_at_ms=NOW)
    for k, v in kw.items():
        setattr(acc, k, v)
    return acc


# --------------------------------------------------------------------- PnL


def test_all_time_decomposition_and_reconciliation():
    r = compute_pnl(simple_account(), 0, NOW)
    assert r.realised_price_pnl == pytest.approx(90)
    assert r.fees == pytest.approx(7)
    assert r.funding == pytest.approx(-4)
    assert r.realised == pytest.approx(79)
    assert r.unrealised_now == pytest.approx(50)
    assert r.net == pytest.approx(129)
    assert r.realised + r.unrealised_change + r.spot_net == pytest.approx(r.net)
    assert r.reconciled is True and r.reconciliation_diff == pytest.approx(0)
    assert r.avg_capital == pytest.approx(1000)       # deposit at the very start
    assert r.return_pct == pytest.approx(0.129)
    assert r.closing_trades == 2 and r.wins == 1 and r.losses == 1 and r.open_trips == 1
    assert r.fills == 5 and r.fills_complete


def test_fee_already_includes_builder_fee_no_double_count():
    acc = simple_account()
    acc.fills[0]["builderFee"] = "1.5"  # HL: builderFee is a component of fee
    r = compute_pnl(acc, 0, NOW)
    assert r.fees == pytest.approx(7)


def test_reconciliation_flags_mismatch():
    acc = simple_account()
    bad = hist((T0, 0), (NOW, 500))
    acc.portfolio = portfolio(bad, bad, hist((T0, 1000), (NOW, 1500)))
    r = compute_pnl(acc, 0, NOW)
    assert r.reconciled is False
    assert any("differs from the exchange" in w for w in r.warnings)


def test_deposits_are_not_profit():
    """A big deposit mid-window must not show up as PnL or inflate the return."""
    acc = simple_account()
    acc.ledger.append({"time": T0 + 20 * DAY, "hash": "0x2", "delta": {"type": "deposit", "usdc": "9000"}})
    acc.portfolio["allTime"]["accountValueHistory"] = hist((T0, 1000), (T0 + 20 * DAY, 10100), (NOW, 10129))
    r = compute_pnl(acc, 0, NOW)
    assert r.net == pytest.approx(129)
    # Modified Dietz: 1000 + 9000 * (20/40) = 5500
    assert r.avg_capital == pytest.approx(5500)
    assert r.return_pct == pytest.approx(129 / 5500)


def test_window_uses_exchange_equity_change_and_start_value():
    acc = simple_account()
    w = T0 + 10 * DAY
    pnl = hist((T0, 0), (w, 100), (NOW, 129))
    acc.portfolio = portfolio(pnl, pnl, hist((T0, 1000), (w, 1100), (NOW, 1129)))
    r = compute_pnl(acc, w, NOW)
    assert r.net == pytest.approx(29)             # 129 - 100 within the window
    assert r.start_value == pytest.approx(1100)
    assert r.return_pct == pytest.approx(29 / 1100)
    assert r.fills == 0 and r.closing_trades == 0   # all fills were before the window
    assert r.unrealised_change == pytest.approx(29)


def test_window_older_than_account_is_clamped():
    r = compute_pnl(simple_account(), T0 - 100 * DAY, NOW)
    assert r.window_start_ms == 0
    assert r.avg_capital == pytest.approx(1000)   # not diluted by 100 empty days
    assert any("younger than the requested period" in w for w in r.warnings)


def test_spot_is_reported_from_exchange_not_recomputed():
    acc = simple_account()
    acc.fills.append(fill(T0 + 6 * DAY, "@107", "A", 5, 60, 0, closed=999, fee=0.01, fee_token="HYPE"))
    total = hist((T0, 0), (NOW, 159))
    perp = hist((T0, 0), (NOW, 129))
    acc.portfolio = portfolio(total, perp, hist((T0, 1000), (NOW, 1159)))
    r = compute_pnl(acc, 0, NOW)
    assert r.spot_net == pytest.approx(30)
    assert r.net == pytest.approx(159)
    assert r.realised_price_pnl == pytest.approx(90)   # spot closedPnl (999) ignored
    assert r.spot_fills == 1 and r.fills == 5


def test_missing_old_fills_detected():
    acc = simple_account()
    acc.funding.insert(0, {"time": T0 - 30 * DAY, "hash": "0x0",
                           "delta": {"type": "funding", "coin": "BTC", "usdc": "-1"}})
    r = compute_pnl(acc, 0, NOW)
    assert r.fills_complete is False
    assert any("no longer serves" in w for w in r.warnings)


def test_tiny_capital_warning():
    acc = simple_account()
    acc.ledger = [{"time": T0, "hash": "0x1", "delta": {"type": "deposit", "usdc": "20"}}]
    r = compute_pnl(acc, 0, NOW)
    assert any("not meaningful" in w for w in r.warnings)


def test_send_direction():
    acc = simple_account()
    other = "0x" + "cd" * 20
    acc.ledger = [
        {"time": T0, "hash": "a", "delta": {"type": "send", "user": other, "destination": ADDR, "usdcValue": "1000"}},
        {"time": T0 + 20 * DAY, "hash": "b", "delta": {"type": "send", "user": ADDR, "destination": other,
                                                         "usdcValue": "400", "fee": "1"}},
    ]
    r = compute_pnl(acc, 0, NOW)
    assert r.net_flows == pytest.approx(1000 - 401)
    assert r.avg_capital == pytest.approx(1000 - 401 * 0.5)


# ------------------------------------------------------------ round trips


def test_round_trip_flip_counts_two_trips():
    fills = [fill(1, "SOL", "B", 1, 10, 0, fee=0.1),
             fill(2, "SOL", "A", 3, 12, 1, closed=2, fee=0.3),      # long 1 -> short 2: closes trip 1
             fill(3, "SOL", "B", 2, 11, -2, closed=2, fee=0.2)]     # short closed: trip 2
    closed, still_open = round_trips(fills)
    assert closed == [pytest.approx(-0.1 + 2 - 0.3), pytest.approx(2 - 0.2)]
    assert still_open == 0


def test_round_trip_scaling_in_counts_once():
    fills = [fill(i, "BTC", "B", 1, 100, i - 1, fee=0.1) for i in range(1, 6)]
    fills.append(fill(6, "BTC", "A", 5, 110, 5, closed=50, fee=0.5))
    closed, _ = round_trips(fills)
    assert closed == [pytest.approx(50 - 1.0)]


def test_order_fills_chains_same_millisecond_by_start_position():
    """Live data: dozens of fills per ms with non-chronological trade ids."""
    fs = [fill(5, "NEAR", "B", 4.7, 1, 9.4, tid=1), fill(5, "NEAR", "B", 4.7, 1, 4.7, tid=2),
          fill(5, "NEAR", "B", 4.7, 1, 0.0, tid=3)]
    ordered = order_fills(fs)
    assert [f["startPosition"] for f in ordered] == ["0.0", "4.7", "9.4"]


# --------------------------------------------------------------- paging


def test_paging_does_not_drop_fills_sharing_the_boundary_millisecond(monkeypatch):
    monkeypatch.setattr(hl, "FILLS_PAGE", 3)
    data = [fill(t, "BTC", "B", 1, 1, i, tid=100 + i) for i, t in enumerate([1, 2, 3, 3, 3, 4])]

    def post(body):
        k = body["type"]
        if k == "userFillsByTime":
            return [f for f in data if f["time"] >= body["startTime"]][:3]
        if k in ("userFunding", "userNonFundingLedgerUpdates", "userTwapSliceFills"):
            return []
        if k == "clearinghouseState":
            return {"assetPositions": [], "marginSummary": {"accountValue": "0"}}
        if k == "portfolio":
            return []
        raise AssertionError(k)

    acc = fetch_account(ADDR, post=post, pause=0)
    assert sorted(f["tid"] for f in acc.fills) == [100, 101, 102, 103, 104, 105]


def test_invalid_address_rejected():
    with pytest.raises(hl.HLError):
        fetch_account("0x123", post=lambda b: [])


# ------------------------------------------------------------- claims


@pytest.mark.parametrize("text,pct,usd,window,rate", [
    ("my bot made 300% this month", 3.0, None, 30, None),
    ("+45.5% in 2 weeks", 0.455, None, 14, None),
    ("turned $500 into $5,000 in 30 days", 9.0, 4500, 30, None),
    ("turned 1k into 10k", 9.0, 9000, None, None),
    ("5% a day, every day", 0.05, None, None, 1),
    ("10x in a week", 9.0, None, 7, None),
    ("made $12,400 profit last month", None, 12400, 30, None),
    ("-20% today", -0.2, None, 1, None),
    ("10% a week for 3 months", 0.1, None, 90, 7),
])
def test_parse_claim(text, pct, usd, window, rate):
    c = parse_claim(text)
    assert (c.pct is None and pct is None) or c.pct == pytest.approx(pct)
    assert (c.usd is None and usd is None) or c.usd == pytest.approx(usd)
    assert c.window_days == window
    assert c.rate_unit_days == rate


def test_window_start_for_claims():
    assert window_start_for(parse_claim("300% this month"), NOW, None) == NOW - 30 * DAY
    assert window_start_for(parse_claim("5% a day"), NOW, None) == NOW - 30 * DAY
    assert window_start_for(None, NOW, None) == 0
    assert window_start_for(parse_claim("300% this month"), NOW, 7) == NOW - 7 * DAY


# ------------------------------------------------------------- verdicts


def _report(**over):
    r = compute_pnl(simple_account(), 0, NOW)
    for k, v in over.items():
        setattr(r, k, v)
    return r


def test_judge_consistent_but_thin_evidence():
    v = judge(parse_claim("made 12% total"), _report())
    assert v.level == "CONSISTENT"
    assert v.evidence_strength == "thin"
    assert any("evidence behind them is weak" in x for x in v.reasons)


def test_judge_grossly_overstated():
    v = judge(parse_claim("my bot made 300% this month"), _report())
    assert v.level == "GROSSLY_OVERSTATED"


def test_judge_contradicted_when_wallet_lost():
    v = judge(parse_claim("+50%"), _report(net=-200.0, return_pct=-0.2))
    assert v.level == "CONTRADICTED"


def test_judge_rate_claim_compounds():
    v = judge(parse_claim("5% a day"), _report(window_days=30.0, return_pct=0.5, net=500.0))
    # 1.05^30 - 1 = 3.3219
    assert v.comparable_claim_pct == pytest.approx(1.05 ** 30 - 1)
    assert v.level == "GROSSLY_OVERSTATED"


def test_judge_flags_gross_vs_net():
    # claim equals the before-cost result; costs explain the gap
    r = _report(net=60.0, return_pct=0.06, gross_before_costs=100.0, fees=50.0, funding=-10.0, avg_capital=1000.0)
    v = judge(parse_claim("+10%"), r)
    assert v.level == "OVERSTATED"
    assert any("before* fees and funding" in x for x in v.reasons)


def test_judge_usd_claim():
    v = judge(parse_claim("made $120 profit"), _report())
    assert v.level == "CONSISTENT"


def test_judge_pct_claim_on_tiny_capital_is_unverifiable():
    v = judge(parse_claim("300%"), _report(avg_capital=22.0, net=-6.5, return_pct=-0.29))
    assert v.level == "UNVERIFIABLE"
    assert "proves nothing" in v.reasons[0]


def test_judge_no_claim():
    assert judge(None, _report()).level == "NO_CLAIM"


def test_evidence_concentration():
    r = _report(closing_trades=40, best_trade_share=0.7, t_stat=3.0, unrealised_now=0.0)
    strength, why = evidence_strength(r)
    assert strength == "thin" and any("One trade produced 70%" in w for w in why)


def test_evidence_solid():
    r = _report(closing_trades=200, wins=120, losses=80, best_trade_share=0.05, top3_share=0.12, t_stat=3.4,
                unrealised_now=0.0, realised=1000.0, net=1000.0)
    assert evidence_strength(r)[0] == "solid"


# ------------------------------------------------------------- orchestration


def test_verify_end_to_end_with_injected_fetch():
    out = verify(ADDR, "my bot made 300%", fetch=lambda a: simple_account(), now_ms=NOW)
    assert out["verdict"]["level"] == "GROSSLY_OVERSTATED"
    assert out["pnl"]["closing_trades"] == 2
    assert out["errors"] == []


def test_verify_reports_fetch_errors():
    def boom(a):
        raise hl.HLError("Hyperliquid API HTTP 429")
    out = verify(ADDR, "", fetch=boom)
    assert out["pnl"] is None and "429" in out["errors"][0]


def test_pnl_api_and_page_served():
    import json
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer

    from scamcheck import web

    web.verify = lambda a, c, d: verify(a, c, d, fetch=lambda x: simple_account(), now_ms=NOW)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        page = urllib.request.urlopen(base + "/pnl").read().decode()
        assert "Claimed-PnL Verifier" in page
        assert b"function render" in urllib.request.urlopen(base + "/pnl.js").read()
        req = urllib.request.Request(base + "/api/pnl", data=json.dumps(
            {"address": ADDR, "claim": "300% this month"}).encode(), headers={"Content-Type": "application/json"})
        body = json.loads(urllib.request.urlopen(req).read())
        assert body["verdict"]["level"] == "GROSSLY_OVERSTATED"
        bad = urllib.request.Request(base + "/api/pnl", data=json.dumps({"address": ADDR, "days": -5}).encode(),
                                     headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(bad)
        assert e.value.code == 400
    finally:
        srv.shutdown()


def test_pnl_ui_never_uses_innerhtml():
    from pathlib import Path
    js = (Path(__file__).parent.parent / "scamcheck" / "static" / "pnl.js").read_text()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "document.write" not in js
