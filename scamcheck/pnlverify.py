"""Orchestration for the Claimed-PnL Verifier (shared by CLI and web)."""

from __future__ import annotations

import time

from .hyperliquid import AccountData, HLError, fetch_account
from .pnlcheck import compute_pnl, judge, parse_claim, window_start_for

DISCLAIMER = ("Figures come from Hyperliquid's public on-chain record. This proves what the wallet did, "
              "not who owns it: check that the wallet really belongs to whoever made the claim.")


def verify(address: str, claim_text: str = "", days: float | None = None, *,
           fetch=fetch_account, now_ms: int | None = None) -> dict:
    """Return a JSON-safe report: {address, claim, pnl, verdict, positions, errors, disclaimer}."""
    claim = parse_claim(claim_text) if claim_text and claim_text.strip() else None
    out: dict = {"address": (address or "").strip(), "claim": claim.to_dict() if claim else None,
                 "pnl": None, "verdict": None, "errors": [], "disclaimer": DISCLAIMER, "source": "hyperliquid"}
    try:
        acc: AccountData = fetch(out["address"])
    except HLError as e:
        out["errors"].append(str(e))
        return out
    now = now_ms or acc.fetched_at_ms or int(time.time() * 1000)
    start = window_start_for(claim, now, days)
    report = compute_pnl(acc, start, now)
    out["pnl"] = report.to_dict()
    out["verdict"] = judge(claim, report).to_dict()
    if report.fills == 0 and report.spot_fills == 0 and not report.open_positions and report.net == 0:
        out["errors"].append("No Hyperliquid trading found for this address in the period. "
                             "It may trade on another venue or chain, which this version does not cover.")
    return out
