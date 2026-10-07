"""Command-line interface.

    python -m scamcheck path/to/Bot.sol
    python -m scamcheck https://www.youtube.com/watch?v=XXXXXXXXXXX
    cat Bot.sol | python -m scamcheck -
    python -m scamcheck Bot.sol --json --no-llm
    python -m scamcheck pnl 0xWALLET --claim "my bot made 300% this month"
    python -m scamcheck pnl 0xWALLET --days 30 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import check

EXIT = {"SCAM": 3, "HIGH_RISK": 2, "CAUTION": 1, "NO_RED_FLAGS": 0, "INCONCLUSIVE": 0}


PNL_EXIT = {"CONSISTENT": 0, "NO_CLAIM": 0, "OVERSTATED": 1, "GROSSLY_OVERSTATED": 2, "CONTRADICTED": 3,
            "UNVERIFIABLE": 4}


def _money(x) -> str:
    return "n/a" if x is None else ("-" if x < 0 else "") + f"${abs(x):,.2f}"


def _pct(x) -> str:
    return "n/a" if x is None else f"{x * 100:+,.1f}%"


def pnl_main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="scamcheck pnl",
                                description="Check a 'my bot made X%' claim against a wallet's on-chain record (Hyperliquid).")
    p.add_argument("address", help="0x… wallet address")
    p.add_argument("--claim", default="", help='the claim, e.g. "turned $500 into $5k in 2 weeks"')
    p.add_argument("--days", type=float, help="lookback window in days (default: from the claim, else all time)")
    p.add_argument("--json", action="store_true", help="print the full JSON report")
    a = p.parse_args(argv)
    from .pnlverify import verify
    r = verify(a.address, a.claim, a.days)
    if a.json:
        print(json.dumps(r, indent=2))
        return PNL_EXIT.get((r.get("verdict") or {}).get("level"), 4)
    for e in r["errors"]:
        print(f"! {e}")
    if not r["pnl"]:
        return 4
    v, m = r["verdict"], r["pnl"]
    print(f"\nVERDICT: {v['headline']}")
    if r["claim"]:
        print(f"  claimed:  {v['claimed']}")
    print(f"  observed: {v['observed']}")
    print(f"\n  Net PnL               {_money(m['net']):>16}   ({_pct(m['return_pct'])} on avg capital {_money(m['avg_capital'])})")
    print(f"    realised (perps)    {_money(m['realised']):>16}   = price {_money(m['realised_price_pnl'])} "
          f"- fees {_money(m['fees'])} + funding {_money(m['funding'])}")
    print(f"    open-position value {_money(m['unrealised_change']):>16}   (change over the period, incl. positions "
          f"carried in; open now: {_money(m['unrealised_now'])})")
    if abs(m["spot_net"]) > 0.005:
        print(f"    spot (exchange)     {_money(m['spot_net']):>16}")
    wr = "n/a" if m["win_rate"] is None else f"{m['win_rate']:.0%}"
    print(f"\n  Rests on: {m['closing_trades']} completed trades ({m['wins']} won / {m['losses']} lost, win rate {wr}), "
          f"{m['fills']} perp fills over {m['active_days']} active days. Evidence: {v['evidence_strength'].upper()}")
    for why in v["reasons"]:
        print(f"   - {why}")
    for w in m["warnings"]:
        print(f"  ! {w}")
    print(f"\n{r['disclaimer']}")
    return PNL_EXIT.get(v["level"], 4)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "pnl":
        return pnl_main(argv[1:])
    p = argparse.ArgumentParser(prog="scamcheck", description="Check 'AI trading bot' tutorial code for scam patterns.")
    p.add_argument("target", nargs="?", help="Solidity file, '-' for stdin, a YouTube link, or a pastebin/gist link")
    p.add_argument("--json", action="store_true", help="print the full JSON report")
    p.add_argument("--no-llm", action="store_true", help="skip the LLM explanation")
    p.add_argument("--check-llm", action="store_true", help="verify the LLM key/provider with one tiny call and exit")
    a = p.parse_args(argv)
    if a.check_llm:
        from .explain import self_test
        ok, msg = self_test()
        print(("LLM OK: " if ok else "LLM FAILED: ") + msg)
        return 0 if ok else 1
    if not a.target:
        p.error("target is required (or use --check-llm)")

    if a.target == "-":
        text = sys.stdin.read()
    elif Path(a.target).is_file():
        text = Path(a.target).read_text(encoding="utf-8", errors="replace")
    else:
        text = a.target
    r = check(text, use_llm=not a.no_llm)

    if a.json:
        print(json.dumps(r, indent=2))
    else:
        v = r["verdict"]
        print(f"\nVERDICT: {v['headline']}")
        print(f"  actually trades: {v['trades']}   forwards funds: {v['forwards_funds']}   risk: {v['score']}/100\n")
        for f in (r["analysis"] or {}).get("findings", []):
            loc = f"L{f['line']}" if f["line"] else "   "
            print(f"  [{f['severity']:>8}] {loc:>5}  {f['title']}")
        for n in r["narrative_flags"]:
            print(f"  [{n['severity']:>8}] video  {n['title']}")
        for e in r["errors"]:
            print(f"  ! {e}")
        print("\n" + r["explanation"]["text"])
        print(f"\n({r['explanation']['source']}) {r['disclaimer']}")
    return EXIT.get(r["verdict"]["level"], 0)


if __name__ == "__main__":
    sys.exit(main())
