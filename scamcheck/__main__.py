"""Command-line interface.

    python -m scamcheck path/to/Bot.sol
    python -m scamcheck https://www.youtube.com/watch?v=XXXXXXXXXXX
    cat Bot.sol | python -m scamcheck -
    python -m scamcheck Bot.sol --json --no-llm
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .checker import check

EXIT = {"SCAM": 3, "HIGH_RISK": 2, "CAUTION": 1, "NO_RED_FLAGS": 0, "INCONCLUSIVE": 0}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="scamcheck", description="Check 'AI trading bot' tutorial code for scam patterns.")
    p.add_argument("target", help="Solidity file, '-' for stdin, a YouTube link, or a pastebin/gist link")
    p.add_argument("--json", action="store_true", help="print the full JSON report")
    p.add_argument("--no-llm", action="store_true", help="skip the LLM explanation")
    a = p.parse_args(argv)

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
