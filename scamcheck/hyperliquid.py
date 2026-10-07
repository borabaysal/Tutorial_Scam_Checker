"""Hyperliquid public data client (no API key; fills/fees/funding are public on HL L1).

Pitfalls verified against the live API (Oct 2026), each of which silently
corrupts PnL if ignored:

* ``userFillsByTime`` returns at most 2000 fills per call -> paginate by time.
* ``userFunding`` / ``userNonFundingLedgerUpdates`` return at most 500 rows per
  call -> paginate too (missing pages produced a ~$1k funding gap in testing).
* TWAP child fills are NOT in ``userFillsByTime``; they come from
  ``userTwapSliceFills`` (recent window only). An account trading only via
  TWAP otherwise looks like it never traded.
* The API rate-limits aggressively (HTTP 429) -> exponential backoff.

All HTTP goes through an injectable ``post`` so tests run offline.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

INFO_URL = "https://api.hyperliquid.xyz/info"
FILLS_PAGE = 2000
LEDGER_PAGE = 500
MAX_FILLS = 50_000  # hard stop: a market maker can have millions of fills

Post = Callable[[dict], object]
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


class HLError(RuntimeError):
    pass


def http_post(body: dict, *, retries: int = 6, timeout: int = 30) -> object:
    data = json.dumps(body).encode()
    delay = 2.0
    for attempt in range(retries):
        req = urllib.request.Request(INFO_URL, data=data, headers={
            "Content-Type": "application/json", "User-Agent": "TutorialScamChecker/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise HLError(f"Hyperliquid API HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
                continue
            raise HLError(f"Hyperliquid API unreachable: {e}") from e
    raise HLError("Hyperliquid API retries exhausted")


@dataclass
class AccountData:
    address: str
    fills: list[dict] = field(default_factory=list)
    funding: list[dict] = field(default_factory=list)
    ledger: list[dict] = field(default_factory=list)
    state: dict = field(default_factory=dict)
    portfolio: dict = field(default_factory=dict)
    fetched_at_ms: int = 0
    fills_truncated: bool = False  # hit MAX_FILLS: older history not loaded
    twap_fills: int = 0
    warnings: list[str] = field(default_factory=list)


def _row_key(kind: str, row: dict):
    if kind == "userFillsByTime":
        return row.get("tid")
    return (row.get("time"), row.get("hash"), str(row.get("delta")))


def _paged(post: Post, kind: str, address: str, start_ms: int, page: int, cap: int,
           pause: float) -> tuple[list[dict], bool]:
    """Page forward in time, deduplicating rows.

    The next page starts AT the last timestamp, not after it: dozens of fills
    can share one millisecond, and ``last_time + 1`` silently dropped the rest
    of that millisecond (thousands of dollars of PnL on live accounts).
    """
    out: list[dict] = []
    seen: set = set()
    start = start_ms
    while True:
        batch = post({"type": kind, "user": address, "startTime": start})
        if not isinstance(batch, list):
            raise HLError(f"unexpected {kind} response")
        new = 0
        for row in batch:
            k = _row_key(kind, row)
            if k not in seen:
                seen.add(k)
                out.append(row)
                new += 1
        if len(batch) < page:
            return out, False
        if len(out) >= cap:
            return out, True
        last = int(batch[-1]["time"])
        # A full page that is all one millisecond (or all already seen) can't
        # advance by timestamp; step past it rather than loop forever.
        start = last + 1 if (new == 0 or int(batch[0]["time"]) == last) else last
        if pause:
            time.sleep(pause)


def order_fills(fills: list[dict]) -> list[dict]:
    """Chronological order that respects position continuity.

    Trade ids are NOT chronological, and many fills share a millisecond, so
    within each millisecond we chain fills per coin by ``startPosition``
    (each fill starts where the previous one ended).
    """
    def side(f):
        return 1 if f.get("side") == "B" else -1

    def flt(x):
        try:
            return float(x)
        except (TypeError, ValueError):
            return 0.0

    by_time: dict[int, list[dict]] = {}
    for f in fills:
        by_time.setdefault(int(f["time"]), []).append(f)
    pos: dict[str, float] = {}
    out: list[dict] = []
    for t in sorted(by_time):
        group = by_time[t]
        if len(group) > 1:
            pending = group[:]
            chained = []
            while pending:
                pick = None
                for f in pending:
                    cur = pos.get(f["coin"])
                    if cur is not None and abs(flt(f.get("startPosition")) - cur) <= 1e-9 * max(1.0, abs(cur)):
                        pick = f
                        break
                if pick is None:  # no continuation known: lowest |startPosition| move first
                    pick = min(pending, key=lambda f: (f["coin"], side(f) * flt(f.get("startPosition"))))
                pending.remove(pick)
                chained.append(pick)
                pos[pick["coin"]] = flt(pick.get("startPosition")) + side(pick) * flt(pick.get("sz"))
            group = chained
        else:
            f = group[0]
            pos[f["coin"]] = flt(f.get("startPosition")) + side(f) * flt(f.get("sz"))
        out.extend(group)
    return out


def fetch_account(address: str, *, start_ms: int = 0, post: Post = http_post, pause: float = 0.4) -> AccountData:
    if not ADDRESS_RE.match(address or ""):
        raise HLError("not a valid 0x… wallet address")
    address = address.lower()
    acc = AccountData(address=address, fetched_at_ms=int(time.time() * 1000))

    fills, acc.fills_truncated = _paged(post, "userFillsByTime", address, start_ms, FILLS_PAGE, MAX_FILLS, pause)
    twap = post({"type": "userTwapSliceFills", "user": address}) or []
    twap_fills = [t["fill"] for t in twap if isinstance(t, dict) and "fill" in t]
    acc.twap_fills = len(twap_fills)
    if len(twap) >= FILLS_PAGE:
        acc.warnings.append("TWAP slice history is capped by the API; older TWAP fills may be missing.")
    # TWAP slices carry a zero hash; dedupe on trade id across both sources.
    by_tid = {f["tid"]: f for f in fills}
    for f in twap_fills:
        if int(f.get("time", 0)) >= start_ms:
            by_tid.setdefault(f["tid"], f)
    acc.fills = order_fills(list(by_tid.values()))

    acc.funding, trunc_f = _paged(post, "userFunding", address, start_ms, LEDGER_PAGE, 10**7, pause)
    acc.ledger, trunc_l = _paged(post, "userNonFundingLedgerUpdates", address, 0, LEDGER_PAGE, 10**7, pause)
    acc.state = post({"type": "clearinghouseState", "user": address}) or {}
    pf = post({"type": "portfolio", "user": address}) or []
    acc.portfolio = dict(pf) if isinstance(pf, list) else {}
    if acc.fills_truncated:
        # Paging runs oldest -> newest, so a cap loses the MOST RECENT fills.
        # The verifier treats this as incomplete data, never as a result.
        acc.warnings.append(f"Stopped after {MAX_FILLS:,} fills: the most recent fills are missing, so PnL is incomplete.")
    return acc
