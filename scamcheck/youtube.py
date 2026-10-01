"""YouTube ingestion: metadata, transcript, and linked contract source.

Scam "AI trading bot" tutorials almost always follow the same script: open
Remix, paste code from a link in the description, deploy, fund the contract,
press Start. So for a video we:

1. Pull title / channel / description (InnerTube player API).
2. Pull the transcript (captions) if available.
3. Find code links in the description and fetch raw Solidity from a small
   allow-list of paste/code hosts (never arbitrary URLs: this is a server that
   accepts user input, so arbitrary fetches would be an SSRF hole).
4. Scan the narrative for the scam script (deploy-fund-start, profit promises,
   "leave at least X ETH", comment-section manipulation...).

All network access goes through ``http_get`` so tests can inject a fake.
"""

from __future__ import annotations

import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

MAX_FETCH_BYTES = 2_000_000
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) TutorialScamChecker/0.1"

# InnerTube clients. The WEB client's caption URLs now need a PO token and
# return empty bodies; ANDROID/IOS still return usable timedtext (verified
# 2026-10). Tried in order.
INNERTUBE_CLIENTS = [
    ("ANDROID", "20.10.38", {"androidSdkVersion": 30},
     "com.google.android.youtube/20.10.38 (Linux; U; Android 11) gzip"),
    ("IOS", "20.10.4", {"deviceModel": "iPhone16,2"},
     "com.google.ios.youtube/20.10.4 (iPhone16,2; U; CPU iOS 18_3 like Mac OS X)"),
]

VIDEO_ID_RE = re.compile(
    r"(?:youtube\.com/(?:watch\?(?:.*&)?v=|shorts/|embed/|live/|v/)|youtu\.be/)([A-Za-z0-9_-]{11})"
)

URL_RE = re.compile(r"https?://[^\s\"'<>()\[\]]+")

HttpGet = Callable[..., bytes]


class FetchError(RuntimeError):
    pass


def http_get(url: str, *, data: bytes | None = None, headers: dict | None = None, timeout: int = 15) -> bytes:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_FETCH_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise FetchError(f"HTTP {e.code} fetching {url}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise FetchError(f"network error fetching {url}: {e}") from e
    if len(body) > MAX_FETCH_BYTES:
        raise FetchError(f"response too large from {url}")
    return body


def extract_video_id(text: str) -> str | None:
    m = VIDEO_ID_RE.search(text)
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# Code-link resolution (allow-listed hosts only)
# --------------------------------------------------------------------------


def raw_code_url(url: str) -> str | None:
    """Map a share link to a raw-text URL on an allow-listed host, else None."""
    url = url.rstrip(".,;)")
    p = urllib.parse.urlparse(url)
    host = (p.hostname or "").lower().removeprefix("www.")
    parts = [x for x in p.path.split("/") if x]
    if p.scheme != "https" and not (p.scheme == "http" and host in ("pastebin.com",)):
        return None
    if host == "pastebin.com" and parts:
        pid = parts[-1]
        return f"https://pastebin.com/raw/{pid}" if re.fullmatch(r"[A-Za-z0-9]{6,12}", pid) else None
    if host == "gist.github.com" and len(parts) >= 1:
        gid = parts[-1]
        return f"gist:{gid}" if re.fullmatch(r"[0-9a-f]{20,40}", gid) else None
    if host == "gist.githubusercontent.com":
        return url
    if host == "github.com" and len(parts) >= 5 and parts[2] == "blob":
        return f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{'/'.join(parts[3:])}"
    if host == "raw.githubusercontent.com":
        return url
    if host in ("rentry.co", "rentry.org") and parts:
        return f"https://{host}/{parts[0]}/raw"
    if host == "hastebin.com" and parts:
        return f"https://hastebin.com/raw/{parts[-1].split('.')[0]}"
    if host == "paste.ee" and len(parts) >= 2 and parts[0] in ("p", "r"):
        return f"https://paste.ee/r/{parts[1]}"
    if host == "codeshare.io" and parts:
        # codeshare has no raw endpoint without JS; the page embeds the code.
        return f"codeshare:{parts[0]}"
    return None


def fetch_code(url: str, get: HttpGet = http_get) -> str:
    raw = raw_code_url(url)
    if raw is None:
        raise FetchError(f"unsupported code host: {url}")
    if raw.startswith("gist:"):
        meta = json.loads(get(f"https://api.github.com/gists/{raw[5:]}", headers={"Accept": "application/vnd.github+json"}))
        files = meta.get("files", {})
        sol = [f for n, f in files.items() if n.endswith(".sol")] or list(files.values())
        return "\n\n".join(f.get("content", "") for f in sol)
    if raw.startswith("codeshare:"):
        page = get(f"https://codeshare.io/{raw[10:]}").decode("utf-8", "replace")
        m = re.search(r'<textarea[^>]*id="editor"[^>]*>(.*?)</textarea>', page, re.S)
        if not m:
            raise FetchError("could not find code on codeshare page")
        return html.unescape(m.group(1))
    return get(raw).decode("utf-8", "replace")


def looks_like_solidity(text: str) -> bool:
    return bool(re.search(r"\bpragma\s+solidity\b|\bcontract\s+\w+\s*(is\s+[\w, ]+)?\{", text))


# --------------------------------------------------------------------------
# Transcript / narrative red flags
# --------------------------------------------------------------------------

NARRATIVE_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    ("REMIX_DEPLOY_FUND_START", "high", "Classic 'deploy in Remix, fund it, press start' script",
     re.compile(r"remix.{0,400}(deploy).{0,600}(fund|send|deposit|transfer).{0,600}\b(start|action|run)\b", re.I | re.S)),
    ("MIN_BALANCE_PRESSURE", "high", "Tells you to leave a minimum amount of ETH/BNB in the bot",
     re.compile(r"(at least|minimum( of)?|no less than|recommend(ed)?)\s*(\d+(\.\d+)?|half an?|one|two|three)\s*(eth|bnb|ether)", re.I)),
    ("PROFIT_PROMISE", "high", "Promises specific or passive profits",
     re.compile(r"(\d+\s*%\s*(daily|a day|per day|weekly|a week))|passive income|(earn|made|make|profit(s|ed)?)\s+\$?\d[\d,.]*\s*(k\b|eth|bnb|dollars|usd|\$)?\s*(a|per|every)\s*(day|week|hour)|risk[- ]free|guaranteed", re.I)),
    ("GAS_FEE_EXCUSE", "medium", "Explains why small deposits 'won't work' (gas/slippage excuse)",
     re.compile(r"(gas fees?|slippage|network fees?).{0,80}(eat|cover|won'?t (work|be profitable)|not profitable|too (small|low))", re.I)),
    ("SECRECY_URGENCY", "medium", "Urgency or secrecy pressure",
     re.compile(r"(before (it|this) gets? (patched|taken down|removed))|(limited time)|(don'?t share)|(only works? (for|while))", re.I)),
    ("AI_HYPE", "low", "Leans on AI / ChatGPT branding",
     re.compile(r"\b(chat ?gpt|gpt-?\d|openai|ai[- ]powered|ai bot|artificial intelligence)\b", re.I)),
    ("COMMENTS_SOCIAL_PROOF", "low", "Points to comments/likes as proof it works",
     re.compile(r"(check|read|look at) the comments|comments? (prove|show)|everyone in the comments", re.I)),
    ("OLD_COMPILER", "medium", "Asks you to pick an old Solidity compiler version",
     re.compile(r"(compiler|version).{0,40}0\.6\.\d", re.I)),
]


@dataclass
class VideoInfo:
    video_id: str
    title: str = ""
    channel: str = ""
    description: str = ""
    transcript: str = ""
    transcript_source: str = ""
    code_links: list[str] = field(default_factory=list)
    other_links: list[str] = field(default_factory=list)
    fetched_code: list[dict] = field(default_factory=list)  # {url, ok, source|error}
    inline_code: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = dict(self.__dict__)
        d["transcript"] = self.transcript[:20000]
        d["fetched_code"] = [{k: v for k, v in c.items() if k != "source"} | {"chars": len(c.get("source", ""))}
                             for c in self.fetched_code]
        return d


def narrative_flags(text: str) -> list[dict]:
    out = []
    for rule_id, sev, title, rx in NARRATIVE_PATTERNS:
        m = rx.search(text)
        if m:
            s = max(0, m.start() - 60)
            quote = re.sub(r"\s+", " ", text[s : m.end() + 60]).strip()
            out.append({"rule_id": rule_id, "severity": sev, "title": title, "evidence": quote[:240]})
    return out


def _parse_timedtext(xml: str) -> str:
    chunks = re.findall(r"<(?:p|text)\b[^>]*>(.*?)</(?:p|text)>", xml, re.S)
    words = [html.unescape(html.unescape(re.sub(r"<[^>]+>", "", c))) for c in chunks]
    return re.sub(r"\s+", " ", " ".join(words)).strip()


def _player(video_id: str, get: HttpGet) -> tuple[dict, str]:
    last_err = "no client succeeded"
    for name, ver, extra, ua in INNERTUBE_CLIENTS:
        body = {"context": {"client": {"clientName": name, "clientVersion": ver, "hl": "en", **extra}}, "videoId": video_id}
        try:
            raw = get("https://www.youtube.com/youtubei/v1/player?prettyPrint=false",
                      data=json.dumps(body).encode(), headers={"Content-Type": "application/json", "User-Agent": ua})
            pr = json.loads(raw)
        except (FetchError, ValueError) as e:
            last_err = str(e)
            continue
        if pr.get("videoDetails"):
            return pr, ua
        last_err = pr.get("playabilityStatus", {}).get("reason") or pr.get("playabilityStatus", {}).get("status", "unknown")
    raise FetchError(f"could not load video {video_id}: {last_err}")


def fetch_video(url_or_id: str, get: HttpGet = http_get, fetch_linked_code: bool = True) -> VideoInfo:
    vid = extract_video_id(url_or_id) or (url_or_id if re.fullmatch(r"[A-Za-z0-9_-]{11}", url_or_id) else None)
    if not vid:
        raise FetchError("not a YouTube video link")
    info = VideoInfo(video_id=vid)
    pr, ua = _player(vid, get)
    vd = pr.get("videoDetails", {})
    info.title = vd.get("title", "")
    info.channel = vd.get("author", "")
    info.description = vd.get("shortDescription", "")

    tracks = pr.get("captions", {}).get("playerCaptionsTracklistRenderer", {}).get("captionTracks", [])
    # Prefer human English captions, then auto-generated English, then anything.
    tracks.sort(key=lambda t: (not t.get("languageCode", "").startswith("en"), t.get("kind") == "asr"))
    for t in tracks:
        try:
            xml = get(t["baseUrl"], headers={"User-Agent": ua}).decode("utf-8", "replace")
        except FetchError as e:
            info.errors.append(f"transcript: {e}")
            continue
        text = _parse_timedtext(xml)
        if text:
            info.transcript = text
            info.transcript_source = f"{t.get('languageCode')}{' (auto)' if t.get('kind') == 'asr' else ''}"
            break
    if not info.transcript:
        info.errors.append("transcript: none available")

    seen = set()
    for u in URL_RE.findall(info.description):
        u = u.rstrip(".,;)")
        if u in seen:
            continue
        seen.add(u)
        (info.code_links if raw_code_url(u) else info.other_links).append(u)

    if looks_like_solidity(info.description):
        info.inline_code = info.description

    if fetch_linked_code:
        for u in info.code_links[:5]:
            try:
                src = fetch_code(u, get)
                info.fetched_code.append({"url": u, "ok": True, "is_solidity": looks_like_solidity(src), "source": src})
            except (FetchError, ValueError, KeyError) as e:
                info.fetched_code.append({"url": u, "ok": False, "error": str(e)})
    return info
