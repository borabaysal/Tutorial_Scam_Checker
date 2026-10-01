"""Top-level orchestration: turn raw user input into a report."""

from __future__ import annotations

import re
from typing import Any

from . import youtube
from .explain import explain
from .solidity import analyze_solidity
from .verdict import compute_verdict

MAX_INPUT_CHARS = 300_000


def detect_input(text: str) -> str:
    t = text.strip()
    if youtube.extract_video_id(t) and len(t) < 500 and "\n" not in t:
        return "youtube"
    if re.match(r"https?://\S+$", t) and youtube.raw_code_url(t):
        return "code_url"
    return "solidity"


def check(text: str, *, use_llm: bool = True, get: youtube.HttpGet = youtube.http_get) -> dict[str, Any]:
    text = (text or "")[:MAX_INPUT_CHARS]
    kind = detect_input(text)
    report: dict[str, Any] = {"input_type": kind, "errors": []}
    code, video, narrative = "", None, []

    if kind == "youtube":
        try:
            info = youtube.fetch_video(text.strip(), get=get)
        except youtube.FetchError as e:
            report["errors"].append(str(e))
            info = None
        if info:
            video = info.to_dict()
            report["video"] = video
            report["errors"] += info.errors
            narrative = youtube.narrative_flags(" ".join([info.title, info.description, info.transcript]))
            sol = [c["source"] for c in info.fetched_code if c.get("ok") and c.get("is_solidity")]
            if info.inline_code:
                sol.append(info.inline_code)
            code = "\n\n".join(sol)
            if not code and info.code_links:
                report["errors"].append("Code link(s) found but none could be fetched as Solidity.")
            if not info.code_links and not info.inline_code:
                report["errors"].append("No code link in the video description. Paste the code directly for a full check.")
    elif kind == "code_url":
        try:
            code = youtube.fetch_code(text.strip(), get)
        except youtube.FetchError as e:
            report["errors"].append(str(e))
    else:
        code = text

    analysis = analyze_solidity(code) if code.strip() else None
    verdict = compute_verdict(analysis, narrative)
    report["verdict"] = verdict.to_dict()
    report["analysis"] = analysis.to_dict() if analysis else None
    report["narrative_flags"] = narrative
    report["explanation"] = explain(verdict, analysis, narrative, code, video, use_llm=use_llm)
    report["disclaimer"] = ("Automated heuristic checks. They can prove that code sends funds somewhere suspicious; "
                            "they cannot prove code is safe. Not financial or security advice.")
    return report
