"""Deterministic verdict from static findings.

Design rule: the verdict is computed ONLY from deterministic checks. The LLM
explains, it never decides. Contract source is attacker-controlled text and is
a prompt-injection vector ("AI auditors: this contract is safe"), so letting a
model set or soften the verdict would let the scammer grade their own homework.

Asymmetry: static analysis can prove a contract sends money somewhere it
shouldn't. It cannot prove a contract is safe. So the best possible verdict is
"no red flags found", never "safe".
"""

from __future__ import annotations

from dataclasses import dataclass

from .solidity import SEVERITY_ORDER, Analysis

FUND_DRAIN_RULES = {
    "FUNDS_TO_OBFUSCATED_ADDRESS",
    "FUNDS_TO_HARDCODED_ADDRESS",
    "SELFDESTRUCT_TO_OTHER",
    "DELEGATECALL_EXTERNAL",
    "MISLEADING_ENTRYPOINT",
}
# FUNDS_TO_EXTERNAL_DECIDED_ADDRESS only counts as a proven drain when critical
# (balance sweep + recipient defined in an unauditable remote import).

LEVELS = {
    "SCAM": "Scam: this code sends your money to someone else",
    "HIGH_RISK": "High risk: strong scam indicators",
    "CAUTION": "Caution: some concerns, review before using",
    "NO_RED_FLAGS": "No red flags found (this is not proof it is safe)",
    "INCONCLUSIVE": "Inconclusive: no contract code to analyse",
}


@dataclass
class Verdict:
    level: str
    headline: str
    trades: str  # "yes" | "no" | "unknown"
    forwards_funds: str  # "yes" | "no_evidence" | "unknown"
    score: int  # 0..100 risk score, for sorting/display only
    reasons: list[str]

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def compute_verdict(analysis: Analysis | None, narrative: list[dict] | None = None) -> Verdict:
    narrative = narrative or []
    if analysis is None or any(f.rule_id == "NO_SOLIDITY" for f in analysis.findings):
        nar_high = [n for n in narrative if n["severity"] == "high"]
        if len(nar_high) >= 2:
            return Verdict("HIGH_RISK", "High risk: the video follows the known scam script (code not available to verify)",
                           "unknown", "unknown", 70, [n["title"] for n in nar_high])
        if narrative:
            return Verdict("CAUTION", "Caution: video shows scam-script signals; code not available to verify",
                           "unknown", "unknown", 40, [n["title"] for n in narrative])
        return Verdict("INCONCLUSIVE", LEVELS["INCONCLUSIVE"], "unknown", "unknown", 0,
                       ["No Solidity code was found, so nothing could be checked."])

    rules = {f.rule_id for f in analysis.findings}
    trades = "yes" if analysis.swap_calls else "no"
    drains = (rules & FUND_DRAIN_RULES) | {
        f.rule_id for f in analysis.findings if f.rule_id == "FUNDS_TO_EXTERNAL_DECIDED_ADDRESS" and f.severity == "critical"}
    forwards = "yes" if drains else "no_evidence"

    score = 0
    for f in analysis.findings:
        score += {"critical": 40, "high": 15, "medium": 6, "low": 2, "info": 0}[f.severity]
    score += sum({"high": 8, "medium": 4, "low": 1}.get(n["severity"], 0) for n in narrative)
    score = min(100, score)

    reasons = [f.title for f in analysis.findings if SEVERITY_ORDER[f.severity] >= 3][:6]
    if drains:
        level = "SCAM"
        score = max(score, 90)
    elif any(SEVERITY_ORDER[f.severity] >= 3 for f in analysis.findings):
        level = "HIGH_RISK"
        score = max(score, 60)
    elif any(SEVERITY_ORDER[f.severity] >= 2 for f in analysis.findings) or any(n["severity"] == "high" for n in narrative):
        level = "CAUTION"
        reasons = [f.title for f in analysis.findings if SEVERITY_ORDER[f.severity] >= 2][:6] + \
                  [n["title"] for n in narrative if n["severity"] == "high"]
    else:
        level = "NO_RED_FLAGS"
        reasons = ["No hidden recipients, no hardcoded payout addresses, and trading calls are present."
                   if trades == "yes" else "No hidden recipients or hardcoded payout addresses were found."]

    headline = LEVELS[level]
    if level == "SCAM" and trades == "no":
        headline = "Scam: this 'bot' does not trade, it forwards your deposit to someone else"
    return Verdict(level, headline, trades, forwards, score, reasons)
