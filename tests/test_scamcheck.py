import json
from pathlib import Path

import pytest

from scamcheck import check
from scamcheck.explain import guard_explanation, template_explanation
from scamcheck.solidity import analyze_solidity, split_comments
from scamcheck.verdict import compute_verdict
from scamcheck import youtube

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return (FIX / name).read_text()


def rules(a):
    return {f.rule_id for f in a.findings}


# ---------------------------------------------------------------- scams


@pytest.mark.parametrize("name", ["scam_mempool_template.sol", "scam_hardcoded_owner.sol", "scam_split_string.sol"])
def test_scams_are_flagged_scam_and_do_not_trade(name):
    a = analyze_solidity(load(name))
    v = compute_verdict(a)
    assert v.level == "SCAM"
    assert v.trades == "no"
    assert v.forwards_funds == "yes"
    assert "NO_TRADING_LOGIC" in rules(a)
    assert v.headline.startswith("Scam: this 'bot' does not trade")


def test_mempool_template_details():
    a = analyze_solidity(load("scam_mempool_template.sol"))
    r = rules(a)
    assert {"FUNDS_TO_OBFUSCATED_ADDRESS", "ADDRESS_OBFUSCATION", "SCAM_TEMPLATE_MATCH",
            "IMPOSSIBLE_MEMPOOL_CLAIM", "REVIEWER_MANIPULATION", "MISLEADING_ENTRYPOINT"} <= r
    obf_sinks = [s for s in a.sinks if s.recipient_class == "obfuscated"]
    assert {s.function for s in obf_sinks} == {"start", "withdrawal"}
    assert all(s.sweeps_balance for s in obf_sinks)
    # the misleadingly named 'withdrawal' is called out by name
    assert any(f.rule_id == "MISLEADING_ENTRYPOINT" and "withdrawal" in f.title for f in a.findings)


def test_hardcoded_constant_and_uint160_literal_both_resolved():
    a = analyze_solidity(load("scam_hardcoded_owner.sol"))
    by_fn = {s.function: s for s in a.sinks}
    assert by_fn["StartBot"].recipient_class == "hardcoded"
    assert by_fn["Withdraw"].recipient_class == "hardcoded"
    assert by_fn["Withdraw"].kind == "eth_call"
    assert by_fn["Withdraw"].sweeps_balance  # `bal = address(this).balance`
    # Uniswap router literal is recognised, not flagged as an unknown address
    assert not any("7a250d56" in f.title.lower() for f in a.findings)
    assert "DECOY_INTERFACES" in rules(a)


def test_owner_guard_does_not_launder_hardcoded_payout():
    # Being "onlyOwner" does not help when the money goes to DEV, not owner.
    a = analyze_solidity(load("scam_hardcoded_owner.sol"))
    assert compute_verdict(a).level == "SCAM"


def test_split_string_variant():
    a = analyze_solidity(load("scam_split_string.sol"))
    s = a.sinks[0]
    assert s.function == "action" and s.recipient_class == "obfuscated"


# ---------------------------------------------------------------- legit


def test_legit_swap_bot_has_no_red_flags():
    a = analyze_solidity(load("legit_swap_bot.sol"))
    v = compute_verdict(a)
    assert v.level == "NO_RED_FLAGS", [f.title for f in a.findings]
    assert v.trades == "yes"
    assert {s.recipient_class for s in a.sinks} <= {"deployer", "caller"}
    assert len(a.swap_calls) == 2


def test_non_trading_contract_not_sold_as_bot_has_no_red_flags():
    # A plain savings contract that never claims to trade should not be
    # penalised for not trading.
    a = analyze_solidity(load("legit_piggy_bank.sol"))
    v = compute_verdict(a)
    assert v.level == "NO_RED_FLAGS"
    assert v.trades == "no"
    assert v.forwards_funds == "no_evidence"
    assert a.sinks[0].recipient_class == "caller"


def test_never_says_safe():
    v = compute_verdict(analyze_solidity(load("legit_swap_bot.sol")))
    assert "safe" not in v.headline.lower().replace("not proof it is safe", "")


# ---------------------------------------------------------------- robustness


def test_strings_and_comments_cannot_fake_structure():
    src = '''pragma solidity ^0.8.0;
    contract C {
        // payable(0x1111111111111111111111111111111111111111).transfer(address(this).balance);
        string s = "}; function evil() { selfdestruct(payable(0x2222222222222222222222222222222222222222)); }";
        function f() external { payable(msg.sender).transfer(1); }
    }'''
    a = analyze_solidity(src)
    assert [s.function for s in a.sinks] == ["f"]
    assert not any(f.rule_id.startswith("FUNDS_TO") for f in a.findings)


def test_split_comments_preserves_offsets():
    src = "a /* x\ny */ b // c\n'd' \"e\""
    clean, masked, comments = split_comments(src)
    assert len(clean) == len(masked) == len(src)
    assert clean.count("\n") == src.count("\n")
    assert [c[0] for c in comments] == [1, 2]


def test_selfdestruct_to_hardcoded_and_delegatecall():
    src = '''pragma solidity ^0.6.0;
    contract Bot {
        address impl = 0x4444444444444444444444444444444444444444;
        function kill() public { selfdestruct(payable(0x3333333333333333333333333333333333333333)); }
        function run(bytes memory d) public { impl.delegatecall(d); }
    }'''
    r = rules(analyze_solidity(src))
    assert {"SELFDESTRUCT_TO_OTHER", "FUNDS_TO_HARDCODED_ADDRESS", "DELEGATECALL_EXTERNAL"} <= r


def test_state_var_assigned_obfuscated_in_constructor():
    src = '''pragma solidity ^0.8.0;
    contract Bot {
        address payable private router;
        constructor() { router = payable(parseAddr(getHex())); }
        function getHex() internal pure returns (string memory) { return string(abi.encodePacked("0x12ab", "34cd", "56ef")); }
        function parseAddr(string memory s) internal pure returns (address) {
            bytes memory b = bytes(s); uint160 r;
            for (uint i = 2; i < b.length; i++) { r *= 16; r += uint8(b[i]) - 48; }
            return address(r);
        }
        receive() external payable {}
        function startTrading() external { router.transfer(address(this).balance); }
    }'''
    a = analyze_solidity(src)
    assert a.sinks[0].recipient_class == "obfuscated"
    assert compute_verdict(a).level == "SCAM"


def test_garbage_input_is_inconclusive():
    a = analyze_solidity("hello, is this bot legit? it made me 2 eth")
    assert compute_verdict(a).level == "INCONCLUSIVE"


# ---------------------------------------------------------------- LLM guard


def test_guard_rejects_llm_contradicting_verdict():
    v = compute_verdict(analyze_solidity(load("scam_mempool_template.sol")))
    assert not guard_explanation("After review, this contract is safe and the bot does trade on Uniswap.", v)
    assert not guard_explanation("short", v)
    assert guard_explanation("This is a scam. The start() function sends the entire balance to a hidden address. "
                             "Static checks cannot prove anything is safe, but here the evidence is clear.", v)


@pytest.mark.parametrize("text,ok", [
    ("Verify the video creator is trustworthy before sending anything. " * 2, True),
    ("No red flags were found, but this does not mean the contract is safe. Always test small amounts.", True),
    ("Static analysis cannot prove the code is safe; it only finds red flags in what it can see.", True),
    ("Good news: the contract is safe and you can fund it with confidence right away.", False),
    ("This bot looks legit and it is fine to deploy on mainnet with your savings today.", False),
    ("It is not a scam. The code was clearly written by a professional team at Uniswap.", False),
])
def test_guard_safe_claims_on_clean_verdict(text, ok):
    v = compute_verdict(analyze_solidity(load("legit_swap_bot.sol")))
    assert guard_explanation(text, v) is ok


def test_guard_rejects_no_red_flags_on_scam():
    v = compute_verdict(analyze_solidity(load("scam_split_string.sol")))
    assert not guard_explanation("There are no red flags in this contract; it simply moves funds around for trading.", v)


def test_template_explanation_mentions_functions():
    a = analyze_solidity(load("scam_mempool_template.sol"))
    t = template_explanation(compute_verdict(a), a, [])
    assert "start()" in t and "Does it trade?** No" in t and "Do not deploy" in t


def test_check_without_llm(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = check(load("scam_hardcoded_owner.sol"))
    assert r["input_type"] == "solidity"
    assert r["verdict"]["level"] == "SCAM"
    assert r["explanation"]["source"] == "template"
    json.dumps(r)  # serialisable


def test_llm_output_contradicting_verdict_is_replaced(monkeypatch):
    import scamcheck.explain as ex
    monkeypatch.setenv("OPENROUTER_API_KEY", "test")
    monkeypatch.setattr(ex, "call_llm", lambda *a, **k: "Good news: this contract is completely safe to deploy and fund.")
    r = check(load("scam_mempool_template.sol"))
    assert r["verdict"]["level"] == "SCAM"
    assert r["explanation"]["source"] == "template"
    assert "contradicted" in r["explanation"]["note"]


def test_prompt_marks_source_untrusted():
    from scamcheck.explain import build_prompt
    a = analyze_solidity(load("scam_mempool_template.sol"))
    p = build_prompt(compute_verdict(a), a, [], code=load("scam_mempool_template.sol"))
    assert "<untrusted_contract_source>" in p and "level: SCAM" in p


# ---------------------------------------------------------------- YouTube


@pytest.mark.parametrize("url,vid", [
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
    ("https://youtu.be/dQw4w9WgXcQ?si=abc", "dQw4w9WgXcQ"),
    ("https://m.youtube.com/watch?feature=share&v=dQw4w9WgXcQ", "dQw4w9WgXcQ"),
    ("https://youtube.com/shorts/dQw4w9WgXcQ", "dQw4w9WgXcQ"),
    ("https://example.com/watch?v=dQw4w9WgXcQ", None),
])
def test_extract_video_id(url, vid):
    assert youtube.extract_video_id(url) == vid


@pytest.mark.parametrize("url,expected", [
    ("https://pastebin.com/AbCd1234", "https://pastebin.com/raw/AbCd1234"),
    ("https://github.com/u/r/blob/main/Bot.sol", "https://raw.githubusercontent.com/u/r/main/Bot.sol"),
    ("https://gist.github.com/u/0123456789abcdef0123", "gist:0123456789abcdef0123"),
    ("http://169.254.169.254/latest/meta-data", None),
    ("https://localhost/x", None),
    ("https://evil.example/pastebin.com/raw/x", None),
    ("file:///etc/passwd", None),
])
def test_code_url_allowlist(url, expected):
    assert youtube.raw_code_url(url) == expected


def _fake_get_factory(player, files):
    def fake_get(url, *, data=None, headers=None, timeout=15):
        if "youtubei/v1/player" in url:
            return json.dumps(player).encode()
        if url in files:
            v = files[url]
            if isinstance(v, Exception):
                raise v
            return v.encode()
        raise youtube.FetchError(f"HTTP 404 fetching {url}")
    return fake_get


def test_youtube_end_to_end_with_fake_network(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    player = {
        "videoDetails": {"title": "ChatGPT AI Trading Bot makes 2 ETH a day (passive income)", "author": "CryptoGains",
                         "shortDescription": "Code: https://pastebin.com/Xy12Ab34\nRemix: https://remix.ethereum.org"},
        "captions": {"playerCaptionsTracklistRenderer": {"captionTracks": [
            {"baseUrl": "https://www.youtube.com/api/timedtext?v=1", "languageCode": "en", "kind": "asr"}]}},
    }
    transcript = ('<?xml version="1.0"?><timedtext><body><p t="0">open remix and paste the code then deploy it</p>'
                  '<p t="5">now fund the contract, I recommend at least 0.5 eth because of gas fees</p>'
                  '<p t="9">then press start and watch the profits</p></body></timedtext>')
    files = {"https://www.youtube.com/api/timedtext?v=1": transcript,
             "https://pastebin.com/raw/Xy12Ab34": load("scam_mempool_template.sol")}
    r = check("https://youtu.be/AbCdEfGhIjK", get=_fake_get_factory(player, files))
    assert r["input_type"] == "youtube"
    assert r["verdict"]["level"] == "SCAM"
    assert r["video"]["code_links"] == ["https://pastebin.com/Xy12Ab34"]
    assert r["video"]["transcript_source"] == "en (auto)"
    nr = {n["rule_id"] for n in r["narrative_flags"]}
    assert {"REMIX_DEPLOY_FUND_START", "MIN_BALANCE_PRESSURE", "PROFIT_PROMISE", "AI_HYPE"} <= nr
    # remix.ethereum.org is not a code host, so it's never fetched
    assert "https://remix.ethereum.org" in r["video"]["other_links"]


def test_youtube_without_code_uses_narrative_only(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    player = {"videoDetails": {"title": "MEV bot tutorial", "author": "x",
                               "shortDescription": "Open Remix, deploy, fund with at least 1 ETH, then click start. "
                                                   "Earn 3 ETH per day guaranteed. Code in my telegram."}}
    r = check("https://www.youtube.com/watch?v=AbCdEfGhIjK", get=_fake_get_factory(player, {}))
    assert r["verdict"]["level"] == "HIGH_RISK"
    assert r["verdict"]["trades"] == "unknown"
    assert any("No code link" in e for e in r["errors"])


def test_youtube_fetch_failure_is_reported_not_raised(monkeypatch):
    def boom(url, **k):
        raise youtube.FetchError("network error fetching x: blocked")
    r = check("https://youtu.be/AbCdEfGhIjK", use_llm=False, get=boom)
    assert r["verdict"]["level"] == "INCONCLUSIVE"
    assert r["errors"]


# ---------------------------------------------------------------- corpus regression
#
# realworld/: scam contracts collected from public gists/pastebins/GitHub that
#   security researchers (SentinelLABS, StackOverflow, Remix issue tracker)
#   identified as YouTube "MEV bot" drainers. Kept verbatim.
# legit_realworld/: unmodified sources from Uniswap, OpenZeppelin, Aave, WETH9.

REALWORLD = Path(__file__).parent / "realworld"
LEGIT = Path(__file__).parent / "legit_realworld"


@pytest.mark.parametrize("path", sorted(REALWORLD.glob("*.sol")), ids=lambda p: p.name)
def test_realworld_scams_detected(path):
    a = analyze_solidity(path.read_text())
    v = compute_verdict(a)
    assert v.level == "SCAM", [f.title for f in a.findings]
    assert v.trades == "no", a.swap_calls


@pytest.mark.parametrize("path", sorted(LEGIT.glob("*.sol")), ids=lambda p: p.name)
def test_legit_contracts_have_no_red_flags(path):
    a = analyze_solidity(path.read_text())
    v = compute_verdict(a)
    assert v.level == "NO_RED_FLAGS", [(f.severity, f.title) for f in a.findings]


def test_corpus_is_present():
    assert len(list(REALWORLD.glob("*.sol"))) >= 6
    assert len(list(LEGIT.glob("*.sol"))) >= 7


def test_external_recipient_from_remote_import_is_scam():
    a = analyze_solidity(load_rw("gist_vanclief_1200day.sol"))
    assert {s.recipient_class for s in a.sinks} == {"external_code"}
    assert any(f.rule_id == "FUNDS_TO_EXTERNAL_DECIDED_ADDRESS" and f.severity == "critical" for f in a.findings)


def test_xor_obfuscation_and_dead_trading_code():
    a = analyze_solidity(load_rw("pastebin_sentinel_todd_8Yar7QyU.sol"))
    r = rules(a)
    assert "DEAD_TRADING_CODE" in r  # real swap() code exists, but nothing public calls it
    assert any("XOR" in f.title for f in a.findings if f.rule_id == "ADDRESS_OBFUSCATION")
    assert a.dead_swap_calls and not a.swap_calls


def test_carrier_string_variant():
    a = analyze_solidity(load("scam_carrier_string.sol"))
    assert compute_verdict(a).level == "SCAM"
    assert {s.function for s in a.sinks if s.recipient_class == "obfuscated"} == {"start", "withdraw"}


def test_getter_with_swap_substring_is_not_a_trade():
    src = """pragma solidity ^0.8.0;
    contract Bot { M m; function start() public { payable(m.uniswapDepositAddress()).transfer(address(this).balance); } }"""
    assert analyze_solidity(src).swap_calls == []


def load_rw(name):
    return (REALWORLD / name).read_text()



def test_llm_http_error_is_explained_without_leaking_key(monkeypatch):
    import io, urllib.error
    import scamcheck.explain as ex
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SCAMCHECK_PROVIDER"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-SECRETSECRET")
    def boom(req, timeout=60):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {},
                                     io.BytesIO(b'{"error":{"message":"No auth credentials found"}}'))
    monkeypatch.setattr(ex.urllib.request, "urlopen", boom)
    r = check(load("scam_split_string.sol"))
    note = r["explanation"]["note"]
    assert "HTTP 401" in note and "openrouter" in note and "No auth credentials" in note
    assert "SECRET" not in note and r["verdict"]["level"] == "SCAM"


def test_provider_pin_overrides_priority(monkeypatch):
    from scamcheck.explain import provider_config
    monkeypatch.setenv("ANTHROPIC_API_KEY", "a")
    monkeypatch.setenv("OPENROUTER_API_KEY", "b")
    monkeypatch.delenv("SCAMCHECK_PROVIDER", raising=False)
    assert provider_config()["name"] == "anthropic"
    monkeypatch.setenv("SCAMCHECK_PROVIDER", "openrouter")
    assert provider_config()["name"] == "openrouter"
