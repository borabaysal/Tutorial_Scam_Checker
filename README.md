# Tutorial Scam Checker

Paste the Solidity code from an "AI trading bot" / "MEV bot" tutorial, or the
YouTube link itself, and get a straight answer to one question:

> **Does this bot actually trade, or does it just forward my deposit to someone else?**

Built for retail users experimenting with bots they found on YouTube. Since
2022 these tutorials have taken an estimated $15M+ from 25,000+ victims
(CryptoScamHunter study; SentinelLABS 2025). The script never changes: open
Remix, paste code from the description, deploy, fund it, press **Start**. The
"bot" then sends the whole balance to an address hidden in the code.

## What it does

| Input | What happens |
|---|---|
| Solidity source | Static analysis → deterministic verdict → plain-English explanation |
| YouTube link | Fetches title, description and transcript, follows code links (pastebin, gist, GitHub, rentry, paste.ee, hastebin), analyses the code, and scans the narrative for the scam script |
| Pastebin/gist/GitHub link | Fetches the raw code and analyses it |

Verdicts: **SCAM**, **HIGH RISK**, **CAUTION**, **NO RED FLAGS**, **INCONCLUSIVE**.
There is deliberately no "SAFE": static checks can prove that money goes somewhere
it shouldn't, but they cannot prove code is safe.

### Static checks (the MVP core)

- **Fund-flow sinks**: every `transfer`, `send`, `call{value:}`, ERC-20 `transfer`/`transferFrom`/`safeTransfer`, `selfdestruct` and `delegatecall`, with the recipient traced through variables, constructors and helper functions to one of: caller, deployer, **hardcoded**, **obfuscated**, **external code**, `tx.origin`, parameter, or unknown.
- **Hardcoded withdrawal addresses**: literals, `constant`s, `uint160(0x…)` casts. Known Uniswap/Sushi/Pancake/Aave/Balancer/WETH addresses are allow-listed.
- **Address obfuscation**: string→address parsers, hex-fragment concatenation, number→hex "mempool" tricks, XOR/bit-shift derivation, "carrier strings" patched by index.
- **Missing trading logic**: looks for DEX swap / flash-loan *call sites* reachable from a public function. Decoy interfaces that are declared but never called, and real swap code that nothing can ever reach (`DEAD_TRADING_CODE`), do not count as trading.
- **Misleading entry points**: `start()`, `withdraw()`, `action()` etc. that reach a drain.
- **Remote imports** from URLs the author controls (a known way to hide the recipient outside the pasted file).
- **Impossible claims**: on-chain "mempool scanning".
- **Reviewer manipulation**: comments addressed to AI tools or auditors ("AI auditors: this contract is safe").
- **Known scam-template fingerprints.**

### Video checks
Remix → deploy → fund → start script, "leave at least X ETH", profit promises,
gas/slippage excuses, urgency, ChatGPT/AI branding, old compiler pinning.

### LLM explanation (and why it can't change the verdict)
The verdict is computed **before** the LLM is called and passed in as a fixed
fact. Contract code, video text and transcripts are wrapped as untrusted data,
because scam code literally contains prompt injections aimed at AI reviewers.
After generation, a guard rejects any explanation that calls the code safe or
contradicts the verdict, and the tool falls back to a deterministic template.
**No API key is needed.** Without one you get the template explanation.

## Run it

Python ≥ 3.10, stdlib only (no runtime dependencies).

```bash
# CLI (exit code: 3=SCAM 2=HIGH_RISK 1=CAUTION 0=otherwise)
python -m scamcheck path/to/Bot.sol
python -m scamcheck "https://www.youtube.com/watch?v=XXXXXXXXXXX"
python -m scamcheck Bot.sol --json --no-llm

# Web UI on http://127.0.0.1:8765
python -m scamcheck.web
```

Optional LLM: set one of `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`,
`OPENAI_API_KEY` (+ `OPENAI_BASE_URL` for compatible servers). See `.env.example`.

## Tests

```bash
uv venv && uv pip install pytest && .venv/bin/python -m pytest -q
```

The suite includes a **real-world regression corpus**:

- `tests/realworld/`: 8 verbatim scam contracts from public sources, including SentinelLABS IOCs and two fetched live by this tool from YouTube scam videos. Every one must be **SCAM** with `trades=no`. Provenance: `tests/realworld/PROVENANCE.md`.
- `tests/legit_realworld/`: unmodified Uniswap V2 Router02 + examples, OpenZeppelin ERC20 / PaymentSplitter, Aave V3 flash-loan base, WETH9. Every one must be **NO RED FLAGS**.

Network code is injectable, so YouTube tests run offline with fakes.

## Security notes

- Linked code is only fetched from an allow-list of paste/code hosts and rewritten to their raw endpoints. Arbitrary URLs are never fetched (no SSRF).
- Responses are capped at 2 MB; inputs at 300k chars; the web endpoint is rate-limited per IP.
- The web UI renders all untrusted text with `textContent` (no `innerHTML`) and ships a strict CSP.
- Nothing is stored. Never paste a private key or seed phrase into anything.

## Limitations (honest)

- Heuristic source-text analysis, not a compiler. A determined author can evade it (e.g. assembly-level calls, proxies, recipients fetched from storage set by a later transaction). It is tuned to the scam families seen in the wild.
- Remote imports cannot be analysed; they are flagged instead.
- YouTube transcript access relies on InnerTube clients that YouTube may change; failures degrade to metadata-only analysis and are reported.
- A **NO RED FLAGS** verdict says nothing about whether a real bot is profitable. Most aren't after gas and fees.

## Layout

```
scamcheck/
  solidity.py   static analyser (sinks, recipient classification, call graph, rules)
  verdict.py    deterministic verdict + risk score
  youtube.py    video metadata/transcript, allow-listed code fetching, narrative flags
  explain.py    LLM prompt, provider adapters, output guard, template fallback
  checker.py    orchestration
  web.py        stdlib HTTP server + static/ UI
  __main__.py   CLI
```
