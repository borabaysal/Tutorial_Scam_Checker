"""Static analysis of Solidity source for "trading bot" scam patterns.

This is deliberately a lightweight, dependency-free *heuristic* analyser, not a
compiler. It works on source text (comments stripped, string contents masked)
and answers two questions a retail user actually cares about:

1. Where can ETH / tokens held by this contract go?  (fund-flow sinks and who
   receives them: the caller, the deployer, a hardcoded address, or an address
   reconstructed from obfuscated strings/numbers)
2. Does the contract actually trade?  (call sites to DEX swap / flash-loan
   functions, as opposed to interfaces that are declared but never called)

Static checks can prove the *presence* of red flags; they can never prove a
contract is safe. The verdict layer reflects that asymmetry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# Well-known protocol addresses (lower-case). A literal pointing here is
# expected in genuine DEX code and is not, by itself, a red flag.
KNOWN_PROTOCOL_ADDRESSES: dict[str, str] = {
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router02 (Ethereum)",
    "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f": "Uniswap V2 Factory (Ethereum)",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 SwapRouter02",
    "0x1f98431c8ad98523631ae4a59f267346ea31f984": "Uniswap V3 Factory",
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH (Ethereum)",
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2 Router (BSC)",
    "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router (Ethereum)",
    "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "WBNB (BSC)",
    "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2": "Aave V3 Pool (Ethereum)",
    "0xba12222222228d8ba445958a75a0704d566bf2c8": "Balancer V2 Vault",
    "0x0000000000000000000000000000000000000000": "zero address",
    "0x000000000000000000000000000000000000dead": "burn address",
}

# Function names lifted from the widely-circulated YouTube "MEV / front-running
# bot" scam template and its forks. They exist to look technical while
# reassembling the scammer's address from fragments.
SCAM_TEMPLATE_FINGERPRINTS = {
    "parsememorypool", "callmempool", "checkliquidity", "getmempooloffset",
    "getmempoollength", "getmempoolheight", "getmempooldepth", "getmempoolshort",
    "getmempoollong", "startexploration", "findnewcontracts", "loadcurrentcontract",
    "nextcontract", "ordercontractsbyliquidity", "fetchmempooldata",
    "fetchmempoolversion", "fetchmempooledition", "mempool", "callfrontrunactionmempool",
    "getpairhexprefix", "findcontracts", "beginexploration",
}

# Words that indicate the code is being *sold as a profit bot*. Kept narrow on
# purpose: generic DeFi words ("trade", "liquidity", "flash loan") appear in
# honest infrastructure such as WETH9 or Aave base contracts.
TRADING_CLAIM_WORDS = re.compile(
    r"\b(arbitrage|arb|front[-_ ]?run\w*|frontrun\w*|sandwich|mev|snip(e|er|ing)|"
    r"mempool|profit(s|able)?|trading ?bot|bot|start ?trading)\b",
    re.IGNORECASE,
)

# A real swap / flash-loan *call site*: `<expr>.swapExactETHForTokens(` etc.
# Method names must *start* with a trading verb or contain a camel-case
# "Swap" token followed by a direction ("tokenToEthSwapInput", Uniswap V1).
# A bare substring match would accept "uniswapDepositAddress()", a getter that
# real scams use to fetch the scammer's address.
SWAP_CALL_RE = re.compile(
    r"\.\s*(swap\w*|\w+Swap(?:Input|Output)\w*|exactInput\w*|exactOutput\w*|flashLoan\w*|flash|"
    r"multicall|addLiquidity\w*|removeLiquidity\w*)\s*[({]"
)
# Low-level calls that encode a swap selector explicitly.
SWAP_ENCODED_RE = re.compile(
    r"abi\.encode(?:WithSignature|WithSelector|Call)\s*\(\s*[\"']?[^,)]*?"
    r"(swap|exactInput|exactOutput|flashLoan)",
    re.IGNORECASE,
)

ADDRESS_LITERAL_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
HEX_FRAGMENT_RE = re.compile(r"^(0x)?[0-9a-fA-F]{3,40}$")

PROMPT_INJECTION_RE = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|rules)|"
    r"\b(ai|llm|gpt|chatgpt|claude|assistant|auditor|scanner)\b.{0,60}\b(safe|legit|"
    r"not a scam|no issues|verified)\b|this (contract|code) is (100% )?(safe|audited|legit))",
    re.IGNORECASE,
)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    line: int | None = None
    evidence: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Function:
    name: str
    kind: str  # function | constructor | receive | fallback
    header: str
    body: str
    start: int  # offset of body '{' in the clean source
    line: int
    container: str
    container_kind: str  # contract | interface | library | abstract
    params: list[str] = field(default_factory=list)

    @property
    def is_declaration_only(self) -> bool:
        return self.body == ""

    @property
    def returns_address(self) -> bool:
        m = re.search(r"\breturns\s*\(([^)]*)\)", self.header)
        return bool(m and re.search(r"\baddress\b", m.group(1)))


@dataclass
class Sink:
    """A place where value leaves the contract."""

    kind: str  # eth_transfer | eth_send | eth_call | token_transfer | selfdestruct | delegatecall
    function: str
    line: int
    recipient_expr: str
    recipient_class: str
    amount_expr: str
    sweeps_balance: bool
    snippet: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Analysis:
    findings: list[Finding]
    sinks: list[Sink]
    swap_calls: list[dict]
    dead_swap_calls: list[dict]
    contracts: list[str]
    functions: list[str]
    claims_trading: bool
    address_literals: list[dict]

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "sinks": [s.to_dict() for s in self.sinks],
            "swap_calls": self.swap_calls,
            "dead_swap_calls": self.dead_swap_calls,
            "contracts": self.contracts,
            "functions": self.functions,
            "claims_trading": self.claims_trading,
            "address_literals": self.address_literals,
        }


# --------------------------------------------------------------------------
# Source preprocessing
# --------------------------------------------------------------------------


def split_comments(src: str) -> tuple[str, str, list[tuple[int, str]]]:
    """Return (code_without_comments, code_with_strings_masked, comments).

    Both returned strings have exactly the same length and line layout as
    ``src`` so offsets and line numbers stay valid across all three views.
    """
    out: list[str] = []
    masked: list[str] = []
    comments: list[tuple[int, str]] = []
    i, n, line = 0, len(src), 1
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            comments.append((line, src[i + 2 : j].strip()))
            pad = " " * (j - i)
            out.append(pad)
            masked.append(pad)
            i = j
            continue
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            chunk = src[i:j]
            comments.append((line, chunk.strip("/* \n\t")))
            pad = "".join("\n" if ch == "\n" else " " for ch in chunk)
            out.append(pad)
            masked.append(pad)
            line += chunk.count("\n")
            i = j
            continue
        if c in ('"', "'"):
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            chunk = src[i:j]
            out.append(chunk)
            # keep the quotes, blank the contents so braces/semicolons inside
            # strings cannot confuse the structural scanner
            masked.append(c + " " * max(0, len(chunk) - 2) + (c if len(chunk) > 1 else ""))
            i = j
            continue
        if c == "\n":
            line += 1
        out.append(c)
        masked.append(c)
        i += 1
    return "".join(out), "".join(masked), comments


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _match_close(text: str, open_idx: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == open_ch:
            depth += 1
        elif text[k] == close_ch:
            depth -= 1
            if depth == 0:
                return k
    return len(text) - 1


CONTAINER_RE = re.compile(r"\b(abstract\s+contract|contract|interface|library)\s+(\w+)[^{;]*\{")
FUNC_RE = re.compile(r"\b(?:function\s+(\w+)|(constructor)|(receive)|(fallback))\s*\(")


def extract_structure(clean: str, masked: str) -> tuple[list[tuple[str, str, int, int]], list[Function]]:
    containers: list[tuple[str, str, int, int]] = []
    for m in CONTAINER_RE.finditer(masked):
        open_idx = m.end() - 1
        close = _match_close(masked, open_idx, "{", "}")
        kind = "abstract" if m.group(1).startswith("abstract") else m.group(1)
        containers.append((m.group(2), kind, open_idx, close))

    def container_at(off: int) -> tuple[str, str]:
        best = ("<file>", "contract", -1)
        for name, kind, s, e in containers:
            if s <= off <= e and s > best[2]:
                best = (name, kind, s)
        return best[0], best[1]

    functions: list[Function] = []
    for m in FUNC_RE.finditer(masked):
        name = m.group(1) or m.group(2) or m.group(3) or m.group(4)
        kind = "function" if m.group(1) else name
        paren_open = m.end() - 1
        paren_close = _match_close(masked, paren_open, "(", ")")
        # header runs until the first '{' or ';' at paren-depth 0
        k = paren_close + 1
        depth = 0
        while k < len(masked):
            ch = masked[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0 and ch in "{;":
                break
            k += 1
        header = clean[m.start() : k]
        params_src = clean[paren_open + 1 : paren_close]
        params = [p.strip().split()[-1] for p in params_src.split(",") if len(p.strip().split()) > 1]
        body = ""
        if k < len(masked) and masked[k] == "{":
            end = _match_close(masked, k, "{", "}")
            body = clean[k : end + 1]
        cname, ckind = container_at(m.start())
        functions.append(
            Function(name, kind, header, body, k, line_of(clean, m.start()), cname, ckind, params)
        )
    return containers, functions


# --------------------------------------------------------------------------
# Expression helpers
# --------------------------------------------------------------------------


def receiver_before(text: str, dot_idx: int) -> str:
    """Walk backwards from a '.' to recover the receiver expression.

    Handles identifiers, member access, indexing and (nested) call/cast
    parentheses such as ``payable(address(uint160(x)))``.
    """
    k = dot_idx - 1
    while k >= 0 and text[k].isspace():
        k -= 1
    end = k + 1
    while k >= 0:
        ch = text[k]
        if ch in ")]":
            open_ch = "(" if ch == ")" else "["
            depth = 0
            while k >= 0:
                if text[k] == ch:
                    depth += 1
                elif text[k] == open_ch:
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            k -= 1
            continue
        if ch.isalnum() or ch in "_.$":
            k -= 1
            continue
        break
    return text[k + 1 : end].strip()


def call_args(text: str, open_paren: int) -> list[str]:
    close = _match_close(text, open_paren, "(", ")")
    inner = text[open_paren + 1 : close]
    args, depth, cur = [], 0, []
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def _unwrap(expr: str) -> str:
    expr = expr.strip()
    while True:
        m = re.fullmatch(r"(?:payable|address)\s*\((.*)\)", expr, re.DOTALL)
        if not m:
            return expr
        expr = m.group(1).strip()


TRUSTED_IMPORT_RE = re.compile(
    r"^(https://)?github\.com/(OpenZeppelin|Uniswap|aave|balancer-labs|smartcontractkit)/[^/]+/blob/", re.I)


def _trusted_import(path: str) -> bool:
    return bool(TRUSTED_IMPORT_RE.match(path))


def _hex_fragments(text: str) -> list[str]:
    frags = []
    for a, b in re.findall(r"\"([^\"\n]*)\"|'([^'\n]*)'", text):
        v = a or b
        if v and HEX_FRAGMENT_RE.match(v) and (re.search(r"[a-fA-F]", v) or v.startswith("0x")):
            frags.append(v)
    return frags


# --------------------------------------------------------------------------
# Analyser
# --------------------------------------------------------------------------


class SolidityAnalyzer:
    def __init__(self, source: str):
        self.source = source
        self.clean, self.masked, self.comments = split_comments(source)
        self.containers, self.functions = extract_structure(self.clean, self.masked)
        self.fn_by_name: dict[str, list[Function]] = {}
        for f in self.functions:
            self.fn_by_name.setdefault(f.name, []).append(f)
        self.findings: list[Finding] = []
        self.obfuscators = self._find_obfuscators()
        self.untrusted_imports = [
            p for p in re.findall(r"\bimport\s+[^;]*?[\"']([^\"']+)[\"']", self.clean)
            if re.match(r"https?://|ipfs://|github\.com/|raw\.githubusercontent", p, re.I) and not _trusted_import(p)
        ]
        self.reachable = self._reachable_functions()

    # -- call graph --------------------------------------------------------

    def _is_entrypoint(self, f: Function) -> bool:
        if f.kind in ("constructor", "receive", "fallback"):
            return True
        # Pre-0.5 Solidity defaults to public when no visibility is given.
        return not re.search(r"\b(internal|private)\b", f.header)

    def _reachable_functions(self) -> set[str]:
        """Names of implemented functions reachable from an externally callable entry point.

        Internal calls are matched by bare name (``foo(`` not preceded by ``.``),
        which over-approximates across overloads; that is the safe direction for
        "is this trading code ever executed?". Modifiers are not followed.
        """
        impl = self._implemented()
        names = {f.name for f in impl}
        edges: dict[str, set[str]] = {}
        for f in impl:
            mbody = self.masked[f.start : f.start + len(f.body)]
            called = {m.group(1) for m in re.finditer(r"(?<![.\w])([A-Za-z_]\w*)\s*\(", mbody)} & names
            edges.setdefault(f.name, set()).update(called - {f.name})
        seen = {f.name for f in impl if self._is_entrypoint(f)}
        stack = list(seen)
        while stack:
            for g in edges.get(stack.pop(), ()):
                if g not in seen:
                    seen.add(g)
                    stack.append(g)
        return seen

    # -- helpers ---------------------------------------------------------

    def _add(self, rule_id, severity, title, detail, line=None, evidence=""):
        self.findings.append(Finding(rule_id, severity, title, detail, line, evidence.strip()[:300]))

    def _snippet(self, line: int) -> str:
        lines = self.source.splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    def _implemented(self) -> list[Function]:
        return [f for f in self.functions if not f.is_declaration_only and f.container_kind != "interface"]

    def _find_obfuscators(self) -> dict[str, str]:
        """Functions that turn strings/numbers into addresses or hex text."""
        result: dict[str, str] = {}
        for f in self._implemented():
            b = f.body
            reason = None
            char_math = bool(
                re.search(r"bytes\s*\(\s*\w+\s*\)\s*\[|\bb\d*\s*\[", b)
                and re.search(r"\b(48|55|57|65|70|87|97|102)\b|0x30|0x61", b)
            )
            hex_out = bool(re.search(r"%\s*16\b|>>\s*4\b", b) and re.search(r"\b(48|55|87)\b|0123456789abcdef|0x30", b, re.I))
            if f.returns_address and re.search(r"\buint160\s*\(.*(\^|\bxor\b|<<|>>|~)", b, re.S):
                reason = "derives an address with XOR/bit-shifting of hidden constants"
            elif f.returns_address and (char_math or (re.search(r"\buint160\b", b) and "string" in f.header)):
                reason = "converts a string into an address character by character"
            elif f.returns_address and re.search(r"\b(parseAddr|toAddress|fromHex)\w*\s*\(", b):
                reason = "returns an address produced by a string-parsing helper"
            elif char_math and re.search(r"\buint160\b|\*=\s*(16|256)", b):
                reason = "assembles an integer/address from hex characters"
            elif hex_out:
                reason = "converts numbers into hex text (used to rebuild an address from fragments)"
            elif re.search(r"\breturns\s*\(\s*string", f.header) and len(_hex_fragments(b)) >= 2:
                reason = "returns hard-coded hex fragments"
            elif "string" in f.header and re.search(r"abi\.encodePacked|string\.concat", b) and (
                len(_hex_fragments(b)) >= 2 or f.name.lower() in SCAM_TEMPLATE_FINGERPRINTS
            ):
                reason = "concatenates hex fragments into a string"
            if reason:
                result[f.name] = reason
        # Propagate: a function that calls an obfuscator and returns an address
        # (or the concatenated string) is also an obfuscator.
        changed = True
        while changed:
            changed = False
            for f in self._implemented():
                if f.name in result:
                    continue
                calls_obf = any(re.search(rf"\b{re.escape(o)}\s*\(", f.body) for o in result)
                if calls_obf and (f.returns_address or re.search(r"\breturns\s*\(\s*string", f.header)):
                    result[f.name] = "returns an address derived from obfuscated data"
                    changed = True
        return result

    # -- recipient classification --------------------------------------

    def _assignments(self, ident: str) -> list[tuple[str, int]]:
        out = []
        decl = re.compile(
            rf"\baddress(?:\s+payable)?(?:\s+(?:public|private|internal|constant|immutable))*\s+{re.escape(ident)}\s*=\s*([^;]+);"
        )
        assign = re.compile(rf"(?<![\w.]){re.escape(ident)}\s*=(?!=)\s*([^;]+);")
        seen = set()
        for rx in (decl, assign):
            for m in rx.finditer(self.clean):
                if m.start(1) not in seen:
                    seen.add(m.start(1))
                    out.append((m.group(1).strip(), m.start()))
        return out

    def _func_at(self, offset: int) -> Function | None:
        best = None
        for f in self.functions:
            if f.body and f.start <= offset <= f.start + len(f.body):
                if best is None or f.start > best.start:
                    best = f
        return best

    def classify(self, expr: str, depth: int = 0, fn: Function | None = None) -> str:
        """Classify where a recipient expression points.

        Returns one of: caller, deployer, hardcoded, known_protocol,
        obfuscated, external_code, tx_origin, parameter, unknown.
        """
        e = _unwrap(expr)
        if re.search(r"\bmsg\.sender\b|_msgSender\s*\(", e):
            return "caller"
        if re.search(r"\btx\.origin\b", e):
            return "tx_origin"
        lit = ADDRESS_LITERAL_RE.search(e)
        if lit:
            return "known_protocol" if lit.group(0).lower() in KNOWN_PROTOCOL_ADDRESSES else "hardcoded"
        for o in self.obfuscators:
            if re.search(rf"\b{re.escape(o)}\s*\(", e):
                return "obfuscated"
        if re.search(r"\b(uint160|bytes20)\s*\(\s*(uint256\s*\(\s*)?(0x[0-9a-fA-F]{8,}|\d{10,})", e):
            return "hardcoded"
        if re.fullmatch(r"0x[0-9a-fA-F]{8,}|\d{20,}", e):
            return "hardcoded"
        if depth > 5:
            return "unknown"
        if re.fullmatch(r"[A-Za-z_]\w*", e):
            if fn and e in fn.params:
                return "parameter"
            classes = []
            for rhs, off in self._assignments(e):
                where = self._func_at(off)
                cls = self.classify(rhs, depth + 1, where)
                # msg.sender captured at deploy time (constructor or state
                # initialiser) is the deployer, not whoever calls later.
                if cls == "caller" and (where is None or where.kind == "constructor"):
                    cls = "deployer"
                classes.append(cls)
            for bad in ("obfuscated", "hardcoded", "tx_origin"):
                if bad in classes:
                    return bad
            if classes and all(c in ("deployer", "caller") for c in classes):
                return "deployer" if "deployer" in classes else "caller"
            if classes:
                return classes[0]
        # `manager.depositAddress()` / `IThing(x).getRouter()`: the recipient is
        # decided by code that is not in this file (often a remote import).
        if re.fullmatch(r"[A-Za-z_][\w.]*(\([^()]*\))?\s*\.\s*[A-Za-z_]\w*\s*\(.*\)", e, re.S) and not re.match(r"(abi|msg|block|tx)\.", e):
            return "external_code"
        call = re.match(r"([A-Za-z_]\w*)\s*\(", e)
        if call and call.group(1) in self.fn_by_name:
            for f in self.fn_by_name[call.group(1)]:
                for r in re.finditer(r"\breturn\s+([^;]+);", f.body):
                    cls = self.classify(r.group(1), depth + 1, f)
                    if cls != "unknown":
                        return cls
        return "unknown"

    # -- sink discovery --------------------------------------------------

    def find_sinks(self) -> list[Sink]:
        sinks: list[Sink] = []
        patterns = [
            (r"\.\s*transfer\s*\(", "transfer"),
            (r"\.\s*send\s*\(", "eth_send"),
            (r"\.\s*call\s*\{[^}]*value\s*:", "eth_call"),
            (r"\.\s*call\.value\s*\(", "eth_call_legacy"),
            (r"\.\s*transferFrom\s*\(", "token_transfer_from"),
            (r"\.\s*safeTransfer\s*\(", "safe_transfer"),
            (r"\.\s*delegatecall\s*\(", "delegatecall"),
        ]
        for f in self._implemented():
            base = f.start
            mbody = self.masked[base : base + len(f.body)]
            cbody = f.body
            for rx, kind in patterns:
                for m in re.finditer(rx, mbody):
                    dot = m.start()
                    recv = receiver_before(cbody, dot)
                    kind_out, recipient, amount = self._decode_sink(kind, recv, mbody, cbody, m.start())
                    line = line_of(self.clean, base + dot)
                    sweeps = bool(
                        re.search(r"address\s*\(\s*this\s*\)\s*\.balance|\bselfbalance\b|balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", amount)
                        or (amount and self._var_is_balance(amount, cbody))
                    )
                    sinks.append(
                        Sink(kind_out, f.name, line, recipient, self.classify(recipient, fn=f), amount, sweeps, self._snippet(line))
                    )
            for m in re.finditer(r"\b(selfdestruct|suicide)\s*\(", mbody):
                args = call_args(cbody, m.end() - 1)
                recipient = args[0] if args else ""
                line = line_of(self.clean, base + m.start())
                sinks.append(Sink("selfdestruct", f.name, line, recipient, self.classify(recipient, fn=f), "entire balance", True, self._snippet(line)))
        return sinks

    @staticmethod
    def _decode_sink(kind: str, recv: str, mbody: str, cbody: str, at: int) -> tuple[str, str, str]:
        """Return (normalised_kind, recipient_expr, amount_expr) for one sink match."""
        if kind == "eth_call":
            brace = mbody.find("{", at)
            close = _match_close(mbody, brace, "{", "}")
            vm = re.search(r"value\s*:\s*([^,}]+)", cbody[brace : close + 1])
            return "eth_call", recv, (vm.group(1).strip() if vm else "")
        args = call_args(cbody, mbody.find("(", at))
        if kind == "transfer":
            if len(args) >= 2:  # ERC20 token.transfer(to, amount)
                return "token_transfer", args[0], args[1]
            return "eth_transfer", recv, (args[0] if args else "")
        if kind == "safe_transfer":
            return ("token_transfer", args[0], args[1]) if len(args) >= 2 else ("token_transfer", recv, "")
        if kind == "token_transfer_from":
            return ("token_transfer", args[1], args[2]) if len(args) >= 3 else ("token_transfer", "", "")
        if kind == "eth_call_legacy":
            return "eth_call", recv.rsplit(".call", 1)[0], (args[0] if args else "")
        if kind == "eth_send":
            return "eth_send", recv, (args[0] if args else "")
        return kind, recv, ""

    @staticmethod
    def _var_is_balance(amount: str, body: str) -> bool:
        ident = amount.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", ident):
            return False
        return bool(re.search(rf"\b{re.escape(ident)}\s*=\s*address\s*\(\s*this\s*\)\s*\.balance", body))

    # -- swap discovery --------------------------------------------------

    def find_swap_calls(self) -> tuple[list[dict], list[dict]]:
        """Return (reachable_calls, dead_calls).

        Scam contracts often contain real-looking swap code inside internal
        functions that nothing ever calls. Only calls reachable from a public
        entry point count as "trades".
        """
        calls = []
        for f in self._implemented():
            mbody = self.masked[f.start : f.start + len(f.body)]
            for m in SWAP_CALL_RE.finditer(mbody):
                recv = receiver_before(f.body, m.start())
                if not recv or recv in ("this", "super"):
                    continue
                calls.append({"function": f.name, "method": m.group(1), "target": recv,
                              "line": line_of(self.clean, f.start + m.start())})
            for m in SWAP_ENCODED_RE.finditer(f.body):
                calls.append({"function": f.name, "method": m.group(1), "target": "<low-level call>",
                              "line": line_of(self.clean, f.start + m.start())})
        live = [c for c in calls if c["function"] in self.reachable]
        dead = [c for c in calls if c["function"] not in self.reachable]
        return live, dead

    # -- rules -------------------------------------------------------------

    def run(self) -> Analysis:
        sinks = self.find_sinks()
        swaps, dead_swaps = self.find_swap_calls()
        identifiers = " ".join(f.name for f in self.functions) + " " + " ".join(c[0] for c in self.containers)
        identifiers = re.sub(r"([a-z])([A-Z])", r"\1 \2", identifiers)
        comment_text = " ".join(c for _, c in self.comments)
        claims_trading = bool(TRADING_CLAIM_WORDS.search(identifiers) or TRADING_CLAIM_WORDS.search(comment_text))

        if not self.functions:
            self._add("NO_SOLIDITY", "info", "No Solidity functions found",
                      "The input does not look like Solidity source code, so no contract checks ran.")
        else:
            self._rule_fund_flow(sinks)
            self._rule_trading(swaps, dead_swaps, claims_trading)
            self._rule_obfuscation()
            self._rule_fingerprints()
            self._rule_address_literals()
            self._rule_mempool_claim()
            self._rule_remote_imports()
            self._rule_prompt_injection()
            self._rule_tx_origin()

        self.findings.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.line or 0))
        literals = [
            {"address": m.group(0), "line": line_of(self.clean, m.start()),
             "label": KNOWN_PROTOCOL_ADDRESSES.get(m.group(0).lower())}
            for m in ADDRESS_LITERAL_RE.finditer(self.clean)
        ]
        return Analysis(
            findings=self.findings,
            sinks=sinks,
            swap_calls=swaps,
            dead_swap_calls=dead_swaps,
            contracts=[f"{k} {n}" for n, k, _, _ in self.containers],
            functions=[f"{f.container}.{f.name}" for f in self._implemented()],
            claims_trading=claims_trading,
            address_literals=literals,
        )

    def _rule_fund_flow(self, sinks: list[Sink]) -> None:
        flagged_fns: set[str] = set()
        for s in sinks:
            where = f"`{s.function}()` line {s.line}"
            what = "the entire balance" if s.sweeps_balance else "funds"
            if s.kind == "delegatecall":
                if s.recipient_class in ("hardcoded", "obfuscated", "unknown", "parameter"):
                    self._add("DELEGATECALL_EXTERNAL", "critical", "Delegatecall to outside code",
                              f"{where} hands full control of this contract (and its funds) to code at `{s.recipient_expr}`, "
                              "which you cannot see here.", s.line, s.snippet)
                continue
            if s.recipient_class == "obfuscated":
                self._add("FUNDS_TO_OBFUSCATED_ADDRESS", "critical",
                          "Funds sent to an address hidden behind string/number tricks",
                          f"{where} sends {what} to `{s.recipient_expr}`, an address the code rebuilds from fragments at "
                          "runtime. Legitimate bots have no reason to hide where money goes; this is the signature of the "
                          "YouTube 'MEV bot' scam.", s.line, s.snippet)
                flagged_fns.add(s.function)
            elif s.recipient_class == "hardcoded":
                self._add("FUNDS_TO_HARDCODED_ADDRESS", "critical" if s.sweeps_balance or s.kind == "selfdestruct" else "high",
                          "Funds sent to a hardcoded address",
                          f"{where} sends {what} to a fixed address written into the code, not to you. Whoever controls that "
                          "address gets the money.", s.line, s.snippet)
                flagged_fns.add(s.function)
            elif s.recipient_class == "external_code":
                # Paying an address returned by another contract is normal DeFi
                # plumbing (e.g. Router02 paying `pairFor(...)`). It becomes the
                # scam pattern when that other contract lives in a remote import
                # the author controls, and especially when the whole balance goes.
                untrusted = bool(self.untrusted_imports)
                sev = ("critical" if s.sweeps_balance else "high") if untrusted else ("medium" if s.sweeps_balance else "low")
                self._add("FUNDS_TO_EXTERNAL_DECIDED_ADDRESS", sev,
                          "Recipient address is decided by code you cannot see",
                          f"{where} sends {what} to `{s.recipient_expr}`. That address comes from another contract"
                          + (f" defined in a remote import (`{self.untrusted_imports[0]}`) that the author can change at any "
                             "time." if untrusted else ".")
                          + " This is a known trick to hide the scammer's address outside the pasted code.", s.line, s.snippet)
                if untrusted:
                    flagged_fns.add(s.function)
            elif s.recipient_class == "tx_origin":
                self._add("FUNDS_TO_TX_ORIGIN", "medium", "Funds sent to tx.origin",
                          f"{where} pays tx.origin, which is phishable and unusual in honest code.", s.line, s.snippet)
            elif s.recipient_class == "unknown" and s.sweeps_balance:
                self._add("BALANCE_SWEEP_UNRESOLVED", "high", "Entire balance sent to an address this checker could not resolve",
                          f"{where} sends the whole contract balance to `{s.recipient_expr}`. Verify by hand that this can only "
                          "be your wallet.", s.line, s.snippet)
            if s.kind == "selfdestruct" and s.recipient_class not in ("caller", "deployer"):
                self._add("SELFDESTRUCT_TO_OTHER", "critical", "Self-destruct pays someone other than you",
                          f"{where} destroys the contract and sends everything to `{s.recipient_expr}`.", s.line, s.snippet)

        # Entry points (public functions a user would press) that reach a bad sink.
        bad = set(flagged_fns)
        for f in self._implemented():
            if f.name in bad:
                continue
            if any(re.search(rf"\b{re.escape(b)}\s*\(", f.body) for b in flagged_fns):
                bad.add(f.name)
        for f in self._implemented():
            if f.name in bad and re.search(r"withdraw|start|action|run|execute|claim|refund|stop|go$", f.name, re.I) \
                    and not re.search(r"\b(private|internal)\b", f.header):
                self._add("MISLEADING_ENTRYPOINT", "critical", f"`{f.name}()` sends your money to someone else",
                          f"Calling `{f.name}()` moves funds to an address that is not yours. In these scams the victim "
                          f"deposits ETH and presses '{f.name}', which is exactly what drains them.", f.line, self._snippet(f.line))

    def _rule_trading(self, swaps: list[dict], dead: list[dict], claims_trading: bool) -> None:
        if dead:
            fns = sorted({c["function"] for c in dead})
            self._add("DEAD_TRADING_CODE", "high" if not swaps else "medium",
                      "Trading code exists but can never run",
                      f"Swap code in {', '.join(f'`{x}()`' for x in fns)} is never called from any function you can press. "
                      "It is there to make the contract look like a real bot.", dead[0]["line"], self._snippet(dead[0]["line"]))
        if swaps:
            return
        declared = [f for f in self.functions if f.is_declaration_only and re.match(r"(swap|exactInput|exactOutput|flashLoan)", f.name)]
        concrete = any(k == "contract" for _, k, _, _ in self.containers)
        if claims_trading and concrete:
            self._add("NO_TRADING_LOGIC", "high", "Claims to trade, but contains no reachable trading code",
                      "The code talks about trading/arbitrage/front-running, but there is not a single call to a DEX swap or "
                      "flash-loan function. Without such calls the contract physically cannot trade; any 'profit' shown in "
                      "the video is staged.")
        elif any(k == "contract" for _, k, _, _ in self.containers):
            # Not sold as a bot: absence of trading is information, not a risk.
            self._add("NO_TRADING_LOGIC", "info", "No trading logic found",
                      "No calls to DEX swap or flash-loan functions were found. If this was sold as a trading bot, it does not trade.")
        if declared:
            self._add("DECOY_INTERFACES", "medium", "Trading interfaces declared but never used",
                      f"Swap functions are declared ({', '.join(sorted({d.name for d in declared}))}) but never called. "
                      "Scam templates include these so the code looks like a real bot.", declared[0].line,
                      self._snippet(declared[0].line))

    def _rule_obfuscation(self) -> None:
        for name, reason in self.obfuscators.items():
            f = self.fn_by_name[name][0]
            self._add("ADDRESS_OBFUSCATION", "high", f"`{name}()` {reason}",
                      "Honest contracts store addresses plainly. Building them out of string or number fragments exists to "
                      "stop you (and block explorers) from seeing who receives the money.", f.line, self._snippet(f.line))
        frags = _hex_fragments(self.clean)
        if len(frags) >= 4 and not self.obfuscators:
            self._add("HEX_FRAGMENTS", "medium", f"{len(frags)} short hex-string fragments in the code",
                      "Scattered hex fragments are commonly concatenated into a hidden address.")

    def _rule_fingerprints(self) -> None:
        hits = sorted({f.name for f in self.functions if f.name.lower() in SCAM_TEMPLATE_FINGERPRINTS})
        if len(hits) >= 2:
            self._add("SCAM_TEMPLATE_MATCH", "high", "Matches a known scam template",
                      f"Function names {', '.join(hits)} come from a widely shared fake 'MEV/front-running bot' contract "
                      "that sends deposits to the scammer.", self.fn_by_name[hits[0]][0].line)

    def _rule_address_literals(self) -> None:
        for m in ADDRESS_LITERAL_RE.finditer(self.clean):
            a = m.group(0)
            if a.lower() in KNOWN_PROTOCOL_ADDRESSES:
                continue
            line = line_of(self.clean, m.start())
            if not any(f.line == line and f.rule_id.startswith("FUNDS_TO") for f in self.findings):
                self._add("HARDCODED_ADDRESS", "low", f"Unrecognised hardcoded address {a}",
                          "Not a known DEX/protocol address. Check what it is used for and look it up on a block explorer.",
                          line, self._snippet(line))

    def _rule_mempool_claim(self) -> None:
        text = (" ".join(f.name for f in self.functions) + " " + " ".join(c for _, c in self.comments)).lower()
        if "mempool" in text or "mem pool" in text or "memorypool" in text:
            self._add("IMPOSSIBLE_MEMPOOL_CLAIM", "high", "Claims to read the mempool from inside a contract",
                      "A smart contract cannot see pending transactions; it only runs when a transaction calls it. Real MEV "
                      "bots are off-chain programs. Code that 'scans the mempool' on-chain is theatre.")

    def _rule_remote_imports(self) -> None:
        for m in re.finditer(r"\bimport\s+[^;]*?[\"']([^\"']+)[\"']", self.clean):
            path = m.group(1)
            if re.match(r"https?://|ipfs://|github\.com/|raw\.githubusercontent", path, re.I):
                trusted = _trusted_import(path)
                line = line_of(self.clean, m.start())
                self._add("REMOTE_IMPORT", "medium" if trusted else "high",
                          "Imports code from a URL" + ("" if trusted else " you cannot audit here"),
                          f"`{path}` is pulled in at compile time. This checker cannot see it; scammers hide the payload in "
                          "imported files.", line, self._snippet(line))

    def _rule_prompt_injection(self) -> None:
        for line, text in self.comments:
            if PROMPT_INJECTION_RE.search(text):
                self._add("REVIEWER_MANIPULATION", "high", "Comment tries to convince reviewers/AI the code is safe",
                          "Honest code does not address AI tools or auditors. Treat this as an attempt to manipulate the review.",
                          line, text[:200])
                break

    def _rule_tx_origin(self) -> None:
        m = re.search(r"\btx\.origin\b", self.masked)
        if m:
            line = line_of(self.clean, m.start())
            if not any(f.line == line for f in self.findings):
                self._add("TX_ORIGIN", "low", "Uses tx.origin", "tx.origin-based logic is unsafe and rare in legitimate code.",
                          line, self._snippet(line))


def analyze_solidity(source: str) -> Analysis:
    return SolidityAnalyzer(source).run()
