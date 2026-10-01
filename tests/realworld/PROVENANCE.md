# Real-world scam corpus: provenance

Every file here is **verbatim** malicious Solidity collected from public sources
for regression testing. **Never deploy any of them.** Each one sends deposited
funds to an attacker.

| File | Source | Identified by |
|---|---|---|
| `gist_vanclief_1200day.sol` | https://gist.github.com/Vanclief/e0df5df955a9bc0e3700c8d5750ca1ee | Gist titled 'Code from scam "How To Make $1200/DAY On Uniswap"'; recipient comes from a remote-import `Manager` contract |
| `gist_netanelben_pancake.sol` | https://gist.github.com/netanelben/b4d54eb3cb67dd0c110e91099320e91f | PancakeSwap variant of the mempool template |
| `gist_namesavvy.sol` | https://gist.github.com/namesavvy/a920c02d3f6c460d5081a42d854ffa05 | Template variant with Start/Stop/withdrawal all draining |
| `pastebin_kcDR4Mkx.sol` | https://pastebin.com/kcDR4Mkx | Classic 0.6.6 "UniswapFrontrunBot" template |
| `pastebin_sentinel_todd_8Yar7QyU.sol` | https://pastebin.com/raw/8Yar7QyU | SentinelLABS IOC (ToddTutorials video, 2025): XOR-obfuscated recipient and real-but-unreachable swap code |
| `github_shbhmantil_mev.sol` | https://github.com/shbhmantil/be-aware-of-scams/blob/main/MEV-Bot-Scam.sol | Repo documenting the scam |
| `github_walbertmike_mewbot_yt_myHKJk1t7rc.sol` | https://github.com/Walbertmike/mewbot/blob/main/bot.sol | Fetched live by this tool from the description of YouTube video `myHKJk1t7rc` ("Building a Crypto Trading Bot with ChatGPT", 2025-10-01) |
| `pastebin_gW0GG449_yt_q9b0ZG4gICw.sol` | https://pastebin.com/raw/gW0GG449 | Fetched live by this tool from YouTube video `q9b0ZG4gICw` ("How to Create Passive Income MEV Bot on Ethereum", same "Jane" script SentinelLABS tied to the Jazz_Braze campaign) |

`../legit_realworld/` holds unmodified Uniswap V2, OpenZeppelin, Aave V3 and
WETH9 sources, used as a false-positive control set.
