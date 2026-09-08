# Agent Tank submission — copy/paste sheet

Form: https://portal.genlayer.foundation/agent-tank/hackathon/submit
(fields below match the form order; respect the character limits)

---

## 00 Track
Autonomous Protocols

## 01 GitHub repository
https://github.com/Misagh95/sentinel

## Project name
Sentinel

## 02 One-liner (max 180 chars)
An Intelligent Contract that guards other contracts: it reads exploit evidence, checks live state, and pauses or throttles the target by validator consensus — no multisig, no vote.

(178 chars)

## 03 Description (max 1000 chars)
DeFi loses billions to exploits, and the real problem is reaction time: a drain takes minutes, a human multisig takes hours.

Sentinel is an autonomous circuit breaker built as a GenLayer Intelligent Contract. A protocol registers a natural-language security policy for any contract that exposes a small guardian interface (pause / unpause / set limit / get_status).

Two layers of defence:
1) Deterministic tripwire — anyone can call check_health(); hard numeric limits (e.g. max drawdown) trigger an instant pause with no LLM.
2) Evidence-based judgment — anyone stakes GEN and reports an incident with a URL (tx trace, advisory, monitoring dashboard). Validators fetch the evidence, read the target's live state, and reach consensus on {pause | throttle | none}. Correct reports earn a bounty; spam gets slashed.

Every verdict is stored on-chain with evidence link, confidence and reasoning — a public, auditable incident log. Only possible on GenLayer: web access + LLM judgment + Equivalence Principle + cross-contract emit.

(≈990 chars)

## 04 Demo video
https://www.youtube.com/watch?v=<YOUR_VIDEO_ID>

## 05 How-to (steps)

Step 1 — Install
    git clone https://github.com/Misagh95/sentinel && cd sentinel
    pip install -r requirements.txt

Step 2 — Lint with the official GenVM linter
    genvm-lint check contracts/sentinel.py
    genvm-lint check contracts/vault.py
    → "Lint passed / Validation passed" for both

Step 3 — Run the test-suite
    pytest -q
    → 20 passed (tripwire, LLM verdicts, slashing, validator consensus, recovery)

Step 4 — Run the end-to-end demo (offline, deterministic)
    python scripts/demo.py
    → scene 2: attacker drains 20% via unprotected migrate_liquidity()
    → scene 3: watcher reports with evidence, verdict = PAUSE, validator AGREE
    → scene 4: vault is PAUSED, second drain reverts, reporter rewarded
    → scene 5: FUD report → NONE, stake slashed

Step 5 — (optional) Same demo with a real LLM
    OPENAI_API_KEY=sk-... python scripts/demo.py --live

Step 6 — (optional) Deploy to a network and open the dashboard
    export ACCOUNT_PRIVATE_KEY=0x...
    python scripts/deploy.py --network testnet_asimov
    open docs/index.html?rpc=<RPC>&sentinel=<ADDR>&vault=<ADDR>

## 06 Review verification (max 500 chars, private)
On Bradbury: read vault 0xa1e6…4865 get_status() → guardian=0x565a…3667 (Sentinel). Tx 0xf06e…f134 = attacker drain 4000 (40%). Tx 0x3f75…768f = check_health → Sentinel emitted pause(); child tx 0x6950…88ef paused the vault. Tx 0xb253…6b78 = attacker's 2nd drain FINISHED_WITH_ERROR "vault paused". Sentinel list_incidents(vault) → #0 tripwire sev 5. Locally: `pytest -q` → 20 passed; `python scripts/demo.py` shows full LLM path.

(≈480 chars)

## Contract links
Sentinel:     https://explorer-bradbury.genlayer.com/address/0x565a86900585395ad328A6a507E3f3D9c3dd3667
GuardedVault: https://explorer-bradbury.genlayer.com/address/0xa1e63b959cE47f24f3c0C178fA4a51766a304865

## 07 Project links
Website (required): https://Misagh95.github.io/sentinel/   (GitHub Pages serving docs/index.html)
    — or the GitHub repo URL if you don't set up Pages
GitHub: https://github.com/Misagh95/sentinel
