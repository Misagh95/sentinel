# 🛡 Sentinel — autonomous circuit breaker for smart contracts

> **Agent Tank Hackathon · Track: Autonomous Protocols**
> *"Systems that run themselves. If a contract pauses, tunes or rewrites another contract with no one voting, it belongs here."*

DeFi loses billions to exploits, and the real killer is **reaction time**: a drain takes minutes, a human multisig takes hours.
Sentinel is a GenLayer Intelligent Contract that **guards other contracts** and can **pause or throttle them on its own** —
no multisig, no governance vote, no human in the loop. Decisions are made by validator consensus over real evidence.

```
                     ┌──────────────────────────────────────────────┐
  anyone ──report──▶ │  Sentinel (Intelligent Contract)             │
  + stake + URL      │                                              │
                     │  1. tripwire: hard numeric limits (no LLM)   │──pause()────────┐
  keeper ─check────▶ │  2. judgment: fetch evidence ─▶ read target  │──throttle()───┐ │
                     │     live state ─▶ LLM verdict ─▶ consensus   │               ▼ ▼
                     │  3. economics: bounty / slash / audit trail  │      ┌────────────────┐
                     └──────────────────────────────────────────────┘      │ Guarded target │
                                                                           │ (any contract) │
                                                                           └────────────────┘
```

## 🟢 Live on GenLayer Testnet Bradbury

| Contract | Address |
|---|---|
| **Sentinel** | [`0x565a86900585395ad328A6a507E3f3D9c3dd3667`](https://explorer-bradbury.genlayer.com/address/0x565a86900585395ad328A6a507E3f3D9c3dd3667) |
| **GuardedVault** | [`0xa1e63b959cE47f24f3c0C178fA4a51766a304865`](https://explorer-bradbury.genlayer.com/address/0xa1e63b959cE47f24f3c0C178fA4a51766a304865) |

The full exploit → autonomous halt story, executed on the real testnet with real validator consensus (every link is verifiable in the explorer):

| # | What happened | Tx |
|---|---|---|
| 1 | `vault.set_guardian(sentinel)` — Sentinel becomes the guardian | [`0xef3e…ef1b`](https://explorer-bradbury.genlayer.com/tx/0xef3eb806f8c0423063f6624ab68974cb5c3eb89c253883952d2d6ea349c0ef1b) |
| 2 | `sentinel.register_policy(vault, rules, tripwire=30%, …)` | on Sentinel |
| 3 | user `deposit(10000)` | [`0x8747…d472`](https://explorer-bradbury.genlayer.com/tx/0x8747106fd1285d99a9e1c4dda6d7dcef0580e7c594dd1261d383627e306cd472) |
| 4 | 🔴 **attacker** calls unprotected `migrate_liquidity(4000)` — 40 % drained | [`0xf06e…f134`](https://explorer-bradbury.genlayer.com/tx/0xf06ecec690ec632be30a8f17c094444332434f6033dabc8f0117dfff24acf134) |
| 5 | 🛡 anyone calls `sentinel.check_health(vault)` → Sentinel emits `pause("tripwire: drawdown 4000 bps >= limit 3000")` to the vault | [`0x3f75…768f`](https://explorer-bradbury.genlayer.com/tx/0x3f7585300ac20d9d3e725f82d0750ac7d1658c50af4888e9ca8d3a13e2b9768f) → child [`0x6950…88ef`](https://explorer-bradbury.genlayer.com/tx/0x6950a7cedc8b470f2ec85bd1cbdd2262bc753878582eb95ed2a0419a5eb488ef) |
| 6 | 🔴 attacker tries again → **reverted: `vault paused`** | [`0xb253…6b78`](https://explorer-bradbury.genlayer.com/tx/0xb2533bb892e84a5208ea56a792abb001074269e466e6dd1606e4e10315246b78) |
| 7 | owner `sentinel.lift_halt(vault)` → `unpause()` emitted on finalization | [`0x313d…8bfd`](https://explorer-bradbury.genlayer.com/tx/0x313daabb79f6512990ac81f84d7cd2b518cd68b66b12423dd300ad8accb68bfd) |

Verify yourself: read `get_status()` on the vault and `list_incidents(vault)` on Sentinel — incident #0 is
`action=tripwire, severity=5, confidence=100, reported_at=2026-09-08T14:26:39Z`.
Addresses and all tx hashes are also in [`deployments/testnet_bradbury.json`](deployments/testnet_bradbury.json).

## Why this can only exist on GenLayer

A guardian that reads a security advisory, checks it against the contract's live state and *decides* is impossible on the EVM.
Sentinel uses the three things only Intelligent Contracts have:

| Capability | Used for |
|---|---|
| `gl.nondet.web.get()` | fetch the reporter's evidence (tx trace, advisory, monitoring dashboard) |
| `gl.nondet.exec_prompt()` | judge evidence + live state against the protocol's natural-language policy |
| **Equivalence Principle** (`run_nondet_unsafe` with a custom validator) | every validator independently re-derives the verdict; only the *decision fields* must match, free-text reasoning may differ. A lying leader is rejected. |
| Cross-contract `emit()` | Sentinel actually calls `pause()` / `set_max_withdraw_bps()` on the target — with `on='accepted'` so an emergency halt doesn't wait for the appeal window |

## How it works

**Two layers of defence**

1. **Deterministic tripwire** — `check_health(target)`. Anyone (a keeper bot, a user, another contract) can call it.
   Pure math: if drawdown ≥ policy limit → pause. Instant, cheap, no LLM.
2. **Evidence-based judgment** — `report_incident(target, evidence_url, description)` with a stake.
   Validators fetch the URL, read `target.get_status()`, and the model returns
   `{action: none|throttle|pause, severity 0-5, confidence 0-100, reason}`.
   A confidence below the policy threshold is deterministically downgraded to `none` so every validator applies the same rule.

**Economics (anti-spam)**

| Verdict | Reporter | Target |
|---|---|---|
| `pause` | stake back + full bounty | paused |
| `throttle` | stake back + ½ bounty | max single withdrawal capped |
| `none` | stake slashed to treasury | untouched |

Every verdict is stored on-chain with reporter, evidence URL, confidence and reasoning → a public, auditable incident log.

**Recovery** — only the policy owner can `lift_halt()` after fixing the bug.

## Guarding *your* contract

Any contract works if it exposes four methods and sets Sentinel as guardian:

```python
def pause(self, reason: str): ...          # must be idempotent
def unpause(self): ...
def set_max_withdraw_bps(self, bps: int): ...
@gl.public.view
def get_status(self) -> dict: ...          # anything you want the judge to see (reserves, drawdown, …)
```

Then:

```python
sentinel.register_policy(
    target=vault, rules="Pause on any unauthorized transfer of reserves…",
    max_drawdown_bps=3000, throttle_bps=1000, min_confidence=70, min_stake=…, bounty=…)
vault.set_guardian(sentinel)
```

`contracts/vault.py` (`GuardedVault`) is a reference implementation — with an **intentional access-control bug** in
`migrate_liquidity()` so the demo can stage a realistic drain.

## Quick start

```bash
pip install -r requirements.txt

# 1. Lint with the official GenVM linter
genvm-lint check contracts/sentinel.py
genvm-lint check contracts/vault.py

# 2. Run the test-suite (20 tests: tripwire, LLM verdicts, slashing, validator consensus, recovery)
pytest -q

# 3. Watch the full story in your terminal (offline, mocked LLM)
python scripts/demo.py

# 3b. …or with a real model judging real evidence
OPENAI_API_KEY=sk-… python scripts/demo.py --live
```

Demo output (abridged):

```
── 2. Exploit
    attacker → vault.migrate_liquidity(attacker, 2000)   (no owner check — the bug)
  ✖ 2,000 drained. Drawdown 20% — below the 30% hard tripwire, a pure-math guard would stay silent.
── 3. Report with evidence
    verdict: action=PAUSE  severity=5/5  confidence=95%
  ✔ validator re-ran the judgment independently → AGREE
── 4. Autonomous halt
    vault: PAUSED  reserves=8,000
  ✔ Sentinel paused the vault. No multisig, no vote, no human.
    attacker → vault.migrate_liquidity(attacker, 8000)
  ✔ reverted: vault paused
── 5. Spam resistance
    verdict: action=NONE  confidence=92%
  ✔ stake slashed → treasury now 930
```

## Deploy

```bash
# local network (GenLayer Studio via docker, or `glsim --port 4000`)
python scripts/deploy.py --network localnet

# testnet
export ACCOUNT_PRIVATE_KEY=0x…
python scripts/deploy.py --network testnet_asimov --fund 1000000000000000000
```

Addresses are written to `deployments/<network>.json`. Open `docs/index.html`
(`?rpc=…&sentinel=0x…&vault=0x…`) for a live dashboard: vault health, policy, incident log, and a form to stake & report.

## Project layout

```
contracts/sentinel.py   the guardian (policy registry, tripwire, evidence judgment, rewards, incident log)
contracts/vault.py      reference guarded contract with the guardian interface (+ intentional bug for the demo)
tests/                  multi-contract test harness on glsim's engine; web + LLM mocked, cross-contract calls real
scripts/demo.py         end-to-end story (offline or --live)
scripts/deploy.py       deploy + wire on localnet / studionet / testnets
docs/index.html     zero-build dashboard (genlayer-js)
```

## Design notes

* **Storage vs. non-determinism** — everything the nondet block needs (policy rules, target status JSON) is copied to
  plain Python values first; storage and cross-contract calls are forbidden inside `leader_fn`.
* **Validator logic** — validators *re-run* the whole task (fetch + judge) and compare `action` exactly and `severity`
  within ±1. Reasoning text is stored but never compared. Leader errors are always rejected.
* **`on='accepted'` for `pause()`** — speed matters in an emergency; the target's `pause()` is idempotent so re-emission
  during appeals is harmless. `unpause()` uses `on='finalized'`.
* **Malformed model output** — normalised to `action: none`; garbage can never halt a healthy contract.

## Roadmap

* Multiple targets per policy, and policies that *tune* parameters continuously (fees, LTV, caps) — not just halt.
* Watcher agents that auto-report from monitoring feeds (Forta / Hypernative / Tenderly alerts).
* EVM targets via `gl.evm.contract_interface` so Sentinel can guard contracts on GenLayer's chain layer.
* Appeal path: a slashed reporter can escalate to a second, larger validator set.

## License

MIT
