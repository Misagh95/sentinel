#!/usr/bin/env python3
"""
Sentinel demo — the whole story in one terminal, no Docker, no API keys.

    python scripts/demo.py            # mocked LLM (deterministic, offline)
    python scripts/demo.py --live     # real LLM via OPENAI_API_KEY / ANTHROPIC_API_KEY

Scenes:
  1. Deploy GuardedVault + Sentinel, attach Sentinel as guardian, register policy.
  2. Attacker calls the unprotected migrate_liquidity() -> 20% drained (below tripwire).
  3. A watcher stakes GEN and reports the drain with evidence.
     Validators fetch the evidence, read the vault's live state, and reach consensus.
  4. Sentinel pauses the vault autonomously. Attacker's second drain fails.
  5. Bonus: a FUD report is rejected and its stake is slashed.
  6. Owner fixes the bug, lifts the halt.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

# ---------------------------------------------------------------- pretty printing
C = {"g": "\033[92m", "r": "\033[91m", "y": "\033[93m", "b": "\033[94m", "d": "\033[2m", "x": "\033[0m", "B": "\033[1m"}
def c(k, s): return f"{C[k]}{s}{C['x']}"
def h(s): print("\n" + c("B", "── " + s + " ") + c("d", "─" * max(0, 70 - len(s))))
def ok(s): print(c("g", "  ✔ ") + s)
def bad(s): print(c("r", "  ✖ ") + s)
def info(s): print(c("d", "    " + s))
def status(sb, vault):
    s = sb.call(vault, "get_status")
    flag = c("r", "PAUSED") if s["paused"] else c("g", "RUNNING")
    print(f"    vault: {flag}  reserves={s['reserves']:,}  drawdown={s['drawdown_bps']/100:.1f}%  "
          f"max_withdraw={s['max_withdraw_bps']/100:.0f}%" + (f"  reason='{s['pause_reason']}'" if s['paused'] else ""))
    return s

EVIDENCE_URL = "https://evidence.example.com/incidents/vault-drain-0xabc.json"
EVIDENCE_BODY = json.dumps({
    "type": "exploit_report",
    "contract": "GuardedVault",
    "function": "migrate_liquidity(address,uint256)",
    "finding": "missing onlyOwner modifier; any EOA can move reserves",
    "tx": {"hash": "0xabc123", "from": "0xattacker", "amount": 2000, "reserves_before": 10000, "reserves_after": 8000},
    "attacker_funding": "fresh EOA funded via mixer 3 minutes before the call",
    "recommendation": "pause immediately; a second call can drain the remainder",
}, indent=1)
FUD_URL = "https://crypto-rumors.example.com/top-10-hacks"
FUD_BODY = "<html><h1>Top 10 DeFi hacks of all time</h1><p>Generic listicle. Nothing about this vault.</p></html>"

RULES = ("Pause immediately on any unauthorized transfer of reserves, any access-control or reentrancy "
         "exploit, or any single outflow above 25% of reserves. Throttle on credible but unconfirmed "
         "threats. Ignore generic news, rumors and unrelated incidents.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="use a real LLM (needs OPENAI_API_KEY or ANTHROPIC_API_KEY)")
    ap.add_argument("--model", default=None, help="provider:model, e.g. openai:gpt-4o-mini or anthropic:claude-3-5-haiku-latest")
    ap.add_argument("--fast", action="store_true", help="no dramatic pauses")
    a = ap.parse_args()
    pause = (lambda s=0.8: None) if a.fast else (lambda s=0.8: time.sleep(s))

    from conftest import Sandbox
    sb = Sandbox()
    live = None
    if a.live:
        from glsim.live_io import create_llm_handler
        model = a.model or ("anthropic:claude-3-5-haiku-latest" if os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("OPENAI_API_KEY") else None)
        live = create_llm_handler(model)
        sb.vm._live_llm_handler = live
        print(c("y", f"live LLM mode: {model or 'openai:gpt-4o-mini'}"))

    print(c("B", "\n🛡  SENTINEL — autonomous circuit breaker on GenLayer\n"))

    # ---------------------------------------------------------------- scene 1
    h("1. Deploy & wire")
    vault = sb.deploy("vault.py", sender=sb.owner)
    sentinel = sb.deploy("sentinel.py", sender=sb.owner)
    ok(f"GuardedVault  {vault}")
    ok(f"Sentinel      {sentinel}")
    sb.call(vault, "set_guardian", sentinel, sender=sb.owner)
    ok("vault.set_guardian(sentinel)  — Sentinel can now pause/throttle the vault")
    sb.call(sentinel, "register_policy", vault, RULES, 3000, 1000, 70, 10, 100, sender=sb.owner, value=1_000)
    ok("sentinel.register_policy(vault, rules, tripwire=30% drawdown, throttle=10%, min_conf=70, stake=10, bounty=100)")
    info("policy: " + RULES)
    sb.call(vault, "deposit", 10_000, sender=sb.user)
    ok("user deposits 10,000")
    status(sb, vault)
    pause()

    # ---------------------------------------------------------------- scene 2
    h("2. Exploit")
    print("    attacker → vault.migrate_liquidity(attacker, 2000)   " + c("d", "(no owner check — the bug)"))
    sb.call(vault, "migrate_liquidity", sb.hex(sb.attacker), 2_000, sender=sb.attacker)
    bad("2,000 drained. Drawdown 20% — below the 30% hard tripwire, a pure-math guard would stay silent.")
    print("    keeper → sentinel.check_health(vault) = " + c("y", sb.call(sentinel, "check_health", vault)))
    status(sb, vault)
    pause()

    # ---------------------------------------------------------------- scene 3
    h("3. Report with evidence")
    if not live:
        sb.mock_llm(r"You are Sentinel", {
            "action": "pause", "severity": 5, "confidence": 95,
            "reason": "Evidence documents an unauthorized migrate_liquidity call by a non-owner; the 20% drawdown in live state matches the reported drain and a repeat call can empty the vault."})
    sb.mock_web(r"evidence\.example\.com", EVIDENCE_BODY)
    print(f"    watcher stakes 50 and reports: {EVIDENCE_URL}")
    info("validators: fetch evidence → read vault.get_status() → LLM judgment → consensus on {action, severity}")
    pause(1.2)
    t0 = time.time()
    action = sb.call(sentinel, "report_incident", vault, EVIDENCE_URL,
                     "migrate_liquidity is callable by anyone; attacker already moved 2000 and will call again",
                     sender=sb.reporter, value=50)
    inc = sb.call(sentinel, "get_incident", sb.call(sentinel, "incident_count") - 1)
    print(f"    verdict: action={c('r' if action == 'pause' else 'y', action.upper())}  severity={inc['severity']}/5  "
          f"confidence={inc['confidence']}%  ({time.time()-t0:.1f}s)")
    info("reason: " + inc["reason"])
    agree = sb.run_validator()
    ok(f"validator re-ran the judgment independently → {'AGREE' if agree else 'DISAGREE'}")
    pause()

    # ---------------------------------------------------------------- scene 4
    h("4. Autonomous halt")
    s = status(sb, vault)
    if s["paused"]:
        ok("Sentinel paused the vault. No multisig, no vote, no human.")
    print("    attacker → vault.migrate_liquidity(attacker, 8000)")
    try:
        sb.call(vault, "migrate_liquidity", sb.hex(sb.attacker), 8_000, sender=sb.attacker)
        bad("drain succeeded (unexpected)")
    except Exception as e:
        ok(f"reverted: {str(e).split(':',1)[-1].strip()[:80]}")
    ok(f"watcher rewards: {sb.call(sentinel, 'rewards_of', sb.hex(sb.reporter))} (stake 50 back + bounty 100)")
    pause()

    # ---------------------------------------------------------------- scene 5
    h("5. Spam resistance")
    sb.call(sentinel, "lift_halt", vault, sender=sb.owner)   # reopen so a report is accepted
    sb.clear_mocks()
    if not live:
        sb.mock_llm(r"You are Sentinel", {"action": "none", "severity": 0, "confidence": 92,
                                          "reason": "Generic listicle; no reference to this contract and live state shows no new anomaly."})
    sb.mock_web(r"crypto-rumors\.example\.com", FUD_BODY)
    print(f"    troll stakes 30 and reports 'OMG HACKED': {FUD_URL}")
    action = sb.call(sentinel, "report_incident", vault, FUD_URL, "OMG THIS VAULT IS HACKED SELL NOW", sender=sb.attacker, value=30)
    inc = sb.call(sentinel, "get_incident", sb.call(sentinel, "incident_count") - 1)
    print(f"    verdict: action={c('g', action.upper())}  confidence={inc['confidence']}%")
    info("reason: " + inc["reason"])
    ok(f"stake slashed → treasury now {sb.call(sentinel, 'get_treasury')}")
    status(sb, vault)
    pause()

    # ---------------------------------------------------------------- scene 6
    h("6. Audit trail")
    for i in sb.call(sentinel, "list_incidents", vault):
        print(f"    #{i['id']}  {i['action']:<8} sev={i['severity']} conf={i['confidence']:>3}%  by {i['reporter'][:10]}…  {i['evidence_url'] or '(health check)'}")
    print()
    print(c("B", "Every decision is on-chain, evidence-linked, and reached by validator consensus."))
    print()
    sb.close()


if __name__ == "__main__":
    main()
