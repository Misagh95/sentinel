"""
End-to-end behaviour of Sentinel against a live GuardedVault.

Web + LLM calls are mocked (this is a unit suite); cross-contract calls are
real: Sentinel genuinely pauses / throttles the Vault through its guardian
interface.
"""
import pytest

EVIDENCE_URL = "https://evidence.example.com/incident/42.json"

EXPLOIT_EVIDENCE = """
{"tx": "0xabc", "from": "0xattacker", "to": "GuardedVault.migrate_liquidity",
 "amount": 4000, "reserves_before": 10000, "reserves_after": 6000,
 "note": "migrate_liquidity has no owner check; caller is not the owner; funds sent to fresh EOA"}
"""

PAUSE_VERDICT = {
    "action": "pause", "severity": 5, "confidence": 96,
    "reason": "Unauthorized caller drained 40% of reserves via migrate_liquidity; matches live drawdown.",
}
THROTTLE_VERDICT = {
    "action": "throttle", "severity": 3, "confidence": 80,
    "reason": "Suspicious outflow pattern, unconfirmed.",
}
NONE_VERDICT = {
    "action": "none", "severity": 0, "confidence": 90,
    "reason": "Evidence is a generic blog post unrelated to this contract.",
}


# --------------------------------------------------------------------------- policy

def test_policy_registered(guarded):
    sb, vault, sentinel = guarded
    p = sb.call(sentinel, "get_policy", vault)
    assert p["target"].lower() == vault.lower()
    assert p["max_drawdown_bps"] == 3000
    assert p["active"] and not p["halted"]
    assert sb.call(sentinel, "list_targets")[0].lower() == vault.lower()
    assert sb.call(sentinel, "get_treasury") == 1_000


def test_policy_input_validation(sandbox):
    sb = sandbox
    vault = sb.deploy("vault.py", sender=sb.owner)
    sentinel = sb.deploy("sentinel.py", sender=sb.owner)
    with pytest.raises(Exception, match="max_drawdown_bps out of range"):
        sb.call(sentinel, "register_policy", vault, "r", 20000, 1000, 70, 0, 0, sender=sb.owner)
    with pytest.raises(Exception, match="min_confidence out of range"):
        sb.call(sentinel, "register_policy", vault, "r", 3000, 1000, 101, 0, 0, sender=sb.owner)


def test_only_policy_owner_can_replace(guarded):
    sb, vault, sentinel = guarded
    with pytest.raises(Exception, match="policy owned by someone else"):
        sb.call(sentinel, "register_policy", vault, "hijack", 0, 0, 0, 0, 0, sender=sb.attacker)


# --------------------------------------------------------------------------- layer 1: tripwire

def test_tripwire_pauses_vault_on_drawdown(guarded):
    sb, vault, sentinel = guarded
    assert sb.call(sentinel, "check_health", vault, sender=sb.user) == "healthy"

    # attacker drains 40% > 30% limit
    sb.call(vault, "migrate_liquidity", sb.hex(sb.attacker), 4_000, sender=sb.attacker)

    assert sb.call(sentinel, "check_health", vault, sender=sb.user) == "paused"

    status = sb.call(vault, "get_status")
    assert status["paused"] is True
    assert status["pause_reason"].startswith("tripwire")

    # further drain attempts are blocked
    with pytest.raises(Exception, match="vault paused"):
        sb.call(vault, "migrate_liquidity", sb.hex(sb.attacker), 1_000, sender=sb.attacker)

    inc = sb.call(sentinel, "list_incidents", vault)
    assert len(inc) == 1 and inc[0]["action"] == "tripwire" and inc[0]["severity"] == 5
    assert sb.call(sentinel, "get_policy", vault)["halted"] is True


def test_tripwire_is_idle_below_limit(guarded):
    sb, vault, sentinel = guarded
    sb.call(vault, "withdraw", 2_000, sender=sb.user)  # 20% drawdown < 30%
    assert sb.call(sentinel, "check_health", vault) == "healthy"
    assert sb.call(vault, "get_status")["paused"] is False


# --------------------------------------------------------------------------- layer 2: evidence + LLM

def test_report_pause_flow(guarded):
    sb, vault, sentinel = guarded
    sb.call(vault, "migrate_liquidity", sb.hex(sb.attacker), 2_000, sender=sb.attacker)  # 20%: below tripwire
    sb.mock_web(r"evidence\.example\.com", EXPLOIT_EVIDENCE)
    sb.mock_llm(r"You are Sentinel", PAUSE_VERDICT)

    action = sb.call(
        sentinel, "report_incident", vault, EVIDENCE_URL,
        "migrate_liquidity is being called by a non-owner and draining reserves",
        sender=sb.reporter, value=50,
    )
    assert action == "pause"

    status = sb.call(vault, "get_status")
    assert status["paused"] is True
    assert status["pause_reason"].startswith("sentinel:")

    inc = sb.call(sentinel, "get_incident", 0)
    assert inc["action"] == "pause"
    assert inc["confidence"] == 96
    assert inc["reporter"].lower() == sb.hex(sb.reporter).lower()
    assert inc["evidence_url"] == EVIDENCE_URL

    # reporter gets stake back + bounty; treasury pays the bounty
    assert sb.call(sentinel, "rewards_of", sb.hex(sb.reporter)) == 50 + 100
    assert sb.call(sentinel, "get_treasury") == 1_000 - 100

    # a second report on a halted target is rejected
    with pytest.raises(Exception, match="already halted"):
        sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "again", sender=sb.reporter, value=50)


def test_report_throttle_flow(guarded):
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", "{\"note\": \"odd withdrawals\"}")
    sb.mock_llm(r"You are Sentinel", THROTTLE_VERDICT)

    action = sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "weird pattern",
                     sender=sb.reporter, value=20)
    assert action == "throttle"

    status = sb.call(vault, "get_status")
    assert status["paused"] is False
    assert status["max_withdraw_bps"] == 1000  # throttled to policy.throttle_bps

    with pytest.raises(Exception, match="exceeds max single withdrawal"):
        sb.call(vault, "withdraw", 5_000, sender=sb.user)

    assert sb.call(sentinel, "rewards_of", sb.hex(sb.reporter)) == 20 + 50  # half bounty
    assert sb.call(sentinel, "get_policy", vault)["halted"] is False


def test_false_alarm_slashes_stake(guarded):
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", "<html>Top 10 crypto hacks of all time</html>")
    sb.mock_llm(r"You are Sentinel", NONE_VERDICT)

    action = sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "OMG HACKED!!!",
                     sender=sb.attacker, value=30)
    assert action == "none"
    assert sb.call(vault, "get_status")["paused"] is False
    assert sb.call(sentinel, "rewards_of", sb.hex(sb.attacker)) == 0
    assert sb.call(sentinel, "get_treasury") == 1_000 + 30  # slashed


def test_low_confidence_verdict_is_downgraded(guarded):
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", EXPLOIT_EVIDENCE)
    sb.mock_llm(r"You are Sentinel", {"action": "pause", "severity": 4, "confidence": 40, "reason": "maybe"})

    action = sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "hmm",
                     sender=sb.reporter, value=10)
    assert action == "none"
    inc = sb.call(sentinel, "get_incident", 0)
    assert inc["reason"].startswith("(downgraded")
    assert sb.call(vault, "get_status")["paused"] is False


def test_malformed_llm_output_is_safe(guarded):
    """Garbage from the model must never pause a healthy contract."""
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", "x")
    sb.mock_llm(r"You are Sentinel", "I think you should PAUSE everything!!! {not json")
    action = sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "x", sender=sb.reporter, value=10)
    assert action == "none"
    assert sb.call(vault, "get_status")["paused"] is False


def test_report_requires_stake_and_https(guarded):
    sb, vault, sentinel = guarded
    with pytest.raises(Exception, match="insufficient stake"):
        sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "x", sender=sb.reporter, value=1)
    with pytest.raises(Exception, match="must be http"):
        sb.call(sentinel, "report_incident", vault, "ipfs://abc", "x", sender=sb.reporter, value=10)


# --------------------------------------------------------------------------- consensus (validator behaviour)

def test_validator_agrees_when_independent_run_matches(guarded):
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", EXPLOIT_EVIDENCE)
    sb.mock_llm(r"You are Sentinel", PAUSE_VERDICT)
    sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "drain", sender=sb.reporter, value=10)
    # validator re-runs leader_fn with the same mocks -> same decision -> agree
    assert sb.run_validator() is True


def test_validator_rejects_leader_that_lies(guarded):
    """A malicious leader claiming 'pause' when validators see 'none' is rejected."""
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", "<html>unrelated</html>")
    sb.mock_llm(r"You are Sentinel", NONE_VERDICT)
    sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "x", sender=sb.reporter, value=10)

    forged = {"action": "pause", "severity": 5, "confidence": 99, "reason": "trust me"}
    assert sb.run_validator(leader_result=forged) is False


def test_validator_tolerates_reasoning_and_small_severity_drift(guarded):
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", EXPLOIT_EVIDENCE)
    sb.mock_llm(r"You are Sentinel", PAUSE_VERDICT)
    sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "drain", sender=sb.reporter, value=10)

    drifted = dict(PAUSE_VERDICT, severity=4, reason="worded completely differently")
    assert sb.run_validator(leader_result=drifted) is True
    far = dict(PAUSE_VERDICT, severity=2)
    assert sb.run_validator(leader_result=far) is False


def test_validator_rejects_leader_error(guarded):
    sb, vault, sentinel = guarded
    sb.mock_web(r"evidence\.example\.com", EXPLOIT_EVIDENCE)
    sb.mock_llm(r"You are Sentinel", PAUSE_VERDICT)
    sb.call(sentinel, "report_incident", vault, EVIDENCE_URL, "drain", sender=sb.reporter, value=10)
    assert sb.run_validator(leader_error=RuntimeError("boom")) is False


# --------------------------------------------------------------------------- recovery

def test_owner_can_lift_halt(guarded):
    sb, vault, sentinel = guarded
    sb.call(vault, "migrate_liquidity", sb.hex(sb.attacker), 4_000, sender=sb.attacker)
    assert sb.call(sentinel, "check_health", vault) == "paused"
    assert sb.call(vault, "get_status")["paused"] is True

    with pytest.raises(Exception, match="only policy owner"):
        sb.call(sentinel, "lift_halt", vault, sender=sb.attacker)

    sb.call(sentinel, "lift_halt", vault, sender=sb.owner)
    assert sb.call(vault, "get_status")["paused"] is False
    assert sb.call(sentinel, "get_policy", vault)["halted"] is False
