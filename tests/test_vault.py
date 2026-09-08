import pytest


def test_deposit_and_status(sandbox):
    sb = sandbox
    vault = sb.deploy("vault.py", sender=sb.owner)
    sb.call(vault, "deposit", 5_000, sender=sb.user)
    s = sb.call(vault, "get_status")
    assert s["reserves"] == 5_000
    assert s["peak_reserves"] == 5_000
    assert s["drawdown_bps"] == 0
    assert s["paused"] is False
    assert sb.call(vault, "balance_of", sb.hex(sb.user)) == 5_000


def test_intentional_bug_allows_anyone_to_drain(sandbox):
    sb = sandbox
    vault = sb.deploy("vault.py", sender=sb.owner)
    sb.call(vault, "deposit", 10_000, sender=sb.user)
    # attacker is not owner, yet migrate_liquidity works -> the bug Sentinel guards against
    sb.call(vault, "migrate_liquidity", sb.hex(sb.attacker), 4_000, sender=sb.attacker)
    s = sb.call(vault, "get_status")
    assert s["reserves"] == 6_000
    assert s["drawdown_bps"] == 4_000
    assert s["last_outflow"] == 4_000


def test_only_guardian_can_pause(sandbox):
    sb = sandbox
    vault = sb.deploy("vault.py", sender=sb.owner)
    with pytest.raises(Exception, match="only guardian"):
        sb.call(vault, "pause", "nope", sender=sb.attacker)
    sb.call(vault, "pause", "maintenance", sender=sb.owner)
    assert sb.call(vault, "get_status")["paused"] is True
    with pytest.raises(Exception, match="vault paused"):
        sb.call(vault, "deposit", 1, sender=sb.user)
    sb.call(vault, "unpause", sender=sb.owner)
    assert sb.call(vault, "get_status")["paused"] is False


def test_throttle_limits_single_withdrawal(sandbox):
    sb = sandbox
    vault = sb.deploy("vault.py", sender=sb.owner)
    sb.call(vault, "deposit", 10_000, sender=sb.user)
    sb.call(vault, "set_max_withdraw_bps", 1000, sender=sb.owner)  # 10%
    with pytest.raises(Exception, match="exceeds max single withdrawal"):
        sb.call(vault, "withdraw", 2_000, sender=sb.user)
    sb.call(vault, "withdraw", 1_000, sender=sb.user)
    assert sb.call(vault, "get_status")["reserves"] == 9_000
