# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
GuardedVault — a deliberately simple liquidity vault that exposes a
*guardian interface* so an external Intelligent Contract (Sentinel) can
pause it or tighten its limits without any human multisig in the loop.

    Guardian interface (what Sentinel calls):
        pause(reason)                  -> halt withdrawals
        unpause()                      -> resume
        set_max_withdraw_bps(bps)      -> throttle max single withdrawal
        get_status()                   -> machine-readable health snapshot

NOTE: `migrate_liquidity` intentionally has a *missing access-control check*
(the single most common root cause of real DeFi exploits). It exists so the
demo can stage a realistic drain and show Sentinel reacting to it.
"""

from genlayer import *


class GuardedVault(gl.Contract):
    owner: Address
    guardian: Address
    paused: bool
    pause_reason: str
    reserves: u256
    peak_reserves: u256
    max_withdraw_bps: u256            # max single withdrawal as share of reserves (10000 = 100%)
    balances: TreeMap[Address, u256]
    tx_count: u256
    last_outflow: u256                # size of the last outflow (withdraw/migrate)

    def __init__(self):
        self.owner = gl.message.sender_address
        self.guardian = gl.message.sender_address   # owner until a Sentinel is attached
        self.paused = False
        self.pause_reason = ""
        self.reserves = u256(0)
        self.peak_reserves = u256(0)
        self.max_withdraw_bps = u256(10000)
        self.tx_count = u256(0)
        self.last_outflow = u256(0)

    # ------------------------------------------------------------------ helpers
    def _only_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            raise gl.vm.UserError("only owner")

    def _only_guardian(self) -> None:
        s = gl.message.sender_address
        if s != self.guardian and s != self.owner:
            raise gl.vm.UserError("only guardian")

    def _not_paused(self) -> None:
        if self.paused:
            raise gl.vm.UserError("vault paused: " + self.pause_reason)

    # ------------------------------------------------------------------ admin
    @gl.public.write
    def set_guardian(self, guardian: str) -> None:
        """Attach a Sentinel contract as guardian."""
        self._only_owner()
        self.guardian = Address(guardian)

    # ------------------------------------------------------------------ user flows
    @gl.public.write
    def deposit(self, amount: int) -> None:
        """Ledger-style deposit (amount in wei-like units)."""
        self._not_paused()
        if amount <= 0:
            raise gl.vm.UserError("amount must be positive")
        s = gl.message.sender_address
        self.balances[s] = u256(self.balances.get(s, u256(0)) + amount)
        self.reserves = u256(self.reserves + amount)
        if self.reserves > self.peak_reserves:
            self.peak_reserves = self.reserves
        self.tx_count = u256(self.tx_count + 1)

    @gl.public.write
    def withdraw(self, amount: int) -> None:
        self._not_paused()
        s = gl.message.sender_address
        bal = self.balances.get(s, u256(0))
        if amount <= 0 or amount > bal:
            raise gl.vm.UserError("insufficient balance")
        limit = self.reserves * self.max_withdraw_bps // 10000
        if amount > limit:
            raise gl.vm.UserError("exceeds max single withdrawal")
        self.balances[s] = u256(bal - amount)
        self.reserves = u256(self.reserves - amount)
        self.last_outflow = u256(amount)
        self.tx_count = u256(self.tx_count + 1)

    @gl.public.write
    def migrate_liquidity(self, to: str, amount: int) -> None:
        """
        Legacy admin function. BUG (intentional, for the demo): no owner check.
        Anyone can drain reserves — exactly the class of bug Sentinel exists for.
        """
        self._not_paused()
        if amount <= 0 or amount > self.reserves:
            raise gl.vm.UserError("bad amount")
        self.reserves = u256(self.reserves - amount)
        self.last_outflow = u256(amount)
        self.tx_count = u256(self.tx_count + 1)

    # ------------------------------------------------------------------ guardian interface
    @gl.public.write
    def pause(self, reason: str) -> None:
        self._only_guardian()
        if self.paused:
            return  # idempotent: safe under duplicate 'accepted' messages
        self.paused = True
        self.pause_reason = reason

    @gl.public.write
    def unpause(self) -> None:
        self._only_guardian()
        self.paused = False
        self.pause_reason = ""

    @gl.public.write
    def set_max_withdraw_bps(self, bps: int) -> None:
        self._only_guardian()
        if bps < 0 or bps > 10000:
            raise gl.vm.UserError("bps out of range")
        self.max_withdraw_bps = u256(bps)

    # ------------------------------------------------------------------ views
    @gl.public.view
    def get_status(self) -> dict:
        peak = int(self.peak_reserves)
        reserves = int(self.reserves)
        drawdown_bps = 0 if peak == 0 else (peak - reserves) * 10000 // peak
        return {
            "paused": self.paused,
            "pause_reason": self.pause_reason,
            "reserves": reserves,
            "peak_reserves": peak,
            "drawdown_bps": drawdown_bps,
            "max_withdraw_bps": int(self.max_withdraw_bps),
            "last_outflow": int(self.last_outflow),
            "tx_count": int(self.tx_count),
            "guardian": self.guardian.as_hex,
            "owner": self.owner.as_hex,
        }

    @gl.public.view
    def balance_of(self, who: str) -> int:
        return int(self.balances.get(Address(who), u256(0)))
