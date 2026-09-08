"""
Test harness: a tiny multi-contract sandbox built on glsim's SimEngine.

Direct mode (gltest.direct) runs one contract in-memory but has no
cross-contract routing. glsim's engine adds per-contract storage, real
`gl.get_contract_at(...).view()/emit()` routing and a PostMessage queue,
while still letting us mock web + LLM calls. That is exactly what Sentinel
needs: Sentinel must *actually* pause the Vault in tests.
"""
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SDK_VERSION = "v0.2.16"  # newest genvm release that still ships genvm-universal.tar.xz


@pytest.fixture(scope="session", autouse=True)
def _pin_sdk_version():
    """
    Pin the GenVM SDK the direct runner downloads. The SDK must *not* be
    imported before the first deploy (it reads the tx message from fd 0 at
    import time), so we only pin the version here and let the loader import it.
    """
    from gltest.direct import sdk_loader
    original = sdk_loader.get_latest_version
    sdk_loader.get_latest_version = lambda: SDK_VERSION
    yield
    sdk_loader.get_latest_version = original


class Sandbox:
    """Thin convenience wrapper around glsim.engine.SimEngine."""

    def __init__(self):
        from glsim.engine import SimEngine
        from glsim.state import StateStore
        from gltest.direct.loader import create_address

        self.engine = SimEngine(StateStore())
        self.engine.activate()
        self.vm = self.engine.vm
        self.owner = create_address("owner")
        self.reporter = create_address("reporter")
        self.attacker = create_address("attacker")
        self.user = create_address("user")
        self.vm.sender = self.owner

    # -- lifecycle
    def close(self):
        self.engine.deactivate()

    # -- helpers
    @staticmethod
    def hex(addr) -> str:
        b = addr.as_bytes if hasattr(addr, "as_bytes") else addr
        return "0x" + b.hex()

    def deploy(self, name: str, *args, sender=None, **kwargs) -> str:
        addr, _ = self.engine.deploy(
            str(ROOT / "contracts" / name), list(args), kwargs,
            sender=self.hex(sender) if sender is not None else None,
        )
        return addr

    def call(self, addr: str, method: str, *args, sender=None, value: int = 0, **kwargs):
        prev_value = self.vm.value
        self.vm.value = value
        try:
            return self.engine.call_method(
                addr, method, list(args), kwargs,
                sender=self.hex(sender) if sender is not None else None,
            )
        finally:
            self.vm.value = prev_value

    def mock_web(self, url_pattern: str, body: str, status: int = 200):
        self.vm.mock_web(url_pattern, {"status": status, "body": body})

    def mock_llm(self, prompt_pattern: str, response: dict | str):
        self.vm.mock_llm(prompt_pattern, response if isinstance(response, str) else json.dumps(response))

    def clear_mocks(self):
        self.vm.clear_mocks()

    def run_validator(self, **kw) -> bool:
        return self.vm.run_validator(**kw)


@pytest.fixture
def sandbox():
    sb = Sandbox()
    try:
        yield sb
    finally:
        sb.close()


DEFAULT_RULES = (
    "Pause immediately on any unauthorized transfer of reserves, any reentrancy or "
    "access-control exploit, or any outflow larger than 25% of reserves in a single "
    "transaction. Throttle on credible but unconfirmed reports. Ignore generic FUD."
)


@pytest.fixture
def guarded(sandbox):
    """Vault + Sentinel wired together with a funded policy."""
    sb = sandbox
    vault = sb.deploy("vault.py", sender=sb.owner)
    sentinel = sb.deploy("sentinel.py", sender=sb.owner)
    sb.call(vault, "set_guardian", sentinel, sender=sb.owner)
    sb.call(
        sentinel, "register_policy",
        vault, DEFAULT_RULES,
        3000,   # max_drawdown_bps  -> tripwire at 30% drawdown
        1000,   # throttle_bps      -> 10% max single withdrawal when throttled
        70,     # min_confidence
        10,     # min_stake (wei-ish units for tests)
        100,    # bounty
        sender=sb.owner, value=1_000,
    )
    sb.call(vault, "deposit", 10_000, sender=sb.user)
    return sb, vault, sentinel
