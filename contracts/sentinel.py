# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
Sentinel — an autonomous circuit-breaker for other contracts.

A protocol registers a *policy* for one of its contracts (the "target").
The policy has two layers:

  1. Deterministic tripwire   — hard numeric limits (e.g. max drawdown).
                                Anyone can call `check_health()`; no LLM,
                                no evidence needed. Pure math, instant.
  2. Evidence-based judgment  — anyone can `report_incident()` with a URL
                                (tx trace, security advisory, monitoring
                                dashboard, post-mortem). Validators fetch
                                the evidence, read the target's live state,
                                and reach consensus on an action:
                                    none | throttle | pause
                                Reporters stake GEN; correct reports earn a
                                bounty, spam loses the stake.

When the verdict is `pause` or `throttle`, Sentinel calls the target's
guardian interface directly — no human multisig, no governance vote.

Target contracts only need to expose:
    pause(reason: str), unpause(), set_max_withdraw_bps(bps: int), get_status() -> dict
"""

from genlayer import *
from dataclasses import dataclass
import json
import typing


# --------------------------------------------------------------------------- types

@allow_storage
@dataclass
class Policy:
    owner: Address
    target: Address
    rules: str                 # natural-language security policy
    max_drawdown_bps: u256     # deterministic tripwire (0 = disabled)
    throttle_bps: u256         # what max_withdraw_bps to set on "throttle"
    min_confidence: u256       # LLM confidence required to act (0-100)
    min_stake: u256            # reporter stake required (wei)
    bounty: u256               # paid to reporter on a correct report (wei)
    active: bool
    halted: bool
    incidents: u256


@allow_storage
@dataclass
class Incident:
    id: u256
    target: Address
    reporter: Address
    evidence_url: str
    description: str
    action: str                # none | throttle | pause | tripwire
    severity: u256             # 0-5
    confidence: u256           # 0-100
    reason: str
    stake: u256
    reported_at: str


@gl.contract_interface
class GuardedTarget:
    class View:
        def get_status(self) -> dict: ...

    class Write:
        def pause(self, reason: str) -> None: ...
        def unpause(self) -> None: ...
        def set_max_withdraw_bps(self, bps: int) -> None: ...


@gl.evm.contract_interface
class _Recipient:
    class View:
        pass

    class Write:
        pass


ACTIONS = ("none", "throttle", "pause")
EVIDENCE_LIMIT = 6000  # chars of evidence passed to the model


# --------------------------------------------------------------------------- contract

class Sentinel(gl.Contract):
    policies: TreeMap[Address, Policy]
    targets: DynArray[Address]
    incidents: DynArray[Incident]
    rewards: TreeMap[Address, u256]   # pull-payment ledger for reporter bounties
    treasury: u256                    # slashed stakes + deposits that fund bounties

    def __init__(self):
        self.treasury = u256(0)

    # ------------------------------------------------------------------ policy admin

    @gl.public.write.payable
    def register_policy(
        self,
        target: str,
        rules: str,
        max_drawdown_bps: int,
        throttle_bps: int,
        min_confidence: int,
        min_stake: int,
        bounty: int,
    ) -> None:
        """Register (or replace) the policy guarding `target`. Value sent funds bounties."""
        t = Address(target)
        if max_drawdown_bps < 0 or max_drawdown_bps > 10000:
            raise gl.vm.UserError("max_drawdown_bps out of range")
        if throttle_bps < 0 or throttle_bps > 10000:
            raise gl.vm.UserError("throttle_bps out of range")
        if min_confidence < 0 or min_confidence > 100:
            raise gl.vm.UserError("min_confidence out of range")
        if t in self.policies and self.policies[t].owner != gl.message.sender_address:
            raise gl.vm.UserError("policy owned by someone else")
        if t not in self.policies:
            self.targets.append(t)
        self.policies[t] = Policy(
            owner=gl.message.sender_address,
            target=t,
            rules=rules,
            max_drawdown_bps=u256(max_drawdown_bps),
            throttle_bps=u256(throttle_bps),
            min_confidence=u256(min_confidence),
            min_stake=u256(min_stake),
            bounty=u256(bounty),
            active=True,
            halted=False,
            incidents=u256(0),
        )
        self.treasury = u256(self.treasury + gl.message.value)

    @gl.public.write.payable
    def fund(self) -> None:
        """Top up the bounty treasury."""
        self.treasury = u256(self.treasury + gl.message.value)

    @gl.public.write
    def lift_halt(self, target: str) -> None:
        """Policy owner resumes the target after remediation."""
        t = Address(target)
        p = self._policy(t)
        if p.owner != gl.message.sender_address:
            raise gl.vm.UserError("only policy owner")
        p.halted = False
        GuardedTarget(t).emit(on="finalized").unpause()

    # ------------------------------------------------------------------ layer 1: deterministic tripwire

    @gl.public.write
    def check_health(self, target: str) -> str:
        """
        Anyone (a keeper bot, a user, another contract) can call this.
        Reads the target's live status and enforces hard numeric limits.
        No LLM involved — cheap, instant, fully deterministic.
        """
        t = Address(target)
        p = self._policy(t)
        if not p.active or p.halted:
            return "skipped"
        status = GuardedTarget(t).view().get_status()
        drawdown = int(status.get("drawdown_bps", 0))
        if p.max_drawdown_bps > 0 and drawdown >= int(p.max_drawdown_bps):
            reason = "tripwire: drawdown " + str(drawdown) + " bps >= limit " + str(int(p.max_drawdown_bps))
            self._record(t, gl.message.sender_address, "", "automatic health check",
                         "tripwire", 5, 100, reason, 0)
            self._pause(t, reason)
            return "paused"
        return "healthy"

    # ------------------------------------------------------------------ layer 2: evidence-based judgment

    @gl.public.write.payable
    def report_incident(self, target: str, evidence_url: str, description: str) -> str:
        """
        Report a suspected exploit / anomaly with a URL as evidence.
        Validators fetch the evidence, look at the target's live state and
        reach consensus on an action. Returns the action taken.
        """
        t = Address(target)
        p = self._policy(t)
        if not p.active:
            raise gl.vm.UserError("policy inactive")
        if p.halted:
            raise gl.vm.UserError("target already halted")
        stake = gl.message.value
        if stake < p.min_stake:
            raise gl.vm.UserError("insufficient stake")
        if not (evidence_url.startswith("https://") or evidence_url.startswith("http://")):
            raise gl.vm.UserError("evidence_url must be http(s)")

        # --- everything the non-deterministic block needs is copied to memory first
        #     (storage and cross-contract calls are not allowed inside it)
        status = GuardedTarget(t).view().get_status()
        status_json = json.dumps(_plain(status), sort_keys=True)
        rules = p.rules
        min_confidence = int(p.min_confidence)
        url = evidence_url
        desc = description[:1000]

        def leader_fn() -> dict:
            resp = gl.nondet.web.get(url)
            body = resp.body.decode("utf-8", errors="replace") if resp.body else ""
            evidence = body[:EVIDENCE_LIMIT]
            prompt = _build_prompt(rules, status_json, desc, evidence)
            raw = gl.nondet.exec_prompt(prompt, response_format="json")
            return _normalize_verdict(raw, min_confidence)

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return False
            mine = leader_fn()
            theirs = leader_result.calldata
            if not isinstance(theirs, dict):
                return False
            # Decision fields must match; free-text reasoning may differ.
            if theirs.get("action") != mine.get("action"):
                return False
            if abs(int(theirs.get("severity", 0)) - int(mine.get("severity", 0))) > 1:
                return False
            return True

        verdict = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        action = str(verdict["action"])
        severity = int(verdict["severity"])
        confidence = int(verdict["confidence"])
        reason = str(verdict["reason"])[:500]
        reporter = gl.message.sender_address

        self._record(t, reporter, evidence_url, desc, action, severity, confidence, reason, int(stake))

        if action == "pause":
            self._pause(t, "sentinel: " + reason)
            self._reward(reporter, stake, p.bounty)
        elif action == "throttle":
            GuardedTarget(t).emit(on="accepted").set_max_withdraw_bps(int(p.throttle_bps))
            self._reward(reporter, stake, u256(p.bounty // 2))
        else:
            # False alarm: stake is slashed into the treasury (anti-spam).
            self.treasury = u256(self.treasury + stake)
        return action

    # ------------------------------------------------------------------ rewards

    @gl.public.write
    def claim_rewards(self) -> None:
        who = gl.message.sender_address
        amount = self.rewards.get(who, u256(0))
        if amount == 0:
            raise gl.vm.UserError("nothing to claim")
        self.rewards[who] = u256(0)
        _Recipient(who).emit_transfer(value=amount)

    # ------------------------------------------------------------------ views

    @gl.public.view
    def get_policy(self, target: str) -> dict:
        p = self._policy(Address(target))
        return {
            "owner": p.owner.as_hex,
            "target": p.target.as_hex,
            "rules": p.rules,
            "max_drawdown_bps": int(p.max_drawdown_bps),
            "throttle_bps": int(p.throttle_bps),
            "min_confidence": int(p.min_confidence),
            "min_stake": int(p.min_stake),
            "bounty": int(p.bounty),
            "active": p.active,
            "halted": p.halted,
            "incidents": int(p.incidents),
        }

    @gl.public.view
    def list_targets(self) -> list:
        return [a.as_hex for a in self.targets]

    @gl.public.view
    def get_incident(self, incident_id: int) -> dict:
        if incident_id < 0 or incident_id >= len(self.incidents):
            raise gl.vm.UserError("no such incident")
        return _incident_dict(self.incidents[incident_id])

    @gl.public.view
    def list_incidents(self, target: str) -> list:
        t = Address(target)
        return [_incident_dict(i) for i in self.incidents if i.target == t]

    @gl.public.view
    def incident_count(self) -> int:
        return len(self.incidents)

    @gl.public.view
    def rewards_of(self, who: str) -> int:
        return int(self.rewards.get(Address(who), u256(0)))

    @gl.public.view
    def get_treasury(self) -> int:
        return int(self.treasury)

    # ------------------------------------------------------------------ internals

    def _policy(self, t: Address) -> Policy:
        if t not in self.policies:
            raise gl.vm.UserError("no policy for target")
        return self.policies[t]

    def _pause(self, t: Address, reason: str) -> None:
        self.policies[t].halted = True
        # 'accepted' = act as soon as initial consensus lands. An emergency
        # halt should not wait for the appeal window; the target's pause()
        # is idempotent so duplicate messages are harmless.
        GuardedTarget(t).emit(on="accepted").pause(reason[:200])

    def _reward(self, reporter: Address, stake: u256, bounty: u256) -> None:
        paid = bounty if bounty <= self.treasury else self.treasury
        self.treasury = u256(self.treasury - paid)
        self.rewards[reporter] = u256(self.rewards.get(reporter, u256(0)) + stake + paid)

    def _record(self, t: Address, reporter: Address, url: str, desc: str, action: str,
                severity: int, confidence: int, reason: str, stake: int) -> None:
        self.incidents.append(Incident(
            id=u256(len(self.incidents)),
            target=t,
            reporter=reporter,
            evidence_url=url,
            description=desc,
            action=action,
            severity=u256(severity),
            confidence=u256(confidence),
            reason=reason,
            stake=u256(stake),
            reported_at=str(gl.message_raw.get("datetime", "")),
        ))
        self.policies[t].incidents = u256(self.policies[t].incidents + 1)


# --------------------------------------------------------------------------- pure helpers

def _plain(x: typing.Any) -> typing.Any:
    """Make calldata-decoded values JSON-serialisable."""
    if isinstance(x, dict):
        return {str(k): _plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_plain(v) for v in x]
    if isinstance(x, Address):
        return x.as_hex
    if isinstance(x, bytes):
        return x.hex()
    return x


def _build_prompt(rules: str, status_json: str, description: str, evidence: str) -> str:
    return (
        "You are Sentinel, an autonomous on-chain circuit breaker guarding a smart contract.\n"
        "Decide whether the contract must be paused, throttled, or left running.\n\n"
        "SECURITY POLICY set by the protocol owner:\n"
        f"{rules}\n\n"
        "LIVE STATE of the guarded contract (JSON):\n"
        f"{status_json}\n\n"
        "REPORTER'S CLAIM:\n"
        f"{description}\n\n"
        "EVIDENCE fetched from the reporter's URL (may be truncated):\n"
        f"{evidence}\n\n"
        "Rules for your decision:\n"
        "- 'pause': evidence shows an active exploit, unauthorized drain, or a critical "
        "vulnerability that is being (or is about to be) exploited, AND it is consistent with the live state.\n"
        "- 'throttle': suspicious activity or a plausible but unconfirmed threat; limiting withdrawals is proportionate.\n"
        "- 'none': evidence is irrelevant, fabricated, generic, or contradicts the live state.\n"
        "- Be skeptical: a URL that merely claims 'hack' without concrete, specific, matching details is NOT enough.\n"
        "- The reporter is financially motivated; do not reward vague or copy-pasted reports.\n\n"
        "Respond with ONLY a JSON object, no markdown:\n"
        '{"action": "none" | "throttle" | "pause", "severity": 0-5, "confidence": 0-100, '
        '"reason": "one or two sentences"}'
    )


def _normalize_verdict(raw: typing.Any, min_confidence: int) -> dict:
    """Coerce the model output into a canonical, comparable decision."""
    data: dict = {}
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str):
        s = raw.strip()
        if s.startswith("```"):
            s = s.strip("`")
            if s.lower().startswith("json"):
                s = s[4:]
        try:
            data = json.loads(s)
        except Exception:
            data = {}
    action = str(data.get("action", "none")).strip().lower()
    if action not in ACTIONS:
        action = "none"
    severity = _clamp(data.get("severity", 0), 0, 5)
    confidence = _clamp(data.get("confidence", 0), 0, 100)
    reason = str(data.get("reason", ""))[:500]
    # Deterministic post-processing so every validator applies the same threshold.
    if confidence < min_confidence and action != "none":
        reason = f"(downgraded: confidence {confidence} < {min_confidence}) " + reason
        action = "none"
    return {"action": action, "severity": severity, "confidence": confidence, "reason": reason}


def _clamp(v: typing.Any, lo: int, hi: int) -> int:
    try:
        n = int(float(v))
    except Exception:
        n = lo
    return max(lo, min(hi, n))


def _incident_dict(i: Incident) -> dict:
    return {
        "id": int(i.id),
        "target": i.target.as_hex,
        "reporter": i.reporter.as_hex,
        "evidence_url": i.evidence_url,
        "description": i.description,
        "action": i.action,
        "severity": int(i.severity),
        "confidence": int(i.confidence),
        "reason": i.reason,
        "stake": int(i.stake),
        "reported_at": i.reported_at,
    }
