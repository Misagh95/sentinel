#!/usr/bin/env python3
"""
Deploy GuardedVault + Sentinel to a GenLayer network and wire them together.

    # Local Studio (docker) or glsim:
    python scripts/deploy.py --network localnet

    # Hosted Studio / testnets (needs a funded key):
    export ACCOUNT_PRIVATE_KEY=0x...
    python scripts/deploy.py --network studionet
    python scripts/deploy.py --network testnet_asimov

Writes deployments/<network>.json with both addresses for the frontend/README.
"""
import argparse
import json
import os
import sys
from pathlib import Path

from genlayer_py import create_client, create_account
from genlayer_py import chains
from genlayer_py.types import TransactionStatus

ROOT = Path(__file__).resolve().parents[1]

RULES = ("Pause immediately on any unauthorized transfer of reserves, any access-control or reentrancy "
         "exploit, or any single outflow above 25% of reserves. Throttle on credible but unconfirmed "
         "threats. Ignore generic news, rumors and unrelated incidents.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", default="localnet", choices=["localnet", "studionet", "testnet_asimov", "testnet_bradbury"])
    ap.add_argument("--endpoint", default=None, help="override RPC url (e.g. http://127.0.0.1:4000/api for glsim)")
    ap.add_argument("--fund", type=int, default=0, help="GEN (wei) to seed the Sentinel bounty treasury")
    a = ap.parse_args()

    chain = getattr(chains, a.network)
    pk = os.environ.get("ACCOUNT_PRIVATE_KEY")
    account = create_account(pk) if pk else create_account()
    client = create_client(chain=chain, endpoint=a.endpoint, account=account)
    print(f"network={a.network} deployer={account.address}")

    def deploy(name, args=None):
        code = (ROOT / "contracts" / name).read_text()
        tx = client.deploy_contract(code=code, args=args or [])
        rcpt = client.wait_for_transaction_receipt(transaction_hash=tx, status=TransactionStatus.ACCEPTED, retries=60)
        addr = rcpt["data"]["contract_address"]
        print(f"  deployed {name:<12} -> {addr}")
        return addr

    def write(addr, fn, args, value=0):
        tx = client.write_contract(address=addr, function_name=fn, args=args, value=value)
        client.wait_for_transaction_receipt(transaction_hash=tx, status=TransactionStatus.ACCEPTED, retries=60)
        print(f"  {fn}({', '.join(str(x)[:24] for x in args)}) ok")

    vault = deploy("vault.py")
    sentinel = deploy("sentinel.py")
    write(vault, "set_guardian", [sentinel])
    write(sentinel, "register_policy",
          [vault, RULES, 3000, 1000, 70, 10, 100], value=a.fund)

    out = ROOT / "deployments"
    out.mkdir(exist_ok=True)
    (out / f"{a.network}.json").write_text(json.dumps(
        {"network": a.network, "vault": vault, "sentinel": sentinel, "deployer": account.address}, indent=2))
    print(f"\nwrote deployments/{a.network}.json")
    print("status:", client.read_contract(address=vault, function_name="get_status", args=[]))


if __name__ == "__main__":
    sys.exit(main())
