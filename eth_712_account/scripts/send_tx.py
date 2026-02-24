#!/usr/bin/env python3
"""
Send InvokeV3 transactions or build EFO (Execute From Outside) calldata
for the eth_712_account contract on Starknet.

Modes:
  Regular TX: Signs and sends an InvokeV3 transaction (__validate__ -> __execute__).
  EFO (--efo): Signs an OutsideExecution and prints the calldata for execute_from_outside_v2.

Both modes use the same dynamic EIP-712 domain separator (matching eth_712_utils.cairo):
- name: keccak(SN_CHAIN_ID)
- verifyingContract: contract_address_low (lower 128 bits)
- Signature is 6 felts: [r_high, r_low, s_high, s_low, v, evm_chain_id]

Setup:
    cd eth_712_account/scripts
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Examples:
    # Regular transaction (STRK approval)
    ./send_tx.py -a 0x1234...

    # Dry run
    ./send_tx.py -a 0x1234... --dry-run

    # EFO with ANY_CALLER (default)
    ./send_tx.py -a 0x1234... --efo

    # EFO with specific caller
    ./send_tx.py -a 0x1234... --efo --sender 0xCAFE

    # EFO with custom calls
    ./send_tx.py -a 0x1234... --efo --calls calls.json --nonce 42
"""

import argparse
import asyncio
import json
import os
import time
import warnings

import aiohttp
from eth_account import Account
from starknet_py.net.client_models import ResourceBounds, ResourceBoundsMapping
from starknet_py.net.full_node_client import FullNodeClient
from starknet_py.net.models.transaction import InvokeV3

from eip712 import (
    ANY_CALLER,
    L1_DATA_ID,
    L1_GAS_ID,
    L2_GAS_ID,
    MASK_128,
    domain_separator,
    hash_outside_execution,
    hash_transaction,
    outside_execution_msg_hash,
    sign_and_split,
    to_bytes32,
    transaction_msg_hash,
)

warnings.filterwarnings("ignore", category=UserWarning, module="starknet_py")

# ============================================================================
# Configuration defaults
# ============================================================================

DEFAULT_RPC_URL = os.environ.get("STARKNET_RPC")
DEFAULT_ETH_PRIVATE_KEY = "0xa6d86467b6ec9e161649b27edfd8519e75a2e1cf5f4c309c628706e6999780e8"
DEFAULT_SN_CHAIN_ID = "SN_SEPOLIA"
DEFAULT_EVM_CHAIN_ID = 1

DEFAULT_CALL = {
    "address": "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
    "selector": "0x219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c",
    "data": [
        "0x6a9125a67b0c35f1e760421f7699d82e600d6ddf3f5503a629f389d94b704ba",
        "0x0",
        "0x0",
    ],
}

# ============================================================================
# Input parsing helpers
# ============================================================================


def to_int(v) -> int:
    """Convert hex string or int to int."""
    return int(str(v), 0)


def parse_chain_id(value: str) -> str:
    """Parse chain ID text (e.g. 'SN_SEPOLIA'). Returned as-is for domain hashing."""
    return value


def sn_chain_name_to_felt(name: str) -> int:
    """Convert chain name string to felt252 (for metadata.chain_id)."""
    return int.from_bytes(name.encode("ascii"), "big")


def normalize_call(call: dict) -> dict:
    """Convert JSON call format (address/data) to canonical format (to/calldata)."""
    return {
        "to": to_int(call["address"]),
        "selector": to_int(call["selector"]),
        "calldata": [to_int(x) for x in call["data"]],
    }


def load_calls_from_json(filepath: str) -> list:
    """Load calls array from a JSON file."""
    calls = json.load(open(filepath))
    if not isinstance(calls, list):
        calls = [calls]
    return calls


# ============================================================================
# Resource bounds
# ============================================================================


def build_resource_bounds() -> ResourceBoundsMapping:
    """
    Build ResourceBoundsMapping for the transaction.
    The values are good for all typical transactions.
    """
    return ResourceBoundsMapping(
        l1_gas=ResourceBounds(max_amount=0x0, max_price_per_unit=0x1000000000000000),
        l1_data_gas=ResourceBounds(max_amount=0x1000, max_price_per_unit=0x10000000000000),
        l2_gas=ResourceBounds(max_amount=0x5F5E100, max_price_per_unit=0x2540BE400),
    )


def rb_mapping_to_felts(rb: ResourceBoundsMapping) -> list[int]:
    """Convert ResourceBoundsMapping to 9-felt array for EIP-712 signing."""
    return [
        L1_GAS_ID, rb.l1_gas.max_amount, rb.l1_gas.max_price_per_unit,
        L2_GAS_ID, rb.l2_gas.max_amount, rb.l2_gas.max_price_per_unit,
        L1_DATA_ID, rb.l1_data_gas.max_amount, rb.l1_data_gas.max_price_per_unit,
    ]


# ============================================================================
# Call serialization (for Starknet calldata)
# ============================================================================


def serialize_calls_to_felts(calls: list) -> list:
    """Serialize a list of calls to felts for calldata."""
    n_calls = len(calls)
    rc_calls = [n_calls]

    for call in calls:
        call_felts = [call["address"], call["selector"]]
        data = call["data"]
        call_felts.append(len(data))
        call_felts.extend(data)

        call_felts = [to_int(r) for r in call_felts]
        rc_calls.extend(call_felts)
    return rc_calls


def serialize_efo_calldata(oe: dict, calls: list, signature: list) -> list:
    """Serialize OutsideExecution + signature as calldata for execute_from_outside_v2."""
    calldata = [oe["caller"], oe["nonce"], oe["execute_after"], oe["execute_before"]]
    calldata.append(len(calls))
    for call in calls:
        calldata.append(to_int(call["address"]))
        calldata.append(to_int(call["selector"]))
        data = call["data"]
        calldata.append(len(data))
        calldata.extend([to_int(d) for d in data])
    calldata.append(len(signature))
    calldata.extend(signature)
    return calldata


# ============================================================================
# RPC helpers
# ============================================================================


async def get_nonce(rpc_url: str, account_address: int) -> int:
    """Fetch the current nonce for the account."""
    payload = {
        "jsonrpc": "2.0",
        "method": "starknet_getNonce",
        "params": {"block_id": "pending", "contract_address": hex(account_address)},
        "id": 1,
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(rpc_url, json=payload) as response:
            result = await response.json()
            if "error" in result:
                raise Exception(f"RPC error: {result['error']}")
            return int(result["result"], 16)


# ============================================================================
# Transaction signing and sending
# ============================================================================


def sign_tx(
    calls: list[dict],
    metadata: dict,
    signer,
    sn_chain_name: str,
    contract_address: int,
    evm_chain_id: int,
    debug: bool = False,
) -> list:
    """Sign a transaction and return 6-felt signature list."""
    canonical_calls = [normalize_call(c) for c in calls]
    msg_hash = transaction_msg_hash(
        canonical_calls, metadata, sn_chain_name, contract_address, evm_chain_id,
    )
    if debug:
        ds = domain_separator(sn_chain_name, contract_address, evm_chain_id)
        sh = hash_transaction(canonical_calls, metadata)
        print(f"  Domain separator: {hex(ds)}")
        print(f"  Struct hash: {hex(sh)}")
        print(f"  Message hash: {hex(msg_hash)}")
    sig = sign_and_split(msg_hash, signer.key, evm_chain_id)
    return [sig["r_high"], sig["r_low"], sig["s_high"], sig["s_low"], sig["v"], sig["chain_id"]]


def build_invoke_v3(
    calls: list, sender_address: int, signature: list, nonce: int,
    resource_bounds: ResourceBoundsMapping, tip: int = 0, version: int = 3,
) -> InvokeV3:
    """Build an InvokeV3 transaction object."""
    calldata = serialize_calls_to_felts(calls)
    return InvokeV3(
        version=version,
        signature=signature,
        nonce=nonce,
        resource_bounds=resource_bounds,
        calldata=calldata,
        sender_address=sender_address,
        tip=tip,
    )


async def send_invoke_v3(
    calls: list, rpc_url: str, account_address: int, signer,
    sn_chain_name: str, evm_chain_id: int, dry_run: bool = False,
):
    """Prepare, sign, and send an InvokeV3 transaction."""
    sn_chain_id_felt = sn_chain_name_to_felt(sn_chain_name)
    print(f"Account: {hex(account_address)}")
    print(f"Signer ETH address: {signer.address}")
    print(f"RPC: {rpc_url}")
    print(f"SN Chain ID: {hex(sn_chain_id_felt)}")
    print(f"EVM Chain ID: {evm_chain_id}")

    on_chain_nonce = await get_nonce(rpc_url, account_address)
    print(f"On-chain nonce: {on_chain_nonce}")

    resource_bounds = build_resource_bounds()
    print(f"\nResource bounds:")
    print(f"  l1_gas: amount={hex(resource_bounds.l1_gas.max_amount)}, price={hex(resource_bounds.l1_gas.max_price_per_unit)}")
    print(f"  l1_data_gas: amount={hex(resource_bounds.l1_data_gas.max_amount)}, price={hex(resource_bounds.l1_data_gas.max_price_per_unit)}")
    print(f"  l2_gas: amount={hex(resource_bounds.l2_gas.max_amount)}, price={hex(resource_bounds.l2_gas.max_price_per_unit)}")

    metadata = {
        "version": 3,
        "chain_id": sn_chain_id_felt,
        "execution_resources": rb_mapping_to_felts(resource_bounds),
        "tip": 0,
        "nonce": on_chain_nonce,
    }

    print(f"\nSigning metadata:")
    print(f"  version: {metadata['version']}")
    print(f"  chain_id: {hex(metadata['chain_id'])}")
    print(f"  nonce: {metadata['nonce']}")

    print("\nSigning transaction...")
    print(f"  Execution resources (9 felts):")
    for i, v in enumerate(metadata["execution_resources"]):
        print(f"    [{i}]: {hex(v)}")
    signature = sign_tx(
        calls, metadata, signer, sn_chain_name, account_address, evm_chain_id, debug=True,
    )
    print(f"Signature: {[hex(s) for s in signature]}")

    invoke_tx = build_invoke_v3(calls, account_address, signature, on_chain_nonce, resource_bounds)
    print(f"\nInvokeV3 transaction:")
    print(f"  sender: {hex(invoke_tx.sender_address)}")
    print(f"  nonce: {invoke_tx.nonce}")
    print(f"  calldata length: {len(invoke_tx.calldata)}")

    tx_hash = invoke_tx.calculate_hash(chain_id=sn_chain_id_felt)
    print(f"  tx_hash: {hex(tx_hash)}")

    if dry_run:
        print("\n[DRY RUN] Transaction not sent.")
        return {"tx_hash": hex(tx_hash), "invoke_tx": invoke_tx}

    print("\nSending transaction...")
    try:
        client = FullNodeClient(node_url=rpc_url)
        result = await client.send_transaction(invoke_tx)
        print(f"Transaction sent! tx_hash: {hex(result.transaction_hash)}")
        return result.transaction_hash
    except Exception as e:
        print(f"Error: {e}")
        raise


# ============================================================================
# EFO (Execute From Outside) handling
# ============================================================================


def sign_efo(
    oe: dict, calls: list[dict], signer, sn_chain_name: str,
    contract_address: int, evm_chain_id: int, debug: bool = False,
) -> list:
    """Sign an OutsideExecution and return 6-felt signature list."""
    canonical_calls = [normalize_call(c) for c in calls]
    oe_with_calls = {**oe, "calls": canonical_calls}
    msg_hash = outside_execution_msg_hash(
        oe_with_calls, sn_chain_name, contract_address, evm_chain_id,
    )
    if debug:
        ds = domain_separator(sn_chain_name, contract_address, evm_chain_id)
        oe_hash = hash_outside_execution(oe_with_calls)
        print(f"  Domain separator: {hex(ds)}")
        print(f"  Struct hash: {hex(oe_hash)}")
        print(f"  Message hash: {hex(msg_hash)}")
    sig = sign_and_split(msg_hash, signer.key, evm_chain_id)
    return [sig["r_high"], sig["r_low"], sig["s_high"], sig["s_low"], sig["v"], sig["chain_id"]]


def handle_efo(args, calls, calls_source, signer, account_address, sn_chain_name):
    """Handle EFO mode: sign and print calldata for execute_from_outside_v2."""
    evm_chain_id = args.evm_chain_id
    caller = to_int(args.sender) if args.sender else ANY_CALLER
    nonce = args.nonce if args.nonce is not None else int(time.time())

    oe = {
        "caller": caller,
        "nonce": nonce,
        "execute_after": args.execute_after,
        "execute_before": args.execute_before,
    }

    print("=" * 60)
    print("ETH 712 Account - Execute From Outside (EFO)")
    print("=" * 60)
    print(f"\nAccount: {hex(account_address)}")
    print(f"Signer ETH address: {signer.address}")
    print(f"SN Chain ID: {sn_chain_name}")
    print(f"EVM Chain ID: {evm_chain_id}")

    caller_label = " (ANY_CALLER)" if caller == ANY_CALLER else ""
    print(f"\nOutsideExecution:")
    print(f"  caller: {hex(caller)}{caller_label}")
    print(f"  nonce: {nonce}")
    print(f"  execute_after: {oe['execute_after']}")
    print(f"  execute_before: {oe['execute_before']}")
    print(f"  calls ({calls_source}): {len(calls)}")
    for i, call in enumerate(calls, start=1):
        print(f"    [{i}] to={str(call['address'])[:20]}... selector={str(call['selector'])[:20]}...")

    print("\nSigning outside execution...")
    signature = sign_efo(
        oe, calls, signer, sn_chain_name, account_address, evm_chain_id, debug=True,
    )
    print(f"Signature: {[hex(s) for s in signature]}")

    calldata = serialize_efo_calldata(oe, calls, signature)
    calldata_hex = " ".join(hex(v) for v in calldata)

    print(f"\n{'=' * 60}")
    print("Calldata for execute_from_outside_v2:")
    print(f"{'=' * 60}")
    print(f"\nstarkli invoke {hex(account_address)} execute_from_outside_v2 \\")
    print(f"  {calldata_hex}")

    return calldata


# ============================================================================
# CLI and main
# ============================================================================


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Send InvokeV3 transaction to eth_712_account on Starknet",
    )
    parser.add_argument("--calls", "-c", help="JSON file containing calls array")
    parser.add_argument("--rpc", "-r", default=DEFAULT_RPC_URL, help="Starknet RPC URL")
    parser.add_argument("--account", "-a", required=True, help="eth_712_account contract address")
    parser.add_argument("--eth-private-key", "-k", default=DEFAULT_ETH_PRIVATE_KEY)
    parser.add_argument(
        "--sn-chain-id", default=DEFAULT_SN_CHAIN_ID,
        help=f"SN chain name (e.g. SN_SEPOLIA), default: {DEFAULT_SN_CHAIN_ID}",
    )
    parser.add_argument(
        "--evm-chain-id", type=int, default=DEFAULT_EVM_CHAIN_ID,
        help=f"EVM chain ID (default: {DEFAULT_EVM_CHAIN_ID})",
    )
    parser.add_argument("--dry-run", "-d", action="store_true", help="Prepare but do not send")
    parser.add_argument("--efo", action="store_true", help="EFO mode: print calldata, no tx sent")
    parser.add_argument("--sender", default=None, help="EFO caller address (default: ANY_CALLER)")
    parser.add_argument(
        "--nonce", type=int, default=None, help="EFO nonce (default: unix timestamp)",
    )
    parser.add_argument("--execute-after", type=int, default=0, help="EFO execute_after timestamp")
    parser.add_argument(
        "--execute-before", type=int, default=0xFFFFFFFFFFFFFFFF,
        help="EFO execute_before timestamp (default: 0xFFFFFFFFFFFFFFFF)",
    )
    return parser.parse_args()


async def main():
    """Main entry point."""
    args = parse_args()

    account_address = to_int(args.account)
    signer = Account.from_key(args.eth_private_key)
    sn_chain_name = args.sn_chain_id

    if args.calls:
        calls = load_calls_from_json(args.calls)
        calls_source = f"Loaded from: {args.calls}"
    else:
        calls = [DEFAULT_CALL]
        calls_source = "Default: [STRK approval]"

    if args.efo:
        return handle_efo(args, calls, calls_source, signer, account_address, sn_chain_name)

    print("=" * 60)
    print("ETH 712 Account - Send InvokeV3 Transaction")
    print("=" * 60)
    print(f"\nCalls ({calls_source}): {len(calls)}")
    for i, call in enumerate(calls, start=1):
        print(f"  [{i}] to={str(call['address'])[:20]}... selector={str(call['selector'])[:20]}...")

    return await send_invoke_v3(
        calls, args.rpc, account_address, signer, sn_chain_name, args.evm_chain_id, args.dry_run,
    )


if __name__ == "__main__":
    asyncio.run(main())
