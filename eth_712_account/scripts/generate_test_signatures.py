#!/usr/bin/env python3
"""
Generate EIP-712 signatures for eth_712_account test cases.

This script generates signatures that match the hashing logic in eth_712_utils.cairo.
The signatures are used in test_execute_from_outside tests with actual calls.

Setup:
    cd eth_712_account/scripts
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

Usage:
    python generate_test_signatures.py

Dependencies: eth-account, web3 (see requirements.txt)
"""

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

# Test private key (same as used for existing test signatures)
# Address: 0xbF60187c5dFfA627249f1C3000A4168dbB9D7A1A
PRIVATE_KEY = "0xa6d86467b6ec9e161649b27edfd8519e75a2e1cf5f4c309c628706e6999780e8"

# Expected deployed contract address (deterministic from snforge)
# This is the lower 128 bits used in verifyingContract
EXPECTED_CONTRACT_ADDRESS = 0x651b6cc1595bcd7edddc42163b57e066956b8fba487dd781cd7e4b3a671ffe4

# Test constants matching test_utils.cairo
EXECUTE_AFTER = 1000
EXECUTE_BEFORE = 3000
TEST_NONCE = 1
ETH_CHAIN_ID = 1
ANY_CALLER = int.from_bytes(b"ANY_CALLER", "big")

MASK_128 = (1 << 128) - 1
MASK_250 = (1 << 250) - 1
# ERC20 Mock address - deterministic based on snforge deployment
ERC20_MOCK_ADDRESS = 0x405ea0439568d265140400aa7b31e896604406bdfa7e73e18dec06303c31c6c

# Test addresses for spender/recipient (matching test.cairo)
TEST_SPENDER = 0x1234
TEST_RECIPIENT = 0x5678

# Specific caller address for testing non-ANY_CALLER scenarios
SPECIFIC_CALLER = 0xCAFE

# Starknet chain ID for domain name (keccak of this string)
SN_CHAIN_ID = "SN_MAIN"


def keccak256(data: bytes) -> bytes:
    """Compute keccak256 hash."""
    return Web3.keccak(data)


def keccak256_str(s: str) -> bytes:
    """Compute keccak256 of a string."""
    return keccak256(s.encode("utf-8"))


def to_bytes32(val: int) -> bytes:
    """Convert u256 to 32 bytes (big-endian)."""
    return val.to_bytes(32, "big")


def hash_felt_array(felts: list[int]) -> bytes:
    """Hash an array of felts (keccak of concatenated 32-byte representations)."""
    data = b"".join(to_bytes32(f) for f in felts)
    return keccak256(data)


# Type hashes (must match eth_712_utils.cairo)
EIP712_DOMAIN_TYPE_HASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f
CALL_TYPE_HASH = 0x7793b9bed3b87c6119fe923f0da4e85e1f97a03272a446514622ee7bd62ad25f
OUTSIDE_EXECUTION_TYPE_HASH = 0x57fbef2abe14202f3651b3935a8feddd357b8f83a862e046239d196ec76f281e
VERSION_HASH = 0xad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5


def hash_call(call: dict) -> bytes:
    """
    Hash a Call struct matching push_call in eth_712_utils.cairo.

    call = {"to": int, "selector": int, "calldata": list[int]}
    """
    # Hash: keccak(CALL_TYPE_HASH || to || selector || hash(calldata))
    data = (
        to_bytes32(CALL_TYPE_HASH)
        + to_bytes32(call["to"])
        + to_bytes32(call["selector"])
        + hash_felt_array(call["calldata"])
    )
    return keccak256(data)


def hash_call_array(calls: list[dict]) -> bytes:
    """Hash an array of Calls (keccak of concatenated call hashes)."""
    data = b"".join(hash_call(c) for c in calls)
    return keccak256(data)


def hash_outside_execution(outside_execution: dict) -> bytes:
    """
    Hash OutsideExecution struct matching push_outside_execution in eth_712_utils.cairo.

    NOTE: The Cairo code hashes fields in this order:
    1. OUTSIDE_EXECUTION_TYPE_HASH
    2. hash(calls)
    3. caller
    4. nonce
    5. execute_after
    6. execute_before
    """
    calls_hash = hash_call_array(outside_execution["calls"])

    data = (
        to_bytes32(OUTSIDE_EXECUTION_TYPE_HASH)
        + calls_hash
        + to_bytes32(outside_execution["caller"])
        + to_bytes32(outside_execution["nonce"])
        + to_bytes32(outside_execution["execute_after"])
        + to_bytes32(outside_execution["execute_before"])
    )
    return keccak256(data)


def get_domain_separator(contract_address: int, evm_chain_id: int, sn_chain_name: str) -> bytes:
    """
    Compute EIP-712 domain separator matching push_domain_separator in eth_712_utils.cairo.

    Domain fields:
    - name: keccak(sn_chain_name)
    - version: VERSION_HASH (keccak("2"))
    - chainId: evm_chain_id
    - verifyingContract: lower 128 bits of contract_address
    """
    name_hash = keccak256_str(sn_chain_name)

    # verifyingContract is the lower 128 bits of the contract address
    verifying_contract = contract_address & MASK_128

    data = (
        to_bytes32(EIP712_DOMAIN_TYPE_HASH)
        + name_hash
        + to_bytes32(VERSION_HASH)
        + to_bytes32(evm_chain_id)
        + to_bytes32(verifying_contract)
    )
    return keccak256(data)


def get_message_hash(
    outside_execution: dict,
    contract_address: int,
    evm_chain_id: int,
    sn_chain_name: str = SN_CHAIN_ID,
) -> bytes:
    """
    Compute the full EIP-712 message hash matching get_outside_execution_hash in eth_712_utils.cairo.

    Format: keccak(0x19 || 0x01 || domain_separator || struct_hash)
    """
    domain_separator = get_domain_separator(contract_address, evm_chain_id, sn_chain_name)
    struct_hash = hash_outside_execution(outside_execution)

    data = b"\x19\x01" + domain_separator + struct_hash
    return keccak256(data)


def sign_outside_execution(
    outside_execution: dict,
    contract_address: int,
    evm_chain_id: int = ETH_CHAIN_ID,
    sn_chain_name: str = SN_CHAIN_ID,
    private_key: str = PRIVATE_KEY,
) -> dict:
    """
    Sign an OutsideExecution and return signature components.

    Returns: {"r_high", "r_low", "s_high", "s_low", "v", "chain_id"}
    """
    msg_hash = get_message_hash(outside_execution, contract_address, evm_chain_id, sn_chain_name)

    # Sign using eth_account
    account = Account.from_key(private_key)
    signed = account.unsafe_sign_hash(msg_hash)

    r = signed.r
    s = signed.s
    v = signed.v

    # Split r and s into high/low 128-bit parts (for Cairo felt252)
    r_high = r >> 128
    r_low = r & ((1 << 128) - 1)
    s_high = s >> 128
    s_low = s & ((1 << 128) - 1)

    return {
        "r_high": r_high,
        "r_low": r_low,
        "s_high": s_high,
        "s_low": s_low,
        "v": v,
        "chain_id": evm_chain_id,
    }


def format_signature_cairo(sig: dict, name: str) -> str:
    """Format signature as Cairo code."""
    return f"""/// Signature for {name}
pub fn get_{name}_signature() -> Array<felt252> {{
    array![
        0x{sig['r_high']:032x}, // r_high
        0x{sig['r_low']:032x}, // r_low
        0x{sig['s_high']:032x}, // s_high
        0x{sig['s_low']:032x}, // s_low
        {sig['v']}, // v
        {sig['chain_id']} // chain_id (EVM)
    ]
}}
"""


def selector(name: str) -> int:
    """Compute Starknet selector (sn_keccak of function name)."""
    # sn_keccak is keccak256 with the top 250 bits
    h = keccak256_str(name)
    val = int.from_bytes(h, "big")
    # Mask to 250 bits (felt252 constraint)
    return val & MASK_250


# ============================================================================
# Test Case Definitions
# ============================================================================

def generate_single_call_approve_test(
    contract_address: int,
    token_address: int,
    spender: int,
    amount: int,
) -> tuple[dict, dict]:
    """
    Generate OutsideExecution for single approve call test.

    Returns: (outside_execution, signature)
    """
    # approve(spender: ContractAddress, amount: u256)
    # calldata: [spender, amount_low, amount_high]
    amount_low = amount & MASK_128
    amount_high = amount >> 128

    call = {
        "to": token_address,
        "selector": selector("approve"),
        "calldata": [spender, amount_low, amount_high],
    }

    outside_execution = {
        "caller": ANY_CALLER,
        "nonce": TEST_NONCE,
        "execute_after": EXECUTE_AFTER,
        "execute_before": EXECUTE_BEFORE,
        "calls": [call],
    }

    sig = sign_outside_execution(outside_execution, contract_address)
    return outside_execution, sig


def generate_multi_call_test(
    contract_address: int,
    token_address: int,
    spender: int,
    recipient: int,
    approve_amount: int,
    transfer_amount: int,
) -> tuple[dict, dict]:
    """
    Generate OutsideExecution for multi-call test (approve + transfer).

    Returns: (outside_execution, signature)
    """
    approve_low = approve_amount & MASK_128
    approve_high = approve_amount >> 128
    transfer_low = transfer_amount & MASK_128
    transfer_high = transfer_amount >> 128

    calls = [
        {
            "to": token_address,
            "selector": selector("approve"),
            "calldata": [spender, approve_low, approve_high],
        },
        {
            "to": token_address,
            "selector": selector("transfer"),
            "calldata": [recipient, transfer_low, transfer_high],
        },
    ]

    outside_execution = {
        "caller": ANY_CALLER,
        "nonce": 2,  # Different nonce for this test
        "execute_after": EXECUTE_AFTER,
        "execute_before": EXECUTE_BEFORE,
        "calls": calls,
    }

    sig = sign_outside_execution(outside_execution, contract_address)
    return outside_execution, sig


def generate_atomicity_test(
    contract_address: int,
    token_address: int,
    spender: int,
    recipient: int,
    approve_amount: int,
    transfer_amount: int,  # Should be > balance to cause revert
) -> tuple[dict, dict]:
    """
    Generate OutsideExecution for atomicity test (approve succeeds, transfer fails).

    Returns: (outside_execution, signature)
    """
    approve_low = approve_amount & MASK_128
    approve_high = approve_amount >> 128
    transfer_low = transfer_amount & MASK_128
    transfer_high = transfer_amount >> 128

    calls = [
        {
            "to": token_address,
            "selector": selector("approve"),
            "calldata": [spender, approve_low, approve_high],
        },
        {
            "to": token_address,
            "selector": selector("transfer"),
            "calldata": [recipient, transfer_low, transfer_high],
        },
    ]

    outside_execution = {
        "caller": ANY_CALLER,
        "nonce": 3,  # Different nonce for this test
        "execute_after": EXECUTE_AFTER,
        "execute_before": EXECUTE_BEFORE,
        "calls": calls,
    }

    sig = sign_outside_execution(outside_execution, contract_address)
    return outside_execution, sig


def generate_specific_caller_test(
    contract_address: int,
    caller: int,
    nonce: int,
) -> tuple[dict, dict]:
    """
    Generate OutsideExecution with a specific caller (not ANY_CALLER).
    Uses empty calls for simplicity.

    Returns: (outside_execution, signature)
    """
    outside_execution = {
        "caller": caller,
        "nonce": nonce,
        "execute_after": EXECUTE_AFTER,
        "execute_before": EXECUTE_BEFORE,
        "calls": [],
    }

    sig = sign_outside_execution(outside_execution, contract_address)
    return outside_execution, sig


def main():
    """Generate and print all test signatures."""
    print("=" * 80)
    print("EIP-712 Test Signature Generator for eth_712_account")
    print("=" * 80)
    print()

    contract_address = EXPECTED_CONTRACT_ADDRESS
    token_address = ERC20_MOCK_ADDRESS
    spender = TEST_SPENDER
    recipient = TEST_RECIPIENT

    # Nonces matching test_utils.cairo
    NONCE_SINGLE_CALL = 100
    NONCE_MULTI_CALL = 101
    NONCE_ATOMICITY = 102
    NONCE_SPECIFIC_CALLER = 103

    # Test amounts (matching test.cairo).
    APPROVE_AMOUNT = 500
    TRANSFER_AMOUNT = 100
    INITIAL_SUPPLY = 1000

    print(f"Contract address: 0x{contract_address:064x}")
    print(f"Token address: 0x{token_address:064x}")
    print(f"Spender: 0x{spender:x}")
    print(f"Recipient: 0x{recipient:x}")
    print()

    print("Test 1: Single Call (approve 500 tokens)")
    print("-" * 40)

    # OSE: OutsideExecution.
    ose, sig = generate_single_call_approve_test(
        contract_address=contract_address,
        token_address=token_address,
        spender=spender,
        amount=APPROVE_AMOUNT,
    )
    # Override nonce to match test.
    ose["nonce"] = NONCE_SINGLE_CALL
    sig = sign_outside_execution(ose, contract_address)
    print(f"Nonce: {NONCE_SINGLE_CALL}")
    print(format_signature_cairo(sig, "single_call_approve"))

    print()
    print("Test 2: Multi Call (approve 500 + transfer 100)")
    print("-" * 40)
    ose, sig = generate_multi_call_test(
        contract_address=contract_address,
        token_address=token_address,
        spender=spender,
        recipient=recipient,
        approve_amount=APPROVE_AMOUNT,
        transfer_amount=TRANSFER_AMOUNT,
    )
    # Override nonce to match test.
    ose["nonce"] = NONCE_MULTI_CALL
    sig = sign_outside_execution(ose, contract_address)
    print(f"Nonce: {NONCE_MULTI_CALL}")
    print(format_signature_cairo(sig, "multi_call"))

    print()
    print("Test 3: Atomicity (approve 500 + transfer 1001 - fails)")
    print("-" * 40)
    ose, sig = generate_atomicity_test(
        contract_address=contract_address,
        token_address=token_address,
        spender=spender,
        recipient=recipient,
        approve_amount=APPROVE_AMOUNT,
        transfer_amount=INITIAL_SUPPLY + 1,  # More than balance.
    )
    # Override nonce to match test
    ose["nonce"] = NONCE_ATOMICITY
    sig = sign_outside_execution(ose, contract_address)
    print(f"Nonce: {NONCE_ATOMICITY}")
    print(format_signature_cairo(sig, "atomicity_test"))

    print()
    print("Test 4: Specific Caller (non-ANY_CALLER)")
    print("-" * 40)
    ose, sig = generate_specific_caller_test(
        contract_address=contract_address,
        caller=SPECIFIC_CALLER,
        nonce=NONCE_SPECIFIC_CALLER,
    )
    print(f"Nonce: {NONCE_SPECIFIC_CALLER}")
    print(f"Caller: 0x{SPECIFIC_CALLER:x}")
    print(format_signature_cairo(sig, "specific_caller"))

    print()
    print("=" * 80)
    print("Copy the signatures above into test_utils.cairo")
    print("=" * 80)


if __name__ == "__main__":
    main()
