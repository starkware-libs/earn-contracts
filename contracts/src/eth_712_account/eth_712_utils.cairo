use core::integer::u256;
use core::keccak::compute_keccak_byte_array;
use openzeppelin::account::extensions::src9::OutsideExecution;
use starknet::account::Call;
use starknet::eth_address::EthAddress;
use starknet::eth_signature::public_key_point_to_eth_address;
use starknet::secp256_trait::{Signature, recover_public_key};
use starknet::secp256k1::Secp256k1Point;

// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
const EIP712_DOMAIN_TYPE_HASH: u256 =
    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f_u256;

// keccak256("Call(uint256 address,uint256 selector,uint256[] data)")
const CALL_TYPE_HASH: u256 =
    0x7793b9bed3b87c6119fe923f0da4e85e1f97a03272a446514622ee7bd62ad25f_u256;

const OUTSIDE_EXECUTION_TYPE_HASH: u256 =
    0x57fbef2abe14202f3651b3935a8feddd357b8f83a862e046239d196ec76f281e_u256;

// keccak("Starknet")
const NAME_HASH: u256 = 0xc3396425150568dfb7fcdc8d6f89c8846fe7f8f6c00a83ff9e5eb0424d62d7c3_u256;

// keccak("2") (version of the EIP-712 domain).
const VERSION_HASH: u256 = 0xad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5_u256;

// keccak256("\x19Ethereum Signed Message:\n41Sign to verify that you own this account.")
// msg_hash of the account ownership message. (Fixed per all chains).
const OWNERSHIP_TRANSFER_MSG_HASH: u256 =
    0x3ce976d55131cd0bdd49f20afbded052d8e907dc6034d95cdf117a8fd7752e3c_u256;

/// Adds a felt252 to the byte array (as 32 bytes).
fn push_felt(ref res: ByteArray, val: felt252) {
    push_u256(ref res, val.into());
}

/// Adds a u256 to the byte array (as 32 bytes) in reverse order.
fn push_u256_reverse(ref res: ByteArray, val: u256) {
    res.append_word_rev(val.low.into(), 16);
    res.append_word_rev(val.high.into(), 16);
}

/// Adds a u256 to the byte array `val.high` and then `val.low`.
fn push_u256(ref res: ByteArray, val: u256) {
    res.append_word(val.high.into(), 16);
    res.append_word(val.low.into(), 16);
}

/// Adds a span of felt252 to the byte array (as the hash of the concatenation of the felts).
fn push_felt_array(ref res: ByteArray, felts: Span<felt252>) {
    let mut byte_array: ByteArray = "";
    for x in felts {
        push_felt(ref byte_array, *x);
    }
    push_keccak(ref res, @byte_array);
}

pub fn push_keccak(ref res: ByteArray, byte_array: @ByteArray) {
    push_u256_reverse(ref res, compute_keccak_byte_array(byte_array));
}

pub fn push_call(ref res: ByteArray, call: @Call) {
    let mut byte_array: ByteArray = "";
    let Call { to, selector, calldata } = *call;
    // Push type hash.
    push_u256(ref byte_array, CALL_TYPE_HASH);

    push_felt(ref byte_array, to.into());
    push_felt(ref byte_array, selector);
    push_felt_array(ref byte_array, calldata);
    push_keccak(ref res, @byte_array);
}

/// Adds an array of Call to the byte array (as the hash of the concatenation of the Calls).
fn push_call_array(ref res: ByteArray, calls: Span<Call>) {
    let mut byte_array: ByteArray = "";
    for x in calls {
        push_call(ref byte_array, x);
    }
    push_keccak(ref res, @byte_array);
}

pub fn push_outside_execution(ref res: ByteArray, outside_execution: @OutsideExecution) {
    let mut byte_array: ByteArray = "";

    push_u256(ref byte_array, OUTSIDE_EXECUTION_TYPE_HASH);
    let OutsideExecution {
        caller, nonce, execute_after, execute_before, calls,
    } = *outside_execution;

    push_call_array(ref byte_array, calls);
    push_felt(ref byte_array, caller.into());
    push_felt(ref byte_array, nonce);
    push_felt(ref byte_array, execute_after.into());
    push_felt(ref byte_array, execute_before.into());

    push_u256_reverse(ref res, compute_keccak_byte_array(@byte_array));
}

pub fn push_domain_separator(ref res: ByteArray, chain_id: felt252) {
    let mut byte_array: ByteArray = "";

    push_u256(ref byte_array, EIP712_DOMAIN_TYPE_HASH);
    push_u256(ref byte_array, NAME_HASH);
    push_u256(ref byte_array, VERSION_HASH);
    push_u256(ref byte_array, chain_id.into());

    // For the verifyingContract field we push Zero address.
    push_u256(ref byte_array, 0_u256);

    push_keccak(ref res, @byte_array);
}

pub fn get_outside_execution_hash(outside_execution: @OutsideExecution, chain_id: felt252) -> u256 {
    let mut byte_array: ByteArray = "";

    // EIP-191 header.
    byte_array.append_byte(0x19);
    byte_array.append_byte(0x1);

    push_domain_separator(ref byte_array, chain_id);
    push_outside_execution(ref byte_array, outside_execution);

    let msg_hash = compute_keccak_byte_array(@byte_array);
    u256 {
        low: core::integer::u128_byte_reverse(msg_hash.high),
        high: core::integer::u128_byte_reverse(msg_hash.low),
    }
}

/// Returns the eth address of the signer of the message, or None if the signature is malformed.
pub fn recover_eth_address(msg_hash: u256, signature: Signature) -> Option<EthAddress> {
    let public_key_point = recover_public_key::<Secp256k1Point>(:msg_hash, :signature)?;
    Some(public_key_point_to_eth_address(:public_key_point))
}

pub fn extract_signature(signature: Span<felt252>) -> (Signature, felt252) {
    assert(signature.len() == 6, 'INVALID_SIGNATURE_LENGTH');
    let r_high: u128 = (*signature[0]).try_into().unwrap();
    let r_low: u128 = (*signature[1]).try_into().unwrap();
    let s_high: u128 = (*signature[2]).try_into().unwrap();
    let s_low: u128 = (*signature[3]).try_into().unwrap();
    let r = u256 { low: r_low, high: r_high };
    let s = u256 { low: s_low, high: s_high };
    let v: u128 = (*signature[4]).try_into().unwrap();
    let chain_id = *signature[5];
    (Signature { r, s, y_parity: v % 2 == 0 }, chain_id)
}

/// Returns `true` if the signature is valid for the given message hash and eth address.
pub fn is_valid_signature(msg_hash: u256, signature: Signature, eth_address: EthAddress) -> bool {
    recover_eth_address(:msg_hash, :signature) == Some(eth_address)
}

/// Asserts eth address ownership signature is valid.
pub fn assert_valid_owner(eth_address: EthAddress, signature: Signature) {
    let msg_hash = OWNERSHIP_TRANSFER_MSG_HASH;
    assert(is_valid_signature(:msg_hash, :signature, :eth_address), 'INVALID_OWNERSHIP_SIGNATURE');
}
