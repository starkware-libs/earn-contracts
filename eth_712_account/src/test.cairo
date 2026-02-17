use eth_712_account::interface::{IAccount712AdminDispatcher, IAccount712AdminDispatcherTrait};
use eth_712_account::test_utils::{
    EXECUTE_AFTER, EXECUTE_BEFORE, MOCK_ERC20_INITIAL_SUPPLY, NONCE_ATOMICITY, NONCE_MULTI_CALL,
    NONCE_SINGLE_CALL, NONCE_SPECIFIC_CALLER, SPECIFIC_CALLER, TEST_ETH_ADDRESS, TEST_NONCE,
    build_approve_call, build_outside_execution_with_calls,
    build_outside_execution_with_specific_caller, build_transfer_call,
    declare_register_interfaces_eic, deploy_eth712_account, get_atomicity_test_signature,
    get_invalid_outside_execution_signature, get_invalid_signature, get_multi_call_signature,
    get_outside_execution_signature, get_ownership_signature, get_signature_evm_chain_id_2,
    get_signature_wrong_contract_address, get_signature_wrong_sn_chain_name,
    get_single_call_approve_signature, get_specific_caller_signature, get_test_outside_execution,
    setup_efo_test, setup_efo_test_with_erc20, setup_efo_test_with_timestamp,
};
use openzeppelin::account::extensions::src9::interface::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, ISRC9_V2SafeDispatcher,
    ISRC9_V2SafeDispatcherTrait, ISRC9_V2_ID,
};
use openzeppelin::account::interface::ISRC6_ID;
use openzeppelin::introspection::interface::{ISRC5Dispatcher, ISRC5DispatcherTrait};
use openzeppelin::token::erc20::interface::IERC20DispatcherTrait;
use snforge_std::{EventSpyTrait, load, spy_events};
use starknet::EthAddress;
use starkware_utils_testing::test_utils::cheat_caller_address_once;
use testing_utils::event_helpers::get_event_by_selector;

// ================================
// initialize tests
// ================================

#[test]
fn test_initialize_success() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize with valid signature
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Verify eth_address was stored correctly by reading storage directly
    let stored_values = load(account_address, selector!("eth_address"), 1);
    let stored_eth_address: EthAddress = (*stored_values.at(0)).try_into().unwrap();
    assert!(stored_eth_address == TEST_ETH_ADDRESS(), "eth_address not stored correctly");

    // Verify interfaces are registered
    let src5 = ISRC5Dispatcher { contract_address: account_address };
    assert!(src5.supports_interface(ISRC9_V2_ID), "ISRC9_V2_ID not registered");
    assert!(src5.supports_interface(ISRC6_ID), "ISRC6_ID not registered");
}

#[test]
#[should_panic(expected: 'ALREADY_INITIALIZED')]
fn test_initialize_already_initialized_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // First initialization should succeed
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Second initialization should fail
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());
}

#[test]
#[should_panic(expected: 'INVALID_OWNERSHIP_SIGNATURE')]
fn test_initialize_invalid_signature_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize with invalid signature
    account_contract.initialize(TEST_ETH_ADDRESS(), get_invalid_signature());
}

// ================================
// upgrade tests
// ================================

const DUMMY_CLASS_HASH: felt252 = 'DUMMY_CLASS_HASH';

#[test]
#[should_panic(expected: 'UNAUTHORIZED')]
fn test_upgrade_unauthorized_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize first
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Try to upgrade from external caller (not self) - reverts before checking class hash
    account_contract.upgrade(DUMMY_CLASS_HASH.try_into().unwrap(), Option::None);
}

#[test]
fn test_upgrade_from_self_succeeds() {
    let (account_address, class_hash) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize first
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Spoof caller as self for a single call
    cheat_caller_address_once(contract_address: account_address, caller_address: account_address);

    let mut spy = spy_events();
    account_contract.upgrade(class_hash, Option::None);

    // Verify Upgraded event was emitted
    let events = spy.get_events();
    let event_option = get_event_by_selector(events.events.span(), selector!("Upgraded"));
    assert!(event_option.is_some(), "Upgraded event not found");
    let (from, event) = event_option.unwrap();
    assert!(*from == account_address, "Event from wrong address");
    assert!(event.data.len() > 0, "Event has no data");
    let class_hash_felt: felt252 = class_hash.into();
    assert!(*event.data.at(0) == class_hash_felt, "Wrong class hash in event");
}

#[test]
fn test_upgrade_with_eic() {
    let (account_address, class_hash) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize first
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Spoof caller as self for a single call
    cheat_caller_address_once(contract_address: account_address, caller_address: account_address);

    let eic_class_hash = declare_register_interfaces_eic();

    // Register a custom interface via EIC
    let custom_interface_id: felt252 = 0x12345678;
    let eic_data: Span<felt252> = array![custom_interface_id].span();

    account_contract.upgrade(class_hash, Option::Some((eic_class_hash, eic_data)));

    // Verify the custom interface was registered
    let src5 = ISRC5Dispatcher { contract_address: account_address };
    assert!(src5.supports_interface(custom_interface_id), "Custom interface not registered");
}

// ================================
// execute_from_outside_v2 tests
// ================================

#[test]
fn test_execute_from_outside_success() {
    let src9 = setup_efo_test();
    let outside_execution = get_test_outside_execution();
    let signature = get_outside_execution_signature();

    // Execute - this should succeed
    src9.execute_from_outside_v2(outside_execution, signature.span());

    // Verify nonce is now used
    assert!(!src9.is_valid_outside_execution_nonce(TEST_NONCE), "Nonce should be marked as used");
}

#[test]
#[should_panic(expected: 'EXECUTED_TOO_EARLY')]
fn test_execute_from_outside_too_early_reverts() {
    let src9 = setup_efo_test_with_timestamp(EXECUTE_AFTER - 1);
    let outside_execution = get_test_outside_execution();
    let signature = get_outside_execution_signature();

    src9.execute_from_outside_v2(outside_execution, signature.span());
}

#[test]
#[should_panic(expected: 'EXECUTED_TOO_LATE')]
fn test_execute_from_outside_too_late_reverts() {
    let src9 = setup_efo_test_with_timestamp(EXECUTE_BEFORE + 1);
    let outside_execution = get_test_outside_execution();
    let signature = get_outside_execution_signature();

    src9.execute_from_outside_v2(outside_execution, signature.span());
}

#[test]
#[should_panic(expected: 'DUPLICATE_NONCE')]
fn test_execute_from_outside_duplicate_nonce_reverts() {
    let src9 = setup_efo_test();
    let outside_execution = get_test_outside_execution();
    let signature = get_outside_execution_signature();

    // First execution should succeed
    src9.execute_from_outside_v2(outside_execution, signature.span());

    // Second execution with same nonce should fail
    src9.execute_from_outside_v2(outside_execution, signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_invalid_signature_reverts() {
    let src9 = setup_efo_test();
    let outside_execution = get_test_outside_execution();
    let invalid_signature = get_invalid_outside_execution_signature();

    src9.execute_from_outside_v2(outside_execution, invalid_signature.span());
}

#[test]
fn test_is_valid_outside_execution_nonce() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };

    // Fresh nonces should be valid
    assert!(src9.is_valid_outside_execution_nonce(1), "Nonce 1 should be valid");
    assert!(src9.is_valid_outside_execution_nonce(2), "Nonce 2 should be valid");
    assert!(src9.is_valid_outside_execution_nonce(12345), "Nonce 12345 should be valid");
}

// ================================
// Domain separator validation tests
// ================================

#[test]
fn test_execute_from_outside_different_evm_chain_id_succeeds() {
    // NOTE: The EVM chain ID is passed WITH the signature (signature[5]) and is used
    // to compute the message hash. This means signatures from different EVM chains
    // are valid as long as they were signed with the correct domain separator.
    // This is by design - it allows signing from multiple EVM chains.
    let src9 = setup_efo_test();
    let outside_execution = get_test_outside_execution();

    // Signature generated with EVM chain ID 2 - valid because contract uses chain_id from signature
    let chain_id_2_signature = get_signature_evm_chain_id_2();

    let _results = src9.execute_from_outside_v2(outside_execution, chain_id_2_signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_mismatched_chain_id_in_signature_reverts() {
    // Test that passing a different chain_id in the signature than what was used
    // to generate the signature causes validation to fail.
    let src9 = setup_efo_test();
    let outside_execution = get_test_outside_execution();

    // Get valid signature (generated with chain_id=1) but change chain_id to 2
    let sig = get_outside_execution_signature();
    let tampered_signature = array![
        *sig.at(0), *sig.at(1), *sig.at(2), *sig.at(3), *sig.at(4),
        2 // chain_id = 2 (but signature was generated with chain_id=1)
    ];

    // Fails because contract computes hash with chain_id=2 but signature used chain_id=1
    src9.execute_from_outside_v2(outside_execution, tampered_signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_wrong_sn_chain_name_reverts() {
    let src9 = setup_efo_test();
    let outside_execution = get_test_outside_execution();

    // Signature generated with SN_SEPOLIA instead of SN_MAIN - domain name hash mismatch
    let wrong_sn_chain_signature = get_signature_wrong_sn_chain_name();

    src9.execute_from_outside_v2(outside_execution, wrong_sn_chain_signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_wrong_contract_address_reverts() {
    let src9 = setup_efo_test();
    let outside_execution = get_test_outside_execution();

    // Signature generated with wrong contract address - verifyingContract mismatch
    let wrong_contract_signature = get_signature_wrong_contract_address();

    src9.execute_from_outside_v2(outside_execution, wrong_contract_signature.span());
}

/// Test helper: arbitrary address for spender/recipient in tests.
fn TEST_SPENDER() -> starknet::ContractAddress {
    0x1234_felt252.try_into().unwrap()
}

fn TEST_RECIPIENT() -> starknet::ContractAddress {
    0x5678_felt252.try_into().unwrap()
}

// ================================
// execute_from_outside_v2 tests with actual calls
// ================================

#[test]
fn test_execute_from_outside_single_call_succeeds() {
    let (src9, token_address, token) = setup_efo_test_with_erc20();

    // Build approve call: account approves spender for 500 tokens
    let approve_amount: u256 = 500_u256;
    let approve_call = build_approve_call(token_address, TEST_SPENDER(), approve_amount);
    let outside_execution = build_outside_execution_with_calls(
        array![approve_call].span(), NONCE_SINGLE_CALL,
    );

    src9.execute_from_outside_v2(outside_execution, get_single_call_approve_signature().span());

    // Verify the approval was set
    let allowance = token.allowance(src9.contract_address, TEST_SPENDER());
    assert!(allowance == approve_amount, "Approval not set correctly");
}

#[test]
fn test_execute_from_outside_multi_call_succeeds() {
    let (src9, token_address, token) = setup_efo_test_with_erc20();

    // Build two calls: approve 500 + transfer 100
    let approve_amount: u256 = 500_u256;
    let transfer_amount: u256 = 100_u256;
    let approve_call = build_approve_call(token_address, TEST_SPENDER(), approve_amount);
    let transfer_call = build_transfer_call(token_address, TEST_RECIPIENT(), transfer_amount);
    let outside_execution = build_outside_execution_with_calls(
        array![approve_call, transfer_call].span(), NONCE_MULTI_CALL,
    );

    // Record initial balances
    let account_address = src9.contract_address;
    let initial_account_balance = token.balance_of(account_address);
    let initial_recipient_balance = token.balance_of(TEST_RECIPIENT());

    src9.execute_from_outside_v2(outside_execution, get_multi_call_signature().span());

    // Verify both side effects
    assert!(token.allowance(account_address, TEST_SPENDER()) == approve_amount, "Approval failed");
    assert!(
        token.balance_of(account_address) == initial_account_balance - transfer_amount,
        "Account balance not reduced",
    );
    assert!(
        token.balance_of(TEST_RECIPIENT()) == initial_recipient_balance + transfer_amount,
        "Recipient balance not increased",
    );
}

/// Test that when one call in a multi-call execution fails, the entire execution fails.
/// NOTE: Starknet guarantees atomicity at the protocol level - all state changes are rolled
/// back when a transaction fails. However, snforge's test environment doesn't fully simulate
/// this rollback behavior, so we can only verify that the error is properly propagated.
#[test]
#[feature("safe_dispatcher")]
fn test_execute_from_outside_multi_call_failure_propagates() {
    let (src9, token_address, _) = setup_efo_test_with_erc20();

    // Build two calls: approve 500 (would succeed) + transfer more than balance (will fail)
    let approve_amount: u256 = 500_u256;
    let transfer_amount: u256 = MOCK_ERC20_INITIAL_SUPPLY + 1_u256;
    let approve_call = build_approve_call(token_address, TEST_SPENDER(), approve_amount);
    let transfer_call = build_transfer_call(token_address, TEST_RECIPIENT(), transfer_amount);
    let outside_execution = build_outside_execution_with_calls(
        array![approve_call, transfer_call].span(), NONCE_ATOMICITY,
    );

    // Due cairo test limitations, we cannot verify that the state changes are rolled back.
    // So we just verify that the error is propagated.

    // Use safe dispatcher to verify the error is propagated
    let safe_src9 = ISRC9_V2SafeDispatcher { contract_address: src9.contract_address };
    let result = safe_src9
        .execute_from_outside_v2(outside_execution, get_atomicity_test_signature().span());

    // Verify that the execution failed (error from second call propagates)
    assert!(result.is_err(), "Expected call to fail due to insufficient balance");
}

/// Test execute_from_outside_v2 with a specific caller (not ANY_CALLER).
/// The execution should succeed when called by the exact specified caller.
#[test]
fn test_execute_from_outside_specific_caller_succeeds() {
    let src9 = setup_efo_test();

    let specific_caller: starknet::ContractAddress = SPECIFIC_CALLER.try_into().unwrap();
    let outside_execution = build_outside_execution_with_specific_caller(
        NONCE_SPECIFIC_CALLER, specific_caller,
    );

    // Spoof caller to be the specific caller
    cheat_caller_address_once(src9.contract_address, specific_caller);

    // Should succeed because caller matches
    src9.execute_from_outside_v2(outside_execution, get_specific_caller_signature().span());
}

/// Test execute_from_outside_v2 with a specific caller, but called from wrong address.
/// The execution should revert when the actual caller doesn't match.
#[test]
#[should_panic(expected: 'INVALID_CALLER')]
fn test_execute_from_outside_wrong_caller_reverts() {
    let src9 = setup_efo_test();

    let specific_caller: starknet::ContractAddress = SPECIFIC_CALLER.try_into().unwrap();
    let wrong_caller: starknet::ContractAddress = 0xDEAD.try_into().unwrap();
    let outside_execution = build_outside_execution_with_specific_caller(
        NONCE_SPECIFIC_CALLER, specific_caller,
    );

    // Spoof caller to be a DIFFERENT address than specified
    cheat_caller_address_once(src9.contract_address, wrong_caller);

    // Should fail because caller doesn't match
    src9.execute_from_outside_v2(outside_execution, get_specific_caller_signature().span());
}
