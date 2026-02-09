use openzeppelin::account::extensions::src9::interface::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, ISRC9_V2_ID,
};
use openzeppelin::account::interface::ISRC6_ID;
use openzeppelin::introspection::interface::{ISRC5Dispatcher, ISRC5DispatcherTrait};
use snforge_std::{
    EventSpyTrait, spy_events, start_cheat_block_timestamp, start_cheat_caller_address,
    start_cheat_chain_id_global, stop_cheat_caller_address,
};
use crate::interface::{IAccount712AdminDispatcher, IAccount712AdminDispatcherTrait};
use crate::test_utils::{
    EXECUTE_AFTER, EXECUTE_BEFORE, TEST_ETH_ADDRESS, TEST_NONCE, TEST_TIMESTAMP, WRONG_ETH_ADDRESS,
    deploy_eth712_account, get_invalid_outside_execution_signature, get_invalid_signature,
    get_outside_execution_signature, get_ownership_signature, get_signature_wrong_contract_address,
    get_signature_wrong_evm_chain_id, get_signature_wrong_sn_chain_name, get_test_outside_execution,
};

// ================================
// initialize tests
// ================================

#[test]
fn test_initialize_success() {
    let contract_address = deploy_eth712_account();
    let dispatcher = IAccount712AdminDispatcher { contract_address };

    // Initialize with valid signature
    dispatcher.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Verify interfaces are registered
    let src5 = ISRC5Dispatcher { contract_address };
    assert!(src5.supports_interface(ISRC9_V2_ID), "ISRC9_V2_ID not registered");
    assert!(src5.supports_interface(ISRC6_ID), "ISRC6_ID not registered");
}

#[test]
#[should_panic(expected: 'ALREADY_INITIALIZED')]
fn test_initialize_already_initialized_reverts() {
    let contract_address = deploy_eth712_account();
    let dispatcher = IAccount712AdminDispatcher { contract_address };

    // First initialization should succeed
    dispatcher.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Second initialization should fail
    dispatcher.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());
}

#[test]
#[should_panic(expected: 'INVALID_OWNERSHIP_SIGNATURE')]
fn test_initialize_invalid_signature_reverts() {
    let contract_address = deploy_eth712_account();
    let dispatcher = IAccount712AdminDispatcher { contract_address };

    // Initialize with invalid signature
    dispatcher.initialize(TEST_ETH_ADDRESS(), get_invalid_signature());
}

#[test]
#[should_panic(expected: 'INVALID_OWNERSHIP_SIGNATURE')]
fn test_initialize_wrong_address_reverts() {
    let contract_address = deploy_eth712_account();
    let dispatcher = IAccount712AdminDispatcher { contract_address };

    // Initialize with correct signature but wrong address
    dispatcher.initialize(WRONG_ETH_ADDRESS(), get_ownership_signature());
}

// ================================
// upgrade tests
// ================================

#[test]
#[should_panic(expected: 'UNAUTHORIZED')]
fn test_upgrade_unauthorized_reverts() {
    let contract_address = deploy_eth712_account();
    let dispatcher = IAccount712AdminDispatcher { contract_address };

    // Initialize first
    dispatcher.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Try to upgrade from external caller (not self)
    let new_class_hash = crate::test_utils::declare_eth712_account();
    dispatcher.upgrade(new_class_hash, Option::None);
}

#[test]
fn test_upgrade_from_self_succeeds() {
    let contract_address = deploy_eth712_account();
    let dispatcher = IAccount712AdminDispatcher { contract_address };

    // Initialize first
    dispatcher.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Spoof caller as self
    start_cheat_caller_address(contract_address, contract_address);

    let mut spy = spy_events();
    let new_class_hash = crate::test_utils::declare_eth712_account();
    dispatcher.upgrade(new_class_hash, Option::None);

    // Verify an event was emitted (Upgraded event)
    let events = spy.get_events();
    assert!(events.events.len() > 0, "No events emitted");

    // Verify the event data contains the new class hash
    let (from, event) = events.events.at(0);
    assert!(*from == contract_address, "Event from wrong address");
    assert!(event.data.len() > 0, "Event has no data");
    assert!(*event.data.at(0) == new_class_hash.into(), "Wrong class hash in event");

    stop_cheat_caller_address(contract_address);
}

#[test]
fn test_upgrade_with_eic() {
    let contract_address = deploy_eth712_account();
    let dispatcher = IAccount712AdminDispatcher { contract_address };

    // Initialize first
    dispatcher.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Spoof caller as self
    start_cheat_caller_address(contract_address, contract_address);

    let new_class_hash = crate::test_utils::declare_eth712_account();
    let eic_class_hash = crate::test_utils::declare_register_interfaces_eic();

    // Register a custom interface via EIC
    let custom_interface_id: felt252 = 0x12345678;
    let eic_data: Span<felt252> = array![custom_interface_id].span();

    dispatcher.upgrade(new_class_hash, Option::Some((eic_class_hash, eic_data)));

    // Verify the custom interface was registered
    let src5 = ISRC5Dispatcher { contract_address };
    assert!(src5.supports_interface(custom_interface_id), "Custom interface not registered");

    stop_cheat_caller_address(contract_address);
}

// ================================
// execute_from_outside_v2 tests
// ================================

#[test]
fn test_execute_from_outside_success() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set timestamp to be within the valid window
    start_cheat_block_timestamp(contract_address, TEST_TIMESTAMP);

    // Set chain ID to SN_MAIN for domain separator
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);
    let signature = get_outside_execution_signature();

    // Execute - this should succeed
    let _results = src9.execute_from_outside_v2(outside_execution, signature.span());

    // Verify nonce is now used
    assert!(!src9.is_valid_outside_execution_nonce(TEST_NONCE), "Nonce should be marked as used");
}

#[test]
#[should_panic(expected: 'EXECUTED_TOO_EARLY')]
fn test_execute_from_outside_too_early_reverts() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set timestamp BEFORE execute_after (too early)
    start_cheat_block_timestamp(contract_address, EXECUTE_AFTER - 1);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);
    let signature = get_outside_execution_signature();

    // This should fail with EXECUTED_TOO_EARLY
    src9.execute_from_outside_v2(outside_execution, signature.span());
}

#[test]
#[should_panic(expected: 'EXECUTED_TOO_LATE')]
fn test_execute_from_outside_too_late_reverts() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set timestamp AFTER execute_before (too late)
    start_cheat_block_timestamp(contract_address, EXECUTE_BEFORE + 1);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);
    let signature = get_outside_execution_signature();

    // This should fail with EXECUTED_TOO_LATE
    src9.execute_from_outside_v2(outside_execution, signature.span());
}

#[test]
#[should_panic(expected: 'DUPLICATE_NONCE')]
fn test_execute_from_outside_duplicate_nonce_reverts() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    start_cheat_block_timestamp(contract_address, TEST_TIMESTAMP);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);
    let signature = get_outside_execution_signature();

    // First execution should succeed
    src9.execute_from_outside_v2(outside_execution, signature.span());

    // Second execution with same nonce should fail
    let outside_execution2 = get_test_outside_execution(contract_address);
    let signature2 = get_outside_execution_signature();
    src9.execute_from_outside_v2(outside_execution2, signature2.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_invalid_signature_reverts() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    start_cheat_block_timestamp(contract_address, TEST_TIMESTAMP);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);
    let invalid_signature = get_invalid_outside_execution_signature();

    // This should fail with INVALID_SIGNATURE
    src9.execute_from_outside_v2(outside_execution, invalid_signature.span());
}

#[test]
fn test_is_valid_outside_execution_nonce() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    let src9 = ISRC9_V2Dispatcher { contract_address };

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

    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    start_cheat_block_timestamp(contract_address, TEST_TIMESTAMP);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);

    // Signature generated with EVM chain ID 2 (e.g., from a different EVM chain)
    // This is valid because the contract uses the chain_id from the signature
    let chain_id_2_signature = get_signature_wrong_evm_chain_id();

    // This succeeds because the signature is valid for chain_id=2
    let _results = src9.execute_from_outside_v2(outside_execution, chain_id_2_signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_mismatched_chain_id_in_signature_reverts() {
    // Test that passing a different chain_id in the signature than what was used
    // to generate the signature causes validation to fail.

    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    start_cheat_block_timestamp(contract_address, TEST_TIMESTAMP);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);

    // Get valid signature (generated with chain_id=1) but change chain_id to 2
    // This creates a mismatch: signature was computed with chain_id=1 domain,
    // but we tell the contract to verify with chain_id=2 domain
    let mut sig = get_outside_execution_signature();
    // Modify the last element (chain_id) from 1 to 2
    let tampered_signature = array![
        *sig.at(0), // r_high
        *sig.at(1), // r_low
        *sig.at(2), // s_high
        *sig.at(3), // s_low
        *sig.at(4), // v
        2 // chain_id = 2 (but signature was generated with chain_id=1)
    ];

    // This should fail with INVALID_SIGNATURE because the contract will compute
    // the hash using chain_id=2 but the signature was created with chain_id=1
    src9.execute_from_outside_v2(outside_execution, tampered_signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_wrong_sn_chain_name_reverts() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID (SN_MAIN)
    start_cheat_block_timestamp(contract_address, TEST_TIMESTAMP);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);

    // Use signature generated with wrong Starknet chain name (SN_SEPOLIA instead of SN_MAIN)
    let wrong_sn_chain_signature = get_signature_wrong_sn_chain_name();

    // This should fail with INVALID_SIGNATURE because the domain name hash
    // (keccak of SN_SEPOLIA) doesn't match what the contract computes (keccak of SN_MAIN)
    src9.execute_from_outside_v2(outside_execution, wrong_sn_chain_signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_wrong_contract_address_reverts() {
    let contract_address = deploy_eth712_account();
    let admin = IAccount712AdminDispatcher { contract_address };

    // Initialize the account
    admin.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    start_cheat_block_timestamp(contract_address, TEST_TIMESTAMP);
    start_cheat_chain_id_global('SN_MAIN');

    let src9 = ISRC9_V2Dispatcher { contract_address };
    let outside_execution = get_test_outside_execution(contract_address);

    // Use signature generated with wrong contract address in domain separator
    let wrong_contract_signature = get_signature_wrong_contract_address();

    // This should fail with INVALID_SIGNATURE because the verifyingContract
    // in the signature doesn't match this contract's address
    src9.execute_from_outside_v2(outside_execution, wrong_contract_signature.span());
}
