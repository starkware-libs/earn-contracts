use eth_712_account::interface::{IAccount712AdminDispatcher, IAccount712AdminDispatcherTrait};
use eth_712_account::test_utils::{
    EXECUTE_AFTER, EXECUTE_BEFORE, TEST_ETH_ADDRESS, TEST_NONCE, TEST_TIMESTAMP,
    declare_register_interfaces_eic, deploy_eth712_account, get_invalid_outside_execution_signature,
    get_invalid_signature, get_outside_execution_signature, get_ownership_signature,
    get_signature_wrong_contract_address, get_signature_wrong_evm_chain_id,
    get_signature_wrong_sn_chain_name, get_test_outside_execution,
};
use openzeppelin::account::extensions::src9::interface::{
    ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, ISRC9_V2_ID,
};
use openzeppelin::account::interface::ISRC6_ID;
use openzeppelin::introspection::interface::{ISRC5Dispatcher, ISRC5DispatcherTrait};
use snforge_std::cheatcodes::CheatSpan;
use snforge_std::{EventSpyTrait, cheat_block_timestamp, cheat_chain_id, load, spy_events};
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
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set timestamp to be within the valid window
    cheat_block_timestamp(account_address, TEST_TIMESTAMP, CheatSpan::Indefinite);

    // Set chain ID to SN_MAIN for domain separator
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);
    let signature = get_outside_execution_signature();

    // Execute - this should succeed
    let _results = src9.execute_from_outside_v2(outside_execution, signature.span());

    // Verify nonce is now used
    assert!(!src9.is_valid_outside_execution_nonce(TEST_NONCE), "Nonce should be marked as used");
}

#[test]
#[should_panic(expected: 'EXECUTED_TOO_EARLY')]
fn test_execute_from_outside_too_early_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set timestamp BEFORE execute_after (too early)
    cheat_block_timestamp(account_address, EXECUTE_AFTER - 1, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);
    let signature = get_outside_execution_signature();

    // This should fail with EXECUTED_TOO_EARLY
    src9.execute_from_outside_v2(outside_execution, signature.span());
}

#[test]
#[should_panic(expected: 'EXECUTED_TOO_LATE')]
fn test_execute_from_outside_too_late_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set timestamp AFTER execute_before (too late)
    cheat_block_timestamp(account_address, EXECUTE_BEFORE + 1, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);
    let signature = get_outside_execution_signature();

    // This should fail with EXECUTED_TOO_LATE
    src9.execute_from_outside_v2(outside_execution, signature.span());
}

#[test]
#[should_panic(expected: 'DUPLICATE_NONCE')]
fn test_execute_from_outside_duplicate_nonce_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    cheat_block_timestamp(account_address, TEST_TIMESTAMP, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);
    let signature = get_outside_execution_signature();

    // First execution should succeed
    src9.execute_from_outside_v2(outside_execution, signature.span());

    // Second execution with same nonce should fail
    let outside_execution2 = get_test_outside_execution(account_address);
    let signature2 = get_outside_execution_signature();
    src9.execute_from_outside_v2(outside_execution2, signature2.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_invalid_signature_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    cheat_block_timestamp(account_address, TEST_TIMESTAMP, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);
    let invalid_signature = get_invalid_outside_execution_signature();

    // This should fail with INVALID_SIGNATURE
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

    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    cheat_block_timestamp(account_address, TEST_TIMESTAMP, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);

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

    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    cheat_block_timestamp(account_address, TEST_TIMESTAMP, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);

    // Get valid signature (generated with chain_id=1) but change chain_id to 2
    // This creates a mismatch: signature was computed with chain_id=1 domain,
    // but we tell the contract to verify with chain_id=2 domain
    let sig = get_outside_execution_signature();
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
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID (SN_MAIN)
    cheat_block_timestamp(account_address, TEST_TIMESTAMP, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);

    // Use signature generated with wrong Starknet chain name (SN_SEPOLIA instead of SN_MAIN)
    let wrong_sn_chain_signature = get_signature_wrong_sn_chain_name();

    // This should fail with INVALID_SIGNATURE because the domain name hash
    // (keccak of SN_SEPOLIA) doesn't match what the contract computes (keccak of SN_MAIN)
    src9.execute_from_outside_v2(outside_execution, wrong_sn_chain_signature.span());
}

#[test]
#[should_panic(expected: 'INVALID_SIGNATURE')]
fn test_execute_from_outside_wrong_contract_address_reverts() {
    let (account_address, _) = deploy_eth712_account();
    let account_contract = IAccount712AdminDispatcher { contract_address: account_address };

    // Initialize the account
    account_contract.initialize(TEST_ETH_ADDRESS(), get_ownership_signature());

    // Set valid timestamp and chain ID
    cheat_block_timestamp(account_address, TEST_TIMESTAMP, CheatSpan::Indefinite);
    cheat_chain_id(account_address, 'SN_MAIN', CheatSpan::Indefinite);

    let src9 = ISRC9_V2Dispatcher { contract_address: account_address };
    let outside_execution = get_test_outside_execution(account_address);

    // Use signature generated with wrong contract address in domain separator
    let wrong_contract_signature = get_signature_wrong_contract_address();

    // This should fail with INVALID_SIGNATURE because the verifyingContract
    // in the signature doesn't match this contract's address
    src9.execute_from_outside_v2(outside_execution, wrong_contract_signature.span());
}
