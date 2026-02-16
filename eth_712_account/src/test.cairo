use eth_712_account::interface::{IAccount712AdminDispatcher, IAccount712AdminDispatcherTrait};
use eth_712_account::test_utils::{
    TEST_ETH_ADDRESS, declare_register_interfaces_eic, deploy_eth712_account, get_invalid_signature,
    get_ownership_signature,
};
use openzeppelin::account::extensions::src9::interface::ISRC9_V2_ID;
use openzeppelin::account::interface::ISRC6_ID;
use openzeppelin::introspection::interface::{ISRC5Dispatcher, ISRC5DispatcherTrait};
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
