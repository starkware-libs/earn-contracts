use openzeppelin::account::extensions::src9::interface::ISRC9_V2_ID;
use openzeppelin::account::interface::ISRC6_ID;
use openzeppelin::introspection::interface::{ISRC5Dispatcher, ISRC5DispatcherTrait};
use snforge_std::{EventSpyTrait, spy_events, start_cheat_caller_address, stop_cheat_caller_address};
use crate::interface::{IAccount712AdminDispatcher, IAccount712AdminDispatcherTrait};
use crate::test_utils::{
    TEST_ETH_ADDRESS, WRONG_ETH_ADDRESS, deploy_eth712_account, get_invalid_signature,
    get_ownership_signature,
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
