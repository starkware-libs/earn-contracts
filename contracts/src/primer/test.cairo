use snforge_std::{ContractClassTrait, DeclareResultTrait, TokenImpl};
use starknet::get_contract_address;
use starknet::syscalls::get_class_hash_at_syscall;
use crate::primer::primer::{IPrimerDispatcher, IPrimerDispatcherTrait};
use crate::test_utils::declare_dummy_eth_address_contract;
#[test]
#[should_panic(expected: 'INVALID_CALLER')]
fn test_primer_update_class_hash_invalid_caller() {
    /// set_class_hash should only be callable by the upgrade account set at construction.
    /// Here we impersonate a different caller and expect the function to panic with
    /// 'INVALID_CALLER'.
    let primer_class = snforge_std::declare("Primer").unwrap().contract_class();
    let (primer_addr, _) = primer_class.deploy(@array![]).unwrap();

    let primer = IPrimerDispatcher { contract_address: primer_addr };
    // Impersonate a non-upgrade caller for the next call.
    starkware_utils_testing::test_utils::cheat_caller_address_once(
        contract_address: primer_addr, caller_address: 0x1.try_into().unwrap(),
    );
    // Attempt to update class hash with the wrong caller - should panic (see attribute above).
    let dummy_eth_address_contract_class_hash = declare_dummy_eth_address_contract();
    primer.set_class_hash(new_class_hash: dummy_eth_address_contract_class_hash);
}

#[test]
fn test_primer_sanity_set_class_hash() {
    /// Happy path: after deployment, impersonate the upgrade account and update class hash.
    /// Verifies the on-chain class hash equals the provided value.
    let primer_class = snforge_std::declare("Primer").unwrap().contract_class();
    let (primer_addr, _) = primer_class.deploy(@array![]).unwrap();

    let primer = IPrimerDispatcher { contract_address: primer_addr };
    // Impersonate the upgrade account (same address used by the test infra for this call).
    // Update the class hash and assert it took effect.
    let dummy_eth_address_contract_class_hash = declare_dummy_eth_address_contract();
    starkware_utils_testing::test_utils::cheat_caller_address_once(
        contract_address: primer_addr, caller_address: get_contract_address(),
    );
    primer.set_class_hash(new_class_hash: dummy_eth_address_contract_class_hash);
    let class_hash = get_class_hash_at_syscall(primer_addr).unwrap();
    assert!(class_hash == dummy_eth_address_contract_class_hash, "class hash mismatch");
}

