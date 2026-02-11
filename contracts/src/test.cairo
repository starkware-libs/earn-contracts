use contracts::primer::primer::{IPrimerDispatcher, IPrimerDispatcherTrait};
use snforge_std::{ContractClassTrait, DeclareResultTrait};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ClassHash, SyscallResultTrait, get_contract_address};
use starkware_utils_testing::test_utils::cheat_caller_address_once;

// Minimal no-op contract used as upgrade target in tests.
#[starknet::contract]
mod DummyUpgradeTarget {
    #[storage]
    struct Storage {}
}

fn declare_dummy_upgrade_target() -> ClassHash {
    *snforge_std::declare("DummyUpgradeTarget").unwrap_syscall().contract_class().class_hash
}

#[test]
#[should_panic(expected: 'INVALID_CALLER')]
fn test_primer_set_class_hash_invalid_caller() {
    /// set_class_hash should only be callable by the upgrade account set at construction.
    /// Here we impersonate a different caller and expect the function to panic with
    /// 'INVALID_CALLER'.
    let primer_class = snforge_std::declare("Primer").unwrap().contract_class();
    let (primer_addr, _) = primer_class.deploy(@array![]).unwrap();

    let primer = IPrimerDispatcher { contract_address: primer_addr };
    // Impersonate a non-upgrade caller for the next call.
    cheat_caller_address_once(
        contract_address: primer_addr, caller_address: 0x1.try_into().unwrap(),
    );
    // Attempt to update class hash with the wrong caller - should panic (see attribute above).
    let test_class_hash = declare_dummy_upgrade_target();
    primer.set_class_hash(new_class_hash: test_class_hash);
}

#[test]
fn test_primer_set_class_hash_success() {
    /// Happy path: after deployment, impersonate the upgrade account and update class hash.
    /// Verifies the on-chain class hash equals the provided value.
    let primer_class = snforge_std::declare("Primer").unwrap().contract_class();
    let (primer_addr, _) = primer_class.deploy(@array![]).unwrap();

    let primer = IPrimerDispatcher { contract_address: primer_addr };
    // Impersonate the upgrade account (same address used by the test infra for this call).
    // Update the class hash and assert it took effect.
    let test_class_hash = declare_dummy_upgrade_target();
    cheat_caller_address_once(
        contract_address: primer_addr, caller_address: get_contract_address(),
    );
    primer.set_class_hash(new_class_hash: test_class_hash);
    let class_hash = get_class_hash_at_syscall(primer_addr).unwrap();
    assert!(class_hash == test_class_hash, "class hash mismatch");
}
