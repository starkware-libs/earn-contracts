// Re-export shared testing utilities from the testing_utils package.

// Package-specific helpers

use snforge_std::{ContractClassTrait, DeclareResultTrait};
use starknet::{ContractAddress, SyscallResultTrait};
pub use testing_utils::dummy_contracts::declare_dummy_eth_address_contract;
pub use testing_utils::event_helpers::{find_event_index_by_selector, get_event_by_selector};

/// Deploy the EarnReporter contract and return its address.
pub(crate) fn deploy_earn_reporter(owner: ContractAddress) -> ContractAddress {
    let earn_reporter_class = snforge_std::declare("EarnReporter")
        .unwrap_syscall()
        .contract_class();
    let (earn_reporter_addr, _) = earn_reporter_class
        .deploy(@array![owner.into()])
        .unwrap_syscall();
    earn_reporter_addr
}
