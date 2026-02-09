use snforge_std::cheatcodes::events::Event;
use snforge_std::{ContractClassTrait, DeclareResultTrait, TokenImpl};
use starknet::{ClassHash, ContractAddress, SyscallResultTrait};

/// Returns the index of the nth event whose first key equals the given selector.
pub(crate) fn find_event_index_by_selector(
    events: Span<(ContractAddress, Event)>, selector: felt252, n: usize,
) -> Option<usize> {
    let mut i = 0_usize;
    let mut seen = 0_usize;
    for (_, ev) in events {
        if ev.keys.len() > 0 && *ev.keys.at(0) == selector {
            if seen == n {
                return Option::Some(i);
            }
            seen += 1;
        }
        i += 1;
    }
    None
}

/// Returns a cloned copy of the first event emitted with the given selector (if any).
pub(crate) fn get_event_by_selector(
    events: Span<(ContractAddress, Event)>, selector: felt252,
) -> Option<@(ContractAddress, Event)> {
    match find_event_index_by_selector(:events, :selector, n: 0) {
        Option::Some(i) => {
            let (from, ev) = events.at(i);
            Option::Some(@(*from, ev.clone()))
        },
        None => None,
    }
}

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

// Minimal no-op contract for tests: stores an EthAddress passed at construction.
#[starknet::contract]
pub mod DummyEthAddressContract {
    use starknet::eth_address::EthAddress;
    use starknet::secp256_trait::Signature;
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn initialize(ref self: ContractState, eth_address: EthAddress, signature: Signature) {
        return;
    }
}

pub(crate) fn declare_dummy_eth_address_contract() -> ClassHash {
    *snforge_std::declare("DummyEthAddressContract").unwrap_syscall().contract_class().class_hash
}
