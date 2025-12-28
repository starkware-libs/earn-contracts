use contracts::account_factory::utils::{PRIMER_CLASS_HASH, compute_contract_address};
use snforge_std::cheatcodes::events::Event;
use snforge_std::{ContractClassTrait, DeclareResultTrait, TokenImpl};
use starknet::eth_address::EthAddress;
use starknet::{ClassHash, ContractAddress, SyscallResultTrait};
use starkware_utils::constants::SYMBOL;
use starkware_utils_testing::test_utils::{
    set_account_as_app_governor, set_account_as_app_role_admin,
};

pub(crate) fn APP_ROLE_ADMIN() -> ContractAddress {
    'APP_ROLE_ADMIN'.try_into().unwrap()
}

pub(crate) fn APP_GOVERNOR() -> ContractAddress {
    'APP_GOVERNOR'.try_into().unwrap()
}


pub(crate) fn GOVERNANCE_ADMIN() -> ContractAddress {
    'GOVERNANCE_ADMIN'.try_into().unwrap()
}

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

/// Returns a cloned copy of the nth event emitted with the given selector (if any).
pub(crate) fn get_event_by_selector_n(
    events: Span<(ContractAddress, Event)>, selector: felt252, n: usize,
) -> Option<@(ContractAddress, Event)> {
    match find_event_index_by_selector(:events, :selector, :n) {
        Option::Some(i) => {
            let (from, ev) = events.at(i);
            Option::Some(@(*from, ev.clone()))
        },
        None => None,
    }
}


/// Mirrors AccountFactory.eth_address_to_account for tests, using the
/// PRIMER_CLASS_HASH and the account factory address as the deployer address. The difference
/// between this and AccountFactory.eth_address_to_account is that this function gets the deployer
/// address from the caller.
pub(crate) fn eth_address_to_account(
    account_factory: ContractAddress, eth_address: EthAddress,
) -> ContractAddress {
    compute_contract_address(
        salt: eth_address.into(),
        class_hash: PRIMER_CLASS_HASH.into(),
        constructor_calldata: array![].span(),
        deployer_address: account_factory.into(),
    )
}

//TODO - Move to starkware_utils_testing
pub(crate) fn deploy_mock_erc20_contract(
    initial_supply: u256, owner_address: ContractAddress, name: ByteArray,
) -> ContractAddress {
    let mut calldata = ArrayTrait::new();
    name.serialize(ref calldata);
    SYMBOL().serialize(ref calldata);
    initial_supply.serialize(ref calldata);
    owner_address.serialize(ref calldata);
    let erc20_contract = snforge_std::declare("DualCaseERC20Mock")
        .unwrap_syscall()
        .contract_class();
    let (token_address, _) = erc20_contract.deploy(@calldata).unwrap_syscall();
    token_address
}

/// Declare the `Primer` contract and return its class hash.
pub(crate) fn declare_primer_contract() -> ClassHash {
    *snforge_std::declare("Primer").unwrap_syscall().contract_class().class_hash
}


fn set_account_factory_default_roles(account_factory: ContractAddress) {
    // App role admin
    set_account_as_app_role_admin(
        contract: account_factory, account: APP_ROLE_ADMIN(), governance_admin: GOVERNANCE_ADMIN(),
    );
    // App governor (requires app role admin)
    set_account_as_app_governor(
        contract: account_factory, account: APP_GOVERNOR(), app_role_admin: APP_ROLE_ADMIN(),
    );
}


/// Sets up the AccountFactory test environment:
/// - deploys the `AccountFactory` contract,
/// - sets default roles,
/// - declares the `Primer` contract so its class hash is available.
pub(crate) fn setup_account_factory_test_env() -> ContractAddress {
    let calldata = account_factory_constructor_calldata();
    let account_factory_contract = snforge_std::declare("AccountFactory")
        .unwrap_syscall()
        .contract_class();
    let (account_factory_contract_address, _) = account_factory_contract
        .deploy(@calldata)
        .unwrap_syscall();
    set_account_factory_default_roles(account_factory_contract_address);
    declare_primer_contract();
    account_factory_contract_address
}

/// Builds the constructor calldata array for AccountFactory.
pub(crate) fn account_factory_constructor_calldata() -> Array<felt252> {
    let governance_admin: ContractAddress = GOVERNANCE_ADMIN();
    let upgrade_delay: u64 = 0;
    let account_class_hash: ClassHash = declare_dummy_eth_address_contract();
    let mut calldata: Array<felt252> = array![];
    Serde::serialize(@governance_admin, ref calldata);
    Serde::serialize(@upgrade_delay, ref calldata);
    Serde::serialize(@account_class_hash, ref calldata);
    calldata
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


/// Declare the `SecondDummyEthAddressContract` contract and return its class hash.
#[starknet::contract]
pub mod SecondDummyEthAddressContract {
    use starknet::eth_address::EthAddress;
    use starknet::secp256_trait::Signature;
    #[storage]
    struct Storage {}

    #[constructor]
    pub fn constructor(ref self: ContractState) {
        // This assert is just to get a different class hash for the contract.
        assert!(true, "ERROR");
    }
    #[external(v0)]
    fn initialize(ref self: ContractState, eth_address: EthAddress, signature: Signature) {
        return;
    }
}

/// Declare the `SecondDummyEthAddressContract` contract and return its class hash.
pub(crate) fn declare_second_dummy_eth_address_contract() -> ClassHash {
    *snforge_std::declare("SecondDummyEthAddressContract")
        .unwrap_syscall()
        .contract_class()
        .class_hash
}
