use snforge_std::DeclareResultTrait;
use starknet::{ClassHash, SyscallResultTrait};

/// Minimal no-op contract for tests: stores an EthAddress passed at construction.
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

/// Declare the `DummyEthAddressContract` contract and return its class hash.
pub fn declare_dummy_eth_address_contract() -> ClassHash {
    *snforge_std::declare("DummyEthAddressContract").unwrap_syscall().contract_class().class_hash
}

/// Second dummy contract with a different class hash for upgrade testing.
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
pub fn declare_second_dummy_eth_address_contract() -> ClassHash {
    *snforge_std::declare("SecondDummyEthAddressContract")
        .unwrap_syscall()
        .contract_class()
        .class_hash
}
