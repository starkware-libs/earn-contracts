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

/// Minimal ISRC9_V2 stub used to test the EarnInvokeHelper. Records the
/// number of times `execute_from_outside_v2` was called and the caller at
/// each invocation, so tests can assert that the helper forwarded properly.
#[starknet::contract]
pub mod MockOutsideExecutionTarget {
    use openzeppelin::account::extensions::src9::OutsideExecution;
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        call_count: u64,
        last_caller: ContractAddress,
        last_nonce: felt252,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Recorded: Recorded,
    }

    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct Recorded {
        pub caller: ContractAddress,
        pub nonce: felt252,
    }

    #[starknet::interface]
    pub trait IMockTarget<TContractState> {
        fn call_count(self: @TContractState) -> u64;
        fn last_caller(self: @TContractState) -> ContractAddress;
        fn last_nonce(self: @TContractState) -> felt252;
        fn execute_from_outside_v2(
            ref self: TContractState,
            outside_execution: OutsideExecution,
            signature: Span<felt252>,
        ) -> Array<Span<felt252>>;
    }

    #[abi(embed_v0)]
    impl MockImpl of IMockTarget<ContractState> {
        fn call_count(self: @ContractState) -> u64 {
            self.call_count.read()
        }

        fn last_caller(self: @ContractState) -> ContractAddress {
            self.last_caller.read()
        }

        fn last_nonce(self: @ContractState) -> felt252 {
            self.last_nonce.read()
        }

        fn execute_from_outside_v2(
            ref self: ContractState,
            outside_execution: OutsideExecution,
            signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            let _ = signature;
            let caller = get_caller_address();
            self.call_count.write(self.call_count.read() + 1);
            self.last_caller.write(caller);
            self.last_nonce.write(outside_execution.nonce);
            self.emit(Event::Recorded(Recorded { caller, nonce: outside_execution.nonce }));
            array![]
        }
    }
}

/// Declare the `MockOutsideExecutionTarget` contract and return its class hash.
pub fn declare_mock_outside_execution_target() -> ClassHash {
    *snforge_std::declare("MockOutsideExecutionTarget")
        .unwrap_syscall()
        .contract_class()
        .class_hash
}
