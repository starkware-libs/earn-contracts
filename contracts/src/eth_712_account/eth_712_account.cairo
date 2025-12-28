// SPDX-License-Identifier: Apache-2.0
// Copy & Extends OpenZeppelin Contracts for Cairo v2.0.0 (presets/src/account.cairo)

/// StarknetEth712Account
///
/// Account contract that supports ISRC9_V2 (Execute from outside v2) and ISRC5 (Introspection).
/// The Account contract is initialized with an Ethereum address.
/// The transaction executed by the account is validated using EIP-712.
/// and signed using Secp256k1.
/// This allows the account to sign the txs from the wallet of a remote chain,
/// and execute them locally on Starknet.

#[starknet::contract]
pub mod StarknetEth712Account {
    use contracts::eth_712_account::eth_712_utils::{
        assert_valid_owner, extract_signature, get_outside_execution_hash, is_valid_signature,
    };
    use contracts::eth_712_account::interface::{
        IAccount712Admin, IEICDispatcherTrait, IEICLibraryDispatcher, Upgraded,
    };
    use core::num::traits::Zero;
    use openzeppelin::account::extensions::src9::interface::ISRC9_V2_ID;
    use openzeppelin::account::extensions::src9::{ISRC9_V2, OutsideExecution};
    use openzeppelin::account::utils::execute_calls;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::introspection::src5::SRC5Component::InternalTrait as SRC5InternalTrait;
    use starknet::secp256_trait::Signature;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::replace_class_syscall;
    use starknet::{ClassHash, EthAddress, SyscallResultTrait};

    component!(path: SRC5Component, storage: src5, event: SRC5Event);


    #[storage]
    pub struct Storage {
        #[substorage(v0)]
        pub src5: SRC5Component::Storage,
        pub SRC9_nonces: Map<felt252, bool>,
        pub eth_address: EthAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        SRC5Event: SRC5Component::Event,
        Upgraded: Upgraded,
    }

    // SRC5
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;

    // ABI implementation.

    #[abi(embed_v0)]
    impl AdminImpl of IAccount712Admin<ContractState> {
        fn initialize(ref self: ContractState, eth_address: EthAddress, signature: Signature) {
            assert(self.eth_address.read().is_zero(), 'ALREADY_INITIALIZED');
            assert_valid_owner(:eth_address, :signature);
            self.eth_address.write(eth_address);

            // Register 'execute_from_outside_v2' interface, as paymaster requires this.
            self.src5.register_interface(ISRC9_V2_ID);
        }
        fn upgrade(
            ref self: ContractState,
            new_class_hash: ClassHash,
            eic_data: Option<(ClassHash, Span<felt252>)>,
        ) {
            self.assert_only_self();
            if let Some((class_hash, eic_init_data)) = eic_data {
                IEICLibraryDispatcher { class_hash }.eic_initialize(eic_init_data);
            }
            replace_class_syscall(new_class_hash).unwrap_syscall();
            self.emit(Upgraded { class_hash: new_class_hash });
        }
    }

    #[abi(embed_v0)]
    impl ISRC9_V2Impl of ISRC9_V2<ContractState> {
        fn execute_from_outside_v2(
            ref self: ContractState, outside_execution: OutsideExecution, signature: Span<felt252>,
        ) -> Array<Span<felt252>> {
            let OutsideExecution {
                caller, nonce, execute_after, execute_before, calls,
            } = outside_execution;

            // 1. Validate the caller.
            //    It must be either the one specified in the outside execution,
            //    unless 'ANY_CALLER' is specified.
            if caller.into() != 'ANY_CALLER' {
                assert(starknet::get_caller_address() == caller, 'INVALID_CALLER');
            }

            // 2. Validate the execution time span
            let now = starknet::get_block_timestamp();
            assert(execute_after < now, 'EXECUTED_TOO_EARLY');
            assert(now < execute_before, 'EXECUTED_TOO_LATE');

            // 3. Validate the nonce
            assert(self.is_valid_outside_execution_nonce(nonce), 'DUPLICATE_NONCE');

            // 4. Mark the nonce as used
            self.SRC9_nonces.write(nonce, true);

            // 5. Validate the signature.
            // We pass the EVM Chain ID as the last element of the signature.
            let (signature, evm_chain_id) = extract_signature(:signature);
            let msg_hash = get_outside_execution_hash(@outside_execution, chain_id: evm_chain_id);
            assert(
                is_valid_signature(:msg_hash, :signature, eth_address: self.eth_address.read()),
                'INVALID_SIGNATURE',
            );
            execute_calls(calls)
        }

        fn is_valid_outside_execution_nonce(self: @ContractState, nonce: felt252) -> bool {
            !self.SRC9_nonces.read(nonce)
        }
    }

    #[generate_trait]
    pub impl InternalImpl of InternalTrait {
        fn assert_only_self(self: @ContractState) {
            let caller = starknet::get_caller_address();
            let self = starknet::get_contract_address();
            assert(self == caller, 'UNAUTHORIZED');
        }
    }
}
