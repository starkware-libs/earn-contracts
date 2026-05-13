use openzeppelin::account::extensions::src9::OutsideExecution;
use starknet::ContractAddress;

/// Mirror of `privacy::objects::OpenNoteDeposit`. We always return an empty
/// span; the fields here are never serialized with real data.
#[derive(Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u256,
}

#[starknet::interface]
pub trait IEarnInvokeHelper<TContractState> {
    /// Privacy-pool helper selector. The privacy pool calls
    /// `target.privacy_invoke(...)` and the function name is fixed.
    ///
    /// We forward the (outside_execution, signature) pair to
    /// `target_account.execute_from_outside_v2`. The account validates the
    /// EIP-712 signature against its stored owner_eth_address and runs the
    /// inner calls (e.g. counter.increment) atomically.
    fn privacy_invoke(
        ref self: TContractState,
        target_account: ContractAddress,
        outside_execution: OutsideExecution,
        signature: Array<felt252>,
        note_id: felt252,
    ) -> Span<OpenNoteDeposit>;

    fn privacy_pool(self: @TContractState) -> ContractAddress;
}

/// Privacy-pool helper that lets a private transaction trigger
/// `execute_from_outside_v2` on a Tier 2 account.
///
/// On-chain trace after a sponsored execute:
///   - The deploy tx is signed by AVNU's relayer.
///   - The pool calls THIS helper's `privacy_invoke`.
///   - This helper calls `target_account.execute_from_outside_v2(...)`.
///   - The account validates the signature with the session key's eth address
///     and executes the inner calls.
///
/// The account contract's caller-validation in `execute_from_outside_v2`
/// requires either `caller == ANY_CALLER` or `caller == this_helper_addr`.
/// In the SDK flow we set `caller = ANY_CALLER` so we don't have to pin the
/// helper address into the signed OutsideExecution.
#[starknet::contract]
pub mod EarnInvokeHelper {
    use openzeppelin::account::extensions::src9::{
        ISRC9_V2Dispatcher, ISRC9_V2DispatcherTrait, OutsideExecution,
    };
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address};
    use super::{IEarnInvokeHelper, OpenNoteDeposit};

    #[storage]
    struct Storage {
        privacy_pool: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        InvokedThroughPool: InvokedThroughPool,
    }

    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct InvokedThroughPool {
        pub target_account: ContractAddress,
    }

    #[constructor]
    pub fn constructor(ref self: ContractState, privacy_pool: ContractAddress) {
        self.privacy_pool.write(privacy_pool);
    }

    #[abi(embed_v0)]
    pub impl EarnInvokeHelperImpl of IEarnInvokeHelper<ContractState> {
        fn privacy_invoke(
            ref self: ContractState,
            target_account: ContractAddress,
            outside_execution: OutsideExecution,
            signature: Array<felt252>,
            note_id: felt252,
        ) -> Span<OpenNoteDeposit> {
            // note_id is part of the privacy-pool protocol but unused here.
            let _ = note_id;

            // Only the pool may invoke. Without this an arbitrary caller could
            // bypass the proof system and submit arbitrary execute_from_outside_v2
            // calls — still authorized by the account's signature check, but
            // not protected by Tier 2's relayer-paid envelope.
            let caller = get_caller_address();
            assert(caller == self.privacy_pool.read(), 'CALLER_NOT_PRIVACY_POOL');

            let account = ISRC9_V2Dispatcher { contract_address: target_account };
            account.execute_from_outside_v2(outside_execution, signature.span());

            self.emit(Event::InvokedThroughPool(InvokedThroughPool { target_account }));

            array![].span()
        }

        fn privacy_pool(self: @ContractState) -> ContractAddress {
            self.privacy_pool.read()
        }
    }
}
