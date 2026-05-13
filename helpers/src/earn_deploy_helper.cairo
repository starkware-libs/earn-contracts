use starknet::secp256_trait::Signature;
use starknet::{ContractAddress, EthAddress};

/// Return type expected by the Starknet privacy pool from any `privacy_invoke`
/// helper. We re-declare it locally with the same on-the-wire layout the pool
/// uses (`{ note_id: felt252, token: ContractAddress, amount: u256 }`) so this
/// crate stays decoupled from the privacy-pool repo. EarnDeployHelper never
/// produces deposits — it always returns `array![].span()` — so this struct's
/// fields are only ever serialized as a zero-length prefix and never carry data.
#[derive(Drop, Serde)]
pub struct OpenNoteDeposit {
    pub note_id: felt252,
    pub token: ContractAddress,
    pub amount: u256,
}

#[starknet::interface]
pub trait IEarnDeployHelper<TContractState> {
    /// Selector hit by the privacy pool's `_apply_invoke` syscall.
    ///
    /// Calldata layout (provided by the SDK when the user builds a private tx):
    ///   - session_eth_address: EthAddress     -- owner key for the new account
    ///   - signature:           Signature      -- secp256k1 ownership signature
    ///                                            over OWNERSHIP_TRANSFER_MSG_HASH
    ///                                            signed by the session key
    ///   - note_id:             felt252        -- unused here, but the privacy
    ///                                            pool's helper-contract
    ///                                            protocol always serializes a
    ///                                            note_id as the last argument
    ///                                            of any `privacy_invoke` call
    fn privacy_invoke(
        ref self: TContractState,
        session_eth_address: EthAddress,
        signature: Signature,
        note_id: felt252,
    ) -> Span<OpenNoteDeposit>;

    fn privacy_pool(self: @TContractState) -> ContractAddress;
    fn account_factory(self: @TContractState) -> ContractAddress;
}

/// Invoke helper that lets a private-pool transaction deploy a Tier 2 unlinkable
/// Starknet account in the same atomic proof that pays the paymaster fee.
///
/// The helper's only job is to forward `(session_eth_address, signature)` into
/// `IAccountFactory::deploy_account`. It accepts no tokens and forwards none —
/// if the caller wants to fund the new account in the same private tx, they
/// add an extra `withdraw` action to the same proof, targeting the account's
/// deterministic address (computable client-side from `session_eth_address`
/// before any on-chain state changes).
///
/// Privacy property: nothing this helper touches on-chain references the user's
/// real MetaMask address. The helper itself doesn't even know the MM address
/// exists — that's the whole point.
#[starknet::contract]
pub mod EarnDeployHelper {
    use account_factory::account_factory::{IAccountFactoryDispatcher, IAccountFactoryDispatcherTrait};
    use starknet::secp256_trait::Signature;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, EthAddress, get_caller_address};
    use super::{IEarnDeployHelper, OpenNoteDeposit};

    #[storage]
    struct Storage {
        privacy_pool: ContractAddress,
        account_factory: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        DeployedViaPool: DeployedViaPool,
    }

    /// Emitted on a successful helper invocation. Note: indexed by the helper's
    /// own address, not the user's; combined with the privacy-pool calldata
    /// being opaque, this leaks nothing back to a MetaMask identity.
    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct DeployedViaPool {
        pub account_address: ContractAddress,
    }

    #[constructor]
    pub fn constructor(
        ref self: ContractState,
        privacy_pool: ContractAddress,
        account_factory: ContractAddress,
    ) {
        self.privacy_pool.write(privacy_pool);
        self.account_factory.write(account_factory);
    }

    #[abi(embed_v0)]
    pub impl EarnDeployHelperImpl of IEarnDeployHelper<ContractState> {
        fn privacy_invoke(
            ref self: ContractState,
            session_eth_address: EthAddress,
            signature: Signature,
            note_id: felt252,
        ) -> Span<OpenNoteDeposit> {
            // note_id is part of the privacy-pool helper protocol but we have
            // no use for it here (we do not move funds through this helper).
            let _ = note_id;

            // Pool-only entry: any direct external caller would defeat the
            // unlinkability story by bypassing the proof verification step.
            let caller = get_caller_address();
            assert(caller == self.privacy_pool.read(), 'CALLER_NOT_PRIVACY_POOL');

            let factory = IAccountFactoryDispatcher {
                contract_address: self.account_factory.read(),
            };
            let account_address = factory
                .deploy_account(:session_eth_address, :signature);

            self.emit(Event::DeployedViaPool(DeployedViaPool { account_address }));

            // No surplus tokens to re-deposit into the pool. The pool's
            // Serde::deserialize<Span<OpenNoteDeposit>> on an empty span reads a
            // single zero-length felt — the inner struct shape is irrelevant.
            array![].span()
        }

        fn privacy_pool(self: @ContractState) -> ContractAddress {
            self.privacy_pool.read()
        }

        fn account_factory(self: @ContractState) -> ContractAddress {
            self.account_factory.read()
        }
    }
}
