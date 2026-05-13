use starknet::secp256_trait::Signature;
use starknet::{ClassHash, EthAddress};

#[starknet::interface]
pub trait IAccount712Admin<TContractState> {
    /// Bind the account to an owner key, identified by its Ethereum-format address.
    ///
    /// `owner_eth_address` is the secp256k1 public-key derived Ethereum-format address
    /// of whichever key will sign future `execute_from_outside_v2` calls. Under the
    /// Tier 2 unlinkable flow this is a fresh "session" key derived from a one-time
    /// MetaMask bootstrap signature — it is intentionally NOT the user's real MM
    /// address; nothing on chain ties this value back to the user's Ethereum identity.
    fn initialize(
        ref self: TContractState, owner_eth_address: EthAddress, signature: Signature,
    );
    fn upgrade(
        ref self: TContractState,
        new_class_hash: ClassHash,
        eic_data: Option<(ClassHash, Span<felt252>)>,
    );
}

#[starknet::interface]
pub trait IEIC<TContractState> {
    fn eic_initialize(ref self: TContractState, data: Span<felt252>);
}

/// Emitted when the contract is upgraded.
#[derive(Drop, Debug, PartialEq, starknet::Event)]
pub struct Upgraded {
    pub class_hash: ClassHash,
}
