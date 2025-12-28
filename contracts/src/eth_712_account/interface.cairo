use starknet::secp256_trait::Signature;
use starknet::{ClassHash, EthAddress};

#[starknet::interface]
pub trait IAccount712Admin<TContractState> {
    fn initialize(ref self: TContractState, eth_address: EthAddress, signature: Signature);
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
