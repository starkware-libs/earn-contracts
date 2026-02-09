use starknet::{ContractAddress, EthAddress};

#[starknet::interface]
pub trait IStrategyImplementation<TContractState> {
    fn account_factory(self: @TContractState) -> ContractAddress;

    /// Applies the decoded strategy to a prefunded position owner.
    /// Reverts on failure (the outer `apply` catches this and emits `ApplyFailed` + refunds).
    fn apply_on_self(
        ref self: TContractState,
        token_in: ContractAddress,
        amount: u256,
        position_owner: ContractAddress,
        eth_address: EthAddress,
        chain_id: felt252,
        protocol: felt252,
        parameters: Span<felt252>,
    );

    fn set_earn_reporter(ref self: TContractState, reporter: ContractAddress);

    /// Returns the current earn reporter contract address.
    fn earn_reporter(self: @TContractState) -> ContractAddress;

    /// Applies the strategy for the caller by transferring `amount` of `token_in`, executing
    /// the strategy encoded in the protocol selector and token_in, in `parameters`, and
    /// emitting `ApplyFailed` + refunding to the position owner on failure.
    ///
    /// `parameters` encodes: `(eth_address, signature, chain_id, protocol, payload...)`.
    /// For Avnu, `payload...` contains serialized `AvnuParameters`.
    fn apply(
        ref self: TContractState,
        token_in: ContractAddress,
        amount: u256,
        parameters: Span<felt252>,
    );
}
