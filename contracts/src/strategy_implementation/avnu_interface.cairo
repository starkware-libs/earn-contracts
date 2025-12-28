use starknet::ContractAddress;

#[starknet::interface]
pub(crate) trait IAvnu<TContractState> {
    fn multi_route_swap(
        ref self: TContractState,
        sell_token_address: ContractAddress,
        sell_token_amount: u256,
        buy_token_address: ContractAddress,
        buy_token_amount: u256,
        buy_token_min_amount: u256,
        beneficiary: ContractAddress,
        integrator_fee_amount_bps: u128,
        integrator_fee_recipient: ContractAddress,
        routes: Array<Route>,
    ) -> bool;
}

#[derive(Drop, Serde, Clone)]
pub(crate) struct Route {
    pub sell_token: ContractAddress,
    pub buy_token: ContractAddress,
    pub exchange_address: ContractAddress,
    pub percent: u128,
    pub additional_swap_params: Span<felt252>,
}


// These are the parameters for the multi route swap function.
#[derive(Drop, Serde, Clone)]
pub(crate) struct AvnuParameters {
    pub sell_token_address: ContractAddress,
    pub sell_token_amount: u256,
    pub buy_token_address: ContractAddress,
    pub buy_token_amount: u256,
    pub buy_token_min_amount: u256,
    pub beneficiary: ContractAddress,
    pub integrator_fee_amount_bps: u128,
    pub integrator_fee_recipient: ContractAddress,
    pub routes: Array<Route>,
}

