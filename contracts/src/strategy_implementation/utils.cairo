use contracts::known_addresses::AVNU_EXCHANGE;
use contracts::strategy_implementation::avnu_interface::{
    AvnuParameters, IAvnuDispatcher, IAvnuDispatcherTrait,
};
use core::hash::HashStateTrait;
use core::panic_with_felt252;
use core::pedersen::PedersenTrait;
use starknet::ContractAddress;
use starknet::secp256_trait::Signature;
use crate::known_addresses::{
    ENDUR_LBTC, ENDUR_SOLVBTC, ENDUR_TBTC, ENDUR_WBTC, LBTC, SOLVBTC, TBTC, TROVES_LBTC,
    TROVES_SOLVBTC, TROVES_TBTC, TROVES_WBTC, WBTC,
};


pub(crate) const CONTRACT_ADDRESS_SALT: felt252 = 0;

const CONTRACT_ADDRESS_PREFIX: felt252 = 'STARKNET_CONTRACT_ADDRESS';


#[starknet::interface]
pub(crate) trait IERC4626Deposit<TContractState> {
    fn deposit(ref self: TContractState, assets: u256, receiver: ContractAddress) -> u256;
}

// These are the routes for the multi route swap function.

/// Supported Bitcoin wrapper tokens that can be used as `token_in` by the strategy
/// implementation. Each variant maps to a concrete ERC20 contract address via
/// `TokenTrait::contract_address`.
#[derive(Drop, Copy)]
pub(crate) enum Token {
    WBTC,
    TBTC,
    SOLVBTC,
    LBTC,
}


/// High-level strategy classification derived from (protocol selector + token_in) used by
/// `apply_on_self`.
/// For ENDUR and TROVES variants, the attached `Token` encodes the expected `token_in`.
/// AVNU does not carry a Token.
#[derive(Drop, Copy)]
pub(crate) enum Strategy {
    Endur: Token,
    Troves: Token,
    Avnu,
}

/// Helpers to derive concrete addresses from a high-level `Strategy`.
#[generate_trait]
pub(crate) impl _StrategyImpl of StrategyTrait {
    /// Returns the concrete strategy contract address for a given `Strategy`.
    fn strategy_address(self: Strategy) -> ContractAddress {
        match self {
            Strategy::Endur(Token::WBTC) => ENDUR_WBTC,
            Strategy::Endur(Token::TBTC) => ENDUR_TBTC,
            Strategy::Endur(Token::SOLVBTC) => ENDUR_SOLVBTC,
            Strategy::Endur(Token::LBTC) => ENDUR_LBTC,
            Strategy::Troves(Token::WBTC) => TROVES_WBTC,
            Strategy::Troves(Token::TBTC) => TROVES_TBTC,
            Strategy::Troves(Token::SOLVBTC) => TROVES_SOLVBTC,
            Strategy::Troves(Token::LBTC) => TROVES_LBTC,
            Strategy::Avnu => AVNU_EXCHANGE,
        }
    }
}


// A trait to get the contract address for a given Token.
#[generate_trait]
pub(crate) impl _TokenImpl of TokenTrait {
    fn contract_address(self: Token) -> ContractAddress {
        match self {
            Token::WBTC => WBTC,
            Token::TBTC => TBTC,
            Token::SOLVBTC => SOLVBTC,
            Token::LBTC => LBTC,
        }
    }
    fn new_from_token_address(token_in: ContractAddress) -> Token {
        if token_in == WBTC {
            return Token::WBTC;
        } else if token_in == TBTC {
            return Token::TBTC;
        } else if token_in == SOLVBTC {
            return Token::SOLVBTC;
        } else if token_in == LBTC {
            return Token::LBTC;
        } else {
            panic_with_felt252('INVALID_TOKEN');
        }
    }
}


/// Classifies `(protocol, token_in)` into a `Strategy`.
///
/// Reverts with:
/// - 'INVALID_PROTOCOL' if the protocol selector is unknown.
/// - 'INVALID_TOKEN' if `token_in` is not a supported wrapper token (ENDUR/TROVES only).
/// Note: for `protocol == 'AVNU'` we don't validate `token_in` here.
pub(crate) fn strategy_from_protocol_and_token(
    protocol: felt252, token_in: ContractAddress,
) -> Strategy {
    if protocol == 'AVNU' {
        return Strategy::Avnu;
    }

    let token = TokenTrait::new_from_token_address(:token_in);
    if protocol == 'TROVES' {
        return Strategy::Troves(token);
    }

    if protocol == 'ENDUR' {
        return Strategy::Endur(token);
    }

    panic_with_felt252('INVALID_PROTOCOL');
}


/// Computes the Pedersen hash on the elements of the span using a hash state.
pub(crate) fn compute_pedersen_on_elements(data: Span<felt252>) -> felt252 {
    let mut state = PedersenTrait::new(0);
    for value in data {
        state = state.update(*value);
    }
    state = state.update(data.len().into());
    state.finalize()
}


/// Computes the contract address for a given salt, class hash, constructor calldata and deployer
/// address.
pub(crate) fn compute_contract_address(
    salt: felt252,
    class_hash: felt252,
    constructor_calldata: Span<felt252>,
    deployer_address: felt252,
) -> ContractAddress {
    let calldata_hash = compute_pedersen_on_elements(constructor_calldata);

    let mut data = ArrayTrait::new();
    data.append(CONTRACT_ADDRESS_PREFIX);
    data.append(deployer_address);
    data.append(salt);
    data.append(class_hash);
    data.append(calldata_hash);

    let span = data.span();
    compute_pedersen_on_elements(span).try_into().expect('INVALID_CONTRACT_ADDRESS')
}


pub(crate) fn avnu_multi_route_swap(
    avnu: ContractAddress, avnu_parameters: AvnuParameters,
) -> bool {
    let avnu_interface = IAvnuDispatcher { contract_address: avnu };
    avnu_interface
        .multi_route_swap(
            sell_token_address: avnu_parameters.sell_token_address,
            sell_token_amount: avnu_parameters.sell_token_amount,
            buy_token_address: avnu_parameters.buy_token_address,
            buy_token_amount: avnu_parameters.buy_token_amount,
            buy_token_min_amount: avnu_parameters.buy_token_min_amount,
            beneficiary: avnu_parameters.beneficiary,
            integrator_fee_amount_bps: avnu_parameters.integrator_fee_amount_bps,
            integrator_fee_recipient: avnu_parameters.integrator_fee_recipient,
            routes: avnu_parameters.routes,
        )
}

/// Deserializes a secp256k1 signature from `parameters`, consuming 5 items:
/// `[r_high, r_low, s_high, s_low, v]`.
///
/// Returns `Signature { r: u256{low, high}, s: u256{low, high}, y_parity: bool }`.
/// Panics with `INVALID_SIGNATURE_FORMAT` if decoding fails.
pub(crate) fn deserialize_signature(ref parameters: Span<felt252>) -> Signature {
    let r_high: u128 = Serde::deserialize(ref parameters).expect('INVALID_SIGNATURE_FORMAT');
    let r_low: u128 = Serde::deserialize(ref parameters).expect('INVALID_SIGNATURE_FORMAT');
    let r: u256 = u256 { low: r_low, high: r_high };

    let s_high: u128 = Serde::deserialize(ref parameters).expect('INVALID_SIGNATURE_FORMAT');
    let s_low: u128 = Serde::deserialize(ref parameters).expect('INVALID_SIGNATURE_FORMAT');
    let s: u256 = u256 { low: s_low, high: s_high };

    // If v is 27 it should be false, if v is 28 it should be true.
    let v: u128 = Serde::deserialize(ref parameters).expect('INVALID_SIGNATURE_FORMAT');
    let y_parity: bool = v % 2 == 0;

    Signature { r, s, y_parity }
}
