use contracts::known_addresses::{AVNU_EXCHANGE, MIDAS_RE7_BTC};
use contracts::strategy_implementation::avnu_interface::{AvnuParameters, Route};
use contracts::strategy_implementation::interface::{
    IStrategyImplementationDispatcher, IStrategyImplementationDispatcherTrait,
};
use contracts::strategy_implementation::strategy_implementation::StrategyImplementation::{
    ApplyFailed, Deposited, MultiRouteSwap, PositionOwnerDeployed,
};
use contracts::strategy_implementation::utils::{
    Strategy, StrategyTrait, TokenTrait, deserialize_signature, strategy_from_protocol_and_token,
};
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::cheatcodes::events::Event;
use snforge_std::{ContractClassTrait, DeclareResultTrait, TokenImpl};
use starknet::eth_address::EthAddress;
use starknet::secp256_trait::Signature;
use starknet::{ContractAddress, SyscallResultTrait};
use starkware_utils::constants::SYMBOL;
use starkware_utils_testing::test_utils::{
    assert_expected_event_emitted, cheat_caller_address_once, set_account_as_app_governor,
    set_account_as_app_role_admin,
};
use crate::test_utils::{
    APP_GOVERNOR, APP_ROLE_ADMIN, GOVERNANCE_ADMIN, eth_address_to_account, get_event_by_selector,
    setup_account_factory_test_env,
};


#[derive(Drop, Copy)]
pub(crate) struct ApplyParameters {
    pub token_in: ContractAddress,
    pub amount: u256,
    pub parameters: Span<felt252>,
}

/// Sets default StrategyImplementation roles using testing helpers and constants.
pub(crate) fn set_strategy_implementation_default_roles(strategy_implementation: ContractAddress) {
    // App role admin
    set_account_as_app_role_admin(
        contract: strategy_implementation,
        account: APP_ROLE_ADMIN(),
        governance_admin: GOVERNANCE_ADMIN(),
    );
    // App governor (requires app role admin)
    set_account_as_app_governor(
        contract: strategy_implementation,
        account: APP_GOVERNOR(),
        app_role_admin: APP_ROLE_ADMIN(),
    );
}


pub(crate) fn strategy_implementation_constructor_calldata(
    account_factory_addr: ContractAddress,
) -> Array<felt252> {
    let mut calldata: Array<felt252> = array![];
    Serde::serialize(@GOVERNANCE_ADMIN(), ref calldata);
    Serde::serialize(@0, ref calldata);
    Serde::serialize(@account_factory_addr, ref calldata);
    calldata
}

/// Sets up the test environment for StrategyImplementation by declaring the primer contract,
/// deploying the account factory contract, and deploying the strategy implementation contract.
/// Returns the address of the strategy implementation contract.
pub(crate) fn setup_strategy_implementation_test_env() -> ContractAddress {
    // Set up the account factory test environment (deploy + roles + declare primer).
    let account_factory_addr = setup_account_factory_test_env();
    let calldata = strategy_implementation_constructor_calldata(:account_factory_addr);
    deploy_strategy_implementation_with_calldata(calldata)
}

pub(crate) fn deploy_strategy_implementation_with_calldata(
    calldata: Array<felt252>,
) -> ContractAddress {
    let strategy_implementation_contract = snforge_std::declare("StrategyImplementation")
        .unwrap_syscall()
        .contract_class();
    let (strategy_implementation_contract_address, _) = strategy_implementation_contract
        .deploy(@calldata)
        .unwrap_syscall();
    set_strategy_implementation_default_roles(strategy_implementation_contract_address);

    strategy_implementation_contract_address
}


pub(crate) fn dummy_apply_parameters(token_in: ContractAddress, amount: u256) -> ApplyParameters {
    dummy_apply_parameters_with_protocol('DUMMY_PROTOCOL', :token_in, :amount)
}

/// Serializes a `Signature` into calldata in the exact layout expected by the strategy code.
/// Layout (5 felts): `r_high, r_low, s_high, s_low, y_parity`.
pub(crate) fn serialize_signature(signature: @Signature, ref calldata: Array<felt252>) {
    Serde::serialize(signature.r.high, ref calldata);
    Serde::serialize(signature.r.low, ref calldata);
    Serde::serialize(signature.s.high, ref calldata);
    Serde::serialize(signature.s.low, ref calldata);
    Serde::serialize(signature.y_parity, ref calldata);
}

pub(crate) fn dummy_apply_parameters_with_protocol(
    protocol: felt252, token_in: ContractAddress, amount: u256,
) -> ApplyParameters {
    let mut calldata = ArrayTrait::new();
    let eth_address: EthAddress = '0x1012'.try_into().unwrap();
    let signature: Signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };
    Serde::serialize(@eth_address, ref calldata);
    serialize_signature(signature: @signature, ref calldata: calldata);
    Serde::serialize(@1, ref calldata); // chain id
    Serde::serialize(@protocol, ref calldata);
    ApplyParameters { token_in, amount, parameters: calldata.span() }
}


/// Deploys a dummy ERC20 at `address_to_deploy_at` with a fixed initial supply and owner,
/// then prefunds `account_to_fund` with `amount` and approves the StrategyImplementation
/// contract to pull `amount` via ERC20 `transfer_from`.
pub(crate) fn deploy_and_prefund_dummy_erc20_at(
    strategy_implementation_addr: ContractAddress,
    account_to_fund: ContractAddress,
    address_to_deploy_at: ContractAddress,
    amount: u256,
) {
    let minted_account: ContractAddress = 0x10.try_into().unwrap();
    deploy_mock_erc20_contract_at(
        initial_supply: 1000_u256,
        owner_address: minted_account,
        name: "DummyERC20",
        address_to_deploy_at: address_to_deploy_at,
    );
    cheat_transfer_and_approve(
        token: address_to_deploy_at,
        :amount,
        funds_sender: minted_account,
        funds_receiver: account_to_fund,
        approve_to: strategy_implementation_addr,
    );
}

/// Deploys a dummy ERC20, prefunds `account_to_fund`, and returns ApplyParameters
/// (token_in = dummy token, amount, parameters = encoded (eth_address, signature, chain_id,
/// protocol)).
pub(crate) fn build_prefunded_apply_parameters_with_amount(
    strategy_implementation_addr: ContractAddress, account_to_fund: ContractAddress, amount: u256,
) -> ApplyParameters {
    let dummy_token: ContractAddress = 0x45692.try_into().unwrap();
    deploy_and_prefund_dummy_erc20_at(
        :strategy_implementation_addr, :account_to_fund, address_to_deploy_at: dummy_token, :amount,
    );
    dummy_apply_parameters(token_in: dummy_token, :amount)
}


/// Deploys a dummy ERC20 at `address_to_deploy_at`, prefunds `account_to_fund` with 500_u256,
/// and returns ApplyParameters with token_in fixed to `address_to_deploy_at`.
pub(crate) fn build_prefunded_apply_parameters_with_token_address(
    strategy_implementation_addr: ContractAddress,
    account_to_fund: ContractAddress,
    address_to_deploy_at: ContractAddress,
    protocol: felt252,
) -> ApplyParameters {
    let amount = 500_u256;
    deploy_and_prefund_dummy_erc20_at(
        :strategy_implementation_addr, :account_to_fund, :address_to_deploy_at, :amount,
    );
    dummy_apply_parameters_with_protocol(:protocol, token_in: address_to_deploy_at, :amount)
}


/// Deploys a dummy ERC20 at `address_to_deploy_at`, prefunds `account_to_fund` with 500_u256,
/// and returns ApplyParameters sized for ~10 calls (amount / 10).
pub(crate) fn build_prefunded_for_few_apply_calls(
    strategy_implementation_addr: ContractAddress,
    account_to_fund: ContractAddress,
    address_to_deploy_at: ContractAddress,
    protocol: felt252,
) -> ApplyParameters {
    let amount = 500_u256;
    deploy_and_prefund_dummy_erc20_at(
        :strategy_implementation_addr, :account_to_fund, :address_to_deploy_at, :amount,
    );
    dummy_apply_parameters_with_protocol(
        :protocol, token_in: address_to_deploy_at, amount: amount / 10,
    )
}


/// Deploys dummy ERC20s for token_in, prefunds `account_to_fund` with 500_u256 of token_in, and
/// returns Avnu ApplyParameters:
/// (token_in, amount, parameters encoding (eth_address, signature, chain_id,
/// protocol='AVNU', AvnuParameters)).
pub(crate) fn build_prefunded_avnu(
    strategy_implementation_addr: ContractAddress,
    account_to_fund: ContractAddress,
    address_to_deploy_token_in: ContractAddress,
) -> ApplyParameters {
    let buy_token = MIDAS_RE7_BTC;
    let amount = 500_u256;
    deploy_and_prefund_dummy_erc20_at(
        :strategy_implementation_addr,
        :account_to_fund,
        address_to_deploy_at: address_to_deploy_token_in,
        :amount,
    );
    // In order to transfer the funds from avnu of the token out, we let the avnu be the owner of
    // the token out.
    deploy_mock_erc20_contract_at(
        initial_supply: amount,
        owner_address: AVNU_EXCHANGE,
        name: "DummyERC20",
        address_to_deploy_at: buy_token,
    );
    let avnu_parameters = dummy_avnu_parameters(
        :strategy_implementation_addr, token_in: address_to_deploy_token_in, :buy_token, :amount,
    );
    ApplyParameters { token_in: address_to_deploy_token_in, amount, parameters: avnu_parameters }
}


fn dummy_avnu_parameters(
    strategy_implementation_addr: ContractAddress,
    token_in: ContractAddress,
    buy_token: ContractAddress,
    amount: u256,
) -> Span<felt252> {
    // The parameters for apply when calling avnu_multi_route_swap are:
    // eth_address, signature, chain_id, protocol, ...tail.
    // Within the tail (which is used for avnu_multi_route_swap), the parameters are:
    // avnu_multi_route_swap parameters:
    // 1. sell_token_address: ContractAddress
    // 2. sell_token_amount: u256
    // 3. buy_token_address: ContractAddress
    // 4. buy_token_amount: u256
    // 5. buy_token_min_amount: u256
    // 6. beneficiary: ContractAddress
    // 7. integrator_fee_amount_bps: u128
    // 8. integrator_fee_recipient: ContractAddress
    // 9. routes: Array<Route>
    let eth_address: EthAddress = '0x1012'.try_into().unwrap();
    let signature: Signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };
    let chain_id: felt252 = 1;
    // The beneficiary is the strategy implementation address.
    let beneficiary = strategy_implementation_addr;

    let integrator_fee_amount_bps: u128 = 100_u128;
    let integrator_fee_recipient: ContractAddress = 0x1014.try_into().unwrap();
    let route1 = Route {
        sell_token: token_in,
        buy_token,
        exchange_address: AVNU_EXCHANGE,
        percent: 20_u128,
        additional_swap_params: array![1, 2, 3, 4, 5].span(),
    };
    let route2 = Route {
        sell_token: buy_token,
        buy_token: token_in,
        exchange_address: AVNU_EXCHANGE,
        percent: 40_u128,
        additional_swap_params: array![6, 7, 8, 9, 10].span(),
    };
    let routes = array![route1, route2];
    let avnu_parameters_to_serialize = AvnuParameters {
        sell_token_address: token_in,
        sell_token_amount: amount,
        buy_token_address: buy_token,
        buy_token_amount: amount,
        buy_token_min_amount: amount - 1,
        beneficiary,
        integrator_fee_amount_bps,
        integrator_fee_recipient,
        routes,
    };
    let mut avnu_parameters = ArrayTrait::new();
    // Serialize the common parameters.
    Serde::serialize(@eth_address, ref avnu_parameters);
    serialize_signature(signature: @signature, ref calldata: avnu_parameters);
    Serde::serialize(@chain_id, ref avnu_parameters);
    Serde::serialize(@'AVNU', ref avnu_parameters);
    // Serialize the avnu parameters.
    Serde::serialize(@avnu_parameters_to_serialize, ref avnu_parameters);
    avnu_parameters.span()
}


/// Asserts Avnu swap success outcome:
/// - strategy implementation holds no `token_in`.
/// - position owner received `buy_token` >= `buy_token_min_amount` derived from parameters.
/// - a `MultiRouteSwap` event with expected fields is emitted by the strategy implementation.
/// - the overall emitted events match the success case (only `MultiRouteSwap`).
pub(crate) fn validate_avnu_swap(
    events: Span<(ContractAddress, Event)>,
    strategy_implementation_addr: ContractAddress,
    token_in: ContractAddress,
    amount: u256,
    parameters: @ApplyParameters,
) {
    let mut params_to_serde = *parameters.parameters;
    let eth_address = deserialize_eth_address_and_skip_signature_and_chain_id(ref params_to_serde);
    let account_factory = get_account_factory(:strategy_implementation_addr);
    let position_owner = eth_address_to_account(:account_factory, :eth_address);

    let _: felt252 = Serde::deserialize(ref params_to_serde).expect('INVALID_PROTOCOL');
    let avnu_parameters: AvnuParameters = Serde::deserialize(ref params_to_serde)
        .expect('INVALID_AVNU_PARAMETERS');
    let buy_token_address = avnu_parameters.buy_token_address;
    let buy_token = IERC20Dispatcher { contract_address: buy_token_address };
    let sell_token = IERC20Dispatcher { contract_address: token_in };
    assert!(
        sell_token.balance_of(strategy_implementation_addr) == 0,
        "strategy implementation should hold 0 of token_in after Avnu swap",
    );

    // Assuming that the buy token balance before was 0.
    let buy_token_balance = buy_token.balance_of(position_owner);
    assert!(
        buy_token_balance >= avnu_parameters.buy_token_min_amount,
        "position owner did not receive enough buy_token (below min)",
    );
    let expected_event = MultiRouteSwap {
        position_owner,
        sell_token: token_in,
        amount_sold: amount,
        // In the test we are using all the amount of token_in, so there is no amount not sold.
        amount_not_sold: 0,
        buy_token: buy_token_address,
        amount_received: buy_token_balance,
    };
    let spied_event = get_event_by_selector(:events, selector: selector!("MultiRouteSwap"))
        .unwrap();
    assert_expected_event_emitted(
        :spied_event,
        :expected_event,
        expected_event_selector: @selector!("MultiRouteSwap"),
        expected_event_name: "MultiRouteSwap",
    );

    // Expect exactly one event (the MultiRouteSwap asserted above)
    assert!(events.len() == 1, "expected exactly 1 event (MultiRouteSwap) on success");
}

pub(crate) fn deserialize_eth_address_and_skip_signature_and_chain_id(
    ref params_to_serde: Span<felt252>,
) -> EthAddress {
    let eth_address = Serde::deserialize(ref params_to_serde).expect('INVALID_ETH_ADDRESS');
    let _: Signature = deserialize_signature(ref params_to_serde);
    let _: felt252 = Serde::deserialize(ref params_to_serde).expect('SERIALIZATION_FAILED');
    eth_address
}

pub(crate) fn get_account_factory(
    strategy_implementation_addr: ContractAddress,
) -> ContractAddress {
    let strategy_implementation = IStrategyImplementationDispatcher {
        contract_address: strategy_implementation_addr,
    };
    strategy_implementation.account_factory()
}


pub(crate) fn get_position_owner(
    strategy_implementation_addr: ContractAddress, parameters: @Span<felt252>,
) -> ContractAddress {
    let account_factory = get_account_factory(:strategy_implementation_addr);
    let mut params_to_serde = *parameters;
    let eth_address = Serde::deserialize(ref params_to_serde).expect('INVALID_ETH_ADDRESS');
    eth_address_to_account(:account_factory, :eth_address)
}


pub(crate) fn apply(
    strategy_implementation_addr: ContractAddress,
    apply_caller: ContractAddress,
    parameters: ApplyParameters,
) {
    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: apply_caller,
    );
    let strategy_implementation = IStrategyImplementationDispatcher {
        contract_address: strategy_implementation_addr,
    };
    strategy_implementation
        .apply(
            token_in: parameters.token_in,
            amount: parameters.amount,
            parameters: parameters.parameters,
        );
}


/// Asserts that the handle_failure path is taken and the position owner received the full balance
/// of the token after failure.
pub(crate) fn assert_apply_failed_with_refund(
    events: Span<(ContractAddress, Event)>,
    strategy_implementation_addr: ContractAddress,
    mut apply_parameters: ApplyParameters,
    errors: Array<felt252>,
) {
    let eth_address = deserialize_eth_address_and_skip_signature_and_chain_id(
        ref apply_parameters.parameters,
    );
    let account_factory = get_account_factory(:strategy_implementation_addr);
    let position_owner = eth_address_to_account(:account_factory, :eth_address);
    let _token = IERC20Dispatcher { contract_address: apply_parameters.token_in };

    // Assert that the position owner received the full balance of the token after failure.
    assert!(
        _token.balance_of(position_owner) == apply_parameters.amount,
        "position owner should receive the full balance",
    );
    // Assert that the strategy implementation did not receive any balance of the token after
    // failure.
    assert!(
        _token.balance_of(strategy_implementation_addr) == 0,
        "strategy implementation should have zero balance after refund",
    );

    // Assert that the ApplyFailed event was emitted with the expected arguments.
    let protocol: felt252 = Serde::deserialize(ref apply_parameters.parameters)
        .expect('PROTOCOL_SERIALIZATION_FAILED');
    assert_apply_failed_event(
        :events,
        :position_owner,
        :protocol,
        token_in: apply_parameters.token_in,
        amount: apply_parameters.amount,
        :errors,
    );
}

pub(crate) fn assert_apply_failed_event(
    events: Span<(ContractAddress, Event)>,
    position_owner: ContractAddress,
    protocol: felt252,
    token_in: ContractAddress,
    amount: u256,
    errors: Array<felt252>,
) {
    let expected_event = ApplyFailed { position_owner, protocol, token_in, amount, errors };
    let spied_event = get_event_by_selector(:events, selector: selector!("ApplyFailed")).unwrap();
    assert_expected_event_emitted(
        :spied_event,
        :expected_event,
        expected_event_selector: @selector!("ApplyFailed"),
        expected_event_name: "ApplyFailed",
    );
}


/// Asserts that the nth `Deposited` event matches the expected args.
/// - `protocol`: apply header protocol felt (`'ENDUR'` / `'TROVES'`).
/// - `wrapper_token`: wrapper `token_in` used for classification.
/// - If `protocol == 'TROVES'`, the expected emitted `Deposited.token` is the LST token.
pub(crate) fn assert_deposited_event(
    events: Span<(ContractAddress, Event)>,
    funds_receiver: ContractAddress,
    protocol: felt252,
    wrapper_token: ContractAddress,
    amount_deposited: u256,
    amount_received: u256,
) {
    let strategy = strategy_from_protocol_and_token(:protocol, token_in: wrapper_token);

    // Expected `Deposited.token` (the asset deposited into the vault).
    let mut deposited_token = wrapper_token;
    if protocol == 'TROVES' {
        deposited_token =
            Strategy::Endur(TokenTrait::new_from_token_address(token_in: wrapper_token))
            .strategy_address();
    }
    let expected_event = Deposited {
        receiver_address: funds_receiver,
        token_deposited: wrapper_token,
        amount_deposited: amount_deposited,
        token_received: strategy.strategy_address(),
        amount_received: amount_received,
    };
    let spied_event = get_event_by_selector(:events, selector: selector!("Deposited")).unwrap();

    assert_expected_event_emitted(
        :spied_event,
        :expected_event,
        expected_event_selector: @selector!("Deposited"),
        expected_event_name: "Deposited",
    );
}


/// Asserts that a `PositionOwnerDeployed` event was emitted with the given arguments.
pub(crate) fn assert_position_owner_deployed_event(
    events: Span<(ContractAddress, Event)>, position_owner: ContractAddress,
) {
    let expected_event = PositionOwnerDeployed { position_owner };
    let spied_event = get_event_by_selector(:events, selector: selector!("PositionOwnerDeployed"))
        .unwrap();

    assert_expected_event_emitted(
        :spied_event,
        :expected_event,
        expected_event_selector: @selector!("PositionOwnerDeployed"),
        expected_event_name: "PositionOwnerDeployed",
    );
}


pub(crate) fn cheat_transfer(
    token: ContractAddress, amount: u256, from: ContractAddress, to: ContractAddress,
) {
    let _token = IERC20Dispatcher { contract_address: token };
    cheat_caller_address_once(contract_address: token, caller_address: from);
    _token.transfer(to, amount);
}

pub(crate) fn cheat_approve(
    token: ContractAddress, amount: u256, from: ContractAddress, to: ContractAddress,
) {
    let _token = IERC20Dispatcher { contract_address: token };
    cheat_caller_address_once(contract_address: token, caller_address: from);
    _token.approve(to, amount);
}

/// Test helper that sets up token flow for StrategyImplementation:
/// - transfers `amount` of `token` from `funds_sender` to `funds_receiver`.
/// - then, from `funds_receiver`, approves `approve_to` to spend `amount` via ERC20
/// `transfer_from`.
pub(crate) fn cheat_transfer_and_approve(
    token: ContractAddress,
    amount: u256,
    funds_sender: ContractAddress,
    funds_receiver: ContractAddress,
    approve_to: ContractAddress,
) {
    let _token = IERC20Dispatcher { contract_address: token };
    cheat_caller_address_once(contract_address: token, caller_address: funds_sender);
    _token.transfer(funds_receiver, amount);
    cheat_caller_address_once(contract_address: token, caller_address: funds_receiver);
    _token.approve(approve_to, amount);
}

pub(crate) fn deploy_mock_erc20_contract_at(
    initial_supply: u256,
    owner_address: ContractAddress,
    name: ByteArray,
    address_to_deploy_at: ContractAddress,
) {
    let mut calldata = ArrayTrait::new();
    name.serialize(ref calldata);
    SYMBOL().serialize(ref calldata);
    initial_supply.serialize(ref calldata);
    owner_address.serialize(ref calldata);
    let erc20_contract = snforge_std::declare("DualCaseERC20Mock")
        .unwrap_syscall()
        .contract_class();
    let (token_address, _) = erc20_contract
        .deploy_at(@calldata, address_to_deploy_at)
        .unwrap_syscall();
    assert!(token_address == address_to_deploy_at, "deploy_at failed");
}


// -----------------------------------------------------------------------------
// Minimal ERC4626-like mock for tests: deposit pulls an ERC20 asset from the caller
// and mints a different token (shares) to the receiver. Requires prior approval.
// -----------------------------------------------------------------------------
#[starknet::interface]
pub trait IERC4626DepositMintMock<TContractState> {
    fn shares_balance_of(self: @TContractState, account: ContractAddress) -> u256;
    fn preview_deposit(self: @TContractState, assets: u256) -> u256;
}

#[starknet::contract]
pub mod ERC4626DepositMintMock {
    use contracts::strategy_implementation::test_utils::IERC4626DepositMintMock;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use openzeppelin::token::erc20::{DefaultConfig, ERC20Component, ERC20HooksEmptyImpl};
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);

    #[abi(embed_v0)]
    impl ERC20Impl = ERC20Component::ERC20Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC20MetadataImpl = ERC20Component::ERC20MetadataImpl<ContractState>;
    impl InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        pub ERC4626_asset: ContractAddress,
        pub ERC20_asset: ContractAddress,
        pub ERC20_owner_address: ContractAddress,
    }


    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, erc4626_asset_address: ContractAddress) {
        // This is the token that will be deposited into the ERC4626 contract.
        self.ERC4626_asset.write(erc4626_asset_address);
        // Initialize the ERC20 token. This is the token that will be minted to the receiver.
        self.erc20.initializer(name: "DummyERC20", symbol: "DUMMY");
    }

    // Mimics an ERC4626 deposit but simply mints shares equal to assets * 2
    // and credits them to the receiver.
    #[external(v0)]
    fn deposit(ref self: ContractState, assets: u256, receiver: ContractAddress) -> u256 {
        // Transfer the assets from the caller to the contract.
        let caller = starknet::get_caller_address();
        let this = starknet::get_contract_address();
        let asset_dispatcher = IERC20Dispatcher { contract_address: self.ERC4626_asset.read() };
        asset_dispatcher.transfer_from(caller, this, assets);

        // Mint "shares" (a different token) directly to the receiver.
        let shares = self.preview_deposit(assets);
        self.erc20.mint(receiver, shares);
        shares
    }
    #[abi(embed_v0)]
    impl ERC4626DepositMintMockImpl of IERC4626DepositMintMock<ContractState> {
        fn shares_balance_of(self: @ContractState, account: ContractAddress) -> u256 {
            self.erc20.balance_of(account)
        }
        fn preview_deposit(self: @ContractState, assets: u256) -> u256 {
            assets * 2
        }
    }
}

pub(crate) fn deploy_erc4626_deposit_mint_mock(
    erc4626_asset_address: ContractAddress, address_to_deploy_at: ContractAddress,
) {
    let mut calldata = ArrayTrait::new();
    erc4626_asset_address.serialize(ref calldata);
    let cls = snforge_std::declare("ERC4626DepositMintMock").unwrap_syscall().contract_class();
    let (erc4626, _) = cls.deploy_at(@calldata, address_to_deploy_at).unwrap_syscall();
    assert!(erc4626 == address_to_deploy_at, "deploy_at failed");
}

// -----------------------------------------------------------------------------
// Minimal ERC4626-like mock for tests: panics with 'ERROR' for all deposits.
// -----------------------------------------------------------------------------
#[starknet::contract]
pub mod ERC4626DepositMockFailure {
    use core::panic_with_felt252;
    use openzeppelin::token::erc20::{DefaultConfig, ERC20Component, ERC20HooksEmptyImpl};
    use starknet::ContractAddress;


    #[storage]
    struct Storage {}


    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
    }

    // Panics with 'ERROR' for all deposits.
    #[external(v0)]
    fn deposit(ref self: ContractState, assets: u256, receiver: ContractAddress) -> u256 {
        panic_with_felt252('ERROR');
    }
}

pub(crate) fn deploy_4626_failure_mock(address_to_deploy_at: ContractAddress) {
    let mut calldata = ArrayTrait::new();
    let cls = snforge_std::declare("ERC4626DepositMockFailure").unwrap_syscall().contract_class();
    let (erc4626, _) = cls.deploy_at(@calldata, address_to_deploy_at).unwrap_syscall();
    assert!(erc4626 == address_to_deploy_at, "deploy_at failed");
}

// -----------------------------------------------------------------------------
// Dummy Avnu-like contract: deserializes swap params, pulls sell token, sends
// buy token to caller, and returns true. Used to test Avnu multi_route_swap.
// -----------------------------------------------------------------------------
#[starknet::contract]
pub mod DummyAvnu {
    use contracts::strategy_implementation::avnu_interface::AvnuParameters;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn multi_route_swap(ref self: ContractState, avnu_parameters: AvnuParameters) -> bool {
        let sell_token = IERC20Dispatcher { contract_address: avnu_parameters.sell_token_address };
        let buy_token = IERC20Dispatcher { contract_address: avnu_parameters.buy_token_address };
        sell_token
            .transfer_from(
                starknet::get_caller_address(),
                starknet::get_contract_address(),
                avnu_parameters.sell_token_amount,
            );
        buy_token.transfer(starknet::get_caller_address(), avnu_parameters.buy_token_min_amount);
        true
    }
}

pub(crate) fn deploy_dummy_avnu(address_to_deploy_at: ContractAddress) {
    let mut calldata = ArrayTrait::new();
    let cls = snforge_std::declare("DummyAvnu").unwrap_syscall().contract_class();

    let (addr, _) = cls.deploy_at(@calldata, address_to_deploy_at).unwrap_syscall();
    assert!(addr == address_to_deploy_at, "deploy_at failed");
}


// -----------------------------------------------------------------------------
// Dummy Avnu failure contract: transfers less than buy_token_min_amount to caller, and returns
// true.
// Used to simulate under-delivery in Avnu multi_route_swap tests.
// -----------------------------------------------------------------------------
#[starknet::contract]
pub mod DummyAvnuFailure {
    use contracts::strategy_implementation::avnu_interface::AvnuParameters;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};

    #[storage]
    struct Storage {}

    #[external(v0)]
    fn multi_route_swap(ref self: ContractState, avnu_parameters: AvnuParameters) -> bool {
        let sell_token = IERC20Dispatcher { contract_address: avnu_parameters.sell_token_address };
        let buy_token = IERC20Dispatcher { contract_address: avnu_parameters.buy_token_address };
        sell_token
            .transfer_from(
                starknet::get_caller_address(),
                starknet::get_contract_address(),
                avnu_parameters.sell_token_amount,
            );
        buy_token
            .transfer(starknet::get_caller_address(), avnu_parameters.buy_token_min_amount - 1);
        true
    }
}

pub(crate) fn deploy_dummy_avnu_failure(address_to_deploy_at: ContractAddress) {
    let mut calldata = ArrayTrait::new();
    let cls = snforge_std::declare("DummyAvnuFailure").unwrap_syscall().contract_class();

    let (addr, _) = cls.deploy_at(@calldata, address_to_deploy_at).unwrap_syscall();
    assert!(addr == address_to_deploy_at, "deploy_at failed");
}


// -----------------------------------------------------------------------------
// Dummy Avnu failure contract: return false in Avnu multi_route_swap.
// -----------------------------------------------------------------------------
#[starknet::contract]
pub mod DummyAvnuFalse {
    use contracts::strategy_implementation::avnu_interface::AvnuParameters;
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn multi_route_swap(ref self: ContractState, parameters: AvnuParameters) -> bool {
        false
    }
}

pub(crate) fn deploy_dummy_avnu_false(address_to_deploy_at: ContractAddress) {
    let mut calldata = ArrayTrait::new();
    let cls = snforge_std::declare("DummyAvnuFalse").unwrap_syscall().contract_class();

    let (addr, _) = cls.deploy_at(@calldata, address_to_deploy_at).unwrap_syscall();
    assert!(addr == address_to_deploy_at, "deploy_at failed");
}
