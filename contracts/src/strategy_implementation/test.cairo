use contracts::known_addresses::{
    AVNU_EXCHANGE, ENDUR_TBTC, ENDUR_WBTC, LBTC, TBTC, TROVES_TBTC, WBTC,
};
use contracts::strategy_implementation::interface::{
    IStrategyImplementationDispatcher, IStrategyImplementationDispatcherTrait,
    IStrategyImplementationSafeDispatcher, IStrategyImplementationSafeDispatcherTrait,
};
use core::array::ArrayTrait;
use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::TokenImpl;
use snforge_std::cheatcodes::events::{EventSpyTrait, EventsFilterTrait};
use starknet::ContractAddress;
use starknet::eth_address::EthAddress;
use starknet::secp256_trait::Signature;
use starkware_utils_testing::test_utils::{assert_panic_with_felt_error, cheat_caller_address_once};
use crate::strategy_implementation::test_utils::{
    ApplyParameters, IERC4626DepositMintMockDispatcher, IERC4626DepositMintMockDispatcherTrait,
    apply, assert_apply_failed_with_refund, assert_deposited_event,
    build_prefunded_apply_parameters_with_amount,
    build_prefunded_apply_parameters_with_token_address, build_prefunded_avnu,
    cheat_transfer_and_approve, deploy_4626_failure_mock, deploy_and_prefund_dummy_erc20_at,
    deploy_dummy_avnu, deploy_dummy_avnu_failure, deploy_dummy_avnu_false,
    deploy_erc4626_deposit_mint_mock, deploy_mock_erc20_contract_at, dummy_apply_parameters,
    dummy_apply_parameters_with_protocol, get_account_factory, get_position_owner,
    serialize_signature, setup_strategy_implementation_test_env, validate_avnu_swap,
};
use crate::test_utils::get_event_by_selector;


#[test]
fn test_apply_zero_amount_returns() {
    /// Apply(amount = 0): expect the call to return immediately without any further logic.

    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    let apply_parameters = build_prefunded_apply_parameters_with_amount(
        :strategy_implementation_addr, account_to_fund: apply_caller, amount: 0,
    );

    // Act: call apply with amount 0. This should return immediately without any further logic.
    let mut spy = snforge_std::spy_events();
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    assert!(events.len() == 0, "No events expected on apply with amount 0");
}

#[test]
#[should_panic(expected: 'ONLY_SELF_CALLER')]
fn test_apply_on_self_invalid_caller_panics() {
    /// apply_on_self should only be callable by the strategy implementation contract itself.
    /// Here we impersonate a different caller and expect the function to panic with
    /// 'ONLY_SELF_CALLER'.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let strategy_implementation = IStrategyImplementationDispatcher {
        contract_address: strategy_implementation_addr,
    };

    // Impersonate a non-self caller for the next call.
    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: 0x1234.try_into().unwrap(),
    );

    let position_owner: ContractAddress = 0x10.try_into().unwrap();
    let parameters = array![].span();

    // This should panic with 'ONLY_SELF_CALLER' due to the caller-address guard in apply_on_self.
    strategy_implementation
        .apply_on_self(
            token_in: WBTC, amount: 0_u256, :position_owner, protocol: 'ENDUR', :parameters,
        );
}

#[test]
fn test_apply_invalid_protocol() {
    /// Apply with an unknown protocol selector.
    /// Since `token_in` is valid (WBTC), protocol classification should fail with
    /// `INVALID_PROTOCOL`, emitting ApplyFailed, and refunding.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Use an unknown protocol selector; header classification should reject it as INVALID_PROTOCOL.
    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: WBTC,
        protocol: 'BAD',
    );

    let mut spy = snforge_std::spy_events();
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
    // Apply failed path should emit ApplyFailed + transfer the amount to the position
    // owner.
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['INVALID_PROTOCOL', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, :apply_parameters, :errors,
    );
}

#[test]
fn test_apply_invalid_token_emits_apply_failed_and_refunds() {
    /// Apply with a valid protocol but an unknown `token_in`:
    /// header classification must fail with INVALID_TOKEN, emitting ApplyFailed,
    /// and refunding.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Use a dummy ERC20 address that is not one of the supported wrapper tokens.
    let unknown_token: ContractAddress = 0x45692.try_into().unwrap();
    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: unknown_token,
        protocol: 'ENDUR',
    );

    let mut spy = snforge_std::spy_events();
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);

    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['INVALID_TOKEN', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, :apply_parameters, :errors,
    );
}


#[test]
#[feature("safe_dispatcher")]
fn test_deposit_token_to_vault_amount_greater_than_balance_panics() {
    /// Apply with amount > approved balance: deposit_token_to_vault triggers an ERC20
    /// `insufficient allowance` panic and emits no events.

    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let strategy_implementation = IStrategyImplementationSafeDispatcher {
        contract_address: strategy_implementation_addr,
    };
    let apply_caller = 0x4324.try_into().unwrap();

    let minted_account: ContractAddress = 0x10.try_into().unwrap();
    deploy_mock_erc20_contract_at(
        initial_supply: 1000_u256,
        owner_address: minted_account,
        name: "DummyERC20",
        address_to_deploy_at: WBTC,
    );

    // Prefund with 200
    let balance = 200;
    cheat_transfer_and_approve(
        token: WBTC,
        amount: balance,
        funds_sender: minted_account,
        funds_receiver: apply_caller,
        approve_to: strategy_implementation_addr,
    );
    let amount = 300_u256;
    let apply_parameters = dummy_apply_parameters(token_in: WBTC, :amount);

    let mut spy = snforge_std::spy_events();
    // Apply with 300 > 200. Should panic with ERC20: insufficient allowance from failure path.
    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: apply_caller,
    );
    let mut result = strategy_implementation
        .apply(
            token_in: apply_parameters.token_in,
            amount: apply_parameters.amount,
            parameters: apply_parameters.parameters,
        );
    assert_panic_with_felt_error(:result, expected_error: 'ERC20: insufficient allowance');
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();

    assert!(events.len() == 0, "No events expected on ERC20: insufficient allowance panic");
    let account_factory_events = spy
        .get_events()
        .emitted_by(get_account_factory(:strategy_implementation_addr))
        .events
        .span();
    assert!(
        account_factory_events.len() == 0,
        "No event expected on AccountFactory when ERC20: insufficient allowance panic",
    );

    // Ensure balances are unchanged: all WBTC remains with the caller, and none was moved to the
    // position owner or the strategy implementation contract.
    let _wbtc = IERC20Dispatcher { contract_address: WBTC };
    let position_owner = get_position_owner(
        :strategy_implementation_addr, parameters: @apply_parameters.parameters,
    );
    assert!(
        _wbtc.balance_of(apply_caller) == balance,
        "caller should still hold the original prefunded WBTC balance",
    );
    assert!(
        _wbtc.balance_of(strategy_implementation_addr) == 0,
        "strategy implementation should hold 0 WBTC after failed deposit",
    );
    assert!(
        _wbtc.balance_of(position_owner) == 0,
        "position owner should hold 0 WBTC when deposit fails before ApplyFailed handler",
    );
}


#[test]
fn test_deposit_endur_token_successful() {
    /// Apply(WBTC, ENDUR_WBTC): deposits into the ENDUR vault, transfers shares to the position
    /// owner, and emits Deposited.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Deploy the ERC4626 mock contract at the ENDUR_WBTC address.
    deploy_erc4626_deposit_mint_mock(erc4626_asset_address: WBTC, address_to_deploy_at: ENDUR_WBTC);
    let _shares = IERC4626DepositMintMockDispatcher { contract_address: ENDUR_WBTC };

    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: WBTC,
        protocol: 'ENDUR',
    );
    let position_owner = get_position_owner(
        :strategy_implementation_addr, parameters: @apply_parameters.parameters,
    );

    // Call apply with amount that is less than the balance of the token. The apply function should
    // perform the deposit only on the amount.

    let mut spy = snforge_std::spy_events();
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
    let expected_amount = _shares.preview_deposit(assets: apply_parameters.amount);

    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    assert_deposited_event(
        :events,
        funds_receiver: position_owner,
        protocol: 'ENDUR',
        wrapper_token: WBTC,
        amount_deposited: apply_parameters.amount,
        amount_received: expected_amount,
    );
    let _asset = IERC20Dispatcher { contract_address: WBTC };
    assert!(
        _asset.balance_of(position_owner) == 1, "position owner should have no balance of WBTC",
    );
    assert!(
        _shares.shares_balance_of(position_owner) == expected_amount,
        "position owner should have the balance of the shares received",
    );
    // assert_position_owner_deployed_event(:events, :position_owner);
    assert!(events.len() == 1, "One event expected on deposit successful - Deposited event");
}
#[test]
fn test_deposit_token_to_vault_balance_greater_than_amount() {
    /// Apply(WBTC -> ENDUR_WBTC) with balance > amount: deposit exactly `amount`, return
    /// preview_deposit(amount), emit one Deposited to the position owner; balances: owner has 0
    /// WBTC and `expected_amount` shares, the caller contract keeps (balance - amount) WBTC and 0
    /// shares. The strategy implementation contract keeps 0 WBTC and 0 shares.

    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Deploy the ERC4626 mock contract at the ENDUR_WBTC address.
    deploy_erc4626_deposit_mint_mock(erc4626_asset_address: WBTC, address_to_deploy_at: ENDUR_WBTC);
    let _shares = IERC4626DepositMintMockDispatcher { contract_address: ENDUR_WBTC };

    let minted_account: ContractAddress = 0x10.try_into().unwrap();
    deploy_mock_erc20_contract_at(
        initial_supply: 1000_u256,
        owner_address: minted_account,
        name: "DummyERC20",
        address_to_deploy_at: WBTC,
    );

    // Prefund with 400
    let balance = 400_u256;
    cheat_transfer_and_approve(
        token: WBTC,
        amount: balance,
        funds_sender: minted_account,
        funds_receiver: apply_caller,
        approve_to: strategy_implementation_addr,
    );
    let amount = 300_u256;
    let apply_parameters = dummy_apply_parameters_with_protocol(
        protocol: 'ENDUR', token_in: WBTC, :amount,
    );
    let position_owner = get_position_owner(
        :strategy_implementation_addr, parameters: @apply_parameters.parameters,
    );

    let mut spy = snforge_std::spy_events();
    // Apply with 300 < 400. Expect the position owner to receive the corresponding share amount.
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
    let expected_amount = _shares.preview_deposit(assets: amount);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();

    assert_deposited_event(
        :events,
        funds_receiver: position_owner,
        protocol: 'ENDUR',
        wrapper_token: WBTC,
        amount_deposited: amount,
        amount_received: expected_amount,
    );
    // When the apply is successful, the funds should be transferred to the position owner from the
    // apply caller via the strategy implementation contract. Since the amount that was approved is
    // greater than the amount that was deposited, the caller should hold the remaining balance.
    let _asset = IERC20Dispatcher { contract_address: WBTC };
    assert!(
        _asset.balance_of(position_owner) == 0, "position owner should have no balance of WBTC",
    );
    assert!(
        _shares.shares_balance_of(position_owner) == expected_amount,
        "position owner should have {expected_amount} shares",
    );

    assert!(
        _asset.balance_of(strategy_implementation_addr) == 0,
        "strategy implementation should have no balance of WBTC",
    );
    assert!(
        _shares.shares_balance_of(strategy_implementation_addr) == 0,
        "strategy implementation should have no shares of WBTC",
    );

    assert!(
        _asset.balance_of(apply_caller) == balance - amount,
        "caller should hold the remaining balance of WBTC",
    );

    assert!(
        events.len() == 1,
        "One event expected on deposit successful to ENDUR_WBTC - Deposited event",
    );

    let account_factory_events = spy
        .get_events()
        .emitted_by(get_account_factory(:strategy_implementation_addr))
        .events
        .span();
    assert!(
        account_factory_events.len() == 1,
        "One event expected on AccountFactory on deposit successful to ENDUR_WBTC - AccountDeployed event",
    );
}


#[test]
#[should_panic(expected: 'INVALID_SIGNATURE_FORMAT')]
fn test_apply_missing_signature_panics() {
    /// When `parameters` contain only `eth_address`, calling `apply` must panic with
    /// `INVALID_SIGNATURE_FORMAT` since signature is not decoded inside the strategy flow.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Prefund the caller and approve the strategy implementation so that `apply` reaches the
    // point where it decodes `signature`.
    let dummy_token: ContractAddress = 0x45692.try_into().unwrap();
    let amount = 100_u256;
    deploy_and_prefund_dummy_erc20_at(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: dummy_token,
        :amount,
    );

    // Build parameters with only eth_address.
    let eth_address: EthAddress = '0x1012'.try_into().unwrap();
    let mut calldata = ArrayTrait::new();
    Serde::serialize(@eth_address, ref calldata);

    let apply_parameters = ApplyParameters {
        token_in: dummy_token, amount, parameters: calldata.span(),
    };

    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
}

#[test]
#[should_panic(expected: 'SERIALIZATION_FAILED')]
fn test_apply_missing_chain_id_panics() {
    /// When `parameters` contain only `eth_address` and `signature`, calling `apply` should panic
    /// with `SERIALIZATION_FAILED` since chain id is not decoded inside the strategy flow.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Prefund the caller and approve the strategy implementation so that `apply` reaches the
    // point where it decodes `signature`.
    let dummy_token: ContractAddress = 0x45692.try_into().unwrap();
    let amount = 100_u256;
    deploy_and_prefund_dummy_erc20_at(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: dummy_token,
        :amount,
    );

    // Build parameters with only eth_address.
    let eth_address: EthAddress = '0x1012'.try_into().unwrap();
    let signature: Signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };
    let mut calldata = ArrayTrait::new();
    Serde::serialize(@eth_address, ref calldata);
    serialize_signature(signature: @signature, ref calldata: calldata);

    let apply_parameters = ApplyParameters {
        token_in: dummy_token, amount, parameters: calldata.span(),
    };

    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
}

#[test]
#[should_panic(expected: 'PROTOCOL_SERIALIZATION_FAILED')]
fn test_apply_missing_protocol_panics() {
    /// When `parameters` contain only `eth_address`, `signature`, and `chain_id`, calling
    /// `apply` should panic with `PROTOCOL_SERIALIZATION_FAILED` since protocol is not decoded
    /// inside the strategy flow, propagating `PROTOCOL_SERIALIZATION_FAILED`.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Prefund the caller and approve the strategy implementation so that `apply` reaches the
    // point where it decodes `protocol`.
    let dummy_token: ContractAddress = 0x45692.try_into().unwrap();
    let amount = 100_u256;
    deploy_and_prefund_dummy_erc20_at(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: dummy_token,
        :amount,
    );

    // Build parameters with only eth_address.
    let eth_address: EthAddress = '0x1012'.try_into().unwrap();
    let signature: Signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };
    let mut calldata = ArrayTrait::new();
    Serde::serialize(@eth_address, ref calldata);
    serialize_signature(signature: @signature, ref calldata: calldata);
    Serde::serialize(@1, ref calldata); // chain id

    let apply_parameters = ApplyParameters {
        token_in: dummy_token, amount, parameters: calldata.span(),
    };

    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
}

#[test]
fn test_deposit_troves_token_successful() {
    /// Apply(TBTC, TROVES_TBTC): deposit TBTC into ENDUR_TBTC to mint xTBTC, deposit xTBTC into
    /// TROVES_TBTC, transfer shares to the position owner, and emit two Deposited events.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();
    // Deploy the ERC4626 mock contract at the ENDUR_TBTC address.
    deploy_erc4626_deposit_mint_mock(erc4626_asset_address: TBTC, address_to_deploy_at: ENDUR_TBTC);
    // Deploy the ERC4626 mock contract at the TROVES_TBTC address.
    deploy_erc4626_deposit_mint_mock(
        erc4626_asset_address: ENDUR_TBTC, address_to_deploy_at: TROVES_TBTC,
    );
    let _lst_shares = IERC4626DepositMintMockDispatcher { contract_address: ENDUR_TBTC };
    let _troves_shares = IERC4626DepositMintMockDispatcher { contract_address: TROVES_TBTC };

    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: TBTC,
        protocol: 'TROVES',
    );
    let position_owner = get_position_owner(
        :strategy_implementation_addr, parameters: @apply_parameters.parameters,
    );

    let mut spy = snforge_std::spy_events();
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
    let expected_lst_amount = _lst_shares.preview_deposit(assets: apply_parameters.amount);
    let expected_trvoes_amount = _troves_shares.preview_deposit(assets: expected_lst_amount);

    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    assert_deposited_event(
        :events,
        funds_receiver: position_owner,
        protocol: 'TROVES',
        wrapper_token: TBTC,
        amount_deposited: apply_parameters.amount,
        amount_received: expected_trvoes_amount,
    );
    let _asset = IERC20Dispatcher { contract_address: TBTC };
    // When the apply is successful, the funds should be transferred to the position owner from the
    // apply caller via the strategy implementation contract.
    assert!(
        _asset.balance_of(position_owner) == 0, "position owner should have no balance of TBTC",
    );
    assert!(
        _lst_shares.shares_balance_of(position_owner) == 0,
        "position owner should have no balance of the LST shares received",
    );
    assert!(
        _troves_shares.shares_balance_of(position_owner) == expected_trvoes_amount,
        "position owner should have the balance of the shares received",
    );
    assert!(
        _asset.balance_of(strategy_implementation_addr) == 0,
        "strategy_implementation_addr should have no balance of TBTC",
    );
    assert!(
        _lst_shares.shares_balance_of(strategy_implementation_addr) == 0,
        "strategy_implementation_addr should have no balance of the LST shares received",
    );
    assert!(
        _troves_shares.shares_balance_of(strategy_implementation_addr) == 0,
        "strategy_implementation_addr should have no shares",
    );
    assert!(_asset.balance_of(apply_caller) == 0, "apply_caller should have no balance of TBTC");

    assert!(
        events.len() == 1,
        "One event expected on deposit successful to TROVES_TBTC - Deposited event",
    );

    let account_factory_events = spy
        .get_events()
        .emitted_by(get_account_factory(:strategy_implementation_addr))
        .events
        .span();
    assert!(
        account_factory_events.len() == 1,
        "One event expected on AccountFactory on deposit successful to TROVES_TBTC - AccountDeployed event",
    );
}


#[test]
fn test_deposit_troves_failure_on_endur() {
    /// Apply(TBTC, TROVES_TBTC): if the initial ENDUR_TBTC deposit fails, emit ApplyFailed and
    /// refund TBTC to the position owner.

    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();
    // Deploy the ERC4626 mock failure contract at the ENDUR_TBTC address. This will panic with
    // 'ERROR'.
    deploy_4626_failure_mock(address_to_deploy_at: ENDUR_TBTC);
    // Deploy the ERC4626 mock contract at the TROVES_TBTC address.
    deploy_erc4626_deposit_mint_mock(
        erc4626_asset_address: ENDUR_TBTC, address_to_deploy_at: TROVES_TBTC,
    );

    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: TBTC,
        protocol: 'TROVES',
    );

    // The apply should fail with 'ERROR' on the first deposit to the ENDUR_TBTC vault and the
    // balance of the TBTC should be transferred to the position owner.
    let mut spy = snforge_std::spy_events();
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);

    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['ERROR', 'ENTRYPOINT_FAILED', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, :apply_parameters, :errors,
    );

    assert!(
        events.len() == 1,
        "On ENDUR_TBTC deposit failure, exactly one event is expected: ApplyFailed",
    );
    let account_factory_events = spy
        .get_events()
        .emitted_by(get_account_factory(:strategy_implementation_addr))
        .events
        .span();
    assert!(
        account_factory_events.len() == 1,
        "One event expected on AccountFactory on ENDUR_TBTC deposit failure - AccountDeployed event",
    );
}

#[test]
fn test_avnu_multi_route_swap() {
    /// Test multi route swap with Avnu strategy. Deploy DummyAvnu at AVNU_EXCHANGE. Call apply to
    /// initiate multi route swap.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let strategy_implementation = IStrategyImplementationDispatcher {
        contract_address: strategy_implementation_addr,
    };
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu(address_to_deploy_at: AVNU_EXCHANGE);

    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );

    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: apply_caller,
    );
    strategy_implementation
        .apply(
            token_in: apply_parameters.token_in,
            amount: apply_parameters.amount,
            parameters: apply_parameters.parameters,
        );

    let events_avnu = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    validate_avnu_swap(
        events: events_avnu,
        :strategy_implementation_addr,
        token_in: apply_parameters.token_in,
        amount: apply_parameters.amount,
        parameters: @apply_parameters,
    );
}

#[test]
fn test_avnu_failure_less_than_min_amount() {
    /// Avnu failure: deploy DummyAvnuFailure at AVNU_EXCHANGE and call apply; expect failure since
    /// the amount out is less than the buy min amount.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let strategy_implementation = IStrategyImplementationDispatcher {
        contract_address: strategy_implementation_addr,
    };
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu_failure(address_to_deploy_at: AVNU_EXCHANGE);

    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );

    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: apply_caller,
    );
    strategy_implementation
        .apply(
            token_in: apply_parameters.token_in,
            amount: apply_parameters.amount,
            parameters: apply_parameters.parameters,
        );

    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['TOKEN_GAIN_LESS_THAN_MIN_AMOUNT', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, :apply_parameters, :errors,
    );
    // Failure path: ensure no MultiRouteSwap emitted
    let ev_opt = get_event_by_selector(:events, selector: selector!("MultiRouteSwap"));
    assert!(ev_opt.is_none(), "expected no MultiRouteSwap events on failure");
}

#[test]
fn test_avnu_failure_with_false() {
    /// Avnu failure: deploy DummyAvnuFalse at AVNU_EXCHANGE and call apply; expect
    /// AVNU_MULTI_ROUTE_SWAP_FAILED because Avnu's multi_route_swap returns false.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let strategy_implementation = IStrategyImplementationDispatcher {
        contract_address: strategy_implementation_addr,
    };
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu_false(address_to_deploy_at: AVNU_EXCHANGE);

    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );

    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: apply_caller,
    );
    strategy_implementation
        .apply(
            token_in: apply_parameters.token_in,
            amount: apply_parameters.amount,
            parameters: apply_parameters.parameters,
        );

    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['AVNU_MULTI_ROUTE_SWAP_FAILED', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, :apply_parameters, :errors,
    );
}

#[test]
fn test_avnu_invalid_parameters_error() {
    /// Avnu failure: corrupt AvnuParameters in the tail so deserialization fails.
    /// Expect - ApplyFailed with error = INVALID_AVNU_PARAMETERS
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu(address_to_deploy_at: AVNU_EXCHANGE);

    // Start from valid Avnu apply parameters, then remove one felt inside the AvnuParameters tail
    // to force INVALID_AVNU_PARAMETERS in avnu_multi_route_swap.
    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );

    let mut new_parameters = ArrayTrait::new();
    for i in 0..apply_parameters.parameters.len() {
        // Drop index 11 to corrupt the serialized AvnuParameters part of the span.
        if i != 11 {
            new_parameters.append(*apply_parameters.parameters[i]);
        }
    }

    let new_apply_parameters = ApplyParameters {
        parameters: new_parameters.span(), ..apply_parameters,
    };
    apply(:strategy_implementation_addr, :apply_caller, parameters: new_apply_parameters);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['INVALID_AVNU_PARAMETERS', 'ENTRYPOINT_FAILED'];

    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, apply_parameters: new_apply_parameters, :errors,
    );
}

#[test]
fn test_avnu_oversized_parameters_unexpected_parameters_error() {
    /// Avnu failure: append extra felts after a valid AvnuParameters tail so that
    /// `avnu_multi_route_swap` sees leftover data and fails with UNEXPECTED_PARAMETERS.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu(address_to_deploy_at: AVNU_EXCHANGE);

    // Start from valid Avnu apply parameters, then append one extra felt after the serialized
    // AvnuParameters tail to force UNEXPECTED_PARAMETERS in avnu_multi_route_swap.
    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );

    let mut new_parameters = ArrayTrait::new();
    for i in apply_parameters.parameters {
        new_parameters.append(*i);
    }
    // Append one extra felt at the end of the AvnuParameters tail.
    new_parameters.append(1);

    let new_apply_parameters = ApplyParameters {
        parameters: new_parameters.span(), ..apply_parameters,
    };
    apply(:strategy_implementation_addr, :apply_caller, parameters: new_apply_parameters);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['UNEXPECTED_PARAMETERS', 'ENTRYPOINT_FAILED'];

    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, apply_parameters: new_apply_parameters, :errors,
    );
}


#[test]
fn test_avnu_invalid_header_sell_token_address() {
    /// Avnu header validation failure:
    /// - start from valid Avnu apply parameters;
    /// - change `sell_token_address` inside AvnuParameters so it differs from the `token_in`
    /// argument;
    /// - expect INVALID_SELL_TOKEN_ADDRESS, ApplyFailed, and refund.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu(address_to_deploy_at: AVNU_EXCHANGE);

    // Build valid Avnu apply parameters.
    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );
    let mut new_params = array![];
    for i in 0..apply_parameters.parameters.len() {
        // apply_parameters.parameters[0] is the eth address, [1] - [5] are the signatures, [6] is
        // the chain id, [7] is the protocol selector, [8] is the sell token address.
        if i != 8 {
            new_params.append(*apply_parameters.parameters[i]);
        } else {
            new_params.append((*apply_parameters.parameters[i] - 1));
        }
    }

    let new_apply_parameters = ApplyParameters {
        parameters: new_params.span(), ..apply_parameters,
    };

    apply(:strategy_implementation_addr, :apply_caller, parameters: new_apply_parameters);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['INVALID_SELL_TOKEN_ADDRESS', 'ENTRYPOINT_FAILED'];

    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, apply_parameters: new_apply_parameters, :errors,
    );
}


#[test]
fn test_avnu_invalid_header_buy_token_address() {
    /// Avnu header validation failure:
    /// - start from valid Avnu apply parameters;
    /// - change `buy_token_address` inside AvnuParameters so it differs from the `buy_token`
    /// argument;
    /// - expect INVALID_BUY_TOKEN_ADDRESS, ApplyFailed, and refund.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu(address_to_deploy_at: AVNU_EXCHANGE);

    // Build valid Avnu apply parameters.
    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );
    let mut new_params = array![];
    for i in 0..apply_parameters.parameters.len() {
        // apply_parameters.parameters[0] is the eth address, [1] - [5] are the signatures, [6] is
        // the chain id, [7] is the protocol selector, [8] is the sell token address, [9] is the
        // sell token amount (low), [10] is the sell token amount (high), [11] is the buy token
        // address.
        if i != 11 {
            new_params.append(*apply_parameters.parameters[i]);
        } else {
            new_params.append((*apply_parameters.parameters[i] - 1));
        }
    }

    let new_apply_parameters = ApplyParameters {
        parameters: new_params.span(), ..apply_parameters,
    };

    apply(:strategy_implementation_addr, :apply_caller, parameters: new_apply_parameters);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['INVALID_BUY_TOKEN_ADDRESS', 'ENTRYPOINT_FAILED'];

    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, apply_parameters: new_apply_parameters, :errors,
    );
}


#[test]
fn test_avnu_invalid_header_beneficiary() {
    /// Avnu header validation failure:
    /// - start from valid Avnu apply parameters;
    /// - change `beneficiary` inside AvnuParameters so it differs from the strategy implementation
    /// address
    /// argument;
    /// - expect INVALID_BENEFICIARY, ApplyFailed, and refund.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy = snforge_std::spy_events();

    deploy_dummy_avnu(address_to_deploy_at: AVNU_EXCHANGE);

    // Build valid Avnu apply parameters.
    let apply_parameters = build_prefunded_avnu(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_token_in: TBTC,
    );
    let mut new_params = array![];
    for i in 0..apply_parameters.parameters.len() {
        // apply_parameters.parameters[0] is the eth address, [1] - [5] are the signatures, [6] is
        // the chain id, [7] is the protocol selector, [8] is the sell token address, [9] is the
        // sell token amount (low), [10] is the sell token amount (high), [11] is the buy token
        // address, [12]
        // is the buy token amount (low), [13] is the buy token amount (high), [14] is the buy token
        // min amount (low), [15] is the buy token min amount (high), [16] is the beneficiary.
        if i != 16 {
            new_params.append(*apply_parameters.parameters[i]);
        } else {
            new_params.append((*apply_parameters.parameters[i] - 1));
        }
    }

    let new_apply_parameters = ApplyParameters {
        parameters: new_params.span(), ..apply_parameters,
    };

    apply(:strategy_implementation_addr, :apply_caller, parameters: new_apply_parameters);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['INVALID_BENEFICIARY', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, apply_parameters: new_apply_parameters, :errors,
    );
}


#[test]
fn test_apply_oversized_parameters_fail_for_endur_and_troves() {
    /// Extra parameters should cause failure (ApplyFailed + refund) for ENDUR and
    // TROVES.
    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let strategy_implementation = IStrategyImplementationDispatcher {
        contract_address: strategy_implementation_addr,
    };
    let apply_caller = 0x4324.try_into().unwrap();
    let mut spy_endur = snforge_std::spy_events();

    // Build a valid ENDUR(TBTC) apply() call and then replace the parameters span with an
    // oversized one.
    let protocol = 'ENDUR';
    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: TBTC,
        :protocol,
    );
    let mut params_to_serde = apply_parameters.parameters;
    let eth_address: EthAddress = Serde::deserialize(ref params_to_serde)
        .expect('INVALID_ETH_ADDRESS');
    let signature: Signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };

    // Oversized ENDUR parameters: [eth_address, signature, chain_id, protocol, extra parameter]
    let mut endur_params = array![];
    Serde::serialize(@eth_address, ref endur_params);
    serialize_signature(signature: @signature, ref calldata: endur_params);
    Serde::serialize(@1, ref endur_params); // chain id
    Serde::serialize(@protocol, ref endur_params);
    Serde::serialize(@123, ref endur_params); // extra parameter

    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: apply_caller,
    );
    strategy_implementation
        .apply(
            token_in: apply_parameters.token_in,
            amount: apply_parameters.amount,
            parameters: endur_params.span(),
        );
    let events_endur = spy_endur
        .get_events()
        .emitted_by(strategy_implementation_addr)
        .events
        .span();
    let errors = array!['UNEXPECTED_PARAMETERS', 'ENTRYPOINT_FAILED'];

    assert_apply_failed_with_refund(
        events: events_endur, :strategy_implementation_addr, :apply_parameters, :errors,
    );
    let apply_caller_2 = 0x222222.try_into().unwrap();
    let mut spy_troves = snforge_std::spy_events();

    let protocol = 'TROVES';
    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller_2,
        address_to_deploy_at: LBTC,
        :protocol,
    );

    let mut troves_params = array![];
    Serde::serialize(@eth_address, ref troves_params);
    serialize_signature(signature: @signature, ref calldata: troves_params);
    Serde::serialize(@1, ref troves_params); // chain id
    Serde::serialize(@protocol, ref troves_params);
    Serde::serialize(@123, ref troves_params); // extra parameter

    // Oversized TROVES parameters: [eth_address, signature, chain_id, protocol, extra parameter]
    cheat_caller_address_once(
        contract_address: strategy_implementation_addr, caller_address: apply_caller_2,
    );
    strategy_implementation
        .apply(
            token_in: apply_parameters.token_in,
            amount: apply_parameters.amount,
            parameters: troves_params.span(),
        );
    let events_troves = spy_troves
        .get_events()
        .emitted_by(strategy_implementation_addr)
        .events
        .span();
    let errors = array!['UNEXPECTED_PARAMETERS', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        events: events_troves, :strategy_implementation_addr, :apply_parameters, :errors,
    );
}

#[test]
fn test_deposit_troves_failure_on_troves() {
    /// Apply(TBTC, TROVES_TBTC): if the second TROVES_TBTC deposit fails, revert the first deposit,
    /// emit ApplyFailed, and refund TBTC to the position owner.

    let strategy_implementation_addr = setup_strategy_implementation_test_env();
    let apply_caller = 0x4324.try_into().unwrap();

    // Deploy the ERC4626 mock contract at the ENDUR_TBTC address.
    deploy_erc4626_deposit_mint_mock(erc4626_asset_address: TBTC, address_to_deploy_at: ENDUR_TBTC);
    // Deploy the ERC4626 mock failure contract at the TROVES_TBTC address. This will panic with
    // 'ERROR'.
    deploy_4626_failure_mock(address_to_deploy_at: TROVES_TBTC);

    let apply_parameters = build_prefunded_apply_parameters_with_token_address(
        :strategy_implementation_addr,
        account_to_fund: apply_caller,
        address_to_deploy_at: TBTC,
        protocol: 'TROVES',
    );
    let position_owner = get_position_owner(
        :strategy_implementation_addr, parameters: @apply_parameters.parameters,
    );
    // The apply should succeed with the first deposit to the ENDUR_TBTC vault and fail with 'ERROR'
    // on the second deposit to the TROVES_TBTC vault and the balance of the TBTC should be
    // transferred to the position owner. The deposit to the ENDUR_TBTC is reverted since the
    // apply_on_self is all or nothing .
    let mut spy = snforge_std::spy_events();
    apply(:strategy_implementation_addr, :apply_caller, parameters: apply_parameters);
    let events = spy.get_events().emitted_by(strategy_implementation_addr).events.span();
    let errors = array!['ERROR', 'ENTRYPOINT_FAILED', 'ENTRYPOINT_FAILED'];
    assert_apply_failed_with_refund(
        :events, :strategy_implementation_addr, :apply_parameters, :errors,
    );

    let _lst_shares = IERC4626DepositMintMockDispatcher { contract_address: ENDUR_TBTC };

    assert!(
        _lst_shares.shares_balance_of(position_owner) == 0,
        "position owner should have no balance of the LST",
    );
    assert!(
        _lst_shares.shares_balance_of(strategy_implementation_addr) == 0,
        "strategy implementation should have no shares of the LST",
    );
}
