use helpers::earn_deploy_helper::{IEarnDeployHelperDispatcher, IEarnDeployHelperDispatcherTrait};
use helpers::earn_invoke_helper::{IEarnInvokeHelperDispatcher, IEarnInvokeHelperDispatcherTrait};
use openzeppelin::account::extensions::src9::OutsideExecution;
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::account::Call;
use starknet::secp256_trait::Signature;
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, EthAddress, SyscallResultTrait};
use starkware_utils_testing::test_utils::cheat_caller_address_once;
use testing_utils::account_factory_utils::{eth_address_to_account, setup_account_factory_test_env};
use testing_utils::dummy_contracts::MockOutsideExecutionTarget::{
    IMockTargetDispatcher, IMockTargetDispatcherTrait,
};

fn MOCK_PRIVACY_POOL() -> ContractAddress {
    'MOCK_PRIVACY_POOL'.try_into().unwrap()
}

fn NOT_POOL() -> ContractAddress {
    'RANDO_CALLER'.try_into().unwrap()
}

fn deploy_helper(privacy_pool: ContractAddress, account_factory: ContractAddress) -> ContractAddress {
    let contract = declare("EarnDeployHelper").unwrap_syscall().contract_class();
    let mut calldata = array![];
    Serde::serialize(@privacy_pool, ref calldata);
    Serde::serialize(@account_factory, ref calldata);
    let (helper_address, _) = contract.deploy(@calldata).unwrap_syscall();
    helper_address
}

#[test]
fn test_privacy_invoke_deploys_account_when_called_by_pool() {
    /// The pool can call privacy_invoke with (session_eth_address, signature),
    /// and the helper deploys the deterministic Tier 2 account.
    let factory_addr = setup_account_factory_test_env();
    let helper_addr = deploy_helper(MOCK_PRIVACY_POOL(), factory_addr);
    let helper = IEarnDeployHelperDispatcher { contract_address: helper_addr };

    let session_eth_address: EthAddress = '0xC0FFEE'.try_into().unwrap();
    let signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };

    let expected_account = eth_address_to_account(
        account_factory: factory_addr, eth_address: session_eth_address,
    );

    // Pre-call: nothing deployed at the predicted address yet.
    let class_hash_before = get_class_hash_at_syscall(expected_account).unwrap_syscall();
    assert!(class_hash_before.into() == 0, "account should not be deployed yet");

    // Caller MUST be the configured privacy pool.
    cheat_caller_address_once(contract_address: helper_addr, caller_address: MOCK_PRIVACY_POOL());
    let deposits = helper.privacy_invoke(:session_eth_address, :signature, note_id: 0);

    // The helper never returns surplus.
    assert!(deposits.len() == 0, "privacy_invoke must return an empty deposit span");

    // The factory deployed the deterministic account.
    let class_hash_after = get_class_hash_at_syscall(expected_account).unwrap_syscall();
    assert!(class_hash_after.into() != 0, "account should be deployed at expected address");
}

#[test]
#[should_panic(expected: 'CALLER_NOT_PRIVACY_POOL')]
fn test_privacy_invoke_rejects_non_pool_caller() {
    /// Any caller other than the configured privacy pool must be rejected;
    /// otherwise an external caller could deploy accounts at attacker-chosen
    /// session addresses outside the proof-validated path.
    let factory_addr = setup_account_factory_test_env();
    let helper_addr = deploy_helper(MOCK_PRIVACY_POOL(), factory_addr);
    let helper = IEarnDeployHelperDispatcher { contract_address: helper_addr };

    let session_eth_address: EthAddress = '0xC0FFEE'.try_into().unwrap();
    let signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };

    cheat_caller_address_once(contract_address: helper_addr, caller_address: NOT_POOL());
    helper.privacy_invoke(:session_eth_address, :signature, note_id: 0);
}

#[test]
fn test_privacy_invoke_is_idempotent() {
    /// Calling privacy_invoke twice with the same session_eth_address should
    /// return the same account address (factory.deploy_account is idempotent).
    let factory_addr = setup_account_factory_test_env();
    let helper_addr = deploy_helper(MOCK_PRIVACY_POOL(), factory_addr);
    let helper = IEarnDeployHelperDispatcher { contract_address: helper_addr };

    let session_eth_address: EthAddress = '0xC0FFEE'.try_into().unwrap();
    let signature = Signature { r: 0x1012, s: 0x1012, y_parity: true };
    let expected_account = eth_address_to_account(
        account_factory: factory_addr, eth_address: session_eth_address,
    );

    cheat_caller_address_once(contract_address: helper_addr, caller_address: MOCK_PRIVACY_POOL());
    helper.privacy_invoke(:session_eth_address, :signature, note_id: 0);
    let class_hash_after_first = get_class_hash_at_syscall(expected_account).unwrap_syscall();

    cheat_caller_address_once(contract_address: helper_addr, caller_address: MOCK_PRIVACY_POOL());
    helper.privacy_invoke(:session_eth_address, :signature, note_id: 0);
    let class_hash_after_second = get_class_hash_at_syscall(expected_account).unwrap_syscall();

    assert!(
        class_hash_after_first == class_hash_after_second,
        "class hash must be stable across duplicate invocations",
    );
}

#[test]
fn test_constructor_stores_pool_and_factory() {
    let factory_addr = setup_account_factory_test_env();
    let helper_addr = deploy_helper(MOCK_PRIVACY_POOL(), factory_addr);
    let helper = IEarnDeployHelperDispatcher { contract_address: helper_addr };

    assert!(helper.privacy_pool() == MOCK_PRIVACY_POOL(), "pool not stored correctly");
    assert!(helper.account_factory() == factory_addr, "factory not stored correctly");
}

// ─── EarnInvokeHelper tests ─────────────────────────────────────────────────

fn deploy_invoke_helper(privacy_pool: ContractAddress) -> ContractAddress {
    let contract = declare("EarnInvokeHelper").unwrap_syscall().contract_class();
    let mut calldata = array![];
    Serde::serialize(@privacy_pool, ref calldata);
    let (addr, _) = contract.deploy(@calldata).unwrap_syscall();
    addr
}

fn deploy_mock_target() -> ContractAddress {
    let contract = declare("MockOutsideExecutionTarget").unwrap_syscall().contract_class();
    let (addr, _) = contract.deploy(@array![]).unwrap_syscall();
    addr
}

fn dummy_outside_execution(nonce: felt252) -> OutsideExecution {
    OutsideExecution {
        // ANY_CALLER — the mock target doesn't validate the caller.
        caller: 'ANY_CALLER'.try_into().unwrap(),
        nonce,
        execute_after: 0,
        execute_before: 0xFFFFFFFF,
        calls: array![].span(),
    }
}

fn _unused_call_silencer() -> Call {
    // Just to keep the Call import wired in for future tests; the mock
    // doesn't read calls in the OutsideExecution.
    Call { to: 0x0.try_into().unwrap(), selector: 0, calldata: array![].span() }
}

#[test]
fn test_invoke_helper_forwards_to_target_account() {
    let pool = MOCK_PRIVACY_POOL();
    let helper_addr = deploy_invoke_helper(pool);
    let helper = IEarnInvokeHelperDispatcher { contract_address: helper_addr };
    let target_addr = deploy_mock_target();
    let target = IMockTargetDispatcher { contract_address: target_addr };

    let ose = dummy_outside_execution(nonce: 42);
    let signature: Array<felt252> = array![0x11, 0x22, 0x33];

    cheat_caller_address_once(contract_address: helper_addr, caller_address: pool);
    let deposits = helper
        .privacy_invoke(
            target_account: target_addr,
            outside_execution: ose,
            signature: signature,
            note_id: 0,
        );
    assert!(deposits.len() == 0, "must return empty deposit span");

    // The mock recorded the helper as msg.sender and stored the nonce we passed.
    assert!(target.call_count() == 1, "target should be called exactly once");
    assert!(target.last_caller() == helper_addr, "target should see helper as caller");
    assert!(target.last_nonce() == 42, "target should receive our outside_execution nonce");
}

#[test]
#[should_panic(expected: 'CALLER_NOT_PRIVACY_POOL')]
fn test_invoke_helper_rejects_non_pool_caller() {
    let pool = MOCK_PRIVACY_POOL();
    let helper_addr = deploy_invoke_helper(pool);
    let helper = IEarnInvokeHelperDispatcher { contract_address: helper_addr };
    let target_addr = deploy_mock_target();

    cheat_caller_address_once(contract_address: helper_addr, caller_address: NOT_POOL());
    helper
        .privacy_invoke(
            target_account: target_addr,
            outside_execution: dummy_outside_execution(nonce: 1),
            signature: array![],
            note_id: 0,
        );
}

#[test]
fn test_invoke_helper_constructor_stores_pool() {
    let pool = MOCK_PRIVACY_POOL();
    let helper_addr = deploy_invoke_helper(pool);
    let helper = IEarnInvokeHelperDispatcher { contract_address: helper_addr };
    assert!(helper.privacy_pool() == pool, "pool not stored correctly");
}
