use earn_reporter::earn_reporter::EarnReporter::OrderCreated;
use earn_reporter::earn_reporter::{IEarnReporterDispatcher, IEarnReporterDispatcherTrait};
use earn_reporter::test_utils::deploy_earn_reporter;
use openzeppelin::access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};
use snforge_std::cheatcodes::events::{EventSpyTrait, EventsFilterTrait};
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ContractAddress, SyscallResultTrait, get_contract_address};
use starkware_utils_testing::test_utils::{assert_expected_event_emitted, cheat_caller_address_once};
use testing_utils::dummy_contracts::declare_dummy_eth_address_contract;
use testing_utils::event_helpers::get_event_by_selector;

fn default_order_created_event() -> OrderCreated {
    OrderCreated {
        order_creator_address: 0x1234.try_into().unwrap(),
        evm_address: '0x5679'.try_into().unwrap(),
        caller_address: 0x9999.try_into().unwrap(),
        strategy_id: 42,
        order_type: 'deposit',
        original_chain_id: 1,
        asset_amount: 100,
        shares_amount: 95,
        token: 0x5678.try_into().unwrap(),
        is_closing_position: false,
    }
}

fn call_report_order_created(reporter: IEarnReporterDispatcher, event: @OrderCreated) {
    reporter
        .report_order_created(
            order_creator_address: *event.order_creator_address,
            evm_address: *event.evm_address,
            strategy_id: *event.strategy_id,
            order_type: *event.order_type,
            original_chain_id: *event.original_chain_id,
            asset_amount: *event.asset_amount,
            shares_amount: *event.shares_amount,
            token: *event.token,
            is_closing_position: *event.is_closing_position,
        );
}

#[test]
fn test_report_order_created() {
    let owner = get_contract_address();
    let reporter_addr = deploy_earn_reporter(owner: owner);
    let reporter = IEarnReporterDispatcher { contract_address: reporter_addr };
    let mut spy = snforge_std::spy_events();
    let event = default_order_created_event();
    cheat_caller_address_once(
        contract_address: reporter_addr, caller_address: event.caller_address,
    );

    call_report_order_created(reporter, @event);

    let events = spy.get_events().emitted_by(reporter_addr).events.span();
    assert!(events.len() == 1, "Expected one OrderCreated event");
    let spied_event = get_event_by_selector(:events, selector: selector!("OrderCreated")).unwrap();
    assert_expected_event_emitted(
        spied_event: spied_event,
        expected_event: event,
        expected_event_selector: @selector!("OrderCreated"),
        expected_event_name: "OrderCreated",
    );
}

#[test]
#[should_panic(expected: 'Caller is not the owner')]
fn test_replace_owner_invalid_caller() {
    let owner = get_contract_address();
    let reporter_addr = deploy_earn_reporter(owner: owner);
    let ownable = IOwnableDispatcher { contract_address: reporter_addr };
    let new_owner: ContractAddress = 0x1111.try_into().unwrap();
    let non_owner_caller: ContractAddress = 0x1.try_into().unwrap();
    cheat_caller_address_once(contract_address: reporter_addr, caller_address: non_owner_caller);

    ownable.transfer_ownership(:new_owner);
}

#[test]
#[should_panic(expected: 'Caller is not the owner')]
fn test_upgrade_invalid_caller() {
    let owner = get_contract_address();
    let reporter_addr = deploy_earn_reporter(owner: owner);
    let reporter = IEarnReporterDispatcher { contract_address: reporter_addr };
    let non_owner_caller: ContractAddress = 0x1.try_into().unwrap();
    cheat_caller_address_once(contract_address: reporter_addr, caller_address: non_owner_caller);
    let new_class_hash = declare_dummy_eth_address_contract();

    reporter.upgrade(:new_class_hash);
}

#[test]
fn test_transfer_ownership_and_upgrade() {
    let old_owner = get_contract_address();
    let reporter_addr = deploy_earn_reporter(owner: old_owner);
    let reporter = IEarnReporterDispatcher { contract_address: reporter_addr };
    let ownable = IOwnableDispatcher { contract_address: reporter_addr };
    let new_owner: ContractAddress = 0x1111.try_into().unwrap();
    cheat_caller_address_once(contract_address: reporter_addr, caller_address: old_owner);
    ownable.transfer_ownership(new_owner: new_owner);
    let new_class_hash = declare_dummy_eth_address_contract();
    cheat_caller_address_once(contract_address: reporter_addr, caller_address: new_owner);

    reporter.upgrade(new_class_hash: new_class_hash);

    let class_hash = get_class_hash_at_syscall(reporter_addr).unwrap_syscall();
    assert!(class_hash == new_class_hash, "class hash mismatch");
}

#[test]
#[should_panic(expected: 'INVALID_ORDER_TYPE')]
fn test_report_order_created_invalid_order_type() {
    let owner = get_contract_address();
    let reporter_addr = deploy_earn_reporter(owner: owner);
    let reporter = IEarnReporterDispatcher { contract_address: reporter_addr };

    let mut event = default_order_created_event();
    event.order_type = 'invalid';

    call_report_order_created(reporter, @event);
}
