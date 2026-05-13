use counter::counter::Counter::{Event, Incremented};
use counter::counter::{ICounterDispatcher, ICounterDispatcherTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, spy_events,
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::{ContractAddress, SyscallResultTrait};

fn ANY_CALLER() -> ContractAddress {
    'CALLER_1'.try_into().unwrap()
}

fn OTHER_CALLER() -> ContractAddress {
    'CALLER_2'.try_into().unwrap()
}

fn deploy_counter() -> ICounterDispatcher {
    let contract = declare("Counter").unwrap_syscall().contract_class();
    let (address, _) = contract.deploy(@array![]).unwrap_syscall();
    ICounterDispatcher { contract_address: address }
}

#[test]
fn test_counter_starts_at_zero() {
    let counter = deploy_counter();
    assert!(counter.get_count() == 0, "fresh counter should start at 0");
}

#[test]
fn test_increment_by_one() {
    let counter = deploy_counter();
    let mut spy = spy_events();

    start_cheat_caller_address(counter.contract_address, ANY_CALLER());
    counter.increment();
    stop_cheat_caller_address(counter.contract_address);

    assert!(counter.get_count() == 1, "count should be 1 after one increment");
    assert!(counter.get_last_caller() == ANY_CALLER(), "last_caller should reflect invoker");

    spy
        .assert_emitted(
            @array![
                (
                    counter.contract_address,
                    Event::Incremented(
                        Incremented { caller: ANY_CALLER(), new_count: 1, amount: 1 },
                    ),
                ),
            ],
        );
}

#[test]
fn test_increment_by_amount() {
    let counter = deploy_counter();

    start_cheat_caller_address(counter.contract_address, ANY_CALLER());
    counter.increment_by(5);
    counter.increment_by(3);
    stop_cheat_caller_address(counter.contract_address);

    assert!(counter.get_count() == 8, "expected 5+3=8");
}

#[test]
#[should_panic(expected: 'ZERO_AMOUNT')]
fn test_increment_by_zero_reverts() {
    let counter = deploy_counter();
    start_cheat_caller_address(counter.contract_address, ANY_CALLER());
    counter.increment_by(0);
}

#[test]
fn test_last_caller_updates() {
    let counter = deploy_counter();

    start_cheat_caller_address(counter.contract_address, ANY_CALLER());
    counter.increment();
    stop_cheat_caller_address(counter.contract_address);

    start_cheat_caller_address(counter.contract_address, OTHER_CALLER());
    counter.increment();
    stop_cheat_caller_address(counter.contract_address);

    assert!(counter.get_count() == 2, "two increments expected");
    assert!(
        counter.get_last_caller() == OTHER_CALLER(),
        "last_caller should reflect most recent invoker",
    );
}
