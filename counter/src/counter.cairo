use starknet::ContractAddress;

#[starknet::interface]
pub trait ICounter<TContractState> {
    fn increment(ref self: TContractState);
    fn increment_by(ref self: TContractState, amount: u64);
    fn get_count(self: @TContractState) -> u64;
    fn get_last_caller(self: @TContractState) -> ContractAddress;
}

/// Minimal counter contract used as a demo target for the Tier 2 unlinkable
/// account flow: a Tier 2 Starknet account calls `increment` (via the privacy
/// pool + paymaster) so we can confirm end-to-end that an action originated
/// from the unlinkable account without any on-chain link back to the user's
/// MetaMask address. The contract itself has no privacy logic — it only
/// records the count and the last caller so tests can assert who invoked it.
#[starknet::contract]
pub mod Counter {
    use core::num::traits::Zero;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address};
    use super::ICounter;

    #[storage]
    struct Storage {
        count: u64,
        last_caller: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Incremented: Incremented,
    }

    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct Incremented {
        pub caller: ContractAddress,
        pub new_count: u64,
        pub amount: u64,
    }

    #[abi(embed_v0)]
    impl CounterImpl of ICounter<ContractState> {
        fn increment(ref self: ContractState) {
            self.do_increment(1);
        }

        fn increment_by(ref self: ContractState, amount: u64) {
            assert(!amount.is_zero(), 'ZERO_AMOUNT');
            self.do_increment(amount);
        }

        fn get_count(self: @ContractState) -> u64 {
            self.count.read()
        }

        fn get_last_caller(self: @ContractState) -> ContractAddress {
            self.last_caller.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn do_increment(ref self: ContractState, amount: u64) {
            let caller = get_caller_address();
            let new_count = self.count.read() + amount;
            self.count.write(new_count);
            self.last_caller.write(caller);
            self.emit(Event::Incremented(Incremented { caller, new_count, amount }));
        }
    }
}
