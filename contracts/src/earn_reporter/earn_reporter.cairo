use starknet::{ClassHash, ContractAddress, EthAddress};

#[starknet::interface]
pub trait IEarnReporter<TContractState> {
    fn report_order_created(
        ref self: TContractState,
        order_creator_address: ContractAddress,
        evm_address: EthAddress,
        // id of the strategy of the order (i.e endur, troves, etc)
        strategy_id: felt252,
        order_type: felt252,
        original_chain_id: u256,
        asset_amount: u256,
        shares_amount: u256,
        // The asset token that the user intended to deposit/withdraw
        token: ContractAddress,
        // Indicates that the position is being closed (i.e. user is withdrawing all assets)
        is_closing_position: bool,
    );
    fn upgrade(ref self: TContractState, new_class_hash: ClassHash);
}

#[starknet::contract]
pub mod EarnReporter {
    use contracts::earn_reporter::earn_reporter::IEarnReporter;
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::access::ownable::OwnableComponent::InternalTrait as OwnableInternalTrait;
    use openzeppelin_upgrades::UpgradeableComponent;
    use openzeppelin_upgrades::UpgradeableComponent::InternalTrait as UpgradeableInternalTrait;
    use starknet::{ClassHash, ContractAddress, EthAddress, get_caller_address};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        OrderCreated: OrderCreated,
    }

    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct OrderCreated {
        #[key]
        pub order_creator_address: ContractAddress,
        pub evm_address: EthAddress,
        // This represent the event contract caller
        #[key]
        pub caller_address: ContractAddress,
        pub strategy_id: felt252,
        pub order_type: felt252,
        pub original_chain_id: u256,
        pub asset_amount: u256,
        pub shares_amount: u256,
        pub token: ContractAddress,
        pub is_closing_position: bool,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(:owner);
    }

    #[abi(embed_v0)]
    impl EarnReporterImpl of IEarnReporter<ContractState> {
        fn report_order_created(
            ref self: ContractState,
            order_creator_address: ContractAddress,
            evm_address: EthAddress,
            strategy_id: felt252,
            order_type: felt252,
            original_chain_id: u256,
            asset_amount: u256,
            shares_amount: u256,
            token: ContractAddress,
            is_closing_position: bool,
        ) {
            assert(order_type == 'deposit' || order_type == 'withdraw', 'INVALID_ORDER_TYPE');
            self
                .emit(
                    Event::OrderCreated(
                        OrderCreated {
                            order_creator_address,
                            evm_address,
                            caller_address: get_caller_address(),
                            strategy_id,
                            order_type,
                            original_chain_id,
                            asset_amount,
                            shares_amount,
                            token,
                            is_closing_position,
                        },
                    ),
                );
        }

        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(:new_class_hash);
        }
    }
}
