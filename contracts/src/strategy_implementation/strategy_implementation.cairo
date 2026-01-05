#[starknet::contract]
pub mod StrategyImplementation {
    use RolesComponent::InternalTrait as RolesInternalTrait;
    use contracts::account_factory::account_factory::{
        IAccountFactoryDispatcher, IAccountFactoryDispatcherTrait,
    };
    use contracts::known_addresses::MIDAS_RE7_BTC;
    use contracts::strategy_implementation::avnu_interface::AvnuParameters;
    use contracts::strategy_implementation::interface::{
        IStrategyImplementation, IStrategyImplementationSafeDispatcher,
        IStrategyImplementationSafeDispatcherTrait,
    };
    use contracts::strategy_implementation::utils::{
        IERC4626DepositDispatcher, IERC4626DepositDispatcherTrait, Strategy, StrategyTrait,
        avnu_multi_route_swap, deserialize_signature, strategy_from_protocol_and_token,
    };
    use core::panic_with_felt252;
    use core::traits::Into;
    use openzeppelin::access::accesscontrol::AccessControlComponent;
    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ClassHash, ContractAddress, get_caller_address, get_contract_address};
    use starkware_utils::components::replaceability::ReplaceabilityComponent;
    use starkware_utils::components::replaceability::ReplaceabilityComponent::InternalReplaceabilityTrait;
    use starkware_utils::components::roles::RolesComponent;

    component!(path: RolesComponent, storage: roles, event: RolesEvent);
    component!(path: AccessControlComponent, storage: accesscontrol, event: accesscontrolEvent);
    component!(path: SRC5Component, storage: src5, event: src5Event);
    component!(path: ReplaceabilityComponent, storage: replaceability, event: ReplaceabilityEvent);

    #[abi(embed_v0)]
    impl RolesImpl = RolesComponent::RolesImpl<ContractState>;
    #[abi(embed_v0)]
    impl ReplaceabilityImpl =
        ReplaceabilityComponent::ReplaceabilityImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        roles: RolesComponent::Storage,
        #[substorage(v0)]
        accesscontrol: AccessControlComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        replaceability: ReplaceabilityComponent::Storage,
        account_factory: ContractAddress,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        ReplaceabilityEvent: ReplaceabilityComponent::Event,
        #[flat]
        RolesEvent: RolesComponent::Event,
        #[flat]
        accesscontrolEvent: AccessControlComponent::Event,
        #[flat]
        src5Event: SRC5Component::Event,
        Deposited: Deposited,
        ApplyFailed: ApplyFailed,
        MultiRouteSwap: MultiRouteSwap,
        AccountClassHashChanged: AccountClassHashChanged,
        PositionOwnerDeployed: PositionOwnerDeployed,
    }


    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct AccountClassHashChanged {
        pub previous_class_hash: ClassHash,
        pub new_class_hash: ClassHash,
    }

    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct PositionOwnerDeployed {
        pub position_owner: ContractAddress,
    }

    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct MultiRouteSwap {
        pub position_owner: ContractAddress,
        pub sell_token: ContractAddress,
        pub amount_sold: u256,
        pub amount_not_sold: u256,
        pub buy_token: ContractAddress,
        pub amount_received: u256,
    }

    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct Deposited {
        pub receiver_address: ContractAddress,
        pub token_deposited: ContractAddress,
        pub amount_deposited: u256,
        pub token_received: ContractAddress,
        pub amount_received: u256,
    }


    #[derive(Drop, starknet::Event, Debug, PartialEq)]
    pub struct ApplyFailed {
        pub position_owner: ContractAddress,
        pub protocol: felt252,
        pub token_in: ContractAddress,
        pub amount: u256,
        pub errors: Array<felt252>,
    }

    #[generate_trait]
    impl _InternalImpl of InternalImplTrait {
        fn handle_apply_on_self_result(
            ref self: ContractState,
            result: Result<(), Array<felt252>>,
            token_in: ContractAddress,
            amount: u256,
            position_owner: ContractAddress,
            protocol: felt252,
        ) {
            if let Err(errors) = result {
                // On failure, transfer `amount` to the position owner. At this point, the
                // contract must still hold at least `amount`, because it was transferred in at
                // the start of the transaction and any operation that could have consumed it
                // has reverted.
                IERC20Dispatcher { contract_address: token_in }.transfer(position_owner, amount);
                // ApplyFailed's protocol emits the protocol selector felt (e.g. 'ENDUR',
                // 'TROVES', 'AVNU') rather than a strategy contract address, to ensure the
                // tx won't revert if the protocol selector is invalid.
                // The error was propagated from the failed call.
                self
                    .emit(
                        Event::ApplyFailed(
                            ApplyFailed { position_owner, protocol, token_in, amount, errors },
                        ),
                    );
            }
        }

        fn deposit_token_to_vault(
            ref self: ContractState,
            strategy: ContractAddress,
            token: ContractAddress,
            amount: u256,
            funds_receiver: ContractAddress,
        ) -> u256 {
            IERC20Dispatcher { contract_address: token }.approve(strategy, amount);
            IERC4626DepositDispatcher { contract_address: strategy }
                .deposit(assets: amount, receiver: funds_receiver)
        }


        /// - Approves `token_in` and calls Avnu's multi_route_swap(avnu_parameters),
        ///   expecting `true`.
        /// - Sends received `buy_token` (`amount_buy >= buy_min_amount`) to `position_owner`.
        /// - Refunds any unused `token_in` to `position_owner`, emits `MultiRouteSwap`,
        ///   and returns the received `buy_token` amount.
        fn avnu_multi_route_swap(
            ref self: ContractState,
            sell_token_address: ContractAddress,
            sell_token_amount: u256,
            strategy: ContractAddress,
            position_owner: ContractAddress,
            mut avnu_parameters: Span<felt252>,
        ) -> u256 {
            // The avnu_parameters is a Span<felt252> that needs to be deserialized to be able to
            // pass them to the multi route swap function.
            let avnu_parameters_: AvnuParameters = Serde::deserialize(ref avnu_parameters)
                .expect('INVALID_AVNU_PARAMETERS');
            assert(avnu_parameters.len() == 0, 'UNEXPECTED_PARAMETERS');

            // Validate the avnu parameters.
            assert(
                avnu_parameters_.sell_token_address == sell_token_address,
                'INVALID_SELL_TOKEN_ADDRESS',
            );
            assert(
                avnu_parameters_.buy_token_address == MIDAS_RE7_BTC, 'INVALID_BUY_TOKEN_ADDRESS',
            );

            // The beneficiary is the strategy implementation address since it is the one that
            // will receive the buy token. After the swap, the buy token will be transferred to the
            // position owner.
            let contract_address = get_contract_address();
            assert(avnu_parameters_.beneficiary == contract_address, 'INVALID_BENEFICIARY');

            let sell_token = IERC20Dispatcher { contract_address: sell_token_address };
            sell_token.approve(strategy, sell_token_amount);
            let sell_token_before = sell_token.balance_of(contract_address);

            let buy_token_address = avnu_parameters_.buy_token_address;
            let buy_token = IERC20Dispatcher { contract_address: buy_token_address };
            let buy_token_before = buy_token.balance_of(contract_address);

            let buy_token_min_amount = avnu_parameters_.buy_token_min_amount;
            if !avnu_multi_route_swap(avnu: strategy, avnu_parameters: avnu_parameters_) {
                panic_with_felt252('AVNU_MULTI_ROUTE_SWAP_FAILED');
            }
            // Validate that the buy_token_gained is greater than the buy min amount. Transfer the
            // buy_token_gained to the position owner.
            let buy_token_after = buy_token.balance_of(contract_address);
            let buy_token_gained = buy_token_after - buy_token_before;
            assert(buy_token_gained >= buy_token_min_amount, 'TOKEN_GAIN_LESS_THAN_MIN_AMOUNT');
            assert(buy_token.transfer(position_owner, buy_token_gained), 'UNEXPECTED_ERROR');
            // Validate that the swap used the entire amount of token_in. If not, transfer the
            // remaining amount (`token_in_refund`) to the position owner.
            let sell_token_after = sell_token.balance_of(contract_address);
            let sell_token_used = sell_token_before - sell_token_after;
            let sell_token_refund = sell_token_amount - sell_token_used;
            if sell_token_refund > 0 {
                assert(sell_token.transfer(position_owner, sell_token_refund), 'UNEXPECTED_ERROR');
                sell_token.approve(strategy, 0);
            }

            self
                .emit(
                    Event::MultiRouteSwap(
                        MultiRouteSwap {
                            position_owner,
                            sell_token: sell_token_address,
                            amount_sold: sell_token_used,
                            amount_not_sold: sell_token_refund,
                            buy_token: buy_token_address,
                            amount_received: buy_token_gained,
                        },
                    ),
                );
            buy_token_gained
        }
    }

    #[constructor]
    pub fn constructor(
        ref self: ContractState,
        governance_admin: ContractAddress,
        upgrade_delay: u64,
        account_factory: ContractAddress,
    ) {
        self.roles.initialize(:governance_admin);
        self.account_factory.write(account_factory);
        self.replaceability.initialize(:upgrade_delay);
    }

    #[abi(embed_v0)]
    impl StrategyImplementationImpl of IStrategyImplementation<ContractState> {
        fn apply_on_self(
            ref self: ContractState,
            token_in: ContractAddress,
            amount: u256,
            position_owner: ContractAddress,
            protocol: felt252,
            mut parameters: Span<felt252>,
        ) {
            // Only the contract itself can call this function.
            let contract_address = get_contract_address();
            assert(get_caller_address() == contract_address, 'ONLY_SELF_CALLER');

            let strategy: Strategy = strategy_from_protocol_and_token(:protocol, :token_in);
            match strategy {
                Strategy::Endur(_) => {
                    // No additional parameters are expected for Endur after the common header.
                    assert(parameters.len() == 0, 'UNEXPECTED_PARAMETERS');
                    let lst_amount = self
                        .deposit_token_to_vault(
                            strategy: strategy.strategy_address(),
                            token: token_in,
                            :amount,
                            funds_receiver: position_owner,
                        );
                    self
                        .emit(
                            Event::Deposited(
                                Deposited {
                                    receiver_address: position_owner,
                                    token_deposited: token_in,
                                    amount_deposited: amount,
                                    token_received: strategy.strategy_address(),
                                    amount_received: lst_amount,
                                },
                            ),
                        );
                },
                Strategy::Troves(token) => {
                    // No additional parameters are expected for Troves after the common header.
                    assert(parameters.len() == 0, 'UNEXPECTED_PARAMETERS');

                    // If the strategy is a Troves strategy, need to do two deposits:
                    // 1. Deposit the wrapper token to the corresponding LST token using the Endur
                    // strategy.
                    // 2. Deposit the LST token to the Troves strategy.
                    let lst_token = Strategy::Endur(token).strategy_address();
                    // The lst amount should stay in this contract to be able to deposit it to the
                    // Troves strategy.
                    let lst_amount = self
                        .deposit_token_to_vault(
                            strategy: lst_token,
                            token: token_in,
                            :amount,
                            funds_receiver: contract_address,
                        );
                    let troves_amount = self
                        .deposit_token_to_vault(
                            strategy: strategy.strategy_address(), //  Troves strategy.
                            token: lst_token,
                            amount: lst_amount,
                            funds_receiver: position_owner,
                        );
                    self
                        .emit(
                            Event::Deposited(
                                Deposited {
                                    receiver_address: position_owner,
                                    token_deposited: token_in,
                                    amount_deposited: amount,
                                    token_received: strategy.strategy_address(),
                                    amount_received: troves_amount,
                                },
                            ),
                        );
                },
                Strategy::Avnu => {
                    self
                        .avnu_multi_route_swap(
                            sell_token_address: token_in,
                            sell_token_amount: amount,
                            strategy: strategy.strategy_address(),
                            :position_owner,
                            avnu_parameters: parameters,
                        );
                },
            }
        }

        /// Applies the strategy for the caller by transferring `amount` of `token_in`, executing
        /// the strategy encoded in the protocol selector and token_in, in `parameters`, and
        /// emitting `ApplyFailed` + refunding to the position owner on failure.
        ///
        /// Args:
        /// - `token_in`: ERC20 token to operate on.
        /// - `amount`: Positive amount of `token_in` to apply.
        /// - `parameters`: ABI-encoded header and strategy payload (eth_address, signature,
        /// chain_id, protocol and optional Avnu parameters when `protocol == 'AVNU'`).
        #[feature("safe_dispatcher")]
        fn apply(
            ref self: ContractState,
            token_in: ContractAddress,
            amount: u256,
            mut parameters: Span<felt252>,
        ) {
            if amount == 0 {
                return;
            }
            let caller_address = get_caller_address();
            // If the amount is greater than the the approved balance, the transfer will fail and
            // the transaction will revert.
            assert(
                IERC20Dispatcher { contract_address: token_in }
                    .transfer_from(
                        sender: caller_address, recipient: get_contract_address(), :amount,
                    ),
                'UNEXPECTED_ERROR',
            );

            let eth_address = Serde::deserialize(ref parameters).expect('INVALID_ETH_ADDRESS');
            let account_factory = IAccountFactoryDispatcher {
                contract_address: self.account_factory.read(),
            };

            let signature = deserialize_signature(ref parameters);
            // `chain_id` is not used by StrategyImplementation; it is included to keep the header
            // format consistent with the parameters used for outside execution.
            let _chain_id: felt252 = Serde::deserialize(ref parameters)
                .expect('SERIALIZATION_FAILED');

            let position_owner = account_factory.deploy_account(:eth_address, :signature);

            let protocol: felt252 = Serde::deserialize(ref parameters)
                .expect('PROTOCOL_SERIALIZATION_FAILED');

            // Safe dispatcher to handle the apply_on_self failure gracefully.
            let result = IStrategyImplementationSafeDispatcher {
                contract_address: get_contract_address(),
            }
                .apply_on_self(:token_in, :amount, :position_owner, :protocol, :parameters);

            self
                .handle_apply_on_self_result(
                    :result, :token_in, :amount, :position_owner, :protocol,
                );
        }

        fn account_factory(self: @ContractState) -> ContractAddress {
            self.account_factory.read()
        }
    }
}
