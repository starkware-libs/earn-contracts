use core::hash::HashStateTrait;
use core::num::traits::Zero;
use core::pedersen::PedersenTrait;
use starknet::secp256_trait::Signature;
use starknet::syscalls::get_class_hash_at_syscall;
use starknet::{ClassHash, ContractAddress, EthAddress, SyscallResultTrait, get_contract_address};
pub(crate) const CONTRACT_ADDRESS_SALT: felt252 = 0;

#[cfg(target: "test")]
pub const PRIMER_CLASS_HASH: ClassHash =
    0x0279a9bb18604f4ae57633373d56656063203f236cc5aeceea8f2cf40f6336d7
    .try_into()
    .unwrap();

// Recomputed for scarb 2.16.1 release-profile builds. If you upgrade scarb
// or change Primer source, rerun `sncast utils class-hash --package contracts
// --contract-name Primer` and update this constant — the on-chain Primer
// declaration's class hash MUST match this value or the factory's
// deploy_syscall will fail with CLASS_NOT_DECLARED.
#[cfg(not(target: "test"))]
pub const PRIMER_CLASS_HASH: ClassHash =
    0x03edae2158f4aea6295470678fc7de27e19d7e40f295cda90d786d17b3531fdf
    .try_into()
    .unwrap();

const CONTRACT_ADDRESS_PREFIX: felt252 = 'STARKNET_CONTRACT_ADDRESS';

#[starknet::interface]
pub(crate) trait IEthAccountInitializer<TContractState> {
    fn initialize(
        ref self: TContractState, owner_eth_address: EthAddress, signature: Signature,
    );
}

/// Computes the Pedersen hash on the elements of the span using a hash state.
// TODO: Move this function to a shared utils package to avoid duplication across packages.
pub fn compute_pedersen_on_elements(data: Span<felt252>) -> felt252 {
    let mut state = PedersenTrait::new(0);
    for value in data {
        state = state.update(*value);
    }
    state = state.update(data.len().into());
    state.finalize()
}


/// Computes the account contract address for a given Eth address.
pub fn eth_address_to_account(eth_address: EthAddress) -> ContractAddress {
    compute_contract_address(
        salt: eth_address.into(),
        class_hash: PRIMER_CLASS_HASH.into(),
        constructor_calldata: array![].span(),
        deployer_address: get_contract_address().into(),
    )
}


/// Computes the contract address for a given salt, class hash, constructor calldata and deployer
/// address.
pub fn compute_contract_address(
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

/// Checks if the contract is deployed at the given address.
pub fn is_deployed(addr: ContractAddress) -> bool {
    get_class_hash_at_syscall(addr).unwrap_syscall() != Zero::zero()
}
