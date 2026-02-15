use snforge_std::{ContractClassTrait, DeclareResultTrait};
use starknet::{ContractAddress, SyscallResultTrait};

/// Deploy the EarnReporter contract and return its address.
pub(crate) fn deploy_earn_reporter(owner: ContractAddress) -> ContractAddress {
    let earn_reporter_class = snforge_std::declare("EarnReporter")
        .unwrap_syscall()
        .contract_class();
    let (earn_reporter_addr, _) = earn_reporter_class
        .deploy(@array![owner.into()])
        .unwrap_syscall();
    earn_reporter_addr
}
