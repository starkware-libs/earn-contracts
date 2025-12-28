use starknet::ContractAddress;

// Token contract addresses.
pub(crate) const WBTC: ContractAddress =
    0x03fe2b97c1fd336e750087d68b9b867997fd64a2661ff3ca5a7c771641e8e7ac
    .try_into()
    .unwrap();
pub(crate) const TBTC: ContractAddress =
    0x04daa17763b286d1e59b97c283C0b8C949994C361e426A28F743c67bDfE9a32f
    .try_into()
    .unwrap();
pub(crate) const SOLVBTC: ContractAddress =
    0x0593e034DdA23eea82d2bA9a30960ED42CF4A01502Cc2351Dc9B9881F9931a68
    .try_into()
    .unwrap();

pub(crate) const LBTC: ContractAddress =
    0x036834a40984312f7f7de8d31e3f6305b325389eaeea5b1c0664b2fb936461a4
    .try_into()
    .unwrap();

pub(crate) const MIDAS_RE7_BTC: ContractAddress =
    0x04E4fb1a9Ca7E84bAe609B9Dc0078ad7719E49187Ae7e425bB47D131710Eddac
    .try_into()
    .unwrap();

// MIDAS token.
pub(crate) const MIDAS: ContractAddress =
    0x04e4fb1a9ca7e84bae609b9dc0078ad7719e49187ae7e425bb47d131710eddac
    .try_into()
    .unwrap();

// Contract addresses for Troves strategies. Each strategy differs in the token it supports.
pub(crate) const TROVES_WBTC: ContractAddress =
    0x2da9d0f96a46b453f55604313785dc866424240b1c6811d13bef594343db818
    .try_into()
    .unwrap();
pub(crate) const TROVES_TBTC: ContractAddress =
    0x47d5f68477e5637ce0e56436c6b5eee5a354e6828995dae106b11a48679328
    .try_into()
    .unwrap();
pub(crate) const TROVES_SOLVBTC: ContractAddress =
    0x437ef1e7d0f100b2e070b7a65cafec0b2be31b0290776da8b4112f5473d8d9
    .try_into()
    .unwrap();
pub(crate) const TROVES_LBTC: ContractAddress =
    0x064cF24d4883FE569926419a0569ab34497C6956a1a308fA883257f7486d7030
    .try_into()
    .unwrap();

// Contract addresses for Endur strategies. Each strategy differs in the token it supports.
pub(crate) const ENDUR_WBTC: ContractAddress =
    0x06a567e68c805323525fe1649adb80b03cddf92c23d2629a6779f54192dffc13
    .try_into()
    .unwrap();

pub(crate) const ENDUR_TBTC: ContractAddress =
    0x043a35c1425a0125ef8c171f1a75c6f31ef8648edcc8324b55ce1917db3f9b91
    .try_into()
    .unwrap();

pub(crate) const ENDUR_LBTC: ContractAddress =
    0x07dd3c80de9fcc5545f0cb83678826819c79619ed7992cc06ff81fc67cd2efe0
    .try_into()
    .unwrap();

pub(crate) const ENDUR_SOLVBTC: ContractAddress =
    0x0580f3dc564a7b82f21d40d404b3842d490ae7205e6ac07b1b7af2b4a5183dc9
    .try_into()
    .unwrap();


// Avnu strategy
pub(crate) const AVNU_EXCHANGE: ContractAddress =
    0x04270219d365d6B017231b52e92B3fb5d7C8378b05e9Abc97724537a80E93b0f
    .try_into()
    .unwrap();
