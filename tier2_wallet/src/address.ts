import { hash } from "starknet";

import { PRIMER_CLASS_HASH } from "./constants.js";
import type { Hex } from "./types.js";
import { hexToBigInt } from "./util.js";

/**
 * Network the Tier 2 deployment targets. Determines which PRIMER_CLASS_HASH
 * is used (test vs prod).
 */
export type Network = "test" | "prod";

/**
 * Compute the deterministic Starknet account contract address the factory
 * will deploy for a given session Ethereum-format address.
 *
 * Mirrors `account_factory/src/utils.cairo::eth_address_to_account`:
 *   address = pedersen_on_elements([
 *       'STARKNET_CONTRACT_ADDRESS',
 *       deployer = factory_address,
 *       salt     = session_eth_address as felt252,
 *       class_hash = PRIMER_CLASS_HASH,
 *       calldata_hash = pedersen_on_elements([])
 *   ])
 *
 * Pre-computing this client-side is essential for the Tier 2 flow: the
 * frontend builds private-pool actions that transfer funds to this address
 * BEFORE the account is actually deployed.
 */
export function computeAccountAddress(opts: {
  sessionEthAddress: bigint | Hex;
  factoryAddress: bigint | Hex;
  network?: Network;
  /** Override `PRIMER_CLASS_HASH` for unusual deployments. */
  primerClassHash?: bigint;
}): bigint {
  const network = opts.network ?? "prod";
  const salt = toBigInt(opts.sessionEthAddress);
  const deployer = toBigInt(opts.factoryAddress);
  const classHash =
    opts.primerClassHash ?? PRIMER_CLASS_HASH[network];

  const addrHex = hash.calculateContractAddressFromHash(
    "0x" + salt.toString(16),
    "0x" + classHash.toString(16),
    [],
    "0x" + deployer.toString(16),
  );

  return BigInt(addrHex);
}

function toBigInt(v: bigint | Hex): bigint {
  return typeof v === "bigint" ? v : hexToBigInt(v);
}
