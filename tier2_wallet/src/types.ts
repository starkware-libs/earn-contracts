/**
 * Shared types for the Tier 2 wallet primitives.
 */

/** Hex string with `0x` prefix. */
export type Hex = `0x${string}`;

/** A secp256k1 session keypair derived from the MM bootstrap signature. */
export interface SessionKey {
  /** 32-byte private scalar as a hex string (0x-prefixed). */
  privKey: Hex;
  /**
   * 64-byte uncompressed public key (X || Y, no 0x04 prefix), hex-encoded.
   * Useful for ecrecover-style verification.
   */
  pubKeyUncompressed: Hex;
  /** 20-byte Ethereum-format address derived from the public key. */
  ethAddress: Hex;
}

/** Cairo `Signature { r: u256, s: u256, y_parity: bool }`. */
export interface CairoSignature {
  r: bigint;
  s: bigint;
  /** Cairo convention: `y_parity = (v % 2 == 0)`, i.e. EVM v=28 → true. */
  yParity: boolean;
}

/** A single Starknet call inside an OutsideExecution. */
export interface Call {
  to: bigint;
  selector: bigint;
  calldata: bigint[];
}

/** OutsideExecution payload as defined by ISRC9_V2. */
export interface OutsideExecution {
  caller: bigint;
  nonce: bigint;
  executeAfter: bigint;
  executeBefore: bigint;
  calls: Call[];
}

/** Domain parameters required to compute an OutsideExecution EIP-712 hash. */
export interface OutsideExecutionDomain {
  /** Starknet account contract address (used as `verifyingContract`). */
  accountAddress: bigint;
  /** EVM source chain ID encoded in the domain separator. */
  evmChainId: bigint;
  /**
   * Starknet chain identifier as a short-string-encoded felt
   * (e.g. for "SN_SEPOLIA": 0x534e5f5345504f4c4941). The Cairo side
   * keccaks the byte form of this felt to compute the domain `name`.
   */
  starknetChainId: bigint;
}

/**
 * The 6-felt span ISRC9_V2 expects as the `signature` argument to
 * `execute_from_outside_v2`. Layout per `eth_712_utils.cairo:136-147`:
 *   [r_high, r_low, s_high, s_low, v, evm_chain_id]
 */
export type OutsideExecutionSignature = [
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
  bigint,
];
