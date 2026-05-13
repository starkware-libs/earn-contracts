import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { hexToBytes } from "@noble/hashes/utils";

import {
  CALL_TYPE_HASH,
  EIP712_DOMAIN_TYPE_HASH,
  MASK_128,
  OUTSIDE_EXECUTION_TYPE_HASH,
  OWNERSHIP_TRANSFER_MSG_HASH,
  VERSION_HASH,
} from "./constants.js";
import type {
  CairoSignature,
  Call,
  OutsideExecution,
  OutsideExecutionDomain,
  OutsideExecutionSignature,
  SessionKey,
} from "./types.js";
import {
  bigintToBytes32,
  bytes32ToBigInt,
  concat,
  feltToByteArray,
} from "./util.js";

// ─── Ownership signature ────────────────────────────────────────────────────

/**
 * Produce the signature `factory.deploy_account` expects.
 *
 * The Cairo side validates with:
 *   `assert_valid_owner(eth_address: owner_eth_address, signature)`
 *   → `recover_eth_address(OWNERSHIP_TRANSFER_MSG_HASH, sig) == owner_eth_address`
 *
 * So we sign `OWNERSHIP_TRANSFER_MSG_HASH` (a fixed pre-hashed message) with
 * the session private key and serialize as `{r, s, y_parity}`.
 *
 * Note the Cairo `y_parity` convention: `y_parity = (v % 2 == 0)`. With the
 * EVM `recovery` byte ∈ {0, 1}, this translates to `recovery == 1`.
 */
export function signOwnership(session: SessionKey): CairoSignature {
  const priv = hexToBytes(session.privKey.slice(2));
  const msgHash = bigintToBytes32(OWNERSHIP_TRANSFER_MSG_HASH);
  const sig = secp256k1.sign(msgHash, priv, { lowS: true });
  const recovery = sig.recovery ?? 0;
  // Cairo: y_parity = (v % 2 == 0). With v = 27 + recovery → y_parity true iff
  // recovery == 1 (v == 28). Encode with that meaning.
  return {
    r: sig.r,
    s: sig.s,
    yParity: recovery === 1,
  };
}

/** Encode a {@link CairoSignature} as the calldata felts the dispatcher expects. */
export function encodeOwnershipSignature(sig: CairoSignature): bigint[] {
  return [
    sig.r & MASK_128,
    sig.r >> 128n,
    sig.s & MASK_128,
    sig.s >> 128n,
    sig.yParity ? 1n : 0n,
  ];
}

// ─── EIP-712 OutsideExecution signature ─────────────────────────────────────

/** Hash a single Call per `push_call` in eth_712_utils.cairo. */
export function hashCall(call: Call): Uint8Array {
  const calldataConcat = concat(
    ...call.calldata.map((felt) => bigintToBytes32(felt)),
  );
  const calldataHash = keccak_256(calldataConcat);
  return keccak_256(
    concat(
      bigintToBytes32(CALL_TYPE_HASH),
      bigintToBytes32(call.to),
      bigintToBytes32(call.selector),
      calldataHash,
    ),
  );
}

/** Hash an array of Calls per `push_call_array`. */
export function hashCallArray(calls: Call[]): Uint8Array {
  return keccak_256(concat(...calls.map(hashCall)));
}

/** Hash the OutsideExecution struct per `push_outside_execution`. */
export function hashOutsideExecution(ose: OutsideExecution): Uint8Array {
  const callsHash = hashCallArray(ose.calls);
  return keccak_256(
    concat(
      bigintToBytes32(OUTSIDE_EXECUTION_TYPE_HASH),
      callsHash,
      bigintToBytes32(ose.caller),
      bigintToBytes32(ose.nonce),
      bigintToBytes32(ose.executeAfter),
      bigintToBytes32(ose.executeBefore),
    ),
  );
}

/**
 * Compute the EIP-712 domain separator per `push_domain_separator`.
 * `name` uses the keccak of the Starknet chain id encoded as its byte
 * representation (matching Cairo's `sn_chain_id_keccak`).
 */
export function computeDomainSeparator(domain: OutsideExecutionDomain): Uint8Array {
  const nameHash = keccak_256(feltToByteArray(domain.starknetChainId));
  const verifyingContract = domain.accountAddress & MASK_128; // low 128 bits only
  return keccak_256(
    concat(
      bigintToBytes32(EIP712_DOMAIN_TYPE_HASH),
      nameHash,
      bigintToBytes32(VERSION_HASH),
      bigintToBytes32(domain.evmChainId),
      bigintToBytes32(verifyingContract),
    ),
  );
}

/**
 * Compute the final EIP-712 message hash that `is_valid_signature` recovers
 * against. Format: `keccak(0x19 || 0x01 || domain_separator || struct_hash)`.
 */
export function computeOutsideExecutionHash(
  ose: OutsideExecution,
  domain: OutsideExecutionDomain,
): Uint8Array {
  return keccak_256(
    concat(
      new Uint8Array([0x19, 0x01]),
      computeDomainSeparator(domain),
      hashOutsideExecution(ose),
    ),
  );
}

/**
 * Sign an OutsideExecution with the session key and produce the 6-felt span
 * `execute_from_outside_v2` expects.
 *
 * Span layout (matches `extract_signature` in eth_712_utils.cairo):
 *   [r_high, r_low, s_high, s_low, v, evm_chain_id]
 *
 * `v` is encoded as `27 + recovery` so that, after the Cairo `(v % 2 == 0)`
 * check, the resulting `y_parity` matches what secp256k1 recovery actually
 * produced.
 */
export function signOutsideExecution(opts: {
  session: SessionKey;
  outsideExecution: OutsideExecution;
  domain: OutsideExecutionDomain;
}): OutsideExecutionSignature {
  const { session, outsideExecution, domain } = opts;
  const digest = computeOutsideExecutionHash(outsideExecution, domain);
  const priv = hexToBytes(session.privKey.slice(2));
  const sig = secp256k1.sign(digest, priv, { lowS: true });
  const recovery = sig.recovery ?? 0;
  const v = BigInt(27 + recovery);
  return [
    sig.r >> 128n,           // r_high
    sig.r & MASK_128,        // r_low
    sig.s >> 128n,           // s_high
    sig.s & MASK_128,        // s_low
    v,                       // v
    domain.evmChainId,       // chain_id (EVM)
  ];
}

/**
 * Convenience: return the EIP-712 digest as a bigint (matches what the Cairo
 * `get_outside_execution_hash` returns).
 */
export function outsideExecutionHashAsBigInt(
  ose: OutsideExecution,
  domain: OutsideExecutionDomain,
): bigint {
  return bytes32ToBigInt(computeOutsideExecutionHash(ose, domain));
}
