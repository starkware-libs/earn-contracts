import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import type { Hex } from "./types.js";

/**
 * Derive the Ethereum-format address from a secp256k1 public key.
 * Accepts either uncompressed (65-byte with 0x04 prefix) or 64-byte raw
 * (X || Y) public keys.
 */
export function addressFromPubKey(pubKey: Uint8Array): Hex {
  const raw = pubKey.length === 65 ? pubKey.subarray(1) : pubKey;
  if (raw.length !== 64) {
    throw new Error(`unexpected pubkey length: ${pubKey.length}`);
  }
  const hash = keccak_256(raw);
  return ("0x" + bytesToHex(hash.subarray(12))) as Hex;
}

/** Convert a 0x-prefixed hex string to bigint. */
export function hexToBigInt(hex: string): bigint {
  return BigInt(hex.startsWith("0x") ? hex : "0x" + hex);
}

/** Pack a bigint as 32 big-endian bytes. */
export function bigintToBytes32(val: bigint): Uint8Array {
  if (val < 0n || val >= 1n << 256n) {
    throw new RangeError(`bigintToBytes32: value out of u256 range: ${val}`);
  }
  const out = new Uint8Array(32);
  let v = val;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Concatenate Uint8Arrays. */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Cairo `felt_to_byte_array`: returns the felt as its big-endian byte
 * representation with leading zero bytes stripped. Matches the helper
 * used by `sn_chain_id_keccak`.
 */
export function feltToByteArray(felt: bigint): Uint8Array {
  if (felt < 0n) throw new RangeError("felt must be non-negative");
  if (felt === 0n) return new Uint8Array(0);
  const hex = felt.toString(16);
  const padded = hex.length % 2 === 0 ? hex : "0" + hex;
  return hexToBytes(padded);
}

/** Compute keccak256 over the byte representation of a felt (used for chain id). */
export function keccakFelt(felt: bigint): Uint8Array {
  return keccak_256(feltToByteArray(felt));
}

/** Compute keccak256 over a UTF-8 string. */
export function keccakString(s: string): Uint8Array {
  return keccak_256(new TextEncoder().encode(s));
}

/** Read 32 bytes big-endian as bigint. */
export function bytes32ToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error(`expected 32 bytes, got ${bytes.length}`);
  }
  return BigInt("0x" + bytesToHex(bytes));
}
