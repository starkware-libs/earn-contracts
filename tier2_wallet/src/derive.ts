import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import { BOOTSTRAP_MESSAGE, SECP256K1_N } from "./constants.js";
import type { MmSigner } from "./mm-signer.js";
import type { Hex, SessionKey } from "./types.js";
import { addressFromPubKey } from "./util.js";

/**
 * Derive the Tier 2 session keypair from a MetaMask bootstrap signature.
 *
 * Algorithm:
 *   1. Have the MM signer produce a deterministic personal_sign over the
 *      fixed BOOTSTRAP_MESSAGE.
 *   2. seed = keccak256(signature_bytes).
 *   3. privKey = (seed mod (N - 1)) + 1     where N = secp256k1 order.
 *      (`+ 1` ensures the scalar is non-zero; rejecting the ~0% probability
 *      that seed-mod-N collides on 0 keeps the derivation total.)
 *   4. pubKey = G * privKey.
 *   5. ethAddress = lower-20-bytes of keccak256(pubKey_uncompressed_xy).
 *
 * The whole privacy property of Tier 2 hinges on this private key NEVER
 * being equal to the user's MetaMask key — i.e., that the user signed an
 * arbitrary message rather than handing over their seed. The two keys
 * share entropy via the signature, but the public key derived here has
 * no on-chain history outside this Starknet account.
 */
export async function deriveSessionKey(
  signer: MmSigner,
  bootstrapMessage: string = BOOTSTRAP_MESSAGE,
): Promise<SessionKey> {
  const sig = await signer.personalSign(bootstrapMessage);
  return deriveSessionKeyFromSignature(sig);
}

/**
 * Construct a SessionKey from a raw 32-byte secp256k1 private key. Mostly
 * useful for tests that need to use the same key as a non-JS reference
 * implementation (e.g. the Python signature generator). Production callers
 * should never invoke this directly — they should derive via
 * {@link deriveSessionKey}.
 */
export function sessionKeyFromPriv(privHex: Hex): SessionKey {
  if (!privHex.startsWith("0x") || privHex.length !== 66) {
    throw new Error("expected 32-byte hex private key");
  }
  const privBytes = hexToBytes(privHex.slice(2));
  const pub = secp256k1.getPublicKey(privBytes, false);
  return {
    privKey: privHex,
    pubKeyUncompressed: ("0x" + bytesToHex(pub.subarray(1))) as Hex,
    ethAddress: addressFromPubKey(pub),
  };
}

/**
 * Variant of {@link deriveSessionKey} for when the caller already holds the
 * raw `personal_sign` output. Useful in tests and when the bootstrap signature
 * is cached.
 */
export function deriveSessionKeyFromSignature(sig: Hex): SessionKey {
  if (!sig.startsWith("0x") || sig.length !== 132) {
    throw new Error(`expected 65-byte hex signature, got length ${sig.length}`);
  }
  const sigBytes = hexToBytes(sig.slice(2));
  const seedBytes = keccak_256(sigBytes);
  const seed = BigInt("0x" + bytesToHex(seedBytes));

  // privKey ∈ [1, N-1].
  const privScalar = (seed % (SECP256K1_N - 1n)) + 1n;
  const privHex = privScalar.toString(16).padStart(64, "0");
  const privBytes = hexToBytes(privHex);

  const pub = secp256k1.getPublicKey(privBytes, false); // 65-byte 0x04 || X || Y
  const pubXY = pub.subarray(1);
  return {
    privKey: ("0x" + privHex) as Hex,
    pubKeyUncompressed: ("0x" + bytesToHex(pubXY)) as Hex,
    ethAddress: addressFromPubKey(pub),
  };
}
