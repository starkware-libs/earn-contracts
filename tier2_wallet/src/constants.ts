/**
 * Constants mirroring the on-chain Cairo definitions.
 *
 * Any change to a typehash, class hash, or message string on the Cairo side
 * MUST be reflected here verbatim. The wallet computes signatures off-chain
 * that must match what `eth_712_utils.cairo` and `account_factory` consume.
 */

// keccak256("\x19Ethereum Signed Message:\n41Sign to verify that you own this account.")
// from eth_712_utils.cairo:27
export const OWNERSHIP_TRANSFER_MSG_HASH =
  0x3ce976d55131cd0bdd49f20afbded052d8e907dc6034d95cdf117a8fd7752e3cn;

// keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
// from eth_712_utils.cairo:12
export const EIP712_DOMAIN_TYPE_HASH =
  0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400fn;

// keccak256("Call(uint256 address,uint256 selector,uint256[] data)")
// from eth_712_utils.cairo:16
export const CALL_TYPE_HASH =
  0x7793b9bed3b87c6119fe923f0da4e85e1f97a03272a446514622ee7bd62ad25fn;

// keccak256 of the OutsideExecution struct typestring; see eth_712_utils.cairo:19
export const OUTSIDE_EXECUTION_TYPE_HASH =
  0x57fbef2abe14202f3651b3935a8feddd357b8f83a862e046239d196ec76f281en;

// keccak256("2") — domain version
export const VERSION_HASH =
  0xad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5n;

// account_factory/src/utils.cairo: PRIMER_CLASS_HASH. Two values exist —
// the test-target hash and the production hash. Wallet code must pick
// the right one for the deployment target.
export const PRIMER_CLASS_HASH = {
  // Must match account_factory/src/utils.cairo::PRIMER_CLASS_HASH and the
  // on-chain Primer class declaration. If you upgrade scarb or change Primer,
  // bump both sides.
  prod:
    0x03edae2158f4aea6295470678fc7de27e19d7e40f295cda90d786d17b3531fdfn,
  test:
    0x0279a9bb18604f4ae57633373d56656063203f236cc5aeceea8f2cf40f6336d7n,
} as const;

// Fixed message MM signs to derive the session key. Versioning lets us
// rotate the derivation in the future without breaking existing users —
// they keep their v1 key, new users get v2.
export const BOOTSTRAP_MESSAGE = "Derive Earn Starknet account key v1";

// 'ANY_CALLER' as a felt (ASCII-encoded).
// Use TextEncoder so this module is browser-safe (Buffer is Node-only).
export const ANY_CALLER = bytesToBigIntBE(
  new TextEncoder().encode("ANY_CALLER"),
);

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

export const MASK_128 = (1n << 128n) - 1n;
export const MASK_250 = (1n << 250n) - 1n;
export const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
