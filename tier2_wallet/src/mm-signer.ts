import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

import type { Hex } from "./types.js";
import { addressFromPubKey } from "./util.js";

/**
 * Abstraction over whatever produces a `personal_sign` signature.
 *
 * In production this is a `window.ethereum.request({ method: 'personal_sign' })`
 * wrapper. In tests it is a stand-in that uses a known private key so that the
 * derived session key (and therefore every downstream artifact) is reproducible.
 *
 * `personalSign` MUST be deterministic for the same key + message
 * (RFC-6979). Wallets that use non-deterministic ECDSA will produce a
 * different session key on each call and will not be supported.
 */
export interface MmSigner {
  /**
   * Return the Ethereum-format address that backs this signer. Used purely
   * for sanity checks in the demo — never recorded on Starknet.
   */
  address(): Promise<Hex>;

  /**
   * Sign `message` with the EIP-191 personal_sign envelope:
   *   keccak256("\x19Ethereum Signed Message:\n" || len(message) || message)
   * Returns a hex string `0x{r}{s}{v}` (65 bytes / 130 hex chars).
   */
  personalSign(message: string): Promise<Hex>;
}

/**
 * Compute the EIP-191 personal_sign digest for a message.
 */
export function personalSignDigest(message: string): Uint8Array {
  const msgBytes = utf8ToBytes(message);
  const prefix = utf8ToBytes(
    `\x19Ethereum Signed Message:\n${msgBytes.length}`,
  );
  const combined = new Uint8Array(prefix.length + msgBytes.length);
  combined.set(prefix, 0);
  combined.set(msgBytes, prefix.length);
  return keccak_256(combined);
}

/**
 * Test signer backed by a fixed private key. Never use this in production.
 *
 * The default key matches `eth_712_account/scripts/generate_test_signatures.py`
 * (`0xa6d86467...e8`, address `0xbF60187c5dFfA627249f1C3000A4168dbB9D7A1A`)
 * so Python-generated reference signatures and JS-generated signatures can be
 * compared directly as cross-checks.
 */
export class FixedKeyMmSigner implements MmSigner {
  readonly privKey: Uint8Array;

  constructor(
    privKeyHex: Hex = "0xa6d86467b6ec9e161649b27edfd8519e75a2e1cf5f4c309c628706e6999780e8",
  ) {
    this.privKey = hexToBytes(privKeyHex.slice(2));
  }

  async address(): Promise<Hex> {
    const pub = secp256k1.getPublicKey(this.privKey, false);
    return addressFromPubKey(pub);
  }

  async personalSign(message: string): Promise<Hex> {
    const digest = personalSignDigest(message);
    const sig = secp256k1.sign(digest, this.privKey, { lowS: true });
    // Build EVM-style 65-byte signature: r || s || v (v = 27 + recovery)
    const r = sig.r.toString(16).padStart(64, "0");
    const s = sig.s.toString(16).padStart(64, "0");
    const v = (27 + (sig.recovery ?? 0)).toString(16).padStart(2, "0");
    return ("0x" + r + s + v) as Hex;
  }

  /** Convenience: return the address synchronously for tests. */
  addressSync(): Hex {
    const pub = secp256k1.getPublicKey(this.privKey, false);
    return addressFromPubKey(pub);
  }

  /** Convenience: return the signature synchronously for tests. */
  personalSignSync(message: string): Hex {
    const digest = personalSignDigest(message);
    const sig = secp256k1.sign(digest, this.privKey, { lowS: true });
    const r = sig.r.toString(16).padStart(64, "0");
    const s = sig.s.toString(16).padStart(64, "0");
    const v = (27 + (sig.recovery ?? 0)).toString(16).padStart(2, "0");
    return ("0x" + r + s + v) as Hex;
  }
}

/**
 * Adapter for `window.ethereum` (EIP-1193 provider). Only available in
 * browsers; this file is import-safe in Node because the class is lazy.
 */
export class BrowserMmSigner implements MmSigner {
  private cachedAddress: Hex | null = null;
  private readonly provider: {
    request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
  };

  constructor(provider: unknown) {
    if (
      provider == null ||
      typeof (provider as { request?: unknown }).request !== "function"
    ) {
      throw new Error("provider does not look like an EIP-1193 provider");
    }
    this.provider = provider as {
      request: (
        args: { method: string; params?: unknown[] },
      ) => Promise<unknown>;
    };
  }

  async address(): Promise<Hex> {
    if (this.cachedAddress) return this.cachedAddress;
    const accounts = (await this.provider.request({
      method: "eth_requestAccounts",
    })) as Hex[];
    if (!Array.isArray(accounts) || accounts.length === 0) {
      throw new Error("eth_requestAccounts returned no accounts");
    }
    this.cachedAddress = accounts[0];
    return accounts[0];
  }

  async personalSign(message: string): Promise<Hex> {
    const addr = await this.address();
    const hexMsg = ("0x" + bytesToHex(utf8ToBytes(message))) as Hex;
    const sig = (await this.provider.request({
      method: "personal_sign",
      params: [hexMsg, addr],
    })) as Hex;
    if (typeof sig !== "string" || !sig.startsWith("0x") || sig.length !== 132) {
      throw new Error(`personal_sign returned malformed signature: ${sig}`);
    }
    return sig;
  }
}
