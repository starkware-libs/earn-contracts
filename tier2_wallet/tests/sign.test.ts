/**
 * EIP-712 cross-check against `eth_712_account/scripts/generate_test_signatures.py`.
 *
 * The Python script signs four canonical OutsideExecutions with a known
 * private key and prints the signature felts. The JS sign module must
 * produce byte-identical output. If any of these tests fail, the on-chain
 * `is_valid_signature` check will reject signatures from this wallet —
 * meaning the wallet cannot drive the existing Cairo contract.
 */
import { describe, expect, it } from "vitest";
import { hash } from "starknet";

import {
  ANY_CALLER,
  MASK_128,
  OWNERSHIP_TRANSFER_MSG_HASH,
  computeAccountAddress,
  computeOutsideExecutionHash,
  encodeOwnershipSignature,
  sessionKeyFromPriv,
  signOutsideExecution,
  signOwnership,
} from "../src/index.js";

import type { Call, OutsideExecution } from "../src/index.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bigintToBytes32 } from "../src/util.js";
import { keccak_256 } from "@noble/hashes/sha3";

// ─── Python-script constants (must stay in lockstep with generate_test_signatures.py) ──

const PYTHON_TEST_PRIV =
  "0xa6d86467b6ec9e161649b27edfd8519e75a2e1cf5f4c309c628706e6999780e8" as const;
const PYTHON_TEST_ETH_ADDRESS =
  "0xbf60187c5dffa627249f1c3000a4168dbb9d7a1a";

const CONTRACT_ADDR =
  0x0651b6cc1595bcd7edddc42163b57e066956b8fba487dd781cd7e4b3a671ffe4n;
const TOKEN_ADDR =
  0x0405ea0439568d265140400aa7b31e896604406bdfa7e73e18dec06303c31c6cn;
const SPENDER = 0x1234n;
const RECIPIENT = 0x5678n;
const SPECIFIC_CALLER = 0xcafen;

const ETH_CHAIN_ID = 1n;
const SN_CHAIN_ID_FELT = BigInt(
  "0x" + Buffer.from("SN_MAIN", "utf8").toString("hex"),
); // 0x534e5f4d41494e

const EXECUTE_AFTER = 1000n;
const EXECUTE_BEFORE = 3000n;

const APPROVE_AMOUNT = 500n;
const TRANSFER_AMOUNT = 100n;
const INITIAL_SUPPLY = 1000n;

function selector(name: string): bigint {
  return BigInt(hash.starknetKeccak(name));
}

function approveCall(amount: bigint): Call {
  return {
    to: TOKEN_ADDR,
    selector: selector("approve"),
    calldata: [SPENDER, amount & MASK_128, amount >> 128n],
  };
}

function transferCall(amount: bigint): Call {
  return {
    to: TOKEN_ADDR,
    selector: selector("transfer"),
    calldata: [RECIPIENT, amount & MASK_128, amount >> 128n],
  };
}

const DOMAIN = {
  accountAddress: CONTRACT_ADDR,
  evmChainId: ETH_CHAIN_ID,
  starknetChainId: SN_CHAIN_ID_FELT,
};

const SESSION = sessionKeyFromPriv(PYTHON_TEST_PRIV);

describe("signOwnership", () => {
  it("session-key bookkeeping matches the Python test vector", () => {
    expect(SESSION.ethAddress.toLowerCase()).toEqual(PYTHON_TEST_ETH_ADDRESS);
  });

  it("signature recovers to the session ETH address", () => {
    const sig = signOwnership(SESSION);
    const recovered = recoverEthAddress(
      bigintToBytes32(OWNERSHIP_TRANSFER_MSG_HASH),
      sig.r,
      sig.s,
      sig.yParity,
    );
    expect(recovered.toLowerCase()).toEqual(PYTHON_TEST_ETH_ADDRESS);
  });

  it("encodes to five felts in [r_low, r_high, s_low, s_high, y_parity] order", () => {
    const sig = signOwnership(SESSION);
    const felts = encodeOwnershipSignature(sig);
    expect(felts).toHaveLength(5);
    expect(felts[0]).toEqual(sig.r & MASK_128);
    expect(felts[1]).toEqual(sig.r >> 128n);
    expect(felts[2]).toEqual(sig.s & MASK_128);
    expect(felts[3]).toEqual(sig.s >> 128n);
    expect(felts[4]).toEqual(sig.yParity ? 1n : 0n);
  });
});

describe("signOutsideExecution — Python parity", () => {
  it("Test 1: single approve(500) at nonce=100 matches Python", () => {
    const ose: OutsideExecution = {
      caller: ANY_CALLER,
      nonce: 100n,
      executeAfter: EXECUTE_AFTER,
      executeBefore: EXECUTE_BEFORE,
      calls: [approveCall(APPROVE_AMOUNT)],
    };
    const sig = signOutsideExecution({
      session: SESSION,
      outsideExecution: ose,
      domain: DOMAIN,
    });
    expect(sig).toEqual([
      0x1df31ee91675558108ce242888ccbf09n,
      0xce39f1955774fd02a7c93cb9a7ccf33bn,
      0x1b35465d87708c6d1c70d216e91b6a79n,
      0x916b0be291ada83ecea84291854f2e98n,
      27n,
      ETH_CHAIN_ID,
    ]);
  });

  it("Test 2: approve(500) + transfer(100) at nonce=101 matches Python", () => {
    const ose: OutsideExecution = {
      caller: ANY_CALLER,
      nonce: 101n,
      executeAfter: EXECUTE_AFTER,
      executeBefore: EXECUTE_BEFORE,
      calls: [approveCall(APPROVE_AMOUNT), transferCall(TRANSFER_AMOUNT)],
    };
    const sig = signOutsideExecution({
      session: SESSION,
      outsideExecution: ose,
      domain: DOMAIN,
    });
    expect(sig).toEqual([
      0xe823335915d3f9c1a8cf05182f4d5366n,
      0xa83e96990bab81e018fd27aa284c0ad0n,
      0x7c4d2c87ace56a14eb444063a5bdb343n,
      0xf23b9d84fc44d9a10fbb0abb7cfa2badn,
      28n,
      ETH_CHAIN_ID,
    ]);
  });

  it("Test 3: atomicity (approve + over-transfer) at nonce=102 matches Python", () => {
    const ose: OutsideExecution = {
      caller: ANY_CALLER,
      nonce: 102n,
      executeAfter: EXECUTE_AFTER,
      executeBefore: EXECUTE_BEFORE,
      calls: [
        approveCall(APPROVE_AMOUNT),
        transferCall(INITIAL_SUPPLY + 1n),
      ],
    };
    const sig = signOutsideExecution({
      session: SESSION,
      outsideExecution: ose,
      domain: DOMAIN,
    });
    expect(sig).toEqual([
      0xd0cbbfc6638e59a5e3b576ae9b2305ddn,
      0xbabcee977ce0c6b0ee9ece7f944dbce3n,
      0x6f27c710ab23db5cf1e101e87602d5fdn,
      0x9170f7129929d19c9a6234d0797ca300n,
      28n,
      ETH_CHAIN_ID,
    ]);
  });

  it("Test 4: specific caller (empty calls) at nonce=103 matches Python", () => {
    const ose: OutsideExecution = {
      caller: SPECIFIC_CALLER,
      nonce: 103n,
      executeAfter: EXECUTE_AFTER,
      executeBefore: EXECUTE_BEFORE,
      calls: [],
    };
    const sig = signOutsideExecution({
      session: SESSION,
      outsideExecution: ose,
      domain: DOMAIN,
    });
    expect(sig).toEqual([
      0x661b512c1158c255c61c5f0214f167c7n,
      0x961538890df420779799bd7a8d236e06n,
      0x3fbcc975607ffe4640fc6c175ee5cdaen,
      0x5fc913ba9a2de3bbe95914339a7a8666n,
      27n,
      ETH_CHAIN_ID,
    ]);
  });
});

describe("EIP-712 hash determinism", () => {
  it("changes when nonce changes", () => {
    const baseOse: OutsideExecution = {
      caller: ANY_CALLER,
      nonce: 100n,
      executeAfter: EXECUTE_AFTER,
      executeBefore: EXECUTE_BEFORE,
      calls: [approveCall(APPROVE_AMOUNT)],
    };
    const h1 = computeOutsideExecutionHash(baseOse, DOMAIN);
    const h2 = computeOutsideExecutionHash(
      { ...baseOse, nonce: 101n },
      DOMAIN,
    );
    expect(h1).not.toEqual(h2);
  });

  it("changes when verifying contract changes", () => {
    const ose: OutsideExecution = {
      caller: ANY_CALLER,
      nonce: 100n,
      executeAfter: EXECUTE_AFTER,
      executeBefore: EXECUTE_BEFORE,
      calls: [approveCall(APPROVE_AMOUNT)],
    };
    const h1 = computeOutsideExecutionHash(ose, DOMAIN);
    const h2 = computeOutsideExecutionHash(ose, {
      ...DOMAIN,
      accountAddress: DOMAIN.accountAddress + 1n,
    });
    expect(h1).not.toEqual(h2);
  });
});

describe("integration: derive → address → sign", () => {
  it("end-to-end pipeline produces consistent artifacts", () => {
    const session = sessionKeyFromPriv(PYTHON_TEST_PRIV);
    const factoryAddr = 0xfacade_facade_facaden;
    const accountAddr = computeAccountAddress({
      sessionEthAddress: session.ethAddress,
      factoryAddress: factoryAddr,
      network: "prod",
    });
    const ownership = signOwnership(session);

    expect(typeof accountAddr).toEqual("bigint");
    expect(ownership.r).toBeGreaterThan(0n);
    expect(ownership.s).toBeGreaterThan(0n);

    // Re-deriving must yield the same artifacts.
    const accountAddr2 = computeAccountAddress({
      sessionEthAddress: session.ethAddress,
      factoryAddress: factoryAddr,
      network: "prod",
    });
    expect(accountAddr2).toEqual(accountAddr);
  });
});

// ─── helpers ────────────────────────────────────────────────────────────────

/**
 * Recover the Ethereum-format address that produced an (r, s, y_parity)
 * signature over `msgHash`. We can't reach into the wallet's `recover_eth_address`
 * Cairo helper from JS, so we re-derive using @noble/curves.
 */
function recoverEthAddress(
  msgHash: Uint8Array,
  r: bigint,
  s: bigint,
  yParity: boolean,
): string {
  // Cairo convention: y_parity == true ↔ v == 28 ↔ recovery == 1.
  const recovery = yParity ? 1 : 0;
  const sig = new secp256k1.Signature(r, s).addRecoveryBit(recovery);
  const pub = sig.recoverPublicKey(msgHash).toRawBytes(false); // 65-byte 0x04 || X || Y
  const xy = pub.subarray(1);
  const hashBytes = keccak_256(xy);
  return "0x" + Buffer.from(hashBytes.subarray(12)).toString("hex");
}
