import { describe, expect, it } from "vitest";
import { hash } from "starknet";

import {
  PRIMER_CLASS_HASH,
  computeAccountAddress,
  sessionKeyFromPriv,
} from "../src/index.js";

const TEST_PRIV =
  "0xa6d86467b6ec9e161649b27edfd8519e75a2e1cf5f4c309c628706e6999780e8" as const;
// Stark-curve addresses must be < 2^251 + ε. Picked something inside that range.
const FACTORY_ADDR =
  0x01a2b3c4d5e6f7890123456789abcdef0123456789abcdef0123456789abcdefn;

describe("computeAccountAddress", () => {
  it("matches starknet.js calculateContractAddressFromHash", () => {
    const session = sessionKeyFromPriv(TEST_PRIV);
    const ours = computeAccountAddress({
      sessionEthAddress: session.ethAddress,
      factoryAddress: FACTORY_ADDR,
      network: "prod",
    });
    const ref = BigInt(
      hash.calculateContractAddressFromHash(
        session.ethAddress,
        "0x" + PRIMER_CLASS_HASH.prod.toString(16),
        [],
        "0x" + FACTORY_ADDR.toString(16),
      ),
    );
    expect(ours).toEqual(ref);
  });

  it("is deterministic for the same inputs", () => {
    const session = sessionKeyFromPriv(TEST_PRIV);
    const a = computeAccountAddress({
      sessionEthAddress: session.ethAddress,
      factoryAddress: FACTORY_ADDR,
    });
    const b = computeAccountAddress({
      sessionEthAddress: session.ethAddress,
      factoryAddress: FACTORY_ADDR,
    });
    expect(a).toEqual(b);
  });

  it("differs across networks (test vs prod primer)", () => {
    const session = sessionKeyFromPriv(TEST_PRIV);
    const prod = computeAccountAddress({
      sessionEthAddress: session.ethAddress,
      factoryAddress: FACTORY_ADDR,
      network: "prod",
    });
    const test = computeAccountAddress({
      sessionEthAddress: session.ethAddress,
      factoryAddress: FACTORY_ADDR,
      network: "test",
    });
    expect(prod).not.toEqual(test);
  });

  it("differs across different session addresses", () => {
    const a = computeAccountAddress({
      sessionEthAddress: 0x1111111111111111111111111111111111111111n,
      factoryAddress: FACTORY_ADDR,
    });
    const b = computeAccountAddress({
      sessionEthAddress: 0x2222222222222222222222222222222222222222n,
      factoryAddress: FACTORY_ADDR,
    });
    expect(a).not.toEqual(b);
  });
});
