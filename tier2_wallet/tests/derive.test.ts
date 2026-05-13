import { describe, expect, it } from "vitest";

import {
  BOOTSTRAP_MESSAGE,
  FixedKeyMmSigner,
  deriveSessionKey,
  deriveSessionKeyFromSignature,
  sessionKeyFromPriv,
} from "../src/index.js";

describe("deriveSessionKey", () => {
  it("is deterministic for the same MM key + message", async () => {
    const signer = new FixedKeyMmSigner();
    const a = await deriveSessionKey(signer);
    const b = await deriveSessionKey(signer);
    expect(a).toEqual(b);
  });

  it("never equals the underlying MM address", async () => {
    const signer = new FixedKeyMmSigner();
    const mmAddr = (await signer.address()).toLowerCase();
    const session = await deriveSessionKey(signer);
    expect(session.ethAddress.toLowerCase()).not.toEqual(mmAddr);
  });

  it("changes when the bootstrap message changes", async () => {
    const signer = new FixedKeyMmSigner();
    const a = await deriveSessionKey(signer, BOOTSTRAP_MESSAGE);
    const b = await deriveSessionKey(signer, BOOTSTRAP_MESSAGE + "x");
    expect(a.ethAddress).not.toEqual(b.ethAddress);
  });

  it("deriveSessionKeyFromSignature agrees with deriveSessionKey", async () => {
    const signer = new FixedKeyMmSigner();
    const sig = await signer.personalSign(BOOTSTRAP_MESSAGE);
    const fromSig = deriveSessionKeyFromSignature(sig);
    const fromSigner = await deriveSessionKey(signer);
    expect(fromSig).toEqual(fromSigner);
  });

  it("sessionKeyFromPriv round-trips through the noble curve", () => {
    const priv =
      "0xa6d86467b6ec9e161649b27edfd8519e75a2e1cf5f4c309c628706e6999780e8" as const;
    const k = sessionKeyFromPriv(priv);
    expect(k.privKey).toEqual(priv);
    // Address derived from priv key 0xa6d8...e8 is fixed and well-known
    // (this is the Python test vector's address).
    expect(k.ethAddress.toLowerCase()).toEqual(
      "0xbf60187c5dffa627249f1c3000a4168dbb9d7a1a",
    );
  });

  it("rejects malformed signatures", () => {
    expect(() => deriveSessionKeyFromSignature("0xdeadbeef" as any)).toThrow();
  });
});
