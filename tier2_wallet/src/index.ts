/**
 * Tier 2 wallet primitives.
 *
 * The public API is intentionally narrow. Compose these four building blocks
 * to flow a user from "I clicked Connect MetaMask" to "I have an unlinkable
 * Starknet account that can sign txs":
 *
 *   1. `deriveSessionKey(mmSigner)`                  → SessionKey
 *   2. `computeAccountAddress({ sessionEthAddress, factoryAddress })`
 *                                                    → Starknet account addr
 *   3. `signOwnership(session)`                      → CairoSignature for
 *                                                       factory.deploy_account
 *   4. `signOutsideExecution({ session, outsideExecution, domain })`
 *                                                    → 6-felt span for
 *                                                       execute_from_outside_v2
 */

export * from "./constants.js";
export * from "./types.js";
export * from "./util.js";
export * from "./mm-signer.js";
export * from "./derive.js";
export * from "./address.js";
export * from "./sign.js";
export * from "./paymaster.js";
export * from "./sponsored-deploy.js";
export * from "./sponsored-execute.js";
