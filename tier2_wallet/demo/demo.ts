import {
  Account,
  RpcProvider,
  constants as starknetConstants,
} from "starknet";
import {
  IndexerDiscoveryProvider,
  ProvingServiceProofProvider,
  createPrivateTransfers,
} from "@starkware-libs/starknet-privacy-sdk";

import {
  BOOTSTRAP_MESSAGE,
  BrowserMmSigner,
  PRIMER_CLASS_HASH,
  PaymasterClient,
  computeAccountAddress,
  counterIncrementCall,
  deriveSessionKey,
  encodeOwnershipSignature,
  privateSponsoredDeployTier2Account,
  privateSponsoredExecuteOnTier2Account,
  readCounterCount,
  signOwnership,
} from "../src/index.js";
import { DEMO_CONFIG } from "./config.js";

/**
 * Browser demo of the full Tier 2 unlinkable deploy flow.
 *
 * Steps:
 *   1. Connect MetaMask                          → `eth_requestAccounts`
 *   2. Derive session key                        → personal_sign + keccak + secp256k1
 *   3. Compute deterministic Starknet account    → mirror Cairo derivation
 *   4. Sign ownership                            → secp256k1 over OWNERSHIP_TRANSFER_MSG_HASH
 *   5. Deploy via Alice + privacy pool + paymaster (sponsored_private)
 *      — Alice pays the gas from her pool notes; nothing on chain references
 *        the user's MetaMask address.
 */

const els = {
  status: byId("status"),
  mmAddr: byId("mm-addr"),
  sessionAddr: byId("session-addr"),
  accountAddr: byId("account-addr"),
  ownershipSig: byId("ownership-sig"),
  sponsoredOutput: byId("sponsored-output"),
  sponsoredLog: byId("sponsored-log"),
  counterOutput: byId("counter-output"),
  counterLog: byId("counter-log"),
  counterValueBefore: byId("counter-value-before"),
  counterValueAfter: byId("counter-value-after"),
  connectBtn: byId("connect-btn") as HTMLButtonElement,
  deriveBtn: byId("derive-btn") as HTMLButtonElement,
  computeBtn: byId("compute-btn") as HTMLButtonElement,
  signBtn: byId("sign-btn") as HTMLButtonElement,
  sponsoredBtn: byId("sponsored-btn") as HTMLButtonElement,
  counterBtn: byId("counter-btn") as HTMLButtonElement,
  counterReadBtn: byId("counter-read-btn") as HTMLButtonElement,
  factoryInput: byId("factory-input") as HTMLInputElement,
  networkSelect: byId("network-select") as HTMLSelectElement,
  bootstrapMsg: byId("bootstrap-msg"),
};

function byId(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} not in DOM`);
  return el;
}

function status(msg: string, kind: "info" | "ok" | "err" = "info"): void {
  els.status.textContent = msg;
  els.status.className = `status status--${kind}`;
}

function ensureMm(): unknown {
  const eth = (globalThis as { ethereum?: unknown }).ethereum;
  if (!eth) throw new Error("MetaMask not detected. Install the extension and refresh.");
  return eth;
}

let signer: BrowserMmSigner | null = null;
let sessionKey: Awaited<ReturnType<typeof deriveSessionKey>> | null = null;
let accountAddrBigInt: bigint | null = null;
let lastDeploy:
  | Awaited<ReturnType<typeof privateSponsoredDeployTier2Account>>
  | null = null;

// Prefill factory address + bootstrap msg + counter address from config.
els.bootstrapMsg.textContent = BOOTSTRAP_MESSAGE;
els.factoryInput.value = DEMO_CONFIG.factoryAddress;
els.networkSelect.value = DEMO_CONFIG.network;
const counterAddrDisplay = document.getElementById("counter-addr-display");
if (counterAddrDisplay) counterAddrDisplay.textContent = DEMO_CONFIG.counterAddress;

els.connectBtn.addEventListener("click", async () => {
  try {
    status("Requesting accounts from MetaMask…");
    signer = new BrowserMmSigner(ensureMm());
    const addr = await signer.address();
    els.mmAddr.textContent = addr;
    els.deriveBtn.disabled = false;
    status(`Connected as ${addr}`, "ok");
  } catch (e) {
    status(errMsg(e), "err");
  }
});

els.deriveBtn.addEventListener("click", async () => {
  try {
    if (!signer) throw new Error("Connect MetaMask first");
    status(`Signing "${BOOTSTRAP_MESSAGE}" in MetaMask…`);
    sessionKey = await deriveSessionKey(signer);
    els.sessionAddr.textContent = sessionKey.ethAddress;
    els.computeBtn.disabled = false;
    els.signBtn.disabled = false;
    els.sponsoredBtn.disabled = false;
    status("Session key derived. NOTHING was broadcast — pure client crypto.", "ok");
  } catch (e) {
    status(errMsg(e), "err");
  }
});

els.computeBtn.addEventListener("click", () => {
  try {
    if (!sessionKey) throw new Error("Derive session key first");
    const factoryAddress = els.factoryInput.value.trim();
    if (!factoryAddress.startsWith("0x")) {
      throw new Error("Factory address must be 0x-prefixed hex");
    }
    const network =
      els.networkSelect.value === "test" ? ("test" as const) : ("prod" as const);
    const addr = computeAccountAddress({
      sessionEthAddress: sessionKey.ethAddress,
      factoryAddress: factoryAddress as `0x${string}`,
      network,
    });
    accountAddrBigInt = addr;
    els.accountAddr.textContent = "0x" + addr.toString(16).padStart(64, "0");
    status(
      `Account would be deployed at this address by factory ${factoryAddress}.`,
      "ok",
    );
  } catch (e) {
    status(errMsg(e), "err");
  }
});

els.signBtn.addEventListener("click", () => {
  try {
    if (!sessionKey) throw new Error("Derive session key first");
    const sig = signOwnership(sessionKey);
    const felts = encodeOwnershipSignature(sig).map((f) => "0x" + f.toString(16));
    els.ownershipSig.textContent = JSON.stringify(felts, null, 2);
    status(
      "Ownership signature ready. Pass these 5 felts as the `signature` field to factory.deploy_account.",
      "ok",
    );
  } catch (e) {
    status(errMsg(e), "err");
  }
});

els.sponsoredBtn.addEventListener("click", async () => {
  els.sponsoredBtn.disabled = true;
  try {
    if (!sessionKey) throw new Error("Derive session key first");
    appendLog("");
    appendLog("── Sponsored private deploy ─────────────────────────────");

    const provider = new RpcProvider({ nodeUrl: DEMO_CONFIG.starknetRpcUrl });
    const alice = new Account({
      provider,
      address: DEMO_CONFIG.alice.address,
      signer: DEMO_CONFIG.alice.privateKey,
      cairoVersion: "1",
    });
    appendLog(`alice account: ${DEMO_CONFIG.alice.address}`);

    const discovery = new IndexerDiscoveryProvider(
      DEMO_CONFIG.discoveryUrl,
      DEMO_CONFIG.poolAddress,
    );
    const provingProvider = new ProvingServiceProofProvider(
      DEMO_CONFIG.provingUrl,
      DEMO_CONFIG.starknetChainId as unknown as starknetConstants.StarknetChainId,
    );

    const viewingKey = BigInt(DEMO_CONFIG.alice.viewingKey);
    const transfers = createPrivateTransfers({
      account: alice,
      viewingKeyProvider: { getViewingKey: async () => viewingKey },
      provingProvider,
      discoveryProvider: discovery,
      poolContractAddress: DEMO_CONFIG.poolAddress,
    });

    const paymaster = new PaymasterClient(
      DEMO_CONFIG.paymasterUrl,
      DEMO_CONFIG.paymasterApiKey,
    );

    status("Building sponsored private deploy via Alice…");
    const result = await privateSponsoredDeployTier2Account(
      {
        starknetChainId: DEMO_CONFIG.starknetChainId,
        poolAddress: DEMO_CONFIG.poolAddress,
        poolFeeToken: DEMO_CONFIG.poolFeeToken,
        helperAddress: DEMO_CONFIG.helperAddress,
        factoryAddress: DEMO_CONFIG.factoryAddress,
        network: DEMO_CONFIG.network,
        paymasterApiKey: DEMO_CONFIG.paymasterApiKey,
        paymasterUrl: DEMO_CONFIG.paymasterUrl,
      },
      {
        alice,
        provider,
        transfers,
        paymaster,
        session: sessionKey,
        log: appendLog,
      },
    );
    lastDeploy = result;

    els.sponsoredOutput.textContent =
      `tx: ${result.transactionHash}\n` +
      `account: ${result.accountAddressHex}\n` +
      `class hash at account: ${result.classHashAtAddress}\n` +
      `fee paid by Alice: ${result.feePaidByAlice}`;
    status(
      `Deployed! Tier 2 account live at ${result.accountAddressHex}. MetaMask never paid gas, never signed a Starknet tx, and is not referenced on-chain.`,
      "ok",
    );
  } catch (e) {
    appendLog(`ERROR: ${errMsg(e)}`);
    status(errMsg(e), "err");
  } finally {
    els.sponsoredBtn.disabled = false;
  }
});

function appendLog(line: string): void {
  const ts = new Date().toISOString().slice(11, 23);
  els.sponsoredLog.textContent += `[${ts}] ${line}\n`;
  els.sponsoredLog.scrollTop = els.sponsoredLog.scrollHeight;
}

function appendCounterLog(line: string): void {
  const ts = new Date().toISOString().slice(11, 23);
  els.counterLog.textContent += `[${ts}] ${line}\n`;
  els.counterLog.scrollTop = els.counterLog.scrollHeight;
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

// ─── Step 6: Increment Counter via Tier 2 account ──────────────────────────

let lastIncrement: Awaited<
  ReturnType<typeof privateSponsoredExecuteOnTier2Account>
> | null = null;

els.counterReadBtn.addEventListener("click", async () => {
  try {
    const provider = new RpcProvider({ nodeUrl: DEMO_CONFIG.starknetRpcUrl });
    const count = await readCounterCount(provider, DEMO_CONFIG.counterAddress);
    els.counterValueBefore.textContent = count.toString();
    status(`Counter is currently at ${count}.`, "ok");
  } catch (e) {
    status(errMsg(e), "err");
  }
});

els.counterBtn.addEventListener("click", async () => {
  els.counterBtn.disabled = true;
  try {
    if (!sessionKey) throw new Error("Derive session key first (step 2)");
    if (!lastDeploy)
      throw new Error("Deploy the Tier 2 account first (step 5)");

    appendCounterLog("");
    appendCounterLog("── Sponsored private execute ────────────────────────");

    const provider = new RpcProvider({ nodeUrl: DEMO_CONFIG.starknetRpcUrl });
    const beforeCount = await readCounterCount(
      provider,
      DEMO_CONFIG.counterAddress,
    );
    els.counterValueBefore.textContent = beforeCount.toString();
    appendCounterLog(`counter before: ${beforeCount}`);

    const alice = new Account({
      provider,
      address: DEMO_CONFIG.alice.address,
      signer: DEMO_CONFIG.alice.privateKey,
      cairoVersion: "1",
    });
    const discovery = new IndexerDiscoveryProvider(
      DEMO_CONFIG.discoveryUrl,
      DEMO_CONFIG.poolAddress,
    );
    const provingProvider = new ProvingServiceProofProvider(
      DEMO_CONFIG.provingUrl,
      DEMO_CONFIG.starknetChainId as unknown as starknetConstants.StarknetChainId,
    );
    const viewingKey = BigInt(DEMO_CONFIG.alice.viewingKey);
    const transfers = createPrivateTransfers({
      account: alice,
      viewingKeyProvider: { getViewingKey: async () => viewingKey },
      provingProvider,
      discoveryProvider: discovery,
      poolContractAddress: DEMO_CONFIG.poolAddress,
    });
    const paymaster = new PaymasterClient(
      DEMO_CONFIG.paymasterUrl,
      DEMO_CONFIG.paymasterApiKey,
    );

    status("Building sponsored private Counter.increment…");
    const result = await privateSponsoredExecuteOnTier2Account(
      {
        starknetChainId: DEMO_CONFIG.starknetChainId,
        poolAddress: DEMO_CONFIG.poolAddress,
        poolFeeToken: DEMO_CONFIG.poolFeeToken,
        invokeHelperAddress: DEMO_CONFIG.invokeHelperAddress,
        paymasterApiKey: DEMO_CONFIG.paymasterApiKey,
        paymasterUrl: DEMO_CONFIG.paymasterUrl,
      },
      {
        alice,
        provider,
        transfers,
        paymaster,
        session: sessionKey,
        accountAddress: lastDeploy.accountAddressHex,
        calls: [counterIncrementCall(DEMO_CONFIG.counterAddress)],
        nonce: BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000)),
        log: appendCounterLog,
      },
    );
    lastIncrement = result;

    const afterCount = await readCounterCount(
      provider,
      DEMO_CONFIG.counterAddress,
    );
    els.counterValueAfter.textContent = afterCount.toString();
    appendCounterLog(`counter after: ${afterCount}`);

    els.counterOutput.textContent =
      `tx: ${result.transactionHash}\n` +
      `nonce used: ${result.outsideExecution.nonce}\n` +
      `fee paid by Alice: ${result.feePaidByAlice}\n` +
      `counter: ${beforeCount} → ${afterCount}`;
    status(
      `Counter incremented via Tier 2 account ${lastDeploy.accountAddressHex}. MetaMask never signed a Starknet tx; Alice's notes paid the gas.`,
      "ok",
    );
  } catch (e) {
    appendCounterLog(`ERROR: ${errMsg(e)}`);
    status(errMsg(e), "err");
  } finally {
    els.counterBtn.disabled = false;
  }
});

// Expose for console poking.
(globalThis as unknown as { tier2?: unknown }).tier2 = {
  get signer() { return signer; },
  get sessionKey() { return sessionKey; },
  get accountAddrBigInt() { return accountAddrBigInt; },
  get lastDeploy() { return lastDeploy; },
  get lastIncrement() { return lastIncrement; },
  PRIMER_CLASS_HASH,
  config: DEMO_CONFIG,
};
