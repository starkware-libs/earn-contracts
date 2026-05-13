/**
 * Tier 2 unlinkable account deploy via Alice + the AVNU sponsored_private flow.
 *
 * What this orchestrates (see `paymaster/examples/private-sponsored-web/src/flow.ts`
 * for the canonical recipe — we adapt the "private deploy a Counter" pattern
 * to "private deploy a Tier 2 account through EarnDeployHelper"):
 *
 *   1. Ask the AVNU paymaster for a fee quote (mode = sponsored_private).
 *      Server returns a fee_action: withdraw <fee_amount> of <pool_fee_token>
 *      to <forwarder>.
 *   2. Use the Privacy SDK builder to construct apply_actions containing:
 *        a. The fee withdraw to the AVNU forwarder (pays gas).
 *        b. An InvokeExternal targeting EarnDeployHelper.privacy_invoke with
 *           the user's session_eth_address + ownership signature + a placeholder
 *           note_id. The helper forwards to factory.deploy_account.
 *      Generate a ZK proof covering both actions in a single atomic tx.
 *   3. Submit (apply_actions_call + proof + proof_facts) to
 *      `paymaster_executeTransaction`. AVNU's relayer signs and submits the
 *      tx — Alice's address never appears as msg.sender. The new Tier 2
 *      account is deployed at the deterministic address derived from the
 *      session_eth_address; the MetaMask user's identity is never on chain.
 *
 * The "Alice" account in this module is the *pool sponsor* — she has notes
 * inside the privacy pool, she generates and signs the proof, and the
 * paymaster's `withdraw` to its forwarder is debited against her notes. She
 * does NOT touch the MM user's session key, and the MM user does NOT need
 * any Starknet balance to be deployed.
 */

import { hash, type Account, type RpcProvider } from "starknet";
import type {
  PrivateTransfersInterface,
} from "@starkware-libs/starknet-privacy-sdk";

import { computeAccountAddress, type Network } from "./address.js";
import { signOwnership } from "./sign.js";
import { PaymasterClient, toFelt0x } from "./paymaster.js";
import type { CairoSignature, Hex, SessionKey } from "./types.js";

/** Per-tx tuning. Mirrors the AVNU PoC defaults. */
const NOTE_MATURITY_BLOCKS = 10;

export interface SponsoredDeployConfig {
  /** Sepolia chain id ("0x534e5f5345504f4c4941"). */
  starknetChainId: bigint | Hex | string;
  /** Privacy pool contract address. */
  poolAddress: Hex | string;
  /** The token Alice's notes hold AND the token paymaster fees are paid in. */
  poolFeeToken: Hex | string;
  /** Deployed EarnDeployHelper address (calls factory.deploy_account). */
  helperAddress: Hex | string;
  /** Deployed AccountFactory address. Used only to predict the resulting
   *  Starknet account address client-side. */
  factoryAddress: Hex | string;
  /** "prod" → PRIMER_CLASS_HASH.prod, "test" → PRIMER_CLASS_HASH.test. */
  network?: Network;
  /** Optional paymaster API key (AVNU managed instance). */
  paymasterApiKey?: string;
  /** Optional custom paymaster URL (defaults to AVNU sepolia). */
  paymasterUrl?: string;
}

export interface SponsoredDeployArgs {
  /** Connected starknet.js account for Alice (the pool sponsor). */
  alice: Account;
  /** RpcProvider pointing at the chain Alice's account uses. */
  provider: RpcProvider;
  /** Initialized SDK builder (call createPrivateTransfers({...}) externally). */
  transfers: PrivateTransfersInterface;
  /** AVNU paymaster client. */
  paymaster: PaymasterClient;
  /** The Tier 2 user's session keypair (from deriveSessionKey). */
  session: SessionKey;
  /** Override: provide a pre-built ownership signature. Defaults to signing
   *  with `session` here. */
  ownershipSignature?: CairoSignature;
  /** Optional one-line progress logger (browser demo uses this). */
  log?: (line: string) => void;
}

export interface SponsoredDeployResult {
  /** The Starknet account address that was just deployed. */
  accountAddress: bigint;
  /** Hex form of the same address (0x-prefixed, padded). */
  accountAddressHex: string;
  /** Paymaster's transaction hash for the deploy. */
  transactionHash: string;
  /** Class hash now sitting at the deployed address. */
  classHashAtAddress: string;
  /** Privacy-pool fee that Alice paid. */
  feePaidByAlice: bigint;
}

/**
 * Encode `EarnDeployHelper.privacy_invoke` calldata.
 *
 * Cairo signature:
 *   fn privacy_invoke(
 *     session_eth_address: EthAddress,
 *     signature: Signature,        -- u256 r, u256 s, bool y_parity
 *     note_id: felt252,
 *   )
 *
 * Cairo Serde for u256 is `[low_felt, high_felt]`. Signature serializes as
 * `[r.low, r.high, s.low, s.high, y_parity ? 1 : 0]` → 5 felts. So the full
 * calldata is 7 felts.
 */
export function encodePrivacyInvokeCalldata(args: {
  sessionEthAddress: bigint | Hex | string;
  signature: CairoSignature;
  noteId?: bigint;
}): string[] {
  const session =
    typeof args.sessionEthAddress === "bigint"
      ? args.sessionEthAddress
      : BigInt(args.sessionEthAddress);
  const { r, s, yParity } = args.signature;
  const noteId = args.noteId ?? 0n;
  const MASK_128 = (1n << 128n) - 1n;
  return [
    "0x" + session.toString(16),
    "0x" + (r & MASK_128).toString(16),
    "0x" + (r >> 128n).toString(16),
    "0x" + (s & MASK_128).toString(16),
    "0x" + (s >> 128n).toString(16),
    yParity ? "0x1" : "0x0",
    "0x" + noteId.toString(16),
  ];
}

/**
 * Run the full private sponsored deploy for one MetaMask-derived session key.
 */
export async function privateSponsoredDeployTier2Account(
  cfg: SponsoredDeployConfig,
  args: SponsoredDeployArgs,
): Promise<SponsoredDeployResult> {
  const log = args.log ?? (() => {});

  // Predict the Starknet account address before we touch the chain so we can
  // verify the deploy landed where it should.
  const accountAddress = computeAccountAddress({
    sessionEthAddress: args.session.ethAddress,
    factoryAddress: cfg.factoryAddress as Hex,
    network: cfg.network ?? "prod",
  });
  const accountAddressHex =
    "0x" + accountAddress.toString(16).padStart(64, "0");
  log(`expected Tier 2 account address: ${accountAddressHex}`);

  // 1. Fee quote.
  log("requesting paymaster fee quote (sponsored_private)…");
  const build = await args.paymaster.buildApplyAction(
    String(cfg.poolAddress),
    String(cfg.poolFeeToken),
  );
  const feeAmount = BigInt(build.fee_action.amount);
  const forwarder = build.fee_action.recipient;
  log(`  fee=${feeAmount} of ${build.fee_action.token}, forwarder=${forwarder}`);

  // 2. Build apply_actions: fee withdraw + invoke EarnDeployHelper.privacy_invoke.
  const ownership =
    args.ownershipSignature ?? signOwnership(args.session);
  const invokeCalldata = encodePrivacyInvokeCalldata({
    sessionEthAddress: args.session.ethAddress,
    signature: ownership,
    noteId: 0n,
  });
  log(
    `invoke calldata: helper=${cfg.helperAddress} session=${args.session.ethAddress}`,
  );

  const provingBlockId =
    (await args.provider.getBlockNumber()) - NOTE_MATURITY_BLOCKS;
  log(`generating proof against block ${provingBlockId}…`);

  const aliceAddress = (args.alice as unknown as { address: string }).address;
  const { callAndProof } = await args.transfers
    .build({
      autoSetup: true,
      autoDiscover: { notes: "refresh", channels: "refresh" },
      autoSelectNotes: "all",
    })
    .surplusTo(aliceAddress)
    .with(String(cfg.poolFeeToken), (t) => {
      t.withdraw({ recipient: forwarder, amount: feeAmount });
    })
    .invoke(() => ({
      contractAddress: String(cfg.helperAddress),
      entrypoint: "privacy_invoke",
      calldata: invokeCalldata,
    }))
    .execute({ provingBlockId });
  log(
    `proof generated (${callAndProof.proof.proofFacts?.length ?? 0} facts)`,
  );

  // 3. Submit via paymaster.
  log("paymaster_executeTransaction…");
  const result = await args.paymaster.executeApplyAction(
    callAndProof.call,
    callAndProof.proof.data ?? "",
    (callAndProof.proof.proofFacts ?? []).map((x) => toFelt0x(x)),
    build.parameters,
  );
  log(`  submitted: ${result.transaction_hash}`);
  await args.provider.waitForTransaction(result.transaction_hash);
  log(`  confirmed`);

  // 4. Verify the deploy actually landed.
  let classHashAtAddress = "0x0";
  try {
    classHashAtAddress = await args.provider.getClassHashAt(accountAddressHex);
  } catch (e) {
    log(
      `WARN: getClassHashAt(${accountAddressHex}) failed: ${
        (e as Error).message
      }`,
    );
  }
  log(`account class at deployed address: ${classHashAtAddress}`);

  return {
    accountAddress,
    accountAddressHex,
    transactionHash: result.transaction_hash,
    classHashAtAddress,
    feePaidByAlice: feeAmount,
  };
}

/**
 * Cheap selector check — handy for sanity logging.
 */
export function privacyInvokeSelector(): string {
  return hash.getSelectorFromName("privacy_invoke");
}
