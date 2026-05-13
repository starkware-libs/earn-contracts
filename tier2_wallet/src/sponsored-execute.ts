/**
 * Tier 2 Counter call via Alice + the AVNU sponsored_private flow.
 *
 * Sibling of sponsored-deploy.ts. Where the deploy invokes EarnDeployHelper
 * (which calls factory.deploy_account), this flow invokes EarnInvokeHelper
 * (which calls target_account.execute_from_outside_v2). The signature
 * verified by the Tier 2 account is the session key's EIP-712 signature over
 * the OutsideExecution — not anything MetaMask produced directly.
 *
 *   relayer tx                              (signed by AVNU, NOT the user)
 *   └─ forwarder.execute_private_sponsored
 *      └─ pool.apply_actions
 *         ├─ withdraw(fee_token, recipient=forwarder)        (Alice's gas)
 *         └─ InvokeExternal → EarnInvokeHelper.privacy_invoke(
 *               target_account=tier2_account_addr,
 *               outside_execution=<ANY_CALLER, nonce, …, calls=[counter.increment]>,
 *               signature=<6 felts signed by session_key>,
 *               note_id=0,
 *            )
 *            └─ tier2_account.execute_from_outside_v2(...)
 *               └─ counter.increment()
 */

import type { Account, RpcProvider } from "starknet";
import { hash } from "starknet";
import type { PrivateTransfersInterface } from "@starkware-libs/starknet-privacy-sdk";

import { ANY_CALLER } from "./constants.js";
import { signOutsideExecution } from "./sign.js";
import { PaymasterClient, toFelt0x } from "./paymaster.js";
import type {
  Call,
  Hex,
  OutsideExecution,
  OutsideExecutionDomain,
  SessionKey,
} from "./types.js";

export interface SponsoredExecuteConfig {
  starknetChainId: bigint | Hex | string;
  poolAddress: Hex | string;
  poolFeeToken: Hex | string;
  /** Deployed EarnInvokeHelper address. */
  invokeHelperAddress: Hex | string;
  paymasterApiKey?: string;
  paymasterUrl?: string;
}

export interface SponsoredExecuteArgs {
  alice: Account;
  provider: RpcProvider;
  transfers: PrivateTransfersInterface;
  paymaster: PaymasterClient;
  /** The Tier 2 user's session keypair. */
  session: SessionKey;
  /** The deployed Tier 2 account address (returned from sponsored-deploy). */
  accountAddress: Hex | string;
  /** Inner calls the account should execute (e.g. one Counter.increment). */
  calls: Call[];
  /** Unique-per-account nonce. Tip: use Date.now() converted to bigint. */
  nonce: bigint;
  /** Optional sliding window for the OutsideExecution. Defaults to ~10 minutes. */
  executeAfter?: bigint;
  executeBefore?: bigint;
  log?: (line: string) => void;
}

export interface SponsoredExecuteResult {
  transactionHash: string;
  feePaidByAlice: bigint;
  outsideExecution: OutsideExecution;
}

const NOTE_MATURITY_BLOCKS = 10;

/**
 * Run one Tier 2 outside-execution sponsored privately by Alice.
 */
export async function privateSponsoredExecuteOnTier2Account(
  cfg: SponsoredExecuteConfig,
  args: SponsoredExecuteArgs,
): Promise<SponsoredExecuteResult> {
  const log = args.log ?? (() => {});

  // 1. Build the OutsideExecution payload + session-key signature.
  const nowSec = BigInt(Math.floor(Date.now() / 1000));
  const ose: OutsideExecution = {
    caller: ANY_CALLER,
    nonce: args.nonce,
    executeAfter: args.executeAfter ?? nowSec - 60n,
    executeBefore: args.executeBefore ?? nowSec + 600n,
    calls: args.calls,
  };
  const domain: OutsideExecutionDomain = {
    accountAddress: BigInt(args.accountAddress as Hex),
    evmChainId: 1n, // The EIP-712 domain's `chainId` field. Cairo doesn't care; we keep "1" for parity with the Python reference.
    starknetChainId:
      typeof cfg.starknetChainId === "bigint"
        ? cfg.starknetChainId
        : BigInt(cfg.starknetChainId),
  };
  const sig = signOutsideExecution({
    session: args.session,
    outsideExecution: ose,
    domain,
  });
  log(`signed OutsideExecution nonce=${args.nonce} calls=${args.calls.length}`);

  // 2. Quote the paymaster fee.
  log("requesting paymaster fee quote (sponsored_private)…");
  const build = await args.paymaster.buildApplyAction(
    String(cfg.poolAddress),
    String(cfg.poolFeeToken),
  );
  const feeAmount = BigInt(build.fee_action.amount);
  const forwarder = build.fee_action.recipient;
  log(`  fee=${feeAmount} of ${build.fee_action.token}, forwarder=${forwarder}`);

  // 3. Build the EarnInvokeHelper.privacy_invoke calldata. Cairo signature:
  //      privacy_invoke(
  //        target_account: ContractAddress,
  //        outside_execution: OutsideExecution,
  //        signature: Array<felt252>,
  //        note_id: felt252,
  //      )
  //    Order of serialized felts:
  //      target_account
  //      caller, nonce, execute_after, execute_before
  //      calls.len(), [for each call: to, selector, calldata.len(), ...calldata]
  //      signature.len(), ...signature
  //      note_id
  const calldata: string[] = [];
  calldata.push("0x" + BigInt(args.accountAddress as Hex).toString(16));
  calldata.push("0x" + ose.caller.toString(16));
  calldata.push("0x" + ose.nonce.toString(16));
  calldata.push("0x" + ose.executeAfter.toString(16));
  calldata.push("0x" + ose.executeBefore.toString(16));
  calldata.push("0x" + BigInt(ose.calls.length).toString(16));
  for (const c of ose.calls) {
    calldata.push("0x" + c.to.toString(16));
    calldata.push("0x" + c.selector.toString(16));
    calldata.push("0x" + BigInt(c.calldata.length).toString(16));
    for (const d of c.calldata) calldata.push("0x" + d.toString(16));
  }
  calldata.push("0x" + BigInt(sig.length).toString(16));
  for (const f of sig) calldata.push("0x" + f.toString(16));
  calldata.push("0x0"); // note_id

  log(`invoke helper=${cfg.invokeHelperAddress} target=${args.accountAddress}`);

  // 4. Generate proof.
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
      contractAddress: String(cfg.invokeHelperAddress),
      entrypoint: "privacy_invoke",
      calldata,
    }))
    .execute({ provingBlockId });
  log(
    `proof generated (${callAndProof.proof.proofFacts?.length ?? 0} facts)`,
  );

  // 5. Submit via paymaster.
  log("paymaster_executeTransaction…");
  const result = await args.paymaster.executeApplyAction(
    callAndProof.call,
    callAndProof.proof.data ?? "",
    (callAndProof.proof.proofFacts ?? []).map((x) => toFelt0x(x)),
    build.parameters,
  );
  log(`  submitted: ${result.transaction_hash}`);
  await args.provider.waitForTransaction(result.transaction_hash);
  log("  confirmed");

  return {
    transactionHash: result.transaction_hash,
    feePaidByAlice: feeAmount,
    outsideExecution: ose,
  };
}

/** Helper: build a Call for Counter.increment(). */
export function counterIncrementCall(counterAddress: Hex | string): Call {
  return {
    to: BigInt(counterAddress as Hex),
    selector: BigInt(hash.getSelectorFromName("increment")),
    calldata: [],
  };
}

/** Helper: read Counter.get_count() — view-only, no tx. */
export async function readCounterCount(
  provider: RpcProvider,
  counterAddress: Hex | string,
): Promise<bigint> {
  const out = await provider.callContract({
    contractAddress: String(counterAddress),
    entrypoint: "get_count",
    calldata: [],
  });
  return BigInt(out[0]);
}
