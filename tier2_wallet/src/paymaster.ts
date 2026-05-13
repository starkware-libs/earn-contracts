/**
 * AVNU paymaster JSON-RPC client (sponsored_private flow only).
 *
 * Vendored from `paymaster/examples/private-sponsored-web/src/paymaster.ts`
 * with light edits — the original is published under AGPLv3.
 *
 * Two RPCs we use:
 *   - `paymaster_buildTransaction`  → fee quote + forwarder address
 *   - `paymaster_executeTransaction` → submit the proof + apply_actions call
 *
 * `sponsored_private` mode means the user pays the paymaster's fee from
 * inside their own pool notes (the SDK bundles a `withdraw` action targeting
 * the forwarder into the same proof). Nothing leaves the user's funded
 * Starknet wallet — Alice's identity stays inside the pool.
 */

import { hash, type Call } from "starknet";

export type PaymasterCall = {
  to: string;
  selector: string;
  calldata: string[];
};

export type ApplyActionBuildRequest = {
  transaction: {
    type: "apply_action";
    apply_action: { pool_address: string };
  };
  parameters: {
    version: "0x1";
    fee_mode: {
      mode: "sponsored_private";
      pool_fee_token: string;
      tip?: "slow" | "normal" | "fast";
    };
    time_bounds?: { execute_after: number; execute_before: number };
  };
};

export type FeeEstimate = {
  gas_token_price_in_strk: string;
  estimated_fee_in_strk: string;
  estimated_fee_in_gas_token: string;
  suggested_max_fee_in_strk: string;
  suggested_max_fee_in_gas_token: string;
};

export type FeeAction = {
  type: "withdraw";
  recipient: string;
  token: string;
  amount: string;
};

export type ApplyActionBuildResponse = {
  type: "apply_action";
  parameters: ApplyActionBuildRequest["parameters"];
  fee: FeeEstimate;
  fee_action: FeeAction;
};

export type ApplyActionExecuteRequest = {
  transaction: {
    type: "apply_action";
    apply_action: {
      apply_actions_call: PaymasterCall;
      proof: string;
      proof_facts: string[];
    };
  };
  parameters: ApplyActionBuildRequest["parameters"];
};

export type ExecuteResponse = {
  transaction_hash: string;
  tracking_id: string;
};

export class PaymasterClient {
  constructor(
    private readonly url: string,
    private readonly apiKey: string = "",
  ) {}

  async buildApplyAction(
    poolAddress: string,
    poolFeeToken: string,
  ): Promise<ApplyActionBuildResponse> {
    const params: ApplyActionBuildRequest = {
      transaction: { type: "apply_action", apply_action: { pool_address: poolAddress } },
      parameters: {
        version: "0x1",
        fee_mode: { mode: "sponsored_private", pool_fee_token: poolFeeToken, tip: "normal" },
      },
    };
    return this.rpc("paymaster_buildTransaction", params);
  }

  async executeApplyAction(
    applyActionsCall: Call | PaymasterCall,
    proof: string,
    proofFacts: string[],
    parameters: ApplyActionBuildRequest["parameters"],
  ): Promise<ExecuteResponse> {
    const params: ApplyActionExecuteRequest = {
      transaction: {
        type: "apply_action",
        apply_action: {
          apply_actions_call: normalizeCall(applyActionsCall),
          proof,
          proof_facts: proofFacts,
        },
      },
      parameters,
    };
    return this.rpc("paymaster_executeTransaction", params);
  }

  private async rpc<T>(method: string, params: unknown): Promise<T> {
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.apiKey) headers["x-paymaster-api-key"] = this.apiKey;
    const response = await fetch(this.url, { method: "POST", headers, body });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Paymaster HTTP ${response.status}: ${text}`);
    }
    const json = (await response.json()) as
      | { result: T }
      | { error: { code: number; message: string; data?: unknown } };
    if ("error" in json) {
      throw new Error(
        `Paymaster ${method} error (${json.error.code}): ${json.error.message}${
          json.error.data ? ` :: ${JSON.stringify(json.error.data)}` : ""
        }`,
      );
    }
    return json.result;
  }
}

/**
 * The Rust paymaster server deserializes Felts with serde_with `UfeHex`, which
 * requires `0x`-prefixed hex strings. starknet.js's BigNumberish often comes
 * through as a decimal string; normalize everything to hex.
 */
export function toFelt0x(value: unknown): string {
  if (typeof value === "bigint") return "0x" + value.toString(16);
  if (typeof value === "number") return "0x" + value.toString(16);
  if (typeof value === "string") {
    if (value.startsWith("0x") || value.startsWith("0X")) return value;
    if (/^[0-9]+$/.test(value)) return "0x" + BigInt(value).toString(16);
    return "0x" + BigInt(value).toString(16);
  }
  throw new Error(`Cannot convert ${typeof value} to felt: ${String(value)}`);
}

/**
 * starknet.js exposes Call as `{ contractAddress, entrypoint, calldata }`
 * but the paymaster RPC uses `{ to, selector, calldata }`. The Privacy SDK
 * returns the latter shape, but we accept both defensively.
 */
function normalizeCall(call: Call | PaymasterCall): PaymasterCall {
  const anyCall = call as Record<string, unknown>;
  const to = (anyCall.to ?? anyCall.contractAddress ?? anyCall.contract_address) as string;
  const selectorRaw = (anyCall.selector ?? anyCall.entry_point_selector ?? anyCall.entrypoint) as string;
  const selectorIsHex =
    /^0x[0-9a-fA-F]+$/.test(selectorRaw) || /^[0-9]+$/.test(selectorRaw);
  const selector = selectorIsHex
    ? toFelt0x(selectorRaw)
    : hash.getSelectorFromName(selectorRaw);
  const calldata = ((anyCall.calldata ?? []) as unknown[]).map((x) => toFelt0x(x));
  return { to: toFelt0x(to), selector, calldata };
}
