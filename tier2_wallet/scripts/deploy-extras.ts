/**
 * Phase F deploy: declare + deploy the *runtime* artifacts that go on top of
 * the core Tier 2 stack:
 *
 *   - Declare EarnInvokeHelper class                (idempotent)
 *   - Deploy a single EarnInvokeHelper instance     bound to the privacy pool
 *   - Deploy a single Counter instance              (Counter class declared
 *                                                    in deploy-contracts.ts)
 *
 * Output: appends to sepolia-deployments.json and patches .env with
 * INVOKE_HELPER_ADDRESS + COUNTER_ADDRESS so the runtime picks them up.
 *
 * Re-runnable. Each invocation creates a NEW Counter+helper pair (we don't
 * try to be idempotent at the address level here — Counter is cheap; if
 * you want a stable address, comment out the deploy and reuse what's in
 * .env / sepolia-deployments.json).
 */
import "dotenv/config";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Account,
  CallData,
  RpcProvider,
  hash,
  type CompiledSierra,
  type CompiledSierraCasm,
} from "starknet";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = resolve(__dirname, "../..");

function required(name: string): string {
  const v = process.env[name];
  if (!v) {
    console.error(`✗ Missing env var: ${name}. Set it in tier2_wallet/.env`);
    process.exit(1);
  }
  return v;
}

function readClass(relPath: string): { sierra: CompiledSierra; casm: CompiledSierraCasm } {
  const sierraPath = resolve(WORKSPACE_ROOT, `target/release/${relPath}.contract_class.json`);
  const casmPath = resolve(
    WORKSPACE_ROOT,
    `target/release/${relPath}.compiled_contract_class.json`,
  );
  if (!existsSync(sierraPath) || !existsSync(casmPath)) {
    console.error(
      `✗ Missing build artifact: ${relPath}. Run \`SCARB_PROFILE=release scarb build\` from the workspace root first.`,
    );
    process.exit(1);
  }
  return {
    sierra: JSON.parse(readFileSync(sierraPath, "utf8")) as CompiledSierra,
    casm: JSON.parse(readFileSync(casmPath, "utf8")) as CompiledSierraCasm,
  };
}

async function isDeclared(provider: RpcProvider, classHash: string): Promise<boolean> {
  try {
    await provider.getClassByHash(classHash);
    return true;
  } catch {
    return false;
  }
}

async function declareClass(
  provider: RpcProvider,
  account: Account,
  name: string,
  relPath: string,
): Promise<string> {
  const { sierra, casm } = readClass(relPath);
  const classHash = hash.computeContractClassHash(sierra);
  const compiledClassHash = hash.computeCompiledClassHash(casm);

  if (await isDeclared(provider, classHash)) {
    console.log(`  ✓ ${name.padEnd(28)} class ${classHash}  (already declared)`);
    return classHash;
  }

  console.log(`  → declaring ${name} class ${classHash}…`);
  const declared = await account.declareIfNot({
    contract: sierra,
    casm,
    classHash,
    compiledClassHash,
  });
  if (declared.transaction_hash) {
    console.log(`    tx: ${declared.transaction_hash}`);
    await provider.waitForTransaction(declared.transaction_hash);
  }
  console.log(`  ✓ ${name.padEnd(28)} declared`);
  return classHash;
}

async function deployViaUDC(
  provider: RpcProvider,
  account: Account,
  name: string,
  udcAddress: string,
  classHash: string,
  constructorCalldata: string[],
): Promise<string> {
  const salt = "0x" + BigInt(Date.now()).toString(16);
  const calldata = CallData.compile([
    classHash,
    salt,
    "0",
    constructorCalldata.length.toString(),
    ...constructorCalldata,
  ]);

  console.log(`  → deploying ${name} via UDC (salt ${salt})…`);
  const tx = await account.execute({
    contractAddress: udcAddress,
    entrypoint: "deployContract",
    calldata,
  });
  console.log(`    tx: ${tx.transaction_hash}`);
  const receipt = (await provider.waitForTransaction(tx.transaction_hash)) as unknown as {
    events?: { from_address?: string; data?: string[] }[];
  };
  const udcBig = BigInt(udcAddress);
  const udcEvent = (receipt.events ?? []).find(
    (e) =>
      e.from_address != null &&
      BigInt(e.from_address) === udcBig &&
      (e.data?.length ?? 0) >= 1,
  );
  const addr = udcEvent?.data?.[0];
  if (!addr) {
    console.error("✗ UDC deploy event missing — could not extract deployed address.");
    console.error(JSON.stringify(receipt, null, 2));
    process.exit(1);
  }
  console.log(`  ✓ ${name.padEnd(28)} deployed at ${addr}`);
  return addr;
}

function persistAddresses(addresses: Record<string, string>) {
  const jsonPath = resolve(__dirname, "../sepolia-deployments.json");
  let existing: Record<string, string> = {};
  if (existsSync(jsonPath)) {
    existing = JSON.parse(readFileSync(jsonPath, "utf8"));
  }
  const merged = { ...existing, ...addresses };
  writeFileSync(jsonPath, JSON.stringify(merged, null, 2) + "\n");
  console.log(`\n✓ Updated ${jsonPath}`);

  const envPath = resolve(__dirname, "../.env");
  if (!existsSync(envPath)) {
    console.log("(.env not found — skipping env rewrite; copy values from the JSON above)");
    return;
  }
  let env = readFileSync(envPath, "utf8");
  for (const [key, value] of Object.entries(addresses)) {
    const re = new RegExp(`^${key}=.*$`, "m");
    if (re.test(env)) {
      env = env.replace(re, `${key}=${value}`);
    } else {
      env += `\n${key}=${value}`;
    }
  }
  writeFileSync(envPath, env);
  console.log(`✓ Updated ${envPath}`);
}

async function main() {
  const rpcUrl = required("STARKNET_RPC_URL");
  const adminAddress = required("STARKNET_ADMIN_ADDRESS");
  const adminPriv = required("STARKNET_ADMIN_PRIVATE_KEY");
  const udcAddress = required("UDC_ADDRESS");
  const privacyPool = required("PRIVACY_POOL_ADDRESS");

  const provider = new RpcProvider({ nodeUrl: rpcUrl });
  console.log(`Chain: ${await provider.getChainId()}`);
  console.log(`Admin: ${adminAddress}\n`);

  const account = new Account({
    provider,
    address: adminAddress,
    signer: adminPriv,
    cairoVersion: "1",
  });

  console.log("── Declaring classes ──────────────────────────────────────");
  // Counter was already declared by deploy-contracts.ts; we just need its
  // class hash here. EarnInvokeHelper is new in Phase F.
  const counterClass = await declareClass(provider, account, "Counter", "counter_Counter");
  const invokeHelperClass = await declareClass(
    provider,
    account,
    "EarnInvokeHelper",
    "helpers_EarnInvokeHelper",
  );

  console.log("\n── Deploying singletons ───────────────────────────────────");
  // Counter has no constructor args.
  const counterAddr = await deployViaUDC(
    provider,
    account,
    "Counter",
    udcAddress,
    counterClass,
    [],
  );
  // EarnInvokeHelper(privacy_pool).
  const invokeHelperAddr = await deployViaUDC(
    provider,
    account,
    "EarnInvokeHelper",
    udcAddress,
    invokeHelperClass,
    [privacyPool],
  );

  persistAddresses({
    COUNTER_CLASS_HASH: counterClass,
    INVOKE_HELPER_CLASS_HASH: invokeHelperClass,
    COUNTER_ADDRESS: counterAddr,
    INVOKE_HELPER_ADDRESS: invokeHelperAddr,
  });

  console.log("\n✓ Phase F deploys complete.");
}

main().catch((e) => {
  console.error("\n✗ deploy-extras failed:", e instanceof Error ? e.message : String(e));
  if (e instanceof Error && e.stack) console.error(e.stack);
  process.exit(1);
});
