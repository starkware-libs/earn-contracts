/**
 * Declare + deploy the Tier 2 stack to Starknet Sepolia:
 *
 *   1. Declare Primer                       (account_factory factory step 1)
 *   2. Declare StarknetEth712Account        (the upgrade target the Primer becomes)
 *   3. Declare AccountFactory               (factory bytecode)
 *   4. Declare EarnDeployHelper             (privacy_invoke shim)
 *   5. Declare Counter                      (demo target — instances created later)
 *   6. Deploy AccountFactory(governance_admin=ADMIN, upgrade_delay=0,
 *                            account_class_hash=StarknetEth712Account class)
 *   7. Deploy EarnDeployHelper(privacy_pool=PRIVACY_POOL, account_factory=factory_addr)
 *
 * The script is idempotent: it skips declarations / deployments that already
 * exist on chain. Run it as many times as needed while iterating.
 *
 * Output: sepolia-deployments.json with every address + class hash. The
 * script also rewrites tier2_wallet/.env's FACTORY_ADDRESS / HELPER_ADDRESS
 * / COUNTER_CLASS_HASH / STARKNET_ETH712_ACCOUNT_CLASS_HASH lines so the
 * runtime picks them up without you editing by hand.
 *
 * Private keys: NEVER printed to stdout. Reads only from .env via dotenv.
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

async function deployContract(
  provider: RpcProvider,
  account: Account,
  name: string,
  udcAddress: string,
  classHash: string,
  constructorCalldata: string[],
): Promise<string> {
  // unique=false → deterministic on (deployer, salt, classHash, calldata).
  // Salt is the current millisecond so repeated runs produce a new address;
  // we don't try to be idempotent at the address level here (the deploy step
  // is cheap once classes are declared).
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
  // RPC returns from_address without leading zero ("0x41a78…"), our env has
  // the full padded form ("0x041a78…"). Compare as bigints to ignore that.
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

/** Persist deployment addresses to disk + back into .env so callers pick them up. */
function persistAddresses(addresses: Record<string, string>) {
  const outPath = resolve(__dirname, "../sepolia-deployments.json");
  writeFileSync(outPath, JSON.stringify(addresses, null, 2) + "\n");
  console.log(`\n✓ Wrote ${outPath}`);

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
  console.log(`✓ Updated ${envPath} with deployed addresses`);
}

async function main() {
  const rpcUrl = required("STARKNET_RPC_URL");
  const adminAddress = required("STARKNET_ADMIN_ADDRESS");
  const adminPriv = required("STARKNET_ADMIN_PRIVATE_KEY");
  const udcAddress = required("UDC_ADDRESS");
  const privacyPool = required("PRIVACY_POOL_ADDRESS");

  // The Primer class hash is baked into account_factory/src/utils.cairo. If
  // our local build doesn't produce that hash, the factory will not be able
  // to deploy_syscall the Primer on chain → abort early with a clear error.
  const EXPECTED_PRIMER =
    "0x03edae2158f4aea6295470678fc7de27e19d7e40f295cda90d786d17b3531fdf";

  const provider = new RpcProvider({ nodeUrl: rpcUrl });
  const chainId = await provider.getChainId();
  console.log(`Chain: ${chainId}`);
  console.log(`Admin: ${adminAddress}\n`);

  const account = new Account({
    provider,
    address: adminAddress,
    signer: adminPriv,
    cairoVersion: "1",
  });

  console.log("── Declaring classes ──────────────────────────────────────");
  const primerHash = await declareClass(provider, account, "Primer", "contracts_Primer");
  if (BigInt(primerHash) !== BigInt(EXPECTED_PRIMER)) {
    console.error(
      `\n✗ Primer class hash drift!\n  expected: ${EXPECTED_PRIMER}\n  got:      ${primerHash}\n` +
        `  Update account_factory/src/utils.cairo::PRIMER_CLASS_HASH AND\n` +
        `  tier2_wallet/src/constants.ts::PRIMER_CLASS_HASH.prod to the new value,\n` +
        `  then rebuild and re-run.`,
    );
    process.exit(1);
  }
  const accountClass = await declareClass(
    provider,
    account,
    "StarknetEth712Account",
    "eth_712_account_StarknetEth712Account",
  );
  const factoryClass = await declareClass(
    provider,
    account,
    "AccountFactory",
    "account_factory_AccountFactory",
  );
  const helperClass = await declareClass(
    provider,
    account,
    "EarnDeployHelper",
    "helpers_EarnDeployHelper",
  );
  const counterClass = await declareClass(provider, account, "Counter", "counter_Counter");

  console.log("\n── Deploying singletons ───────────────────────────────────");
  // AccountFactory(governance_admin: ContractAddress, upgrade_delay: u64, account_class_hash: ClassHash)
  const factoryAddr = await deployContract(
    provider,
    account,
    "AccountFactory",
    udcAddress,
    factoryClass,
    [adminAddress, "0", accountClass],
  );

  // EarnDeployHelper(privacy_pool: ContractAddress, account_factory: ContractAddress)
  const helperAddr = await deployContract(
    provider,
    account,
    "EarnDeployHelper",
    udcAddress,
    helperClass,
    [privacyPool, factoryAddr],
  );

  persistAddresses({
    PRIMER_CLASS_HASH: primerHash,
    STARKNET_ETH712_ACCOUNT_CLASS_HASH: accountClass,
    FACTORY_CLASS_HASH: factoryClass,
    HELPER_CLASS_HASH: helperClass,
    COUNTER_CLASS_HASH: counterClass,
    FACTORY_ADDRESS: factoryAddr,
    HELPER_ADDRESS: helperAddr,
  });

  console.log("\n✓ All deployments complete.");
}

main().catch((e) => {
  console.error("\n✗ deploy-contracts failed:", e instanceof Error ? e.message : String(e));
  if (e instanceof Error && e.stack) console.error(e.stack);
  process.exit(1);
});
