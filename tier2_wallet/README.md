# tier2_wallet

Client primitives for the Tier 2 unlinkable Starknet account flow. Pure
client-side cryptography — no Starknet RPCs, no paymaster, no privacy pool.
Everything in this package is composable building blocks the higher-level
demo / wallet code will assemble.

```
MetaMask wallet  ─── personal_sign(BOOTSTRAP_MESSAGE) ───►  this lib
                                                              │
                                                              ▼
                                                    secp256k1 session key
                                                    (independent of MM)
                                                              │
                                            ┌─────────────────┼──────────────────┐
                                            ▼                 ▼                  ▼
                                computeAccountAddress   signOwnership      signOutsideExecution
                                (Starknet addr)         (deploy_account)   (execute_from_outside_v2)
```

## Public API

```ts
import {
  deriveSessionKey,          // MmSigner → SessionKey  (deterministic)
  sessionKeyFromPriv,        // raw priv → SessionKey  (tests only)
  computeAccountAddress,     // session addr + factory → deterministic Starknet addr
  signOwnership,             // SessionKey → { r, s, yParity } for factory.deploy_account
  encodeOwnershipSignature,  // → 5 felts in the order Cairo Serde expects
  signOutsideExecution,      // OutsideExecution → 6 felts for execute_from_outside_v2
  computeOutsideExecutionHash, // EIP-712 digest, useful for cross-checks
  BrowserMmSigner,           // window.ethereum adapter
  FixedKeyMmSigner,          // test-only signer with a fixed private key
} from "tier2-wallet";
```

## Tests

```bash
npm install
npm run test
```

20 tests including 4 byte-identical parity checks against
`eth_712_account/scripts/generate_test_signatures.py`. If those fail, the
on-chain `is_valid_signature` check will reject the wallet — they are the
contract.

## Browser demo

```bash
npm install
npm run demo                    # bundles + serves on http://localhost:8088
# or step by step:
npm run demo:bundle             # esbuild → demo/dist/demo.js
npm run demo:serve              # python3 -m http.server 8088
```

Open the URL in a browser with MetaMask installed. The page:

1. Connects MetaMask (`eth_requestAccounts`).
2. Asks MM to `personal_sign` the fixed bootstrap message.
3. Derives the session key, shows its ETH-format address.
4. Computes the deterministic Starknet account address for a configurable
   factory.
5. Produces the ownership signature felts to pass to `deploy_account`.

Nothing is broadcast on-chain in the demo. The next milestone wires this
into the AVNU paymaster + `starknet-privacy-sdk` to actually deploy.

## Security notes

- **The session key is reproducible from the MM bootstrap signature alone.**
  This means the user only needs MetaMask (any RFC-6979 wallet — Ledger
  notably differs) to recover access. There is no second seed to back up.
- **The session key is never equal to the MM key.** It's derived from the
  signature, which is a one-way function of (msgHash, MMpriv). MetaMask
  doesn't even know its key produced this scalar.
- **Determinism gotcha.** If a future wallet rotates to non-deterministic
  ECDSA, the same MetaMask seed will produce a different session key on each
  call → loss of access. Test against the wallets you intend to support.
- **The bootstrap message is versioned (`v1`).** Bump to `v2` to rotate the
  derivation; existing users keep `v1` keys.
- **Cairo `y_parity` convention quirk.** Cairo uses `y_parity = (v % 2 == 0)`
  (so v=27 → false, v=28 → true). The encoding helpers handle this — don't
  pass raw EVM `v` to Cairo without going through `signOwnership` /
  `signOutsideExecution`.

## Cross-references

- Cairo factory: `account_factory/src/account_factory.cairo` (deploys via
  `session_eth_address` salt)
- Cairo account: `eth_712_account/src/eth_712_account.cairo`
- EIP-712 hash logic: `eth_712_account/src/eth_712_utils.cairo`
- Python reference signatures: `eth_712_account/scripts/generate_test_signatures.py`
