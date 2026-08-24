# @chainberry/trust-wallet-core

Expo native module wrapping [Trust Wallet Core](https://github.com/trustwallet/wallet-core) for HD wallet generation, address derivation, and transaction signing. Runs the real native library (Kotlin/JNI on Android, Swift on iOS) — not the WASM build, so it works fine under Hermes.

Supported chains: Ethereum, BNB Smart Chain, Polygon, Solana, Tron, TON, Bitcoin, Bitcoin Cash (address derivation only — see Security model), Litecoin, XRP (see `Chain`).

## Installation

```sh
npx expo install @chainberry/trust-wallet-core
```

This is an Expo config plugin module with native Android/iOS code, so it requires a development build (`expo prebuild` / EAS Build) — it will not work in Expo Go.

### Android: GitHub Packages authentication required

Trust Wallet Core's Android artifact is published to GitHub Packages, which requires authentication even though the package itself is public. Without credentials, `./gradlew` will fail to resolve `com.trustwallet:wallet-core`.

Set up **one** of:

```sh
# Env vars (CI / one-off terminal)
export GITHUB_ACTOR=your-github-username
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx   # classic PAT, read:packages scope only
```

or add to `~/.gradle/gradle.properties` (permanent local dev setup):

```properties
gpr.user=your-github-username
gpr.key=ghp_xxxxxxxxxxxx
```

Generate a token at github.com/settings/tokens → "classic" → check `read:packages`.

### iOS

`WalletCore` is pulled in via CocoaPods (`s.dependency 'TrustWalletCore'`) — no extra auth needed, `pod install` handles it. Biometric/passcode gating uses `LocalAuthentication` (system framework, no extra dependency).

Android biometric gating additionally pulls in `androidx.biometric:biometric:1.1.0`.

## Usage

```ts
import { createWallet, importWallet, signTransaction, exportMnemonic } from "@chainberry/trust-wallet-core";

const { walletId, addresses } = await createWallet(); // 128-bit / 12-word by default
// addresses: { ethereum: "0x...", solana: "...", bnb: "0x...", bitcoin: "...", ... }

const restored = await importWallet(mnemonic);

// Triggers a native biometry/passcode prompt; only signed tx bytes/hex cross back to JS.
const { signedTx } = await signTransaction(walletId, "ethereum", unsignedTx);

// Explicit backup flow only — biometry/passcode gated.
const mnemonic = await exportMnemonic(walletId);
```

## API

- `createWallet(strength = 128)` — generates a new BIP-39 mnemonic and persists it natively (Keychain on iOS / Keystore-backed file on Android, biometry-or-passcode gated). Returns `{ walletId, addresses }` — the mnemonic itself never leaves native code. No BIP-39 passphrase support: `signTransaction` always reconstructs the wallet with an empty passphrase, so a caller-supplied one would derive addresses from a seed different from the one actually used to sign.
- `importWallet(mnemonic)` — validates and persists an existing mnemonic the same way. The `mnemonic` argument is a one-time exposure from the caller (e.g. a text-entry backup-restore screen); discard your own copy immediately after this call resolves.
- `listWallets()` — returns `{ walletId, addresses }[]` for every persisted wallet, reading only the ungated metadata store. No biometric prompt.
- `deleteWallet(walletId)` — removes the wallet's native key material and metadata entry. Irreversible; not biometric-gated (deleting reveals nothing, so this is a UX confirmation concern, not a key-secrecy one).
- `signTransaction(walletId, chain, unsignedTx)` — triggers a native biometry/passcode prompt, then derives the key and signs entirely inside native code. Returns `{ signedTx, meta? }`; `meta` currently only carries TON's `txHash`.
- `exportMnemonic(walletId)` — the one sanctioned mnemonic exposure. Biometry/passcode gated. Use only for an explicit "reveal recovery phrase" backup screen; don't hold the result in app state beyond that screen's lifetime.

## Security model

Mnemonic and derived private keys are generated, persisted, and used for signing entirely inside this module's native code (Swift/Kotlin) — they are never serialized back across the JS bridge, with the single exception of `exportMnemonic`'s explicit backup flow. This is a deliberate change from this module's earlier version, which returned raw private keys to JS on every address derivation; that let a compromised/malicious JS dependency, an attached JS debugger, or a JS-heap memory dump read wallet secrets in full. Now the JS runtime never holds them at all.

Storage: one biometry-or-passcode-gated secret per wallet (`SecAccessControl` + iOS Keychain; an Android Keystore AES key gating an encrypted on-disk file), plus a separate, ungated metadata entry (`walletId` → addresses) for read-only UI that shouldn't need a biometric prompt just to show an address or balance.

**Android hardware backing is best-effort, not guaranteed.** Key creation requests StrongBox first (API 28+), falling back to a plain Keystore key (which Keymaster backs with a TEE on virtually all real devices, but which can be software-only on an emulator or a device with no secure hardware at all) on `StrongBoxUnavailableException` or below API 28. The actual security level achieved is verified via `KeyInfo` right after creation and logged (`NativeWalletStore` logcat tag) — a software-only key is tolerated rather than blocking wallet creation, so this is a best-effort hardening measure, not an enforced guarantee. Don't assume every wallet on every device is hardware-backed; check the logs on a specific device/build if that matters for your threat model.

Bitcoin Cash is derivation-only: sending BCH is unsupported both here and upstream (`chainberry-wallet`'s self-custody transaction preparation has no BCH case), so this module only derives its address.

**Not yet verified against a real device/build**: the per-chain `SigningInput` field mappings for Bitcoin, Litecoin, Tron, XRP, and TON, and Solana's raw-transaction signing mode, were written against the general Trust Wallet Core API shape but haven't been compiled or run against this module's pinned `wallet-core` version. Confirm field names and produce byte-for-byte signed-output parity against the previous JS-based signers (or a testnet broadcast) before trusting any of these chains with real funds. Ethereum/BNB/Polygon signing is a straightforward reshape of what this module already proved out.

## License

MIT. Trust Wallet Core itself is Apache-2.0 — see [trustwallet/wallet-core](https://github.com/trustwallet/wallet-core) for its license.
