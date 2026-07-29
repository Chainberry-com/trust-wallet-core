# @chainberry/trust-wallet-core

Expo native module wrapping [Trust Wallet Core](https://github.com/trustwallet/wallet-core) for HD wallet generation, address derivation, and transaction signing. Runs the real native library (Kotlin/JNI on Android, Swift on iOS) — not the WASM build, so it works fine under Hermes.

Supported coins: Ethereum, Solana, BNB Smart Chain (see `SupportedCoin`).

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

`WalletCore` is pulled in via CocoaPods (`s.dependency 'TrustWalletCore'`) — no extra auth needed, `pod install` handles it.

## Usage

```ts
import { generateWallet, restoreWallet, getAddressForCoin } from "@chainberry/trust-wallet-core";

const { mnemonic, wallets } = await generateWallet(); // 128-bit / 12-word by default
// wallets: { ethereum: "0x...", solana: "...", bnb: "0x..." }

const restored = await restoreWallet(mnemonic);

const { address, privateKey } = await getAddressForCoin(mnemonic, "ethereum");
```

## API

- `generateWallet(strength = 128, passphrase = "")` — creates a new BIP-39 mnemonic (128 = 12 words, 256 = 24 words) and returns it along with the derived address for every supported coin.
- `restoreWallet(mnemonic, passphrase = "")` — validates an existing mnemonic and returns the same shape as `generateWallet`. Throws if the mnemonic is invalid.
- `getAddressForCoin(mnemonic, coin, passphrase = "")` — derives `{ address, privateKey }` for a single coin (`"ethereum" | "solana" | "bnb"`).

## Security note

`getAddressForCoin` returns the raw private key as hex to JS. That's a deliberate tradeoff for this module — it does no key storage or signing orchestration itself, it only derives keys. Callers are responsible for how the mnemonic and private keys are held, encrypted at rest, and cleared from memory. Don't treat this module as a secure enclave; it isn't one.

## License

MIT. Trust Wallet Core itself is Apache-2.0 — see [trustwallet/wallet-core](https://github.com/trustwallet/wallet-core) for its license.
