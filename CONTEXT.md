# Trust Wallet Core (native storage)

Native module that generates, persists, and signs with self-custody wallets on-device. Splits each wallet's data across two independent OS-level stores that cannot be written to transactionally, which is the source of most of the vocabulary below.

## Language

**Secret store**:
The biometry/passcode-gated store holding a wallet's mnemonic (iOS Keychain item; Android Keystore-encrypted file plus its Keystore key). Never readable without a fresh authentication prompt.
_Avoid_: Keychain, Keystore (platform-specific; use when literally talking about one platform's API)

**Metadata store**:
The ungated store holding, per wallet, only its derived addresses — readable with no prompt, used for `listWallets` and address display.
_Avoid_: index, wallet list

**Lifecycle-mutating operation**:
`createWallet`, `importWallet`, or `deleteWallet` — any call that writes to both the secret store and the metadata store. Serialized against a single global lock per platform, because both stores are read-modify-written as a whole blob, not per-wallet.
_Avoid_: write operation

**Orphan**:
A secret store resource (mnemonic item/file, or on Android a Keystore key alias) with no matching metadata entry. The expected result of a create or delete interrupted mid-flight; silently garbage-collected by the reconciliation pass.
_Avoid_: dangling wallet, leaked wallet

**Zombie**:
A metadata entry with no matching secret store resource. Should never arise from a normal lifecycle path (create writes the secret before metadata; delete removes metadata before the secret) — if one is found, it is deliberately left in place rather than auto-healed, so it surfaces loudly as `ERR_WALLET_NOT_FOUND` the next time the wallet is used.
_Avoid_: orphaned metadata, ghost wallet

**Reconciliation pass**:
The one-shot orphan cleanup that runs once during native module init, before the JS layer can issue its first lifecycle-mutating call. The actual source of crash-safety for interrupted operations — not the best-effort in-call rollback, which only runs for a thrown error, never for a killed process.
_Avoid_: cleanup, garbage collection (use only when referring to what the pass does to an orphan, not the pass itself)
