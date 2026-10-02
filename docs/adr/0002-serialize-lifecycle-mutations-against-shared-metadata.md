# Serialize lifecycle-mutating operations against the shared metadata store

**Status**: accepted

`createWallet`, `importWallet`, and `deleteWallet` all read the entire metadata blob, mutate a copy, and write the whole thing back — so two concurrent calls racing on *different* wallet ids still lose an update, not just two calls on the same id. A single global lock per platform (not per-walletId) now serializes the whole operation, including the biometric/passcode prompt, for at most one lifecycle-mutating call in flight at a time. `createWallet`/`importWallet` fail fast with `ERR_WALLET_OPERATION_IN_PROGRESS` (wired into JS as a quiet no-op, like `ERR_WALLET_AUTH_CANCELLED`) rather than queue, so a double-tap can never mint two wallets; `deleteWallet` queues instead, since two distinct deletes are both legitimate and should both eventually happen.

## Rejected alternatives

- **Per-walletId locking**: rejected outright, not just weaker — the critical section is the shared metadata blob itself, so it doesn't protect two different wallets' concurrent creates from clobbering each other.
- **Serializing only the store-write tail, not the auth prompt**: rejected — leaves two concurrent biometric prompts able to race each other, a separate latent bug this closes as a side effect of the simpler "one op in flight" model.
