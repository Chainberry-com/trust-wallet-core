# Crash-safe wallet lifecycle via reconciliation, not cross-store transactions

**Status**: accepted

A wallet's secret and metadata live in two independent OS stores with no shared transaction. `createWallet` writes the secret then the metadata; `deleteWallet` now removes the metadata then the secret — both orderings chosen so any interruption leaves an **orphan** (secret with no metadata), never a **zombie** (metadata with no secret) visible to the user. A reconciliation pass runs once during native module init, before any JS call is possible, and deletes orphans it finds; this — not the existing best-effort `try?`/`runCatching` rollback on create — is what actually guarantees crash-safety, since no code runs after a hard process kill. Lifecycle state is inferred structurally from cross-store presence/absence rather than a persisted status field, since two stores already encode exactly this.

## Rejected alternatives

- **Persisted status field** (e.g. `pendingCreate`/`pendingDelete` on the metadata record): rejected — it's a third thing that itself needs crash-safe writing, for no benefit once reconciliation only needs to run once at a point where nothing can legitimately be in flight.
- **Lazy reconciliation on every `listWallets` call**: rejected — reintroduces a real race against same-session in-flight operations (needing a grace period or lock) that init-time reconciliation avoids by construction, since a killed process can't have a legitimate survivor call.
- **Auto-healing a zombie** by dropping its metadata entry on discovery: rejected — this is key custody; silently removing the user's only visible record that a wallet's secret is gone is worse than a loud, specific error the next time they touch it.
