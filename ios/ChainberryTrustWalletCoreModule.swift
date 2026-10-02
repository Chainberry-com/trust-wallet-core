import ExpoModulesCore
import UIKit
import WalletCore
@preconcurrency import LocalAuthentication

// Mnemonic/private-key material never crosses back to JS except `exportMnemonic` — an
// explicit, biometric/passcode-gated backup flow. Every other method returns only
// walletIds, addresses, or signed transaction bytes/hex.
public class ChainberryTrustWalletCoreModule: Module {
  public func definition() -> ModuleDefinition {
    Name("TrustWalletCore")

    // Runs once, right after module init, before any of the AsyncFunctions below can be reached
    // from JS — so nothing can legitimately be mid-operation yet, which is exactly what makes a
    // one-shot pass here sufficient (no lock/grace-period needed against an in-flight call). This
    // is the actual crash-safety mechanism for an interrupted create/delete; see CONTEXT.md and
    // docs/adr/0001. `reconcileOrphans` is non-throwing — never allowed to block or crash startup.
    OnCreate {
      NativeWalletStore.reconcileOrphans()
    }

    // strength 128 = 12 words, 256 = 24 words. Returns { walletId, addresses, isTestnet }.
    // No BIP-39 passphrase support: signTransaction always reconstructs the wallet with an
    // empty passphrase, so accepting one here would derive addresses from a seed different
    // from the one actually used to sign — always pass "" to stay consistent with that.
    // isTestnet selects the address format for BTC/LTC/BCH (see ChainSigner.address(for:)) —
    // every other chain's address is the same on mainnet and testnet. This value is persisted
    // as immutable per-wallet metadata (NativeWalletStore.WalletRecord) — signTransaction reads
    // it back from there instead of accepting it as a parameter, so it can never drift.
    AsyncFunction("createWallet") { (strength: Int, isTestnet: Bool) throws -> [String: Any] in
      guard let wallet = HDWallet(strength: Int32(strength), passphrase: "") else {
        throw Exception(name: "WalletError", description: "Failed to generate wallet")
      }
      do {
        return try Self.persistNewWallet(wallet: wallet, isTestnet: isTestnet)
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // One-time mnemonic exposure from JS, at import only — never retained after this call.
    // Returns { walletId, addresses, isTestnet }. No BIP-39 passphrase support (see `createWallet`).
    AsyncFunction("importWallet") { (mnemonic: String, isTestnet: Bool) throws -> [String: Any] in
      guard let wallet = HDWallet(mnemonic: mnemonic, passphrase: "") else {
        throw Exception(name: "InvalidMnemonic", description: "Invalid mnemonic phrase")
      }
      do {
        return try Self.persistNewWallet(wallet: wallet, isTestnet: isTestnet)
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // Reads only the ungated metadata store — no biometric prompt.
    AsyncFunction("listWallets") { () throws -> [[String: Any]] in
      do {
        return try NativeWalletStore.loadMetadata().map { walletId, record in
          ["walletId": walletId, "addresses": record.addresses, "isTestnet": record.isTestnet]
        }
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // Irreversible — requires a fresh biometric/passcode confirmation before anything is
    // deleted, same gate as `signTransaction`/`exportMnemonic`. A compromised/malicious JS
    // caller can still invoke this directly (there's no UI call site today), so the gate
    // must live here rather than in JS.
    //
    // Removes the metadata entry *before* the secret (Keychain item) — the reverse of the old
    // ordering. If this is interrupted between the two steps, the wallet is already gone from
    // `listWallets` and only an orphaned Keychain item is left behind, which the next app
    // launch's reconciliation pass cleans up (see docs/adr/0001) — never a metadata record still
    // pointing at a secret that's already gone.
    AsyncFunction("deleteWallet") { (walletId: String) async throws -> Void in
      try await Self.withLifecycleLock(rejectIfBusy: false) {
        do {
          let id = try NativeWalletStore.validateWalletId(walletId)
          _ = try await Self.authenticatedContext(reason: "Delete wallet")
          var metadata = try NativeWalletStore.loadMetadata()
          metadata.removeValue(forKey: id)
          try NativeWalletStore.saveMetadata(metadata)
          try NativeWalletStore.deleteMnemonic(walletId: id)
        } catch let e as NativeWalletStoreError {
          throw e.asException
        }
      }
    }

    // Triggers the native biometry/passcode prompt, then signs entirely in-process.
    // Returns { signedTx, meta? }. Network mode (mainnet/testnet) is read from the wallet's own
    // persisted record, not accepted as a parameter — see ChainSigner.key(for:) and
    // NativeWalletStore.WalletRecord for why a caller-supplied value here could sign with the
    // wrong key for BTC/LTC.
    AsyncFunction("signTransaction") { (walletId: String, chain: String, unsignedTx: [String: Any]) async throws -> [String: Any] in
      do {
        let id = try NativeWalletStore.validateWalletId(walletId)
        let chainKey = try ChainKey(fromJs: chain)
        try await Self.confirmTransaction(chain: chainKey, unsignedTx: unsignedTx)
        let context = try await Self.authenticatedContext(reason: "Sign transaction")
        let mnemonic = try NativeWalletStore.loadMnemonic(walletId: id, context: context)
        guard let wallet = HDWallet(mnemonic: mnemonic, passphrase: "") else {
          throw Exception(name: "InvalidMnemonic", description: "Stored mnemonic failed validation")
        }
        // Backfill any addresses that were missing when the wallet was first stored
        // (e.g. chains added after the wallet was created). Runs silently after the
        // biometric gate — no extra prompt needed.
        var metadata = try NativeWalletStore.loadMetadata()
        guard var record = metadata[id] else {
          throw NativeWalletStoreError.notFound(walletId: id)
        }
        let isTestnet = record.isTestnet
        var changed = false
        for chain in ChainKey.allCases {
          if record.addresses[chain.rawValue] == nil {
            record.addresses[chain.rawValue] = ChainSigner.address(for: chain, wallet: wallet, isTestnet: isTestnet)
            changed = true
          }
        }
        if changed {
          metadata[id] = record
          try? NativeWalletStore.saveMetadata(metadata)
        }
        let result = try ChainSigner.sign(chain: chainKey, wallet: wallet, unsignedTx: unsignedTx, isTestnet: isTestnet)
        var response: [String: Any] = ["signedTx": result.signedTx]
        if let meta = result.meta { response["meta"] = meta }
        return response
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // The one sanctioned mnemonic exposure — explicit backup flow only.
    AsyncFunction("exportMnemonic") { (walletId: String) async throws -> String in
      do {
        let id = try NativeWalletStore.validateWalletId(walletId)
        let context = try await Self.authenticatedContext(reason: "Reveal recovery phrase")
        return try NativeWalletStore.loadMnemonic(walletId: id, context: context)
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }
  }

  // MARK: - Lifecycle serialization (see docs/adr/0002)

  /// Serializes create/import/delete against each other — a `Task`-based actor rather than
  /// `NSLock`, since these calls `await` across the biometric prompt and holding an `NSLock`
  /// across a suspension point (where Swift Concurrency may resume on a different underlying
  /// thread) is unsafe.
  private actor LifecycleLock {
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    /// Non-blocking: returns `false` immediately if already held (used by create/import, which
    /// reject rather than queue).
    func tryAcquire() -> Bool {
      guard !locked else { return false }
      locked = true
      return true
    }

    /// Blocking: waits until the lock is free, then acquires it (used by delete, which queues).
    func acquire() async {
      guard locked else {
        locked = true
        return
      }
      await withCheckedContinuation { waiters.append($0) }
    }

    /// Hands ownership directly to the next waiter rather than freeing the lock and letting
    /// every waiter race a fresh `tryAcquire`/`acquire`.
    func release() {
      if !waiters.isEmpty {
        waiters.removeFirst().resume()
      } else {
        locked = false
      }
    }
  }

  private static let lifecycleLock = LifecycleLock()

  /// Serializes `body` — including the biometric/passcode prompt, not just the store writes —
  /// against every other lifecycle-mutating call, so at most one is ever touching the shared
  /// metadata store at a time (see docs/adr/0002). Also forecloses a second, separate bug: two
  /// concurrent `LAContext` evaluations racing each other.
  ///
  /// `rejectIfBusy` chooses the policy for a caller that finds the lock already held:
  /// `createWallet`/`importWallet` reject immediately (`ERR_WALLET_OPERATION_IN_PROGRESS`) so a
  /// double-tap can never mint two wallets; `deleteWallet` queues instead, since two distinct
  /// deletes are both legitimate and should both eventually happen.
  private static func withLifecycleLock<T>(rejectIfBusy: Bool, _ body: () async throws -> T) async throws -> T {
    if rejectIfBusy {
      guard await lifecycleLock.tryAcquire() else {
        throw Exception(
          name: "OperationInProgress",
          description: "Another wallet operation is already in progress",
          code: "ERR_WALLET_OPERATION_IN_PROGRESS"
        )
      }
    } else {
      await lifecycleLock.acquire()
    }
    do {
      let result = try await body()
      await lifecycleLock.release()
      return result
    } catch {
      await lifecycleLock.release()
      throw error
    }
  }

  // MARK: - Helpers

  /// Presents a native UIAlertController showing decoded tx details (chain, recipient, amount,
  /// fee). The user must tap "Confirm & Sign" before biometric auth fires — this is the only
  /// place in the native module where informed consent is collected.
  private static func confirmTransaction(chain: ChainKey, unsignedTx: [String: Any]) async throws {
    let message = try ChainSigner.buildSummary(chain: chain, unsignedTx: unsignedTx)
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      DispatchQueue.main.async {
        let scene = UIApplication.shared.connectedScenes
          .filter({ $0.activationState == .foregroundActive })
          .compactMap({ $0 as? UIWindowScene })
          .first
        var rootVC = scene?.windows.first(where: { $0.isKeyWindow })?.rootViewController
        while let presented = rootVC?.presentedViewController { rootVC = presented }
        guard let topVC = rootVC else {
          continuation.resume(throwing: Exception(name: "NoViewController", description: "Cannot present confirmation"))
          return
        }
        let alert = UIAlertController(title: "Confirm Transaction", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
          continuation.resume(throwing: Exception(name: "UserCancelled", description: "Transaction cancelled by user"))
        })
        alert.addAction(UIAlertAction(title: "Confirm & Sign", style: .default) { _ in
          continuation.resume(returning: ())
        })
        topVC.present(alert, animated: true)
      }
    }
  }

  private static func persistNewWallet(wallet: HDWallet, isTestnet: Bool) throws -> [String: Any] {
    let walletId = UUID().uuidString
    var addresses: [String: String] = [:]
    for chain in ChainKey.allCases {
      addresses[chain.rawValue] = ChainSigner.address(for: chain, wallet: wallet, isTestnet: isTestnet)
    }

    try NativeWalletStore.saveMnemonic(wallet.mnemonic, walletId: walletId)
    do {
      var metadata = try NativeWalletStore.loadMetadata()
      metadata[walletId] = NativeWalletStore.WalletRecord(isTestnet: isTestnet, addresses: addresses)
      try NativeWalletStore.saveMetadata(metadata)
    } catch {
      // The mnemonic is already persisted but has no metadata pointer — compensate by
      // best-effort deleting it rather than leaving a permanent, invisible orphan. If this
      // rollback delete also fails, there's nothing more useful to do than propagate the
      // original error; the item is at least no worse off than before this call.
      try? NativeWalletStore.deleteMnemonic(walletId: walletId)
      throw error
    }

    return ["walletId": walletId, "addresses": addresses, "isTestnet": isTestnet]
  }

  /// Prompts biometry-or-device-passcode via `.deviceOwnerAuthentication` (Apple's
  /// combined policy — no separate fallback branch needed), then hands back the
  /// now-authenticated context for a single Keychain read via `kSecUseAuthenticationContext`.
  private static func authenticatedContext(reason: String) async throws -> LAContext {
    let context = LAContext()
    var evalError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evalError) else {
      throw classifyAuthError(evalError, fallbackDescription: "No biometry or device passcode is set up")
    }
    return try await withCheckedThrowingContinuation { continuation in
      context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, authError in
        if success {
          continuation.resume(returning: context)
        } else {
          continuation.resume(throwing: classifyAuthError(authError, fallbackDescription: "Authentication failed"))
        }
      }
    }
  }

  /// Classifies an `LAError` from either `canEvaluatePolicy`'s precheck or `evaluatePolicy`'s
  /// prompt callback into the same typed error codes Android's `NativeWalletStore.kt`
  /// (`classifyPromptError`/`AuthUnavailable`) uses, so `use-wallet.ts`'s `WALLET_ERROR_COPY` —
  /// written once, keyed by code, shared across both platforms — actually fires here instead of
  /// every prompt failure collapsing into one generic "Authentication failed" banner. This
  /// matters most for cancellation: dismissing the prompt must produce `ERR_WALLET_AUTH_CANCELLED`
  /// (mapped to a quiet no-op, not a banner) on both platforms, not just Android.
  ///
  /// Deliberately does not attempt an iOS equivalent of Android's `KeyInvalidated`
  /// (`KeyPermanentlyInvalidatedException` after an enrollment change) — on iOS that surfaces
  /// later, as a `SecItemCopyMatching` `OSStatus` failure inside `loadMnemonic`, not as an
  /// `LAError` here; aligning that would mean auditing `NativeWalletStore.classify(_:)`'s
  /// `errSecAuthFailed`/`errSecInteractionNotAllowed` handling separately; scoped out of this
  /// pass since a wrong OSStatus->meaning mapping there is materially harder to get right without
  /// device verification than this prompt-level LAError classification is.
  private static func classifyAuthError(_ error: Error?, fallbackDescription: String) -> Exception {
    guard let laError = error as? LAError else {
      return Exception(
        name: "AuthenticationFailed",
        description: error?.localizedDescription ?? fallbackDescription,
        code: "ERR_AUTHENTICATION_FAILED"
      )
    }
    switch laError.code {
    case .userCancel, .appCancel, .systemCancel:
      // User dismissed the prompt rather than authentication actually failing — kept distinct
      // from the default case below so `WALLET_ERROR_COPY`'s `null` entry for this code can
      // treat it as a quiet no-op instead of an error to surface (mirrors Android's
      // `AuthCancelled`).
      return Exception(name: "AuthCancelled", description: "Authentication was cancelled", code: "ERR_WALLET_AUTH_CANCELLED")
    case .biometryLockout:
      // iOS exposes one lockout state (cleared only by a passcode unlock), closest to Android's
      // ERROR_LOCKOUT_PERMANENT rather than its auto-clearing temporary variant.
      return Exception(
        name: "AuthLockedOutPermanent",
        description: "Too many failed authentication attempts — unlock your device to reset",
        code: "ERR_WALLET_AUTH_LOCKED_OUT_PERMANENT"
      )
    case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet:
      // Existing-wallet-use-time unavailability (no secure auth is currently satisfiable) —
      // mirrors Android's `AuthUnavailable` precheck, distinct from `.noDevicePasscode`
      // (`ERR_NO_DEVICE_PASSCODE`) which is specifically the wallet-*creation*-time gate.
      return Exception(
        name: "AuthUnavailable",
        description: "Authentication unavailable: \(laError.localizedDescription)",
        code: "ERR_WALLET_AUTH_UNAVAILABLE"
      )
    default:
      return Exception(name: "AuthenticationFailed", description: laError.localizedDescription, code: "ERR_AUTHENTICATION_FAILED")
    }
  }
}
