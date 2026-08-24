import ExpoModulesCore
import UIKit
import WalletCore
@preconcurrency import LocalAuthentication

// Mnemonic/private-key material never crosses back to JS except `exportMnemonic` — an
// explicit, biometric/passcode-gated backup flow. Every other method returns only
// walletIds, addresses, or signed transaction bytes/hex.
public class TrustWalletCoreModule: Module {
  public func definition() -> ModuleDefinition {
    Name("TrustWalletCore")

    // strength 128 = 12 words, 256 = 24 words. Returns { walletId, addresses }.
    AsyncFunction("createWallet") { (strength: Int, passphrase: String) throws -> [String: Any] in
      guard let wallet = HDWallet(strength: Int32(strength), passphrase: passphrase) else {
        throw Exception(name: "WalletError", description: "Failed to generate wallet")
      }
      do {
        return try Self.persistNewWallet(wallet: wallet)
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // One-time mnemonic exposure from JS, at import only — never retained after this call.
    // Returns { walletId, addresses }.
    AsyncFunction("importWallet") { (mnemonic: String, passphrase: String) throws -> [String: Any] in
      guard let wallet = HDWallet(mnemonic: mnemonic, passphrase: passphrase) else {
        throw Exception(name: "InvalidMnemonic", description: "Invalid mnemonic phrase")
      }
      do {
        return try Self.persistNewWallet(wallet: wallet)
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // Reads only the ungated metadata store — no biometric prompt.
    AsyncFunction("listWallets") { () throws -> [[String: Any]] in
      do {
        return try NativeWalletStore.loadMetadata().map { walletId, addresses in
          ["walletId": walletId, "addresses": addresses]
        }
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // Irreversible — requires a fresh biometric/passcode confirmation before anything is
    // deleted, same gate as `signTransaction`/`exportMnemonic`. A compromised/malicious JS
    // caller can still invoke this directly (there's no UI call site today), so the gate
    // must live here rather than in JS.
    AsyncFunction("deleteWallet") { (walletId: String) async throws -> Void in
      do {
        let id = try NativeWalletStore.validateWalletId(walletId)
        _ = try await Self.authenticatedContext(reason: "Delete wallet")
        try NativeWalletStore.deleteMnemonic(walletId: id)
        var metadata = try NativeWalletStore.loadMetadata()
        metadata.removeValue(forKey: id)
        try NativeWalletStore.saveMetadata(metadata)
      } catch let e as NativeWalletStoreError {
        throw e.asException
      }
    }

    // Triggers the native biometry/passcode prompt, then signs entirely in-process.
    // Returns { signedTx, meta? }.
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
        let result = try ChainSigner.sign(chain: chainKey, wallet: wallet, unsignedTx: unsignedTx)
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

  // MARK: - Helpers

  /// Presents a native UIAlertController showing decoded tx details (chain, recipient, amount,
  /// fee). The user must tap "Confirm & Sign" before biometric auth fires — this is the only
  /// place in the native module where informed consent is collected.
  private static func confirmTransaction(chain: ChainKey, unsignedTx: [String: Any]) async throws {
    let message = ChainSigner.buildSummary(chain: chain, unsignedTx: unsignedTx)
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

  private static func persistNewWallet(wallet: HDWallet) throws -> [String: Any] {
    let walletId = UUID().uuidString
    var addresses: [String: String] = [:]
    for chain in ChainKey.allCases {
      addresses[chain.rawValue] = wallet.getAddressForCoin(coin: chain.coinType)
    }

    try NativeWalletStore.saveMnemonic(wallet.mnemonic, walletId: walletId)
    do {
      var metadata = try NativeWalletStore.loadMetadata()
      metadata[walletId] = addresses
      try NativeWalletStore.saveMetadata(metadata)
    } catch {
      // The mnemonic is already persisted but has no metadata pointer — compensate by
      // best-effort deleting it rather than leaving a permanent, invisible orphan. If this
      // rollback delete also fails, there's nothing more useful to do than propagate the
      // original error; the item is at least no worse off than before this call.
      try? NativeWalletStore.deleteMnemonic(walletId: walletId)
      throw error
    }

    return ["walletId": walletId, "addresses": addresses]
  }

  /// Prompts biometry-or-device-passcode via `.deviceOwnerAuthentication` (Apple's
  /// combined policy — no separate fallback branch needed), then hands back the
  /// now-authenticated context for a single Keychain read via `kSecUseAuthenticationContext`.
  private static func authenticatedContext(reason: String) async throws -> LAContext {
    let context = LAContext()
    var evalError: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &evalError) else {
      throw Exception(
        name: "BiometryUnavailable",
        description: evalError?.localizedDescription ?? "No biometry or device passcode is set up"
      )
    }
    return try await withCheckedThrowingContinuation { continuation in
      context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, authError in
        if success {
          continuation.resume(returning: context)
        } else {
          continuation.resume(throwing: Exception(
            name: "AuthenticationFailed",
            description: authError?.localizedDescription ?? "Authentication failed"
          ))
        }
      }
    }
  }
}
