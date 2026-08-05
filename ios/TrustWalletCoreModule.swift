import ExpoModulesCore
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
      return try Self.persistNewWallet(wallet: wallet)
    }

    // One-time mnemonic exposure from JS, at import only — never retained after this call.
    // Returns { walletId, addresses }.
    AsyncFunction("importWallet") { (mnemonic: String, passphrase: String) throws -> [String: Any] in
      guard let wallet = HDWallet(mnemonic: mnemonic, passphrase: passphrase) else {
        throw Exception(name: "InvalidMnemonic", description: "Invalid mnemonic phrase")
      }
      return try Self.persistNewWallet(wallet: wallet)
    }

    // Reads only the ungated metadata store — no biometric prompt.
    AsyncFunction("listWallets") { () -> [[String: Any]] in
      NativeWalletStore.loadMetadata().map { walletId, addresses in
        ["walletId": walletId, "addresses": addresses]
      }
    }

    AsyncFunction("deleteWallet") { (walletId: String) throws -> Void in
      NativeWalletStore.deleteMnemonic(walletId: walletId)
      var metadata = NativeWalletStore.loadMetadata()
      metadata.removeValue(forKey: walletId)
      try NativeWalletStore.saveMetadata(metadata)
    }

    // Triggers the native biometry/passcode prompt, then signs entirely in-process.
    // Returns { signedTx, meta? }.
    AsyncFunction("signTransaction") { (walletId: String, chain: String, unsignedTx: [String: Any]) async throws -> [String: Any] in
      let chainKey = try ChainKey(fromJs: chain)
      let context = try await Self.authenticatedContext(reason: "Sign transaction")
      let mnemonic = try NativeWalletStore.loadMnemonic(walletId: walletId, context: context)
      guard let wallet = HDWallet(mnemonic: mnemonic, passphrase: "") else {
        throw Exception(name: "InvalidMnemonic", description: "Stored mnemonic failed validation")
      }
      let result = try ChainSigner.sign(chain: chainKey, wallet: wallet, unsignedTx: unsignedTx)
      var response: [String: Any] = ["signedTx": result.signedTx]
      if let meta = result.meta { response["meta"] = meta }
      return response
    }

    // The one sanctioned mnemonic exposure — explicit backup flow only.
    AsyncFunction("exportMnemonic") { (walletId: String) async throws -> String in
      let context = try await Self.authenticatedContext(reason: "Reveal recovery phrase")
      return try NativeWalletStore.loadMnemonic(walletId: walletId, context: context)
    }
  }

  // MARK: - Helpers

  private static func persistNewWallet(wallet: HDWallet) throws -> [String: Any] {
    let walletId = UUID().uuidString
    var addresses: [String: String] = [:]
    for chain in ChainKey.allCases {
      addresses[chain.rawValue] = wallet.getAddressForCoin(coin: chain.coinType)
    }

    try NativeWalletStore.saveMnemonic(wallet.mnemonic, walletId: walletId)
    var metadata = NativeWalletStore.loadMetadata()
    metadata[walletId] = addresses
    try NativeWalletStore.saveMetadata(metadata)

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
