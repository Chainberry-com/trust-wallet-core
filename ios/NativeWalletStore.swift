import Foundation
import Security
import LocalAuthentication

/// Errors surfaced to the Expo bridge as `Exception`s by the caller.
enum NativeWalletStoreError: Error, CustomStringConvertible {
  case keychainWrite(OSStatus)
  case keychainRead(OSStatus)
  case notFound
  case noDevicePasscode

  var description: String {
    switch self {
    case .keychainWrite(let status): return "Keychain write failed (OSStatus \(status))"
    case .keychainRead(let status): return "Keychain read failed (OSStatus \(status))"
    case .notFound: return "Wallet not found"
    case .noDevicePasscode: return "A device passcode must be set before creating or importing a wallet"
    }
  }
}

/// Persists mnemonics in the iOS Keychain, gated by biometry-or-device-passcode
/// (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` + `SecAccessControl`), plus a
/// parallel ungated metadata store (walletId -> per-chain addresses) for read-only UI
/// (address display, balance lookups) that shouldn't need a biometric prompt.
///
/// Deliberately does not use `react-native-keychain` or wallet-core's `StoredKey`
/// keystore-JSON format — the mnemonic bytes are the only secret; wrapping them in an
/// additional password-protected keystore would just relocate the secret to a password
/// that itself needs identical OS-level gating, for no additional protection.
enum NativeWalletStore {
  private static let walletServicePrefix = "com.chainberry.vault.wallet."
  private static let mnemonicAccount = "mnemonic"
  private static let metadataService = "com.chainberry.vault.wallet-metadata"
  private static let metadataAccount = "index"

  // MARK: - Mnemonic (biometry/passcode gated)

  static func saveMnemonic(_ mnemonic: String, walletId: String) throws {
    var accessError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
      [.biometryCurrentSet, .or, .devicePasscode],
      &accessError
    ) else {
      throw NativeWalletStoreError.noDevicePasscode
    }

    let service = walletServicePrefix + walletId
    // Delete any existing item first: SecItemAdd fails on a duplicate primary key, and
    // access control cannot be changed via SecItemUpdate — a fresh add is required.
    SecItemDelete([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: mnemonicAccount,
    ] as CFDictionary)

    let addQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: mnemonicAccount,
      kSecValueData as String: Data(mnemonic.utf8),
      kSecAttrAccessControl as String: access,
    ]
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NativeWalletStoreError.keychainWrite(status)
    }
  }

  /// Triggers the biometry/passcode prompt (via the supplied `LAContext`, so the caller
  /// controls the prompt's reason string) and returns the mnemonic on success.
  static func loadMnemonic(walletId: String, context: LAContext) throws -> String {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: walletServicePrefix + walletId,
      kSecAttrAccount as String: mnemonicAccount,
      kSecReturnData as String: true,
      kSecUseAuthenticationContext as String: context,
    ]

    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
      throw status == errSecItemNotFound ? NativeWalletStoreError.notFound : NativeWalletStoreError.keychainRead(status)
    }
    guard let data = result as? Data, let mnemonic = String(data: data, encoding: .utf8) else {
      throw NativeWalletStoreError.notFound
    }
    return mnemonic
  }

  static func deleteMnemonic(walletId: String) {
    SecItemDelete([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: walletServicePrefix + walletId,
      kSecAttrAccount as String: mnemonicAccount,
    ] as CFDictionary)
  }

  // MARK: - Metadata (ungated: walletId -> { chain: address })

  static func saveMetadata(_ wallets: [String: [String: String]]) throws {
    let data = try JSONSerialization.data(withJSONObject: wallets)
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: metadataService,
      kSecAttrAccount as String: metadataAccount,
    ]
    SecItemDelete(query as CFDictionary)

    var addQuery = query
    addQuery[kSecValueData as String] = data
    addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    let status = SecItemAdd(addQuery as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NativeWalletStoreError.keychainWrite(status)
    }
  }

  static func loadMetadata() -> [String: [String: String]] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: metadataService,
      kSecAttrAccount as String: metadataAccount,
      kSecReturnData as String: true,
    ]
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess,
          let data = result as? Data,
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] else {
      return [:]
    }
    return obj
  }
}
