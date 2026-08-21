import Foundation
import Security
import LocalAuthentication
import ExpoModulesCore

/// Errors surfaced to the Expo bridge as `Exception`s (via `.asException`) by the caller.
///
/// `.notFound` and `.corrupted` are deliberately distinct: `.notFound` means "there is
/// legitimately nothing here yet" (e.g. no metadata has ever been written, or a wallet id
/// has no matching Keychain item) and is safe to treat as an empty/absent result. `.corrupted`
/// means "something is here but it isn't what we expect" (malformed JSON, non-UTF8 mnemonic
/// bytes) and must never be silently treated as absent — doing so is exactly how a transient
/// read failure can cause `createWallet` to stomp a real, unreadable index with a fresh one.
enum NativeWalletStoreError: Error, LocalizedError, CustomStringConvertible {
  case keychainWrite(OSStatus)
  case keychainRead(OSStatus)
  case notFound(walletId: String)
  case corrupted(String)
  case permissionDenied(OSStatus)
  case invalidWalletId(String)
  case noDevicePasscode

  var description: String {
    switch self {
    case .keychainWrite(let status): return "Keychain write failed (OSStatus \(status))"
    case .keychainRead(let status): return "Keychain read failed (OSStatus \(status))"
    case .notFound(let walletId): return walletId.isEmpty ? "Wallet not found" : "Wallet not found: \(walletId)"
    case .corrupted(let detail): return "Wallet data is corrupted: \(detail)"
    case .permissionDenied(let status): return "Permission denied (OSStatus \(status))"
    case .invalidWalletId(let walletId): return "Invalid wallet id: \(walletId)"
    case .noDevicePasscode: return "A device passcode must be set before creating or importing a wallet"
    }
  }

  // `LocalizedError` conformance matters: expo-modules-core wraps any thrown error that is
  // *not* an `Exception` in `UnexpectedException(error)`, whose `reason` is
  // `error.localizedDescription` — not our `description`. Without this, every
  // `NativeWalletStoreError` thrown across the bridge silently loses its message to JS.
  var errorDescription: String? { description }

  var code: String {
    switch self {
    case .notFound: return "ERR_WALLET_NOT_FOUND"
    case .corrupted: return "ERR_WALLET_DATA_CORRUPTED"
    case .permissionDenied: return "ERR_WALLET_PERMISSION_DENIED"
    case .keychainWrite, .keychainRead: return "ERR_KEYCHAIN_IO"
    case .invalidWalletId: return "ERR_INVALID_WALLET_ID"
    case .noDevicePasscode: return "ERR_NO_DEVICE_PASSCODE"
    }
  }

  /// Converts to a proper Expo `Exception` so `code`/`description` survive the bridge
  /// (see the `errorDescription` note above) instead of being flattened by `UnexpectedException`.
  var asException: Exception {
    Exception(name: "NativeWalletStoreError", description: description, code: code)
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

  /// Classifies a Keychain `OSStatus` into a typed error. `errSecItemNotFound` is handled
  /// by each call site individually (it means different things for a read-that-defaults-to-
  /// empty vs. a delete-that's-idempotent vs. a genuine not-found), so it's intentionally not
  /// folded in here except as a fallback for callers that just want *a* not-found error.
  private static func classify(_ status: OSStatus, walletId: String? = nil, isWrite: Bool = false) -> NativeWalletStoreError {
    switch status {
    case errSecItemNotFound:
      return .notFound(walletId: walletId ?? "")
    case errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled:
      return .permissionDenied(status)
    default:
      return isWrite ? .keychainWrite(status) : .keychainRead(status)
    }
  }

  /// Wallet ids are always internally generated as UUIDs (`UUID().uuidString`). Any
  /// caller-supplied id is validated against that format before it's used to build a
  /// Keychain service string, rejecting malformed/adversarial input up front.
  static func validateWalletId(_ walletId: String) throws -> String {
    guard UUID(uuidString: walletId) != nil else {
      throw NativeWalletStoreError.invalidWalletId(walletId)
    }
    return walletId
  }

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
    // errSecItemNotFound (nothing to delete yet) is expected and fine; anything else means
    // the slot may still be occupied, so surface it rather than attempting (and likely
    // failing) the add anyway.
    let deleteStatus = SecItemDelete([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: mnemonicAccount,
    ] as CFDictionary)
    guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
      throw classify(deleteStatus, walletId: walletId, isWrite: true)
    }

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
      throw classify(status, walletId: walletId)
    }
    guard let data = result as? Data, let mnemonic = String(data: data, encoding: .utf8) else {
      throw NativeWalletStoreError.corrupted("stored mnemonic bytes are not valid UTF-8")
    }
    return mnemonic
  }

  /// Idempotent: deleting a wallet id that has no Keychain item is treated as success (there's
  /// nothing left to delete), matching normal `deleteWallet` semantics. Any other failure
  /// (e.g. an interaction-not-allowed/auth error) is surfaced rather than silently discarded.
  static func deleteMnemonic(walletId: String) throws {
    let status = SecItemDelete([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: walletServicePrefix + walletId,
      kSecAttrAccount as String: mnemonicAccount,
    ] as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw classify(status, walletId: walletId, isWrite: true)
    }
  }

  // MARK: - Metadata (ungated: walletId -> { chain: address })

  /// Atomically replaces the metadata blob via `SecItemUpdate` when it already exists,
  /// falling back to `SecItemAdd` only on the very first write. Unlike the mnemonic item,
  /// the metadata item carries no `SecAccessControl`, so there's no access-control-change
  /// obstacle to updating in place — this removes the delete-then-add race window entirely
  /// (a crash between delete and add used to be able to lose the index outright).
  static func saveMetadata(_ wallets: [String: [String: String]]) throws {
    let data = try JSONSerialization.data(withJSONObject: wallets)
    let baseQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: metadataService,
      kSecAttrAccount as String: metadataAccount,
    ]

    let updateStatus = SecItemUpdate(baseQuery as CFDictionary, [kSecValueData as String: data] as CFDictionary)
    if updateStatus == errSecItemNotFound {
      var addQuery = baseQuery
      addQuery[kSecValueData as String] = data
      addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
      guard addStatus == errSecSuccess else {
        throw NativeWalletStoreError.keychainWrite(addStatus)
      }
      return
    }
    guard updateStatus == errSecSuccess else {
      throw NativeWalletStoreError.keychainWrite(updateStatus)
    }
  }

  /// Distinguishes "no metadata has ever been written" (legitimately empty — `errSecItemNotFound`)
  /// from a genuine read/corruption failure, which now throws instead of being silently
  /// masked as an empty map. Masking it was the root cause of the "transient read failure
  /// followed by createWallet overwrites the index" scenario: a real failure here must abort
  /// the caller, not look identical to "no wallets yet".
  static func loadMetadata() throws -> [String: [String: String]] {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: metadataService,
      kSecAttrAccount as String: metadataAccount,
      kSecReturnData as String: true,
    ]
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
      return [:]
    }
    guard status == errSecSuccess, let data = result as? Data else {
      throw classify(status)
    }
    guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] else {
      throw NativeWalletStoreError.corrupted("metadata JSON is unreadable")
    }
    return obj
  }
}
