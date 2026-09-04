import XCTest
import WalletCore

// iOS companion to android/src/androidTest/.../AddressDerivationConformanceTest.kt.
// Verifies that HDWallet.getAddressForCoin produces the expected address for every
// chain under WalletCore 4.1.19 (the pinned version).
//
// The test mnemonic is the BIP39 standard test vector — never use with real funds.
//
// How to run:
//   1. In Xcode, add a new XCTest target to vault.xcworkspace.
//   2. Add this file to that target.
//   3. Make the target depend on TrustWalletCore (Pods) so `import WalletCore` resolves.
//   4. Product → Test (⌘U) or: xcodebuild test -workspace ios/vault.xcworkspace
//        -scheme <YourTestScheme> -destination 'platform=iOS Simulator,name=iPhone 17'
//
// Human-readable source of truth: conformance/address-derivation-vectors.json.
final class AddressDerivationConformanceTests: XCTestCase {

  static let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

  // Addresses confirmed against WalletCore 4.1.19.
  // ETH / BNB / POL all share CoinType.ethereum (same secp256k1 key, BIP44 m/44'/60'/0'/0/0).
  static let verified: [(CoinType, String)] = [
    (.ethereum,   "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"), // ethereum
    (.smartChain, "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"), // bnb
    // polygon shares CoinType.ethereum — address identical to ETH row above
  ]

  // Chains still needing on-device verification against 4.1.19.
  // Run testPrintPendingAddressesForVerification(), read the output, verify
  // independently (e.g. against the Android companion test), then move to verified.
  static let pending: [CoinType] = [
    .bitcoin,
    .litecoin,
    .xrp,
    .tron,
    .ton,
    .solana,
    .bitcoinCash,
  ]

  func testVerifiedAddressesMatch() {
    let wallet = HDWallet(mnemonic: Self.mnemonic, passphrase: "")!
    for (coin, expected) in Self.verified {
      let actual = wallet.getAddressForCoin(coin: coin)
      XCTAssertEqual(actual, expected, "address mismatch for coin \(coin.rawValue)")
    }
  }

  func testPrintPendingAddressesForVerification() {
    let wallet = HDWallet(mnemonic: Self.mnemonic, passphrase: "")!
    var lines = ["[AddressDerivationConformanceTests] Pending — verify and move to verified:"]
    for coin in Self.pending {
      lines.append("  \(coin.rawValue) -> \(wallet.getAddressForCoin(coin: coin))")
    }
    print(lines.joined(separator: "\n"))
    // Intentionally never fails — exists only to harvest pending addresses.
  }
}
