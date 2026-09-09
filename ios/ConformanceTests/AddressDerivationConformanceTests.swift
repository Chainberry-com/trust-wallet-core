import XCTest
import WalletCore

// iOS companion to android/src/androidTest/.../AddressDerivationConformanceTest.kt.
// Verifies that HDWallet.getAddressForCoin produces the expected address for every
// chain under WalletCore 4.1.19 (the pinned version).
//
// The test mnemonic is the BIP39 standard test vector — never use with real funds.
//
// How to run:
//   xcodebuild test -workspace ios/vault.xcworkspace -scheme WalletConformanceTests \
//     -destination 'platform=iOS Simulator,name=iPhone 17'
final class AddressDerivationConformanceTests: XCTestCase {

  static let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

  // All addresses confirmed against WalletCore 4.1.19 on-device (Android instrumented test
  // 2026-08-27; iOS confirmed via this test suite). ETH/BNB/POL share CoinType.ethereum.
  static let verified: [(coin: CoinType, chain: String, expected: String)] = [
    (.ethereum,    "ethereum",    "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
    (.smartChain,  "bnb",         "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
    (.ethereum,    "polygon",     "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
    (.bitcoin,     "bitcoin",     "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
    (.litecoin,    "litecoin",    "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh"),
    (.xrp,         "xrp",         "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3"),
    (.tron,        "tron",        "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH"),
    (.ton,         "ton",         "UQAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-RKY"),
    (.solana,      "solana",      "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL"),
    (.bitcoinCash, "bitcoincash", "bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6"),
  ]

  func testVerifiedAddressesMatch() {
    let wallet = HDWallet(mnemonic: Self.mnemonic, passphrase: "")!
    for v in Self.verified {
      let actual = wallet.getAddressForCoin(coin: v.coin)
      XCTAssertEqual(actual, v.expected, "chain '\(v.chain)': derived '\(actual)' ≠ expected '\(v.expected)'")
    }
  }
}
